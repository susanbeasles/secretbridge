use crate::error::EnclaveError;
use crate::service::EnclaveService;
use sb_proto::crypto::NoiseSession;
use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use sb_proto::rpc::{EnclaveRequest, EnclaveResponse};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use zeroize::Zeroizing;

pub const DEFAULT_VSOCK_PORT: u32 = 5190;
const MAX_CONCURRENT_SESSIONS: usize = 16;

/// Parses a 64-character hex Noise static public key (e.g. from kernel cmdline `sb.client_pubkey=`).
pub fn parse_pubkey_hex(hex_str: &str) -> Result<[u8; 32], EnclaveError> {
    let trimmed = hex_str.trim();
    let raw = hex::decode(trimmed).map_err(|_| {
        EnclaveError::new(
            ErrorCode::Validation,
            "expected 64-character hex X25519 public key",
        )
    })?;
    raw.as_slice().try_into().map_err(|_| {
        EnclaveError::new(
            ErrorCode::Validation,
            "Noise static public key must decode to 32 bytes",
        )
    })
}

/// Extracts `sb.client_pubkey=<hex>` from a kernel command-line string (`/proc/cmdline`).
pub fn extract_cmdline_client_pubkey(cmdline: &str) -> Option<&str> {
    for token in cmdline.split_whitespace() {
        if let Some(val) = token.strip_prefix("sb.client_pubkey=")
            && !val.is_empty()
        {
            return Some(val);
        }
    }
    None
}

/// Extracts and validates `sb.vsock_port=<1..=65535>` from `/proc/cmdline`.
pub fn extract_cmdline_vsock_port(cmdline: &str) -> Result<Option<u32>, EnclaveError> {
    let mut found: Option<u32> = None;
    for token in cmdline.split_whitespace() {
        if let Some(val) = token.strip_prefix("sb.vsock_port=") {
            let port = val.parse::<u32>().map_err(|_| {
                EnclaveError::new(
                    ErrorCode::Validation,
                    "invalid sb.vsock_port integer on kernel command line",
                )
            })?;
            if !(1..=65_535).contains(&port) {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "sb.vsock_port on kernel command line must be in 1..=65535",
                ));
            }
            found = Some(port);
        }
    }
    Ok(found)
}

/// Checks whether an exact space-delimited token (e.g. `sb.net_fallback=qemu_slirp`) appears on `/proc/cmdline`.
pub fn cmdline_has_token(cmdline: &str, expected_token: &str) -> bool {
    cmdline.split_whitespace().any(|tok| tok == expected_token)
}

pub const DEFAULT_ENCLAVE_KEY_PATH: &str = "/etc/secretbridge/enclave_noise.key";

/// Generates a persistent 32-byte X25519 enclave static identity (`0400`, `O_NOFOLLOW`) for
/// sealing inside `initramfs` (or local dev key storage) and writes its 64-hex public key to `pub_hex_path`.
pub fn write_generated_enclave_identity(
    priv_path: &Path,
    pub_hex_path: &Path,
) -> Result<[u8; 32], EnclaveError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let kp = sb_proto::crypto::generate_noise_keypair()?;
    if let Some(parent) = priv_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            EnclaveError::new(
                ErrorCode::InternalError,
                format!("failed creating enclave identity directory: {e}"),
            )
        })?;
    }
    if let Some(pub_parent) = pub_hex_path.parent()
        && !pub_parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(pub_parent).map_err(|e| {
            EnclaveError::new(
                ErrorCode::InternalError,
                format!("failed creating enclave pubkey directory: {e}"),
            )
        })?;
    }

    let _ = std::fs::remove_file(priv_path);
    let mut priv_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(priv_path)
        .map_err(|e| {
            EnclaveError::new(
                ErrorCode::InternalError,
                format!("failed creating enclave static key file: {e}"),
            )
        })?;
    std::fs::set_permissions(priv_path, std::fs::Permissions::from_mode(0o400)).map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed setting 0400 mode on enclave static key: {e}"),
        )
    })?;
    priv_file.write_all(&*kp.private).map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed writing enclave static key: {e}"),
        )
    })?;
    priv_file.sync_all().map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed syncing enclave static key: {e}"),
        )
    })?;

    let mut pub_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(pub_hex_path)
        .map_err(|e| {
            EnclaveError::new(
                ErrorCode::InternalError,
                format!("failed creating enclave pubkey file: {e}"),
            )
        })?;
    writeln!(pub_file, "{}", hex::encode(kp.public)).map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed writing enclave pubkey hex: {e}"),
        )
    })?;
    Ok(kp.public)
}

/// Loads a provisioned 32-byte X25519 enclave static keypair (`O_NOFOLLOW | O_NONBLOCK`, owner-only mode)
/// so the guest enclave maintains a deterministic authenticated identity across managed restarts.
/// When `shred_after_read` is true (guest PID 1), overwrites and unlinks the `tmpfs` copy immediately.
pub fn load_enclave_static_keypair(
    key_path: &Path,
    shred_after_read: bool,
) -> Result<sb_proto::crypto::StaticKeypair, EnclaveError> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let c_path = CString::new(key_path.as_os_str().as_bytes())
        .map_err(|_| EnclaveError::new(ErrorCode::Validation, "invalid enclave key path"))?;
    // SAFETY: `c_path` is NUL-terminated; `O_NOFOLLOW | O_NONBLOCK` rejects symlinks and avoids FIFO hangs.
    let raw_fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        return Err(EnclaveError::new(
            ErrorCode::Unauthorized,
            format!(
                "missing provisioned enclave static key at {} (build initramfs with vm/build-initramfs.sh or pass --enclave-key-file)",
                key_path.display()
            ),
        ));
    }
    // SAFETY: `raw_fd` is newly opened and owned solely by `file`.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(raw_fd, &mut st) } != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        return Err(EnclaveError::new(
            ErrorCode::Validation,
            "enclave static key must be a regular file",
        ));
    }
    if (st.st_mode & 0o077) != 0 {
        return Err(EnclaveError::new(
            ErrorCode::Validation,
            "refusing to load group/world-accessible enclave static key file (expected 0400 or 0600)",
        ));
    }
    if st.st_size != 32 {
        return Err(EnclaveError::new(
            ErrorCode::Validation,
            "enclave static key file must be exactly 32 raw bytes",
        ));
    }

    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *priv_bytes).map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed reading enclave static key: {e}"),
        )
    })?;
    drop(file);

    if shred_after_read {
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        if let Ok(mut wipe_file) = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(key_path)
        {
            let _ = wipe_file.write_all(&[0u8; 32]);
            let _ = wipe_file.sync_all();
        }
        let _ = std::fs::remove_file(key_path);
    }

    sb_proto::crypto::derive_noise_keypair_from_private(*priv_bytes).map_err(EnclaveError::from)
}

/// Handles a single mutually-authenticated `Noise_IK` RPC session.
/// Immediately drops `stream` on unauthorized handshake or framing violation.
pub fn serve_noise_connection<S: Read + Write>(
    mut stream: S,
    service: &EnclaveService,
    enclave_private: &[u8; 32],
    authorized_client_pubkey: &[u8; 32],
) -> Result<(), EnclaveError> {
    let mut session =
        NoiseSession::accept_responder(&mut stream, enclave_private, authorized_client_pubkey)?;

    loop {
        let req_bytes = match session.recv_message(&mut stream) {
            Ok(bytes) => bytes,
            Err(ProtoError::Transport(msg))
                if msg.contains("UnexpectedEof")
                    || msg.contains("eof")
                    || msg.contains("early eof")
                    || msg.contains("failed to fill whole buffer") =>
            {
                return Ok(());
            }
            Err(err) => return Err(EnclaveError::from(err)),
        };

        let response = match serde_json::from_slice::<EnclaveRequest>(&req_bytes) {
            Ok(req) => service.handle(req),
            Err(parse_err) => EnclaveResponse::err(SanitizedError::new(
                ErrorCode::Validation,
                format!("malformed RPC request payload: {parse_err}"),
            )),
        };

        let resp_bytes = Zeroizing::new(serde_json::to_vec(&response).map_err(|e| {
            EnclaveError::new(
                ErrorCode::InternalError,
                format!("failed to serialize RPC response: {e}"),
            )
        })?);
        session.send_message(&mut stream, &resp_bytes)?;
    }
}

/// Serves `Noise_IK` RPC sessions over a mode-`0600` Unix domain socket (used by host bridges & tests).
pub fn serve_unix_listener(
    socket_path: &Path,
    service: Arc<EnclaveService>,
    enclave_private: Zeroizing<[u8; 32]>,
    authorized_client_pubkey: [u8; 32],
    shutdown: Arc<AtomicBool>,
) -> Result<(), EnclaveError> {
    if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "refusing to unlink non-socket or symlinked path",
            ));
        }
        std::fs::remove_file(socket_path).map_err(|e| {
            EnclaveError::new(
                ErrorCode::TransportFailure,
                format!("failed removing stale unix socket: {e}"),
            )
        })?;
    }

    let listener = {
        // SAFETY: `umask` is async-signal-safe and always succeeds; restored immediately by DropGuard.
        let prev_umask = unsafe { libc::umask(0o077) };
        let _umask_guard = std::mem::DropGuard::new(prev_umask, |old| {
            // SAFETY: Restores previous process umask unconditionally.
            unsafe {
                libc::umask(old);
            }
        });
        std::os::unix::net::UnixListener::bind(socket_path).map_err(|e| {
            EnclaveError::new(
                ErrorCode::TransportFailure,
                format!("failed to bind unix listener: {e}"),
            )
        })?
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(socket_path, perms).map_err(|e| {
            EnclaveError::new(
                ErrorCode::TransportFailure,
                format!("failed to chmod 0600 unix socket: {e}"),
            )
        })?;
    }
    listener.set_nonblocking(true).map_err(|e| {
        EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("failed to set nonblocking listener: {e}"),
        )
    })?;

    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
                if active.load(Ordering::Acquire) >= MAX_CONCURRENT_SESSIONS {
                    drop(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::AcqRel);
                let svc = Arc::clone(&service);
                let priv_copy = enclave_private.clone();
                let act = Arc::clone(&active);
                thread::spawn(move || {
                    let _slot_guard = std::mem::DropGuard::new(act, |counter| {
                        counter.fetch_sub(1, Ordering::AcqRel);
                    });
                    let _ = serve_noise_connection(
                        stream,
                        svc.as_ref(),
                        &priv_copy,
                        &authorized_client_pubkey,
                    );
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(err) => {
                return Err(EnclaveError::new(
                    ErrorCode::TransportFailure,
                    format!("unix listener accept error: {e}", e = err),
                ));
            }
        }
    }
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Serves `Noise_IK` RPC sessions directly over Linux `AF_VSOCK` (`VMADDR_CID_ANY`, `port`).
#[cfg(target_os = "linux")]
pub fn serve_vsock_listener(
    port: u32,
    service: Arc<EnclaveService>,
    enclave_private: Zeroizing<[u8; 32]>,
    authorized_client_pubkey: [u8; 32],
    shutdown: Arc<AtomicBool>,
) -> Result<(), EnclaveError> {
    use std::mem::DropGuard;
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: `socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0)` creates an owned socket fd or -1.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK socket creation failed: {err}"),
        ));
    }

    let fd_guard = DropGuard::new(raw_fd, |fd| {
        // SAFETY: `fd` is owned solely by this scope until transferred to `OwnedFd`.
        unsafe {
            let _ = libc::close(fd);
        }
    });

    // SAFETY: zero-initializing `libc::sockaddr_vm` POD struct before populating fields.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr.svm_port = port;

    // SAFETY: `addr` is valid and sized to `size_of::<sockaddr_vm>()`.
    let bind_rc = unsafe {
        libc::bind(
            *fd_guard,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if bind_rc < 0 {
        let err = std::io::Error::last_os_error();
        return Err(EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK bind on port {port} failed: {err}"),
        ));
    }

    // SAFETY: `fd_guard` holds a bound stream socket.
    let listen_rc = unsafe { libc::listen(*fd_guard, 16) };
    if listen_rc < 0 {
        let err = std::io::Error::last_os_error();
        return Err(EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK listen failed: {err}"),
        ));
    }

    let confirmed_fd = DropGuard::dismiss(fd_guard);
    // SAFETY: `confirmed_fd` is a valid open socket fd now owned by `listener_fd`.
    let _listener_fd = unsafe { OwnedFd::from_raw_fd(confirmed_fd) };

    let active = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::Acquire) {
        // SAFETY: accepting connection from valid listening socket `confirmed_fd` with `SOCK_CLOEXEC`.
        let conn_fd = unsafe {
            libc::accept4(
                confirmed_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            return Err(EnclaveError::new(
                ErrorCode::TransportFailure,
                format!("AF_VSOCK accept4 failed: {err}"),
            ));
        }

        // Apply 30s read/write timeout to accepted vsock stream
        let tv = libc::timeval {
            tv_sec: 30,
            tv_usec: 0,
        };
        // SAFETY: `conn_fd` is a valid connected socket and `tv` is properly initialized.
        unsafe {
            let _ = libc::setsockopt(
                conn_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
            let _ = libc::setsockopt(
                conn_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                (&raw const tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        // SAFETY: `conn_fd` was freshly returned by `accept4`.
        let owned_conn = unsafe { OwnedFd::from_raw_fd(conn_fd) };
        let stream = std::fs::File::from(owned_conn);

        if active.load(Ordering::Acquire) >= MAX_CONCURRENT_SESSIONS {
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let svc = Arc::clone(&service);
        let priv_copy = enclave_private.clone();
        let act = Arc::clone(&active);
        thread::spawn(move || {
            let _slot_guard = DropGuard::new(act, |counter| {
                counter.fetch_sub(1, Ordering::AcqRel);
            });
            let _ =
                serve_noise_connection(stream, svc.as_ref(), &priv_copy, &authorized_client_pubkey);
        });
    }
    Ok(())
}
