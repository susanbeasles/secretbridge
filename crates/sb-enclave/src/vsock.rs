use crate::error::EnclaveError;
use crate::mem_secret::MemSecret;
use crate::service::EnclaveService;
use sb_proto::crypto::NoiseSession;
use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use sb_proto::rpc::{EnclaveRequest, EnclaveResponse};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_VSOCK_PORT: u32 = 5190;
const MAX_CONCURRENT_SESSIONS: usize = 16;

/// Enclave `Noise_IK` static identity whose 32-byte private key resides strictly inside
/// `memfd_secret(2)` / `mlock(2)` + `MADV_DONTDUMP` RAM (`MemSecret`, `V2-C1`).
#[derive(Clone)]
pub struct MlockedNoiseIdentity {
    pub private: Arc<MemSecret>,
    pub public: [u8; 32],
}

/// Generates a fresh per-boot ephemeral `Noise_IK` static keypair inside locked enclave RAM (`V2-C1`).
/// Never writes any private key material to `initramfs` or host disk.
pub fn generate_ephemeral_enclave_identity() -> Result<MlockedNoiseIdentity, EnclaveError> {
    let mut kp = sb_proto::crypto::generate_noise_keypair()?;
    let locked_priv = MemSecret::from_slice(&*kp.private)?;
    let pub_key = kp.public;
    kp.private.zeroize();
    Ok(MlockedNoiseIdentity {
        private: Arc::new(locked_priv),
        public: pub_key,
    })
}

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

fn extract_cmdline_port_param(
    cmdline: &str,
    prefix: &str,
    label: &str,
) -> Result<Option<u32>, EnclaveError> {
    let mut found: Option<u32> = None;
    for token in cmdline.split_whitespace() {
        if let Some(val) = token.strip_prefix(prefix) {
            let port = val.parse::<u32>().map_err(|_| {
                EnclaveError::new(
                    ErrorCode::Validation,
                    format!("invalid {label} integer on kernel command line"),
                )
            })?;
            if !(1..=65_535).contains(&port) {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    format!("{label} on kernel command line must be in 1..=65535"),
                ));
            }
            found = Some(port);
        }
    }
    Ok(found)
}

/// Extracts and validates `sb.vsock_port=<1..=65535>` from `/proc/cmdline`.
pub fn extract_cmdline_vsock_port(cmdline: &str) -> Result<Option<u32>, EnclaveError> {
    extract_cmdline_port_param(cmdline, "sb.vsock_port=", "sb.vsock_port")
}

/// Extracts and validates `sb.egress_vsock_port=<1..=65535>` from `/proc/cmdline`.
pub fn extract_cmdline_egress_vsock_port(cmdline: &str) -> Result<Option<u32>, EnclaveError> {
    extract_cmdline_port_param(cmdline, "sb.egress_vsock_port=", "sb.egress_vsock_port")
}

/// Checks whether an exact space-delimited token (e.g. `sb.net_fallback=qemu_slirp`) appears on `/proc/cmdline`.
pub fn cmdline_has_token(cmdline: &str, expected_token: &str) -> bool {
    cmdline.split_whitespace().any(|tok| tok == expected_token)
}

/// Loads an optional out-of-band 32-byte X25519 enclave static key file (`O_NOFOLLOW | O_NONBLOCK`,
/// owner-only mode) directly into locked `MemSecret` RAM (used only when explicitly passed via
/// `--enclave-key-file` on external HSM/volume-mounted enclaves; never embedded in `initramfs`).
pub fn load_enclave_static_keypair(key_path: &Path) -> Result<MlockedNoiseIdentity, EnclaveError> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

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
                "unable to open enclave static key at {}",
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
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe {
            let _ = libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }

    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    file.read_exact(&mut *priv_bytes).map_err(|e| {
        EnclaveError::new(
            ErrorCode::InternalError,
            format!("failed reading enclave static key: {e}"),
        )
    })?;
    drop(file);

    let derived = sb_proto::crypto::derive_noise_keypair_from_private(*priv_bytes)?;
    let locked_priv = MemSecret::from_slice(&*priv_bytes)?;
    Ok(MlockedNoiseIdentity {
        private: Arc::new(locked_priv),
        public: derived.public,
    })
}

/// Binds a guest-internal loopback proxy (`127.0.0.1:0`) forwarding HTTPS `CONNECT` streams over
/// `AF_VSOCK` (`VMADDR_CID_HOST = 2`, `host_egress_port`) so QEMU can run with `-netdev restrict=on`
/// while `libop_uniffi_core.so` and `ureq` retain end-to-end guest-terminated TLS (`V2-H6`).
#[cfg(target_os = "linux")]
pub fn spawn_guest_vsock_https_proxy(host_egress_port: u32) -> Result<String, EnclaveError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| {
        EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("failed binding guest loopback HTTPS proxy: {e}"),
        )
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("failed reading guest loopback proxy address: {e}"),
        )
    })?;

    let _ = thread::Builder::new()
        .name("sb-guest-egress-vsock".into())
        .spawn(move || {
            for incoming in listener.incoming().flatten() {
                thread::spawn(move || {
                    let _ = relay_guest_tcp_to_host_vsock(incoming, host_egress_port);
                });
            }
        });

    Ok(format!("http://127.0.0.1:{}", local_addr.port()))
}

#[cfg(target_os = "linux")]
fn relay_guest_tcp_to_host_vsock(
    mut tcp_stream: std::net::TcpStream,
    host_egress_port: u32,
) -> std::io::Result<()> {
    use std::mem::DropGuard;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::time::Duration;

    let _ = tcp_stream.set_read_timeout(Some(Duration::from_secs(45)));
    let _ = tcp_stream.set_write_timeout(Some(Duration::from_secs(45)));

    let raw_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd_guard = DropGuard::new(raw_fd, |fd| unsafe {
        let _ = libc::close(fd);
    });

    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = libc::VMADDR_CID_HOST;
    addr.svm_port = host_egress_port;

    let rc = unsafe {
        libc::connect(
            *fd_guard,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let confirmed_fd = DropGuard::dismiss(fd_guard);
    let vsock_owned = unsafe { OwnedFd::from_raw_fd(confirmed_fd) };
    let mut vsock_writer = std::fs::File::from(vsock_owned);
    let mut vsock_reader = vsock_writer.try_clone()?;
    let mut tcp_writer = tcp_stream.try_clone()?;

    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut tcp_stream, &mut vsock_writer);
        unsafe {
            use std::os::fd::AsRawFd;
            let _ = libc::shutdown(vsock_writer.as_raw_fd(), libc::SHUT_WR);
        }
    });
    let _ = std::io::copy(&mut vsock_reader, &mut tcp_writer);
    let _ = tcp_writer.shutdown(std::net::Shutdown::Both);
    let _ = t1.join();
    Ok(())
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
    enclave_private: Arc<MemSecret>,
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
                let priv_ref = Arc::clone(&enclave_private);
                let act = Arc::clone(&active);
                thread::spawn(move || {
                    let _slot_guard = std::mem::DropGuard::new(act, |counter| {
                        counter.fetch_sub(1, Ordering::AcqRel);
                    });
                    if let Ok(key32) = priv_ref.as_bytes().try_into() {
                        let _ = serve_noise_connection(
                            stream,
                            svc.as_ref(),
                            key32,
                            &authorized_client_pubkey,
                        );
                    }
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
    enclave_private: Arc<MemSecret>,
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
        let priv_ref = Arc::clone(&enclave_private);
        let act = Arc::clone(&active);
        thread::spawn(move || {
            let _slot_guard = DropGuard::new(act, |counter| {
                counter.fetch_sub(1, Ordering::AcqRel);
            });
            if let Ok(key32) = priv_ref.as_bytes().try_into() {
                let _ =
                    serve_noise_connection(stream, svc.as_ref(), key32, &authorized_client_pubkey);
            }
        });
    }
    Ok(())
}
