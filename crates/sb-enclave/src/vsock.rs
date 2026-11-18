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
        if meta.file_type().is_symlink() {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "refusing to bind over symlinked socket path",
            ));
        }
        let _ = std::fs::remove_file(socket_path);
    }

    let listener = std::os::unix::net::UnixListener::bind(socket_path).map_err(|e| {
        EnclaveError::new(
            ErrorCode::TransportFailure,
            format!("failed to bind unix listener: {e}"),
        )
    })?;
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
