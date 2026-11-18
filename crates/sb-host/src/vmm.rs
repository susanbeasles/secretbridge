use crate::manifest_io::HostError;
use sb_proto::crypto::{NoiseSession, StaticKeypair, constant_time_eq_32, generate_noise_keypair};
use sb_proto::error::ErrorCode;
use sb_proto::rpc::{EnclaveRequest, EnclaveResponse};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::DropGuard;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const DEFAULT_GUEST_CID: u32 = 42;
pub const DEFAULT_VSOCK_PORT: u32 = 5190;

/// Verifies a kernel or initramfs image with `O_NOFOLLOW`, regular-file check, non-world-writable
/// permissions, and constant-time SHA-256 comparison BEFORE passing it to the VMM (closes S9/S12).
pub fn verify_boot_artifact_sha256(
    path: &Path,
    expected_sha256: &[u8; 32],
    label: &str,
) -> Result<(), HostError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            HostError::new(
                ErrorCode::Validation,
                format!("unable to open {label} artifact '{}': {e}", path.display()),
            )
        })?;
    let meta = file.metadata().map_err(|e| {
        HostError::new(
            ErrorCode::Validation,
            format!("unable to stat {label} artifact: {e}"),
        )
    })?;
    if !meta.is_file() {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} artifact must be a regular file"),
        ));
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o002) != 0 {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!("refusing to boot world-writable {label} artifact"),
            ));
        }
    }

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| {
            HostError::new(
                ErrorCode::Validation,
                format!("error reading {label} artifact: {e}"),
            )
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if !constant_time_eq_32(&actual, expected_sha256) {
        return Err(HostError::new(
            ErrorCode::CryptoFailure,
            format!("{label} SHA-256 verification failed against pinned digest"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum EnclaveEndpoint {
    /// Linux KVM separate-kernel microVM (`AF_VSOCK` CID + port).
    Vsock { cid: u32, port: u32 },
    /// Mode-0600 Unix domain socket bridge (macOS `VZVirtioSocketDevice` host shim or local enclave).
    UnixSocket { path: PathBuf },
}

pub struct ManagedEnclaveHandle {
    endpoint: EnclaveEndpoint,
    client_keypair: StaticKeypair,
    enclave_pubkey: [u8; 32],
    child_vm: Option<Child>,
}

impl Drop for ManagedEnclaveHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child_vm.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone)]
pub struct MicroVmLaunchSpec {
    pub vmm_binary: PathBuf,
    pub kernel_path: PathBuf,
    pub kernel_sha256: [u8; 32],
    pub initramfs_path: PathBuf,
    pub initramfs_sha256: [u8; 32],
    pub guest_cid: u32,
    pub vsock_port: u32,
    pub memory_mib: u32,
}

impl ManagedEnclaveHandle {
    /// Connects to an already-running enclave over `AF_VSOCK` or a mode-`0600` Unix socket.
    pub fn connect_existing(
        endpoint: EnclaveEndpoint,
        client_keypair: StaticKeypair,
        enclave_pubkey: [u8; 32],
    ) -> Self {
        Self {
            endpoint,
            client_keypair,
            enclave_pubkey,
            child_vm: None,
        }
    }

    /// Verifies kernel & initramfs SHA-256 digests and boots an isolated separate-kernel Linux
    /// microVM (`qemu-system-* -M microvm -enable-kvm` with `vhost-vsock-pci`), binding the
    /// enclave to a fresh ephemeral client `Noise_IK` static public key via kernel cmdline
    /// and reading the enclave's fresh ephemeral `Noise_IK` static public key from serial stdout.
    pub fn boot_kvm_microvm(spec: &MicroVmLaunchSpec) -> Result<Self, HostError> {
        verify_boot_artifact_sha256(&spec.kernel_path, &spec.kernel_sha256, "vmlinuz")?;
        verify_boot_artifact_sha256(&spec.initramfs_path, &spec.initramfs_sha256, "initramfs")?;

        if !Path::new("/dev/kvm").exists() {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                "/dev/kvm is not available on this Linux host; enable KVM virtualization",
            ));
        }

        let client_kp = generate_noise_keypair()?;
        let client_pk_hex = hex::encode(client_kp.public);
        let cmdline = format!(
            "console=ttyS0 reboot=k panic=1 pci=off nomodules quiet rdinit=/init sb.client_pubkey={client_pk_hex}"
        );

        let arch_machine = if cfg!(target_arch = "aarch64") {
            "virt,accel=kvm,gic-version=3"
        } else {
            "microvm,accel=kvm"
        };

        let child = Command::new(&spec.vmm_binary)
            .args([
                "-machine",
                arch_machine,
                "-m",
                &format!("{}M", spec.memory_mib.max(128)),
                "-smp",
                "1",
                "-nodefaults",
                "-no-user-config",
                "-nographic",
                "-serial",
                "stdio",
                "-kernel",
            ])
            .arg(&spec.kernel_path)
            .arg("-initrd")
            .arg(&spec.initramfs_path)
            .args(["-append", &cmdline])
            .args([
                "-netdev",
                "user,id=net0,restrict=off",
                "-device",
                "virtio-net-device,netdev=net0",
                "-device",
                &format!("vhost-vsock-device,guest-cid={},id=vsock0", spec.guest_cid),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                HostError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to launch microVM VMM '{}': {e}",
                        spec.vmm_binary.display()
                    ),
                )
            })?;

        // Ensure child VM is killed via DropGuard if serial handshake fails or times out.
        let mut child_guard = DropGuard::new(child, |mut c| {
            let _ = c.kill();
            let _ = c.wait();
        });

        let stdout = child_guard.stdout.take().ok_or_else(|| {
            HostError::new(ErrorCode::TransportFailure, "missing microVM serial stdout")
        })?;
        let enclave_pubkey = read_enclave_pubkey_banner(stdout, Duration::from_secs(15))?;
        let confirmed_child = DropGuard::dismiss(child_guard);

        Ok(Self {
            endpoint: EnclaveEndpoint::Vsock {
                cid: spec.guest_cid,
                port: spec.vsock_port,
            },
            client_keypair: client_kp,
            enclave_pubkey,
            child_vm: Some(confirmed_child),
        })
    }

    /// Spawns `sb-enclave` over a local mode-0600 Unix domain socket (used on macOS alongside
    /// the `Virtualization.framework` `VZVirtioSocketDevice` bridge and in automated CI tests).
    pub fn spawn_local_bridge_process(
        enclave_bin: &Path,
        socket_path: &Path,
        extra_args: &[String],
    ) -> Result<Self, HostError> {
        let client_kp = generate_noise_keypair()?;
        let client_pk_hex = hex::encode(client_kp.public);

        let mut cmd = Command::new(enclave_bin);
        cmd.arg("--unix-socket")
            .arg(socket_path)
            .arg("--authorized-client-pubkey-hex")
            .arg(&client_pk_hex)
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| {
            HostError::new(
                ErrorCode::TransportFailure,
                format!("failed spawning enclave process: {e}"),
            )
        })?;
        let mut child_guard = DropGuard::new(child, |mut c| {
            let _ = c.kill();
            let _ = c.wait();
        });

        let stdout = child_guard.stdout.take().ok_or_else(|| {
            HostError::new(ErrorCode::TransportFailure, "missing enclave stdout pipe")
        })?;
        let enclave_pubkey = read_enclave_pubkey_banner(stdout, Duration::from_secs(10))?;

        // Wait up to 3s for listener socket file to appear
        let wait_deadline = Instant::now() + Duration::from_secs(3);
        while !socket_path.exists() && Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        let confirmed_child = DropGuard::dismiss(child_guard);
        Ok(Self {
            endpoint: EnclaveEndpoint::UnixSocket {
                path: socket_path.to_path_buf(),
            },
            client_keypair: client_kp,
            enclave_pubkey,
            child_vm: Some(confirmed_child),
        })
    }

    pub fn enclave_pubkey(&self) -> &[u8; 32] {
        &self.enclave_pubkey
    }

    /// Executes a mutually-authenticated `Noise_IK` encrypted RPC call against the enclave.
    pub fn call(&self, request: &EnclaveRequest) -> Result<EnclaveResponse, HostError> {
        let req_bytes = Zeroizing::new(serde_json::to_vec(request).map_err(|e| {
            HostError::new(
                ErrorCode::Validation,
                format!("failed serializing enclave request: {e}"),
            )
        })?);

        match &self.endpoint {
            EnclaveEndpoint::UnixSocket { path } => {
                let mut stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
                    HostError::new(
                        ErrorCode::TransportFailure,
                        format!("failed connecting to enclave socket: {e}"),
                    )
                })?;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(45)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(45)));
                self.exchange_over_stream(&mut stream, &req_bytes)
            }
            EnclaveEndpoint::Vsock { cid, port } => {
                let mut vsock_file = connect_linux_vsock(*cid, *port)?;
                self.exchange_over_stream(&mut vsock_file, &req_bytes)
            }
        }
    }

    fn exchange_over_stream<S: Read + Write>(
        &self,
        stream: &mut S,
        req_bytes: &[u8],
    ) -> Result<EnclaveResponse, HostError> {
        let mut noise = NoiseSession::connect_initiator(
            stream,
            &self.client_keypair.private,
            &self.enclave_pubkey,
        )?;
        noise.send_message(stream, req_bytes)?;
        let resp_bytes = noise.recv_message(stream)?;
        serde_json::from_slice::<EnclaveResponse>(&resp_bytes).map_err(|e| {
            HostError::new(
                ErrorCode::TransportFailure,
                format!("invalid enclave response JSON: {e}"),
            )
        })
    }
}

fn read_enclave_pubkey_banner<R: Read + Send + 'static>(
    reader: R,
    timeout: Duration,
) -> Result<[u8; 32], HostError> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        while buf_reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some(hex_pk) = line.trim().strip_prefix("SB_ENCLAVE_NOISE_PUBKEY=") {
                let _ = tx.send(hex_pk.to_string());
                return;
            }
            line.clear();
        }
    });

    let pk_hex = rx.recv_timeout(timeout).map_err(|_| {
        HostError::new(
            ErrorCode::TransportFailure,
            "timed out waiting for SB_ENCLAVE_NOISE_PUBKEY banner from guest enclave",
        )
    })?;
    let raw = hex::decode(pk_hex.trim()).map_err(|_| {
        HostError::new(
            ErrorCode::CryptoFailure,
            "invalid hex in SB_ENCLAVE_NOISE_PUBKEY banner",
        )
    })?;
    raw.as_slice().try_into().map_err(|_| {
        HostError::new(
            ErrorCode::CryptoFailure,
            "enclave Noise static public key must be 32 bytes",
        )
    })
}

#[cfg(target_os = "linux")]
fn connect_linux_vsock(cid: u32, port: u32) -> Result<std::fs::File, HostError> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: creates a stream `AF_VSOCK` socket with `SOCK_CLOEXEC`.
    let raw_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HostError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK socket() failed: {err}"),
        ));
    }
    let fd_guard = DropGuard::new(raw_fd, |fd| unsafe {
        let _ = libc::close(fd);
    });

    let tv = libc::timeval {
        tv_sec: 45,
        tv_usec: 0,
    };
    // SAFETY: `fd_guard` is a valid socket fd; `tv` is initialized.
    unsafe {
        let _ = libc::setsockopt(
            *fd_guard,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            *fd_guard,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // SAFETY: zero-initializing POD `sockaddr_vm`.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;

    // SAFETY: `addr` has exact `sockaddr_vm` size.
    let rc = unsafe {
        libc::connect(
            *fd_guard,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HostError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK connect(cid={cid}, port={port}) failed: {err}"),
        ));
    }

    let confirmed_fd = DropGuard::dismiss(fd_guard);
    // SAFETY: `confirmed_fd` is newly created and owned exclusively here.
    let owned = unsafe { OwnedFd::from_raw_fd(confirmed_fd) };
    Ok(std::fs::File::from(owned))
}

#[cfg(not(target_os = "linux"))]
fn connect_linux_vsock(_cid: u32, _port: u32) -> Result<std::fs::File, HostError> {
    Err(HostError::new(
        ErrorCode::TransportFailure,
        "direct host AF_VSOCK requires Linux; on macOS arm64 use Virtualization.framework VZVirtioSocketDevice UnixSocket bridge",
    ))
}
