use rand::RngCore;
use rand::rngs::OsRng;
use sb_host::HostBridge;
use sb_host::capture::NativeOsCaptureProvider;
use sb_host::manifest_io::HostError;
use sb_host::vmm::{
    DEFAULT_GUEST_CID, DEFAULT_VSOCK_PORT, EnclaveEndpoint, ManagedEnclaveHandle, MicroVmLaunchSpec,
};
use sb_proto::crypto::generate_noise_keypair;
use sb_proto::error::ErrorCode;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

enum BackendMode {
    KvmMicroVm(MicroVmLaunchSpec),
    LocalEnclaveProcess {
        enclave_bin: PathBuf,
        enclave_socket: PathBuf,
        extra_args: Vec<String>,
    },
    ExistingVsock {
        cid: u32,
        port: u32,
        enclave_pubkey: [u8; 32],
    },
}

struct HostCli {
    ide_socket: PathBuf,
    mode: BackendMode,
}

fn parse_hex_32(hex_str: &str, label: &str) -> Result<[u8; 32], HostError> {
    let raw = hex::decode(hex_str.trim()).map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            format!("invalid 64-character hex digest for {label}"),
        )
    })?;
    raw.as_slice().try_into().map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            format!("{label} digest must be 32 bytes"),
        )
    })
}

fn parse_cli() -> Result<HostCli, HostError> {
    let mut ide_socket: Option<PathBuf> = None;
    let mut vmm_binary = PathBuf::from("qemu-system-x86_64");
    let mut kernel_path: Option<PathBuf> = None;
    let mut kernel_sha256: Option<[u8; 32]> = None;
    let mut initramfs_path: Option<PathBuf> = None;
    let mut initramfs_sha256: Option<[u8; 32]> = None;
    let mut guest_cid = DEFAULT_GUEST_CID;
    let mut vsock_port = DEFAULT_VSOCK_PORT;
    let mut memory_mib = 256u32;
    let mut enclave_bin: Option<PathBuf> = None;
    let mut enclave_socket: Option<PathBuf> = None;
    let mut enclave_pubkey: Option<[u8; 32]> = None;
    let mut enclave_extra_args = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ide-socket" => {
                ide_socket = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --ide-socket path")
                })?));
            }
            "--vmm-binary" => {
                vmm_binary = PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --vmm-binary path")
                })?);
            }
            "--kernel" => {
                kernel_path = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --kernel path")
                })?));
            }
            "--kernel-sha256" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --kernel-sha256 hex")
                })?;
                kernel_sha256 = Some(parse_hex_32(&val, "kernel-sha256")?);
            }
            "--initramfs" => {
                initramfs_path = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --initramfs path")
                })?));
            }
            "--initramfs-sha256" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --initramfs-sha256 hex")
                })?;
                initramfs_sha256 = Some(parse_hex_32(&val, "initramfs-sha256")?);
            }
            "--guest-cid" => {
                guest_cid = args
                    .next()
                    .ok_or_else(|| HostError::new(ErrorCode::Validation, "missing --guest-cid"))?
                    .parse()
                    .map_err(|_| HostError::new(ErrorCode::Validation, "invalid --guest-cid"))?;
            }
            "--vsock-port" => {
                vsock_port = args
                    .next()
                    .ok_or_else(|| HostError::new(ErrorCode::Validation, "missing --vsock-port"))?
                    .parse()
                    .map_err(|_| HostError::new(ErrorCode::Validation, "invalid --vsock-port"))?;
            }
            "--memory-mib" => {
                memory_mib = args
                    .next()
                    .ok_or_else(|| HostError::new(ErrorCode::Validation, "missing --memory-mib"))?
                    .parse()
                    .map_err(|_| HostError::new(ErrorCode::Validation, "invalid --memory-mib"))?;
            }
            "--enclave-bin" => {
                enclave_bin = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --enclave-bin path")
                })?));
            }
            "--enclave-socket" => {
                enclave_socket = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --enclave-socket path")
                })?));
            }
            "--enclave-pubkey-hex" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --enclave-pubkey-hex")
                })?;
                enclave_pubkey = Some(parse_hex_32(&val, "enclave-pubkey-hex")?);
            }
            "--enclave-arg" => {
                enclave_extra_args.push(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --enclave-arg value")
                })?);
            }
            other => {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    format!("unrecognized sb-host flag: {other}"),
                ));
            }
        }
    }

    let ide_socket = ide_socket.ok_or_else(|| {
        HostError::new(
            ErrorCode::Validation,
            "--ide-socket <path> is required for sb-host",
        )
    })?;

    let mode = if let (Some(kp), Some(ks), Some(ip), Some(is)) =
        (kernel_path, kernel_sha256, initramfs_path, initramfs_sha256)
    {
        BackendMode::KvmMicroVm(MicroVmLaunchSpec {
            vmm_binary,
            kernel_path: kp,
            kernel_sha256: ks,
            initramfs_path: ip,
            initramfs_sha256: is,
            guest_cid,
            vsock_port,
            memory_mib,
        })
    } else if let (Some(bin), Some(sock)) = (enclave_bin, enclave_socket) {
        BackendMode::LocalEnclaveProcess {
            enclave_bin: bin,
            enclave_socket: sock,
            extra_args: enclave_extra_args,
        }
    } else if let Some(pk) = enclave_pubkey {
        BackendMode::ExistingVsock {
            cid: guest_cid,
            port: vsock_port,
            enclave_pubkey: pk,
        }
    } else {
        return Err(HostError::new(
            ErrorCode::Validation,
            "specify either KVM microVM flags (--kernel/--kernel-sha256/--initramfs/--initramfs-sha256), --enclave-bin + --enclave-socket, or --enclave-pubkey-hex",
        ));
    };

    Ok(HostCli { ide_socket, mode })
}

fn run() -> Result<(), HostError> {
    let cli = parse_cli()?;
    let handle = match cli.mode {
        BackendMode::KvmMicroVm(spec) => ManagedEnclaveHandle::boot_kvm_microvm(&spec)?,
        BackendMode::LocalEnclaveProcess {
            enclave_bin,
            enclave_socket,
            extra_args,
        } => ManagedEnclaveHandle::spawn_local_bridge_process(
            &enclave_bin,
            &enclave_socket,
            &extra_args,
        )?,
        BackendMode::ExistingVsock {
            cid,
            port,
            enclave_pubkey,
        } => {
            let client_kp = generate_noise_keypair()?;
            ManagedEnclaveHandle::connect_existing(
                EnclaveEndpoint::Vsock { cid, port },
                client_kp,
                enclave_pubkey,
            )
        }
    };

    let mut auth_token = [0u8; 32];
    OsRng.fill_bytes(&mut auth_token);
    let auth_hex = hex::encode(auth_token);

    // Emit single startup handshake line on stdout for the spawning JetBrains IDE process.
    println!(
        "SB_HOST_READY socket={} token={auth_hex}",
        cli.ide_socket.display()
    );
    let _ = std::io::stdout().flush();

    let bridge = HostBridge::new(handle, Arc::new(NativeOsCaptureProvider), auth_token);
    zeroize::Zeroize::zeroize(&mut auth_token);
    bridge.serve_ide_unix_socket(&cli.ide_socket)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("sb-host error [{:?}]: {}", err.code, err.message);
        std::process::exit(1);
    }
}
