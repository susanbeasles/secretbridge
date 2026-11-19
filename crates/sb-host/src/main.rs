use rand::RngCore;
use rand::rngs::OsRng;
use sb_host::HostBridge;
use sb_host::capture::NativeOsCaptureProvider;
use sb_host::manifest_io::HostError;
use sb_host::vmm::{
    DEFAULT_GUEST_CID, DEFAULT_VSOCK_PORT, EnclaveEndpoint, ManagedEnclaveHandle,
    MicroVmLaunchSpec, default_vmm_binary_path,
};
use sb_proto::error::ErrorCode;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmBackendPreference {
    Auto,
    Kvm,
    Vz,
}

enum BackendMode {
    NativeMicroVm {
        backend: VmBackendPreference,
        spec: MicroVmLaunchSpec,
    },
    LocalEnclaveProcess {
        enclave_bin: PathBuf,
        enclave_socket: PathBuf,
        authorized_client_pubkey: [u8; 32],
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
    let mut backend = VmBackendPreference::Auto;
    let mut vmm_binary = default_vmm_binary_path();
    let mut vmm_sha256: Option<[u8; 32]> = None;
    let mut kernel_path: Option<PathBuf> = None;
    let mut kernel_sha256: Option<[u8; 32]> = None;
    let mut initramfs_path: Option<PathBuf> = None;
    let mut initramfs_sha256: Option<[u8; 32]> = None;
    let mut authorized_client_pubkey: Option<[u8; 32]> = None;
    let mut guest_cid = DEFAULT_GUEST_CID;
    let mut vsock_port = DEFAULT_VSOCK_PORT;
    let mut memory_mib = 256u32;
    let mut enclave_bin: Option<PathBuf> = None;
    let mut enclave_socket: Option<PathBuf> = None;
    let mut enclave_key_file: Option<PathBuf> = None;
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
            "--backend" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --backend value")
                })?;
                backend = match val.as_str() {
                    "auto" => VmBackendPreference::Auto,
                    "kvm" => VmBackendPreference::Kvm,
                    "vz" => VmBackendPreference::Vz,
                    other => {
                        return Err(HostError::new(
                            ErrorCode::Validation,
                            format!("unsupported --backend '{other}'; expected auto, kvm, or vz"),
                        ));
                    }
                };
            }
            "--vmm-binary" => {
                vmm_binary = PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --vmm-binary path")
                })?);
            }
            "--vmm-sha256" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --vmm-sha256 hex")
                })?;
                vmm_sha256 = Some(parse_hex_32(&val, "vmm-sha256")?);
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
            "--authorized-client-pubkey-hex" => {
                let val = args.next().ok_or_else(|| {
                    HostError::new(
                        ErrorCode::Validation,
                        "missing --authorized-client-pubkey-hex",
                    )
                })?;
                authorized_client_pubkey = Some(parse_hex_32(&val, "authorized-client-pubkey")?);
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
            "--enclave-key-file" => {
                enclave_key_file = Some(PathBuf::from(args.next().ok_or_else(|| {
                    HostError::new(ErrorCode::Validation, "missing --enclave-key-file path")
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
    let staging_dir = ide_socket.parent().map(|p| p.join(".sb-boot-stage"));

    let mode = if let (Some(kp), Some(ks), Some(ip), Some(is)) =
        (kernel_path, kernel_sha256, initramfs_path, initramfs_sha256)
    {
        let client_pk = authorized_client_pubkey.ok_or_else(|| {
            HostError::new(
                ErrorCode::Validation,
                "--authorized-client-pubkey-hex <64-hex> is required when booting a microVM",
            )
        })?;
        BackendMode::NativeMicroVm {
            backend,
            spec: MicroVmLaunchSpec {
                vmm_binary,
                vmm_sha256,
                kernel_path: kp,
                kernel_sha256: ks,
                initramfs_path: ip,
                initramfs_sha256: is,
                authorized_client_pubkey: client_pk,
                guest_cid,
                vsock_port,
                memory_mib,
                staging_dir,
            },
        }
    } else if let (Some(bin), Some(sock)) = (enclave_bin, enclave_socket) {
        let client_pk = authorized_client_pubkey.ok_or_else(|| {
            HostError::new(
                ErrorCode::Validation,
                "--authorized-client-pubkey-hex <64-hex> is required with --enclave-bin",
            )
        })?;
        if let Some(kf) = enclave_key_file {
            let kf_raw = kf.to_string_lossy();
            if kf_raw.is_empty() || kf_raw.starts_with('-') || !kf.is_absolute() {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "--enclave-key-file must be a non-empty absolute path",
                ));
            }
            enclave_extra_args.push("--enclave-key-file".to_string());
            enclave_extra_args.push(kf_raw.into_owned());
        }
        BackendMode::LocalEnclaveProcess {
            enclave_bin: bin,
            enclave_socket: sock,
            authorized_client_pubkey: client_pk,
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
            "specify microVM flags (--kernel/--kernel-sha256/--initramfs/--initramfs-sha256/--authorized-client-pubkey-hex), --enclave-bin + --enclave-socket + --authorized-client-pubkey-hex, or --enclave-pubkey-hex",
        ));
    };

    Ok(HostCli { ide_socket, mode })
}

fn boot_backend(mode: BackendMode) -> Result<ManagedEnclaveHandle, HostError> {
    match mode {
        BackendMode::NativeMicroVm { backend, spec } => match backend {
            VmBackendPreference::Auto => ManagedEnclaveHandle::boot_native_microvm(&spec),
            VmBackendPreference::Kvm => ManagedEnclaveHandle::boot_kvm_microvm(&spec),
            VmBackendPreference::Vz => {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                {
                    ManagedEnclaveHandle::boot_macos_vz_microvm(&spec)
                }
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                {
                    let _ = spec;
                    Err(HostError::new(
                        ErrorCode::Validation,
                        "--backend vz is only supported on macOS arm64",
                    ))
                }
            }
        },
        BackendMode::LocalEnclaveProcess {
            enclave_bin,
            enclave_socket,
            authorized_client_pubkey,
            extra_args,
        } => ManagedEnclaveHandle::spawn_local_bridge_process(
            &enclave_bin,
            &enclave_socket,
            authorized_client_pubkey,
            &extra_args,
        ),
        BackendMode::ExistingVsock {
            cid,
            port,
            enclave_pubkey,
        } => Ok(ManagedEnclaveHandle::connect_existing(
            EnclaveEndpoint::Vsock { cid, port },
            enclave_pubkey,
        )),
    }
}

fn run() -> Result<(), HostError> {
    let cli = parse_cli()?;
    let handle = boot_backend(cli.mode)?;

    // Bind the mode-0600 Unix listener BEFORE emitting SB_HOST_READY so the IDE can connect
    // immediately without racing listener creation (closes H5).
    let listener = HostBridge::bind_ide_unix_listener(&cli.ide_socket)?;

    let mut auth_token = [0u8; 32];
    OsRng.fill_bytes(&mut auth_token);
    let auth_hex = Zeroizing::new(hex::encode(auth_token));
    let enclave_pk_hex = hex::encode(handle.enclave_pubkey());

    let bridge = Arc::new(HostBridge::new(
        handle,
        Arc::new(NativeOsCaptureProvider),
        auth_token,
    ));
    auth_token.zeroize();

    // Emit fixed-prefix startup banner with `socket=` LAST so paths containing spaces parse cleanly (H8).
    println!(
        "SB_HOST_READY token={} enckey={enclave_pk_hex} socket={}",
        auth_hex.as_str(),
        cli.ide_socket.display()
    );
    let _ = std::io::stdout().flush();
    drop(auth_hex);

    bridge.serve_bound_ide_listener(listener, None)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("sb-host error [{:?}]: {}", err.code, err.message);
        std::process::exit(1);
    }
}
