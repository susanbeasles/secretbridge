use sb_enclave::aws::SigV4AwsClient;
use sb_enclave::error::EnclaveError;
use sb_enclave::github::RestGitHubClient;
use sb_enclave::service::EnclaveService;
#[cfg(debug_assertions)]
use sb_enclave::vault::{InMemoryVaultProvider, parse_sha256_allowlist_csv};
use sb_enclave::vault::{UniffiCoreVaultProvider, VaultProvider, compiled_op_core_allowlist};
use sb_enclave::vsock::{
    DEFAULT_VSOCK_PORT, extract_cmdline_client_pubkey, parse_pubkey_hex, serve_unix_listener,
};
use sb_proto::crypto::generate_noise_keypair;
use sb_proto::error::ErrorCode;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

struct CliConfig {
    vsock_port: u32,
    unix_socket: Option<PathBuf>,
    authorized_client_pubkey: [u8; 32],
    op_core_lib: PathBuf,
    op_core_sha256: Vec<[u8; 32]>,
    #[cfg(debug_assertions)]
    in_memory_test_token: Option<String>,
}

#[cfg(target_os = "linux")]
fn init_guest_pid1_environment() -> Result<(), EnclaveError> {
    use std::ffi::CString;
    use std::mem::DropGuard;

    for dir in ["/proc", "/sys", "/dev", "/etc"] {
        let _ = std::fs::create_dir_all(dir);
    }

    fn mount_pseudo_fs(
        target: &str,
        fstype: &str,
        flags: libc::c_ulong,
    ) -> Result<(), EnclaveError> {
        let c_src = CString::new(fstype).expect("static cstr");
        let c_tgt = CString::new(target).expect("static cstr");
        let c_type = CString::new(fstype).expect("static cstr");
        // SAFETY: All pointers are valid NUL-terminated strings; `data` is NULL.
        let rc = unsafe {
            libc::mount(
                c_src.as_ptr(),
                c_tgt.as_ptr(),
                c_type.as_ptr(),
                flags,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EBUSY) {
                return Err(EnclaveError::new(
                    ErrorCode::TransportFailure,
                    format!("PID-1 failed mounting {target} ({fstype}): {err}"),
                ));
            }
        }
        Ok(())
    }

    let hardened_flags = (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong;
    mount_pseudo_fs("/proc", "proc", hardened_flags)?;
    mount_pseudo_fs("/sys", "sysfs", hardened_flags)?;
    mount_pseudo_fs(
        "/dev",
        "devtmpfs",
        (libc::MS_NOSUID | libc::MS_NOEXEC) as libc::c_ulong,
    )?;

    // Configure loopback + guest NAT interface via netdevice ioctls (zero busybox/shell in guest).
    // SAFETY: Creates an owned AF_INET datagram socket for netdevice ioctls.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Ok(());
    }
    let _sock_guard = DropGuard::new(sock, |fd| {
        // SAFETY: `fd` is owned solely by this scope.
        unsafe {
            let _ = libc::close(fd);
        }
    });

    fn make_sin(ip: [u8; 4]) -> libc::sockaddr {
        // SAFETY: Zero-initialized POD `sockaddr_in` reinterpreted as `sockaddr`.
        unsafe {
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip);
            std::ptr::read((&raw const sin).cast::<libc::sockaddr>())
        }
    }

    fn set_if_ipv4_up(sock: i32, ifname: &str, ip: [u8; 4], mask: [u8; 4]) -> bool {
        if ifname.is_empty() || ifname.len() >= libc::IFNAMSIZ {
            return false;
        }
        // SAFETY: Zero-initialized POD `ifreq` populated with bounded interface name.
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            for (idx, b) in ifname.bytes().enumerate() {
                ifr.ifr_name[idx] = b as libc::c_char;
            }
            ifr.ifr_ifru.ifru_addr = make_sin(ip);
            if libc::ioctl(sock, libc::SIOCSIFADDR as _, &mut ifr) != 0 {
                return false;
            }
            ifr.ifr_ifru.ifru_addr = make_sin(mask);
            let _ = libc::ioctl(sock, libc::SIOCSIFNETMASK as _, &mut ifr);

            let mut flag_req: libc::ifreq = std::mem::zeroed();
            for (idx, b) in ifname.bytes().enumerate() {
                flag_req.ifr_name[idx] = b as libc::c_char;
            }
            if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut flag_req) == 0 {
                flag_req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
                let _ = libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &mut flag_req);
            }
        }
        true
    }

    let _ = set_if_ipv4_up(sock, "lo", [127, 0, 0, 1], [255, 0, 0, 0]);

    // Check if kernel `ip=dhcp` already configured a default route & `/proc/net/pnp`.
    let has_default_route = std::fs::read_to_string("/proc/net/route")
        .map(|s| {
            s.lines()
                .skip(1)
                .any(|l| l.split_whitespace().nth(1) == Some("00000000"))
        })
        .unwrap_or(false);

    if let Ok(pnp) = std::fs::read_to_string("/proc/net/pnp") {
        let mut resolv = String::new();
        for line in pnp.lines() {
            if line.starts_with("nameserver ") {
                resolv.push_str(line);
                resolv.push('\n');
            }
        }
        if !resolv.is_empty() {
            let _ = std::fs::write("/etc/resolv.conf", resolv);
        }
    }

    if !has_default_route {
        let primary_nic = std::fs::read_dir("/sys/class/net")
            .ok()
            .and_then(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .find(|n| n != "lo")
            })
            .unwrap_or_else(|| "eth0".to_string());

        if set_if_ipv4_up(sock, &primary_nic, [10, 0, 2, 15], [255, 255, 255, 0]) {
            // Add default gateway 10.0.2.2 (QEMU user-mode SLIRP NAT).
            // SAFETY: Zero-initialized `rtentry` populated with valid `AF_INET` sockaddrs.
            unsafe {
                let mut rt: libc::rtentry = std::mem::zeroed();
                rt.rt_dst = make_sin([0, 0, 0, 0]);
                rt.rt_genmask = make_sin([0, 0, 0, 0]);
                rt.rt_gateway = make_sin([10, 0, 2, 2]);
                rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
                let _ = libc::ioctl(sock, libc::SIOCADDRT as _, &mut rt);
            }
            if std::fs::metadata("/etc/resolv.conf").is_err() {
                let _ = std::fs::write("/etc/resolv.conf", "nameserver 10.0.2.3\n");
            }
        }
    }

    Ok(())
}

fn parse_args() -> Result<CliConfig, EnclaveError> {
    let mut vsock_port = DEFAULT_VSOCK_PORT;
    let mut unix_socket: Option<PathBuf> = None;
    let mut client_pk_hex: Option<String> = std::env::var("SB_AUTHORIZED_CLIENT_PUBKEY_HEX").ok();
    let mut op_core_lib = PathBuf::from(
        std::env::var("SB_OP_CORE_LIB")
            .unwrap_or_else(|_| "/usr/lib/libop_uniffi_core.so".to_string()),
    );
    let mut runtime_sha256_csv: Option<String> = std::env::var("SB_OP_CORE_SHA256")
        .ok()
        .filter(|s| !s.trim().is_empty());
    #[cfg(debug_assertions)]
    let mut in_memory_test_token: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vsock-port" => {
                let val = args.next().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing --vsock-port value")
                })?;
                vsock_port = val.parse::<u32>().map_err(|_| {
                    EnclaveError::new(ErrorCode::Validation, "invalid --vsock-port integer")
                })?;
            }
            "--unix-socket" => {
                let val = args.next().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing --unix-socket path")
                })?;
                unix_socket = Some(PathBuf::from(val));
            }
            "--authorized-client-pubkey-hex" => {
                client_pk_hex = Some(args.next().ok_or_else(|| {
                    EnclaveError::new(
                        ErrorCode::Validation,
                        "missing --authorized-client-pubkey-hex value",
                    )
                })?);
            }
            "--op-core-lib" => {
                let val = args.next().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing --op-core-lib path")
                })?;
                op_core_lib = PathBuf::from(val);
            }
            "--op-core-sha256" => {
                let val = args.next().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing --op-core-sha256 value")
                })?;
                runtime_sha256_csv = Some(val);
            }
            "--in-memory-vault-test-token" => {
                let val = args.next().ok_or_else(|| {
                    EnclaveError::new(
                        ErrorCode::Validation,
                        "missing --in-memory-vault-test-token value",
                    )
                })?;
                #[cfg(debug_assertions)]
                {
                    in_memory_test_token = Some(val);
                }
                #[cfg(not(debug_assertions))]
                {
                    let _ = val;
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "--in-memory-vault-test-token is disabled in release builds",
                    ));
                }
            }
            other => {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    format!("unrecognized enclave flag: {other}"),
                ));
            }
        }
    }

    if client_pk_hex.is_none()
        && let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline")
        && let Some(found) = extract_cmdline_client_pubkey(&cmdline)
    {
        client_pk_hex = Some(found.to_string());
    }

    let pk_hex = client_pk_hex.ok_or_else(|| {
        EnclaveError::new(
            ErrorCode::Unauthorized,
            "missing authorized client Noise static public key (sb.client_pubkey or --authorized-client-pubkey-hex)",
        )
    })?;
    let authorized_client_pubkey = parse_pubkey_hex(&pk_hex)?;

    #[cfg(not(debug_assertions))]
    let op_core_sha256 = {
        if runtime_sha256_csv.is_some() {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "runtime --op-core-sha256 / SB_OP_CORE_SHA256 overrides are disabled in release builds; compile with SB_PINNED_OP_CORE_SHA256",
            ));
        }
        compiled_op_core_allowlist()?
    };

    #[cfg(debug_assertions)]
    let op_core_sha256 = {
        let mut list = compiled_op_core_allowlist()?;
        if let Some(rt_csv) = runtime_sha256_csv {
            list.extend(parse_sha256_allowlist_csv(&rt_csv)?);
        }
        list
    };

    Ok(CliConfig {
        vsock_port,
        unix_socket,
        authorized_client_pubkey,
        op_core_lib,
        op_core_sha256,
        #[cfg(debug_assertions)]
        in_memory_test_token,
    })
}

fn run() -> Result<(), EnclaveError> {
    #[cfg(target_os = "linux")]
    if std::process::id() == 1 {
        init_guest_pid1_environment()?;
    }

    let cfg = parse_args()?;

    #[cfg(debug_assertions)]
    let vault_provider: Arc<dyn VaultProvider> = match cfg.in_memory_test_token {
        Some(tok) => {
            let mock = InMemoryVaultProvider::new(tok, true);
            mock.seed_vault("vault-dev-01", "Dev Vault", true, true);
            Arc::new(mock)
        }
        None => Arc::new(UniffiCoreVaultProvider::load_verified(
            &cfg.op_core_lib,
            cfg.op_core_sha256,
        )?),
    };

    #[cfg(not(debug_assertions))]
    let vault_provider: Arc<dyn VaultProvider> = Arc::new(UniffiCoreVaultProvider::load_verified(
        &cfg.op_core_lib,
        cfg.op_core_sha256,
    )?);

    let aws_client = Arc::new(SigV4AwsClient::default());
    let github_client = Arc::new(RestGitHubClient::default());
    let service = Arc::new(EnclaveService::new(
        vault_provider,
        aws_client,
        github_client,
    ));

    let enclave_kp = generate_noise_keypair()?;
    let pubkey_hex = hex::encode(enclave_kp.public);
    println!("SB_ENCLAVE_NOISE_PUBKEY={pubkey_hex}");
    let _ = std::io::stdout().flush();

    let shutdown = Arc::new(AtomicBool::new(false));
    if let Some(sock_path) = cfg.unix_socket {
        return serve_unix_listener(
            &sock_path,
            service,
            enclave_kp.private,
            cfg.authorized_client_pubkey,
            shutdown,
        );
    }

    #[cfg(target_os = "linux")]
    {
        sb_enclave::vsock::serve_vsock_listener(
            cfg.vsock_port,
            service,
            enclave_kp.private,
            cfg.authorized_client_pubkey,
            shutdown,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg.vsock_port;
        Err(EnclaveError::new(
            ErrorCode::TransportFailure,
            "AF_VSOCK enclave guest listener requires a Linux kernel; use --unix-socket on non-Linux hosts",
        ))
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("sb-enclave error [{:?}]: {}", err.code, err.message);
        std::process::exit(1);
    }
}
