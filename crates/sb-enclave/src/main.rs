use sb_enclave::aws::SigV4AwsClient;
use sb_enclave::error::EnclaveError;
use sb_enclave::github::RestGitHubClient;
use sb_enclave::service::EnclaveService;
use sb_enclave::vault::{InMemoryVaultProvider, UniffiCoreVaultProvider, VaultProvider};
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
    in_memory_test_token: Option<String>,
}

fn parse_sha256_list(csv: &str) -> Result<Vec<[u8; 32]>, EnclaveError> {
    let mut out = Vec::new();
    for item in csv.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let raw = hex::decode(trimmed).map_err(|_| {
            EnclaveError::new(
                ErrorCode::Validation,
                "invalid hex SHA-256 digest in allowlist",
            )
        })?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            EnclaveError::new(ErrorCode::Validation, "SHA-256 digest must be 32 bytes")
        })?;
        out.push(arr);
    }
    Ok(out)
}

fn parse_args() -> Result<CliConfig, EnclaveError> {
    let mut vsock_port = DEFAULT_VSOCK_PORT;
    let mut unix_socket: Option<PathBuf> = None;
    let mut client_pk_hex: Option<String> = std::env::var("SB_AUTHORIZED_CLIENT_PUBKEY_HEX").ok();
    let mut op_core_lib = PathBuf::from(
        std::env::var("SB_OP_CORE_LIB")
            .unwrap_or_else(|_| "/usr/lib/libop_uniffi_core.so".to_string()),
    );
    let mut op_core_sha256_csv = std::env::var("SB_OP_CORE_SHA256").unwrap_or_default();
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
                op_core_sha256_csv = args.next().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing --op-core-sha256 value")
                })?;
            }
            "--in-memory-vault-test-token" => {
                in_memory_test_token = Some(args.next().ok_or_else(|| {
                    EnclaveError::new(
                        ErrorCode::Validation,
                        "missing --in-memory-vault-test-token value",
                    )
                })?);
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
    let op_core_sha256 = parse_sha256_list(&op_core_sha256_csv)?;

    Ok(CliConfig {
        vsock_port,
        unix_socket,
        authorized_client_pubkey,
        op_core_lib,
        op_core_sha256,
        in_memory_test_token,
    })
}

fn run() -> Result<(), EnclaveError> {
    let cfg = parse_args()?;
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
