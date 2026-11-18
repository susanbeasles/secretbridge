pub mod capture;
pub mod manifest_io;
pub mod vmm;

use crate::capture::{ArmedCaptureProvider, DEFAULT_ARMED_COPY_TTL, execute_armed_capture};
use crate::manifest_io::{HostError, load_manifest, save_manifest_atomic};
use crate::vmm::ManagedEnclaveHandle;
use sb_proto::crypto::constant_time_eq_32;
use sb_proto::error::{ErrorCode, SanitizedError};
use sb_proto::rpc::{CaptureTarget, EnclaveRequest, EnclaveResponse, EnclaveResult};
use sb_proto::types::{Manifest, OpRef, SecretName, Slug};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedHostEnvelope {
    pub auth_token_hex: String,
    pub command: HostCommand,
}

impl Drop for AuthenticatedHostEnvelope {
    fn drop(&mut self) {
        self.auth_token_hex.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "host_op", rename_all = "kebab-case")]
pub enum HostCommand {
    /// Forwards an RPC request over `Noise_IK` to the isolated guest enclave.
    Enclave { request: EnclaveRequest },
    /// Runs the 15-second native Armed Copy Hijack (`mlock` -> X25519 seal -> enclave `CompleteCapture`).
    ArmedCapture {
        manifest_path: String,
        environment: Slug,
        target: CaptureTarget,
    },
    /// Safely reads and validates `secretbridge.json` on the host (`O_NOFOLLOW`, no symlink ancestors).
    ManifestLoad { manifest_path: String },
    /// Atomically writes a validated `secretbridge.json` (`0600`/mode-preserving + `fsync`).
    ManifestSave {
        manifest_path: String,
        manifest: Manifest,
    },
    /// Binds or updates a secret `op://` reference in `secretbridge.json` (preserving cloud flags, B7).
    ManifestBind {
        manifest_path: String,
        environment: Slug,
        name: SecretName,
        r#ref: OpRef,
        #[serde(default)]
        group: Option<Slug>,
        #[serde(default)]
        github: Option<bool>,
        #[serde(default)]
        aws: Option<bool>,
    },
    /// Marks a bound secret as `absent` in `secretbridge.json` for next sync deletion.
    ManifestMarkAbsent {
        manifest_path: String,
        environment: Slug,
        name: SecretName,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<EnclaveResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SanitizedError>,
}

impl HostResponse {
    pub fn from_enclave(resp: EnclaveResponse) -> Self {
        if resp.ok {
            Self {
                ok: true,
                enclave: Some(resp),
                manifest: None,
                error: None,
            }
        } else {
            let err = resp.error.clone();
            Self {
                ok: false,
                enclave: Some(resp),
                manifest: None,
                error: err,
            }
        }
    }

    pub fn from_manifest(manifest: Manifest) -> Self {
        Self {
            ok: true,
            enclave: None,
            manifest: Some(manifest),
            error: None,
        }
    }

    pub fn err(error: SanitizedError) -> Self {
        Self {
            ok: false,
            enclave: None,
            manifest: None,
            error: Some(error),
        }
    }
}

pub struct HostBridge {
    enclave: ManagedEnclaveHandle,
    capture_provider: Arc<dyn ArmedCaptureProvider>,
    expected_auth_token: [u8; 32],
}

impl HostBridge {
    pub fn new(
        enclave: ManagedEnclaveHandle,
        capture_provider: Arc<dyn ArmedCaptureProvider>,
        expected_auth_token: [u8; 32],
    ) -> Self {
        Self {
            enclave,
            capture_provider,
            expected_auth_token,
        }
    }

    pub fn verify_ide_token(&self, token_hex: &str) -> Result<(), HostError> {
        let raw = hex::decode(token_hex.trim()).map_err(|_| {
            HostError::new(ErrorCode::Unauthorized, "malformed host bridge auth token")
        })?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            HostError::new(
                ErrorCode::Unauthorized,
                "invalid host bridge auth token length",
            )
        })?;
        if !constant_time_eq_32(&arr, &self.expected_auth_token) {
            return Err(HostError::new(
                ErrorCode::Unauthorized,
                "invalid host bridge auth token",
            ));
        }
        Ok(())
    }

    pub fn handle_authenticated(&self, env: AuthenticatedHostEnvelope) -> HostResponse {
        if let Err(err) = self.verify_ide_token(&env.auth_token_hex) {
            return HostResponse::err(err.into_sanitized());
        }
        self.execute_command(&env.command)
    }

    pub fn execute_command(&self, cmd: &HostCommand) -> HostResponse {
        match self.dispatch_inner(cmd) {
            Ok(resp) => resp,
            Err(err) => HostResponse::err(err.into_sanitized()),
        }
    }

    fn dispatch_inner(&self, cmd: &HostCommand) -> Result<HostResponse, HostError> {
        match cmd {
            HostCommand::Enclave { request } => {
                let resp = self.enclave.call(request)?;
                Ok(HostResponse::from_enclave(resp))
            }
            HostCommand::ArmedCapture {
                manifest_path,
                environment,
                target,
            } => {
                let manifest = load_manifest(Path::new(manifest_path))?;
                let begin_resp = self.enclave.call(&EnclaveRequest::BeginCapture {
                    manifest,
                    environment: environment.clone(),
                    target: target.clone(),
                })?;
                if !begin_resp.ok {
                    return Ok(HostResponse::from_enclave(begin_resp));
                }
                let Some(EnclaveResult::CaptureStarted(challenge)) = begin_resp.result else {
                    return Err(HostError::new(
                        ErrorCode::TransportFailure,
                        "unexpected enclave response for BeginCapture",
                    ));
                };
                let ttl =
                    Duration::from_millis(challenge.expires_in_ms).min(DEFAULT_ARMED_COPY_TTL);
                let sealed = execute_armed_capture(
                    self.capture_provider.as_ref(),
                    &challenge.pk_capture_b64,
                    ttl,
                )?;
                let complete_resp = self.enclave.call(&EnclaveRequest::CompleteCapture {
                    capture_id: challenge.capture_id,
                    sealed_secret_b64: sealed.sealed_secret_b64,
                    mode: sealed.mode,
                })?;
                Ok(HostResponse::from_enclave(complete_resp))
            }
            HostCommand::ManifestLoad { manifest_path } => {
                let manifest = load_manifest(Path::new(manifest_path))?;
                Ok(HostResponse::from_manifest(manifest))
            }
            HostCommand::ManifestSave {
                manifest_path,
                manifest,
            } => {
                save_manifest_atomic(Path::new(manifest_path), manifest)?;
                Ok(HostResponse::from_manifest(manifest.clone()))
            }
            HostCommand::ManifestBind {
                manifest_path,
                environment,
                name,
                r#ref,
                group,
                github,
                aws,
            } => {
                let path = PathBuf::from(manifest_path);
                let mut manifest = load_manifest(&path)?;
                manifest.bind_secret(
                    environment,
                    name.clone(),
                    r#ref.clone(),
                    group.clone(),
                    *github,
                    *aws,
                )?;
                save_manifest_atomic(&path, &manifest)?;
                Ok(HostResponse::from_manifest(manifest))
            }
            HostCommand::ManifestMarkAbsent {
                manifest_path,
                environment,
                name,
            } => {
                let path = PathBuf::from(manifest_path);
                let mut manifest = load_manifest(&path)?;
                manifest.mark_secret_absent(environment, name)?;
                save_manifest_atomic(&path, &manifest)?;
                Ok(HostResponse::from_manifest(manifest))
            }
        }
    }

    /// Serves newline-delimited JSON `AuthenticatedHostEnvelope` requests over a mode-`0600`
    /// local Unix domain socket for the JetBrains IDE plugin.
    pub fn serve_ide_unix_socket(&self, socket_path: &Path) -> Result<(), HostError> {
        if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
            if meta.file_type().is_symlink() {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "refusing to bind IDE host socket over symlink",
                ));
            }
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = std::os::unix::net::UnixListener::bind(socket_path).map_err(|e| {
            HostError::new(
                ErrorCode::TransportFailure,
                format!("failed binding IDE host socket: {e}"),
            )
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    HostError::new(
                        ErrorCode::TransportFailure,
                        format!("failed setting 0600 permissions on IDE host socket: {e}"),
                    )
                },
            )?;
        }

        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
            let Ok(reader_sock) = stream.try_clone() else {
                continue;
            };
            let mut reader = BufReader::new(reader_sock);
            let mut line = zeroize::Zeroizing::new(String::new());
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let resp = match serde_json::from_str::<AuthenticatedHostEnvelope>(&line) {
                Ok(env) => self.handle_authenticated(env),
                Err(e) => HostResponse::err(SanitizedError::new(
                    ErrorCode::Validation,
                    format!("invalid IDE host request JSON: {e}"),
                )),
            };
            if let Ok(mut out) = serde_json::to_vec(&resp) {
                out.push(b'\n');
                let _ = stream.write_all(&out);
                let _ = stream.flush();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::MlockedHostBuffer;
    use crate::vmm::{EnclaveEndpoint, verify_boot_artifact_sha256};
    use sb_enclave::aws::InMemoryAwsClient;
    use sb_enclave::github::InMemoryGitHubClient;
    use sb_enclave::service::EnclaveService;
    use sb_enclave::vault::InMemoryVaultProvider;
    use sb_enclave::vsock::serve_unix_listener;
    use sb_proto::crypto::generate_noise_keypair;
    use sb_proto::rpc::{CaptureInterceptMode, SessionCredentialsInput};
    use sha2::{Digest, Sha256};
    use std::mem::DropGuard;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    struct MockArmedCapture {
        secret: Vec<u8>,
        mode: CaptureInterceptMode,
    }

    impl ArmedCaptureProvider for MockArmedCapture {
        fn capture_once(
            &self,
            _ttl: Duration,
        ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
            Ok((MlockedHostBuffer::from_bytes(&self.secret)?, self.mode))
        }
    }

    fn make_test_dir() -> PathBuf {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("repo root")
            .join("vm/out")
            .join(format!("test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&base).expect("create test scratch dir under vm/out");
        base
    }

    #[test]
    fn manifest_atomic_save_rejects_symlinks_and_preserves_0600_closing_s11() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let manifest_path = dir.join("secretbridge.json");
        let manifest = Manifest::from_json_str(
            r#"{
              "version": 2,
              "project": "secretbridge",
              "account": "vespoli.1password.com",
              "environments": {
                "dev": { "vault": "vault-dev-01", "secrets": {} }
              }
            }"#,
        )
        .unwrap();

        save_manifest_atomic(&manifest_path, &manifest).unwrap();
        let meta = std::fs::symlink_metadata(&manifest_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let loaded = load_manifest(&manifest_path).unwrap();
        assert_eq!(loaded, manifest);

        // Symlinked manifest must be rejected on both load and save
        let symlink_path = dir.join("evil-link.json");
        std::os::unix::fs::symlink(&manifest_path, &symlink_path).unwrap();
        assert!(load_manifest(&symlink_path).is_err());
        assert!(save_manifest_atomic(&symlink_path, &manifest).is_err());
    }

    #[test]
    fn boot_artifact_sha256_verification_rejects_tampering_and_symlinks() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let img = dir.join("vmlinuz-test");
        std::fs::write(&img, b"fake-kernel-image-bytes").unwrap();
        std::fs::set_permissions(&img, std::fs::Permissions::from_mode(0o600)).unwrap();
        let digest: [u8; 32] = Sha256::digest(b"fake-kernel-image-bytes").into();
        assert!(verify_boot_artifact_sha256(&img, &digest, "vmlinuz").is_ok());

        let wrong_digest = [0xAA; 32];
        assert_eq!(
            verify_boot_artifact_sha256(&img, &wrong_digest, "vmlinuz")
                .unwrap_err()
                .code,
            ErrorCode::CryptoFailure
        );

        let link = dir.join("vmlinuz-symlink");
        std::os::unix::fs::symlink(&img, &link).unwrap();
        assert!(verify_boot_artifact_sha256(&link, &digest, "vmlinuz").is_err());
    }

    #[test]
    fn host_bridge_end_to_end_armed_copy_hijack_and_manifest_bind_over_noise_ik() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let sock_path = dir.join("enclave.sock");
        let manifest_path = dir.join("secretbridge.json");
        let initial_manifest = Manifest::from_json_str(
            r#"{
              "version": 2,
              "project": "secretbridge",
              "account": "vespoli.1password.com",
              "environments": {
                "dev": { "vault": "vault-dev-01", "secrets": {} }
              }
            }"#,
        )
        .unwrap();
        save_manifest_atomic(&manifest_path, &initial_manifest).unwrap();

        let enclave_kp = generate_noise_keypair().unwrap();
        let client_kp = generate_noise_keypair().unwrap();

        let vault = Arc::new(InMemoryVaultProvider::new("ops_tok_abc", true));
        vault.seed_vault("vault-dev-01", "Dev Vault", true, true);
        let aws = Arc::new(InMemoryAwsClient::new(
            "123456789012",
            "arn:aws:iam::123456789012:role/dev",
        ));
        let gh = Arc::new(InMemoryGitHubClient::new("anthonyvespoli"));
        let svc = Arc::new(EnclaveService::new(vault, aws, gh));

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_srv = Arc::clone(&shutdown);
        let sock_srv = sock_path.clone();
        let enc_priv = enclave_kp.private.clone();
        let cli_pub = client_kp.public;
        let srv_thread = std::thread::spawn(move || {
            serve_unix_listener(&sock_srv, svc, enc_priv, cli_pub, shutdown_srv).unwrap();
        });

        while !sock_path.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }

        let handle = ManagedEnclaveHandle::connect_existing(
            EnclaveEndpoint::UnixSocket {
                path: sock_path.clone(),
            },
            client_kp,
            enclave_kp.public,
        );
        let auth_token = [0x5Au8; 32];
        let auth_hex = hex::encode(auth_token);
        let bridge = HostBridge::new(
            handle,
            Arc::new(MockArmedCapture {
                secret: b"copied-secret-from-mlock-never-in-jvm".to_vec(),
                mode: CaptureInterceptMode::ZeroPasteboard,
            }),
            auth_token,
        );

        // Unauthorized IDE token rejected
        let bad_auth = bridge.handle_authenticated(AuthenticatedHostEnvelope {
            auth_token_hex: "00".repeat(32),
            command: HostCommand::ManifestLoad {
                manifest_path: manifest_path.to_string_lossy().into_owned(),
            },
        });
        assert!(!bad_auth.ok);
        assert_eq!(bad_auth.error.unwrap().code, ErrorCode::Unauthorized);

        // Configure enclave session credentials
        let cfg = bridge.handle_authenticated(AuthenticatedHostEnvelope {
            auth_token_hex: auth_hex.clone(),
            command: HostCommand::Enclave {
                request: EnclaveRequest::ConfigureSession {
                    credentials: SessionCredentialsInput {
                        op_service_account_token: Some("ops_tok_abc".into()),
                        github_token: None,
                        aws_access_key_id: None,
                        aws_secret_access_key: None,
                        aws_session_token: None,
                    },
                },
            },
        });
        assert!(cfg.ok);

        // Trigger Armed Copy Hijack through HostBridge -> EnclaveService
        let cap_resp = bridge.handle_authenticated(AuthenticatedHostEnvelope {
            auth_token_hex: auth_hex.clone(),
            command: HostCommand::ArmedCapture {
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                environment: "dev".parse().unwrap(),
                target: CaptureTarget::NewItem {
                    title: "Captured Stripe Key".into(),
                    field_name: "STRIPE_SECRET_KEY".parse().unwrap(),
                    tags: vec!["payments".into()],
                },
            },
        });
        assert!(cap_resp.ok);
        let cap_wire = serde_json::to_string(&cap_resp).unwrap();
        assert!(!cap_wire.contains("copied-secret-from-mlock-never-in-jvm"));
        let Some(EnclaveResult::SecretStored(receipt)) = cap_resp.enclave.unwrap().result else {
            panic!("expected SecretStored receipt");
        };
        assert_eq!(
            receipt.intercept_mode,
            Some(CaptureInterceptMode::ZeroPasteboard)
        );

        // Bind returned op:// ref into secretbridge.json via HostBridge
        let bind_resp = bridge.handle_authenticated(AuthenticatedHostEnvelope {
            auth_token_hex: auth_hex,
            command: HostCommand::ManifestBind {
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                environment: "dev".parse().unwrap(),
                name: "STRIPE_SECRET_KEY".parse().unwrap(),
                r#ref: receipt.r#ref.clone(),
                group: Some("billing".parse().unwrap()),
                github: Some(true),
                aws: Some(false),
            },
        });
        assert!(bind_resp.ok);
        let updated = load_manifest(&manifest_path).unwrap();
        let spec = &updated.environments[&"dev".parse::<Slug>().unwrap()].secrets
            [&"STRIPE_SECRET_KEY".parse::<SecretName>().unwrap()];
        assert_eq!(spec.r#ref.as_ref(), Some(&receipt.r#ref));
        assert!(!spec.aws);

        shutdown.store(true, Ordering::Release);
        srv_thread.join().unwrap();
    }
}
