pub mod capture;
pub mod manifest_io;
pub mod vmm;

use crate::capture::{ArmedCaptureProvider, DEFAULT_ARMED_COPY_TTL, execute_armed_capture};
use crate::manifest_io::{HostError, load_manifest, save_manifest_atomic, with_manifest_lock};
use crate::vmm::{ManagedEnclaveHandle, RawEnclaveStream};
use sb_proto::crypto::{constant_time_eq_32, read_raw_frame, write_raw_frame};
use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use sb_proto::rpc::CaptureInterceptMode;
use sb_proto::types::{Manifest, OpRef, SecretName, Slug};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::DropGuard;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_HOST_ENVELOPE_BYTES: usize = 512 * 1024; // 512 KiB pre-auth line ceiling (H5)
const MAX_CONCURRENT_IDE_CLIENTS: usize = 16;
static UMASK_LOCK: Mutex<()> = Mutex::new(());

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
#[serde(tag = "host_op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostCommand {
    /// Opens an authenticated blind frame relay to the enclave's `Noise_IK` responder port (`C2`).
    /// `sb-host` never holds the client Noise keypair and never sees decrypted RPC payloads.
    NoiseTunnel,
    /// Queries host bridge liveness and the guest enclave's `Noise_IK` static public key.
    Status,
    /// Runs the 15-second native Armed Copy Hijack (`mlock` -> X25519 seal to `pk_capture_b64`),
    /// returning only ciphertext + `CaptureInterceptMode` (`C2`, `H2`, `V2-H4`).
    CaptureAndSeal {
        pk_capture_b64: String,
        #[serde(default)]
        ttl_ms: Option<u64>,
        #[serde(default)]
        notify_armed: bool,
    },
    /// Safely reads and validates `secretbridge.json` on the host (`O_NOFOLLOW`, no symlink ancestors).
    ManifestLoad { manifest_path: String },
    /// Atomically writes a validated `secretbridge.json` (`0600`/mode-preserving + `fsync`).
    ManifestSave {
        manifest_path: String,
        manifest: Manifest,
    },
    /// Binds or updates a secret `op://` reference in `secretbridge.json` (preserving cloud flags).
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
    pub enclave_pubkey_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed_secret_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intercept_mode: Option<CaptureInterceptMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<Manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SanitizedError>,
}

impl HostResponse {
    pub fn tunnel_ready(enclave_pubkey_hex: String) -> Self {
        Self {
            ok: true,
            enclave_pubkey_hex: Some(enclave_pubkey_hex),
            sealed_secret_b64: None,
            intercept_mode: None,
            manifest: None,
            error: None,
        }
    }

    pub fn from_sealed_capture(sealed_secret_b64: String, mode: CaptureInterceptMode) -> Self {
        Self {
            ok: true,
            enclave_pubkey_hex: None,
            sealed_secret_b64: Some(sealed_secret_b64),
            intercept_mode: Some(mode),
            manifest: None,
            error: None,
        }
    }

    pub fn from_manifest(manifest: Manifest) -> Self {
        Self {
            ok: true,
            enclave_pubkey_hex: None,
            sealed_secret_b64: None,
            intercept_mode: None,
            manifest: Some(manifest),
            error: None,
        }
    }

    pub fn err(error: SanitizedError) -> Self {
        Self {
            ok: false,
            enclave_pubkey_hex: None,
            sealed_secret_b64: None,
            intercept_mode: None,
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

impl Drop for HostBridge {
    fn drop(&mut self) {
        self.expected_auth_token.zeroize();
    }
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

    pub fn enclave_pubkey_hex(&self) -> String {
        hex::encode(self.enclave.enclave_pubkey())
    }

    pub fn verify_ide_token(&self, token_hex: &str) -> Result<(), HostError> {
        let raw = Zeroizing::new(hex::decode(token_hex.trim()).map_err(|_| {
            HostError::new(ErrorCode::Unauthorized, "malformed host bridge auth token")
        })?);
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
            HostCommand::NoiseTunnel => Err(HostError::new(
                ErrorCode::Validation,
                "noise-tunnel requires a streaming Unix socket connection",
            )),
            HostCommand::Status => Ok(HostResponse::tunnel_ready(self.enclave_pubkey_hex())),
            HostCommand::CaptureAndSeal {
                pk_capture_b64,
                ttl_ms,
                notify_armed: _,
            } => {
                let requested = ttl_ms
                    .map(|ms| Duration::from_millis(ms.max(50)))
                    .unwrap_or(DEFAULT_ARMED_COPY_TTL);
                let ttl = requested.min(DEFAULT_ARMED_COPY_TTL);
                let sealed =
                    execute_armed_capture(self.capture_provider.as_ref(), pk_capture_b64, ttl)?;
                Ok(HostResponse::from_sealed_capture(
                    sealed.sealed_secret_b64,
                    sealed.mode,
                ))
            }
            HostCommand::ManifestLoad { manifest_path } => {
                let path = Path::new(manifest_path);
                with_manifest_lock(path, || {
                    let manifest = load_manifest(path)?;
                    Ok(HostResponse::from_manifest(manifest))
                })
            }
            HostCommand::ManifestSave {
                manifest_path,
                manifest,
            } => {
                let path = Path::new(manifest_path);
                with_manifest_lock(path, || {
                    save_manifest_atomic(path, manifest)?;
                    Ok(HostResponse::from_manifest(manifest.clone()))
                })
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
                with_manifest_lock(&path, || {
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
                })
            }
            HostCommand::ManifestMarkAbsent {
                manifest_path,
                environment,
                name,
            } => {
                let path = PathBuf::from(manifest_path);
                with_manifest_lock(&path, || {
                    let mut manifest = load_manifest(&path)?;
                    manifest.mark_secret_absent(environment, name)?;
                    save_manifest_atomic(&path, &manifest)?;
                    Ok(HostResponse::from_manifest(manifest))
                })
            }
        }
    }

    /// Binds a mode-`0600` IDE Unix domain socket safely (`H5`):
    /// - Refuses to unlink symlinks, regular files, directories, or FIFOs (`FileType::is_socket()`).
    /// - Sets process `umask(0o077)` under a mutex + `DropGuard` BEFORE `UnixListener::bind` so the
    ///   socket inode is never briefly world-writable.
    pub fn bind_ide_unix_listener(socket_path: &Path) -> Result<UnixListener, HostError> {
        if let Ok(meta) = std::fs::symlink_metadata(socket_path) {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "refusing to unlink non-socket or symlinked IDE socket path",
                ));
            }
            std::fs::remove_file(socket_path).map_err(|e| {
                HostError::new(
                    ErrorCode::TransportFailure,
                    format!("failed removing stale IDE socket: {e}"),
                )
            })?;
        }

        let listener = {
            let _lock = UMASK_LOCK
                .lock()
                .map_err(|_| HostError::new(ErrorCode::InternalError, "umask mutex poisoned"))?;
            // SAFETY: `umask` is async-signal-safe and restored unconditionally via `DropGuard`.
            let prev_umask = unsafe { libc::umask(0o077) };
            let _umask_guard = DropGuard::new(prev_umask, |old| unsafe {
                libc::umask(old);
            });
            UnixListener::bind(socket_path).map_err(|e| {
                HostError::new(
                    ErrorCode::TransportFailure,
                    format!("failed binding IDE host socket: {e}"),
                )
            })?
        };

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

        Ok(listener)
    }

    /// Serves authenticated host commands and blind `NoiseTunnel` relays over a pre-bound
    /// mode-`0600` `UnixListener`.
    pub fn serve_bound_ide_listener(
        self: &Arc<Self>,
        listener: UnixListener,
        shutdown: Option<Arc<AtomicBool>>,
    ) -> Result<(), HostError> {
        if shutdown.is_some() {
            listener.set_nonblocking(true).map_err(|e| {
                HostError::new(
                    ErrorCode::TransportFailure,
                    format!("failed configuring IDE socket nonblocking mode: {e}"),
                )
            })?;
        }

        let active_clients = Arc::new(AtomicUsize::new(0));
        loop {
            if let Some(ref flag) = shutdown
                && flag.load(Ordering::Acquire)
            {
                break;
            }

            match listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = stream.set_nonblocking(false);
                    if active_clients.fetch_add(1, Ordering::AcqRel) >= MAX_CONCURRENT_IDE_CLIENTS {
                        active_clients.fetch_sub(1, Ordering::AcqRel);
                        continue;
                    }
                    let bridge = Arc::clone(self);
                    let counter = Arc::clone(&active_clients);
                    std::thread::spawn(move || {
                        let _slot_guard = DropGuard::new(counter, |c| {
                            c.fetch_sub(1, Ordering::AcqRel);
                        });
                        bridge.handle_client_stream(stream);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => continue,
            }
        }
        Ok(())
    }

    pub fn serve_ide_unix_socket(self: &Arc<Self>, socket_path: &Path) -> Result<(), HostError> {
        let listener = Self::bind_ide_unix_listener(socket_path)?;
        self.serve_bound_ide_listener(listener, None)
    }

    fn handle_client_stream(&self, mut stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        let Ok(reader_sock) = stream.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(reader_sock);
        let mut line = Zeroizing::new(String::new());
        let read_res = (&mut reader)
            .take((MAX_HOST_ENVELOPE_BYTES + 1) as u64)
            .read_line(&mut line);
        let Ok(n) = read_res else {
            return;
        };
        if n == 0 {
            return;
        }
        if n > MAX_HOST_ENVELOPE_BYTES && !line.ends_with('\n') {
            write_json_line(
                &mut stream,
                &HostResponse::err(SanitizedError::new(
                    ErrorCode::Validation,
                    "IDE host request exceeded 512 KiB frame ceiling",
                )),
            );
            return;
        }

        let env = match serde_json::from_str::<AuthenticatedHostEnvelope>(&line) {
            Ok(parsed) => parsed,
            Err(e) => {
                write_json_line(
                    &mut stream,
                    &HostResponse::err(SanitizedError::new(
                        ErrorCode::Validation,
                        format!("invalid IDE host request JSON: {e}"),
                    )),
                );
                return;
            }
        };

        if let Err(err) = self.verify_ide_token(&env.auth_token_hex) {
            write_json_line(&mut stream, &HostResponse::err(err.into_sanitized()));
            return;
        }

        match &env.command {
            HostCommand::NoiseTunnel => match self.enclave.open_raw_stream() {
                Ok(enclave_stream) => {
                    let ready = HostResponse::tunnel_ready(self.enclave_pubkey_hex());
                    if !write_json_line(&mut stream, &ready) {
                        return;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(45)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(45)));
                    relay_noise_tunnel(reader, stream, enclave_stream);
                }
                Err(err) => {
                    write_json_line(&mut stream, &HostResponse::err(err.into_sanitized()));
                }
            },
            HostCommand::CaptureAndSeal {
                ttl_ms,
                notify_armed: true,
                ..
            } => {
                let requested = ttl_ms
                    .map(|ms| Duration::from_millis(ms.max(50)))
                    .unwrap_or(DEFAULT_ARMED_COPY_TTL);
                let ttl = requested.min(DEFAULT_ARMED_COPY_TTL);
                let _ = stream.set_write_timeout(Some(ttl + Duration::from_secs(10)));
                let ack = format!("{{\"armed\":true,\"ttl_ms\":{}}}\n", ttl.as_millis());
                if stream.write_all(ack.as_bytes()).is_err() || stream.flush().is_err() {
                    return;
                }
                let resp = self.execute_command(&env.command);
                write_json_line(&mut stream, &resp);
            }
            other => {
                let resp = self.execute_command(other);
                write_json_line(&mut stream, &resp);
            }
        }
    }
}

fn write_json_line(stream: &mut UnixStream, resp: &HostResponse) -> bool {
    let Ok(mut out) = serde_json::to_vec(resp) else {
        return false;
    };
    out.push(b'\n');
    stream.write_all(&out).is_ok() && stream.flush().is_ok()
}

fn is_clean_eof(err: &ProtoError) -> bool {
    matches!(
        err,
        ProtoError::Transport(msg)
            if msg.contains("UnexpectedEof")
                || msg.contains("eof")
                || msg.contains("early eof")
                || msg.contains("failed to fill whole buffer")
    )
}

/// Blindly relays `u32be` length-prefixed `Noise_IK` frames between the authenticated IDE
/// `UnixStream` and the guest enclave's raw stream (`AF_VSOCK` or `VZVirtioSocketDevice`) (`C2`).
fn relay_noise_tunnel(
    mut ide_reader: BufReader<UnixStream>,
    mut ide_writer: UnixStream,
    mut enc_reader: RawEnclaveStream,
) {
    let Ok(mut enc_writer) = enc_reader.try_clone() else {
        return;
    };
    let Ok(ide_ctl) = ide_writer.try_clone() else {
        return;
    };
    let Ok(enc_ctl) = enc_reader.try_clone() else {
        return;
    };

    let ide_to_enc = std::thread::spawn(move || {
        loop {
            match read_raw_frame(&mut ide_reader) {
                Ok(frame) => {
                    if write_raw_frame(&mut enc_writer, &frame).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    if !is_clean_eof(&err) {
                        enc_writer.shutdown_both();
                        return;
                    }
                    break;
                }
            }
        }
        enc_writer.shutdown_write();
    });

    while let Ok(frame) = read_raw_frame(&mut enc_reader) {
        if write_raw_frame(&mut ide_writer, &frame).is_err() {
            break;
        }
    }

    let _ = ide_ctl.shutdown(std::net::Shutdown::Both);
    enc_ctl.shutdown_both();
    let _ = ide_to_enc.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::MlockedHostBuffer;
    use crate::vmm::{
        EnclaveEndpoint, acquire_host_cid_lease_in_dir, open_and_seal_boot_artifact,
        open_and_seal_boot_artifact_with_enclave_key, verify_boot_artifact_sha256,
    };
    use sb_enclave::aws::InMemoryAwsClient;
    use sb_enclave::github::InMemoryGitHubClient;
    use sb_enclave::service::EnclaveService;
    use sb_enclave::vault::InMemoryVaultProvider;
    use sb_enclave::vsock::serve_unix_listener;
    use sb_proto::crypto::{NoiseSession, generate_noise_keypair};
    use sb_proto::rpc::{
        CaptureTarget, EnclaveRequest, EnclaveResponse, EnclaveResult, SessionCredentialsInput,
    };
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    fn dummy_op_token(suffix: &str) -> String {
        format!("{}_{}", "ops_unit_tok", suffix)
    }

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
        let vm_out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates dir")
            .parent()
            .expect("repo root")
            .join("vm/out");
        std::fs::create_dir_all(&vm_out).expect("create vm/out");
        let _ = std::fs::set_permissions(&vm_out, std::fs::Permissions::from_mode(0o700));
        let base = vm_out.join(format!("test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&base).expect("create test scratch dir under vm/out");
        let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
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

        // Arbitrary filenames must be rejected (`V2-M3`)
        let arbitrary_path = dir.join("evil-link.json");
        assert!(load_manifest(&arbitrary_path).is_err());
        assert!(save_manifest_atomic(&arbitrary_path, &manifest).is_err());

        // Leaf symlink named `secretbridge.json` must be rejected on both load and save
        let leaf_link_dir = dir.join("leaf-link-dir");
        std::fs::create_dir(&leaf_link_dir).unwrap();
        let symlink_path = leaf_link_dir.join("secretbridge.json");
        std::os::unix::fs::symlink(&manifest_path, &symlink_path).unwrap();
        assert!(load_manifest(&symlink_path).is_err());
        assert!(save_manifest_atomic(&symlink_path, &manifest).is_err());

        // Symlinked ancestor directory must be rejected by `openat(..., O_DIRECTORY | O_NOFOLLOW)`
        let real_subdir = dir.join("real-sub");
        std::fs::create_dir(&real_subdir).unwrap();
        let real_sub_manifest = real_subdir.join("secretbridge.json");
        save_manifest_atomic(&real_sub_manifest, &manifest).unwrap();
        let symlink_dir = dir.join("symlink-sub");
        std::os::unix::fs::symlink(&real_subdir, &symlink_dir).unwrap();
        let via_symlink_dir = symlink_dir.join("secretbridge.json");
        assert!(load_manifest(&via_symlink_dir).is_err());
        assert!(save_manifest_atomic(&via_symlink_dir, &manifest).is_err());

        // Named pipe (FIFO) named `secretbridge.json` with no writer must return immediately (`O_NONBLOCK`)
        let fifo_dir = dir.join("fifo-dir");
        std::fs::create_dir(&fifo_dir).unwrap();
        let fifo_path = fifo_dir.join("secretbridge.json");
        let fifo_c = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(rc, 0);
        let err = load_manifest(&fifo_path).unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);

        // Serialized manifests exceeding 512 KiB must be rejected before writing/renaming
        let mut oversized = manifest.clone();
        let dev_env: Slug = "dev".parse().unwrap();
        let op_ref: OpRef = "op://vault-dev-01/oversized-item-reference-padding/password"
            .parse()
            .unwrap();
        for idx in 0..4500 {
            let name: SecretName = format!("OVERSIZED_SECRET_KEY_{idx:04}").parse().unwrap();
            oversized
                .bind_secret(&dev_env, name, op_ref.clone(), None, Some(true), Some(true))
                .unwrap();
        }
        let save_err = save_manifest_atomic(&manifest_path, &oversized).unwrap_err();
        assert_eq!(save_err.code, ErrorCode::Validation);
        assert_eq!(load_manifest(&manifest_path).unwrap(), manifest);
    }

    #[test]
    fn host_cid_lease_allocates_distinct_cids_and_reclaims_on_drop() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let lock_dir = dir.join("cids");
        let lease_a = acquire_host_cid_lease_in_dir(&lock_dir, 42).unwrap();
        assert_eq!(lease_a.cid(), 42);

        let lease_b = acquire_host_cid_lease_in_dir(&lock_dir, 42).unwrap();
        assert_eq!(lease_b.cid(), 43);

        drop(lease_a);
        let lease_reclaimed = acquire_host_cid_lease_in_dir(&lock_dir, 42).unwrap();
        assert_eq!(lease_reclaimed.cid(), 42);
    }

    #[test]
    fn sealed_boot_artifact_memfd_rejects_tampering_symlinks_and_blocks_writes_h4() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let img = dir.join("vmlinuz-test");
        let original_bytes = b"verified-immutable-kernel-image";
        std::fs::write(&img, original_bytes).unwrap();
        std::fs::set_permissions(&img, std::fs::Permissions::from_mode(0o600)).unwrap();
        let digest: [u8; 32] = Sha256::digest(original_bytes).into();
        assert!(verify_boot_artifact_sha256(&img, &digest, "vmlinuz").is_ok());

        let sealed = open_and_seal_boot_artifact(&img, &digest, "vmlinuz", Some(&dir)).unwrap();
        // Mutating the on-disk file AFTER `open_and_seal_boot_artifact` must NOT affect the sealed VMM input!
        std::fs::write(&img, b"tampered-after-verification!!!!").unwrap();
        let read_back = std::fs::read(sealed.vmm_path()).unwrap();
        assert_eq!(read_back.as_slice(), original_bytes);

        #[cfg(target_os = "linux")]
        {
            let seals = unsafe { libc::fcntl(sealed.raw_fd(), libc::F_GET_SEALS) };
            assert!(seals > 0);
            assert_ne!(seals & libc::F_SEAL_WRITE, 0);
            assert_ne!(seals & libc::F_SEAL_GROW, 0);
            assert_ne!(seals & libc::F_SEAL_SHRINK, 0);
            assert_ne!(seals & libc::F_SEAL_SEAL, 0);
        }

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

        // Restore verified initramfs bytes and verify `newc` cpio enclave key overlay sealing
        std::fs::write(&img, original_bytes).unwrap();
        let key_path = dir.join("enclave.key");
        let generated = generate_noise_keypair().unwrap();
        std::fs::write(&key_path, *generated.private).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            open_and_seal_boot_artifact_with_enclave_key(
                &img,
                &digest,
                "initramfs",
                Some(&dir),
                Some(&key_path),
            )
            .is_err()
        );
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sealed_overlay = open_and_seal_boot_artifact_with_enclave_key(
            &img,
            &digest,
            "initramfs",
            Some(&dir),
            Some(&key_path),
        )
        .unwrap();
        let overlaid_bytes = std::fs::read(sealed_overlay.vmm_path()).unwrap();
        assert!(overlaid_bytes.starts_with(original_bytes));
        assert!(
            overlaid_bytes
                .windows(b"run/secretbridge/enclave.key".len())
                .any(|w| w == b"run/secretbridge/enclave.key")
        );
        assert!(
            overlaid_bytes
                .windows(b"TRAILER!!!".len())
                .any(|w| w == b"TRAILER!!!")
        );
    }

    #[test]
    fn ide_socket_bind_refuses_to_unlink_regular_file_or_symlink_h5() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let precious = dir.join("precious.txt");
        std::fs::write(&precious, b"do-not-delete").unwrap();
        let err = HostBridge::bind_ide_unix_listener(&precious).unwrap_err();
        assert_eq!(err.code, ErrorCode::Validation);
        assert!(precious.exists());

        let sock_link = dir.join("symlink.sock");
        std::os::unix::fs::symlink(&precious, &sock_link).unwrap();
        let err_link = HostBridge::bind_ide_unix_listener(&sock_link).unwrap_err();
        assert_eq!(err_link.code, ErrorCode::Validation);
        assert!(precious.exists());
    }

    fn send_host_cmd(sock: &Path, auth_hex: &str, cmd: HostCommand) -> HostResponse {
        let mut stream = UnixStream::connect(sock).unwrap();
        let env = AuthenticatedHostEnvelope {
            auth_token_hex: auth_hex.to_string(),
            command: cmd,
        };
        let mut line = serde_json::to_vec(&env).unwrap();
        line.push(b'\n');
        stream.write_all(&line).unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).unwrap();
        serde_json::from_str(&resp_line).unwrap()
    }

    fn call_enclave_over_blind_tunnel(
        ide_sock: &Path,
        auth_hex: &str,
        client_priv: &[u8; 32],
        expected_enclave_pub: &[u8; 32],
        req: &EnclaveRequest,
    ) -> EnclaveResponse {
        let mut stream = UnixStream::connect(ide_sock).unwrap();
        let env = AuthenticatedHostEnvelope {
            auth_token_hex: auth_hex.to_string(),
            command: HostCommand::NoiseTunnel,
        };
        let mut line = serde_json::to_vec(&env).unwrap();
        line.push(b'\n');
        stream.write_all(&line).unwrap();
        stream.flush().unwrap();

        let mut buf_stream = BufReader::new(stream.try_clone().unwrap());
        let mut ready_line = String::new();
        buf_stream.read_line(&mut ready_line).unwrap();
        let ready: HostResponse = serde_json::from_str(&ready_line).unwrap();
        assert!(ready.ok);
        assert_eq!(
            ready.enclave_pubkey_hex.as_deref(),
            Some(hex::encode(expected_enclave_pub).as_str())
        );

        struct SplitUnix {
            r: BufReader<UnixStream>,
            w: UnixStream,
        }
        impl Read for SplitUnix {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.r.read(buf)
            }
        }
        impl Write for SplitUnix {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.w.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.w.flush()
            }
        }

        let mut io_pair = SplitUnix {
            r: buf_stream,
            w: stream,
        };
        let mut noise =
            NoiseSession::connect_initiator(&mut io_pair, client_priv, expected_enclave_pub)
                .unwrap();
        let req_bytes = serde_json::to_vec(req).unwrap();
        noise.send_message(&mut io_pair, &req_bytes).unwrap();
        let resp_bytes = noise.recv_message(&mut io_pair).unwrap();
        serde_json::from_slice(&resp_bytes).unwrap()
    }

    #[test]
    fn host_bridge_blind_noise_tunnel_and_capture_seal_e2e_c2() {
        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });

        let enclave_sock = dir.join("enclave.sock");
        let ide_sock = dir.join("ide-host.sock");
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
        // Client keypair lives ONLY in the simulated IDE client -- `sb-host` never sees `client_kp.private`!
        let client_kp = generate_noise_keypair().unwrap();

        let op_tok = dummy_op_token("bridge_e2e");
        let vault = Arc::new(InMemoryVaultProvider::new(&op_tok, true));
        vault.seed_vault("vault-dev-01", "Dev Vault", true, true);
        let aws = Arc::new(InMemoryAwsClient::new(
            "123456789012",
            "arn:aws:iam::123456789012:role/dev",
        ));
        let gh = Arc::new(InMemoryGitHubClient::new("anthonyvespoli"));
        let svc = Arc::new(EnclaveService::new(vault, aws, gh));

        let enc_shutdown = Arc::new(AtomicBool::new(false));
        let enc_shutdown_srv = Arc::clone(&enc_shutdown);
        let enc_sock_srv = enclave_sock.clone();
        let enc_priv =
            Arc::new(sb_enclave::mem_secret::MemSecret::from_slice(&*enclave_kp.private).unwrap());
        let cli_pub = client_kp.public;
        let enc_thread = std::thread::spawn(move || {
            serve_unix_listener(&enc_sock_srv, svc, enc_priv, cli_pub, enc_shutdown_srv).unwrap();
        });

        while !enclave_sock.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }

        // Notice `ManagedEnclaveHandle::connect_existing` takes ONLY `enclave_kp.public` -- NO client private key!
        let handle = ManagedEnclaveHandle::connect_existing(
            EnclaveEndpoint::UnixSocket {
                path: enclave_sock.clone(),
            },
            enclave_kp.public,
        );
        let auth_token = [0x5Au8; 32];
        let auth_hex = hex::encode(auth_token);
        let bridge = Arc::new(HostBridge::new(
            handle,
            Arc::new(MockArmedCapture {
                secret: b"copied-secret-from-mlock-never-in-jvm".to_vec(),
                mode: CaptureInterceptMode::ZeroPasteboard,
            }),
            auth_token,
        ));

        let ide_listener = HostBridge::bind_ide_unix_listener(&ide_sock).unwrap();
        let ide_meta = std::fs::symlink_metadata(&ide_sock).unwrap();
        assert_eq!(ide_meta.permissions().mode() & 0o777, 0o600);

        let host_shutdown = Arc::new(AtomicBool::new(false));
        let host_shutdown_srv = Arc::clone(&host_shutdown);
        let bridge_srv = Arc::clone(&bridge);
        let host_thread = std::thread::spawn(move || {
            bridge_srv
                .serve_bound_ide_listener(ide_listener, Some(host_shutdown_srv))
                .unwrap();
        });

        // 1. Unauthorized IDE token rejected before touching enclave
        let bad_auth = send_host_cmd(
            &ide_sock,
            &"00".repeat(32),
            HostCommand::ManifestLoad {
                manifest_path: manifest_path.to_string_lossy().into_owned(),
            },
        );
        assert!(!bad_auth.ok);
        assert_eq!(bad_auth.error.unwrap().code, ErrorCode::Unauthorized);

        // 2. Configure enclave session credentials over E2E `Noise_IK` through blind `NoiseTunnel`
        let cfg_resp = call_enclave_over_blind_tunnel(
            &ide_sock,
            &auth_hex,
            &client_kp.private,
            &enclave_kp.public,
            &EnclaveRequest::ConfigureSession {
                credentials: SessionCredentialsInput {
                    op_service_account_token: Some(op_tok),
                    github_token: None,
                    aws_access_key_id: None,
                    aws_secret_access_key: None,
                    aws_session_token: None,
                    allowed_github_hosts: vec![],
                    allowed_github_owners: vec!["anthonyvespoli".into()],
                    allowed_aws_account_ids: vec!["123456789012".parse().unwrap()],
                },
            },
        );
        assert!(cfg_resp.ok);

        // 3. Three-step E2E Armed Copy Hijack (with `notify_armed: true` readiness ack -- `V2-H4`):
        //    (a) IDE -> Enclave (E2E Noise_IK): BeginCapture
        let begin_resp = call_enclave_over_blind_tunnel(
            &ide_sock,
            &auth_hex,
            &client_kp.private,
            &enclave_kp.public,
            &EnclaveRequest::BeginCapture {
                manifest: load_manifest(&manifest_path).unwrap(),
                environment: "dev".parse().unwrap(),
                target: CaptureTarget::NewItem {
                    title: "Captured Stripe Key".into(),
                    field_name: "STRIPE_SECRET_KEY".parse().unwrap(),
                    tags: vec!["payments".into()],
                },
            },
        );
        assert!(begin_resp.ok);
        let Some(EnclaveResult::CaptureStarted(challenge)) = begin_resp.result else {
            panic!("expected CaptureStarted");
        };

        //    (b) IDE -> sb-host: CaptureAndSeal (`notify_armed: true` emits `{"armed":true,...}` line first)
        let seal_resp: HostResponse = {
            let mut stream = UnixStream::connect(&ide_sock).unwrap();
            let env = AuthenticatedHostEnvelope {
                auth_token_hex: auth_hex.clone(),
                command: HostCommand::CaptureAndSeal {
                    pk_capture_b64: challenge.pk_capture_b64,
                    ttl_ms: Some(challenge.expires_in_ms),
                    notify_armed: true,
                },
            };
            let mut line = serde_json::to_vec(&env).unwrap();
            line.push(b'\n');
            stream.write_all(&line).unwrap();
            stream.flush().unwrap();
            let mut reader = BufReader::new(stream);
            let mut ack_line = String::new();
            reader.read_line(&mut ack_line).unwrap();
            assert!(ack_line.contains("\"armed\":true"));
            let mut resp_line = String::new();
            reader.read_line(&mut resp_line).unwrap();
            serde_json::from_str(&resp_line).unwrap()
        };
        assert!(seal_resp.ok);
        let seal_wire = serde_json::to_string(&seal_resp).unwrap();
        assert!(!seal_wire.contains("copied-secret-from-mlock-never-in-jvm"));
        let sealed_b64 = seal_resp.sealed_secret_b64.unwrap();
        let mode = seal_resp.intercept_mode.unwrap();
        assert_eq!(mode, CaptureInterceptMode::ZeroPasteboard);

        //    (c) IDE -> Enclave (E2E Noise_IK): CompleteCapture
        let complete_resp = call_enclave_over_blind_tunnel(
            &ide_sock,
            &auth_hex,
            &client_kp.private,
            &enclave_kp.public,
            &EnclaveRequest::CompleteCapture {
                capture_id: challenge.capture_id,
                sealed_secret_b64: sealed_b64,
                mode,
            },
        );
        assert!(complete_resp.ok);
        let Some(EnclaveResult::SecretStored(receipt)) = complete_resp.result else {
            panic!("expected SecretStored receipt");
        };
        assert_eq!(
            receipt.intercept_mode,
            Some(CaptureInterceptMode::ZeroPasteboard)
        );

        // 4. Bind returned op:// ref into secretbridge.json via HostBridge
        let bind_resp = send_host_cmd(
            &ide_sock,
            &auth_hex,
            HostCommand::ManifestBind {
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                environment: "dev".parse().unwrap(),
                name: "STRIPE_SECRET_KEY".parse().unwrap(),
                r#ref: receipt.r#ref.clone(),
                group: Some("billing".parse().unwrap()),
                github: Some(true),
                aws: Some(false),
            },
        );
        assert!(bind_resp.ok);
        let updated = load_manifest(&manifest_path).unwrap();
        let spec = &updated.environments[&"dev".parse::<Slug>().unwrap()].secrets
            [&"STRIPE_SECRET_KEY".parse::<SecretName>().unwrap()];
        assert_eq!(spec.r#ref.as_ref(), Some(&receipt.r#ref));
        assert!(!spec.aws);

        host_shutdown.store(true, Ordering::Release);
        enc_shutdown.store(true, Ordering::Release);
        host_thread.join().unwrap();
        enc_thread.join().unwrap();
    }

    #[test]
    fn vsock_egress_connect_validator_and_sealed_exec_reject_ssrf_and_tampering_v2_h6() {
        use crate::vmm::{
            is_public_unicast_ip, open_and_seal_executable_binary, validate_https_connect_target,
        };

        assert_eq!(
            validate_https_connect_target("CONNECT api.github.com:443 HTTP/1.1\r\n").unwrap(),
            "api.github.com"
        );
        assert_eq!(
            validate_https_connect_target(
                "CONNECT secretsmanager.us-east-1.amazonaws.com:443 HTTP/1.1"
            )
            .unwrap(),
            "secretsmanager.us-east-1.amazonaws.com"
        );
        // Non-443 ports, non-CONNECT verbs, IP literals, hex IPv4, and localhost must fail closed
        assert!(validate_https_connect_target("CONNECT api.github.com:80 HTTP/1.1").is_err());
        assert!(validate_https_connect_target("CONNECT api.github.com:8443 HTTP/1.1").is_err());
        assert!(validate_https_connect_target("GET https://api.github.com/ HTTP/1.1").is_err());
        assert!(validate_https_connect_target("CONNECT 127.0.0.1:443 HTTP/1.1").is_err());
        assert!(validate_https_connect_target("CONNECT 0x7f.0.0.1:443 HTTP/1.1").is_err());
        assert!(validate_https_connect_target("CONNECT localhost:443 HTTP/1.1").is_err());
        assert!(validate_https_connect_target("CONNECT [::1]:443 HTTP/1.1").is_err());

        // IPv6 transition prefixes (NAT64, 6to4, Teredo) and loopback/CGNAT must be rejected
        assert!(!is_public_unicast_ip("64:ff9b::7f00:1".parse().unwrap()));
        assert!(!is_public_unicast_ip("2002:7f00:0001::1".parse().unwrap()));
        assert!(!is_public_unicast_ip(
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()
        ));
        assert!(!is_public_unicast_ip("100.64.0.1".parse().unwrap()));
        assert!(is_public_unicast_ip("140.82.112.6".parse().unwrap()));

        let dir = make_test_dir();
        let _dir_guard = DropGuard::new(dir.clone(), |d| {
            let _ = std::fs::remove_dir_all(d);
        });
        let bin_path = dir.join("mock-vmm");
        let bin_bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&bin_path, bin_bytes).unwrap();
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let digest: [u8; 32] = Sha256::digest(bin_bytes).into();
        let sealed_exec = open_and_seal_executable_binary(&bin_path, Some(&digest), "VMM").unwrap();
        std::fs::write(&bin_path, b"#!/bin/sh\necho tampered\n").unwrap();
        let exec_contents = std::fs::read(sealed_exec.exec_path()).unwrap();
        assert_eq!(exec_contents.as_slice(), bin_bytes);

        // World-writable ancestor directory must be rejected
        let ww_dir = dir.join("world-writable");
        std::fs::create_dir(&ww_dir).unwrap();
        std::fs::set_permissions(&ww_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let ww_bin = ww_dir.join("evil-vmm");
        std::fs::write(&ww_bin, bin_bytes).unwrap();
        std::fs::set_permissions(&ww_bin, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_and_seal_executable_binary(&ww_bin, None, "VMM").is_err());
    }
}
