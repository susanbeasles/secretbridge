use crate::aws::{AwsClient, AwsCredentials, TAG_ENVIRONMENT, TAG_PROJECT};
use crate::error::EnclaveError;
use crate::github::GitHubClient;
use crate::mem_secret::MemSecret;
use crate::templates::render_template;
use crate::vault::{VaultProvider, ensure_service_account_vault_allowed};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use sb_proto::crypto::{generate_sealed_box_keypair, unseal_base64};
use sb_proto::error::ErrorCode;
use sb_proto::plan::{
    AwsObservedMetadata, DEFAULT_PLAN_TTL_SECS, PlanAction, PlanSigner, PlannedOp, SignedPlan,
    TargetKind, UnsignedPlan, sha256_hex,
};
use sb_proto::rpc::{
    ApplyReport, BindingEntry, CaptureChallenge, CaptureInterceptMode, CaptureTarget, DoctorEntry,
    EnclaveRequest, EnclaveResponse, EnclaveResult, OpStepResult, SessionCredentialsInput,
};
use sb_proto::types::{
    AwsAccountId, AwsTarget, GitHubHost, GitHubScope, GitHubTarget, Manifest, OpRef, SecretName,
    SecretState, Slug,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const CAPTURE_TTL: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CAPTURES: usize = 8;
const MAX_GITHUB_SECRET_BYTES: usize = 48 * 1024; // 48 KiB GitHub Actions limit
const MAX_AWS_SECRET_BYTES: usize = 65_536; // 64 KiB AWS Secrets Manager limit

#[derive(Clone)]
struct SessionState {
    op_token: Option<Arc<MemSecret>>,
    github_token: Option<Arc<MemSecret>>,
    aws_creds: Option<Arc<AwsCredentials>>,
    allowed_github_host: GitHubHost,
    allowed_github_owners: BTreeSet<String>,
    allowed_aws_accounts: BTreeSet<String>,
    credentials_fingerprint: String,
}

impl Default for SessionState {
    fn default() -> Self {
        let mut s = Self {
            op_token: None,
            github_token: None,
            aws_creds: None,
            allowed_github_host: GitHubHost::default(),
            allowed_github_owners: BTreeSet::new(),
            allowed_aws_accounts: BTreeSet::new(),
            credentials_fingerprint: String::new(),
        };
        s.credentials_fingerprint = s.compute_fingerprint();
        s
    }
}

impl SessionState {
    fn compute_fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"sb-session-v2\0");
        match &self.op_token {
            Some(tok) => {
                h.update([1u8]);
                h.update((tok.len() as u64).to_be_bytes());
                h.update(tok.as_bytes());
            }
            None => h.update([0u8]),
        }
        match &self.github_token {
            Some(tok) => {
                h.update([1u8]);
                h.update((tok.len() as u64).to_be_bytes());
                h.update(tok.as_bytes());
            }
            None => h.update([0u8]),
        }
        match &self.aws_creds {
            Some(creds) => {
                h.update([1u8]);
                h.update((creds.access_key_id.len() as u64).to_be_bytes());
                h.update(creds.access_key_id.as_bytes());
                h.update((creds.secret_access_key.len() as u64).to_be_bytes());
                h.update(creds.secret_access_key.as_bytes());
                if let Some(st) = &creds.session_token {
                    h.update([1u8]);
                    h.update((st.len() as u64).to_be_bytes());
                    h.update(st.as_bytes());
                } else {
                    h.update([0u8]);
                }
            }
            None => h.update([0u8]),
        }
        h.update(self.allowed_github_host.as_str().as_bytes());
        h.update([0u8]);
        for owner in &self.allowed_github_owners {
            h.update(owner.as_bytes());
            h.update([0u8]);
        }
        h.update([0xff]);
        for acct in &self.allowed_aws_accounts {
            h.update(acct.as_bytes());
            h.update([0u8]);
        }
        hex::encode(h.finalize())
    }
}

struct PendingCapture {
    secret_key: Zeroizing<[u8; 32]>,
    vault_id: String,
    target: CaptureTarget,
    expires_at: Instant,
}

pub struct EnclaveService {
    vault: Arc<dyn VaultProvider>,
    aws: Arc<dyn AwsClient>,
    github: Arc<dyn GitHubClient>,
    plan_signer: PlanSigner,
    session: Mutex<SessionState>,
    captures: Mutex<BTreeMap<String, PendingCapture>>,
    managed_github_secrets: Mutex<BTreeSet<String>>,
    clock_override_unix_secs: Mutex<Option<u64>>,
}

impl EnclaveService {
    pub fn new(
        vault: Arc<dyn VaultProvider>,
        aws: Arc<dyn AwsClient>,
        github: Arc<dyn GitHubClient>,
    ) -> Self {
        let mut hmac_key = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_key);
        let signer = PlanSigner::new(hmac_key, DEFAULT_PLAN_TTL_SECS);
        zeroize::Zeroize::zeroize(&mut hmac_key);
        Self {
            vault,
            aws,
            github,
            plan_signer: signer,
            session: Mutex::new(SessionState::default()),
            captures: Mutex::new(BTreeMap::new()),
            managed_github_secrets: Mutex::new(BTreeSet::new()),
            clock_override_unix_secs: Mutex::new(None),
        }
    }

    pub fn set_clock_override_for_test(&self, unix_secs: Option<u64>) {
        if let Ok(mut guard) = self.clock_override_unix_secs.lock() {
            *guard = unix_secs;
        }
    }

    fn now_unix_secs(&self) -> u64 {
        if let Ok(guard) = self.clock_override_unix_secs.lock()
            && let Some(override_ts) = *guard
        {
            return override_ts;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }

    pub fn handle(&self, req: EnclaveRequest) -> EnclaveResponse {
        match self.dispatch(req) {
            Ok(res) => EnclaveResponse::ok(res),
            Err(err) => EnclaveResponse::err(err.into_sanitized()),
        }
    }

    fn dispatch(&self, req: EnclaveRequest) -> Result<EnclaveResult, EnclaveError> {
        match req {
            EnclaveRequest::ConfigureSession { credentials } => self.configure_session(credentials),
            EnclaveRequest::Capabilities => self.with_op_token(|tok| {
                Ok(EnclaveResult::Capabilities(
                    self.vault.probe_capabilities(tok)?,
                ))
            }),
            EnclaveRequest::Doctor { manifest } => self.doctor(manifest.as_ref()),
            EnclaveRequest::ValidateConfig { config } => {
                config.validate()?;
                let digest = sha256_hex(&config)?;
                Ok(EnclaveResult::ConfigValid {
                    valid: true,
                    manifest_digest: digest,
                })
            }
            EnclaveRequest::Vaults => self.with_op_token(|tok| {
                Ok(EnclaveResult::Vaults {
                    vaults: self.vault.list_vaults(tok)?,
                })
            }),
            EnclaveRequest::VaultCreate { name } => self.with_op_token(|tok| {
                ensure_service_account_vault_allowed(&name)?;
                Ok(EnclaveResult::VaultCreated(
                    self.vault.create_vault(tok, &name)?,
                ))
            }),
            EnclaveRequest::Items {
                manifest,
                environment,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                ensure_service_account_vault_allowed(&env.vault)?;
                self.with_op_token(|tok| {
                    Ok(EnclaveResult::Items {
                        items: self.vault.list_items(tok, &env.vault)?,
                    })
                })
            }
            EnclaveRequest::Fields {
                manifest,
                environment,
                item,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                ensure_service_account_vault_allowed(&env.vault)?;
                self.with_op_token(|tok| {
                    Ok(EnclaveResult::Fields(
                        self.vault.get_item_fields(tok, &env.vault, &item)?,
                    ))
                })
            }
            EnclaveRequest::GenerateSecret {
                manifest,
                environment,
                target,
                spec,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                ensure_service_account_vault_allowed(&env.vault)?;
                let generated = MemSecret::generate_csprng(&spec)?;
                self.with_op_token(|tok| {
                    let receipt = self
                        .vault
                        .store_secret(tok, &env.vault, &target, &generated, None)?;
                    Ok(EnclaveResult::SecretStored(receipt))
                })
            }
            EnclaveRequest::BeginCapture {
                manifest,
                environment,
                target,
            } => self.begin_capture(&manifest, &environment, target),
            EnclaveRequest::CompleteCapture {
                capture_id,
                sealed_secret_b64,
                mode,
            } => self.complete_capture(&capture_id, &sealed_secret_b64, mode),
            EnclaveRequest::EditMetadata {
                manifest,
                environment,
                item,
                title,
                tags,
                remove_field_id,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                ensure_service_account_vault_allowed(&env.vault)?;
                self.with_op_token(|tok| {
                    let (id, updated_title) = self.vault.edit_metadata(
                        tok,
                        &env.vault,
                        &item,
                        title.as_deref(),
                        tags.as_deref(),
                        remove_field_id.as_deref(),
                    )?;
                    Ok(EnclaveResult::ItemUpdated {
                        id,
                        title: updated_title,
                    })
                })
            }
            EnclaveRequest::Archive {
                manifest,
                environment,
                item,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                ensure_service_account_vault_allowed(&env.vault)?;
                self.with_op_token(|tok| {
                    self.vault.archive_item(tok, &env.vault, &item)?;
                    Ok(EnclaveResult::ItemArchived { archived: item })
                })
            }
            EnclaveRequest::Move {
                manifest,
                environment,
                item,
                destination,
            } => {
                if environment == destination {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "source and destination environments must differ",
                    ));
                }
                let src_env = Self::require_env(&manifest, &environment)?;
                let dst_env = Self::require_env(&manifest, &destination)?;
                ensure_service_account_vault_allowed(&src_env.vault)?;
                ensure_service_account_vault_allowed(&dst_env.vault)?;
                self.with_op_token(|tok| {
                    let new_item_id = self.vault.move_item(
                        tok,
                        &src_env.vault,
                        &dst_env.vault,
                        &item,
                        &destination,
                    )?;
                    Ok(EnclaveResult::ItemMoved {
                        moved: item,
                        new_item_id,
                        destination: destination.clone(),
                        notice: format!(
                            "Item copied to vault '{}' and archived in '{}'; update secretbridge.json bindings for '{destination}'",
                            dst_env.vault, src_env.vault
                        ),
                    })
                })
            }
            EnclaveRequest::Bindings {
                manifest,
                environment,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                let bindings = env
                    .secrets
                    .iter()
                    .map(|(name, spec)| BindingEntry {
                        name: name.clone(),
                        spec: spec.clone(),
                    })
                    .collect();
                Ok(EnclaveResult::Bindings { bindings })
            }
            EnclaveRequest::AdoptAws {
                manifest,
                environment,
                name,
                confirm_unmanaged,
            } => self.adopt_aws(&manifest, &environment, &name, confirm_unmanaged),
            EnclaveRequest::PrepareGithub {
                manifest,
                environment,
            } => self.prepare_github(&manifest, &environment),
            EnclaveRequest::Plan {
                manifest,
                environment,
            } => self.build_plan(&manifest, &environment),
            EnclaveRequest::Apply {
                manifest,
                signed_plan,
            } => self.apply_plan(&manifest, &signed_plan),
            EnclaveRequest::Template {
                manifest,
                environment,
                kind,
                action_sha,
            } => {
                let env = Self::require_env(&manifest, &environment)?;
                let sess = self.snapshot_session()?;
                if let Some(gh) = &env.github {
                    Self::ensure_github_target_allowed(&sess, gh)?;
                }
                if kind == sb_proto::rpc::TemplateKind::Workflow1password
                    && action_sha.is_none()
                    && !sess.allowed_github_host.is_default_github_com()
                {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "action_sha (pinnedLoadSecretsActionSha) is required when rendering Workflow1password for non-github.com enterprise hosts",
                    ));
                }
                let gh_tok = if sess.allowed_github_host.is_default_github_com() {
                    sess.github_token.as_deref()
                } else {
                    None
                };
                let content = render_template(
                    &manifest,
                    &environment,
                    kind,
                    action_sha.as_ref(),
                    self.github.as_ref(),
                    gh_tok,
                )?;
                Ok(EnclaveResult::TemplateRendered { content })
            }
        }
    }

    fn snapshot_session(&self) -> Result<SessionState, EnclaveError> {
        let guard = self.session.lock().map_err(|_| {
            EnclaveError::new(ErrorCode::InternalError, "enclave session lock poisoned")
        })?;
        Ok(guard.clone())
    }

    fn with_op_token<T>(
        &self,
        f: impl FnOnce(&MemSecret) -> Result<T, EnclaveError>,
    ) -> Result<T, EnclaveError> {
        let op_tok = {
            let guard = self.session.lock().map_err(|_| {
                EnclaveError::new(ErrorCode::InternalError, "enclave session lock poisoned")
            })?;
            guard.op_token.clone()
        };
        let Some(tok) = op_tok else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "OP_SERVICE_ACCOUNT_TOKEN is not configured in enclave session",
            ));
        };
        f(&tok)
    }

    fn require_env<'a>(
        manifest: &'a Manifest,
        environment: &Slug,
    ) -> Result<&'a sb_proto::types::EnvironmentConfig, EnclaveError> {
        manifest.validate()?;
        manifest.environments.get(environment).ok_or_else(|| {
            EnclaveError::new(
                ErrorCode::Validation,
                format!("unknown environment '{environment}'"),
            )
        })
    }

    fn ensure_github_target_allowed(
        sess: &SessionState,
        target: &GitHubTarget,
    ) -> Result<(), EnclaveError> {
        target.validate()?;
        if target.host != sess.allowed_github_host {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                format!(
                    "GitHub host '{}' is not authorized for this enclave session (bound host: '{}')",
                    target.host, sess.allowed_github_host
                ),
            ));
        }
        if sess.allowed_github_owners.is_empty() {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "allowed_github_owners allowlist must be configured in enclave session before accessing GitHub targets",
            ));
        }
        let owner_lower = match target.scope {
            GitHubScope::Repository | GitHubScope::Environment => target
                .repository
                .as_ref()
                .expect("validated")
                .owner()
                .as_str()
                .to_ascii_lowercase(),
            GitHubScope::Organization => target
                .organization
                .as_ref()
                .expect("validated")
                .as_str()
                .to_ascii_lowercase(),
        };
        if !sess.allowed_github_owners.contains(&owner_lower) {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                format!(
                    "GitHub owner/organization '{owner_lower}' is not in the session allowlist"
                ),
            ));
        }
        Ok(())
    }

    fn ensure_aws_target_allowed(
        sess: &SessionState,
        target: &AwsTarget,
    ) -> Result<(), EnclaveError> {
        target.validate()?;
        if sess.allowed_aws_accounts.is_empty() {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "allowed_aws_accounts allowlist must be configured in enclave session before accessing AWS targets",
            ));
        }
        if !sess
            .allowed_aws_accounts
            .contains(target.account_id.as_str())
        {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                format!(
                    "AWS account '{}' is not in the session allowlist",
                    target.account_id
                ),
            ));
        }
        Ok(())
    }

    fn github_secret_key(target: &GitHubTarget, name: &SecretName) -> Result<String, EnclaveError> {
        let (host, scope, owner_repo, env_str, secret_upper) =
            target.normalized_destination_key(name)?;
        Ok(format!(
            "{host}|{scope:?}|{owner_repo}|{env_str}|{secret_upper}"
        ))
    }

    fn is_github_secret_managed(
        &self,
        target: &GitHubTarget,
        name: &SecretName,
    ) -> Result<bool, EnclaveError> {
        let key = Self::github_secret_key(target, name)?;
        let guard = self.managed_github_secrets.lock().map_err(|_| {
            EnclaveError::new(ErrorCode::InternalError, "managed secrets lock poisoned")
        })?;
        Ok(guard.contains(&key))
    }

    fn record_github_secret_managed(
        &self,
        target: &GitHubTarget,
        name: &SecretName,
        present: bool,
    ) -> Result<(), EnclaveError> {
        let key = Self::github_secret_key(target, name)?;
        let mut guard = self.managed_github_secrets.lock().map_err(|_| {
            EnclaveError::new(ErrorCode::InternalError, "managed secrets lock poisoned")
        })?;
        if present {
            guard.insert(key);
        } else {
            guard.remove(&key);
        }
        Ok(())
    }

    fn configure_session(
        &self,
        creds: SessionCredentialsInput,
    ) -> Result<EnclaveResult, EnclaveError> {
        let allowed_github_host = match creds.allowed_github_hosts.as_slice() {
            [] => GitHubHost::default(),
            [single] => single.trim().parse::<GitHubHost>()?,
            _ => {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "a GitHub token in an enclave session must be bound to a single GitHub host",
                ));
            }
        };

        let mut allowed_github_owners = BTreeSet::new();
        for raw_owner in &creds.allowed_github_owners {
            let trimmed = raw_owner.trim();
            if !trimmed.is_empty() {
                let parsed: Slug = trimmed.parse()?;
                allowed_github_owners.insert(parsed.as_str().to_ascii_lowercase());
            }
        }

        let mut allowed_aws_accounts = BTreeSet::new();
        for raw_acct in &creds.allowed_aws_account_ids {
            let trimmed = raw_acct.trim();
            if !trimmed.is_empty() {
                let parsed: AwsAccountId = trimmed.parse()?;
                allowed_aws_accounts.insert(parsed.as_str().to_string());
            }
        }

        let op_token = match &creds.op_service_account_token {
            Some(op) if !op.trim().is_empty() => {
                Some(Arc::new(MemSecret::from_slice(op.trim().as_bytes())?))
            }
            _ => None,
        };

        let github_token = match &creds.github_token {
            Some(gh) if !gh.trim().is_empty() => {
                Some(Arc::new(MemSecret::from_slice(gh.trim().as_bytes())?))
            }
            _ => None,
        };

        let ak_trimmed = creds.aws_access_key_id.as_deref().unwrap_or("").trim();
        let sk_trimmed = creds.aws_secret_access_key.as_deref().unwrap_or("").trim();
        let aws_creds = match (ak_trimmed.is_empty(), sk_trimmed.is_empty()) {
            (true, true) => None,
            (false, false) => {
                let session_token = match &creds.aws_session_token {
                    Some(st) if !st.trim().is_empty() => {
                        Some(MemSecret::from_slice(st.trim().as_bytes())?)
                    }
                    _ => None,
                };
                Some(Arc::new(AwsCredentials {
                    access_key_id: MemSecret::from_slice(ak_trimmed.as_bytes())?,
                    secret_access_key: MemSecret::from_slice(sk_trimmed.as_bytes())?,
                    session_token,
                }))
            }
            _ => {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "both aws_access_key_id and aws_secret_access_key must be provided together",
                ));
            }
        };

        let mut new_state = SessionState {
            op_token,
            github_token,
            aws_creds,
            allowed_github_host,
            allowed_github_owners,
            allowed_aws_accounts,
            credentials_fingerprint: String::new(),
        };
        new_state.credentials_fingerprint = new_state.compute_fingerprint();

        let has_op_token = new_state.op_token.is_some();
        let has_github_token = new_state.github_token.is_some();
        let has_aws_credentials = new_state.aws_creds.is_some();

        // Atomically replace session state, rotate plan HMAC key, and clear pending captures (`C2`, `H3`)
        {
            let mut guard = self.session.lock().map_err(|_| {
                EnclaveError::new(ErrorCode::InternalError, "enclave session lock poisoned")
            })?;
            *guard = new_state;
        }
        let mut fresh_hmac_key = [0u8; 32];
        OsRng.fill_bytes(&mut fresh_hmac_key);
        let rotate_res = self.plan_signer.rotate_key(fresh_hmac_key);
        zeroize::Zeroize::zeroize(&mut fresh_hmac_key);
        rotate_res?;

        if let Ok(mut caps) = self.captures.lock() {
            caps.clear();
        }
        if let Ok(mut managed) = self.managed_github_secrets.lock() {
            managed.clear();
        }

        Ok(EnclaveResult::SessionConfigured {
            has_op_token,
            has_github_token,
            has_aws_credentials,
        })
    }

    fn doctor(&self, manifest: Option<&Manifest>) -> Result<EnclaveResult, EnclaveError> {
        if let Some(m) = manifest {
            m.validate()?;
        }
        let sess = self.snapshot_session()?;
        let mut entries = Vec::new();

        match &sess.op_token {
            Some(tok) => match self.vault.probe_capabilities(tok) {
                Ok(caps) => entries.push(DoctorEntry {
                    subsystem: "1password-enclave".into(),
                    status: "ready".into(),
                    detail: Some(format!(
                        "authenticated={}, can_create_vaults={}, vaults={}",
                        caps.authenticated,
                        caps.can_create_vaults,
                        caps.accessible_vault_ids.len()
                    )),
                }),
                Err(e) => entries.push(DoctorEntry {
                    subsystem: "1password-enclave".into(),
                    status: "error".into(),
                    detail: Some(e.message),
                }),
            },
            None => entries.push(DoctorEntry {
                subsystem: "1password-enclave".into(),
                status: "unconfigured".into(),
                detail: Some("OP_SERVICE_ACCOUNT_TOKEN not loaded in enclave".into()),
            }),
        }

        // Only ever probe the session-bound GitHub host (`C1` SSRF/token-exfiltration prevention)
        let bound_host = sess.allowed_github_host.as_str();
        match &sess.github_token {
            Some(tok) => match self.github.check_authenticated_user(tok, bound_host) {
                Ok(login) => entries.push(DoctorEntry {
                    subsystem: format!("github:{bound_host}"),
                    status: "ready".into(),
                    detail: Some(format!("authenticated as {login}")),
                }),
                Err(e) => entries.push(DoctorEntry {
                    subsystem: format!("github:{bound_host}"),
                    status: "error".into(),
                    detail: Some(e.message),
                }),
            },
            None => entries.push(DoctorEntry {
                subsystem: format!("github:{bound_host}"),
                status: "unconfigured".into(),
                detail: Some("GitHub token not loaded in enclave".into()),
            }),
        }

        if let Some(m) = manifest {
            for (env_name, env) in &m.environments {
                if let Some(gh) = &env.github
                    && let Err(e) = Self::ensure_github_target_allowed(&sess, gh)
                {
                    entries.push(DoctorEntry {
                        subsystem: format!("github-target:{env_name}"),
                        status: "error".into(),
                        detail: Some(e.message),
                    });
                }
                if let Some(aws) = &env.aws {
                    if let Err(e) = Self::ensure_aws_target_allowed(&sess, aws) {
                        entries.push(DoctorEntry {
                            subsystem: format!("aws:{env_name}"),
                            status: "error".into(),
                            detail: Some(e.message),
                        });
                        continue;
                    }
                    match &sess.aws_creds {
                        Some(creds) => match self.aws.verify_caller_identity(creds, aws) {
                            Ok(id) => entries.push(DoctorEntry {
                                subsystem: format!("aws:{env_name}"),
                                status: "ready".into(),
                                detail: Some(format!("account={} arn={}", id.account, id.arn)),
                            }),
                            Err(e) => entries.push(DoctorEntry {
                                subsystem: format!("aws:{env_name}"),
                                status: "error".into(),
                                detail: Some(e.message),
                            }),
                        },
                        None => entries.push(DoctorEntry {
                            subsystem: format!("aws:{env_name}"),
                            status: "unconfigured".into(),
                            detail: Some("AWS credentials not loaded in enclave".into()),
                        }),
                    }
                }
            }
        }

        Ok(EnclaveResult::Doctor { entries })
    }

    fn begin_capture(
        &self,
        manifest: &Manifest,
        environment: &Slug,
        target: CaptureTarget,
    ) -> Result<EnclaveResult, EnclaveError> {
        let env = Self::require_env(manifest, environment)?;
        ensure_service_account_vault_allowed(&env.vault)?;
        if self.snapshot_session()?.op_token.is_none() {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "OP_SERVICE_ACCOUNT_TOKEN is required before arming secret capture",
            ));
        }

        let mut captures = self
            .captures
            .lock()
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "capture lock poisoned"))?;
        let now = Instant::now();
        captures.retain(|_, v| v.expires_at > now);
        if captures.len() >= MAX_ACTIVE_CAPTURES {
            return Err(EnclaveError::new(
                ErrorCode::CaptureUnavailable,
                "too many active capture challenges; wait 15 seconds and retry",
            ));
        }

        let (sk, pk) = generate_sealed_box_keypair();
        let capture_id = Uuid::new_v4().to_string();
        let pk_capture_b64 = B64.encode(pk);
        captures.insert(
            capture_id.clone(),
            PendingCapture {
                secret_key: sk,
                vault_id: env.vault.clone(),
                target,
                expires_at: now + CAPTURE_TTL,
            },
        );

        Ok(EnclaveResult::CaptureStarted(CaptureChallenge {
            capture_id,
            pk_capture_b64,
            expires_in_ms: CAPTURE_TTL.as_millis() as u64,
        }))
    }

    fn complete_capture(
        &self,
        capture_id: &str,
        sealed_secret_b64: &str,
        mode: CaptureInterceptMode,
    ) -> Result<EnclaveResult, EnclaveError> {
        let pending = {
            let mut captures = self.captures.lock().map_err(|_| {
                EnclaveError::new(ErrorCode::InternalError, "capture lock poisoned")
            })?;
            let now = Instant::now();
            captures.retain(|_, v| v.expires_at > now);
            captures.remove(capture_id)
        };
        let Some(pending) = pending else {
            return Err(EnclaveError::new(
                ErrorCode::CaptureExpired,
                "capture challenge expired or was already consumed",
            ));
        };
        if Instant::now() > pending.expires_at {
            return Err(EnclaveError::new(
                ErrorCode::CaptureExpired,
                "capture challenge 15-second TTL expired",
            ));
        }

        let opened = unseal_base64(&pending.secret_key, sealed_secret_b64)?;
        if opened.is_empty() {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "captured secret cannot be empty",
            ));
        }
        let mem_secret = MemSecret::from_slice(&opened)?;
        self.with_op_token(|tok| {
            let receipt = self.vault.store_secret(
                tok,
                &pending.vault_id,
                &pending.target,
                &mem_secret,
                Some(mode),
            )?;
            Ok(EnclaveResult::SecretStored(receipt))
        })
    }

    fn adopt_aws(
        &self,
        manifest: &Manifest,
        environment: &Slug,
        name: &SecretName,
        confirm_unmanaged: bool,
    ) -> Result<EnclaveResult, EnclaveError> {
        let env = Self::require_env(manifest, environment)?;
        let Some(aws) = &env.aws else {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "AWS target is not configured for this environment",
            ));
        };
        if !env.secrets.contains_key(name) {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                format!("secret '{name}' is not bound in environment '{environment}'"),
            ));
        }
        let sess = self.snapshot_session()?;
        Self::ensure_aws_target_allowed(&sess, aws)?;
        let Some(creds) = sess.aws_creds.as_deref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "AWS credentials are not configured in enclave session",
            ));
        };
        self.aws.verify_caller_identity(creds, aws)?;
        let resource = format!("{}{}", aws.prefix.as_str(), name.as_str());
        let Some(existing) = self.aws.describe_secret(creds, aws, &resource)? else {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                format!("AWS secret '{resource}' does not exist"),
            ));
        };
        if existing.has_conflicting_owner(manifest.project.as_str(), environment.as_str()) {
            return Err(EnclaveError::new(
                ErrorCode::OwnershipConflict,
                format!(
                    "AWS secret '{resource}' is already tagged as owned by a different SecretBridge project or environment"
                ),
            ));
        }
        if !existing.is_owned_by(manifest.project.as_str(), environment.as_str())
            && !confirm_unmanaged
        {
            return Err(EnclaveError::new(
                ErrorCode::OwnershipConflict,
                format!(
                    "AWS secret '{resource}' has no SecretBridge ownership tags; pass confirm_unmanaged=true after operator confirmation"
                ),
            ));
        }

        let mut tags = BTreeMap::new();
        tags.insert(
            TAG_PROJECT.to_string(),
            manifest.project.as_str().to_string(),
        );
        tags.insert(
            TAG_ENVIRONMENT.to_string(),
            environment.as_str().to_string(),
        );
        self.aws.tag_secret(creds, aws, &resource, &tags)?;
        Ok(EnclaveResult::AwsAdopted {
            adopted: resource,
            notice: "AWS secret tagged with SecretBridge ownership metadata".into(),
        })
    }

    fn prepare_github(
        &self,
        manifest: &Manifest,
        environment: &Slug,
    ) -> Result<EnclaveResult, EnclaveError> {
        let env = Self::require_env(manifest, environment)?;
        let Some(gh) = &env.github else {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "GitHub target is not configured for this environment",
            ));
        };
        let sess = self.snapshot_session()?;
        Self::ensure_github_target_allowed(&sess, gh)?;
        let Some(tok) = sess.github_token.as_deref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "GitHub token is not configured in enclave session",
            ));
        };
        let prepared = self.github.prepare_environment(tok, gh)?;
        for (name, spec) in &env.secrets {
            if spec.github && spec.state == SecretState::Present {
                self.record_github_secret_managed(gh, name, true)?;
            }
        }
        Ok(EnclaveResult::GithubPrepared {
            prepared,
            notice: "GitHub deployment environment verified and declared secrets marked managed"
                .into(),
        })
    }

    fn collect_present_refs(env: &sb_proto::types::EnvironmentConfig) -> Vec<&OpRef> {
        env.secrets
            .values()
            .filter(|s| s.state == SecretState::Present)
            .filter_map(|s| s.r#ref.as_ref())
            .collect()
    }

    fn build_plan(
        &self,
        manifest: &Manifest,
        environment: &Slug,
    ) -> Result<EnclaveResult, EnclaveError> {
        let env = Self::require_env(manifest, environment)?;
        ensure_service_account_vault_allowed(&env.vault)?;
        let sess = self.snapshot_session()?;
        let Some(op_tok) = sess.op_token.as_deref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "OP_SERVICE_ACCOUNT_TOKEN is not configured in enclave session",
            ));
        };

        let manifest_digest = sha256_hex(manifest)?;
        let refs = Self::collect_present_refs(env);
        let source_revision_digest = self
            .vault
            .source_revision_digest(op_tok, &env.vault, &refs)?;

        // Pre-validate secret sizes inside enclave memory before signing plan
        for (name, spec) in &env.secrets {
            if spec.state == SecretState::Present
                && let Some(op_ref) = &spec.r#ref
            {
                let secret_val = self.vault.resolve_ref(op_tok, &env.vault, op_ref)?;
                if env.github.is_some() && spec.github && secret_val.len() > MAX_GITHUB_SECRET_BYTES
                {
                    return Err(EnclaveError::new(
                        ErrorCode::SizeLimitExceeded,
                        format!("{name}: secret exceeds GitHub Actions 48 KiB limit"),
                    ));
                }
                if env.aws.is_some() && spec.aws && secret_val.len() > MAX_AWS_SECRET_BYTES {
                    return Err(EnclaveError::new(
                        ErrorCode::SizeLimitExceeded,
                        format!("{name}: secret exceeds AWS Secrets Manager 65536-byte limit"),
                    ));
                }
            }
        }

        let mut operations = Vec::new();
        let mut github_actor = None;
        if let Some(gh) = &env.github
            && env.secrets.values().any(|s| s.github)
        {
            Self::ensure_github_target_allowed(&sess, gh)?;
            let Some(gh_tok) = sess.github_token.as_deref() else {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "GitHub token is required to plan GitHub Actions sync",
                ));
            };
            github_actor = Some(
                self.github
                    .check_authenticated_user(gh_tok, gh.host.as_str())?,
            );
            let remote_gh = self.github.list_secret_timestamps(gh_tok, gh)?;
            for (name, spec) in &env.secrets {
                if !spec.github {
                    continue;
                }
                match spec.state {
                    SecretState::Present => {
                        let remote_entry = remote_gh.get(name.as_str());
                        if remote_entry.is_some() {
                            let is_managed = self.is_github_secret_managed(gh, name)?;
                            if !is_managed && !spec.allow_unmanaged_github_overwrite {
                                return Err(EnclaveError::new(
                                    ErrorCode::OwnershipConflict,
                                    format!(
                                        "refusing to overwrite pre-existing unmanaged GitHub secret '{name}'; run prepare-github or set allow_unmanaged_github_overwrite=true if intended"
                                    ),
                                ));
                            }
                        }
                        let observed_updated_at = remote_entry.cloned().flatten();
                        operations.push(PlannedOp::Github {
                            name: name.clone(),
                            action: PlanAction::Set,
                            destination: gh.clone(),
                            observed_updated_at,
                        });
                    }
                    SecretState::Absent => {
                        if let Some(observed_updated_at) = remote_gh.get(name.as_str()) {
                            let is_managed = self.is_github_secret_managed(gh, name)?;
                            if !is_managed && !spec.allow_unmanaged_github_delete {
                                return Err(EnclaveError::new(
                                    ErrorCode::OwnershipConflict,
                                    format!(
                                        "refusing to delete pre-existing unmanaged GitHub secret '{name}'; set allow_unmanaged_github_delete=true if intended"
                                    ),
                                ));
                            }
                            operations.push(PlannedOp::Github {
                                name: name.clone(),
                                action: PlanAction::Delete,
                                destination: gh.clone(),
                                observed_updated_at: observed_updated_at.clone(),
                            });
                        }
                    }
                }
            }
        }

        let mut aws_identity = None;
        if let Some(aws) = &env.aws
            && env.secrets.values().any(|s| s.aws)
        {
            Self::ensure_aws_target_allowed(&sess, aws)?;
            let Some(creds) = sess.aws_creds.as_deref() else {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "AWS credentials are required to plan AWS Secrets Manager sync",
                ));
            };
            aws_identity = Some(self.aws.verify_caller_identity(creds, aws)?);
            for (name, spec) in &env.secrets {
                if !spec.aws {
                    continue;
                }
                let resource = format!("{}{}", aws.prefix.as_str(), name.as_str());
                let existing = self.aws.describe_secret(creds, aws, &resource)?;
                match (spec.state, existing) {
                    (SecretState::Present, None) => {
                        operations.push(PlannedOp::Aws {
                            name: name.clone(),
                            action: PlanAction::Create,
                            resource,
                            destination: aws.clone(),
                            observed: AwsObservedMetadata {
                                arn: None,
                                versions: BTreeMap::new(),
                                modified: None,
                                deleted: None,
                            },
                        });
                    }
                    (SecretState::Present, Some(rec)) => {
                        if rec.deleted.is_some() {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!(
                                    "AWS secret '{resource}' is pending deletion; restore it before syncing"
                                ),
                            ));
                        }
                        if !rec.is_owned_by(manifest.project.as_str(), environment.as_str()) {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!(
                                    "AWS secret '{resource}' is not owned by project '{}' environment '{environment}'; run adopt-aws explicitly",
                                    manifest.project
                                ),
                            ));
                        }
                        operations.push(PlannedOp::Aws {
                            name: name.clone(),
                            action: PlanAction::Update,
                            resource,
                            destination: aws.clone(),
                            observed: rec.to_observed(),
                        });
                    }
                    (SecretState::Absent, None) => {}
                    (SecretState::Absent, Some(rec)) => {
                        if rec.deleted.is_some() {
                            continue;
                        }
                        if !rec.is_owned_by(manifest.project.as_str(), environment.as_str()) {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!(
                                    "refusing to delete unowned AWS secret '{resource}'; run adopt-aws first if intended"
                                ),
                            ));
                        }
                        operations.push(PlannedOp::Aws {
                            name: name.clone(),
                            action: PlanAction::Delete,
                            resource,
                            destination: aws.clone(),
                            observed: rec.to_observed(),
                        });
                    }
                }
            }
        }

        let unsigned = UnsignedPlan {
            plan_id: Uuid::new_v4().to_string(),
            version: 2,
            environment: environment.clone(),
            manifest_digest,
            source_revision_digest,
            credentials_fingerprint: sess.credentials_fingerprint,
            github_actor,
            aws_identity,
            issued_at_unix_secs: self.now_unix_secs(),
            operations,
        };
        let signed = self.plan_signer.sign(unsigned)?;
        Ok(EnclaveResult::Planned(signed))
    }

    fn apply_plan(
        &self,
        manifest: &Manifest,
        signed_plan: &SignedPlan,
    ) -> Result<EnclaveResult, EnclaveError> {
        // 1. Verify per-session HMAC-SHA256, unconsumed plan_id, & TTL (`S4`, `H3`)
        self.plan_signer.verify(signed_plan, self.now_unix_secs())?;

        // 2. Verify manifest digest matches signed plan (closes TOCTOU manifest swap)
        let env_name = &signed_plan.plan.environment;
        let env = Self::require_env(manifest, env_name)?;
        ensure_service_account_vault_allowed(&env.vault)?;
        let current_manifest_digest = sha256_hex(manifest)?;
        if current_manifest_digest != signed_plan.plan.manifest_digest {
            return Err(EnclaveError::new(
                ErrorCode::StalePlan,
                "secretbridge.json changed since plan was generated; run plan again",
            ));
        }

        let sess = self.snapshot_session()?;
        if sess.credentials_fingerprint != signed_plan.plan.credentials_fingerprint {
            return Err(EnclaveError::new(
                ErrorCode::StalePlan,
                "enclave session credentials changed since plan was generated; run plan again",
            ));
        }

        let Some(op_tok) = sess.op_token.as_deref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "OP_SERVICE_ACCOUNT_TOKEN is not configured in enclave session",
            ));
        };

        // 3. Re-verify 1Password source revision digest before writing anything
        let refs = Self::collect_present_refs(env);
        let current_source_digest = self
            .vault
            .source_revision_digest(op_tok, &env.vault, &refs)?;
        if current_source_digest != signed_plan.plan.source_revision_digest {
            return Err(EnclaveError::new(
                ErrorCode::StalePlan,
                "1Password source items changed since plan was generated; run plan again",
            ));
        }

        // 4. Re-verify GitHub actor if GitHub operations are present (`H3`)
        if let Some(expected_actor) = &signed_plan.plan.github_actor
            && let Some(gh_target) = &env.github
        {
            Self::ensure_github_target_allowed(&sess, gh_target)?;
            let Some(gh_tok) = sess.github_token.as_deref() else {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "GitHub token missing for planned GitHub operations",
                ));
            };
            let actual_actor = self
                .github
                .check_authenticated_user(gh_tok, gh_target.host.as_str())?;
            if &actual_actor != expected_actor {
                return Err(EnclaveError::new(
                    ErrorCode::StalePlan,
                    "GitHub authenticated actor changed since plan was generated",
                ));
            }
        }

        // 5. Re-verify AWS caller identity if AWS operations are present
        if let Some(expected_aws_id) = &signed_plan.plan.aws_identity
            && let Some(aws_target) = &env.aws
        {
            Self::ensure_aws_target_allowed(&sess, aws_target)?;
            let Some(creds) = sess.aws_creds.as_deref() else {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "AWS credentials missing for planned AWS operations",
                ));
            };
            let actual_id = self.aws.verify_caller_identity(creds, aws_target)?;
            if &actual_id != expected_aws_id {
                return Err(EnclaveError::new(
                    ErrorCode::StalePlan,
                    "AWS caller identity changed since plan was generated",
                ));
            }
        }

        // 6. Atomically consume `plan_id` before executing any external mutation (`H3`)
        self.plan_signer
            .consume_verified(signed_plan, self.now_unix_secs())?;

        let mut results = Vec::new();
        let ops = &signed_plan.plan.operations;
        for (idx, op) in ops.iter().enumerate() {
            match self.execute_single_op(manifest, env_name, env, &sess, op_tok, op) {
                Ok(()) => {
                    results.push(OpStepResult {
                        target: op.target_kind(),
                        name: op.name().clone(),
                        action: op.action(),
                        succeeded: true,
                        error: None,
                    });
                }
                Err(err) => {
                    // Record exact failure and remaining pending ops (closes S6)
                    results.push(OpStepResult {
                        target: op.target_kind(),
                        name: op.name().clone(),
                        action: op.action(),
                        succeeded: false,
                        error: Some(err.message),
                    });
                    let pending = ops[idx + 1..].to_vec();
                    return Ok(EnclaveResult::Applied(ApplyReport {
                        complete: false,
                        results,
                        pending,
                    }));
                }
            }
        }

        Ok(EnclaveResult::Applied(ApplyReport {
            complete: true,
            results,
            pending: Vec::new(),
        }))
    }

    fn execute_single_op(
        &self,
        manifest: &Manifest,
        env_name: &Slug,
        env: &sb_proto::types::EnvironmentConfig,
        sess: &SessionState,
        op_tok: &MemSecret,
        op: &PlannedOp,
    ) -> Result<(), EnclaveError> {
        match op {
            PlannedOp::Github {
                name,
                action,
                destination,
                observed_updated_at,
            } => {
                Self::ensure_github_target_allowed(sess, destination)?;
                let Some(gh_tok) = sess.github_token.as_deref() else {
                    return Err(EnclaveError::new(
                        ErrorCode::Unauthorized,
                        "GitHub token missing during apply",
                    ));
                };
                let remote_now = self.github.list_secret_timestamps(gh_tok, destination)?;
                let actual_updated = remote_now.get(name.as_str()).cloned().flatten();
                if &actual_updated != observed_updated_at {
                    return Err(EnclaveError::new(
                        ErrorCode::StalePlan,
                        format!("GitHub secret '{name}' changed remotely since plan was created"),
                    ));
                }
                match action {
                    PlanAction::Set | PlanAction::Create | PlanAction::Update => {
                        let spec = env.secrets.get(name).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing secret spec")
                        })?;
                        let op_ref = spec.r#ref.as_ref().ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing op:// reference")
                        })?;
                        let secret_val = self.vault.resolve_ref(op_tok, &env.vault, op_ref)?;
                        if secret_val.len() > MAX_GITHUB_SECRET_BYTES {
                            return Err(EnclaveError::new(
                                ErrorCode::SizeLimitExceeded,
                                format!("{name}: secret exceeds GitHub Actions 48 KiB limit"),
                            ));
                        }
                        let (pub_key, repo_ids) =
                            self.github.get_encryption_target(gh_tok, destination)?;
                        self.github.put_secret(
                            gh_tok,
                            destination,
                            name,
                            &secret_val,
                            &pub_key,
                            &repo_ids,
                        )?;
                        self.record_github_secret_managed(destination, name, true)?;
                        Ok(())
                    }
                    PlanAction::Delete => {
                        let spec = env.secrets.get(name).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing secret spec")
                        })?;
                        let is_managed = self.is_github_secret_managed(destination, name)?;
                        if !is_managed && !spec.allow_unmanaged_github_delete {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!(
                                    "refusing to delete unmanaged GitHub secret '{name}' without allow_unmanaged_github_delete=true"
                                ),
                            ));
                        }
                        self.github.delete_secret(gh_tok, destination, name)?;
                        self.record_github_secret_managed(destination, name, false)?;
                        Ok(())
                    }
                }
            }
            PlannedOp::Aws {
                name,
                action,
                resource,
                destination,
                observed,
            } => {
                Self::ensure_aws_target_allowed(sess, destination)?;
                let Some(creds) = sess.aws_creds.as_deref() else {
                    return Err(EnclaveError::new(
                        ErrorCode::Unauthorized,
                        "AWS credentials missing during apply",
                    ));
                };
                let current = self.aws.describe_secret(creds, destination, resource)?;
                match action {
                    PlanAction::Create => {
                        if current.is_some() {
                            return Err(EnclaveError::new(
                                ErrorCode::StalePlan,
                                format!("AWS secret '{resource}' was created concurrently"),
                            ));
                        }
                        let spec = env.secrets.get(name).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing secret spec")
                        })?;
                        let op_ref = spec.r#ref.as_ref().ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing op:// reference")
                        })?;
                        let secret_val = self.vault.resolve_ref(op_tok, &env.vault, op_ref)?;
                        if secret_val.len() > MAX_AWS_SECRET_BYTES {
                            return Err(EnclaveError::new(
                                ErrorCode::SizeLimitExceeded,
                                format!(
                                    "{name}: secret exceeds AWS Secrets Manager 65536-byte limit"
                                ),
                            ));
                        }
                        let mut tags = BTreeMap::new();
                        tags.insert(
                            TAG_PROJECT.to_string(),
                            manifest.project.as_str().to_string(),
                        );
                        tags.insert(TAG_ENVIRONMENT.to_string(), env_name.as_str().to_string());
                        self.aws
                            .create_secret(creds, destination, resource, &secret_val, &tags)
                    }
                    PlanAction::Update | PlanAction::Set => {
                        let Some(rec) = current else {
                            return Err(EnclaveError::new(
                                ErrorCode::StalePlan,
                                format!("AWS secret '{resource}' disappeared before update"),
                            ));
                        };
                        if rec.modified != observed.modified {
                            return Err(EnclaveError::new(
                                ErrorCode::StalePlan,
                                format!(
                                    "AWS secret '{resource}' changed remotely since plan was created"
                                ),
                            ));
                        }
                        if !rec.is_owned_by(manifest.project.as_str(), env_name.as_str()) {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!("AWS secret '{resource}' lost ownership tags"),
                            ));
                        }
                        let spec = env.secrets.get(name).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing secret spec")
                        })?;
                        let op_ref = spec.r#ref.as_ref().ok_or_else(|| {
                            EnclaveError::new(ErrorCode::Validation, "missing op:// reference")
                        })?;
                        let secret_val = self.vault.resolve_ref(op_tok, &env.vault, op_ref)?;
                        if secret_val.len() > MAX_AWS_SECRET_BYTES {
                            return Err(EnclaveError::new(
                                ErrorCode::SizeLimitExceeded,
                                format!(
                                    "{name}: secret exceeds AWS Secrets Manager 65536-byte limit"
                                ),
                            ));
                        }
                        self.aws
                            .update_secret(creds, destination, resource, &secret_val)
                    }
                    PlanAction::Delete => {
                        let Some(rec) = current else {
                            return Err(EnclaveError::new(
                                ErrorCode::StalePlan,
                                format!("AWS secret '{resource}' disappeared before delete"),
                            ));
                        };
                        if rec.modified != observed.modified {
                            return Err(EnclaveError::new(
                                ErrorCode::StalePlan,
                                format!(
                                    "AWS secret '{resource}' changed remotely since plan was created"
                                ),
                            ));
                        }
                        if !rec.is_owned_by(manifest.project.as_str(), env_name.as_str()) {
                            return Err(EnclaveError::new(
                                ErrorCode::OwnershipConflict,
                                format!("refusing to delete unowned AWS secret '{resource}'"),
                            ));
                        }
                        self.aws.delete_secret(
                            creds,
                            destination,
                            resource,
                            destination.recovery_days.get(),
                        )
                    }
                }
            }
        }
    }
}

pub const _TARGET_KINDS_ANCHOR: [TargetKind; 2] = [TargetKind::Github, TargetKind::Aws];
