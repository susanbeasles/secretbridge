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
use sb_proto::types::{Manifest, OpRef, SecretState, Slug};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const CAPTURE_TTL: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CAPTURES: usize = 8;
const MAX_GITHUB_SECRET_BYTES: usize = 48 * 1024; // 48 KiB GitHub Actions limit
const MAX_AWS_SECRET_BYTES: usize = 65_536; // 64 KiB AWS Secrets Manager limit

#[derive(Default)]
struct SessionState {
    op_token: Option<MemSecret>,
    github_token: Option<MemSecret>,
    aws_creds: Option<AwsCredentials>,
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
            } => self.adopt_aws(&manifest, &environment, &name),
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
                let sess = self.lock_session()?;
                let content = render_template(
                    &manifest,
                    &environment,
                    kind,
                    action_sha.as_ref(),
                    self.github.as_ref(),
                    sess.github_token.as_ref(),
                )?;
                Ok(EnclaveResult::TemplateRendered { content })
            }
        }
    }

    fn lock_session(&self) -> Result<std::sync::MutexGuard<'_, SessionState>, EnclaveError> {
        self.session.lock().map_err(|_| {
            EnclaveError::new(ErrorCode::InternalError, "enclave session lock poisoned")
        })
    }

    fn with_op_token<T>(
        &self,
        f: impl FnOnce(&MemSecret) -> Result<T, EnclaveError>,
    ) -> Result<T, EnclaveError> {
        let sess = self.lock_session()?;
        let Some(tok) = sess.op_token.as_ref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "OP_SERVICE_ACCOUNT_TOKEN is not configured in enclave session",
            ));
        };
        f(tok)
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

    fn configure_session(
        &self,
        creds: SessionCredentialsInput,
    ) -> Result<EnclaveResult, EnclaveError> {
        let mut sess = self.lock_session()?;
        if let Some(op) = &creds.op_service_account_token {
            let trimmed = op.trim();
            sess.op_token = if trimmed.is_empty() {
                None
            } else {
                Some(MemSecret::from_slice(trimmed.as_bytes())?)
            };
        }
        if let Some(gh) = &creds.github_token {
            let trimmed = gh.trim();
            sess.github_token = if trimmed.is_empty() {
                None
            } else {
                Some(MemSecret::from_slice(trimmed.as_bytes())?)
            };
        }
        match (&creds.aws_access_key_id, &creds.aws_secret_access_key) {
            (Some(ak), Some(sk)) if !ak.trim().is_empty() && !sk.trim().is_empty() => {
                let session_token = match &creds.aws_session_token {
                    Some(st) if !st.trim().is_empty() => {
                        Some(MemSecret::from_slice(st.trim().as_bytes())?)
                    }
                    _ => None,
                };
                sess.aws_creds = Some(AwsCredentials {
                    access_key_id: MemSecret::from_slice(ak.trim().as_bytes())?,
                    secret_access_key: MemSecret::from_slice(sk.trim().as_bytes())?,
                    session_token,
                });
            }
            (Some(ak), _) if ak.trim().is_empty() => {
                sess.aws_creds = None;
            }
            _ => {}
        }

        Ok(EnclaveResult::SessionConfigured {
            has_op_token: sess.op_token.is_some(),
            has_github_token: sess.github_token.is_some(),
            has_aws_credentials: sess.aws_creds.is_some(),
        })
    }

    fn doctor(&self, manifest: Option<&Manifest>) -> Result<EnclaveResult, EnclaveError> {
        if let Some(m) = manifest {
            m.validate()?;
        }
        let sess = self.lock_session()?;
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

        let mut gh_hosts = vec!["github.com".to_string()];
        if let Some(m) = manifest {
            for env in m.environments.values() {
                if let Some(gh) = &env.github {
                    let h = gh.host.as_str().to_string();
                    if !gh_hosts.contains(&h) {
                        gh_hosts.push(h);
                    }
                }
            }
        }
        for host in gh_hosts {
            match &sess.github_token {
                Some(tok) => match self.github.check_authenticated_user(tok, &host) {
                    Ok(login) => entries.push(DoctorEntry {
                        subsystem: format!("github:{host}"),
                        status: "ready".into(),
                        detail: Some(format!("authenticated as {login}")),
                    }),
                    Err(e) => entries.push(DoctorEntry {
                        subsystem: format!("github:{host}"),
                        status: "error".into(),
                        detail: Some(e.message),
                    }),
                },
                None => entries.push(DoctorEntry {
                    subsystem: format!("github:{host}"),
                    status: "unconfigured".into(),
                    detail: Some("GitHub token not loaded in enclave".into()),
                }),
            }
        }

        if let Some(m) = manifest {
            for (env_name, env) in &m.environments {
                if let Some(aws) = &env.aws {
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
        {
            let sess = self.lock_session()?;
            if sess.op_token.is_none() {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "OP_SERVICE_ACCOUNT_TOKEN is required before arming secret capture",
                ));
            }
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
        name: &sb_proto::types::SecretName,
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
        };
        let sess = self.lock_session()?;
        let Some(creds) = sess.aws_creds.as_ref() else {
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
        let sess = self.lock_session()?;
        let Some(tok) = sess.github_token.as_ref() else {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "GitHub token is not configured in enclave session",
            ));
        };
        let prepared = self.github.prepare_environment(tok, gh)?;
        Ok(EnclaveResult::GithubPrepared {
            prepared,
            notice: "GitHub deployment environment verified".into(),
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
        let sess = self.lock_session()?;
        let Some(op_tok) = sess.op_token.as_ref() else {
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
        if let Some(gh) = &env.github
            && env.secrets.values().any(|s| s.github)
        {
            let Some(gh_tok) = sess.github_token.as_ref() else {
                return Err(EnclaveError::new(
                    ErrorCode::Unauthorized,
                    "GitHub token is required to plan GitHub Actions sync",
                ));
            };
            let remote_gh = self.github.list_secret_timestamps(gh_tok, gh)?;
            for (name, spec) in &env.secrets {
                if !spec.github {
                    continue;
                }
                match spec.state {
                    SecretState::Present => {
                        let observed_updated_at = remote_gh.get(name.as_str()).cloned().flatten();
                        operations.push(PlannedOp::Github {
                            name: name.clone(),
                            action: PlanAction::Set,
                            destination: gh.clone(),
                            observed_updated_at,
                        });
                    }
                    SecretState::Absent => {
                        if let Some(observed_updated_at) = remote_gh.get(name.as_str()) {
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
            let Some(creds) = sess.aws_creds.as_ref() else {
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
            version: 2,
            environment: environment.clone(),
            manifest_digest,
            source_revision_digest,
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
        // 1. Verify per-boot HMAC-SHA256 & plan TTL (closes S4)
        self.plan_signer.verify(signed_plan, self.now_unix_secs())?;

        // 2. Verify manifest digest matches signed plan (closes TOCTOU manifest swap)
        let env = Self::require_env(manifest, &signed_plan.plan.environment)?;
        ensure_service_account_vault_allowed(&env.vault)?;
        let current_manifest_digest = sha256_hex(manifest)?;
        if current_manifest_digest != signed_plan.plan.manifest_digest {
            return Err(EnclaveError::new(
                ErrorCode::StalePlan,
                "secretbridge.json changed since plan was generated; run plan again",
            ));
        }

        let sess = self.lock_session()?;
        let Some(op_tok) = sess.op_token.as_ref() else {
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

        // 4. Re-verify AWS caller identity if AWS operations are present
        if let Some(expected_aws_id) = &signed_plan.plan.aws_identity
            && let Some(aws_target) = &env.aws
        {
            let Some(creds) = sess.aws_creds.as_ref() else {
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

        let mut results = Vec::new();
        let ops = &signed_plan.plan.operations;
        for (idx, op) in ops.iter().enumerate() {
            match self.execute_single_op(manifest, env, &sess, op_tok, op) {
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
                let Some(gh_tok) = sess.github_token.as_ref() else {
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
                        )
                    }
                    PlanAction::Delete => self.github.delete_secret(gh_tok, destination, name),
                }
            }
            PlannedOp::Aws {
                name,
                action,
                resource,
                destination,
                observed,
            } => {
                let Some(creds) = sess.aws_creds.as_ref() else {
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
                        tags.insert(
                            TAG_ENVIRONMENT.to_string(),
                            manifest
                                .environments
                                .iter()
                                .find_map(|(k, v)| {
                                    if v.vault == env.vault {
                                        Some(k.as_str().to_string())
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default(),
                        );
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
                        let env_slug = manifest
                            .environments
                            .iter()
                            .find_map(|(k, v)| (v.vault == env.vault).then_some(k.as_str()))
                            .unwrap_or_default();
                        if !rec.is_owned_by(manifest.project.as_str(), env_slug) {
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
                        let env_slug = manifest
                            .environments
                            .iter()
                            .find_map(|(k, v)| (v.vault == env.vault).then_some(k.as_str()))
                            .unwrap_or_default();
                        if !rec.is_owned_by(manifest.project.as_str(), env_slug) {
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
