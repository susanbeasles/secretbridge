use crate::error::{ProtoError, SanitizedError};
use crate::plan::{PlannedOp, SignedPlan, TargetKind};
use crate::types::{CommitSha40, Manifest, OpRef, SecretName, SecretSpec, Slug};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateKind {
    Env,
    WorkflowNative,
    Workflow1password,
    Terraform,
    Cdk,
    Cloudformation,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretCharset {
    #[default]
    AlphanumericSymbols,
    Alphanumeric,
    HexLower,
    Base64Url,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGenerateSpec {
    length: u16,
    #[serde(default)]
    charset: SecretCharset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGenerateSpec")]
pub struct GenerateSpec {
    pub length: u16,
    #[serde(default)]
    pub charset: SecretCharset,
}

impl TryFrom<RawGenerateSpec> for GenerateSpec {
    type Error = ProtoError;

    fn try_from(raw: RawGenerateSpec) -> Result<Self, Self::Error> {
        if !(16..=1024).contains(&raw.length) {
            return Err(ProtoError::Validation(
                "generated secret length must be between 16 and 1024 characters".into(),
            ));
        }
        Ok(Self {
            length: raw.length,
            charset: raw.charset,
        })
    }
}

impl Default for GenerateSpec {
    fn default() -> Self {
        Self {
            length: 40,
            charset: SecretCharset::AlphanumericSymbols,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureTarget {
    NewItem {
        title: String,
        field_name: SecretName,
        #[serde(default)]
        tags: Vec<String>,
    },
    ExistingItemNewField {
        item_id: String,
        field_name: SecretName,
    },
    ReplaceFieldValue {
        item_id: String,
        field_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureInterceptMode {
    /// Active key event swallowed before foreground app touched system clipboard.
    ZeroPasteboard,
    /// Fallback 1ms clipboard snapshot-capture-restore triggered (e.g. web Copy icon button).
    PasteboardFallback,
}

/// Write-only session credentials and destination allowlists sealed into enclave memory over `Noise_IK`.
/// Zeroized on drop; never echoed in any response or log.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct SessionCredentialsInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_service_account_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_secret_access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_session_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_github_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_github_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_aws_account_ids: Vec<String>,
}

impl std::fmt::Debug for SessionCredentialsInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCredentialsInput")
            .field("op_service_account_token", &"[REDACTED]")
            .field("github_token", &"[REDACTED]")
            .field("aws_access_key_id", &"[REDACTED]")
            .field("aws_secret_access_key", &"[REDACTED]")
            .field("aws_session_token", &"[REDACTED]")
            .field("allowed_github_hosts", &self.allowed_github_hosts)
            .field("allowed_github_owners", &self.allowed_github_owners)
            .field("allowed_aws_account_ids", &self.allowed_aws_account_ids)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EnclaveRequest {
    ConfigureSession {
        credentials: SessionCredentialsInput,
    },
    Capabilities,
    Doctor {
        #[serde(default)]
        manifest: Option<Manifest>,
    },
    ValidateConfig {
        config: Manifest,
    },
    Vaults,
    VaultCreate {
        name: String,
    },
    Items {
        manifest: Manifest,
        environment: Slug,
    },
    Fields {
        manifest: Manifest,
        environment: Slug,
        item: String,
    },
    /// Generates a new secret via OS CSPRNG strictly inside the guest VM (0% host exposure).
    GenerateSecret {
        manifest: Manifest,
        environment: Slug,
        target: CaptureTarget,
        #[serde(default)]
        spec: GenerateSpec,
    },
    /// Mints a single-use 15s TTL X25519 capture key (`pk_capture`) inside the enclave.
    BeginCapture {
        manifest: Manifest,
        environment: Slug,
        target: CaptureTarget,
    },
    /// Delivers the X25519-sealed secret captured by `sb-host` Armed Copy Hijack.
    CompleteCapture {
        capture_id: String,
        sealed_secret_b64: String,
        mode: CaptureInterceptMode,
    },
    EditMetadata {
        manifest: Manifest,
        environment: Slug,
        item: String,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        tags: Option<Vec<String>>,
        #[serde(default)]
        remove_field_id: Option<String>,
    },
    Archive {
        manifest: Manifest,
        environment: Slug,
        item: String,
    },
    Move {
        manifest: Manifest,
        environment: Slug,
        item: String,
        destination: Slug,
    },
    Bindings {
        manifest: Manifest,
        environment: Slug,
    },
    AdoptAws {
        manifest: Manifest,
        environment: Slug,
        name: SecretName,
        #[serde(default)]
        confirm_unmanaged: bool,
    },
    PrepareGithub {
        manifest: Manifest,
        environment: Slug,
    },
    Plan {
        manifest: Manifest,
        environment: Slug,
    },
    Apply {
        manifest: Manifest,
        signed_plan: SignedPlan,
    },
    Template {
        manifest: Manifest,
        environment: Slug,
        kind: TemplateKind,
        #[serde(default)]
        action_sha: Option<CommitSha40>,
    },
}

// =========================================================================
// Metadata-Only Response DTOs (compile-time guarantee: zero secret values!)
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccountCapabilities {
    pub authenticated: bool,
    pub can_create_vaults: bool,
    pub accessible_vault_ids: Vec<String>,
    pub read_only_vault_ids: Vec<String>,
    pub notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSummary {
    pub id: String,
    pub name: String,
    pub writable: bool,
    pub created_by_service_account: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSummary {
    pub id: String,
    pub label: String,
    pub field_type: String,
    pub r#ref: OpRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemFieldsResponse {
    pub id: String,
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
    pub fields: Vec<FieldSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMutationReceipt {
    pub item_id: String,
    pub title: String,
    pub field_id: String,
    pub r#ref: OpRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intercept_mode: Option<CaptureInterceptMode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureChallenge {
    pub capture_id: String,
    pub pk_capture_b64: String,
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingEntry {
    pub name: SecretName,
    pub spec: SecretSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorEntry {
    pub subsystem: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpStepResult {
    pub target: TargetKind,
    pub name: SecretName,
    pub action: crate::plan::PlanAction,
    pub succeeded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReport {
    pub complete: bool,
    pub results: Vec<OpStepResult>,
    pub pending: Vec<PlannedOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnclaveResult {
    SessionConfigured {
        has_op_token: bool,
        has_github_token: bool,
        has_aws_credentials: bool,
    },
    Capabilities(ServiceAccountCapabilities),
    Doctor {
        entries: Vec<DoctorEntry>,
    },
    ConfigValid {
        valid: bool,
        manifest_digest: String,
    },
    Vaults {
        vaults: Vec<VaultSummary>,
    },
    VaultCreated(VaultSummary),
    Items {
        items: Vec<ItemSummary>,
    },
    Fields(ItemFieldsResponse),
    SecretStored(SecretMutationReceipt),
    CaptureStarted(CaptureChallenge),
    ItemUpdated {
        id: String,
        title: String,
    },
    ItemArchived {
        archived: String,
    },
    ItemMoved {
        moved: String,
        new_item_id: String,
        destination: Slug,
        notice: String,
    },
    Bindings {
        bindings: Vec<BindingEntry>,
    },
    AwsAdopted {
        adopted: String,
        notice: String,
    },
    GithubPrepared {
        prepared: String,
        notice: String,
    },
    Planned(SignedPlan),
    Applied(ApplyReport),
    TemplateRendered {
        content: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnclaveResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<EnclaveResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SanitizedError>,
}

impl EnclaveResponse {
    pub fn ok(result: EnclaveResult) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(error: SanitizedError) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(error),
        }
    }
}
