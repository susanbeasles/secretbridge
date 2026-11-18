use crate::error::ProtoError;
use crate::types::{AwsTarget, GitHubTarget, SecretName, Slug};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Default maximum validity window for a previewed plan (15 minutes).
pub const DEFAULT_PLAN_TTL_SECS: u64 = 900;

/// Produces deterministic RFC-8785-style canonical JSON bytes (sorted object keys, compact separators).
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let val = serde_json::to_value(value)
        .map_err(|e| ProtoError::Validation(format!("serialization failed: {e}")))?;
    let sorted = sort_json_value(val);
    serde_json::to_vec(&sorted)
        .map_err(|e| ProtoError::Validation(format!("canonical json failed: {e}")))
}

fn sort_json_value(val: Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut btree = serde_json::Map::new();
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (k, v) in entries {
                btree.insert(k, sort_json_value(v));
            }
            Value::Object(btree)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json_value).collect()),
        other => other,
    }
}

pub fn sha256_hex<T: Serialize>(value: &T) -> Result<String, ProtoError> {
    let bytes = canonical_json_bytes(value)?;
    let hash = Sha256::digest(&bytes);
    Ok(hex::encode(hash))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsIdentitySummary {
    pub account: String,
    pub arn: String,
}

/// Allowlisted AWS secret metadata only -- never includes `SecretString` or `SecretBinary` (S8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsObservedMetadata {
    pub arn: Option<String>,
    #[serde(default)]
    pub versions: BTreeMap<String, Vec<String>>,
    pub modified: Option<String>,
    pub deleted: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Github,
    Aws,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanAction {
    Create,
    Update,
    Set,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "lowercase")]
pub enum PlannedOp {
    Github {
        name: SecretName,
        action: PlanAction,
        destination: GitHubTarget,
        observed_updated_at: Option<String>,
    },
    Aws {
        name: SecretName,
        action: PlanAction,
        resource: String,
        destination: AwsTarget,
        observed: AwsObservedMetadata,
    },
}

impl PlannedOp {
    pub fn name(&self) -> &SecretName {
        match self {
            Self::Github { name, .. } | Self::Aws { name, .. } => name,
        }
    }

    pub fn action(&self) -> PlanAction {
        match self {
            Self::Github { action, .. } | Self::Aws { action, .. } => *action,
        }
    }

    pub fn target_kind(&self) -> TargetKind {
        match self {
            Self::Github { .. } => TargetKind::Github,
            Self::Aws { .. } => TargetKind::Aws,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPlan {
    pub version: u32,
    pub environment: Slug,
    pub manifest_digest: String,
    pub source_revision_digest: String,
    pub aws_identity: Option<AwsIdentitySummary>,
    pub issued_at_unix_secs: u64,
    pub operations: Vec<PlannedOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPlan {
    pub plan: UnsignedPlan,
    /// Ephemeral enclave HMAC-SHA256 binding `plan` to this enclave boot session (closes S4).
    pub plan_mac: String,
}

/// Per-boot enclave HMAC signer preventing forged or stale plans from executing in `apply`.
pub struct PlanSigner {
    key: Zeroizing<[u8; 32]>,
    ttl_secs: u64,
}

impl PlanSigner {
    pub fn new(key: [u8; 32], ttl_secs: u64) -> Self {
        Self {
            key: Zeroizing::new(key),
            ttl_secs,
        }
    }

    pub fn sign(&self, plan: UnsignedPlan) -> Result<SignedPlan, ProtoError> {
        let canonical = canonical_json_bytes(&plan)?;
        let mut mac = HmacSha256::new_from_slice(&*self.key)
            .map_err(|_| ProtoError::Crypto("invalid HMAC key".into()))?;
        mac.update(&canonical);
        let tag = hex::encode(mac.finalize().into_bytes());
        Ok(SignedPlan {
            plan,
            plan_mac: tag,
        })
    }

    pub fn verify(&self, signed: &SignedPlan, now_unix_secs: u64) -> Result<(), ProtoError> {
        let tag_bytes = hex::decode(&signed.plan_mac)
            .map_err(|_| ProtoError::StalePlan("malformed plan_mac".into()))?;
        let canonical = canonical_json_bytes(&signed.plan)?;
        let mut mac = HmacSha256::new_from_slice(&*self.key)
            .map_err(|_| ProtoError::Crypto("invalid HMAC key".into()))?;
        mac.update(&canonical);
        mac.verify_slice(&tag_bytes).map_err(|_| {
            ProtoError::StalePlan(
                "plan signature verification failed; preview sync again before applying".into(),
            )
        })?;

        if now_unix_secs < signed.plan.issued_at_unix_secs {
            return Err(ProtoError::StalePlan(
                "plan timestamp is in the future".into(),
            ));
        }
        if now_unix_secs.saturating_sub(signed.plan.issued_at_unix_secs) > self.ttl_secs {
            return Err(ProtoError::StalePlan(
                "plan has expired; preview sync again before applying".into(),
            ));
        }
        Ok(())
    }
}
