use crate::error::ProtoError;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

pub const SAFE_ITEM_CATEGORIES: &[&str] = &[
    "SECURE_NOTE",
    "API_CREDENTIAL",
    "PASSWORD",
    "DATABASE",
    "SERVER",
];

pub fn is_safe_item_category(category: &str) -> bool {
    SAFE_ITEM_CATEGORIES.contains(&category)
}

/// RFC-3986 unreserved percent-encoding for a single URL path segment.
/// Even after strict ASCII allowlist validation, every dynamic segment interpolated
/// into a GitHub REST URL passes through this encoder to defeat path/query injection (S2).
pub fn percent_encode_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(char::from(HEX_UPPER[(b >> 4) as usize]));
            out.push(char::from(HEX_UPPER[(b & 0x0F) as usize]));
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn reject_control_or_non_ascii(value: &str, field: &str) -> Result<(), ProtoError> {
    if value.is_empty() {
        return Err(ProtoError::Validation(format!("{field} must not be empty")));
    }
    if value.starts_with('-') {
        return Err(ProtoError::Validation(format!(
            "{field} must not start with '-'"
        )));
    }
    for b in value.bytes() {
        if !(0x20..=0x7E).contains(&b) {
            return Err(ProtoError::Validation(format!(
                "{field} must contain only printable 7-bit ASCII characters"
            )));
        }
    }
    Ok(())
}

fn validate_manifest_identifier(value: &str, field: &str) -> Result<(), ProtoError> {
    if value.is_empty() || value.len() > 128 {
        return Err(ProtoError::Validation(format!(
            "{field} must be 1..=128 characters"
        )));
    }
    if value.starts_with('-') || value == "." || value == ".." || value.contains("..") {
        return Err(ProtoError::Validation(format!(
            "{field} cannot start with '-' or contain '..'"
        )));
    }
    for b in value.bytes() {
        if !(0x21..=0x7E).contains(&b)
            || matches!(
                b,
                b'/' | b'\\' | b'?' | b'#' | b'%' | b'"' | b'\'' | b'`' | b'$'
            )
        {
            return Err(ProtoError::Validation(format!(
                "{field} contains whitespace or forbidden characters"
            )));
        }
    }
    Ok(())
}

macro_rules! impl_validated_str_serde {
    ($ty:ident) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse::<$ty>().map_err(de::Error::custom)
            }
        }
    };
}

/// Strict ASCII identifier slug (`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`), rejecting `.` and `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slug(String);

impl Slug {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn url_encoded(&self) -> String {
        percent_encode_segment(&self.0)
    }
}

impl FromStr for Slug {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 128 {
            return Err(ProtoError::Validation("invalid slug length".into()));
        }
        if s == "." || s == ".." || s.contains("..") {
            return Err(ProtoError::Validation("slug cannot contain '..'".into()));
        }
        let mut bytes = s.bytes();
        let Some(first) = bytes.next() else {
            return Err(ProtoError::Validation("empty slug".into()));
        };
        if !first.is_ascii_alphanumeric() {
            return Err(ProtoError::Validation(
                "slug must start with an ASCII letter or digit".into(),
            ));
        }
        if !bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')) {
            return Err(ProtoError::Validation(
                "slug contains invalid characters".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(Slug);

/// Application secret variable name (`^[A-Z_][A-Z0-9_]{0,127}$`, never starting with `GITHUB_`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn url_encoded(&self) -> String {
        percent_encode_segment(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 128 {
            return Err(ProtoError::Validation(
                "secret name must be 1..=128 characters".into(),
            ));
        }
        if s.starts_with("GITHUB_") {
            return Err(ProtoError::Validation(
                "secret names cannot start with reserved prefix GITHUB_".into(),
            ));
        }
        let mut bytes = s.bytes();
        let Some(first) = bytes.next() else {
            return Err(ProtoError::Validation("empty secret name".into()));
        };
        if !(first.is_ascii_uppercase() || first == b'_') {
            return Err(ProtoError::Validation(
                "secret names must be uppercase ASCII identifiers".into(),
            ));
        }
        if !bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
            return Err(ProtoError::Validation(
                "secret names must contain only A-Z, 0-9, and _".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(SecretName);

/// Validated 1Password reference (`op://<vault>/<item>/[<section>/]<field>`).
/// Rejects shell/dotenv metacharacters, quotes, backslashes, control chars, and `..` (S7, S10).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpRef {
    raw: String,
    vault: String,
    item: String,
    section: Option<String>,
    field: String,
}

impl OpRef {
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }

    pub fn item(&self) -> &str {
        &self.item
    }

    pub fn section(&self) -> Option<&str> {
        self.section.as_deref()
    }

    pub fn field(&self) -> &str {
        &self.field
    }
}

impl FromStr for OpRef {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 512 {
            return Err(ProtoError::Validation("op:// reference is too long".into()));
        }
        let Some(rest) = s.strip_prefix("op://") else {
            return Err(ProtoError::Validation(
                "reference must start with op://".into(),
            ));
        };
        for b in rest.bytes() {
            if !(0x20..=0x7E).contains(&b)
                || matches!(b, b'"' | b'\'' | b'\\' | b'$' | b'`' | b'?' | b'#' | b'%')
            {
                return Err(ProtoError::Validation(
                    "op:// reference contains forbidden characters".into(),
                ));
            }
        }
        let parts: Vec<&str> = rest.split('/').collect();
        if !(3..=4).contains(&parts.len()) {
            return Err(ProtoError::Validation(
                "op:// reference must have 3 or 4 path segments".into(),
            ));
        }
        for part in &parts {
            if part.is_empty() || *part == "." || part.contains("..") || part.starts_with('-') {
                return Err(ProtoError::Validation(
                    "op:// reference contains invalid path segment".into(),
                ));
            }
        }
        let (vault, item, section, field) = if parts.len() == 3 {
            (
                parts[0].to_string(),
                parts[1].to_string(),
                None,
                parts[2].to_string(),
            )
        } else {
            (
                parts[0].to_string(),
                parts[1].to_string(),
                Some(parts[2].to_string()),
                parts[3].to_string(),
            )
        };
        Ok(Self {
            raw: s.to_string(),
            vault,
            item,
            section,
            field,
        })
    }
}

impl fmt::Display for OpRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for OpRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for OpRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<OpRef>().map_err(de::Error::custom)
    }
}

/// Strict RFC-1123 ASCII hostname (`github.com` or GHES hostname; no scheme, port, or leading `-`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitHubHost(String);

impl Default for GitHubHost {
    fn default() -> Self {
        Self("github.com".to_string())
    }
}

impl GitHubHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_default_github_com(&self) -> bool {
        self.0 == "github.com"
    }
}

impl FromStr for GitHubHost {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 253 {
            return Err(ProtoError::Validation("invalid GitHub hostname".into()));
        }
        if s.parse::<std::net::IpAddr>().is_ok() {
            return Err(ProtoError::Validation(
                "GitHub hostname must not be an IP address literal".into(),
            ));
        }
        let lower = s.to_ascii_lowercase();
        if lower == "localhost" {
            return Err(ProtoError::Validation(
                "GitHub hostname cannot be localhost".into(),
            ));
        }
        let labels: Vec<&str> = lower.split('.').collect();
        if labels.len() < 2 {
            return Err(ProtoError::Validation(
                "GitHub hostname must be a qualified domain".into(),
            ));
        }
        for label in &labels {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(ProtoError::Validation(
                    "invalid GitHub hostname label".into(),
                ));
            }
        }
        let tld = labels[labels.len() - 1];
        // RFC 1123 / IANA TLDs must begin with an ASCII letter; rejecting leading digits
        // blocks decimal dotted-quads, octal IPv4, and hex IPv4 (`0xa9.0xfe.0xa9.0xfe`, `0x7f.0.0.0x1`).
        if tld.as_bytes()[0].is_ascii_digit() {
            return Err(ProtoError::Validation(
                "GitHub hostname top-level label must start with an ASCII letter".into(),
            ));
        }
        if matches!(
            tld,
            "localhost"
                | "local"
                | "internal"
                | "arpa"
                | "home"
                | "lan"
                | "corp"
                | "invalid"
                | "onion"
        ) {
            return Err(ProtoError::Validation(
                "GitHub hostname uses a reserved or local-only TLD".into(),
            ));
        }
        Ok(Self(lower))
    }
}

impl_validated_str_serde!(GitHubHost);

/// Strict `owner/repo` pair where both segments are pure ASCII slugs without `.` or `..` (S2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitHubRepoFullName {
    raw: String,
    owner: Slug,
    repo: Slug,
}

impl GitHubRepoFullName {
    pub fn owner(&self) -> &Slug {
        &self.owner
    }

    pub fn repo(&self) -> &Slug {
        &self.repo
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl FromStr for GitHubRepoFullName {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((owner_raw, repo_raw)) = s.split_once('/') else {
            return Err(ProtoError::Validation(
                "GitHub repository must have format owner/repo".into(),
            ));
        };
        if repo_raw.contains('/') {
            return Err(ProtoError::Validation(
                "GitHub repository must have exactly one '/'".into(),
            ));
        }
        let owner: Slug = owner_raw.parse()?;
        let repo: Slug = repo_raw.parse()?;
        Ok(Self {
            raw: format!("{owner}/{repo}"),
            owner,
            repo,
        })
    }
}

impl fmt::Display for GitHubRepoFullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for GitHubRepoFullName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for GitHubRepoFullName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<GitHubRepoFullName>().map_err(de::Error::custom)
    }
}

/// Validated GitHub deployment environment name (printable ASCII, <= 255 chars, no `.`/`..` or control chars).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitHubEnvName(String);

impl GitHubEnvName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn url_encoded(&self) -> String {
        percent_encode_segment(&self.0)
    }
}

impl FromStr for GitHubEnvName {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        reject_control_or_non_ascii(s, "GitHub environment")?;
        if s.len() > 255
            || s == "."
            || s == ".."
            || s.contains("..")
            || s.contains('/')
            || s.contains('\\')
        {
            return Err(ProtoError::Validation(
                "GitHub environment name cannot contain '/', '\\', or '..'".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(GitHubEnvName);

/// Validated AWS region (`^[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]*$`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AwsRegion {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3
            || parts[0].len() != 2
            || !parts[0].bytes().all(|b| b.is_ascii_lowercase())
        {
            return Err(ProtoError::Validation("invalid AWS region".into()));
        }
        let last = parts[parts.len() - 1];
        if last.is_empty() || last.starts_with('0') || !last.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ProtoError::Validation("invalid AWS region number".into()));
        }
        for mid in &parts[1..parts.len() - 1] {
            if mid.is_empty() || !mid.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(ProtoError::Validation("invalid AWS region segment".into()));
            }
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(AwsRegion);

/// Validated 12-digit numeric AWS account ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for AwsAccountId {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 12 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ProtoError::Validation(
                "AWS account_id must have 12 ASCII digits".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(AwsAccountId);

/// Validated AWS Secrets Manager prefix ending in `/`, length 2..=400, no `..` or `//`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AwsSecretPrefix(String);

impl AwsSecretPrefix {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn full_secret_name(&self, secret: &SecretName) -> String {
        format!("{}{}", self.0, secret.as_str())
    }
}

impl FromStr for AwsSecretPrefix {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 || s.len() > 400 || !s.ends_with('/') || s.starts_with('/') {
            return Err(ProtoError::Validation(
                "AWS prefix must be 2..=400 chars, not start with '/', and end with '/'".into(),
            ));
        }
        if s.contains("..") || s.contains("//") {
            return Err(ProtoError::Validation(
                "AWS prefix cannot contain '..' or '//'".into(),
            ));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'=' | b'.' | b'@' | b'-')
        }) {
            return Err(ProtoError::Validation(
                "AWS prefix contains invalid characters".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(AwsSecretPrefix);

/// AWS Secrets Manager deletion recovery window (`7..=30` days, S11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryDays(u8);

impl Default for RecoveryDays {
    fn default() -> Self {
        Self(30)
    }
}

impl RecoveryDays {
    pub fn new(days: u8) -> Result<Self, ProtoError> {
        if !(7..=30).contains(&days) {
            return Err(ProtoError::Validation(
                "AWS recovery_days must be between 7 and 30".into(),
            ));
        }
        Ok(Self(days))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

impl Serialize for RecoveryDays {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for RecoveryDays {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let days = u8::deserialize(deserializer)?;
        RecoveryDays::new(days).map_err(de::Error::custom)
    }
}

/// Verified 40-hex-character lowercase commit SHA (e.g. for `1Password/load-secrets-action`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitSha40(String);

impl CommitSha40 {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CommitSha40 {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProtoError::Validation(
                "expected 40-character lowercase hex commit SHA".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl_validated_str_serde!(CommitSha40);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretState {
    #[default]
    Present,
    Absent,
}

fn default_true() -> bool {
    true
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<OpRef>,
    #[serde(default)]
    pub state: SecretState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Slug>,
    #[serde(default = "default_true")]
    pub github: bool,
    #[serde(default = "default_true")]
    pub aws: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_unmanaged_github_delete: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_unmanaged_github_overwrite: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitHubScope {
    Repository,
    Environment,
    Organization,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGitHubTarget {
    scope: GitHubScope,
    #[serde(default)]
    host: GitHubHost,
    repository: Option<GitHubRepoFullName>,
    organization: Option<Slug>,
    environment: Option<GitHubEnvName>,
    repositories: Option<Vec<Slug>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGitHubTarget")]
pub struct GitHubTarget {
    pub scope: GitHubScope,
    #[serde(default)]
    pub host: GitHubHost,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<GitHubRepoFullName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Slug>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<GitHubEnvName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repositories: Option<Vec<Slug>>,
}

impl TryFrom<RawGitHubTarget> for GitHubTarget {
    type Error = ProtoError;

    fn try_from(raw: RawGitHubTarget) -> Result<Self, Self::Error> {
        let target = Self {
            scope: raw.scope,
            host: raw.host,
            repository: raw.repository,
            organization: raw.organization,
            environment: raw.environment,
            repositories: raw.repositories,
        };
        target.validate()?;
        Ok(target)
    }
}

impl GitHubTarget {
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self.scope {
            GitHubScope::Repository => {
                if self.repository.is_none() {
                    return Err(ProtoError::Validation(
                        "repository scope requires 'repository'".into(),
                    ));
                }
                if self.organization.is_some()
                    || self.environment.is_some()
                    || self.repositories.is_some()
                {
                    return Err(ProtoError::Validation(
                        "repository scope forbids organization/environment/repositories fields"
                            .into(),
                    ));
                }
            }
            GitHubScope::Environment => {
                if self.repository.is_none() || self.environment.is_none() {
                    return Err(ProtoError::Validation(
                        "environment scope requires 'repository' and 'environment'".into(),
                    ));
                }
                if self.organization.is_some() || self.repositories.is_some() {
                    return Err(ProtoError::Validation(
                        "environment scope forbids organization/repositories fields".into(),
                    ));
                }
            }
            GitHubScope::Organization => {
                if self.organization.is_none() {
                    return Err(ProtoError::Validation(
                        "organization scope requires 'organization'".into(),
                    ));
                }
                let Some(repos) = &self.repositories else {
                    return Err(ProtoError::Validation(
                        "organization secrets require an explicit nonempty repository allowlist"
                            .into(),
                    ));
                };
                if repos.is_empty() {
                    return Err(ProtoError::Validation(
                        "organization repository allowlist cannot be empty".into(),
                    ));
                }
                if self.repository.is_some() || self.environment.is_some() {
                    return Err(ProtoError::Validation(
                        "organization scope forbids repository/environment fields".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn owner_or_org_lower(&self) -> Result<String, ProtoError> {
        self.validate()?;
        match self.scope {
            GitHubScope::Organization => Ok(self
                .organization
                .as_ref()
                .expect("validated")
                .as_str()
                .to_ascii_lowercase()),
            GitHubScope::Repository | GitHubScope::Environment => Ok(self
                .repository
                .as_ref()
                .expect("validated")
                .owner()
                .as_str()
                .to_ascii_lowercase()),
        }
    }

    pub fn normalized_destination_key(
        &self,
        secret_name: &SecretName,
    ) -> Result<(String, GitHubScope, String, String, String), ProtoError> {
        self.validate()?;
        let scope_target = match self.scope {
            GitHubScope::Organization => self
                .organization
                .as_ref()
                .expect("validated")
                .as_str()
                .to_ascii_lowercase(),
            GitHubScope::Repository | GitHubScope::Environment => self
                .repository
                .as_ref()
                .expect("validated")
                .as_str()
                .to_ascii_lowercase(),
        };
        let gh_env = self
            .environment
            .as_ref()
            .map(|e| e.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        Ok((
            self.host.as_str().to_ascii_lowercase(),
            self.scope,
            scope_target,
            gh_env,
            secret_name.as_str().to_ascii_lowercase(),
        ))
    }

    /// Safe REST endpoint path (leading slash omitted, every dynamic segment percent-encoded).
    pub fn secrets_endpoint_path(&self) -> Result<String, ProtoError> {
        self.validate()?;
        match self.scope {
            GitHubScope::Organization => {
                let org = self.organization.as_ref().expect("validated");
                Ok(format!("orgs/{}/actions/secrets", org.url_encoded()))
            }
            GitHubScope::Environment => {
                let repo = self.repository.as_ref().expect("validated");
                let env = self.environment.as_ref().expect("validated");
                Ok(format!(
                    "repos/{}/{}/environments/{}/secrets",
                    repo.owner().url_encoded(),
                    repo.repo().url_encoded(),
                    env.url_encoded()
                ))
            }
            GitHubScope::Repository => {
                let repo = self.repository.as_ref().expect("validated");
                Ok(format!(
                    "repos/{}/{}/actions/secrets",
                    repo.owner().url_encoded(),
                    repo.repo().url_encoded()
                ))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAwsTarget {
    profile: Option<Slug>,
    region: AwsRegion,
    account_id: AwsAccountId,
    prefix: AwsSecretPrefix,
    kms_key_id: Option<String>,
    #[serde(default)]
    recovery_days: RecoveryDays,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawAwsTarget")]
pub struct AwsTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Slug>,
    pub region: AwsRegion,
    pub account_id: AwsAccountId,
    pub prefix: AwsSecretPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub recovery_days: RecoveryDays,
}

impl TryFrom<RawAwsTarget> for AwsTarget {
    type Error = ProtoError;

    fn try_from(raw: RawAwsTarget) -> Result<Self, Self::Error> {
        let target = Self {
            profile: raw.profile,
            region: raw.region,
            account_id: raw.account_id,
            prefix: raw.prefix,
            kms_key_id: raw.kms_key_id,
            recovery_days: raw.recovery_days,
        };
        target.validate()?;
        Ok(target)
    }
}

impl AwsTarget {
    pub fn validate(&self) -> Result<(), ProtoError> {
        if let Some(kms) = &self.kms_key_id {
            reject_control_or_non_ascii(kms, "kms_key_id")?;
            if kms.len() > 256 || kms.contains(char::is_whitespace) {
                return Err(ProtoError::Validation("invalid kms_key_id".into()));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironmentConfig {
    vault: String,
    #[serde(default)]
    secrets: BTreeMap<SecretName, SecretSpec>,
    github: Option<GitHubTarget>,
    aws: Option<AwsTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawEnvironmentConfig")]
pub struct EnvironmentConfig {
    pub vault: String,
    #[serde(default)]
    pub secrets: BTreeMap<SecretName, SecretSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github: Option<GitHubTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsTarget>,
}

impl EnvironmentConfig {
    pub fn validate(&self) -> Result<(), ProtoError> {
        validate_manifest_identifier(&self.vault, "vault")?;
        if let Some(gh) = &self.github {
            gh.validate()?;
        }
        if let Some(aws) = &self.aws {
            aws.validate()?;
        }
        for (secret_name, spec) in &self.secrets {
            if spec.state == SecretState::Present && spec.r#ref.is_none() {
                return Err(ProtoError::Validation(format!(
                    "{secret_name}: present secret requires op:// reference"
                )));
            }
            if let Some(op_ref) = &spec.r#ref
                && op_ref.vault() != self.vault
            {
                return Err(ProtoError::Validation(format!(
                    "{secret_name}: reference vault '{}' must match environment vault '{}'",
                    op_ref.vault(),
                    self.vault
                )));
            }
        }
        Ok(())
    }
}

impl TryFrom<RawEnvironmentConfig> for EnvironmentConfig {
    type Error = ProtoError;

    fn try_from(raw: RawEnvironmentConfig) -> Result<Self, Self::Error> {
        let cfg = Self {
            vault: raw.vault,
            secrets: raw.secrets,
            github: raw.github,
            aws: raw.aws,
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: u32,
    project: Slug,
    account: String,
    environments: BTreeMap<Slug, EnvironmentConfig>,
}

/// Root project manifest (`secretbridge.json`).
/// Note `#[serde(try_from = "RawManifest")]` + `#[serde(deny_unknown_fields)]`:
/// any `tools` block from v0.1.0 is rejected (S1) and `.validate()` runs on every deserialize (C5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawManifest")]
pub struct Manifest {
    pub version: u32,
    pub project: Slug,
    pub account: String,
    pub environments: BTreeMap<Slug, EnvironmentConfig>,
}

impl TryFrom<RawManifest> for Manifest {
    type Error = ProtoError;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        let manifest = Self {
            version: raw.version,
            project: raw.project,
            account: raw.account,
            environments: raw.environments,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}

impl Manifest {
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.version != 1 && self.version != 2 {
            return Err(ProtoError::Validation(
                "manifest version must be 1 or 2".into(),
            ));
        }
        validate_manifest_identifier(&self.account, "account")?;
        if self.environments.is_empty() {
            return Err(ProtoError::Validation(
                "at least one environment is required".into(),
            ));
        }

        let mut vaults_seen_norm = BTreeSet::new();
        let mut gh_destinations = BTreeSet::new();
        let mut aws_destinations = BTreeSet::new();

        for (env_name, env) in &self.environments {
            env.validate().map_err(|e| {
                ProtoError::Validation(format!("environment '{env_name}' invalid: {e}"))
            })?;
            let norm_vault = env.vault.to_ascii_lowercase();
            if !vaults_seen_norm.insert(norm_vault) {
                return Err(ProtoError::Validation(
                    "each environment must use a separate vault".into(),
                ));
            }

            for (secret_name, spec) in &env.secrets {
                if let Some(gh) = &env.github
                    && spec.github
                {
                    let dest_key = gh.normalized_destination_key(secret_name)?;
                    if !gh_destinations.insert(dest_key) {
                        return Err(ProtoError::Validation(
                            "environment collision in GitHub targets".into(),
                        ));
                    }
                }

                if let Some(aws) = &env.aws
                    && spec.aws
                {
                    let dest_key = (
                        aws.account_id.as_str().to_string(),
                        aws.region.as_str().to_string(),
                        aws.prefix.full_secret_name(secret_name),
                    );
                    if !aws_destinations.insert(dest_key) {
                        return Err(ProtoError::Validation(
                            "environment collision in AWS targets".into(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn from_json_str(raw: &str) -> Result<Self, ProtoError> {
        let manifest: Self = serde_json::from_str(raw)
            .map_err(|e| ProtoError::Validation(format!("invalid manifest JSON: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Binds or updates a secret reference while preserving existing `github`/`aws` flags (fixes B7).
    pub fn bind_secret(
        &mut self,
        env_name: &Slug,
        name: SecretName,
        op_ref: OpRef,
        group: Option<Slug>,
        github: Option<bool>,
        aws: Option<bool>,
    ) -> Result<(), ProtoError> {
        let Some(env) = self.environments.get_mut(env_name) else {
            return Err(ProtoError::Validation(format!(
                "unknown environment '{env_name}'"
            )));
        };
        if op_ref.vault() != env.vault {
            return Err(ProtoError::Validation(format!(
                "{name}: reference must belong to environment vault '{}'",
                env.vault
            )));
        }
        let prev = env.secrets.get(&name);
        let next_group = group.or_else(|| prev.and_then(|p| p.group.clone()));
        let next_github = github.unwrap_or_else(|| prev.map(|p| p.github).unwrap_or(true));
        let next_aws = aws.unwrap_or_else(|| prev.map(|p| p.aws).unwrap_or(true));
        let next_allow_delete = prev
            .map(|p| p.allow_unmanaged_github_delete)
            .unwrap_or(false);
        let next_allow_overwrite = prev
            .map(|p| p.allow_unmanaged_github_overwrite)
            .unwrap_or(false);
        env.secrets.insert(
            name,
            SecretSpec {
                r#ref: Some(op_ref),
                state: SecretState::Present,
                group: next_group,
                github: next_github,
                aws: next_aws,
                allow_unmanaged_github_delete: next_allow_delete,
                allow_unmanaged_github_overwrite: next_allow_overwrite,
            },
        );
        self.validate()
    }

    pub fn mark_secret_absent(
        &mut self,
        env_name: &Slug,
        name: &SecretName,
    ) -> Result<(), ProtoError> {
        let Some(env) = self.environments.get_mut(env_name) else {
            return Err(ProtoError::Validation(format!(
                "unknown environment '{env_name}'"
            )));
        };
        let Some(spec) = env.secrets.get_mut(name) else {
            return Err(ProtoError::Validation("binding does not exist".into()));
        };
        spec.state = SecretState::Absent;
        self.validate()
    }
}
