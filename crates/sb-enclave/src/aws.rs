use crate::error::EnclaveError;
use crate::mem_secret::MemSecret;
use hmac::{Hmac, Mac};
use sb_proto::error::ErrorCode;
use sb_proto::plan::{AwsIdentitySummary, AwsObservedMetadata};
use sb_proto::types::AwsTarget;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::mem::DropGuard;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub const TAG_PROJECT: &str = "SecretBridgeProject";
pub const TAG_ENVIRONMENT: &str = "SecretBridgeEnvironment";

pub struct AwsCredentials {
    pub access_key_id: MemSecret,
    pub secret_access_key: MemSecret,
    pub session_token: Option<MemSecret>,
}

/// Metadata-only representation of an AWS Secrets Manager secret (never holds `SecretString`, S8).
#[derive(Debug, Clone)]
pub struct AwsSecretRecord {
    pub arn: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub versions: BTreeMap<String, Vec<String>>,
    pub modified: Option<String>,
    pub deleted: Option<String>,
}

impl AwsSecretRecord {
    pub fn to_observed(&self) -> AwsObservedMetadata {
        AwsObservedMetadata {
            arn: self.arn.clone(),
            versions: self.versions.clone(),
            modified: self.modified.clone(),
            deleted: self.deleted.clone(),
        }
    }

    pub fn is_owned_by(&self, project: &str, env_name: &str) -> bool {
        self.tags.get(TAG_PROJECT).map(String::as_str) == Some(project)
            && self.tags.get(TAG_ENVIRONMENT).map(String::as_str) == Some(env_name)
    }

    pub fn has_conflicting_owner(&self, project: &str, env_name: &str) -> bool {
        (self.tags.contains_key(TAG_PROJECT)
            && self.tags.get(TAG_PROJECT).map(String::as_str) != Some(project))
            || (self.tags.contains_key(TAG_ENVIRONMENT)
                && self.tags.get(TAG_ENVIRONMENT).map(String::as_str) != Some(env_name))
    }
}

pub trait AwsClient: Send + Sync {
    fn verify_caller_identity(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
    ) -> Result<AwsIdentitySummary, EnclaveError>;

    /// Returns `Ok(None)` when the secret does not exist (`ResourceNotFoundException`).
    fn describe_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
    ) -> Result<Option<AwsSecretRecord>, EnclaveError>;

    fn tag_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError>;

    fn create_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        name: &str,
        value: &MemSecret,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError>;

    fn update_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        value: &MemSecret,
    ) -> Result<(), EnclaveError>;

    fn delete_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        recovery_days: u8,
    ) -> Result<(), EnclaveError>;
}

// =========================================================================
// Direct HTTPS + AWS SigV4 Client (`rustls`, zero `aws` CLI or boto3)
// =========================================================================

pub struct SigV4AwsClient {
    agent: ureq::Agent,
    endpoint_override: Option<String>,
}

#[derive(Deserialize)]
struct DescribeSecretWireDto {
    #[serde(rename = "ARN")]
    arn: Option<String>,
    #[serde(rename = "Tags", default)]
    tags: Vec<AwsTagWireDto>,
    #[serde(rename = "VersionIdsToStages", default)]
    version_ids_to_stages: BTreeMap<String, Vec<String>>,
    #[serde(rename = "LastChangedDate")]
    last_changed_date: Option<serde_json::Value>,
    #[serde(rename = "DeletedDate")]
    deleted_date: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AwsTagWireDto {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Deserialize)]
struct AwsErrorWireDto {
    #[serde(rename = "__type")]
    error_type: Option<String>,
}

impl Default for SigV4AwsClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl SigV4AwsClient {
    pub fn new(endpoint_override: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self {
            agent,
            endpoint_override,
        }
    }

    fn secretsmanager_host_and_url(&self, region: &str) -> (String, String) {
        if let Some(base) = &self.endpoint_override {
            let trimmed = base.trim_end_matches('/');
            let host = trimmed
                .strip_prefix("https://")
                .or_else(|| trimmed.strip_prefix("http://"))
                .unwrap_or(trimmed)
                .to_string();
            (host, format!("{trimmed}/"))
        } else {
            let host = format!("secretsmanager.{region}.amazonaws.com");
            let url = format!("https://{host}/");
            (host, url)
        }
    }

    fn sts_host_and_url(&self, region: &str) -> (String, String) {
        if let Some(base) = &self.endpoint_override {
            let trimmed = base.trim_end_matches('/');
            let host = trimmed
                .strip_prefix("https://")
                .or_else(|| trimmed.strip_prefix("http://"))
                .unwrap_or(trimmed)
                .to_string();
            (host, format!("{trimmed}/"))
        } else {
            let host = format!("sts.{region}.amazonaws.com");
            let url = format!("https://{host}/");
            (host, url)
        }
    }

    fn call_secrets_manager(
        &self,
        creds: &AwsCredentials,
        region: &str,
        amz_target: &str,
        body_bytes: &[u8],
        allow_not_found: bool,
    ) -> Result<Option<String>, EnclaveError> {
        let (host, url) = self.secretsmanager_host_and_url(region);
        let (amz_date, date_stamp) = format_amz_timestamps(SystemTime::now());
        let payload_hash = hex::encode(Sha256::digest(body_bytes));

        let mut canonical_headers = BTreeMap::new();
        canonical_headers.insert(
            "content-type".to_string(),
            "application/x-amz-json-1.1".to_string(),
        );
        canonical_headers.insert("host".to_string(), host);
        canonical_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
        canonical_headers.insert("x-amz-date".to_string(), amz_date.clone());
        canonical_headers.insert("x-amz-target".to_string(), amz_target.to_string());
        if let Some(tok) = &creds.session_token {
            canonical_headers.insert(
                "x-amz-security-token".to_string(),
                tok.as_str()?.to_string(),
            );
        }

        let auth_header = sign_aws_v4(
            creds,
            "POST",
            "/",
            "",
            &canonical_headers,
            &payload_hash,
            &amz_date,
            &date_stamp,
            region,
            "secretsmanager",
        )?;

        let mut req = self
            .agent
            .post(&url)
            .set("Content-Type", "application/x-amz-json-1.1")
            .set("X-Amz-Date", &amz_date)
            .set("X-Amz-Content-Sha256", &payload_hash)
            .set("X-Amz-Target", amz_target)
            .set("Authorization", &auth_header);
        if let Some(tok) = &creds.session_token {
            req = req.set("X-Amz-Security-Token", tok.as_str()?);
        }

        match req.send_bytes(body_bytes) {
            Ok(resp) => {
                let text = resp.into_string().map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "AWS response read failed")
                })?;
                Ok(Some(text))
            }
            Err(ureq::Error::Status(status, resp)) => {
                let err_body = resp.into_string().unwrap_or_default();
                let parsed_code = serde_json::from_str::<AwsErrorWireDto>(&err_body)
                    .ok()
                    .and_then(|d| d.error_type)
                    .unwrap_or_default();
                let short_code = parsed_code
                    .rsplit_once('#')
                    .map(|(_, r)| r)
                    .unwrap_or(&parsed_code);
                if allow_not_found && short_code == "ResourceNotFoundException" {
                    return Ok(None);
                }
                let safe_code = match short_code {
                    "AccessDeniedException"
                    | "ResourceExistsException"
                    | "InvalidRequestException"
                    | "ResourceNotFoundException"
                    | "ExpiredTokenException" => short_code,
                    _ => "RequestFailed",
                };
                Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    format!("AWS Secrets Manager HTTP {status}: {safe_code}"),
                ))
            }
            Err(_) => Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "AWS network or TLS connection failed",
            )),
        }
    }
}

impl AwsClient for SigV4AwsClient {
    fn verify_caller_identity(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
    ) -> Result<AwsIdentitySummary, EnclaveError> {
        let region = target.region.as_str();
        let (host, url) = self.sts_host_and_url(region);
        let body = b"Action=GetCallerIdentity&Version=2011-06-15";
        let (amz_date, date_stamp) = format_amz_timestamps(SystemTime::now());
        let payload_hash = hex::encode(Sha256::digest(body));

        let mut canonical_headers = BTreeMap::new();
        canonical_headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        );
        canonical_headers.insert("host".to_string(), host);
        canonical_headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
        canonical_headers.insert("x-amz-date".to_string(), amz_date.clone());
        if let Some(tok) = &creds.session_token {
            canonical_headers.insert(
                "x-amz-security-token".to_string(),
                tok.as_str()?.to_string(),
            );
        }

        let auth_header = sign_aws_v4(
            creds,
            "POST",
            "/",
            "",
            &canonical_headers,
            &payload_hash,
            &amz_date,
            &date_stamp,
            region,
            "sts",
        )?;

        let mut req = self
            .agent
            .post(&url)
            .set(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .set("Accept", "application/json")
            .set("X-Amz-Date", &amz_date)
            .set("X-Amz-Content-Sha256", &payload_hash)
            .set("Authorization", &auth_header);
        if let Some(tok) = &creds.session_token {
            req = req.set("X-Amz-Security-Token", tok.as_str()?);
        }

        let resp_text = req
            .send_bytes(body)
            .map_err(|_| {
                EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "AWS STS GetCallerIdentity failed",
                )
            })?
            .into_string()
            .map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "AWS STS body read failed")
            })?;

        let (account, arn) = extract_sts_account_and_arn(&resp_text).ok_or_else(|| {
            EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "malformed STS identity response",
            )
        })?;

        if account != target.account_id.as_str() {
            return Err(EnclaveError::new(
                ErrorCode::OwnershipConflict,
                "AWS credentials resolve to a different account than target account_id",
            ));
        }
        Ok(AwsIdentitySummary { account, arn })
    }

    fn describe_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
    ) -> Result<Option<AwsSecretRecord>, EnclaveError> {
        let body = serde_json::to_vec(&serde_json::json!({ "SecretId": secret_id }))
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "json encode failed"))?;
        let Some(raw) = self.call_secrets_manager(
            creds,
            target.region.as_str(),
            "secretsmanager.DescribeSecret",
            &body,
            true,
        )?
        else {
            return Ok(None);
        };
        let dto: DescribeSecretWireDto = serde_json::from_str(&raw).map_err(|_| {
            EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "failed parsing DescribeSecret metadata",
            )
        })?;
        let tags = dto.tags.into_iter().map(|t| (t.key, t.value)).collect();
        Ok(Some(AwsSecretRecord {
            arn: dto.arn,
            tags,
            versions: dto.version_ids_to_stages,
            modified: dto.last_changed_date.map(|v| v.to_string()),
            deleted: dto.deleted_date.map(|v| v.to_string()),
        }))
    }

    fn tag_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError> {
        let wire_tags: Vec<serde_json::Value> = tags
            .iter()
            .map(|(k, v)| serde_json::json!({ "Key": k, "Value": v }))
            .collect();
        let body = serde_json::to_vec(&serde_json::json!({
            "SecretId": secret_id,
            "Tags": wire_tags,
        }))
        .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "json encode failed"))?;
        self.call_secrets_manager(
            creds,
            target.region.as_str(),
            "secretsmanager.TagResource",
            &body,
            false,
        )?;
        Ok(())
    }

    fn create_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        name: &str,
        value: &MemSecret,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError> {
        let secret_str = value.as_str()?;
        let wire_tags: Vec<serde_json::Value> = tags
            .iter()
            .map(|(k, v)| serde_json::json!({ "Key": k, "Value": v }))
            .collect();
        let mut obj = serde_json::json!({
            "Name": name,
            "SecretString": secret_str,
            "ClientRequestToken": Uuid::new_v4().to_string(),
            "Tags": wire_tags,
        });
        if let Some(kms) = &target.kms_key_id {
            obj["KmsKeyId"] = serde_json::Value::String(kms.clone());
        }
        let body = serde_json::to_vec(&obj)
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "json encode failed"))?;
        let body_guard = DropGuard::new(body, |mut b| b.zeroize());
        self.call_secrets_manager(
            creds,
            target.region.as_str(),
            "secretsmanager.CreateSecret",
            &body_guard,
            false,
        )?;
        Ok(())
    }

    fn update_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        value: &MemSecret,
    ) -> Result<(), EnclaveError> {
        let secret_str = value.as_str()?;
        let mut obj = serde_json::json!({
            "SecretId": secret_id,
            "SecretString": secret_str,
            "ClientRequestToken": Uuid::new_v4().to_string(),
        });
        if let Some(kms) = &target.kms_key_id {
            obj["KmsKeyId"] = serde_json::Value::String(kms.clone());
        }
        let body = serde_json::to_vec(&obj)
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "json encode failed"))?;
        let body_guard = DropGuard::new(body, |mut b| b.zeroize());
        self.call_secrets_manager(
            creds,
            target.region.as_str(),
            "secretsmanager.UpdateSecret",
            &body_guard,
            false,
        )?;
        Ok(())
    }

    fn delete_secret(
        &self,
        creds: &AwsCredentials,
        target: &AwsTarget,
        secret_id: &str,
        recovery_days: u8,
    ) -> Result<(), EnclaveError> {
        let body = serde_json::to_vec(&serde_json::json!({
            "SecretId": secret_id,
            "RecoveryWindowInDays": recovery_days,
        }))
        .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "json encode failed"))?;
        self.call_secrets_manager(
            creds,
            target.region.as_str(),
            "secretsmanager.DeleteSecret",
            &body,
            false,
        )?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_aws_v4(
    creds: &AwsCredentials,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers: &BTreeMap<String, String>,
    payload_hash_hex: &str,
    amz_date: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<String, EnclaveError> {
    let mut header_lines = String::new();
    let mut signed_names = Vec::with_capacity(canonical_headers.len());
    for (k, v) in canonical_headers {
        header_lines.push_str(k);
        header_lines.push(':');
        header_lines.push_str(v.trim());
        header_lines.push('\n');
        signed_names.push(k.as_str());
    }
    let signed_headers = signed_names.join(";");
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{header_lines}\n{signed_headers}\n{payload_hash_hex}"
    );
    let canonical_req_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_req_hash}");

    let mut k_secret = Zeroizing::new(Vec::with_capacity(4 + creds.secret_access_key.len()));
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(creds.secret_access_key.as_bytes());

    let k_date = Zeroizing::new(hmac_sha256(&k_secret, date_stamp.as_bytes())?);
    let k_region = Zeroizing::new(hmac_sha256(&*k_date, region.as_bytes())?);
    let k_service = Zeroizing::new(hmac_sha256(&*k_region, service.as_bytes())?);
    let k_signing = Zeroizing::new(hmac_sha256(&*k_service, b"aws4_request")?);
    let sig = hex::encode(hmac_sha256(&*k_signing, string_to_sign.as_bytes())?);

    let akid = creds.access_key_id.as_str()?;
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{credential_scope}, SignedHeaders={signed_headers}, Signature={sig}"
    ))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], EnclaveError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| EnclaveError::new(ErrorCode::CryptoFailure, "HMAC init failed"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

pub fn format_amz_timestamps(now: SystemTime) -> (String, String) {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hh = rem / 3_600;
    let mm = (rem % 3_600) / 60;
    let ss = rem % 60;
    let (year, month, day) = civil_from_days(days as i64);
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_date = format!("{date_stamp}T{hh:02}{mm:02}{ss:02}Z");
    (amz_date, date_stamp)
}

/// Howard Hinnant's civil-from-days algorithm (UTC proleptic Gregorian).
fn civil_from_days(z_raw: i64) -> (i64, u32, u32) {
    let z = z_raw + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

fn extract_sts_account_and_arn(body: &str) -> Option<(String, String)> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        let res = json
            .get("GetCallerIdentityResponse")
            .and_then(|r| r.get("GetCallerIdentityResult"))
            .unwrap_or(&json);
        if let (Some(acc), Some(arn)) = (
            res.get("Account").and_then(|v| v.as_str()),
            res.get("Arn").and_then(|v| v.as_str()),
        ) {
            return Some((acc.to_string(), arn.to_string()));
        }
    }
    let acc = extract_xml_tag(body, "Account")?;
    let arn = extract_xml_tag(body, "Arn")?;
    Some((acc, arn))
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

// =========================================================================
// Deterministic In-Memory AWS Client (for Unit/Integration Tests)
// =========================================================================

pub struct StoredAwsSecret {
    pub record: AwsSecretRecord,
    pub value: MemSecret,
}

struct MockAwsState {
    account_id: String,
    arn: String,
    secrets: BTreeMap<String, StoredAwsSecret>,
    fail_on_secret: Option<String>,
}

pub struct InMemoryAwsClient {
    state: Mutex<MockAwsState>,
}

impl InMemoryAwsClient {
    pub fn new(account_id: &str, arn: &str) -> Self {
        Self {
            state: Mutex::new(MockAwsState {
                account_id: account_id.to_string(),
                arn: arn.to_string(),
                secrets: BTreeMap::new(),
                fail_on_secret: None,
            }),
        }
    }

    pub fn set_fail_on_secret(&self, secret_name: Option<String>) {
        self.state.lock().unwrap().fail_on_secret = secret_name;
    }

    pub fn seed_existing(
        &self,
        name: &str,
        value: &str,
        tags: BTreeMap<String, String>,
        deleted: Option<String>,
    ) {
        let mut st = self.state.lock().unwrap();
        let arn = format!(
            "arn:aws:secretsmanager:us-west-2:{}:secret:{name}",
            st.account_id
        );
        st.secrets.insert(
            name.to_string(),
            StoredAwsSecret {
                record: AwsSecretRecord {
                    arn: Some(arn),
                    tags,
                    versions: BTreeMap::from([("v1".to_string(), vec!["AWSCURRENT".to_string()])]),
                    modified: Some("2026-11-18T00:00:00Z".into()),
                    deleted,
                },
                value: MemSecret::from_slice(value.as_bytes()).unwrap(),
            },
        );
    }

    pub fn stored_value_equals(&self, name: &str, expected: &[u8]) -> bool {
        let st = self.state.lock().unwrap();
        st.secrets
            .get(name)
            .is_some_and(|s| s.value.as_bytes() == expected && s.record.deleted.is_none())
    }
}

impl AwsClient for InMemoryAwsClient {
    fn verify_caller_identity(
        &self,
        _creds: &AwsCredentials,
        target: &AwsTarget,
    ) -> Result<AwsIdentitySummary, EnclaveError> {
        let st = self.state.lock().unwrap();
        if st.account_id != target.account_id.as_str() {
            return Err(EnclaveError::new(
                ErrorCode::OwnershipConflict,
                "AWS profile resolves to a different account than configured target",
            ));
        }
        Ok(AwsIdentitySummary {
            account: st.account_id.clone(),
            arn: st.arn.clone(),
        })
    }

    fn describe_secret(
        &self,
        _creds: &AwsCredentials,
        _target: &AwsTarget,
        secret_id: &str,
    ) -> Result<Option<AwsSecretRecord>, EnclaveError> {
        let st = self.state.lock().unwrap();
        Ok(st.secrets.get(secret_id).map(|s| s.record.clone()))
    }

    fn tag_secret(
        &self,
        _creds: &AwsCredentials,
        _target: &AwsTarget,
        secret_id: &str,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError> {
        let mut st = self.state.lock().unwrap();
        let Some(sec) = st.secrets.get_mut(secret_id) else {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "ResourceNotFoundException",
            ));
        };
        for (k, v) in tags {
            sec.record.tags.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    fn create_secret(
        &self,
        _creds: &AwsCredentials,
        target: &AwsTarget,
        name: &str,
        value: &MemSecret,
        tags: &BTreeMap<String, String>,
    ) -> Result<(), EnclaveError> {
        let mut st = self.state.lock().unwrap();
        if st.fail_on_secret.as_deref() == Some(name) {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "simulated AWS write failure",
            ));
        }
        let arn = format!(
            "arn:aws:secretsmanager:{}:{}:secret:{name}",
            target.region, st.account_id
        );
        st.secrets.insert(
            name.to_string(),
            StoredAwsSecret {
                record: AwsSecretRecord {
                    arn: Some(arn),
                    tags: tags.clone(),
                    versions: BTreeMap::from([("v1".to_string(), vec!["AWSCURRENT".to_string()])]),
                    modified: Some("2026-11-18T01:00:00Z".into()),
                    deleted: None,
                },
                value: MemSecret::from_slice(value.as_bytes())?,
            },
        );
        Ok(())
    }

    fn update_secret(
        &self,
        _creds: &AwsCredentials,
        _target: &AwsTarget,
        secret_id: &str,
        value: &MemSecret,
    ) -> Result<(), EnclaveError> {
        let mut st = self.state.lock().unwrap();
        if st.fail_on_secret.as_deref() == Some(secret_id) {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "simulated AWS update failure",
            ));
        }
        let Some(sec) = st.secrets.get_mut(secret_id) else {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "ResourceNotFoundException",
            ));
        };
        sec.value = MemSecret::from_slice(value.as_bytes())?;
        sec.record.modified = Some("2026-11-18T02:00:00Z".into());
        Ok(())
    }

    fn delete_secret(
        &self,
        _creds: &AwsCredentials,
        _target: &AwsTarget,
        secret_id: &str,
        recovery_days: u8,
    ) -> Result<(), EnclaveError> {
        if !(7..=30).contains(&recovery_days) {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "AWS recovery_days must be 7..=30",
            ));
        }
        let mut st = self.state.lock().unwrap();
        let Some(sec) = st.secrets.get_mut(secret_id) else {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "ResourceNotFoundException",
            ));
        };
        sec.record.deleted = Some(format!("scheduled+{recovery_days}d"));
        Ok(())
    }
}
