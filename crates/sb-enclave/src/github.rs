use crate::error::EnclaveError;
use crate::mem_secret::MemSecret;
use sb_proto::crypto::seal_base64;
use sb_proto::error::ErrorCode;
use sb_proto::types::{CommitSha40, GitHubScope, GitHubTarget, SecretName};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GitHubPublicKey {
    pub key_id: String,
    pub key_b64: String,
}

pub trait GitHubClient: Send + Sync {
    fn check_authenticated_user(
        &self,
        token: &MemSecret,
        host: &str,
    ) -> Result<String, EnclaveError>;

    fn prepare_environment(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<String, EnclaveError>;

    fn list_secret_timestamps(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<BTreeMap<String, Option<String>>, EnclaveError>;

    fn get_encryption_target(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<(GitHubPublicKey, Vec<u64>), EnclaveError>;

    fn put_secret(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
        value: &MemSecret,
        pub_key: &GitHubPublicKey,
        selected_repo_ids: &[u64],
    ) -> Result<(), EnclaveError>;

    fn delete_secret(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
    ) -> Result<(), EnclaveError>;

    fn resolve_load_secrets_action_sha(
        &self,
        token: Option<&MemSecret>,
    ) -> Result<CommitSha40, EnclaveError>;
}

// =========================================================================
// Direct HTTPS GitHub REST Client (`rustls`, zero `gh` CLI)
// =========================================================================

pub struct RestGitHubClient {
    agent: ureq::Agent,
    base_url_override: Option<String>,
}

#[derive(Deserialize)]
struct GhUserDto {
    login: String,
}

#[derive(Deserialize)]
struct GhSecretsPageDto {
    #[serde(default)]
    secrets: Vec<GhSecretMetaDto>,
}

#[derive(Deserialize)]
struct GhSecretMetaDto {
    name: String,
    updated_at: Option<String>,
}

#[derive(Deserialize)]
struct GhPublicKeyDto {
    key_id: String,
    key: String,
}

#[derive(Deserialize)]
struct GhRepoDto {
    id: u64,
}

#[derive(Deserialize)]
struct GhGitRefDto {
    object: GhGitObjectDto,
}

#[derive(Deserialize)]
struct GhGitObjectDto {
    #[serde(rename = "type")]
    obj_type: String,
    sha: String,
}

impl Default for RestGitHubClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RestGitHubClient {
    pub fn new(base_url_override: Option<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(15))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self {
            agent,
            base_url_override,
        }
    }

    fn api_base(&self, host: &str) -> String {
        if let Some(over) = &self.base_url_override {
            return over.trim_end_matches('/').to_string();
        }
        if host.eq_ignore_ascii_case("github.com") {
            "https://api.github.com".to_string()
        } else {
            format!("https://{host}/api/v3")
        }
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        token: Option<&MemSecret>,
    ) -> Result<ureq::Request, EnclaveError> {
        let mut req = self
            .agent
            .request(method, url)
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", "SecretBridge-Enclave/0.2");
        if let Some(tok) = token {
            req = req.set("Authorization", &format!("Bearer {}", tok.as_str()?));
        }
        Ok(req)
    }
}

impl GitHubClient for RestGitHubClient {
    fn check_authenticated_user(
        &self,
        token: &MemSecret,
        host: &str,
    ) -> Result<String, EnclaveError> {
        let url = format!("{}/user", self.api_base(host));
        let resp = self
            .request("GET", &url, Some(token))?
            .call()
            .map_err(|_| {
                EnclaveError::new(ErrorCode::Unauthorized, "GitHub authentication failed")
            })?;
        let user: GhUserDto = resp.into_json().map_err(|_| {
            EnclaveError::new(ErrorCode::UpstreamFailure, "invalid GitHub user response")
        })?;
        Ok(user.login)
    }

    fn prepare_environment(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<String, EnclaveError> {
        target.validate()?;
        if target.scope != GitHubScope::Environment {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "configure a GitHub environment target first",
            ));
        }
        let repo = target.repository.as_ref().expect("validated");
        let env_name = target.environment.as_ref().expect("validated");
        let url = format!(
            "{}/repos/{}/{}/environments/{}",
            self.api_base(target.host.as_str()),
            repo.owner().url_encoded(),
            repo.repo().url_encoded(),
            env_name.url_encoded()
        );
        match self.request("GET", &url, Some(token))?.call() {
            Ok(_) => Ok(env_name.as_str().to_string()),
            Err(ureq::Error::Status(404, _)) => {
                self.request("PUT", &url, Some(token))?
                    .send_json(serde_json::json!({}))
                    .map_err(|_| {
                        EnclaveError::new(
                            ErrorCode::UpstreamFailure,
                            "failed creating GitHub deployment environment",
                        )
                    })?;
                Ok(env_name.as_str().to_string())
            }
            Err(ureq::Error::Status(code, _)) => Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                format!("GitHub environment check failed (HTTP {code})"),
            )),
            Err(_) => Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "GitHub connection failed",
            )),
        }
    }

    fn list_secret_timestamps(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<BTreeMap<String, Option<String>>, EnclaveError> {
        let endpoint = target.secrets_endpoint_path()?;
        let base = self.api_base(target.host.as_str());
        let mut out = BTreeMap::new();
        let mut page = 1u32;
        loop {
            let url = format!("{base}/{endpoint}?per_page=100&page={page}");
            let resp = self
                .request("GET", &url, Some(token))?
                .call()
                .map_err(|e| match e {
                    ureq::Error::Status(code, _) => EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        format!("GitHub list secrets failed (HTTP {code})"),
                    ),
                    _ => EnclaveError::new(ErrorCode::UpstreamFailure, "GitHub connection failed"),
                })?;
            let dto: GhSecretsPageDto = resp.into_json().map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "invalid GitHub secrets list")
            })?;
            let count = dto.secrets.len();
            for s in dto.secrets {
                out.insert(s.name, s.updated_at);
            }
            if count < 100 || page >= 50 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    fn get_encryption_target(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<(GitHubPublicKey, Vec<u64>), EnclaveError> {
        let endpoint = target.secrets_endpoint_path()?;
        let base = self.api_base(target.host.as_str());
        let pk_url = format!("{base}/{endpoint}/public-key");
        let pk_dto: GhPublicKeyDto = self
            .request("GET", &pk_url, Some(token))?
            .call()
            .map_err(|_| {
                EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "failed fetching GitHub Actions public key",
                )
            })?
            .into_json()
            .map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "invalid GitHub public key JSON")
            })?;

        let mut repo_ids = Vec::new();
        if target.scope == GitHubScope::Organization {
            let org = target.organization.as_ref().expect("validated");
            let repos = target.repositories.as_ref().expect("validated");
            if repos.is_empty() {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "organization repository allowlist cannot be empty",
                ));
            }
            for repo_slug in repos {
                let r_url = format!(
                    "{base}/repos/{}/{}",
                    org.url_encoded(),
                    repo_slug.url_encoded()
                );
                let r_dto: GhRepoDto = self
                    .request("GET", &r_url, Some(token))?
                    .call()
                    .map_err(|_| {
                        EnclaveError::new(
                            ErrorCode::UpstreamFailure,
                            format!("failed resolving org repository '{}'", repo_slug.as_str()),
                        )
                    })?
                    .into_json()
                    .map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "invalid repository JSON")
                    })?;
                repo_ids.push(r_dto.id);
            }
        }
        Ok((
            GitHubPublicKey {
                key_id: pk_dto.key_id,
                key_b64: pk_dto.key,
            },
            repo_ids,
        ))
    }

    fn put_secret(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
        value: &MemSecret,
        pub_key: &GitHubPublicKey,
        selected_repo_ids: &[u64],
    ) -> Result<(), EnclaveError> {
        let encrypted_value = seal_base64(&pub_key.key_b64, value.as_bytes())?;
        let mut payload = serde_json::json!({
            "key_id": pub_key.key_id,
            "encrypted_value": encrypted_value,
        });
        if target.scope == GitHubScope::Organization {
            if selected_repo_ids.is_empty() {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "organization secrets require non-empty selected_repository_ids",
                ));
            }
            payload["visibility"] = serde_json::Value::String("selected".into());
            payload["selected_repository_ids"] = serde_json::json!(selected_repo_ids);
        }
        let endpoint = target.secrets_endpoint_path()?;
        let url = format!(
            "{}/{endpoint}/{}",
            self.api_base(target.host.as_str()),
            name.url_encoded()
        );
        self.request("PUT", &url, Some(token))?
            .send_json(payload)
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    format!("GitHub secret write failed (HTTP {code})"),
                ),
                _ => EnclaveError::new(ErrorCode::UpstreamFailure, "GitHub connection failed"),
            })?;
        Ok(())
    }

    fn delete_secret(
        &self,
        token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
    ) -> Result<(), EnclaveError> {
        let endpoint = target.secrets_endpoint_path()?;
        let url = format!(
            "{}/{endpoint}/{}",
            self.api_base(target.host.as_str()),
            name.url_encoded()
        );
        self.request("DELETE", &url, Some(token))?
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    format!("GitHub secret delete failed (HTTP {code})"),
                ),
                _ => EnclaveError::new(ErrorCode::UpstreamFailure, "GitHub connection failed"),
            })?;
        Ok(())
    }

    fn resolve_load_secrets_action_sha(
        &self,
        token: Option<&MemSecret>,
    ) -> Result<CommitSha40, EnclaveError> {
        let base = self.api_base("github.com");
        let ref_url = format!("{base}/repos/1Password/load-secrets-action/git/ref/tags/v5");
        let git_ref: GhGitRefDto = self
            .request("GET", &ref_url, token)?
            .call()
            .map_err(|_| {
                EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "failed resolving 1Password/load-secrets-action tag",
                )
            })?
            .into_json()
            .map_err(|_| EnclaveError::new(ErrorCode::UpstreamFailure, "invalid git ref JSON"))?;

        let mut obj = git_ref.object;
        for _ in 0..3 {
            if obj.obj_type != "tag" {
                break;
            }
            let sha_checked: CommitSha40 = obj.sha.parse()?;
            let tag_url = format!(
                "{base}/repos/1Password/load-secrets-action/git/tags/{}",
                sha_checked.as_str()
            );
            let deref: GhGitRefDto = self
                .request("GET", &tag_url, token)?
                .call()
                .map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed dereferencing git tag")
                })?
                .into_json()
                .map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "invalid git tag JSON")
                })?;
            obj = deref.object;
        }
        if obj.obj_type != "commit" {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "could not resolve 1Password/load-secrets-action to a commit SHA",
            ));
        }
        Ok(obj.sha.parse()?)
    }
}

// =========================================================================
// Deterministic In-Memory GitHub Client (for Unit/Integration Tests)
// =========================================================================

struct MockGhState {
    user_login: String,
    keypair_sk: zeroize::Zeroizing<[u8; 32]>,
    pub_key: GitHubPublicKey,
    secrets: BTreeMap<(String, String), (String, String)>, // (endpoint, name) -> (encrypted_b64, updated_at)
    environments: Vec<String>,
    org_repos: BTreeMap<String, u64>,
}

pub struct InMemoryGitHubClient {
    state: Mutex<MockGhState>,
}

impl InMemoryGitHubClient {
    pub fn new(user_login: &str) -> Self {
        use base64::Engine;
        let (sk, pk) = sb_proto::crypto::generate_sealed_box_keypair();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pk);
        Self {
            state: Mutex::new(MockGhState {
                user_login: user_login.to_string(),
                keypair_sk: sk,
                pub_key: GitHubPublicKey {
                    key_id: "key-01".into(),
                    key_b64: pk_b64,
                },
                secrets: BTreeMap::new(),
                environments: Vec::new(),
                org_repos: BTreeMap::from([("secretbridge".into(), 101)]),
            }),
        }
    }

    pub fn decrypt_stored_secret(
        &self,
        target: &GitHubTarget,
        name: &str,
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let ep = target.secrets_endpoint_path().ok()?;
        let st = self.state.lock().unwrap();
        let (enc_b64, _) = st.secrets.get(&(ep, name.to_string()))?;
        sb_proto::crypto::unseal_base64(&st.keypair_sk, enc_b64).ok()
    }
}

impl GitHubClient for InMemoryGitHubClient {
    fn check_authenticated_user(
        &self,
        _token: &MemSecret,
        _host: &str,
    ) -> Result<String, EnclaveError> {
        Ok(self.state.lock().unwrap().user_login.clone())
    }

    fn prepare_environment(
        &self,
        _token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<String, EnclaveError> {
        target.validate()?;
        let env_name = target
            .environment
            .as_ref()
            .ok_or_else(|| EnclaveError::new(ErrorCode::Validation, "not environment scope"))?
            .as_str()
            .to_string();
        let mut st = self.state.lock().unwrap();
        if !st.environments.contains(&env_name) {
            st.environments.push(env_name.clone());
        }
        Ok(env_name)
    }

    fn list_secret_timestamps(
        &self,
        _token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<BTreeMap<String, Option<String>>, EnclaveError> {
        let ep = target.secrets_endpoint_path()?;
        let st = self.state.lock().unwrap();
        let mut out = BTreeMap::new();
        for ((k_ep, name), (_, updated)) in &st.secrets {
            if k_ep == &ep {
                out.insert(name.clone(), Some(updated.clone()));
            }
        }
        Ok(out)
    }

    fn get_encryption_target(
        &self,
        _token: &MemSecret,
        target: &GitHubTarget,
    ) -> Result<(GitHubPublicKey, Vec<u64>), EnclaveError> {
        target.validate()?;
        let st = self.state.lock().unwrap();
        let mut ids = Vec::new();
        if target.scope == GitHubScope::Organization {
            for r in target.repositories.as_ref().expect("validated") {
                let id = st.org_repos.get(r.as_str()).copied().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "unknown org repo")
                })?;
                ids.push(id);
            }
        }
        Ok((st.pub_key.clone(), ids))
    }

    fn put_secret(
        &self,
        _token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
        value: &MemSecret,
        pub_key: &GitHubPublicKey,
        _selected_repo_ids: &[u64],
    ) -> Result<(), EnclaveError> {
        let ep = target.secrets_endpoint_path()?;
        let sealed = seal_base64(&pub_key.key_b64, value.as_bytes())?;
        let mut st = self.state.lock().unwrap();
        st.secrets.insert(
            (ep, name.as_str().to_string()),
            (sealed, "2026-11-18T00:00:00Z".into()),
        );
        Ok(())
    }

    fn delete_secret(
        &self,
        _token: &MemSecret,
        target: &GitHubTarget,
        name: &SecretName,
    ) -> Result<(), EnclaveError> {
        let ep = target.secrets_endpoint_path()?;
        let mut st = self.state.lock().unwrap();
        st.secrets.remove(&(ep, name.as_str().to_string()));
        Ok(())
    }

    fn resolve_load_secrets_action_sha(
        &self,
        _token: Option<&MemSecret>,
    ) -> Result<CommitSha40, EnclaveError> {
        Ok("0123456789abcdef0123456789abcdef01234567".parse()?)
    }
}
