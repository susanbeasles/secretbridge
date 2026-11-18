use crate::error::EnclaveError;
use crate::mem_secret::MemSecret;
use libloading::Library;
use sb_proto::crypto::constant_time_eq_32;
use sb_proto::error::ErrorCode;
use sb_proto::plan::sha256_hex;
use sb_proto::rpc::{
    CaptureInterceptMode, CaptureTarget, FieldSummary, ItemFieldsResponse, ItemSummary,
    SecretMutationReceipt, ServiceAccountCapabilities, VaultSummary,
};
use sb_proto::types::{OpRef, Slug, is_safe_item_category};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char};
use std::io::Read;
use std::mem::DropGuard;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;
use zeroize::Zeroize;

pub const MANAGED_TAG: &str = "secretbridge-managed";

const BUILTIN_FORBIDDEN_VAULTS: &[&str] = &["personal", "private", "employee"];

pub fn ensure_service_account_vault_allowed(vault_name_or_id: &str) -> Result<(), EnclaveError> {
    let lower = vault_name_or_id.trim().to_ascii_lowercase();
    if BUILTIN_FORBIDDEN_VAULTS.contains(&lower.as_str()) {
        return Err(EnclaveError::new(
            ErrorCode::VaultRestriction,
            "1Password Service Accounts cannot access built-in Personal, Private, or Employee vaults",
        ));
    }
    Ok(())
}

pub trait VaultProvider: Send + Sync {
    fn probe_capabilities(
        &self,
        token: &MemSecret,
    ) -> Result<ServiceAccountCapabilities, EnclaveError>;

    fn list_vaults(&self, token: &MemSecret) -> Result<Vec<VaultSummary>, EnclaveError>;

    fn create_vault(&self, token: &MemSecret, name: &str) -> Result<VaultSummary, EnclaveError>;

    fn list_items(
        &self,
        token: &MemSecret,
        vault_id: &str,
    ) -> Result<Vec<ItemSummary>, EnclaveError>;

    fn get_item_fields(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<ItemFieldsResponse, EnclaveError>;

    fn resolve_ref(
        &self,
        token: &MemSecret,
        expected_vault: &str,
        op_ref: &OpRef,
    ) -> Result<MemSecret, EnclaveError>;

    fn store_secret(
        &self,
        token: &MemSecret,
        vault_id: &str,
        target: &CaptureTarget,
        secret: &MemSecret,
        intercept_mode: Option<CaptureInterceptMode>,
    ) -> Result<SecretMutationReceipt, EnclaveError>;

    fn edit_metadata(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
        title: Option<&str>,
        tags: Option<&[String]>,
        remove_field_id: Option<&str>,
    ) -> Result<(String, String), EnclaveError>;

    fn archive_item(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<(), EnclaveError>;

    fn move_item(
        &self,
        token: &MemSecret,
        src_vault_id: &str,
        dst_vault_id: &str,
        item_id: &str,
        dst_env: &Slug,
    ) -> Result<String, EnclaveError>;

    fn source_revision_digest(
        &self,
        token: &MemSecret,
        vault_id: &str,
        refs: &[&OpRef],
    ) -> Result<String, EnclaveError>;
}

// =========================================================================
// Official `libop_uniffi_core.so` C-FFI Provider (FD-pinned SHA-256 check)
// =========================================================================

type InitClientFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type InvokeSyncFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type FreeStringFn = unsafe extern "C" fn(*mut c_char);

pub struct UniffiCoreVaultProvider {
    lib: Library,
    allowed_digests: Vec<[u8; 32]>,
    verified_digest: [u8; 32],
}

#[derive(Serialize)]
struct CoreInvokeEnvelope<'a, P: Serialize> {
    client_id: u64,
    invocation: CoreInvocation<'a, P>,
}

#[derive(Serialize)]
struct CoreInvocation<'a, P: Serialize> {
    name: &'a str,
    parameters: P,
}

#[derive(Deserialize)]
struct CoreVaultDto {
    id: String,
    title: String,
    #[serde(default)]
    can_write: Option<bool>,
    #[serde(default)]
    created_by_service_account: Option<bool>,
}

#[derive(Deserialize)]
struct CoreItemOverviewDto {
    id: String,
    title: String,
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    version: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct CoreFieldDto {
    id: String,
    title: String,
    field_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    section_id: Option<String>,
    #[serde(default)]
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

impl Drop for CoreFieldDto {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct CoreItemDto {
    id: String,
    title: String,
    vault_id: String,
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    fields: Vec<CoreFieldDto>,
    #[serde(default)]
    version: u64,
}

impl UniffiCoreVaultProvider {
    /// Opens `so_path` with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW`, verifies regular-file mode
    /// and SHA-256 against `allowed_digests`, and loads `/proc/self/fd/{fd}` on Linux to
    /// eliminate file-swap TOCTOU between hashing and `dlopen`.
    pub fn load_verified(
        so_path: &Path,
        allowed_digests: Vec<[u8; 32]>,
    ) -> Result<Self, EnclaveError> {
        if allowed_digests.is_empty() {
            return Err(EnclaveError::new(
                ErrorCode::CryptoFailure,
                "at least one pinned SHA-256 digest is required for libop_uniffi_core.so",
            ));
        }
        let c_path = CString::new(so_path.to_string_lossy().as_bytes())
            .map_err(|_| EnclaveError::new(ErrorCode::Validation, "invalid library path"))?;

        // SAFETY: `c_path` is a valid NUL-terminated path; O_NOFOLLOW refuses symlinks.
        let raw_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw_fd < 0 {
            return Err(EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "unable to open libop_uniffi_core.so (missing or symlinked)",
            ));
        }

        // SAFETY: `raw_fd` is newly opened and owned solely by `file`.
        let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `raw_fd` is valid while `file` is live.
        let stat_rc = unsafe { libc::fstat(raw_fd, &mut stat) };
        if stat_rc != 0 || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "libop_uniffi_core.so must be a regular file",
            ));
        }
        if (stat.st_mode & 0o002) != 0 {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "refusing to load world-writable libop_uniffi_core.so",
            ));
        }

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "failed hashing core library")
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if !allowed_digests
            .iter()
            .any(|expected| constant_time_eq_32(&actual, expected))
        {
            return Err(EnclaveError::new(
                ErrorCode::CryptoFailure,
                "libop_uniffi_core.so SHA-256 digest mismatch against pinned allowlist",
            ));
        }

        #[cfg(target_os = "linux")]
        let load_target = format!("/proc/self/fd/{raw_fd}");
        #[cfg(not(target_os = "linux"))]
        let load_target = so_path.to_string_lossy().into_owned();

        // SAFETY: We just verified regular file permissions and exact SHA-256 on this open fd.
        let lib = unsafe { Library::new(&load_target) }.map_err(|_| {
            EnclaveError::new(
                ErrorCode::UpstreamFailure,
                "dlopen failed for libop_uniffi_core.so (ensure glibc runtime is present)",
            )
        })?;

        Ok(Self {
            lib,
            allowed_digests,
            verified_digest: actual,
        })
    }

    pub fn verified_digest(&self) -> &[u8; 32] {
        &self.verified_digest
    }

    pub fn allowed_digests_count(&self) -> usize {
        self.allowed_digests.len()
    }

    fn with_session<T, F>(&self, token: &MemSecret, f: F) -> Result<T, EnclaveError>
    where
        F: FnOnce(u64) -> Result<T, EnclaveError>,
    {
        let tok_str = token.as_str()?;
        let mut cfg_json = serde_json::json!({
            "programmingLanguage": "Rust",
            "sdkVersion": "0.5.0",
            "integrationName": "SecretBridge Enclave",
            "integrationVersion": env!("CARGO_PKG_VERSION"),
            "requestLibraryName": "sb-enclave-ffi",
            "requestLibraryVersion": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "osVersion": "linux-microvm",
            "architecture": std::env::consts::ARCH,
            "serviceAccountToken": tok_str,
        })
        .to_string();
        let cfg_guard = DropGuard::new(&mut cfg_json, |s| s.zeroize());
        let c_cfg = CString::new(cfg_guard.as_bytes()).map_err(|_| {
            EnclaveError::new(ErrorCode::Validation, "token contains interior NUL byte")
        })?;
        let c_cfg_guard = DropGuard::new(c_cfg.into_bytes_with_nul(), |mut b| b.zeroize());

        let init_raw = self.call_ffi_symbol("op_core_init_client", c_cfg_guard.as_ptr().cast())?;
        let client_id: u64 = serde_json::from_str(&init_raw).map_err(|_| {
            EnclaveError::new(
                ErrorCode::Unauthorized,
                "1Password Service Account authentication failed",
            )
        })?;

        let release_guard = DropGuard::new(client_id, |cid| {
            let rel = serde_json::json!({ "client_id": cid }).to_string();
            if let Ok(c_rel) = CString::new(rel) {
                let _ = self.call_ffi_symbol("op_core_release_client", c_rel.as_ptr());
            }
        });

        f(*release_guard)
    }

    fn invoke<P: Serialize>(
        &self,
        client_id: u64,
        name: &str,
        params: P,
    ) -> Result<MemSecret, EnclaveError> {
        let mut raw_req = serde_json::to_string(&CoreInvokeEnvelope {
            client_id,
            invocation: CoreInvocation {
                name,
                parameters: params,
            },
        })
        .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "FFI request encode failed"))?;
        let req_guard = DropGuard::new(&mut raw_req, |s| s.zeroize());
        let c_req = CString::new(req_guard.as_bytes())
            .map_err(|_| EnclaveError::new(ErrorCode::Validation, "FFI request contains NUL"))?;
        let c_req_guard = DropGuard::new(c_req.into_bytes_with_nul(), |mut b| b.zeroize());

        let mut resp_str =
            self.call_ffi_symbol("op_core_invoke_sync", c_req_guard.as_ptr().cast())?;
        let resp_guard = DropGuard::new(&mut resp_str, |s| s.zeroize());
        MemSecret::from_slice(resp_guard.as_bytes())
    }

    fn call_ffi_symbol(
        &self,
        symbol_name: &str,
        arg_ptr: *const c_char,
    ) -> Result<String, EnclaveError> {
        // SAFETY: Symbols follow 1Password SDK Core C-string JSON ABI (`fn(*const c_char) -> *mut c_char` + `op_core_free_string`).
        unsafe {
            let func: libloading::Symbol<'_, InvokeSyncFn> =
                self.lib.get(symbol_name.as_bytes()).map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        format!("missing FFI symbol {symbol_name} in libop_uniffi_core.so"),
                    )
                })?;
            let free_fn: libloading::Symbol<'_, FreeStringFn> =
                self.lib.get(b"op_core_free_string\0").map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing op_core_free_string in libop_uniffi_core.so",
                    )
                })?;
            let _ = std::mem::size_of::<InitClientFn>();

            let out_ptr = func(arg_ptr);
            if out_ptr.is_null() {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "libop_uniffi_core returned null response",
                ));
            }
            let ptr_guard = DropGuard::new(out_ptr, |p| {
                let len = libc::strlen(p);
                std::ptr::write_bytes(p.cast::<u8>(), 0, len);
                free_fn(p);
            });
            let c_str = CStr::from_ptr(*ptr_guard);
            c_str.to_str().map(str::to_owned).map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "invalid UTF-8 from FFI")
            })
        }
    }
}

impl VaultProvider for UniffiCoreVaultProvider {
    fn probe_capabilities(
        &self,
        token: &MemSecret,
    ) -> Result<ServiceAccountCapabilities, EnclaveError> {
        let vaults = self.list_vaults(token)?;
        let can_create = self.with_session(token, |cid| {
            match self.invoke(cid, "VaultsCheckCanCreate", serde_json::json!({})) {
                Ok(resp) => Ok(resp.as_str().unwrap_or("false").contains("true")),
                Err(_) => Ok(false),
            }
        })?;
        let accessible: Vec<String> = vaults.iter().map(|v| v.id.clone()).collect();
        let read_only: Vec<String> = vaults
            .iter()
            .filter(|v| !v.writable)
            .map(|v| v.id.clone())
            .collect();
        Ok(ServiceAccountCapabilities {
            authenticated: true,
            can_create_vaults: can_create,
            accessible_vault_ids: accessible,
            read_only_vault_ids: read_only,
            notice: "Service Accounts cannot access Personal/Private vaults and can only modify or delete vaults they created or were granted write permission on.".into(),
        })
    }

    fn list_vaults(&self, token: &MemSecret) -> Result<Vec<VaultSummary>, EnclaveError> {
        self.with_session(token, |cid| {
            let raw = self.invoke(cid, "VaultsList", serde_json::json!({}))?;
            let parsed: Vec<CoreVaultDto> =
                serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding vault list")
                })?;
            Ok(parsed
                .into_iter()
                .filter(|v| ensure_service_account_vault_allowed(&v.title).is_ok())
                .map(|v| VaultSummary {
                    id: v.id,
                    name: v.title,
                    writable: v.can_write.unwrap_or(true),
                    created_by_service_account: v.created_by_service_account.unwrap_or(false),
                })
                .collect())
        })
    }

    fn create_vault(&self, token: &MemSecret, name: &str) -> Result<VaultSummary, EnclaveError> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.starts_with('-') || trimmed.len() > 64 {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "invalid vault name",
            ));
        }
        ensure_service_account_vault_allowed(trimmed)?;
        let caps = self.probe_capabilities(token)?;
        if !caps.can_create_vaults {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "OP_SERVICE_ACCOUNT_TOKEN does not have can_create_vaults permission",
            ));
        }
        self.with_session(token, |cid| {
            let raw = self.invoke(cid, "VaultsCreate", serde_json::json!({ "title": trimmed }))?;
            let v: CoreVaultDto = serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding created vault")
            })?;
            Ok(VaultSummary {
                id: v.id,
                name: v.title,
                writable: true,
                created_by_service_account: true,
            })
        })
    }

    fn list_items(
        &self,
        token: &MemSecret,
        vault_id: &str,
    ) -> Result<Vec<ItemSummary>, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        self.with_session(token, |cid| {
            let raw = self.invoke(
                cid,
                "ItemsList",
                serde_json::json!({ "vault_id": vault_id }),
            )?;
            let parsed: Vec<CoreItemOverviewDto> =
                serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding items list")
                })?;
            Ok(parsed
                .into_iter()
                .map(|i| ItemSummary {
                    id: i.id,
                    title: i.title,
                    category: i.category,
                    tags: i.tags,
                })
                .collect())
        })
    }

    fn get_item_fields(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<ItemFieldsResponse, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        self.with_session(token, |cid| {
            let raw = self.invoke(
                cid,
                "ItemsGet",
                serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
            )?;
            let item: CoreItemDto = serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item metadata")
            })?;
            if item.vault_id != vault_id {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "item does not belong to selected environment vault",
                ));
            }
            let mut fields = Vec::new();
            for f in &item.fields {
                if matches!(f.field_type.as_str(), "FILE" | "OTP" | "TOTP") {
                    continue;
                }
                let raw_ref = match &f.section_id {
                    Some(sec) => format!("op://{vault_id}/{}/{sec}/{}", item.id, f.id),
                    None => format!("op://{vault_id}/{}/{}", item.id, f.id),
                };
                if let Ok(op_ref) = raw_ref.parse::<OpRef>() {
                    fields.push(FieldSummary {
                        id: f.id.clone(),
                        label: f.title.clone(),
                        field_type: f.field_type.clone(),
                        r#ref: op_ref,
                    });
                }
            }
            Ok(ItemFieldsResponse {
                id: item.id,
                title: item.title,
                category: item.category,
                tags: item.tags,
                fields,
            })
        })
    }

    fn resolve_ref(
        &self,
        token: &MemSecret,
        expected_vault: &str,
        op_ref: &OpRef,
    ) -> Result<MemSecret, EnclaveError> {
        ensure_service_account_vault_allowed(expected_vault)?;
        if op_ref.vault() != expected_vault {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "reference vault does not match selected environment vault",
            ));
        }
        self.with_session(token, |cid| {
            self.invoke(
                cid,
                "SecretsResolve",
                serde_json::json!({ "secret_reference": op_ref.as_str() }),
            )
        })
    }

    fn store_secret(
        &self,
        token: &MemSecret,
        vault_id: &str,
        target: &CaptureTarget,
        secret: &MemSecret,
        intercept_mode: Option<CaptureInterceptMode>,
    ) -> Result<SecretMutationReceipt, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let secret_str = secret.as_str()?;
        self.with_session(token, |cid| match target {
            CaptureTarget::NewItem {
                title,
                field_name,
                tags,
            } => {
                let field_id = Uuid::new_v4().simple().to_string();
                let mut all_tags = tags.clone();
                if !all_tags.iter().any(|t| t == MANAGED_TAG) {
                    all_tags.push(MANAGED_TAG.to_string());
                }
                let mut payload = serde_json::json!({
                    "vault_id": vault_id,
                    "title": title,
                    "category": "SECURE_NOTE",
                    "tags": all_tags,
                    "fields": [{
                        "id": field_id,
                        "title": field_name.as_str(),
                        "field_type": "CONCEALED",
                        "value": secret_str,
                    }]
                });
                let res = self.invoke(cid, "ItemsCreate", &payload);
                if let Some(arr) = payload.get_mut("fields").and_then(|v| v.as_array_mut()) {
                    for f in arr {
                        if let Some(v) = f.get_mut("value").and_then(|x| x.as_str()) {
                            let _ = v;
                        }
                        f["value"] = serde_json::Value::String(String::new());
                    }
                }
                let raw = res?;
                let created: CoreItemDto =
                    serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                        EnclaveError::new(
                            ErrorCode::UpstreamFailure,
                            "failed decoding created item",
                        )
                    })?;
                let op_ref: OpRef =
                    format!("op://{vault_id}/{}/{}", created.id, field_id).parse()?;
                Ok(SecretMutationReceipt {
                    item_id: created.id,
                    title: created.title,
                    field_id,
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
            CaptureTarget::ExistingItemNewField {
                item_id,
                field_name,
            } => {
                let raw_get = self.invoke(
                    cid,
                    "ItemsGet",
                    serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
                )?;
                let mut item: CoreItemDto =
                    serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                    })?;
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                let field_id = Uuid::new_v4().simple().to_string();
                item.fields.push(CoreFieldDto {
                    id: field_id.clone(),
                    title: field_name.as_str().to_string(),
                    field_type: "CONCEALED".into(),
                    section_id: None,
                    value: secret_str.to_string(),
                    purpose: None,
                });
                let raw_put = self.invoke(cid, "ItemsPut", &item)?;
                let updated: CoreItemDto =
                    serde_json::from_slice(raw_put.as_bytes()).map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed updating item")
                    })?;
                let op_ref: OpRef =
                    format!("op://{vault_id}/{}/{}", updated.id, field_id).parse()?;
                Ok(SecretMutationReceipt {
                    item_id: updated.id,
                    title: updated.title,
                    field_id,
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
            CaptureTarget::ReplaceFieldValue { item_id, field_id } => {
                let raw_get = self.invoke(
                    cid,
                    "ItemsGet",
                    serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
                )?;
                let mut item: CoreItemDto =
                    serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                    })?;
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                let Some(field) = item.fields.iter_mut().find(|f| f.id == *field_id) else {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "field_id not found on item",
                    ));
                };
                field.value.zeroize();
                field.value = secret_str.to_string();
                let sec_part = field.section_id.clone();
                let raw_put = self.invoke(cid, "ItemsPut", &item)?;
                let updated: CoreItemDto =
                    serde_json::from_slice(raw_put.as_bytes()).map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed updating item")
                    })?;
                let op_ref: OpRef = match sec_part {
                    Some(sec) => format!("op://{vault_id}/{}/{sec}/{field_id}", updated.id),
                    None => format!("op://{vault_id}/{}/{field_id}", updated.id),
                }
                .parse()?;
                Ok(SecretMutationReceipt {
                    item_id: updated.id,
                    title: updated.title,
                    field_id: field_id.clone(),
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
        })
    }

    fn edit_metadata(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
        title: Option<&str>,
        tags: Option<&[String]>,
        remove_field_id: Option<&str>,
    ) -> Result<(String, String), EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        self.with_session(token, |cid| {
            let raw_get = self.invoke(
                cid,
                "ItemsGet",
                serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
            )?;
            let mut item: CoreItemDto =
                serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                })?;
            if !is_safe_item_category(&item.category) {
                return Err(EnclaveError::new(
                    ErrorCode::CapabilityDenied,
                    "only safe application-secret item categories can be edited",
                ));
            }
            if let Some(t) = title {
                if t.trim().is_empty() {
                    return Err(EnclaveError::new(ErrorCode::Validation, "empty title"));
                }
                item.title = t.to_string();
            }
            if let Some(new_tags) = tags {
                item.tags = new_tags.to_vec();
            }
            if let Some(fid) = remove_field_id {
                let Some(existing) = item.fields.iter().find(|f| f.id == fid) else {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "field does not exist",
                    ));
                };
                if existing.purpose.is_some() {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "built-in purpose fields cannot be removed",
                    ));
                }
                item.fields.retain(|f| f.id != fid);
            }
            let raw_put = self.invoke(cid, "ItemsPut", &item)?;
            let updated: CoreItemDto = serde_json::from_slice(raw_put.as_bytes())
                .map_err(|_| EnclaveError::new(ErrorCode::UpstreamFailure, "failed saving item"))?;
            Ok((updated.id, updated.title))
        })
    }

    fn archive_item(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<(), EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        self.with_session(token, |cid| {
            let raw_get = self.invoke(
                cid,
                "ItemsGet",
                serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
            )?;
            let item: CoreItemDto = serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
                EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
            })?;
            // Closes S5: archive enforces SAFE_ITEM_CATEGORIES just like edit!
            if !is_safe_item_category(&item.category) {
                return Err(EnclaveError::new(
                    ErrorCode::CapabilityDenied,
                    "refusing to archive non-application item category",
                ));
            }
            let _ = self.invoke(
                cid,
                "ItemsArchive",
                serde_json::json!({ "vault_id": vault_id, "item_id": item_id }),
            )?;
            Ok(())
        })
    }

    fn move_item(
        &self,
        token: &MemSecret,
        src_vault_id: &str,
        dst_vault_id: &str,
        item_id: &str,
        _dst_env: &Slug,
    ) -> Result<String, EnclaveError> {
        ensure_service_account_vault_allowed(src_vault_id)?;
        ensure_service_account_vault_allowed(dst_vault_id)?;
        if src_vault_id == dst_vault_id {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "choose a different destination vault",
            ));
        }
        self.with_session(token, |cid| {
            let raw_get = self.invoke(
                cid,
                "ItemsGet",
                serde_json::json!({ "vault_id": src_vault_id, "item_id": item_id }),
            )?;
            let mut item: CoreItemDto =
                serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                })?;
            // Closes S5: move enforces SAFE_ITEM_CATEGORIES!
            if !is_safe_item_category(&item.category) {
                return Err(EnclaveError::new(
                    ErrorCode::CapabilityDenied,
                    "refusing to move non-application item category",
                ));
            }
            item.vault_id = dst_vault_id.to_string();
            let raw_created = self.invoke(cid, "ItemsCreate", &item)?;
            let created: CoreItemDto =
                serde_json::from_slice(raw_created.as_bytes()).map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "failed creating item in destination vault",
                    )
                })?;
            let _ = self.invoke(
                cid,
                "ItemsArchive",
                serde_json::json!({ "vault_id": src_vault_id, "item_id": item_id }),
            )?;
            Ok(created.id)
        })
    }

    fn source_revision_digest(
        &self,
        token: &MemSecret,
        vault_id: &str,
        refs: &[&OpRef],
    ) -> Result<String, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        self.with_session(token, |cid| {
            let raw = self.invoke(
                cid,
                "ItemsList",
                serde_json::json!({ "vault_id": vault_id }),
            )?;
            let items: Vec<CoreItemOverviewDto> =
                serde_json::from_slice(raw.as_bytes()).map_err(|_| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "failed listing item versions")
                })?;
            let by_id: BTreeMap<String, u64> =
                items.into_iter().map(|i| (i.id, i.version)).collect();
            let mut pairs = Vec::with_capacity(refs.len());
            for r in refs {
                pairs.push((r.as_str().to_string(), by_id.get(r.item()).copied()));
            }
            Ok(sha256_hex(&pairs)?)
        })
    }
}

// =========================================================================
// Deterministic In-Memory Enclave Vault Provider (for Unit/Integration Tests)
// =========================================================================

pub struct StoredField {
    pub id: String,
    pub label: String,
    pub field_type: String,
    pub section_id: Option<String>,
    pub purpose: Option<String>,
    pub value: MemSecret,
}

pub struct StoredItem {
    pub id: String,
    pub title: String,
    pub category: String,
    pub tags: Vec<String>,
    pub fields: Vec<StoredField>,
    pub archived: bool,
    pub version: u64,
}

pub struct StoredVault {
    pub id: String,
    pub name: String,
    pub writable: bool,
    pub created_by_service_account: bool,
    pub items: BTreeMap<String, StoredItem>,
}

struct MockState {
    expected_token: String,
    can_create_vaults: bool,
    vaults: BTreeMap<String, StoredVault>,
}

pub struct InMemoryVaultProvider {
    state: Mutex<MockState>,
}

impl InMemoryVaultProvider {
    pub fn new(expected_token: impl Into<String>, can_create_vaults: bool) -> Self {
        Self {
            state: Mutex::new(MockState {
                expected_token: expected_token.into(),
                can_create_vaults,
                vaults: BTreeMap::new(),
            }),
        }
    }

    pub fn seed_vault(&self, id: &str, name: &str, writable: bool, created_by_sa: bool) {
        let mut st = self.state.lock().unwrap();
        st.vaults.insert(
            id.to_string(),
            StoredVault {
                id: id.to_string(),
                name: name.to_string(),
                writable,
                created_by_service_account: created_by_sa,
                items: BTreeMap::new(),
            },
        );
    }

    pub fn seed_item(
        &self,
        vault_id: &str,
        item_id: &str,
        title: &str,
        category: &str,
        fields: Vec<(&str, &str, Option<&str>, &str)>,
    ) {
        let mut st = self.state.lock().unwrap();
        let vault = st.vaults.get_mut(vault_id).expect("seeded vault exists");
        let stored_fields = fields
            .into_iter()
            .map(|(fid, label, sec, val)| StoredField {
                id: fid.to_string(),
                label: label.to_string(),
                field_type: "CONCEALED".into(),
                section_id: sec.map(str::to_string),
                purpose: None,
                value: MemSecret::from_slice(val.as_bytes()).expect("MemSecret alloc"),
            })
            .collect();
        vault.items.insert(
            item_id.to_string(),
            StoredItem {
                id: item_id.to_string(),
                title: title.to_string(),
                category: category.to_string(),
                tags: vec![MANAGED_TAG.to_string()],
                fields: stored_fields,
                archived: false,
                version: 1,
            },
        );
    }

    fn auth<'a>(
        &'a self,
        token: &MemSecret,
    ) -> Result<std::sync::MutexGuard<'a, MockState>, EnclaveError> {
        let st = self
            .state
            .lock()
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "vault mutex poisoned"))?;
        if token.as_bytes() != st.expected_token.as_bytes() {
            return Err(EnclaveError::new(
                ErrorCode::Unauthorized,
                "invalid OP_SERVICE_ACCOUNT_TOKEN",
            ));
        }
        Ok(st)
    }
}

impl VaultProvider for InMemoryVaultProvider {
    fn probe_capabilities(
        &self,
        token: &MemSecret,
    ) -> Result<ServiceAccountCapabilities, EnclaveError> {
        let st = self.auth(token)?;
        let accessible = st.vaults.keys().cloned().collect();
        let read_only = st
            .vaults
            .values()
            .filter(|v| !v.writable)
            .map(|v| v.id.clone())
            .collect();
        Ok(ServiceAccountCapabilities {
            authenticated: true,
            can_create_vaults: st.can_create_vaults,
            accessible_vault_ids: accessible,
            read_only_vault_ids: read_only,
            notice: "Service Accounts cannot access Personal/Private vaults.".into(),
        })
    }

    fn list_vaults(&self, token: &MemSecret) -> Result<Vec<VaultSummary>, EnclaveError> {
        let st = self.auth(token)?;
        Ok(st
            .vaults
            .values()
            .map(|v| VaultSummary {
                id: v.id.clone(),
                name: v.name.clone(),
                writable: v.writable,
                created_by_service_account: v.created_by_service_account,
            })
            .collect())
    }

    fn create_vault(&self, token: &MemSecret, name: &str) -> Result<VaultSummary, EnclaveError> {
        ensure_service_account_vault_allowed(name)?;
        let mut st = self.auth(token)?;
        if !st.can_create_vaults {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "OP_SERVICE_ACCOUNT_TOKEN does not have can_create_vaults permission",
            ));
        }
        let id = format!("vault-{}", Uuid::new_v4().simple());
        let summary = VaultSummary {
            id: id.clone(),
            name: name.to_string(),
            writable: true,
            created_by_service_account: true,
        };
        st.vaults.insert(
            id.clone(),
            StoredVault {
                id,
                name: name.to_string(),
                writable: true,
                created_by_service_account: true,
                items: BTreeMap::new(),
            },
        );
        Ok(summary)
    }

    fn list_items(
        &self,
        token: &MemSecret,
        vault_id: &str,
    ) -> Result<Vec<ItemSummary>, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let st = self.auth(token)?;
        let Some(vault) = st.vaults.get(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        Ok(vault
            .items
            .values()
            .filter(|i| !i.archived)
            .map(|i| ItemSummary {
                id: i.id.clone(),
                title: i.title.clone(),
                category: i.category.clone(),
                tags: i.tags.clone(),
            })
            .collect())
    }

    fn get_item_fields(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<ItemFieldsResponse, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let st = self.auth(token)?;
        let Some(vault) = st.vaults.get(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        let Some(item) = vault.items.get(item_id).filter(|i| !i.archived) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown item"));
        };
        let mut fields = Vec::new();
        for f in &item.fields {
            if matches!(f.field_type.as_str(), "FILE" | "OTP") {
                continue;
            }
            let raw = match &f.section_id {
                Some(sec) => format!("op://{vault_id}/{}/{sec}/{}", item.id, f.id),
                None => format!("op://{vault_id}/{}/{}", item.id, f.id),
            };
            fields.push(FieldSummary {
                id: f.id.clone(),
                label: f.label.clone(),
                field_type: f.field_type.clone(),
                r#ref: raw.parse()?,
            });
        }
        Ok(ItemFieldsResponse {
            id: item.id.clone(),
            title: item.title.clone(),
            category: item.category.clone(),
            tags: item.tags.clone(),
            fields,
        })
    }

    fn resolve_ref(
        &self,
        token: &MemSecret,
        expected_vault: &str,
        op_ref: &OpRef,
    ) -> Result<MemSecret, EnclaveError> {
        ensure_service_account_vault_allowed(expected_vault)?;
        if op_ref.vault() != expected_vault {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "reference vault mismatch",
            ));
        }
        let st = self.auth(token)?;
        let Some(vault) = st.vaults.get(expected_vault) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        let Some(item) = vault.items.get(op_ref.item()).filter(|i| !i.archived) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
        };
        let matches: Vec<&StoredField> = item
            .fields
            .iter()
            .filter(|f| {
                let sec_ok = f.section_id.as_deref() == op_ref.section();
                let id_or_label = f.id == op_ref.field() || f.label == op_ref.field();
                sec_ok && id_or_label
            })
            .collect();
        if matches.len() != 1 {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "reference did not resolve to a unique field",
            ));
        }
        MemSecret::from_slice(matches[0].value.as_bytes())
    }

    fn store_secret(
        &self,
        token: &MemSecret,
        vault_id: &str,
        target: &CaptureTarget,
        secret: &MemSecret,
        intercept_mode: Option<CaptureInterceptMode>,
    ) -> Result<SecretMutationReceipt, EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let mut st = self.auth(token)?;
        let Some(vault) = st.vaults.get_mut(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        if !vault.writable {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "Service Account has read-only access to this vault",
            ));
        }
        match target {
            CaptureTarget::NewItem {
                title,
                field_name,
                tags,
            } => {
                let item_id = format!("item-{}", Uuid::new_v4().simple());
                let field_id = format!("fld-{}", Uuid::new_v4().simple());
                let mut item_tags = tags.clone();
                if !item_tags.iter().any(|t| t == MANAGED_TAG) {
                    item_tags.push(MANAGED_TAG.to_string());
                }
                vault.items.insert(
                    item_id.clone(),
                    StoredItem {
                        id: item_id.clone(),
                        title: title.clone(),
                        category: "SECURE_NOTE".into(),
                        tags: item_tags,
                        fields: vec![StoredField {
                            id: field_id.clone(),
                            label: field_name.as_str().to_string(),
                            field_type: "CONCEALED".into(),
                            section_id: None,
                            purpose: None,
                            value: MemSecret::from_slice(secret.as_bytes())?,
                        }],
                        archived: false,
                        version: 1,
                    },
                );
                let op_ref: OpRef = format!("op://{vault_id}/{item_id}/{field_id}").parse()?;
                Ok(SecretMutationReceipt {
                    item_id,
                    title: title.clone(),
                    field_id,
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
            CaptureTarget::ExistingItemNewField {
                item_id,
                field_name,
            } => {
                let Some(item) = vault.items.get_mut(item_id).filter(|i| !i.archived) else {
                    return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
                };
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                if item.fields.iter().any(|f| f.label == field_name.as_str()) {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "field label already exists on item",
                    ));
                }
                let field_id = format!("fld-{}", Uuid::new_v4().simple());
                item.fields.push(StoredField {
                    id: field_id.clone(),
                    label: field_name.as_str().to_string(),
                    field_type: "CONCEALED".into(),
                    section_id: None,
                    purpose: None,
                    value: MemSecret::from_slice(secret.as_bytes())?,
                });
                item.version += 1;
                let op_ref: OpRef = format!("op://{vault_id}/{}/{field_id}", item.id).parse()?;
                Ok(SecretMutationReceipt {
                    item_id: item.id.clone(),
                    title: item.title.clone(),
                    field_id,
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
            CaptureTarget::ReplaceFieldValue { item_id, field_id } => {
                let Some(item) = vault.items.get_mut(item_id).filter(|i| !i.archived) else {
                    return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
                };
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                let Some(field) = item.fields.iter_mut().find(|f| f.id == *field_id) else {
                    return Err(EnclaveError::new(ErrorCode::Validation, "field not found"));
                };
                field.value = MemSecret::from_slice(secret.as_bytes())?;
                let sec = field.section_id.clone();
                item.version += 1;
                let op_ref: OpRef = match sec {
                    Some(s) => format!("op://{vault_id}/{}/{s}/{field_id}", item.id),
                    None => format!("op://{vault_id}/{}/{field_id}", item.id),
                }
                .parse()?;
                Ok(SecretMutationReceipt {
                    item_id: item.id.clone(),
                    title: item.title.clone(),
                    field_id: field_id.clone(),
                    r#ref: op_ref,
                    intercept_mode,
                })
            }
        }
    }

    fn edit_metadata(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
        title: Option<&str>,
        tags: Option<&[String]>,
        remove_field_id: Option<&str>,
    ) -> Result<(String, String), EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let mut st = self.auth(token)?;
        let Some(vault) = st.vaults.get_mut(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        if !vault.writable {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "vault is read-only for this Service Account",
            ));
        }
        let Some(item) = vault.items.get_mut(item_id).filter(|i| !i.archived) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
        };
        if !is_safe_item_category(&item.category) {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "only safe application-secret item categories can be edited",
            ));
        }
        if let Some(t) = title {
            if t.trim().is_empty() {
                return Err(EnclaveError::new(ErrorCode::Validation, "empty title"));
            }
            item.title = t.to_string();
        }
        if let Some(new_tags) = tags {
            item.tags = new_tags.to_vec();
        }
        if let Some(fid) = remove_field_id {
            let Some(f) = item.fields.iter().find(|x| x.id == fid) else {
                return Err(EnclaveError::new(ErrorCode::Validation, "field not found"));
            };
            if f.purpose.is_some() {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "built-in fields cannot be removed",
                ));
            }
            item.fields.retain(|x| x.id != fid);
        }
        item.version += 1;
        Ok((item.id.clone(), item.title.clone()))
    }

    fn archive_item(
        &self,
        token: &MemSecret,
        vault_id: &str,
        item_id: &str,
    ) -> Result<(), EnclaveError> {
        ensure_service_account_vault_allowed(vault_id)?;
        let mut st = self.auth(token)?;
        let Some(vault) = st.vaults.get_mut(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        if !vault.writable {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "vault is read-only for this Service Account",
            ));
        }
        let Some(item) = vault.items.get_mut(item_id).filter(|i| !i.archived) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
        };
        if !is_safe_item_category(&item.category) {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "refusing to archive non-application item category",
            ));
        }
        item.archived = true;
        item.version += 1;
        Ok(())
    }

    fn move_item(
        &self,
        token: &MemSecret,
        src_vault_id: &str,
        dst_vault_id: &str,
        item_id: &str,
        _dst_env: &Slug,
    ) -> Result<String, EnclaveError> {
        ensure_service_account_vault_allowed(src_vault_id)?;
        ensure_service_account_vault_allowed(dst_vault_id)?;
        if src_vault_id == dst_vault_id {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "choose a different destination vault",
            ));
        }
        let mut st = self.auth(token)?;
        if !st.vaults.get(src_vault_id).is_some_and(|v| v.writable)
            || !st.vaults.get(dst_vault_id).is_some_and(|v| v.writable)
        {
            return Err(EnclaveError::new(
                ErrorCode::CapabilityDenied,
                "both source and destination vaults must be writable by Service Account",
            ));
        }
        let cloned_item = {
            let Some(src_vault) = st.vaults.get_mut(src_vault_id) else {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "unknown source vault",
                ));
            };
            let Some(src_item) = src_vault.items.get_mut(item_id).filter(|i| !i.archived) else {
                return Err(EnclaveError::new(ErrorCode::Validation, "item not found"));
            };
            if !is_safe_item_category(&src_item.category) {
                return Err(EnclaveError::new(
                    ErrorCode::CapabilityDenied,
                    "refusing to move non-application item category",
                ));
            }
            let new_id = format!("item-{}", Uuid::new_v4().simple());
            let mut new_fields = Vec::with_capacity(src_item.fields.len());
            for f in &src_item.fields {
                new_fields.push(StoredField {
                    id: f.id.clone(),
                    label: f.label.clone(),
                    field_type: f.field_type.clone(),
                    section_id: f.section_id.clone(),
                    purpose: f.purpose.clone(),
                    value: MemSecret::from_slice(f.value.as_bytes())?,
                });
            }
            src_item.archived = true;
            src_item.version += 1;
            StoredItem {
                id: new_id,
                title: src_item.title.clone(),
                category: src_item.category.clone(),
                tags: src_item.tags.clone(),
                fields: new_fields,
                archived: false,
                version: 1,
            }
        };
        let new_id = cloned_item.id.clone();
        st.vaults
            .get_mut(dst_vault_id)
            .expect("checked")
            .items
            .insert(new_id.clone(), cloned_item);
        Ok(new_id)
    }

    fn source_revision_digest(
        &self,
        token: &MemSecret,
        vault_id: &str,
        refs: &[&OpRef],
    ) -> Result<String, EnclaveError> {
        let st = self.auth(token)?;
        let Some(vault) = st.vaults.get(vault_id) else {
            return Err(EnclaveError::new(ErrorCode::Validation, "unknown vault"));
        };
        let mut pairs = Vec::with_capacity(refs.len());
        for r in refs {
            let ver = vault
                .items
                .get(r.item())
                .filter(|i| !i.archived)
                .map(|i| i.version);
            pairs.push((r.as_str().to_string(), ver));
        }
        Ok(sha256_hex(&pairs)?)
    }
}
