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
use std::ffi::CString;
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
// Official `libop_uniffi_core.so` UniFFI C-FFI Provider (FD-pinned SHA-256)
// =========================================================================

/// Compile-time pinned SHA-256 allowlist (comma-separated 64-hex digests) baked into `.rodata`
/// when building release enclave images (`SB_PINNED_OP_CORE_SHA256`).
pub const COMPILED_OP_CORE_SHA256_CSV: Option<&str> = option_env!("SB_PINNED_OP_CORE_SHA256");

pub fn parse_sha256_allowlist_csv(csv: &str) -> Result<Vec<[u8; 32]>, EnclaveError> {
    let mut out = Vec::new();
    for item in csv.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let raw = hex::decode(trimmed).map_err(|_| {
            EnclaveError::new(
                ErrorCode::Validation,
                "invalid hex SHA-256 digest in allowlist",
            )
        })?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            EnclaveError::new(ErrorCode::Validation, "SHA-256 digest must be 32 bytes")
        })?;
        out.push(arr);
    }
    Ok(out)
}

pub fn compiled_op_core_allowlist() -> Result<Vec<[u8; 32]>, EnclaveError> {
    match COMPILED_OP_CORE_SHA256_CSV {
        Some(csv) => parse_sha256_allowlist_csv(csv),
        None => Ok(Vec::new()),
    }
}

/// Mozilla UniFFI `RustBuffer` C ABI (`libop_uniffi_core.so`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RustBuffer {
    pub capacity: u64,
    pub len: u64,
    pub data: *mut u8,
}

impl Default for RustBuffer {
    fn default() -> Self {
        Self {
            capacity: 0,
            len: 0,
            data: std::ptr::null_mut(),
        }
    }
}

/// Mozilla UniFFI `ForeignBytes` C ABI (`libop_uniffi_core.so`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForeignBytes {
    pub len: i32,
    pub data: *const u8,
}

/// Mozilla UniFFI `RustCallStatus` C ABI (`0 = CALL_SUCCESS`, `1 = CALL_ERROR`, `2 = PANIC`).
#[repr(C)]
#[derive(Default)]
pub struct RustCallStatus {
    pub code: i8,
    pub error_buf: RustBuffer,
}

pub type UniffiContractVersionFn = unsafe extern "C" fn() -> u32;
pub type RustBufferFromBytesFn =
    unsafe extern "C" fn(ForeignBytes, *mut RustCallStatus) -> RustBuffer;
pub type RustBufferFreeFn = unsafe extern "C" fn(RustBuffer, *mut RustCallStatus);
pub type UniffiBufToBufFn = unsafe extern "C" fn(RustBuffer, *mut RustCallStatus) -> RustBuffer;
pub type UniffiAsyncBufFn = unsafe extern "C" fn(RustBuffer) -> u64;
pub type UniffiFutureContinuationCallback = extern "C" fn(callback_data: u64, poll_result: i8);
pub type UniffiFuturePollRustBufferFn = unsafe extern "C" fn(
    handle: u64,
    callback: UniffiFutureContinuationCallback,
    callback_data: u64,
);
pub type UniffiFutureCompleteRustBufferFn =
    unsafe extern "C" fn(handle: u64, out_status: *mut RustCallStatus) -> RustBuffer;
pub type UniffiFutureFreeRustBufferFn = unsafe extern "C" fn(handle: u64);
pub type UniffiReleaseClientFn = unsafe extern "C" fn(u64, *mut RustCallStatus);

#[derive(Clone, Copy)]
pub enum UniffiBufCall {
    Sync(UniffiBufToBufFn),
    Async {
        start: UniffiAsyncBufFn,
        poll: UniffiFuturePollRustBufferFn,
        complete: UniffiFutureCompleteRustBufferFn,
        free: UniffiFutureFreeRustBufferFn,
    },
}

#[derive(Clone, Copy)]
pub struct UniffiSymbolTable {
    pub rustbuffer_from_bytes: RustBufferFromBytesFn,
    pub rustbuffer_free: RustBufferFreeFn,
    pub init_client: UniffiBufCall,
    pub invoke: UniffiBufCall,
    pub release_client: UniffiReleaseClientFn,
}

enum CoreFfiBackend {
    Dynamic {
        _lib: Library,
        symbols: UniffiSymbolTable,
    },
    #[cfg(test)]
    TestSymbols(UniffiSymbolTable),
}

pub struct UniffiCoreVaultProvider {
    backend: CoreFfiBackend,
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

/// Metadata-only field DTO: `_ignored_value` skips `"value"` in-place on `MemSecret` bytes
/// without allocating any unlocked heap `String` (`C3`).
#[derive(Deserialize)]
struct CoreFieldMetaOnlyDto {
    id: String,
    title: String,
    #[serde(alias = "fieldType")]
    field_type: String,
    #[serde(default, alias = "sectionId")]
    section_id: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default, rename = "value")]
    _ignored_value: Option<serde::de::IgnoredAny>,
}

/// Metadata-only item DTO: never materializes secret field values onto the unlocked heap (`C3`).
#[derive(Deserialize)]
struct CoreItemMetaOnlyDto {
    id: String,
    title: String,
    #[serde(alias = "vaultId")]
    vault_id: String,
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    fields: Vec<CoreFieldMetaOnlyDto>,
    #[serde(default)]
    version: u64,
}

/// Volatile-zeroizes the initialized slice `[0..len]` while preserving the exact `(capacity, len, data)`
/// header so UniFFI's internal `Vec::from_raw_parts` frees the allocation without UB (`C3`).
unsafe fn zeroize_and_free_rustbuffer(free_fn: RustBufferFreeFn, buf: RustBuffer) {
    if !buf.data.is_null() {
        let valid_len = buf.len.min(buf.capacity) as usize;
        if valid_len > 0 {
            // SAFETY: `buf.data` was allocated by UniFFI with at least `valid_len` initialized bytes.
            let slice = unsafe { std::slice::from_raw_parts_mut(buf.data, valid_len) };
            slice.zeroize();
        }
        let mut free_status = RustCallStatus::default();
        // SAFETY: `buf` retains its exact `capacity`, `len`, and `data` allocated by UniFFI.
        unsafe {
            free_fn(buf, &raw mut free_status);
        }
    }
}

fn parse_hex_u16_4(raw4: &[u8]) -> Option<u16> {
    if raw4.len() != 4 {
        return None;
    }
    let mut acc = 0u16;
    for &b in raw4 {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        acc = (acc << 4) | u16::from(nibble);
    }
    Some(acc)
}

pub(crate) fn unescape_json_string_to_mem_secret(
    quoted_json: &[u8],
) -> Result<MemSecret, EnclaveError> {
    let trimmed = std::str::from_utf8(quoted_json)
        .map_err(|_| EnclaveError::new(ErrorCode::UpstreamFailure, "invalid UTF-8 from core FFI"))?
        .trim();
    let inner = if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1]
    } else if let Some(extracted) = extract_json_object_string_field_raw(trimmed, "ok")
        .or_else(|| extract_json_object_string_field_raw(trimmed, "data"))
    {
        extracted
    } else {
        return Err(EnclaveError::new(
            ErrorCode::UpstreamFailure,
            "unexpected secret response shape from core FFI",
        ));
    };

    MemSecret::write_with(inner.len().max(1), |cur| {
        let bytes = inner.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] != b'\\' {
                cur.write_bytes(&bytes[i..i + 1])?;
                i += 1;
                continue;
            }
            i += 1;
            if i >= bytes.len() {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "truncated JSON escape in secret response",
                ));
            }
            match bytes[i] {
                b'"' => cur.write_bytes(b"\"")?,
                b'\\' => cur.write_bytes(b"\\")?,
                b'/' => cur.write_bytes(b"/")?,
                b'b' => cur.write_bytes(b"\x08")?,
                b'f' => cur.write_bytes(b"\x0c")?,
                b'n' => cur.write_bytes(b"\n")?,
                b'r' => cur.write_bytes(b"\r")?,
                b't' => cur.write_bytes(b"\t")?,
                b'u' => {
                    if i + 4 >= bytes.len() {
                        return Err(EnclaveError::new(
                            ErrorCode::UpstreamFailure,
                            "truncated unicode escape in secret response",
                        ));
                    }
                    let hi = parse_hex_u16_4(&bytes[i + 1..i + 5]).ok_or_else(|| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "bad unicode escape")
                    })?;
                    i += 4;
                    let code_point = if (0xD800..=0xDBFF).contains(&hi) {
                        if i + 6 >= bytes.len() || &bytes[i + 1..i + 3] != b"\\u" {
                            return Err(EnclaveError::new(
                                ErrorCode::UpstreamFailure,
                                "unpaired high surrogate in secret response",
                            ));
                        }
                        let lo = parse_hex_u16_4(&bytes[i + 3..i + 7]).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::UpstreamFailure, "bad low surrogate")
                        })?;
                        if !(0xDC00..=0xDFFF).contains(&lo) {
                            return Err(EnclaveError::new(
                                ErrorCode::UpstreamFailure,
                                "invalid UTF-16 surrogate pair in secret response",
                            ));
                        }
                        i += 6;
                        0x10000 + (((u32::from(hi) - 0xD800) << 10) | (u32::from(lo) - 0xDC00))
                    } else {
                        u32::from(hi)
                    };
                    let ch = char::from_u32(code_point).ok_or_else(|| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "invalid unicode scalar")
                    })?;
                    let mut utf8 = [0u8; 4];
                    let encoded = ch.encode_utf8(&mut utf8);
                    cur.write_bytes(encoded.as_bytes())?;
                    utf8.zeroize();
                }
                _ => {
                    return Err(EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "unsupported JSON escape in secret response",
                    ));
                }
            }
            i += 1;
        }
        Ok(())
    })
}

/// Finds `"<target_key>": "<raw_escaped_contents>"` at top-level depth 1 without allocating.
fn extract_json_object_string_field_raw<'a>(json: &'a str, target_key: &str) -> Option<&'a str> {
    let b = json.as_bytes();
    let mut i = skip_ws(b, 0);
    if i >= b.len() || b[i] != b'{' {
        return None;
    }
    i += 1;
    let mut depth = 1usize;
    while i < b.len() && depth > 0 {
        i = skip_ws(b, i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'"' if depth == 1 => {
                let (k_start, k_end, next_i) = scan_json_string_inner(b, i)?;
                i = skip_ws(b, next_i);
                if i < b.len() && b[i] == b':' {
                    i = skip_ws(b, i + 1);
                    if &json[k_start..k_end] == target_key && i < b.len() && b[i] == b'"' {
                        let (v_start, v_end, _) = scan_json_string_inner(b, i)?;
                        return Some(&json[v_start..v_end]);
                    }
                }
            }
            b'"' => {
                let (_, _, next_i) = scan_json_string_inner(b, i)?;
                i = next_i;
            }
            _ => i += 1,
        }
    }
    None
}

/// Scans byte ranges `(start, end)` of each `{ ... }` object inside top-level `"fields": [ ... ]`
/// in an already `serde_json`-validated `ItemsGet` `MemSecret` buffer (`C3`).
fn scan_top_level_fields_array_spans(json: &[u8]) -> Result<Vec<(usize, usize)>, EnclaveError> {
    let mut i = skip_ws(json, 0);
    if i >= json.len() || json[i] != b'{' {
        return Err(EnclaveError::new(
            ErrorCode::UpstreamFailure,
            "expected JSON object for item",
        ));
    }
    i += 1;
    let mut depth = 1usize;
    while i < json.len() && depth > 0 {
        i = skip_ws(json, i);
        if i >= json.len() {
            break;
        }
        match json[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                i += 1;
            }
            b'"' if depth == 1 => {
                let (k_start, k_end, after_key) =
                    scan_json_string_inner(json, i).ok_or_else(|| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "malformed JSON key")
                    })?;
                i = skip_ws(json, after_key);
                if i < json.len() && json[i] == b':' {
                    i = skip_ws(json, i + 1);
                    if &json[k_start..k_end] == b"fields" {
                        if i >= json.len() || json[i] != b'[' {
                            return Ok(Vec::new());
                        }
                        i += 1;
                        let mut spans = Vec::new();
                        loop {
                            i = skip_ws(json, i);
                            if i >= json.len() {
                                return Err(EnclaveError::new(
                                    ErrorCode::UpstreamFailure,
                                    "unterminated fields array",
                                ));
                            }
                            if json[i] == b']' {
                                return Ok(spans);
                            }
                            if json[i] == b',' {
                                i += 1;
                                continue;
                            }
                            let elem_start = i;
                            let elem_end = scan_json_value_end(json, i)?;
                            spans.push((elem_start, elem_end));
                            i = elem_end;
                        }
                    } else {
                        i = scan_json_value_end(json, i)?;
                    }
                }
            }
            b'"' => {
                let (_, _, next_i) = scan_json_string_inner(json, i).ok_or_else(|| {
                    EnclaveError::new(ErrorCode::UpstreamFailure, "malformed JSON string")
                })?;
                i = next_i;
            }
            _ => i += 1,
        }
    }
    Ok(Vec::new())
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn scan_json_string_inner(b: &[u8], quote_idx: usize) -> Option<(usize, usize, usize)> {
    if quote_idx >= b.len() || b[quote_idx] != b'"' {
        return None;
    }
    let start = quote_idx + 1;
    let mut i = start;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some((start, i, i + 1)),
            _ => i += 1,
        }
    }
    None
}

fn scan_json_value_end(b: &[u8], start: usize) -> Result<usize, EnclaveError> {
    let i = skip_ws(b, start);
    if i >= b.len() {
        return Err(EnclaveError::new(
            ErrorCode::UpstreamFailure,
            "unexpected EOF in JSON value",
        ));
    }
    match b[i] {
        b'"' => scan_json_string_inner(b, i)
            .map(|(_, _, end)| end)
            .ok_or_else(|| EnclaveError::new(ErrorCode::UpstreamFailure, "unterminated string")),
        b'{' | b'[' => {
            let mut depth = 1usize;
            let mut cur = i + 1;
            while cur < b.len() && depth > 0 {
                match b[cur] {
                    b'"' => {
                        let (_, _, next) = scan_json_string_inner(b, cur).ok_or_else(|| {
                            EnclaveError::new(ErrorCode::UpstreamFailure, "unterminated string")
                        })?;
                        cur = next;
                    }
                    b'{' | b'[' => {
                        depth += 1;
                        cur += 1;
                    }
                    b'}' | b']' => {
                        depth -= 1;
                        cur += 1;
                    }
                    _ => cur += 1,
                }
            }
            if depth != 0 {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "unbalanced JSON container",
                ));
            }
            Ok(cur)
        }
        _ => {
            let mut cur = i;
            while cur < b.len()
                && !matches!(b[cur], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                cur += 1;
            }
            Ok(cur)
        }
    }
}

/// Writes an `ItemsPut` or `ItemsCreate` UniFFI invocation JSON envelope directly into `MemSecret`
/// by splicing existing raw field JSON slices from `src_raw` (`MemSecret`) and optional new/replaced
/// `secret` (`MemSecret`) without allocating unlocked heap `String`s (`C3`).
#[allow(clippy::too_many_arguments)]
fn build_item_mutation_envelope(
    client_id: u64,
    method_name: &str,
    meta: &CoreItemMetaOnlyDto,
    vault_id_override: Option<&str>,
    src_raw_bytes: &[u8],
    field_spans: &[(usize, usize)],
    replace_field: Option<(&str, &MemSecret)>,
    append_field: Option<(&str, &str, &MemSecret)>,
    remove_field_id: Option<&str>,
) -> Result<MemSecret, EnclaveError> {
    if field_spans.len() != meta.fields.len() {
        return Err(EnclaveError::new(
            ErrorCode::UpstreamFailure,
            "item field span count mismatch",
        ));
    }
    let extra_secret_len = replace_field
        .map(|(_, s)| s.len() * 6 + 256)
        .unwrap_or(0)
        .saturating_add(append_field.map(|(_, _, s)| s.len() * 6 + 256).unwrap_or(0));
    let header_json = serde_json::json!({
        "id": meta.id,
        "title": meta.title,
        "vault_id": vault_id_override.unwrap_or(&meta.vault_id),
        "category": meta.category,
        "tags": meta.tags,
        "version": meta.version,
    })
    .to_string();
    let cap_est = src_raw_bytes
        .len()
        .saturating_add(header_json.len())
        .saturating_add(extra_secret_len)
        .saturating_add(512);

    let header_prefix = header_json
        .strip_suffix('}')
        .ok_or_else(|| EnclaveError::new(ErrorCode::InternalError, "invalid item header JSON"))?;

    MemSecret::write_with(cap_est, |cur| {
        cur.write_str(&format!(
            "{{\"client_id\":{client_id},\"invocation\":{{\"name\":\"{method_name}\",\"parameters\":"
        ))?;
        cur.write_str(header_prefix)?;
        cur.write_str(",\"fields\":[")?;

        let mut wrote_any = false;
        for (idx, f_meta) in meta.fields.iter().enumerate() {
            if remove_field_id.is_some_and(|rem| rem == f_meta.id) {
                continue;
            }
            if wrote_any {
                cur.write_bytes(b",")?;
            }
            if let Some((target_fid, new_secret)) = replace_field
                && f_meta.id == target_fid
            {
                let f_stub = serde_json::json!({
                    "id": f_meta.id,
                    "title": f_meta.title,
                    "field_type": f_meta.field_type,
                    "section_id": f_meta.section_id,
                    "purpose": f_meta.purpose,
                })
                .to_string();
                let stub_prefix = f_stub.strip_suffix('}').ok_or_else(|| {
                    EnclaveError::new(ErrorCode::InternalError, "invalid field stub JSON")
                })?;
                cur.write_str(stub_prefix)?;
                cur.write_str(",\"value\":")?;
                cur.write_json_string(new_secret.as_str()?)?;
                cur.write_str("}")?;
            } else {
                let (s, e) = field_spans[idx];
                cur.write_bytes(&src_raw_bytes[s..e])?;
            }
            wrote_any = true;
        }

        if let Some((new_fid, new_title, new_secret)) = append_field {
            if wrote_any {
                cur.write_bytes(b",")?;
            }
            let f_stub = serde_json::json!({
                "id": new_fid,
                "title": new_title,
                "field_type": "CONCEALED",
            })
            .to_string();
            let stub_prefix = f_stub.strip_suffix('}').ok_or_else(|| {
                EnclaveError::new(ErrorCode::InternalError, "invalid new field stub JSON")
            })?;
            cur.write_str(stub_prefix)?;
            cur.write_str(",\"value\":")?;
            cur.write_json_string(new_secret.as_str()?)?;
            cur.write_str("}")?;
        }

        cur.write_str("]}}}")
    })
}

impl UniffiCoreVaultProvider {
    /// Opens `so_path` with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW`, verifies regular-file mode
    /// and SHA-256 against `allowed_digests`, loads `/proc/self/fd/{fd}` on Linux to
    /// eliminate file-swap TOCTOU between hashing and `dlopen`, and resolves Mozilla UniFFI
    /// entrypoints (`C3`).
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

        // Resolve and cache raw function pointers tied to `lib`'s lifetime inside `Self`.
        // SAFETY: `lib` stays alive inside `CoreFfiBackend::Dynamic` for the entire lifetime of `Self`,
        // and `Library::drop` only runs when `Self` is dropped.
        let symbols = unsafe {
            let contract_version_fn = *lib
                .get::<UniffiContractVersionFn>(
                    b"ffi_op_uniffi_core_uniffi_contract_version\0",
                )
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_uniffi_contract_version in libop_uniffi_core.so",
                    )
                })?;
            let contract_version = contract_version_fn();
            if !(26..=32).contains(&contract_version) {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "unsupported libop_uniffi_core.so UniFFI contract version (expected 26..=32 for 64-bit RustBuffer ABI)",
                ));
            }

            let rustbuffer_from_bytes = *lib
                .get::<RustBufferFromBytesFn>(b"ffi_op_uniffi_core_rustbuffer_from_bytes\0")
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_rustbuffer_from_bytes in libop_uniffi_core.so",
                    )
                })?;
            let rustbuffer_free = *lib
                .get::<RustBufferFreeFn>(b"ffi_op_uniffi_core_rustbuffer_free\0")
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_rustbuffer_free in libop_uniffi_core.so",
                    )
                })?;

            let future_poll = *lib
                .get::<UniffiFuturePollRustBufferFn>(
                    b"ffi_op_uniffi_core_rust_future_poll_rust_buffer\0",
                )
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_rust_future_poll_rust_buffer in libop_uniffi_core.so",
                    )
                })?;
            let future_complete = *lib
                .get::<UniffiFutureCompleteRustBufferFn>(
                    b"ffi_op_uniffi_core_rust_future_complete_rust_buffer\0",
                )
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_rust_future_complete_rust_buffer in libop_uniffi_core.so",
                    )
                })?;
            let future_free = *lib
                .get::<UniffiFutureFreeRustBufferFn>(
                    b"ffi_op_uniffi_core_rust_future_free_rust_buffer\0",
                )
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing ffi_op_uniffi_core_rust_future_free_rust_buffer in libop_uniffi_core.so",
                    )
                })?;

            let init_client_start = *lib
                .get::<UniffiAsyncBufFn>(b"uniffi_op_uniffi_core_fn_func_init_client\0")
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing uniffi_op_uniffi_core_fn_func_init_client in libop_uniffi_core.so",
                    )
                })?;
            let init_client = UniffiBufCall::Async {
                start: init_client_start,
                poll: future_poll,
                complete: future_complete,
                free: future_free,
            };

            let invoke = if let Ok(sync_fn) =
                lib.get::<UniffiBufToBufFn>(b"uniffi_op_uniffi_core_fn_func_invoke_sync\0")
            {
                UniffiBufCall::Sync(*sync_fn)
            } else {
                let async_invoke = *lib
                    .get::<UniffiAsyncBufFn>(b"uniffi_op_uniffi_core_fn_func_invoke\0")
                    .map_err(|_| {
                        EnclaveError::new(
                            ErrorCode::UpstreamFailure,
                            "missing invoke_sync/invoke in libop_uniffi_core.so",
                        )
                    })?;
                UniffiBufCall::Async {
                    start: async_invoke,
                    poll: future_poll,
                    complete: future_complete,
                    free: future_free,
                }
            };

            let release_client = *lib
                .get::<UniffiReleaseClientFn>(b"uniffi_op_uniffi_core_fn_func_release_client\0")
                .map_err(|_| {
                    EnclaveError::new(
                        ErrorCode::UpstreamFailure,
                        "missing uniffi_op_uniffi_core_fn_func_release_client in libop_uniffi_core.so",
                    )
                })?;
            UniffiSymbolTable {
                rustbuffer_from_bytes,
                rustbuffer_free,
                init_client,
                invoke,
                release_client,
            }
        };

        Ok(Self {
            backend: CoreFfiBackend::Dynamic { _lib: lib, symbols },
            allowed_digests,
            verified_digest: actual,
        })
    }

    #[cfg(test)]
    pub fn from_test_symbol_table(symbols: UniffiSymbolTable) -> Self {
        Self {
            backend: CoreFfiBackend::TestSymbols(symbols),
            allowed_digests: vec![[0xAA; 32]],
            verified_digest: [0xAA; 32],
        }
    }

    fn symbols(&self) -> &UniffiSymbolTable {
        match &self.backend {
            CoreFfiBackend::Dynamic { symbols, .. } => symbols,
            #[cfg(test)]
            CoreFfiBackend::TestSymbols(symbols) => symbols,
        }
    }

    pub fn verified_digest(&self) -> &[u8; 32] {
        &self.verified_digest
    }

    pub fn allowed_digests_count(&self) -> usize {
        self.allowed_digests.len()
    }

    fn lower_bytes_to_rustbuffer(&self, payload: &[u8]) -> Result<RustBuffer, EnclaveError> {
        let len_i32 = i32::try_from(payload.len()).map_err(|_| {
            EnclaveError::new(ErrorCode::SizeLimitExceeded, "FFI payload exceeds i32::MAX")
        })?;
        let syms = self.symbols();
        let fb = ForeignBytes {
            len: len_i32,
            data: payload.as_ptr(),
        };
        let mut status = RustCallStatus::default();
        // SAFETY: `fb` points to `payload` valid for the synchronous `rustbuffer_from_bytes` call.
        let rbuf = unsafe { (syms.rustbuffer_from_bytes)(fb, &raw mut status) };
        if status.code != 0 {
            // SAFETY: On non-zero status, `status.error_buf` belongs to caller and must be freed.
            unsafe {
                zeroize_and_free_rustbuffer(syms.rustbuffer_free, status.error_buf);
            }
            return Err(EnclaveError::new(
                ErrorCode::InternalError,
                "UniFFI rustbuffer_from_bytes failed",
            ));
        }
        Ok(rbuf)
    }

    fn call_buf_to_mem_secret(
        &self,
        target: UniffiBufCall,
        arg_payload: &MemSecret,
        err_code_on_call_error: ErrorCode,
        err_msg: &'static str,
    ) -> Result<MemSecret, EnclaveError> {
        let syms = self.symbols();
        let arg_buf = self.lower_bytes_to_rustbuffer(arg_payload.as_bytes())?;
        let mut status = RustCallStatus::default();
        let ret_buf = match target {
            UniffiBufCall::Sync(func) => {
                // SAFETY: Sync UniFFI function consumes `arg_buf` and populates `status` / returns `RustBuffer`.
                unsafe { func(arg_buf, &raw mut status) }
            }
            UniffiBufCall::Async {
                start,
                poll,
                complete,
                free,
            } => drive_uniffi_rustbuffer_future(arg_buf, start, poll, complete, free, &mut status)?,
        };
        if status.code != 0 {
            // SAFETY: Free `status.error_buf` without echoing raw upstream error text across vsock.
            unsafe {
                zeroize_and_free_rustbuffer(syms.rustbuffer_free, status.error_buf);
            }
            return Err(EnclaveError::new(err_code_on_call_error, err_msg));
        }
        let free_fn = syms.rustbuffer_free;
        let ret_guard = DropGuard::new(ret_buf, |b| {
            // SAFETY: `b` was returned with `status.code == 0` and is owned by this scope.
            unsafe {
                zeroize_and_free_rustbuffer(free_fn, b);
            }
        });
        let valid_len = ret_guard.len.min(ret_guard.capacity) as usize;
        let slice = if ret_guard.data.is_null() || valid_len == 0 {
            &[][..]
        } else {
            // SAFETY: `ret_guard.data` has `valid_len` initialized bytes until `ret_guard` drops.
            unsafe { std::slice::from_raw_parts(ret_guard.data, valid_len) }
        };
        MemSecret::from_slice(slice)
    }

    fn call_release_client(&self, client_id: u64) {
        let syms = self.symbols();
        let mut status = RustCallStatus::default();
        // SAFETY: `release_client(client_id: u64, *mut RustCallStatus)` takes `client_id` directly.
        unsafe {
            (syms.release_client)(client_id, &raw mut status);
            if status.code != 0 {
                zeroize_and_free_rustbuffer(syms.rustbuffer_free, status.error_buf);
            }
        }
    }

    fn with_session<T, F>(&self, token: &MemSecret, f: F) -> Result<T, EnclaveError>
    where
        F: FnOnce(u64) -> Result<T, EnclaveError>,
    {
        let tok_str = token.as_str()?;
        let cfg_prefix = serde_json::json!({
            "programmingLanguage": "Rust",
            "sdkVersion": "0.5.0",
            "integrationName": "SecretBridge Enclave",
            "integrationVersion": env!("CARGO_PKG_VERSION"),
            "requestLibraryName": "sb-enclave-ffi",
            "requestLibraryVersion": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "osVersion": "linux-microvm",
            "architecture": std::env::consts::ARCH,
        })
        .to_string();
        let prefix = cfg_prefix
            .strip_suffix('}')
            .ok_or_else(|| EnclaveError::new(ErrorCode::InternalError, "invalid init json"))?;

        // Build config JSON directly inside locked `MemSecret` so `tok_str` never lands in a heap `String` (`C3`).
        let cfg_mem = MemSecret::write_with(prefix.len() + tok_str.len() * 6 + 64, |cur| {
            cur.write_str(prefix)?;
            cur.write_str(",\"serviceAccountToken\":")?;
            cur.write_json_string(tok_str)?;
            cur.write_str("}")
        })?;

        let syms = self.symbols();
        let init_resp = self.call_buf_to_mem_secret(
            syms.init_client,
            &cfg_mem,
            ErrorCode::Unauthorized,
            "1Password Service Account authentication failed",
        )?;
        let client_id = parse_client_id_from_mem_secret(&init_resp)?;

        let release_guard = DropGuard::new(client_id, |cid| {
            self.call_release_client(cid);
        });

        f(*release_guard)
    }

    fn invoke<P: Serialize>(
        &self,
        client_id: u64,
        name: &str,
        params: P,
    ) -> Result<MemSecret, EnclaveError> {
        let req_bytes = serde_json::to_vec(&CoreInvokeEnvelope {
            client_id,
            invocation: CoreInvocation {
                name,
                parameters: params,
            },
        })
        .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "FFI request encode failed"))?;
        let req_guard = DropGuard::new(req_bytes, |mut b| b.zeroize());
        let req_mem = MemSecret::from_slice(&req_guard)?;
        self.invoke_raw_envelope(&req_mem)
    }

    fn invoke_raw_envelope(&self, envelope_mem: &MemSecret) -> Result<MemSecret, EnclaveError> {
        let syms = self.symbols();
        self.call_buf_to_mem_secret(
            syms.invoke,
            envelope_mem,
            ErrorCode::UpstreamFailure,
            "1Password SDK Core invocation failed",
        )
    }
}

struct UniffiFutureWaker {
    poll_state: std::sync::Mutex<Option<i8>>,
    cvar: std::sync::Condvar,
}

impl UniffiFutureWaker {
    fn new() -> Self {
        Self {
            poll_state: std::sync::Mutex::new(None),
            cvar: std::sync::Condvar::new(),
        }
    }
}

extern "C" fn uniffi_future_continuation_cb(callback_data: u64, poll_result: i8) {
    if callback_data == 0 {
        return;
    }
    // SAFETY: `callback_data` was produced by `Arc::into_raw` right before `poll` and is consumed once per callback.
    let waker =
        unsafe { std::sync::Arc::from_raw(callback_data as usize as *const UniffiFutureWaker) };
    if let Ok(mut guard) = waker.poll_state.lock() {
        *guard = Some(poll_result);
        waker.cvar.notify_all();
    }
}

fn drive_uniffi_rustbuffer_future(
    arg_buf: RustBuffer,
    start: UniffiAsyncBufFn,
    poll: UniffiFuturePollRustBufferFn,
    complete: UniffiFutureCompleteRustBufferFn,
    free: UniffiFutureFreeRustBufferFn,
    out_status: &mut RustCallStatus,
) -> Result<RustBuffer, EnclaveError> {
    use std::time::Duration;

    // SAFETY: `start` consumes `arg_buf` and returns an owned UniFFI `RustFuture` handle.
    let handle = unsafe { start(arg_buf) };
    if handle == 0 {
        return Err(EnclaveError::new(
            ErrorCode::UpstreamFailure,
            "UniFFI async function returned null future handle",
        ));
    }
    let handle_guard = DropGuard::new(handle, |h| {
        // SAFETY: Every UniFFI `RustFuture` handle must be freed once via `rust_future_free_*`.
        unsafe {
            free(h);
        }
    });

    let waker = std::sync::Arc::new(UniffiFutureWaker::new());
    const MAX_POLL_ROUNDS: usize = 4_096;
    for _ in 0..MAX_POLL_ROUNDS {
        {
            let mut guard = waker
                .poll_state
                .lock()
                .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "waker lock poisoned"))?;
            *guard = None;
        }
        let cb_data = std::sync::Arc::into_raw(std::sync::Arc::clone(&waker)) as usize as u64;
        // SAFETY: `handle_guard` is live; `uniffi_future_continuation_cb` reclaims `cb_data` once.
        unsafe {
            poll(*handle_guard, uniffi_future_continuation_cb, cb_data);
        }

        let mut guard = waker
            .poll_state
            .lock()
            .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "waker lock poisoned"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(45);
        while guard.is_none() {
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "timed out polling 1Password UniFFI async future",
                ));
            }
            let (next_guard, _) = waker
                .cvar
                .wait_timeout(guard, deadline - now)
                .map_err(|_| EnclaveError::new(ErrorCode::InternalError, "waker wait poisoned"))?;
            guard = next_guard;
        }
        match *guard {
            Some(0) => {
                drop(guard);
                // SAFETY: `poll` reported `READY (0)`, so `complete` may be called once before `free`.
                let ret = unsafe { complete(*handle_guard, &raw mut *out_status) };
                return Ok(ret);
            }
            Some(1) => {
                // `WAKE (1)`: poll again.
                continue;
            }
            _ => {
                return Err(EnclaveError::new(
                    ErrorCode::UpstreamFailure,
                    "unexpected UniFFI future poll status",
                ));
            }
        }
    }

    Err(EnclaveError::new(
        ErrorCode::UpstreamFailure,
        "exceeded maximum UniFFI async poll iterations",
    ))
}

fn parse_client_id_from_mem_secret(resp: &MemSecret) -> Result<u64, EnclaveError> {
    let raw = resp.as_str()?.trim();
    if let Ok(id) = raw.parse::<u64>() {
        return Ok(id);
    }
    #[derive(Deserialize)]
    struct WrappedId {
        #[serde(alias = "data")]
        ok: Option<u64>,
        client_id: Option<u64>,
    }
    if let Ok(w) = serde_json::from_str::<WrappedId>(raw)
        && let Some(id) = w.ok.or(w.client_id)
    {
        return Ok(id);
    }
    Err(EnclaveError::new(
        ErrorCode::Unauthorized,
        "1Password Service Account authentication failed",
    ))
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
            let item: CoreItemMetaOnlyDto =
                serde_json::from_slice(raw.as_bytes()).map_err(|_| {
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
            let raw = self.invoke(
                cid,
                "SecretsResolve",
                serde_json::json!({ "secret_reference": op_ref.as_str() }),
            )?;
            unescape_json_string_to_mem_secret(raw.as_bytes())
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
        let _ = secret.as_str()?;
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
                let meta = CoreItemMetaOnlyDto {
                    id: String::new(),
                    title: title.clone(),
                    vault_id: vault_id.to_string(),
                    category: "SECURE_NOTE".into(),
                    tags: all_tags,
                    fields: Vec::new(),
                    version: 0,
                };
                let envelope = build_item_mutation_envelope(
                    cid,
                    "ItemsCreate",
                    &meta,
                    None,
                    &[],
                    &[],
                    None,
                    Some((&field_id, field_name.as_str(), secret)),
                    None,
                )?;
                let raw = self.invoke_raw_envelope(&envelope)?;
                let created: CoreItemMetaOnlyDto =
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
                let item: CoreItemMetaOnlyDto = serde_json::from_slice(raw_get.as_bytes())
                    .map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                    })?;
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                let spans = scan_top_level_fields_array_spans(raw_get.as_bytes())?;
                let field_id = Uuid::new_v4().simple().to_string();
                let envelope = build_item_mutation_envelope(
                    cid,
                    "ItemsPut",
                    &item,
                    None,
                    raw_get.as_bytes(),
                    &spans,
                    None,
                    Some((&field_id, field_name.as_str(), secret)),
                    None,
                )?;
                let raw_put = self.invoke_raw_envelope(&envelope)?;
                let updated: CoreItemMetaOnlyDto = serde_json::from_slice(raw_put.as_bytes())
                    .map_err(|_| {
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
                let item: CoreItemMetaOnlyDto = serde_json::from_slice(raw_get.as_bytes())
                    .map_err(|_| {
                        EnclaveError::new(ErrorCode::UpstreamFailure, "failed decoding item")
                    })?;
                if !is_safe_item_category(&item.category) {
                    return Err(EnclaveError::new(
                        ErrorCode::CapabilityDenied,
                        "only safe application-secret item categories can be modified",
                    ));
                }
                let Some(field) = item.fields.iter().find(|f| f.id == *field_id) else {
                    return Err(EnclaveError::new(
                        ErrorCode::Validation,
                        "field_id not found on item",
                    ));
                };
                let sec_part = field.section_id.clone();
                let spans = scan_top_level_fields_array_spans(raw_get.as_bytes())?;
                let envelope = build_item_mutation_envelope(
                    cid,
                    "ItemsPut",
                    &item,
                    None,
                    raw_get.as_bytes(),
                    &spans,
                    Some((field_id.as_str(), secret)),
                    None,
                    None,
                )?;
                let raw_put = self.invoke_raw_envelope(&envelope)?;
                let updated: CoreItemMetaOnlyDto = serde_json::from_slice(raw_put.as_bytes())
                    .map_err(|_| {
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
            let mut item: CoreItemMetaOnlyDto = serde_json::from_slice(raw_get.as_bytes())
                .map_err(|_| {
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
            }
            let spans = scan_top_level_fields_array_spans(raw_get.as_bytes())?;
            let envelope = build_item_mutation_envelope(
                cid,
                "ItemsPut",
                &item,
                None,
                raw_get.as_bytes(),
                &spans,
                None,
                None,
                remove_field_id,
            )?;
            let raw_put = self.invoke_raw_envelope(&envelope)?;
            let updated: CoreItemMetaOnlyDto = serde_json::from_slice(raw_put.as_bytes())
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
            let item: CoreItemMetaOnlyDto =
                serde_json::from_slice(raw_get.as_bytes()).map_err(|_| {
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
            let item: CoreItemMetaOnlyDto =
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
            let spans = scan_top_level_fields_array_spans(raw_get.as_bytes())?;
            let envelope = build_item_mutation_envelope(
                cid,
                "ItemsCreate",
                &item,
                Some(dst_vault_id),
                raw_get.as_bytes(),
                &spans,
                None,
                None,
                None,
            )?;
            let raw_created = self.invoke_raw_envelope(&envelope)?;
            let created: CoreItemMetaOnlyDto = serde_json::from_slice(raw_created.as_bytes())
                .map_err(|_| {
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
