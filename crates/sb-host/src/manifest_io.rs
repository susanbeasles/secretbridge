use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use sb_proto::types::Manifest;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::mem::DropGuard;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const MAX_MANIFEST_BYTES: u64 = 512 * 1024; // 512 KiB ceiling

#[derive(Debug, Clone)]
pub struct HostError {
    pub code: ErrorCode,
    pub message: String,
}

impl HostError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let s = SanitizedError::new(code, message);
        Self {
            code: s.code,
            message: s.message,
        }
    }

    pub fn into_sanitized(self) -> SanitizedError {
        SanitizedError::new(self.code, self.message)
    }
}

impl From<ProtoError> for HostError {
    fn from(err: ProtoError) -> Self {
        let s = err.into_sanitized();
        Self {
            code: s.code,
            message: s.message,
        }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for HostError {}

/// Verifies that neither `path` nor any existing ancestor directory is a symlink (closes S11).
fn ensure_no_symlink_components(path: &Path) -> Result<PathBuf, HostError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| HostError::new(ErrorCode::Validation, format!("cwd error: {e}")))?
            .join(path)
    };

    let mut cur = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "parent-directory '..' traversal is not permitted in manifest path",
                ));
            }
            other => cur.push(other),
        }
        if let Ok(meta) = fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!(
                    "refusing to traverse or modify symlinked path '{}'",
                    cur.display()
                ),
            ));
        }
    }
    Ok(abs)
}

/// Loads and strictly validates `secretbridge.json` with `O_NOFOLLOW` and size bounds.
pub fn load_manifest(path: &Path) -> Result<Manifest, HostError> {
    let checked = ensure_no_symlink_components(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&checked)
        .map_err(|e| {
            HostError::new(
                ErrorCode::ManifestIo,
                format!("unable to open secretbridge.json: {e}"),
            )
        })?;
    let meta = file.metadata().map_err(|e| {
        HostError::new(
            ErrorCode::Validation,
            format!("unable to stat secretbridge.json: {e}"),
        )
    })?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES {
        return Err(HostError::new(
            ErrorCode::Validation,
            "secretbridge.json must be a regular file <= 512 KiB",
        ));
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw).map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            "secretbridge.json is not valid UTF-8",
        )
    })?;
    Manifest::from_json_str(&raw).map_err(HostError::from)
}

/// Atomically writes `secretbridge.json` after full schema validation, preserving existing mode
/// (or defaulting to `0600`), `fsync`ing both file and parent directory, and cleaning up partial
/// temp files deterministically via `std::mem::DropGuard` (closes S11).
pub fn save_manifest_atomic(path: &Path, manifest: &Manifest) -> Result<(), HostError> {
    manifest.validate()?;
    let checked = ensure_no_symlink_components(path)?;
    let parent = checked.parent().ok_or_else(|| {
        HostError::new(
            ErrorCode::Validation,
            "manifest path must have a valid parent directory",
        )
    })?;
    let file_name = checked
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| HostError::new(ErrorCode::Validation, "invalid manifest filename"))?;

    let desired_mode = match fs::symlink_metadata(&checked) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "refusing to overwrite symlinked manifest",
                ));
            }
            meta.permissions().mode() & 0o777
        }
        Err(_) => 0o600,
    };

    let mut payload = serde_json::to_string_pretty(manifest).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("manifest serialization failed: {e}"),
        )
    })?;
    payload.push('\n');

    let tmp_name = format!(".{file_name}.{}.tmp", Uuid::new_v4().simple());
    let tmp_path = parent.join(tmp_name);

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(desired_mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| {
            HostError::new(
                ErrorCode::InternalError,
                format!("failed creating temporary manifest file: {e}"),
            )
        })?;

    // Guard temporary file so any write/sync/rename failure removes it cleanly.
    let tmp_guard = DropGuard::new(tmp_path.clone(), |p| {
        let _ = fs::remove_file(p);
    });

    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(desired_mode)).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("failed setting manifest permissions: {e}"),
        )
    })?;

    tmp_file.write_all(payload.as_bytes()).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("failed writing temporary manifest: {e}"),
        )
    })?;
    tmp_file.sync_all().map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("failed syncing temporary manifest: {e}"),
        )
    })?;
    drop(tmp_file);

    // Re-verify target wasn't swapped for a symlink before atomic rename
    if let Ok(meta) = fs::symlink_metadata(&checked)
        && meta.file_type().is_symlink()
    {
        return Err(HostError::new(
            ErrorCode::Validation,
            "refusing to replace symlinked manifest",
        ));
    }

    fs::rename(&tmp_path, &checked).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("atomic manifest rename failed: {e}"),
        )
    })?;

    // Dismiss cleanup guard now that tmp_path has been atomically renamed into place
    let _ = DropGuard::dismiss(tmp_guard);

    if let Ok(dir_fd) = File::open(parent) {
        let _ = dir_fd.sync_all();
    }
    Ok(())
}
