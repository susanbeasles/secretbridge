use sb_proto::error::{ErrorCode, ProtoError, SanitizedError};
use sb_proto::types::Manifest;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::DropGuard;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
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

fn is_symlink_errno(errno: Option<i32>) -> bool {
    #[cfg(target_os = "macos")]
    {
        matches!(errno, Some(libc::ELOOP) | Some(libc::EMLINK))
    }
    #[cfg(not(target_os = "macos"))]
    {
        matches!(errno, Some(libc::ELOOP))
    }
}

/// Walks every ancestor component of `path` from `/` using `openat(..., O_DIRECTORY | O_NOFOLLOW)`
/// and returns the pinned parent directory `OwnedFd` plus the validated leaf filename.
/// Eliminates ancestor symlink-swap TOCTOU races across all subsequent `openat`/`renameat`/`unlinkat` calls.
fn open_verified_parent_dirfd(path: &Path) -> Result<(OwnedFd, CString, String), HostError> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| HostError::new(ErrorCode::Validation, format!("cwd error: {e}")))?
            .join(path)
    };

    let mut normal_segments = Vec::new();
    for comp in abs.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "parent-directory '..' traversal is not permitted in manifest path",
                ));
            }
            Component::Prefix(_) => {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "unsupported path prefix in manifest path",
                ));
            }
            Component::Normal(seg) => normal_segments.push(seg),
        }
    }

    let leaf_os = normal_segments.pop().ok_or_else(|| {
        HostError::new(
            ErrorCode::Validation,
            "manifest path must include a valid filename",
        )
    })?;
    let leaf_str = leaf_os
        .to_str()
        .filter(|s| !s.is_empty() && !s.contains('/'))
        .ok_or_else(|| HostError::new(ErrorCode::Validation, "invalid manifest filename"))?
        .to_string();
    let leaf_cstr = CString::new(leaf_os.as_bytes())
        .map_err(|_| HostError::new(ErrorCode::Validation, "NUL byte in manifest filename"))?;

    // SAFETY: `c"/"` is a static NUL-terminated root path.
    let root_raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        return Err(HostError::new(
            ErrorCode::ManifestIo,
            format!(
                "unable to open root directory: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `root_raw` is newly opened and owned solely by `cur_dir`.
    let mut cur_dir = unsafe { OwnedFd::from_raw_fd(root_raw) };

    for seg in normal_segments {
        let seg_cstr = CString::new(seg.as_bytes()).map_err(|_| {
            HostError::new(
                ErrorCode::Validation,
                "NUL byte in manifest ancestor directory",
            )
        })?;
        // SAFETY: `cur_dir` is a valid open directory fd; `seg_cstr` is NUL-terminated.
        let next_raw = unsafe {
            libc::openat(
                cur_dir.as_raw_fd(),
                seg_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_raw < 0 {
            let err = io::Error::last_os_error();
            if is_symlink_errno(err.raw_os_error()) || err.raw_os_error() == Some(libc::ENOTDIR) {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    format!(
                        "refusing to traverse symlinked or non-directory ancestor '{}'",
                        seg.to_string_lossy()
                    ),
                ));
            }
            return Err(HostError::new(
                ErrorCode::ManifestIo,
                format!(
                    "unable to open manifest parent component '{}': {err}",
                    seg.to_string_lossy()
                ),
            ));
        }
        // SAFETY: `next_raw` is newly opened and replaces `cur_dir`.
        cur_dir = unsafe { OwnedFd::from_raw_fd(next_raw) };
    }

    Ok((cur_dir, leaf_cstr, leaf_str))
}

/// Loads and strictly validates `secretbridge.json` relative to a verified directory descriptor
/// with `O_NOFOLLOW | O_NONBLOCK` (preventing symlink traversal and FIFO blocking hangs) and size bounds.
pub fn load_manifest(path: &Path) -> Result<Manifest, HostError> {
    let (parent_fd, leaf_cstr, _) = open_verified_parent_dirfd(path)?;

    // Open with O_NONBLOCK | O_NOFOLLOW so FIFOs/special nodes never block openat before fstat!
    // SAFETY: `parent_fd` is a valid directory fd and `leaf_cstr` is a single NUL-terminated filename.
    let raw_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let err = io::Error::last_os_error();
        if is_symlink_errno(err.raw_os_error()) {
            return Err(HostError::new(
                ErrorCode::Validation,
                "refusing to open symlinked secretbridge.json",
            ));
        }
        return Err(HostError::new(
            ErrorCode::ManifestIo,
            format!("unable to open secretbridge.json: {err}"),
        ));
    }

    // SAFETY: `raw_fd` is newly opened and owned solely by `file`.
    let file = unsafe { File::from_raw_fd(raw_fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!(
                "unable to stat secretbridge.json: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || (st.st_size as u64) > MAX_MANIFEST_BYTES
    {
        return Err(HostError::new(
            ErrorCode::Validation,
            "secretbridge.json must be a regular file <= 512 KiB",
        ));
    }

    // Clear O_NONBLOCK now that regular-file status is confirmed.
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }

    let mut bounded = Vec::with_capacity((st.st_size as usize).min(64 * 1024));
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bounded)
        .map_err(|e| {
            HostError::new(
                ErrorCode::ManifestIo,
                format!("error reading secretbridge.json: {e}"),
            )
        })?;
    if (bounded.len() as u64) > MAX_MANIFEST_BYTES {
        return Err(HostError::new(
            ErrorCode::Validation,
            "secretbridge.json exceeded 512 KiB ceiling while reading",
        ));
    }
    let raw = String::from_utf8(bounded).map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            "secretbridge.json is not valid UTF-8",
        )
    })?;
    Manifest::from_json_str(&raw).map_err(HostError::from)
}

/// Atomically writes `secretbridge.json` relative to a verified parent directory descriptor (`openat` +
/// `fchmod` + `renameat` + `unlinkat` `DropGuard` + `fsync(parent_fd)`), eliminating ancestor symlink races.
pub fn save_manifest_atomic(path: &Path, manifest: &Manifest) -> Result<(), HostError> {
    manifest.validate()?;
    let (parent_fd, leaf_cstr, file_name) = open_verified_parent_dirfd(path)?;

    let mut existing_st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `parent_fd` is valid and `leaf_cstr` is NUL-terminated; AT_SYMLINK_NOFOLLOW does not dereference symlinks.
    let stat_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
            &mut existing_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let desired_mode: u32 = if stat_rc == 0 {
        if (existing_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(HostError::new(
                ErrorCode::Validation,
                "refusing to overwrite symlink or non-regular file at secretbridge.json",
            ));
        }
        (existing_st.st_mode as u32) & 0o777
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            return Err(HostError::new(
                ErrorCode::ManifestIo,
                format!("unable to inspect target manifest path: {err}"),
            ));
        }
        0o600
    };

    let mut payload = serde_json::to_string_pretty(manifest).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("manifest serialization failed: {e}"),
        )
    })?;
    payload.push('\n');

    let tmp_name = format!(".{file_name}.{}.tmp", Uuid::new_v4().simple());
    let tmp_cstr = CString::new(tmp_name.as_bytes())
        .map_err(|_| HostError::new(ErrorCode::InternalError, "invalid temp filename"))?;

    // SAFETY: Creates exclusive mode-0600 temp file directly inside `parent_fd` with O_NOFOLLOW.
    let tmp_raw_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            tmp_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if tmp_raw_fd < 0 {
        return Err(HostError::new(
            ErrorCode::InternalError,
            format!(
                "failed creating temporary manifest file: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    // SAFETY: `tmp_raw_fd` is newly created and owned solely by `tmp_file`.
    let mut tmp_file = unsafe { File::from_raw_fd(tmp_raw_fd) };
    let parent_raw = parent_fd.as_raw_fd();
    let tmp_guard = DropGuard::new(tmp_cstr.clone(), move |name| {
        // SAFETY: `parent_raw` outlives `tmp_guard` within this function frame; unlinks temp file on failure.
        unsafe {
            let _ = libc::unlinkat(parent_raw, name.as_ptr(), 0);
        }
    });

    if unsafe { libc::fchmod(tmp_file.as_raw_fd(), desired_mode as libc::mode_t) } != 0 {
        return Err(HostError::new(
            ErrorCode::InternalError,
            format!(
                "failed setting manifest permissions: {}",
                io::Error::last_os_error()
            ),
        ));
    }

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

    // Re-check destination relative to `parent_fd` right before renameat.
    let mut pre_rename_st: libc::stat = unsafe { std::mem::zeroed() };
    let pre_rc = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
            &mut pre_rename_st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if pre_rc == 0 && (pre_rename_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(HostError::new(
            ErrorCode::Validation,
            "refusing to replace symlink or special file at secretbridge.json",
        ));
    }

    // SAFETY: Atomically renames `tmp_cstr` -> `leaf_cstr` inside the same verified `parent_fd`.
    if unsafe {
        libc::renameat(
            parent_fd.as_raw_fd(),
            tmp_cstr.as_ptr(),
            parent_fd.as_raw_fd(),
            leaf_cstr.as_ptr(),
        )
    } != 0
    {
        return Err(HostError::new(
            ErrorCode::InternalError,
            format!(
                "atomic manifest renameat failed: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let _ = DropGuard::dismiss(tmp_guard);
    // SAFETY: Syncs directory entry durability on the verified parent directory descriptor.
    unsafe {
        let _ = libc::fsync(parent_fd.as_raw_fd());
    }
    Ok(())
}
