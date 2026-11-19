use crate::manifest_io::HostError;
use sb_proto::crypto::constant_time_eq_32;
use sb_proto::error::ErrorCode;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::DropGuard;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_GUEST_CID: u32 = 42;
pub const DEFAULT_VSOCK_PORT: u32 = 5190;
const MAX_BOOT_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB ceiling
const MAX_SERIAL_BANNER_BYTES: usize = 64 * 1024; // 64 KiB pre-banner bound

/// Returns the default absolute VMM binary path for the current Linux host architecture.
pub fn default_vmm_binary_path() -> PathBuf {
    if cfg!(target_arch = "aarch64") {
        PathBuf::from("/usr/bin/qemu-system-aarch64")
    } else {
        PathBuf::from("/usr/bin/qemu-system-x86_64")
    }
}

/// Verified host executable handle (`V2-H6`):
/// - Walks every ancestor directory from `/` with `openat(..., O_DIRECTORY | O_NOFOLLOW)` rejecting
///   symlinked or world-writable (`0o002`) parent directories.
/// - On Linux, copies the verified executable into a write-sealed `memfd_create` (`MFD_EXEC`)
///   executed via `/proc/self/fd/<fd>` when supported by the host kernel's `vm.memfd_noexec` policy,
///   eliminating path-reopen TOCTOU between SHA-256 verification and `execve`.
pub struct VerifiedExecutable {
    exec_path: PathBuf,
    _backing_file: File,
}

impl VerifiedExecutable {
    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }
}

fn open_verified_executable_file(path: &Path, label: &str) -> Result<File, HostError> {
    let raw_str = path.to_string_lossy();
    if raw_str.is_empty() || raw_str.starts_with('-') {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} binary path must not be empty or start with '-'"),
        ));
    }
    if !path.is_absolute() {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} binary path must be absolute"),
        ));
    }

    let mut segments = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    format!("{label} binary path must not contain '..' or path prefixes"),
                ));
            }
            Component::Normal(seg) => segments.push(seg),
        }
    }
    let leaf_os = segments.pop().ok_or_else(|| {
        HostError::new(
            ErrorCode::Validation,
            format!("{label} binary path must name an executable file"),
        )
    })?;
    let leaf_cstr = CString::new(leaf_os.as_bytes()).map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            format!("NUL byte in {label} binary filename"),
        )
    })?;

    // SAFETY: `c"/"` is a static NUL-terminated root path.
    let root_raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_raw < 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!(
                "unable to open '/' while verifying {label}: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `root_raw` is newly opened and owned solely by `cur_dir`.
    let mut cur_dir = unsafe { OwnedFd::from_raw_fd(root_raw) };

    for seg in segments {
        let seg_cstr = CString::new(seg.as_bytes()).map_err(|_| {
            HostError::new(
                ErrorCode::Validation,
                format!("NUL byte in {label} ancestor directory"),
            )
        })?;
        // SAFETY: `cur_dir` is a valid directory fd and `seg_cstr` is NUL-terminated.
        let next_raw = unsafe {
            libc::openat(
                cur_dir.as_raw_fd(),
                seg_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_raw < 0 {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!(
                    "refusing to traverse symlinked or inaccessible ancestor '{}' for {label}: {}",
                    seg.to_string_lossy(),
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: `next_raw` is newly opened and replaces `cur_dir`.
        cur_dir = unsafe { OwnedFd::from_raw_fd(next_raw) };
        let mut dir_st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(cur_dir.as_raw_fd(), &mut dir_st) } != 0 {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!("unable to stat ancestor directory for {label}"),
            ));
        }
        if (dir_st.st_mode & 0o002) != 0 {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!(
                    "refusing to execute {label} inside world-writable ancestor directory '{}'",
                    seg.to_string_lossy()
                ),
            ));
        }
    }

    // SAFETY: Opens leaf executable inside verified `cur_dir` without following symlinks.
    let bin_raw = unsafe {
        libc::openat(
            cur_dir.as_raw_fd(),
            leaf_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if bin_raw < 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!(
                "unable to open {label} binary '{}': {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `bin_raw` is newly opened and owned solely by `file`.
    let file = unsafe { File::from_raw_fd(bin_raw) };
    let meta = file.metadata().map_err(|e| {
        HostError::new(
            ErrorCode::Validation,
            format!("unable to stat {label} binary: {e}"),
        )
    })?;
    if !meta.is_file() {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} binary must be a regular file"),
        ));
    }
    let mode = meta.permissions().mode();
    if (mode & 0o111) == 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} binary is not executable"),
        ));
    }
    if (mode & 0o002) != 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("refusing to execute world-writable {label} binary"),
        ));
    }
    unsafe {
        let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            let _ = libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    Ok(file)
}

/// Verifies an executable host binary (`qemu-system-*` or `sb-enclave`) before spawning and seals
/// it into an immutable executable `memfd` on Linux (`V2-H6`).
pub fn open_and_seal_executable_binary(
    path: &Path,
    expected_sha256: Option<&[u8; 32]>,
    label: &str,
) -> Result<VerifiedExecutable, HostError> {
    let mut file = open_verified_executable_file(path, label)?;

    #[cfg(target_os = "linux")]
    {
        const MFD_EXEC_FLAG: libc::c_uint = 0x0010;
        // SAFETY: `c"sb_verified_exec"` is NUL-terminated. Try `MFD_EXEC` (Linux >= 6.3) first,
        // falling back to standard `MFD_CLOEXEC | MFD_ALLOW_SEALING` on older kernels (`EINVAL`).
        let mut raw_memfd = unsafe {
            libc::memfd_create(
                c"sb_verified_exec".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC_FLAG,
            )
        };
        if raw_memfd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            raw_memfd = unsafe {
                libc::memfd_create(
                    c"sb_verified_exec".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
        }
        if raw_memfd >= 0 {
            // SAFETY: `raw_memfd` was freshly created by `memfd_create`.
            let mut memfd_file = unsafe { File::from_raw_fd(raw_memfd) };
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 32 * 1024];
            loop {
                let n = file.read(&mut buf).map_err(|e| {
                    HostError::new(
                        ErrorCode::Validation,
                        format!("error reading {label} binary: {e}"),
                    )
                })?;
                if n == 0 {
                    break;
                }
                if expected_sha256.is_some() {
                    hasher.update(&buf[..n]);
                }
                memfd_file.write_all(&buf[..n]).map_err(|e| {
                    HostError::new(
                        ErrorCode::InternalError,
                        format!("failed copying {label} binary into sealed memfd: {e}"),
                    )
                })?;
            }
            if let Some(expected) = expected_sha256 {
                let actual: [u8; 32] = hasher.finalize().into();
                if !constant_time_eq_32(&actual, expected) {
                    return Err(HostError::new(
                        ErrorCode::CryptoFailure,
                        format!("{label} binary SHA-256 verification failed against pinned digest"),
                    ));
                }
            }
            let _ = memfd_file.seek(SeekFrom::Start(0));
            let _ = unsafe { libc::fchmod(memfd_file.as_raw_fd(), 0o500) };
            let seals =
                libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
            if unsafe { libc::fcntl(memfd_file.as_raw_fd(), libc::F_ADD_SEALS, seals) } == 0 {
                let fd_num = memfd_file.as_raw_fd();
                return Ok(VerifiedExecutable {
                    exec_path: PathBuf::from(format!("/proc/self/fd/{fd_num}")),
                    _backing_file: memfd_file,
                });
            }
            file.seek(SeekFrom::Start(0)).map_err(|e| {
                HostError::new(
                    ErrorCode::InternalError,
                    format!("failed rewinding {label} binary: {e}"),
                )
            })?;
        }
    }

    if let Some(expected) = expected_sha256 {
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|e| {
                HostError::new(
                    ErrorCode::Validation,
                    format!("error hashing {label} binary: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if !constant_time_eq_32(&actual, expected) {
            return Err(HostError::new(
                ErrorCode::CryptoFailure,
                format!("{label} binary SHA-256 verification failed against pinned digest"),
            ));
        }
    }

    Ok(VerifiedExecutable {
        exec_path: path.to_path_buf(),
        _backing_file: file,
    })
}

pub fn verify_executable_binary(
    path: &Path,
    expected_sha256: Option<&[u8; 32]>,
    label: &str,
) -> Result<PathBuf, HostError> {
    let _verified = open_and_seal_executable_binary(path, expected_sha256, label)?;
    Ok(path.to_path_buf())
}

/// Verifies a kernel or initramfs image with `O_NOFOLLOW`, regular-file check, non-world-writable
/// permissions, and constant-time SHA-256 comparison.
pub fn verify_boot_artifact_sha256(
    path: &Path,
    expected_sha256: &[u8; 32],
    label: &str,
) -> Result<(), HostError> {
    let _sealed = open_and_seal_boot_artifact(path, expected_sha256, label, None)?;
    Ok(())
}

/// Immutable verified boot image handle eliminating filesystem TOCTOU between SHA-256 verification
/// and VMM ingestion (`H4`):
/// - On Linux: backed by an anonymous `memfd_create` sealed with
///   `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE` and passed via `/proc/self/fd/<fd>`.
/// - On macOS: backed by a mode-`0400` `O_EXCL | O_NOFOLLOW` copy in a private `0700` staging dir.
pub struct SealedBootArtifact {
    vmm_path: PathBuf,
    #[cfg(target_os = "linux")]
    memfd_file: File,
    #[cfg(not(target_os = "linux"))]
    staged_cleanup_path: Option<PathBuf>,
}

impl SealedBootArtifact {
    pub fn vmm_path(&self) -> &Path {
        &self.vmm_path
    }

    #[cfg(target_os = "linux")]
    pub fn raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.memfd_file.as_raw_fd()
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for SealedBootArtifact {
    fn drop(&mut self) {
        if let Some(path) = self.staged_cleanup_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn open_and_seal_boot_artifact(
    path: &Path,
    expected_sha256: &[u8; 32],
    label: &str,
    staging_dir: Option<&Path>,
) -> Result<SealedBootArtifact, HostError> {
    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            HostError::new(
                ErrorCode::Validation,
                format!("unable to open {label} artifact '{}': {e}", path.display()),
            )
        })?;
    let meta = src.metadata().map_err(|e| {
        HostError::new(
            ErrorCode::Validation,
            format!("unable to stat {label} artifact: {e}"),
        )
    })?;
    if !meta.is_file() {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} artifact must be a regular file"),
        ));
    }
    if meta.len() == 0 || meta.len() > MAX_BOOT_ARTIFACT_BYTES {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("{label} artifact size must be between 1 byte and 512 MiB"),
        ));
    }
    if (meta.permissions().mode() & 0o002) != 0 {
        return Err(HostError::new(
            ErrorCode::Validation,
            format!("refusing to boot world-writable {label} artifact"),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let _ = staging_dir;
        open_and_seal_linux_memfd(&mut src, expected_sha256, label)
    }

    #[cfg(not(target_os = "linux"))]
    {
        open_and_stage_private_copy(&mut src, expected_sha256, label, path, staging_dir)
    }
}

#[cfg(target_os = "linux")]
fn open_and_seal_linux_memfd(
    src: &mut File,
    expected_sha256: &[u8; 32],
    label: &str,
) -> Result<SealedBootArtifact, HostError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: `c"sb_boot_artifact"` is NUL-terminated; `MFD_CLOEXEC | MFD_ALLOW_SEALING` creates an
    // unlinked anonymous file descriptor owned exclusively by this process.
    let raw_fd = unsafe {
        libc::memfd_create(
            c"sb_boot_artifact".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw_fd < 0 {
        return Err(HostError::new(
            ErrorCode::InternalError,
            format!(
                "memfd_create failed for {label}: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `raw_fd` was freshly returned by `memfd_create`.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut memfd_file = File::from(owned_fd);

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).map_err(|e| {
            HostError::new(
                ErrorCode::Validation,
                format!("error reading {label} artifact: {e}"),
            )
        })?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > MAX_BOOT_ARTIFACT_BYTES {
            return Err(HostError::new(
                ErrorCode::Validation,
                format!("{label} artifact exceeded 512 MiB while streaming"),
            ));
        }
        hasher.update(&buf[..n]);
        memfd_file.write_all(&buf[..n]).map_err(|e| {
            HostError::new(
                ErrorCode::InternalError,
                format!("failed writing {label} to sealed memfd: {e}"),
            )
        })?;
    }

    let actual: [u8; 32] = hasher.finalize().into();
    if !constant_time_eq_32(&actual, expected_sha256) {
        return Err(HostError::new(
            ErrorCode::CryptoFailure,
            format!("{label} SHA-256 verification failed against pinned digest"),
        ));
    }

    memfd_file.seek(SeekFrom::Start(0)).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!("failed rewinding {label} memfd: {e}"),
        )
    })?;

    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: `memfd_file` was created with `MFD_ALLOW_SEALING`; sealing freezes its contents.
    let rc = unsafe { libc::fcntl(memfd_file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    if rc < 0 {
        return Err(HostError::new(
            ErrorCode::InternalError,
            format!(
                "fcntl(F_ADD_SEALS) failed for {label}: {}",
                io::Error::last_os_error()
            ),
        ));
    }

    let fd_num = memfd_file.as_raw_fd();
    Ok(SealedBootArtifact {
        vmm_path: PathBuf::from(format!("/proc/self/fd/{fd_num}")),
        memfd_file,
    })
}

#[cfg(not(target_os = "linux"))]
fn open_and_stage_private_copy(
    src: &mut File,
    expected_sha256: &[u8; 32],
    label: &str,
    original_path: &Path,
    staging_dir: Option<&Path>,
) -> Result<SealedBootArtifact, HostError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 32 * 1024];

    if let Some(dir) = staging_dir {
        std::fs::create_dir_all(dir).map_err(|e| {
            HostError::new(
                ErrorCode::InternalError,
                format!("failed creating boot staging dir: {e}"),
            )
        })?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            HostError::new(
                ErrorCode::InternalError,
                format!("failed securing boot staging dir permissions: {e}"),
            )
        })?;
        let staged_path = dir.join(format!(".sb-{label}-{}.img", uuid::Uuid::new_v4().simple()));
        let mut dst = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged_path)
            .map_err(|e| {
                HostError::new(
                    ErrorCode::InternalError,
                    format!("failed creating staged {label} copy: {e}"),
                )
            })?;
        let guard = DropGuard::new(staged_path.clone(), |p| {
            let _ = std::fs::remove_file(p);
        });
        let mut total = 0u64;
        loop {
            let n = src.read(&mut buf).map_err(|e| {
                HostError::new(
                    ErrorCode::Validation,
                    format!("error reading {label} artifact: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_BOOT_ARTIFACT_BYTES {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    format!("{label} artifact exceeded 512 MiB"),
                ));
            }
            hasher.update(&buf[..n]);
            dst.write_all(&buf[..n]).map_err(|e| {
                HostError::new(
                    ErrorCode::InternalError,
                    format!("failed writing staged {label} copy: {e}"),
                )
            })?;
        }
        dst.sync_all().map_err(|e| {
            HostError::new(
                ErrorCode::InternalError,
                format!("failed syncing staged {label} copy: {e}"),
            )
        })?;
        drop(dst);
        let actual: [u8; 32] = hasher.finalize().into();
        if !constant_time_eq_32(&actual, expected_sha256) {
            return Err(HostError::new(
                ErrorCode::CryptoFailure,
                format!("{label} SHA-256 verification failed against pinned digest"),
            ));
        }
        let confirmed = DropGuard::dismiss(guard);
        Ok(SealedBootArtifact {
            vmm_path: confirmed.clone(),
            staged_cleanup_path: Some(confirmed),
        })
    } else {
        loop {
            let n = src.read(&mut buf).map_err(|e| {
                HostError::new(
                    ErrorCode::Validation,
                    format!("error reading {label} artifact: {e}"),
                )
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if !constant_time_eq_32(&actual, expected_sha256) {
            return Err(HostError::new(
                ErrorCode::CryptoFailure,
                format!("{label} SHA-256 verification failed against pinned digest"),
            ));
        }
        Ok(SealedBootArtifact {
            vmm_path: original_path.to_path_buf(),
            staged_cleanup_path: None,
        })
    }
}

/// Raw full-duplex byte stream connected to the guest enclave's `Noise_IK` responder port.
/// `sb-host` forwards raw `Noise_IK` ciphertext frames over this stream without holding any
/// Noise session keys (`C2`).
pub enum RawEnclaveStream {
    Unix(std::os::unix::net::UnixStream),
    SocketFile(File),
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    MacosVz {
        file: File,
        conn: Arc<macos_vz::RetainedVzConnection>,
    },
}

impl RawEnclaveStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Unix(s) => s.try_clone().map(Self::Unix),
            Self::SocketFile(f) => f.try_clone().map(Self::SocketFile),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, conn } => Ok(Self::MacosVz {
                file: file.try_clone()?,
                conn: Arc::clone(conn),
            }),
        }
    }

    pub fn shutdown_write(&self) {
        match self {
            Self::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
            Self::SocketFile(f) => {
                // SAFETY: `f` wraps a valid stream socket fd (`AF_VSOCK`).
                unsafe {
                    let _ = libc::shutdown(f.as_raw_fd(), libc::SHUT_WR);
                }
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, .. } => {
                // SAFETY: `file` wraps a valid `VZVirtioSocketConnection` stream fd.
                unsafe {
                    let _ = libc::shutdown(file.as_raw_fd(), libc::SHUT_WR);
                }
            }
        }
    }

    pub fn shutdown_both(&self) {
        match self {
            Self::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Self::SocketFile(f) => {
                // SAFETY: `f` wraps a valid stream socket fd.
                unsafe {
                    let _ = libc::shutdown(f.as_raw_fd(), libc::SHUT_RDWR);
                }
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, .. } => {
                // SAFETY: `file` wraps a valid stream socket fd.
                unsafe {
                    let _ = libc::shutdown(file.as_raw_fd(), libc::SHUT_RDWR);
                }
            }
        }
    }
}

impl Read for RawEnclaveStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.read(buf),
            Self::SocketFile(f) => f.read(buf),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, .. } => file.read(buf),
        }
    }
}

impl Write for RawEnclaveStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::SocketFile(f) => f.write(buf),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, .. } => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.flush(),
            Self::SocketFile(f) => f.flush(),
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            Self::MacosVz { file, .. } => file.flush(),
        }
    }
}

#[derive(Clone)]
pub enum EnclaveEndpoint {
    /// Linux KVM separate-kernel microVM (`AF_VSOCK` CID + port).
    Vsock { cid: u32, port: u32 },
    /// Mode-`0600` Unix domain socket (local enclave process / CI tests).
    UnixSocket { path: PathBuf },
    /// macOS `arm64` `Virtualization.framework` `VZVirtioSocketDevice` direct guest connection (`C4`).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    MacosVz {
        vm: Arc<macos_vz::VzVmRuntime>,
        port: u32,
    },
}

pub struct HostCidLease {
    cid: u32,
    _lock_file: File,
}

impl HostCidLease {
    pub fn cid(&self) -> u32 {
        self.cid
    }
}

pub fn default_host_cid_lock_dir(fallback_dir: Option<&Path>) -> Result<PathBuf, HostError> {
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(home).join(".local/run/secretbridge-cids"));
    }
    if let Some(dir) = fallback_dir {
        return Ok(dir.join("secretbridge-cids"));
    }
    Err(HostError::new(
        ErrorCode::Validation,
        "unable to determine host CID lock directory: HOME is not set",
    ))
}

/// Acquires a host-wide exclusive `flock(LOCK_EX | LOCK_NB)` lease on an `AF_VSOCK` guest CID
/// inside `lock_dir`, probing `preferred_cid..=65535` followed by `3..preferred_cid` so multiple
/// IDE processes or `sb-host` instances on the same machine never collide on a managed guest CID.
pub fn acquire_host_cid_lease_in_dir(
    lock_dir: &Path,
    preferred_cid: u32,
) -> Result<HostCidLease, HostError> {
    use std::os::fd::AsRawFd;

    if !(3..=65_535).contains(&preferred_cid) {
        return Err(HostError::new(
            ErrorCode::Validation,
            "preferred guest AF_VSOCK CID must be in 3..=65535",
        ));
    }
    std::fs::create_dir_all(lock_dir).map_err(|e| {
        HostError::new(
            ErrorCode::InternalError,
            format!(
                "failed creating host CID lock directory '{}': {e}",
                lock_dir.display()
            ),
        )
    })?;
    let dir_meta = std::fs::symlink_metadata(lock_dir).map_err(|e| {
        HostError::new(
            ErrorCode::Validation,
            format!("unable to stat host CID lock directory: {e}"),
        )
    })?;
    if !dir_meta.is_dir() || dir_meta.file_type().is_symlink() {
        return Err(HostError::new(
            ErrorCode::Validation,
            "refusing symlinked or non-directory host CID lock path",
        ));
    }
    let _ = std::fs::set_permissions(lock_dir, std::fs::Permissions::from_mode(0o700));

    for candidate in (preferred_cid..=65_535).chain(3..preferred_cid) {
        let lock_path = lock_dir.join(format!("vmm-cid-{candidate}.lock"));
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
        {
            Ok(f) => f,
            Err(_) => continue,
        };
        let meta = match file.metadata() {
            Ok(m) if m.is_file() => m,
            _ => continue,
        };
        let _ = meta;
        // SAFETY: `file` owns a valid open file description; `LOCK_EX | LOCK_NB` never blocks.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(HostCidLease {
                cid: candidate,
                _lock_file: file,
            });
        }
    }

    Err(HostError::new(
        ErrorCode::TransportFailure,
        "exhausted all host AF_VSOCK guest CIDs in 3..=65535",
    ))
}

/// Returns `true` iff `ip` is a globally routable public unicast IPv4/IPv6 address (`V2-H5`, `V2-H6`).
pub fn is_public_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_unicast_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_public_unicast_v4(mapped_v4);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let segs = v6.segments();
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                return false;
            }
            if (segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0)
                || (segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001)
            {
                return false;
            }
            if segs[0] == 0x2002 {
                return false;
            }
            if segs[0] == 0x2001 && segs[1] == 0x0000 {
                return false;
            }
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            if (segs[0] & 0xffc0) == 0xfe80 || (segs[0] & 0xffc0) == 0xfec0 {
                return false;
            }
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return false;
            }
            true
        }
    }
}

fn is_public_unicast_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    if v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
    {
        return false;
    }
    if o[0] == 0 {
        return false;
    }
    if o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    if o[0] >= 240 {
        return false;
    }
    true
}

/// Validates an HTTP `CONNECT <host>:443 HTTP/1.x` request line from the guest enclave's
/// `AF_VSOCK` egress bridge (`V2-H6`). Rejects non-`CONNECT` verbs, ports other than `443`,
/// IP literals, numeric/hex/octal TLDs, and internal/loopback suffixes.
pub fn validate_https_connect_target(request_line: &str) -> Result<String, HostError> {
    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_ascii_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if parts.next().is_some()
        || method != "CONNECT"
        || (version != "HTTP/1.1" && version != "HTTP/1.0")
    {
        return Err(HostError::new(
            ErrorCode::Validation,
            "host AF_VSOCK egress proxy only accepts HTTP/1.x CONNECT requests",
        ));
    }
    let (host_raw, port_raw) = authority.rsplit_once(':').ok_or_else(|| {
        HostError::new(
            ErrorCode::Validation,
            "CONNECT authority must include explicit :443 port",
        )
    })?;
    if port_raw != "443" {
        return Err(HostError::new(
            ErrorCode::Unauthorized,
            "host AF_VSOCK egress proxy restricts outbound traffic strictly to TCP port 443",
        ));
    }
    if host_raw.starts_with('[') || host_raw.ends_with(']') {
        return Err(HostError::new(
            ErrorCode::Validation,
            "IP literals are not permitted in host AF_VSOCK egress proxy",
        ));
    }
    let validated_host: sb_proto::types::GitHubHost = host_raw.parse().map_err(|_| {
        HostError::new(
            ErrorCode::Validation,
            "CONNECT target must be a valid public DNS hostname",
        )
    })?;
    Ok(validated_host.as_str().to_string())
}

pub struct HostVsockHttpsEgressProxy {
    port: u32,
    listener_fd: OwnedFd,
    shutdown: Arc<AtomicBool>,
}

impl HostVsockHttpsEgressProxy {
    pub fn port(&self) -> u32 {
        self.port
    }

    #[cfg(target_os = "linux")]
    pub fn bind_for_guest_cid(expected_guest_cid: u32) -> Result<Self, HostError> {
        // SAFETY: Creates a host `AF_VSOCK` stream socket with `SOCK_CLOEXEC`.
        let raw_fd =
            unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                format!(
                    "AF_VSOCK egress proxy socket() failed: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: `raw_fd` is newly created and owned solely by `listener_fd`.
        let listener_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = libc::VMADDR_PORT_ANY;

        if unsafe {
            libc::bind(
                listener_fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                format!(
                    "AF_VSOCK egress proxy bind() failed: {}",
                    io::Error::last_os_error()
                ),
            ));
        }

        let mut bound_addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut bound_len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                listener_fd.as_raw_fd(),
                (&raw mut bound_addr).cast::<libc::sockaddr>(),
                &raw mut bound_len,
            )
        } < 0
        {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                format!(
                    "AF_VSOCK egress proxy getsockname() failed: {}",
                    io::Error::last_os_error()
                ),
            ));
        }

        if unsafe { libc::listen(listener_fd.as_raw_fd(), 16) } < 0 {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                format!(
                    "AF_VSOCK egress proxy listen() failed: {}",
                    io::Error::last_os_error()
                ),
            ));
        }

        let dup_raw = unsafe { libc::fcntl(listener_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_raw < 0 {
            return Err(HostError::new(
                ErrorCode::InternalError,
                format!(
                    "dup(AF_VSOCK egress listener) failed: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        // SAFETY: `dup_raw` was freshly duplicated for the accept thread.
        let accept_fd = unsafe { OwnedFd::from_raw_fd(dup_raw) };
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_worker = Arc::clone(&shutdown);
        let active_conns = Arc::new(AtomicUsize::new(0));
        let assigned_port = bound_addr.svm_port;

        std::thread::spawn(move || {
            while !shutdown_worker.load(Ordering::Relaxed) {
                let mut peer_addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
                let mut peer_len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
                let client_raw = unsafe {
                    libc::accept4(
                        accept_fd.as_raw_fd(),
                        (&raw mut peer_addr).cast::<libc::sockaddr>(),
                        &raw mut peer_len,
                        libc::SOCK_CLOEXEC,
                    )
                };
                if client_raw < 0 {
                    if shutdown_worker.load(Ordering::Relaxed) {
                        break;
                    }
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                // SAFETY: `client_raw` was freshly returned by `accept4`.
                let client_file = File::from(unsafe { OwnedFd::from_raw_fd(client_raw) });
                if peer_addr.svm_cid != expected_guest_cid {
                    drop(client_file);
                    continue;
                }
                if active_conns.fetch_add(1, Ordering::AcqRel) >= 16 {
                    active_conns.fetch_sub(1, Ordering::AcqRel);
                    drop(client_file);
                    continue;
                }
                let active_clone = Arc::clone(&active_conns);
                std::thread::spawn(move || {
                    let _slot_guard = DropGuard::new(active_clone, |cnt| {
                        cnt.fetch_sub(1, Ordering::AcqRel);
                    });
                    handle_https_connect_tunnel(client_file);
                });
            }
        });

        Ok(Self {
            port: assigned_port,
            listener_fd,
            shutdown,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn bind_for_guest_cid(_expected_guest_cid: u32) -> Result<Self, HostError> {
        Err(HostError::new(
            ErrorCode::TransportFailure,
            "AF_VSOCK host egress proxy is only supported on Linux",
        ))
    }
}

impl Drop for HostVsockHttpsEgressProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        unsafe {
            let _ = libc::shutdown(self.listener_fd.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
}

#[cfg(target_os = "linux")]
fn handle_https_connect_tunnel(mut guest_stream: File) {
    use std::net::ToSocketAddrs;

    apply_socket_timeouts(guest_stream.as_raw_fd());
    let mut header_buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while header_buf.len() < 4096 {
        match guest_stream.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => {
                header_buf.push(byte[0]);
                if header_buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
    if !header_buf.ends_with(b"\r\n\r\n") {
        let _ = guest_stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        return;
    }
    let Ok(header_str) = std::str::from_utf8(&header_buf) else {
        let _ = guest_stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        return;
    };
    let first_line = header_str.lines().next().unwrap_or("");
    let Ok(host) = validate_https_connect_target(first_line) else {
        let _ = guest_stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
    };

    let Ok(resolved_iter) = (host.as_str(), 443u16).to_socket_addrs() else {
        let _ = guest_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        return;
    };
    let addrs: Vec<std::net::SocketAddr> = resolved_iter.collect();
    if addrs.is_empty() || !addrs.iter().all(|a| is_public_unicast_ip(a.ip())) {
        let _ = guest_stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        return;
    }

    let mut upstream = None;
    for candidate in addrs {
        if let Ok(tcp) = std::net::TcpStream::connect_timeout(&candidate, Duration::from_secs(10)) {
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(45)));
            let _ = tcp.set_write_timeout(Some(Duration::from_secs(45)));
            upstream = Some(tcp);
            break;
        }
    }
    let Some(mut tcp_stream) = upstream else {
        let _ = guest_stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        return;
    };

    if guest_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
        || guest_stream.flush().is_err()
    {
        return;
    }

    let Ok(mut guest_reader) = guest_stream.try_clone() else {
        return;
    };
    let Ok(mut tcp_writer) = tcp_stream.try_clone() else {
        return;
    };

    let t_up = std::thread::spawn(move || {
        let _ = io::copy(&mut guest_reader, &mut tcp_writer);
        let _ = tcp_writer.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut tcp_stream, &mut guest_stream);
    unsafe {
        let _ = libc::shutdown(guest_stream.as_raw_fd(), libc::SHUT_WR);
    }
    let _ = t_up.join();
}

pub struct ManagedEnclaveHandle {
    endpoint: EnclaveEndpoint,
    enclave_pubkey: [u8; 32],
    child_vm: Option<Child>,
    _boot_artifacts: Vec<SealedBootArtifact>,
    _verified_executables: Vec<VerifiedExecutable>,
    _cid_lease: Option<HostCidLease>,
    _egress_proxy: Option<HostVsockHttpsEgressProxy>,
}

impl Drop for ManagedEnclaveHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child_vm.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone)]
pub struct MicroVmLaunchSpec {
    pub vmm_binary: PathBuf,
    pub vmm_sha256: Option<[u8; 32]>,
    pub kernel_path: PathBuf,
    pub kernel_sha256: [u8; 32],
    pub initramfs_path: PathBuf,
    pub initramfs_sha256: [u8; 32],
    pub authorized_client_pubkey: [u8; 32],
    pub guest_cid: u32,
    pub vsock_port: u32,
    pub memory_mib: u32,
    pub staging_dir: Option<PathBuf>,
}

impl ManagedEnclaveHandle {
    /// Connects to an already-running enclave over `AF_VSOCK` or a mode-`0600` Unix socket.
    pub fn connect_existing(endpoint: EnclaveEndpoint, enclave_pubkey: [u8; 32]) -> Self {
        Self {
            endpoint,
            enclave_pubkey,
            child_vm: None,
            _boot_artifacts: Vec::new(),
            _verified_executables: Vec::new(),
            _cid_lease: None,
            _egress_proxy: None,
        }
    }

    /// Boots the platform's native isolated microVM backend:
    /// - Linux (`x86_64`/`aarch64`): KVM + QEMU (`q35` / `virt`) using `memfd`-sealed boot images
    ///   and `AF_VSOCK` (`vhost-vsock-pci`).
    /// - macOS (`aarch64`): `Virtualization.framework` (`VZVirtualMachine` + `VZVirtioSocketDevice`).
    pub fn boot_native_microvm(spec: &MicroVmLaunchSpec) -> Result<Self, HostError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Self::boot_macos_vz_microvm(spec)
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            Self::boot_kvm_microvm(spec)
        }
    }

    /// Verifies & seals VMM binary + kernel & initramfs into immutable `memfd`s (`H4`, `V2-H6`),
    /// restricts QEMU SLIRP (`restrict=on`) so guest packets can never reach host loopback, and
    /// exposes a public-unicast-only `:443` `CONNECT` bridge over `AF_VSOCK`.
    pub fn boot_kvm_microvm(spec: &MicroVmLaunchSpec) -> Result<Self, HostError> {
        let verified_vmm =
            open_and_seal_executable_binary(&spec.vmm_binary, spec.vmm_sha256.as_ref(), "VMM")?;
        let sealed_kernel = open_and_seal_boot_artifact(
            &spec.kernel_path,
            &spec.kernel_sha256,
            "vmlinuz",
            spec.staging_dir.as_deref(),
        )?;
        let sealed_initramfs = open_and_seal_boot_artifact(
            &spec.initramfs_path,
            &spec.initramfs_sha256,
            "initramfs",
            spec.staging_dir.as_deref(),
        )?;

        if !Path::new("/dev/kvm").exists() {
            return Err(HostError::new(
                ErrorCode::TransportFailure,
                "/dev/kvm is not available on this Linux host; enable KVM virtualization",
            ));
        }
        if !(3..=65_535).contains(&spec.guest_cid) {
            return Err(HostError::new(
                ErrorCode::Validation,
                "guest AF_VSOCK CID must be in 3..=65535 (CIDs 0..=2 are reserved)",
            ));
        }

        let cid_lock_dir = default_host_cid_lock_dir(spec.staging_dir.as_deref())?;
        let client_pk_hex = hex::encode(spec.authorized_client_pubkey);
        let (arch_machine, console_dev) = if cfg!(target_arch = "aarch64") {
            ("virt,accel=kvm,gic-version=3", "ttyAMA0")
        } else {
            ("q35,accel=kvm", "ttyS0")
        };

        let mut skipped_leases = Vec::new();
        let mut preferred_cid = spec.guest_cid;
        const MAX_CID_ATTEMPTS: usize = 8;

        for attempt in 0..MAX_CID_ATTEMPTS {
            let cid_lease = acquire_host_cid_lease_in_dir(&cid_lock_dir, preferred_cid)?;
            let leased_cid = cid_lease.cid();
            let egress_proxy = HostVsockHttpsEgressProxy::bind_for_guest_cid(leased_cid)?;
            let cmdline = format!(
                "console={console_dev} reboot=k panic=1 nomodules quiet rdinit=/init ip=dhcp sb.net_fallback=qemu_slirp sb.vsock_port={} sb.egress_vsock_port={} sb.client_pubkey={client_pk_hex}",
                spec.vsock_port,
                egress_proxy.port()
            );

            let mut cmd = Command::new(verified_vmm.exec_path());
            cmd.args([
                "-machine",
                arch_machine,
                "-cpu",
                "host",
                "-m",
                &format!("{}M", spec.memory_mib.max(128)),
                "-smp",
                "1",
                "-nodefaults",
                "-no-user-config",
                "-nographic",
                "-serial",
                "stdio",
                "-kernel",
            ])
            .arg(sealed_kernel.vmm_path())
            .arg("-initrd")
            .arg(sealed_initramfs.vmm_path())
            .args(["-append", &cmdline])
            .args([
                "-object",
                "rng-random,filename=/dev/urandom,id=rng0",
                "-device",
                "virtio-rng-pci,rng=rng0",
                "-netdev",
                "user,id=net0,restrict=on",
                "-device",
                "virtio-net-pci,netdev=net0",
                "-device",
                &format!("vhost-vsock-pci,guest-cid={leased_cid},id=vsock0"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                let parent_pid = unsafe { libc::getpid() };
                let kernel_fd = sealed_kernel.raw_fd();
                let initrd_fd = sealed_initramfs.raw_fd();
                // SAFETY: Runs in forked child before `execve`; uses only async-signal-safe libc calls
                // (`prctl`, `getppid`, `fcntl`, `_exit`) to bind lifecycle to parent and pass sealed memfds.
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::getppid() != parent_pid {
                            libc::_exit(1);
                        }
                        for fd in [kernel_fd, initrd_fd] {
                            let flags = libc::fcntl(fd, libc::F_GETFD);
                            if flags < 0 {
                                return Err(io::Error::last_os_error());
                            }
                            if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                                return Err(io::Error::last_os_error());
                            }
                        }
                        Ok(())
                    });
                }
            }

            let child = cmd.spawn().map_err(|e| {
                HostError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to launch microVM VMM '{}': {e}",
                        spec.vmm_binary.display()
                    ),
                )
            })?;

            let mut child_guard = DropGuard::new(child, |mut c| {
                let _ = c.kill();
                let _ = c.wait();
            });

            let stderr_capture = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
            if let Some(stderr) = child_guard.stderr.take() {
                spawn_stderr_capture_drainer(stderr, std::sync::Arc::clone(&stderr_capture));
            }
            let stdout = child_guard.stdout.take().ok_or_else(|| {
                HostError::new(ErrorCode::TransportFailure, "missing microVM serial stdout")
            })?;
            match read_enclave_pubkey_banner_and_drain(stdout, Duration::from_secs(20)) {
                Ok(enclave_pubkey) => {
                    drop(skipped_leases);
                    let confirmed_child = DropGuard::dismiss(child_guard);
                    return Ok(Self {
                        endpoint: EnclaveEndpoint::Vsock {
                            cid: leased_cid,
                            port: spec.vsock_port,
                        },
                        enclave_pubkey,
                        child_vm: Some(confirmed_child),
                        _boot_artifacts: vec![sealed_kernel, sealed_initramfs],
                        _verified_executables: vec![verified_vmm],
                        _cid_lease: Some(cid_lease),
                        _egress_proxy: Some(egress_proxy),
                    });
                }
                Err(boot_err) => {
                    drop(child_guard);
                    drop(egress_proxy);
                    let stderr_snapshot = stderr_capture
                        .lock()
                        .map(|s| s.to_ascii_lowercase())
                        .unwrap_or_default();
                    let cid_conflict = stderr_snapshot.contains("guest-cid")
                        || stderr_snapshot.contains("vhost-vsock")
                        || stderr_snapshot.contains("address already in use");
                    if cid_conflict && attempt + 1 < MAX_CID_ATTEMPTS {
                        preferred_cid = if leased_cid >= 65_535 {
                            3
                        } else {
                            leased_cid + 1
                        };
                        skipped_leases.push(cid_lease);
                        continue;
                    }
                    return Err(boot_err);
                }
            }
        }

        Err(HostError::new(
            ErrorCode::TransportFailure,
            "unable to allocate an unused vhost-vsock guest CID after multiple attempts",
        ))
    }

    /// Boots an isolated Linux `arm64` microVM via Apple's `Virtualization.framework`
    /// (`VZVirtualMachine` + `VZVirtioSocketDevice`) on macOS `arm64` (`C4`).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn boot_macos_vz_microvm(spec: &MicroVmLaunchSpec) -> Result<Self, HostError> {
        let sealed_kernel = open_and_seal_boot_artifact(
            &spec.kernel_path,
            &spec.kernel_sha256,
            "vmlinuz",
            spec.staging_dir.as_deref(),
        )?;
        let sealed_initramfs = open_and_seal_boot_artifact(
            &spec.initramfs_path,
            &spec.initramfs_sha256,
            "initramfs",
            spec.staging_dir.as_deref(),
        )?;

        let client_pk_hex = hex::encode(spec.authorized_client_pubkey);
        let cmdline = format!(
            "console=hvc0 reboot=k panic=1 nomodules quiet rdinit=/init ip=dhcp sb.vsock_port={} sb.client_pubkey={client_pk_hex}",
            spec.vsock_port
        );

        let (vz_runtime, serial_reader) = macos_vz::VzVmRuntime::start(
            sealed_kernel.vmm_path(),
            sealed_initramfs.vmm_path(),
            &cmdline,
            spec.memory_mib.max(128),
        )?;
        let enclave_pubkey =
            read_enclave_pubkey_banner_and_drain(serial_reader, Duration::from_secs(20))?;

        Ok(Self {
            endpoint: EnclaveEndpoint::MacosVz {
                vm: Arc::new(vz_runtime),
                port: spec.vsock_port,
            },
            enclave_pubkey,
            child_vm: None,
            _boot_artifacts: vec![sealed_kernel, sealed_initramfs],
            _verified_executables: Vec::new(),
            _cid_lease: None,
            _egress_proxy: None,
        })
    }

    /// Spawns `sb-enclave` over a local mode-`0600` Unix domain socket (used in automated CI/integration tests).
    pub fn spawn_local_bridge_process(
        enclave_bin: &Path,
        socket_path: &Path,
        authorized_client_pubkey: [u8; 32],
        extra_args: &[String],
    ) -> Result<Self, HostError> {
        let verified_bin = open_and_seal_executable_binary(enclave_bin, None, "sb-enclave")?;
        let client_pk_hex = hex::encode(authorized_client_pubkey);

        let mut cmd = Command::new(verified_bin.exec_path());
        cmd.arg("--unix-socket")
            .arg(socket_path)
            .arg("--authorized-client-pubkey-hex")
            .arg(&client_pk_hex)
            .args(extra_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let parent_pid = unsafe { libc::getpid() };
            // SAFETY: Async-signal-safe `prctl` + `getppid` in forked child before `execve`.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        libc::_exit(1);
                    }
                    Ok(())
                });
            }
        }

        let child = cmd.spawn().map_err(|e| {
            HostError::new(
                ErrorCode::TransportFailure,
                format!("failed spawning enclave process: {e}"),
            )
        })?;
        let mut child_guard = DropGuard::new(child, |mut c| {
            let _ = c.kill();
            let _ = c.wait();
        });

        if let Some(stderr) = child_guard.stderr.take() {
            spawn_pipe_drainer(stderr);
        }
        let stdout = child_guard.stdout.take().ok_or_else(|| {
            HostError::new(ErrorCode::TransportFailure, "missing enclave stdout pipe")
        })?;
        let enclave_pubkey = read_enclave_pubkey_banner_and_drain(stdout, Duration::from_secs(10))?;

        let wait_deadline = Instant::now() + Duration::from_secs(3);
        while !socket_path.exists() && Instant::now() < wait_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }

        let confirmed_child = DropGuard::dismiss(child_guard);
        Ok(Self {
            endpoint: EnclaveEndpoint::UnixSocket {
                path: socket_path.to_path_buf(),
            },
            enclave_pubkey,
            child_vm: Some(confirmed_child),
            _boot_artifacts: Vec::new(),
            _verified_executables: vec![verified_bin],
            _cid_lease: None,
            _egress_proxy: None,
        })
    }

    pub fn enclave_pubkey(&self) -> &[u8; 32] {
        &self.enclave_pubkey
    }

    /// Opens a raw stream to the guest enclave's `Noise_IK` responder port for blind frame relay (`C2`).
    pub fn open_raw_stream(&self) -> Result<RawEnclaveStream, HostError> {
        match &self.endpoint {
            EnclaveEndpoint::UnixSocket { path } => {
                let stream = std::os::unix::net::UnixStream::connect(path).map_err(|e| {
                    HostError::new(
                        ErrorCode::TransportFailure,
                        format!("failed connecting to enclave socket: {e}"),
                    )
                })?;
                let _ = stream.set_read_timeout(Some(Duration::from_secs(45)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(45)));
                Ok(RawEnclaveStream::Unix(stream))
            }
            EnclaveEndpoint::Vsock { cid, port } => {
                let vsock_file = connect_linux_vsock(*cid, *port)?;
                Ok(RawEnclaveStream::SocketFile(vsock_file))
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            EnclaveEndpoint::MacosVz { vm, port } => {
                let (conn_file, retained_conn) =
                    macos_vz::VzVmRuntime::connect_vsock_port(vm, *port)?;
                Ok(RawEnclaveStream::MacosVz {
                    file: conn_file,
                    conn: Arc::new(retained_conn),
                })
            }
        }
    }
}

fn spawn_pipe_drainer<R: Read + Send + 'static>(mut reader: R) {
    let _ = std::thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut io::sink());
    });
}

fn spawn_stderr_capture_drainer<R: Read + Send + 'static>(
    mut reader: R,
    captured: std::sync::Arc<std::sync::Mutex<String>>,
) {
    let _ = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Ok(mut guard) = captured.lock()
                && guard.len() < 4096
            {
                let remaining = 4096 - guard.len();
                let slice = &buf[..n.min(remaining)];
                guard.push_str(&String::from_utf8_lossy(slice));
            }
        }
    });
}

/// Reads bounded serial output (`<= 64 KiB`) until `SB_ENCLAVE_NOISE_PUBKEY=<64-hex>` is seen,
/// then continues draining `reader` into `io::sink()` in the background so guest serial writes
/// never block on a full pipe (`H4`).
fn read_enclave_pubkey_banner_and_drain<R: Read + Send + 'static>(
    mut reader: R,
    timeout: Duration,
) -> Result<[u8; 32], HostError> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<String, HostError>>();
    std::thread::spawn(move || {
        let mut window = Vec::with_capacity(1024);
        let mut total_before_banner = 0usize;
        let mut chunk = [0u8; 512];
        let mut found = false;

        loop {
            match reader.read(&mut chunk) {
                Ok(0) => {
                    if !found {
                        let _ = tx.send(Err(HostError::new(
                            ErrorCode::TransportFailure,
                            "guest serial closed before emitting SB_ENCLAVE_NOISE_PUBKEY",
                        )));
                    }
                    return;
                }
                Ok(n) => {
                    if !found {
                        total_before_banner = total_before_banner.saturating_add(n);
                        if total_before_banner > MAX_SERIAL_BANNER_BYTES {
                            let _ = tx.send(Err(HostError::new(
                                ErrorCode::TransportFailure,
                                "guest serial output exceeded 64 KiB before emitting SB_ENCLAVE_NOISE_PUBKEY",
                            )));
                            found = true;
                            continue;
                        }
                        window.extend_from_slice(&chunk[..n]);
                        while let Some(nl_pos) = window.iter().position(|&b| b == b'\n') {
                            let line_bytes: Vec<u8> = window.drain(..=nl_pos).collect();
                            let line = String::from_utf8_lossy(&line_bytes);
                            if let Some(hex_pk) =
                                line.trim().strip_prefix("SB_ENCLAVE_NOISE_PUBKEY=")
                            {
                                let _ = tx.send(Ok(hex_pk.trim().to_string()));
                                found = true;
                                window.clear();
                                window.shrink_to_fit();
                                break;
                            }
                        }
                        if !found && window.len() > 4096 {
                            // Bound single-line memory even if guest emits no newlines
                            let keep_from = window.len().saturating_sub(256);
                            window.drain(..keep_from);
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    if !found {
                        let _ = tx.send(Err(HostError::new(
                            ErrorCode::TransportFailure,
                            format!("error reading guest serial output: {e}"),
                        )));
                    }
                    return;
                }
            }
        }
    });

    let pk_hex = rx.recv_timeout(timeout).map_err(|_| {
        HostError::new(
            ErrorCode::TransportFailure,
            "timed out waiting for SB_ENCLAVE_NOISE_PUBKEY banner from guest enclave",
        )
    })??;
    let raw = hex::decode(pk_hex.trim()).map_err(|_| {
        HostError::new(
            ErrorCode::CryptoFailure,
            "invalid hex in SB_ENCLAVE_NOISE_PUBKEY banner",
        )
    })?;
    raw.as_slice().try_into().map_err(|_| {
        HostError::new(
            ErrorCode::CryptoFailure,
            "enclave Noise static public key must be 32 bytes",
        )
    })
}

fn apply_socket_timeouts(raw_fd: libc::c_int) {
    let tv = libc::timeval {
        tv_sec: 45,
        tv_usec: 0,
    };
    // SAFETY: `raw_fd` is a valid stream socket descriptor; `tv` is initialized.
    unsafe {
        let _ = libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

#[cfg(target_os = "linux")]
fn connect_linux_vsock(cid: u32, port: u32) -> Result<File, HostError> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: creates a stream `AF_VSOCK` socket with `SOCK_CLOEXEC`.
    let raw_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        let err = io::Error::last_os_error();
        return Err(HostError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK socket() failed: {err}"),
        ));
    }
    let fd_guard = DropGuard::new(raw_fd, |fd| unsafe {
        let _ = libc::close(fd);
    });

    apply_socket_timeouts(*fd_guard);

    // SAFETY: zero-initializing POD `sockaddr_vm`.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;

    // SAFETY: `addr` has exact `sockaddr_vm` size.
    let rc = unsafe {
        libc::connect(
            *fd_guard,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return Err(HostError::new(
            ErrorCode::TransportFailure,
            format!("AF_VSOCK connect(cid={cid}, port={port}) failed: {err}"),
        ));
    }

    let confirmed_fd = DropGuard::dismiss(fd_guard);
    // SAFETY: `confirmed_fd` is newly created and owned exclusively here.
    let owned = unsafe { OwnedFd::from_raw_fd(confirmed_fd) };
    Ok(File::from(owned))
}

#[cfg(not(target_os = "linux"))]
fn connect_linux_vsock(_cid: u32, _port: u32) -> Result<File, HostError> {
    Err(HostError::new(
        ErrorCode::TransportFailure,
        "direct host AF_VSOCK requires Linux; on macOS arm64 use Virtualization.framework VZVirtioSocketDevice",
    ))
}

// =========================================================================
// macOS arm64 Virtualization.framework + VZVirtioSocketDevice Backend (C4)
// =========================================================================

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_vz {
    use super::*;
    use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::ptr;
    use std::sync::{Condvar, Mutex};

    type Id = *mut c_void;
    type Sel = *const c_void;
    type DispatchQueue = *mut c_void;

    const BLOCK_HAS_COPY_DISPOSE: c_int = 1 << 25;

    #[link(name = "Virtualization", kind = "framework")]
    #[link(name = "Foundation", kind = "framework")]
    #[link(name = "objc")]
    unsafe extern "C" {
        static _NSConcreteStackBlock: [*const c_void; 32];

        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);

        fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
        fn dispatch_async_f(
            queue: DispatchQueue,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
        fn dispatch_release(object: DispatchQueue);
    }

    unsafe fn cls(name: &CStr) -> Id {
        unsafe { objc_getClass(name.as_ptr()) }
    }

    unsafe fn sel(name: &CStr) -> Sel {
        unsafe { sel_registerName(name.as_ptr()) }
    }

    #[repr(C)]
    struct BlockDescriptor<B> {
        reserved: c_ulong,
        size: c_ulong,
        copy_helper: unsafe extern "C" fn(*mut B, *const B),
        dispose_helper: unsafe extern "C" fn(*mut B),
    }

    #[repr(C)]
    struct ArcStackBlock1<T> {
        isa: *const c_void,
        flags: c_int,
        reserved: c_int,
        invoke: unsafe extern "C" fn(*mut Self, Id),
        descriptor: *const BlockDescriptor<Self>,
        ctx: *const T,
    }

    impl<T> Drop for ArcStackBlock1<T> {
        fn drop(&mut self) {
            if !self.ctx.is_null() {
                unsafe {
                    drop(Arc::from_raw(self.ctx));
                }
            }
        }
    }

    unsafe extern "C" fn copy_block1<T>(
        dst: *mut ArcStackBlock1<T>,
        src: *const ArcStackBlock1<T>,
    ) {
        unsafe {
            let ptr = (*src).ctx;
            Arc::increment_strong_count(ptr);
            (*dst).ctx = ptr;
        }
    }

    unsafe extern "C" fn dispose_block1<T>(src: *mut ArcStackBlock1<T>) {
        unsafe {
            let ptr = (*src).ctx;
            if !ptr.is_null() {
                drop(Arc::from_raw(ptr));
            }
        }
    }

    #[repr(C)]
    struct ArcStackBlock2<T> {
        isa: *const c_void,
        flags: c_int,
        reserved: c_int,
        invoke: unsafe extern "C" fn(*mut Self, Id, Id),
        descriptor: *const BlockDescriptor<Self>,
        ctx: *const T,
    }

    impl<T> Drop for ArcStackBlock2<T> {
        fn drop(&mut self) {
            if !self.ctx.is_null() {
                unsafe {
                    drop(Arc::from_raw(self.ctx));
                }
            }
        }
    }

    unsafe extern "C" fn copy_block2<T>(
        dst: *mut ArcStackBlock2<T>,
        src: *const ArcStackBlock2<T>,
    ) {
        unsafe {
            let ptr = (*src).ctx;
            Arc::increment_strong_count(ptr);
            (*dst).ctx = ptr;
        }
    }

    unsafe extern "C" fn dispose_block2<T>(src: *mut ArcStackBlock2<T>) {
        unsafe {
            let ptr = (*src).ctx;
            if !ptr.is_null() {
                drop(Arc::from_raw(ptr));
            }
        }
    }

    type CompletionSignal<R> = Arc<(Mutex<Option<Result<R, HostError>>>, Condvar)>;

    fn new_signal<R>() -> CompletionSignal<R> {
        Arc::new((Mutex::new(None), Condvar::new()))
    }

    fn complete_signal<R>(sig: &CompletionSignal<R>, res: Result<R, HostError>) {
        if let Ok(mut guard) = sig.0.lock() {
            *guard = Some(res);
            sig.1.notify_all();
        }
    }

    fn wait_signal<R>(
        sig: &CompletionSignal<R>,
        timeout: Duration,
        op: &str,
    ) -> Result<R, HostError> {
        let guard = sig.0.lock().map_err(|_| {
            HostError::new(ErrorCode::InternalError, "VZ completion mutex poisoned")
        })?;
        let (mut guard, _) = sig
            .1
            .wait_timeout_while(guard, timeout, |slot| slot.is_none())
            .map_err(|_| HostError::new(ErrorCode::InternalError, "VZ completion wait poisoned"))?;
        guard.take().ok_or_else(|| {
            HostError::new(
                ErrorCode::TransportFailure,
                format!("Virtualization.framework timed out during {op}"),
            )
        })?
    }

    unsafe fn nsstring_from_str(s: &str) -> Result<Id, HostError> {
        let cstr = CString::new(s).map_err(|_| {
            HostError::new(
                ErrorCode::Validation,
                "NUL byte in Virtualization.framework string",
            )
        })?;
        unsafe {
            let msg_str: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);
            let obj = msg_str(
                cls(c"NSString"),
                sel(c"stringWithUTF8String:"),
                cstr.as_ptr(),
            );
            if obj.is_null() {
                return Err(HostError::new(
                    ErrorCode::InternalError,
                    "NSString allocation failed",
                ));
            }
            Ok(obj)
        }
    }

    unsafe fn file_url_from_path(path: &Path) -> Result<Id, HostError> {
        let path_str = path.to_str().ok_or_else(|| {
            HostError::new(
                ErrorCode::Validation,
                "boot artifact path must be valid UTF-8",
            )
        })?;
        unsafe {
            let ns_path = nsstring_from_str(path_str)?;
            let msg_url: unsafe extern "C" fn(Id, Sel, Id) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);
            let url = msg_url(cls(c"NSURL"), sel(c"fileURLWithPath:"), ns_path);
            if url.is_null() {
                return Err(HostError::new(
                    ErrorCode::Validation,
                    "NSURL fileURLWithPath failed",
                ));
            }
            Ok(url)
        }
    }

    unsafe fn nserror_description(err: Id) -> String {
        if err.is_null() {
            return "unknown NSError".to_string();
        }
        unsafe {
            let msg0: unsafe extern "C" fn(Id, Sel) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);
            let msg_utf8: unsafe extern "C" fn(Id, Sel) -> *const c_char =
                std::mem::transmute(objc_msgSend as *const c_void);
            let desc = msg0(err, sel(c"localizedDescription"));
            if desc.is_null() {
                return "NSError (null description)".to_string();
            }
            let ptr = msg_utf8(desc, sel(c"UTF8String"));
            if ptr.is_null() {
                "NSError (non-UTF8 description)".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        }
    }

    pub struct VzVmRuntime {
        vm_obj: Id,
        queue: DispatchQueue,
        _stdin_write_keepalive: File,
    }

    // SAFETY: `vm_obj` is ONLY ever accessed on the serial `queue` via `dispatch_async_f`,
    // satisfying Apple's `VZVirtualMachine` single-queue confinement contract.
    unsafe impl Send for VzVmRuntime {}
    unsafe impl Sync for VzVmRuntime {}

    /// Keeps `VZVirtioSocketConnection` retained for the entire lifetime of `RawEnclaveStream` (`V2-C3`),
    /// preventing `-dealloc` from tearing down the virtio-vsock stream while `dup`ed fds are active.
    pub struct RetainedVzConnection {
        conn_obj: Id,
        vm: Arc<VzVmRuntime>,
    }

    unsafe impl Send for RetainedVzConnection {}
    unsafe impl Sync for RetainedVzConnection {}

    unsafe extern "C" fn release_obj_on_queue(raw_obj: *mut c_void) {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let release_fn: unsafe extern "C" fn(Id, Sel) =
                std::mem::transmute(objc_msgSend as *const c_void);
            release_fn(raw_obj as Id, sel(c"release"));
            objc_autoreleasePoolPop(pool);
        }
    }

    impl Drop for RetainedVzConnection {
        fn drop(&mut self) {
            if !self.conn_obj.is_null() {
                unsafe {
                    dispatch_async_f(self.vm.queue, self.conn_obj, release_obj_on_queue);
                }
            }
        }
    }

    struct StartContext {
        kernel_path: PathBuf,
        initrd_path: PathBuf,
        cmdline: String,
        memory_mib: u32,
        guest_stdin_read_fd: c_int,
        guest_stdout_write_fd: c_int,
        queue: DispatchQueue,
        signal: CompletionSignal<usize>,
    }

    unsafe extern "C" fn on_vm_started(
        block: *mut ArcStackBlock1<(CompletionSignal<usize>, usize)>,
        err: Id,
    ) {
        unsafe {
            let (ref sig, vm_addr) = *(*block).ctx;
            if err.is_null() {
                complete_signal(sig, Ok(vm_addr));
            } else {
                let msg0: unsafe extern "C" fn(Id, Sel) =
                    std::mem::transmute(objc_msgSend as *const c_void);
                msg0(vm_addr as Id, sel(c"release"));
                complete_signal(
                    sig,
                    Err(HostError::new(
                        ErrorCode::TransportFailure,
                        format!(
                            "VZVirtualMachine start failed: {}",
                            nserror_description(err)
                        ),
                    )),
                );
            }
        }
    }

    unsafe extern "C" fn start_vm_on_queue(raw_ctx: *mut c_void) {
        unsafe {
            let ctx = Box::from_raw(raw_ctx.cast::<StartContext>());
            let pool = objc_autoreleasePoolPush();
            let _pool_guard = DropGuard::new(pool, |p| objc_autoreleasePoolPop(p));

            // Track pipe FD ownership explicitly so `NSFileHandle(closeOnDealloc: YES)` never
            // double-closes an FD if `validateWithError:` or VM allocation fails (`V2-C3`).
            let mut unowned_stdin_fd = Some(ctx.guest_stdin_read_fd);
            let mut unowned_stdout_fd = Some(ctx.guest_stdout_write_fd);

            let setup_res: Result<Id, HostError> = (|| {
                let msg0: unsafe extern "C" fn(Id, Sel) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let msg1: unsafe extern "C" fn(Id, Sel, Id) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let set1: unsafe extern "C" fn(Id, Sel, Id) =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let set_u64: unsafe extern "C" fn(Id, Sel, u64) =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let init_fh: unsafe extern "C" fn(Id, Sel, c_int, i8) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let init_serial: unsafe extern "C" fn(Id, Sel, Id, Id) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let array_with_obj: unsafe extern "C" fn(Id, Sel, Id) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let validate_fn: unsafe extern "C" fn(Id, Sel, *mut Id) -> i8 =
                    std::mem::transmute(objc_msgSend as *const c_void);
                let init_vm: unsafe extern "C" fn(Id, Sel, Id, DispatchQueue) -> Id =
                    std::mem::transmute(objc_msgSend as *const c_void);

                let kernel_url = file_url_from_path(&ctx.kernel_path)?;
                let initrd_url = file_url_from_path(&ctx.initrd_path)?;
                let cmd_ns = nsstring_from_str(&ctx.cmdline)?;

                let boot = msg1(
                    msg0(cls(c"VZLinuxBootLoader"), sel(c"alloc")),
                    sel(c"initWithKernelURL:"),
                    kernel_url,
                );
                msg0(boot, sel(c"autorelease"));
                set1(boot, sel(c"setInitialRamdiskURL:"), initrd_url);
                set1(boot, sel(c"setCommandLine:"), cmd_ns);

                let fh_read = init_fh(
                    msg0(cls(c"NSFileHandle"), sel(c"alloc")),
                    sel(c"initWithFileDescriptor:closeOnDealloc:"),
                    ctx.guest_stdin_read_fd,
                    1,
                );
                if fh_read.is_null() {
                    return Err(HostError::new(
                        ErrorCode::InternalError,
                        "NSFileHandle(stdin) allocation failed",
                    ));
                }
                unowned_stdin_fd = None;
                msg0(fh_read, sel(c"autorelease"));

                let fh_write = init_fh(
                    msg0(cls(c"NSFileHandle"), sel(c"alloc")),
                    sel(c"initWithFileDescriptor:closeOnDealloc:"),
                    ctx.guest_stdout_write_fd,
                    1,
                );
                if fh_write.is_null() {
                    return Err(HostError::new(
                        ErrorCode::InternalError,
                        "NSFileHandle(stdout) allocation failed",
                    ));
                }
                unowned_stdout_fd = None;
                msg0(fh_write, sel(c"autorelease"));

                let serial_att = init_serial(
                    msg0(cls(c"VZFileHandleSerialPortAttachment"), sel(c"alloc")),
                    sel(c"initWithFileHandleForReading:fileHandleForWriting:"),
                    fh_read,
                    fh_write,
                );
                msg0(serial_att, sel(c"autorelease"));
                let serial_cfg = msg0(
                    msg0(
                        cls(c"VZVirtioConsoleDeviceSerialPortConfiguration"),
                        sel(c"alloc"),
                    ),
                    sel(c"init"),
                );
                msg0(serial_cfg, sel(c"autorelease"));
                set1(serial_cfg, sel(c"setAttachment:"), serial_att);

                let entropy_cfg = msg0(
                    msg0(cls(c"VZVirtioEntropyDeviceConfiguration"), sel(c"alloc")),
                    sel(c"init"),
                );
                msg0(entropy_cfg, sel(c"autorelease"));

                let nat_att = msg0(
                    msg0(cls(c"VZNATNetworkDeviceAttachment"), sel(c"alloc")),
                    sel(c"init"),
                );
                msg0(nat_att, sel(c"autorelease"));
                let net_cfg = msg0(
                    msg0(cls(c"VZVirtioNetworkDeviceConfiguration"), sel(c"alloc")),
                    sel(c"init"),
                );
                msg0(net_cfg, sel(c"autorelease"));
                set1(net_cfg, sel(c"setAttachment:"), nat_att);

                let sock_cfg = msg0(
                    msg0(cls(c"VZVirtioSocketDeviceConfiguration"), sel(c"alloc")),
                    sel(c"init"),
                );
                msg0(sock_cfg, sel(c"autorelease"));

                let vm_cfg = msg0(
                    msg0(cls(c"VZVirtualMachineConfiguration"), sel(c"alloc")),
                    sel(c"init"),
                );
                msg0(vm_cfg, sel(c"autorelease"));
                set_u64(vm_cfg, sel(c"setCPUCount:"), 1);
                set_u64(
                    vm_cfg,
                    sel(c"setMemorySize:"),
                    u64::from(ctx.memory_mib) * 1024 * 1024,
                );
                set1(vm_cfg, sel(c"setBootLoader:"), boot);
                set1(
                    vm_cfg,
                    sel(c"setSerialPorts:"),
                    array_with_obj(cls(c"NSArray"), sel(c"arrayWithObject:"), serial_cfg),
                );
                set1(
                    vm_cfg,
                    sel(c"setEntropyDevices:"),
                    array_with_obj(cls(c"NSArray"), sel(c"arrayWithObject:"), entropy_cfg),
                );
                set1(
                    vm_cfg,
                    sel(c"setNetworkDevices:"),
                    array_with_obj(cls(c"NSArray"), sel(c"arrayWithObject:"), net_cfg),
                );
                set1(
                    vm_cfg,
                    sel(c"setSocketDevices:"),
                    array_with_obj(cls(c"NSArray"), sel(c"arrayWithObject:"), sock_cfg),
                );

                let mut val_err: Id = ptr::null_mut();
                if validate_fn(vm_cfg, sel(c"validateWithError:"), &raw mut val_err) == 0 {
                    return Err(HostError::new(
                        ErrorCode::Validation,
                        format!(
                            "VZVirtualMachineConfiguration invalid: {}",
                            nserror_description(val_err)
                        ),
                    ));
                }

                let vm = init_vm(
                    msg0(cls(c"VZVirtualMachine"), sel(c"alloc")),
                    sel(c"initWithConfiguration:queue:"),
                    vm_cfg,
                    ctx.queue,
                );
                if vm.is_null() {
                    return Err(HostError::new(
                        ErrorCode::TransportFailure,
                        "VZVirtualMachine allocation failed",
                    ));
                }
                Ok(vm)
            })();

            match setup_res {
                Ok(vm) => {
                    static DESC: BlockDescriptor<ArcStackBlock1<(CompletionSignal<usize>, usize)>> =
                        BlockDescriptor {
                            reserved: 0,
                            size: std::mem::size_of::<
                                ArcStackBlock1<(CompletionSignal<usize>, usize)>,
                            >() as c_ulong,
                            copy_helper: copy_block1,
                            dispose_helper: dispose_block1,
                        };
                    let payload = Arc::new((Arc::clone(&ctx.signal), vm as usize));
                    let mut block = ArcStackBlock1 {
                        isa: (&raw const _NSConcreteStackBlock).cast::<c_void>(),
                        flags: BLOCK_HAS_COPY_DISPOSE,
                        reserved: 0,
                        invoke: on_vm_started,
                        descriptor: &raw const DESC,
                        ctx: Arc::into_raw(payload),
                    };
                    let start_fn: unsafe extern "C" fn(Id, Sel, *mut c_void) =
                        std::mem::transmute(objc_msgSend as *const c_void);
                    start_fn(
                        vm,
                        sel(c"startWithCompletionHandler:"),
                        (&raw mut block).cast(),
                    );
                }
                Err(e) => {
                    if let Some(fd) = unowned_stdin_fd.take() {
                        let _ = libc::close(fd);
                    }
                    if let Some(fd) = unowned_stdout_fd.take() {
                        let _ = libc::close(fd);
                    }
                    complete_signal(&ctx.signal, Err(e));
                }
            }
        }
    }

    struct ConnectContext {
        vm_obj: Id,
        port: u32,
        signal: CompletionSignal<(c_int, usize)>,
    }

    unsafe extern "C" fn on_vsock_connected(
        block: *mut ArcStackBlock2<CompletionSignal<(c_int, usize)>>,
        conn: Id,
        err: Id,
    ) {
        unsafe {
            let sig = &*(*block).ctx;
            if !err.is_null() || conn.is_null() {
                complete_signal(
                    sig,
                    Err(HostError::new(
                        ErrorCode::TransportFailure,
                        format!(
                            "VZVirtioSocketDevice connect failed: {}",
                            nserror_description(err)
                        ),
                    )),
                );
                return;
            }
            let retain_fn: unsafe extern "C" fn(Id, Sel) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);
            let release_fn: unsafe extern "C" fn(Id, Sel) =
                std::mem::transmute(objc_msgSend as *const c_void);
            let fd_fn: unsafe extern "C" fn(Id, Sel) -> c_int =
                std::mem::transmute(objc_msgSend as *const c_void);
            let src_fd = fd_fn(conn, sel(c"fileDescriptor"));
            if src_fd < 0 {
                complete_signal(
                    sig,
                    Err(HostError::new(
                        ErrorCode::TransportFailure,
                        "VZVirtioSocketConnection returned invalid fileDescriptor",
                    )),
                );
                return;
            }
            let retained_conn = retain_fn(conn, sel(c"retain"));
            let dup_fd = libc::fcntl(src_fd, libc::F_DUPFD_CLOEXEC, 0);
            if dup_fd < 0 {
                release_fn(retained_conn, sel(c"release"));
                complete_signal(
                    sig,
                    Err(HostError::new(
                        ErrorCode::TransportFailure,
                        format!("dup(vsock fd) failed: {}", io::Error::last_os_error()),
                    )),
                );
                return;
            }
            complete_signal(sig, Ok((dup_fd, retained_conn as usize)));
        }
    }

    unsafe extern "C" fn connect_vsock_on_queue(raw_ctx: *mut c_void) {
        unsafe {
            let ctx = Box::from_raw(raw_ctx.cast::<ConnectContext>());
            let pool = objc_autoreleasePoolPush();
            let _pool_guard = DropGuard::new(pool, |p| objc_autoreleasePoolPop(p));

            let msg0: unsafe extern "C" fn(Id, Sel) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);
            let count_fn: unsafe extern "C" fn(Id, Sel) -> usize =
                std::mem::transmute(objc_msgSend as *const c_void);
            let idx_fn: unsafe extern "C" fn(Id, Sel, usize) -> Id =
                std::mem::transmute(objc_msgSend as *const c_void);

            let devs = msg0(ctx.vm_obj, sel(c"socketDevices"));
            if devs.is_null() || count_fn(devs, sel(c"count")) == 0 {
                complete_signal(
                    &ctx.signal,
                    Err(HostError::new(
                        ErrorCode::TransportFailure,
                        "VZVirtualMachine has no VZVirtioSocketDevice configured",
                    )),
                );
                return;
            }
            let sock_dev = idx_fn(devs, sel(c"objectAtIndex:"), 0);

            static DESC: BlockDescriptor<ArcStackBlock2<CompletionSignal<(c_int, usize)>>> =
                BlockDescriptor {
                    reserved: 0,
                    size: std::mem::size_of::<ArcStackBlock2<CompletionSignal<(c_int, usize)>>>()
                        as c_ulong,
                    copy_helper: copy_block2,
                    dispose_helper: dispose_block2,
                };
            let mut block = ArcStackBlock2 {
                isa: (&raw const _NSConcreteStackBlock).cast::<c_void>(),
                flags: BLOCK_HAS_COPY_DISPOSE,
                reserved: 0,
                invoke: on_vsock_connected,
                descriptor: &raw const DESC,
                ctx: Arc::into_raw(Arc::clone(&ctx.signal)),
            };
            let connect_fn: unsafe extern "C" fn(Id, Sel, u32, *mut c_void) =
                std::mem::transmute(objc_msgSend as *const c_void);
            connect_fn(
                sock_dev,
                sel(c"connectToPort:completionHandler:"),
                ctx.port,
                (&raw mut block).cast(),
            );
        }
    }

    unsafe extern "C" fn release_vm_on_queue(raw_vm: *mut c_void) {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let vm = raw_vm as Id;
            let can_stop: unsafe extern "C" fn(Id, Sel) -> i8 =
                std::mem::transmute(objc_msgSend as *const c_void);
            let req_stop: unsafe extern "C" fn(Id, Sel, *mut Id) -> i8 =
                std::mem::transmute(objc_msgSend as *const c_void);
            let release_fn: unsafe extern "C" fn(Id, Sel) =
                std::mem::transmute(objc_msgSend as *const c_void);
            if can_stop(vm, sel(c"canRequestStop")) != 0 {
                let mut err: Id = ptr::null_mut();
                let _ = req_stop(vm, sel(c"requestStopWithError:"), &raw mut err);
            }
            release_fn(vm, sel(c"release"));
            objc_autoreleasePoolPop(pool);
        }
    }

    impl VzVmRuntime {
        pub fn start(
            kernel_path: &Path,
            initrd_path: &Path,
            cmdline: &str,
            memory_mib: u32,
        ) -> Result<(Self, File), HostError> {
            let mut stdin_fds = [0 as c_int; 2];
            let mut stdout_fds = [0 as c_int; 2];
            // SAFETY: Creates POSIX pipes for serial console attachment.
            unsafe {
                if libc::pipe(stdin_fds.as_mut_ptr()) != 0 {
                    return Err(HostError::new(
                        ErrorCode::InternalError,
                        "pipe(stdin) failed for VZ serial port",
                    ));
                }
                if libc::pipe(stdout_fds.as_mut_ptr()) != 0 {
                    let _ = libc::close(stdin_fds[0]);
                    let _ = libc::close(stdin_fds[1]);
                    return Err(HostError::new(
                        ErrorCode::InternalError,
                        "pipe(stdout) failed for VZ serial port",
                    ));
                }
                let _ = libc::fcntl(stdin_fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                let _ = libc::fcntl(stdout_fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
            }
            // SAFETY: Host ends of the two newly created pipes.
            let stdin_write = unsafe { File::from_raw_fd(stdin_fds[1]) };
            let stdout_read = unsafe { File::from_raw_fd(stdout_fds[0]) };

            // SAFETY: Creates dedicated serial GCD queue (`DISPATCH_QUEUE_SERIAL` == NULL).
            let queue = unsafe {
                dispatch_queue_create(c"me.vespoli.secretbridge.vz".as_ptr(), ptr::null())
            };
            if queue.is_null() {
                unsafe {
                    let _ = libc::close(stdin_fds[0]);
                    let _ = libc::close(stdout_fds[1]);
                }
                return Err(HostError::new(
                    ErrorCode::InternalError,
                    "dispatch_queue_create failed",
                ));
            }
            let queue_guard = DropGuard::new(queue, |q| unsafe { dispatch_release(q) });

            let signal = new_signal::<usize>();
            let ctx = Box::new(StartContext {
                kernel_path: kernel_path.to_path_buf(),
                initrd_path: initrd_path.to_path_buf(),
                cmdline: cmdline.to_string(),
                memory_mib,
                guest_stdin_read_fd: stdin_fds[0],
                guest_stdout_write_fd: stdout_fds[1],
                queue: *queue_guard,
                signal: Arc::clone(&signal),
            });

            unsafe {
                dispatch_async_f(*queue_guard, Box::into_raw(ctx).cast(), start_vm_on_queue);
            }

            let vm_addr = wait_signal(&signal, Duration::from_secs(20), "VM boot")?;
            let confirmed_queue = DropGuard::dismiss(queue_guard);
            Ok((
                Self {
                    vm_obj: vm_addr as Id,
                    queue: confirmed_queue,
                    _stdin_write_keepalive: stdin_write,
                },
                stdout_read,
            ))
        }

        pub fn connect_vsock_port(
            self: &Arc<Self>,
            port: u32,
        ) -> Result<(File, RetainedVzConnection), HostError> {
            let signal = new_signal::<(c_int, usize)>();
            let ctx = Box::new(ConnectContext {
                vm_obj: self.vm_obj,
                port,
                signal: Arc::clone(&signal),
            });
            unsafe {
                dispatch_async_f(
                    self.queue,
                    Box::into_raw(ctx).cast(),
                    connect_vsock_on_queue,
                );
            }
            let (raw_fd, conn_addr) =
                wait_signal(&signal, Duration::from_secs(15), "VZVirtioSocket connect")?;
            apply_socket_timeouts(raw_fd);
            // SAFETY: `raw_fd` was `F_DUPFD_CLOEXEC`'d exclusively for this caller;
            // `conn_addr` was explicitly `-retain`ed on the VZ GCD queue.
            let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            Ok((
                File::from(owned),
                RetainedVzConnection {
                    conn_obj: conn_addr as Id,
                    vm: Arc::clone(self),
                },
            ))
        }
    }

    impl Drop for VzVmRuntime {
        fn drop(&mut self) {
            unsafe {
                dispatch_async_f(self.queue, self.vm_obj, release_vm_on_queue);
                dispatch_release(self.queue);
            }
        }
    }
}
