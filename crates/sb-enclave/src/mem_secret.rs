use crate::error::EnclaveError;
use rand::RngCore;
use rand::rngs::OsRng;
use sb_proto::error::ErrorCode;
use sb_proto::rpc::{GenerateSpec, SecretCharset};
use std::fmt;
use std::mem::DropGuard;
use std::ptr::NonNull;
use zeroize::Zeroize;

/// Kernel-isolated secret buffer inside the enclave.
///
/// On Linux 5.14+, allocates pages backed by `memfd_secret(2)` (removed from the kernel
/// direct map and unswappable). Falls back cleanly to anonymous `mmap` + `MADV_DONTDUMP` +
/// fail-closed `mlock(2)` (H2). Uses Rust 1.100's `std::mem::DropGuard` during setup so partial
/// failures deterministically close descriptors, volatile-zeroize, munlock, and munmap.
pub struct MemSecret {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    is_anon_mlocked: bool,
}

// SAFETY: `MemSecret` exclusively owns its private anonymous / memfd_secret mapping.
unsafe impl Send for MemSecret {}
unsafe impl Sync for MemSecret {}

pub struct MemSecretCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl MemSecretCursor<'_> {
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EnclaveError> {
        let end = self.pos.checked_add(bytes.len()).ok_or_else(|| {
            EnclaveError::new(ErrorCode::SizeLimitExceeded, "secret buffer overflow")
        })?;
        if end > self.buf.len() {
            return Err(EnclaveError::new(
                ErrorCode::SizeLimitExceeded,
                "secret payload exceeded isolated buffer capacity",
            ));
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    pub fn write_str(&mut self, s: &str) -> Result<(), EnclaveError> {
        self.write_bytes(s.as_bytes())
    }

    /// Writes `raw` UTF-8 bytes as a quoted JSON string (`"..."`) directly into locked memory.
    pub fn write_json_string(&mut self, raw: &str) -> Result<(), EnclaveError> {
        self.write_bytes(b"\"")?;
        for ch in raw.chars() {
            match ch {
                '"' => self.write_bytes(b"\\\"")?,
                '\\' => self.write_bytes(b"\\\\")?,
                '\n' => self.write_bytes(b"\\n")?,
                '\r' => self.write_bytes(b"\\r")?,
                '\t' => self.write_bytes(b"\\t")?,
                c if (c as u32) < 0x20 => {
                    let mut esc = [0u8; 6];
                    let hex_digits = b"0123456789abcdef";
                    let v = c as u32;
                    esc[0] = b'\\';
                    esc[1] = b'u';
                    esc[2] = b'0';
                    esc[3] = b'0';
                    esc[4] = hex_digits[((v >> 4) & 0x0F) as usize];
                    esc[5] = hex_digits[(v & 0x0F) as usize];
                    self.write_bytes(&esc)?;
                }
                c => {
                    let mut utf8 = [0u8; 4];
                    let encoded = c.encode_utf8(&mut utf8);
                    self.write_bytes(encoded.as_bytes())?;
                    utf8.zeroize();
                }
            }
        }
        self.write_bytes(b"\"")
    }
}

impl MemSecret {
    pub fn from_slice(secret: &[u8]) -> Result<Self, EnclaveError> {
        let mem = Self::allocate(secret.len())?;
        if !secret.is_empty() {
            // SAFETY: `mem.ptr` is valid and uniquely owned for `secret.len()` <= `mem.cap`.
            unsafe {
                std::ptr::copy_nonoverlapping(secret.as_ptr(), mem.ptr.as_ptr(), secret.len());
            }
        }
        Ok(mem)
    }

    /// Pre-allocates `max_len` bytes in `memfd_secret`/`mlock` and lets `writer` populate
    /// them in-place without staging secrets through unlocked heap `String` or `Vec<u8>`.
    pub fn write_with<F>(max_len: usize, writer: F) -> Result<Self, EnclaveError>
    where
        F: FnOnce(&mut MemSecretCursor<'_>) -> Result<(), EnclaveError>,
    {
        let mut mem = Self::allocate(max_len)?;
        // SAFETY: `mem.ptr` is uniquely owned and valid for `mem.cap` bytes (`max_len <= mem.cap`).
        let slice = unsafe { std::slice::from_raw_parts_mut(mem.ptr.as_ptr(), mem.cap) };
        let mut cursor = MemSecretCursor { buf: slice, pos: 0 };
        writer(&mut cursor)?;
        mem.len = cursor.pos;
        Ok(mem)
    }

    pub fn generate_csprng(spec: &GenerateSpec) -> Result<Self, EnclaveError> {
        let len = usize::from(spec.length);
        if !(8..=4096).contains(&len) {
            return Err(EnclaveError::new(
                ErrorCode::Validation,
                "generated secret length must be between 8 and 4096 characters",
            ));
        }
        let alphabet: &[u8] = match spec.charset {
            SecretCharset::AlphanumericSymbols => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}?"
            }
            SecretCharset::Alphanumeric => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            }
            SecretCharset::HexLower => b"0123456789abcdef",
            SecretCharset::Base64Url => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            }
        };

        let mem = Self::allocate(len)?;
        // Guard temporary random byte scratch buffer with DropGuard so even a panic wipes it.
        let mut scratch = DropGuard::new([0u8; 256], |mut buf| {
            buf.zeroize();
        });

        let alpha_len = alphabet.len();
        // Rejection threshold eliminates modulo bias: floor(256 / alpha_len) * alpha_len
        let threshold = (256 / alpha_len) * alpha_len;
        let mut written = 0usize;

        while written < len {
            OsRng.fill_bytes(&mut *scratch);
            for &b in scratch.iter() {
                if written == len {
                    break;
                }
                let idx = usize::from(b);
                if idx < threshold {
                    let ch = alphabet[idx % alpha_len];
                    // SAFETY: `written < len <= mem.cap` and `mem.ptr` is uniquely owned.
                    unsafe {
                        mem.ptr.as_ptr().add(written).write(ch);
                    }
                    written += 1;
                }
            }
        }
        Ok(mem)
    }

    fn allocate(len: usize) -> Result<Self, EnclaveError> {
        let page_size = page_size_bytes();
        let alloc_len = len.max(1);
        let cap = alloc_len.div_ceil(page_size) * page_size;

        #[cfg(target_os = "linux")]
        if let Some(ptr) = try_alloc_memfd_secret(cap) {
            return Ok(Self {
                ptr,
                len,
                cap,
                is_anon_mlocked: false, // memfd_secret pages are implicitly locked & unmapped from direct map
            });
        }

        alloc_anon_mlocked(len, cap)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `self.ptr` points to `self.len` initialized bytes valid for `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_str(&self) -> Result<&str, EnclaveError> {
        std::str::from_utf8(self.as_bytes()).map_err(|_| {
            EnclaveError::new(ErrorCode::Validation, "secret value is not valid UTF-8")
        })
    }
}

impl fmt::Debug for MemSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemSecret([REDACTED; {} bytes])", self.len)
    }
}

impl Drop for MemSecret {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is a valid mapping of `self.cap` bytes owned exclusively by `self`.
        // `zeroize()` uses volatile writes + atomic compiler fence so LLVM cannot elide the wipe (H2).
        unsafe {
            let full_mapping = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap);
            full_mapping.zeroize();
            if self.is_anon_mlocked {
                let _ = libc::munlock(self.ptr.as_ptr().cast(), self.cap);
            }
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.cap);
        }
    }
}

fn page_size_bytes() -> usize {
    // SAFETY: `sysconf(_SC_PAGESIZE)` has no memory preconditions.
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 { ps as usize } else { 4096 }
}

#[cfg(target_os = "linux")]
fn try_alloc_memfd_secret(cap: usize) -> Option<NonNull<u8>> {
    // SAFETY: `syscall(SYS_memfd_secret, O_CLOEXEC)` returns a new fd or -1 with errno.
    let raw_fd = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC as libc::c_uint) };
    if raw_fd < 0 {
        return None;
    }
    let fd = raw_fd as libc::c_int;
    // Deterministic fd closure on return (mapping stays alive after close).
    let _fd_guard = DropGuard::new(fd, |f| {
        // SAFETY: `f` is an open file descriptor owned solely by this scope.
        unsafe {
            let _ = libc::close(f);
        }
    });

    // SAFETY: `fd` is valid and `cap` fits in `off_t`.
    let trunc_rc = unsafe { libc::ftruncate(fd, cap as libc::off_t) };
    if trunc_rc != 0 {
        return None;
    }

    // SAFETY: `mmap` of `cap` bytes on our private `memfd_secret` fd.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            cap,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if mapped == libc::MAP_FAILED || mapped.is_null() {
        return None;
    }
    NonNull::new(mapped.cast::<u8>())
}

fn alloc_anon_mlocked(len: usize, cap: usize) -> Result<MemSecret, EnclaveError> {
    // SAFETY: anonymous private mmap with null hint.
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            cap,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED || mapped.is_null() {
        return Err(EnclaveError::new(
            ErrorCode::InternalError,
            "failed to allocate isolated secret memory",
        ));
    }
    let Some(ptr) = NonNull::new(mapped.cast::<u8>()) else {
        return Err(EnclaveError::new(
            ErrorCode::InternalError,
            "null mmap pointer",
        ));
    };

    // Guard mapping during madvise/mlock setup using Rust 1.100 DropGuard; dismiss on success.
    let guard = DropGuard::new(ptr, |p| {
        // SAFETY: `p` is a valid `cap`-byte mapping if setup aborts early.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(p.as_ptr(), cap);
            slice.zeroize();
            let _ = libc::munmap(p.as_ptr().cast(), cap);
        }
    });

    #[cfg(target_os = "linux")]
    // SAFETY: `MADV_DONTDUMP` excludes secret pages from core dumps on Linux.
    unsafe {
        let _ = libc::madvise(guard.as_ptr().cast(), cap, libc::MADV_DONTDUMP);
    }

    // SAFETY: `mlock` pins `cap` bytes in physical RAM; fail closed if locking fails (H2).
    let lock_rc = unsafe { libc::mlock(guard.as_ptr().cast(), cap) };
    if lock_rc != 0 {
        return Err(EnclaveError::new(
            ErrorCode::InternalError,
            "mlock failed for enclave secret buffer; check RLIMIT_MEMLOCK",
        ));
    }

    let confirmed_ptr = DropGuard::dismiss(guard);
    Ok(MemSecret {
        ptr: confirmed_ptr,
        len,
        cap,
        is_anon_mlocked: true,
    })
}
