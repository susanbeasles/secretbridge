use crate::manifest_io::HostError;
use sb_proto::crypto::seal_base64;
use sb_proto::error::ErrorCode;
use sb_proto::rpc::CaptureInterceptMode;
use std::io::Read;
use std::mem::DropGuard;
use std::ptr::NonNull;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub const DEFAULT_ARMED_COPY_TTL: Duration = Duration::from_secs(15);
const MAX_CAPTURED_SECRET_BYTES: usize = 65_536;

/// Result of an Armed Copy Hijack: contains ONLY the X25519 sealed-box ciphertext
/// bound to the enclave's single-use 15-second `pk_capture` key.
#[derive(Debug, Clone)]
pub struct SealedCaptureResult {
    pub sealed_secret_b64: String,
    pub mode: CaptureInterceptMode,
}

/// Page-aligned `mlock(2)` buffer on the host used solely for sub-millisecond
/// capture -> X25519 `seal_base64` -> volatile zeroize -> `munlock` -> `munmap` (`H2`).
pub struct MlockedHostBuffer {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
}

// SAFETY: `MlockedHostBuffer` uniquely owns its anonymous private mapping.
unsafe impl Send for MlockedHostBuffer {}
// SAFETY: `MlockedHostBuffer` only exposes shared immutable `&[u8]` reads once constructed.
unsafe impl Sync for MlockedHostBuffer {}

impl MlockedHostBuffer {
    fn alloc_locked(min_bytes: usize) -> Result<(NonNull<u8>, usize), HostError> {
        // SAFETY: `sysconf(_SC_PAGESIZE)` has no memory safety preconditions.
        let page_sz = unsafe {
            let v = libc::sysconf(libc::_SC_PAGESIZE);
            if v > 0 { v as usize } else { 4096 }
        };
        let cap = min_bytes.max(1).div_ceil(page_sz) * page_sz;

        // SAFETY: anonymous private mmap with null address hint.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cap,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED || raw.is_null() {
            return Err(HostError::new(
                ErrorCode::InternalError,
                "mmap failed for host capture buffer",
            ));
        }
        let Some(ptr) = NonNull::new(raw.cast::<u8>()) else {
            return Err(HostError::new(
                ErrorCode::InternalError,
                "null mmap pointer",
            ));
        };

        let guard = DropGuard::new(ptr, |p| {
            // SAFETY: `p` is a valid `cap`-byte mapping if initialization aborts; `Zeroize` uses volatile writes.
            unsafe {
                std::slice::from_raw_parts_mut(p.as_ptr(), cap).zeroize();
                let _ = libc::munmap(p.as_ptr().cast(), cap);
            }
        });

        #[cfg(target_os = "linux")]
        // SAFETY: excludes capture buffer from core dumps.
        unsafe {
            let _ = libc::madvise(guard.as_ptr().cast(), cap, libc::MADV_DONTDUMP);
        }

        // SAFETY: pins capture buffer into physical RAM so swap never sees plaintext (`H2` fail-closed).
        let lock_rc = unsafe { libc::mlock(guard.as_ptr().cast(), cap) };
        if lock_rc != 0 {
            return Err(HostError::new(
                ErrorCode::InternalError,
                "mlock failed for host capture buffer (raise RLIMIT_MEMLOCK)",
            ));
        }

        let confirmed = DropGuard::dismiss(guard);
        Ok((confirmed, cap))
    }

    pub fn from_bytes(src: &[u8]) -> Result<Self, HostError> {
        if src.is_empty() {
            return Err(HostError::new(
                ErrorCode::Validation,
                "captured secret is empty",
            ));
        }
        if src.len() > MAX_CAPTURED_SECRET_BYTES {
            return Err(HostError::new(
                ErrorCode::SizeLimitExceeded,
                "captured secret exceeds 64 KiB maximum",
            ));
        }
        let (ptr, cap) = Self::alloc_locked(src.len())?;
        // SAFETY: `ptr` points to `cap >= src.len()` locked writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), ptr.as_ptr(), src.len());
        }
        Ok(Self {
            ptr,
            len: src.len(),
            cap,
        })
    }

    /// Streams directly from an OS pipe/fd into a pre-locked `mlock(2)` page mapping
    /// without allocating any unlocked heap `Vec<u8>`.
    pub fn from_reader_bounded<R: Read>(reader: &mut R) -> Result<Self, HostError> {
        let (ptr, cap) = Self::alloc_locked(MAX_CAPTURED_SECRET_BYTES + 1)?;
        let guard = DropGuard::new((ptr, cap), |(p, c)| {
            // SAFETY: `p` is valid and `mlock`ed for `c` bytes; volatile zeroize before munlock/munmap.
            unsafe {
                std::slice::from_raw_parts_mut(p.as_ptr(), c).zeroize();
                let _ = libc::munlock(p.as_ptr().cast(), c);
                let _ = libc::munmap(p.as_ptr().cast(), c);
            }
        });

        let mut total = 0usize;
        // SAFETY: `guard.0` has `cap >= MAX_CAPTURED_SECRET_BYTES + 1` writable bytes.
        let dst = unsafe {
            std::slice::from_raw_parts_mut(guard.0.as_ptr(), MAX_CAPTURED_SECRET_BYTES + 1)
        };
        while total <= MAX_CAPTURED_SECRET_BYTES {
            match reader.read(&mut dst[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(HostError::new(
                        ErrorCode::CaptureUnavailable,
                        "failed reading captured secret stream",
                    ));
                }
            }
        }
        // Trim a single trailing LF/CRLF added by selection streams only if non-empty? No: preserve exact bytes!
        if total == 0 {
            return Err(HostError::new(
                ErrorCode::Validation,
                "captured secret is empty",
            ));
        }
        if total > MAX_CAPTURED_SECRET_BYTES {
            return Err(HostError::new(
                ErrorCode::SizeLimitExceeded,
                "captured secret exceeds 64 KiB maximum",
            ));
        }

        let (confirmed_ptr, confirmed_cap) = DropGuard::dismiss(guard);
        Ok(Self {
            ptr: confirmed_ptr,
            len: total,
            cap: confirmed_cap,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.ptr` is valid for `self.len` bytes for `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for MlockedHostBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is uniquely owned and `self.cap` bytes long; `zeroize()` uses volatile writes (`H2`).
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap).zeroize();
            let _ = libc::munlock(self.ptr.as_ptr().cast(), self.cap);
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.cap);
        }
    }
}

/// Trait allowing deterministic testing of the Armed Copy Hijack pipeline on headless CI
/// while delegating to the native OS hook (`CGEventTap`/`AXUIElement` on macOS,
/// X11 `libX11` / Wayland `ext-data-control`/`zwlr-data-control` wire socket on Linux) in production.
pub trait ArmedCaptureProvider: Send + Sync {
    fn capture_once(
        &self,
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError>;
}

/// Seals a captured secret directly from `mlock()` RAM to the enclave's single-use
/// `pk_capture_b64` X25519 key and immediately drops (zeroizes + munlocks) the buffer.
pub fn execute_armed_capture(
    provider: &dyn ArmedCaptureProvider,
    pk_capture_b64: &str,
    ttl: Duration,
) -> Result<SealedCaptureResult, HostError> {
    let effective_ttl = ttl.min(DEFAULT_ARMED_COPY_TTL);
    let (mlocked_buf, mode) = provider.capture_once(effective_ttl)?;
    let buf_guard = DropGuard::new(mlocked_buf, drop);
    let sealed_secret_b64 = seal_base64(pk_capture_b64, buf_guard.as_bytes())?;
    drop(buf_guard);
    Ok(SealedCaptureResult {
        sealed_secret_b64,
        mode,
    })
}

pub struct NativeOsCaptureProvider;

impl ArmedCaptureProvider for NativeOsCaptureProvider {
    fn capture_once(
        &self,
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        #[cfg(target_os = "macos")]
        {
            macos_imp::capture_macos_armed(ttl)
        }
        #[cfg(target_os = "linux")]
        {
            linux_imp::capture_linux_armed(ttl)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = ttl;
            Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "Armed Copy Hijack is supported only on macOS arm64 and Linux x86_64/arm64 in v1",
            ))
        }
    }
}

// =========================================================================
// macOS arm64 Native Implementation (`H6`):
// Active CGEventTap (swallows Cmd+C -> AXUIElement kAXSelectedTextAttribute
// with CFGetTypeID verification, Esc cancel) + 1ms NSPasteboard fallback
// with per-iteration NSAutoreleasePool and NUL-safe initWithBytes restore.
// =========================================================================
#[cfg(target_os = "macos")]
mod macos_imp {
    use super::{CaptureInterceptMode, HostError, Instant, MlockedHostBuffer};
    use sb_proto::error::ErrorCode;
    use std::ffi::{CStr, c_char, c_void};
    use std::mem::DropGuard;
    use std::sync::Mutex;
    use std::time::Duration;

    type CFTypeRef = *const c_void;
    type CFTypeID = usize;
    type CFStringRef = *const c_void;
    type CFMachPortRef = *mut c_void;
    type CFRunLoopSourceRef = *mut c_void;
    type CFRunLoopRef = *mut c_void;
    type CGEventRef = *mut c_void;
    type CGEventTapProxy = *mut c_void;
    type AXUIElementRef = *mut c_void;

    const K_CG_SESSION_EVENT_TAP: u32 = 1;
    const K_CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
    const K_CG_EVENT_TAP_OPTION_DEFAULT: u32 = 0;
    const K_CG_EVENT_KEY_DOWN: u32 = 10;
    const K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT: u32 = 0xFFFFFFFE;
    const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
    const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;
    const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 0x0002_0000;
    const K_CG_EVENT_FLAG_MASK_ALTERNATE: u64 = 0x0008_0000;
    const K_CG_EVENT_FLAG_MASK_CONTROL: u64 = 0x0004_0000;
    const ANSI_KEY_C: i64 = 8;
    const ANSI_KEY_ESCAPE: i64 = 53;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const NS_UTF8_STRING_ENCODING: usize = 4;

    #[link(name = "Carbon", kind = "framework")]
    unsafe extern "C" {
        fn IsSecureEventInputEnabled() -> bool;
    }

    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn AXIsProcessTrusted() -> bool;
        fn AXUIElementCreateSystemWide() -> AXUIElementRef;
        fn AXUIElementCopyAttributeValue(
            element: AXUIElementRef,
            attribute: CFStringRef,
            value: *mut CFTypeRef,
        ) -> i32;

        fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: u64,
            callback: extern "C" fn(CGEventTapProxy, u32, CGEventRef, *mut c_void) -> CGEventRef,
            user_info: *mut c_void,
        ) -> CFMachPortRef;
        fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
        fn CGEventGetFlags(event: CGEventRef) -> u64;
        fn CGEventGetIntegerValueField(event: CGEventRef, field: u32) -> i64;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopCommonModes: CFStringRef;
        static kCFRunLoopDefaultMode: CFStringRef;

        fn CFRelease(cf: CFTypeRef);
        fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
        fn CFStringGetTypeID() -> CFTypeID;
        fn CFMachPortInvalidate(port: CFMachPortRef);
        fn CFMachPortCreateRunLoopSource(
            allocator: CFTypeRef,
            port: CFMachPortRef,
            order: isize,
        ) -> CFRunLoopSourceRef;
        fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
        fn CFRunLoopRemoveSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFStringRef);
        fn CFRunLoopRunInMode(
            mode: CFStringRef,
            seconds: f64,
            return_after_source_handled: bool,
        ) -> i32;
        fn CFRunLoopStop(rl: CFRunLoopRef);
        fn CFStringCreateWithCString(
            alloc: CFTypeRef,
            c_str: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFStringGetLength(the_string: CFStringRef) -> isize;
        fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
        fn CFStringGetCString(
            the_string: CFStringRef,
            buffer: *mut c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> bool;
    }

    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    struct TapSharedState {
        tap_port: CFMachPortRef,
        run_loop: CFRunLoopRef,
        captured: Mutex<Option<Result<MlockedHostBuffer, HostError>>>,
    }

    unsafe fn cfstring_from_static(s: &'static CStr) -> CFStringRef {
        // SAFETY: `s` is a valid NUL-terminated ASCII CStr.
        unsafe {
            CFStringCreateWithCString(std::ptr::null(), s.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        }
    }

    unsafe fn read_ax_selected_text_into_mlock() -> Option<Result<MlockedHostBuffer, HostError>> {
        let sys_wide = unsafe { AXUIElementCreateSystemWide() };
        if sys_wide.is_null() {
            return None;
        }
        let _sys_guard = DropGuard::new(sys_wide, |p| unsafe { CFRelease(p.cast()) });

        let attr_focused = unsafe { cfstring_from_static(c"AXFocusedUIElement") };
        if attr_focused.is_null() {
            return None;
        }
        let _af_guard = DropGuard::new(attr_focused, |p| unsafe { CFRelease(p) });

        let mut focused: CFTypeRef = std::ptr::null();
        let rc = unsafe { AXUIElementCopyAttributeValue(sys_wide, attr_focused, &mut focused) };
        if rc != 0 || focused.is_null() {
            return None;
        }
        let _foc_guard = DropGuard::new(focused, |p| unsafe { CFRelease(p) });

        let attr_selected = unsafe { cfstring_from_static(c"AXSelectedText") };
        if attr_selected.is_null() {
            return None;
        }
        let _as_guard = DropGuard::new(attr_selected, |p| unsafe { CFRelease(p) });

        let mut selected_val: CFTypeRef = std::ptr::null();
        let rc2 = unsafe {
            AXUIElementCopyAttributeValue(focused.cast_mut(), attr_selected, &mut selected_val)
        };
        if rc2 != 0 || selected_val.is_null() {
            return None;
        }
        let _sel_guard = DropGuard::new(selected_val, |p| unsafe { CFRelease(p) });

        // Verify CFTypeID is actually CFString before calling CFStringGetLength (`H6`).
        if unsafe { CFGetTypeID(selected_val) != CFStringGetTypeID() } {
            return None;
        }

        let utf16_len = unsafe { CFStringGetLength(selected_val) };
        if utf16_len <= 0 {
            return None;
        }
        let max_bytes =
            unsafe { CFStringGetMaximumSizeForEncoding(utf16_len, K_CF_STRING_ENCODING_UTF8) + 1 };
        if max_bytes <= 1 || max_bytes > 65_537 {
            return Some(Err(HostError::new(
                ErrorCode::SizeLimitExceeded,
                "selected secret exceeds 64 KiB limit",
            )));
        }

        let mut scratch = zeroize::Zeroizing::new(vec![0u8; max_bytes as usize]);
        let ok = unsafe {
            CFStringGetCString(
                selected_val,
                scratch.as_mut_ptr().cast::<c_char>(),
                max_bytes,
                K_CF_STRING_ENCODING_UTF8,
            )
        };
        if !ok {
            return None;
        }
        let nul_pos = scratch.iter().position(|&b| b == 0).unwrap_or(0);
        if nul_pos == 0 {
            return None;
        }
        Some(MlockedHostBuffer::from_bytes(&scratch[..nul_pos]))
    }

    extern "C" fn event_tap_callback(
        _proxy: CGEventTapProxy,
        event_type: u32,
        event: CGEventRef,
        user_info: *mut c_void,
    ) -> CGEventRef {
        if user_info.is_null() {
            return event;
        }
        // SAFETY: `user_info` points to `TapSharedState` valid for the entire runloop scope.
        let state = unsafe { &*(user_info.cast::<TapSharedState>()) };

        if event_type == K_CG_EVENT_TAP_DISABLED_BY_TIMEOUT {
            unsafe {
                CGEventTapEnable(state.tap_port, true);
            }
            return event;
        }
        if event_type != K_CG_EVENT_KEY_DOWN || event.is_null() {
            return event;
        }

        let flags = unsafe { CGEventGetFlags(event) };
        let keycode = unsafe { CGEventGetIntegerValueField(event, K_CG_KEYBOARD_EVENT_KEYCODE) };

        if keycode == ANSI_KEY_ESCAPE {
            if let Ok(mut slot) = state.captured.lock() {
                *slot = Some(Err(HostError::new(
                    ErrorCode::CaptureExpired,
                    "Armed Copy cancelled by user (Esc)",
                )));
            }
            unsafe {
                CFRunLoopStop(state.run_loop);
            }
            return std::ptr::null_mut();
        }

        let cmd_only = (flags & K_CG_EVENT_FLAG_MASK_COMMAND) != 0
            && (flags
                & (K_CG_EVENT_FLAG_MASK_SHIFT
                    | K_CG_EVENT_FLAG_MASK_ALTERNATE
                    | K_CG_EVENT_FLAG_MASK_CONTROL))
                == 0;

        if cmd_only && keycode == ANSI_KEY_C {
            if let Some(res) = unsafe { read_ax_selected_text_into_mlock() } {
                if let Ok(mut slot) = state.captured.lock() {
                    *slot = Some(res);
                }
                unsafe {
                    CFRunLoopStop(state.run_loop);
                }
                // Return NULL to swallow Cmd+C so the source app NEVER writes to NSPasteboard!
                return std::ptr::null_mut();
            }
        }
        event
    }

    unsafe fn general_pasteboard() -> *mut c_void {
        unsafe {
            let cls = objc_getClass(c"NSPasteboard".as_ptr());
            let sel = sel_registerName(c"generalPasteboard".as_ptr());
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            f(cls, sel)
        }
    }

    unsafe fn pasteboard_change_count(pb: *mut c_void) -> isize {
        unsafe {
            let sel = sel_registerName(c"changeCount".as_ptr());
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            f(pb, sel)
        }
    }

    unsafe fn pasteboard_read_utf8_mlocked(pb: *mut c_void) -> Option<MlockedHostBuffer> {
        unsafe {
            let ns_string_cls = objc_getClass(c"NSString".as_ptr());
            let sel_str_utf8 = sel_registerName(c"stringWithUTF8String:".as_ptr());
            let mk_str: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *const c_char,
            ) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let pb_type = mk_str(
                ns_string_cls,
                sel_str_utf8,
                c"public.utf8-plain-text".as_ptr(),
            );
            if pb_type.is_null() {
                return None;
            }
            let sel_str_for_type = sel_registerName(c"stringForType:".as_ptr());
            let get_str: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let ns_val = get_str(pb, sel_str_for_type, pb_type);
            if ns_val.is_null() {
                return None;
            }
            let sel_len = sel_registerName(c"lengthOfBytesUsingEncoding:".as_ptr());
            let len_fn: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> usize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let byte_len = len_fn(ns_val, sel_len, NS_UTF8_STRING_ENCODING);
            let sel_utf8 = sel_registerName(c"UTF8String".as_ptr());
            let get_cstr: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const u8 =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let c_ptr = get_cstr(ns_val, sel_utf8);
            if c_ptr.is_null() || byte_len == 0 {
                return None;
            }
            let bytes = std::slice::from_raw_parts(c_ptr, byte_len);
            MlockedHostBuffer::from_bytes(bytes).ok()
        }
    }

    unsafe fn pasteboard_restore(pb: *mut c_void, prior: Option<&MlockedHostBuffer>) {
        unsafe {
            let sel_clear = sel_registerName(c"clearContents".as_ptr());
            let clear_fn: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let _ = clear_fn(pb, sel_clear);

            if let Some(prev) = prior {
                let raw = prev.as_bytes();
                let ns_string_cls = objc_getClass(c"NSString".as_ptr());
                let sel_alloc = sel_registerName(c"alloc".as_ptr());
                let alloc_fn: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                    std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                let allocated = alloc_fn(ns_string_cls, sel_alloc);
                if allocated.is_null() {
                    return;
                }
                let sel_init = sel_registerName(c"initWithBytes:length:encoding:".as_ptr());
                let init_fn: unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_void,
                    *const u8,
                    usize,
                    usize,
                ) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                let ns_val = init_fn(
                    allocated,
                    sel_init,
                    raw.as_ptr(),
                    raw.len(),
                    NS_UTF8_STRING_ENCODING,
                );
                if ns_val.is_null() {
                    return;
                }
                let _rel_guard = DropGuard::new(ns_val, |obj| {
                    let sel_rel = sel_registerName(c"release".as_ptr());
                    let rel_fn: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                        std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                    rel_fn(obj, sel_rel);
                });

                let sel_str_utf8 = sel_registerName(c"stringWithUTF8String:".as_ptr());
                let mk_str: unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_void,
                    *const c_char,
                ) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                let pb_type = mk_str(
                    ns_string_cls,
                    sel_str_utf8,
                    c"public.utf8-plain-text".as_ptr(),
                );
                if !pb_type.is_null() {
                    let sel_set = sel_registerName(c"setString:forType:".as_ptr());
                    let set_fn: unsafe extern "C" fn(
                        *mut c_void,
                        *mut c_void,
                        *mut c_void,
                        *mut c_void,
                    ) -> bool = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                    let _ = set_fn(pb, sel_set, ns_val, pb_type);
                }
            }
        }
    }

    pub fn capture_macos_armed(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        if unsafe { IsSecureEventInputEnabled() } {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "macOS Secure Event Input is currently enabled by another process; close active password prompts or use In-VM Generate Secret",
            ));
        }
        if unsafe { !AXIsProcessTrusted() } {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "macOS Accessibility permission is required for Armed Copy Hijack (System Settings -> Privacy & Security -> Accessibility)",
            ));
        }

        let init_pool = unsafe { objc_autoreleasePoolPush() };
        let (pb, initial_change_count, prior_snapshot) = {
            let _pool_guard = DropGuard::new(init_pool, |p| unsafe { objc_autoreleasePoolPop(p) });
            let pb = unsafe { general_pasteboard() };
            let cnt = if pb.is_null() {
                0
            } else {
                unsafe { pasteboard_change_count(pb) }
            };
            let snap = if pb.is_null() {
                None
            } else {
                unsafe { pasteboard_read_utf8_mlocked(pb) }
            };
            (pb, cnt, snap)
        };

        let rl = unsafe { CFRunLoopGetCurrent() };
        let shared = Box::new(TapSharedState {
            tap_port: std::ptr::null_mut(),
            run_loop: rl,
            captured: Mutex::new(None),
        });
        let shared_ptr = Box::into_raw(shared);
        let _box_guard = DropGuard::new(shared_ptr, |p| unsafe {
            drop(Box::from_raw(p));
        });

        let mask = 1u64 << K_CG_EVENT_KEY_DOWN;
        let tap = unsafe {
            CGEventTapCreate(
                K_CG_SESSION_EVENT_TAP,
                K_CG_HEAD_INSERT_EVENT_TAP,
                K_CG_EVENT_TAP_OPTION_DEFAULT,
                mask,
                event_tap_callback,
                shared_ptr.cast::<c_void>(),
            )
        };
        if tap.is_null() {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "CGEventTapCreate failed; grant Input Monitoring / Accessibility permission to JetBrains IDE",
            ));
        }
        unsafe {
            (*shared_ptr).tap_port = tap;
        }
        let _tap_guard = DropGuard::new(tap, |port| unsafe {
            CGEventTapEnable(port, false);
            CFMachPortInvalidate(port);
            CFRelease(port.cast());
        });

        let source = unsafe { CFMachPortCreateRunLoopSource(std::ptr::null(), tap, 0) };
        if source.is_null() {
            return Err(HostError::new(
                ErrorCode::InternalError,
                "CFMachPortCreateRunLoopSource failed",
            ));
        }
        unsafe {
            CFRunLoopAddSource(rl, source, kCFRunLoopCommonModes);
            CGEventTapEnable(tap, true);
        }
        let _src_guard = DropGuard::new((rl, source), |(loop_ref, src)| unsafe {
            CFRunLoopRemoveSource(loop_ref, src, kCFRunLoopCommonModes);
            CFRelease(src.cast());
        });

        let deadline = Instant::now() + ttl;
        while Instant::now() < deadline {
            let iter_pool = unsafe { objc_autoreleasePoolPush() };
            let _iter_pool_guard =
                DropGuard::new(iter_pool, |p| unsafe { objc_autoreleasePoolPop(p) });

            unsafe {
                let _ = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.001, true);
            }
            if let Ok(mut guard) = unsafe { (*shared_ptr).captured.lock() }
                && let Some(res) = guard.take()
            {
                return res.map(|buf| (buf, CaptureInterceptMode::ZeroPasteboard));
            }
            if !pb.is_null() && unsafe { pasteboard_change_count(pb) } != initial_change_count {
                let captured_opt = unsafe { pasteboard_read_utf8_mlocked(pb) };
                unsafe {
                    pasteboard_restore(pb, prior_snapshot.as_ref());
                }
                if let Some(buf) = captured_opt {
                    return Ok((buf, CaptureInterceptMode::PasteboardFallback));
                }
            }
        }

        Err(HostError::new(
            ErrorCode::CaptureExpired,
            "15-second Armed Copy window expired before Cmd+C or Copy was triggered",
        ))
    }
}

// =========================================================================
// Linux x86_64/arm64 Native Implementation (`H6` -- ZERO external subprocesses!):
// 1. Wayland: Pure-Rust Unix socket wire client for `ext_data_control_manager_v1`
//    and `zwlr_data_control_manager_v1` reading `receive` pipe directly into `mlock()`.
// 2. X11: Direct `libX11.so.6` FFI (`XGrabKey` Ctrl+C + Esc, `XConvertSelection`
//    on `PRIMARY` / `CLIPBOARD` into `mlock()`, `XSetSelectionOwner` wipe).
// =========================================================================
#[cfg(target_os = "linux")]
mod linux_imp {
    use super::{
        CaptureInterceptMode, HostError, Instant, MAX_CAPTURED_SECRET_BYTES, MlockedHostBuffer,
    };
    use sb_proto::error::ErrorCode;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::mem::DropGuard;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;
    use zeroize::Zeroize;

    pub fn capture_linux_armed(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            match capture_wayland_data_control(ttl) {
                Ok(res) => return Ok(res),
                Err(e)
                    if e.code == ErrorCode::CaptureUnavailable
                        && std::env::var_os("DISPLAY").is_some() =>
                {
                    // Compositor lacks data-control protocol; fall back to XWayland if DISPLAY is present.
                }
                Err(e) => return Err(e),
            }
        }
        if std::env::var_os("DISPLAY").is_some() {
            return capture_x11_armed(ttl);
        }
        Err(HostError::new(
            ErrorCode::CaptureUnavailable,
            "neither WAYLAND_DISPLAY nor DISPLAY is active; use In-VM Generate Secret on headless Linux",
        ))
    }

    // ---------------------------------------------------------------------
    // Pure-Rust Wayland `ext_data_control_manager_v1` / `zwlr_data_control_manager_v1`
    // ---------------------------------------------------------------------

    fn resolve_wayland_socket_path() -> Result<PathBuf, HostError> {
        let wl_disp = std::env::var("WAYLAND_DISPLAY").map_err(|_| {
            HostError::new(ErrorCode::CaptureUnavailable, "WAYLAND_DISPLAY is not set")
        })?;
        let candidate = PathBuf::from(&wl_disp);
        let full = if candidate.is_absolute() {
            candidate
        } else {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
                HostError::new(ErrorCode::CaptureUnavailable, "XDG_RUNTIME_DIR is not set")
            })?;
            PathBuf::from(runtime_dir).join(candidate)
        };
        let meta = std::fs::symlink_metadata(&full).map_err(|_| {
            HostError::new(ErrorCode::CaptureUnavailable, "Wayland socket not found")
        })?;
        if meta.file_type().is_symlink() || !meta.file_type().is_socket() {
            return Err(HostError::new(
                ErrorCode::Validation,
                "refusing symlinked or non-socket WAYLAND_DISPLAY path",
            ));
        }
        Ok(full)
    }

    fn wl_encode_string(out: &mut Vec<u8>, s: &str) {
        let len_with_nul = (s.len() + 1) as u32;
        out.extend_from_slice(&len_with_nul.to_ne_bytes());
        out.extend_from_slice(s.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn wl_send_msg(
        stream: &mut UnixStream,
        obj_id: u32,
        opcode: u16,
        payload: &[u8],
    ) -> Result<(), HostError> {
        let total_len = 8 + payload.len();
        let mut msg = Vec::with_capacity(total_len);
        msg.extend_from_slice(&obj_id.to_ne_bytes());
        let word2 = ((total_len as u32) << 16) | u32::from(opcode);
        msg.extend_from_slice(&word2.to_ne_bytes());
        msg.extend_from_slice(payload);
        stream.write_all(&msg).map_err(|_| {
            HostError::new(ErrorCode::CaptureUnavailable, "Wayland socket write failed")
        })
    }

    fn wl_send_msg_with_fd(
        stream: &UnixStream,
        obj_id: u32,
        opcode: u16,
        payload: &[u8],
        fd_to_pass: i32,
    ) -> Result<(), HostError> {
        let total_len = 8 + payload.len();
        let mut msg = Vec::with_capacity(total_len);
        msg.extend_from_slice(&obj_id.to_ne_bytes());
        let word2 = ((total_len as u32) << 16) | u32::from(opcode);
        msg.extend_from_slice(&word2.to_ne_bytes());
        msg.extend_from_slice(payload);

        let iov = libc::iovec {
            iov_base: msg.as_mut_ptr().cast(),
            iov_len: msg.len(),
        };

        // SAFETY: Construct standard POSIX `SCM_RIGHTS` control message passing single fd.
        unsafe {
            let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
            let mut cbuf = vec![0u8; cmsg_space];
            let mut hdr: libc::msghdr = std::mem::zeroed();
            hdr.msg_iov = (&raw const iov).cast_mut();
            hdr.msg_iovlen = 1;
            hdr.msg_control = cbuf.as_mut_ptr().cast();
            hdr.msg_controllen = cmsg_space;

            let cmsg = libc::CMSG_FIRSTHDR(&hdr);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<i32>(), fd_to_pass);

            let sent = libc::sendmsg(stream.as_raw_fd(), &hdr, libc::MSG_NOSIGNAL);
            if sent as usize != msg.len() {
                return Err(HostError::new(
                    ErrorCode::CaptureUnavailable,
                    "Wayland SCM_RIGHTS sendmsg failed",
                ));
            }
        }
        Ok(())
    }

    fn wl_read_event(stream: &mut UnixStream) -> Result<(u32, u16, Vec<u8>), HostError> {
        let mut hdr = [0u8; 8];
        stream.read_exact(&mut hdr).map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) {
                HostError::new(ErrorCode::CaptureExpired, "Wayland poll slice elapsed")
            } else {
                HostError::new(ErrorCode::CaptureUnavailable, "Wayland socket closed")
            }
        })?;
        let sender = u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let word2 = u32::from_ne_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let size = (word2 >> 16) as usize;
        let opcode = (word2 & 0xFFFF) as u16;
        if !(8..=4096).contains(&size) {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "invalid Wayland event frame length",
            ));
        }
        let mut body = vec![0u8; size - 8];
        if !body.is_empty() {
            stream.read_exact(&mut body).map_err(|_| {
                HostError::new(ErrorCode::CaptureUnavailable, "Wayland truncated event")
            })?;
        }
        Ok((sender, opcode, body))
    }

    fn wl_parse_string(buf: &[u8], offset: usize) -> Option<(String, usize)> {
        if offset + 4 > buf.len() {
            return None;
        }
        let slen = u32::from_ne_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        if slen == 0 {
            return Some((String::new(), offset + 4));
        }
        let padded = slen.div_ceil(4) * 4;
        if offset + 4 + padded > buf.len() {
            return None;
        }
        let raw = &buf[offset + 4..offset + 4 + slen - 1];
        let s = std::str::from_utf8(raw).ok()?.to_string();
        Some((s, offset + 4 + padded))
    }

    fn capture_wayland_data_control(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        let sock_path = resolve_wayland_socket_path()?;
        let mut stream = UnixStream::connect(&sock_path).map_err(|_| {
            HostError::new(
                ErrorCode::CaptureUnavailable,
                "failed connecting to WAYLAND_DISPLAY",
            )
        })?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        // Object IDs: 1 = wl_display, 2 = wl_registry, 3 = sync1, 4 = wl_seat, 5 = manager, 6 = device, 7 = sync2
        wl_send_msg(&mut stream, 1, 1, &2u32.to_ne_bytes())?; // get_registry(2)
        wl_send_msg(&mut stream, 1, 0, &3u32.to_ne_bytes())?; // sync(3)

        let mut seat_global: Option<(u32, u32)> = None;
        let mut mgr_global: Option<(u32, String, u32)> = None;

        loop {
            let (sender, opcode, body) = wl_read_event(&mut stream)?;
            if sender == 3 && opcode == 0 {
                break;
            }
            if sender == 2 && opcode == 0 && body.len() >= 8 {
                let name = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                if let Some((iface, next_off)) = wl_parse_string(&body, 4)
                    && next_off + 4 <= body.len()
                {
                    let ver = u32::from_ne_bytes([
                        body[next_off],
                        body[next_off + 1],
                        body[next_off + 2],
                        body[next_off + 3],
                    ]);
                    if iface == "wl_seat" && seat_global.is_none() {
                        seat_global = Some((name, ver.min(1)));
                    } else if iface == "ext_data_control_manager_v1"
                        || (iface == "zwlr_data_control_manager_v1" && mgr_global.is_none())
                    {
                        mgr_global = Some((name, iface, 1));
                    }
                }
            }
        }

        let Some((seat_name, seat_ver)) = seat_global else {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "Wayland compositor did not advertise wl_seat",
            ));
        };
        let Some((mgr_name, mgr_iface, mgr_ver)) = mgr_global else {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "Wayland compositor does not advertise ext_data_control_manager_v1 or zwlr_data_control_manager_v1",
            ));
        };

        // wl_registry.bind(name: u32, iface: string, version: u32, id: new_id) -> opcode 0
        let mut bind_seat = Vec::new();
        bind_seat.extend_from_slice(&seat_name.to_ne_bytes());
        wl_encode_string(&mut bind_seat, "wl_seat");
        bind_seat.extend_from_slice(&seat_ver.to_ne_bytes());
        bind_seat.extend_from_slice(&4u32.to_ne_bytes());
        wl_send_msg(&mut stream, 2, 0, &bind_seat)?;

        let mut bind_mgr = Vec::new();
        bind_mgr.extend_from_slice(&mgr_name.to_ne_bytes());
        wl_encode_string(&mut bind_mgr, &mgr_iface);
        bind_mgr.extend_from_slice(&mgr_ver.to_ne_bytes());
        bind_mgr.extend_from_slice(&5u32.to_ne_bytes());
        wl_send_msg(&mut stream, 2, 0, &bind_mgr)?;

        // manager.get_data_device(id = 6, seat = 4) -> opcode 1
        let mut get_dev = Vec::with_capacity(8);
        get_dev.extend_from_slice(&6u32.to_ne_bytes());
        get_dev.extend_from_slice(&4u32.to_ne_bytes());
        wl_send_msg(&mut stream, 5, 1, &get_dev)?;
        wl_send_msg(&mut stream, 1, 0, &7u32.to_ne_bytes())?; // sync(7) to drain pre-existing selection

        let mut offer_mimes: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        loop {
            let (sender, opcode, body) = wl_read_event(&mut stream)?;
            if sender == 7 && opcode == 0 {
                break;
            }
            if sender == 6 && opcode == 0 && body.len() >= 4 {
                let oid = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                offer_mimes.insert(oid, Vec::new());
            } else if offer_mimes.contains_key(&sender)
                && opcode == 0
                && let Some((mime, _)) = wl_parse_string(&body, 0)
                && let Some(list) = offer_mimes.get_mut(&sender)
            {
                list.push(mime);
            }
        }
        offer_mimes.clear();

        let deadline = Instant::now() + ttl;
        while Instant::now() < deadline {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                break;
            }
            let _ = stream.set_read_timeout(Some(rem.min(Duration::from_millis(250))));
            let (sender, opcode, body) = match wl_read_event(&mut stream) {
                Ok(ev) => ev,
                Err(e) if e.code == ErrorCode::CaptureExpired => continue,
                Err(e) => return Err(e),
            };

            if sender == 6 && opcode == 0 && body.len() >= 4 {
                let oid = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                offer_mimes.insert(oid, Vec::new());
            } else if offer_mimes.contains_key(&sender)
                && opcode == 0
                && let Some((mime, _)) = wl_parse_string(&body, 0)
                && let Some(list) = offer_mimes.get_mut(&sender)
            {
                list.push(mime);
            } else if sender == 6 && opcode == 1 && body.len() >= 4 {
                let selected_offer = u32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                if selected_offer == 0 {
                    continue;
                }
                let chosen_mime = offer_mimes
                    .get(&selected_offer)
                    .and_then(|m| {
                        m.iter()
                            .find(|x| x.as_str() == "text/plain;charset=utf-8")
                            .or_else(|| m.iter().find(|x| x.as_str() == "UTF8_STRING"))
                            .or_else(|| m.iter().find(|x| x.starts_with("text/plain")))
                    })
                    .cloned()
                    .unwrap_or_else(|| "text/plain;charset=utf-8".to_string());

                let mut pipe_fds = [-1i32; 2];
                // SAFETY: `pipe2` initializes `pipe_fds` with owned CLOEXEC descriptors on success.
                if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                    return Err(HostError::new(
                        ErrorCode::InternalError,
                        "pipe2 failed during Wayland secret capture",
                    ));
                }
                // SAFETY: `pipe_fds[0]` and `pipe_fds[1]` are newly created descriptors.
                let mut read_pipe = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
                let write_fd_guard = DropGuard::new(pipe_fds[1], |fd| unsafe {
                    let _ = libc::close(fd);
                });

                let mut recv_payload = Vec::new();
                wl_encode_string(&mut recv_payload, &chosen_mime);
                wl_send_msg_with_fd(&stream, selected_offer, 0, &recv_payload, *write_fd_guard)?;
                drop(write_fd_guard);
                let _ = stream.flush();

                let captured = MlockedHostBuffer::from_reader_bounded(&mut read_pipe)?;

                // Wipe compositor clipboard selection (`set_selection(0)`) & destroy offer immediately (`H6`).
                let _ = wl_send_msg(&mut stream, 6, 0, &0u32.to_ne_bytes());
                let _ = wl_send_msg(&mut stream, selected_offer, 1, &[]);
                let _ = stream.flush();
                return Ok((captured, CaptureInterceptMode::PasteboardFallback));
            }
        }

        Err(HostError::new(
            ErrorCode::CaptureExpired,
            "15-second Wayland Armed Copy window expired",
        ))
    }

    // ---------------------------------------------------------------------
    // Direct X11 `libX11.so.6` Implementation (`H6` -- zero `xclip`)
    // ---------------------------------------------------------------------

    fn capture_x11_armed(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        use std::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};

        type Display = c_void;
        type Window = c_ulong;
        type Atom = c_ulong;
        type Time = c_ulong;
        type KeySym = c_ulong;
        type KeyCode = u8;

        const CONTROL_MASK: c_uint = 1 << 2;
        const LOCK_MASK: c_uint = 1 << 1;
        const MOD2_MASK: c_uint = 1 << 4;
        const ANY_MODIFIER: c_uint = 1 << 15;
        const GRAB_MODE_ASYNC: c_int = 1;
        const KEY_PRESS: c_int = 2;
        const SELECTION_NOTIFY: c_int = 31;
        const XK_LOWER_C: KeySym = 0x0063;
        const XK_ESCAPE: KeySym = 0xff1b;

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct XKeyEvent {
            event_type: c_int,
            serial: c_ulong,
            send_event: c_int,
            display: *mut Display,
            window: Window,
            root: Window,
            subwindow: Window,
            time: Time,
            x: c_int,
            y: c_int,
            x_root: c_int,
            y_root: c_int,
            state: c_uint,
            keycode: c_uint,
            same_screen: c_int,
        }

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct XSelectionEvent {
            event_type: c_int,
            serial: c_ulong,
            send_event: c_int,
            display: *mut Display,
            requestor: Window,
            selection: Atom,
            target: Atom,
            property: Atom,
            time: Time,
        }

        #[repr(C)]
        union XEvent {
            event_type: c_int,
            xkey: XKeyEvent,
            xselection: XSelectionEvent,
            pad: [c_long; 24],
        }

        // SAFETY: `dlopen` with `RTLD_LAZY | RTLD_LOCAL` loads system `libX11.so.6` without shell/CLI tools.
        let libx11 =
            unsafe { libc::dlopen(c"libX11.so.6".as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
        if libx11.is_null() {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "libX11.so.6 is unavailable on this Linux host",
            ));
        }
        let _dl_guard = DropGuard::new(libx11, |h| unsafe {
            let _ = libc::dlclose(h);
        });

        unsafe fn sym<T>(handle: *mut c_void, name: &'static CStr) -> Option<T> {
            let ptr = unsafe { libc::dlsym(handle, name.as_ptr()) };
            if ptr.is_null() {
                None
            } else {
                Some(unsafe { std::mem::transmute_copy(&ptr) })
            }
        }

        type FnOpenDisplay = unsafe extern "C" fn(*const c_char) -> *mut Display;
        type FnCloseDisplay = unsafe extern "C" fn(*mut Display) -> c_int;
        type FnDefaultRootWindow = unsafe extern "C" fn(*mut Display) -> Window;
        type FnCreateSimpleWindow = unsafe extern "C" fn(
            *mut Display,
            Window,
            c_int,
            c_int,
            c_uint,
            c_uint,
            c_uint,
            c_ulong,
            c_ulong,
        ) -> Window;
        type FnDestroyWindow = unsafe extern "C" fn(*mut Display, Window) -> c_int;
        type FnInternAtom = unsafe extern "C" fn(*mut Display, *const c_char, c_int) -> Atom;
        type FnGetSelectionOwner = unsafe extern "C" fn(*mut Display, Atom) -> Window;
        type FnSetSelectionOwner = unsafe extern "C" fn(*mut Display, Atom, Window, Time) -> c_int;
        type FnConvertSelection =
            unsafe extern "C" fn(*mut Display, Atom, Atom, Atom, Window, Time) -> c_int;
        type FnGetWindowProperty = unsafe extern "C" fn(
            *mut Display,
            Window,
            Atom,
            c_long,
            c_long,
            c_int,
            Atom,
            *mut Atom,
            *mut c_int,
            *mut c_ulong,
            *mut c_ulong,
            *mut *mut c_uchar,
        ) -> c_int;
        type FnDeleteProperty = unsafe extern "C" fn(*mut Display, Window, Atom) -> c_int;
        type FnFree = unsafe extern "C" fn(*mut c_void) -> c_int;
        type FnKeysymToKeycode = unsafe extern "C" fn(*mut Display, KeySym) -> KeyCode;
        type FnGrabKey =
            unsafe extern "C" fn(*mut Display, c_int, c_uint, Window, c_int, c_int, c_int) -> c_int;
        type FnUngrabKey = unsafe extern "C" fn(*mut Display, c_int, c_uint, Window) -> c_int;
        type FnPending = unsafe extern "C" fn(*mut Display) -> c_int;
        type FnNextEvent = unsafe extern "C" fn(*mut Display, *mut XEvent) -> c_int;
        type FnCheckTypedWindowEvent =
            unsafe extern "C" fn(*mut Display, Window, c_int, *mut XEvent) -> c_int;
        type FnSync = unsafe extern "C" fn(*mut Display, c_int) -> c_int;

        let load_err = || {
            HostError::new(
                ErrorCode::CaptureUnavailable,
                "missing required X11 selection symbols in libX11.so.6",
            )
        };
        let x_open: FnOpenDisplay = unsafe { sym(libx11, c"XOpenDisplay") }.ok_or_else(load_err)?;
        let x_close: FnCloseDisplay =
            unsafe { sym(libx11, c"XCloseDisplay") }.ok_or_else(load_err)?;
        let x_root: FnDefaultRootWindow =
            unsafe { sym(libx11, c"XDefaultRootWindow") }.ok_or_else(load_err)?;
        let x_create_win: FnCreateSimpleWindow =
            unsafe { sym(libx11, c"XCreateSimpleWindow") }.ok_or_else(load_err)?;
        let x_destroy_win: FnDestroyWindow =
            unsafe { sym(libx11, c"XDestroyWindow") }.ok_or_else(load_err)?;
        let x_atom: FnInternAtom = unsafe { sym(libx11, c"XInternAtom") }.ok_or_else(load_err)?;
        let x_get_owner: FnGetSelectionOwner =
            unsafe { sym(libx11, c"XGetSelectionOwner") }.ok_or_else(load_err)?;
        let x_set_owner: FnSetSelectionOwner =
            unsafe { sym(libx11, c"XSetSelectionOwner") }.ok_or_else(load_err)?;
        let x_convert: FnConvertSelection =
            unsafe { sym(libx11, c"XConvertSelection") }.ok_or_else(load_err)?;
        let x_get_prop: FnGetWindowProperty =
            unsafe { sym(libx11, c"XGetWindowProperty") }.ok_or_else(load_err)?;
        let x_del_prop: FnDeleteProperty =
            unsafe { sym(libx11, c"XDeleteProperty") }.ok_or_else(load_err)?;
        let x_free: FnFree = unsafe { sym(libx11, c"XFree") }.ok_or_else(load_err)?;
        let x_ks2kc: FnKeysymToKeycode =
            unsafe { sym(libx11, c"XKeysymToKeycode") }.ok_or_else(load_err)?;
        let x_grab: FnGrabKey = unsafe { sym(libx11, c"XGrabKey") }.ok_or_else(load_err)?;
        let x_ungrab: FnUngrabKey = unsafe { sym(libx11, c"XUngrabKey") }.ok_or_else(load_err)?;
        let x_pending: FnPending = unsafe { sym(libx11, c"XPending") }.ok_or_else(load_err)?;
        let x_next: FnNextEvent = unsafe { sym(libx11, c"XNextEvent") }.ok_or_else(load_err)?;
        let x_check_win_ev: FnCheckTypedWindowEvent =
            unsafe { sym(libx11, c"XCheckTypedWindowEvent") }.ok_or_else(load_err)?;
        let x_sync: FnSync = unsafe { sym(libx11, c"XSync") }.ok_or_else(load_err)?;

        let dpy = unsafe { x_open(std::ptr::null()) };
        if dpy.is_null() {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "unable to connect to X11 DISPLAY",
            ));
        }
        let _dpy_guard = DropGuard::new(dpy, |d| unsafe {
            let _ = x_close(d);
        });

        let root = unsafe { x_root(dpy) };
        let req_win = unsafe { x_create_win(dpy, root, -10, -10, 1, 1, 0, 0, 0) };
        if req_win == 0 {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "XCreateSimpleWindow failed",
            ));
        }
        let _win_guard = DropGuard::new(req_win, |w| unsafe {
            let _ = x_destroy_win(dpy, w);
        });

        let atom_primary = unsafe { x_atom(dpy, c"PRIMARY".as_ptr(), 0) };
        let atom_clipboard = unsafe { x_atom(dpy, c"CLIPBOARD".as_ptr(), 0) };
        let atom_utf8 = unsafe { x_atom(dpy, c"UTF8_STRING".as_ptr(), 0) };
        let atom_string = unsafe { x_atom(dpy, c"STRING".as_ptr(), 0) };
        let atom_prop = unsafe { x_atom(dpy, c"SB_ARMED_CAPTURE_PROP".as_ptr(), 0) };
        let atom_incr = unsafe { x_atom(dpy, c"INCR".as_ptr(), 0) };

        let read_sel = |sel_atom: Atom| -> Option<MlockedHostBuffer> {
            let owner = unsafe { x_get_owner(dpy, sel_atom) };
            if owner == 0 || owner == req_win {
                return None;
            }
            for target_atom in [atom_utf8, atom_string] {
                unsafe {
                    let _ = x_del_prop(dpy, req_win, atom_prop);
                    let _ = x_convert(dpy, sel_atom, target_atom, atom_prop, req_win, 0);
                    let _ = x_sync(dpy, 0);
                }
                let wait_until = Instant::now() + Duration::from_millis(80);
                let mut got_prop = false;
                while Instant::now() < wait_until {
                    let mut sev = XEvent { pad: [0; 24] };
                    if unsafe { x_check_win_ev(dpy, req_win, SELECTION_NOTIFY, &mut sev) } != 0 {
                        got_prop = unsafe { sev.xselection.property != 0 };
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                if !got_prop {
                    continue;
                }
                let mut actual_type: Atom = 0;
                let mut actual_fmt: c_int = 0;
                let mut nitems: c_ulong = 0;
                let mut bytes_after: c_ulong = 0;
                let mut prop_ptr: *mut c_uchar = std::ptr::null_mut();
                let rc = unsafe {
                    x_get_prop(
                        dpy,
                        req_win,
                        atom_prop,
                        0,
                        (MAX_CAPTURED_SECRET_BYTES as c_long / 4) + 4,
                        1, // Delete = True
                        0, // AnyPropertyType
                        &mut actual_type,
                        &mut actual_fmt,
                        &mut nitems,
                        &mut bytes_after,
                        &mut prop_ptr,
                    )
                };
                if rc != 0 || prop_ptr.is_null() {
                    continue;
                }
                let byte_len = if actual_fmt == 8 { nitems as usize } else { 0 };
                let _prop_guard = DropGuard::new((prop_ptr, byte_len), |(p, len)| unsafe {
                    if len > 0 {
                        std::slice::from_raw_parts_mut(p, len).zeroize();
                    }
                    let _ = x_free(p.cast());
                });
                if actual_type == atom_incr || bytes_after > 0 || byte_len == 0 {
                    continue;
                }
                let slice = unsafe { std::slice::from_raw_parts(prop_ptr, byte_len) };
                if let Ok(locked) = MlockedHostBuffer::from_bytes(slice) {
                    return Some(locked);
                }
            }
            None
        };

        let clear_sel = |sel_atom: Atom| unsafe {
            let _ = x_set_owner(dpy, sel_atom, req_win, 0);
            let _ = x_set_owner(dpy, sel_atom, 0, 0);
            let _ = x_sync(dpy, 0);
        };

        let kc_c = c_int::from(unsafe { x_ks2kc(dpy, XK_LOWER_C) });
        let kc_esc = c_int::from(unsafe { x_ks2kc(dpy, XK_ESCAPE) });
        let modifiers = [
            CONTROL_MASK,
            CONTROL_MASK | MOD2_MASK,
            CONTROL_MASK | LOCK_MASK,
            CONTROL_MASK | MOD2_MASK | LOCK_MASK,
        ];
        for &m in &modifiers {
            unsafe {
                let _ = x_grab(dpy, kc_c, m, root, 0, GRAB_MODE_ASYNC, GRAB_MODE_ASYNC);
            }
        }
        unsafe {
            let _ = x_grab(
                dpy,
                kc_esc,
                ANY_MODIFIER,
                root,
                0,
                GRAB_MODE_ASYNC,
                GRAB_MODE_ASYNC,
            );
            let _ = x_sync(dpy, 0);
        }

        let _grab_guard = DropGuard::new(dpy, |d| unsafe {
            for &m in &modifiers {
                let _ = x_ungrab(d, kc_c, m, root);
            }
            let _ = x_ungrab(d, kc_esc, ANY_MODIFIER, root);
            let _ = x_sync(d, 0);
        });

        let initial_clip = read_sel(atom_clipboard);
        let initial_hash: Option<[u8; 32]> = initial_clip.as_ref().map(|b| {
            use sha2::{Digest, Sha256};
            Sha256::digest(b.as_bytes()).into()
        });
        drop(initial_clip);

        let deadline = Instant::now() + ttl;
        let mut last_clip_poll = Instant::now();
        while Instant::now() < deadline {
            while unsafe { x_pending(dpy) } > 0 {
                let mut ev = XEvent { pad: [0; 24] };
                unsafe {
                    let _ = x_next(dpy, &mut ev);
                }
                if unsafe { ev.event_type } == KEY_PRESS {
                    let pressed_kc = unsafe { ev.xkey.keycode } as c_int;
                    if pressed_kc == kc_esc {
                        return Err(HostError::new(
                            ErrorCode::CaptureExpired,
                            "Armed Copy cancelled by user (Esc)",
                        ));
                    }
                    if pressed_kc == kc_c
                        && let Some(primary) = read_sel(atom_primary)
                    {
                        clear_sel(atom_primary);
                        return Ok((primary, CaptureInterceptMode::ZeroPasteboard));
                    }
                }
            }

            if last_clip_poll.elapsed() >= Duration::from_millis(10) {
                last_clip_poll = Instant::now();
                if let Some(cur_clip) = read_sel(atom_clipboard) {
                    let cur_hash: [u8; 32] = {
                        use sha2::{Digest, Sha256};
                        Sha256::digest(cur_clip.as_bytes()).into()
                    };
                    if initial_hash.as_ref() != Some(&cur_hash) {
                        clear_sel(atom_clipboard);
                        return Ok((cur_clip, CaptureInterceptMode::PasteboardFallback));
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        Err(HostError::new(
            ErrorCode::CaptureExpired,
            "15-second X11 Armed Copy window expired",
        ))
    }
}
