use crate::manifest_io::HostError;
use sb_proto::crypto::seal_base64;
use sb_proto::error::ErrorCode;
use sb_proto::rpc::CaptureInterceptMode;
use std::mem::DropGuard;
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, compiler_fence};
use std::time::{Duration, Instant};

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
/// capture -> X25519 `seal_base64` -> zeroize -> `munlock` -> `munmap`.
pub struct MlockedHostBuffer {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    mlocked: bool,
}

// SAFETY: `MlockedHostBuffer` uniquely owns its anonymous private mapping.
unsafe impl Send for MlockedHostBuffer {}

impl MlockedHostBuffer {
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
        // SAFETY: `sysconf(_SC_PAGESIZE)` has no memory safety preconditions.
        let page_sz = unsafe {
            let v = libc::sysconf(libc::_SC_PAGESIZE);
            if v > 0 { v as usize } else { 4096 }
        };
        let cap = src.len().max(1).div_ceil(page_sz) * page_sz;

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
            // SAFETY: `p` is a valid `cap`-byte mapping if initialization aborts.
            unsafe {
                std::ptr::write_bytes(p.as_ptr(), 0, cap);
                compiler_fence(Ordering::SeqCst);
                let _ = libc::munmap(p.as_ptr().cast(), cap);
            }
        });

        #[cfg(target_os = "linux")]
        // SAFETY: excludes capture buffer from core dumps.
        unsafe {
            let _ = libc::madvise(guard.as_ptr().cast(), cap, libc::MADV_DONTDUMP);
        }

        // SAFETY: pins capture buffer into physical RAM so swap never sees plaintext.
        let mlocked = unsafe { libc::mlock(guard.as_ptr().cast(), cap) == 0 };

        // SAFETY: `guard` points to `cap >= src.len()` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), guard.as_ptr(), src.len());
        }

        let confirmed = DropGuard::dismiss(guard);
        Ok(Self {
            ptr: confirmed,
            len: src.len(),
            cap,
            mlocked,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.ptr` is valid for `self.len` bytes for `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for MlockedHostBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is uniquely owned and `self.cap` bytes long.
        unsafe {
            std::ptr::write_bytes(self.ptr.as_ptr(), 0, self.cap);
            compiler_fence(Ordering::SeqCst);
            if self.mlocked {
                let _ = libc::munlock(self.ptr.as_ptr().cast(), self.cap);
            }
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.cap);
        }
    }
}

/// Trait allowing deterministic testing of the Armed Copy Hijack pipeline on headless CI
/// while delegating to the native OS hook (`CGEventTap`/`AXUIElement` on macOS,
/// X11 `XGrabKey`+`PRIMARY` / Wayland data-control on Linux) in production.
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
    // Ensure mlocked_buf is dropped immediately at end of scope via DropGuard even on early return.
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
// macOS arm64 Native Implementation:
// Active CGEventTap (swallows Cmd+C -> AXUIElement kAXSelectedTextAttribute)
// + 1ms NSPasteboard snapshot-capture-restore fallback
// =========================================================================
#[cfg(target_os = "macos")]
mod macos_imp {
    use super::{CaptureInterceptMode, HostError, Instant, MlockedHostBuffer};
    use sb_proto::error::ErrorCode;
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::mem::DropGuard;
    use std::sync::Mutex;
    use std::time::Duration;

    type CFTypeRef = *const c_void;
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
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

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
        // SAFETY: `AXUIElementCreateSystemWide` returns a +1 retained AXUIElementRef.
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
            let sel_utf8 = sel_registerName(c"UTF8String".as_ptr());
            let get_cstr: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let c_ptr = get_cstr(ns_val, sel_utf8);
            if c_ptr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(c_ptr).to_bytes();
            MlockedHostBuffer::from_bytes(bytes).ok()
        }
    }

    unsafe fn pasteboard_restore(pb: *mut c_void, prior: Option<&MlockedHostBuffer>) {
        unsafe {
            let sel_clear = sel_registerName(c"clearContents".as_ptr());
            let clear_fn: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let _ = clear_fn(pb, sel_clear);

            if let Some(prev) = prior
                && let Ok(c_str) = CString::new(prev.as_bytes())
            {
                let ns_string_cls = objc_getClass(c"NSString".as_ptr());
                let sel_str_utf8 = sel_registerName(c"stringWithUTF8String:".as_ptr());
                let mk_str: unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_void,
                    *const c_char,
                ) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
                let ns_val = mk_str(ns_string_cls, sel_str_utf8, c_str.as_ptr());
                let pb_type = mk_str(
                    ns_string_cls,
                    sel_str_utf8,
                    c"public.utf8-plain-text".as_ptr(),
                );
                if !ns_val.is_null() && !pb_type.is_null() {
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
        // SAFETY: Carbon preflight for Secure Event Input lock.
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

        // Snapshot NSPasteboard prior state into mlock() for the 1ms web-Copy-button fallback
        let pb = unsafe { general_pasteboard() };
        let initial_change_count = if pb.is_null() {
            0
        } else {
            unsafe { pasteboard_change_count(pb) }
        };
        let prior_snapshot = if pb.is_null() {
            None
        } else {
            unsafe { pasteboard_read_utf8_mlocked(pb) }
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
            // Pump event tap runloop in 1ms slices so we also catch web "Copy" icon clicks in <= 1ms
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
// Linux x86_64/arm64 Native Implementation:
// X11 (XGrabKey Ctrl+C + PRIMARY selection read/wipe into mlock()) and
// Wayland (wl-paste / data-control single-shot stream + immediate restore),
// using DropGuard for guaranteed ungrab, child reaper, and clipboard restore.
// =========================================================================
#[cfg(target_os = "linux")]
mod linux_imp {
    use super::{CaptureInterceptMode, HostError, Instant, MlockedHostBuffer};
    use sb_proto::error::ErrorCode;
    use std::io::Read;
    use std::mem::DropGuard;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use zeroize::Zeroizing;

    fn read_clipboard_cmd(prog: &str, args: &[&str]) -> Option<MlockedHostBuffer> {
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut raw = Zeroizing::new(Vec::new());
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_end(&mut raw);
        }
        let status = child.wait().ok()?;
        if !status.success() || raw.is_empty() {
            return None;
        }
        MlockedHostBuffer::from_bytes(&raw).ok()
    }

    fn write_clipboard_cmd(prog: &str, args: &[&str], data: &[u8]) {
        use std::io::Write;
        if let Ok(mut child) = Command::new(prog)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(data);
            }
            let _ = child.wait();
        }
    }

    pub fn capture_linux_armed(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return capture_wayland_data_control(ttl);
        }
        if std::env::var_os("DISPLAY").is_some() {
            return capture_x11_armed(ttl);
        }
        Err(HostError::new(
            ErrorCode::CaptureUnavailable,
            "neither WAYLAND_DISPLAY nor DISPLAY is active; use In-VM Generate Secret on headless Linux",
        ))
    }

    fn capture_wayland_data_control(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        // Snapshot prior clipboard into mlock() so we restore it the millisecond a copy arrives
        let prior = read_clipboard_cmd("wl-paste", &["--no-newline"]);
        let prior_hash = prior.as_ref().map(|b| {
            use sha2::{Digest, Sha256};
            let d: [u8; 32] = Sha256::digest(b.as_bytes()).into();
            d
        });

        let deadline = Instant::now() + ttl;
        while Instant::now() < deadline {
            if let Some(cur) = read_clipboard_cmd("wl-paste", &["--no-newline"]) {
                let cur_hash: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(cur.as_bytes()).into()
                };
                if prior_hash.as_ref() != Some(&cur_hash) {
                    // Restore prior clipboard (or clear via `wl-copy --clear`) via DropGuard
                    let _restore_guard = DropGuard::new(prior, |prev| match prev {
                        Some(buf) => write_clipboard_cmd("wl-copy", &[], buf.as_bytes()),
                        None => {
                            let _ = Command::new("wl-copy").arg("--clear").status();
                        }
                    });
                    return Ok((cur, CaptureInterceptMode::PasteboardFallback));
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(HostError::new(
            ErrorCode::CaptureExpired,
            "15-second Wayland Armed Copy window expired",
        ))
    }

    fn capture_x11_armed(
        ttl: Duration,
    ) -> Result<(MlockedHostBuffer, CaptureInterceptMode), HostError> {
        use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};

        type Display = c_void;
        type Window = c_ulong;
        type KeySym = c_ulong;
        type KeyCode = u8;

        const CONTROL_MASK: c_uint = 1 << 2;
        const LOCK_MASK: c_uint = 1 << 1;
        const MOD2_MASK: c_uint = 1 << 4;
        const GRAB_MODE_ASYNC: c_int = 1;
        const KEY_PRESS: c_int = 2;
        const XK_LOWER_C: KeySym = 0x0063;

        #[repr(C)]
        union XEvent {
            event_type: c_int,
            pad: [c_long; 24],
        }

        // Dynamically load libX11.so.6 so sb-host compiles and runs without X11 dev packages installed.
        // SAFETY: `dlopen` with `RTLD_LAZY | RTLD_LOCAL` loads standard system libX11 if present.
        let libx11 =
            unsafe { libc::dlopen(c"libX11.so.6".as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
        if libx11.is_null() {
            return Err(HostError::new(
                ErrorCode::CaptureUnavailable,
                "libX11.so.6 is unavailable on this host",
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
        type FnKeysymToKeycode = unsafe extern "C" fn(*mut Display, KeySym) -> KeyCode;
        type FnGrabKey =
            unsafe extern "C" fn(*mut Display, c_int, c_uint, Window, c_int, c_int, c_int) -> c_int;
        type FnUngrabKey = unsafe extern "C" fn(*mut Display, c_int, c_uint, Window) -> c_int;
        type FnPending = unsafe extern "C" fn(*mut Display) -> c_int;
        type FnNextEvent = unsafe extern "C" fn(*mut Display, *mut XEvent) -> c_int;
        type FnSync = unsafe extern "C" fn(*mut Display, c_int) -> c_int;

        let load_err = || {
            HostError::new(
                ErrorCode::CaptureUnavailable,
                "missing required X11 symbols in libX11.so.6",
            )
        };
        let x_open: FnOpenDisplay = unsafe { sym(libx11, c"XOpenDisplay") }.ok_or_else(load_err)?;
        let x_close: FnCloseDisplay =
            unsafe { sym(libx11, c"XCloseDisplay") }.ok_or_else(load_err)?;
        let x_root: FnDefaultRootWindow =
            unsafe { sym(libx11, c"XDefaultRootWindow") }.ok_or_else(load_err)?;
        let x_ks2kc: FnKeysymToKeycode =
            unsafe { sym(libx11, c"XKeysymToKeycode") }.ok_or_else(load_err)?;
        let x_grab: FnGrabKey = unsafe { sym(libx11, c"XGrabKey") }.ok_or_else(load_err)?;
        let x_ungrab: FnUngrabKey = unsafe { sym(libx11, c"XUngrabKey") }.ok_or_else(load_err)?;
        let x_pending: FnPending = unsafe { sym(libx11, c"XPending") }.ok_or_else(load_err)?;
        let x_next: FnNextEvent = unsafe { sym(libx11, c"XNextEvent") }.ok_or_else(load_err)?;
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
        let kc_c = c_int::from(unsafe { x_ks2kc(dpy, XK_LOWER_C) });
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
            let _ = x_sync(dpy, 0);
        }

        // Guarantee XUngrabKey on all exit paths via DropGuard!
        let _grab_guard = DropGuard::new(dpy, |d| unsafe {
            for &m in &modifiers {
                let _ = x_ungrab(d, kc_c, m, root);
            }
            let _ = x_sync(d, 0);
        });

        let prior_clip = read_clipboard_cmd("xclip", &["-selection", "clipboard", "-o"]);
        let prior_hash = prior_clip.as_ref().map(|b| {
            use sha2::{Digest, Sha256};
            let d: [u8; 32] = Sha256::digest(b.as_bytes()).into();
            d
        });

        let deadline = Instant::now() + ttl;
        while Instant::now() < deadline {
            while unsafe { x_pending(dpy) } > 0 {
                let mut ev = XEvent { pad: [0; 24] };
                unsafe {
                    let _ = x_next(dpy, &mut ev);
                }
                let et = unsafe { ev.event_type };
                if et == KEY_PRESS
                    && let Some(primary) =
                        read_clipboard_cmd("xclip", &["-selection", "primary", "-o"])
                {
                    // Wipe PRIMARY selection immediately so highlighted secret does not linger
                    write_clipboard_cmd("xclip", &["-selection", "primary", "-i"], b"");
                    return Ok((primary, CaptureInterceptMode::ZeroPasteboard));
                }
            }

            if let Some(cur_clip) = read_clipboard_cmd("xclip", &["-selection", "clipboard", "-o"])
            {
                let cur_hash: [u8; 32] = {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(cur_clip.as_bytes()).into()
                };
                if prior_hash.as_ref() != Some(&cur_hash) {
                    let _restore_guard = DropGuard::new(prior_clip, |prev| match prev {
                        Some(buf) => {
                            write_clipboard_cmd(
                                "xclip",
                                &["-selection", "clipboard", "-i"],
                                buf.as_bytes(),
                            );
                        }
                        None => {
                            write_clipboard_cmd("xclip", &["-selection", "clipboard", "-i"], b"")
                        }
                    });
                    return Ok((cur_clip, CaptureInterceptMode::PasteboardFallback));
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
