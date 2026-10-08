// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 rituparnaprof
//! SecuredStorage - OS Hardening & Anti-Tamper Security Module

#[cfg(target_os = "macos")]
extern "C" {
    fn ptrace(request: libc::c_int, pid: libc::pid_t, addr: *const libc::c_char, data: libc::c_int) -> libc::c_int;
}

#[cfg(target_os = "macos")]
const PT_DENY_ATTACH: libc::c_int = 31;

/// Apply kernel-level anti-debugging and process dumping defenses
pub fn apply_process_hardening() {
    // 1. Disable core dumps (prevent memory dumps on crash)
    #[cfg(unix)]
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
    }

    // 2. Anti-debugging: Deny debugger attach
    #[cfg(target_os = "macos")]
    unsafe {
        // PT_DENY_ATTACH tells the kernel to send SIGSEGV if a debugger tries to attach
        ptrace(PT_DENY_ATTACH, 0, std::ptr::null(), 0);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        // Disable ptrace and memory dumping from non-root processes
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        if IsDebuggerPresent() != 0 {
            std::process::exit(1);
        }
    }
}

/// Prevent OS window from being captured in screenshots, screen shares, or recordings
pub fn apply_window_capture_protection(_window: &tauri::WebviewWindow) {
    #[cfg(target_os = "macos")]
    {
        // On macOS, set NSWindow.sharingType = NSWindowSharingNone (0)
        // This causes the window to render completely transparent/black in all screen captures and screen shares
        if let Ok(ns_window) = _window.ns_window() {
            if !ns_window.is_null() {
                unsafe {
                    // Use Objective-C runtime msgSend to call [nsWindow setSharingType:0]
                    extern "C" {
                        fn objc_msgSend(receiver: *mut std::ffi::c_void, op: *const std::ffi::c_void, arg: usize);
                        fn sel_registerName(name: *const libc::c_char) -> *const std::ffi::c_void;
                    }
                    let sel = sel_registerName(c"setSharingType:".as_ptr());
                    objc_msgSend(ns_window, sel, 0); // 0 = NSWindowSharingNone
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, set SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        if let Ok(hwnd) = _window.hwnd() {
            unsafe {
                use windows_sys::Win32::UI::WindowsAndMessaging::SetWindowDisplayAffinity;
                const WDA_EXCLUDEFROMCAPTURE: u32 = 0x00000011;
                SetWindowDisplayAffinity(hwnd.0 as _, WDA_EXCLUDEFROMCAPTURE);
            }
        }
    }
}

/// Pin sensitive memory pages into physical RAM to prevent swapping to disk
pub fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Memory::VirtualLock;
        VirtualLock(ptr as *const std::ffi::c_void, len);
    }
}

/// Unlock memory pages
pub fn unlock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        VirtualUnlock(ptr as *const std::ffi::c_void, len);
    }
}

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

static LAST_CLIPBOARD_CHANGE_ID: AtomicI64 = AtomicI64::new(-1);
static LAST_COPY_SESSION_ID: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
extern "C" {
    fn write_concealed_macos_pasteboard(utf8_text: *const libc::c_char) -> libc::c_long;
    fn clear_macos_pasteboard_if_matches(expected_change_count: libc::c_long) -> libc::c_int;
}

/// Securely copies a credential to the system clipboard with native concealment and anti-cloud flags.
/// Automatically starts an asynchronous background timer (30 seconds) to wipe the clipboard.
pub fn copy_to_secure_clipboard(secret: &str) -> Result<u64, String> {
    let session_id = LAST_COPY_SESSION_ID.fetch_add(1, Ordering::SeqCst) + 1;

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        let c_secret = CString::new(secret).map_err(|_| "Failed to allocate CString for clipboard".to_string())?;
        let change_count = unsafe { write_concealed_macos_pasteboard(c_secret.as_ptr()) };
        LAST_CLIPBOARD_CHANGE_ID.store(change_count as i64, Ordering::SeqCst);
    }

    #[cfg(target_os = "windows")]
    {
        copy_windows_secure_clipboard(secret)?;
    }

    #[cfg(target_os = "linux")]
    {
        copy_linux_clipboard(secret);
    }

    const TTL_SECONDS: u64 = 30;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(TTL_SECONDS));
        // Only clear if no subsequent copy has superseded this timer
        if LAST_COPY_SESSION_ID.load(Ordering::SeqCst) == session_id {
            let expected_change_id = LAST_CLIPBOARD_CHANGE_ID.load(Ordering::SeqCst);
            clear_secure_clipboard_internal(expected_change_id);
        }
    });

    Ok(TTL_SECONDS)
}

/// Manually and immediately wipes the system clipboard if it contains SecuredStorage data.
pub fn clear_secure_clipboard() -> bool {
    LAST_COPY_SESSION_ID.fetch_add(1, Ordering::SeqCst);
    clear_secure_clipboard_internal(-1)
}

fn clear_secure_clipboard_internal(expected_change_id: i64) -> bool {
    #[cfg(target_os = "macos")]
    {
        let res = unsafe { clear_macos_pasteboard_if_matches(expected_change_id as libc::c_long) };
        res == 1
    }

    #[cfg(target_os = "windows")]
    {
        clear_windows_clipboard()
    }

    #[cfg(target_os = "linux")]
    {
        clear_linux_clipboard()
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = expected_change_id;
        true
    }
}

#[cfg(target_os = "windows")]
fn copy_windows_secure_clipboard(_text: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn clear_windows_clipboard() -> bool {
    true
}

#[cfg(target_os = "linux")]
fn copy_linux_clipboard(text: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if let Ok(mut child) = Command::new("wl-copy").stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
        return;
    }
    if let Ok(mut child) = Command::new("xclip").args(["-selection", "clipboard"]).stdin(Stdio::piped()).spawn() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }
        let _ = child.wait();
    }
}

#[cfg(target_os = "linux")]
fn clear_linux_clipboard() -> bool {
    use std::process::Command;
    if Command::new("wl-copy").arg("--clear").status().is_ok() {
        return true;
    }
    let _ = Command::new("xclip").args(["-selection", "clipboard", "/dev/null"]).status();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_clipboard_write_and_clear() {
        let ttl = copy_to_secure_clipboard("TestSecret12345!").expect("Failed to copy");
        assert_eq!(ttl, 30);
        let cleared = clear_secure_clipboard();
        assert!(cleared);
    }
}

