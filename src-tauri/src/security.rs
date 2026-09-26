// SecuredStorage - OS Hardening & Anti-Tamper Security Module

#[cfg(target_os = "macos")]
extern "C" {
    fn ptrace(request: libc::c_int, pid: libc::pid_t, addr: *const libc::c_char, data: libc::c_int) -> libc::c_int;
}

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
pub fn apply_window_capture_protection(window: &tauri::WebviewWindow) {
    #[cfg(target_os = "macos")]
    {
        // On macOS, set NSWindow.sharingType = NSWindowSharingNone (0)
        // This causes the window to render completely transparent/black in all screen captures and screen shares
        use tauri::Manager;
        if let Ok(ns_window_ptr) = window.ns_window() {
            let ns_window = ns_window_ptr as *mut std::ffi::c_void;
            if !ns_window.is_null() {
                unsafe {
                    // Use Objective-C runtime msgSend to call [nsWindow setSharingType:0]
                    extern "C" {
                        fn objc_msgSend(receiver: *mut std::ffi::c_void, op: *const std::ffi::c_void, arg: usize);
                        fn sel_registerName(name: *const libc::c_char) -> *const std::ffi::c_void;
                    }
                    let sel = sel_registerName(b"setSharingType:\0".as_ptr() as *const libc::c_char);
                    objc_msgSend(ns_window, sel, 0); // 0 = NSWindowSharingNone
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, set SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
        if let Ok(hwnd) = window.hwnd() {
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
