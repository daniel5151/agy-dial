//! Console attachment utilities for running as a Windows GUI subsystem
//! application.

use std::fs::OpenOptions;
use std::os::windows::io::IntoRawHandle;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::ATTACH_PARENT_PROCESS;
use windows::Win32::System::Console::AttachConsole;
use windows::Win32::System::Console::GetStdHandle;
use windows::Win32::System::Console::STD_ERROR_HANDLE;
use windows::Win32::System::Console::STD_OUTPUT_HANDLE;
use windows::Win32::System::Console::SetStdHandle;

/// Attempts to attach to the parent terminal console if one exists.
pub fn init() -> bool {
    // SAFETY: Checking whether stdout is already attached.
    let existing_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let has_existing_stdout = match existing_stdout {
        Ok(h) => !h.is_invalid() && !h.0.is_null(),
        Err(_) => false,
    };

    if has_existing_stdout {
        return true;
    }

    // SAFETY: Attaching to the parent console if invoked from CLI.
    let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) }.is_ok();
    if attached {
        redirect_stdio();
    }
    attached
}

/// Redirects standard handles to the console device.
pub fn redirect_stdio() {
    if let Ok(file) = OpenOptions::new().write(true).open("CONOUT$") {
        let raw = file.into_raw_handle();
        // SAFETY: Redirecting stdout and stderr handles to CONOUT$.
        unsafe {
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, HANDLE(raw));
            let _ = SetStdHandle(STD_ERROR_HANDLE, HANDLE(raw));
        }
    }
}
