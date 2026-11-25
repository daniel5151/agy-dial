//! Windows registry auto-start (run on boot) configuration.

use std::env::current_exe;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::HKEY;
use windows::Win32::System::Registry::HKEY_CURRENT_USER;
use windows::Win32::System::Registry::KEY_READ;
use windows::Win32::System::Registry::KEY_WRITE;
use windows::Win32::System::Registry::REG_SZ;
use windows::Win32::System::Registry::RegCloseKey;
use windows::Win32::System::Registry::RegDeleteValueW;
use windows::Win32::System::Registry::RegOpenKeyExW;
use windows::Win32::System::Registry::RegQueryValueExW;
use windows::Win32::System::Registry::RegSetValueExW;
use windows::core::PCWSTR;
use windows::core::w;

const RUN_KEY_PATH: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const APP_REG_NAME: PCWSTR = w!("AgyDial");

/// Checks whether the run-on-boot registry entry exists for `agy-dial`.
pub fn is_autostart_enabled() -> bool {
    let mut hkey = HKEY::default();
    // SAFETY: Opening HKCU Run subkey with read-only access.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            Some(0),
            KEY_READ,
            &mut hkey,
        )
    };
    if status != ERROR_SUCCESS {
        return false;
    }

    // SAFETY: Checking existence of the value name.
    let status = unsafe { RegQueryValueExW(hkey, APP_REG_NAME, None, None, None, None) };

    // SAFETY: Closing open registry key handle.
    unsafe {
        let _ = RegCloseKey(hkey);
    }

    status == ERROR_SUCCESS
}

/// Enables or disables the run-on-boot registry entry for `agy-dial`.
pub fn set_autostart_enabled(enabled: bool) -> anyhow::Result<()> {
    let mut hkey = HKEY::default();
    // SAFETY: Opening HKCU Run subkey with write access.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            Some(0),
            KEY_WRITE,
            &mut hkey,
        )
    };
    if status != ERROR_SUCCESS {
        anyhow::bail!("Failed to open Run registry key: error code {status:?}");
    }

    let result = if enabled {
        let exe_path = current_exe()?;
        let path_str = format!("\"{}\"", exe_path.display());
        let wide: Vec<u16> = OsStr::new(&path_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: Converting wide slice to byte slice for RegSetValueExW.
        let byte_slice = unsafe {
            std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len() * size_of::<u16>())
        };
        // SAFETY: Setting quoted executable path in the Run key.
        unsafe { RegSetValueExW(hkey, APP_REG_NAME, Some(0), REG_SZ, Some(byte_slice)) }
    } else {
        // SAFETY: Removing the value from the Run key.
        unsafe { RegDeleteValueW(hkey, APP_REG_NAME) }
    };

    // SAFETY: Closing registry key handle.
    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if result != ERROR_SUCCESS && (!enabled && result != ERROR_FILE_NOT_FOUND) {
        anyhow::bail!("Failed to modify Run registry value: error code {result:?}");
    }

    Ok(())
}
