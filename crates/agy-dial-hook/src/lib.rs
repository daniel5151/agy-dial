//! Injected DLL for `agy.exe` that hooks `ReadConsoleInputW` and installs a
//! pure x64 tail-call detour on `SetCycleMode` -> `SetSelectedModel`.

use agy_dial_proto::HostMessage;
use agy_dial_proto::pipe_name;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::LibraryLoader::FreeLibraryAndExitThread;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::SystemServices::DLL_PROCESS_DETACH;
use windows::Win32::System::Threading::CreateThread;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::System::Threading::THREAD_CREATION_FLAGS;
use windows::core::BOOL;

mod cave;
mod input_hook;

static MODULE_HANDLE: AtomicUsize = AtomicUsize::new(0);

/// Standard Windows DLL entry point.
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            MODULE_HANDLE.store(module.0 as usize, Ordering::Release);
            // SAFETY: Disabling thread attach/detach notifications for this
            // module.
            unsafe {
                let _ = DisableThreadLibraryCalls(module);
                let _ = CreateThread(
                    None,
                    0,
                    Some(worker_thread),
                    None,
                    THREAD_CREATION_FLAGS(0),
                    None,
                );
            }
        }
        DLL_PROCESS_DETACH => {
            input_hook::uninstall();
            cave::uninstall();
        }
        _ => {}
    }
    BOOL(1)
}

unsafe extern "system" fn worker_thread(_param: *mut c_void) -> u32 {
    run_ipc_loop();

    input_hook::uninstall();
    cave::uninstall();

    // Give any in-flight ReadConsoleInputW call a brief moment to finish before
    // unloading.
    std::thread::sleep(Duration::from_millis(50));

    let hmod = HMODULE(MODULE_HANDLE.load(Ordering::Acquire) as *mut c_void);
    if !hmod.is_invalid() {
        // SAFETY: Unloading this DLL cleanly and terminating this worker
        // thread.
        unsafe {
            FreeLibraryAndExitThread(hmod, 0);
        }
    }
    0
}

fn run_ipc_loop() {
    // SAFETY: Querying the PID of the host `agy.exe` process.
    let pid = unsafe { GetCurrentProcessId() };
    let path = pipe_name(pid);

    // Retry briefly while the host creates the named pipe server.
    let mut pipe_file = None;
    for _ in 0..50 {
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) {
            pipe_file = Some(file);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let Some(file) = pipe_file else {
        return;
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            break;
        };
        let Ok(msg) = serde_json::from_str::<HostMessage>(&line) else {
            continue;
        };
        match msg {
            HostMessage::Install {
                set_cycle_mode_rva,
                set_selected_model_rva,
                families,
                initial_model,
            } => {
                input_hook::set_families(families, Some(&initial_model));
                if cave::install(set_cycle_mode_rva, set_selected_model_rva).is_ok() {
                    let _ = input_hook::install();
                }
            }
            HostMessage::UpdateFamilies { families } => {
                input_hook::set_families(families, None);
            }
            HostMessage::Uninstall => {
                break;
            }
        }
    }
}
