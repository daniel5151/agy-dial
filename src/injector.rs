//! Process watcher, DLL injector (`LoadLibraryW`), and per-PID named pipe IPC
//! for driving `agy_dial_hook.dll` inside running `agy.exe` instances.

use agy_dial_proto::HostMessage;
use agy_dial_proto::ModelFamily;
use agy_dial_proto::pipe_name;
use anyhow::Context;
use anyhow::bail;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::ERROR_PIPE_CONNECTED;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows::Win32::System::Diagnostics::ToolHelp::Process32FirstW;
use windows::Win32::System::Diagnostics::ToolHelp::Process32NextW;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RELEASE;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Memory::VirtualAllocEx;
use windows::Win32::System::Memory::VirtualFreeEx;
use windows::Win32::System::Pipes::ConnectNamedPipe;
use windows::Win32::System::Pipes::CreateNamedPipeW;
use windows::Win32::System::Pipes::PIPE_READMODE_BYTE;
use windows::Win32::System::Pipes::PIPE_TYPE_BYTE;
use windows::Win32::System::Pipes::PIPE_WAIT;
use windows::Win32::System::Threading::CreateRemoteThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::PROCESS_CREATE_THREAD;
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
use windows::Win32::System::Threading::PROCESS_VM_OPERATION;
use windows::Win32::System::Threading::PROCESS_VM_READ;
use windows::Win32::System::Threading::PROCESS_VM_WRITE;
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::core::PCWSTR;
use windows::core::s;
use windows::core::w;

use crate::config::Config;
use crate::gosym::ResolvedSymbols;
use crate::models;
use crate::wsl_bridge::WslClients;

const TARGET_EXE_NAME: &str = "agy.exe";
const HOOK_DLL_NAME: &str = "agy_dial_hook.dll";

/// Shared catalog of discovered model families and user-toggled enabled state.
pub struct ModelCatalog {
    /// All model families returned by `agy models` (excluding `Orchestrator`).
    pub all_families: Vec<ModelFamily>,
    /// Persistent enable/disable preferences.
    pub config: Config,
}

impl ModelCatalog {
    /// Returns only the model families currently enabled by the user.
    pub fn enabled_families(&self) -> Vec<ModelFamily> {
        self.config.filter_families(&self.all_families)
    }
}

/// Locates `agy_dial_hook.dll` next to the running `agy-dial.exe`.
pub fn find_hook_dll() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("Failed to locate current executable")?;
    let dir = exe
        .parent()
        .context("Executable path has no parent directory")?;
    let candidate = dir.join(HOOK_DLL_NAME);
    if candidate.is_file() {
        return Ok(candidate);
    }
    bail!(
        "Could not find '{}' next to '{}'. Build the workspace with `cargo build --workspace`.",
        HOOK_DLL_NAME,
        exe.display()
    )
}

/// Enumerates PIDs of all currently running `agy.exe` processes.
pub fn enumerate_agy_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    // SAFETY: Taking a snapshot of all processes via ToolHelp32.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return pids;
    };
    if snapshot == INVALID_HANDLE_VALUE {
        return pids;
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: Iterating `PROCESSENTRY32W` entries in the ToolHelp snapshot.
    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let nul = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..nul]);
                if name.eq_ignore_ascii_case(TARGET_EXE_NAME) {
                    pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    pids
}

struct AttachedInstance {
    pipe: HANDLE,
}

impl AttachedInstance {
    fn send(&self, msg: &HostMessage) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        let bytes = line.as_bytes();
        let mut written = 0u32;
        // SAFETY: Writing a serialized JSON message line to the open named pipe
        // handle.
        unsafe {
            WriteFile(self.pipe, Some(bytes), Some(&mut written), None)
                .context("WriteFile to hook pipe failed")?;
        }
        Ok(())
    }
}

impl Drop for AttachedInstance {
    fn drop(&mut self) {
        if !self.pipe.is_invalid() && !self.pipe.0.is_null() {
            // SAFETY: Closing the per-PID named pipe handle on detach/drop.
            unsafe {
                let _ = CloseHandle(self.pipe);
            }
        }
    }
}

fn inject_dll(pid: u32, dll_path: &Path) -> anyhow::Result<()> {
    let wide_path: Vec<u16> = OsStr::new(dll_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let byte_len = wide_path.len() * size_of::<u16>();

    let access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;

    // SAFETY: Opening target `agy.exe` process owned by the current user.
    let process = unsafe { OpenProcess(access, false, pid) }
        .with_context(|| format!("OpenProcess({pid}) failed"))?;

    let result = (|| -> anyhow::Result<()> {
        // SAFETY: Allocating memory inside the target process for the DLL path.
        let remote_mem = unsafe {
            VirtualAllocEx(
                process,
                None,
                byte_len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_mem.is_null() {
            bail!("VirtualAllocEx({pid}) returned null");
        }

        let write_and_load = (|| -> anyhow::Result<()> {
            // SAFETY: Writing the UTF-16 DLL path into the allocated remote
            // buffer.
            unsafe {
                WriteProcessMemory(
                    process,
                    remote_mem,
                    wide_path.as_ptr().cast(),
                    byte_len,
                    None,
                )
                .context("WriteProcessMemory failed")?;
            }

            // SAFETY: Resolving `LoadLibraryW` from `kernel32.dll` (shared base
            // across processes).
            let load_library = unsafe {
                let k32 = GetModuleHandleW(w!("kernel32.dll"))?;
                GetProcAddress(k32, s!("LoadLibraryW"))
                    .context("GetProcAddress(LoadLibraryW) failed")?
            };

            // SAFETY: Converting `LoadLibraryW` function pointer for
            // `CreateRemoteThread`.
            let start_routine: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
                unsafe { std::mem::transmute(load_library) };

            // SAFETY: Spawning a remote thread calling
            // `LoadLibraryW(remote_mem)` in `agy.exe`.
            let thread = unsafe {
                CreateRemoteThread(
                    process,
                    None,
                    0,
                    Some(start_routine),
                    Some(remote_mem),
                    0,
                    None,
                )
                .context("CreateRemoteThread(LoadLibraryW) failed")?
            };

            // SAFETY: Waiting up to 5s for `LoadLibraryW` to finish, then
            // closing the thread handle.
            unsafe {
                let _ = WaitForSingleObject(thread, 5_000);
                let _ = CloseHandle(thread);
            }
            Ok(())
        })();

        // SAFETY: Freeing the temporary remote path buffer.
        unsafe {
            let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        }
        write_and_load
    })();

    // SAFETY: Closing target process handle.
    unsafe {
        let _ = CloseHandle(process);
    }

    result
}

fn attach_pid(
    pid: u32,
    dll_path: &Path,
    symbols: ResolvedSymbols,
    families: &[ModelFamily],
    initial_model: &str,
) -> anyhow::Result<AttachedInstance> {
    let pipe_path = pipe_name(pid);
    let wide_pipe: Vec<u16> = OsStr::new(&pipe_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: Creating a per-PID named pipe server before injecting the DLL.
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide_pipe.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            16 * 1024,
            16 * 1024,
            0,
            None,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        bail!("CreateNamedPipeW('{pipe_path}') failed");
    }

    if let Err(e) = inject_dll(pid, dll_path) {
        // SAFETY: Closing pipe handle on injection failure.
        unsafe {
            let _ = CloseHandle(pipe);
        }
        return Err(e);
    }

    // SAFETY: Waiting for the injected DLL's worker thread to connect to our
    // named pipe.
    let connect_res = unsafe { ConnectNamedPipe(pipe, None) };
    if let Err(e) = connect_res {
        if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
            // SAFETY: Closing pipe handle on connection failure.
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return Err(e).context("ConnectNamedPipe failed");
        }
    }

    let instance = AttachedInstance { pipe };
    instance.send(&HostMessage::Install {
        set_cycle_mode_rva: symbols.set_cycle_mode_rva,
        set_selected_model_rva: symbols.set_selected_model_rva,
        families: families.to_vec(),
        initial_model: initial_model.to_owned(),
    })?;

    Ok(instance)
}

/// Runs the background process-watching and DLL-injection loop.
pub fn run_watcher_loop<F>(
    agy_exe: PathBuf,
    dll_path: PathBuf,
    symbols: ResolvedSymbols,
    catalog: Arc<Mutex<ModelCatalog>>,
    wsl_clients: Arc<Mutex<WslClients>>,
    ignored_pids: HashSet<u32>,
    running: Arc<AtomicBool>,
    refresh_requested: Arc<AtomicBool>,
    families_dirty: Arc<AtomicBool>,
    win_attached_count: Arc<AtomicUsize>,
    wsl_attached_count: Arc<AtomicUsize>,
    on_status_change: F,
) where
    F: Fn(),
{
    let mut attached: HashMap<u32, AttachedInstance> = HashMap::new();
    let mut failed_pids: HashSet<u32> = HashSet::new();
    let mut last_reported_count = usize::MAX;

    while running.load(Ordering::Relaxed) {
        let live_pids: HashSet<u32> = enumerate_agy_pids().into_iter().collect();

        // Prune exited Windows processes.
        attached.retain(|pid, _| {
            let alive = live_pids.contains(pid);
            if !alive {
                log::info!("[{pid}] agy.exe exited; cleaned up.");
            }
            alive
        });
        failed_pids.retain(|pid| live_pids.contains(pid));

        // Prune disconnected WSL2 bridge clients (non-blocking PeekNamedPipe).
        if let Ok(mut reg) = wsl_clients.lock() {
            let remaining_wsl = reg.prune_disconnected();
            let prev_wsl = wsl_attached_count.swap(remaining_wsl, Ordering::Relaxed);
            if prev_wsl != remaining_wsl {
                on_status_change();
            }
        }

        // Handle manual "Refresh Models" trigger from tray menu.
        if refresh_requested.swap(false, Ordering::AcqRel) {
            log::info!("Refreshing available models via `agy models`...");
            match models::fetch_model_families(&agy_exe) {
                Ok(new_all) => {
                    log::info!("Loaded {} model families.", new_all.len());
                    if let Ok(mut cat) = catalog.lock() {
                        cat.all_families = new_all;
                    }
                    families_dirty.store(true, Ordering::Release);
                }
                Err(e) => log::error!("Failed to refresh models: {e:#}"),
            }
        }

        // Push updated enabled model list to all Windows and WSL2 instances if
        // toggled or refreshed.
        if families_dirty.swap(false, Ordering::AcqRel) {
            let enabled = catalog
                .lock()
                .map(|cat| cat.enabled_families())
                .unwrap_or_default();
            let msg = HostMessage::UpdateFamilies { families: enabled };
            attached.retain(|pid, inst| {
                if let Err(e) = inst.send(&msg) {
                    log::warn!("[{pid}] Pipe write failed during family update: {e}");
                    false
                } else {
                    true
                }
            });
            let remaining_wsl = wsl_clients
                .lock()
                .map(|mut reg| reg.broadcast(&msg))
                .unwrap_or(0);
            let prev_wsl = wsl_attached_count.swap(remaining_wsl, Ordering::Relaxed);
            log::info!(
                "Broadcasted enabled model families to {} Windows + {} WSL instance(s).",
                attached.len(),
                remaining_wsl
            );
            if prev_wsl != remaining_wsl {
                on_status_change();
            }
        }

        // Attach to newly discovered agy.exe instances.
        let mut enabled_cache: Option<Vec<ModelFamily>> = None;
        for &pid in &live_pids {
            if ignored_pids.contains(&pid)
                || attached.contains_key(&pid)
                || failed_pids.contains(&pid)
            {
                continue;
            }
            let enabled = enabled_cache.get_or_insert_with(|| {
                catalog
                    .lock()
                    .map(|cat| cat.enabled_families())
                    .unwrap_or_default()
            });
            let initial_model = models::read_current_model();
            log::info!("[{pid}] Attaching to agy.exe...");
            match attach_pid(pid, &dll_path, symbols, enabled, &initial_model) {
                Ok(inst) => {
                    log::info!("[{pid}] Surface Dial hook active (initial: '{initial_model}').");
                    attached.insert(pid, inst);
                }
                Err(e) => {
                    log::warn!("[{pid}] Failed to attach: {e:#}");
                    failed_pids.insert(pid);
                }
            }
        }

        let count = attached.len();
        if count != last_reported_count {
            last_reported_count = count;
            win_attached_count.store(count, Ordering::Relaxed);
            on_status_change();
        }

        std::thread::sleep(Duration::from_millis(750));
    }

    // Cleanly instruct all hooked instances to unpatch and unload.
    log::info!(
        "Unpatching {} attached agy.exe instance(s)...",
        attached.len()
    );
    for (pid, inst) in attached.drain() {
        if let Err(e) = inst.send(&HostMessage::Uninstall) {
            log::warn!("[{pid}] Failed to send Uninstall: {e}");
        }
        drop(inst);
    }
    win_attached_count.store(0, Ordering::Relaxed);
}
