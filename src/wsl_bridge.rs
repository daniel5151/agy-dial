//! Windows-side named pipe control server and `--wsl-bridge` stdio forwarder
//! for unifying WSL2 `agy-dial-wsl` sessions with the Windows tray app.

use agy_dial_proto::CONTROL_PIPE_NAME;
use agy_dial_proto::HostMessage;
use anyhow::Context;
use std::ffi::OsStr;
use std::io::Read;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
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
use windows::Win32::Storage::FileSystem::CreateFileW;
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_NONE;
use windows::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::Storage::FileSystem::WriteFile;
use windows::Win32::System::Pipes::ConnectNamedPipe;
use windows::Win32::System::Pipes::CreateNamedPipeW;
use windows::Win32::System::Pipes::PIPE_READMODE_BYTE;
use windows::Win32::System::Pipes::PIPE_TYPE_BYTE;
use windows::Win32::System::Pipes::PIPE_UNLIMITED_INSTANCES;
use windows::Win32::System::Pipes::PIPE_WAIT;
use windows::Win32::System::Pipes::PeekNamedPipe;
use windows::core::PCWSTR;

use crate::injector::ModelCatalog;

struct WslClient {
    id: u64,
    pipe: HANDLE,
}

// SAFETY: Win32 pipe `HANDLE` is synchronized by `WslClients` mutex.
unsafe impl Send for WslClient {}

/// Thread-safe registry of connected WSL2 bridge clients.
pub struct WslClients {
    next_id: u64,
    clients: Vec<WslClient>,
}

impl WslClients {
    /// Creates an empty client registry.
    pub fn new() -> Self {
        Self {
            next_id: 1,
            clients: Vec::new(),
        }
    }

    fn insert(&mut self, pipe: HANDLE) -> (u64, usize) {
        let id = self.next_id;
        self.next_id += 1;
        self.clients.push(WslClient { id, pipe });
        (id, self.clients.len())
    }

    /// Non-blockingly prunes any disconnected WSL2 bridge clients via
    /// `PeekNamedPipe`. Returns the remaining live client count.
    pub fn prune_disconnected(&mut self) -> usize {
        self.clients.retain(|c| {
            // SAFETY: Non-blocking liveness probe on the open named pipe
            // handle.
            let alive = unsafe { PeekNamedPipe(c.pipe, None, 0, None, None, None) }.is_ok();
            if !alive {
                log::info!("[wsl#{}] Disconnected.", c.id);
                // SAFETY: Closing broken client pipe handle.
                unsafe {
                    let _ = CloseHandle(c.pipe);
                }
            }
            alive
        });
        self.clients.len()
    }

    /// Broadcasts a `HostMessage` line to all connected WSL2 bridge clients.
    pub fn broadcast(&mut self, msg: &HostMessage) -> usize {
        let Ok(mut line) = serde_json::to_string(msg) else {
            return self.clients.len();
        };
        line.push('\n');
        let bytes = line.as_bytes();

        self.clients.retain(|c| {
            let mut written = 0u32;
            // SAFETY: Writing a serialized JSON line to an open client pipe
            // handle.
            let ok = unsafe { WriteFile(c.pipe, Some(bytes), Some(&mut written), None) }.is_ok();
            if !ok {
                log::info!("[wsl#{}] Disconnected during broadcast.", c.id);
                // SAFETY: Closing broken client pipe handle.
                unsafe {
                    let _ = CloseHandle(c.pipe);
                }
            }
            ok
        });
        self.clients.len()
    }

    /// Closes all connected client pipes (called on host shutdown).
    pub fn close_all(&mut self) {
        for client in self.clients.drain(..) {
            // SAFETY: Closing client pipe handle on shutdown.
            unsafe {
                let _ = CloseHandle(client.pipe);
            }
        }
    }
}

fn send_line(pipe: HANDLE, msg: &HostMessage) -> bool {
    let Ok(mut line) = serde_json::to_string(msg) else {
        return false;
    };
    line.push('\n');
    let mut written = 0u32;
    // SAFETY: Writing a JSON line to an open pipe handle.
    unsafe { WriteFile(pipe, Some(line.as_bytes()), Some(&mut written), None) }.is_ok()
}

/// Runs the `\\.\pipe\agy-dial-control` listener loop accepting WSL2 bridge
/// connections.
pub fn run_control_server<F>(
    catalog: Arc<Mutex<ModelCatalog>>,
    clients: Arc<Mutex<WslClients>>,
    wsl_count: Arc<AtomicUsize>,
    running: Arc<AtomicBool>,
    on_status_change: F,
) where
    F: Fn() + Send + Sync + 'static,
{
    let wide_pipe: Vec<u16> = OsStr::new(CONTROL_PIPE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    while running.load(Ordering::Relaxed) {
        // SAFETY: Creating a new multi-instance named pipe server handle for
        // WSL2 clients.
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR::from_raw(wide_pipe.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0),
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                16 * 1024,
                16 * 1024,
                0,
                None,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        // SAFETY: Waiting for the next `--wsl-bridge` process to connect.
        let connect_res = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(e) = connect_res {
            if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                // SAFETY: Closing failed pipe instance.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        }

        if !running.load(Ordering::Relaxed) {
            // SAFETY: Closing pipe instance during shutdown.
            unsafe {
                let _ = CloseHandle(pipe);
            }
            break;
        }

        // Send initial enabled families list immediately upon connect.
        let enabled = catalog
            .lock()
            .map(|cat| cat.enabled_families())
            .unwrap_or_default();
        if !send_line(pipe, &HostMessage::UpdateFamilies { families: enabled }) {
            // SAFETY: Closing pipe handle if initial handshake write failed.
            unsafe {
                let _ = CloseHandle(pipe);
            }
            continue;
        }

        let (id, new_count) = match clients.lock() {
            Ok(mut reg) => reg.insert(pipe),
            Err(_) => {
                // SAFETY: Closing pipe handle on poisoned mutex.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        };
        log::info!("[wsl#{id}] Connected via control pipe (total WSL: {new_count}).");
        wsl_count.store(new_count, Ordering::Relaxed);
        on_status_change();
    }

    if let Ok(mut reg) = clients.lock() {
        reg.close_all();
    }
    wsl_count.store(0, Ordering::Relaxed);
}

/// Wakes up a blocked `ConnectNamedPipe` call during clean shutdown by opening
/// and immediately closing a dummy client connection to `CONTROL_PIPE_NAME`.
pub fn wake_control_server() {
    let wide_pipe: Vec<u16> = OsStr::new(CONTROL_PIPE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: Opening and immediately closing the control pipe to unblock
    // `ConnectNamedPipe`.
    unsafe {
        if let Ok(h) = CreateFileW(
            PCWSTR::from_raw(wide_pipe.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            let _ = CloseHandle(h);
        }
    }
}

/// Runs `agy-dial.exe --wsl-bridge`: connects to the running Windows tray app's
/// `\\.\pipe\agy-dial-control` pipe and relays messages over stdin/stdout for
/// WSL2.
pub fn run_bridge_client() -> anyhow::Result<()> {
    let wide_pipe: Vec<u16> = OsStr::new(CONTROL_PIPE_NAME)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: Connecting to the Windows tray host's control named pipe.
    let pipe = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide_pipe.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .context("Could not connect to agy-dial control pipe (is agy-dial.exe running?)")?;

    // Watch stdin EOF so when the WSL2 parent exits we terminate immediately.
    // Do NOT call CloseHandle(pipe) here: closing a synchronous pipe handle
    // while another thread is inside ReadFile(pipe) deadlocks; exit(0) lets
    // the OS close it.
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 256];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        std::process::exit(0);
    });

    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 4096];
    loop {
        let mut read = 0u32;
        // SAFETY: Reading `HostMessage` JSON lines from the Windows control
        // pipe.
        let res = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut read), None) };
        if res.is_err() || read == 0 {
            break;
        }
        if stdout.write_all(&buf[..read as usize]).is_err() || stdout.flush().is_err() {
            break;
        }
    }

    // SAFETY: Closing pipe handle before exiting bridge process.
    unsafe {
        let _ = CloseHandle(pipe);
    }
    Ok(())
}
