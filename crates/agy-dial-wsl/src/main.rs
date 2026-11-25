//! WSL2 PTY + one-shot `ptrace` wrapper for Google Antigravity CLI (`agy`) that
//! integrates with the Windows `agy-dial.exe` tray control plane.

#[cfg(target_os = "linux")]
mod bridge;
#[cfg(target_os = "linux")]
mod elfsym;
#[cfg(target_os = "linux")]
mod ptrace_patch;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("agy-dial-wsl is only supported on Linux / WSL2.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux_main::run() {
        eprintln!("agy-dial-wsl error: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux_main {
    use anyhow::bail;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::Ordering;

    use crate::bridge;
    use crate::bridge::DialState;
    use crate::elfsym;
    use crate::ptrace_patch;

    const SHIFT_TAB_VT: &[u8] = b"\x1b[9;2u";

    static PTY_MASTER_FD: AtomicI32 = AtomicI32::new(-1);
    static WINCH_FLAG: AtomicBool = AtomicBool::new(false);

    extern "C" fn handle_sigwinch(_sig: libc::c_int) {
        WINCH_FLAG.store(true, Ordering::Release);
    }

    fn sync_pty_winsize() {
        let master = PTY_MASTER_FD.load(Ordering::Acquire);
        if master < 0 {
            return;
        }
        let mut ws: libc::winsize =
            // SAFETY: `winsize` is a plain C integer struct.
            unsafe { std::mem::zeroed() };
        // SAFETY: Querying parent terminal dimensions and forwarding them to
        // the PTY.
        unsafe {
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
                let _ = libc::ioctl(master, libc::TIOCSWINSZ, &ws);
            }
        }
    }

    struct RawModeGuard {
        orig: libc::termios,
        active: bool,
    }

    impl RawModeGuard {
        fn enter() -> Self {
            let mut orig: libc::termios =
                // SAFETY: `termios` is a plain C struct.
                unsafe { std::mem::zeroed() };
            // SAFETY: Saving stdin termios and switching stdin to raw mode.
            let active = unsafe {
                if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0 {
                    let mut raw = orig;
                    libc::cfmakeraw(&mut raw);
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) == 0
                } else {
                    false
                }
            };
            Self { orig, active }
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            if self.active {
                // SAFETY: Restoring original stdin termios on exit.
                unsafe {
                    let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
                }
            }
        }
    }

    fn find_real_agy() -> anyhow::Result<PathBuf> {
        if let Ok(env_bin) = std::env::var("AGY_REAL_BIN") {
            let p = PathBuf::from(env_bin);
            if p.is_file() {
                return Ok(p);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".local").join("bin").join("agy");
            if p.is_file() {
                return Ok(p);
            }
        }
        let self_canon = std::env::current_exe()
            .ok()
            .and_then(|p| fs::canonicalize(p).ok());
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("agy");
                if candidate.is_file() {
                    let cand_canon = fs::canonicalize(&candidate).ok();
                    if cand_canon != self_canon {
                        return Ok(candidate);
                    }
                }
            }
        }
        bail!(
            "Could not locate real Linux `agy` binary (set AGY_REAL_BIN or install to ~/.local/bin/agy)"
        )
    }

    fn should_bypass_wrapper(args: &[String]) -> bool {
        // SAFETY: Checking if stdin and stdout are interactive TTYs.
        let is_tty = unsafe {
            libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1
        };
        if !is_tty {
            return true;
        }

        const NON_TUI_SUBCMDS: &[&str] = &[
            "models",
            "acp",
            "plugin",
            "agents",
            "update",
            "login",
            "logout",
            "version",
            "help",
            "--help",
            "-h",
            "--version",
            "-v",
        ];
        if let Some(first) = args.first() {
            if NON_TUI_SUBCMDS.contains(&first.as_str()) {
                return true;
            }
        }
        args.iter()
            .any(|a| matches!(a.as_str(), "-p" | "--print" | "--prompt"))
    }

    fn exec_passthrough(real_agy: &Path, args: &[String]) -> anyhow::Result<()> {
        let c_prog = CString::new(real_agy.as_os_str().as_bytes())?;
        let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        c_args.push(c_prog.clone());
        for arg in args {
            c_args.push(CString::new(arg.as_str())?);
        }
        let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        // SAFETY: Replacing current process image with `real_agy` for non-TUI
        // invocations.
        unsafe {
            libc::execv(c_prog.as_ptr(), argv.as_ptr());
        }
        bail!(
            "execv('{}') failed: {}",
            real_agy.display(),
            std::io::Error::last_os_error()
        )
    }

    /// Scans `buf` for a Kitty CSI-u sequence `\x1b[(91|92|93);<mod>u` with
    /// Ctrl+Alt. Returns `Some((start, end, key_code))` on match.
    fn find_dial_csi_u(buf: &[u8]) -> Option<(usize, usize, u32)> {
        let mut i = 0;
        while i + 5 < buf.len() {
            if buf[i] == 0x1b && buf[i + 1] == b'[' {
                let tail = &buf[i + 2..];
                if let Some(u_rel) = tail.iter().position(|&b| b == b'u') {
                    if let Ok(body) = std::str::from_utf8(&tail[..u_rel]) {
                        if let Some((code_str, mod_part)) = body.split_once(';') {
                            let mod_str = mod_part.split(':').next().unwrap_or(mod_part);
                            if let (Ok(code), Ok(mod_val)) =
                                (code_str.parse::<u32>(), mod_str.parse::<u32>())
                            {
                                let mod_bits = mod_val.saturating_sub(1);
                                if matches!(code, 91..=93) && (mod_bits & 6) == 6 {
                                    return Some((i, i + 2 + u_rel + 1, code));
                                }
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        None
    }

    fn write_all_fd(fd: RawFd, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            // SAFETY: Writing raw bytes to a valid open file descriptor.
            let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            data = &data[n as usize..];
        }
        true
    }

    pub fn run() -> anyhow::Result<()> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let real_agy = find_real_agy()?;

        if should_bypass_wrapper(&args) {
            return exec_passthrough(&real_agy, &args);
        }

        let symbols = match elfsym::resolve_linux_agy_symbols(&real_agy) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("agy-dial-wsl: symbol lookup failed ({e:#}); running agy directly.");
                return exec_passthrough(&real_agy, &args);
            }
        };

        let dial_state = Arc::new(Mutex::new(DialState::new()));
        let initial_model = bridge::read_initial_model();

        // Seed local model list in the background as a standalone fallback; if
        // Windows `agy-dial.exe` is running, the bridge immediately
        // pushes the tray-filtered list.
        let running = Arc::new(AtomicBool::new(true));
        {
            let state_bg = dial_state.clone();
            let real_bg = real_agy.clone();
            let init_model = initial_model.clone();
            std::thread::spawn(move || {
                let fams = bridge::fetch_local_families(&real_bg);
                if !fams.is_empty() {
                    if let Ok(mut st) = state_bg.lock() {
                        if st.is_empty() {
                            st.set_families(fams, Some(&init_model));
                        }
                    }
                }
            });
        }

        let _bridge_thread =
            bridge::spawn_windows_bridge(dial_state.clone(), initial_model, running.clone());

        let child = match ptrace_patch::spawn_and_patch(&real_agy, &args, symbols) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("agy-dial-wsl: ptrace patch failed ({e:#}); running agy directly.");
                running.store(false, Ordering::Relaxed);
                return exec_passthrough(&real_agy, &args);
            }
        };

        PTY_MASTER_FD.store(child.pty_master, Ordering::Release);
        // SAFETY: Installing SIGWINCH handler to mirror terminal resizes to the
        // child PTY.
        unsafe {
            libc::signal(libc::SIGWINCH, handle_sigwinch as *const () as usize);
        }

        let _raw_guard = RawModeGuard::enter();
        let mut read_buf = [0u8; 4096];

        loop {
            if WINCH_FLAG.swap(false, Ordering::AcqRel) {
                sync_pty_winsize();
            }

            let mut fds = [
                libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: child.pty_master,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            // SAFETY: Polling stdin and the child PTY master fd.
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
            if ready < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }

            if (fds[1].revents & libc::POLLIN) != 0 {
                // SAFETY: Reading output bytes from child PTY master.
                let n = unsafe {
                    libc::read(
                        child.pty_master,
                        read_buf.as_mut_ptr().cast(),
                        read_buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                let _ = write_all_fd(libc::STDOUT_FILENO, &read_buf[..n as usize]);
            }

            if (fds[0].revents & libc::POLLIN) != 0 {
                // SAFETY: Reading input bytes from parent stdin.
                let n = unsafe {
                    libc::read(
                        libc::STDIN_FILENO,
                        read_buf.as_mut_ptr().cast(),
                        read_buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                let slice = &read_buf[..n as usize];
                if let Some((start, end, key_code)) = find_dial_csi_u(slice) {
                    if start > 0 {
                        let _ = write_all_fd(child.pty_master, &slice[..start]);
                    }
                    let next_label = if let Ok(mut st) = dial_state.lock() {
                        match key_code {
                            91 => st.step_down(),
                            93 => st.step_up(),
                            92 => st.cycle_family(),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    if let Some(label) = next_label {
                        if ptrace_patch::queue_model_vm(child.pid, child.data_mem, &label) {
                            let _ = write_all_fd(child.pty_master, SHIFT_TAB_VT);
                        }
                    }
                    if end < slice.len() {
                        let _ = write_all_fd(child.pty_master, &slice[end..]);
                    }
                } else {
                    let _ = write_all_fd(child.pty_master, slice);
                }
            }

            if (fds[1].revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                break;
            }
        }

        running.store(false, Ordering::Relaxed);
        drop(_raw_guard);

        // SAFETY: Closing PTY master fd and reaping the child process.
        unsafe {
            libc::close(child.pty_master);
        }
        let mut status: libc::c_int = 0;
        // SAFETY: Reaping child process exit status.
        let _ = unsafe { libc::waitpid(child.pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            0
        };
        std::process::exit(exit_code);
    }
}
