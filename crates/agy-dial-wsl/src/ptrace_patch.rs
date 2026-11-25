//! One-shot `ptrace` startup cave installer and `process_vm_writev` model queue
//! for Linux x86_64 `agy`.

use anyhow::Context;
use anyhow::bail;
use std::ffi::CString;
use std::ffi::c_void;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::elfsym::ResolvedElfSymbols;

const MAX_LABEL_LEN: usize = 192;

/// Handle to a spawned, patched, and `ptrace`-detached `agy` child process.
pub struct PatchedChild {
    /// Child process ID.
    pub pid: libc::pid_t,
    /// Master PTY file descriptor bridged to the child's stdin/stdout/stderr.
    pub pty_master: RawFd,
    /// Remote address of the 4096-byte `data_mem` page inside the child.
    pub data_mem: u64,
}

fn ptrace_peek_u64(pid: libc::pid_t, addr: u64) -> anyhow::Result<u64> {
    // SAFETY: Clearing errno and invoking `PTRACE_PEEKTEXT` on a stopped traced
    // child.
    unsafe {
        *libc::__errno_location() = 0;
        let val = libc::ptrace(
            libc::PTRACE_PEEKTEXT,
            pid,
            addr as *mut c_void,
            std::ptr::null_mut::<c_void>(),
        );
        let err = *libc::__errno_location();
        if val == -1 && err != 0 {
            bail!(
                "PTRACE_PEEKTEXT(0x{addr:x}) failed: {}",
                std::io::Error::from_raw_os_error(err)
            );
        }
        Ok(val as u64)
    }
}

fn ptrace_poke_u64(pid: libc::pid_t, addr: u64, word: u64) -> anyhow::Result<()> {
    // SAFETY: Invoking `PTRACE_POKETEXT` on a stopped traced child.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_POKETEXT,
            pid,
            addr as *mut c_void,
            word as *mut c_void,
        )
    };
    if rc != 0 {
        bail!(
            "PTRACE_POKETEXT(0x{addr:x}) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn ptrace_write_bytes(pid: libc::pid_t, addr: u64, bytes: &[u8]) -> anyhow::Result<()> {
    let mut pos = 0usize;
    while pos < bytes.len() {
        let cur = addr + pos as u64;
        let aligned = cur & !7;
        let shift = (cur - aligned) as usize;
        let chunk_len = (8 - shift).min(bytes.len() - pos);

        let mut word_bytes = if chunk_len == 8 {
            [0u8; 8]
        } else {
            ptrace_peek_u64(pid, aligned)?.to_le_bytes()
        };
        word_bytes[shift..shift + chunk_len].copy_from_slice(&bytes[pos..pos + chunk_len]);
        ptrace_poke_u64(pid, aligned, u64::from_le_bytes(word_bytes))?;
        pos += chunk_len;
    }
    Ok(())
}

fn find_pie_base(pid: libc::pid_t, real_agy: &Path) -> anyhow::Result<u64> {
    let canonical = fs::canonicalize(real_agy).unwrap_or_else(|_| real_agy.to_path_buf());
    let target_str = canonical.to_string_lossy();
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("Failed to read /proc/{pid}/maps"))?;

    for line in maps.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        // First mapping of the executable with file offset 0 is the PIE base.
        if parts[2] == "00000000" && parts[5] == target_str.as_ref() {
            let start_hex = parts[0]
                .split('-')
                .next()
                .context("Malformed /proc/pid/maps range")?;
            return u64::from_str_radix(start_hex, 16)
                .context("Invalid hex address in /proc/pid/maps");
        }
    }

    bail!(
        "Could not find PIE base for '{}' in /proc/{pid}/maps",
        target_str
    )
}

fn remote_mmap_rwx(pid: libc::pid_t, len: u64) -> anyhow::Result<u64> {
    let mut orig_regs: libc::user_regs_struct =
        // SAFETY: `user_regs_struct` is a plain C integer struct.
        unsafe { std::mem::zeroed() };
    // SAFETY: Reading registers from the stopped traced child.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::from_mut(&mut orig_regs).cast::<c_void>(),
        )
    } != 0
    {
        bail!("PTRACE_GETREGS failed: {}", std::io::Error::last_os_error());
    }

    let rip = orig_regs.rip;
    let orig_word = ptrace_peek_u64(pid, rip)?;

    // Inject `0x0f 0x05` (`syscall`) at RIP while preserving the remaining 6
    // bytes.
    let mut patched = orig_word.to_le_bytes();
    patched[0] = 0x0f;
    patched[1] = 0x05;
    ptrace_poke_u64(pid, rip, u64::from_le_bytes(patched))?;

    let mut call_regs = orig_regs;
    call_regs.rax = libc::SYS_mmap as u64;
    call_regs.rdi = 0; // addr = NULL
    call_regs.rsi = len; // length = 8192
    call_regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    call_regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    call_regs.r8 = u64::MAX; // fd = -1
    call_regs.r9 = 0; // offset = 0

    // SAFETY: Setting syscall registers and single-stepping the injected
    // `syscall`.
    unsafe {
        if libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::from_ref(&call_regs).cast::<c_void>(),
        ) != 0
        {
            let _ = ptrace_poke_u64(pid, rip, orig_word);
            bail!(
                "PTRACE_SETREGS (mmap) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        if libc::ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        ) != 0
        {
            let _ = ptrace_poke_u64(pid, rip, orig_word);
            bail!(
                "PTRACE_SINGLESTEP failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let mut status: libc::c_int = 0;
    // SAFETY: Waiting for the single-step trap after `SYS_mmap`.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        bail!(
            "waitpid after SYS_mmap failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let mut out_regs: libc::user_regs_struct =
        // SAFETY: `user_regs_struct` is a plain C integer struct.
        unsafe { std::mem::zeroed() };
    // SAFETY: Reading `SYS_mmap` return value in `rax`, then restoring code and
    // registers.
    unsafe {
        let _ = libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::from_mut(&mut out_regs).cast::<c_void>(),
        );
        ptrace_poke_u64(pid, rip, orig_word)?;
        if libc::ptrace(
            libc::PTRACE_SETREGS,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::from_ref(&orig_regs).cast::<c_void>(),
        ) != 0
        {
            bail!(
                "PTRACE_SETREGS (restore) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let mapped = out_regs.rax;
    if mapped == 0 || mapped > 0xffff_ffff_ffff_f000 {
        bail!("Remote SYS_mmap failed with return value 0x{mapped:x}");
    }
    Ok(mapped)
}

/// Spawns `real_agy` inside a PTY, installs the 89-byte x64 tail-call cave at
/// startup via one-shot `ptrace`, and detaches so `agy` runs at full native
/// speed.
pub fn spawn_and_patch(
    real_agy: &Path,
    args: &[String],
    symbols: ResolvedElfSymbols,
) -> anyhow::Result<PatchedChild> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    let mut ws: libc::winsize =
        // SAFETY: `winsize` is a plain C integer struct.
        unsafe { std::mem::zeroed() };
    // SAFETY: Querying parent terminal window size to mirror into the child
    // PTY.
    let has_ws = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;

    // SAFETY: Allocating a new PTY master/slave pair.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            if has_ws {
                &mut ws
            } else {
                std::ptr::null_mut()
            },
        )
    } != 0
    {
        bail!("openpty failed: {}", std::io::Error::last_os_error());
    }

    let c_prog = CString::new(real_agy.as_os_str().as_bytes())?;
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(c_prog.clone());
    for arg in args {
        c_args.push(CString::new(arg.as_str())?);
    }
    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: Forking child process to exec `real_agy` attached to the PTY
    // slave.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // SAFETY: Closing PTY descriptors on fork failure.
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        bail!("fork failed: {}", std::io::Error::last_os_error());
    }

    if pid == 0 {
        // SAFETY: Child sets up controlling PTY, requests PTRACE_TRACEME, and
        // execs `real_agy`.
        unsafe {
            libc::close(master);
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            libc::dup2(slave, libc::STDIN_FILENO);
            libc::dup2(slave, libc::STDOUT_FILENO);
            libc::dup2(slave, libc::STDERR_FILENO);
            if slave > 2 {
                libc::close(slave);
            }
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            );
            libc::execv(c_prog.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }

    // Parent closes slave fd.
    // SAFETY: Closing child-side PTY slave descriptor in the parent.
    unsafe {
        libc::close(slave);
    }

    // Wait for initial `SIGTRAP` triggered by `execv`.
    let mut status: libc::c_int = 0;
    // SAFETY: Waiting for the traced child's post-exec stop.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        bail!(
            "waitpid (post-exec) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if !libc::WIFSTOPPED(status) {
        bail!("Child exited prematurely during exec (status={status})");
    }

    let install_result = (|| -> anyhow::Result<u64> {
        let pie_base = find_pie_base(pid, real_agy)?;
        let set_cycle_mode = pie_base + symbols.set_cycle_mode_va;
        let set_selected_model = pie_base + symbols.set_selected_model_va;

        let orig = symbols.original_prologue;
        let rel32 = i32::from_le_bytes([orig[14], orig[15], orig[16], orig[17]]);
        let resume_target = set_cycle_mode + 18;
        let morestack_target = (resume_target as i64 + rel32 as i64) as u64;

        let mem_base = remote_mmap_rwx(pid, 8192)?;
        let data_mem = mem_base;
        let cave_mem = mem_base + 4096;

        // Initialize data_mem header:
        // +0x00: pendingFlag = 0
        // +0x08: modelStrPtr = data_mem + 0x80
        // +0x10: modelStrLen = 0
        // +0x18: target SetSelectedModel
        // +0x30: captured *store.Manager
        let mut data_hdr = [0u8; 0x38];
        data_hdr[0x08..0x10].copy_from_slice(&(data_mem + 0x80).to_le_bytes());
        data_hdr[0x18..0x20].copy_from_slice(&set_selected_model.to_le_bytes());
        ptrace_write_bytes(pid, data_mem, &data_hdr)?;

        // Assemble exact 89-byte x64 tail-call cave (identical to Windows).
        let mut cave = Vec::with_capacity(0x59);
        cave.extend_from_slice(&[0x49, 0xbc]);
        cave.extend_from_slice(&data_mem.to_le_bytes());
        cave.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, 0x30]);
        cave.extend_from_slice(&[0x49, 0x83, 0x7c, 0x24, 0x00, 0x00]);
        cave.extend_from_slice(&[0x74, 0x18]);
        cave.extend_from_slice(&[0x49, 0xc7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00]);
        cave.extend_from_slice(&[0x49, 0x8b, 0x5c, 0x24, 0x08]);
        cave.extend_from_slice(&[0x49, 0x8b, 0x4c, 0x24, 0x10]);
        cave.extend_from_slice(&[0x41, 0xff, 0x64, 0x24, 0x18]);
        cave.extend_from_slice(&orig[0..12]);
        cave.extend_from_slice(&[0x76, 0x0e]);
        cave.extend_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
        cave.extend_from_slice(&resume_target.to_le_bytes());
        cave.extend_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
        cave.extend_from_slice(&morestack_target.to_le_bytes());
        if cave.len() != 0x59 {
            bail!("Internal cave length mismatch: {}", cave.len());
        }
        ptrace_write_bytes(pid, cave_mem, &cave)?;

        // Patch SetCycleMode+0x00 with 14-byte indirect jmp to cave_mem + 4
        // NOPs.
        let mut patch = [0x90u8; 18];
        patch[0..6].copy_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
        patch[6..14].copy_from_slice(&cave_mem.to_le_bytes());
        ptrace_write_bytes(pid, set_cycle_mode, &patch)?;

        Ok(data_mem)
    })();

    // Always detach ptrace so the child continues running freely.
    // SAFETY: Detaching ptrace from the child process.
    let detach_rc = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if detach_rc != 0 {
        bail!("PTRACE_DETACH failed: {}", std::io::Error::last_os_error());
    }

    let data_mem = install_result?;
    Ok(PatchedChild {
        pid,
        pty_master: master,
        data_mem,
    })
}

/// Writes `label` and arms `pendingFlag = 1` inside the running `agy` child via
/// `process_vm_writev` (no ptrace stop required).
pub fn queue_model_vm(pid: libc::pid_t, data_mem: u64, label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
        return false;
    }

    let str_addr = data_mem + 0x80;
    let mut ptr_len = [0u8; 16];
    ptr_len[0..8].copy_from_slice(&str_addr.to_le_bytes());
    ptr_len[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());

    let local = [
        libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        },
        libc::iovec {
            iov_base: ptr_len.as_ptr().cast_mut().cast(),
            iov_len: ptr_len.len(),
        },
    ];
    let remote = [
        libc::iovec {
            iov_base: str_addr as *mut c_void,
            iov_len: bytes.len(),
        },
        libc::iovec {
            iov_base: (data_mem + 0x08) as *mut c_void,
            iov_len: ptr_len.len(),
        },
    ];

    // SAFETY: Writing string bytes and (ptr, len) into `data_mem` of our child
    // process.
    let n1 = unsafe { libc::process_vm_writev(pid, local.as_ptr(), 2, remote.as_ptr(), 2, 0) };
    if n1 < 0 {
        return false;
    }

    // Commit `pendingFlag = 1` in a second write so string + length are visible
    // first.
    let flag = 1u64.to_le_bytes();
    let local_flag = libc::iovec {
        iov_base: flag.as_ptr().cast_mut().cast(),
        iov_len: 8,
    };
    let remote_flag = libc::iovec {
        iov_base: data_mem as *mut c_void,
        iov_len: 8,
    };
    // SAFETY: Arming `pendingFlag = 1` at `data_mem + 0x00` in our child
    // process.
    let n2 = unsafe { libc::process_vm_writev(pid, &local_flag, 1, &remote_flag, 1, 0) };
    n2 == 8
}
