//! Pure x64 tail-call detour on `store.(*Manager).SetCycleMode` ->
//! `SetSelectedModel`.
//!
//! Both Go methods share the exact `abiinternal` signature:
//! `func (m *store.Manager) Fn(s string)` (`RAX = *store.Manager, RBX = ptr,
//! RCX = len -> void`). Because the cave only ever executes `JMP` (never
//! `CALL`), `[RSP]` stays inside `(*ConversationModel).handleCycleMode` (a
//! valid `gopclntab` PC), avoiding Go `morestack` / GC stack-walker panics.

use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::MEM_COMMIT;
use windows::Win32::System::Memory::MEM_RELEASE;
use windows::Win32::System::Memory::MEM_RESERVE;
use windows::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
use windows::Win32::System::Memory::PAGE_READWRITE;
use windows::Win32::System::Memory::VirtualAlloc;
use windows::Win32::System::Memory::VirtualFree;
use windows::Win32::System::Memory::VirtualProtect;

const PROLOGUE_LEN: usize = 18;
const MAX_LABEL_LEN: usize = 192;

struct CaveState {
    patch_addr: *mut u8,
    original_bytes: [u8; PROLOGUE_LEN],
    cave_mem: *mut c_void,
    data_mem: *mut u8,
}

// SAFETY: Access to `CaveState` is serialized by `CAVE_STATE` mutex, and
// `data_mem` updates use atomic release ordering for the pending flag.
unsafe impl Send for CaveState {}

static CAVE_STATE: Mutex<Option<CaveState>> = Mutex::new(None);

/// Installs the pure x64 tail-call cave onto `SetCycleMode`.
pub fn install(set_cycle_mode_rva: u64, set_selected_model_rva: u64) -> Result<(), String> {
    let mut guard = CAVE_STATE.lock().map_err(|_| "cave mutex poisoned")?;
    if guard.is_some() {
        return Ok(());
    }

    // SAFETY: Querying the base address of the current executable (`agy.exe`).
    let module =
        unsafe { GetModuleHandleW(None) }.map_err(|e| format!("GetModuleHandleW failed: {e}"))?;
    let base = module.0 as usize;

    let set_cycle_mode = (base + set_cycle_mode_rva as usize) as *mut u8;
    let set_selected_model = (base + set_selected_model_rva as usize) as u64;

    let mut orig = [0u8; PROLOGUE_LEN];
    // SAFETY: `set_cycle_mode` points to the entry of `SetCycleMode` inside
    // `agy.exe`.
    unsafe {
        ptr::copy_nonoverlapping(set_cycle_mode, orig.as_mut_ptr(), PROLOGUE_LEN);
    }

    // Verify expected 18-byte Go large-frame prologue:
    // +0x00 (8B): 4c 8d a4 24 <imm32>   lea r12, [rsp + imm32]
    // +0x08 (4B): 4d 3b 66 10           cmp r12, [r14 + 0x10]
    // +0x0c (6B): 0f 86 <rel32>         jbe morestack
    if orig[0..4] != [0x4c, 0x8d, 0xa4, 0x24]
        || orig[8..12] != [0x4d, 0x3b, 0x66, 0x10]
        || orig[12..14] != [0x0f, 0x86]
    {
        return Err(format!("Unexpected SetCycleMode prologue: {:02x?}", orig));
    }

    let rel32 = i32::from_le_bytes([orig[14], orig[15], orig[16], orig[17]]);
    let resume_target = (set_cycle_mode as usize + PROLOGUE_LEN) as u64;
    let morestack_target = (resume_target as i64 + rel32 as i64) as u64;

    // SAFETY: Allocating a page for shared cave data (pending flag, string
    // ptr/len, target addr).
    let data_mem = unsafe { VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if data_mem.is_null() {
        return Err("VirtualAlloc failed for data_mem".to_owned());
    }
    let data_ptr = data_mem.cast::<u8>();

    // SAFETY: `data_ptr` is a freshly allocated, zero-initialized 4096-byte RW
    // page.
    unsafe {
        // +0x00: pendingFlag = 0
        data_ptr.cast::<u64>().write(0);
        // +0x08: modelStrPtr = data_ptr + 0x80
        data_ptr
            .add(0x08)
            .cast::<u64>()
            .write(data_ptr.add(0x80) as u64);
        // +0x10: modelStrLen = 0
        data_ptr.add(0x10).cast::<u64>().write(0);
        // +0x18: target SetSelectedModel
        data_ptr.add(0x18).cast::<u64>().write(set_selected_model);
        // +0x30: captured *store.Manager
        data_ptr.add(0x30).cast::<u64>().write(0);
    }

    // Assemble the 89-byte x64 tail-call cave.
    let mut cave_bytes = Vec::with_capacity(0x59);
    // +0x00 (10B): movabs r12, data_ptr
    cave_bytes.extend_from_slice(&[0x49, 0xbc]);
    cave_bytes.extend_from_slice(&(data_ptr as u64).to_le_bytes());
    // +0x0a (5B): mov [r12 + 0x30], rax
    cave_bytes.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, 0x30]);
    // +0x0f (6B): cmp qword ptr [r12 + 0x00], 0
    cave_bytes.extend_from_slice(&[0x49, 0x83, 0x7c, 0x24, 0x00, 0x00]);
    // +0x15 (2B): je +0x18 (skip 24-byte redirect path -> +0x2f)
    cave_bytes.extend_from_slice(&[0x74, 0x18]);

    // === REDIRECT PATH (+0x17..+0x2e, 24 bytes) ===
    // mov qword ptr [r12 + 0x00], 0 (9B)
    cave_bytes.extend_from_slice(&[0x49, 0xc7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // mov rbx, [r12 + 0x08] (5B)
    cave_bytes.extend_from_slice(&[0x49, 0x8b, 0x5c, 0x24, 0x08]);
    // mov rcx, [r12 + 0x10] (5B)
    cave_bytes.extend_from_slice(&[0x49, 0x8b, 0x4c, 0x24, 0x10]);
    // jmp qword ptr [r12 + 0x18] (5B) -> tail-call SetSelectedModel
    cave_bytes.extend_from_slice(&[0x41, 0xff, 0x64, 0x24, 0x18]);

    // === NORMAL PATH (+0x2f) ===
    // Replay lea r12, [rsp + imm32] + cmp r12, [r14 + 0x10] (12B)
    cave_bytes.extend_from_slice(&orig[0..12]);
    // +0x3b (2B): jbe +0x0e (skip 14-byte resume jmp -> +0x4b)
    cave_bytes.extend_from_slice(&[0x76, 0x0e]);
    // +0x3d (14B): jmp qword ptr [rip + 0]; dq resume_target
    cave_bytes.extend_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
    cave_bytes.extend_from_slice(&resume_target.to_le_bytes());
    // +0x4b (14B): jmp qword ptr [rip + 0]; dq morestack_target
    cave_bytes.extend_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
    cave_bytes.extend_from_slice(&morestack_target.to_le_bytes());

    if cave_bytes.len() != 0x59 {
        // SAFETY: Freeing allocated data page on unexpected assembly length
        // mismatch.
        unsafe {
            let _ = VirtualFree(data_mem, 0, MEM_RELEASE);
        }
        return Err(format!(
            "Internal cave length mismatch: {}",
            cave_bytes.len()
        ));
    }

    // SAFETY: Allocating executable cave page.
    let cave_mem = unsafe { VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if cave_mem.is_null() {
        // SAFETY: Freeing `data_mem` on allocation failure.
        unsafe {
            let _ = VirtualFree(data_mem, 0, MEM_RELEASE);
        }
        return Err("VirtualAlloc failed for cave_mem".to_owned());
    }

    // SAFETY: Copying verified cave bytes and marking the cave page RX.
    unsafe {
        ptr::copy_nonoverlapping(cave_bytes.as_ptr(), cave_mem.cast::<u8>(), cave_bytes.len());
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(cave_mem, 4096, PAGE_EXECUTE_READ, &mut old_prot)
            .map_err(|e| format!("VirtualProtect(cave_mem) failed: {e}"))?;
    }

    // Build 18-byte patch: 14-byte indirect jmp to cave_mem + 4 NOPs.
    let mut patch = [0x90u8; PROLOGUE_LEN];
    patch[0..6].copy_from_slice(&[0xff, 0x25, 0x00, 0x00, 0x00, 0x00]);
    patch[6..14].copy_from_slice(&(cave_mem as u64).to_le_bytes());

    // SAFETY: Temporarily making `SetCycleMode`'s first 18 bytes RWX to install
    // the jump, then restoring original page protection.
    unsafe {
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(
            set_cycle_mode.cast(),
            PROLOGUE_LEN,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
        .map_err(|e| format!("VirtualProtect(SetCycleMode) failed: {e}"))?;
        ptr::copy_nonoverlapping(patch.as_ptr(), set_cycle_mode, PROLOGUE_LEN);
        let mut _ignored = PAGE_PROTECTION_FLAGS::default();
        let _ = VirtualProtect(set_cycle_mode.cast(), PROLOGUE_LEN, old_prot, &mut _ignored);
    }

    *guard = Some(CaveState {
        patch_addr: set_cycle_mode,
        original_bytes: orig,
        cave_mem,
        data_mem: data_ptr,
    });

    Ok(())
}

/// Writes `label` into the cave's data page and arms `pendingFlag = 1` so the
/// next `SetCycleMode` call tail-calls `SetSelectedModel`.
pub fn queue_model(label: &str) {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
        return;
    }

    let Ok(guard) = CAVE_STATE.lock() else {
        return;
    };
    let Some(state) = guard.as_ref() else {
        return;
    };

    // SAFETY: `state.data_mem` is a valid 4096-byte RW page; string bytes and
    // length are written before the atomic Release store of `pendingFlag =
    // 1`.
    unsafe {
        let str_buf = state.data_mem.add(0x80);
        ptr::copy_nonoverlapping(bytes.as_ptr(), str_buf, bytes.len());
        state.data_mem.add(0x08).cast::<u64>().write(str_buf as u64);
        state
            .data_mem
            .add(0x10)
            .cast::<u64>()
            .write(bytes.len() as u64);
        let flag = &*state.data_mem.cast::<AtomicU64>();
        flag.store(1, Ordering::Release);
    }
}

/// Restores `SetCycleMode`'s original 18-byte prologue and frees allocated
/// pages.
pub fn uninstall() {
    let Ok(mut guard) = CAVE_STATE.lock() else {
        return;
    };
    let Some(state) = guard.take() else {
        return;
    };

    // SAFETY: Restoring original bytes of `SetCycleMode` and freeing cave
    // pages.
    unsafe {
        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        if VirtualProtect(
            state.patch_addr.cast(),
            PROLOGUE_LEN,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
        .is_ok()
        {
            ptr::copy_nonoverlapping(
                state.original_bytes.as_ptr(),
                state.patch_addr,
                PROLOGUE_LEN,
            );
            let mut _ignored = PAGE_PROTECTION_FLAGS::default();
            let _ = VirtualProtect(
                state.patch_addr.cast(),
                PROLOGUE_LEN,
                old_prot,
                &mut _ignored,
            );
        }
        let _ = VirtualFree(state.cave_mem, 0, MEM_RELEASE);
        let _ = VirtualFree(state.data_mem.cast(), 0, MEM_RELEASE);
    }
}
