//! `kernel32.dll!ReadConsoleInputW` hook via MinHook.
//!
//! Intercepts Windows Terminal Kitty CSI-u sequences sent by the Surface Dial:
//! - `Ctrl+Alt+[` (`\x1b[91;7u`) -> step effort down
//! - `Ctrl+Alt+]` (`\x1b[93;7u`) -> step effort up
//! - `Ctrl+Alt+\` (`\x1b[92;7u`) -> cycle model family
//!
//! When a change occurs, queues the new model label in [`crate::cave`] and
//! rewrites the console input buffer to `\x1b[9;2u` (`Shift+Tab`) so `agy`'s
//! own Go TUI loop triggers our tail-call cave cleanly mid-prompt.

use agy_dial_proto::ModelFamily;
use minhook::MinHook;
use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::INPUT_RECORD;
use windows::Win32::System::Console::KEY_EVENT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::core::BOOL;
use windows::core::s;
use windows::core::w;

use crate::cave;

const SHIFT_TAB_VT: &[u8] = b"\x1b[9;2u";

type ReadConsoleInputWFn =
    unsafe extern "system" fn(HANDLE, *mut INPUT_RECORD, u32, *mut u32) -> BOOL;

static ORIG_READ_CONSOLE_INPUT_W: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static HOOK_TARGET: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

struct DialState {
    families: Vec<ModelFamily>,
    family_idx: usize,
    variant_idx: usize,
}

impl DialState {
    fn sync_from_label(&mut self, label: &str) {
        let norm = label.trim().to_ascii_lowercase();
        if norm.is_empty() {
            return;
        }
        for (f_idx, fam) in self.families.iter().enumerate() {
            for (v_idx, var) in fam.variants.iter().enumerate() {
                if var.label.to_ascii_lowercase() == norm {
                    self.family_idx = f_idx;
                    self.variant_idx = v_idx;
                    return;
                }
            }
        }
    }

    fn current_label(&self) -> Option<&str> {
        self.families
            .get(self.family_idx)
            .and_then(|f| f.variants.get(self.variant_idx))
            .map(|v| v.label.as_str())
    }

    fn step_down(&mut self) -> Option<String> {
        if self.variant_idx > 0 {
            self.variant_idx -= 1;
            self.current_label().map(str::to_owned)
        } else {
            None
        }
    }

    fn step_up(&mut self) -> Option<String> {
        let max_idx = self
            .families
            .get(self.family_idx)?
            .variants
            .len()
            .checked_sub(1)?;
        if self.variant_idx < max_idx {
            self.variant_idx += 1;
            self.current_label().map(str::to_owned)
        } else {
            None
        }
    }

    fn cycle_family(&mut self) -> Option<String> {
        if self.families.is_empty() {
            return None;
        }
        let prev_tier = self
            .families
            .get(self.family_idx)
            .and_then(|f| f.variants.get(self.variant_idx))
            .map(|v| v.tier.to_ascii_lowercase())
            .unwrap_or_default();

        self.family_idx = (self.family_idx + 1) % self.families.len();
        let next_variants = &self.families[self.family_idx].variants;
        if let Some(pos) = next_variants
            .iter()
            .position(|v| v.tier.to_ascii_lowercase() == prev_tier)
        {
            self.variant_idx = pos;
        } else {
            self.variant_idx = self.variant_idx.min(next_variants.len().saturating_sub(1));
        }
        self.current_label().map(str::to_owned)
    }
}

static DIAL_STATE: Mutex<DialState> = Mutex::new(DialState {
    families: Vec::new(),
    family_idx: 0,
    variant_idx: 0,
});

/// Updates the tracked model families, preserving this instance's current model
/// selection when `initial_model` is `None`.
pub fn set_families(families: Vec<ModelFamily>, initial_model: Option<&str>) {
    if let Ok(mut state) = DIAL_STATE.lock() {
        let prev_label = initial_model
            .map(str::to_owned)
            .or_else(|| state.current_label().map(str::to_owned));
        state.families = families;
        state.family_idx = 0;
        state.variant_idx = 0;
        if let Some(label) = prev_label {
            state.sync_from_label(&label);
        }
    }
}

/// Installs the MinHook detour on `kernel32.dll!ReadConsoleInputW`.
pub fn install() -> Result<(), String> {
    if !HOOK_TARGET.load(Ordering::Acquire).is_null() {
        return Ok(());
    }

    // SAFETY: Resolving `ReadConsoleInputW` from `kernel32.dll`.
    let target = unsafe {
        let k32 = GetModuleHandleW(w!("kernel32.dll"))
            .map_err(|e| format!("GetModuleHandleW(kernel32) failed: {e}"))?;
        GetProcAddress(k32, s!("ReadConsoleInputW"))
            .ok_or_else(|| "GetProcAddress(ReadConsoleInputW) returned null".to_owned())?
            as *mut c_void
    };

    // SAFETY: Creating and enabling a standard Win32 C-ABI hook on
    // `ReadConsoleInputW`.
    unsafe {
        let orig = MinHook::create_hook(target, hooked_read_console_input_w as *mut c_void)
            .map_err(|e| format!("MinHook::create_hook failed: {e:?}"))?;
        ORIG_READ_CONSOLE_INPUT_W.store(orig, Ordering::Release);
        HOOK_TARGET.store(target, Ordering::Release);
        MinHook::enable_hook(target).map_err(|e| format!("MinHook::enable_hook failed: {e:?}"))?;
    }

    Ok(())
}

/// Disables and removes the `ReadConsoleInputW` hook.
pub fn uninstall() {
    let target = HOOK_TARGET.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !target.is_null() {
        // SAFETY: Disabling and removing the previously created MinHook detour.
        unsafe {
            let _ = MinHook::disable_hook(target);
            let _ = MinHook::remove_hook(target);
        }
    }
}

/// Parses a Kitty CSI-u sequence `\x1b[<keycode>;<mod>u` for
/// Ctrl+Alt+`[`/`\`/`]`. Returns `Some(91 | 92 | 93)` when matched.
fn match_dial_csi_u(seq: &str) -> Option<u32> {
    let bytes = seq.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i] == 0x1b && bytes[i + 1] == b'[' {
            let rest = &seq[i + 2..];
            if let Some(u_pos) = rest.find('u') {
                let body = &rest[..u_pos];
                if let Some((code_str, mod_part)) = body.split_once(';') {
                    let mod_str = mod_part.split(':').next().unwrap_or(mod_part);
                    if let (Ok(code), Ok(mod_val)) =
                        (code_str.parse::<u32>(), mod_str.parse::<u32>())
                    {
                        let mod_bits = mod_val.saturating_sub(1);
                        if matches!(code, 91..=93) && (mod_bits & 6) == 6 {
                            return Some(code);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

fn write_vt_char_record(rec: &mut INPUT_RECORD, ch: u8) {
    rec.EventType = KEY_EVENT as u16;
    rec.Event.KeyEvent.bKeyDown = BOOL(1);
    rec.Event.KeyEvent.wRepeatCount = 1;
    rec.Event.KeyEvent.wVirtualKeyCode = 0;
    rec.Event.KeyEvent.wVirtualScanCode = 0;
    rec.Event.KeyEvent.uChar.UnicodeChar = u16::from(ch);
    rec.Event.KeyEvent.dwControlKeyState = 0;
}

fn write_noop_keyup_record(rec: &mut INPUT_RECORD) {
    rec.EventType = KEY_EVENT as u16;
    rec.Event.KeyEvent.bKeyDown = BOOL(0);
    rec.Event.KeyEvent.wRepeatCount = 1;
    rec.Event.KeyEvent.wVirtualKeyCode = 0;
    rec.Event.KeyEvent.wVirtualScanCode = 0;
    rec.Event.KeyEvent.uChar.UnicodeChar = 0;
    rec.Event.KeyEvent.dwControlKeyState = 0;
}

unsafe extern "system" fn hooked_read_console_input_w(
    console_input: HANDLE,
    buffer: *mut INPUT_RECORD,
    length: u32,
    num_events_read: *mut u32,
) -> BOOL {
    let orig_ptr = ORIG_READ_CONSOLE_INPUT_W.load(Ordering::Acquire);
    if orig_ptr.is_null() {
        return BOOL(0);
    }

    // SAFETY: `orig_ptr` is the MinHook trampoline for `ReadConsoleInputW`.
    let orig: ReadConsoleInputWFn = unsafe { std::mem::transmute(orig_ptr) };
    // SAFETY: Forwarding original Win32 arguments to `ReadConsoleInputW`.
    let ok = unsafe { orig(console_input, buffer, length, num_events_read) };
    if !ok.as_bool() || buffer.is_null() || num_events_read.is_null() {
        return ok;
    }

    // SAFETY: `num_events_read` is valid and `buffer` holds `count`
    // `INPUT_RECORD`s.
    let count = unsafe { *num_events_read } as usize;
    if count < 5 {
        return ok;
    }

    // SAFETY: `buffer` is valid for `count` elements as guaranteed by
    // `ReadConsoleInputW`.
    let records = unsafe { std::slice::from_raw_parts_mut(buffer, length as usize) };
    let mut seq = String::with_capacity(count);
    for rec in &records[..count] {
        if rec.EventType == KEY_EVENT as u16 {
            // SAFETY: `EventType == KEY_EVENT`, so reading `KeyEvent` is valid.
            let ke = unsafe { rec.Event.KeyEvent };
            if ke.bKeyDown.as_bool() {
                // SAFETY: Reading `UnicodeChar` from `ReadConsoleInputW` key
                // event.
                let ch = unsafe { ke.uChar.UnicodeChar };
                if let Some(c) = char::from_u32(u32::from(ch)) {
                    if ch > 0 {
                        seq.push(c);
                    }
                }
            }
        }
    }

    let Some(key_code) = match_dial_csi_u(&seq) else {
        return ok;
    };

    let next_label = if let Ok(mut state) = DIAL_STATE.lock() {
        match key_code {
            91 => state.step_down(),
            93 => state.step_up(),
            92 => state.cycle_family(),
            _ => None,
        }
    } else {
        None
    };

    if let Some(label) = next_label {
        if (length as usize) >= SHIFT_TAB_VT.len() {
            cave::queue_model(&label);
            for (idx, &b) in SHIFT_TAB_VT.iter().enumerate() {
                write_vt_char_record(&mut records[idx], b);
            }
            // SAFETY: Updating output event count to the length of our
            // Shift+Tab VT sequence.
            unsafe {
                *num_events_read = SHIFT_TAB_VT.len() as u32;
            }
            return ok;
        }
    }

    // Already at effort boundary (or buffer too small): swallow the key event
    // cleanly.
    write_noop_keyup_record(&mut records[0]);
    // SAFETY: Updating output event count to 1 no-op KeyUp record.
    unsafe {
        *num_events_read = 1;
    }
    ok
}
