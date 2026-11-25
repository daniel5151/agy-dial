//! Pure-Rust Go 1.20+ `gopclntab` symbol resolver for Windows PE32+ binaries.

use anyhow::Context;
use anyhow::bail;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Go 1.20+ `gopclntab` magic (`0xfffffff1`, little-endian) followed by 2 zero
/// pad bytes.
const MAGIC_GO120: &[u8] = &[0xf1, 0xff, 0xff, 0xff, 0x00, 0x00];

/// Resolved RVAs required by `agy_dial_hook.dll`.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedSymbols {
    /// RVA of `google3/third_party/jetski/cli/store/store.(*Manager).
    /// SetCycleMode`.
    pub set_cycle_mode_rva: u64,
    /// RVA of `google3/third_party/jetski/cli/store/store.(*Manager).
    /// SetSelectedModel`.
    pub set_selected_model_rva: u64,
}

const SYM_SET_CYCLE_MODE: &str =
    "google3/third_party/jetski/cli/store/store.(*Manager).SetCycleMode";
const SYM_SET_SELECTED_MODEL: &str =
    "google3/third_party/jetski/cli/store/store.(*Manager).SetSelectedModel";

fn read_u16(data: &[u8], off: usize) -> anyhow::Result<u16> {
    let bytes: [u8; 2] = data
        .get(off..off + 2)
        .context("unexpected EOF reading u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], off: usize) -> anyhow::Result<u32> {
    let bytes: [u8; 4] = data
        .get(off..off + 4)
        .context("unexpected EOF reading u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], off: usize) -> anyhow::Result<i32> {
    let bytes: [u8; 4] = data
        .get(off..off + 4)
        .context("unexpected EOF reading i32")?
        .try_into()?;
    Ok(i32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], off: usize) -> anyhow::Result<u64> {
    let bytes: [u8; 8] = data
        .get(off..off + 8)
        .context("unexpected EOF reading u64")?
        .try_into()?;
    Ok(u64::from_le_bytes(bytes))
}

fn parse_pe_info(data: &[u8]) -> anyhow::Result<(u64, u64)> {
    let e_lfanew = read_u32(data, 0x3c)? as usize;
    let coff_off = e_lfanew + 4;
    let num_sections = read_u16(data, coff_off + 2)? as usize;
    let size_opt = read_u16(data, coff_off + 16)? as usize;
    let opt_off = coff_off + 20;

    let magic = read_u16(data, opt_off)?;
    if magic != 0x20b {
        bail!("Unsupported PE optional header magic: 0x{magic:x} (expected PE32+)");
    }
    let image_base = read_u64(data, opt_off + 24)?;

    let sec_off = opt_off + size_opt;
    let mut text_rva = 0x1000u64;
    for i in 0..num_sections {
        let off = sec_off + i * 40;
        let name_bytes = data
            .get(off..off + 8)
            .context("unexpected EOF reading PE section header")?;
        if name_bytes.starts_with(b".text\0") || name_bytes == b".text\0\0\0" {
            text_rva = u64::from(read_u32(data, off + 12)?);
            break;
        }
    }

    Ok((image_base, text_rva))
}

fn find_pclntab(data: &[u8]) -> anyhow::Result<usize> {
    let mut start = 0;
    while let Some(rel) = data[start..]
        .windows(MAGIC_GO120.len())
        .position(|w| w == MAGIC_GO120)
    {
        let idx = start + rel;
        // Check minLC = 1 (x86/x64) and ptrSize = 8 (64-bit) at +6, +7.
        if data.get(idx + 6) == Some(&1) && data.get(idx + 7) == Some(&8) {
            return Ok(idx);
        }
        start = idx + 1;
    }
    bail!("Could not find Go 1.20+ gopclntab in binary")
}

/// Resolves the required `agy.exe` symbol RVAs from its embedded `gopclntab`.
pub fn resolve_agy_symbols(exe_path: &Path) -> anyhow::Result<ResolvedSymbols> {
    let data =
        fs::read(exe_path).with_context(|| format!("Failed to read '{}'", exe_path.display()))?;
    let (image_base, text_rva) = parse_pe_info(&data)?;
    let base = find_pclntab(&data)?;

    let nfunc = read_u64(&data, base + 8)? as usize;
    let text_start = read_u64(&data, base + 24)?;
    let funcname_off = read_u64(&data, base + 32)? as usize;
    let pcln_off = read_u64(&data, base + 64)? as usize;

    let base_rva = if text_start == 0 {
        text_rva
    } else {
        text_start.saturating_sub(image_base)
    };

    let funcnametab = base + funcname_off;
    let ftab = base + pcln_off;

    let mut found: HashMap<&str, u64> = HashMap::new();
    for i in 0..nfunc {
        let entry_off = u64::from(read_u32(&data, ftab + i * 8)?);
        let func_off = read_u32(&data, ftab + i * 8 + 4)? as usize;
        let name_off = read_i32(&data, ftab + func_off + 4)? as isize;
        if name_off < 0 {
            continue;
        }
        let name_start = funcnametab + name_off as usize;
        let Some(slice) = data.get(name_start..) else {
            continue;
        };
        let Some(nul) = slice.iter().position(|&b| b == 0) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(&slice[..nul]) else {
            continue;
        };

        if name == SYM_SET_CYCLE_MODE {
            found.insert(SYM_SET_CYCLE_MODE, base_rva + entry_off);
        } else if name == SYM_SET_SELECTED_MODEL {
            found.insert(SYM_SET_SELECTED_MODEL, base_rva + entry_off);
        }

        if found.len() == 2 {
            break;
        }
    }

    let set_cycle_mode_rva = *found
        .get(SYM_SET_CYCLE_MODE)
        .with_context(|| format!("Symbol not found: {SYM_SET_CYCLE_MODE}"))?;
    let set_selected_model_rva = *found
        .get(SYM_SET_SELECTED_MODEL)
        .with_context(|| format!("Symbol not found: {SYM_SET_SELECTED_MODEL}"))?;

    Ok(ResolvedSymbols {
        set_cycle_mode_rva,
        set_selected_model_rva,
    })
}
