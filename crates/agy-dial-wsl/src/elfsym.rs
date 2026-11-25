//! Pure-Rust ELF64 Go 1.20+ `gopclntab` symbol resolver for Linux `agy`.

use anyhow::Context;
use anyhow::bail;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const MAGIC_GO120: &[u8] = &[0xf1, 0xff, 0xff, 0xff, 0x00, 0x00];

const SYM_SET_CYCLE_MODE: &str =
    "google3/third_party/jetski/cli/store/store.(*Manager).SetCycleMode";
const SYM_SET_SELECTED_MODEL: &str =
    "google3/third_party/jetski/cli/store/store.(*Manager).SetSelectedModel";

/// Resolved ELF virtual addresses (relative to PIE base) required for hooking
/// Linux `agy`.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedElfSymbols {
    /// Virtual address offset of `store.(*Manager).SetCycleMode`.
    pub set_cycle_mode_va: u64,
    /// Virtual address offset of `store.(*Manager).SetSelectedModel`.
    pub set_selected_model_va: u64,
    /// Verified original 18-byte prologue of `SetCycleMode`.
    pub original_prologue: [u8; 18],
}

fn read_u16(data: &[u8], off: usize) -> anyhow::Result<u16> {
    let b: [u8; 2] = data
        .get(off..off + 2)
        .context("EOF reading u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(data: &[u8], off: usize) -> anyhow::Result<u32> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .context("EOF reading u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(b))
}

fn read_i32(data: &[u8], off: usize) -> anyhow::Result<i32> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .context("EOF reading i32")?
        .try_into()?;
    Ok(i32::from_le_bytes(b))
}

fn read_u64(data: &[u8], off: usize) -> anyhow::Result<u64> {
    let b: [u8; 8] = data
        .get(off..off + 8)
        .context("EOF reading u64")?
        .try_into()?;
    Ok(u64::from_le_bytes(b))
}

fn read_i64(data: &[u8], off: usize) -> anyhow::Result<i64> {
    let b: [u8; 8] = data
        .get(off..off + 8)
        .context("EOF reading i64")?
        .try_into()?;
    Ok(i64::from_le_bytes(b))
}

struct ElfSection {
    name: String,
    addr: u64,
    offset: u64,
    size: u64,
}

fn parse_elf_sections(data: &[u8]) -> anyhow::Result<Vec<ElfSection>> {
    if data.get(0..4) != Some(b"\x7fELF") || data.get(4) != Some(&2) {
        bail!("Target binary is not an ELF64 executable");
    }
    let e_shoff = read_u64(data, 40)? as usize;
    let e_shentsize = read_u16(data, 58)? as usize;
    let e_shnum = read_u16(data, 60)? as usize;
    let e_shstrndx = read_u16(data, 62)? as usize;

    let shstr_hdr = e_shoff + e_shstrndx * e_shentsize;
    let shstr_off = read_u64(data, shstr_hdr + 24)? as usize;

    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let off = e_shoff + i * e_shentsize;
        let sh_name = read_u32(data, off)? as usize;
        let addr = read_u64(data, off + 16)?;
        let offset = read_u64(data, off + 24)?;
        let size = read_u64(data, off + 32)?;

        let name = if let Some(slice) = data.get(shstr_off + sh_name..) {
            let nul = slice.iter().position(|&b| b == 0).unwrap_or(0);
            String::from_utf8_lossy(&slice[..nul]).into_owned()
        } else {
            String::new()
        };

        sections.push(ElfSection {
            name,
            addr,
            offset,
            size,
        });
    }
    Ok(sections)
}

fn va_to_file_offset(sections: &[ElfSection], va: u64) -> Option<usize> {
    for sec in sections {
        if sec.addr != 0 && va >= sec.addr && va < sec.addr + sec.size {
            return Some((sec.offset + (va - sec.addr)) as usize);
        }
    }
    None
}

fn file_offset_to_va(sections: &[ElfSection], fo: usize) -> Option<u64> {
    let fo_u64 = fo as u64;
    for sec in sections {
        if sec.addr != 0 && fo_u64 >= sec.offset && fo_u64 < sec.offset + sec.size {
            return Some(sec.addr + (fo_u64 - sec.offset));
        }
    }
    None
}

fn find_pclntab(data: &[u8]) -> anyhow::Result<usize> {
    let mut start = 0;
    while let Some(rel) = data[start..]
        .windows(MAGIC_GO120.len())
        .position(|w| w == MAGIC_GO120)
    {
        let idx = start + rel;
        if data.get(idx + 6) == Some(&1) && data.get(idx + 7) == Some(&8) {
            return Ok(idx);
        }
        start = idx + 1;
    }
    bail!("Could not find Go 1.20+ gopclntab in ELF binary")
}

fn is_valid_large_frame_prologue(bytes: &[u8]) -> bool {
    bytes.len() >= 18
        && bytes[0..4] == [0x4c, 0x8d, 0xa4, 0x24]
        && bytes[8..12] == [0x4d, 0x3b, 0x66, 0x10]
        && bytes[12..14] == [0x0f, 0x86]
}

/// Resolves `SetCycleMode` and `SetSelectedModel` virtual address offsets from
/// a Linux `agy` ELF binary.
pub fn resolve_linux_agy_symbols(exe_path: &Path) -> anyhow::Result<ResolvedElfSymbols> {
    let data =
        fs::read(exe_path).with_context(|| format!("Failed to read '{}'", exe_path.display()))?;
    let sections = parse_elf_sections(&data)?;
    let base = find_pclntab(&data)?;
    let pcln_va = file_offset_to_va(&sections, base)
        .context("Could not map gopclntab file offset to ELF virtual address")?;

    let nfunc = read_u64(&data, base + 8)? as usize;
    let header_text_start = read_u64(&data, base + 24)?;
    let funcname_off = read_u64(&data, base + 32)? as usize;
    let pcln_off = read_u64(&data, base + 64)? as usize;

    let funcnametab = base + funcname_off;
    let ftab = base + pcln_off;

    let mut eoffs: HashMap<&str, u64> = HashMap::new();
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
            eoffs.insert(SYM_SET_CYCLE_MODE, entry_off);
        } else if name == SYM_SET_SELECTED_MODEL {
            eoffs.insert(SYM_SET_SELECTED_MODEL, entry_off);
        }
        if eoffs.len() == 2 {
            break;
        }
    }

    let cycle_eoff = *eoffs
        .get(SYM_SET_CYCLE_MODE)
        .with_context(|| format!("Symbol not found: {SYM_SET_CYCLE_MODE}"))?;
    let select_eoff = *eoffs
        .get(SYM_SET_SELECTED_MODEL)
        .with_context(|| format!("Symbol not found: {SYM_SET_SELECTED_MODEL}"))?;

    // Collect candidate `textStart` values:
    // 1. Non-zero header_text_start (non-PIE builds)
    // 2. `.rela.dyn` relocation targeting `firstmoduledata.text` (Go PIE
    //    builds)
    // 3. Fallback: `.text` section start
    let mut candidate_starts: Vec<u64> = Vec::new();
    if header_text_start != 0 {
        candidate_starts.push(header_text_start);
    }

    if let Some(rela) = sections.iter().find(|s| s.name == ".rela.dyn") {
        let text_sec = sections.iter().find(|s| s.name == ".text");
        let text_lo = text_sec.map_or(0, |s| s.addr);
        let text_hi = text_sec.map_or(u64::MAX, |s| s.addr + s.size);

        let mut relas: HashMap<u64, u64> = HashMap::new();
        let mut moduledata_vas: Vec<u64> = Vec::new();
        let start = rela.offset as usize;
        let end = start + rela.size as usize;
        let mut off = start;
        while off + 24 <= end {
            let r_offset = read_u64(&data, off)?;
            let r_addend = read_i64(&data, off + 16)?;
            if r_addend > 0 {
                let add = r_addend as u64;
                relas.insert(r_offset, add);
                if add == pcln_va {
                    moduledata_vas.push(r_offset);
                }
            }
            off += 24;
        }

        for md_va in moduledata_vas {
            for delta in (0..0x180u64).step_by(8) {
                if let Some(&val) = relas.get(&(md_va + delta)) {
                    if val >= text_lo && val < text_hi && !candidate_starts.contains(&val) {
                        candidate_starts.push(val);
                    }
                }
            }
        }
    }

    if let Some(text_sec) = sections.iter().find(|s| s.name == ".text") {
        if !candidate_starts.contains(&text_sec.addr) {
            candidate_starts.push(text_sec.addr);
        }
    }

    for text_start in candidate_starts {
        let cycle_va = text_start + cycle_eoff;
        let Some(fo) = va_to_file_offset(&sections, cycle_va) else {
            continue;
        };
        let Some(slice) = data.get(fo..fo + 18) else {
            continue;
        };
        if is_valid_large_frame_prologue(slice) {
            let mut orig = [0u8; 18];
            orig.copy_from_slice(slice);
            return Ok(ResolvedElfSymbols {
                set_cycle_mode_va: cycle_va,
                set_selected_model_va: text_start + select_eoff,
                original_prologue: orig,
            });
        }
    }

    bail!("Could not verify SetCycleMode prologue at any candidate textStart")
}
