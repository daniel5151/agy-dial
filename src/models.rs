//! Dynamic model discovery via `agy models` and initial model lookup from
//! `~/.gemini/antigravity-cli/settings.json`.

use agy_dial_proto::ModelFamily;
use agy_dial_proto::ModelVariant;
use anyhow::Context;
use anyhow::bail;
use std::collections::HashMap;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Returns the default path to `agy.exe` (`%LOCALAPPDATA%\agy\bin\agy.exe`).
pub fn find_agy_exe() -> anyhow::Result<PathBuf> {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let candidate = PathBuf::from(local_app_data)
            .join("agy")
            .join("bin")
            .join("agy.exe");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("agy.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    bail!("Could not locate agy.exe in %LOCALAPPDATA%\\agy\\bin or PATH")
}

/// Returns the path to `~/.gemini/antigravity-cli/settings.json`.
pub fn settings_path() -> Option<PathBuf> {
    let home = std::env::var("USERPROFILE").ok()?;
    Some(
        PathBuf::from(home)
            .join(".gemini")
            .join("antigravity-cli")
            .join("settings.json"),
    )
}

/// Reads the current `"model"` string from `settings.json` (used as the initial
/// model guess when attaching to a newly launched `agy.exe` instance).
pub fn read_current_model() -> String {
    let Some(path) = settings_path() else {
        return String::new();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return String::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
        return String::new();
    };
    val.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned()
}

fn effort_rank(tier: &str) -> Option<u8> {
    match tier.to_ascii_lowercase().as_str() {
        "low" => Some(0),
        "medium" => Some(1),
        "high" => Some(2),
        "xhigh" => Some(3),
        "max" => Some(4),
        _ => None,
    }
}

fn split_label_variant(label: &str) -> (&str, &str) {
    let trimmed = label.trim();
    if let Some(open) = trimmed.rfind('(') {
        if trimmed.ends_with(')') && open > 0 {
            let base = trimmed[..open].trim();
            let tier = trimmed[open + 1..trimmed.len() - 1].trim();
            return (base, tier);
        }
    }
    (trimmed, "")
}

/// Runs `agy models` and parses all available model families and effort levels,
/// excluding `Orchestrator` (which has no linear effort knob).
pub fn fetch_model_families(agy_exe: &Path) -> anyhow::Result<Vec<ModelFamily>> {
    let output = Command::new(agy_exe)
        .arg("models")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .with_context(|| format!("Failed to run '{} models'", agy_exe.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`agy models` exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut families: HashMap<String, Vec<ModelVariant>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for line in stdout.lines() {
        let Some((_id, label)) = line.split_once('\t') else {
            continue;
        };
        let label = label.trim();
        if label.is_empty() {
            continue;
        }
        let (base, tier) = split_label_variant(label);
        if base.eq_ignore_ascii_case("orchestrator") {
            continue;
        }

        let base_key = base.to_owned();
        if !families.contains_key(&base_key) {
            order.push(base_key.clone());
        }
        families.entry(base_key).or_default().push(ModelVariant {
            tier: tier.to_owned(),
            label: label.to_owned(),
        });
    }

    let mut result = Vec::with_capacity(order.len());
    for base in order {
        let Some(mut variants) = families.remove(&base) else {
            continue;
        };
        if variants.iter().all(|v| effort_rank(&v.tier).is_some()) {
            variants.sort_by_key(|v| effort_rank(&v.tier).unwrap_or(u8::MAX));
        }
        result.push(ModelFamily {
            name: base,
            variants,
        });
    }

    Ok(result)
}
