//! Model state management, local `agy models` fallback, and Windows tray
//! control-plane bridge (`agy-dial.exe --wsl-bridge`).

use agy_dial_proto::HostMessage;
use agy_dial_proto::ModelFamily;
use agy_dial_proto::ModelVariant;
use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Per-session tracked model/effort cursor inside `agy-dial-wsl`.
pub struct DialState {
    families: Vec<ModelFamily>,
    family_idx: usize,
    variant_idx: usize,
}

impl DialState {
    /// Creates an empty `DialState`.
    pub fn new() -> Self {
        Self {
            families: Vec::new(),
            family_idx: 0,
            variant_idx: 0,
        }
    }

    /// Returns `true` if no model families have been loaded yet.
    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    /// Replaces the enabled model families, preserving the current selection if
    /// present.
    pub fn set_families(&mut self, families: Vec<ModelFamily>, initial_model: Option<&str>) {
        let prev_label = initial_model
            .map(str::to_owned)
            .or_else(|| self.current_label().map(str::to_owned));
        self.families = families;
        self.family_idx = 0;
        self.variant_idx = 0;
        if let Some(label) = prev_label {
            self.sync_from_label(&label);
        }
    }

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

    /// Steps down one effort level within the current model family.
    pub fn step_down(&mut self) -> Option<String> {
        if self.variant_idx > 0 {
            self.variant_idx -= 1;
            self.current_label().map(str::to_owned)
        } else {
            None
        }
    }

    /// Steps up one effort level within the current model family.
    pub fn step_up(&mut self) -> Option<String> {
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

    /// Cycles to the next enabled model family, keeping a matching effort tier
    /// when available.
    pub fn cycle_family(&mut self) -> Option<String> {
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

/// Reads the initial `"model"` setting from WSL2
/// `~/.gemini/antigravity-cli/settings.json`.
pub fn read_initial_model() -> String {
    let Ok(home) = std::env::var("HOME") else {
        return String::new();
    };
    let path = PathBuf::from(home)
        .join(".gemini")
        .join("antigravity-cli")
        .join("settings.json");
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

/// Runs Linux `agy models` as a standalone fallback when Windows `agy-dial.exe`
/// isn't running or hasn't pushed families yet.
pub fn fetch_local_families(real_agy: &Path) -> Vec<ModelFamily> {
    let Ok(output) = Command::new(real_agy)
        .arg("models")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
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
    result
}

/// Locates the Windows `agy-dial.exe` binary via `AGY_DIAL_WIN_EXE` or standard
/// WSL `/mnt/c/Users/*/src/agy-dial/target/release/agy-dial.exe` paths.
pub fn find_windows_agy_dial_exe() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("AGY_DIAL_WIN_EXE") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Ok(entries) = fs::read_dir("/mnt/c/Users") {
        for entry in entries.flatten() {
            let candidate = entry
                .path()
                .join("src")
                .join("agy-dial")
                .join("target")
                .join("release")
                .join("agy-dial.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Spawns a background thread that connects to Windows `agy-dial.exe
/// --wsl-bridge` and keeps `dial_state` synchronized with the Windows tray
/// menu.
pub fn spawn_windows_bridge(
    dial_state: Arc<Mutex<DialState>>,
    initial_model: String,
    running: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let win_exe = find_windows_agy_dial_exe()?;
    Some(std::thread::spawn(move || {
        let mut seeded = false;
        while running.load(Ordering::Relaxed) {
            let Ok(mut child) = Command::new(&win_exe)
                .arg("--wsl-bridge")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                std::thread::sleep(Duration::from_secs(5));
                continue;
            };

            let _stdin_guard = child.stdin.take();
            if let Some(stdout) = child.stdout.take() {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(line) = line else {
                        break;
                    };
                    let Ok(msg) = serde_json::from_str::<HostMessage>(&line) else {
                        continue;
                    };
                    if let HostMessage::UpdateFamilies { families } = msg {
                        if let Ok(mut st) = dial_state.lock() {
                            let init = if !seeded && st.is_empty() {
                                seeded = true;
                                Some(initial_model.as_str())
                            } else {
                                seeded = true;
                                None
                            };
                            st.set_families(families, init);
                        }
                    }
                }
            }

            drop(_stdin_guard);
            let _ = child.kill();
            let _ = child.wait();

            if running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }))
}
