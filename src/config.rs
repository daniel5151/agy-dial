//! Portable JSON configuration stored adjacent to `agy-dial.exe`.

use agy_dial_proto::ModelFamily;
use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const CONFIG_FILENAME: &str = "agy-dial.json";

/// Persistent user preferences for `agy-dial`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Model family names explicitly unchecked in the tray `Models` submenu.
    /// Storing disabled families ensures newly released models are enabled by
    /// default.
    #[serde(default)]
    pub disabled_families: BTreeSet<String>,
}

impl Config {
    /// Returns the portable config file path next to `agy-dial.exe`.
    pub fn path() -> anyhow::Result<PathBuf> {
        let exe = std::env::current_exe().context("Failed to locate current executable")?;
        let dir = exe
            .parent()
            .context("Executable path has no parent directory")?;
        Ok(dir.join(CONFIG_FILENAME))
    }

    /// Loads `agy-dial.json` next to the executable, or returns defaults if not
    /// present.
    pub fn load() -> Self {
        let Ok(path) = Self::path() else {
            return Self::default();
        };
        let Ok(content) = fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str(&content) {
            Ok(cfg) => cfg,
            Err(e) => {
                log::warn!("Failed to parse '{}': {e}; using defaults", path.display());
                Self::default()
            }
        }
    }

    /// Writes the current config to `agy-dial.json` next to the executable.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::path()?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json).with_context(|| format!("Failed to write '{}'", path.display()))?;
        Ok(())
    }

    /// Returns whether a model family is enabled for dial cycling.
    pub fn is_enabled(&self, family_name: &str) -> bool {
        !self.disabled_families.contains(family_name)
    }

    /// Toggles a model family on/off and persists the updated config.
    /// Returns the new enabled state.
    pub fn toggle_family(&mut self, family_name: &str) -> bool {
        let now_enabled = if self.disabled_families.remove(family_name) {
            true
        } else {
            self.disabled_families.insert(family_name.to_owned());
            false
        };
        if let Err(e) = self.save() {
            log::error!("Failed to save config: {e:#}");
        }
        now_enabled
    }

    /// Filters `all` down to only the currently enabled model families.
    pub fn filter_families(&self, all: &[ModelFamily]) -> Vec<ModelFamily> {
        all.iter()
            .filter(|f| self.is_enabled(&f.name))
            .cloned()
            .collect()
    }
}
