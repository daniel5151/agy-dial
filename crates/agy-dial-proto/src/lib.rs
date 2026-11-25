//! Shared IPC protocol types between `agy-dial.exe`, `agy_dial_hook.dll`, and
//! `agy-dial-wsl`.

use serde::Deserialize;
use serde::Serialize;

/// Shared control-plane named pipe path used by WSL2 bridge clients to connect
/// to the Windows `agy-dial.exe` tray host.
pub const CONTROL_PIPE_NAME: &str = r"\\.\pipe\agy-dial-control";

/// A single selectable model variant within a model family (e.g. `Low`, `High`,
/// `XHigh`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVariant {
    /// Short tier label inside parentheses (e.g. `"High"`, `"XHigh"`), or empty
    /// if none.
    pub tier: String,
    /// Full display label accepted by `SetSelectedModel` (e.g. `"Gemini 4 Neon
    /// (High)"`).
    pub label: String,
}

/// A model family and its ordered list of variants/effort tiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFamily {
    /// Base model family name (e.g. `"Gemini 4 Neon"`).
    pub name: String,
    /// Ordered variants from lowest to highest effort.
    pub variants: Vec<ModelVariant>,
}

/// Messages sent from `agy-dial.exe` to hook clients (Windows DLL and WSL2
/// bridges) over newline-delimited JSON pipes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    /// Initial handshake payload that installs the x64 tail-call cave and input
    /// hook.
    Install {
        /// RVA of `store.(*Manager).SetCycleMode` inside `agy.exe`.
        set_cycle_mode_rva: u64,
        /// RVA of `store.(*Manager).SetSelectedModel` inside `agy.exe`.
        set_selected_model_rva: u64,
        /// Dynamically discovered (and user-filtered) model families from `agy
        /// models`.
        families: Vec<ModelFamily>,
        /// Initial active model label read at attach time.
        initial_model: String,
    },
    /// Replaces the enabled model families (after a tray toggle or refresh),
    /// preserving each `agy` instance's own active model selection when
    /// possible.
    UpdateFamilies {
        /// Updated enabled model families.
        families: Vec<ModelFamily>,
    },
    /// Restores patched bytes, removes the input hook, and unloads the DLL
    /// cleanly.
    Uninstall,
}

/// Returns the Windows named pipe path for a given Windows `agy.exe` process
/// ID.
pub fn pipe_name(pid: u32) -> String {
    format!(r"\\.\pipe\agy-dial-{pid}")
}
