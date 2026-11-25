# agy-dial

Add model/effort keyboard shortcuts into Antigravity CLI (on Windows + WSL2).

Uses brittle(-ish) DLL-injection / ptrace hooks to call internal Antigravity CLI Go functions directly, bypassing the UI.

Tested working on `agy` version 1.5.17.

Will it work on future versions? ¯\\\_(ツ)_/¯

> [!NOTE]
>
> Don't actually use this!
>
> Immediately after getting this working, I thought to myself: "hmm, does changing effort/model mid conversation result in cache misses?"
>
> And, uhh, yeah - it _really_ does, lol.

## How it works

1. **`agy-dial.exe`** runs in the Windows system tray, resolves `store.(*Manager).SetCycleMode` and `SetSelectedModel` dynamically from `agy.exe`'s Go `gopclntab`, fetches your account's available models via `agy models`, injects `agy_dial_hook.dll` into newly launched Windows `agy.exe` processes, and serves a control named pipe (`\\.\pipe\agy-dial-control`) for WSL2 sessions.
2. **`agy_dial_hook.dll`** hooks `kernel32.dll!ReadConsoleInputW` (via MinHook) to catch Windows Terminal Kitty CSI-u sequences sent by a Surface Dial Custom Tool, tracks each `agy.exe` instance's model/effort independently, and rewrites the input event into a synthetic `Shift+Tab` (`\x1b[9;2u`) that triggers a pure x64 tail-call detour from `SetCycleMode` into `SetSelectedModel`—working mid-prompt with zero Go `morestack`/GC stack-walker overhead.
3. **`agy-dial-wsl`** (Linux/WSL2) wraps `agy` in a PTY, installs the same 89-byte x64 tail-call detour via one-shot `ptrace` at startup (detaching immediately so `agy` runs at native speed), intercepts Kitty CSI-u directly on `stdin`, queues models via `process_vm_writev`, and connects to the Windows tray control plane via `agy-dial.exe --wsl-bridge` so the same tray **Models** toggles govern both Windows and WSL2.
4. Right-click the tray icon to toggle which model families are included in dial cycling, refresh available models, toggle **Start on Boot**, or exit cleanly. Preferences are persisted portably to `agy-dial.json` next to `agy-dial.exe`.

## Why?

Honestly, because I own a [Microsoft Surface Dial](https://www.microsoft.com/en-us/d/surface-dial/925r551sktgn) and I thought it'd be funny to dial in effort by spinning the knob, lol

Don't get me wrong, you _can_ just use the keyboard shortcuts directly... but it's more fun if you own a Dial and configure it as so:

Open **Settings → Bluetooth & devices → Wheel → Add (+) → Custom tool** (scoped to **Windows Terminal**):

| Dial Action | Shortcut | Effect in `agy` |
| --- | --- | --- |
| **Rotate left** | `Ctrl+Alt+[` | Step reasoning effort down (`XHigh` → `High` → `Medium` → `Low`) |
| **Rotate right** | `Ctrl+Alt+]` | Step reasoning effort up (`Low` → `Medium` → `High` → `XHigh`) |
| **Click** | `Ctrl+Alt+\` | Cycle enabled model families (preserving current effort tier when available) |

## Build & Run

### Windows host + hook DLL
```powershell
cargo build --release --workspace
```
Both `agy-dial.exe` and `agy_dial_hook.dll` are placed side-by-side in `target\release\`.

```powershell
# Default: attaches to newly launched agy.exe instances (ignores pre-existing ones)
.\target\release\agy-dial.exe

# Opt-in: also attach to already-running agy.exe instances at startup
.\target\release\agy-dial.exe --all
```

### WSL2 wrapper (`agy-dial-wsl`)
Inside WSL2:
```bash
cargo build --release -p agy-dial-wsl --target-dir /tmp/agy-dial-wsl-target
cp /tmp/agy-dial-wsl-target/release/agy-dial-wsl ~/bin/agy-dial-wsl
```
And alias `agy` in `~/.zshrc`:
```zsh
alias agy="$HOME/bin/agy-dial-wsl"
```
