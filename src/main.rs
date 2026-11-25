//! Standalone Windows tray host for Surface Dial effort/model switching in
//! Antigravity CLI (`agy`), supporting both native Windows `agy.exe` and WSL2
//! `agy-dial-wsl` sessions.

#![windows_subsystem = "windows"]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

mod autostart;
mod config;
mod console;
mod gosym;
mod injector;
mod models;
mod tray;
mod wsl_bridge;

fn main() {
    // Fast-path: headless stdio bridge invoked by `agy-dial-wsl` inside WSL2.
    if std::env::args().any(|a| a == "--wsl-bridge") {
        if let Err(err) = wsl_bridge::run_bridge_client() {
            eprintln!("agy-dial bridge error: {err:#}");
            std::process::exit(1);
        }
        return;
    }

    let has_console = console::init();

    let mut logger_builder = pretty_env_logger::formatted_timed_builder();
    if let Ok(filters) = std::env::var("RUST_LOG") {
        logger_builder.parse_filters(&filters);
    } else {
        logger_builder.filter_level(log::LevelFilter::Info);
    }
    logger_builder.init();

    if let Err(err) = do_main() {
        log::error!("Fatal error: {err}");
        for cause in err.chain().skip(1) {
            log::error!("Caused by: {cause}");
        }
        if !has_console {
            tray::show_error_box("agy-dial - Error", &format!("{err:#}"));
        }
        std::process::exit(1);
    }
}

fn do_main() -> anyhow::Result<()> {
    log::info!("Starting agy-dial v{}", env!("CARGO_PKG_VERSION"));

    // Default to only attaching to newly launched agy.exe instances (pass --all
    // to hook existing ones).
    let attach_all = std::env::args().any(|a| a == "--all");

    let agy_exe = models::find_agy_exe()?;
    log::info!("Found agy.exe: {}", agy_exe.display());

    let dll_path = injector::find_hook_dll()?;
    log::info!("Found hook DLL: {}", dll_path.display());

    let symbols = gosym::resolve_agy_symbols(&agy_exe)?;
    log::info!(
        "Resolved Go symbols: SetCycleMode=0x{:08x}, SetSelectedModel=0x{:08x}",
        symbols.set_cycle_mode_rva,
        symbols.set_selected_model_rva
    );

    let cfg = config::Config::load();
    let all_families = models::fetch_model_families(&agy_exe)?;
    log::info!(
        "Loaded {} model families from `agy models`:",
        all_families.len()
    );
    for fam in &all_families {
        let tiers: Vec<&str> = fam
            .variants
            .iter()
            .map(|v| {
                if v.tier.is_empty() {
                    v.label.as_str()
                } else {
                    v.tier.as_str()
                }
            })
            .collect();
        let state = if cfg.is_enabled(&fam.name) {
            "enabled"
        } else {
            "disabled"
        };
        log::info!("  {} ({state}): [{}]", fam.name, tiers.join(", "));
    }

    let ignored_pids: HashSet<u32> = if attach_all {
        log::info!("--all set; attaching to all running and new agy.exe instances.");
        HashSet::new()
    } else {
        let existing: HashSet<u32> = injector::enumerate_agy_pids().into_iter().collect();
        if !existing.is_empty() {
            log::info!(
                "Ignoring pre-existing agy.exe PIDs: {existing:?} (pass --all to hook them)"
            );
        }
        existing
    };

    let catalog = Arc::new(Mutex::new(injector::ModelCatalog {
        all_families,
        config: cfg,
    }));
    let wsl_clients = Arc::new(Mutex::new(wsl_bridge::WslClients::new()));

    let running = Arc::new(AtomicBool::new(true));
    let refresh_requested = Arc::new(AtomicBool::new(false));
    let families_dirty = Arc::new(AtomicBool::new(false));
    let win_attached_count = Arc::new(AtomicUsize::new(0));
    let wsl_attached_count = Arc::new(AtomicUsize::new(0));

    let hwnd = tray::run_tray_ui(
        running.clone(),
        refresh_requested.clone(),
        families_dirty.clone(),
        win_attached_count.clone(),
        wsl_attached_count.clone(),
        catalog.clone(),
    )?;
    let hwnd_raw = hwnd.0 as usize;

    // Spawn WSL2 control-plane named pipe server thread.
    let wsl_server_handle = {
        let catalog_bg = catalog.clone();
        let clients_bg = wsl_clients.clone();
        let wsl_count_bg = wsl_attached_count.clone();
        let running_bg = running.clone();
        std::thread::spawn(move || {
            wsl_bridge::run_control_server(
                catalog_bg,
                clients_bg,
                wsl_count_bg,
                running_bg,
                move || tray::post_status_update(hwnd_raw),
            );
        })
    };

    // Spawn Windows agy.exe watcher & DLL injector thread.
    let watcher_handle = {
        let running_bg = running.clone();
        let refresh_bg = refresh_requested.clone();
        let dirty_bg = families_dirty.clone();
        let win_count_bg = win_attached_count.clone();
        let wsl_count_bg = wsl_attached_count.clone();
        let catalog_bg = catalog.clone();
        let clients_bg = wsl_clients.clone();
        std::thread::spawn(move || {
            injector::run_watcher_loop(
                agy_exe,
                dll_path,
                symbols,
                catalog_bg,
                clients_bg,
                ignored_pids,
                running_bg,
                refresh_bg,
                dirty_bg,
                win_count_bg,
                wsl_count_bg,
                move || tray::post_status_update(hwnd_raw),
            );
        })
    };

    log::info!("agy-dial running in system tray. Entering message pump...");
    tray::run_message_pump();

    log::info!("Message pump exited. Stopping watcher, WSL server, and unpatching...");
    running.store(false, Ordering::Relaxed);
    wsl_bridge::wake_control_server();
    if let Err(e) = watcher_handle.join() {
        log::warn!("Watcher thread join failed: {e:?}");
    }
    if let Err(e) = wsl_server_handle.join() {
        log::warn!("WSL control server thread join failed: {e:?}");
    }

    log::info!("agy-dial terminated cleanly.");
    Ok(())
}
