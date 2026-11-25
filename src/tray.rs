//! System tray notification area icon, context menu, and Win32 message pump.

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use windows::Win32::Foundation::COLORREF;
use windows::Win32::Foundation::HWND;
use windows::Win32::Foundation::LPARAM;
use windows::Win32::Foundation::LRESULT;
use windows::Win32::Foundation::POINT;
use windows::Win32::Foundation::RECT;
use windows::Win32::Foundation::WPARAM;
use windows::Win32::Graphics::Gdi::ANTIALIASED_QUALITY;
use windows::Win32::Graphics::Gdi::BI_RGB;
use windows::Win32::Graphics::Gdi::BITMAPINFO;
use windows::Win32::Graphics::Gdi::BITMAPINFOHEADER;
use windows::Win32::Graphics::Gdi::CLIP_DEFAULT_PRECIS;
use windows::Win32::Graphics::Gdi::CreateBitmap;
use windows::Win32::Graphics::Gdi::CreateCompatibleDC;
use windows::Win32::Graphics::Gdi::CreateDIBSection;
use windows::Win32::Graphics::Gdi::CreateFontW;
use windows::Win32::Graphics::Gdi::DEFAULT_CHARSET;
use windows::Win32::Graphics::Gdi::DEFAULT_PITCH;
use windows::Win32::Graphics::Gdi::DIB_RGB_COLORS;
use windows::Win32::Graphics::Gdi::DT_CENTER;
use windows::Win32::Graphics::Gdi::DT_SINGLELINE;
use windows::Win32::Graphics::Gdi::DT_VCENTER;
use windows::Win32::Graphics::Gdi::DeleteDC;
use windows::Win32::Graphics::Gdi::DeleteObject;
use windows::Win32::Graphics::Gdi::DrawTextW;
use windows::Win32::Graphics::Gdi::FF_DONTCARE;
use windows::Win32::Graphics::Gdi::FW_NORMAL;
use windows::Win32::Graphics::Gdi::OUT_TT_PRECIS;
use windows::Win32::Graphics::Gdi::SelectObject;
use windows::Win32::Graphics::Gdi::SetBkMode;
use windows::Win32::Graphics::Gdi::SetTextColor;
use windows::Win32::Graphics::Gdi::TRANSPARENT;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::NIF_ICON;
use windows::Win32::UI::Shell::NIF_MESSAGE;
use windows::Win32::UI::Shell::NIF_TIP;
use windows::Win32::UI::Shell::NIM_ADD;
use windows::Win32::UI::Shell::NIM_DELETE;
use windows::Win32::UI::Shell::NIM_MODIFY;
use windows::Win32::UI::Shell::NOTIFYICONDATAW;
use windows::Win32::UI::Shell::Shell_NotifyIconW;
use windows::Win32::UI::WindowsAndMessaging::AppendMenuW;
use windows::Win32::UI::WindowsAndMessaging::CW_USEDEFAULT;
use windows::Win32::UI::WindowsAndMessaging::CreateIconIndirect;
use windows::Win32::UI::WindowsAndMessaging::CreatePopupMenu;
use windows::Win32::UI::WindowsAndMessaging::CreateWindowExW;
use windows::Win32::UI::WindowsAndMessaging::DefWindowProcW;
use windows::Win32::UI::WindowsAndMessaging::DestroyIcon;
use windows::Win32::UI::WindowsAndMessaging::DestroyMenu;
use windows::Win32::UI::WindowsAndMessaging::DestroyWindow;
use windows::Win32::UI::WindowsAndMessaging::DispatchMessageW;
use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
use windows::Win32::UI::WindowsAndMessaging::GetMessageW;
use windows::Win32::UI::WindowsAndMessaging::GetSystemMetrics;
use windows::Win32::UI::WindowsAndMessaging::HICON;
use windows::Win32::UI::WindowsAndMessaging::ICONINFO;
use windows::Win32::UI::WindowsAndMessaging::IDI_APPLICATION;
use windows::Win32::UI::WindowsAndMessaging::LoadIconW;
use windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR;
use windows::Win32::UI::WindowsAndMessaging::MB_OK;
use windows::Win32::UI::WindowsAndMessaging::MF_CHECKED;
use windows::Win32::UI::WindowsAndMessaging::MF_DISABLED;
use windows::Win32::UI::WindowsAndMessaging::MF_GRAYED;
use windows::Win32::UI::WindowsAndMessaging::MF_SEPARATOR;
use windows::Win32::UI::WindowsAndMessaging::MF_STRING;
use windows::Win32::UI::WindowsAndMessaging::MF_UNCHECKED;
use windows::Win32::UI::WindowsAndMessaging::MSG;
use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
use windows::Win32::UI::WindowsAndMessaging::PostMessageW;
use windows::Win32::UI::WindowsAndMessaging::PostQuitMessage;
use windows::Win32::UI::WindowsAndMessaging::RegisterClassExW;
use windows::Win32::UI::WindowsAndMessaging::RegisterWindowMessageW;
use windows::Win32::UI::WindowsAndMessaging::SM_CXSMICON;
use windows::Win32::UI::WindowsAndMessaging::SM_CYSMICON;
use windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow;
use windows::Win32::UI::WindowsAndMessaging::TPM_BOTTOMALIGN;
use windows::Win32::UI::WindowsAndMessaging::TPM_RIGHTBUTTON;
use windows::Win32::UI::WindowsAndMessaging::TrackPopupMenuEx;
use windows::Win32::UI::WindowsAndMessaging::TranslateMessage;
use windows::Win32::UI::WindowsAndMessaging::WM_CLOSE;
use windows::Win32::UI::WindowsAndMessaging::WM_COMMAND;
use windows::Win32::UI::WindowsAndMessaging::WM_DESTROY;
use windows::Win32::UI::WindowsAndMessaging::WM_ENDSESSION;
use windows::Win32::UI::WindowsAndMessaging::WM_NULL;
use windows::Win32::UI::WindowsAndMessaging::WM_QUERYENDSESSION;
use windows::Win32::UI::WindowsAndMessaging::WM_RBUTTONUP;
use windows::Win32::UI::WindowsAndMessaging::WM_USER;
use windows::Win32::UI::WindowsAndMessaging::WNDCLASSEXW;
use windows::Win32::UI::WindowsAndMessaging::WS_EX_TOOLWINDOW;
use windows::Win32::UI::WindowsAndMessaging::WS_POPUP;
use windows::core::BOOL;
use windows::core::PCWSTR;
use windows::core::w;

use crate::autostart::is_autostart_enabled;
use crate::autostart::set_autostart_enabled;
use crate::injector::ModelCatalog;

const WM_TRAY_CALLBACK: u32 = WM_USER + 101;
/// Custom message posted by the watcher thread to refresh tray icon and
/// tooltip.
pub const WM_UPDATE_STATUS: u32 = WM_USER + 102;

const CMD_TITLE: usize = 2001;
const CMD_STATUS: usize = 2002;
const CMD_REFRESH: usize = 2003;
const CMD_AUTOSTART: usize = 2004;
const CMD_EXIT: usize = 2005;
const CMD_MODEL_BASE: usize = 3000;

struct TrayState {
    active_icon: HICON,
    idle_icon: HICON,
    running: Arc<AtomicBool>,
    refresh_requested: Arc<AtomicBool>,
    families_dirty: Arc<AtomicBool>,
    win_attached_count: Arc<AtomicUsize>,
    wsl_attached_count: Arc<AtomicUsize>,
    catalog: Arc<Mutex<ModelCatalog>>,
    taskbar_created_msg: u32,
}

// SAFETY: `HICON` handles are thread-safe Win32 resource pointers for read
// access.
unsafe impl Send for TrayState {}
// SAFETY: `HICON` handles are thread-safe Win32 resource pointers for read
// access.
unsafe impl Sync for TrayState {}

static TRAY_STATE: OnceLock<TrayState> = OnceLock::new();

/// Unicode codepoint for the native Windows 11 `Wheel` (Surface Dial) glyph in
/// `Segoe Fluent Icons` / `Segoe MDL2 Assets`.
const SEGOE_WHEEL_GLYPH: u16 = 0xEE94;

/// Pre-rasterized 24x24 straight-alpha RGBA Antigravity logo badge.
const AGY_BADGE_SIZE: usize = 24;
const AGY_BADGE_RGBA: &[u8] = include_bytes!("../assets/agy_badge_24x24.rgba");

fn sample_badge_bilinear(u: f32, v: f32) -> (f32, f32, f32, f32) {
    let max_coord = (AGY_BADGE_SIZE - 1) as f32;
    let fx = (u * max_coord).clamp(0.0, max_coord);
    let fy = (v * max_coord).clamp(0.0, max_coord);
    let x0 = fx.floor() as usize;
    let y0 = fy.floor() as usize;
    let x1 = (x0 + 1).min(AGY_BADGE_SIZE - 1);
    let y1 = (y0 + 1).min(AGY_BADGE_SIZE - 1);
    let tx = fx - x0 as f32;
    let ty = fy - y0 as f32;

    let fetch = |x: usize, y: usize| -> (f32, f32, f32, f32) {
        let i = (y * AGY_BADGE_SIZE + x) * 4;
        let a = f32::from(AGY_BADGE_RGBA[i + 3]) / 255.0;
        let r = f32::from(AGY_BADGE_RGBA[i]) / 255.0 * a;
        let g = f32::from(AGY_BADGE_RGBA[i + 1]) / 255.0 * a;
        let b = f32::from(AGY_BADGE_RGBA[i + 2]) / 255.0 * a;
        (r, g, b, a)
    };

    let c00 = fetch(x0, y0);
    let c10 = fetch(x1, y0);
    let c01 = fetch(x0, y1);
    let c11 = fetch(x1, y1);

    let lerp = |a: f32, b: f32, t: f32| (b - a).mul_add(t, a);
    let r = lerp(lerp(c00.0, c10.0, tx), lerp(c01.0, c11.0, tx), ty);
    let g = lerp(lerp(c00.1, c10.1, tx), lerp(c01.1, c11.1, tx), ty);
    let b = lerp(lerp(c00.2, c10.2, tx), lerp(c01.2, c11.2, tx), ty);
    let a = lerp(lerp(c00.3, c10.3, tx), lerp(c01.3, c11.3, tx), ty);
    (r, g, b, a)
}

fn overlay_agy_badge(pixels: &mut [u32], w: i32, h: i32, active: bool) {
    let badge_w = w;
    let badge_h = h;
    let x0 = 0;
    let y0 = 0;

    for by in 0..badge_h {
        let v = (by as f32 + 0.5) / badge_h as f32;
        for bx in 0..badge_w {
            let u = (bx as f32 + 0.5) / badge_w as f32;
            let (mut sr, mut sg, mut sb, sa) = sample_badge_bilinear(u, v);
            if sa <= 0.001 {
                continue;
            }

            if !active {
                // Slightly dim/desaturate badge when idle so active vs idle
                // stays clear.
                let luma = sr.mul_add(0.299, sg.mul_add(0.587, sb * 0.114));
                sr = (sr - luma).mul_add(0.45, luma) * 0.78;
                sg = (sg - luma).mul_add(0.45, luma) * 0.78;
                sb = (sb - luma).mul_add(0.45, luma) * 0.78;
            }

            let idx = ((y0 + by) * w + (x0 + bx)) as usize;
            let dst = pixels[idx];
            let da = ((dst >> 24) & 0xFF) as f32 / 255.0;
            let dr = ((dst >> 16) & 0xFF) as f32 / 255.0;
            let dg = ((dst >> 8) & 0xFF) as f32 / 255.0;
            let db = (dst & 0xFF) as f32 / 255.0;

            // Premultiplied source-over compositing
            let inv_sa = 1.0 - sa;
            let oa = da.mul_add(inv_sa, sa);
            let or = dr.mul_add(inv_sa, sr);
            let og = dg.mul_add(inv_sa, sg);
            let ob = db.mul_add(inv_sa, sb);

            let a8 = (oa * 255.0).round().clamp(0.0, 255.0) as u32;
            let r8 = (or * 255.0).round().clamp(0.0, 255.0) as u32;
            let g8 = (og * 255.0).round().clamp(0.0, 255.0) as u32;
            let b8 = (ob * 255.0).round().clamp(0.0, 255.0) as u32;
            pixels[idx] = (a8 << 24) | (r8 << 16) | (g8 << 8) | b8;
        }
    }
}

/// Renders the native Windows 11 `Segoe Fluent Icons` Wheel glyph (`U+EE94`)
/// onto a 32-bit premultiplied BGRA DIB section with smooth anti-aliased alpha.
fn create_dial_icon(active: bool) -> HICON {
    // SAFETY: Querying system small icon metrics for High-DPI support.
    let w = unsafe { GetSystemMetrics(SM_CXSMICON) }.max(32);
    // SAFETY: Querying system small icon metrics for High-DPI support.
    let h = unsafe { GetSystemMetrics(SM_CYSMICON) }.max(32);

    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h, // top-down DIB
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut bits_ptr: *mut c_void = std::ptr::null_mut();
    // SAFETY: Creating a 32bpp top-down BGRA DIB section for smooth alpha
    // blending.
    let hbm_color = unsafe { CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0) };

    let Ok(hbm_color) = hbm_color else {
        // SAFETY: Fallback to standard system application icon.
        return unsafe { LoadIconW(None, IDI_APPLICATION).unwrap_or_default() };
    };

    if !bits_ptr.is_null() {
        // SAFETY: Rendering the Segoe Fluent Icons `Wheel` glyph in white onto
        // a zeroed DIB, then converting GDI grayscale coverage into
        // premultiplied BGRA alpha.
        unsafe {
            let pixels = std::slice::from_raw_parts_mut(bits_ptr.cast::<u32>(), (w * h) as usize);
            pixels.fill(0);

            let hdc = CreateCompatibleDC(None);
            if !hdc.is_invalid() {
                let old_bmp = SelectObject(hdc, hbm_color.into());
                let font_height = -((h * 88) / 100);
                let hfont = CreateFontW(
                    font_height,
                    0,
                    0,
                    0,
                    FW_NORMAL.0 as i32,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET,
                    OUT_TT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    ANTIALIASED_QUALITY,
                    u32::from(DEFAULT_PITCH.0 | FF_DONTCARE.0),
                    w!("Segoe Fluent Icons"),
                );

                let old_font = if !hfont.is_invalid() {
                    Some(SelectObject(hdc, hfont.into()))
                } else {
                    None
                };

                let _ = SetBkMode(hdc, TRANSPARENT);
                let _ = SetTextColor(hdc, COLORREF(0x00FF_FFFF));
                let mut glyph = [SEGOE_WHEEL_GLYPH];
                let mut rc = RECT {
                    left: 0,
                    top: 0,
                    right: w,
                    bottom: h,
                };
                let _ = DrawTextW(
                    hdc,
                    &mut glyph,
                    &mut rc,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );

                if let Some(prev) = old_font {
                    let _ = SelectObject(hdc, prev);
                }
                if !hfont.is_invalid() {
                    let _ = DeleteObject(hfont.into());
                }
                let _ = SelectObject(hdc, old_bmp);
                let _ = DeleteDC(hdc);
            }

            // Convert grayscale coverage in B channel into premultiplied BGRA.
            // Active: crisp white (matches Windows 11 taskbar icons); Idle:
            // muted gray.
            let (tr, tg, tb): (u32, u32, u32) = if active {
                (255, 255, 255)
            } else {
                (145, 150, 158)
            };
            for px in pixels.iter_mut() {
                let alpha = *px & 0xFF;
                if alpha == 0 {
                    *px = 0;
                } else {
                    let r = (tr * alpha + 127) / 255;
                    let g = (tg * alpha + 127) / 255;
                    let b = (tb * alpha + 127) / 255;
                    *px = (alpha << 24) | (r << 16) | (g << 8) | b;
                }
            }

            overlay_agy_badge(pixels, w, h, active);
        }
    }

    // All-zero 1bpp mask tells Windows to use the 32bpp DIB's alpha channel
    // exclusively.
    let bytes_per_row = (((w + 15) / 16) * 2) as usize;
    let mask_bits = vec![0u8; bytes_per_row * (h as usize)];
    // SAFETY: Creating 1bpp mask bitmap for `CreateIconIndirect`.
    let hbm_mask = unsafe { CreateBitmap(w, h, 1, 1, Some(mask_bits.as_ptr().cast())) };

    let icon = if !hbm_mask.is_invalid() {
        let icon_info = ICONINFO {
            fIcon: BOOL(1),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: hbm_mask,
            hbmColor: hbm_color,
        };
        // SAFETY: Assembling 32-bit alpha-blended HICON from DIB and mask.
        unsafe { CreateIconIndirect(&icon_info) }.ok()
    } else {
        None
    };

    // SAFETY: Cleaning up temporary GDI bitmaps.
    unsafe {
        if !hbm_mask.is_invalid() {
            let _ = DeleteObject(hbm_mask.into());
        }
        let _ = DeleteObject(hbm_color.into());
    }

    if let Some(icon) = icon {
        return icon;
    }

    // SAFETY: Fallback to standard system application icon.
    unsafe { LoadIconW(None, IDI_APPLICATION).unwrap_or_default() }
}

fn format_status(win: usize, wsl: usize) -> String {
    match (win, wsl) {
        (0, 0) => "Attached: 0".to_owned(),
        (n, 0) => format!("Attached: {n} Win"),
        (0, m) => format!("Attached: {m} WSL"),
        (n, m) => format!("Attached: {} ({n} Win, {m} WSL)", n + m),
    }
}

fn format_tooltip(win: usize, wsl: usize) -> String {
    match (win, wsl) {
        (0, 0) => "agy-dial - Watching for agy".to_owned(),
        _ => format!("agy-dial - {}", format_status(win, wsl)),
    }
}

fn create_notify_icon_data(hwnd: HWND, icon: HICON, tooltip: &str) -> NOTIFYICONDATAW {
    let mut nid = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: WM_TRAY_CALLBACK,
        hIcon: icon,
        ..Default::default()
    };

    for (i, c) in tooltip.encode_utf16().take(127).enumerate() {
        nid.szTip[i] = c;
    }

    nid
}

unsafe extern "system" fn tray_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let Some(state) = TRAY_STATE.get() else {
        // SAFETY: Forwarding to default window procedure if state not yet
        // initialized.
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    };

    if msg == state.taskbar_created_msg {
        let win = state.win_attached_count.load(Ordering::Relaxed);
        let wsl = state.wsl_attached_count.load(Ordering::Relaxed);
        let icon = if win + wsl > 0 {
            state.active_icon
        } else {
            state.idle_icon
        };
        let tip = format_tooltip(win, wsl);
        let nid = create_notify_icon_data(hwnd, icon, &tip);
        // SAFETY: Re-adding tray icon when Windows Shell restarts the taskbar.
        let _ = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
        return LRESULT(0);
    }

    match msg {
        WM_TRAY_CALLBACK => {
            let event = lparam.0 as u32;
            if event == WM_RBUTTONUP {
                let mut pt = POINT::default();
                // SAFETY: Retrieving cursor position for popup menu placement.
                let _ = unsafe { GetCursorPos(&mut pt) };

                // SAFETY: Constructing Win32 context popup menu.
                let Ok(hmenu) = (unsafe { CreatePopupMenu() }) else {
                    return LRESULT(0);
                };

                let win = state.win_attached_count.load(Ordering::Relaxed);
                let wsl = state.wsl_attached_count.load(Ordering::Relaxed);
                let autostart = is_autostart_enabled();

                let status_text: Vec<u16> = format_status(win, wsl)
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let autostart_flags = if autostart { MF_CHECKED } else { MF_UNCHECKED } | MF_STRING;

                // Snapshot model names & checked states for the Models submenu.
                let model_items: Vec<(String, bool)> = state
                    .catalog
                    .lock()
                    .map(|cat| {
                        cat.all_families
                            .iter()
                            .map(|f| (f.name.clone(), cat.config.is_enabled(&f.name)))
                            .collect()
                    })
                    .unwrap_or_default();

                // SAFETY: Building popup menu and optional Models submenu.
                unsafe {
                    let _ = AppendMenuW(
                        hmenu,
                        MF_STRING | MF_GRAYED | MF_DISABLED,
                        CMD_TITLE,
                        w!("agy-dial"),
                    );
                    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());
                    let _ = AppendMenuW(
                        hmenu,
                        MF_STRING | MF_GRAYED | MF_DISABLED,
                        CMD_STATUS,
                        PCWSTR::from_raw(status_text.as_ptr()),
                    );
                    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());

                    if !model_items.is_empty() {
                        for (idx, (name, enabled)) in model_items.iter().enumerate() {
                            let flags =
                                if *enabled { MF_CHECKED } else { MF_UNCHECKED } | MF_STRING;
                            let wide: Vec<u16> =
                                name.encode_utf16().chain(std::iter::once(0)).collect();
                            let _ = AppendMenuW(
                                hmenu,
                                flags,
                                CMD_MODEL_BASE + idx,
                                PCWSTR::from_raw(wide.as_ptr()),
                            );
                        }
                        let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());
                    }

                    let _ = AppendMenuW(hmenu, MF_STRING, CMD_REFRESH, w!("Refresh Models"));
                    let _ = AppendMenuW(hmenu, autostart_flags, CMD_AUTOSTART, w!("Start on Boot"));
                    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, PCWSTR::null());
                    let _ = AppendMenuW(hmenu, MF_STRING, CMD_EXIT, w!("Exit"));

                    let _ = SetForegroundWindow(hwnd);
                    let _ = TrackPopupMenuEx(
                        hmenu,
                        (TPM_BOTTOMALIGN | TPM_RIGHTBUTTON).0,
                        pt.x,
                        pt.y,
                        hwnd,
                        None,
                    );
                    let _ = PostMessageW(Some(hwnd), WM_NULL, WPARAM(0), LPARAM(0));
                    let _ = DestroyMenu(hmenu);
                }
            }
            LRESULT(0)
        }
        WM_UPDATE_STATUS => {
            let win = state.win_attached_count.load(Ordering::Relaxed);
            let wsl = state.wsl_attached_count.load(Ordering::Relaxed);
            let icon = if win + wsl > 0 {
                state.active_icon
            } else {
                state.idle_icon
            };
            let tip = format_tooltip(win, wsl);
            let nid = create_notify_icon_data(hwnd, icon, &tip);
            // SAFETY: Updating tray icon image and tooltip.
            let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &nid) };
            LRESULT(0)
        }
        WM_COMMAND => {
            match wparam.0 {
                CMD_REFRESH => {
                    state.refresh_requested.store(true, Ordering::Release);
                }
                CMD_AUTOSTART => {
                    let currently_enabled = is_autostart_enabled();
                    if let Err(e) = set_autostart_enabled(!currently_enabled) {
                        log::error!("Failed to toggle autostart: {e}");
                    } else {
                        log::info!("Toggled autostart to: {}", !currently_enabled);
                    }
                }
                CMD_EXIT => {
                    // SAFETY: Posting close message to tray window.
                    unsafe {
                        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
                    }
                }
                id if id >= CMD_MODEL_BASE => {
                    let idx = id - CMD_MODEL_BASE;
                    if let Ok(mut cat) = state.catalog.lock() {
                        if let Some(name) = cat.all_families.get(idx).map(|f| f.name.clone()) {
                            let now_enabled = cat.config.toggle_family(&name);
                            log::info!(
                                "Toggled model '{name}' -> {}",
                                if now_enabled { "enabled" } else { "disabled" }
                            );
                            state.families_dirty.store(true, Ordering::Release);
                        }
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_QUERYENDSESSION => LRESULT(1),
        WM_ENDSESSION => {
            if wparam.0 != 0 {
                state.running.store(false, Ordering::Relaxed);
                let nid = create_notify_icon_data(hwnd, state.idle_icon, "");
                // SAFETY: Deleting tray notification icon on system shutdown.
                let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
                // SAFETY: Destroying tray window.
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            state.running.store(false, Ordering::Relaxed);
            let nid = create_notify_icon_data(hwnd, state.idle_icon, "");
            // SAFETY: Deleting tray notification icon.
            let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
            // SAFETY: Destroying tray window.
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: Quitting Win32 message loop.
            unsafe {
                PostQuitMessage(0);
            }
            LRESULT(0)
        }
        _ => {
            // SAFETY: Passing unhandled messages to default window procedure.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

/// Creates the hidden Win32 tray window and adds the notification area icon.
pub fn run_tray_ui(
    running: Arc<AtomicBool>,
    refresh_requested: Arc<AtomicBool>,
    families_dirty: Arc<AtomicBool>,
    win_attached_count: Arc<AtomicUsize>,
    wsl_attached_count: Arc<AtomicUsize>,
    catalog: Arc<Mutex<ModelCatalog>>,
) -> anyhow::Result<HWND> {
    // SAFETY: Obtaining application module instance handle.
    let hinstance = unsafe { GetModuleHandleW(None)? };

    let class_name = w!("AgyDialTrayClass");
    let wnd_class = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(tray_window_proc),
        hInstance: hinstance.into(),
        lpszClassName: class_name,
        ..Default::default()
    };

    // SAFETY: Registering window class for hidden tray message window.
    let atom = unsafe { RegisterClassExW(&wnd_class) };
    if atom == 0 {
        anyhow::bail!("Failed to register tray window class");
    }

    // SAFETY: Creating hidden message window for shell notifications.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class_name,
            w!("AgyDialTrayWindow"),
            WS_POPUP,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            None,
            None,
            Some(hinstance.into()),
            None,
        )?
    };

    let active_icon = create_dial_icon(true);
    let idle_icon = create_dial_icon(false);
    // SAFETY: Registering for Windows `TaskbarCreated` notification.
    let taskbar_created_msg = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };

    let state = TrayState {
        active_icon,
        idle_icon,
        running,
        refresh_requested,
        families_dirty,
        win_attached_count,
        wsl_attached_count,
        catalog,
        taskbar_created_msg,
    };
    let _ = TRAY_STATE.set(state);

    let nid = create_notify_icon_data(hwnd, idle_icon, &format_tooltip(0, 0));
    // SAFETY: Adding tray icon to notification area.
    unsafe {
        let _ = Shell_NotifyIconW(NIM_ADD, &nid);
    }

    Ok(hwnd)
}

/// Runs the standard Win32 message pump until exit.
pub fn run_message_pump() {
    let mut msg = MSG::default();
    // SAFETY: Standard Win32 message loop retrieving messages for the current
    // thread.
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.into() {
        // SAFETY: Translating and dispatching Win32 messages.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if let Some(state) = TRAY_STATE.get() {
        // SAFETY: Destroying custom icons on exit.
        unsafe {
            let _ = DestroyIcon(state.active_icon);
            let _ = DestroyIcon(state.idle_icon);
        }
    }
}

/// Displays a modal error message box (useful when launched without a console).
pub fn show_error_box(title: &str, message: &str) {
    let wide_title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_msg: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: Displaying standard Win32 modal error dialog.
    unsafe {
        MessageBoxW(
            None,
            PCWSTR::from_raw(wide_msg.as_ptr()),
            PCWSTR::from_raw(wide_title.as_ptr()),
            MB_ICONERROR | MB_OK,
        );
    }
}

/// Posts a status refresh notification to the tray window from any thread.
pub fn post_status_update(hwnd_raw: usize) {
    let hwnd = HWND(hwnd_raw as *mut c_void);
    // SAFETY: Posting status update message to the tray window handle.
    unsafe {
        let _ = PostMessageW(Some(hwnd), WM_UPDATE_STATUS, WPARAM(0), LPARAM(0));
    }
}
