use serde::{Deserialize, Serialize};
use std::mem::zeroed;
use std::ptr::null_mut;
use std::thread;
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
};

use crate::win32_metrics::{
    qpc_elapsed_ms, qpc_now, sample_current_process_memory, ProcessMemorySnapshot,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrayBenchResult {
    pub mode: String,
    pub binary_role: String,
    pub closed_window_ui_process_rss_bytes: u64,
    pub tray_init_ms: f64,
    pub settle_duration_ms: u64,
    pub memory: ProcessMemorySnapshot,
}

fn generate_vault_rgba_icon(width: u32, height: u32) -> Vec<u8> {
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    let cx = width as f32 / 2.0;
    let cy = height as f32 / 2.0;
    for y in 0..height {
        for x in 0..width {
            let dx = (x as f32 + 0.5) - cx;
            let dy = (y as f32 + 0.5) - cy;
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= 14.5 {
                if dist >= 11.5 {
                    rgba.extend_from_slice(&[16, 185, 129, 255]); // Emerald ring
                } else if dist <= 4.5 {
                    rgba.extend_from_slice(&[56, 189, 248, 255]); // Cyan core
                } else {
                    rgba.extend_from_slice(&[15, 23, 42, 255]); // Dark slate body
                }
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    rgba
}

pub fn run_tray_benchmark(binary_role: &str, settle_ms: u64, interactive_loop: bool) -> Result<TrayBenchResult, String> {
    let start_qpc = qpc_now();

    let icon_rgba = generate_vault_rgba_icon(32, 32);
    let icon = Icon::from_rgba(icon_rgba, 32, 32)
        .map_err(|e| format!("Failed creating RGBA tray icon: {e}"))?;

    let menu = Menu::new();
    let item_open = MenuItem::new("Open ZeroVault Status & Settings", true, None);
    let item_lock = MenuItem::new("Lock Vault (Z:\\ZeroVault)", true, None);
    let item_quit = MenuItem::new("Quit ZeroVault Tray Helper", true, None);
    let _ = menu.append(&item_open);
    let _ = menu.append(&item_lock);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&item_quit);

    let quit_id = item_quit.id().clone();

    let tray_icon = TrayIconBuilder::new()
        .with_tooltip("ZeroVault Native Daemon • Z:\\ZeroVault (Unlocked)")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()
        .map_err(|e| format!("TrayIconBuilder failed: {e}"))?;

    let init_qpc = qpc_now();
    let tray_init_ms = qpc_elapsed_ms(start_qpc, init_qpc);

    let deadline = Instant::now() + Duration::from_millis(settle_ms);
    loop {
        unsafe {
            let mut msg: MSG = zeroed();
            while PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        while let Ok(_ev) = TrayIconEvent::receiver().try_recv() {}
        while let Ok(mev) = MenuEvent::receiver().try_recv() {
            if mev.id == quit_id {
                drop(tray_icon);
                let mem = sample_current_process_memory();
                return Ok(TrayBenchResult {
                    mode: "bench-tray".to_owned(),
                    binary_role: binary_role.to_owned(),
                    closed_window_ui_process_rss_bytes: 0,
                    tray_init_ms,
                    settle_duration_ms: settle_ms,
                    memory: mem,
                });
            }
        }

        if !interactive_loop && Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Sample resident Win32 memory WHILE tray icon & Shell_NotifyIconW resources are active.
    let mem = sample_current_process_memory();
    drop(tray_icon);

    Ok(TrayBenchResult {
        mode: "bench-tray".to_owned(),
        binary_role: binary_role.to_owned(),
        closed_window_ui_process_rss_bytes: 0,
        tray_init_ms,
        settle_duration_ms: settle_ms,
        memory: mem,
    })
}
