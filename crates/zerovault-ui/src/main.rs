#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let _ctx: tauri::Context<tauri::Wry> = tauri::generate_context!();
    println!("zerovault-ui wave-0 stub");
}
