#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod backend;
mod result_store;
mod system_scan;

use std::sync::Arc;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(backend::DesktopState::default()))
        .invoke_handler(tauri::generate_handler![
            backend::choose_path,
            backend::clear_override,
            backend::start_scan,
            backend::export_report,
            system_scan::list_scan_drives,
            system_scan::start_system_scan,
            system_scan::system_scan_status,
            system_scan::cancel_system_scan,
            system_scan::system_scan_page,
            system_scan::system_scan_detail,
            system_scan::export_system_scan,
        ])
        .run(tauri::generate_context!())
        .expect("Unable to start Sentinel desktop");
}
