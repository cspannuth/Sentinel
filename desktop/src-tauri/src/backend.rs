//! Thin desktop boundary: native paths stay in Rust, and the engine owns all findings.
use std::{
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use sentinel::{ScanOptions, ScanReport};
use serde::Deserialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct Selection {
    target: Option<PathBuf>,
    options: ScanOptions,
    report: Option<Arc<ScanReport>>,
}

#[derive(Default)]
pub struct DesktopState {
    busy: AtomicBool,
    selection: Mutex<Selection>,
    pub(crate) system: Mutex<Option<Arc<crate::system_scan::SystemSession>>>,
}

// Own the guard inside the worker: dropping an IPC future cannot unlock an active scan.
pub(crate) struct Job(pub(crate) Arc<DesktopState>);
impl Drop for Job {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}
impl DesktopState {
    pub(crate) fn begin(self: &Arc<Self>) -> Result<Job, String> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "Another operation is still running.".to_string())?;
        Ok(Job(self.clone()))
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Selection>, String> {
        self.selection
            .lock()
            .map_err(|_| "Desktop state is unavailable. Restart Sentinel.".into())
    }
    pub(crate) fn scan_options(&self) -> Result<ScanOptions, String> {
        Ok(self.lock()?.options.clone())
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    File,
    Folder,
    Rules,
    Hashes,
}

#[tauri::command]
pub async fn choose_path(
    app: AppHandle,
    state: State<'_, Arc<DesktopState>>,
    kind: Choice,
) -> Result<Option<String>, String> {
    let job = state.begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let dialog = app.dialog().file();
        let picked = match kind {
            Choice::File => dialog
                .set_title("Choose a file to inspect")
                .blocking_pick_file(),
            Choice::Folder => dialog
                .set_title("Choose a folder to inspect")
                .blocking_pick_folder(),
            Choice::Rules => dialog
                .set_title("Choose a YARA rules folder")
                .blocking_pick_folder(),
            Choice::Hashes => dialog
                .set_title("Choose a hash database")
                .add_filter("JSON", &["json"])
                .blocking_pick_file(),
        };
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        let display = path.to_string_lossy().into_owned();
        let mut selection = job.0.lock()?;
        match kind {
            Choice::File | Choice::Folder => selection.target = Some(path),
            Choice::Rules => selection.options.rules_directory = Some(path),
            Choice::Hashes => selection.options.hash_database = Some(path),
        }
        Ok(Some(display))
    })
    .await
    .map_err(|e| format!("File dialog failed: {e}"))?
}

#[tauri::command]
pub fn clear_override(state: State<'_, Arc<DesktopState>>, kind: Choice) -> Result<(), String> {
    let job = state.begin()?;
    let mut selection = job.0.lock()?;
    match kind {
        Choice::Rules => selection.options.rules_directory = None,
        Choice::Hashes => selection.options.hash_database = None,
        _ => return Err("Only detection overrides can be cleared.".into()),
    }
    Ok(())
}

// Shared with tests; no Tauri or UI-specific scanning logic.
fn run_scan(state: &DesktopState) -> Result<serde_json::Value, String> {
    let (target, options) = {
        let mut selection = state.lock()?;
        let target = selection
            .target
            .clone()
            .ok_or("Choose a file or folder first.")?;
        selection.report = None;
        (target, selection.options.clone())
    };
    let report = Arc::new(sentinel::scan_with_options(target, &options));
    let response = serde_json::to_value(report.as_ref()).map_err(|e| e.to_string())?;
    state.lock()?.report = Some(report);
    Ok(response)
}

#[tauri::command]
pub async fn start_scan(state: State<'_, Arc<DesktopState>>) -> Result<serde_json::Value, String> {
    let job = state.begin()?;
    tauri::async_runtime::spawn_blocking(move || run_scan(&job.0))
        .await
        .map_err(|e| format!("Scan worker failed; no completed report is available: {e}"))?
}

// Never overwrite an existing file, including a scanned target or a symlink.
fn save_report(path: &Path, report: &ScanReport) -> Result<(), String> {
    let mut writer = new_report_writer(path)?;
    serde_json::to_writer_pretty(&mut writer, report).map_err(|e| e.to_string())?;
    writer
        .write_all(b"\n")
        .and_then(|_| writer.flush())
        .map_err(|e| format!("Export incomplete: {e}"))
}

pub(crate) fn new_report_writer(path: &Path) -> Result<BufWriter<fs::File>, String> {
    validate_export_path(path)?;
    // Inspect ancestors from the root before reaching a possibly linked child.
    let mut ancestors: Vec<_> = path.ancestors().skip(1).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if is_link(&metadata) {
            return Err("Choose an export folder without links or reparse points.".into());
        }
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Cannot create report (choose a new filename): {e}"))?;
    Ok(BufWriter::new(file))
}

fn validate_export_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return Err("Choose an absolute path with a .json extension.".into());
    }
    #[cfg(windows)]
    for component in path.components() {
        use std::path::{Component, Prefix};
        match component {
            Component::Prefix(prefix)
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::UNC(_, _)) =>
            {
                return Err("Device namespaces are not report destinations.".into());
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy().to_uppercase();
                let stem = name.split('.').next().unwrap_or("").trim_end();
                let numbered = ["COM", "LPT"].iter().any(|prefix| {
                    stem.strip_prefix(prefix).is_some_and(|suffix| {
                        matches!(
                            suffix,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                });
                if name.contains(':')
                    || name.ends_with(['.', ' '])
                    || numbered
                    || matches!(
                        stem,
                        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
                    )
                {
                    return Err(
                        "Device names and alternate data streams are not report destinations."
                            .into(),
                    );
                }
            }
            Component::ParentDir => {
                return Err("Choose a report path without parent-directory components.".into());
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[tauri::command]
pub async fn export_report(
    app: AppHandle,
    state: State<'_, Arc<DesktopState>>,
) -> Result<Option<String>, String> {
    let job = state.begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let report = job
            .0
            .lock()?
            .report
            .clone()
            .ok_or("Run a scan before exporting.")?;
        let picked = app
            .dialog()
            .file()
            .set_title("Export report to a new JSON file")
            .set_file_name("sentinel-report.json")
            .add_filter("JSON", &["json"])
            .blocking_save_file();
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        save_report(&path, &report)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|e| format!("Export failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_operation_at_a_time_and_guard_releases() {
        let state = Arc::new(DesktopState::default());
        let job = state.begin().unwrap();
        assert!(state.begin().is_err());
        drop(job);
        assert!(state.begin().is_ok());
    }
    #[test]
    fn desktop_returns_engine_results_and_exports_exact_report() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("marker with spaces é.txt");
        fs::write(&path, b"SENTINEL_TEST_SIGNATURE").unwrap();
        let state = DesktopState::default();
        state.lock().unwrap().target = Some(path.clone());
        let actual = run_scan(&state).unwrap();
        assert_eq!(actual, serde_json::to_value(sentinel::scan(path)).unwrap());
        assert_eq!(actual["verdict"], "test_match");
        let output = temp.path().join("report.json");
        save_report(&output, state.lock().unwrap().report.as_ref().unwrap()).unwrap();
        assert_eq!(
            actual,
            serde_json::from_slice::<serde_json::Value>(&fs::read(&output).unwrap()).unwrap()
        );
        assert!(save_report(&output, state.lock().unwrap().report.as_ref().unwrap()).is_err());
    }
    #[test]
    fn invalid_target_and_rules_are_not_clean_successes() {
        let temp = tempfile::tempdir().unwrap();
        let state = DesktopState::default();
        assert!(run_scan(&state).is_err());
        state.lock().unwrap().target = Some(temp.path().join("missing"));
        let report = run_scan(&state).unwrap();
        assert_eq!(report["status"], "failed");
        fs::write(temp.path().join("clean.txt"), b"hello").unwrap();
        state.lock().unwrap().target = Some(temp.path().to_owned());
        state.lock().unwrap().options.rules_directory = Some(temp.path().join("missing-rules"));
        let report = run_scan(&state).unwrap();
        assert_ne!(report["status"], "complete");
        assert_ne!(report["verdict"], "no_detections");
    }

    #[test]
    fn empty_folder_and_invalid_hash_override_remain_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let state = DesktopState::default();
        state.lock().unwrap().target = Some(temp.path().to_owned());
        let empty = run_scan(&state).unwrap();
        assert_eq!(empty["status"], "complete");
        assert_eq!(empty["files"], serde_json::json!([]));
        let marker = temp.path().join("marker.txt");
        fs::write(&marker, b"SENTINEL_TEST_SIGNATURE").unwrap();
        state.lock().unwrap().target = Some(marker.clone());
        state.lock().unwrap().options.hash_database = Some(temp.path().join("missing.json"));
        let partial = run_scan(&state).unwrap();
        assert_eq!(partial["status"], "partial");
        assert_eq!(partial["hash_database"]["status"], "failed");
        assert!(save_report(&marker, state.lock().unwrap().report.as_ref().unwrap()).is_err());
        assert_eq!(fs::read(marker).unwrap(), b"SENTINEL_TEST_SIGNATURE");
    }

    #[test]
    #[cfg(windows)]
    fn export_rejects_device_names_and_streams() {
        for path in [
            r"C:\NUL.json",
            r"C:\CON.json",
            r"C:\COM1.json",
            r"C:\LPT¹.json",
            r"C:\file.txt:stream.json",
            r"\\.\NUL.json",
            r"C:\folder\..\report.json",
        ] {
            assert!(validate_export_path(Path::new(path)).is_err(), "{path}");
        }
        assert!(validate_export_path(Path::new(r"C:\reports\new.json")).is_ok());
    }
}
