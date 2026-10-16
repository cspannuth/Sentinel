use sentinel::{FileReport, ScanControl, ScanIssue, ScanOptions, ScanSink, Verdict};
use serde::Serialize;
use serde_json::Value;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

use crate::{
    backend::DesktopState,
    result_store::{ResultPage, ResultStore},
};

#[derive(Serialize)]
pub struct Drive {
    id: String,
    path: String,
}

#[tauri::command]
pub fn list_scan_drives() -> Result<Vec<Drive>, String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_FIXED: u32 = 3;
        // The APIs receive a valid, NUL-terminated drive-root buffer.
        let mask = unsafe { GetLogicalDrives() };
        if mask == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let mut drives = Vec::new();
        for index in 0..26 {
            if mask & (1 << index) == 0 {
                continue;
            }
            let letter = b'A' + index;
            let root = [u16::from(letter), b':' as u16, b'\\' as u16, 0];
            if unsafe { GetDriveTypeW(root.as_ptr()) } == DRIVE_FIXED {
                drives.push(Drive {
                    id: (letter as char).to_string(),
                    path: format!("{}:\\", letter as char),
                });
            }
        }
        Ok(drives)
    }
    #[cfg(not(windows))]
    {
        Err("Full-system drive discovery is supported on Windows only.".into())
    }
}

fn selected_roots(ids: &[String], drives: Vec<Drive>) -> Result<Vec<PathBuf>, String> {
    if ids.is_empty() || ids.len() > 26 {
        return Err("Select at least one local fixed drive.".into());
    }
    let mut roots = Vec::new();
    for id in ids {
        let drive = drives
            .iter()
            .find(|drive| &drive.id == id)
            .ok_or("A selected drive is no longer available as a fixed local drive.")?;
        let path = PathBuf::from(&drive.path);
        if roots.contains(&path) {
            return Err("Duplicate drive selection.".into());
        }
        roots.push(path);
    }
    Ok(roots)
}

#[derive(Clone, Serialize)]
pub struct SessionView {
    pub schema_version: u32,
    pub id: u64,
    pub phase: &'static str,
    pub targets: Vec<String>,
    pub current_path: String,
    pub files: u64,
    pub detections: u64,
    pub skipped: u64,
    pub failed: u64,
    pub incomplete: u64,
    pub issues: u64,
    pub bytes_read: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    pub report: Option<Value>,
    pub sources: Option<Value>,
}

pub struct SystemSession {
    control: Arc<ScanControl>,
    view: Mutex<SessionView>,
    store: Mutex<ResultStore>,
    started: Instant,
    // Drop SQLite handles before deleting the caller-owned temporary directory.
    _directory: tempfile::TempDir,
}
impl SystemSession {
    fn new(roots: &[PathBuf]) -> Result<Self, String> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let directory = tempfile::Builder::new()
            .prefix("sentinel-session-")
            .tempdir()
            .map_err(|e| e.to_string())?;
        let control = Arc::new(ScanControl::with_working_directories(vec![
            directory.path().to_owned(),
        ]));
        let store = Mutex::new(
            ResultStore::create(&directory.path().join("results.sqlite"))
                .map_err(|e| e.to_string())?,
        );
        Ok(Self {
            control,
            store,
            started: Instant::now(),
            _directory: directory,
            view: Mutex::new(SessionView {
                schema_version: 1,
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                phase: "running",
                targets: roots
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect(),
                current_path: String::new(),
                files: 0,
                detections: 0,
                skipped: 0,
                failed: 0,
                incomplete: 0,
                issues: 0,
                bytes_read: 0,
                elapsed_ms: 0,
                error: None,
                report: None,
                sources: None,
            }),
        })
    }
    fn snapshot(&self) -> Result<SessionView, String> {
        let mut view = self
            .view
            .lock()
            .map_err(|_| "Scan state is unavailable")?
            .clone();
        view.bytes_read = self.control.bytes_read();
        if view.phase == "running" {
            view.elapsed_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        }
        Ok(view)
    }
    fn run(self: &Arc<Self>, roots: &[PathBuf], options: &ScanOptions) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = SessionSink(self.clone());
            let report = sentinel::scan_streaming(roots, options, &self.control, &mut sink)
                .map_err(|e| e.to_string())?;
            self.store
                .lock()
                .map_err(|_| "Result store is unavailable")?
                .flush()
                .map_err(|e| e.to_string())?;
            serde_json::to_value(report).map_err(|e| e.to_string())
        }));
        let result = result.unwrap_or_else(|_| {
            Err("Scan worker panicked; the retained results are incomplete.".into())
        });
        if let Ok(mut view) = self.view.lock() {
            view.elapsed_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            match result {
                Ok(report) => {
                    view.phase = if report["cancelled"] == true {
                        "cancelled"
                    } else {
                        "finished"
                    };
                    view.report = Some(report);
                }
                Err(error) => {
                    view.phase = "failed";
                    view.error = Some(error);
                }
            }
        }
    }
}

struct SessionSink(Arc<SystemSession>);
fn unavailable(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
impl ScanSink for SessionSink {
    fn sources(
        &mut self,
        rules: &sentinel::signatures::RuleSetStatus,
        hashes: &sentinel::reputation::HashDatabaseStatus,
    ) -> io::Result<()> {
        self.0.view.lock().map_err(unavailable)?.sources =
            Some(serde_json::json!({"rules": rules, "hash_database": hashes}));
        Ok(())
    }
    fn current_path(&mut self, path: &Path) -> io::Result<()> {
        self.0.view.lock().map_err(unavailable)?.current_path = path.to_string_lossy().into_owned();
        Ok(())
    }
    fn file(&mut self, file: &FileReport) -> io::Result<()> {
        self.0.store.lock().map_err(unavailable)?.file(file)?;
        let mut view = self.0.view.lock().map_err(unavailable)?;
        view.files += 1;
        view.incomplete += u64::from(!file.is_complete());
        view.detections += u64::from(matches!(
            file.verdict,
            Verdict::KnownMaliciousMatch | Verdict::Suspicious
        ));
        view.skipped += u64::from(matches!(
            file.outcome,
            sentinel::FileOutcome::Skipped { .. }
        ));
        view.failed += u64::from(matches!(file.outcome, sentinel::FileOutcome::Failed { .. }));
        Ok(())
    }
    fn issue(&mut self, issue: &ScanIssue) -> io::Result<()> {
        self.0.store.lock().map_err(unavailable)?.issue(issue)?;
        self.0.view.lock().map_err(unavailable)?.issues += 1;
        Ok(())
    }
}

fn active(state: &DesktopState, id: Option<u64>) -> Result<Option<Arc<SystemSession>>, String> {
    let session = state
        .system
        .lock()
        .map_err(|_| "Scan state is unavailable")?
        .clone();
    if let Some(id) = id
        && session
            .as_ref()
            .is_none_or(|session| session.snapshot().map_or(true, |view| view.id != id))
    {
        return Err("This scan session has been replaced. Refresh the view.".into());
    }
    Ok(session)
}

#[tauri::command]
pub async fn start_system_scan(
    state: State<'_, Arc<DesktopState>>,
    drive_ids: Vec<String>,
) -> Result<SessionView, String> {
    let job = state.begin()?;
    let (job, session, roots, options) = tauri::async_runtime::spawn_blocking(move || {
        let roots = selected_roots(&drive_ids, list_scan_drives()?)?;
        let options = job.0.scan_options()?;
        let session = Arc::new(SystemSession::new(&roots)?);
        *job.0
            .system
            .lock()
            .map_err(|_| "Scan state is unavailable")? = Some(session.clone());
        Ok::<_, String>((job, session, roots, options))
    })
    .await
    .map_err(|e| e.to_string())??;
    let response = session.snapshot()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _job = job;
        session.run(&roots, &options);
    });
    Ok(response)
}

#[tauri::command]
pub fn system_scan_status(
    state: State<'_, Arc<DesktopState>>,
    session_id: Option<u64>,
) -> Result<Option<SessionView>, String> {
    active(&state, session_id)?
        .map(|session| session.snapshot())
        .transpose()
}

#[tauri::command]
pub fn cancel_system_scan(
    state: State<'_, Arc<DesktopState>>,
    session_id: u64,
) -> Result<(), String> {
    let session = active(&state, Some(session_id))?.ok_or("No scan is available")?;
    if session.snapshot()?.phase == "running" {
        session.control.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn system_scan_page(
    state: State<'_, Arc<DesktopState>>,
    session_id: u64,
    query: String,
    filter: String,
    page: u32,
    issues: bool,
) -> Result<ResultPage, String> {
    let session = active(&state, Some(session_id))?.ok_or("No scan is available")?;
    tauri::async_runtime::spawn_blocking(move || {
        session
            .store
            .lock()
            .map_err(|_| "Result store is unavailable".to_string())?
            .page(&query, &filter, page, issues)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn system_scan_detail(
    state: State<'_, Arc<DesktopState>>,
    session_id: u64,
    id: i64,
) -> Result<Value, String> {
    let session = active(&state, Some(session_id))?.ok_or("No scan is available")?;
    tauri::async_runtime::spawn_blocking(move || {
        session
            .store
            .lock()
            .map_err(|_| "Result store is unavailable".to_string())?
            .detail(id)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn export_system_scan(
    app: AppHandle,
    state: State<'_, Arc<DesktopState>>,
    session_id: u64,
) -> Result<Option<String>, String> {
    let job = state.begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let session = active(&job.0, Some(session_id))?.ok_or("No scan is available")?;
        let snapshot = session.snapshot()?;
        if snapshot.phase == "running" {
            return Err("Finish or cancel the scan before exporting.".into());
        }
        let picked = app
            .dialog()
            .file()
            .set_title("Export full-system scan to a new JSON file")
            .set_file_name("sentinel-system-report.json")
            .add_filter("JSON", &["json"])
            .blocking_save_file();
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        let mut writer = crate::backend::new_report_writer(&path)?;
        let metadata = serde_json::to_value(snapshot).map_err(|e| e.to_string())?;
        session
            .store
            .lock()
            .map_err(|_| "Result store is unavailable")?
            .export(&mut writer, &metadata)
            .map_err(|e| format!("Export incomplete: {e}"))?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_setup_failure_never_publishes_a_completed_report() {
        let roots = Vec::new();
        let session = Arc::new(SystemSession::new(&roots).unwrap());
        session.run(&roots, &ScanOptions::default());
        let view = session.snapshot().unwrap();
        assert_eq!(view.phase, "failed");
        assert!(view.report.is_none());
        assert!(view.error.is_some());
    }
    #[test]
    #[cfg(windows)]
    fn discovery_returns_only_fixed_drive_letter_roots_without_scanning_them() {
        let drives = list_scan_drives().unwrap();
        assert!(drives.iter().all(|drive| drive.id.len() == 1
            && drive.id.as_bytes()[0].is_ascii_uppercase()
            && drive.path == format!("{}:\\", drive.id)));
    }
    #[test]
    fn drive_ids_are_validated_against_discovered_fixed_drives() {
        let drives = || {
            vec![Drive {
                id: "C".into(),
                path: "C:\\".into(),
            }]
        };
        assert_eq!(
            selected_roots(&["C".into()], drives()).unwrap(),
            vec![PathBuf::from("C:\\")]
        );
        for selection in [
            vec![],
            vec!["Z".into()],
            vec!["C".into(), "C".into()],
            vec!["C:\\Windows".into()],
        ] {
            assert!(selected_roots(&selection, drives()).is_err());
        }
    }
    #[test]
    fn session_runs_the_engine_and_keeps_cancelled_results_distinct() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("marker.txt"), b"SENTINEL_TEST_SIGNATURE").unwrap();
        let roots = vec![temp.path().to_owned()];
        let session = Arc::new(SystemSession::new(&roots).unwrap());
        session.run(&roots, &ScanOptions::default());
        let view = session.snapshot().unwrap();
        assert_eq!(view.phase, "finished");
        assert_eq!(view.files, 1);
        assert_eq!(view.bytes_read, 23);
        assert_eq!(view.report.unwrap()["verdict"], "test_match");
        assert_eq!(
            session
                .store
                .lock()
                .unwrap()
                .page("", "all", 0, false)
                .unwrap()
                .total,
            1
        );
        let stopped = Arc::new(SystemSession::new(&roots).unwrap());
        stopped.control.cancel();
        stopped.run(&roots, &ScanOptions::default());
        let view = stopped.snapshot().unwrap();
        assert_eq!(view.phase, "cancelled");
        assert_eq!(view.files, 0);
        assert_eq!(view.report.unwrap()["status"], "partial");
    }
    #[test]
    fn invalid_sources_are_visible_and_stale_session_ids_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("clean.txt"), b"hello").unwrap();
        let roots = vec![temp.path().to_owned()];
        let session = Arc::new(SystemSession::new(&roots).unwrap());
        session.run(
            &roots,
            &ScanOptions {
                rules_directory: Some(temp.path().join("missing")),
                hash_database: None,
            },
        );
        let view = session.snapshot().unwrap();
        assert_eq!(view.sources.unwrap()["rules"]["status"], "failed");
        assert_eq!(view.report.unwrap()["verdict"], "error");
        let state = DesktopState::default();
        *state.system.lock().unwrap() = Some(session.clone());
        assert!(active(&state, Some(session.snapshot().unwrap().id + 1)).is_err());
    }
}
