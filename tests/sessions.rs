use sentinel::{
    FileReport, ScanControl, ScanIssue, ScanOptions, ScanSink, ScanStatus, Verdict, scan_streaming,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Default)]
struct Results {
    files: Vec<serde_json::Value>,
    issues: Vec<serde_json::Value>,
}
impl ScanSink for Results {
    fn file(&mut self, file: &FileReport) -> io::Result<()> {
        self.files.push(serde_json::to_value(file)?);
        Ok(())
    }
    fn issue(&mut self, issue: &ScanIssue) -> io::Result<()> {
        self.issues.push(serde_json::to_value(issue)?);
        Ok(())
    }
}

#[test]
fn streaming_results_match_regular_engine_and_combine_roots() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a with spaces é");
    let b = temp.path().join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    fs::write(a.join("test.txt"), b"SENTINEL_TEST_SIGNATURE").unwrap();
    fs::write(b.join("clean"), b"hello").unwrap();
    let mut results = Results::default();
    let control = ScanControl::default();
    let report = scan_streaming(
        &[a.clone(), b.clone()],
        &ScanOptions::default(),
        &control,
        &mut results,
    )
    .unwrap();
    let mut expected: Vec<_> = [a, b]
        .iter()
        .flat_map(|path| {
            serde_json::to_value(sentinel::scan(path)).unwrap()["files"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect();
    results
        .files
        .sort_by_key(|file| file["path"]["display"].as_str().unwrap().to_owned());
    expected.sort_by_key(|file| file["path"]["display"].as_str().unwrap().to_owned());
    assert_eq!(results.files, expected);
    assert!(results.issues.is_empty());
    assert_eq!(report.summary.hashed, 2);
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.verdict, Verdict::TestMatch);
    assert_eq!(report.bytes_read, 28);
    assert_eq!(report.roots.len(), 2);
}

#[test]
fn invalid_root_does_not_discard_other_roots_or_positive_findings() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("powershell.txt");
    fs::write(&marker, b"powershell DEMO_ONLY DownloadString IEX").unwrap();
    let mut results = Results::default();
    let report = scan_streaming(
        &[temp.path().join("missing"), marker],
        &ScanOptions::default(),
        &ScanControl::default(),
        &mut results,
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(report.roots[0].status, Some(ScanStatus::Failed));
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.issues, 1);
}

#[test]
fn pre_cancelled_scan_marks_every_root_unvisited() {
    let temp = tempfile::tempdir().unwrap();
    let control = ScanControl::default();
    control.cancel();
    let mut results = Results::default();
    let report = scan_streaming(
        &[temp.path().into()],
        &ScanOptions::default(),
        &control,
        &mut results,
    )
    .unwrap();
    assert!(report.cancelled);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.roots[0].status, None);
    assert!(results.files.is_empty());
    assert_eq!(report.bytes_read, 0);
}

#[test]
fn cancellation_preserves_completed_files_and_never_claims_complete() {
    struct CancelAfterFile<'a> {
        control: &'a ScanControl,
        files: usize,
    }
    impl ScanSink for CancelAfterFile<'_> {
        fn file(&mut self, _: &FileReport) -> io::Result<()> {
            self.files += 1;
            self.control.cancel();
            Ok(())
        }
        fn issue(&mut self, _: &ScanIssue) -> io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    for n in 0..20 {
        fs::write(temp.path().join(format!("{n}.txt")), b"hello").unwrap();
    }
    let control = ScanControl::default();
    let mut sink = CancelAfterFile {
        control: &control,
        files: 0,
    };
    let report = scan_streaming(
        &[temp.path().into()],
        &ScanOptions::default(),
        &control,
        &mut sink,
    )
    .unwrap();
    assert!(report.cancelled);
    assert_eq!(sink.files, 1);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert_eq!(report.status, ScanStatus::Partial);
}

#[test]
fn storage_failure_stops_scanning_without_a_successful_report() {
    struct Failing;
    impl ScanSink for Failing {
        fn file(&mut self, _: &FileReport) -> io::Result<()> {
            Err(io::Error::other("disk full"))
        }
        fn issue(&mut self, _: &ScanIssue) -> io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    fs::write(&path, b"hello").unwrap();
    let error = scan_streaming(
        &[path],
        &ScanOptions::default(),
        &ScanControl::default(),
        &mut Failing,
    )
    .unwrap_err();
    assert!(error.to_string().contains("disk full"));
}

#[test]
fn working_directory_is_explicitly_skipped_and_sources_do_not_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let working = temp.path().join("scanner-cache");
    fs::create_dir(&working).unwrap();
    fs::write(working.join("results.db"), b"do not scan").unwrap();
    fs::write(temp.path().join("clean"), b"hello").unwrap();
    let control = ScanControl::with_working_directories(vec![working]);
    let mut results = Results::default();
    let options = ScanOptions {
        rules_directory: Some(temp.path().join("bad-rules")),
        hash_database: Some(temp.path().join("bad-hashes")),
    };
    let report = scan_streaming(&[temp.path().into()], &options, &control, &mut results).unwrap();
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.skipped, 1);
    assert_eq!(
        results
            .files
            .iter()
            .filter(|file| file["reason"] == "scanner_working_directory")
            .count(),
        1
    );
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Error);
    assert_eq!(report.excluded_working_directories.len(), 1);
}

#[test]
fn empty_roots_missing_roots_and_overlaps_have_distinct_results() {
    let temp = tempfile::tempdir().unwrap();
    let control = ScanControl::default();
    let mut results = Results::default();
    let empty = scan_streaming(
        &[temp.path().into()],
        &ScanOptions::default(),
        &control,
        &mut results,
    )
    .unwrap();
    assert_eq!(empty.status, ScanStatus::Complete);
    assert_eq!(empty.summary.hashed, 0);
    let missing = scan_streaming(
        &[temp.path().join("missing")],
        &ScanOptions::default(),
        &control,
        &mut results,
    )
    .unwrap();
    assert_eq!(missing.status, ScanStatus::Failed);
    assert!(scan_streaming(&[], &ScanOptions::default(), &control, &mut results).is_err());
    for roots in [
        vec![PathBuf::from(temp.path()), temp.path().into()],
        vec![temp.path().into(), temp.path().join("nested")],
    ] {
        assert!(scan_streaming(&roots, &ScanOptions::default(), &control, &mut results).is_err());
    }
}

#[test]
fn large_tree_is_delivered_one_file_at_a_time() {
    struct Count(usize);
    impl ScanSink for Count {
        fn file(&mut self, _: &FileReport) -> io::Result<()> {
            self.0 += 1;
            Ok(())
        }
        fn issue(&mut self, _: &ScanIssue) -> io::Result<()> {
            Ok(())
        }
        fn current_path(&mut self, _: &Path) -> io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    for directory in 0..8 {
        let folder = temp.path().join(directory.to_string());
        fs::create_dir(&folder).unwrap();
        for file in 0..32 {
            fs::write(folder.join(file.to_string()), b"hello").unwrap();
        }
    }
    let mut count = Count(0);
    let report = scan_streaming(
        &[temp.path().into()],
        &ScanOptions::default(),
        &ScanControl::default(),
        &mut count,
    )
    .unwrap();
    assert_eq!(count.0, 256);
    assert_eq!(report.summary.hashed, 256);
    assert_eq!(report.status, ScanStatus::Complete);
}

#[cfg(windows)]
#[test]
fn streaming_skips_junctions_and_preserves_readable_files_next_to_locked_files() {
    use std::{
        os::windows::{fs::OpenOptionsExt, process::CommandExt},
        process::Command,
    };
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.txt"), b"outside").unwrap();
    let junction = temp.path().join("junction");
    let created = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(outside.path())
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(created.status.success());
    let locked = temp.path().join("locked.txt");
    fs::write(&locked, b"locked").unwrap();
    let _lock = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&locked)
        .unwrap();
    fs::write(temp.path().join("normal.txt"), b"hello").unwrap();
    let mut results = Results::default();
    let report = scan_streaming(
        &[temp.path().into()],
        &ScanOptions::default(),
        &ScanControl::default(),
        &mut results,
    )
    .unwrap();
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.skipped, 1);
    assert_eq!(report.summary.failed, 1);
    assert!(!results.files.iter().any(|file| {
        file["path"]["display"]
            .as_str()
            .unwrap()
            .ends_with("outside.txt")
    }));
    fs::remove_dir(junction).unwrap(); // Remove only the junction itself.
    assert_eq!(
        fs::read(outside.path().join("outside.txt")).unwrap(),
        b"outside"
    );
}
