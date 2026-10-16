use std::fs;
use std::io;
use std::path::Path;

use sentinel::{FileOutcome, ScanStatus, SkipReason, scan};

fn digest(report: &sentinel::ScanReport) -> &str {
    assert_eq!(report.status, ScanStatus::Complete);
    match &report.files[0].outcome {
        FileOutcome::Hashed { sha256 } => sha256,
        outcome => panic!("Expected a hash, got {outcome:?}"),
    }
}

#[test]
fn known_sha256_and_metadata_are_reported_without_modifying_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample.txt");
    fs::write(&path, b"abc").unwrap();
    let before = fs::metadata(&path).unwrap();
    let report = scan(&path);
    assert_eq!(
        digest(&report),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let metadata = report.files[0].metadata.as_ref().unwrap();
    assert_eq!(metadata.size_bytes, 3);
    assert!(metadata.modified_unix_ms.is_some());
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.failed, 0);
    assert!(report.issues.is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"abc");
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], 4);
    assert_eq!(json["files"][0]["pe"]["status"], "not_pe");
    assert_eq!(json["status"], "complete");
    assert!(json["files"][0]["path"]["display"].is_string());
    assert!(json["files"][0]["path"].get("native").is_none());
    assert_eq!(json["files"][0]["verdict"], "no_detections");
}

#[test]
fn empty_file_has_the_standard_empty_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("empty");
    fs::write(&path, []).unwrap();
    assert_eq!(
        digest(&scan(path)),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn nested_directories_include_hidden_and_extensionless_files_in_path_order() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("nested/deeper/empty-directory")).unwrap();
    for name in ["z.txt", ".hidden", "nested/a", "nested/deeper/b.bin"] {
        fs::write(directory.path().join(name), b"data").unwrap();
    }
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.summary.hashed, 4);
    assert_eq!(report.files.len(), 4);
    assert!(
        report
            .files
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
}

#[test]
fn multiple_buffers_are_hashed_correctly() {
    // Independent known SHA-256 vector: one million ASCII 'a' bytes.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large.txt");
    fs::write(&path, vec![b'a'; 1_000_000]).unwrap();
    assert_eq!(
        digest(&scan(path)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn empty_directory_is_a_complete_scan_of_zero_files() {
    let directory = tempfile::tempdir().unwrap();
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.summary.hashed, 0);
    assert!(report.files.is_empty());
    assert!(report.issues.is_empty());
}

#[test]
fn missing_target_and_missing_ancestor_are_failed_scans() {
    let directory = tempfile::tempdir().unwrap();
    for name in ["missing", "missing/child"] {
        let report = scan(directory.path().join(name));
        assert_eq!(report.status, ScanStatus::Failed);
        assert_eq!(report.summary.hashed, 0);
        assert_eq!(report.summary.issues, 1);
        assert_eq!(report.issues[0].error.kind, io::ErrorKind::NotFound);
        assert!(report.files.is_empty());
        assert_eq!(serde_json::to_value(report).unwrap()["status"], "failed");
    }
}

#[test]
fn empty_target_is_not_interpreted_as_current_directory() {
    let report = scan("");
    assert_eq!(report.status, ScanStatus::Failed);
    assert_eq!(report.issues[0].error.kind, io::ErrorKind::InvalidInput);
    assert!(report.files.is_empty());
}

#[cfg(windows)]
#[test]
fn device_names_namespaces_and_streams_are_rejected_before_opening() {
    for path in [
        r"\\.\pipe\sentinel-test",
        "NUL",
        "NUL.txt",
        "CON",
        "COM1",
        "LPT³.txt",
        "file:stream",
    ] {
        let report = scan(path);
        assert_eq!(report.status, ScanStatus::Failed);
        assert_eq!(report.issues[0].error.kind, io::ErrorKind::InvalidInput);
        assert!(report.files.is_empty());
    }
}

#[cfg(windows)]
fn create_directory_link(target: &Path, link: &Path) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    // Junctions do not require Developer Mode or symlink privileges.
    let result = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[cfg(unix)]
fn create_directory_link(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn directory_links_are_skipped_including_loops_and_explicit_linked_ancestors() {
    let directory = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.txt"), b"outside").unwrap();
    fs::write(directory.path().join("inside.txt"), b"inside").unwrap();
    let link = directory.path().join("link");
    let cycle = directory.path().join("cycle");
    create_directory_link(outside.path(), &link);
    create_directory_link(directory.path(), &cycle);

    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.skipped, 2);
    assert!(
        !report
            .files
            .iter()
            .any(|file| file.path.ends_with("outside.txt"))
    );
    assert!(report.files.iter().any(|file| matches!(
        file.outcome,
        FileOutcome::Skipped {
            reason: SkipReason::SymlinkOrReparsePoint
        }
    )));
    assert_eq!(scan(&link).status, ScanStatus::Skipped);
    let mut link_with_separator = link.as_os_str().to_os_string();
    link_with_separator.push(std::path::MAIN_SEPARATOR_STR);
    assert_eq!(scan(&link_with_separator).status, ScanStatus::Skipped);
    assert_eq!(scan(link.join(".")).status, ScanStatus::Skipped);
    assert_eq!(scan(link.join("outside.txt")).status, ScanStatus::Skipped);

    // Remove only the junction/link itself, never the target tree.
    #[cfg(windows)]
    {
        fs::remove_dir(&link).unwrap();
        fs::remove_dir(&cycle).unwrap();
    }
    #[cfg(unix)]
    {
        fs::remove_file(&link).unwrap();
        fs::remove_file(&cycle).unwrap();
    }
    assert_eq!(
        fs::read(outside.path().join("outside.txt")).unwrap(),
        b"outside"
    );
}

#[cfg(windows)]
#[test]
fn locked_file_fails_without_discarding_successful_siblings() {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("locked.txt");
    fs::write(&path, b"locked").unwrap();
    fs::write(directory.path().join("readable.txt"), b"readable").unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.failed + report.summary.issues, 1);
    assert_ne!(scan(&path).status, ScanStatus::Complete);
    drop(lock);
    assert_eq!(scan(&path).status, ScanStatus::Complete);
}

#[test]
fn non_unicode_paths_have_lossless_native_json_units() {
    #[cfg(windows)]
    let name = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[b'f' as u16, 0xd800])
    };
    #[cfg(unix)]
    let name = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![b'f', 0xff])
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(name);
    fs::write(&path, b"abc").unwrap();
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.files[0].path, path);
    let json = serde_json::to_value(&report).unwrap();
    let native = &json["files"][0]["path"]["native"];
    assert!(native["units"].is_array());
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        assert_eq!(native["encoding"], "windows_utf16");
        let units: Vec<u16> = serde_json::from_value(native["units"].clone()).unwrap();
        assert_eq!(std::ffi::OsString::from_wide(&units), path.as_os_str());
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(native["encoding"], "unix_bytes");
        let units: Vec<u8> = serde_json::from_value(native["units"].clone()).unwrap();
        assert_eq!(std::ffi::OsString::from_vec(units), path.as_os_str());
    }
}

#[cfg(unix)]
#[test]
fn broken_file_symlink_is_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broken");
    std::os::unix::fs::symlink(directory.path().join("missing"), &path).unwrap();
    assert_eq!(scan(path).status, ScanStatus::Skipped);
}
