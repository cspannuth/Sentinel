use std::process::Command;
mod common;

fn sentinel() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sentinel"))
}

#[test]
fn successful_scan_writes_only_json_to_stdout() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file with spaces.txt");
    std::fs::write(&path, b"abc").unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["summary"]["hashed"], 1);
    assert_eq!(
        json["files"][0]["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn failed_scan_still_emits_json_and_returns_exit_one() {
    let directory = tempfile::tempdir().unwrap();
    let output = sentinel()
        .arg("scan")
        .arg(directory.path().join("missing"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "failed");
    assert_eq!(json["issues"][0]["error"]["kind"], "NotFound");
}

#[test]
fn invalid_arguments_return_exit_two_without_a_report() {
    for arguments in [
        vec![],
        vec!["scan"],
        vec!["unknown", "."],
        vec!["scan", ".", "extra"],
        vec!["scan", ""],
        vec!["scan", ".", "--hashes"],
        vec!["scan", ".", "--hashes", ""],
        vec!["scan", ".", "--hashes", "first", "--hashes", "second"],
        vec!["scan", ".", "--rules", "first", "--rules", "second"],
        vec!["scan", ".", "--rules", "--hashes"],
    ] {
        let output = sentinel().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
    }
}

#[test]
fn help_does_not_start_a_scan() {
    let output = sentinel().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sentinel scan <path>"));
}

#[test]
fn relative_paths_are_accepted() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("sample"), b"abc").unwrap();
    let output = sentinel()
        .current_dir(directory.path())
        .args(["scan", "sample"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["summary"]["hashed"], 1);
}

#[test]
fn pe_analysis_is_json_and_incomplete_analysis_returns_exit_one_with_hash() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample.txt");
    std::fs::write(&path, common::pe_file(true, true)).unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files"][0]["pe"]["status"], "analyzed");
    assert_eq!(json["files"][0]["pe"]["report"]["architecture"], "x86_64");
    std::fs::write(&path, b"MZ").unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "partial");
    assert_eq!(json["files"][0]["status"], "hashed");
    assert_eq!(json["files"][0]["pe"]["status"], "failed");
    assert_eq!(json["summary"]["pe_incomplete"], 1);
    assert!(json["files"][0]["sha256"].is_string());
}

#[test]
fn detection_exit_codes_and_rule_override_are_distinct_from_scan_failures() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("command.txt");
    // Inspected text only; no PowerShell command is executed.
    std::fs::write(
        &path,
        b"powershell -EncodedCommand ZQBjAGgAbwAgAHQAZQBzAHQA",
    )
    .unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["verdict"], "suspicious");
    assert_eq!(json["rules"]["info"]["rule_count"], 20);

    std::fs::write(&path, b"SENTINEL_TEST_SIGNATURE").unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["verdict"], "test_match");

    let output = sentinel()
        .arg("scan")
        .arg(&path)
        .arg("--rules")
        .arg(directory.path().join("missing-rules"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["rules"]["status"], "failed");
    assert_eq!(json["verdict"], "error");
    assert_eq!(json["summary"]["hashed"], 1);
}

#[test]
fn upstream_family_signature_returns_exit_three_with_attribution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inert-fixture.data");
    let mut bytes = common::pe_file(false, false);
    bytes.extend_from_slice(b"__TREEID__PLACEHOLDER__\0__USERID__PLACEHOLDER__\0Windows for Workgroups 3.1a\0PC NETWORK PROGRAM 1.0\0LANMAN1.0\0");
    std::fs::write(&path, bytes).unwrap();
    let output = sentinel().arg("scan").arg(&path).output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["verdict"], "known_malicious_match");
    let found = &json["files"][0]["signatures"]["matches"][0];
    assert_eq!(found["rule_id"], "WannaCry_Ransomware_Gen");
    assert_eq!(
        found["author"],
        "Florian Roth (Nextron Systems) (based on rule by US CERT)"
    );
    assert!(
        found["license"]
            .as_str()
            .unwrap()
            .contains("Detection Rule License 1.1")
    );
}

#[test]
fn scanner_binary_does_not_detect_its_own_embedded_rules() {
    let output = sentinel()
        .args(["scan", env!("CARGO_BIN_EXE_sentinel")])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "complete");
    assert_eq!(json["verdict"], "no_detections");
    assert_eq!(json["summary"]["signature_matches"], 0);
}

#[test]
fn hash_override_supports_test_and_malicious_categories_and_both_option_orders() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("ordinary.txt");
    std::fs::write(&file, b"abc").unwrap();
    let hashes = directory.path().join("hashes.json");
    let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let mut database = serde_json::json!({
        "schema_version": 1, "version": "cli-fixture-v1", "source": "Harmless test fixtures",
        "source_url": "https://example.invalid/fixtures", "license": "CC0-1.0", "retrieved_date": "2026-10-16",
        "entries": [{"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "category": "test", "description": "Harmless abc fixture"}]
    });
    for (category, verdict, exit_code) in [
        ("test", "test_match", 0),
        ("known_malicious", "known_malicious_match", 3),
    ] {
        database["entries"][0]["category"] = serde_json::json!(category);
        std::fs::write(&hashes, serde_json::to_vec(&database).unwrap()).unwrap();
        for hashes_first in [true, false] {
            let mut command = sentinel();
            command.arg("scan").arg(&file);
            if hashes_first {
                command
                    .arg("--hashes")
                    .arg(&hashes)
                    .arg("--rules")
                    .arg(&rules);
            } else {
                command
                    .arg("--rules")
                    .arg(&rules)
                    .arg("--hashes")
                    .arg(&hashes);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(exit_code));
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["schema_version"], 4);
            assert_eq!(json["verdict"], verdict);
            assert_eq!(json["hash_database"]["info"]["origin"], "local-file");
            assert_eq!(json["summary"]["hash_matches"], 1);
            assert_eq!(json["summary"]["signature_matches"], 0);
        }
    }
    for database_path in [&hashes, &directory.path().join("missing.json")] {
        std::fs::write(&hashes, b"bad JSON").unwrap();
        let output = sentinel()
            .arg("scan")
            .arg(&file)
            .arg("--hashes")
            .arg(database_path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["status"], "partial");
        assert_eq!(json["verdict"], "error");
        assert_eq!(json["summary"]["hashed"], 1);
        assert_eq!(json["hash_database"]["status"], "failed");
    }
}
