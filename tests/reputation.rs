use std::fs;
use std::path::{Path, PathBuf};

use sentinel::reputation::{
    HashCategory, HashDatabase, HashDatabaseErrorKind, HashDatabaseStatus, HashOutcome,
    MAX_DATABASE_BYTES,
};
use sentinel::{FileOutcome, ScanOptions, ScanStatus, Verdict, scan, scan_with_options};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn database(sha256: &str, category: &str) -> Value {
    json!({
        "schema_version": 1,
        "version": "fixture-v1",
        "source": "Sentinel harmless integration fixtures",
        "source_url": "https://example.invalid/sentinel-fixtures",
        "license": "CC0-1.0",
        "retrieved_date": "2026-10-16",
        "entries": [{"sha256": sha256, "category": category, "description": "Harmless fixture hash, not real malware"}]
    })
}

fn write_database(directory: &Path, value: &Value) -> PathBuf {
    let path = directory.join("hashes.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

#[test]
fn every_bundled_digest_matches_its_published_source_without_malware_samples() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("indicators/known_hashes.json");
    let loaded = HashDatabase::load(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["entries"].as_array().unwrap().len(), 507);
    let manifest: Value =
        serde_json::from_str(include_str!("../indicators/upstream/manifest.json")).unwrap();
    assert_eq!(
        manifest["commit"],
        "705ead5a0a86fefae3c2390f91a339852384f438"
    );
    let mut source_hashes = std::collections::BTreeSet::new();
    for source in manifest["sources"].as_array().unwrap() {
        let campaign = source["campaign"].as_str().unwrap();
        let upstream = fs::read_to_string(
            path.parent()
                .unwrap()
                .join(format!("upstream/eset-{campaign}.sha256")),
        )
        .unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(upstream.as_bytes())),
            source["sha256"]
        );
        assert_eq!(
            upstream.lines().count(),
            source["count"].as_u64().unwrap() as usize
        );
        assert!(
            source["url"]
                .as_str()
                .unwrap()
                .contains(manifest["commit"].as_str().unwrap())
        );
        for digest in upstream.lines() {
            assert!(source_hashes.insert(digest.to_ascii_lowercase()));
        }
    }
    assert_eq!(source_hashes.len(), 507);
    for digest in source_hashes {
        let HashOutcome::Complete {
            matched: Some(found),
        } = loaded.check(&digest.to_uppercase())
        else {
            panic!("Missing published digest: {digest}");
        };
        assert_eq!(found.indicator.sha256, digest);
        assert_eq!(found.indicator.category, HashCategory::KnownMalicious);
        assert!(found.source.starts_with("ESET Research"));
        assert!(
            found
                .source_url
                .ends_with(manifest["commit"].as_str().unwrap())
        );
        assert_eq!(found.database_version, "eset-selected-2026-10-16-v2");
    }
    assert!(matches!(
        loaded.check(&"0".repeat(64)),
        HashOutcome::Complete { matched: None }
    ));
    assert!(matches!(
        loaded.check("bad digest"),
        HashOutcome::Failed { .. }
    ));

    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("ordinary.txt");
    fs::write(&file, b"ordinary text").unwrap();
    let report = scan(&file);
    assert_eq!(report.schema_version, 4);
    let HashDatabaseStatus::Ready { info } = report.hash_database else {
        panic!("Bundled database failed");
    };
    assert_eq!(info.entry_count, 507);
    assert_eq!(info.origin, "bundled-v2");
    assert_eq!(info.sha256, format!("{:x}", Sha256::digest(bytes)));
    assert_eq!(report.verdict, Verdict::NoDetections);
    assert_eq!(report.summary.hash_checked, 1);
    assert_eq!(report.summary.hash_matches, 0);
}

#[test]
fn larger_hash_databases_exceed_old_limits_and_preserve_exact_lookups() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large.json");
    let mut file = std::io::BufWriter::new(fs::File::create(&path).unwrap());
    let mut header = database(&"a".repeat(64), "test");
    header.as_object_mut().unwrap().remove("entries");
    let header = serde_json::to_string(&header).unwrap();
    write!(file, "{},\"entries\":[", &header[..header.len() - 1]).unwrap();
    for index in 0..100_001 {
        if index != 0 {
            write!(file, ",").unwrap();
        }
        write!(file, r#"{{"sha256":"{index:064x}","category":"test","description":"Harmless synthetic database capacity indicator; this digest was invented for this test."}}"#).unwrap();
    }
    write!(file, "]}}").unwrap();
    file.flush().unwrap();
    drop(file);
    assert!(fs::metadata(&path).unwrap().len() > 16 * 1024 * 1024);
    let database = HashDatabase::load(&path).unwrap();
    for index in [0, 100_000] {
        assert!(matches!(
            database.check(&format!("{index:064x}")),
            HashOutcome::Complete { matched: Some(_) }
        ));
    }
    assert!(matches!(
        database.check(&format!("{:064x}", 100_001)),
        HashOutcome::Complete { matched: None }
    ));
}

#[test]
fn exact_content_matches_survive_renames_but_changes_and_hash_text_do_not() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("inert.txt");
    let content = b"harmless end-to-end reputation fixture";
    let digest = format!("{:x}", Sha256::digest(content));
    let options = ScanOptions {
        hash_database: Some(write_database(
            directory.path(),
            &database(&digest.to_uppercase(), "known_malicious"),
        )),
        ..ScanOptions::default()
    };
    fs::write(&file, content).unwrap();
    for path in [&file, &directory.path().join("renamed.data")] {
        if path != &file {
            fs::rename(&file, path).unwrap();
        }
        let report = scan_with_options(path, &options);
        assert_eq!(report.status, ScanStatus::Complete);
        assert_eq!(report.verdict, Verdict::KnownMaliciousMatch);
        assert_eq!(report.summary.signature_matches, 0);
        assert_eq!(report.summary.hash_matches, 1);
        let Some(HashOutcome::Complete {
            matched: Some(found),
        }) = &report.files[0].hash_reputation
        else {
            panic!("Missing hash evidence");
        };
        assert_eq!(found.indicator.sha256, digest);
        assert_eq!(found.source, "Sentinel harmless integration fixtures");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["files"][0]["hash_reputation"]["matched"]["category"],
            "known_malicious"
        );
    }
    fs::write(&file, [content.as_slice(), b"!"].concat()).unwrap();
    assert_eq!(
        scan_with_options(&file, &options).verdict,
        Verdict::NoDetections
    );
    fs::write(&file, digest.as_bytes()).unwrap();
    assert_eq!(
        scan_with_options(&file, &options).verdict,
        Verdict::NoDetections
    );
}

#[test]
fn test_hashes_stay_test_evidence_and_never_pollute_the_bundled_database() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("fixture");
    fs::write(&file, b"abc").unwrap();
    let options = ScanOptions {
        hash_database: Some(write_database(
            directory.path(),
            &database(&format!("{:x}", Sha256::digest(b"abc")), "test"),
        )),
        ..ScanOptions::default()
    };
    let report = scan_with_options(&file, &options);
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.verdict, Verdict::TestMatch);
    assert_eq!(report.summary.hash_matches, 1);
    assert_eq!(report.summary.signature_matches, 0);
    assert_eq!(scan(&file).verdict, Verdict::NoDetections);
}

#[test]
fn invalid_databases_fail_as_a_whole_and_do_not_hide_successful_hashing() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("fixture");
    fs::write(&file, b"abc").unwrap();
    let base = database(&"a".repeat(64), "known_malicious");
    let mut invalid = Vec::new();
    for hash in [
        "".to_owned(),
        "a".repeat(63),
        "g".repeat(64),
        format!(" {}", "a".repeat(64)),
    ] {
        let mut value = base.clone();
        value["entries"][0]["sha256"] = json!(hash);
        invalid.push(value);
    }
    for (field, value) in [
        ("schema_version", json!(2)),
        ("source", json!(" ")),
        ("license", json!("")),
        ("entries", json!([])),
        ("unexpected", json!(true)),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        invalid.push(changed);
    }
    let mut unknown = base.clone();
    unknown["entries"][0]["category"] = json!("suspicious");
    invalid.push(unknown);
    let mut duplicate = base.clone();
    let mut second = base["entries"][0].clone();
    second["sha256"] = json!("A".repeat(64));
    duplicate["entries"].as_array_mut().unwrap().push(second);
    invalid.push(duplicate);
    for value in invalid {
        let options = ScanOptions {
            hash_database: Some(write_database(directory.path(), &value)),
            ..ScanOptions::default()
        };
        let report = scan_with_options(&file, &options);
        assert_eq!(report.status, ScanStatus::Partial, "{value}");
        assert_eq!(report.verdict, Verdict::Error);
        assert_eq!(report.summary.hashed, 1);
        assert_eq!(report.summary.hash_checked, 0);
        assert_eq!(report.summary.hash_incomplete, 1);
        assert_eq!(report.summary.hash_matches, 0);
        assert_eq!(report.files[0].verdict, Verdict::Inconclusive);
        assert!(
            matches!(report.hash_database, HashDatabaseStatus::Failed { error } if error.kind == HashDatabaseErrorKind::InvalidDatabase)
        );
        assert!(matches!(
            report.files[0].hash_reputation,
            Some(HashOutcome::Failed { .. })
        ));
    }
    let options = ScanOptions {
        hash_database: Some(directory.path().join("missing.json")),
        ..ScanOptions::default()
    };
    assert_eq!(scan_with_options(&file, &options).verdict, Verdict::Error);
    let empty = directory.path().join("empty");
    fs::create_dir(&empty).unwrap();
    assert_eq!(
        scan_with_options(&empty, &options).status,
        ScanStatus::Partial
    );
    assert_eq!(scan_with_options(&empty, &options).verdict, Verdict::Error);
    fs::write(options.hash_database.as_ref().unwrap(), b"{broken json").unwrap();
    assert_eq!(scan_with_options(&file, &options).verdict, Verdict::Error);
    assert!(HashDatabase::load(directory.path()).is_err());
}

#[test]
fn hash_positives_remain_visible_alongside_independent_analysis_failures() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("invalid-pe");
    fs::write(&file, b"MZ").unwrap();
    let options = ScanOptions {
        rules_directory: Some(directory.path().join("missing-rules")),
        hash_database: Some(write_database(
            directory.path(),
            &database(&format!("{:x}", Sha256::digest(b"MZ")), "known_malicious"),
        )),
    };
    let report = scan_with_options(&file, &options);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::KnownMaliciousMatch);
    assert_eq!(report.summary.hash_matches, 1);
    assert_eq!(report.summary.pe_incomplete, 1);
    assert_eq!(report.summary.signature_incomplete, 1);

    // Conversely, a failed hash database must not discard verified YARA evidence.
    fs::write(&file, b"powershell -EncodedCommand DEMO_ONLY").unwrap();
    let options = ScanOptions {
        hash_database: Some(directory.path().join("missing.json")),
        ..ScanOptions::default()
    };
    let report = scan_with_options(&file, &options);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.verdict, Verdict::Suspicious);
    assert_eq!(report.summary.signature_matches, 1);
}

#[test]
fn database_resource_limits_and_unavailable_file_hashes_are_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.json");
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_DATABASE_BYTES + 1)
        .unwrap();
    let error = HashDatabase::load(&path).err().unwrap();
    assert_eq!(error.kind, HashDatabaseErrorKind::ResourceLimit);
    let report = scan(directory.path().join("missing"));
    assert_eq!(report.status, ScanStatus::Failed);
    assert_eq!(report.summary.hash_checked, 0);
    assert_eq!(report.summary.hash_matches, 0);
    // Failed/inconsistent file reads cannot publish hash evidence.
    assert!(report.files.is_empty());
    let good = directory.path().join("good");
    fs::write(&good, b"abc").unwrap();
    let report = scan(&good);
    assert!(matches!(
        report.files[0].outcome,
        FileOutcome::Hashed { .. }
    ));
    assert!(matches!(
        report.files[0].hash_reputation,
        Some(HashOutcome::Complete { matched: None })
    ));
}
