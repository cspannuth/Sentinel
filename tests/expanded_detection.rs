//! Inert pattern containers exercise the new signatures; no malware is executed.
use std::{fs, io::Write};

use sentinel::{
    FileOutcome, ScanOptions, ScanStatus, Verdict,
    pe::PeOutcome,
    scan, scan_with_options,
    signatures::{RuleSetStatus, SignatureOutcome},
};
use serde::Deserialize;
use yara_x::{Compiler, Rules, Scanner};

mod common;

#[derive(Deserialize)]
struct Fixture {
    rule: String,
    bytes: String,
    near_miss: String,
    category: String,
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn matching(rules: &Rules, bytes: &[u8]) -> Vec<String> {
    Scanner::new(rules)
        .scan(bytes)
        .unwrap()
        .matching_rules()
        .map(|rule| rule.identifier().to_owned())
        .collect()
}

#[test]
fn extended_signatures_preserve_upstream_thresholds_headers_and_patterns() {
    use sha2::{Digest, Sha256};
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../rules/upstream/eset-extended-manifest.json"
    ))
    .unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/upstream");
    for source in manifest["sources"].as_array().unwrap() {
        let path = source["path"].as_str().unwrap();
        let bytes = fs::read(root.join(format!("eset-full-{}", path.replace('/', "-")))).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), source["sha256"]);
    }
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../rules/upstream/eset-extended-selected.yar"
            ))
        ),
        manifest["selected_sha256"]
    );
    let mut upstream = Compiler::new();
    upstream
        .add_source(include_str!("../rules/upstream/eset-extended-selected.yar"))
        .unwrap();
    assert!(upstream.warnings().is_empty());
    let upstream = upstream.build();
    let mut adapted = Compiler::new();
    adapted
        .add_source(include_str!("../rules/eset_extended.yar"))
        .unwrap();
    assert!(adapted.warnings().is_empty());
    let adapted = adapted.build();
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("common/eset-extended-fixtures.json")).unwrap();
    assert_eq!(fixtures.len(), 100);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inert-pattern-container");
    for fixture in fixtures {
        let bytes = decode(&fixture.bytes);
        let negative = decode(&fixture.near_miss);
        let mut bad_header = bytes.clone();
        bad_header[0] = 0;
        assert_eq!(matching(&upstream, &bytes), vec![fixture.rule.clone()]);
        for sample in [&bytes, &negative, &bad_header] {
            assert_eq!(matching(&upstream, sample), matching(&adapted, sample));
        }
        assert!(
            matching(&upstream, &negative).is_empty(),
            "{}",
            fixture.rule
        );
        assert!(matching(&upstream, &bad_header).is_empty());
        // Attach the patterns to an ordinary synthetic PE to exercise the full pipeline.
        let mut pe = common::pe_file(false, false);
        pe.extend_from_slice(&bytes[2..]);
        fs::write(&path, pe).unwrap();
        let report = scan(&path);
        assert_eq!(report.status, ScanStatus::Complete, "{report:?}");
        assert_eq!(
            report.verdict,
            if fixture.category == "known_malicious" {
                Verdict::KnownMaliciousMatch
            } else {
                Verdict::Suspicious
            }
        );
        let Some(SignatureOutcome::Complete { matches }) = &report.files[0].signatures else {
            panic!("Signature analysis incomplete");
        };
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, fixture.rule);
        assert_eq!(matches[0].author, "ESET Research");
        assert_eq!(matches[0].license, "BSD-2-Clause");
        assert_eq!(matches[0].version, "sentinel-import-2");
    }
}

#[test]
fn full_128_mib_input_includes_last_bytes_in_yara_and_pe_analysis() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    fs::write(
        rules.join("end.yar"),
        r#"rule EndMarker {
        meta:
            category = "test"
            description = "Harmless marker at end of large input"
            author = "Sentinel tests"
            version = "1"
            license = "CC0-1.0"
        strings: $end = "SENTINEL_LARGE_INPUT_END"
        condition: $end at (filesize - 24)
    }"#,
    )
    .unwrap();
    let path = directory.path().join("large.data");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&common::pe_file(false, false)).unwrap();
    let limit = sentinel::pe::MAX_PE_BYTES;
    assert_eq!(limit, 128 * 1024 * 1024);
    assert_eq!(limit, sentinel::signatures::MAX_SIGNATURE_BYTES);
    file.set_len(limit - 24).unwrap();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::End(0)).unwrap();
    file.write_all(b"SENTINEL_LARGE_INPUT_END").unwrap();
    drop(file);
    let report = scan_with_options(
        &path,
        &ScanOptions {
            rules_directory: Some(rules),
            ..ScanOptions::default()
        },
    );
    assert_eq!(report.status, ScanStatus::Complete, "{report:?}");
    assert_eq!(report.verdict, Verdict::TestMatch);
    assert!(matches!(
        report.files[0].pe,
        Some(PeOutcome::Analyzed { .. })
    ));
    assert!(matches!(
        report.files[0].outcome,
        FileOutcome::Hashed { .. }
    ));
    assert_eq!(report.summary.hash_checked, 1);
}

#[test]
fn larger_rule_collections_load_without_silently_dropping_sources_or_patterns() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules");
    fs::create_dir(&rules).unwrap();
    for source in 0..40 {
        let mut text = String::new();
        for rule in 0..4 {
            text.push_str(&format!(
                r#"rule Fixture_{source}_{rule} {{
                meta:
                    category = "test"
                    description = "Harmless capacity fixture"
                    author = "Sentinel tests"
                    version = "1"
                    license = "CC0-1.0"
                strings:
                    $a = "CAPACITY_A_{source}_{rule}"
                    $b = "CAPACITY_B_{source}_{rule}"
                condition: all of them
            }}"#
            ));
        }
        if source == 0 {
            text.push_str(&format!("\n/*{}*/", " ".repeat(1024 * 1024)));
        }
        fs::write(rules.join(format!("{source:03}.yar")), text).unwrap();
    }
    let path = directory.path().join("input");
    fs::write(&path, b"CAPACITY_A_39_3\0CAPACITY_B_39_3").unwrap();
    let report = sentinel::scan_with_rules(path, rules);
    assert_eq!(report.status, ScanStatus::Complete, "{report:?}");
    assert_eq!(report.verdict, Verdict::TestMatch);
    let RuleSetStatus::Ready { info } = report.rules else {
        panic!("Collection failed");
    };
    assert_eq!(info.sources.len(), 40);
    assert_eq!(info.rule_count, 160);
    assert_eq!(report.summary.signature_matches, 1);
}
