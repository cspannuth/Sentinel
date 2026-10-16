use std::fs;

use sentinel::signatures::{RuleCategory, RuleSetStatus, SignatureOutcome};
use sentinel::{ScanStatus, Verdict, scan, scan_with_rules};
use yara_x::{Compiler, Rules, Scanner};

mod common;

struct Fixture {
    rule: &'static str,
    bytes: Vec<u8>,
    near_miss: Vec<u8>,
    verdict: Verdict,
    size_limit: Option<usize>,
}

fn pe_with(data: &[u8]) -> Vec<u8> {
    let mut bytes = common::pe_file(false, false);
    bytes.extend_from_slice(data);
    bytes
}

fn wide_strings(strings: &[&str]) -> Vec<u8> {
    strings
        .iter()
        .flat_map(|value| value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes))
        .collect()
}

// These are invented byte containers, not malware samples. Never execute them.
fn fixtures() -> Vec<Fixture> {
    let mut fixtures = vec![
        Fixture {
            rule: "WannaCry_Ransomware_Gen",
            bytes: pe_with(b"__TREEID__PLACEHOLDER__\0__USERID__PLACEHOLDER__\0Windows for Workgroups 3.1a\0PC NETWORK PROGRAM 1.0\0LANMAN1.0\0"),
            near_miss: pe_with(b"__TREEID__PLACEHOLDER__\0__USERID__PLACEHOLDER__\0Windows for Workgroups 3.1a\0PC NETWORK PROGRAM 1.0\0"),
            verdict: Verdict::KnownMaliciousMatch,
            size_limit: Some(5000 * 1024),
        },
        Fixture {
            rule: "WannCry_m_vbs",
            bytes: b"SE\0.TargetPath = \"C:\\@\0.CreateShortcut(\"C:\\@\0 = WScript.CreateObject(\"WScript.Shell\")\0".to_vec(),
            near_miss: b"SE\0.CreateShortcut(\"C:\\@\0 = WScript.CreateObject(\"WScript.Shell\")\0".to_vec(),
            verdict: Verdict::Suspicious,
            size_limit: Some(1024),
        },
        Fixture {
            rule: "WannaCry_RansomNote",
            bytes: b"Q: What's wrong with my files?\0A: Don't worry about decryption.\0".to_vec(),
            near_miss: b"Q: What's wrong with my files?\0A: Example explanation.\0".to_vec(),
            verdict: Verdict::Suspicious,
            size_limit: Some(2 * 1024),
        },
    ];

    for pattern in [
        "@.exe\">> m.vbs",
        "cscript.exe //nologo m.vbs",
        "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> ",
        "echo om.Save>> m.vbs",
    ] {
        let mut bytes = b"@e\0".to_vec();
        bytes.extend_from_slice(pattern.as_bytes());
        bytes.push(0);
        fixtures.push(Fixture {
            rule: "WannCry_BAT",
            bytes,
            near_miss: b"@e\0ordinary inert text\0".to_vec(),
            verdict: Verdict::Suspicious,
            size_limit: Some(1024),
        });
    }

    // Both HyperBro branches must retain their four-pattern threshold and UTF-16 semantics.
    for strings in [
        vec![
            "\\cmd.exe /A",
            "vftrace.dll",
            "msmpeng.exe",
            "\\\\.\\pipe\\testpipe",
        ],
        vec![
            "%s\\%d.exe",
            "https://%s:%d/api/v2/ajax",
            " -k networkservice",
            " -k localservice",
        ],
    ] {
        fixtures.push(Fixture {
            rule: "HvS_APT27_HyperBro_Stage3",
            bytes: pe_with(&wide_strings(&strings)),
            near_miss: pe_with(&wide_strings(&strings[..3])),
            verdict: Verdict::KnownMaliciousMatch,
            size_limit: Some(300 * 1024),
        });
    }

    // All three AlienSpy branches are exercised, including the shared pattern normalization.
    for strings in [
        vec![
            "META-INF/MANIFEST.MF",
            "Main.classPK",
            "plugins/Server.classPK",
            "IDPK",
        ],
        vec![
            "config.iniPK",
            "password.iniPK",
            "plugins/Server.classPK",
            "LoadStub.classPK",
            "LoadStubDecrypted.classPK",
            "LoadPassword.classPK",
            "DecryptStub.classPK",
            "ClassLoaders.classPK",
        ],
        vec![
            "config.xml",
            "options",
            "plugins",
            "util/OSHelper",
            "Start.class",
            "AlienSpy",
        ],
    ] {
        let container = |values: &[&str]| {
            let mut bytes = b"PK\0".to_vec();
            bytes.extend_from_slice(values.join("\0").as_bytes());
            bytes.push(0);
            bytes
        };
        // Remove the shared pattern from branch B rather than an unrelated field.
        let missing = if strings.len() == 8 {
            2
        } else {
            strings.len() - 1
        };
        let near: Vec<_> = strings
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (index != missing).then_some(*value))
            .collect();
        fixtures.push(Fixture {
            rule: "crime_win_rat_AlienSpy",
            bytes: container(&strings),
            near_miss: container(&near),
            verdict: Verdict::KnownMaliciousMatch,
            size_limit: Some(800 * 1024),
        });
    }

    for certificate in [
        [
            0x52, 0x76, 0xa4, 0x53, 0xcd, 0x70, 0x9c, 0x18, 0xda, 0x65, 0x15, 0x7e, 0x5f, 0x1f,
            0xde, 0x02,
        ],
        [
            0x12, 0x90, 0xf2, 0x41, 0xd9, 0xb2, 0x80, 0xaf, 0x77, 0xfc, 0xda, 0x12, 0xc6, 0xb4,
            0x96, 0x9c,
        ],
    ] {
        let mut changed = certificate;
        changed[0] ^= 1;
        fixtures.push(Fixture {
            rule: "Gazer_certificate",
            bytes: pe_with(&certificate),
            near_miss: pe_with(&changed),
            verdict: Verdict::Suspicious,
            size_limit: Some(2 * 1024 * 1024),
        });
    }

    let mut log = vec![
        0x01, 0x87, 0xc9, 0x75, 0xc8, 0x69, 0x98, 0xac, 0xe0, 0xc9, 0x7b,
    ];
    log.extend([0; 21]);
    log.extend([0xeb, 0xbb, 0x60, 0xbb, 0x5a]);
    let mut shifted_log = vec![0];
    shifted_log.extend_from_slice(&log);
    fixtures.push(Fixture {
        rule: "turla_outlook_log",
        bytes: log,
        near_miss: shifted_log,
        verdict: Verdict::Suspicious,
        size_limit: None,
    });

    let pdf_text =
        b"%PDF-1.4\0Adobe PDF Library 9.0\0Acrobat PDFMaker 9.0\0W5M0MpCehiHzreSzNTczkc9d\0";
    let mut pdf = pdf_text.to_vec();
    pdf.extend([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]);
    fixtures.push(Fixture {
        rule: "turla_outlook_pdf",
        bytes: pdf,
        near_miss: pdf_text.to_vec(),
        verdict: Verdict::Suspicious,
        size_limit: None,
    });
    fixtures
}

fn matching(rules: &Rules, bytes: &[u8]) -> Vec<String> {
    let mut scanner = Scanner::new(rules);
    let mut names: Vec<_> = scanner
        .scan(bytes)
        .unwrap()
        .matching_rules()
        .map(|rule| rule.identifier().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn imported_rules_match_harmless_fixtures_and_reject_near_misses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inert-fixture.data");
    for fixture in fixtures() {
        fs::write(&path, &fixture.bytes).unwrap();
        let report = scan(&path);
        assert_eq!(
            report.status,
            ScanStatus::Complete,
            "{}: {report:?}",
            fixture.rule
        );
        assert_eq!(report.verdict, fixture.verdict, "{}", fixture.rule);
        let Some(SignatureOutcome::Complete { matches }) = &report.files[0].signatures else {
            panic!("Missing signature result: {report:?}");
        };
        assert_eq!(matches.len(), 1, "{}: {matches:?}", fixture.rule);
        let found = &matches[0];
        assert_eq!(found.rule_id, fixture.rule);
        assert!(!found.author.is_empty());
        assert!(!found.license.is_empty());
        assert_eq!(found.version, "sentinel-import-1");
        assert!(!found.locations.is_empty());
        assert_eq!(
            found.category == RuleCategory::KnownMalicious,
            fixture.verdict == Verdict::KnownMaliciousMatch
        );

        fs::write(&path, &fixture.near_miss).unwrap();
        assert_eq!(
            scan(&path).verdict,
            Verdict::NoDetections,
            "{} near miss",
            fixture.rule
        );
        if let Some(limit) = fixture.size_limit {
            let mut at_limit = fixture.bytes;
            at_limit.resize(limit, 0);
            fs::write(&path, at_limit).unwrap();
            assert_eq!(
                scan(&path).verdict,
                Verdict::NoDetections,
                "{} size boundary",
                fixture.rule
            );
        }
    }
}

#[test]
fn adaptations_preserve_upstream_matches_across_branches_and_boundaries() {
    let mut upstream = Compiler::new();
    upstream
        .add_source(include_str!("../rules/upstream/eset-selected.yar"))
        .unwrap();
    upstream
        .add_source(include_str!(
            "../rules/upstream/signature-base-selected.yar"
        ))
        .unwrap();
    // The sole upstream warning is AlienSpy's identical string in two branches.
    assert_eq!(upstream.warnings().len(), 1);
    assert!(
        upstream.warnings()[0]
            .to_string()
            .contains("duplicate_pattern_value")
    );
    let upstream = upstream.build();
    let mut adapted = Compiler::new();
    adapted
        .add_source(include_str!("../rules/eset.yar"))
        .unwrap();
    adapted
        .add_source(include_str!("../rules/signature_base.yar"))
        .unwrap();
    assert!(adapted.warnings().is_empty());
    let adapted = adapted.build();

    for fixture in fixtures() {
        assert_eq!(
            matching(&upstream, &fixture.bytes),
            vec![fixture.rule.to_owned()]
        );
        let mut examples = vec![fixture.bytes.clone(), fixture.near_miss];
        if fixture.rule != "turla_outlook_pdf" {
            let mut bad_header = fixture.bytes.clone();
            bad_header[0] ^= 1;
            assert!(
                matching(&upstream, &bad_header).is_empty(),
                "{} header",
                fixture.rule
            );
            examples.push(bad_header);
        }
        if let Some(limit) = fixture.size_limit {
            let mut below_limit = fixture.bytes;
            below_limit.resize(limit - 1, 0);
            assert_eq!(
                matching(&upstream, &below_limit),
                vec![fixture.rule.to_owned()]
            );
            examples.push(below_limit.clone());
            below_limit.push(0);
            assert!(matching(&upstream, &below_limit).is_empty());
            examples.push(below_limit);
        }
        for bytes in examples {
            assert_eq!(
                matching(&upstream, &bytes),
                matching(&adapted, &bytes),
                "{} adaptation",
                fixture.rule
            );
        }
    }
}

#[test]
fn benign_content_and_rule_sources_have_no_detections() {
    let directory = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("empty", Vec::new()),
        (
            "plain",
            b"ordinary documentation about PowerShell and Windows networking".to_vec(),
        ),
        (
            "image",
            b"%PDF-1.4 Adobe PDF Library 9.0 Acrobat PDFMaker 9.0".to_vec(),
        ),
        (
            "archive",
            b"PK\0META-INF/MANIFEST.MF\0Main.classPK\0".to_vec(),
        ),
        ("pe", common::pe_file(true, true)),
        (
            "binary",
            (0..8192).map(|index| (index % 251) as u8).collect(),
        ),
    ] {
        fs::write(directory.path().join(name), bytes).unwrap();
    }
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.verdict, Verdict::NoDetections);
    assert_eq!(report.summary.signature_scanned, 6);
    assert_eq!(report.summary.signature_matches, 0);

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = scan(root.join("rules"));
    assert_eq!(sources.status, ScanStatus::Complete, "{sources:?}");
    assert_eq!(sources.verdict, Verdict::NoDetections);
    let overridden = scan_with_rules(directory.path(), root.join("rules"));
    let RuleSetStatus::Ready { info: explicit } = overridden.rules else {
        panic!("Explicit rules failed: {overridden:?}");
    };
    let RuleSetStatus::Ready { info: bundled } = report.rules else {
        panic!("Bundled rules failed");
    };
    assert_eq!(explicit.rule_count, 20);
    assert_eq!(explicit.sha256, bundled.sha256);
}
