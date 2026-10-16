mod common;

use sentinel::pe::{MAX_PE_BYTES, PeFormat, PeImport, PeLimit, PeOutcome, PeReport};
use sentinel::{FileOutcome, ScanReport, ScanStatus, scan};
use std::{fs, io::Write};

fn inspect(bytes: &[u8], name: &str) -> ScanReport {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(name);
    fs::write(&path, bytes).unwrap();
    scan(path)
}

fn parsed(report: &ScanReport) -> &PeReport {
    assert_eq!(report.status, ScanStatus::Complete);
    assert_eq!(report.summary.pe_analyzed, 1);
    assert_eq!(report.summary.pe_incomplete, 0);
    match report.files[0].pe.as_ref().unwrap() {
        PeOutcome::Analyzed { report } => report,
        outcome => panic!("Expected analyzed PE, got {outcome:?}"),
    }
}

fn assert_failed_analysis(bytes: &[u8]) {
    let report = inspect(bytes, "malformed.exe");
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.pe_incomplete, 1);
    assert!(
        matches!(&report.files[0].outcome, FileOutcome::Hashed { sha256 } if sha256.len() == 64)
    );
    assert!(matches!(report.files[0].pe, Some(PeOutcome::Failed { .. })));
    assert!(report.issues.is_empty());
}

#[test]
fn pe32_and_pe32plus_report_headers_sections_and_imports() {
    for is_64 in [false, true] {
        let bytes = common::pe_file(is_64, true);
        let report = inspect(&bytes, "sample"); // Extensionless PE
        let pe = parsed(&report);
        assert_eq!(
            pe.format,
            if is_64 {
                PeFormat::Pe32Plus
            } else {
                PeFormat::Pe32
            }
        );
        assert_eq!(pe.architecture, if is_64 { "x86_64" } else { "x86" });
        assert_eq!(pe.machine, if is_64 { 0x8664 } else { 0x14c });
        assert!(pe.is_dll);
        assert_eq!(pe.coff_timestamp, 1_700_000_000);
        assert_eq!(pe.subsystem, 3);
        assert_eq!(pe.dll_characteristics, 0x140);
        assert_eq!(pe.entry_point_rva, 0x1000);
        assert_eq!(pe.image_base, if is_64 { 0x1_4000_0000 } else { 0x40_0000 });
        assert_eq!(pe.size_of_headers, 0x200);
        assert_eq!(pe.sections.len(), 1);
        let section = &pe.sections[0];
        assert_eq!(section.name, ".text");
        assert_eq!(section.raw_offset, 0x200);
        assert_eq!(section.raw_size, 0x400);
        assert_eq!(section.virtual_address, 0x1000);
        assert_eq!(section.virtual_size, 0x400);
        assert!(section.readable && section.executable && !section.writable);
        assert!(section.entropy.is_finite() && (0.0..=8.0).contains(&section.entropy));
        assert_eq!(pe.imports.len(), 1);
        assert_eq!(pe.imports[0].dll, "KERNEL32.dll");
        assert_eq!(pe.imports[0].symbols.len(), 2);
        assert!(
            matches!(&pe.imports[0].symbols[0], PeImport::Name { name, hint: 7 } if name == "ExitProcess")
        );
        assert!(matches!(
            pe.imports[0].symbols[1],
            PeImport::Ordinal { ordinal: 42 }
        ));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], 4);
        assert_eq!(json["files"][0]["status"], "hashed");
        assert_eq!(json["files"][0]["pe"]["status"], "analyzed");
        assert_eq!(json["files"][0]["verdict"], "no_detections");
    }
}

#[test]
fn content_controls_identification_and_valid_absences_are_not_errors() {
    let report = inspect(b"ordinary text", "pretend.exe");
    assert_eq!(report.status, ScanStatus::Complete);
    assert!(matches!(report.files[0].pe, Some(PeOutcome::NotPe)));
    let report = inspect(&common::pe_file(true, false), "pretend.txt");
    assert!(parsed(&report).imports.is_empty());
    let report = inspect(&[], "empty.exe");
    assert_eq!(report.status, ScanStatus::Complete);
    assert!(matches!(report.files[0].pe, Some(PeOutcome::NotPe)));
}

#[test]
fn entropy_uses_raw_bytes_and_handles_empty_sections() {
    let mut bytes = common::pe_file(false, false);
    let section = 0x98 + 224;
    bytes[0x200..].fill(0);
    assert_eq!(
        parsed(&inspect(&bytes, "zero.exe")).sections[0].entropy,
        0.0
    );
    for (index, byte) in bytes[0x200..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    assert!((parsed(&inspect(&bytes, "uniform.exe")).sections[0].entropy - 8.0).abs() < 1e-12);
    bytes[section + 16..section + 20].copy_from_slice(&0_u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(parsed(&inspect(&bytes, "bss.exe")).sections[0].entropy, 0.0);
}

#[test]
fn malformed_headers_ranges_and_imports_preserve_the_hash_but_are_partial() {
    let original = common::pe_file(true, true);
    for length in [2, 63, 0x82, 0x90, 0x100, 0x190, 0x5ff] {
        assert_failed_analysis(&original[..length]);
    }
    for (offset, value) in [
        (0x3c, u32::MAX),            // Bad e_lfanew
        (0x3c, 0),                   // Header overlap
        (0x80, 0),                   // Bad PE signature
        (0x98 + 60, u32::MAX),       // Bad header extent
        (0x98 + 240 + 20, u32::MAX), // Bad raw section offset
        (0x98 + 240 + 16, u32::MAX), // Bad raw section size
        (0x98 + 112 + 8, 0x9000),    // Unmapped import directory
        (0x98 + 112 + 12, 20),       // Missing terminating descriptor
        (0x300, 0x9000),             // Unmapped lookup RVA
        (0x30c, 0x9000),             // Unmapped DLL name
        (0x310, 0),                  // Missing IAT
        (0x310, 0x13fc),             // IAT slot crosses end of section
        (0x380, 0x9000),             // Unmapped imported symbol name
    ] {
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert_failed_analysis(&bytes);
    }
    let mut bytes = original.clone();
    bytes[0x94..0x96].copy_from_slice(&2_u16.to_le_bytes());
    assert_failed_analysis(&bytes); // Optional header must fit its declared extent
    let mut bytes = original.clone();
    bytes[0x360] = 0xff;
    assert_failed_analysis(&bytes); // Invalid UTF-8 DLL name is explicit failure
    let mut bytes = original.clone();
    bytes[0x380..0x398].fill(0xff);
    assert_failed_analysis(&bytes); // Ordinal reserved bits
    let mut bytes = original;
    bytes[0x380..0x600].fill(0);
    for thunk in bytes[0x380..0x600].as_chunks_mut::<8>().0 {
        thunk.copy_from_slice(&0x8000_0000_0000_0001_u64.to_le_bytes());
    }
    assert_failed_analysis(&bytes); // No lookup terminator within on-disk range
}

#[test]
fn lookup_falls_back_to_iat_and_unknown_machine_codes_are_preserved() {
    let mut bytes = common::pe_file(false, true);
    bytes[0x300..0x304].fill(0);
    bytes[0x84..0x86].copy_from_slice(&0x7777_u16.to_le_bytes());
    let report = inspect(&bytes, "unknown.exe");
    let pe = parsed(&report);
    assert_eq!(pe.machine, 0x7777);
    assert_eq!(pe.architecture, "unknown");
    assert_eq!(pe.imports[0].symbols.len(), 2);
}

#[test]
fn overlapping_import_mappings_are_reported_instead_of_guessed() {
    let mut bytes = common::pe_file(false, true);
    let section = 0x98 + 224;
    bytes.copy_within(section..section + 40, section + 40);
    bytes[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
    assert_failed_analysis(&bytes);
}

#[test]
fn section_and_input_limits_are_explicit_and_hashing_continues() {
    let mut bytes = common::pe_file(true, false);
    bytes[0x86..0x88].copy_from_slice(&257_u16.to_le_bytes());
    let report = inspect(&bytes, "sections.exe");
    assert_eq!(report.status, ScanStatus::Partial);
    assert!(matches!(
        report.files[0].pe,
        Some(PeOutcome::Skipped {
            reason: PeLimit::Sections,
            limit: 256
        })
    ));

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.exe");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(b"MZ").unwrap();
    file.set_len(MAX_PE_BYTES + 1).unwrap();
    drop(file);
    let report = scan(&path);
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 1);
    assert_eq!(report.summary.pe_incomplete, 1);
    assert!(matches!(
        report.files[0].pe,
        Some(PeOutcome::Skipped {
            reason: PeLimit::InputBytes,
            limit: MAX_PE_BYTES
        })
    ));
    assert!(matches!(
        report.files[0].signatures,
        Some(sentinel::signatures::SignatureOutcome::Skipped {
            reason: sentinel::signatures::SignatureLimit::InputBytes,
            ..
        })
    ));
    assert_eq!(report.summary.signature_incomplete, 1);
}

#[test]
fn directory_preserves_successful_pe_and_non_pe_results_next_to_malformed_files() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("valid"), common::pe_file(true, false)).unwrap();
    fs::write(directory.path().join("text.exe"), b"text").unwrap();
    fs::write(directory.path().join("bad"), b"MZ").unwrap();
    let report = scan(directory.path());
    assert_eq!(report.status, ScanStatus::Partial);
    assert_eq!(report.summary.hashed, 3);
    assert_eq!(report.summary.pe_analyzed, 1);
    assert_eq!(report.summary.pe_incomplete, 1);
    assert_eq!(report.files.len(), 3);
}

#[test]
fn legacy_dos_ne_header_is_not_misreported_as_a_valid_pe() {
    let mut bytes = common::pe_file(false, false);
    bytes[0x80..0x84].copy_from_slice(b"NE\0\0");
    let report = inspect(&bytes, "legacy.exe");
    assert_eq!(report.status, ScanStatus::Complete);
    assert!(matches!(report.files[0].pe, Some(PeOutcome::NotPe)));
}
