use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use sentinel::{ScanOptions, ScanStatus, Verdict, scan_with_options};

const USAGE: &str = "Usage: sentinel scan <path> [--rules <directory>] [--hashes <file>]\n       sentinel --help\n\nHash files, compare known hashes, inspect PE structure, and apply local YARA-X signatures.\nWrites JSON to stdout. Files are never executed or uploaded.\nUses bundled rules and hash indicators unless independently replaced.\n--hashes accepts a versioned JSON database, not a raw digest list.\n\nExit codes: 0 complete/no actionable detections (including benign tests),\n            1 partial/failed/skipped scan or output error,\n            2 invalid arguments, 3 complete scan with suspicious/malicious evidence.";

fn main() -> ExitCode {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
        return match writeln!(io::stdout().lock(), "{USAGE}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => output_error(error),
        };
    }
    let Some(options) = scan_options(&arguments) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    let report = scan_with_options(&arguments[1], &options);
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    if let Err(error) = serde_json::to_writer_pretty(&mut stdout, &report) {
        eprintln!("Could not write scan report: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = writeln!(stdout).and_then(|()| stdout.flush()) {
        return output_error(error);
    }
    if report.status == ScanStatus::Complete {
        if matches!(
            report.verdict,
            Verdict::KnownMaliciousMatch | Verdict::Suspicious
        ) {
            eprintln!("Detection evidence found; consult the JSON report.");
            ExitCode::from(3)
        } else {
            ExitCode::SUCCESS
        }
    } else {
        eprintln!(
            "Scan {:?}; consult the JSON report for skipped entries, incomplete checks, and errors.",
            report.status
        );
        ExitCode::FAILURE
    }
}

fn scan_options(arguments: &[OsString]) -> Option<ScanOptions> {
    if arguments.len() < 2 || arguments[0] != "scan" || arguments[1].is_empty() {
        return None;
    }
    let mut options = ScanOptions::default();
    for pair in arguments[2..].chunks(2) {
        if pair.len() != 2 || pair[1].is_empty() || pair[1] == "--rules" || pair[1] == "--hashes" {
            return None;
        }
        let destination = if pair[0] == "--rules" {
            &mut options.rules_directory
        } else if pair[0] == "--hashes" {
            &mut options.hash_database
        } else {
            return None;
        };
        if destination.replace(PathBuf::from(&pair[1])).is_some() {
            return None;
        }
    }
    Some(options)
}

fn output_error(error: io::Error) -> ExitCode {
    eprintln!("Could not write output: {error}");
    ExitCode::FAILURE
}
