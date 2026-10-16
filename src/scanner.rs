use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use crate::pe::{self, MAX_PE_BYTES, PeLimit, PeOutcome};
use crate::reputation::{self, HashDatabase, HashDatabaseError, HashDatabaseStatus, HashOutcome};
use crate::signatures::{
    self, MAX_SIGNATURE_BYTES, RuleSetStatus, SignatureError, SignatureErrorKind, SignatureOutcome,
    SignatureSet,
};
use sha2::{Digest, Sha256};

use crate::report::{
    FileMetadata, FileOutcome, FileReport, Operation, ScanError, ScanIssue, ScanReport, ScanStatus,
    SkipReason, Summary, Verdict,
};

const BUFFER_SIZE: usize = 64 * 1024;

/// Optional replacements for the two bundled local detection collections.
#[derive(Debug, Default, Clone)]
pub struct ScanOptions {
    pub rules_directory: Option<PathBuf>,
    /// A schema-versioned JSON indicator database; replaces the bundled hashes.
    pub hash_database: Option<PathBuf>,
}

/// Hash regular files, compare known hashes, inspect PE candidates, and apply YARA rules.
///
/// Always returns a report, including for invalid targets. Directory failures are
/// recorded in `issues`; failures opening or reading files are per-file outcomes.
/// Links and Windows reparse points (including linked input ancestors) are skipped.
/// Consistency and traversal checks are best effort, not an atomic filesystem snapshot.
pub fn scan(path: impl AsRef<Path>) -> ScanReport {
    scan_with_options(path, &ScanOptions::default())
}

/// Replace bundled rules with a local directory. Invalid rules still produce a
/// report containing available hash/PE observations and explicit setup failure.
pub fn scan_with_rules(path: impl AsRef<Path>, directory: impl AsRef<Path>) -> ScanReport {
    scan_with_options(
        path,
        &ScanOptions {
            rules_directory: Some(directory.as_ref().to_path_buf()),
            ..ScanOptions::default()
        },
    )
}

pub(crate) type SignatureContext<'a> = Result<&'a SignatureSet, &'a SignatureError>;
pub(crate) type HashContext<'a> = Result<&'a HashDatabase, &'a HashDatabaseError>;

/// Scan offline with independently replaceable YARA rules and hash indicators.
/// Invalid replacements are explicit failures, never fallbacks to bundled data.
pub fn scan_with_options(path: impl AsRef<Path>, options: &ScanOptions) -> ScanReport {
    let local_rules = options
        .rules_directory
        .as_ref()
        .map(|path| SignatureSet::load_directory(path));
    let rules = match &local_rules {
        Some(local) => local.as_ref(),
        None => signatures::bundled_rules().as_ref(),
    };
    let local_hashes = options.hash_database.as_ref().map(HashDatabase::load);
    let hashes = match &local_hashes {
        Some(local) => local.as_ref(),
        None => reputation::bundled_hashes().as_ref(),
    };
    scan_impl(path.as_ref(), rules, hashes)
}

fn scan_impl(path: &Path, rules: SignatureContext<'_>, hashes: HashContext<'_>) -> ScanReport {
    let mut report = ScanReport {
        schema_version: 4,
        target: path.to_path_buf(),
        status: ScanStatus::Failed,
        verdict: Verdict::Error,
        rules: match rules {
            Ok(rules) => rules.status(),
            Err(error) => RuleSetStatus::Failed {
                error: error.clone(),
            },
        },
        summary: Summary::default(),
        hash_database: match hashes {
            Ok(database) => database.status(),
            Err(error) => HashDatabaseStatus::Failed {
                error: error.clone(),
            },
        },
        files: Vec::new(),
        issues: Vec::new(),
    };
    if let Err(error) = validate_path(path) {
        add_issue(&mut report, path, Operation::ValidatePath, error);
        return finish(report);
    }
    let target = match std::path::absolute(path) {
        // Remove trailing separators and `.` so metadata cannot dereference a
        // final directory link through a path such as `link/` (notably on Unix).
        Ok(target) => target.components().collect::<PathBuf>(),
        Err(error) => {
            add_issue(&mut report, path, Operation::ValidatePath, error);
            return finish(report);
        }
    };
    report.target = target.clone();

    // Check components in root-to-leaf order before accessing the requested target.
    match linked_ancestor(&target) {
        Ok(Some(_)) => {
            report
                .files
                .push(skipped(&target, None, SkipReason::SymlinkOrReparsePoint));
            report.status = ScanStatus::Skipped;
            return finish(report);
        }
        Err((path, error)) => {
            add_issue(&mut report, &path, Operation::Metadata, error);
            return finish(report);
        }
        Ok(None) => {}
    }

    let metadata = match fs::symlink_metadata(&target) {
        Ok(metadata) => metadata,
        Err(error) => {
            add_issue(&mut report, &target, Operation::Metadata, error);
            return finish(report);
        }
    };
    if let Some(reason) = skip_reason(&metadata) {
        report.files.push(skipped(&target, Some(&metadata), reason));
        report.status = ScanStatus::Skipped;
    } else if metadata.is_file() {
        let file = scan_file(&target, &metadata, rules, hashes);
        report.status = match &file.outcome {
            FileOutcome::Hashed { .. } if file.is_complete() => ScanStatus::Complete,
            FileOutcome::Hashed { .. } => ScanStatus::Partial,
            FileOutcome::Failed { .. } => ScanStatus::Failed,
            FileOutcome::Skipped { .. } => ScanStatus::Skipped,
            FileOutcome::Inconclusive { .. } => ScanStatus::Partial,
        };
        report.files.push(file);
    } else {
        report.status = ScanStatus::Complete;
        scan_directory(&target, &mut report, rules, hashes);
        if !report.issues.is_empty() || report.files.iter().any(|file| !file.is_complete()) {
            report.status = if report.files.is_empty()
                && report.issues.iter().any(|issue| issue.path == target)
            {
                ScanStatus::Failed
            } else {
                ScanStatus::Partial
            };
        }
    }
    finish(report)
}

fn scan_directory(
    target: &Path,
    report: &mut ScanReport,
    rules: SignatureContext<'_>,
    hashes: HashContext<'_>,
) {
    // Only one ReadDir is open at a time; recursion does not consume the call stack.
    let mut pending = vec![target.to_path_buf()];
    while let Some(directory) = pending.pop() {
        match linked_ancestor(&directory) {
            Ok(Some(_)) => {
                report
                    .files
                    .push(skipped(&directory, None, SkipReason::SymlinkOrReparsePoint));
                continue;
            }
            Err((path, error)) => {
                add_issue(report, &path, Operation::Metadata, error);
                continue;
            }
            Ok(None) => {}
        }
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) => {
                add_issue(report, &directory, Operation::Metadata, error);
                continue;
            }
        };
        if let Some(reason) = skip_reason(&metadata) {
            report
                .files
                .push(skipped(&directory, Some(&metadata), reason));
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                add_issue(report, &directory, Operation::ReadDirectory, error);
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    add_issue(report, &directory, Operation::ReadDirectory, error);
                    continue;
                }
            };
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    add_issue(report, &path, Operation::Metadata, error);
                    continue;
                }
            };
            if let Some(reason) = skip_reason(&metadata) {
                report.files.push(skipped(&path, Some(&metadata), reason));
            } else if metadata.is_dir() {
                pending.push(path);
            } else {
                report
                    .files
                    .push(scan_file(&path, &metadata, rules, hashes));
            }
        }
    }
}

fn scan_file(
    path: &Path,
    discovered: &Metadata,
    rules: SignatureContext<'_>,
    hashes: HashContext<'_>,
) -> FileReport {
    scan_file_controlled(
        path,
        discovered,
        rules,
        hashes,
        &crate::ScanControl::default(),
    )
}

pub(crate) fn scan_file_controlled(
    path: &Path,
    discovered: &Metadata,
    rules: SignatureContext<'_>,
    hashes: HashContext<'_>,
    control: &crate::ScanControl,
) -> FileReport {
    let (mut outcome, mut pe, mut signatures) = inspect_file(path, discovered, rules, control)
        .unwrap_or_else(|error| (FileOutcome::Failed { error }, None, None));
    if control.is_cancelled() {
        outcome = FileOutcome::Inconclusive {
            reason: "Scan cancelled during file inspection; conclusions withheld".into(),
        };
        pe = None;
        signatures = None;
    }
    // Only compare a digest after all target-file consistency checks passed.
    let hash_reputation = match &outcome {
        FileOutcome::Hashed { sha256 } => Some(match hashes {
            Ok(database) => database.check(sha256),
            Err(error) => HashOutcome::Failed {
                error: error.clone(),
            },
        }),
        _ => None,
    };
    FileReport {
        path: path.to_path_buf(),
        metadata: Some(FileMetadata::from(discovered)),
        outcome,
        pe,
        signatures,
        hash_reputation,
        verdict: Verdict::Inconclusive, // Finalized with completeness in finish().
    }
}

pub(crate) fn validate_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target path must not be empty",
        ));
    }
    #[cfg(windows)]
    for component in path.components() {
        use std::path::Prefix;
        match component {
            Component::Prefix(prefix)
                if !matches!(
                    prefix.kind(),
                    Prefix::Disk(_)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::UNC(_, _)
                        | Prefix::VerbatimUNC(_, _)
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Device namespaces are not scan targets",
                ));
            }
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                let stem = name
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(' ')
                    .to_ascii_uppercase();
                let numbered_device = stem
                    .strip_prefix("COM")
                    .or_else(|| stem.strip_prefix("LPT"))
                    .is_some_and(|suffix| {
                        matches!(
                            suffix,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    });
                if name.contains(':')
                    || matches!(
                        stem.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    )
                    || numbered_device
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Device names and alternate data streams are not scan targets",
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn inspect_file(
    path: &Path,
    discovered: &Metadata,
    rules: SignatureContext<'_>,
    control: &crate::ScanControl,
) -> Result<(FileOutcome, Option<PeOutcome>, Option<SignatureOutcome>), ScanError> {
    validate_path(path).map_err(|error| ScanError::new(Operation::ValidatePath, error))?;
    match linked_ancestor(path) {
        Ok(Some(_)) => {
            return Ok((
                FileOutcome::Skipped {
                    reason: SkipReason::SymlinkOrReparsePoint,
                },
                None,
                None,
            ));
        }
        Err((_, error)) => return Err(ScanError::new(Operation::Metadata, error)),
        Ok(None) => {}
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the final reparse point itself, never its target. Zero is SECURITY_ANONYMOUS.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .security_qos_flags(0);
    }
    let mut file = options
        .open(path)
        .map_err(|error| ScanError::new(Operation::OpenFile, error))?;
    let before = file
        .metadata()
        .map_err(|error| ScanError::new(Operation::Metadata, error))?;
    if let Some(reason) = skip_reason(&before) {
        return Ok((FileOutcome::Skipped { reason }, None, None));
    }
    if !same_observation(discovered, &before) {
        return Ok((changed(), None, None));
    }
    let digest = hash_reader_controlled(&mut file, before.len(), rules, control)
        .map_err(|error| ScanError::new(Operation::ReadFile, error))?;
    let after = file
        .metadata()
        .map_err(|error| ScanError::new(Operation::Metadata, error))?;
    let path_after =
        fs::symlink_metadata(path).map_err(|error| ScanError::new(Operation::Metadata, error))?;
    match digest {
        Some(result)
            if same_observation(&before, &after) && same_observation(&after, &path_after) =>
        {
            Ok((
                FileOutcome::Hashed {
                    sha256: result.sha256,
                },
                Some(result.pe),
                Some(result.signatures),
            ))
        }
        _ => Ok((changed(), None, None)),
    }
}

fn changed() -> FileOutcome {
    FileOutcome::Inconclusive {
        reason: "File changed during scanning; SHA-256 withheld".into(),
    }
}

#[derive(Debug)]
struct ReadResult {
    sha256: String,
    pe: PeOutcome,
    signatures: SignatureOutcome,
}

/// Hash once, retaining bounded bytes for signatures and PE from that same stream.
/// Read at most the original size plus one to bound work on an appending file.
#[cfg(test)]
fn hash_reader(
    reader: impl Read,
    expected_size: u64,
    rules: SignatureContext<'_>,
) -> io::Result<Option<ReadResult>> {
    hash_reader_controlled(reader, expected_size, rules, &crate::ScanControl::default())
}

fn hash_reader_controlled(
    reader: impl Read,
    expected_size: u64,
    rules: SignatureContext<'_>,
    control: &crate::ScanControl,
) -> io::Result<Option<ReadResult>> {
    let mut reader = reader.take(expected_size.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; BUFFER_SIZE];
    let mut bytes_read = 0_u64;
    let mut prefix = Vec::with_capacity(2);
    let mut captured = Vec::new();
    let mut allocation_failed = false;
    let capture_for_signatures = rules.is_ok() && expected_size <= MAX_SIGNATURE_BYTES;
    loop {
        if control.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Scan cancelled"));
        }
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        bytes_read += count as u64;
        control.read(count);
        if control.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Scan cancelled"));
        }
        hasher.update(&buffer[..count]);
        if prefix.len() < 2 {
            prefix.extend_from_slice(&buffer[..count.min(2 - prefix.len())]);
        }
        if (capture_for_signatures
            || (expected_size <= MAX_PE_BYTES && (prefix.len() < 2 || prefix == b"MZ")))
            && !allocation_failed
        {
            if captured.capacity() < expected_size as usize {
                allocation_failed = captured
                    .try_reserve_exact(expected_size as usize - captured.len())
                    .is_err();
            }
            if !allocation_failed {
                // Do not capture the extra growth-detection byte beyond the input limit.
                let remaining = expected_size as usize - captured.len();
                captured.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        } else if !capture_for_signatures && prefix != b"MZ" {
            captured.clear();
        }
    }
    if bytes_read != expected_size {
        return Ok(None);
    }
    if control.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "Scan cancelled"));
    }
    let pe = if prefix != b"MZ" {
        PeOutcome::NotPe
    } else if expected_size > MAX_PE_BYTES {
        pe::limited(PeLimit::InputBytes, MAX_PE_BYTES)
    } else if allocation_failed {
        PeOutcome::Failed {
            message: "Could not allocate the bounded PE input buffer".into(),
        }
    } else {
        pe::analyze(&captured)
    };
    if control.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "Scan cancelled"));
    }
    let signatures = match rules {
        Err(error) => SignatureOutcome::Failed {
            error: error.clone(),
        },
        Ok(_) if expected_size > MAX_SIGNATURE_BYTES => signatures::input_limit(),
        Ok(_) if allocation_failed => SignatureOutcome::Failed {
            error: SignatureError::new(
                SignatureErrorKind::Allocation,
                "Could not allocate the bounded signature input buffer",
            ),
        },
        Ok(rules) => rules.scan(&captured),
    };
    Ok(Some(ReadResult {
        sha256: format!("{:x}", hasher.finalize()),
        pe,
        signatures,
    }))
}

pub(crate) fn same_observation(first: &Metadata, second: &Metadata) -> bool {
    let same = first.is_file()
        && second.is_file()
        && skip_reason(second).is_none()
        && first.len() == second.len()
        && first.modified().ok() == second.modified().ok()
        && first.created().ok() == second.created().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.ctime() == second.ctime()
            && first.ctime_nsec() == second.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

pub(crate) fn skip_reason(metadata: &Metadata) -> Option<SkipReason> {
    if is_link(metadata) {
        Some(SkipReason::SymlinkOrReparsePoint)
    } else if !metadata.is_file() && !metadata.is_dir() {
        Some(SkipReason::NonRegularFile)
    } else {
        None
    }
}

pub(crate) fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Validate ancestors without following a known link; the final component is checked by the caller.
pub(crate) fn linked_ancestor(path: &Path) -> Result<Option<PathBuf>, (PathBuf, io::Error)> {
    let mut ancestor = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        ancestor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&ancestor) {
            Ok(metadata) if is_link(&metadata) => return Ok(Some(ancestor)),
            Ok(_) => {}
            Err(error) => return Err((ancestor, error)),
        }
    }
    Ok(None)
}

fn skipped(path: &Path, metadata: Option<&Metadata>, reason: SkipReason) -> FileReport {
    FileReport {
        path: path.to_path_buf(),
        metadata: metadata.map(FileMetadata::from),
        outcome: FileOutcome::Skipped { reason },
        pe: None,
        signatures: None,
        hash_reputation: None,
        verdict: Verdict::Inconclusive,
    }
}

fn add_issue(report: &mut ScanReport, path: &Path, operation: Operation, error: io::Error) {
    report.issues.push(ScanIssue {
        path: path.to_path_buf(),
        error: ScanError::new(operation, error),
    });
}

fn finish(mut report: ScanReport) -> ScanReport {
    report.files.sort_by(|a, b| a.path.cmp(&b.path));
    report.issues.sort_by(|a, b| a.path.cmp(&b.path));
    for file in &mut report.files {
        file.verdict = file.assess();
        match file.outcome {
            FileOutcome::Hashed { .. } => report.summary.hashed += 1,
            FileOutcome::Skipped { .. } => report.summary.skipped += 1,
            FileOutcome::Inconclusive { .. } => report.summary.inconclusive += 1,
            FileOutcome::Failed { .. } => report.summary.failed += 1,
        }
        match file.pe {
            Some(PeOutcome::Analyzed { .. }) => report.summary.pe_analyzed += 1,
            Some(PeOutcome::Skipped { .. } | PeOutcome::Failed { .. }) => {
                report.summary.pe_incomplete += 1
            }
            _ => {}
        }
        match &file.signatures {
            Some(SignatureOutcome::Complete { matches }) => {
                report.summary.signature_scanned += 1;
                report.summary.signature_matches += matches.len();
            }
            Some(SignatureOutcome::Failed { .. } | SignatureOutcome::Skipped { .. }) => {
                report.summary.signature_incomplete += 1
            }
            None => {}
        }
        match &file.hash_reputation {
            Some(HashOutcome::Complete { matched }) => {
                report.summary.hash_checked += 1;
                report.summary.hash_matches += usize::from(matched.is_some());
            }
            Some(HashOutcome::Failed { .. }) => report.summary.hash_incomplete += 1,
            None => {}
        }
    }
    report.summary.issues = report.issues.len();
    if (matches!(report.rules, RuleSetStatus::Failed { .. })
        || matches!(report.hash_database, HashDatabaseStatus::Failed { .. }))
        && report.status == ScanStatus::Complete
    {
        report.status = ScanStatus::Partial;
    }
    report.verdict = if report
        .files
        .iter()
        .any(|file| file.verdict == Verdict::KnownMaliciousMatch)
    {
        Verdict::KnownMaliciousMatch
    } else if report
        .files
        .iter()
        .any(|file| file.verdict == Verdict::Suspicious)
    {
        Verdict::Suspicious
    } else if report.status == ScanStatus::Failed
        || matches!(report.rules, RuleSetStatus::Failed { .. })
        || matches!(report.hash_database, HashDatabaseStatus::Failed { .. })
    {
        Verdict::Error
    } else if report.status != ScanStatus::Complete {
        Verdict::Inconclusive
    } else if report
        .files
        .iter()
        .any(|file| file.verdict == Verdict::TestMatch)
    {
        Verdict::TestMatch
    } else {
        Verdict::NoDetections
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_interrupts_hashing_between_buffers_and_counts_only_read_bytes() {
        struct CancellingReader<'a>(&'a crate::ScanControl);
        impl Read for CancellingReader<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer.fill(0);
                self.0.cancel();
                Ok(buffer.len())
            }
        }
        let control = crate::ScanControl::default();
        let error = hash_reader_controlled(
            CancellingReader(&control),
            10 * BUFFER_SIZE as u64,
            signatures::bundled_rules().as_ref(),
            &control,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(control.bytes_read(), BUFFER_SIZE as u64);
    }

    #[test]
    fn changed_lengths_withhold_digest_and_growing_input_is_bounded() {
        assert!(
            hash_reader(&b"ab"[..], 3, signatures::bundled_rules().as_ref())
                .unwrap()
                .is_none()
        );
        assert!(
            hash_reader(&b"abcd"[..], 3, signatures::bundled_rules().as_ref())
                .unwrap()
                .is_none()
        );
        assert!(
            hash_reader(io::repeat(0), 3, signatures::bundled_rules().as_ref())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn read_errors_are_not_successful_hashes() {
        struct Denied;
        impl Read for Denied {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        let error = hash_reader(Denied, 1, signatures::bundled_rules().as_ref()).unwrap_err();
        let error = ScanError::new(Operation::ReadFile, error);
        assert_eq!(error.kind, io::ErrorKind::PermissionDenied);
        assert_eq!(error.operation, Operation::ReadFile);
    }

    #[test]
    fn interrupted_reads_are_retried() {
        struct InterruptedOnce(bool);
        impl Read for InterruptedOnce {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                (&b""[..]).read(buffer)
            }
        }
        assert!(
            hash_reader(
                InterruptedOnce(false),
                0,
                signatures::bundled_rules().as_ref()
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn file_changed_since_discovery_is_inconclusive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("changing.txt");
        fs::write(&path, b"before").unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        fs::write(&path, b"changed length").unwrap();
        let result = scan_file(
            &path,
            &metadata,
            signatures::bundled_rules().as_ref(),
            reputation::bundled_hashes().as_ref(),
        );
        assert!(matches!(result.outcome, FileOutcome::Inconclusive { .. }));
        assert!(result.pe.is_none());
        assert!(result.signatures.is_none());
        assert!(result.hash_reputation.is_none());
    }

    #[test]
    fn disappeared_file_is_a_per_file_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gone.txt");
        fs::write(&path, b"data").unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let result = scan_file(
            &path,
            &metadata,
            signatures::bundled_rules().as_ref(),
            reputation::bundled_hashes().as_ref(),
        );
        assert!(result.pe.is_none());
        assert!(result.hash_reputation.is_none());
        assert!(
            matches!(result.outcome, FileOutcome::Failed { error } if error.kind == io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn directory_enumeration_failure_is_a_scan_issue() {
        let directory = tempfile::tempdir().unwrap();
        let mut report = scan(directory.path());
        let path = directory.path().join("not-a-directory");
        fs::write(&path, b"data").unwrap();
        scan_directory(
            &path,
            &mut report,
            signatures::bundled_rules().as_ref(),
            reputation::bundled_hashes().as_ref(),
        );
        assert!(report.files.is_empty());
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].error.operation, Operation::ReadDirectory);
        assert_eq!(report.issues[0].error.kind, io::ErrorKind::NotADirectory);
    }

    #[test]
    fn mz_prefix_is_identified_when_split_across_reads() {
        let reader = (&b"M"[..]).chain(&b"Z"[..]);
        let result = hash_reader(reader, 2, signatures::bundled_rules().as_ref())
            .unwrap()
            .unwrap();
        assert!(matches!(result.pe, PeOutcome::Failed { .. })); // Truncated MZ candidate
        assert_eq!(result.sha256, format!("{:x}", Sha256::digest(b"MZ")));
    }
}
