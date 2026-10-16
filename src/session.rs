//! Sequential multi-root scans with streaming results and cooperative cancellation.
//! The caller owns result storage; this module has no desktop dependencies.
use std::{
    fs::{self, ReadDir},
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use serde::Serialize;

use crate::{
    FileMetadata, FileOutcome, FileReport, Operation, ScanError, ScanIssue, ScanOptions,
    ScanStatus, SkipReason, Summary, Verdict,
    pe::PeOutcome,
    reputation::{self, HashDatabase, HashDatabaseStatus, HashOutcome},
    scanner::{self, HashContext, SignatureContext},
    signatures::{self, RuleSetStatus, SignatureOutcome, SignatureSet},
};

/// One control per scan. Cancellation is checked between reads/entries/checks;
/// an already-blocked OS read or parser/signature call must return first.
#[derive(Default)]
pub struct ScanControl {
    cancelled: AtomicBool,
    bytes_read: AtomicU64,
    excluded_paths: Vec<PathBuf>,
}
impl ScanControl {
    /// Exclude only caller-owned working directories, reporting each skipped entry.
    pub fn with_working_directories(paths: Vec<PathBuf>) -> Self {
        Self {
            excluded_paths: paths,
            ..Self::default()
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }
    pub(crate) fn read(&self, bytes: usize) {
        self.bytes_read.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

/// A real storage boundary: errors stop the scan instead of dropping results.
pub trait ScanSink {
    fn file(&mut self, file: &FileReport) -> io::Result<()>;
    fn issue(&mut self, issue: &ScanIssue) -> io::Result<()>;
    fn current_path(&mut self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
    fn sources(&mut self, _rules: &RuleSetStatus, _hashes: &HashDatabaseStatus) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ScanRoot {
    #[serde(serialize_with = "crate::report::serialize_path")]
    pub path: PathBuf,
    /// None means cancellation occurred before this root was visited.
    pub status: Option<ScanStatus>,
    pub verdict: Verdict,
    pub summary: Summary,
}

#[derive(Debug, Serialize)]
pub struct WorkingDirectory {
    #[serde(serialize_with = "crate::report::serialize_path")]
    pub path: PathBuf,
}

/// Metadata for streaming report schema 1. Exporters append files and issues.
#[derive(Debug, Serialize)]
pub struct ScanSessionReport {
    pub schema_version: u32,
    pub status: ScanStatus,
    pub verdict: Verdict,
    pub cancelled: bool,
    pub bytes_read: u64,
    pub roots: Vec<ScanRoot>,
    pub excluded_working_directories: Vec<WorkingDirectory>,
    pub rules: RuleSetStatus,
    pub hash_database: HashDatabaseStatus,
    pub summary: Summary,
}

#[derive(Default)]
struct Evidence {
    malicious: bool,
    suspicious: bool,
    test: bool,
}
impl Evidence {
    fn observe(&mut self, verdict: Verdict) {
        self.malicious |= verdict == Verdict::KnownMaliciousMatch;
        self.suspicious |= verdict == Verdict::Suspicious;
        self.test |= verdict == Verdict::TestMatch;
    }
    fn verdict(&self, status: ScanStatus, source_error: bool) -> Verdict {
        if self.malicious {
            Verdict::KnownMaliciousMatch
        } else if self.suspicious {
            Verdict::Suspicious
        } else if source_error || status == ScanStatus::Failed {
            Verdict::Error
        } else if status != ScanStatus::Complete {
            Verdict::Inconclusive
        } else if self.test {
            Verdict::TestMatch
        } else {
            Verdict::NoDetections
        }
    }
}

pub(crate) fn observe_file(summary: &mut Summary, file: &FileReport) {
    match file.outcome {
        FileOutcome::Hashed { .. } => summary.hashed += 1,
        FileOutcome::Skipped { .. } => summary.skipped += 1,
        FileOutcome::Inconclusive { .. } => summary.inconclusive += 1,
        FileOutcome::Failed { .. } => summary.failed += 1,
    }
    match file.pe {
        Some(PeOutcome::Analyzed { .. }) => summary.pe_analyzed += 1,
        Some(PeOutcome::Skipped { .. } | PeOutcome::Failed { .. }) => summary.pe_incomplete += 1,
        _ => {}
    }
    match &file.signatures {
        Some(SignatureOutcome::Complete { matches }) => {
            summary.signature_scanned += 1;
            summary.signature_matches += matches.len();
        }
        Some(SignatureOutcome::Failed { .. } | SignatureOutcome::Skipped { .. }) => {
            summary.signature_incomplete += 1
        }
        _ => {}
    }
    match &file.hash_reputation {
        Some(HashOutcome::Complete { matched }) => {
            summary.hash_checked += 1;
            summary.hash_matches += usize::from(matched.is_some());
        }
        Some(HashOutcome::Failed { .. }) => summary.hash_incomplete += 1,
        _ => {}
    }
}

struct Output<'a> {
    sink: &'a mut dyn ScanSink,
    summary: Summary,
    evidence: Evidence,
    incomplete: bool,
}
impl Output<'_> {
    fn file(&mut self, mut file: FileReport) -> io::Result<()> {
        file.verdict = file.assess();
        self.sink.file(&file)?;
        self.incomplete |= !file.is_complete();
        observe_file(&mut self.summary, &file);
        self.evidence.observe(file.verdict);
        Ok(())
    }
    fn skip(
        &mut self,
        path: &Path,
        metadata: Option<&fs::Metadata>,
        reason: SkipReason,
    ) -> io::Result<()> {
        self.file(FileReport {
            path: path.into(),
            metadata: metadata.map(FileMetadata::from),
            outcome: FileOutcome::Skipped { reason },
            pe: None,
            signatures: None,
            hash_reputation: None,
            verdict: Verdict::Inconclusive,
        })
    }
    fn issue(&mut self, path: &Path, operation: Operation, error: io::Error) -> io::Result<()> {
        self.sink.issue(&ScanIssue {
            path: path.into(),
            error: ScanError::new(operation, error),
        })?;
        self.summary.issues += 1;
        self.incomplete = true;
        Ok(())
    }
}

fn path_within(path: &Path, parent: &Path) -> bool {
    let path: Vec<_> = path.components().collect();
    let parent: Vec<_> = parent.components().collect();
    path.len() >= parent.len()
        && path.iter().zip(parent).all(|(a, b)| {
            #[cfg(windows)]
            {
                a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
            }
            #[cfg(not(windows))]
            {
                *a == b
            }
        })
}

/// Stream every outcome without retaining file reports in memory. Duplicate or
/// overlapping roots are rejected. Sources are loaded exactly once per session.
pub fn scan_streaming(
    paths: &[PathBuf],
    options: &ScanOptions,
    control: &ScanControl,
    sink: &mut dyn ScanSink,
) -> io::Result<ScanSessionReport> {
    if paths.is_empty() || paths.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Choose between 1 and 256 distinct scan roots",
        ));
    }
    let roots: Vec<_> = paths
        .iter()
        .map(|path| {
            std::path::absolute(path)
                .unwrap_or_else(|_| path.clone())
                .components()
                .collect::<PathBuf>()
        })
        .collect();
    if roots.iter().any(|root| {
        root.components()
            .any(|component| component == std::path::Component::ParentDir)
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Streaming scan roots must not contain parent-directory components",
        ));
    }
    for (index, path) in roots.iter().enumerate() {
        if roots[..index]
            .iter()
            .any(|other| path_within(path, other) || path_within(other, path))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Scan roots must not overlap",
            ));
        }
    }
    let local_rules = options
        .rules_directory
        .as_ref()
        .map(|path| SignatureSet::load_directory(path));
    let rules = local_rules
        .as_ref()
        .unwrap_or_else(|| signatures::bundled_rules())
        .as_ref();
    let local_hashes = options.hash_database.as_ref().map(HashDatabase::load);
    let hashes = local_hashes
        .as_ref()
        .unwrap_or_else(|| reputation::bundled_hashes())
        .as_ref();
    let source_error = rules.is_err() || hashes.is_err();
    let rules_status = match rules {
        Ok(rules) => rules.status(),
        Err(error) => RuleSetStatus::Failed {
            error: error.clone(),
        },
    };
    let hash_status = match hashes {
        Ok(hashes) => hashes.status(),
        Err(error) => HashDatabaseStatus::Failed {
            error: error.clone(),
        },
    };
    sink.sources(&rules_status, &hash_status)?;
    let mut output = Output {
        sink,
        summary: Summary::default(),
        evidence: Evidence::default(),
        incomplete: false,
    };
    let mut root_reports = Vec::new();
    for (original, path) in paths.iter().zip(roots) {
        if control.is_cancelled() {
            root_reports.push(ScanRoot {
                path,
                status: None,
                verdict: Verdict::Inconclusive,
                summary: Summary::default(),
            });
            continue;
        }
        let mut root_output = Output {
            sink: output.sink,
            summary: Summary::default(),
            evidence: Evidence::default(),
            incomplete: false,
        };
        let mut status = visit_root(original, &path, rules, hashes, control, &mut root_output)?;
        if control.is_cancelled() || (source_error && status == ScanStatus::Complete) {
            status = ScanStatus::Partial;
        }
        let verdict = root_output.evidence.verdict(status, source_error);
        output.evidence.malicious |= root_output.evidence.malicious;
        output.evidence.suspicious |= root_output.evidence.suspicious;
        output.evidence.test |= root_output.evidence.test;
        output.incomplete |= status != ScanStatus::Complete;
        merge_summary(&mut output.summary, &root_output.summary);
        root_reports.push(ScanRoot {
            path,
            status: Some(status),
            verdict,
            summary: root_output.summary,
        });
    }
    let status = if control.is_cancelled() {
        ScanStatus::Partial
    } else if root_reports
        .iter()
        .all(|root| root.status == Some(ScanStatus::Failed))
    {
        ScanStatus::Failed
    } else if root_reports.len() == 1 && root_reports[0].status == Some(ScanStatus::Skipped) {
        ScanStatus::Skipped
    } else if output.incomplete || source_error {
        ScanStatus::Partial
    } else {
        ScanStatus::Complete
    };
    Ok(ScanSessionReport {
        schema_version: 1,
        status,
        verdict: output.evidence.verdict(status, source_error),
        cancelled: control.is_cancelled(),
        bytes_read: control.bytes_read(),
        roots: root_reports,
        excluded_working_directories: control
            .excluded_paths
            .iter()
            .cloned()
            .map(|path| WorkingDirectory { path })
            .collect(),
        rules: rules_status,
        hash_database: hash_status,
        summary: output.summary,
    })
}

fn visit_root(
    original: &Path,
    path: &Path,
    rules: SignatureContext<'_>,
    hashes: HashContext<'_>,
    control: &ScanControl,
    output: &mut Output<'_>,
) -> io::Result<ScanStatus> {
    if let Err(error) = scanner::validate_path(original) {
        output.issue(original, Operation::ValidatePath, error)?;
        return Ok(ScanStatus::Failed);
    }
    match scanner::linked_ancestor(path) {
        Ok(Some(_)) => {
            output.skip(path, None, SkipReason::SymlinkOrReparsePoint)?;
            return Ok(ScanStatus::Skipped);
        }
        Err((ancestor, error)) => {
            output.issue(&ancestor, Operation::Metadata, error)?;
            return Ok(ScanStatus::Failed);
        }
        _ => {}
    }
    let mut stack: Vec<(PathBuf, ReadDir)> = Vec::new();
    let mut next = Some(path.to_path_buf());
    let mut root_directory = false;
    let mut root_failed = false;
    while let Some(path) = next.take() {
        if control.is_cancelled() {
            break;
        }
        output.sink.current_path(&path)?;
        if control.is_cancelled() {
            break;
        }
        let linked = scanner::linked_ancestor(&path);
        if control
            .excluded_paths
            .iter()
            .any(|excluded| path_within(&path, excluded))
        {
            output.skip(&path, None, SkipReason::ScannerWorkingDirectory)?;
        } else if let Err((ancestor, error)) = linked {
            output.issue(&ancestor, Operation::Metadata, error)?;
        } else if linked.is_ok_and(|link| link.is_some()) {
            output.skip(&path, None, SkipReason::SymlinkOrReparsePoint)?;
        } else {
            match fs::symlink_metadata(&path) {
                Err(error) => {
                    root_failed |= stack.is_empty();
                    output.issue(&path, Operation::Metadata, error)?;
                }
                Ok(metadata) => {
                    if let Some(reason) = scanner::skip_reason(&metadata) {
                        output.skip(&path, Some(&metadata), reason)?;
                    } else if metadata.is_file() {
                        output.file(scanner::scan_file_controlled(
                            &path, &metadata, rules, hashes, control,
                        ))?;
                    } else {
                        root_directory |= stack.is_empty();
                        if stack.len() >= 256 {
                            output.issue(
                                &path,
                                Operation::ReadDirectory,
                                io::Error::other(
                                    "Directory nesting exceeds 256 open traversal levels",
                                ),
                            )?;
                        } else {
                            match fs::read_dir(&path) {
                                Ok(entries) => stack.push((path.clone(), entries)),
                                Err(error) => {
                                    root_failed |= stack.is_empty();
                                    output.issue(&path, Operation::ReadDirectory, error)?;
                                }
                            }
                        }
                    }
                }
            }
        }
        while next.is_none() && !control.is_cancelled() {
            let Some((directory, entries)) = stack.last_mut() else {
                break;
            };
            match entries.next() {
                Some(Ok(entry)) => next = Some(entry.path()),
                Some(Err(error)) => output.issue(directory, Operation::ReadDirectory, error)?,
                None => {
                    stack.pop();
                }
            }
        }
    }
    Ok(
        if root_failed || (!root_directory && output.summary.failed > 0) {
            ScanStatus::Failed
        } else if !root_directory && output.summary.skipped > 0 {
            ScanStatus::Skipped
        } else if output.incomplete {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        },
    )
}

fn merge_summary(total: &mut Summary, part: &Summary) {
    total.hashed += part.hashed;
    total.skipped += part.skipped;
    total.inconclusive += part.inconclusive;
    total.failed += part.failed;
    total.issues += part.issues;
    total.pe_analyzed += part.pe_analyzed;
    total.pe_incomplete += part.pe_incomplete;
    total.signature_scanned += part.signature_scanned;
    total.signature_incomplete += part.signature_incomplete;
    total.signature_matches += part.signature_matches;
    total.hash_checked += part.hash_checked;
    total.hash_matches += part.hash_matches;
    total.hash_incomplete += part.hash_incomplete;
}
