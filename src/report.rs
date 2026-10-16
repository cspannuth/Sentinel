//! Versioned report types. Paths stay native in memory and use an explicit JSON boundary.

use std::fs::Metadata;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::pe::PeOutcome;
use crate::reputation::{HashCategory, HashDatabaseStatus, HashOutcome};
use crate::signatures::{RuleCategory, RuleSetStatus, SignatureOutcome};
use serde::{Serialize, Serializer};

/// Evidence and completeness are independent. No result certifies a file as safe.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    #[serde(serialize_with = "serialize_path")]
    pub target: PathBuf,
    pub status: ScanStatus,
    pub verdict: Verdict,
    pub rules: RuleSetStatus,
    pub hash_database: HashDatabaseStatus,
    pub summary: Summary,
    pub files: Vec<FileReport>,
    /// Path validation, metadata, and directory enumeration failures.
    pub issues: Vec<ScanIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Complete,
    Partial,
    Failed,
    Skipped,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Summary {
    pub hashed: usize,
    pub skipped: usize,
    pub inconclusive: usize,
    pub failed: usize,
    pub issues: usize,
    /// Successfully parsed PE files; hash counts remain independent.
    pub pe_analyzed: usize,
    pub pe_incomplete: usize,
    pub signature_scanned: usize,
    pub signature_incomplete: usize,
    pub signature_matches: usize,
    pub hash_checked: usize,
    pub hash_matches: usize,
    pub hash_incomplete: usize,
}

/// Also records skipped non-regular entries, including directory links.
#[derive(Debug, Serialize)]
pub struct FileReport {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub metadata: Option<FileMetadata>,
    #[serde(flatten)]
    pub outcome: FileOutcome,
    /// None when hashing did not complete consistently and PE results were withheld.
    pub pe: Option<PeOutcome>,
    pub signatures: Option<SignatureOutcome>,
    /// None when a consistent file hash could not be obtained.
    pub hash_reputation: Option<HashOutcome>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    KnownMaliciousMatch,
    Suspicious,
    TestMatch,
    NoDetections,
    Inconclusive,
    Error,
}

impl FileReport {
    /// All configured checks completed on a consistently hashed file. This is not a safety verdict.
    pub fn is_complete(&self) -> bool {
        matches!(self.outcome, FileOutcome::Hashed { .. })
            && matches!(self.pe, Some(PeOutcome::NotPe | PeOutcome::Analyzed { .. }))
            && matches!(self.signatures, Some(SignatureOutcome::Complete { .. }))
            && matches!(self.hash_reputation, Some(HashOutcome::Complete { .. }))
    }

    pub(crate) fn assess(&self) -> Verdict {
        let hash_category = match &self.hash_reputation {
            Some(HashOutcome::Complete {
                matched: Some(found),
            }) => Some(found.indicator.category),
            _ => None,
        };
        let matches = match &self.signatures {
            Some(SignatureOutcome::Complete { matches }) => matches.as_slice(),
            _ => &[],
        };
        if hash_category == Some(HashCategory::KnownMalicious)
            || matches
                .iter()
                .any(|matched| matched.category == RuleCategory::KnownMalicious)
        {
            return Verdict::KnownMaliciousMatch;
        }
        if matches
            .iter()
            .any(|matched| matched.category == RuleCategory::Suspicious)
        {
            return Verdict::Suspicious;
        }
        if matches!(self.outcome, FileOutcome::Failed { .. }) {
            return Verdict::Error;
        }
        if !self.is_complete() {
            return Verdict::Inconclusive;
        }
        if hash_category == Some(HashCategory::Test)
            || matches
                .iter()
                .any(|matched| matched.category == RuleCategory::Test)
        {
            Verdict::TestMatch
        } else {
            Verdict::NoDetections
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FileOutcome {
    Hashed {
        sha256: String,
    },
    Skipped {
        reason: SkipReason,
    },
    /// No digest is published when a consistency check fails.
    Inconclusive {
        reason: String,
    },
    Failed {
        error: ScanError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The scan's own temporary result storage is deliberately excluded.
    ScannerWorkingDirectory,
    SymlinkOrReparsePoint,
    NonRegularFile,
}

#[derive(Debug, Serialize)]
pub struct FileMetadata {
    pub size_bytes: u64,
    pub readonly: bool,
    /// Milliseconds since the Unix epoch; null if unavailable or before the epoch.
    pub modified_unix_ms: Option<u64>,
}

impl From<&Metadata> for FileMetadata {
    fn from(metadata: &Metadata) -> Self {
        Self {
            size_bytes: metadata.len(),
            readonly: metadata.permissions().readonly(),
            modified_unix_ms: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .and_then(|duration| u64::try_from(duration.as_millis()).ok()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanIssue {
    #[serde(serialize_with = "serialize_path")]
    pub path: PathBuf,
    pub error: ScanError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ValidatePath,
    Metadata,
    ReadDirectory,
    OpenFile,
    ReadFile,
}

/// Retains the portable I/O kind and native OS error code without a string-only API.
#[derive(Debug, Serialize)]
pub struct ScanError {
    pub operation: Operation,
    #[serde(serialize_with = "serialize_error_kind")]
    pub kind: io::ErrorKind,
    pub os_code: Option<i32>,
    pub message: String,
}

impl ScanError {
    pub(crate) fn new(operation: Operation, error: io::Error) -> Self {
        Self {
            operation,
            kind: error.kind(),
            os_code: error.raw_os_error(),
            message: error.to_string(),
        }
    }
}

fn serialize_error_kind<S: Serializer>(
    kind: &io::ErrorKind,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format!("{kind:?}"))
}

/// Ordinary paths have only a display string. Invalid Unicode also includes exact native units.
pub(crate) fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct JsonPath<'a> {
        display: std::borrow::Cow<'a, str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        native: Option<NativePath>,
    }

    #[derive(Serialize)]
    #[serde(tag = "encoding", content = "units", rename_all = "snake_case")]
    enum NativePath {
        #[cfg(windows)]
        WindowsUtf16(Vec<u16>),
        #[cfg(unix)]
        UnixBytes(Vec<u8>),
    }

    let native = if path.to_str().is_some() {
        None
    } else {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            Some(NativePath::WindowsUtf16(
                path.as_os_str().encode_wide().collect(),
            ))
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Some(NativePath::UnixBytes(path.as_os_str().as_bytes().to_vec()))
        }
    };

    JsonPath {
        display: path.to_string_lossy(),
        native,
    }
    .serialize(serializer)
}
