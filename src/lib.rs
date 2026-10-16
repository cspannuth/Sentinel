//! Read-only discovery, SHA-256 hashing/reputation, PE analysis, and local YARA detection.
//!
//! A completed hash identifies observed bytes; it is not a malware verdict.
//! See [`scan`] and [`ScanReport`] for the public scanning API.

pub mod pe;
pub mod report;
pub mod reputation;
mod scanner;
pub mod session;
pub mod signatures;
pub use session::{ScanControl, ScanSessionReport, ScanSink, scan_streaming};

pub use report::{
    FileMetadata, FileOutcome, FileReport, Operation, ScanError, ScanIssue, ScanReport, ScanStatus,
    SkipReason, Summary, Verdict,
};
pub use scanner::{ScanOptions, scan, scan_with_options, scan_with_rules};
