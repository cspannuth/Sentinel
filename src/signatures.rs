//! Local YARA-X rules and bounded scanning of the bytes used for SHA-256.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use yara_x::{Compiler, MetaValue, Rules, Scanner};

pub const MAX_SIGNATURE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 128;
const MAX_RULES: usize = 1024;
const MAX_PATTERNS: usize = 4096;
const MAX_PATTERN_MATCHES: usize = 4096;
const LOCATION_SAMPLES: usize = 8;
const SCAN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RuleSetStatus {
    Ready { info: RuleSetInfo },
    Failed { error: SignatureError },
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleSetInfo {
    pub origin: String,
    pub sha256: String,
    pub engine_version: String,
    pub rule_count: usize,
    pub sources: Vec<RuleSource>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleSource {
    #[serde(serialize_with = "crate::report::serialize_path")]
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignatureOutcome {
    Complete { matches: Vec<RuleMatch> },
    Skipped { reason: SignatureLimit, limit: u64 },
    Failed { error: SignatureError },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureLimit {
    InputBytes,
    PatternMatches,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureError {
    pub kind: SignatureErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureErrorKind {
    Io,
    InvalidRules,
    InvalidMetadata,
    ResourceLimit,
    Timeout,
    Allocation,
    Engine,
}

impl SignatureError {
    pub(crate) fn new(kind: SignatureErrorKind, message: impl std::fmt::Display) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    KnownMalicious,
    Suspicious,
    Test,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub namespace: String,
    pub category: RuleCategory,
    pub description: String,
    pub version: String,
    pub author: String,
    pub license: String,
    /// Up to eight locations per public pattern; never an exhaustive occurrence list.
    pub locations: Vec<MatchLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchLocation {
    pub pattern_id: String,
    pub offset: usize,
    pub length: usize,
}

pub(crate) struct SignatureSet {
    rules: Rules,
    metadata: BTreeMap<String, RuleMatch>,
    info: RuleSetInfo,
}

pub(crate) fn bundled_rules() -> &'static Result<SignatureSet, SignatureError> {
    static BUNDLED: OnceLock<Result<SignatureSet, SignatureError>> = OnceLock::new();
    BUNDLED.get_or_init(|| {
        SignatureSet::compile(
            "bundled-v3",
            &[
                (
                    PathBuf::from("rules/eset.yar"),
                    include_str!("../rules/eset.yar").as_bytes().to_vec(),
                ),
                (
                    PathBuf::from("rules/eset_extended.yar"),
                    include_str!("../rules/eset_extended.yar")
                        .as_bytes()
                        .to_vec(),
                ),
                (
                    PathBuf::from("rules/powershell.yar"),
                    include_str!("../rules/powershell.yar").as_bytes().to_vec(),
                ),
                (
                    PathBuf::from("rules/self_test.yar"),
                    include_str!("../rules/self_test.yar").as_bytes().to_vec(),
                ),
                (
                    PathBuf::from("rules/signature_base.yar"),
                    include_str!("../rules/signature_base.yar")
                        .as_bytes()
                        .to_vec(),
                ),
            ],
        )
    })
}

impl SignatureSet {
    pub(crate) fn load_directory(directory: &Path) -> Result<Self, SignatureError> {
        let io_error = |error| SignatureError::new(SignatureErrorKind::Io, error);
        let directory = std::path::absolute(directory).map_err(io_error)?;
        let directory = directory.components().collect::<PathBuf>();
        if crate::scanner::linked_ancestor(&directory)
            .map_err(|(_, error)| io_error(error))?
            .is_some()
        {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidRules,
                "Rule directory has a linked ancestor",
            ));
        }
        let metadata = fs::symlink_metadata(&directory).map_err(io_error)?;
        if !metadata.is_dir() || crate::scanner::is_link(&metadata) {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidRules,
                "Rules must be in an ordinary directory",
            ));
        }
        let mut paths = Vec::new();
        for entry in fs::read_dir(&directory).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if !matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("yar" | "yara")
            ) {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if !metadata.is_file() || crate::scanner::is_link(&metadata) {
                return Err(SignatureError::new(
                    SignatureErrorKind::InvalidRules,
                    "Rule sources must be regular files, not links/reparse points",
                ));
            }
            paths.push(path);
            if paths.len() > MAX_SOURCE_FILES {
                return Err(resource_error("More than 128 rule source files"));
            }
        }
        paths.sort();
        let mut sources = Vec::new();
        let mut total = 0;
        for path in paths {
            let mut bytes = Vec::new();
            File::open(&path)
                .map_err(io_error)?
                .take((MAX_SOURCE_BYTES - total + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            total += bytes.len();
            if total > MAX_SOURCE_BYTES {
                return Err(resource_error("Rule sources exceed 8 MiB"));
            }
            sources.push((path, bytes));
        }
        Self::compile("local-directory", &sources)
    }

    fn compile(origin: &str, sources: &[(PathBuf, Vec<u8>)]) -> Result<Self, SignatureError> {
        if sources.is_empty() {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidRules,
                "No .yar or .yara rule sources found",
            ));
        }
        let mut compiler = Compiler::new();
        compiler
            .enable_includes(false)
            .colorize_errors(false)
            .error_on_slow_pattern(true)
            .error_on_slow_loop(true);
        let mut digest = Sha256::new();
        let mut source_info = Vec::new();
        for (path, bytes) in sources {
            digest.update((bytes.len() as u64).to_le_bytes());
            digest.update(bytes);
            compiler.add_source(bytes.as_slice()).map_err(|error| {
                SignatureError::new(
                    SignatureErrorKind::InvalidRules,
                    format!("{}: {error}", path.display()),
                )
            })?;
            source_info.push(RuleSource {
                path: path.clone(),
                sha256: format!("{:x}", Sha256::digest(bytes)),
            });
        }
        // Warnings may indicate ignored or otherwise weakened rules. Fail the whole
        // collection instead of pretending every supplied rule was accepted.
        if !compiler.warnings().is_empty() {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidRules,
                format!("Rule compiler warning: {}", compiler.warnings()[0]),
            ));
        }
        let rules = compiler.build();
        let mut metadata = BTreeMap::new();
        let mut patterns = 0;
        for rule in rules.iter() {
            if metadata.len() == MAX_RULES {
                return Err(resource_error("More than 1024 rules"));
            }
            if rule.is_private() || rule.is_global() {
                return Err(SignatureError::new(
                    SignatureErrorKind::InvalidRules,
                    "Private/global rules are not supported by this initial rule collection",
                ));
            }
            patterns += rule.patterns().include_private(true).count();
            if patterns > MAX_PATTERNS {
                return Err(resource_error("More than 4096 total rule patterns"));
            }
            metadata.insert(rule.identifier().into(), rule_metadata(&rule)?);
        }
        if metadata.is_empty() {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidRules,
                "Rule collection contains no rules",
            ));
        }
        let info = RuleSetInfo {
            origin: origin.into(),
            sha256: format!("{:x}", digest.finalize()),
            engine_version: yara_x::VERSION.into(),
            rule_count: metadata.len(),
            sources: source_info,
        };
        Ok(Self {
            rules,
            metadata,
            info,
        })
    }

    pub(crate) fn status(&self) -> RuleSetStatus {
        RuleSetStatus::Ready {
            info: self.info.clone(),
        }
    }

    pub(crate) fn scan(&self, bytes: &[u8]) -> SignatureOutcome {
        if bytes.len() as u64 > MAX_SIGNATURE_BYTES {
            return input_limit();
        }
        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(SCAN_TIMEOUT)
            .max_matches_per_pattern(MAX_PATTERN_MATCHES)
            .fast_scan(true);
        let results = match scanner.scan(bytes) {
            Ok(results) => results,
            Err(error) => return scan_error(error),
        };
        // A saturated count can change count/offset-dependent rule conditions.
        // Inspect non-matching rules too and withhold all conclusions at the cap.
        for rule in results.matching_rules().chain(results.non_matching_rules()) {
            for pattern in rule.patterns().include_private(true) {
                if pattern.matches().take(MAX_PATTERN_MATCHES).count() == MAX_PATTERN_MATCHES {
                    return SignatureOutcome::Skipped {
                        reason: SignatureLimit::PatternMatches,
                        limit: MAX_PATTERN_MATCHES as u64,
                    };
                }
            }
        }
        let mut matches = Vec::new();
        for rule in results.matching_rules() {
            let Some(metadata) = self.metadata.get(rule.identifier()) else {
                return SignatureOutcome::Failed {
                    error: SignatureError::new(
                        SignatureErrorKind::Engine,
                        "Matched rule has no validated metadata",
                    ),
                };
            };
            let mut matched = metadata.clone();
            for pattern in rule.patterns() {
                for occurrence in pattern.matches().take(LOCATION_SAMPLES) {
                    let range = occurrence.range();
                    matched.locations.push(MatchLocation {
                        pattern_id: pattern.identifier().into(),
                        offset: range.start,
                        length: range.len(),
                    });
                }
            }
            matches.push(matched);
        }
        matches.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        SignatureOutcome::Complete { matches }
    }
}

fn rule_metadata(rule: &yara_x::Rule<'_, '_>) -> Result<RuleMatch, SignatureError> {
    let values: BTreeMap<_, _> = rule.metadata().collect();
    let string = |key| match values.get(key) {
        Some(MetaValue::String(value)) if !value.is_empty() && value.len() <= 1024 => {
            Ok((*value).to_owned())
        }
        _ => Err(SignatureError::new(
            SignatureErrorKind::InvalidMetadata,
            format!(
                "Rule {} requires string metadata {key} (1..1024 bytes)",
                rule.identifier()
            ),
        )),
    };
    let category = match string("category")?.as_str() {
        "known_malicious" => RuleCategory::KnownMalicious,
        "suspicious" => RuleCategory::Suspicious,
        "test" => RuleCategory::Test,
        _ => {
            return Err(SignatureError::new(
                SignatureErrorKind::InvalidMetadata,
                "Rule category must be known_malicious, suspicious, or test",
            ));
        }
    };
    Ok(RuleMatch {
        rule_id: rule.identifier().into(),
        namespace: rule.namespace().into(),
        category,
        description: string("description")?,
        version: string("version")?,
        author: string("author")?,
        license: string("license")?,
        locations: Vec::new(),
    })
}

pub(crate) fn input_limit() -> SignatureOutcome {
    SignatureOutcome::Skipped {
        reason: SignatureLimit::InputBytes,
        limit: MAX_SIGNATURE_BYTES,
    }
}

fn resource_error(message: &str) -> SignatureError {
    SignatureError::new(SignatureErrorKind::ResourceLimit, message)
}

fn scan_error(error: yara_x::ScanError) -> SignatureOutcome {
    let kind = if matches!(error, yara_x::ScanError::Timeout) {
        SignatureErrorKind::Timeout
    } else {
        SignatureErrorKind::Engine
    };
    SignatureOutcome::Failed {
        error: SignatureError::new(kind, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_produce_an_error_outcome_without_fabricated_matches() {
        assert!(
            matches!(scan_error(yara_x::ScanError::Timeout), SignatureOutcome::Failed { error } if error.kind == SignatureErrorKind::Timeout)
        );
    }
}
