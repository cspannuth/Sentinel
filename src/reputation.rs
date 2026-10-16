//! Offline exact SHA-256 comparisons against an attributed local indicator list.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_DATABASE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 250_000;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HashDatabaseStatus {
    Ready { info: HashDatabaseInfo },
    Failed { error: HashDatabaseError },
}

#[derive(Debug, Clone, Serialize)]
pub struct HashDatabaseInfo {
    pub origin: String,
    #[serde(serialize_with = "crate::report::serialize_path")]
    pub path: PathBuf,
    pub version: String,
    pub source: String,
    pub source_url: String,
    pub license: String,
    /// The curator's retrieval date, not a last-seen time for each indicator.
    pub retrieved_date: String,
    pub sha256: String,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HashOutcome {
    /// None means unknown to this database, not a clean-file classification.
    Complete {
        matched: Option<HashMatch>,
    },
    Failed {
        error: HashDatabaseError,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct HashMatch {
    #[serde(flatten)]
    pub indicator: HashIndicator,
    pub source: String,
    pub source_url: String,
    pub database_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashIndicator {
    pub sha256: String,
    pub category: HashCategory,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashCategory {
    KnownMalicious,
    Test,
}

#[derive(Debug, Clone, Serialize)]
pub struct HashDatabaseError {
    pub kind: HashDatabaseErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashDatabaseErrorKind {
    Io,
    InvalidDatabase,
    ResourceLimit,
}

impl HashDatabaseError {
    fn new(kind: HashDatabaseErrorKind, message: impl std::fmt::Display) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseSource {
    schema_version: u32,
    version: String,
    source: String,
    source_url: String,
    license: String,
    retrieved_date: String,
    entries: Vec<HashIndicator>,
}

/// One attributed collection, indexed once rather than searched per file.
pub struct HashDatabase {
    entries: HashMap<String, HashIndicator>,
    info: HashDatabaseInfo,
}

pub(crate) fn bundled_hashes() -> &'static Result<HashDatabase, HashDatabaseError> {
    static BUNDLED: OnceLock<Result<HashDatabase, HashDatabaseError>> = OnceLock::new();
    BUNDLED.get_or_init(|| {
        HashDatabase::parse(
            include_bytes!("../indicators/known_hashes.json"),
            PathBuf::from("indicators/known_hashes.json"),
            "bundled-v2",
        )
    })
}

impl HashDatabase {
    /// Load a complete replacement collection. No network access or fallback.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, HashDatabaseError> {
        let io_error = |error| HashDatabaseError::new(HashDatabaseErrorKind::Io, error);
        let invalid =
            |message| HashDatabaseError::new(HashDatabaseErrorKind::InvalidDatabase, message);
        let path = std::path::absolute(path.as_ref()).map_err(io_error)?;
        let path = path.components().collect::<PathBuf>();
        crate::scanner::validate_path(&path).map_err(io_error)?;
        if crate::scanner::linked_ancestor(&path)
            .map_err(|(_, error)| io_error(error))?
            .is_some()
        {
            return Err(invalid("Hash database has a linked ancestor"));
        }
        let discovered = fs::symlink_metadata(&path).map_err(io_error)?;
        if !discovered.is_file() || crate::scanner::is_link(&discovered) {
            return Err(invalid(
                "Hash database must be a regular file, not a link/reparse point",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Open the reparse point itself, not its target; use anonymous security QoS.
            options.custom_flags(0x0020_0000).security_qos_flags(0);
        }
        let mut file = options.open(&path).map_err(io_error)?;
        let before = file.metadata().map_err(io_error)?;
        if !before.is_file() || !crate::scanner::same_observation(&discovered, &before) {
            return Err(invalid("Hash database changed before reading"));
        }
        if before.len() > MAX_DATABASE_BYTES {
            return Err(resource_limit("Hash database exceeds 64 MiB"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_DATABASE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 > MAX_DATABASE_BYTES {
            return Err(resource_limit("Hash database exceeds 64 MiB"));
        }
        let after = file.metadata().map_err(io_error)?;
        let path_after = fs::symlink_metadata(&path).map_err(io_error)?;
        if bytes.len() as u64 != before.len()
            || !crate::scanner::same_observation(&before, &after)
            || !crate::scanner::same_observation(&after, &path_after)
        {
            return Err(invalid("Hash database changed while reading"));
        }
        Self::parse(&bytes, path, "local-file")
    }

    fn parse(bytes: &[u8], path: PathBuf, origin: &str) -> Result<Self, HashDatabaseError> {
        if bytes.len() as u64 > MAX_DATABASE_BYTES {
            return Err(resource_limit("Hash database exceeds 64 MiB"));
        }
        let invalid =
            |message| HashDatabaseError::new(HashDatabaseErrorKind::InvalidDatabase, message);
        let source: DatabaseSource =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        if source.schema_version != 1 {
            return Err(invalid("Hash database schema_version must be 1".into()));
        }
        for (name, value) in [
            ("version", &source.version),
            ("source", &source.source),
            ("source_url", &source.source_url),
            ("license", &source.license),
            ("retrieved_date", &source.retrieved_date),
        ] {
            validate_text(name, value)?;
        }
        if source.entries.is_empty() {
            return Err(invalid(
                "Hash database must contain at least one indicator".into(),
            ));
        }
        if source.entries.len() > MAX_ENTRIES {
            return Err(resource_limit("Hash database exceeds 250,000 indicators"));
        }
        let mut entries = HashMap::new();
        for mut indicator in source.entries {
            indicator.sha256 = normalize_hash(&indicator.sha256)?;
            validate_text("description", &indicator.description)?;
            let key = indicator.sha256.clone();
            if entries.insert(key.clone(), indicator).is_some() {
                return Err(invalid(format!("Duplicate SHA-256 indicator: {key}")));
            }
        }
        let info = HashDatabaseInfo {
            origin: origin.into(),
            path,
            version: source.version,
            source: source.source,
            source_url: source.source_url,
            license: source.license,
            retrieved_date: source.retrieved_date,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            entry_count: entries.len(),
        };
        Ok(Self { entries, info })
    }

    /// Compare an SHA-256 digest, not the bytes of a file containing a hash string.
    pub fn check(&self, sha256: &str) -> HashOutcome {
        let digest = match normalize_hash(sha256) {
            Ok(digest) => digest,
            Err(error) => return HashOutcome::Failed { error },
        };
        HashOutcome::Complete {
            matched: self.entries.get(&digest).map(|indicator| HashMatch {
                indicator: indicator.clone(),
                source: self.info.source.clone(),
                source_url: self.info.source_url.clone(),
                database_version: self.info.version.clone(),
            }),
        }
    }

    pub(crate) fn status(&self) -> HashDatabaseStatus {
        HashDatabaseStatus::Ready {
            info: self.info.clone(),
        }
    }
}

fn validate_text(name: &str, value: &str) -> Result<(), HashDatabaseError> {
    if value.trim().is_empty() || value.len() > 1024 {
        return Err(HashDatabaseError::new(
            HashDatabaseErrorKind::InvalidDatabase,
            format!("Hash database {name} must contain 1..1024 bytes of nonblank text"),
        ));
    }
    Ok(())
}

fn normalize_hash(value: &str) -> Result<String, HashDatabaseError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HashDatabaseError::new(
            HashDatabaseErrorKind::InvalidDatabase,
            "SHA-256 must be exactly 64 hexadecimal characters",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn resource_limit(message: &str) -> HashDatabaseError {
    HashDatabaseError::new(HashDatabaseErrorKind::ResourceLimit, message)
}
