use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsStr,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, ambient_authority};
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{AgentArtifact, AgentArtifactId, ArtifactInstallProvenance, OriginAgent, ScanReport};

pub const LIBRARY_MANIFEST_SCHEMA_VERSION: u32 = 4;
pub const MAX_CANONICAL_ENTRY_ID_BYTES: usize = 128;
pub const MAX_LIBRARY_PROJECT_KEY_BYTES: usize = 128;
pub const MAX_LIBRARY_ARTIFACT_BYTES: usize = 1024 * 1024;
pub const MAX_LIBRARY_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LIBRARY_ENTRIES: usize = 4_096;
pub const MAX_LIBRARY_VERSIONS_PER_ENTRY: usize = 1_024;
pub const MAX_LIBRARY_ENABLEMENTS: usize = 16_384;
pub const MAX_LIBRARY_MANAGED_COPIES: usize = 16_384;
pub const MAX_LIBRARY_INSTALLATIONS: usize = 16_384;
pub const MAX_LIBRARY_MANAGED_ROOT_BYTES: usize = 4_096;

const PAM_NAMESPACE_DIRECTORY: &str = "pam";
const LIBRARY_DIRECTORY: &str = "skill-library";
const BLOBS_DIRECTORY: &str = "blobs";
const SHA256_DIRECTORY: &str = "sha256";
const MANIFESTS_DIRECTORY: &str = "manifests";
const COMMITS_DIRECTORY: &str = "commits";
const EPOCHS_DIRECTORY: &str = "epochs";
const PENDING_DIRECTORY: &str = "pending";
const LOCK_FILE: &str = ".library.lock";
const MANIFEST_FILE_SUFFIX: &str = ".json";
const MANIFEST_GENERATION_DIGITS: usize = 20;
const COMMIT_MARKER_SCHEMA_VERSION: u32 = 1;
const MAX_COMMIT_MARKER_BYTES: usize = 1_024;
const MAX_MANIFEST_DIRECTORY_ENTRIES: usize =
    MAX_LIBRARY_ENTRIES * MAX_LIBRARY_VERSIONS_PER_ENTRY + 1;
const MAX_TEMPORARY_FILE_ATTEMPTS: usize = 16;

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

/// A path-safe canonical library identity independent of any agent destination.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CanonicalEntryId(String);

impl CanonicalEntryId {
    /// Parses a lowercase canonical entry identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCanonicalEntryId`] unless the value starts and ends with
    /// an ASCII lowercase letter or digit and contains only lowercase letters,
    /// digits, `-`, `_`, or `.` within the configured byte bound.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidCanonicalEntryId> {
        let value = value.into();
        let bytes = value.as_bytes();
        let boundary_is_valid = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if bytes.is_empty()
            || bytes.len() > MAX_CANONICAL_ENTRY_ID_BYTES
            || !bytes.first().is_some_and(boundary_is_valid)
            || !bytes.last().is_some_and(boundary_is_valid)
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
            || windows_reserved_device_basename(&value)
        {
            return Err(InvalidCanonicalEntryId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CanonicalEntryId {
    type Err = InvalidCanonicalEntryId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for CanonicalEntryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCanonicalEntryId;

impl fmt::Display for InvalidCanonicalEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical entry ID must be a bounded lowercase path-safe name")
    }
}

impl Error for InvalidCanonicalEntryId {}

pub(crate) fn windows_reserved_device_basename(value: &str) -> bool {
    let basename = value.split('.').next().unwrap_or(value);
    let bytes = basename.as_bytes();
    basename.eq_ignore_ascii_case("con")
        || basename.eq_ignore_ascii_case("prn")
        || basename.eq_ignore_ascii_case("aux")
        || basename.eq_ignore_ascii_case("nul")
        || (bytes.len() == 4
            && (bytes[..3].eq_ignore_ascii_case(b"com") || bytes[..3].eq_ignore_ascii_case(b"lpt"))
            && matches!(bytes[3], b'1'..=b'9'))
}

/// A bounded opaque project identity that cannot contain paths or control characters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LibraryProjectKey(String);

impl LibraryProjectKey {
    /// Parses a lowercase path-safe project key.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLibraryProjectKey`] when the key is empty, overlong, or could
    /// disclose a path or control character through durable library metadata.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidLibraryProjectKey> {
        let value = value.into();
        let bytes = value.as_bytes();
        let boundary_is_valid = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if bytes.is_empty()
            || bytes.len() > MAX_LIBRARY_PROJECT_KEY_BYTES
            || !bytes.first().is_some_and(boundary_is_valid)
            || !bytes.last().is_some_and(boundary_is_valid)
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(InvalidLibraryProjectKey);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LibraryProjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for LibraryProjectKey {
    type Err = InvalidLibraryProjectKey;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for LibraryProjectKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidLibraryProjectKey;

impl fmt::Display for InvalidLibraryProjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("library project key must be a bounded lowercase path-safe name")
    }
}

impl Error for InvalidLibraryProjectKey {}

/// A non-sensitive digest binding managed-copy authority to one validated canonical root.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LibraryManagedRootId(ContentDigest);

impl LibraryManagedRootId {
    /// Derives an opaque identity from one existing canonical absolute directory.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidLibraryManagedRoot`] for relative, non-canonical, symlinked,
    /// non-directory, or overlong paths.
    pub fn from_canonical_path(path: &Path) -> Result<Self, InvalidLibraryManagedRoot> {
        if !path.is_absolute() {
            return Err(InvalidLibraryManagedRoot);
        }
        let root_digest = managed_root_digest(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|_| InvalidLibraryManagedRoot)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(InvalidLibraryManagedRoot);
        }
        if fs::canonicalize(path).map_err(|_| InvalidLibraryManagedRoot)? != path {
            return Err(InvalidLibraryManagedRoot);
        }
        Ok(Self(root_digest))
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidLibraryManagedRoot;

impl fmt::Display for InvalidLibraryManagedRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("managed-copy root must be a bounded canonical absolute directory")
    }
}

impl Error for InvalidLibraryManagedRoot {}

#[cfg(unix)]
fn managed_root_digest(path: &Path) -> Result<ContentDigest, InvalidLibraryManagedRoot> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_LIBRARY_MANAGED_ROOT_BYTES {
        return Err(InvalidLibraryManagedRoot);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"pam-managed-root-v2-unix-bytes\0");
    hasher.update(bytes);
    Ok(ContentDigest::from_sha256(hasher.finalize().into()))
}

#[cfg(all(test, unix))]
pub(crate) fn managed_root_digest_for_test(
    path: &Path,
) -> Result<ContentDigest, InvalidLibraryManagedRoot> {
    managed_root_digest(path)
}

#[cfg(windows)]
fn managed_root_digest(path: &Path) -> Result<ContentDigest, InvalidLibraryManagedRoot> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut hasher = Sha256::new();
    hasher.update(b"pam-managed-root-v2-windows-utf16le\0");
    let mut bytes = 0usize;
    for unit in path.as_os_str().encode_wide() {
        bytes = bytes.checked_add(2).ok_or(InvalidLibraryManagedRoot)?;
        if bytes > MAX_LIBRARY_MANAGED_ROOT_BYTES {
            return Err(InvalidLibraryManagedRoot);
        }
        hasher.update(unit.to_le_bytes());
    }
    Ok(ContentDigest::from_sha256(hasher.finalize().into()))
}

#[cfg(not(any(unix, windows)))]
fn managed_root_digest(path: &Path) -> Result<ContentDigest, InvalidLibraryManagedRoot> {
    let bytes = path.to_str().ok_or(InvalidLibraryManagedRoot)?.as_bytes();
    if bytes.len() > MAX_LIBRARY_MANAGED_ROOT_BYTES {
        return Err(InvalidLibraryManagedRoot);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"pam-managed-root-v2-utf8\0");
    hasher.update(bytes);
    Ok(ContentDigest::from_sha256(hasher.finalize().into()))
}

/// Exact project, library version, and agent identity for one enablement decision.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryEnablementKey {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    agent: OriginAgent,
    project: LibraryProjectKey,
}

impl Ord for LibraryEnablementKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.entry_id
            .cmp(&other.entry_id)
            .then_with(|| self.version.as_str().cmp(other.version.as_str()))
            .then_with(|| self.agent.cmp(&other.agent))
            .then_with(|| self.project.cmp(&other.project))
    }
}

impl PartialOrd for LibraryEnablementKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl LibraryEnablementKey {
    #[must_use]
    pub const fn new(
        entry_id: CanonicalEntryId,
        version: ContentDigest,
        agent: OriginAgent,
        project: LibraryProjectKey,
    ) -> Self {
        Self {
            entry_id,
            version,
            agent,
            project,
        }
    }

    #[must_use]
    pub fn entry_id(&self) -> &CanonicalEntryId {
        &self.entry_id
    }

    #[must_use]
    pub fn version(&self) -> &ContentDigest {
        &self.version
    }

    #[must_use]
    pub const fn agent(&self) -> OriginAgent {
        self.agent
    }

    #[must_use]
    pub fn project(&self) -> &LibraryProjectKey {
        &self.project
    }
}

/// Result of an idempotent durable enablement mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryEnablementChange {
    key: LibraryEnablementKey,
    enabled: bool,
    changed: bool,
}

impl LibraryEnablementChange {
    #[must_use]
    pub fn key(&self) -> &LibraryEnablementKey {
        &self.key
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

/// Result of recording ownership from an exact materialization outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryManagedCopyChange {
    key: LibraryEnablementKey,
    recorded: bool,
    changed: bool,
}

impl LibraryManagedCopyChange {
    pub(crate) const fn not_recorded(key: LibraryEnablementKey) -> Self {
        Self {
            key,
            recorded: false,
            changed: false,
        }
    }

    #[must_use]
    pub fn key(&self) -> &LibraryEnablementKey {
        &self.key
    }

    #[must_use]
    pub const fn recorded(&self) -> bool {
        self.recorded
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LibraryInsertDisposition {
    Inserted,
    AlreadyPresent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryInsertOutcome {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    disposition: LibraryInsertDisposition,
}

/// Metadata-only result of adopting one scanned artifact into the canonical library.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LibraryAdoptionOutcome {
    artifact_id: AgentArtifactId,
    artifact: AgentArtifact,
    insert: LibraryInsertOutcome,
}

impl LibraryAdoptionOutcome {
    #[must_use]
    pub fn entry_id(&self) -> &CanonicalEntryId {
        self.insert.entry_id()
    }

    #[must_use]
    pub fn artifact_id(&self) -> &AgentArtifactId {
        &self.artifact_id
    }

    #[must_use]
    pub const fn artifact(&self) -> &AgentArtifact {
        &self.artifact
    }

    #[must_use]
    pub fn version(&self) -> &ContentDigest {
        self.insert.version()
    }

    #[must_use]
    pub const fn disposition(&self) -> LibraryInsertDisposition {
        self.insert.disposition()
    }
}

impl LibraryInsertOutcome {
    #[must_use]
    pub fn entry_id(&self) -> &CanonicalEntryId {
        &self.entry_id
    }

    #[must_use]
    pub fn version(&self) -> &ContentDigest {
        &self.version
    }

    #[must_use]
    pub const fn disposition(&self) -> LibraryInsertDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalLibraryEntry {
    id: CanonicalEntryId,
    versions: Vec<ContentDigest>,
}

/// One metadata-only installation record from an atomic library snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalLibraryInstallation {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    provenance: ArtifactInstallProvenance,
}

impl CanonicalLibraryInstallation {
    #[must_use]
    pub fn entry_id(&self) -> &CanonicalEntryId {
        &self.entry_id
    }

    #[must_use]
    pub fn version(&self) -> &ContentDigest {
        &self.version
    }

    #[must_use]
    pub const fn provenance(&self) -> &ArtifactInstallProvenance {
        &self.provenance
    }
}

/// Metadata-only library state read from one committed manifest generation under one lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalLibrarySnapshot {
    generation: u64,
    entries: Vec<CanonicalLibraryEntry>,
    installations: Vec<CanonicalLibraryInstallation>,
    enablements: Vec<LibraryEnablementKey>,
    managed_copies: Vec<LibraryEnablementKey>,
    managed_roots: Vec<ManifestManagedCopy>,
}

impl CanonicalLibrarySnapshot {
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn entries(&self) -> &[CanonicalLibraryEntry] {
        &self.entries
    }

    #[must_use]
    pub fn installations(&self) -> &[CanonicalLibraryInstallation] {
        &self.installations
    }

    #[must_use]
    pub fn enablements(&self) -> &[LibraryEnablementKey] {
        &self.enablements
    }

    #[must_use]
    pub fn managed_copies(&self) -> &[LibraryEnablementKey] {
        &self.managed_copies
    }

    /// Returns whether the exact key is owned at the supplied opaque canonical-root identity.
    #[must_use]
    pub fn is_managed_at(&self, key: &LibraryEnablementKey, root: &LibraryManagedRootId) -> bool {
        self.managed_roots
            .binary_search_by(|managed| managed.key.cmp(key))
            .ok()
            .is_some_and(|index| &self.managed_roots[index].root == root)
    }
}

impl CanonicalLibraryEntry {
    #[must_use]
    pub fn id(&self) -> &CanonicalEntryId {
        &self.id
    }

    #[must_use]
    pub fn versions(&self) -> &[ContentDigest] {
        &self.versions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LibraryIoOperation {
    OpenHome,
    InitializeDirectories,
    ReadManifest,
    WriteManifest,
    ReadBlob,
    WriteBlob,
}

impl LibraryIoOperation {
    const fn description(self) -> &'static str {
        match self {
            Self::OpenHome => "open the p-track home",
            Self::InitializeDirectories => "initialize the PAM library directories",
            Self::ReadManifest => "read the canonical library manifest",
            Self::WriteManifest => "write the canonical library manifest",
            Self::ReadBlob => "read canonical library bytes",
            Self::WriteBlob => "write canonical library bytes",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LibraryError {
    InvalidHome,
    UnsafePath,
    Io(LibraryIoOperation),
    LockUnavailable,
    ArtifactTooLarge,
    ManifestTooLarge,
    MalformedManifest,
    UnsupportedManifestVersion(u32),
    CorruptManifest,
    ManifestCapacityExceeded,
    VersionCapacityExceeded(CanonicalEntryId),
    EnablementCapacityExceeded,
    ManagedCopyCapacityExceeded,
    InstallationCapacityExceeded,
    InstallProvenanceConflict,
    ManagedCopyRootMismatch,
    EntryNotFound(CanonicalEntryId),
    VersionNotFound {
        entry_id: CanonicalEntryId,
        version: ContentDigest,
    },
    MissingBlob(ContentDigest),
    CorruptBlob {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    BlobContentConflict(ContentDigest),
    IncompleteScan,
    ArtifactNotFound(AgentArtifactId),
    ArtifactSourceUnavailable(AgentArtifactId),
    ArtifactDigestMismatch {
        artifact_id: AgentArtifactId,
        expected: ContentDigest,
        actual: ContentDigest,
    },
}

impl fmt::Display for LibraryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHome => formatter.write_str("p-track home must be an absolute directory"),
            Self::UnsafePath => formatter.write_str("canonical library path is unsafe"),
            Self::Io(operation) => write!(formatter, "PAM could not {}", operation.description()),
            Self::LockUnavailable => formatter.write_str("canonical library lock is unavailable"),
            Self::ArtifactTooLarge => {
                formatter.write_str("canonical library artifact is too large")
            }
            Self::ManifestTooLarge => {
                formatter.write_str("canonical library manifest is too large")
            }
            Self::MalformedManifest => {
                formatter.write_str("canonical library manifest is malformed")
            }
            Self::UnsupportedManifestVersion(version) => {
                write!(
                    formatter,
                    "canonical library manifest version {version} is unsupported"
                )
            }
            Self::CorruptManifest => formatter.write_str("canonical library manifest is corrupt"),
            Self::ManifestCapacityExceeded => {
                formatter.write_str("canonical library entry capacity is exceeded")
            }
            Self::VersionCapacityExceeded(entry_id) => {
                write!(
                    formatter,
                    "canonical library version capacity is exceeded for {entry_id}"
                )
            }
            Self::EnablementCapacityExceeded => {
                formatter.write_str("canonical library enablement capacity is exceeded")
            }
            Self::ManagedCopyCapacityExceeded => {
                formatter.write_str("canonical library managed-copy capacity is exceeded")
            }
            Self::InstallationCapacityExceeded => {
                formatter.write_str("canonical library installation capacity is exceeded")
            }
            Self::InstallProvenanceConflict => {
                formatter.write_str("canonical library installation provenance conflicts")
            }
            Self::ManagedCopyRootMismatch => {
                formatter.write_str("managed copy belongs to a different agent root")
            }
            Self::EntryNotFound(entry_id) => {
                write!(
                    formatter,
                    "canonical library entry {entry_id} was not found"
                )
            }
            Self::VersionNotFound { entry_id, version } => {
                write!(
                    formatter,
                    "canonical library entry {entry_id} has no version {version}"
                )
            }
            Self::MissingBlob(version) => {
                write!(
                    formatter,
                    "canonical library bytes for {version} are missing"
                )
            }
            Self::CorruptBlob { expected, actual } => write!(
                formatter,
                "canonical library bytes expected {expected} but hashed as {actual}"
            ),
            Self::BlobContentConflict(version) => write!(
                formatter,
                "canonical library bytes conflict at content address {version}"
            ),
            Self::IncompleteScan => {
                formatter.write_str("canonical library adoption requires a complete scan")
            }
            Self::ArtifactNotFound(artifact_id) => {
                write!(formatter, "scanned artifact {artifact_id} was not found")
            }
            Self::ArtifactSourceUnavailable(artifact_id) => write!(
                formatter,
                "exact source bytes are unavailable for scanned artifact {artifact_id}"
            ),
            Self::ArtifactDigestMismatch {
                artifact_id,
                expected,
                actual,
            } => write!(
                formatter,
                "scanned artifact {artifact_id} expected {expected} but exact bytes hashed as {actual}"
            ),
        }
    }
}

impl Error for LibraryError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LibraryManifest {
    schema_version: u32,
    generation: u64,
    base_generation: u64,
    entries: Vec<ManifestEntry>,
    enablements: Vec<LibraryEnablementKey>,
    managed_copies: Vec<ManifestManagedCopy>,
    installations: Vec<ManifestInstallation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LibraryManifestV1 {
    schema_version: u32,
    generation: u64,
    entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LibraryManifestV2 {
    schema_version: u32,
    generation: u64,
    entries: Vec<ManifestEntry>,
    enablements: Vec<LibraryEnablementKey>,
    managed_copies: Vec<LibraryEnablementKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct LibraryManifestV3 {
    schema_version: u32,
    generation: u64,
    entries: Vec<ManifestEntry>,
    enablements: Vec<LibraryEnablementKey>,
    managed_copies: Vec<LibraryEnablementKey>,
    installations: Vec<ManifestInstallationV3>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ManifestInstallationV3 {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    provenance: ArtifactInstallProvenanceV3,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
enum ArtifactInstallProvenanceV3 {
    Local,
    Git(GitInstallProvenanceV3),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GitInstallProvenanceV3 {
    url: String,
    commit: String,
    artifact_path: String,
}

#[derive(Deserialize)]
struct ManifestSchemaProbe {
    schema_version: u32,
}

impl LibraryManifest {
    fn empty(generation: u64) -> Self {
        Self {
            schema_version: LIBRARY_MANIFEST_SCHEMA_VERSION,
            generation,
            base_generation: generation,
            entries: Vec::new(),
            enablements: Vec::new(),
            managed_copies: Vec::new(),
            installations: Vec::new(),
        }
    }

    fn validate(&self, expected_generation: u64) -> Result<(), LibraryError> {
        if self.schema_version != LIBRARY_MANIFEST_SCHEMA_VERSION {
            return Err(LibraryError::UnsupportedManifestVersion(
                self.schema_version,
            ));
        }
        if self.generation != expected_generation
            || self.base_generation > self.generation
            || self.entries.len() > MAX_LIBRARY_ENTRIES
            || !strictly_ordered(self.entries.iter().map(|entry| &entry.id))
        {
            return Err(LibraryError::CorruptManifest);
        }
        for entry in &self.entries {
            if entry.versions.is_empty()
                || entry.versions.len() > MAX_LIBRARY_VERSIONS_PER_ENTRY
                || !strictly_ordered(entry.versions.iter().map(ContentDigest::as_str))
            {
                return Err(LibraryError::CorruptManifest);
            }
        }
        if self.enablements.len() > MAX_LIBRARY_ENABLEMENTS
            || self.managed_copies.len() > MAX_LIBRARY_MANAGED_COPIES
            || self.installations.len() > MAX_LIBRARY_INSTALLATIONS
            || !strictly_ordered(self.enablements.iter())
            || !strictly_ordered(self.managed_copies.iter().map(|managed| &managed.key))
            || self.enablements.iter().any(|key| !self.has_version(key))
            || self
                .managed_copies
                .iter()
                .any(|managed| !self.has_version(&managed.key))
        {
            return Err(LibraryError::CorruptManifest);
        }
        let mut managed_destinations = BTreeSet::new();
        for managed in &self.managed_copies {
            let key = &managed.key;
            if !managed_destinations.insert((&key.project, key.agent, &key.entry_id)) {
                return Err(LibraryError::CorruptManifest);
            }
        }
        if !strictly_ordered(
            self.installations
                .iter()
                .map(|installation| (&installation.entry_id, installation.version.as_str())),
        ) || self.installations.iter().any(|installation| {
            !self.has_entry_version(&installation.entry_id, &installation.version)
                || !installation.provenance.validate()
        }) {
            return Err(LibraryError::CorruptManifest);
        }
        Ok(())
    }

    fn has_version(&self, key: &LibraryEnablementKey) -> bool {
        self.has_entry_version(&key.entry_id, &key.version)
    }

    fn has_entry_version(&self, entry_id: &CanonicalEntryId, version: &ContentDigest) -> bool {
        self.entries
            .binary_search_by(|entry| entry.id.cmp(entry_id))
            .ok()
            .is_some_and(|index| {
                self.entries[index]
                    .versions
                    .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
                    .is_ok()
            })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    id: CanonicalEntryId,
    versions: Vec<ContentDigest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestInstallation {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    provenance: ArtifactInstallProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestManagedCopy {
    key: LibraryEnablementKey,
    root: LibraryManagedRootId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitMarker {
    schema_version: u32,
    generation: u64,
    manifest_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingMarker {
    schema_version: u32,
    generation: u64,
}

pub struct CanonicalLibrary {
    root_path: PathBuf,
    root: Dir,
    manifests: Dir,
    commits: Dir,
    epochs: Dir,
    pending: Dir,
    blobs: Dir,
}

impl fmt::Debug for CanonicalLibrary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalLibrary")
            .field("root_path", &self.root_path)
            .finish_non_exhaustive()
    }
}

impl CanonicalLibrary {
    /// Opens or initializes PAM's isolated canonical library below a resolved p-track home.
    ///
    /// # Errors
    ///
    /// Returns an error for a relative, missing, non-directory, or symlink home; unsafe
    /// namespace entries; I/O failures; or an existing malformed or unsupported manifest.
    pub fn open(ptrack_home: &Path) -> Result<Self, LibraryError> {
        if !ptrack_home.is_absolute() {
            return Err(LibraryError::InvalidHome);
        }
        let metadata = fs::symlink_metadata(ptrack_home).map_err(|_| LibraryError::InvalidHome)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LibraryError::InvalidHome);
        }
        let canonical_home = fs::canonicalize(ptrack_home)
            .map_err(|_| LibraryError::Io(LibraryIoOperation::OpenHome))?;
        let home = Dir::open_ambient_dir(&canonical_home, ambient_authority())
            .map_err(|_| LibraryError::Io(LibraryIoOperation::OpenHome))?;
        let namespace = open_or_create_directory(&home, Path::new(PAM_NAMESPACE_DIRECTORY))?;
        let root = open_or_create_directory(&namespace, Path::new(LIBRARY_DIRECTORY))?;
        let manifests = open_or_create_directory(&root, Path::new(MANIFESTS_DIRECTORY))?;
        let commits = open_or_create_directory(&root, Path::new(COMMITS_DIRECTORY))?;
        let epochs = open_or_create_directory(&root, Path::new(EPOCHS_DIRECTORY))?;
        let pending = open_or_create_directory(&root, Path::new(PENDING_DIRECTORY))?;
        let blobs_root = open_or_create_directory(&root, Path::new(BLOBS_DIRECTORY))?;
        let blobs = open_or_create_directory(&blobs_root, Path::new(SHA256_DIRECTORY))?;
        let library = Self {
            root_path: canonical_home
                .join(PAM_NAMESPACE_DIRECTORY)
                .join(LIBRARY_DIRECTORY),
            root,
            manifests,
            commits,
            epochs,
            pending,
            blobs,
        };
        library.initialize_manifest()?;
        Ok(library)
    }

    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Inserts exact bytes as a content-addressed version of one canonical entry.
    ///
    /// # Errors
    ///
    /// Returns an error for bounds, manifest corruption, unsafe paths, failed atomic
    /// publication, or an existing blob that does not contain the exact supplied bytes.
    pub fn insert(
        &self,
        entry_id: CanonicalEntryId,
        bytes: &[u8],
    ) -> Result<LibraryInsertOutcome, LibraryError> {
        self.insert_inner(entry_id, bytes, false)
    }

    #[cfg(test)]
    pub(crate) fn insert_with_post_commit_cleanup_fault(
        &self,
        entry_id: CanonicalEntryId,
        bytes: &[u8],
    ) -> Result<LibraryInsertOutcome, LibraryError> {
        self.insert_inner(entry_id, bytes, true)
    }

    fn insert_inner(
        &self,
        entry_id: CanonicalEntryId,
        bytes: &[u8],
        post_commit_cleanup_fault: bool,
    ) -> Result<LibraryInsertOutcome, LibraryError> {
        if bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES {
            return Err(LibraryError::ArtifactTooLarge);
        }
        let _lock = self.acquire_lock()?;
        let (generation, mut manifest) = self.read_manifest()?;
        let version = digest(bytes);
        let entry_index = manifest
            .entries
            .binary_search_by(|entry| entry.id.cmp(&entry_id));

        if let Ok(index) = entry_index
            && manifest.entries[index]
                .versions
                .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
                .is_ok()
        {
            self.verify_existing_blob(&version, Some(bytes))?;
            return Ok(LibraryInsertOutcome {
                entry_id,
                version,
                disposition: LibraryInsertDisposition::AlreadyPresent,
            });
        }

        match entry_index {
            Ok(index)
                if manifest.entries[index].versions.len() >= MAX_LIBRARY_VERSIONS_PER_ENTRY =>
            {
                return Err(LibraryError::VersionCapacityExceeded(entry_id));
            }
            Err(_) if manifest.entries.len() >= MAX_LIBRARY_ENTRIES => {
                return Err(LibraryError::ManifestCapacityExceeded);
            }
            _ => {}
        }
        self.publish_blob(&version, bytes)?;
        match entry_index {
            Ok(index) => {
                let versions = &mut manifest.entries[index].versions;
                let insertion = versions
                    .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
                    .expect_err("the version was proven absent");
                versions.insert(insertion, version.clone());
            }
            Err(index) => {
                manifest.entries.insert(
                    index,
                    ManifestEntry {
                        id: entry_id.clone(),
                        versions: vec![version.clone()],
                    },
                );
            }
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(LibraryError::ManifestCapacityExceeded)?;
        manifest.generation = next_generation;
        self.publish_manifest_inner(next_generation, &manifest, post_commit_cleanup_fault)?;
        Ok(LibraryInsertOutcome {
            entry_id,
            version,
            disposition: LibraryInsertDisposition::Inserted,
        })
    }

    pub(crate) fn install_bytes(
        &self,
        entry_id: CanonicalEntryId,
        bytes: &[u8],
        provenance: ArtifactInstallProvenance,
    ) -> Result<LibraryInsertOutcome, LibraryError> {
        if bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES {
            return Err(LibraryError::ArtifactTooLarge);
        }
        if !provenance.validate() {
            return Err(LibraryError::InstallProvenanceConflict);
        }
        let _lock = self.acquire_lock()?;
        let (generation, mut manifest) = self.read_manifest()?;
        let version = digest(bytes);
        let installation_index = manifest.installations.binary_search_by(|installation| {
            installation
                .entry_id
                .cmp(&entry_id)
                .then_with(|| installation.version.as_str().cmp(version.as_str()))
        });
        if let Ok(index) = installation_index {
            if manifest.installations[index].provenance != provenance {
                return Err(LibraryError::InstallProvenanceConflict);
            }
            self.verify_existing_blob(&version, Some(bytes))?;
            return Ok(LibraryInsertOutcome {
                entry_id,
                version,
                disposition: LibraryInsertDisposition::AlreadyPresent,
            });
        }
        if manifest.installations.len() >= MAX_LIBRARY_INSTALLATIONS {
            return Err(LibraryError::InstallationCapacityExceeded);
        }

        let entry_index = manifest
            .entries
            .binary_search_by(|entry| entry.id.cmp(&entry_id));
        let version_exists = entry_index.is_ok_and(|index| {
            manifest.entries[index]
                .versions
                .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
                .is_ok()
        });
        match entry_index {
            Ok(index)
                if !version_exists
                    && manifest.entries[index].versions.len() >= MAX_LIBRARY_VERSIONS_PER_ENTRY =>
            {
                return Err(LibraryError::VersionCapacityExceeded(entry_id));
            }
            Err(_) if manifest.entries.len() >= MAX_LIBRARY_ENTRIES => {
                return Err(LibraryError::ManifestCapacityExceeded);
            }
            _ => {}
        }
        if version_exists {
            self.verify_existing_blob(&version, Some(bytes))?;
        } else {
            self.publish_blob(&version, bytes)?;
            match entry_index {
                Ok(index) => {
                    let versions = &mut manifest.entries[index].versions;
                    let insertion = versions
                        .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
                        .expect_err("the version was proven absent");
                    versions.insert(insertion, version.clone());
                }
                Err(index) => manifest.entries.insert(
                    index,
                    ManifestEntry {
                        id: entry_id.clone(),
                        versions: vec![version.clone()],
                    },
                ),
            }
        }
        manifest.installations.insert(
            installation_index.expect_err("the installation was proven absent"),
            ManifestInstallation {
                entry_id: entry_id.clone(),
                version: version.clone(),
                provenance,
            },
        );
        let next_generation = generation
            .checked_add(1)
            .ok_or(LibraryError::ManifestCapacityExceeded)?;
        manifest.generation = next_generation;
        self.publish_manifest(next_generation, &manifest)?;
        Ok(LibraryInsertOutcome {
            entry_id,
            version,
            disposition: if version_exists {
                LibraryInsertDisposition::AlreadyPresent
            } else {
                LibraryInsertDisposition::Inserted
            },
        })
    }

    /// Copies one explicitly selected scanned artifact into the canonical library.
    ///
    /// Adoption reads only the scan's privately retained exact bytes. It never moves, deletes,
    /// or hard-links the original artifact. Repeated identical adoption is idempotent, while
    /// changed bytes for the same stable artifact identity become another content version.
    ///
    /// # Errors
    ///
    /// Returns an error when the scan is incomplete, the artifact or its exact bytes are absent,
    /// retained bytes do not match the normalized content digest, or library insertion fails.
    pub fn adopt(
        &self,
        entry_id: CanonicalEntryId,
        artifact_id: AgentArtifactId,
        scan: &ScanReport,
    ) -> Result<LibraryAdoptionOutcome, LibraryError> {
        if !scan.complete() {
            return Err(LibraryError::IncompleteScan);
        }
        let artifact = scan
            .artifacts()
            .iter()
            .find(|artifact| artifact.id() == artifact_id)
            .cloned()
            .ok_or_else(|| LibraryError::ArtifactNotFound(artifact_id.clone()))?;
        let source = scan
            .artifact_source(&artifact_id)
            .ok_or_else(|| LibraryError::ArtifactSourceUnavailable(artifact_id.clone()))?;
        let actual = digest(source);
        if &actual != artifact.content_hash() {
            return Err(LibraryError::ArtifactDigestMismatch {
                artifact_id,
                expected: artifact.content_hash().clone(),
                actual,
            });
        }
        let artifact_id = artifact.id();
        let insert = self.insert(entry_id, source)?;
        Ok(LibraryAdoptionOutcome {
            artifact_id,
            artifact,
            insert,
        })
    }

    /// Lists every canonical entry and exact content version in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns an error when the strict manifest cannot be read or validated.
    pub fn entries(&self) -> Result<Vec<CanonicalLibraryEntry>, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        Ok(manifest
            .entries
            .into_iter()
            .map(|entry| CanonicalLibraryEntry {
                id: entry.id,
                versions: entry.versions,
            })
            .collect())
    }

    /// Reads all public library metadata from one committed manifest generation under one lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the strict manifest cannot be read or validated.
    pub fn snapshot(&self) -> Result<CanonicalLibrarySnapshot, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (generation, manifest) = self.read_manifest()?;
        let managed_roots = manifest.managed_copies;
        Ok(CanonicalLibrarySnapshot {
            generation,
            entries: manifest
                .entries
                .into_iter()
                .map(|entry| CanonicalLibraryEntry {
                    id: entry.id,
                    versions: entry.versions,
                })
                .collect(),
            installations: manifest
                .installations
                .into_iter()
                .map(|installation| CanonicalLibraryInstallation {
                    entry_id: installation.entry_id,
                    version: installation.version,
                    provenance: installation.provenance,
                })
                .collect(),
            enablements: manifest.enablements,
            managed_copies: managed_roots
                .iter()
                .map(|managed| managed.key.clone())
                .collect(),
            managed_roots,
        })
    }

    /// Returns stored installation provenance for one exact entry version.
    ///
    /// # Errors
    ///
    /// Returns an error when durable library state cannot be read safely.
    pub fn installation_provenance(
        &self,
        entry_id: &CanonicalEntryId,
        version: &ContentDigest,
    ) -> Result<Option<ArtifactInstallProvenance>, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        let index = manifest.installations.binary_search_by(|installation| {
            installation
                .entry_id
                .cmp(entry_id)
                .then_with(|| installation.version.as_str().cmp(version.as_str()))
        });
        Ok(index
            .ok()
            .map(|index| manifest.installations[index].provenance.clone()))
    }

    /// Reads and re-hashes one manifest-authorized content version.
    ///
    /// # Errors
    ///
    /// Returns a typed not-found error or a corruption error when the content-addressed
    /// bytes are missing, unsafe, overlong, or do not match the requested digest.
    pub fn read(
        &self,
        entry_id: &CanonicalEntryId,
        version: &ContentDigest,
    ) -> Result<Vec<u8>, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        let entry = manifest
            .entries
            .binary_search_by(|entry| entry.id.cmp(entry_id))
            .ok()
            .map(|index| &manifest.entries[index])
            .ok_or_else(|| LibraryError::EntryNotFound(entry_id.clone()))?;
        if entry
            .versions
            .binary_search_by(|stored| stored.as_str().cmp(version.as_str()))
            .is_err()
        {
            return Err(LibraryError::VersionNotFound {
                entry_id: entry_id.clone(),
                version: version.clone(),
            });
        }
        self.verify_existing_blob(version, None)
    }

    pub(crate) fn managed_materialization_snapshot(
        &self,
        key: &LibraryEnablementKey,
        root: &LibraryManagedRootId,
    ) -> Result<(Vec<u8>, bool, bool), LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, key)?;
        let expected = self.verify_existing_blob(key.version(), None)?;
        let managed = match managed_copy_for_destination(&manifest, key) {
            Some(managed) if &managed.root != root => {
                return Err(LibraryError::ManagedCopyRootMismatch);
            }
            Some(managed) => managed.key == *key,
            None => false,
        };
        Ok((
            expected,
            manifest.enablements.binary_search(key).is_ok(),
            managed,
        ))
    }

    /// Returns whether this exact project, version, and agent key is enabled.
    ///
    /// Absence is always disabled; enablement never inherits across any key field.
    ///
    /// # Errors
    ///
    /// Returns an error when the referenced library version is absent or durable state
    /// cannot be read safely.
    pub fn is_enabled(&self, key: &LibraryEnablementKey) -> Result<bool, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, key)?;
        Ok(manifest.enablements.binary_search(key).is_ok())
    }

    /// Lists exact enabled keys in deterministic order without source bytes or raw paths.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be read safely.
    pub fn enablements(&self) -> Result<Vec<LibraryEnablementKey>, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        Ok(manifest.enablements)
    }

    /// Idempotently enables one exact project, version, and agent key.
    ///
    /// # Errors
    ///
    /// Returns an error when the referenced version is absent, capacity is exhausted,
    /// or durable publication fails.
    pub fn enable(
        &self,
        key: LibraryEnablementKey,
    ) -> Result<LibraryEnablementChange, LibraryError> {
        self.set_enablement(key, true)
    }

    /// Lists exact managed-copy ownership keys in deterministic order.
    ///
    /// Ownership is retained after disabling a modified or symlinked destination so callers
    /// can continue to report drift without persisting any ambient agent root.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state cannot be read safely.
    pub fn managed_copies(&self) -> Result<Vec<LibraryEnablementKey>, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (_, manifest) = self.read_manifest()?;
        Ok(manifest
            .managed_copies
            .into_iter()
            .map(|managed| managed.key)
            .collect())
    }

    fn set_enablement(
        &self,
        key: LibraryEnablementKey,
        enabled: bool,
    ) -> Result<LibraryEnablementChange, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (generation, mut manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, &key)?;
        let index = manifest.enablements.binary_search(&key);
        let changed = match (enabled, index) {
            (true, Ok(_)) | (false, Err(_)) => false,
            (true, Err(index)) => {
                if manifest.enablements.len() >= MAX_LIBRARY_ENABLEMENTS {
                    return Err(LibraryError::EnablementCapacityExceeded);
                }
                manifest.enablements.insert(index, key.clone());
                true
            }
            (false, Ok(index)) => {
                manifest.enablements.remove(index);
                true
            }
        };
        if changed {
            self.publish_next_manifest(generation, &mut manifest)?;
        }
        Ok(LibraryEnablementChange {
            key,
            enabled,
            changed,
        })
    }

    pub(crate) fn record_managed_copy(
        &self,
        key: LibraryEnablementKey,
        root: LibraryManagedRootId,
    ) -> Result<LibraryManagedCopyChange, LibraryError> {
        let _lock = self.acquire_lock()?;
        let (generation, mut manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, &key)?;
        if manifest.enablements.binary_search(&key).is_err() {
            return Ok(LibraryManagedCopyChange::not_recorded(key));
        }
        if let Some(managed) = managed_copy_for_destination(&manifest, &key)
            && managed.root != root
        {
            return Err(LibraryError::ManagedCopyRootMismatch);
        }
        if manifest
            .managed_copies
            .binary_search_by(|managed| managed.key.cmp(&key))
            .is_ok()
        {
            return Ok(LibraryManagedCopyChange {
                key,
                recorded: true,
                changed: false,
            });
        }
        manifest.managed_copies.retain(|stored| {
            stored.key.project != key.project
                || stored.key.agent != key.agent
                || stored.key.entry_id != key.entry_id
        });
        if manifest.managed_copies.len() >= MAX_LIBRARY_MANAGED_COPIES {
            return Err(LibraryError::ManagedCopyCapacityExceeded);
        }
        let index = manifest
            .managed_copies
            .binary_search_by(|managed| managed.key.cmp(&key))
            .expect_err("the exact managed copy was proven absent");
        manifest.managed_copies.insert(
            index,
            ManifestManagedCopy {
                key: key.clone(),
                root,
            },
        );
        self.publish_next_manifest(generation, &mut manifest)?;
        Ok(LibraryManagedCopyChange {
            key,
            recorded: true,
            changed: true,
        })
    }

    pub(crate) fn transfer_managed_no_op(
        &self,
        key: LibraryEnablementKey,
        root: LibraryManagedRootId,
    ) -> Result<(bool, LibraryManagedCopyChange), LibraryError> {
        self.transfer_managed_no_op_inner(key, root, false)
    }

    #[cfg(test)]
    pub(crate) fn transfer_managed_no_op_with_publish_failure(
        &self,
        key: LibraryEnablementKey,
        root: LibraryManagedRootId,
    ) -> Result<(bool, LibraryManagedCopyChange), LibraryError> {
        self.transfer_managed_no_op_inner(key, root, true)
    }

    fn transfer_managed_no_op_inner(
        &self,
        key: LibraryEnablementKey,
        root: LibraryManagedRootId,
        fail_publish: bool,
    ) -> Result<(bool, LibraryManagedCopyChange), LibraryError> {
        let _lock = self.acquire_lock()?;
        let (generation, mut manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, &key)?;
        if manifest.enablements.binary_search(&key).is_err() {
            return Ok((false, LibraryManagedCopyChange::not_recorded(key)));
        }
        let Some(index) = manifest.managed_copies.iter().position(|managed| {
            managed.key.project == key.project
                && managed.key.agent == key.agent
                && managed.key.entry_id == key.entry_id
        }) else {
            return Ok((true, LibraryManagedCopyChange::not_recorded(key)));
        };
        if manifest.managed_copies[index].root != root {
            return Err(LibraryError::ManagedCopyRootMismatch);
        }
        if manifest.managed_copies[index].key == key {
            return Ok((
                true,
                LibraryManagedCopyChange {
                    key,
                    recorded: true,
                    changed: false,
                },
            ));
        }
        manifest.managed_copies.remove(index);
        let insert = manifest
            .managed_copies
            .binary_search_by(|managed| managed.key.cmp(&key))
            .expect_err("the destination's prior version was removed");
        manifest.managed_copies.insert(
            insert,
            ManifestManagedCopy {
                key: key.clone(),
                root,
            },
        );
        if fail_publish {
            return Err(LibraryError::Io(LibraryIoOperation::WriteManifest));
        }
        self.publish_next_manifest(generation, &mut manifest)?;
        Ok((
            true,
            LibraryManagedCopyChange {
                key,
                recorded: true,
                changed: true,
            },
        ))
    }

    pub(crate) fn disable_managed_copy<T>(
        &self,
        key: &LibraryEnablementKey,
        root: &LibraryManagedRootId,
        fail_ownership_publish: bool,
        operation: impl FnOnce(bool, Option<&[u8]>) -> (T, bool),
    ) -> Result<(LibraryEnablementChange, T), LibraryError> {
        let _lock = self.acquire_lock()?;
        let (mut generation, mut manifest) = self.read_manifest()?;
        ensure_manifest_version(&manifest, key)?;
        let managed = managed_copy_matches_root(&manifest, key, root)?;
        let state_changed = manifest
            .enablements
            .binary_search(key)
            .ok()
            .map(|index| manifest.enablements.remove(index))
            .is_some();
        if state_changed {
            self.publish_next_manifest(generation, &mut manifest)?;
            generation = manifest.generation;
        }
        let expected = if managed {
            Some(self.verify_existing_blob(key.version(), None)?)
        } else {
            None
        };
        let (result, clear_ownership) = operation(managed, expected.as_deref());
        if clear_ownership
            && let Ok(index) = manifest
                .managed_copies
                .binary_search_by(|managed| managed.key.cmp(key))
        {
            if fail_ownership_publish {
                return Err(LibraryError::Io(LibraryIoOperation::WriteManifest));
            }
            manifest.managed_copies.remove(index);
            self.publish_next_manifest(generation, &mut manifest)?;
        }
        Ok((
            LibraryEnablementChange {
                key: key.clone(),
                enabled: false,
                changed: state_changed,
            },
            result,
        ))
    }

    fn publish_next_manifest(
        &self,
        generation: u64,
        manifest: &mut LibraryManifest,
    ) -> Result<(), LibraryError> {
        let next_generation = generation
            .checked_add(1)
            .ok_or(LibraryError::ManifestCapacityExceeded)?;
        manifest.generation = next_generation;
        self.publish_manifest(next_generation, manifest)
    }

    fn publish_migrated_manifest(
        &self,
        generation: u64,
        manifest: &mut LibraryManifest,
    ) -> Result<u64, LibraryError> {
        let next_generation = generation
            .checked_add(1)
            .ok_or(LibraryError::ManifestCapacityExceeded)?;
        manifest.generation = next_generation;
        manifest.base_generation = next_generation;
        manifest.validate(next_generation)?;
        let bytes = encode_manifest(manifest)?;
        let name = manifest_generation_name(next_generation);
        let pending = PendingMarker {
            schema_version: COMMIT_MARKER_SCHEMA_VERSION,
            generation: next_generation,
        };
        let pending_bytes = encode_pending_marker(&pending)?;
        if let Err(error) = publish_immutable_file(
            &self.pending,
            "pending",
            Path::new(&name),
            &pending_bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = self.cleanup_pending_generation(next_generation);
            return Err(error);
        }
        if let Err(error) = publish_immutable_file(
            &self.manifests,
            "manifest",
            Path::new(&name),
            &bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = self.cleanup_pending_generation(next_generation);
            return Err(error);
        }
        let marker = CommitMarker {
            schema_version: COMMIT_MARKER_SCHEMA_VERSION,
            generation: next_generation,
            manifest_digest: digest(&bytes),
        };
        let marker_bytes = encode_commit_marker(&marker)?;
        if let Err(error) = publish_immutable_file(
            &self.epochs,
            "epoch",
            Path::new(&name),
            &marker_bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = remove_generation_file_if_present(
                &self.epochs,
                Path::new(&name),
                LibraryIoOperation::WriteManifest,
            );
            let _ = self.cleanup_pending_generation(next_generation);
            return Err(error);
        }

        let _ = remove_generation_file(
            &self.pending,
            Path::new(&name),
            LibraryIoOperation::WriteManifest,
        );
        self.cleanup_legacy_generations(next_generation)?;
        Ok(next_generation)
    }

    fn initialize_manifest(&self) -> Result<(), LibraryError> {
        let _lock = self.acquire_lock()?;
        match self.read_latest_manifest()? {
            Some((generation, mut manifest, true)) => self
                .publish_migrated_manifest(generation, &mut manifest)
                .map(drop),
            Some(_) => Ok(()),
            None => self.publish_manifest(0, &LibraryManifest::empty(0)),
        }
    }

    fn acquire_lock(&self) -> Result<fs::File, LibraryError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        set_private_file_mode(&mut options);
        let file = self.root.open_with(LOCK_FILE, &options).map_err(|_| {
            match self.root.symlink_metadata(LOCK_FILE) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    LibraryError::UnsafePath
                }
                _ => LibraryError::LockUnavailable,
            }
        })?;
        if !file
            .metadata()
            .map_err(|_| LibraryError::LockUnavailable)?
            .is_file()
        {
            return Err(LibraryError::UnsafePath);
        }
        let lock = file.into_std();
        lock.lock().map_err(|_| LibraryError::LockUnavailable)?;
        Ok(lock)
    }

    fn read_manifest(&self) -> Result<(u64, LibraryManifest), LibraryError> {
        let (generation, mut manifest, migrated) = self
            .read_latest_manifest()?
            .ok_or(LibraryError::CorruptManifest)?;
        if migrated {
            let generation = self.publish_migrated_manifest(generation, &mut manifest)?;
            return Ok((generation, manifest));
        }
        Ok((generation, manifest))
    }

    fn read_latest_manifest(&self) -> Result<Option<(u64, LibraryManifest, bool)>, LibraryError> {
        let epoch = self.read_epoch_marker()?;
        let base_generation = epoch.as_ref().map_or(0, |marker| marker.generation);
        self.recover_pending_generations(epoch.as_ref())?;
        if epoch.is_some() {
            self.cleanup_legacy_generations(base_generation)?;
        }
        let manifest_generations = generation_set(&self.manifests)?
            .into_iter()
            .filter(|generation| *generation >= base_generation)
            .collect::<Vec<_>>();
        let mut commit_generations = generation_set(&self.commits)?
            .into_iter()
            .filter(|generation| *generation >= base_generation)
            .collect::<Vec<_>>();
        if epoch.is_some() {
            if commit_generations.binary_search(&base_generation).is_ok() {
                return Err(LibraryError::CorruptManifest);
            }
            commit_generations.insert(0, base_generation);
        }
        if manifest_generations != commit_generations {
            return Err(LibraryError::CorruptManifest);
        }
        for (expected, generation) in manifest_generations.iter().copied().enumerate() {
            let expected = base_generation
                .checked_add(u64::try_from(expected).unwrap_or(u64::MAX))
                .ok_or(LibraryError::CorruptManifest)?;
            if generation != expected {
                return Err(LibraryError::CorruptManifest);
            }
        }
        let Some(generation) = manifest_generations.last().copied() else {
            return Ok(None);
        };
        let name = manifest_generation_name(generation);
        let bytes = read_bounded_regular_file(
            &self.manifests,
            Path::new(&name),
            MAX_LIBRARY_MANIFEST_BYTES,
            LibraryIoOperation::ReadManifest,
        )?
        .ok_or(LibraryError::CorruptManifest)?;
        let (manifest, migrated) = decode_manifest(&bytes, generation)?;
        if manifest.base_generation != base_generation {
            return Err(LibraryError::CorruptManifest);
        }
        if let Some(epoch) = epoch.as_ref() {
            let base_bytes = self.read_and_validate_manifest(base_generation)?;
            validate_marker(epoch, base_generation, &base_bytes)?;
        }
        if generation != base_generation || epoch.is_none() {
            self.validate_commit_marker(generation, &bytes)?;
        }
        Ok(Some((generation, manifest, migrated)))
    }

    fn read_epoch_marker(&self) -> Result<Option<CommitMarker>, LibraryError> {
        let generations = generation_set(&self.epochs)?;
        if generations.len() > 1 {
            return Err(LibraryError::CorruptManifest);
        }
        let Some(generation) = generations.last().copied() else {
            return Ok(None);
        };
        let name = manifest_generation_name(generation);
        let bytes = read_bounded_regular_file(
            &self.epochs,
            Path::new(&name),
            MAX_COMMIT_MARKER_BYTES,
            LibraryIoOperation::ReadManifest,
        )?
        .ok_or(LibraryError::CorruptManifest)?;
        let marker = serde_json::from_slice::<CommitMarker>(&bytes)
            .map_err(|_| LibraryError::CorruptManifest)?;
        if marker.schema_version != COMMIT_MARKER_SCHEMA_VERSION || marker.generation != generation
        {
            return Err(LibraryError::CorruptManifest);
        }
        Ok(Some(marker))
    }

    fn recover_pending_generations(
        &self,
        epoch: Option<&CommitMarker>,
    ) -> Result<(), LibraryError> {
        let base_generation = epoch.map_or(0, |marker| marker.generation);
        for generation in generation_set(&self.pending)? {
            self.validate_pending_marker(generation)?;
            let name = manifest_generation_name(generation);
            if generation < base_generation {
                let _ = remove_generation_file(
                    &self.pending,
                    Path::new(&name),
                    LibraryIoOperation::WriteManifest,
                );
                continue;
            }
            let manifest_exists = regular_file_exists(&self.manifests, Path::new(&name))?;
            let commit_exists = regular_file_exists(&self.commits, Path::new(&name))?;
            let epoch_commits = epoch.is_some_and(|marker| marker.generation == generation);
            if manifest_exists && (commit_exists || epoch_commits) {
                let bytes = self.read_and_validate_manifest(generation)?;
                if epoch_commits {
                    validate_marker(
                        epoch.expect("epoch commitment was proven present"),
                        generation,
                        &bytes,
                    )?;
                } else {
                    self.validate_commit_marker(generation, &bytes)?;
                }
                let _ = remove_generation_file(
                    &self.pending,
                    Path::new(&name),
                    LibraryIoOperation::WriteManifest,
                );
                continue;
            }
            self.cleanup_pending_generation(generation)?;
        }
        Ok(())
    }

    fn cleanup_legacy_generations(&self, base_generation: u64) -> Result<(), LibraryError> {
        for directory in [&self.manifests, &self.commits, &self.pending] {
            for generation in generation_set(directory)? {
                if generation >= base_generation {
                    continue;
                }
                remove_generation_file(
                    directory,
                    Path::new(&manifest_generation_name(generation)),
                    LibraryIoOperation::WriteManifest,
                )?;
            }
        }
        Ok(())
    }

    fn validate_pending_marker(&self, generation: u64) -> Result<(), LibraryError> {
        let name = manifest_generation_name(generation);
        let bytes = read_bounded_regular_file(
            &self.pending,
            Path::new(&name),
            MAX_COMMIT_MARKER_BYTES,
            LibraryIoOperation::ReadManifest,
        )?
        .ok_or(LibraryError::CorruptManifest)?;
        let marker = serde_json::from_slice::<PendingMarker>(&bytes)
            .map_err(|_| LibraryError::CorruptManifest)?;
        if marker.schema_version != COMMIT_MARKER_SCHEMA_VERSION || marker.generation != generation
        {
            return Err(LibraryError::CorruptManifest);
        }
        Ok(())
    }

    fn read_and_validate_manifest(&self, generation: u64) -> Result<Vec<u8>, LibraryError> {
        let name = manifest_generation_name(generation);
        let bytes = read_bounded_regular_file(
            &self.manifests,
            Path::new(&name),
            MAX_LIBRARY_MANIFEST_BYTES,
            LibraryIoOperation::ReadManifest,
        )?
        .ok_or(LibraryError::CorruptManifest)?;
        decode_manifest(&bytes, generation)?;
        Ok(bytes)
    }

    fn validate_commit_marker(
        &self,
        generation: u64,
        manifest_bytes: &[u8],
    ) -> Result<(), LibraryError> {
        let name = manifest_generation_name(generation);
        let bytes = read_bounded_regular_file(
            &self.commits,
            Path::new(&name),
            MAX_COMMIT_MARKER_BYTES,
            LibraryIoOperation::ReadManifest,
        )?
        .ok_or(LibraryError::CorruptManifest)?;
        let marker = serde_json::from_slice::<CommitMarker>(&bytes)
            .map_err(|_| LibraryError::CorruptManifest)?;
        validate_marker(&marker, generation, manifest_bytes)
    }

    fn publish_manifest(
        &self,
        generation: u64,
        manifest: &LibraryManifest,
    ) -> Result<(), LibraryError> {
        self.publish_manifest_inner(generation, manifest, false)
    }

    fn publish_manifest_inner(
        &self,
        generation: u64,
        manifest: &LibraryManifest,
        post_commit_cleanup_fault: bool,
    ) -> Result<(), LibraryError> {
        manifest.validate(generation)?;
        let bytes = encode_manifest(manifest)?;
        let name = manifest_generation_name(generation);
        let pending = PendingMarker {
            schema_version: COMMIT_MARKER_SCHEMA_VERSION,
            generation,
        };
        let pending_bytes = encode_pending_marker(&pending)?;
        if let Err(error) = publish_immutable_file(
            &self.pending,
            "pending",
            Path::new(&name),
            &pending_bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = self.cleanup_pending_generation(generation);
            return Err(error);
        }
        if let Err(error) = publish_immutable_file(
            &self.manifests,
            "manifest",
            Path::new(&name),
            &bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = self.cleanup_pending_generation(generation);
            return Err(error);
        }
        let marker = CommitMarker {
            schema_version: COMMIT_MARKER_SCHEMA_VERSION,
            generation,
            manifest_digest: digest(&bytes),
        };
        let marker_bytes = encode_commit_marker(&marker)?;
        if let Err(error) = publish_immutable_file(
            &self.commits,
            "commit",
            Path::new(&name),
            &marker_bytes,
            LibraryIoOperation::WriteManifest,
        ) {
            let _ = self.cleanup_pending_generation(generation);
            return Err(error);
        }
        if !post_commit_cleanup_fault {
            let _ = remove_generation_file(
                &self.pending,
                Path::new(&name),
                LibraryIoOperation::WriteManifest,
            );
        }
        Ok(())
    }

    fn cleanup_pending_generation(&self, generation: u64) -> Result<(), LibraryError> {
        let name = manifest_generation_name(generation);
        remove_generation_file_if_present(
            &self.commits,
            Path::new(&name),
            LibraryIoOperation::WriteManifest,
        )?;
        remove_generation_file_if_present(
            &self.manifests,
            Path::new(&name),
            LibraryIoOperation::WriteManifest,
        )?;
        remove_generation_file_if_present(
            &self.pending,
            Path::new(&name),
            LibraryIoOperation::WriteManifest,
        )?;
        Ok(())
    }

    fn publish_blob(&self, version: &ContentDigest, bytes: &[u8]) -> Result<(), LibraryError> {
        let name = Path::new(version.sha256_hex());
        match self.blobs.symlink_metadata(name) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(LibraryError::UnsafePath);
            }
            Ok(_) => return self.verify_existing_blob(version, Some(bytes)).map(drop),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(LibraryError::Io(LibraryIoOperation::ReadBlob)),
        }

        let (mut file, temporary) =
            create_temporary_file(&self.blobs, "blob", LibraryIoOperation::WriteBlob)?;
        let result = (|| {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| LibraryError::Io(LibraryIoOperation::WriteBlob))?;
            drop(file);
            match self.blobs.hard_link(&temporary, &self.blobs, name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.blobs
                        .remove_file(&temporary)
                        .map_err(|_| LibraryError::Io(LibraryIoOperation::WriteBlob))?;
                    return self.verify_existing_blob(version, Some(bytes)).map(drop);
                }
                Err(_) => return Err(LibraryError::Io(LibraryIoOperation::WriteBlob)),
            }
            sync_published_file(&self.blobs, name, LibraryIoOperation::WriteBlob)?;
            self.blobs
                .remove_file(&temporary)
                .map_err(|_| LibraryError::Io(LibraryIoOperation::WriteBlob))?;
            sync_directory(&self.blobs, LibraryIoOperation::WriteBlob)
        })();
        if result.is_err() {
            let _ = self.blobs.remove_file(&temporary);
        }
        result
    }

    fn verify_existing_blob(
        &self,
        version: &ContentDigest,
        expected_bytes: Option<&[u8]>,
    ) -> Result<Vec<u8>, LibraryError> {
        let bytes = read_bounded_regular_file(
            &self.blobs,
            Path::new(version.sha256_hex()),
            MAX_LIBRARY_ARTIFACT_BYTES,
            LibraryIoOperation::ReadBlob,
        )?
        .ok_or_else(|| LibraryError::MissingBlob(version.clone()))?;
        let actual = digest(&bytes);
        if &actual != version {
            return Err(LibraryError::CorruptBlob {
                expected: version.clone(),
                actual,
            });
        }
        if expected_bytes.is_some_and(|expected| expected != bytes) {
            return Err(LibraryError::BlobContentConflict(version.clone()));
        }
        Ok(bytes)
    }
}

fn decode_manifest(
    bytes: &[u8],
    expected_generation: u64,
) -> Result<(LibraryManifest, bool), LibraryError> {
    let schema = serde_json::from_slice::<ManifestSchemaProbe>(bytes)
        .map_err(|_| LibraryError::MalformedManifest)?
        .schema_version;
    match schema {
        1 => {
            let historical = serde_json::from_slice::<LibraryManifestV1>(bytes)
                .map_err(|_| LibraryError::MalformedManifest)?;
            if historical.schema_version != 1 {
                return Err(LibraryError::MalformedManifest);
            }
            let manifest = LibraryManifest {
                schema_version: LIBRARY_MANIFEST_SCHEMA_VERSION,
                generation: historical.generation,
                base_generation: 0,
                entries: historical.entries,
                enablements: Vec::new(),
                managed_copies: Vec::new(),
                installations: Vec::new(),
            };
            manifest.validate(expected_generation)?;
            Ok((manifest, true))
        }
        2 => {
            let historical = serde_json::from_slice::<LibraryManifestV2>(bytes)
                .map_err(|_| LibraryError::MalformedManifest)?;
            if historical.schema_version != 2 {
                return Err(LibraryError::MalformedManifest);
            }
            let manifest = LibraryManifest {
                schema_version: LIBRARY_MANIFEST_SCHEMA_VERSION,
                generation: historical.generation,
                base_generation: 0,
                entries: historical.entries,
                enablements: historical.enablements,
                managed_copies: Vec::new(),
                installations: Vec::new(),
            };
            manifest.validate(expected_generation)?;
            Ok((manifest, true))
        }
        3 => {
            let historical = serde_json::from_slice::<LibraryManifestV3>(bytes)
                .map_err(|_| LibraryError::MalformedManifest)?;
            if historical.schema_version != 3 {
                return Err(LibraryError::MalformedManifest);
            }
            let installations = historical
                .installations
                .into_iter()
                .map(|installation| {
                    let provenance = match installation.provenance {
                        ArtifactInstallProvenanceV3::Local => ArtifactInstallProvenance::Local,
                        ArtifactInstallProvenanceV3::Git(git) => {
                            ArtifactInstallProvenance::migrate_v3_git(
                                &git.url,
                                git.commit,
                                &git.artifact_path,
                            )
                            .ok_or(LibraryError::CorruptManifest)?
                        }
                    };
                    Ok(ManifestInstallation {
                        entry_id: installation.entry_id,
                        version: installation.version,
                        provenance,
                    })
                })
                .collect::<Result<Vec<_>, LibraryError>>()?;
            let manifest = LibraryManifest {
                schema_version: LIBRARY_MANIFEST_SCHEMA_VERSION,
                generation: historical.generation,
                base_generation: 0,
                entries: historical.entries,
                enablements: historical.enablements,
                managed_copies: Vec::new(),
                installations,
            };
            manifest.validate(expected_generation)?;
            Ok((manifest, true))
        }
        LIBRARY_MANIFEST_SCHEMA_VERSION => {
            let manifest = serde_json::from_slice::<LibraryManifest>(bytes)
                .map_err(|_| LibraryError::MalformedManifest)?;
            manifest.validate(expected_generation)?;
            Ok((manifest, false))
        }
        version => Err(LibraryError::UnsupportedManifestVersion(version)),
    }
}

fn strictly_ordered<T: Ord>(mut values: impl Iterator<Item = T>) -> bool {
    let Some(mut previous) = values.next() else {
        return true;
    };
    for current in values {
        if previous >= current {
            return false;
        }
        previous = current;
    }
    true
}

fn ensure_manifest_version(
    manifest: &LibraryManifest,
    key: &LibraryEnablementKey,
) -> Result<(), LibraryError> {
    let entry = manifest
        .entries
        .binary_search_by(|entry| entry.id.cmp(&key.entry_id))
        .ok()
        .map(|index| &manifest.entries[index])
        .ok_or_else(|| LibraryError::EntryNotFound(key.entry_id.clone()))?;
    if entry
        .versions
        .binary_search_by(|version| version.as_str().cmp(key.version.as_str()))
        .is_err()
    {
        return Err(LibraryError::VersionNotFound {
            entry_id: key.entry_id.clone(),
            version: key.version.clone(),
        });
    }
    Ok(())
}

fn managed_copy_for_destination<'a>(
    manifest: &'a LibraryManifest,
    key: &LibraryEnablementKey,
) -> Option<&'a ManifestManagedCopy> {
    manifest.managed_copies.iter().find(|managed| {
        managed.key.project == key.project
            && managed.key.agent == key.agent
            && managed.key.entry_id == key.entry_id
    })
}

fn managed_copy_matches_root(
    manifest: &LibraryManifest,
    key: &LibraryEnablementKey,
    root: &LibraryManagedRootId,
) -> Result<bool, LibraryError> {
    let Ok(index) = manifest
        .managed_copies
        .binary_search_by(|managed| managed.key.cmp(key))
    else {
        return Ok(false);
    };
    if &manifest.managed_copies[index].root != root {
        return Err(LibraryError::ManagedCopyRootMismatch);
    }
    Ok(true)
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn manifest_generation_name(generation: u64) -> String {
    format!("{generation:0MANIFEST_GENERATION_DIGITS$}{MANIFEST_FILE_SUFFIX}")
}

fn parse_manifest_generation_name(name: &OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let digits = name.strip_suffix(MANIFEST_FILE_SUFFIX)?;
    if digits.len() != MANIFEST_GENERATION_DIGITS
        || !digits.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    digits.parse().ok()
}

fn generation_set(directory: &Dir) -> Result<Vec<u64>, LibraryError> {
    let mut generations = Vec::new();
    for (index, entry) in directory
        .entries()
        .map_err(|_| LibraryError::Io(LibraryIoOperation::ReadManifest))?
        .enumerate()
    {
        if index >= MAX_MANIFEST_DIRECTORY_ENTRIES {
            return Err(LibraryError::ManifestCapacityExceeded);
        }
        let entry = entry.map_err(|_| LibraryError::Io(LibraryIoOperation::ReadManifest))?;
        let Some(generation) = parse_manifest_generation_name(&entry.file_name()) else {
            continue;
        };
        let file_type = entry
            .file_type()
            .map_err(|_| LibraryError::Io(LibraryIoOperation::ReadManifest))?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(LibraryError::UnsafePath);
        }
        generations.push(generation);
    }
    generations.sort_unstable();
    Ok(generations)
}

fn encode_manifest(manifest: &LibraryManifest) -> Result<Vec<u8>, LibraryError> {
    let mut bytes =
        serde_json::to_vec_pretty(manifest).map_err(|_| LibraryError::CorruptManifest)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LIBRARY_MANIFEST_BYTES {
        return Err(LibraryError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn encode_commit_marker(marker: &CommitMarker) -> Result<Vec<u8>, LibraryError> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(|_| LibraryError::CorruptManifest)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_COMMIT_MARKER_BYTES {
        return Err(LibraryError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn validate_marker(
    marker: &CommitMarker,
    generation: u64,
    manifest_bytes: &[u8],
) -> Result<(), LibraryError> {
    if marker.schema_version != COMMIT_MARKER_SCHEMA_VERSION
        || marker.generation != generation
        || marker.manifest_digest != digest(manifest_bytes)
    {
        return Err(LibraryError::CorruptManifest);
    }
    Ok(())
}

fn encode_pending_marker(marker: &PendingMarker) -> Result<Vec<u8>, LibraryError> {
    let mut bytes = serde_json::to_vec_pretty(marker).map_err(|_| LibraryError::CorruptManifest)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_COMMIT_MARKER_BYTES {
        return Err(LibraryError::ManifestTooLarge);
    }
    Ok(bytes)
}

fn open_or_create_directory(parent: &Dir, name: &Path) -> Result<Dir, LibraryError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => verify_directory(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            set_private_directory_mode(&mut builder);
            match parent.create_dir_with(name, &builder) {
                Ok(()) => sync_directory(parent, LibraryIoOperation::InitializeDirectories)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => {
                    return Err(LibraryError::Io(LibraryIoOperation::InitializeDirectories));
                }
            }
            parent
                .open_dir_nofollow(name)
                .map_err(|_| LibraryError::UnsafePath)
                .and_then(verify_directory)
        }
        Err(_) => Err(LibraryError::UnsafePath),
    }
}

fn verify_directory(directory: Dir) -> Result<Dir, LibraryError> {
    if directory
        .dir_metadata()
        .map_err(|_| LibraryError::Io(LibraryIoOperation::InitializeDirectories))?
        .is_dir()
    {
        Ok(directory)
    } else {
        Err(LibraryError::UnsafePath)
    }
}

fn create_temporary_file(
    directory: &Dir,
    label: &str,
    operation: LibraryIoOperation,
) -> Result<(File, PathBuf), LibraryError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            ".{label}.pam-tmp-{}-{sequence}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        set_private_file_mode(&mut options);
        match directory.open_with(&path, &options) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(LibraryError::Io(operation)),
        }
    }
    Err(LibraryError::Io(operation))
}

fn publish_immutable_file(
    directory: &Dir,
    label: &str,
    name: &Path,
    bytes: &[u8],
    operation: LibraryIoOperation,
) -> Result<(), LibraryError> {
    let (mut file, temporary) = create_temporary_file(directory, label, operation)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| LibraryError::Io(operation))?;
        drop(file);
        directory
            .hard_link(&temporary, directory, name)
            .map_err(|_| LibraryError::Io(operation))?;
        sync_published_file(directory, name, operation)?;
        sync_directory(directory, operation)?;
        if directory.remove_file(&temporary).is_ok() {
            let _ = sync_directory(directory, operation);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

fn regular_file_exists(directory: &Dir, name: &Path) -> Result<bool, LibraryError> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(LibraryError::UnsafePath)
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LibraryError::Io(LibraryIoOperation::ReadManifest)),
    }
}

fn remove_generation_file(
    directory: &Dir,
    name: &Path,
    operation: LibraryIoOperation,
) -> Result<(), LibraryError> {
    if !regular_file_exists(directory, name)? {
        return Err(LibraryError::Io(operation));
    }
    directory
        .remove_file(name)
        .map_err(|_| LibraryError::Io(operation))?;
    sync_directory(directory, operation)
}

fn remove_generation_file_if_present(
    directory: &Dir,
    name: &Path,
    operation: LibraryIoOperation,
) -> Result<(), LibraryError> {
    if regular_file_exists(directory, name)? {
        remove_generation_file(directory, name, operation)?;
    }
    Ok(())
}

fn read_bounded_regular_file(
    directory: &Dir,
    name: &Path,
    maximum: usize,
    operation: LibraryIoOperation,
) -> Result<Option<Vec<u8>>, LibraryError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return match directory.symlink_metadata(name) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    Err(LibraryError::UnsafePath)
                }
                _ => Err(LibraryError::Io(operation)),
            };
        }
    };
    let before = file.metadata().map_err(|_| LibraryError::Io(operation))?;
    if !before.is_file() {
        return Err(LibraryError::UnsafePath);
    }
    if usize::try_from(before.len()).unwrap_or(usize::MAX) > maximum {
        return Err(if operation == LibraryIoOperation::ReadManifest {
            LibraryError::ManifestTooLarge
        } else {
            LibraryError::ArtifactTooLarge
        });
    }
    let limit = u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(maximum));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| LibraryError::Io(operation))?;
    let after = directory
        .symlink_metadata(name)
        .map_err(|_| LibraryError::Io(operation))?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || after.len() != before.len()
        || bytes.len() > maximum
    {
        return Err(LibraryError::UnsafePath);
    }
    Ok(Some(bytes))
}

fn sync_published_file(
    directory: &Dir,
    name: &Path,
    operation: LibraryIoOperation,
) -> Result<(), LibraryError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|_| {
        match directory.symlink_metadata(name) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                LibraryError::UnsafePath
            }
            _ => LibraryError::Io(operation),
        }
    })?;
    if !file
        .metadata()
        .map_err(|_| LibraryError::Io(operation))?
        .is_file()
    {
        return Err(LibraryError::UnsafePath);
    }
    file.sync_all().map_err(|_| LibraryError::Io(operation))
}

fn sync_directory(directory: &Dir, operation: LibraryIoOperation) -> Result<(), LibraryError> {
    #[cfg(unix)]
    directory
        .open(".")
        .and_then(|file| file.sync_all())
        .map_err(|_| LibraryError::Io(operation))?;
    #[cfg(not(unix))]
    let _ = (directory, operation);
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_mode(builder: &mut DirBuilder) {
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn set_private_directory_mode(_builder: &mut DirBuilder) {}

#[cfg(unix)]
fn set_private_file_mode(options: &mut OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_mode(_options: &mut OpenOptions) {}
