use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    io::{Read, Seek as _, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(any(unix, windows))]
use cap_fs_ext::MetadataExt as _;
#[cfg(unix)]
use cap_fs_ext::OpenOptionsSyncExt as _;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, ambient_authority};
use cap_std::fs::{Dir, DirBuilder, File, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use pam_core::ContentDigest;
use sha2::{Digest as _, Sha256};

use crate::{
    CanonicalEntryId, CanonicalLibrary, LibraryEnablementKey, LibraryError, LibraryManagedRootId,
    MAX_LIBRARY_ARTIFACT_BYTES, OriginAgent,
};
#[cfg(test)]
use crate::{LibraryManagedCopyChange, LibraryProjectKey};

pub const MAX_MATERIALIZATION_BATCH_ENTRIES: usize = 1_024;
pub const MAX_MATERIALIZATION_BATCH_BYTES: usize = 16 * 1024 * 1024;

const MAX_TEMPORARY_FILE_ATTEMPTS: usize = 16;

static NEXT_TEMPORARY_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MaterializationAgent {
    Claude,
    Codex,
    Cursor,
}

impl MaterializationAgent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
        }
    }

    fn relative_path(self, entry_id: &CanonicalEntryId) -> PathBuf {
        match self {
            Self::Claude => PathBuf::from("skills")
                .join(entry_id.as_str())
                .join("SKILL.md"),
            Self::Codex => PathBuf::from("prompts").join(format!("{entry_id}.md")),
            Self::Cursor => PathBuf::from("rules").join(format!("{entry_id}.mdc")),
        }
    }

    #[cfg(test)]
    const fn origin(self) -> OriginAgent {
        match self {
            Self::Claude => OriginAgent::ClaudeCode,
            Self::Codex => OriginAgent::Codex,
            Self::Cursor => OriginAgent::Cursor,
        }
    }

    const fn from_origin(origin: OriginAgent) -> Option<Self> {
        match origin {
            OriginAgent::ClaudeCode => Some(Self::Claude),
            OriginAgent::Codex => Some(Self::Codex),
            OriginAgent::Cursor => Some(Self::Cursor),
            OriginAgent::Pam => None,
        }
    }
}

impl fmt::Display for MaterializationAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationRequest {
    agent: MaterializationAgent,
    root: PathBuf,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
}

impl MaterializationRequest {
    #[must_use]
    pub fn new(
        agent: MaterializationAgent,
        root: impl Into<PathBuf>,
        entry_id: CanonicalEntryId,
        version: ContentDigest,
    ) -> Self {
        Self {
            agent,
            root: root.into(),
            entry_id,
            version,
        }
    }

    #[must_use]
    pub const fn agent(&self) -> MaterializationAgent {
        self.agent
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn entry_id(&self) -> &CanonicalEntryId {
        &self.entry_id
    }

    #[must_use]
    pub fn version(&self) -> &ContentDigest {
        &self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationAction {
    NoOp,
    Create,
    Replace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationDestinationMetadata {
    byte_len: u64,
    digest: ContentDigest,
}

impl MaterializationDestinationMetadata {
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MaterializationPlanItem {
    agent: MaterializationAgent,
    root: PathBuf,
    managed_root: LibraryManagedRootId,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    destination: PathBuf,
    relative_destination: PathBuf,
    action: MaterializationAction,
    existing: Option<MaterializationDestinationMetadata>,
    backup_destination: Option<PathBuf>,
    backup_existed: bool,
    desired_bytes: Vec<u8>,
    existing_bytes: Option<Vec<u8>>,
}

impl fmt::Debug for MaterializationPlanItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializationPlanItem")
            .field("agent", &self.agent)
            .field("root", &self.root)
            .field("managed_root", &self.managed_root)
            .field("entry_id", &self.entry_id)
            .field("version", &self.version)
            .field("destination", &self.destination)
            .field("relative_destination", &self.relative_destination)
            .field("action", &self.action)
            .field("existing", &self.existing)
            .field("backup_destination", &self.backup_destination)
            .field("backup_existed", &self.backup_existed)
            .field("desired_bytes", &self.desired_bytes.len())
            .field(
                "existing_bytes",
                &self.existing_bytes.as_ref().map(Vec::len),
            )
            .finish()
    }
}

impl MaterializationPlanItem {
    #[must_use]
    pub const fn agent(&self) -> MaterializationAgent {
        self.agent
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
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
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub const fn action(&self) -> MaterializationAction {
        self.action
    }

    #[must_use]
    pub fn existing(&self) -> Option<&MaterializationDestinationMetadata> {
        self.existing.as_ref()
    }

    #[must_use]
    pub fn backup_destination(&self) -> Option<&Path> {
        self.backup_destination.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationPlan {
    items: Vec<MaterializationPlanItem>,
}

impl MaterializationPlan {
    #[must_use]
    pub fn items(&self) -> &[MaterializationPlanItem] {
        &self.items
    }
}

/// Closed metadata-only drift states for one exact managed materialization key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationDriftState {
    Clean,
    Missing,
    Modified(ContentDigest),
    Conflict(MaterializationDriftConflict),
}

/// Deterministic reason that a target cannot be compared or resynchronized safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationDriftConflict {
    Disabled,
    Unowned,
    UnsafeRoot,
    UnsafePath,
    Symlink,
    NonRegular,
    Unreadable,
    TooLarge,
    PlanMismatch,
}

impl MaterializationDriftConflict {
    const fn description(self) -> &'static str {
        match self {
            Self::Disabled => "the exact materialization key is disabled",
            Self::Unowned => "the exact materialization key is not owned by PAM",
            Self::UnsafeRoot => "the materialization root is unsafe",
            Self::UnsafePath => "the materialization path is unsafe",
            Self::Symlink => "the materialization path contains a symlink",
            Self::NonRegular => "the materialization path is not a regular file path",
            Self::Unreadable => "the materialization destination cannot be read safely",
            Self::TooLarge => "the materialization destination exceeds its byte bound",
            Self::PlanMismatch => "the resync plan does not match the exact key",
        }
    }
}

/// Read-only metadata for one exact library-versus-materialized comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationDriftInspection {
    key: LibraryEnablementKey,
    destination: PathBuf,
    expected_digest: ContentDigest,
    state: MaterializationDriftState,
}

impl MaterializationDriftInspection {
    #[must_use]
    pub fn key(&self) -> &LibraryEnablementKey {
        &self.key
    }

    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub fn expected_digest(&self) -> &ContentDigest {
        &self.expected_digest
    }

    #[must_use]
    pub fn state(&self) -> &MaterializationDriftState {
        &self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationBackup {
    path: PathBuf,
    byte_len: u64,
    digest: ContentDigest,
}

impl MaterializationBackup {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationOutcome {
    agent: MaterializationAgent,
    managed_root: LibraryManagedRootId,
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    destination: PathBuf,
    action: MaterializationAction,
    backup: Option<MaterializationBackup>,
    ownership_recorded: bool,
}

impl MaterializationOutcome {
    #[must_use]
    pub const fn agent(&self) -> MaterializationAgent {
        self.agent
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
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub const fn action(&self) -> MaterializationAction {
        self.action
    }

    #[must_use]
    pub fn backup(&self) -> Option<&MaterializationBackup> {
        self.backup.as_ref()
    }

    /// Returns whether this apply durably owns the exact project, version, agent, and root key.
    #[must_use]
    pub const fn ownership_recorded(&self) -> bool {
        self.ownership_recorded
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializationBatchOutcome {
    outcomes: Vec<MaterializationOutcome>,
}

impl MaterializationBatchOutcome {
    #[must_use]
    pub fn outcomes(&self) -> &[MaterializationOutcome] {
        &self.outcomes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedCopyCleanupDisposition {
    Removed,
    Missing,
    PreservedModified,
    PreservedSymlink,
    PreservedUnowned,
}

/// Metadata-only result of disabling one exact materialization target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisableMaterializationOutcome {
    key: LibraryEnablementKey,
    state_changed: bool,
    relative_destination: PathBuf,
    cleanup: ManagedCopyCleanupDisposition,
}

impl DisableMaterializationOutcome {
    #[must_use]
    pub fn key(&self) -> &LibraryEnablementKey {
        &self.key
    }

    #[must_use]
    pub const fn state_changed(&self) -> bool {
        self.state_changed
    }

    #[must_use]
    pub fn relative_destination(&self) -> &Path {
        &self.relative_destination
    }

    #[must_use]
    pub const fn cleanup(&self) -> ManagedCopyCleanupDisposition {
        self.cleanup
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaterializationIoOperation {
    OpenRoot,
    LockRoot,
    ReadDestination,
    CreateDirectory,
    WriteBackup,
    WriteDestination,
    RemoveDestination,
    RestoreDestination,
}

impl MaterializationIoOperation {
    const fn description(self) -> &'static str {
        match self {
            Self::OpenRoot => "open the materialization root",
            Self::LockRoot => "lock the materialization root",
            Self::ReadDestination => "read a materialization destination",
            Self::CreateDirectory => "create a materialization directory",
            Self::WriteBackup => "write a materialization backup",
            Self::WriteDestination => "write a materialization destination",
            Self::RemoveDestination => "remove a materialization destination",
            Self::RestoreDestination => "restore a materialization destination",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializationError {
    BatchTooLarge,
    UnsupportedAgent(OriginAgent),
    InvalidRoot(MaterializationAgent),
    UnwritableRoot(MaterializationAgent),
    UnsafePath(PathBuf),
    DestinationTooLarge(PathBuf),
    DestinationConflict(PathBuf),
    BackupConflict(PathBuf),
    CleanupConflict {
        destination: PathBuf,
        quarantine: PathBuf,
    },
    StateChanged(PathBuf),
    VerificationFailed(PathBuf),
    RollbackFailed {
        paths: Vec<PathBuf>,
    },
    ManagedConflict(MaterializationDriftConflict),
    ResyncConflict(MaterializationDriftConflict),
    Library(LibraryError),
    Io(MaterializationIoOperation),
}

impl fmt::Display for MaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BatchTooLarge => formatter.write_str("materialization batch exceeds its bound"),
            Self::UnsupportedAgent(agent) => {
                write!(
                    formatter,
                    "{} has no materialization destination",
                    agent.as_str()
                )
            }
            Self::InvalidRoot(agent) => {
                write!(formatter, "{agent} materialization root is invalid")
            }
            Self::UnwritableRoot(agent) => {
                write!(formatter, "{agent} materialization root is not writable")
            }
            Self::UnsafePath(path) => {
                write!(
                    formatter,
                    "materialization path {} is unsafe",
                    path.display()
                )
            }
            Self::DestinationTooLarge(path) => write!(
                formatter,
                "materialization destination {} is too large",
                path.display()
            ),
            Self::DestinationConflict(path) => write!(
                formatter,
                "materialization destination {} has conflicting requested versions",
                path.display()
            ),
            Self::BackupConflict(path) => write!(
                formatter,
                "materialization backup {} conflicts with the destination bytes",
                path.display()
            ),
            Self::CleanupConflict {
                destination,
                quarantine,
            } => write!(
                formatter,
                "materialization cleanup target {} conflicts; recovery bytes remain at {}",
                destination.display(),
                quarantine.display()
            ),
            Self::StateChanged(path) => write!(
                formatter,
                "materialization destination {} changed after preflight",
                path.display()
            ),
            Self::VerificationFailed(path) => write!(
                formatter,
                "materialization destination {} failed verification",
                path.display()
            ),
            Self::RollbackFailed { paths } => write!(
                formatter,
                "{} materialization paths could not be rolled back",
                paths.len()
            ),
            Self::ManagedConflict(reason) => {
                write!(
                    formatter,
                    "managed materialization conflict: {}",
                    reason.description()
                )
            }
            Self::ResyncConflict(reason) => {
                write!(
                    formatter,
                    "materialization resync conflict: {}",
                    reason.description()
                )
            }
            Self::Library(error) => error.fmt(formatter),
            Self::Io(operation) => write!(formatter, "PAM could not {}", operation.description()),
        }
    }
}

impl Error for MaterializationError {}

impl From<LibraryError> for MaterializationError {
    fn from(error: LibraryError) -> Self {
        Self::Library(error)
    }
}

struct InspectedFile {
    metadata: MaterializationDestinationMetadata,
    bytes: Vec<u8>,
}

enum DriftDestinationState {
    Missing,
    File(InspectedFile),
    Conflict(MaterializationDriftConflict),
}

enum ManagedParentState {
    Missing,
    Symlink,
    Modified,
    Directory(Dir),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PostRenameFailure {
    Sync,
    Read,
    NonRegular,
    RestoreSync,
    RestorePostRemoveSync,
    ExactSync,
    ExactRemove,
}

enum QuarantineVerification {
    Exact,
    Modified,
}

struct QuarantineContext<'a> {
    root: &'a Dir,
    parent: &'a Dir,
    directory: &'a Dir,
    held_name: &'a Path,
    absolute: &'a Path,
    recovery_path: &'a Path,
}

#[derive(Clone, Copy)]
struct QuarantineInjection<'a> {
    recreated_bytes: Option<&'a [u8]>,
    failure: Option<PostRenameFailure>,
}

struct PreparedItem<'a> {
    plan: &'a MaterializationPlanItem,
    root: Dir,
    desired_bytes: Vec<u8>,
}

struct AppliedMutation {
    agent: MaterializationAgent,
    root: PathBuf,
    relative_destination: PathBuf,
    destination: PathBuf,
    backup_relative: Option<PathBuf>,
    previous_bytes: Option<Vec<u8>>,
    published_bytes: Vec<u8>,
    publication_quarantine: Option<PublicationQuarantine>,
}

struct CreatedDirectory {
    agent: MaterializationAgent,
    root: PathBuf,
    relative: PathBuf,
    absolute: PathBuf,
}

struct PublishFailure {
    error: MaterializationError,
    mutated: bool,
    quarantine: Option<PublicationQuarantine>,
}

#[derive(Clone, Copy)]
enum ManagedApply<'a> {
    Materialize(&'a LibraryEnablementKey),
    Resync(&'a LibraryEnablementKey),
}

impl<'a> ManagedApply<'a> {
    const fn key(self) -> &'a LibraryEnablementKey {
        match self {
            Self::Materialize(key) | Self::Resync(key) => key,
        }
    }

    const fn conflict(self, reason: MaterializationDriftConflict) -> MaterializationError {
        match self {
            Self::Materialize(_) => MaterializationError::ManagedConflict(reason),
            Self::Resync(_) => MaterializationError::ResyncConflict(reason),
        }
    }

    const fn requires_existing_ownership(self) -> bool {
        matches!(self, Self::Resync(_))
    }
}

#[derive(Clone, Copy, Default)]
struct ApplyInjection<'a> {
    before_rename_failure: Option<usize>,
    verification_failure: Option<usize>,
    directory_sync_failure: Option<usize>,
    before_publish_writer: Option<(usize, &'a [u8])>,
    after_publish_writer: Option<(usize, &'a [u8])>,
    disable_before_record: bool,
    competing_root_before_record: Option<&'a LibraryManagedRootId>,
}

#[derive(Clone, Copy, Default)]
struct PublishInjection<'a> {
    before_rename_failure: bool,
    verification_failure: bool,
    before_publish_writer: Option<&'a [u8]>,
    after_publish_writer: Option<&'a [u8]>,
}

struct PublicationQuarantine {
    directory: Dir,
    directory_name: PathBuf,
    held_name: PathBuf,
    recovery_path: PathBuf,
}

/// Preflights an entire exact-byte materialization batch without mutating agent roots.
///
/// # Errors
///
/// Returns a typed error when library bytes, roots, paths, existing targets, backups,
/// bounds, or duplicate destinations are invalid.
pub fn plan_materialization(
    library: &CanonicalLibrary,
    requests: &[MaterializationRequest],
) -> Result<MaterializationPlan, MaterializationError> {
    if requests.len() > MAX_MATERIALIZATION_BATCH_ENTRIES {
        return Err(MaterializationError::BatchTooLarge);
    }
    let mut items = Vec::<MaterializationPlanItem>::with_capacity(requests.len());
    let mut destinations = BTreeMap::<PathBuf, usize>::new();
    let mut aggregate_bytes = 0usize;

    for request in requests {
        let desired_bytes = library.read(&request.entry_id, &request.version)?;
        let (root_path, root) = open_root(request.agent, &request.root)?;
        let managed_root = LibraryManagedRootId::from_canonical_path(&root_path)
            .map_err(|_| MaterializationError::InvalidRoot(request.agent))?;
        let relative_destination = request.agent.relative_path(&request.entry_id);
        validate_relative_path(&relative_destination)?;
        let destination = root_path.join(&relative_destination);

        if let Some(existing_index) = destinations.get(&destination).copied() {
            if items[existing_index].version == request.version {
                continue;
            }
            return Err(MaterializationError::DestinationConflict(destination));
        }

        let existing_file = inspect_file(&root, &relative_destination, &destination)?;
        let action = match existing_file.as_ref() {
            None => MaterializationAction::Create,
            Some(existing) if existing.bytes == desired_bytes => MaterializationAction::NoOp,
            Some(_) => MaterializationAction::Replace,
        };
        let existing = existing_file.as_ref().map(|file| file.metadata.clone());
        let existing_bytes = existing_file.as_ref().map(|file| file.bytes.clone());
        let (backup_destination, backup_existed) = if let Some(existing_file) =
            existing_file.as_ref()
            && action == MaterializationAction::Replace
        {
            let backup_relative =
                backup_relative_path(&relative_destination, &existing_file.metadata.digest)?;
            let backup_destination = root_path.join(&backup_relative);
            let backup = inspect_file(&root, &backup_relative, &backup_destination)?;
            if let Some(backup) = backup.as_ref()
                && backup.bytes != existing_file.bytes
            {
                return Err(MaterializationError::BackupConflict(backup_destination));
            }
            (Some(backup_destination), backup.is_some())
        } else {
            (None, false)
        };

        aggregate_bytes = aggregate_bytes
            .checked_add(desired_bytes.len())
            .and_then(|total| total.checked_add(existing_bytes.as_ref().map_or(0, Vec::len)))
            .ok_or(MaterializationError::BatchTooLarge)?;
        if aggregate_bytes > MAX_MATERIALIZATION_BATCH_BYTES {
            return Err(MaterializationError::BatchTooLarge);
        }
        let index = items.len();
        destinations.insert(destination.clone(), index);
        items.push(MaterializationPlanItem {
            agent: request.agent,
            root: root_path,
            managed_root,
            entry_id: request.entry_id.clone(),
            version: request.version.clone(),
            destination,
            relative_destination,
            action,
            existing,
            backup_destination,
            backup_existed,
            desired_bytes,
            existing_bytes,
        });
    }
    Ok(MaterializationPlan { items })
}

/// Builds a zero-write preview for one enabled canonical version at its managed agent root.
///
/// Existing ownership must either be absent or bound to the exact canonical plan root. This
/// prevents a preview for one root from authorizing publication over a copy managed at another.
///
/// # Errors
///
/// Returns a typed conflict when the key is disabled or the plan does not match it, a root
/// mismatch when existing ownership belongs elsewhere, or a normal preflight error.
pub fn plan_managed_materialization(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
) -> Result<MaterializationPlan, MaterializationError> {
    let agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    let plan = plan_materialization(
        library,
        &[MaterializationRequest::new(
            agent,
            agent_root,
            key.entry_id().clone(),
            key.version().clone(),
        )],
    )?;
    let managed = ManagedApply::Materialize(key);
    validate_managed_plan(managed, &plan)?;
    validate_managed_ownership(library, managed, &plan)?;
    Ok(plan)
}

/// Inspects one exact enabled and owned materialization without mutating the agent root.
///
/// The comparison reads bounded regular files without following symlinks. Disabled, unowned,
/// unsafe, or otherwise unreadable targets are returned as closed conflict states.
///
/// # Errors
///
/// Returns an error only when the exact canonical library version or its durable metadata cannot
/// be read safely.
pub fn inspect_materialization_drift(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
) -> Result<MaterializationDriftInspection, MaterializationError> {
    let agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    let relative_destination = agent.relative_path(key.entry_id());
    let supplied_destination = agent_root.join(&relative_destination);
    let expected_digest = key.version().clone();

    let (destination, state) = if library.is_enabled(key)? {
        let Some((root_path, root)) = open_drift_root(agent_root) else {
            return Ok(MaterializationDriftInspection {
                key: key.clone(),
                destination: supplied_destination,
                expected_digest,
                state: MaterializationDriftState::Conflict(
                    MaterializationDriftConflict::UnsafeRoot,
                ),
            });
        };
        let destination = root_path.join(&relative_destination);
        let Ok(managed_root) = LibraryManagedRootId::from_canonical_path(&root_path) else {
            return Ok(MaterializationDriftInspection {
                key: key.clone(),
                destination,
                expected_digest,
                state: MaterializationDriftState::Conflict(
                    MaterializationDriftConflict::UnsafeRoot,
                ),
            });
        };
        let (expected_bytes, enabled, managed) =
            library.managed_materialization_snapshot(key, &managed_root)?;
        let state = if enabled {
            if managed {
                if validate_relative_path(&relative_destination).is_err() {
                    MaterializationDriftState::Conflict(MaterializationDriftConflict::UnsafePath)
                } else {
                    match inspect_drift_destination(&root, &relative_destination, &destination) {
                        DriftDestinationState::Missing => MaterializationDriftState::Missing,
                        DriftDestinationState::File(actual) if actual.bytes == expected_bytes => {
                            MaterializationDriftState::Clean
                        }
                        DriftDestinationState::File(actual) => {
                            MaterializationDriftState::Modified(actual.metadata.digest)
                        }
                        DriftDestinationState::Conflict(reason) => {
                            MaterializationDriftState::Conflict(reason)
                        }
                    }
                }
            } else {
                MaterializationDriftState::Conflict(MaterializationDriftConflict::Unowned)
            }
        } else {
            MaterializationDriftState::Conflict(MaterializationDriftConflict::Disabled)
        };
        (destination, state)
    } else {
        (
            supplied_destination,
            MaterializationDriftState::Conflict(MaterializationDriftConflict::Disabled),
        )
    };

    Ok(MaterializationDriftInspection {
        key: key.clone(),
        destination,
        expected_digest,
        state,
    })
}

/// Builds a zero-write preview for resynchronizing one exact enabled and owned key.
///
/// # Errors
///
/// Returns a typed conflict for disabled, unowned, or unsafe materializations, or a normal
/// materialization preflight error when the target changes during preview.
pub fn plan_materialization_resync(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
) -> Result<MaterializationPlan, MaterializationError> {
    let inspection = inspect_materialization_drift(library, key, agent_root)?;
    if let MaterializationDriftState::Conflict(reason) = inspection.state {
        return Err(MaterializationError::ResyncConflict(reason));
    }
    let agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    plan_materialization(
        library,
        &[MaterializationRequest::new(
            agent,
            agent_root,
            key.entry_id().clone(),
            key.version().clone(),
        )],
    )
}

/// Applies an exact resync preview through the normal backup and no-clobber rollback path.
///
/// # Errors
///
/// Returns a typed conflict if the plan, enablement, or ownership no longer matches the exact
/// project/agent/version key, and otherwise returns the normal apply error on a target race.
pub fn apply_materialization_resync(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    plan: &MaterializationPlan,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    let managed = ManagedApply::Resync(key);
    validate_managed_plan(managed, plan)?;
    validate_managed_ownership(library, managed, plan)?;
    apply_materialization_inner(library, plan, ApplyInjection::default(), Some(managed))
}

/// Applies one managed materialization and records ownership before reporting success.
///
/// The root lock remains held from revalidation through publication and ownership recording.
/// Create and replace mutations are exhaustively rolled back if enablement changes, ownership is
/// concurrently claimed at another root, or durable ownership publication fails. A no-op never
/// claims previously unowned bytes.
///
/// # Errors
///
/// Returns a typed conflict for a disabled, mismatched, or cross-root key. Publication and
/// rollback failures retain the same recovery metadata as low-level materialization.
pub fn apply_managed_materialization(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    plan: &MaterializationPlan,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    let managed = ManagedApply::Materialize(key);
    validate_managed_plan(managed, plan)?;
    apply_materialization_inner(library, plan, ApplyInjection::default(), Some(managed))
}

/// Applies a fully preflighted batch, retaining exact backups for successful replacements.
///
/// # Errors
///
/// Returns a typed error when preflight state changed, publication or verification fails,
/// or a destination cannot be restored to its exact prior state.
#[cfg(test)]
pub(crate) fn apply_materialization(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(library, plan, ApplyInjection::default(), None)
}

/// Records managed-copy ownership from one successful materialization outcome.
///
/// No-op outcomes never establish ownership over files that may have been created by a user.
/// Created and replaced outcomes record their deterministic key bound to a non-sensitive digest
/// of the validated canonical root; the ambient root path itself is never stored.
///
/// # Errors
///
/// Returns an error when the referenced library version or durable manifest is unavailable.
#[cfg(test)]
pub(crate) fn record_materialization(
    library: &CanonicalLibrary,
    project: LibraryProjectKey,
    outcome: &MaterializationOutcome,
) -> Result<LibraryManagedCopyChange, MaterializationError> {
    let key = LibraryEnablementKey::new(
        outcome.entry_id.clone(),
        outcome.version.clone(),
        outcome.agent.origin(),
        project,
    );
    if outcome.action == MaterializationAction::NoOp {
        return Ok(LibraryManagedCopyChange::not_recorded(key));
    }
    library
        .record_managed_copy(key, outcome.managed_root.clone())
        .map_err(Into::into)
}

/// Disables one exact key and safely cleans up its recorded managed copy.
///
/// One root-then-library lock transaction covers state inspection, cleanup, and manifest
/// publication. Exact candidates move atomically into a private quarantine before bounded
/// no-follow verification. Missing files clear ownership; modified or symlinked files are
/// preserved and keep ownership for drift reporting. Unowned files are never inspected.
///
/// # Errors
///
/// Returns an error for an unsupported agent, unsafe root, unavailable library state, or failed
/// durable removal. Enablement remains disabled if a later cleanup step fails.
pub fn disable_materialization(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
) -> Result<DisableMaterializationOutcome, MaterializationError> {
    disable_materialization_inner(library, key, agent_root, None, None, false)
}

#[cfg(test)]
pub(crate) fn disable_materialization_with_recreated_target(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
    recreated_bytes: &[u8],
) -> Result<DisableMaterializationOutcome, MaterializationError> {
    disable_materialization_inner(library, key, agent_root, Some(recreated_bytes), None, false)
}

#[cfg(test)]
pub(crate) fn disable_materialization_with_post_rename_failure(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
    failure: PostRenameFailure,
) -> Result<DisableMaterializationOutcome, MaterializationError> {
    disable_materialization_inner(library, key, agent_root, None, Some(failure), false)
}

#[cfg(test)]
pub(crate) fn disable_materialization_with_ownership_publish_failure(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
) -> Result<DisableMaterializationOutcome, MaterializationError> {
    disable_materialization_inner(library, key, agent_root, None, None, true)
}

fn disable_materialization_inner(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    agent_root: &Path,
    recreated_bytes: Option<&[u8]>,
    post_rename_failure: Option<PostRenameFailure>,
    fail_ownership_publish: bool,
) -> Result<DisableMaterializationOutcome, MaterializationError> {
    let agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    let relative_destination = agent.relative_path(key.entry_id());
    let (root_path, root, _root_lock) = acquire_explicit_root_lock(agent, agent_root)?;
    let managed_root = LibraryManagedRootId::from_canonical_path(&root_path)
        .map_err(|_| MaterializationError::InvalidRoot(agent))?;
    let destination = root_path.join(&relative_destination);
    let (state, cleanup) = library.disable_managed_copy(
        key,
        &managed_root,
        fail_ownership_publish,
        |managed, expected| {
            if !managed {
                return (Ok(ManagedCopyCleanupDisposition::PreservedUnowned), false);
            }
            let expected = expected.expect("managed copies reference verified library bytes");
            match quarantine_managed_destination(
                &root,
                &relative_destination,
                &destination,
                expected,
                recreated_bytes,
                post_rename_failure,
            ) {
                Ok(ManagedCopyCleanupDisposition::Removed) => {
                    (Ok(ManagedCopyCleanupDisposition::Removed), true)
                }
                Ok(ManagedCopyCleanupDisposition::Missing) => {
                    (Ok(ManagedCopyCleanupDisposition::Missing), true)
                }
                Ok(disposition) => (Ok(disposition), false),
                Err(error) => (Err(error), false),
            }
        },
    )?;
    let cleanup = cleanup?;
    Ok(DisableMaterializationOutcome {
        key: key.clone(),
        state_changed: state.changed(),
        relative_destination,
        cleanup,
    })
}

#[cfg(test)]
pub(crate) fn apply_materialization_with_verification_failure(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    failing_index: usize,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            verification_failure: Some(failing_index),
            ..ApplyInjection::default()
        },
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_materialization_with_pre_rename_failure(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    failing_index: usize,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            before_rename_failure: Some(failing_index),
            ..ApplyInjection::default()
        },
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_materialization_with_directory_sync_failure(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    failing_index: usize,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            directory_sync_failure: Some(failing_index),
            ..ApplyInjection::default()
        },
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_materialization_with_pre_publish_writer(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    failing_index: usize,
    writer_bytes: &[u8],
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            before_publish_writer: Some((failing_index, writer_bytes)),
            ..ApplyInjection::default()
        },
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_materialization_with_post_publish_writer(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    failing_index: usize,
    writer_bytes: &[u8],
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            verification_failure: Some(failing_index),
            after_publish_writer: Some((failing_index, writer_bytes)),
            ..ApplyInjection::default()
        },
        None,
    )
}

#[cfg(test)]
pub(crate) fn apply_materialization_resync_with_disable_before_record(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    plan: &MaterializationPlan,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            disable_before_record: true,
            ..ApplyInjection::default()
        },
        Some(ManagedApply::Resync(key)),
    )
}

#[cfg(test)]
pub(crate) fn apply_managed_materialization_with_disable_before_record(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    plan: &MaterializationPlan,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            disable_before_record: true,
            ..ApplyInjection::default()
        },
        Some(ManagedApply::Materialize(key)),
    )
}

#[cfg(test)]
pub(crate) fn apply_managed_materialization_with_competing_root_before_record(
    library: &CanonicalLibrary,
    key: &LibraryEnablementKey,
    plan: &MaterializationPlan,
    competing_root: &Path,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    let agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    let (competing_root, _) = open_root(agent, competing_root)?;
    let competing_root = LibraryManagedRootId::from_canonical_path(&competing_root)
        .map_err(|_| MaterializationError::InvalidRoot(agent))?;
    apply_materialization_inner(
        library,
        plan,
        ApplyInjection {
            competing_root_before_record: Some(&competing_root),
            ..ApplyInjection::default()
        },
        Some(ManagedApply::Materialize(key)),
    )
}

fn apply_materialization_inner(
    library: &CanonicalLibrary,
    plan: &MaterializationPlan,
    injection: ApplyInjection<'_>,
    managed: Option<ManagedApply<'_>>,
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    let _root_locks = acquire_root_locks(plan)?;
    if let Some(managed) = managed {
        validate_managed_plan(managed, plan)?;
        validate_managed_ownership(library, managed, plan)?;
    }
    let prepared = prepare_apply(library, plan)?;
    let mut outcomes = Vec::with_capacity(prepared.len());
    let mut mutations = Vec::new();
    let mut created_directories = Vec::new();

    for (index, prepared) in prepared.iter().enumerate() {
        if prepared.plan.action == MaterializationAction::NoOp {
            outcomes.push(outcome(prepared.plan, None));
            continue;
        }
        let parent_relative = prepared
            .plan
            .relative_destination
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let parent = match open_or_create_parent(
            &prepared.root,
            prepared.plan.agent,
            &prepared.plan.root,
            parent_relative,
            &prepared.plan.destination,
            &mut created_directories,
            injection.directory_sync_failure == Some(index),
        ) {
            Ok(parent) => parent,
            Err(error) => {
                return rollback_after_error(error, &mutations, &created_directories);
            }
        };
        let Some(target_name) = prepared.plan.relative_destination.file_name() else {
            return rollback_after_error(
                MaterializationError::UnsafePath(prepared.plan.destination.clone()),
                &mutations,
                &created_directories,
            );
        };

        if let Err(error) = revalidate_plan_item(&prepared.root, prepared.plan) {
            return rollback_after_error(error, &mutations, &created_directories);
        }

        let backup = match create_backup(&parent, prepared.plan) {
            Ok(backup) => backup,
            Err(error) => {
                return rollback_after_error(error, &mutations, &created_directories);
            }
        };
        let backup_relative = backup.as_ref().map(|backup| {
            prepared
                .plan
                .relative_destination
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(backup.path.file_name().expect("backup has a file name"))
        });
        let mut mutation = AppliedMutation {
            agent: prepared.plan.agent,
            root: prepared.plan.root.clone(),
            relative_destination: prepared.plan.relative_destination.clone(),
            destination: prepared.plan.destination.clone(),
            backup_relative,
            previous_bytes: prepared.plan.existing_bytes.clone(),
            published_bytes: prepared.desired_bytes.clone(),
            publication_quarantine: None,
        };
        let publish_result = publish_destination(
            prepared,
            &parent,
            target_name,
            publish_injection_for_index(injection, index),
        );
        if let Err(failure) = publish_result {
            let failure = *failure;
            if failure.mutated {
                mutation.publication_quarantine = failure.quarantine;
                mutations.push(mutation);
            }
            return rollback_after_error(failure.error, &mutations, &created_directories);
        }
        mutations.push(mutation);
        outcomes.push(outcome(prepared.plan, backup));
    }
    if let Some(managed) = managed {
        let ownership_recorded = record_managed_ownership(
            library,
            managed,
            plan,
            injection,
            &mutations,
            &created_directories,
        )?;
        outcomes
            .first_mut()
            .expect("validated managed plans contain exactly one outcome")
            .ownership_recorded = ownership_recorded;
    }
    Ok(MaterializationBatchOutcome { outcomes })
}

fn publish_injection_for_index(
    injection: ApplyInjection<'_>,
    index: usize,
) -> PublishInjection<'_> {
    PublishInjection {
        before_rename_failure: injection.before_rename_failure == Some(index),
        verification_failure: injection.verification_failure == Some(index),
        before_publish_writer: injection
            .before_publish_writer
            .filter(|(writer_index, _)| *writer_index == index)
            .map(|(_, bytes)| bytes),
        after_publish_writer: injection
            .after_publish_writer
            .filter(|(writer_index, _)| *writer_index == index)
            .map(|(_, bytes)| bytes),
    }
}

fn record_managed_ownership(
    library: &CanonicalLibrary,
    managed: ManagedApply<'_>,
    plan: &MaterializationPlan,
    injection: ApplyInjection<'_>,
    mutations: &[AppliedMutation],
    created_directories: &[CreatedDirectory],
) -> Result<bool, MaterializationError> {
    let key = managed.key();
    let action = plan
        .items
        .first()
        .ok_or_else(|| managed.conflict(MaterializationDriftConflict::PlanMismatch))?
        .action;
    if matches!(managed, ManagedApply::Materialize(_)) && action == MaterializationAction::NoOp {
        let managed_root = plan
            .items
            .first()
            .ok_or_else(|| managed.conflict(MaterializationDriftConflict::PlanMismatch))?
            .managed_root
            .clone();
        let (enabled, change) = library.transfer_managed_no_op(key.clone(), managed_root)?;
        if !enabled {
            return rollback_after_error(
                managed.conflict(MaterializationDriftConflict::Disabled),
                mutations,
                created_directories,
            )
            .map(|_| false);
        }
        return Ok(change.recorded());
    }
    let managed_root = plan
        .items
        .first()
        .ok_or_else(|| managed.conflict(MaterializationDriftConflict::PlanMismatch))?
        .managed_root
        .clone();
    if let Some(competing_root) = injection.competing_root_before_record
        && let Err(error) = library.record_managed_copy(key.clone(), competing_root.clone())
    {
        return rollback_after_error(error.into(), mutations, created_directories).map(|_| false);
    }
    if injection.disable_before_record
        && let Err(error) =
            library.disable_managed_copy(key, &managed_root, false, |_, _| ((), false))
    {
        return rollback_after_error(error.into(), mutations, created_directories).map(|_| false);
    }
    match library.record_managed_copy(key.clone(), managed_root) {
        Ok(change) if change.recorded() => Ok(true),
        Ok(_) => rollback_after_error(
            managed.conflict(MaterializationDriftConflict::Disabled),
            mutations,
            created_directories,
        )
        .map(|_| false),
        Err(error) => {
            rollback_after_error(error.into(), mutations, created_directories).map(|_| false)
        }
    }
}

fn prepare_apply<'a>(
    library: &CanonicalLibrary,
    plan: &'a MaterializationPlan,
) -> Result<Vec<PreparedItem<'a>>, MaterializationError> {
    let mut prepared = Vec::with_capacity(plan.items.len());
    for item in &plan.items {
        let desired_bytes = library.read(&item.entry_id, &item.version)?;
        if desired_bytes != item.desired_bytes {
            return Err(MaterializationError::StateChanged(item.destination.clone()));
        }
        let (root_path, root) = open_root(item.agent, &item.root)?;
        if root_path != item.root
            || item.agent.relative_path(&item.entry_id) != item.relative_destination
            || root_path.join(&item.relative_destination) != item.destination
        {
            return Err(MaterializationError::StateChanged(item.destination.clone()));
        }
        let current = inspect_file(&root, &item.relative_destination, &item.destination)?;
        if current.as_ref().map(|file| &file.metadata) != item.existing.as_ref()
            || current.as_ref().map(|file| &file.bytes) != item.existing_bytes.as_ref()
        {
            return Err(MaterializationError::StateChanged(item.destination.clone()));
        }
        if let Some(backup_destination) = item.backup_destination.as_ref() {
            let backup_relative = backup_relative_path(
                &item.relative_destination,
                item.existing
                    .as_ref()
                    .expect("replace plans have existing metadata")
                    .digest(),
            )?;
            let backup = inspect_file(&root, &backup_relative, backup_destination)?;
            if backup.is_some() != item.backup_existed
                || backup
                    .as_ref()
                    .is_some_and(|file| Some(&file.bytes) != item.existing_bytes.as_ref())
            {
                return Err(MaterializationError::StateChanged(
                    backup_destination.clone(),
                ));
            }
        }
        prepared.push(PreparedItem {
            plan: item,
            root,
            desired_bytes,
        });
    }
    Ok(prepared)
}

fn validate_managed_plan(
    managed: ManagedApply<'_>,
    plan: &MaterializationPlan,
) -> Result<(), MaterializationError> {
    let key = managed.key();
    let expected_agent = MaterializationAgent::from_origin(key.agent())
        .ok_or(MaterializationError::UnsupportedAgent(key.agent()))?;
    let [item] = plan.items.as_slice() else {
        return Err(managed.conflict(MaterializationDriftConflict::PlanMismatch));
    };
    if item.agent != expected_agent
        || item.entry_id != *key.entry_id()
        || item.version != *key.version()
        || item.relative_destination != expected_agent.relative_path(key.entry_id())
    {
        return Err(managed.conflict(MaterializationDriftConflict::PlanMismatch));
    }
    Ok(())
}

fn validate_managed_ownership(
    library: &CanonicalLibrary,
    managed: ManagedApply<'_>,
    plan: &MaterializationPlan,
) -> Result<(), MaterializationError> {
    let key = managed.key();
    let managed_root = &plan
        .items
        .first()
        .ok_or_else(|| managed.conflict(MaterializationDriftConflict::PlanMismatch))?
        .managed_root;
    let (_, enabled, owned_at_root) =
        library.managed_materialization_snapshot(key, managed_root)?;
    if !enabled {
        return Err(managed.conflict(MaterializationDriftConflict::Disabled));
    }
    if managed.requires_existing_ownership() && !owned_at_root {
        return Err(managed.conflict(MaterializationDriftConflict::Unowned));
    }
    Ok(())
}

fn acquire_root_locks(plan: &MaterializationPlan) -> Result<Vec<fs::File>, MaterializationError> {
    let mut roots = BTreeMap::new();
    for item in &plan.items {
        roots.entry(item.root.clone()).or_insert(item.agent);
    }
    let mut locks = Vec::with_capacity(roots.len());
    for (root_path, agent) in roots {
        let (canonical, _root, lock) = acquire_explicit_root_lock(agent, &root_path)?;
        if canonical != root_path {
            return Err(MaterializationError::StateChanged(root_path));
        }
        locks.push(lock);
    }
    Ok(locks)
}

fn acquire_explicit_root_lock(
    agent: MaterializationAgent,
    root_path: &Path,
) -> Result<(PathBuf, Dir, fs::File), MaterializationError> {
    let (canonical, root) = open_root(agent, root_path)?;
    let lock_path = canonical.join(".pam-materialize.lock");
    let file = open_root_lock(&root, &lock_path)?;
    if !file
        .metadata()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::LockRoot))?
        .is_file()
    {
        return Err(MaterializationError::UnsafePath(lock_path));
    }
    let lock = file.into_std();
    lock.lock()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::LockRoot))?;
    sync_directory(&root, MaterializationIoOperation::LockRoot)?;
    Ok((canonical, root, lock))
}

fn open_root_lock(root: &Dir, absolute: &Path) -> Result<File, MaterializationError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let mut create = OpenOptions::new();
        create
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        set_private_file_mode(&mut create);
        match root.open_with(".pam-materialize.lock", &create) {
            Ok(file) => {
                sync_directory(root, MaterializationIoOperation::LockRoot)?;
                return Ok(file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(MaterializationError::Io(
                    MaterializationIoOperation::LockRoot,
                ));
            }
        }

        let mut open = OpenOptions::new();
        open.read(true).write(true).follow(FollowSymlinks::No);
        match root.open_with(".pam-materialize.lock", &open) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return match root.symlink_metadata(".pam-materialize.lock") {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                        Err(MaterializationError::UnsafePath(absolute.to_path_buf()))
                    }
                    _ => Err(MaterializationError::Io(
                        MaterializationIoOperation::LockRoot,
                    )),
                };
            }
        }
    }
    Err(MaterializationError::Io(
        MaterializationIoOperation::LockRoot,
    ))
}

fn revalidate_plan_item(
    root: &Dir,
    item: &MaterializationPlanItem,
) -> Result<(), MaterializationError> {
    let current = inspect_file(root, &item.relative_destination, &item.destination)?;
    if current.as_ref().map(|file| &file.metadata) != item.existing.as_ref()
        || current.as_ref().map(|file| &file.bytes) != item.existing_bytes.as_ref()
    {
        return Err(MaterializationError::StateChanged(item.destination.clone()));
    }
    if let Some(backup_destination) = item.backup_destination.as_ref() {
        let backup_relative = backup_relative_path(
            &item.relative_destination,
            item.existing
                .as_ref()
                .expect("replace plans have existing metadata")
                .digest(),
        )?;
        let backup = inspect_file(root, &backup_relative, backup_destination)?;
        if backup.is_some() != item.backup_existed
            || backup
                .as_ref()
                .is_some_and(|file| Some(&file.bytes) != item.existing_bytes.as_ref())
        {
            return Err(MaterializationError::StateChanged(
                backup_destination.clone(),
            ));
        }
    }
    Ok(())
}

fn outcome(
    item: &MaterializationPlanItem,
    backup: Option<MaterializationBackup>,
) -> MaterializationOutcome {
    MaterializationOutcome {
        agent: item.agent,
        managed_root: item.managed_root.clone(),
        entry_id: item.entry_id.clone(),
        version: item.version.clone(),
        destination: item.destination.clone(),
        action: item.action,
        backup,
        ownership_recorded: false,
    }
}

fn open_root(
    agent: MaterializationAgent,
    root: &Path,
) -> Result<(PathBuf, Dir), MaterializationError> {
    if !root.is_absolute() {
        return Err(MaterializationError::InvalidRoot(agent));
    }
    let metadata =
        fs::symlink_metadata(root).map_err(|_| MaterializationError::InvalidRoot(agent))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(MaterializationError::InvalidRoot(agent));
    }
    if metadata.permissions().readonly() {
        return Err(MaterializationError::UnwritableRoot(agent));
    }
    let canonical = fs::canonicalize(root)
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::OpenRoot))?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::OpenRoot))?;
    Ok((canonical, directory))
}

fn open_drift_root(root: &Path) -> Option<(PathBuf, Dir)> {
    if !root.is_absolute() {
        return None;
    }
    let metadata = fs::symlink_metadata(root).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    let canonical = fs::canonicalize(root).ok()?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority()).ok()?;
    Some((canonical, directory))
}

fn inspect_drift_destination(
    root: &Dir,
    relative: &Path,
    absolute: &Path,
) -> DriftDestinationState {
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let Ok(mut parent) = root.try_clone() else {
        return DriftDestinationState::Conflict(MaterializationDriftConflict::Unreadable);
    };
    for component in parent_relative.components() {
        let Component::Normal(name) = component else {
            return DriftDestinationState::Conflict(MaterializationDriftConflict::UnsafePath);
        };
        let metadata = match parent.symlink_metadata(Path::new(name)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return DriftDestinationState::Missing;
            }
            Err(_) => {
                return DriftDestinationState::Conflict(MaterializationDriftConflict::Unreadable);
            }
        };
        if metadata.file_type().is_symlink() {
            return DriftDestinationState::Conflict(MaterializationDriftConflict::Symlink);
        }
        if !metadata.is_dir() {
            return DriftDestinationState::Conflict(MaterializationDriftConflict::NonRegular);
        }
        parent = match parent.open_dir_nofollow(Path::new(name)) {
            Ok(directory) => directory,
            Err(_) => {
                return DriftDestinationState::Conflict(MaterializationDriftConflict::UnsafePath);
            }
        };
    }
    let Some(name) = relative.file_name() else {
        return DriftDestinationState::Conflict(MaterializationDriftConflict::UnsafePath);
    };
    let metadata = match parent.symlink_metadata(Path::new(name)) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return DriftDestinationState::Missing;
        }
        Err(_) => {
            return DriftDestinationState::Conflict(MaterializationDriftConflict::Unreadable);
        }
    };
    if metadata.file_type().is_symlink() {
        return DriftDestinationState::Conflict(MaterializationDriftConflict::Symlink);
    }
    if !metadata.is_file() {
        return DriftDestinationState::Conflict(MaterializationDriftConflict::NonRegular);
    }
    if usize::try_from(metadata.len()).unwrap_or(usize::MAX) > MAX_LIBRARY_ARTIFACT_BYTES {
        return DriftDestinationState::Conflict(MaterializationDriftConflict::TooLarge);
    }
    match read_regular_file(&parent, Path::new(name), absolute) {
        Ok(Some(file)) => DriftDestinationState::File(file),
        Ok(None) => DriftDestinationState::Missing,
        Err(MaterializationError::DestinationTooLarge(_)) => {
            DriftDestinationState::Conflict(MaterializationDriftConflict::TooLarge)
        }
        Err(MaterializationError::UnsafePath(_)) => {
            DriftDestinationState::Conflict(MaterializationDriftConflict::UnsafePath)
        }
        Err(_) => DriftDestinationState::Conflict(MaterializationDriftConflict::Unreadable),
    }
}

fn validate_relative_path(path: &Path) -> Result<(), MaterializationError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(MaterializationError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn inspect_file(
    root: &Dir,
    relative: &Path,
    absolute: &Path,
) -> Result<Option<InspectedFile>, MaterializationError> {
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let Some(parent) = open_existing_parent(root, parent_relative, absolute)? else {
        return Ok(None);
    };
    let name = relative
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(absolute.to_path_buf()))?;
    read_regular_file(&parent, Path::new(name), absolute)
}

fn quarantine_managed_destination(
    root: &Dir,
    relative: &Path,
    absolute: &Path,
    expected: &[u8],
    recreated_bytes: Option<&[u8]>,
    post_rename_failure: Option<PostRenameFailure>,
) -> Result<ManagedCopyCleanupDisposition, MaterializationError> {
    validate_relative_path(relative)?;
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = match open_managed_parent(root, parent_relative, absolute)? {
        ManagedParentState::Missing => return Ok(ManagedCopyCleanupDisposition::Missing),
        ManagedParentState::Symlink => {
            return Ok(ManagedCopyCleanupDisposition::PreservedSymlink);
        }
        ManagedParentState::Modified => {
            return Ok(ManagedCopyCleanupDisposition::PreservedModified);
        }
        ManagedParentState::Directory(parent) => parent,
    };
    let name = relative
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(absolute.to_path_buf()))?;
    let name = Path::new(name);
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManagedCopyCleanupDisposition::Missing);
        }
        Err(_) => {
            return Err(MaterializationError::Io(
                MaterializationIoOperation::ReadDestination,
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(ManagedCopyCleanupDisposition::PreservedSymlink);
    }
    if !metadata.is_file() {
        return Ok(ManagedCopyCleanupDisposition::PreservedModified);
    }
    let (quarantine, directory_name) = create_quarantine_directory(&parent)?;
    let held_name = Path::new("managed-copy");
    if let Err(error) = parent.rename(name, &quarantine, held_name) {
        let _ = parent.remove_dir(&directory_name);
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(ManagedCopyCleanupDisposition::Missing);
        }
        return Err(MaterializationError::Io(
            MaterializationIoOperation::RemoveDestination,
        ));
    }
    let quarantine_path = absolute
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&directory_name)
        .join(held_name);
    let context = QuarantineContext {
        root,
        parent: &parent,
        directory: &quarantine,
        held_name,
        absolute,
        recovery_path: &quarantine_path,
    };
    let verification = verify_quarantined_destination(
        &context,
        expected,
        QuarantineInjection {
            recreated_bytes,
            failure: post_rename_failure,
        },
    );
    match verification {
        Ok(QuarantineVerification::Exact) => {
            remove_exact_quarantined_destination(&context, &directory_name, post_rename_failure)?;
            Ok(ManagedCopyCleanupDisposition::Removed)
        }
        Ok(QuarantineVerification::Modified) => {
            restore_quarantined_destination(&context, name, &directory_name, post_rename_failure)?;
            Ok(ManagedCopyCleanupDisposition::PreservedModified)
        }
        Err(error) => restore_after_quarantine_error(
            error,
            restore_quarantined_destination(&context, name, &directory_name, post_rename_failure),
        ),
    }
}

fn verify_quarantined_destination(
    context: &QuarantineContext<'_>,
    expected: &[u8],
    injection: QuarantineInjection<'_>,
) -> Result<QuarantineVerification, MaterializationError> {
    if injection.failure == Some(PostRenameFailure::Sync) {
        return Err(MaterializationError::Io(
            MaterializationIoOperation::RemoveDestination,
        ));
    }
    sync_directory(
        context.parent,
        MaterializationIoOperation::RemoveDestination,
    )?;
    sync_directory(
        context.directory,
        MaterializationIoOperation::RemoveDestination,
    )?;
    if let Some(bytes) = injection.recreated_bytes {
        fs::write(context.absolute, bytes)
            .map_err(|_| MaterializationError::Io(MaterializationIoOperation::WriteDestination))?;
    }
    if injection.failure == Some(PostRenameFailure::NonRegular) {
        context
            .directory
            .remove_file(context.held_name)
            .map_err(|_| {
                MaterializationError::Io(MaterializationIoOperation::RestoreDestination)
            })?;
        context
            .directory
            .create_dir(context.held_name)
            .map_err(|_| {
                MaterializationError::Io(MaterializationIoOperation::RestoreDestination)
            })?;
    }
    if injection.failure == Some(PostRenameFailure::Read)
        || injection.failure == Some(PostRenameFailure::RestoreSync)
        || injection.failure == Some(PostRenameFailure::RestorePostRemoveSync)
    {
        return Err(MaterializationError::Io(
            MaterializationIoOperation::ReadDestination,
        ));
    }
    let metadata = context
        .directory
        .symlink_metadata(context.held_name)
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::ReadDestination))?;
    if !metadata.is_file()
        || usize::try_from(metadata.len()).unwrap_or(usize::MAX) > MAX_LIBRARY_ARTIFACT_BYTES
    {
        return Err(MaterializationError::UnsafePath(
            context.recovery_path.to_path_buf(),
        ));
    }
    let quarantined =
        read_regular_file(context.directory, context.held_name, context.recovery_path)?
            .ok_or_else(|| {
                MaterializationError::StateChanged(context.recovery_path.to_path_buf())
            })?;
    if quarantined.metadata.digest == digest(expected) && quarantined.bytes == expected {
        Ok(QuarantineVerification::Exact)
    } else {
        Ok(QuarantineVerification::Modified)
    }
}

fn create_quarantine_directory(parent: &Dir) -> Result<(Dir, PathBuf), MaterializationError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let name = PathBuf::from(format!(".pam-quarantine-{}-{sequence}", std::process::id()));
        let mut builder = DirBuilder::new();
        set_private_directory_mode(&mut builder);
        match parent.create_dir_with(&name, &builder) {
            Ok(()) => {
                sync_directory(parent, MaterializationIoOperation::RemoveDestination)?;
                let directory = parent.open_dir_nofollow(&name).map_err(|_| {
                    MaterializationError::Io(MaterializationIoOperation::RemoveDestination)
                })?;
                return Ok((directory, name));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(MaterializationError::Io(
                    MaterializationIoOperation::RemoveDestination,
                ));
            }
        }
    }
    Err(MaterializationError::Io(
        MaterializationIoOperation::RemoveDestination,
    ))
}

fn restore_quarantined_destination(
    context: &QuarantineContext<'_>,
    destination_name: &Path,
    directory_name: &Path,
    failure: Option<PostRenameFailure>,
) -> Result<(), MaterializationError> {
    match context
        .directory
        .hard_link(context.held_name, context.parent, destination_name)
    {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists
                || context.parent.symlink_metadata(destination_name).is_ok() =>
        {
            return Err(MaterializationError::CleanupConflict {
                destination: context.absolute.to_path_buf(),
                quarantine: context.recovery_path.to_path_buf(),
            });
        }
        Err(_) => {
            return Err(MaterializationError::CleanupConflict {
                destination: context.absolute.to_path_buf(),
                quarantine: context.recovery_path.to_path_buf(),
            });
        }
    }
    verify_restored_destination(context, destination_name)
        .map_err(|_| cleanup_conflict(context))?;
    if failure == Some(PostRenameFailure::RestoreSync) {
        return Err(cleanup_conflict(context));
    }
    sync_published_file(
        context.parent,
        destination_name,
        MaterializationIoOperation::RestoreDestination,
        context.absolute,
    )
    .map_err(|_| cleanup_conflict(context))?;
    sync_directory(
        context.parent,
        MaterializationIoOperation::RestoreDestination,
    )
    .map_err(|_| cleanup_conflict(context))?;
    sync_directory(
        context.directory,
        MaterializationIoOperation::RestoreDestination,
    )
    .map_err(|_| cleanup_conflict(context))?;
    sync_directory(context.root, MaterializationIoOperation::RestoreDestination)
        .map_err(|_| cleanup_conflict(context))?;
    remove_restored_quarantine(context, destination_name, directory_name, failure)
}

fn remove_restored_quarantine(
    context: &QuarantineContext<'_>,
    destination_name: &Path,
    directory_name: &Path,
    failure: Option<PostRenameFailure>,
) -> Result<(), MaterializationError> {
    context
        .directory
        .remove_file(context.held_name)
        .map_err(|_| cleanup_conflict(context))?;
    if failure == Some(PostRenameFailure::RestorePostRemoveSync)
        || sync_directory(
            context.directory,
            MaterializationIoOperation::RestoreDestination,
        )
        .is_err()
    {
        retain_recovery_link(context, destination_name, directory_name);
        return Err(cleanup_conflict(context));
    }
    if context.parent.remove_dir(directory_name).is_err() {
        retain_recovery_link(context, destination_name, directory_name);
        return Err(cleanup_conflict(context));
    }
    if sync_directory(
        context.parent,
        MaterializationIoOperation::RestoreDestination,
    )
    .is_err()
        || sync_directory(context.root, MaterializationIoOperation::RestoreDestination).is_err()
    {
        retain_recovery_link(context, destination_name, directory_name);
        return Err(cleanup_conflict(context));
    }
    Ok(())
}

fn retain_recovery_link(
    context: &QuarantineContext<'_>,
    destination_name: &Path,
    directory_name: &Path,
) {
    let recovery = match context.parent.open_dir_nofollow(directory_name) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            set_private_directory_mode(&mut builder);
            if context
                .parent
                .create_dir_with(directory_name, &builder)
                .is_err()
            {
                return;
            }
            let Ok(directory) = context.parent.open_dir_nofollow(directory_name) else {
                return;
            };
            directory
        }
        Err(_) => return,
    };
    if recovery.symlink_metadata(context.held_name).is_err()
        && context
            .parent
            .hard_link(destination_name, &recovery, context.held_name)
            .is_err()
    {
        return;
    }
    let _ = sync_published_file(
        &recovery,
        context.held_name,
        MaterializationIoOperation::RestoreDestination,
        context.recovery_path,
    );
    let _ = sync_directory(&recovery, MaterializationIoOperation::RestoreDestination);
    let _ = sync_directory(
        context.parent,
        MaterializationIoOperation::RestoreDestination,
    );
    let _ = sync_directory(context.root, MaterializationIoOperation::RestoreDestination);
}

fn verify_restored_destination(
    context: &QuarantineContext<'_>,
    destination_name: &Path,
) -> Result<(), MaterializationError> {
    let quarantined =
        read_regular_file(context.directory, context.held_name, context.recovery_path)?
            .ok_or_else(|| {
                MaterializationError::StateChanged(context.recovery_path.to_path_buf())
            })?;
    let restored = read_regular_file(context.parent, destination_name, context.absolute)?
        .ok_or_else(|| MaterializationError::StateChanged(context.absolute.to_path_buf()))?;
    if restored.metadata == quarantined.metadata && restored.bytes == quarantined.bytes {
        Ok(())
    } else {
        Err(MaterializationError::StateChanged(
            context.absolute.to_path_buf(),
        ))
    }
}

fn remove_exact_quarantined_destination(
    context: &QuarantineContext<'_>,
    directory_name: &Path,
    failure: Option<PostRenameFailure>,
) -> Result<(), MaterializationError> {
    if failure == Some(PostRenameFailure::ExactSync) {
        return Err(MaterializationError::Io(
            MaterializationIoOperation::RemoveDestination,
        ));
    }
    sync_directory(
        context.directory,
        MaterializationIoOperation::RemoveDestination,
    )?;
    sync_directory(
        context.parent,
        MaterializationIoOperation::RemoveDestination,
    )?;
    if failure == Some(PostRenameFailure::ExactRemove) {
        return Err(MaterializationError::Io(
            MaterializationIoOperation::RemoveDestination,
        ));
    }
    context
        .directory
        .remove_file(context.held_name)
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::RemoveDestination))?;
    sync_directory(
        context.directory,
        MaterializationIoOperation::RemoveDestination,
    )?;
    context
        .parent
        .remove_dir(directory_name)
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::RemoveDestination))?;
    sync_directory(
        context.parent,
        MaterializationIoOperation::RemoveDestination,
    )?;
    sync_directory(context.root, MaterializationIoOperation::RemoveDestination)
}

fn cleanup_conflict(context: &QuarantineContext<'_>) -> MaterializationError {
    MaterializationError::CleanupConflict {
        destination: context.absolute.to_path_buf(),
        quarantine: context.recovery_path.to_path_buf(),
    }
}

fn restore_after_quarantine_error(
    original: MaterializationError,
    restoration: Result<(), MaterializationError>,
) -> Result<ManagedCopyCleanupDisposition, MaterializationError> {
    match restoration {
        Ok(()) => Err(original),
        Err(conflict) => Err(conflict),
    }
}

fn open_managed_parent(
    root: &Dir,
    relative: &Path,
    absolute: &Path,
) -> Result<ManagedParentState, MaterializationError> {
    let mut current = root
        .try_clone()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::OpenRoot))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
        };
        let name = Path::new(name);
        let metadata = match current.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ManagedParentState::Missing);
            }
            Err(_) => {
                return Err(MaterializationError::Io(
                    MaterializationIoOperation::ReadDestination,
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Ok(ManagedParentState::Symlink);
        }
        if !metadata.is_dir() {
            return Ok(ManagedParentState::Modified);
        }
        current = current
            .open_dir_nofollow(name)
            .map_err(|_| MaterializationError::UnsafePath(absolute.to_path_buf()))?;
    }
    Ok(ManagedParentState::Directory(current))
}

fn open_existing_parent(
    root: &Dir,
    relative: &Path,
    absolute: &Path,
) -> Result<Option<Dir>, MaterializationError> {
    let mut current = root
        .try_clone()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::OpenRoot))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
        };
        match current.symlink_metadata(Path::new(name)) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
            }
            Ok(metadata) => {
                if metadata.permissions().readonly() {
                    return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
                }
                current = current
                    .open_dir_nofollow(Path::new(name))
                    .map_err(|_| MaterializationError::UnsafePath(absolute.to_path_buf()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => {
                return Err(MaterializationError::Io(
                    MaterializationIoOperation::ReadDestination,
                ));
            }
        }
    }
    Ok(Some(current))
}

fn read_regular_file(
    directory: &Dir,
    name: &Path,
    absolute: &Path,
) -> Result<Option<InspectedFile>, MaterializationError> {
    read_regular_file_inner(directory, name, absolute, || {})
}

fn read_regular_file_inner(
    directory: &Dir,
    name: &Path,
    absolute: &Path,
    after_first_read: impl FnOnce(),
) -> Result<Option<InspectedFile>, MaterializationError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.nonblock(true);
    let mut file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return match directory.symlink_metadata(name) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    Err(MaterializationError::UnsafePath(absolute.to_path_buf()))
                }
                _ => Err(MaterializationError::Io(
                    MaterializationIoOperation::ReadDestination,
                )),
            };
        }
    };
    let before = file
        .metadata()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::ReadDestination))?;
    if !before.is_file() {
        return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
    }
    let before_length = usize::try_from(before.len())
        .map_err(|_| MaterializationError::DestinationTooLarge(absolute.to_path_buf()))?;
    if before_length > MAX_LIBRARY_ARTIFACT_BYTES {
        return Err(MaterializationError::DestinationTooLarge(
            absolute.to_path_buf(),
        ));
    }
    let path_before = directory
        .symlink_metadata(name)
        .map_err(|_| MaterializationError::StateChanged(absolute.to_path_buf()))?;
    if path_before.file_type().is_symlink() || !path_before.is_file() {
        return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
    }
    if !same_file_identity(&before, &path_before)
        || path_before.len() != before.len()
        || path_before.modified().ok() != before.modified().ok()
    {
        return Err(MaterializationError::StateChanged(absolute.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(before_length);
    (&mut file)
        .take(u64::try_from(MAX_LIBRARY_ARTIFACT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::ReadDestination))?;
    if bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES {
        return Err(MaterializationError::DestinationTooLarge(
            absolute.to_path_buf(),
        ));
    }
    if bytes.len() != before_length {
        return Err(MaterializationError::StateChanged(absolute.to_path_buf()));
    }
    after_first_read();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| MaterializationError::StateChanged(absolute.to_path_buf()))?;
    let mut second_bytes = Vec::with_capacity(before_length);
    (&mut file)
        .take(u64::try_from(MAX_LIBRARY_ARTIFACT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut second_bytes)
        .map_err(|_| MaterializationError::StateChanged(absolute.to_path_buf()))?;
    if second_bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES {
        return Err(MaterializationError::DestinationTooLarge(
            absolute.to_path_buf(),
        ));
    }
    if second_bytes.len() != before_length || second_bytes != bytes {
        return Err(MaterializationError::StateChanged(absolute.to_path_buf()));
    }
    let path_after = directory
        .symlink_metadata(name)
        .map_err(|_| MaterializationError::StateChanged(absolute.to_path_buf()))?;
    let handle_after = file
        .metadata()
        .map_err(|_| MaterializationError::StateChanged(absolute.to_path_buf()))?;
    if path_after.file_type().is_symlink() || !path_after.is_file() || !handle_after.is_file() {
        return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
    }
    if !same_file_identity(&before, &path_after)
        || !same_file_identity(&before, &handle_after)
        || path_after.len() != before.len()
        || handle_after.len() != before.len()
        || path_after.modified().ok() != before.modified().ok()
        || handle_after.modified().ok() != before.modified().ok()
    {
        return Err(MaterializationError::StateChanged(absolute.to_path_buf()));
    }
    Ok(Some(InspectedFile {
        metadata: MaterializationDestinationMetadata {
            byte_len: before.len(),
            digest: digest(&bytes),
        },
        bytes,
    }))
}

#[cfg(test)]
pub(crate) fn inspect_file_with_after_first_read(
    agent: MaterializationAgent,
    root: &Path,
    name: &Path,
    after_first_read: impl FnOnce(),
) -> Result<(), MaterializationError> {
    let (root, directory) = open_root(agent, root)?;
    validate_relative_path(name)?;
    read_regular_file_inner(&directory, name, &root.join(name), after_first_read).map(|_| ())
}

#[cfg(any(unix, windows))]
fn same_file_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn backup_relative_path(
    destination: &Path,
    digest: &ContentDigest,
) -> Result<PathBuf, MaterializationError> {
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| MaterializationError::UnsafePath(destination.to_path_buf()))?;
    let backup_name = format!(".{file_name}.pam-backup-{}", digest.sha256_hex());
    Ok(destination
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(backup_name))
}

fn open_or_create_parent(
    root: &Dir,
    agent: MaterializationAgent,
    root_path: &Path,
    relative: &Path,
    absolute: &Path,
    created_directories: &mut Vec<CreatedDirectory>,
    injected_sync_failure: bool,
) -> Result<Dir, MaterializationError> {
    let mut current = root
        .try_clone()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::OpenRoot))?;
    let mut accumulated = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
        };
        accumulated.push(name);
        match current.open_dir_nofollow(Path::new(name)) {
            Ok(directory) => current = directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                set_private_directory_mode(&mut builder);
                match current.create_dir_with(Path::new(name), &builder) {
                    Ok(()) => {
                        created_directories.push(CreatedDirectory {
                            agent,
                            root: root_path.to_path_buf(),
                            relative: accumulated.clone(),
                            absolute: root_path.join(&accumulated),
                        });
                        if injected_sync_failure {
                            return Err(MaterializationError::Io(
                                MaterializationIoOperation::CreateDirectory,
                            ));
                        }
                        sync_directory(&current, MaterializationIoOperation::CreateDirectory)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => {
                        return Err(MaterializationError::Io(
                            MaterializationIoOperation::CreateDirectory,
                        ));
                    }
                }
                current = current
                    .open_dir_nofollow(Path::new(name))
                    .map_err(|_| MaterializationError::UnsafePath(absolute.to_path_buf()))?;
            }
            Err(_) => return Err(MaterializationError::UnsafePath(absolute.to_path_buf())),
        }
        let metadata = current
            .dir_metadata()
            .map_err(|_| MaterializationError::Io(MaterializationIoOperation::CreateDirectory))?;
        if !metadata.is_dir() || metadata.permissions().readonly() {
            return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
        }
    }
    Ok(current)
}

fn create_backup(
    parent: &Dir,
    item: &MaterializationPlanItem,
) -> Result<Option<MaterializationBackup>, MaterializationError> {
    if item.action != MaterializationAction::Replace {
        return Ok(None);
    }
    let existing = item
        .existing
        .as_ref()
        .expect("replace plans have existing metadata");
    let existing_bytes = item
        .existing_bytes
        .as_ref()
        .expect("replace plans retain bounded existing bytes");
    let backup_path = item
        .backup_destination
        .as_ref()
        .expect("replace plans have a backup destination");
    let backup_name = backup_path
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(backup_path.clone()))?;
    if !item.backup_existed {
        publish_new_file(
            parent,
            Path::new(backup_name),
            existing_bytes,
            MaterializationIoOperation::WriteBackup,
            backup_path,
        )?;
    }
    let backup = read_regular_file(parent, Path::new(backup_name), backup_path)?
        .ok_or_else(|| MaterializationError::BackupConflict(backup_path.clone()))?;
    if backup.bytes != *existing_bytes {
        return Err(MaterializationError::BackupConflict(backup_path.clone()));
    }
    Ok(Some(MaterializationBackup {
        path: backup_path.clone(),
        byte_len: existing.byte_len,
        digest: existing.digest.clone(),
    }))
}

fn publish_destination(
    prepared: &PreparedItem<'_>,
    parent: &Dir,
    target_name: &std::ffi::OsStr,
    injection: PublishInjection<'_>,
) -> Result<(), Box<PublishFailure>> {
    let root = &prepared.root;
    let bytes = prepared.desired_bytes.as_slice();
    let action = prepared.plan.action;
    let previous_bytes = prepared.plan.existing_bytes.as_deref();
    let destination = &prepared.plan.destination;
    let operation = MaterializationIoOperation::WriteDestination;
    let name = Path::new(target_name);
    let (mut file, temporary) = create_temporary_file(parent, operation).map_err(|error| {
        Box::new(PublishFailure {
            error,
            mutated: false,
            quarantine: None,
        })
    })?;
    let mut mutated = false;
    let mut quarantine = None;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| MaterializationError::Io(operation))?;
        drop(file);
        if let Some(writer_bytes) = injection.before_publish_writer {
            inject_noncooperating_writer(parent, name, destination, writer_bytes)?;
        }
        if injection.before_rename_failure {
            return Err(MaterializationError::Io(operation));
        }
        match action {
            MaterializationAction::Replace => {
                quarantine = Some(quarantine_replacement_for_publish(
                    root,
                    parent,
                    name,
                    destination,
                    previous_bytes.expect("replace plans retain existing bytes"),
                )?);
            }
            MaterializationAction::Create => {}
            MaterializationAction::NoOp => unreachable!("no-op plans are not published"),
        }
        parent
            .hard_link(&temporary, parent, name)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    || parent.symlink_metadata(name).is_ok()
                {
                    MaterializationError::StateChanged(destination.clone())
                } else {
                    MaterializationError::Io(operation)
                }
            })?;
        mutated = true;
        parent
            .remove_file(&temporary)
            .map_err(|_| MaterializationError::Io(operation))?;
        sync_published_file(parent, name, operation, destination)?;
        sync_directory(parent, operation)?;
        if let Some(writer_bytes) = injection.after_publish_writer {
            inject_noncooperating_writer(parent, name, destination, writer_bytes)?;
        }
        if injection.verification_failure {
            return Err(MaterializationError::VerificationFailed(
                destination.clone(),
            ));
        }
        let published = read_regular_file(parent, name, destination)?
            .ok_or_else(|| MaterializationError::VerificationFailed(destination.clone()))?;
        if published.metadata.digest != digest(bytes) || published.bytes != bytes {
            return Err(MaterializationError::VerificationFailed(
                destination.clone(),
            ));
        }
        if let Some(held) = quarantine.as_ref() {
            finish_publication_quarantine(root, parent, destination, previous_bytes, held)?;
        }
        quarantine = None;
        Ok(())
    })();
    if let Err(mut error) = result {
        let _ = parent.remove_file(&temporary);
        if !mutated
            && let Some(held) = quarantine.as_ref()
            && let Err(restoration) =
                restore_publication_quarantine(root, parent, name, destination, held)
        {
            error = restoration;
        }
        return Err(Box::new(PublishFailure {
            error,
            mutated,
            quarantine,
        }));
    }
    Ok(())
}

fn inject_noncooperating_writer(
    parent: &Dir,
    name: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), MaterializationError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(MaterializationError::UnsafePath(destination.to_path_buf()))
        }
        Ok(_) => replace_with_test_writer(parent, name, bytes, destination),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => publish_new_file(
            parent,
            name,
            bytes,
            MaterializationIoOperation::WriteDestination,
            destination,
        ),
        Err(_) => Err(MaterializationError::Io(
            MaterializationIoOperation::WriteDestination,
        )),
    }
}

fn quarantine_replacement_for_publish(
    root: &Dir,
    parent: &Dir,
    destination_name: &Path,
    destination: &Path,
    expected: &[u8],
) -> Result<PublicationQuarantine, MaterializationError> {
    let (directory, directory_name) = create_quarantine_directory(parent)?;
    let held_name = PathBuf::from("previous-destination");
    if let Err(error) = parent.rename(destination_name, &directory, &held_name) {
        drop(directory);
        let _ = parent.remove_dir(&directory_name);
        let _ = sync_directory(parent, MaterializationIoOperation::WriteDestination);
        return Err(if error.kind() == std::io::ErrorKind::NotFound {
            MaterializationError::StateChanged(destination.to_path_buf())
        } else {
            MaterializationError::Io(MaterializationIoOperation::WriteDestination)
        });
    }
    let recovery_path = destination
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&directory_name)
        .join(&held_name);
    let held = PublicationQuarantine {
        directory,
        directory_name,
        held_name,
        recovery_path,
    };
    let verification = (|| {
        sync_directory(parent, MaterializationIoOperation::WriteDestination)?;
        sync_directory(
            &held.directory,
            MaterializationIoOperation::WriteDestination,
        )?;
        let inspected =
            read_regular_file(&held.directory, &held.held_name, &held.recovery_path)?
                .ok_or_else(|| MaterializationError::StateChanged(destination.to_path_buf()))?;
        if inspected.bytes == expected {
            Ok(())
        } else {
            Err(MaterializationError::StateChanged(
                destination.to_path_buf(),
            ))
        }
    })();
    if verification.is_ok() {
        return Ok(held);
    }
    let error = verification.expect_err("replacement quarantine verification failed");
    match restore_publication_quarantine(root, parent, destination_name, destination, &held) {
        Ok(()) => Err(error),
        Err(conflict) => Err(conflict),
    }
}

fn publication_quarantine_context<'a>(
    root: &'a Dir,
    parent: &'a Dir,
    destination: &'a Path,
    held: &'a PublicationQuarantine,
) -> QuarantineContext<'a> {
    QuarantineContext {
        root,
        parent,
        directory: &held.directory,
        held_name: &held.held_name,
        absolute: destination,
        recovery_path: &held.recovery_path,
    }
}

fn restore_publication_quarantine(
    root: &Dir,
    parent: &Dir,
    destination_name: &Path,
    destination: &Path,
    held: &PublicationQuarantine,
) -> Result<(), MaterializationError> {
    restore_quarantined_destination(
        &publication_quarantine_context(root, parent, destination, held),
        destination_name,
        &held.directory_name,
        None,
    )
}

fn finish_publication_quarantine(
    root: &Dir,
    parent: &Dir,
    destination: &Path,
    expected: Option<&[u8]>,
    held: &PublicationQuarantine,
) -> Result<(), MaterializationError> {
    let context = publication_quarantine_context(root, parent, destination, held);
    let expected = expected.expect("replacement publication retains prior bytes");
    match verify_quarantined_destination(
        &context,
        expected,
        QuarantineInjection {
            recreated_bytes: None,
            failure: None,
        },
    )? {
        QuarantineVerification::Exact => {
            remove_exact_quarantined_destination(&context, &held.directory_name, None)
        }
        QuarantineVerification::Modified => Err(cleanup_conflict(&context)),
    }
}

fn publish_new_file(
    directory: &Dir,
    name: &Path,
    bytes: &[u8],
    operation: MaterializationIoOperation,
    absolute: &Path,
) -> Result<(), MaterializationError> {
    let (mut file, temporary) = create_temporary_file(directory, operation)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| MaterializationError::Io(operation))?;
        drop(file);
        if directory.symlink_metadata(name).is_ok() {
            return Err(MaterializationError::StateChanged(absolute.to_path_buf()));
        }
        directory
            .hard_link(&temporary, directory, name)
            .map_err(|_| MaterializationError::Io(operation))?;
        sync_published_file(directory, name, operation, absolute)?;
        directory
            .remove_file(&temporary)
            .map_err(|_| MaterializationError::Io(operation))?;
        sync_directory(directory, operation)
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

fn rollback_after_error(
    error: MaterializationError,
    mutations: &[AppliedMutation],
    created_directories: &[CreatedDirectory],
) -> Result<MaterializationBatchOutcome, MaterializationError> {
    let mut failed_paths = Vec::new();
    for mutation in mutations.iter().rev() {
        if let Err(error) = rollback_mutation(mutation) {
            match error {
                MaterializationError::CleanupConflict {
                    destination,
                    quarantine,
                } => failed_paths.extend([destination, quarantine]),
                _ => failed_paths.push(mutation.destination.clone()),
            }
        }
    }
    for directory in created_directories.iter().rev() {
        if rollback_created_directory(directory).is_err() {
            failed_paths.push(directory.absolute.clone());
        }
    }
    if failed_paths.is_empty() {
        Err(error)
    } else {
        Err(MaterializationError::RollbackFailed {
            paths: failed_paths,
        })
    }
}

fn rollback_mutation(mutation: &AppliedMutation) -> Result<(), MaterializationError> {
    let (_, root) = open_root(mutation.agent, &mutation.root)?;
    let parent_relative = mutation
        .relative_destination
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let parent = open_existing_parent(&root, parent_relative, &mutation.destination)?.ok_or(
        MaterializationError::Io(MaterializationIoOperation::RestoreDestination),
    )?;
    let target_name = mutation
        .relative_destination
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(mutation.destination.clone()))?;
    validate_rollback_backup(&parent, mutation)?;
    let held = quarantine_destination_for_rollback(
        &root,
        &parent,
        Path::new(target_name),
        &mutation.destination,
    )?;
    let rollback = match held.as_ref() {
        None => restore_previous_no_replace(&parent, Path::new(target_name), mutation),
        Some(held) => {
            rollback_quarantined_destination(&root, &parent, Path::new(target_name), mutation, held)
        }
    };
    rollback?;
    cleanup_retained_publication_quarantine(&root, &parent, mutation)
}

fn validate_rollback_backup(
    parent: &Dir,
    mutation: &AppliedMutation,
) -> Result<(), MaterializationError> {
    let Some(previous_bytes) = mutation.previous_bytes.as_ref() else {
        return Ok(());
    };
    let backup_relative = mutation
        .backup_relative
        .as_ref()
        .ok_or(MaterializationError::Io(
            MaterializationIoOperation::RestoreDestination,
        ))?;
    let backup_name = backup_relative
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(mutation.destination.clone()))?;
    let backup = read_regular_file(
        parent,
        Path::new(backup_name),
        &mutation.root.join(backup_relative),
    )?
    .ok_or(MaterializationError::Io(
        MaterializationIoOperation::RestoreDestination,
    ))?;
    if backup.bytes == *previous_bytes {
        Ok(())
    } else {
        Err(MaterializationError::Io(
            MaterializationIoOperation::RestoreDestination,
        ))
    }
}

fn quarantine_destination_for_rollback(
    root: &Dir,
    parent: &Dir,
    destination_name: &Path,
    destination: &Path,
) -> Result<Option<PublicationQuarantine>, MaterializationError> {
    let (directory, directory_name) = create_quarantine_directory(parent)?;
    let held_name = PathBuf::from("published-destination");
    match parent.rename(destination_name, &directory, &held_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            drop(directory);
            parent.remove_dir(&directory_name).map_err(|_| {
                MaterializationError::Io(MaterializationIoOperation::RestoreDestination)
            })?;
            sync_directory(parent, MaterializationIoOperation::RestoreDestination)?;
            sync_directory(root, MaterializationIoOperation::RestoreDestination)?;
            return Ok(None);
        }
        Err(_) => {
            drop(directory);
            let _ = parent.remove_dir(&directory_name);
            let _ = sync_directory(parent, MaterializationIoOperation::RestoreDestination);
            return Err(MaterializationError::Io(
                MaterializationIoOperation::RestoreDestination,
            ));
        }
    }
    let held = PublicationQuarantine {
        recovery_path: destination
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(&directory_name)
            .join(&held_name),
        directory,
        directory_name,
        held_name,
    };
    let sync_result = sync_directory(parent, MaterializationIoOperation::RestoreDestination)
        .and_then(|()| {
            sync_directory(
                &held.directory,
                MaterializationIoOperation::RestoreDestination,
            )
        });
    if let Err(error) = sync_result {
        return match restore_publication_quarantine(
            root,
            parent,
            destination_name,
            destination,
            &held,
        ) {
            Ok(()) => Err(error),
            Err(conflict) => Err(conflict),
        };
    }
    Ok(Some(held))
}

fn rollback_quarantined_destination(
    root: &Dir,
    parent: &Dir,
    destination_name: &Path,
    mutation: &AppliedMutation,
    held: &PublicationQuarantine,
) -> Result<(), MaterializationError> {
    let context = publication_quarantine_context(root, parent, &mutation.destination, held);
    let inspected = read_regular_file(&held.directory, &held.held_name, &held.recovery_path);
    let Ok(Some(inspected)) = inspected else {
        return Err(cleanup_conflict(&context));
    };
    if inspected.bytes != mutation.published_bytes {
        return match restore_publication_quarantine(
            root,
            parent,
            destination_name,
            &mutation.destination,
            held,
        ) {
            Ok(()) => {
                if let Some(recovery) = mutation
                    .publication_quarantine
                    .as_ref()
                    .map(|quarantine| quarantine.recovery_path.clone())
                    .or_else(|| {
                        mutation
                            .backup_relative
                            .as_ref()
                            .map(|relative| mutation.root.join(relative))
                    })
                {
                    Err(MaterializationError::CleanupConflict {
                        destination: mutation.destination.clone(),
                        quarantine: recovery,
                    })
                } else {
                    Err(MaterializationError::StateChanged(
                        mutation.destination.clone(),
                    ))
                }
            }
            Err(conflict) => Err(conflict),
        };
    }
    restore_previous_no_replace(parent, destination_name, mutation)?;
    remove_exact_quarantined_destination(&context, &held.directory_name, None)
}

fn restore_previous_no_replace(
    parent: &Dir,
    destination_name: &Path,
    mutation: &AppliedMutation,
) -> Result<(), MaterializationError> {
    let Some(previous_bytes) = mutation.previous_bytes.as_ref() else {
        return Ok(());
    };
    let backup = mutation.backup_relative.as_ref().map_or_else(
        || mutation.destination.clone(),
        |relative| mutation.root.join(relative),
    );
    match publish_new_file(
        parent,
        destination_name,
        previous_bytes,
        MaterializationIoOperation::RestoreDestination,
        &mutation.destination,
    ) {
        Ok(()) => Ok(()),
        Err(MaterializationError::StateChanged(_)) => Err(MaterializationError::CleanupConflict {
            destination: mutation.destination.clone(),
            quarantine: backup,
        }),
        Err(error) => Err(error),
    }
}

fn cleanup_retained_publication_quarantine(
    root: &Dir,
    parent: &Dir,
    mutation: &AppliedMutation,
) -> Result<(), MaterializationError> {
    let Some(held) = mutation.publication_quarantine.as_ref() else {
        return Ok(());
    };
    let context = publication_quarantine_context(root, parent, &mutation.destination, held);
    match read_regular_file(&held.directory, &held.held_name, &held.recovery_path) {
        Ok(Some(file))
            if mutation
                .previous_bytes
                .as_ref()
                .is_some_and(|previous| file.bytes == *previous) =>
        {
            remove_exact_quarantined_destination(&context, &held.directory_name, None)
        }
        Ok(None) => {
            match parent.remove_dir(&held.directory_name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(MaterializationError::Io(
                        MaterializationIoOperation::RestoreDestination,
                    ));
                }
            }
            sync_directory(parent, MaterializationIoOperation::RestoreDestination)?;
            sync_directory(root, MaterializationIoOperation::RestoreDestination)
        }
        Ok(Some(_)) | Err(_) => Err(cleanup_conflict(&context)),
    }
}

fn replace_with_test_writer(
    directory: &Dir,
    name: &Path,
    bytes: &[u8],
    absolute: &Path,
) -> Result<(), MaterializationError> {
    let operation = MaterializationIoOperation::WriteDestination;
    let (mut file, temporary) = create_temporary_file(directory, operation)?;
    let result = (|| {
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| MaterializationError::Io(operation))?;
        drop(file);
        directory
            .rename(&temporary, directory, name)
            .map_err(|_| MaterializationError::Io(operation))?;
        sync_published_file(directory, name, operation, absolute)?;
        sync_directory(directory, operation)
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

fn rollback_created_directory(directory: &CreatedDirectory) -> Result<(), MaterializationError> {
    let (_, root) = open_root(directory.agent, &directory.root)?;
    let parent_relative = directory.relative.parent().unwrap_or_else(|| Path::new(""));
    let Some(parent) = open_existing_parent(&root, parent_relative, &directory.absolute)? else {
        return Ok(());
    };
    let name = directory
        .relative
        .file_name()
        .ok_or_else(|| MaterializationError::UnsafePath(directory.absolute.clone()))?;
    let child = match parent.open_dir_nofollow(Path::new(name)) {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(MaterializationError::UnsafePath(directory.absolute.clone())),
    };
    if child
        .entries()
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::RestoreDestination))?
        .next()
        .is_some()
    {
        return Ok(());
    }
    drop(child);
    parent
        .remove_dir(Path::new(name))
        .map_err(|_| MaterializationError::Io(MaterializationIoOperation::RestoreDestination))?;
    sync_directory(&parent, MaterializationIoOperation::RestoreDestination)
}

fn create_temporary_file(
    directory: &Dir,
    operation: MaterializationIoOperation,
) -> Result<(File, PathBuf), MaterializationError> {
    for _ in 0..MAX_TEMPORARY_FILE_ATTEMPTS {
        let sequence = NEXT_TEMPORARY_FILE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            ".pam-materialize-tmp-{}-{sequence}",
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
            Err(_) => return Err(MaterializationError::Io(operation)),
        }
    }
    Err(MaterializationError::Io(operation))
}

fn sync_published_file(
    directory: &Dir,
    name: &Path,
    operation: MaterializationIoOperation,
    absolute: &Path,
) -> Result<(), MaterializationError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|_| MaterializationError::Io(operation))?;
    if !file
        .metadata()
        .map_err(|_| MaterializationError::Io(operation))?
        .is_file()
    {
        return Err(MaterializationError::UnsafePath(absolute.to_path_buf()));
    }
    file.sync_all()
        .map_err(|_| MaterializationError::Io(operation))
}

fn sync_directory(
    directory: &Dir,
    operation: MaterializationIoOperation,
) -> Result<(), MaterializationError> {
    #[cfg(unix)]
    directory
        .open(".")
        .and_then(|file| file.sync_all())
        .map_err(|_| MaterializationError::Io(operation))?;
    #[cfg(not(unix))]
    let _ = (directory, operation);
    Ok(())
}

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
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
