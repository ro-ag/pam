use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

use directories::ProjectDirs;
use pam_core::{CallerId, ProjectId};
use serde::Deserialize;
use uuid::Uuid;

const IDENTITY_FILE_VERSION: u32 = 1;
pub(crate) const MAX_IDENTITY_FILE_BYTES: u64 = 4 * 1024;
const GIT_REPOSITORY_ENVIRONMENT: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_NAMESPACE",
];

/// The local PAM surface using an identity for request scoping.
///
/// These labels distinguish local callers; they are not authentication
/// credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerKind {
    Cli,
    Gui,
    CodingAgent,
    LocalApplication,
}

/// Stable project-scoping identity paired with its canonical discovery root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: ProjectId,
    root: PathBuf,
}

impl ProjectIdentity {
    #[must_use]
    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl CallerKind {
    const fn file_stem(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Gui => "gui",
            Self::CodingAgent => "coding-agent",
            Self::LocalApplication => "local-application",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityErrorKind {
    UserDataUnavailable,
    NotProject,
    ReadFailed,
    WriteFailed,
    MalformedFile,
    UnsupportedVersion,
}

#[derive(Debug)]
pub struct IdentityError {
    kind: IdentityErrorKind,
    path: Option<PathBuf>,
    diagnostic: String,
}

impl IdentityError {
    fn new(kind: IdentityErrorKind, path: Option<PathBuf>, diagnostic: impl Into<String>) -> Self {
        Self {
            kind,
            path,
            diagnostic: diagnostic.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> IdentityErrorKind {
        self.kind
    }

    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            IdentityErrorKind::UserDataUnavailable => {
                formatter.write_str("PAM could not locate the current user's data directory.")
            }
            IdentityErrorKind::NotProject => write!(
                formatter,
                "PAM could not find a project marker or Git repository from {}.",
                display_path(self.path.as_deref())
            ),
            IdentityErrorKind::ReadFailed => write!(
                formatter,
                "PAM could not read identity state at {}.",
                display_path(self.path.as_deref())
            ),
            IdentityErrorKind::WriteFailed => write!(
                formatter,
                "PAM could not persist identity state at {}.",
                display_path(self.path.as_deref())
            ),
            IdentityErrorKind::MalformedFile => write!(
                formatter,
                "PAM found malformed identity state at {}; it was left unchanged.",
                display_path(self.path.as_deref())
            ),
            IdentityErrorKind::UnsupportedVersion => write!(
                formatter,
                "PAM found an unsupported identity-state version at {}; it was left unchanged.",
                display_path(self.path.as_deref())
            ),
        }
    }
}

impl Error for IdentityError {}

#[derive(Deserialize)]
struct VersionHeader {
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerFile {
    version: u32,
    caller_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectMarker {
    version: u32,
    project_id: String,
}

#[derive(Clone, Copy)]
pub(crate) enum PublicationMode {
    PreferHardLink,
    #[cfg(test)]
    ForceRename,
    #[cfg(test)]
    InterruptBeforePublication,
}

struct TemporaryFile(PathBuf);

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if fs::remove_file(&self.0).is_ok()
            && let Some(parent) = self.0.parent()
        {
            drop(sync_directory(parent));
        }
    }
}

/// Loads or creates the durable opaque ID for a local caller kind.
///
/// Caller IDs are request-scoping labels, not proof of identity.
///
/// # Errors
///
/// Returns an error when the OS data directory is unavailable or existing
/// identity state cannot be read, validated, or durably created.
pub fn caller_id(kind: CallerKind) -> Result<CallerId, IdentityError> {
    caller_id_in(&user_data_dir()?, kind)
}

/// Returns PAM's platform-appropriate durable per-user data directory.
///
/// # Errors
///
/// Returns an error when the operating system does not expose a user data
/// directory for the current process.
pub fn user_data_dir() -> Result<PathBuf, IdentityError> {
    ProjectDirs::from("dev", "PAM", "PAM")
        .map(|project_dirs| project_dirs.data_dir().to_path_buf())
        .ok_or_else(|| {
            IdentityError::new(
                IdentityErrorKind::UserDataUnavailable,
                None,
                "the operating system did not provide a user data directory",
            )
        })
}

pub(crate) fn caller_id_in(data_dir: &Path, kind: CallerKind) -> Result<CallerId, IdentityError> {
    caller_id_in_with_publication(data_dir, kind, PublicationMode::PreferHardLink)
}

pub(crate) fn caller_id_in_with_publication(
    data_dir: &Path,
    kind: CallerKind,
    publication_mode: PublicationMode,
) -> Result<CallerId, IdentityError> {
    let path = data_dir
        .join("callers")
        .join(format!("{}.toml", kind.file_stem()));
    if path_exists(&path)? {
        return read_managed_caller_file(&path);
    }

    let id = Uuid::new_v4().to_string();
    let contents = format!("version = {IDENTITY_FILE_VERSION}\ncaller_id = \"{id}\"\n");
    if persist_new_file_with_mode(&path, &contents, publication_mode, |path| {
        read_caller_file_unlocked(path).map(drop)
    })? {
        Ok(CallerId::new(id))
    } else {
        read_managed_caller_file(&path)
    }
}

/// Resolves a stable project-scoping ID from the nearest explicit marker or
/// from identity state stored in the repository's shared Git directory.
///
/// # Errors
///
/// Returns an error when the start path cannot be inspected, a marker is
/// invalid, no Git repository is available, or fallback state cannot be read
/// or durably created.
pub fn discover_project_id(start: impl AsRef<Path>) -> Result<ProjectId, IdentityError> {
    discover_project_id_with_environment(start.as_ref(), None)
}

/// Resolves a stable project-scoping ID and the canonical root that defined it.
///
/// # Errors
///
/// Returns an error when the start path cannot be inspected, a marker is
/// invalid, no Git repository is available, or fallback state cannot be read
/// or durably created.
pub fn discover_project(start: impl AsRef<Path>) -> Result<ProjectIdentity, IdentityError> {
    discover_project_with_environment(start.as_ref(), None)
}

#[cfg(test)]
pub(crate) fn discover_project_id_with_git_environment(
    start: &Path,
    git_dir: &OsStr,
    git_work_tree: &OsStr,
) -> Result<ProjectId, IdentityError> {
    discover_project_id_with_environment(start, Some((git_dir, git_work_tree)))
}

fn discover_project_id_with_environment(
    start: &Path,
    git_environment: Option<(&OsStr, &OsStr)>,
) -> Result<ProjectId, IdentityError> {
    let start = normalized_start(start)?;
    if let Some(marker_path) = nearest_project_marker(&start)? {
        return read_project_marker(&marker_path);
    }

    let common_dir = git_common_dir(&start, git_environment)?;
    git_fallback_project_id(&common_dir)
}

fn discover_project_with_environment(
    start: &Path,
    git_environment: Option<(&OsStr, &OsStr)>,
) -> Result<ProjectIdentity, IdentityError> {
    let start = normalized_start(start)?;
    if let Some(marker_path) = nearest_project_marker(&start)? {
        let root = marker_path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                IdentityError::new(
                    IdentityErrorKind::ReadFailed,
                    Some(marker_path.clone()),
                    "project marker has no project-root parent",
                )
            })?
            .to_path_buf();
        return Ok(ProjectIdentity {
            id: read_project_marker(&marker_path)?,
            root,
        });
    }

    let root = git_worktree_root(&start, git_environment)?;
    let common_dir = git_common_dir(&start, git_environment)?;
    let id = git_fallback_project_id(&common_dir)?;
    Ok(ProjectIdentity { id, root })
}

fn git_fallback_project_id(common_dir: &Path) -> Result<ProjectId, IdentityError> {
    let fallback_path = common_dir.join("pam").join("project.toml");
    if path_exists(&fallback_path)? {
        return read_managed_project_file(&fallback_path);
    }

    let id = Uuid::new_v4().to_string();
    let contents = format!("version = {IDENTITY_FILE_VERSION}\nproject_id = \"{id}\"\n");
    if persist_new_file_with_mode(
        &fallback_path,
        &contents,
        PublicationMode::PreferHardLink,
        |path| read_project_file_unlocked(path).map(drop),
    )? {
        Ok(ProjectId::new(id))
    } else {
        read_managed_project_file(&fallback_path)
    }
}

fn normalized_start(start: &Path) -> Result<PathBuf, IdentityError> {
    let canonical = fs::canonicalize(start).map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(start.to_path_buf()),
            error.to_string(),
        )
    })?;
    if canonical.is_dir() {
        Ok(canonical)
    } else {
        canonical.parent().map(Path::to_path_buf).ok_or_else(|| {
            IdentityError::new(
                IdentityErrorKind::ReadFailed,
                Some(canonical.clone()),
                "the start path has no parent directory",
            )
        })
    }
}

fn nearest_project_marker(start: &Path) -> Result<Option<PathBuf>, IdentityError> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join(".pam").join("project.toml");
        if path_exists(&candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn git_common_dir(
    start: &Path,
    git_environment: Option<(&OsStr, &OsStr)>,
) -> Result<PathBuf, IdentityError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(start)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"]);
    if let Some((git_dir, git_work_tree)) = git_environment {
        command
            .env("GIT_DIR", git_dir)
            .env("GIT_WORK_TREE", git_work_tree);
    }
    for variable in GIT_REPOSITORY_ENVIRONMENT {
        command.env_remove(variable);
    }

    let output = command.output().map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::NotProject,
            Some(start.to_path_buf()),
            error.to_string(),
        )
    })?;

    if !output.status.success() {
        return Err(IdentityError::new(
            IdentityErrorKind::NotProject,
            Some(start.to_path_buf()),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }

    let mut stdout = output.stdout;
    strip_git_record_line_ending(&mut stdout);
    if stdout.is_empty() {
        return Err(IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(start.to_path_buf()),
            "Git did not report a common directory",
        ));
    }
    #[cfg(unix)]
    let common_dir = path_from_git_stdout(stdout);
    #[cfg(not(unix))]
    let common_dir = path_from_git_stdout(stdout).map_err(|diagnostic| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(start.to_path_buf()),
            diagnostic,
        )
    })?;

    fs::canonicalize(&common_dir).map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(common_dir),
            error.to_string(),
        )
    })
}

fn git_worktree_root(
    start: &Path,
    git_environment: Option<(&OsStr, &OsStr)>,
) -> Result<PathBuf, IdentityError> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(start)
        .args(["rev-parse", "--path-format=absolute", "--show-toplevel"]);
    if let Some((git_dir, git_work_tree)) = git_environment {
        command
            .env("GIT_DIR", git_dir)
            .env("GIT_WORK_TREE", git_work_tree);
    }
    for variable in GIT_REPOSITORY_ENVIRONMENT {
        command.env_remove(variable);
    }

    let output = command.output().map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::NotProject,
            Some(start.to_path_buf()),
            error.to_string(),
        )
    })?;
    if !output.status.success() {
        return Err(IdentityError::new(
            IdentityErrorKind::NotProject,
            Some(start.to_path_buf()),
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }

    let mut stdout = output.stdout;
    strip_git_record_line_ending(&mut stdout);
    if stdout.is_empty() {
        return Err(IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(start.to_path_buf()),
            "Git did not report a worktree root",
        ));
    }
    #[cfg(unix)]
    let root = path_from_git_stdout(stdout);
    #[cfg(not(unix))]
    let root = path_from_git_stdout(stdout).map_err(|diagnostic| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(start.to_path_buf()),
            diagnostic,
        )
    })?;

    fs::canonicalize(&root).map_err(|error| {
        IdentityError::new(IdentityErrorKind::ReadFailed, Some(root), error.to_string())
    })
}

#[cfg(unix)]
pub(crate) fn strip_git_record_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(windows)]
pub(crate) fn strip_git_record_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn strip_git_record_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
}

#[cfg(unix)]
fn path_from_git_stdout(bytes: Vec<u8>) -> PathBuf {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    PathBuf::from(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn path_from_git_stdout(bytes: Vec<u8>) -> Result<PathBuf, String> {
    String::from_utf8(bytes)
        .map(PathBuf::from)
        .map_err(|error| error.to_string())
}

fn read_managed_caller_file(path: &Path) -> Result<CallerId, IdentityError> {
    with_shared_identity_lock(path, read_caller_file_unlocked)
}

fn read_caller_file_unlocked(path: &Path) -> Result<CallerId, IdentityError> {
    let contents = read_identity_file(path)?;
    validate_version_header(&contents, path)?;
    let identity: CallerFile = toml::from_str(&contents).map_err(|error| malformed(path, error))?;
    debug_assert_eq!(identity.version, IDENTITY_FILE_VERSION);
    validate_uuid(&identity.caller_id, "caller_id", path)?;
    Ok(CallerId::new(identity.caller_id))
}

fn read_project_marker(path: &Path) -> Result<ProjectId, IdentityError> {
    read_project_file_unlocked(path)
}

fn read_managed_project_file(path: &Path) -> Result<ProjectId, IdentityError> {
    with_shared_identity_lock(path, read_project_file_unlocked)
}

fn read_project_file_unlocked(path: &Path) -> Result<ProjectId, IdentityError> {
    let contents = read_identity_file(path)?;
    validate_version_header(&contents, path)?;
    let identity: ProjectMarker =
        toml::from_str(&contents).map_err(|error| malformed(path, error))?;
    debug_assert_eq!(identity.version, IDENTITY_FILE_VERSION);
    validate_uuid(&identity.project_id, "project_id", path)?;
    Ok(ProjectId::new(identity.project_id))
}

fn with_shared_identity_lock<T>(
    path: &Path,
    read: impl FnOnce(&Path) -> Result<T, IdentityError>,
) -> Result<T, IdentityError> {
    let lock = open_persistent_lock(path)?;
    lock.lock_shared()
        .map_err(|error| read_error(path, error))?;
    let result = read(path);
    drop(lock);
    result
}

fn read_identity_file(path: &Path) -> Result<String, IdentityError> {
    let metadata = identity_file_metadata(path)?.ok_or_else(|| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(path.to_path_buf()),
            "identity state disappeared before it could be read",
        )
    })?;
    validate_file_size(&metadata, path)?;

    let file = open_identity_file(path).map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(path.to_path_buf()),
            error.to_string(),
        )
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(path.to_path_buf()),
            error.to_string(),
        )
    })?;
    validate_regular_file(&opened_metadata, path)?;
    validate_file_size(&opened_metadata, path)?;

    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len().min(MAX_IDENTITY_FILE_BYTES)).unwrap_or(0),
    );
    file.take(MAX_IDENTITY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            IdentityError::new(
                IdentityErrorKind::ReadFailed,
                Some(path.to_path_buf()),
                error.to_string(),
            )
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_IDENTITY_FILE_BYTES {
        return Err(oversized(path));
    }
    String::from_utf8(bytes).map_err(|error| malformed(path, error))
}

fn validate_version_header(contents: &str, path: &Path) -> Result<(), IdentityError> {
    let header: VersionHeader = toml::from_str(contents).map_err(|error| malformed(path, error))?;
    if header.version == IDENTITY_FILE_VERSION {
        Ok(())
    } else {
        Err(IdentityError::new(
            IdentityErrorKind::UnsupportedVersion,
            Some(path.to_path_buf()),
            format!(
                "expected version {IDENTITY_FILE_VERSION}, found {}",
                header.version
            ),
        ))
    }
}

fn validate_uuid(value: &str, field: &str, path: &Path) -> Result<(), IdentityError> {
    let parsed = Uuid::parse_str(value).map_err(|error| {
        IdentityError::new(
            IdentityErrorKind::MalformedFile,
            Some(path.to_path_buf()),
            format!("{field} is not a UUID: {error}"),
        )
    })?;
    if parsed.to_string() == value {
        Ok(())
    } else {
        Err(IdentityError::new(
            IdentityErrorKind::MalformedFile,
            Some(path.to_path_buf()),
            format!("{field} is not a canonical UUID"),
        ))
    }
}

fn path_exists(path: &Path) -> Result<bool, IdentityError> {
    identity_file_metadata(path).map(|metadata| metadata.is_some())
}

fn identity_file_metadata(path: &Path) -> Result<Option<Metadata>, IdentityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular_file(&metadata, path)?;
            validate_file_size(&metadata, path)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(IdentityError::new(
            IdentityErrorKind::ReadFailed,
            Some(path.to_path_buf()),
            error.to_string(),
        )),
    }
}

fn validate_regular_file(metadata: &Metadata, path: &Path) -> Result<(), IdentityError> {
    if metadata.file_type().is_file() {
        Ok(())
    } else {
        Err(IdentityError::new(
            IdentityErrorKind::MalformedFile,
            Some(path.to_path_buf()),
            "identity state must be a regular file, not a symlink, directory, or device",
        ))
    }
}

fn validate_file_size(metadata: &Metadata, path: &Path) -> Result<(), IdentityError> {
    if metadata.len() <= MAX_IDENTITY_FILE_BYTES {
        Ok(())
    } else {
        Err(oversized(path))
    }
}

fn oversized(path: &Path) -> IdentityError {
    IdentityError::new(
        IdentityErrorKind::MalformedFile,
        Some(path.to_path_buf()),
        format!("identity state exceeds the {MAX_IDENTITY_FILE_BYTES}-byte limit"),
    )
}

fn persist_new_file_with_mode<F>(
    path: &Path,
    contents: &str,
    publication_mode: PublicationMode,
    validate_existing: F,
) -> Result<bool, IdentityError>
where
    F: Fn(&Path) -> Result<(), IdentityError>,
{
    let parent = path.parent().ok_or_else(|| {
        IdentityError::new(
            IdentityErrorKind::WriteFailed,
            Some(path.to_path_buf()),
            "identity path has no parent directory",
        )
    })?;
    ensure_directory_tree(parent).map_err(|error| write_error(path, error))?;

    let temporary_path = parent.join(format!(".identity-{}.tmp", Uuid::new_v4()));
    let mut temporary_options = OpenOptions::new();
    temporary_options.create_new(true).write(true);
    harden_open_options(&mut temporary_options);
    let mut temporary = temporary_options
        .open(&temporary_path)
        .map_err(|error| write_error(path, error))?;
    let temporary_guard = TemporaryFile(temporary_path.clone());
    if let Err(error) = temporary
        .write_all(contents.as_bytes())
        .and_then(|()| temporary.sync_all())
    {
        return Err(write_error(path, error));
    }
    drop(temporary);

    #[cfg(test)]
    if matches!(
        publication_mode,
        PublicationMode::InterruptBeforePublication
    ) {
        return Err(IdentityError::new(
            IdentityErrorKind::WriteFailed,
            Some(path.to_path_buf()),
            "injected interruption before publication",
        ));
    }

    let lock = open_persistent_lock(path)?;
    lock.lock().map_err(|error| write_error(path, error))?;
    let published = publish_locked(&temporary_path, path, publication_mode, &validate_existing);
    drop(lock);
    let published = published?;
    drop(temporary_guard);
    sync_directory(parent).map_err(|error| write_error(path, error))?;
    Ok(published)
}

fn publish_locked<F>(
    temporary_path: &Path,
    path: &Path,
    publication_mode: PublicationMode,
    validate_existing: &F,
) -> Result<bool, IdentityError>
where
    F: Fn(&Path) -> Result<(), IdentityError>,
{
    // The persistent OS lock coordinates every PAM writer. Identity values are
    // scoping labels, not an authentication boundary; defending against
    // hostile out-of-band mutation belongs to the later trust/policy layer.
    // Under normal PAM operation an existing target is validated and never
    // overwritten, including when it is malformed.
    if path_exists(path)? {
        validate_existing(path)?;
        return Ok(false);
    }

    let use_rename = match publication_mode {
        PublicationMode::PreferHardLink => match fs::hard_link(temporary_path, path) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                validate_existing(path)?;
                return Ok(false);
            }
            Err(error) if hard_link_unavailable(&error) => true,
            Err(error) => return Err(write_error(path, error)),
        },
        #[cfg(test)]
        PublicationMode::ForceRename => true,
        #[cfg(test)]
        PublicationMode::InterruptBeforePublication => unreachable!("handled before locking"),
    };
    if use_rename {
        fs::rename(temporary_path, path).map_err(|error| write_error(path, error))?;
    }
    if let Some(parent) = path.parent() {
        sync_directory(parent).map_err(|error| write_error(path, error))?;
    }
    Ok(true)
}

fn open_persistent_lock(path: &Path) -> Result<File, IdentityError> {
    let lock_path = identity_lock_path(path);
    let mut create_options = OpenOptions::new();
    create_options.create_new(true).read(true).write(true);
    harden_open_options(&mut create_options);
    match create_options.open(&lock_path) {
        Ok(lock) => {
            lock.sync_all().map_err(|error| write_error(path, error))?;
            if let Some(parent) = lock_path.parent() {
                sync_directory(parent).map_err(|error| write_error(path, error))?;
            }
            Ok(lock)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            open_existing_lock(path, &lock_path)
        }
        Err(error) => Err(write_error(path, error)),
    }
}

fn open_existing_lock(identity_path: &Path, lock_path: &Path) -> Result<File, IdentityError> {
    let metadata =
        fs::symlink_metadata(lock_path).map_err(|error| write_error(identity_path, error))?;
    validate_regular_file(&metadata, lock_path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    harden_open_options(&mut options);
    let lock = options
        .open(lock_path)
        .map_err(|error| write_error(identity_path, error))?;
    let opened_metadata = lock
        .metadata()
        .map_err(|error| write_error(identity_path, error))?;
    validate_regular_file(&opened_metadata, lock_path)?;
    Ok(lock)
}

pub(crate) fn identity_lock_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("identity.toml"))
        .to_string_lossy();
    path.with_file_name(format!(".{file_name}.lock"))
}

fn ensure_directory_tree(path: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) if metadata.file_type().is_dir() => break,
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} is not a directory", cursor.display()),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "directory tree has no existing ancestor",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }

    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&directory)?;
                if !metadata.file_type().is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{} is not a directory", directory.display()),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        sync_directory(&directory)?;
        if let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

fn hard_link_unavailable(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::CrossesDevices
    ) {
        return true;
    }
    hard_link_unavailable_os_error(error.raw_os_error())
}

#[cfg(unix)]
fn hard_link_unavailable_os_error(error: Option<i32>) -> bool {
    matches!(
        error,
        Some(libc::EXDEV | libc::EOPNOTSUPP | libc::EPERM | libc::EMLINK)
    )
}

#[cfg(windows)]
fn hard_link_unavailable_os_error(error: Option<i32>) -> bool {
    matches!(error, Some(1 | 17 | 50))
}

#[cfg(not(any(unix, windows)))]
fn hard_link_unavailable_os_error(_error: Option<i32>) -> bool {
    false
}

fn harden_open_options(options: &mut OpenOptions) {
    harden_open_options_for_platform(options);
}

#[cfg(unix)]
fn harden_open_options_for_platform(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
}

#[cfg(windows)]
fn harden_open_options_for_platform(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    // This prevents following ordinary symlink and junction reparse points.
    // Rust's standard library does not expose every Windows reparse tag, so
    // descriptor metadata below also rejects anything not reported as a
    // regular file. Exotic third-party reparse tags cannot be classified more
    // precisely without a Windows API dependency.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn harden_open_options_for_platform(_options: &mut OpenOptions) {}

fn open_identity_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    harden_open_options(&mut options);
    options.open(path)
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?
        .sync_all()
}

#[cfg(windows)]
pub(crate) fn sync_directory(path: &Path) -> std::io::Result<()> {
    // FlushFileBuffers cannot flush the read-only directory handles available
    // through std. Windows durability therefore relies on sync_all for the
    // completed temporary file followed by atomic hard-link/rename publication.
    // This is intentionally not presented as equivalent to Unix directory
    // fsync durability.
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "directory sync target is not a directory",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn malformed(path: &Path, error: impl fmt::Display) -> IdentityError {
    IdentityError::new(
        IdentityErrorKind::MalformedFile,
        Some(path.to_path_buf()),
        error.to_string(),
    )
}

fn read_error(path: &Path, error: impl fmt::Display) -> IdentityError {
    IdentityError::new(
        IdentityErrorKind::ReadFailed,
        Some(path.to_path_buf()),
        error.to_string(),
    )
}

fn write_error(path: &Path, error: impl fmt::Display) -> IdentityError {
    IdentityError::new(
        IdentityErrorKind::WriteFailed,
        Some(path.to_path_buf()),
        error.to_string(),
    )
}

fn display_path(path: Option<&Path>) -> String {
    path.map_or_else(
        || "an unknown path".to_owned(),
        |path| path.display().to_string(),
    )
}
