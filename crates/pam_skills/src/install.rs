use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{Read, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::io::Write as _;

#[cfg(any(unix, windows))]
use cap_fs_ext::MetadataExt as _;
#[cfg(unix)]
use cap_fs_ext::OpenOptionsSyncExt as _;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, ambient_authority};
#[cfg(unix)]
use cap_std::fs::DirBuilderExt as _;
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
use pam_core::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::library::windows_reserved_device_basename;
use crate::{
    CanonicalEntryId, CanonicalLibrary, LibraryError, LibraryInsertDisposition,
    MAX_LIBRARY_ARTIFACT_BYTES,
};

pub const MAX_GIT_SOURCE_URL_BYTES: usize = 2_048;
pub const MAX_GIT_ARTIFACT_PATH_BYTES: usize = 512;
pub const MAX_GIT_ARTIFACT_PATH_DEPTH: usize = 16;
pub const MAX_GIT_PRIVATE_WORKSPACE_BYTES: u64 = 64 * 1024 * 1024;

const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const GIT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_GIT_METADATA_OUTPUT_BYTES: usize = 8 * 1024;
const MAX_GIT_ERROR_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_TEMPORARY_WORKSPACE_ATTEMPTS: usize = 16;
#[cfg(unix)]
const MAX_GIT_PATH_BYTES: usize = 16 * 1024;
#[cfg(unix)]
const MAX_GIT_PATH_COMPONENTS: usize = 128;
const MAX_GIT_WORKSPACE_ENTRIES: usize = 65_536;
const MAX_GIT_WORKSPACE_DEPTH: usize = 32;
#[cfg(windows)]
const MAX_WINDOWS_SUPERVISOR_ARGUMENTS: usize = 32;
#[cfg(windows)]
const MAX_WINDOWS_SUPERVISOR_VALUE_UTF16: usize = 16_384;
#[cfg(windows)]
const MAX_WINDOWS_SUPERVISOR_ENVIRONMENT_UTF16: usize = 28_000;
#[cfg(windows)]
const WINDOWS_SUPERVISOR_COMMAND: &str = "\"\"%PAM_SUPERVISOR_SCRIPT%\"\"";

static NEXT_INSTALL_WORKSPACE: AtomicU64 = AtomicU64::new(1);
#[cfg(windows)]
static NEXT_GIT_STATUS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ArtifactInstallProvenance {
    Local,
    Git(GitInstallProvenance),
}

impl ArtifactInstallProvenance {
    pub(crate) fn validate(&self) -> bool {
        match self {
            Self::Local => true,
            Self::Git(git) => valid_git_commit(&git.commit),
        }
    }

    fn git(url: &str, commit: String, artifact_path: &str) -> Self {
        Self::Git(GitInstallProvenance {
            repository_digest: provenance_digest(b"git-repository\0", url.as_bytes()),
            commit,
            artifact_path_digest: provenance_digest(
                b"git-artifact-path\0",
                artifact_path.as_bytes(),
            ),
        })
    }

    pub(crate) fn migrate_v3_git(url: &str, commit: String, artifact_path: &str) -> Option<Self> {
        validate_git_url(url).ok()?;
        validate_git_artifact_path(artifact_path).ok()?;
        valid_git_commit(&commit).then(|| Self::git(url, commit, artifact_path))
    }
}

impl fmt::Debug for ArtifactInstallProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => formatter.write_str("Local"),
            Self::Git(git) => formatter.debug_tuple("Git").field(git).finish(),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitInstallProvenance {
    repository_digest: ContentDigest,
    commit: String,
    artifact_path_digest: ContentDigest,
}

impl GitInstallProvenance {
    #[must_use]
    pub fn repository_digest(&self) -> &ContentDigest {
        &self.repository_digest
    }

    #[must_use]
    pub fn commit(&self) -> &str {
        &self.commit
    }

    #[must_use]
    pub fn artifact_path_digest(&self) -> &ContentDigest {
        &self.artifact_path_digest
    }
}

impl fmt::Debug for GitInstallProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitInstallProvenance")
            .field("repository_digest", &self.repository_digest)
            .field("commit", &self.commit)
            .field("artifact_path_digest", &self.artifact_path_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ArtifactInstallSource {
    LocalFile(PathBuf),
    Git(GitArtifactSource),
}

impl ArtifactInstallSource {
    #[must_use]
    pub fn local_file(path: impl Into<PathBuf>) -> Self {
        Self::LocalFile(path.into())
    }

    /// Builds a validated Git source without contacting the remote.
    ///
    /// # Errors
    ///
    /// Returns a non-sensitive typed error for an unsafe URL or artifact path.
    pub fn git(
        url: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Result<Self, ArtifactInstallError> {
        Ok(Self::Git(GitArtifactSource::new(url, artifact_path)?))
    }
}

impl fmt::Debug for ArtifactInstallSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalFile(_) => formatter.write_str("LocalFile(..)"),
            Self::Git(_) => formatter.write_str("Git(..)"),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GitArtifactSource {
    url: String,
    artifact_path: String,
}

impl GitArtifactSource {
    fn new(
        url: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Result<Self, ArtifactInstallError> {
        let url = validate_git_url(&url.into())?;
        let artifact_path = validate_git_artifact_path(&artifact_path.into())?;
        Ok(Self { url, artifact_path })
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }
}

impl fmt::Debug for GitArtifactSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitArtifactSource(..)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ArtifactInstallOutcome {
    entry_id: CanonicalEntryId,
    version: ContentDigest,
    disposition: LibraryInsertDisposition,
    provenance: ArtifactInstallProvenance,
}

impl fmt::Debug for ArtifactInstallOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactInstallOutcome")
            .field("entry_id", &self.entry_id)
            .field("version", &self.version)
            .field("disposition", &self.disposition)
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl ArtifactInstallOutcome {
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

    #[must_use]
    pub fn provenance(&self) -> &ArtifactInstallProvenance {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactInstallError {
    InvalidLocalSource,
    LocalSourceChanged,
    SourceTooLarge,
    InvalidGitUrl,
    InvalidGitArtifactPath,
    GitUnavailable,
    GitCommandFailed,
    GitDeadlineExceeded,
    GitOutputTooLarge,
    GitWorkspaceTooLarge,
    GitContainmentFailed,
    GitBlobUnavailable,
    InvalidGitCommit,
    TemporaryWorkspace,
    Library(LibraryError),
}

impl fmt::Display for ArtifactInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLocalSource => "local install source must be an absolute regular file",
            Self::LocalSourceChanged => "local install source changed while being read",
            Self::SourceTooLarge => "install source exceeds its byte bound",
            Self::InvalidGitUrl => "Git install URL is invalid",
            Self::InvalidGitArtifactPath => "Git artifact path is invalid",
            Self::GitUnavailable => "system Git is unavailable",
            Self::GitCommandFailed => "Git install command failed",
            Self::GitDeadlineExceeded => "Git install command exceeded its deadline",
            Self::GitOutputTooLarge => "Git install command output exceeded its bound",
            Self::GitWorkspaceTooLarge => "Git install workspace exceeded its byte bound",
            Self::GitContainmentFailed => "Git install process tree could not be contained",
            Self::GitBlobUnavailable => "Git artifact blob is unavailable",
            Self::InvalidGitCommit => "Git resolved an invalid commit identity",
            Self::TemporaryWorkspace => "Git install workspace could not be managed safely",
            Self::Library(error) => return error.fmt(formatter),
        };
        formatter.write_str(message)
    }
}

impl Error for ArtifactInstallError {}

impl From<LibraryError> for ArtifactInstallError {
    fn from(error: LibraryError) -> Self {
        Self::Library(error)
    }
}

/// Installs one exact local or Git file into the canonical library.
///
/// # Errors
///
/// Returns a typed error when source validation, bounded acquisition, temporary cleanup, or the
/// atomic library entry/provenance mutation fails.
pub fn install_artifact(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: &ArtifactInstallSource,
) -> Result<ArtifactInstallOutcome, ArtifactInstallError> {
    install_artifact_inner(library, entry_id, source, || {})
}

#[cfg(test)]
pub(crate) fn install_local_artifact_with_after_read(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: &ArtifactInstallSource,
    after_read: impl FnOnce(),
) -> Result<ArtifactInstallOutcome, ArtifactInstallError> {
    install_artifact_inner(library, entry_id, source, after_read)
}

#[cfg(all(test, unix))]
pub(crate) fn install_git_artifact_with_execution(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: &ArtifactInstallSource,
    executable: &Path,
    timeout: Duration,
) -> Result<ArtifactInstallOutcome, ArtifactInstallError> {
    install_git_artifact_with_execution_limits(
        library,
        entry_id,
        source,
        executable,
        timeout,
        MAX_GIT_PRIVATE_WORKSPACE_BYTES,
    )
}

#[cfg(all(test, unix))]
pub(crate) fn install_git_artifact_with_execution_limits(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: &ArtifactInstallSource,
    executable: &Path,
    timeout: Duration,
    workspace_limit: u64,
) -> Result<ArtifactInstallOutcome, ArtifactInstallError> {
    let ArtifactInstallSource::Git(source) = source else {
        return Err(ArtifactInstallError::InvalidGitUrl);
    };
    let (bytes, commit) = read_git_source_with_limits(
        library,
        source,
        executable.as_os_str(),
        timeout,
        workspace_limit,
    )?;
    let provenance = ArtifactInstallProvenance::git(&source.url, commit, &source.artifact_path);
    let inserted = library.install_bytes(entry_id, &bytes, provenance.clone())?;
    Ok(ArtifactInstallOutcome {
        entry_id: inserted.entry_id().clone(),
        version: inserted.version().clone(),
        disposition: inserted.disposition(),
        provenance,
    })
}

fn install_artifact_inner(
    library: &CanonicalLibrary,
    entry_id: CanonicalEntryId,
    source: &ArtifactInstallSource,
    after_local_read: impl FnOnce(),
) -> Result<ArtifactInstallOutcome, ArtifactInstallError> {
    let (bytes, provenance) = match source {
        ArtifactInstallSource::LocalFile(path) => (
            read_local_source(path, after_local_read)?,
            ArtifactInstallProvenance::Local,
        ),
        ArtifactInstallSource::Git(source) => {
            let (bytes, commit) = read_git_source(library, source)?;
            (
                bytes,
                ArtifactInstallProvenance::git(&source.url, commit, &source.artifact_path),
            )
        }
    };
    let inserted = library.install_bytes(entry_id, &bytes, provenance.clone())?;
    Ok(ArtifactInstallOutcome {
        entry_id: inserted.entry_id().clone(),
        version: inserted.version().clone(),
        disposition: inserted.disposition(),
        provenance,
    })
}

fn read_local_source(
    source: &Path,
    after_read: impl FnOnce(),
) -> Result<Vec<u8>, ArtifactInstallError> {
    if !source.is_absolute() {
        return Err(ArtifactInstallError::InvalidLocalSource);
    }
    let path_metadata =
        fs::symlink_metadata(source).map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(ArtifactInstallError::InvalidLocalSource);
    }
    if usize::try_from(path_metadata.len())
        .map_or(true, |length| length > MAX_LIBRARY_ARTIFACT_BYTES)
    {
        return Err(ArtifactInstallError::SourceTooLarge);
    }
    let canonical_before =
        fs::canonicalize(source).map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    let parent = canonical_before
        .parent()
        .ok_or(ArtifactInstallError::InvalidLocalSource)?;
    let name = canonical_before
        .file_name()
        .ok_or(ArtifactInstallError::InvalidLocalSource)?;
    let directory = Dir::open_ambient_dir(parent, ambient_authority())
        .map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    options.nonblock(true);
    let mut file = directory
        .open_with(Path::new(name), &options)
        .map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    let before = file
        .metadata()
        .map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    let before_length =
        usize::try_from(before.len()).map_err(|_| ArtifactInstallError::SourceTooLarge)?;
    if !before.is_file()
        || !same_std_cap_identity(&path_metadata, &before)
        || path_metadata.len() != before.len()
        || path_metadata.modified().ok()
            != before
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std)
        || before_length > MAX_LIBRARY_ARTIFACT_BYTES
    {
        return Err(ArtifactInstallError::InvalidLocalSource);
    }
    let mut bytes = Vec::with_capacity(before_length);
    (&mut file)
        .take(u64::try_from(MAX_LIBRARY_ARTIFACT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactInstallError::InvalidLocalSource)?;
    if bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES {
        return Err(ArtifactInstallError::SourceTooLarge);
    }
    if bytes.len() != before_length {
        return Err(ArtifactInstallError::LocalSourceChanged);
    }
    after_read();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    let mut second_bytes = Vec::with_capacity(bytes.len());
    (&mut file)
        .take(u64::try_from(MAX_LIBRARY_ARTIFACT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut second_bytes)
        .map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    if second_bytes.len() > MAX_LIBRARY_ARTIFACT_BYTES
        || second_bytes.len() != before_length
        || second_bytes != bytes
    {
        return Err(ArtifactInstallError::LocalSourceChanged);
    }
    let after =
        fs::symlink_metadata(source).map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    let canonical_after =
        fs::canonicalize(source).map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    let handle_after = file
        .metadata()
        .map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    let path_after = directory
        .symlink_metadata(Path::new(name))
        .map_err(|_| ArtifactInstallError::LocalSourceChanged)?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || !path_after.is_file()
        || !same_std_cap_identity(&after, &path_after)
        || canonical_after != canonical_before
        || !same_file_identity(&before, &path_after)
        || !same_file_identity(&before, &handle_after)
        || after.len() != before.len()
        || handle_after.len() != before.len()
        || before.modified().ok() != path_after.modified().ok()
        || before.modified().ok() != handle_after.modified().ok()
    {
        return Err(ArtifactInstallError::LocalSourceChanged);
    }
    Ok(bytes)
}

#[cfg(any(unix, windows))]
fn same_file_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn same_std_cap_identity(left: &fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_std_cap_identity(left: &fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;
    use std::os::windows::fs::MetadataExt as _;

    left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[cfg(not(any(unix, windows)))]
fn same_std_cap_identity(left: &fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok()
            == right
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std)
        && left.created().ok()
            == right
                .created()
                .ok()
                .map(cap_std::time::SystemTime::into_std)
}

fn validate_git_url(value: &str) -> Result<String, ArtifactInstallError> {
    if value.is_empty()
        || value.len() > MAX_GIT_SOURCE_URL_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(['#', '?', '"', '<', '>', '|', '\\'])
    {
        return Err(ArtifactInstallError::InvalidGitUrl);
    }
    if let Some(rest) = value.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(ArtifactInstallError::InvalidGitUrl);
        }
    } else if let Some(rest) = value.strip_prefix("file://") {
        if !rest.starts_with('/') || rest.starts_with("//") || rest.contains('@') {
            return Err(ArtifactInstallError::InvalidGitUrl);
        }
    } else {
        return Err(ArtifactInstallError::InvalidGitUrl);
    }
    Ok(value.to_owned())
}

fn validate_git_artifact_path(value: &str) -> Result<String, ArtifactInstallError> {
    if value.is_empty()
        || value.len() > MAX_GIT_ARTIFACT_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', ':', '"', '<', '>', '|'])
        || value.chars().any(char::is_control)
    {
        return Err(ArtifactInstallError::InvalidGitArtifactPath);
    }
    let mut depth = 0usize;
    for component in value.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || windows_reserved_device_basename(component)
        {
            return Err(ArtifactInstallError::InvalidGitArtifactPath);
        }
        depth += 1;
        if depth > MAX_GIT_ARTIFACT_PATH_DEPTH {
            return Err(ArtifactInstallError::InvalidGitArtifactPath);
        }
    }
    Ok(value.to_owned())
}

fn valid_git_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn provenance_digest(domain: &[u8], value: &[u8]) -> ContentDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    ContentDigest::from_sha256(digest.finalize().into())
}

fn read_git_source(
    library: &CanonicalLibrary,
    source: &GitArtifactSource,
) -> Result<(Vec<u8>, String), ArtifactInstallError> {
    let executable = system_git_executable()?;
    read_git_source_with(library, source, &executable, GIT_COMMAND_TIMEOUT)
}

fn read_git_source_with(
    library: &CanonicalLibrary,
    source: &GitArtifactSource,
    executable: &OsStr,
    timeout: Duration,
) -> Result<(Vec<u8>, String), ArtifactInstallError> {
    read_git_source_with_limits(
        library,
        source,
        executable,
        timeout,
        MAX_GIT_PRIVATE_WORKSPACE_BYTES,
    )
}

fn read_git_source_with_limits(
    library: &CanonicalLibrary,
    source: &GitArtifactSource,
    executable: &OsStr,
    timeout: Duration,
    workspace_limit: u64,
) -> Result<(Vec<u8>, String), ArtifactInstallError> {
    let mut workspace = GitWorkspace::create(library)?;
    let execution = GitExecution {
        executable,
        timeout,
        workspace_limit,
    };
    let result = read_git_workspace(&workspace, source, execution);
    if matches!(result, Err(ArtifactInstallError::GitContainmentFailed)) {
        workspace.preserve();
        return result;
    }
    let cleanup = workspace.cleanup();
    cleanup?;
    result
}

fn read_git_workspace(
    workspace: &GitWorkspace,
    source: &GitArtifactSource,
    execution: GitExecution<'_>,
) -> Result<(Vec<u8>, String), ArtifactInstallError> {
    workspace.create_private_directory(Path::new("hooks-disabled"))?;
    run_git(
        workspace,
        &git_arguments(
            workspace,
            None,
            ["init", "--bare", "--quiet", "--template=", "repository.git"],
        ),
        MAX_GIT_METADATA_OUTPUT_BYTES,
        GitOperation::General,
        execution,
    )?;
    let repository = workspace.path.join("repository.git");
    run_git(
        workspace,
        &git_repository_arguments(
            workspace,
            &repository,
            Some(if source.url.starts_with("file://") {
                "file"
            } else {
                "https"
            }),
            [
                "fetch",
                "--quiet",
                "--depth=1",
                "--no-tags",
                "--no-recurse-submodules",
                source.url.as_str(),
                "HEAD",
            ],
        ),
        MAX_GIT_METADATA_OUTPUT_BYTES,
        GitOperation::General,
        execution,
    )?;
    let commit_bytes = run_git(
        workspace,
        &git_repository_arguments(
            workspace,
            &repository,
            None,
            ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        ),
        MAX_GIT_METADATA_OUTPUT_BYTES,
        GitOperation::General,
        execution,
    )?;
    let commit = String::from_utf8(commit_bytes)
        .map_err(|_| ArtifactInstallError::InvalidGitCommit)?
        .trim()
        .to_owned();
    if !valid_git_commit(&commit) {
        return Err(ArtifactInstallError::InvalidGitCommit);
    }
    let object = format!("{commit}:{}", source.artifact_path);
    let size_bytes = run_git(
        workspace,
        &git_repository_arguments(
            workspace,
            &repository,
            None,
            ["cat-file", "-s", object.as_str()],
        ),
        MAX_GIT_METADATA_OUTPUT_BYTES,
        GitOperation::Blob,
        execution,
    )?;
    let size = String::from_utf8(size_bytes)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .ok_or(ArtifactInstallError::GitBlobUnavailable)?;
    if size > MAX_LIBRARY_ARTIFACT_BYTES {
        return Err(ArtifactInstallError::SourceTooLarge);
    }
    let bytes = run_git(
        workspace,
        &git_repository_arguments(
            workspace,
            &repository,
            None,
            ["cat-file", "blob", object.as_str()],
        ),
        MAX_LIBRARY_ARTIFACT_BYTES,
        GitOperation::Blob,
        execution,
    )?;
    if bytes.len() != size {
        return Err(ArtifactInstallError::GitBlobUnavailable);
    }
    Ok((bytes, commit))
}

fn git_repository_arguments<'a>(
    workspace: &GitWorkspace,
    repository: &Path,
    protocol: Option<&str>,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Vec<OsString> {
    let mut result = git_arguments(workspace, protocol, std::iter::empty());
    result.extend([OsString::from("-C"), repository.as_os_str().to_owned()]);
    result.extend(arguments.into_iter().map(OsString::from));
    result
}

fn git_arguments<'a>(
    workspace: &GitWorkspace,
    protocol: Option<&str>,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Vec<OsString> {
    let hooks = workspace.path.join("hooks-disabled");
    let mut result = vec![
        OsString::from("-c"),
        OsString::from(format!("core.hooksPath={}", hooks.display())),
        OsString::from("-c"),
        OsString::from("credential.helper="),
        OsString::from("-c"),
        OsString::from("submodule.recurse=false"),
        OsString::from("-c"),
        OsString::from("protocol.allow=never"),
    ];
    if let Some(protocol) = protocol {
        result.extend([
            OsString::from("-c"),
            OsString::from(format!("protocol.{protocol}.allow=always")),
        ]);
    }
    result.extend(arguments.into_iter().map(OsString::from));
    result
}

#[derive(Clone, Copy)]
enum GitOperation {
    General,
    Blob,
}

#[derive(Clone, Copy)]
struct GitExecution<'a> {
    executable: &'a OsStr,
    timeout: Duration,
    workspace_limit: u64,
}

fn run_git(
    workspace: &GitWorkspace,
    arguments: &[OsString],
    stdout_limit: usize,
    operation: GitOperation,
    execution: GitExecution<'_>,
) -> Result<Vec<u8>, ArtifactInstallError> {
    workspace.ensure_within_limit(execution.workspace_limit)?;
    #[cfg(windows)]
    {
        return run_git_with_windows_supervisor(
            workspace,
            arguments,
            stdout_limit,
            operation,
            execution,
        );
    }
    #[cfg(not(windows))]
    run_git_direct(workspace, arguments, stdout_limit, operation, execution)
}

#[cfg(not(windows))]
fn run_git_direct(
    workspace: &GitWorkspace,
    arguments: &[OsString],
    stdout_limit: usize,
    operation: GitOperation,
    execution: GitExecution<'_>,
) -> Result<Vec<u8>, ArtifactInstallError> {
    let mut command = Command::new(execution.executable);
    command
        .args(arguments)
        .current_dir(&workspace.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_git_environment(&mut command, &workspace.path, execution.executable);
    configure_git_process_group(&mut command);
    let deadline = Instant::now()
        .checked_add(execution.timeout)
        .ok_or(ArtifactInstallError::GitDeadlineExceeded)?;
    let mut child = command
        .spawn()
        .map_err(|_| ArtifactInstallError::GitUnavailable)?;
    let Some(stdout) = child.stdout.take() else {
        terminate_direct_git_tree(&mut child);
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_direct_git_tree(&mut child);
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_worker = spawn_git_drain(stdout, stdout_limit, Arc::clone(&overflow));
    let Ok(stdout_worker) = stdout_worker else {
        terminate_direct_git_tree(&mut child);
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let stderr_worker = spawn_git_drain(stderr, MAX_GIT_ERROR_OUTPUT_BYTES, Arc::clone(&overflow));
    let Ok(stderr_worker) = stderr_worker else {
        terminate_direct_git_tree(&mut child);
        let _ = stdout_worker.join();
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let wait_result = wait_for_git_direct(
        &mut child,
        workspace,
        execution.workspace_limit,
        deadline,
        &overflow,
    );
    terminate_direct_git_tree(&mut child);
    let stdout = stdout_worker
        .join()
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    stderr_worker
        .join()
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    workspace.ensure_within_limit(execution.workspace_limit)?;
    if overflow.load(Ordering::Acquire) {
        return Err(ArtifactInstallError::GitOutputTooLarge);
    }
    if !wait_result? {
        return Err(match operation {
            GitOperation::General => ArtifactInstallError::GitCommandFailed,
            GitOperation::Blob => ArtifactInstallError::GitBlobUnavailable,
        });
    }
    Ok(stdout)
}

#[cfg(not(windows))]
fn wait_for_git_direct(
    child: &mut Child,
    workspace: &GitWorkspace,
    workspace_limit: u64,
    deadline: Instant,
    overflow: &AtomicBool,
) -> Result<bool, ArtifactInstallError> {
    loop {
        if overflow.load(Ordering::Acquire) {
            return Err(ArtifactInstallError::GitOutputTooLarge);
        }
        workspace.ensure_within_limit(workspace_limit)?;
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) if Instant::now() < deadline => thread::sleep(GIT_POLL_INTERVAL),
            Ok(None) => return Err(ArtifactInstallError::GitDeadlineExceeded),
            Err(_) => return Err(ArtifactInstallError::GitCommandFailed),
        }
    }
}

#[cfg(windows)]
fn run_git_with_windows_supervisor(
    workspace: &GitWorkspace,
    arguments: &[OsString],
    stdout_limit: usize,
    operation: GitOperation,
    execution: GitExecution<'_>,
) -> Result<Vec<u8>, ArtifactInstallError> {
    let tools = windows_supervisor_tools()?;
    let sequence = NEXT_GIT_STATUS.fetch_add(1, Ordering::Relaxed);
    let status_name = PathBuf::from(format!("git-status-{sequence}"));
    let temporary_status_name = PathBuf::from(format!("git-status-{sequence}.tmp"));
    let script_name = PathBuf::from(format!("git-supervisor-{sequence}.cmd"));
    let status_path = workspace.path.join(&status_name);
    let temporary_status_path = workspace.path.join(&temporary_status_name);
    let script_path = workspace.path.join(&script_name);
    let supervisor_environment = windows_supervisor_environment(
        execution.executable,
        arguments,
        &workspace.path,
        &temporary_status_path,
        &status_path,
        &tools.wait,
        &script_path,
    )?;
    workspace.write_windows_supervisor_script(&script_name)?;
    let deadline = Instant::now()
        .checked_add(execution.timeout)
        .ok_or(ArtifactInstallError::GitDeadlineExceeded)?;
    let mut command = Command::new(&tools.command);
    use std::os::windows::process::CommandExt as _;
    command
        .args(["/D", "/Q", "/V:OFF", "/S", "/C"])
        .raw_arg(windows_supervisor_fixed_command())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_git_environment(&mut command, &workspace.path, execution.executable);
    command.envs(supervisor_environment);
    let mut child = command
        .spawn()
        .map_err(|_| ArtifactInstallError::GitUnavailable)?;
    let Some(stdout) = child.stdout.take() else {
        terminate_windows_supervisor(&mut child, &tools.taskkill)?;
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_windows_supervisor(&mut child, &tools.taskkill)?;
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_worker = spawn_git_drain(stdout, stdout_limit, Arc::clone(&overflow));
    let Ok(stdout_worker) = stdout_worker else {
        terminate_windows_supervisor(&mut child, &tools.taskkill)?;
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let stderr_worker = spawn_git_drain(stderr, MAX_GIT_ERROR_OUTPUT_BYTES, Arc::clone(&overflow));
    let Ok(stderr_worker) = stderr_worker else {
        terminate_windows_supervisor(&mut child, &tools.taskkill)?;
        let _ = stdout_worker.join();
        return Err(ArtifactInstallError::GitCommandFailed);
    };
    let wait_result = wait_for_windows_git(
        workspace,
        &status_name,
        execution.workspace_limit,
        deadline,
        &overflow,
    );
    if terminate_windows_supervisor(&mut child, &tools.taskkill).is_err() {
        return Err(ArtifactInstallError::GitContainmentFailed);
    }
    let stdout = stdout_worker
        .join()
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    stderr_worker
        .join()
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    workspace.ensure_within_limit(execution.workspace_limit)?;
    if overflow.load(Ordering::Acquire) {
        return Err(ArtifactInstallError::GitOutputTooLarge);
    }
    if !wait_result? {
        return Err(match operation {
            GitOperation::General => ArtifactInstallError::GitCommandFailed,
            GitOperation::Blob => ArtifactInstallError::GitBlobUnavailable,
        });
    }
    Ok(stdout)
}

#[cfg(windows)]
fn wait_for_windows_git(
    workspace: &GitWorkspace,
    status_name: &Path,
    workspace_limit: u64,
    deadline: Instant,
    overflow: &AtomicBool,
) -> Result<bool, ArtifactInstallError> {
    loop {
        if overflow.load(Ordering::Acquire) {
            return Err(ArtifactInstallError::GitOutputTooLarge);
        }
        workspace.ensure_within_limit(workspace_limit)?;
        if let Some(success) = read_windows_git_status(workspace, status_name)? {
            return Ok(success);
        }
        if Instant::now() >= deadline {
            return Err(ArtifactInstallError::GitDeadlineExceeded);
        }
        thread::sleep(GIT_POLL_INTERVAL);
    }
}

#[cfg(windows)]
fn read_windows_git_status(
    workspace: &GitWorkspace,
    status_name: &Path,
) -> Result<Option<bool>, ArtifactInstallError> {
    let metadata = match workspace.directory.symlink_metadata(status_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ArtifactInstallError::GitCommandFailed),
    };
    if !metadata.is_file() || metadata.len() > 32 {
        return Err(ArtifactInstallError::GitCommandFailed);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = workspace
        .directory
        .open_with(status_name, &options)
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    let mut bytes = Vec::with_capacity(32);
    (&mut file)
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactInstallError::GitCommandFailed)?;
    if bytes.len() > 32 {
        return Err(ArtifactInstallError::GitCommandFailed);
    }
    let value = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<i32>().ok())
        .ok_or(ArtifactInstallError::GitCommandFailed)?;
    Ok(Some(value == 0))
}

#[cfg(windows)]
struct WindowsSupervisorTools {
    command: PathBuf,
    taskkill: PathBuf,
    wait: PathBuf,
}

#[cfg(windows)]
fn windows_supervisor_tools() -> Result<WindowsSupervisorTools, ArtifactInstallError> {
    let system_root = env::var_os("SystemRoot").ok_or(ArtifactInstallError::GitUnavailable)?;
    if !Path::new(&system_root).is_absolute() {
        return Err(ArtifactInstallError::GitUnavailable);
    }
    let system32 = PathBuf::from(system_root).join("System32");
    let tools = WindowsSupervisorTools {
        command: system32.join("cmd.exe"),
        taskkill: system32.join("taskkill.exe"),
        wait: system32.join("ping.exe"),
    };
    for executable in [&tools.command, &tools.taskkill, &tools.wait] {
        let metadata =
            fs::symlink_metadata(executable).map_err(|_| ArtifactInstallError::GitUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ArtifactInstallError::GitUnavailable);
        }
    }
    Ok(tools)
}

#[cfg(windows)]
pub(crate) fn windows_supervisor_environment(
    executable: &OsStr,
    arguments: &[OsString],
    working_directory: &Path,
    temporary_status_path: &Path,
    status_path: &Path,
    wait_executable: &Path,
    script_path: &Path,
) -> Result<Vec<(OsString, OsString)>, ArtifactInstallError> {
    if arguments.len() > MAX_WINDOWS_SUPERVISOR_ARGUMENTS {
        return Err(ArtifactInstallError::GitCommandFailed);
    }
    let mut variables = Vec::with_capacity(arguments.len() + 7);
    let mut total_utf16 = 0usize;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_GIT_EXECUTABLE",
        executable,
    )?;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_GIT_CWD",
        working_directory.as_os_str(),
    )?;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_STATUS_TEMP",
        temporary_status_path.as_os_str(),
    )?;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_STATUS_FINAL",
        status_path.as_os_str(),
    )?;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_WAIT_EXECUTABLE",
        wait_executable.as_os_str(),
    )?;
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_SUPERVISOR_SCRIPT",
        script_path.as_os_str(),
    )?;
    let count = OsString::from(arguments.len().to_string());
    push_windows_supervisor_environment(
        &mut variables,
        &mut total_utf16,
        "PAM_GIT_ARG_COUNT",
        &count,
    )?;
    for (index, argument) in arguments.iter().enumerate() {
        push_windows_supervisor_environment(
            &mut variables,
            &mut total_utf16,
            &format!("PAM_GIT_ARG_{index:02}"),
            argument,
        )?;
    }
    Ok(variables)
}

#[cfg(windows)]
fn push_windows_supervisor_environment(
    variables: &mut Vec<(OsString, OsString)>,
    total_utf16: &mut usize,
    name: &str,
    value: &OsStr,
) -> Result<(), ArtifactInstallError> {
    let value = value
        .to_str()
        .filter(|value| !value.contains('"') && !value.chars().any(char::is_control))
        .ok_or(ArtifactInstallError::GitCommandFailed)?;
    let value_utf16 = value.encode_utf16().count();
    if value_utf16 > MAX_WINDOWS_SUPERVISOR_VALUE_UTF16 {
        return Err(ArtifactInstallError::GitCommandFailed);
    }
    *total_utf16 = total_utf16
        .checked_add(name.encode_utf16().count() + 1)
        .and_then(|total| total.checked_add(value_utf16 + 1))
        .ok_or(ArtifactInstallError::GitCommandFailed)?;
    if *total_utf16 > MAX_WINDOWS_SUPERVISOR_ENVIRONMENT_UTF16 {
        return Err(ArtifactInstallError::GitCommandFailed);
    }
    variables.push((OsString::from(name), OsString::from(value)));
    Ok(())
}

#[cfg(windows)]
pub(crate) fn windows_supervisor_script() -> String {
    let mut script = String::from("@echo off\r\nsetlocal DisableDelayedExpansion\r\n");
    script.push_str("cd /D \"%PAM_GIT_CWD%\"\r\n");
    script.push_str("if errorlevel 1 goto pam_protocol_error\r\n");
    for count in 0..=MAX_WINDOWS_SUPERVISOR_ARGUMENTS {
        script.push_str(&format!(
            "if \"%PAM_GIT_ARG_COUNT%\"==\"{count}\" goto pam_args_{count}\r\n"
        ));
    }
    script.push_str("goto pam_protocol_error\r\n");
    for count in 0..=MAX_WINDOWS_SUPERVISOR_ARGUMENTS {
        script.push_str(&format!(":pam_args_{count}\r\n\"%PAM_GIT_EXECUTABLE%\""));
        for index in 0..count {
            script.push_str(&format!(" \"%PAM_GIT_ARG_{index:02}%\""));
        }
        script.push_str("\r\nset \"PAM_GIT_EXIT=%ERRORLEVEL%\"\r\n");
        script.push_str("goto pam_publish\r\n");
    }
    script.push_str(":pam_protocol_error\r\nset \"PAM_GIT_EXIT=-1\"\r\n");
    script.push_str(":pam_publish\r\n");
    script.push_str("> \"%PAM_STATUS_TEMP%\" echo %PAM_GIT_EXIT%\r\n");
    script.push_str("move /Y \"%PAM_STATUS_TEMP%\" \"%PAM_STATUS_FINAL%\" >NUL 2>NUL\r\n");
    script.push_str(":pam_wait\r\n");
    script.push_str("\"%PAM_WAIT_EXECUTABLE%\" -t 127.0.0.1 >NUL 2>NUL\r\n");
    script.push_str("goto pam_wait\r\n");
    script
}

#[cfg(windows)]
pub(crate) const fn windows_supervisor_fixed_command() -> &'static str {
    WINDOWS_SUPERVISOR_COMMAND
}

#[cfg(windows)]
fn terminate_windows_supervisor(
    child: &mut Child,
    taskkill: &Path,
) -> Result<(), ArtifactInstallError> {
    let taskkill_succeeded = Command::new(taskkill)
        .args(windows_taskkill_arguments(child.id()))
        .env_clear()
        .env(
            "SystemRoot",
            taskkill.ancestors().nth(2).unwrap_or(taskkill),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let _ = child.kill();
    let reaped = child.wait().is_ok();
    if taskkill_succeeded && reaped {
        Ok(())
    } else {
        Err(ArtifactInstallError::GitContainmentFailed)
    }
}

fn spawn_git_drain(
    reader: impl Read + Send + 'static,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<std::io::Result<Vec<u8>>>> {
    thread::Builder::new()
        .name("pam-git-output".to_owned())
        .spawn(move || drain_git_output(reader, limit, &overflow))
}

fn drain_git_output(
    mut reader: impl Read,
    limit: usize,
    overflow: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    let retain_limit = limit.saturating_add(1);
    let mut retained = Vec::with_capacity(retain_limit.min(8 * 1024));
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(retained);
        }
        if retained.len() < retain_limit {
            let retain = read.min(retain_limit - retained.len());
            retained.extend_from_slice(&buffer[..retain]);
        }
        if retained.len() > limit {
            overflow.store(true, Ordering::Release);
        }
    }
}

fn system_git_executable() -> Result<OsString, ArtifactInstallError> {
    #[cfg(unix)]
    {
        let path = env::var_os("PATH").ok_or(ArtifactInstallError::GitUnavailable)?;
        resolve_unix_git_executable(&path)
    }
    #[cfg(windows)]
    {
        Ok(OsString::from("git.exe"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(OsString::from("git"))
    }
}

#[cfg(unix)]
fn resolve_unix_git_executable(path: &OsStr) -> Result<OsString, ArtifactInstallError> {
    use std::os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _};

    if path.as_bytes().len() > MAX_GIT_PATH_BYTES {
        return Err(ArtifactInstallError::GitUnavailable);
    }
    for (index, directory) in env::split_paths(path).enumerate() {
        if index >= MAX_GIT_PATH_COMPONENTS {
            return Err(ArtifactInstallError::GitUnavailable);
        }
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join("git");
        if candidate.as_os_str().as_bytes().len() > MAX_GIT_PATH_BYTES {
            continue;
        }
        let Ok(executable) = fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&executable) else {
            continue;
        };
        if executable.is_absolute()
            && executable.as_os_str().as_bytes().len() <= MAX_GIT_PATH_BYTES
            && !metadata.file_type().is_symlink()
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return Ok(executable.into_os_string());
        }
    }
    Err(ArtifactInstallError::GitUnavailable)
}

#[cfg(all(test, unix))]
pub(crate) fn resolve_unix_git_executable_for_test(
    path: &OsStr,
) -> Result<OsString, ArtifactInstallError> {
    resolve_unix_git_executable(path)
}

fn apply_git_environment(command: &mut Command, workspace: &Path, executable: &OsStr) {
    let path = git_child_path(executable);
    let system_root = env::var_os("SystemRoot");
    command
        .env_clear()
        .env("PATH", path)
        .env("HOME", workspace)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", workspace.join("no-global-config"))
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("GIT_SSH_COMMAND", "false")
        .env("XDG_CONFIG_HOME", workspace);
    if let Some(system_root) = system_root {
        command.env("SystemRoot", system_root);
    }
}

#[cfg(unix)]
fn git_child_path(executable: &OsStr) -> OsString {
    let executable = Path::new(executable);
    let mut directories = Vec::new();
    if let Some(parent) = executable.parent() {
        directories.push(parent.to_path_buf());
    }
    for directory in [Path::new("/usr/bin"), Path::new("/bin")] {
        if !directories.iter().any(|candidate| candidate == directory) {
            directories.push(directory.to_path_buf());
        }
    }
    env::join_paths(directories).unwrap_or_else(|_| OsString::from("/usr/bin:/bin"))
}

#[cfg(not(unix))]
fn git_child_path(_executable: &OsStr) -> OsString {
    env::var_os("PATH").unwrap_or_default()
}

#[cfg(unix)]
fn configure_git_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(any(unix, windows)))]
fn configure_git_process_group(_command: &mut Command) {}

#[cfg(not(windows))]
fn terminate_direct_git_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(process_id) = i32::try_from(child.id()) {
        use nix::{sys::signal::Signal, unistd::Pid};
        let _ = nix::sys::signal::killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(windows)]
fn windows_taskkill_arguments(process_id: u32) -> [OsString; 4] {
    [
        OsString::from("/PID"),
        OsString::from(process_id.to_string()),
        OsString::from("/T"),
        OsString::from("/F"),
    ]
}

struct GitWorkspace {
    root: Dir,
    directory: Dir,
    name: PathBuf,
    path: PathBuf,
    cleaned: bool,
}

impl GitWorkspace {
    fn create(library: &CanonicalLibrary) -> Result<Self, ArtifactInstallError> {
        let root = Dir::open_ambient_dir(library.root_path(), ambient_authority())
            .map_err(|_| ArtifactInstallError::TemporaryWorkspace)?;
        for _ in 0..MAX_TEMPORARY_WORKSPACE_ATTEMPTS {
            let sequence = NEXT_INSTALL_WORKSPACE.fetch_add(1, Ordering::Relaxed);
            let name = PathBuf::from(format!("install-tmp-{}-{sequence}", std::process::id()));
            let mut builder = DirBuilder::new();
            set_private_directory_mode(&mut builder);
            match root.create_dir_with(&name, &builder) {
                Ok(()) => {
                    let directory = root
                        .open_dir_nofollow(&name)
                        .map_err(|_| ArtifactInstallError::TemporaryWorkspace)?;
                    return Ok(Self {
                        path: library.root_path().join(&name),
                        root,
                        directory,
                        name,
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ArtifactInstallError::TemporaryWorkspace),
            }
        }
        Err(ArtifactInstallError::TemporaryWorkspace)
    }

    fn create_private_directory(&self, path: &Path) -> Result<(), ArtifactInstallError> {
        let mut builder = DirBuilder::new();
        set_private_directory_mode(&mut builder);
        self.directory
            .create_dir_with(path, &builder)
            .map_err(|_| ArtifactInstallError::TemporaryWorkspace)
    }

    fn ensure_within_limit(&self, maximum: u64) -> Result<(), ArtifactInstallError> {
        let mut entries = 0usize;
        let mut bytes = 0u64;
        accumulate_workspace_size(&self.path, 0, maximum, &mut entries, &mut bytes)
    }

    #[cfg(windows)]
    fn write_windows_supervisor_script(&self, path: &Path) -> Result<(), ArtifactInstallError> {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut file = self
            .directory
            .open_with(path, &options)
            .map_err(|_| ArtifactInstallError::TemporaryWorkspace)?;
        file.write_all(windows_supervisor_script().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| ArtifactInstallError::TemporaryWorkspace)
    }

    fn cleanup(&mut self) -> Result<(), ArtifactInstallError> {
        self.root
            .remove_dir_all(&self.name)
            .map_err(|_| ArtifactInstallError::TemporaryWorkspace)?;
        self.cleaned = true;
        Ok(())
    }

    fn preserve(&mut self) {
        self.cleaned = true;
    }
}

fn accumulate_workspace_size(
    directory: &Path,
    depth: usize,
    maximum: u64,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), ArtifactInstallError> {
    if depth > MAX_GIT_WORKSPACE_DEPTH {
        return Err(ArtifactInstallError::GitWorkspaceTooLarge);
    }
    let children = match fs::read_dir(directory) {
        Ok(children) => children,
        Err(error) if depth > 0 && transient_workspace_race(&error) => return Ok(()),
        Err(_) => return Err(ArtifactInstallError::TemporaryWorkspace),
    };
    for child in children {
        *entries = entries
            .checked_add(1)
            .ok_or(ArtifactInstallError::GitWorkspaceTooLarge)?;
        if *entries > MAX_GIT_WORKSPACE_ENTRIES {
            return Err(ArtifactInstallError::GitWorkspaceTooLarge);
        }
        let child = match child {
            Ok(child) => child,
            Err(error) if transient_workspace_race(&error) => continue,
            Err(_) => return Err(ArtifactInstallError::TemporaryWorkspace),
        };
        let path = child.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if transient_workspace_race(&error) => continue,
            Err(_) => return Err(ArtifactInstallError::TemporaryWorkspace),
        };
        if metadata.is_dir() {
            accumulate_workspace_size(&path, depth + 1, maximum, entries, bytes)?;
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            *bytes = bytes
                .checked_add(metadata.len())
                .ok_or(ArtifactInstallError::GitWorkspaceTooLarge)?;
            if *bytes > maximum {
                return Err(ArtifactInstallError::GitWorkspaceTooLarge);
            }
        } else {
            return Err(ArtifactInstallError::TemporaryWorkspace);
        }
    }
    Ok(())
}

fn transient_workspace_race(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

impl Drop for GitWorkspace {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.root.remove_dir_all(&self.name);
        }
    }
}

#[cfg(unix)]
fn set_private_directory_mode(builder: &mut DirBuilder) {
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn set_private_directory_mode(_builder: &mut DirBuilder) {}
