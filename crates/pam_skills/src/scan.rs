use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{
    FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _, ambient_authority,
};
use cap_std::fs::{Dir, File, OpenOptions};
use pam_core::ContentDigest;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{AgentArtifact, ArtifactKind, ArtifactScope, OriginAgent};

pub const DEFAULT_MAX_FILE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_ARTIFACTS: usize = 4096;
pub const DEFAULT_MAX_AGGREGATE_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_MAX_TRAVERSAL_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimits {
    pub max_file_bytes: usize,
    pub max_artifacts: usize,
    pub max_aggregate_bytes: usize,
    pub max_traversal_depth: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_artifacts: DEFAULT_MAX_ARTIFACTS,
            max_aggregate_bytes: DEFAULT_MAX_AGGREGATE_BYTES,
            max_traversal_depth: DEFAULT_MAX_TRAVERSAL_DEPTH,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanDiagnosticKind {
    AggregateBytesExceeded,
    ArtifactLimitExceeded,
    DuplicateArtifactIdentity,
    FileTooLarge,
    InvalidArtifact,
    InvalidJson,
    InvalidPluginId,
    MissingPluginManifest,
    NonUtf8Content,
    NonUtf8Path,
    PathChangedDuringRead,
    ReadDirectory,
    ReadFile,
    RootUnavailable,
    TraversalDepthExceeded,
    UnsafeFileType,
    UnsafePath,
    UnsafeSymlink,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScanDiagnostic {
    logical_path: String,
    kind: ScanDiagnosticKind,
}

impl ScanDiagnostic {
    #[must_use]
    pub fn logical_path(&self) -> &str {
        &self.logical_path
    }

    #[must_use]
    pub const fn kind(&self) -> ScanDiagnosticKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScanReport {
    artifacts: Vec<AgentArtifact>,
    diagnostics: Vec<ScanDiagnostic>,
    complete: bool,
}

impl ScanReport {
    #[must_use]
    pub fn artifacts(&self) -> &[AgentArtifact] {
        &self.artifacts
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[ScanDiagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn into_artifacts(self) -> Vec<AgentArtifact> {
        self.artifacts
    }
}

pub(crate) struct RootedPath {
    root: PathBuf,
    directory: Dir,
    logical_prefix: String,
}

impl RootedPath {
    fn logical_path(&self, relative: &Path) -> Result<String, ScanDiagnosticKind> {
        let relative = relative_to_logical(relative)?;
        if self.logical_prefix.is_empty() {
            Ok(relative)
        } else {
            Ok(format!("{}/{relative}", self.logical_prefix))
        }
    }
}

#[derive(Debug)]
pub(crate) struct ScannedFile {
    pub logical_path: String,
    pub bytes: Vec<u8>,
    pub content_hash: ContentDigest,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArtifactKey {
    origin: OriginAgent,
    kind: ArtifactKind,
    scope: ArtifactScope,
    logical_path: String,
}

pub(crate) struct ScanSession {
    limits: ScanLimits,
    total_bytes: usize,
    aggregate_exhausted: bool,
    artifact_limit_reported: bool,
    artifacts: BTreeMap<ArtifactKey, AgentArtifact>,
    diagnostics: Vec<ScanDiagnostic>,
}

impl ScanSession {
    pub(crate) fn new(limits: ScanLimits) -> Self {
        Self {
            limits,
            total_bytes: 0,
            aggregate_exhausted: false,
            artifact_limit_reported: false,
            artifacts: BTreeMap::new(),
            diagnostics: Vec::new(),
        }
    }

    pub(crate) fn open_root(
        &mut self,
        root: &Path,
        logical_prefix: impl Into<String>,
        diagnostic_path: &str,
    ) -> Option<RootedPath> {
        let Ok(canonical) = fs::canonicalize(root) else {
            self.diagnostic(diagnostic_path, ScanDiagnosticKind::RootUnavailable);
            return None;
        };
        match fs::metadata(&canonical) {
            Ok(metadata) if metadata.is_dir() => {
                let Ok(directory) = Dir::open_ambient_dir(&canonical, ambient_authority()) else {
                    self.diagnostic(diagnostic_path, ScanDiagnosticKind::RootUnavailable);
                    return None;
                };
                Some(RootedPath {
                    root: canonical,
                    directory,
                    logical_prefix: logical_prefix.into(),
                })
            }
            Ok(_) => {
                self.diagnostic(diagnostic_path, ScanDiagnosticKind::UnsafeFileType);
                None
            }
            Err(_) => {
                self.diagnostic(diagnostic_path, ScanDiagnosticKind::RootUnavailable);
                None
            }
        }
    }

    pub(crate) fn read_optional_file(
        &mut self,
        root: &RootedPath,
        relative: &Path,
    ) -> Option<ScannedFile> {
        if self.aggregate_exhausted {
            return None;
        }
        let diagnostic_path = root
            .logical_path(relative)
            .unwrap_or_else(|_| "<invalid-path>".to_owned());
        let candidate = match Self::resolve(root, relative, false) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return None,
            Err(kind) => {
                self.diagnostic(&diagnostic_path, kind);
                return None;
            }
        };
        let (file, size, resolved_before) = match self.open_bounded_file(root, relative, &candidate)
        {
            Ok(opened) => opened,
            Err(kind) => {
                self.diagnostic(&diagnostic_path, kind);
                return None;
            }
        };

        let read_limit = self.limits.max_file_bytes.saturating_add(1);
        let mut bytes = Vec::with_capacity(size.min(self.limits.max_file_bytes));
        if file
            .take(u64::try_from(read_limit).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .is_err()
        {
            self.diagnostic(&diagnostic_path, ScanDiagnosticKind::ReadFile);
            return None;
        }
        if bytes.len() > self.limits.max_file_bytes {
            self.diagnostic(&diagnostic_path, ScanDiagnosticKind::FileTooLarge);
            return None;
        }
        let Ok(resolved_after) = fs::canonicalize(&candidate) else {
            self.diagnostic(&diagnostic_path, ScanDiagnosticKind::PathChangedDuringRead);
            return None;
        };
        if resolved_before != resolved_after || !resolved_after.starts_with(&root.root) {
            self.diagnostic(&diagnostic_path, ScanDiagnosticKind::PathChangedDuringRead);
            return None;
        }

        let total = match self.total_bytes.checked_add(bytes.len()) {
            Some(total) => total,
            None => usize::MAX,
        };
        if total > self.limits.max_aggregate_bytes {
            self.aggregate_exhausted = true;
            self.diagnostic(&diagnostic_path, ScanDiagnosticKind::AggregateBytesExceeded);
            return None;
        }
        self.total_bytes = total;
        let content_hash = ContentDigest::from_sha256(Sha256::digest(&bytes).into());
        Some(ScannedFile {
            logical_path: diagnostic_path,
            bytes,
            content_hash,
        })
    }

    pub(crate) fn walk_files<F>(
        &mut self,
        root: &RootedPath,
        relative_directory: &Path,
        mut include: F,
    ) -> Vec<PathBuf>
    where
        F: FnMut(&Path) -> bool,
    {
        let directory = match Self::resolve(root, relative_directory, true) {
            Ok(Some(directory)) => directory,
            Ok(None) => return Vec::new(),
            Err(kind) => {
                let path = root
                    .logical_path(relative_directory)
                    .unwrap_or_else(|_| "<invalid-path>".to_owned());
                self.diagnostic(&path, kind);
                return Vec::new();
            }
        };
        let mut stack = vec![(relative_directory.to_path_buf(), directory, 0_usize)];
        let mut files = Vec::new();
        while let Some((relative, absolute, depth)) = stack.pop() {
            let Ok(entries) = fs::read_dir(&absolute) else {
                let path = root
                    .logical_path(&relative)
                    .unwrap_or_else(|_| "<invalid-path>".to_owned());
                self.diagnostic(&path, ScanDiagnosticKind::ReadDirectory);
                continue;
            };
            let Ok(mut entries) = entries.collect::<Result<Vec<_>, _>>() else {
                let path = root
                    .logical_path(&relative)
                    .unwrap_or_else(|_| "<invalid-path>".to_owned());
                self.diagnostic(&path, ScanDiagnosticKind::ReadDirectory);
                continue;
            };
            entries.sort_unstable_by_key(fs::DirEntry::file_name);
            for entry in entries.into_iter().rev() {
                let child_relative = relative.join(entry.file_name());
                let logical_path = match root.logical_path(&child_relative) {
                    Ok(path) => path,
                    Err(kind) => {
                        self.diagnostic("<non-utf8-path>", kind);
                        continue;
                    }
                };
                let Ok(file_type) = entry.file_type() else {
                    self.diagnostic(&logical_path, ScanDiagnosticKind::ReadFile);
                    continue;
                };
                if file_type.is_symlink() {
                    self.diagnostic(&logical_path, ScanDiagnosticKind::UnsafeSymlink);
                } else if file_type.is_dir() {
                    if depth >= self.limits.max_traversal_depth {
                        self.diagnostic(&logical_path, ScanDiagnosticKind::TraversalDepthExceeded);
                    } else {
                        stack.push((child_relative, entry.path(), depth + 1));
                    }
                } else if file_type.is_file() {
                    if include(&child_relative) {
                        files.push(child_relative);
                    }
                } else {
                    self.diagnostic(&logical_path, ScanDiagnosticKind::UnsafeFileType);
                }
            }
        }
        files.sort_unstable();
        files
    }

    pub(crate) fn push_artifact(&mut self, artifact: AgentArtifact) {
        let key = ArtifactKey {
            origin: artifact.origin(),
            kind: artifact.kind(),
            scope: artifact.scope(),
            logical_path: artifact.logical_path().to_owned(),
        };
        if let Some(existing) = self.artifacts.get(&key) {
            if existing != &artifact {
                self.diagnostic(
                    artifact.logical_path(),
                    ScanDiagnosticKind::DuplicateArtifactIdentity,
                );
            }
            return;
        }
        if self.artifacts.len() >= self.limits.max_artifacts {
            if !self.artifact_limit_reported {
                self.artifact_limit_reported = true;
                self.diagnostic(
                    artifact.logical_path(),
                    ScanDiagnosticKind::ArtifactLimitExceeded,
                );
            }
            return;
        }
        self.artifacts.insert(key, artifact);
    }

    pub(crate) fn diagnostic(&mut self, path: &str, kind: ScanDiagnosticKind) {
        self.diagnostics.push(ScanDiagnostic {
            logical_path: path.to_owned(),
            kind,
        });
    }

    pub(crate) fn finish(mut self) -> ScanReport {
        self.diagnostics.sort_unstable();
        self.diagnostics.dedup();
        ScanReport {
            artifacts: self.artifacts.into_values().collect(),
            complete: self.diagnostics.is_empty(),
            diagnostics: self.diagnostics,
        }
    }

    fn open_bounded_file(
        &self,
        root: &RootedPath,
        relative: &Path,
        candidate: &Path,
    ) -> Result<(File, usize, PathBuf), ScanDiagnosticKind> {
        let metadata = fs::symlink_metadata(candidate).map_err(|_| ScanDiagnosticKind::ReadFile)?;
        if metadata.file_type().is_symlink() {
            return Err(ScanDiagnosticKind::UnsafeSymlink);
        }
        if !metadata.is_file() {
            return Err(ScanDiagnosticKind::UnsafeFileType);
        }
        let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if size > self.limits.max_file_bytes {
            return Err(ScanDiagnosticKind::FileTooLarge);
        }
        let resolved = fs::canonicalize(candidate).map_err(|_| ScanDiagnosticKind::ReadFile)?;
        if !resolved.starts_with(&root.root) {
            return Err(ScanDiagnosticKind::UnsafePath);
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        let file = root
            .directory
            .open_with(relative, &options)
            .map_err(|_| ScanDiagnosticKind::UnsafePath)?;
        let metadata = file.metadata().map_err(|_| ScanDiagnosticKind::ReadFile)?;
        if !metadata.is_file() {
            return Err(ScanDiagnosticKind::UnsafeFileType);
        }
        if usize::try_from(metadata.len()).unwrap_or(usize::MAX) > self.limits.max_file_bytes {
            return Err(ScanDiagnosticKind::FileTooLarge);
        }
        Ok((file, size, resolved))
    }

    fn resolve(
        root: &RootedPath,
        relative: &Path,
        expect_directory: bool,
    ) -> Result<Option<PathBuf>, ScanDiagnosticKind> {
        validate_relative_path(relative)?;
        let mut candidate = root.root.clone();
        let components = relative.components().collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                return Err(ScanDiagnosticKind::UnsafePath);
            };
            candidate.push(component);
            let metadata = match fs::symlink_metadata(&candidate) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(ScanDiagnosticKind::ReadFile),
            };
            if metadata.file_type().is_symlink() {
                return Err(ScanDiagnosticKind::UnsafeSymlink);
            }
            let is_last = index + 1 == components.len();
            if !is_last && !metadata.is_dir() {
                return Err(ScanDiagnosticKind::UnsafeFileType);
            }
            if is_last && expect_directory && !metadata.is_dir() {
                return Err(ScanDiagnosticKind::UnsafeFileType);
            }
        }
        let canonical = fs::canonicalize(&candidate).map_err(|_| ScanDiagnosticKind::ReadFile)?;
        if !canonical.starts_with(&root.root) {
            return Err(ScanDiagnosticKind::UnsafePath);
        }
        Ok(Some(candidate))
    }
}

fn validate_relative_path(path: &Path) -> Result<(), ScanDiagnosticKind> {
    if path.as_os_str().is_empty() {
        return Err(ScanDiagnosticKind::UnsafePath);
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ScanDiagnosticKind::UnsafePath);
    }
    Ok(())
}

fn relative_to_logical(path: &Path) -> Result<String, ScanDiagnosticKind> {
    validate_relative_path(path)?;
    let mut logical = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(ScanDiagnosticKind::UnsafePath);
        };
        let component = component.to_str().ok_or(ScanDiagnosticKind::NonUtf8Path)?;
        if !logical.is_empty() {
            logical.push('/');
        }
        logical.push_str(component);
    }
    Ok(logical)
}

pub(crate) fn is_markdown(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("md")
}
