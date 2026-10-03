//! The llama.cpp inference engine as a pinned, digest-verified external binary.
//!
//! PAM itself stays pure Rust; the engine is `llama-server` from one exact
//! upstream GitHub release (`ENGINE_TAG`), one asset per supported target,
//! each pinned by the SHA-256 digest the release API publishes. The archive
//! is fetched with the same resumable curl transfer models use — under the
//! same network profile, from upstream or from an internal mirror that must
//! serve the identical bytes — unpacked by the operating system's own `tar`
//! (which also reads the Windows zip), and the unpacked server must report
//! the pinned build number before it is accepted. The same archive can be
//! supplied from a file on disk ([`import`]): it is copied into the private
//! engine directory and hashed in the same pass, held to the same size and
//! digest, and unpacked and checked the same way, with no network involved.
//! [`remove`] deletes everything under the engine directory. Nothing here
//! runs a model; that is the supervisor's job.
//!
//! Layout under the private base directory:
//!
//! ```text
//! <base>/engine/<asset archive>          transfer target (removed after install)
//! <base>/engine/llama-<tag>/llama-server unpacked release, plus its libraries
//! <base>/engine/.pam-engine.json         manifest: tag, target, digest, version line, source
//! <base>/engine/weights/<sha256>.gguf    the registry's private copies of verified weights
//! <base>/engine/run/                     the supervisor's runtime: socket, API key, pid
//! ```
//!
//! The runtime directory is the supervisor's ([`crate::engine_server`]); it
//! sits under the engine directory, not under the public `<base>/run`, so a
//! sandbox that lets an agent reach the public socket never traverses past
//! the engine's key or socket.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use pam_net::{MirrorBase, NetSettings};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

#[cfg(any(test, feature = "testing"))]
use crate::download::TransferLimits;
use crate::download::{self, DownloadRequest, DownloadState};
use crate::registry::verified_sidecar_path;
use crate::weights::{FREE_SPACE_HEADROOM_BYTES, platform_free_bytes};

/// Chunk size for the import copy: one read is one write is one hash update.
const IMPORT_CHUNK_BYTES: usize = 1024 * 1024;

/// The upstream release tag every target is pinned to.
pub const ENGINE_TAG: &str = "b10938";

/// The build number the unpacked server must report.
pub const ENGINE_BUILD: u64 = 10938;

/// Where the release assets live; the asset name is appended.
pub const ENGINE_RELEASE_BASE: &str =
    "https://github.com/ggml-org/llama.cpp/releases/download/b10938/";

/// One supported operating system and CPU pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    /// Apple Silicon macOS; the asset ships Metal.
    MacosArm64,
    /// x86-64 Windows, CPU build.
    WinCpuX64,
    /// aarch64 Windows, CPU build.
    WinCpuArm64,
}

impl Target {
    /// The target this process runs on, when the release covers it.
    #[must_use]
    pub fn current() -> Option<Self> {
        Self::for_platform(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// The target for an `(os, arch)` pair as `std::env::consts` spells them.
    #[must_use]
    pub fn for_platform(os: &str, arch: &str) -> Option<Self> {
        match (os, arch) {
            ("macos", "aarch64") => Some(Self::MacosArm64),
            ("windows", "x86_64") => Some(Self::WinCpuX64),
            ("windows", "aarch64") => Some(Self::WinCpuArm64),
            _ => None,
        }
    }

    /// The pinned asset for this target.
    #[must_use]
    pub fn asset(self) -> &'static EngineAsset {
        ENGINE_ASSETS
            .iter()
            .find(|asset| asset.target == self)
            .expect("every target has one pinned asset")
    }

    /// The name the manifest records.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::MacosArm64 => "macos-arm64",
            Self::WinCpuX64 => "win-cpu-x64",
            Self::WinCpuArm64 => "win-cpu-arm64",
        }
    }

    fn server_file_name(self) -> &'static str {
        match self {
            Self::WinCpuX64 | Self::WinCpuArm64 => "llama-server.exe",
            Self::MacosArm64 => "llama-server",
        }
    }
}

/// One release archive, pinned by name, digest and size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineAsset {
    /// Which target the archive is for.
    pub target: Target,
    /// The asset file name as published.
    pub name: &'static str,
    /// Lowercase hex SHA-256 of the archive, from the release API.
    pub sha256: &'static str,
    /// The archive size in bytes.
    pub bytes: u64,
}

/// Every pinned asset for [`ENGINE_TAG`], one per supported target.
pub const ENGINE_ASSETS: [EngineAsset; 3] = [
    EngineAsset {
        target: Target::MacosArm64,
        name: "llama-b10938-bin-macos-arm64.tar.gz",
        sha256: "69f236c8aa148eb32bfd76774a0a449e2f9b754c595e8f6d90b12cf7fecb8399",
        bytes: 11_146_574,
    },
    EngineAsset {
        target: Target::WinCpuX64,
        name: "llama-b10938-bin-win-cpu-x64.zip",
        sha256: "ba39502946f4c0e966e5e93393618953dc4c005a252fbaf8c9786c33a9f8b60d",
        bytes: 18_426_584,
    },
    EngineAsset {
        target: Target::WinCpuArm64,
        name: "llama-b10938-bin-win-cpu-arm64.zip",
        sha256: "85bc7b14a62092e17beca76295a0e1cbe88510f02623c3b18707ca470c06faeb",
        bytes: 11_994_892,
    },
];

/// A release to install: the pinned one in production, a synthetic one in
/// tests. Owned strings so a test can point at its own archive and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRelease {
    /// Release tag, e.g. `b10938`.
    pub tag: String,
    /// The build number `llama-server --version` must report.
    pub build: u64,
    /// URL prefix the asset name is appended to.
    pub url_base: String,
    /// The target this release is being installed for.
    pub target: Target,
    /// Archive file name.
    pub asset_name: String,
    /// Lowercase hex SHA-256 the archive must hash to.
    pub sha256: String,
    /// Size the archive must have.
    pub bytes: u64,
}

impl EngineRelease {
    /// The pinned upstream release for `target`.
    #[must_use]
    pub fn pinned(target: Target) -> Self {
        let asset = target.asset();
        Self {
            tag: ENGINE_TAG.to_owned(),
            build: ENGINE_BUILD,
            url_base: ENGINE_RELEASE_BASE.to_owned(),
            target,
            asset_name: asset.name.to_owned(),
            sha256: asset.sha256.to_owned(),
            bytes: asset.bytes,
        }
    }

    /// Where the archive is fetched from: the pinned asset name under the
    /// release base, or under `mirror` when one is set. Only the host
    /// changes; the name, size and digest the bytes are held to do not.
    pub fn url(&self, mirror: Option<&MirrorBase>) -> Result<String, EngineError> {
        match mirror {
            Some(mirror) => mirror
                .join(&self.asset_name)
                .map(String::from)
                .map_err(|error| EngineError::Download {
                    cause: "mirror_invalid".to_owned(),
                    detail: error.to_string(),
                }),
            None => Ok(format!("{}{}", self.url_base, self.asset_name)),
        }
    }

    /// The host of [`Self::url`]: the mirror's, or the upstream release
    /// host.
    #[must_use]
    pub fn host(&self, mirror: Option<&MirrorBase>) -> String {
        match mirror {
            Some(mirror) => mirror.host().to_owned(),
            None => url_host(&self.url_base),
        }
    }

    /// The source a download of this release records in the manifest.
    fn download_source(&self, mirror: Option<&MirrorBase>) -> EngineSource {
        match mirror {
            Some(mirror) => EngineSource::Mirror {
                host: mirror.host().to_owned(),
                url: self.url(Some(mirror)).unwrap_or_default(),
            },
            None => EngineSource::Download {
                host: url_host(&self.url_base),
            },
        }
    }
}

/// The host part of an `https://host/...` string, without a URL parser:
/// the release base is a compiled-in constant.
fn url_host(url: &str) -> String {
    url.split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Where an installed engine's archive came from, as the manifest records
/// it and the GUI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineSource {
    /// Fetched from the upstream release host.
    Download {
        /// The host the archive was fetched from.
        host: String,
    },
    /// Fetched from the human's configured mirror.
    Mirror {
        /// The mirror's host.
        host: String,
        /// The exact URL fetched.
        url: String,
    },
    /// Copied from a file on this machine; the original was left as it was.
    Import {
        /// The path the human gave (the file, or the folder holding it).
        path: String,
        /// Unix milliseconds when the copy was made.
        imported_at_ms: i64,
    },
}

/// Name of the supervisor's runtime directory under the engine directory.
pub const RUNTIME_DIR: &str = "run";

/// Where the engine lives under a private base directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLayout {
    root: PathBuf,
}

impl EngineLayout {
    /// `<base>/engine`.
    #[must_use]
    pub fn new(base: &Path) -> Self {
        Self {
            root: base.join("engine"),
        }
    }

    /// The engine directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The supervisor's private runtime directory, `<base>/engine/run`:
    /// the engine's socket, its per-load API key file and its pid file
    /// ([`crate::engine_server::EngineServer::new`] takes it).
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        self.root.join(RUNTIME_DIR)
    }

    /// Where the archive is downloaded to.
    #[must_use]
    pub fn archive_path(&self, asset_name: &str) -> PathBuf {
        self.root.join(asset_name)
    }

    /// The unpacked release directory for `tag`.
    #[must_use]
    pub fn install_dir(&self, tag: &str) -> PathBuf {
        self.root.join(format!("llama-{tag}"))
    }

    /// The manifest describing what is installed.
    #[must_use]
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join(".pam-engine.json")
    }

    /// The server binary for `tag` on `target`.
    #[must_use]
    pub fn server_path(&self, tag: &str, target: Target) -> PathBuf {
        self.install_dir(tag).join(target.server_file_name())
    }
}

/// What an install recorded, read back by [`status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineManifest {
    /// Release tag installed.
    pub tag: String,
    /// Build number the server reported.
    pub build: u64,
    /// Target the archive was for.
    pub target: Target,
    /// Archive name.
    pub asset: String,
    /// Archive digest that was verified.
    pub sha256: String,
    /// Archive size that was verified.
    pub bytes: u64,
    /// The first line `llama-server --version` printed.
    pub version_line: String,
    /// Unix milliseconds when the install completed.
    pub installed_at_ms: i64,
    /// Where the archive came from. Absent in manifests an older PAM wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<EngineSource>,
}

/// The engine's state for the GUI and the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatus {
    /// The pinned tag this build of PAM expects.
    pub expected_tag: String,
    /// The pinned build number.
    pub expected_build: u64,
    /// This platform's target, when the release covers it.
    pub target: Option<Target>,
    /// Whether the manifest records the pinned tag, build and target and
    /// the server file it names is present. Read from files only: the
    /// digest was verified when the manifest was written, and the binary is
    /// not re-hashed or re-run here.
    pub installed: bool,
    /// The server binary, when installed.
    pub server_path: Option<PathBuf>,
    /// The manifest, when one is present and matches the pinned tag.
    pub manifest: Option<EngineManifest>,
    /// Why the engine is not usable, when it is not.
    pub cause: Option<String>,
}

/// Why an install did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// No pinned asset for this operating system and CPU.
    #[error("no llama.cpp release asset for {os}/{arch}")]
    UnsupportedTarget {
        /// `std::env::consts::OS`.
        os: String,
        /// `std::env::consts::ARCH`.
        arch: String,
    },
    /// The archive transfer failed; `cause` is the downloader's cause.
    #[error("engine download failed ({cause}): {detail}")]
    Download {
        /// Downloader cause, e.g. `digest_mismatch`.
        cause: String,
        /// What happened.
        detail: String,
    },
    /// The human cancelled the transfer.
    #[error("engine download cancelled")]
    Cancelled,
    /// The operating system's `tar` is missing or refused the archive.
    #[error("engine archive could not be unpacked: {detail}")]
    Unpack {
        /// What tar said.
        detail: String,
    },
    /// The unpacked server did not prove it is the pinned build.
    #[error("engine verification failed: {detail}")]
    Verify {
        /// What the server printed, or why it could not run.
        detail: String,
    },
    /// A filesystem step failed.
    #[error("engine install I/O failed: {detail}")]
    Io {
        /// Which step.
        detail: String,
    },
    /// The path given to [`import`] does not exist or cannot be read.
    #[error("{path} does not exist or cannot be read")]
    SourceMissing {
        /// The path as given.
        path: String,
    },
    /// The path given to [`import`] is not the pinned archive: a file with
    /// another name, a folder without the archive in it, or an unpacked
    /// tree (which has no digest to check).
    #[error(
        "{found} is not the pinned engine archive; this build of PAM needs `{expected}` \
         ({bytes} bytes, SHA-256 {sha256}), the release archive itself, or a folder that \
         contains it under that exact name"
    )]
    NotTheAsset {
        /// What was found at the path.
        found: String,
        /// The pinned asset's file name.
        expected: String,
        /// The pinned asset's size.
        bytes: u64,
        /// The pinned asset's digest.
        sha256: String,
    },
    /// The source, or the archive inside the given folder, is a symbolic link.
    #[error("{path} is a symbolic link; give the path of the archive file itself")]
    SourceSymlink {
        /// The link.
        path: String,
    },
    /// The source sits inside the engine directory the install would rewrite.
    #[error("{path} is inside PAM's engine directory, which the install replaces")]
    SourceInsideEngineDir {
        /// The source.
        path: String,
    },
    /// The source file's size is not the pinned size; nothing was copied.
    #[error("the file is {actual} bytes; the pinned archive {expected_name} is {expected} bytes")]
    SizeMismatch {
        /// The pinned size.
        expected: u64,
        /// The file's size.
        actual: u64,
        /// The pinned asset's file name.
        expected_name: String,
    },
    /// The copied bytes do not hash to the pinned digest; the copy was deleted.
    #[error(
        "the file hashes to sha256:{actual}; this build of PAM pins llama.cpp {tag} with \
         sha256:{expected}, and installs nothing else"
    )]
    DigestMismatch {
        /// The pinned digest.
        expected: String,
        /// What the bytes hashed to.
        actual: String,
        /// The pinned tag.
        tag: String,
    },
    /// The volume holding the engine directory cannot take the copy.
    #[error(
        "not enough disk space under {dir} for the engine archive: {needed} bytes needed, {} free",
        free.map_or_else(|| "an unknown amount".to_owned(), |bytes| format!("{bytes} bytes"))
    )]
    NoSpace {
        /// The engine directory.
        dir: PathBuf,
        /// Bytes the copy needs, headroom included.
        needed: u64,
        /// Bytes free there, when known.
        free: Option<u64>,
    },
}

fn io(step: &str, error: &std::io::Error) -> EngineError {
    EngineError::Io {
        detail: format!("{step}: {error}"),
    }
}

/// The engine's state under `base`, from files only: no process is run.
#[must_use]
pub fn status(base: &Path) -> EngineStatus {
    status_for(base, ENGINE_TAG, ENGINE_BUILD, Target::current())
}

fn status_for(base: &Path, tag: &str, build: u64, target: Option<Target>) -> EngineStatus {
    let layout = EngineLayout::new(base);
    let mut status = EngineStatus {
        expected_tag: tag.to_owned(),
        expected_build: build,
        target,
        installed: false,
        server_path: None,
        manifest: None,
        cause: None,
    };
    let Some(target) = target else {
        status.cause = Some("unsupported_target".to_owned());
        return status;
    };
    let Ok(bytes) = std::fs::read(layout.manifest_path()) else {
        status.cause = Some("not_installed".to_owned());
        return status;
    };
    let Ok(manifest) = serde_json::from_slice::<EngineManifest>(&bytes) else {
        status.cause = Some("manifest_invalid".to_owned());
        return status;
    };
    if manifest.tag != tag || manifest.build != build || manifest.target != target {
        status.manifest = Some(manifest);
        status.cause = Some("stale_release".to_owned());
        return status;
    }
    let server = layout.server_path(&manifest.tag, target);
    if !server.is_file() {
        status.manifest = Some(manifest);
        status.cause = Some("server_missing".to_owned());
        return status;
    }
    status.installed = true;
    status.server_path = Some(server);
    status.manifest = Some(manifest);
    status
}

/// Installs the pinned release for this platform under `base`, or reports
/// the installed one. The archive is fetched under the network profile
/// `net`, from upstream or from `mirror`; either way it must hash to the
/// pinned digest. `cancel` stops the transfer; a cancelled transfer keeps
/// its part file for a resume.
pub async fn install(
    base: &Path,
    cancel: watch::Receiver<bool>,
    net: Arc<NetSettings>,
    mirror: Option<&MirrorBase>,
) -> Result<EngineStatus, EngineError> {
    let target = Target::current().ok_or_else(|| EngineError::UnsupportedTarget {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    })?;
    install_with(
        base,
        &EngineRelease::pinned(target),
        cancel,
        net,
        mirror,
        false,
    )
    .await
}

/// [`install`] for an explicit release. Test builds and the `testing`
/// feature only: production has no entry point that takes a release, so no
/// setting, argument or file can install anything but the pinned one.
#[cfg(any(test, feature = "testing"))]
pub async fn install_release(
    base: &Path,
    release: &EngineRelease,
    cancel: watch::Receiver<bool>,
    net: Arc<NetSettings>,
    mirror: Option<&MirrorBase>,
) -> Result<EngineStatus, EngineError> {
    install_with(base, release, cancel, net, mirror, false).await
}

/// [`install_release`] with the archive fetched over plain `http` from a
/// loopback origin: the test allowance, for the fake-release tests here and
/// in the daemon. Test builds and the `testing` feature only.
#[cfg(any(test, feature = "testing"))]
pub async fn install_release_over_plain_http_for_tests(
    base: &Path,
    release: &EngineRelease,
    cancel: watch::Receiver<bool>,
    net: Arc<NetSettings>,
    mirror: Option<&MirrorBase>,
) -> Result<EngineStatus, EngineError> {
    install_with(base, release, cancel, net, mirror, true).await
}

async fn install_with(
    base: &Path,
    release: &EngineRelease,
    cancel: watch::Receiver<bool>,
    net: Arc<NetSettings>,
    mirror: Option<&MirrorBase>,
    plain_http: bool,
) -> Result<EngineStatus, EngineError> {
    let layout = EngineLayout::new(base);
    if let Some(current) = already_installed(base, release) {
        return Ok(current);
    }
    create_private_dir(layout.root())?;
    let archive = fetch_archive(&layout, release, cancel, net, mirror, plain_http).await?;
    finish_install(base, release, &archive, release.download_source(mirror)).await
}

/// Installs the pinned release for this platform from `path`: the pinned
/// archive file by its exact name, or a folder holding it under that name.
/// The file is copied into the engine directory and hashed in the same
/// pass, held to the pinned size and digest, and from there installed
/// exactly like a downloaded archive. The original is never modified, moved
/// or deleted, and no network is used. `cancel` stops the copy.
pub async fn import(
    base: &Path,
    path: &Path,
    cancel: watch::Receiver<bool>,
) -> Result<EngineStatus, EngineError> {
    let target = Target::current().ok_or_else(|| EngineError::UnsupportedTarget {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    })?;
    import_with(base, &EngineRelease::pinned(target), path, cancel).await
}

/// [`import`] for an explicit release. Test builds and the `testing`
/// feature only, for the same reason as [`install_release`].
#[cfg(any(test, feature = "testing"))]
pub async fn import_release(
    base: &Path,
    release: &EngineRelease,
    path: &Path,
    cancel: watch::Receiver<bool>,
) -> Result<EngineStatus, EngineError> {
    import_with(base, release, path, cancel).await
}

async fn import_with(
    base: &Path,
    release: &EngineRelease,
    path: &Path,
    cancel: watch::Receiver<bool>,
) -> Result<EngineStatus, EngineError> {
    let layout = EngineLayout::new(base);
    if let Some(current) = already_installed(base, release) {
        return Ok(current);
    }
    let source = locate_source(&layout, release, path)?;
    create_private_dir(layout.root())?;
    let archive = layout.archive_path(&release.asset_name);
    if archive.exists() {
        std::fs::remove_file(&archive).map_err(|e| io("remove stale archive", &e))?;
        let _ = std::fs::remove_file(verified_sidecar_path(&archive));
    }
    copy_archive(&layout, release, &source, &archive, cancel).await?;
    let given = path.display().to_string();
    finish_install(
        base,
        release,
        &archive,
        EngineSource::Import {
            path: given,
            imported_at_ms: now_ms(),
        },
    )
    .await
}

/// The installed status when the manifest already records this exact
/// release and digest and its server is present: nothing to do.
fn already_installed(base: &Path, release: &EngineRelease) -> Option<EngineStatus> {
    let current = status_for(base, &release.tag, release.build, Some(release.target));
    (current.installed
        && current
            .manifest
            .as_ref()
            .is_some_and(|m| m.sha256 == release.sha256))
    .then_some(current)
}

/// Unpacks a verified archive, requires the server to report the pinned
/// build, moves the release into place and writes the manifest. The archive
/// is removed whatever happens.
async fn finish_install(
    base: &Path,
    release: &EngineRelease,
    archive: &Path,
    source: EngineSource,
) -> Result<EngineStatus, EngineError> {
    let layout = EngineLayout::new(base);
    let scratch = layout.root().join(format!(
        ".unpack-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let verified = unpack_and_verify(archive, &scratch, release).await;
    let _ = std::fs::remove_file(archive);
    // The downloader no longer writes a verification sidecar, but an older pam
    // did; one left beside an archive that is about to be deleted is litter.
    let _ = std::fs::remove_file(verified_sidecar_path(archive));
    let (server_dir, version_line) = match verified {
        Ok(found) => found,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&scratch);
            return Err(error);
        }
    };
    let install_dir = layout.install_dir(&release.tag);
    let _ = std::fs::remove_dir_all(&install_dir);
    let moved = std::fs::rename(&server_dir, &install_dir);
    let _ = std::fs::remove_dir_all(&scratch);
    moved.map_err(|e| io("install unpacked release", &e))?;
    write_manifest(&layout, release, version_line, source)?;
    Ok(status_for(
        base,
        &release.tag,
        release.build,
        Some(release.target),
    ))
}

/// The archive file an import reads: `path` itself when it is a file named
/// exactly like the pinned asset, `path/<asset>` when it is a folder.
/// Anything else is refused by name; a symbolic link at either level is
/// refused rather than followed; a source inside the engine directory is
/// refused because the install would delete it.
fn locate_source(
    layout: &EngineLayout,
    release: &EngineRelease,
    path: &Path,
) -> Result<PathBuf, EngineError> {
    let not_the_asset = |found: String| EngineError::NotTheAsset {
        found,
        expected: release.asset_name.clone(),
        bytes: release.bytes,
        sha256: release.sha256.clone(),
    };
    let given = std::fs::symlink_metadata(path).map_err(|_| EngineError::SourceMissing {
        path: path.display().to_string(),
    })?;
    if given.file_type().is_symlink() {
        return Err(EngineError::SourceSymlink {
            path: path.display().to_string(),
        });
    }
    let candidate = if given.is_dir() {
        let inside = path.join(&release.asset_name);
        let meta = std::fs::symlink_metadata(&inside).map_err(|_| {
            not_the_asset(format!(
                "the folder {} holds no `{}`",
                path.display(),
                release.asset_name
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(EngineError::SourceSymlink {
                path: inside.display().to_string(),
            });
        }
        if !meta.is_file() {
            return Err(not_the_asset(format!(
                "{} is not a regular file",
                inside.display()
            )));
        }
        inside
    } else if given.is_file() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name != release.asset_name {
            return Err(not_the_asset(format!("the file `{name}`")));
        }
        path.to_path_buf()
    } else {
        return Err(not_the_asset(format!(
            "{} is neither a file nor a folder",
            path.display()
        )));
    };
    // Compared canonicalized so a path spelled differently (a `..`, a
    // symlinked parent) cannot name a file under the engine directory.
    if let (Ok(root), Ok(real)) = (layout.root().canonicalize(), candidate.canonicalize())
        && real.starts_with(root)
    {
        return Err(EngineError::SourceInsideEngineDir {
            path: candidate.display().to_string(),
        });
    }
    Ok(candidate)
}

/// Copies the located source into `archive` while hashing the same bytes,
/// off the async threads. The handle is opened once and its size checked on
/// that handle before a byte is written; the digest is compared when the
/// copy is complete, and a copy that does not match, is cancelled or fails
/// is deleted.
async fn copy_archive(
    layout: &EngineLayout,
    release: &EngineRelease,
    source: &Path,
    archive: &Path,
    cancel: watch::Receiver<bool>,
) -> Result<(), EngineError> {
    let mut file = std::fs::File::open(source).map_err(|_| EngineError::SourceMissing {
        path: source.display().to_string(),
    })?;
    let meta = file
        .metadata()
        .map_err(|e| io("read source metadata", &e))?;
    if !meta.is_file() {
        return Err(EngineError::NotTheAsset {
            found: format!("{} is not a regular file", source.display()),
            expected: release.asset_name.clone(),
            bytes: release.bytes,
            sha256: release.sha256.clone(),
        });
    }
    if meta.len() != release.bytes {
        return Err(EngineError::SizeMismatch {
            expected: release.bytes,
            actual: meta.len(),
            expected_name: release.asset_name.clone(),
        });
    }
    let needed = release.bytes.saturating_add(FREE_SPACE_HEADROOM_BYTES);
    let free = platform_free_bytes(layout.root());
    if free.is_some_and(|free| free < needed) {
        return Err(EngineError::NoSpace {
            dir: layout.root().to_path_buf(),
            needed,
            free,
        });
    }
    let dest = archive.to_path_buf();
    let expected_len = release.bytes;
    let copied = tokio::task::spawn_blocking(move || {
        let outcome = copy_hashing_from(&mut file, &dest, expected_len, &cancel);
        if outcome.is_err() {
            let _ = std::fs::remove_file(&dest);
        }
        outcome
    })
    .await
    .map_err(|e| EngineError::Io {
        detail: format!("the copy task panicked: {e}"),
    })?;
    let (sha256, copied_bytes) = copied?;
    if copied_bytes != release.bytes {
        let _ = std::fs::remove_file(archive);
        return Err(EngineError::SizeMismatch {
            expected: release.bytes,
            actual: copied_bytes,
            expected_name: release.asset_name.clone(),
        });
    }
    if sha256 != release.sha256 {
        let _ = std::fs::remove_file(archive);
        return Err(EngineError::DigestMismatch {
            expected: release.sha256.clone(),
            actual: sha256,
            tag: release.tag.clone(),
        });
    }
    Ok(())
}

/// Streams `source` into a new owner-only file at `dest`, hashing exactly
/// the bytes written; stops at `expected_len` so a file that grows under
/// the copy cannot fill the disk, and stops when `cancel` says so.
fn copy_hashing_from(
    source: &mut std::fs::File,
    dest: &Path,
    expected_len: u64,
    cancel: &watch::Receiver<bool>,
) -> Result<(String, u64), EngineError> {
    use sha2::Digest as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut writer = options
        .open(dest)
        .map_err(|e| io("create private archive", &e))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; IMPORT_CHUNK_BYTES];
    let mut total: u64 = 0;
    while total < expected_len {
        if *cancel.borrow() {
            return Err(EngineError::Cancelled);
        }
        let want = usize::try_from((expected_len - total).min(IMPORT_CHUNK_BYTES as u64))
            .unwrap_or(IMPORT_CHUNK_BYTES);
        let read = source
            .read(&mut buffer[..want])
            .map_err(|e| io("read source archive", &e))?;
        if read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|e| io("write private archive", &e))?;
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
    }
    writer
        .sync_all()
        .map_err(|e| io("sync private archive", &e))?;
    Ok((hex::encode(hasher.finalize()), total))
}

/// What [`remove`] deleted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoveReport {
    /// The engine directory.
    pub engine_dir: PathBuf,
    /// The names of the top-level entries removed from it.
    pub removed: Vec<String>,
}

/// Deletes everything under `<base>/engine`: the archive if one is there,
/// the unpacked release, the manifest, the registry's private weight copies,
/// the supervisor's runtime directory and any scratch directory. The directory itself
/// stays (private, empty). The models directory is never touched. Whether
/// a model is loaded is the caller's knowledge, and the caller refuses then.
pub fn remove(base: &Path) -> Result<RemoveReport, EngineError> {
    let layout = EngineLayout::new(base);
    let mut report = RemoveReport {
        engine_dir: layout.root().to_path_buf(),
        removed: Vec::new(),
    };
    let entries = match std::fs::read_dir(layout.root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(io("read engine directory", &error)),
    };
    let mut names: Vec<(String, PathBuf, bool)> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io("read engine directory", &e))?;
        let is_dir = entry
            .file_type()
            .map_err(|e| io("read engine directory", &e))?
            .is_dir();
        names.push((
            entry.file_name().to_string_lossy().into_owned(),
            entry.path(),
            is_dir,
        ));
    }
    // The manifest goes first: a failure part-way then reads as "not
    // installed" rather than as an install whose files are half gone.
    names.sort_by_key(|(name, _, _)| name != ".pam-engine.json");
    for (name, path, is_dir) in names {
        let gone = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        gone.map_err(|e| io(&format!("remove {name}"), &e))?;
        report.removed.push(name);
    }
    Ok(report)
}

/// Unix milliseconds now, saturating.
fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default(),
    )
    .unwrap_or(i64::MAX)
}

/// Fetches the archive with the resumable transfer models use; the
/// downloader refuses a digest or size mismatch before the file lands.
async fn fetch_archive(
    layout: &EngineLayout,
    release: &EngineRelease,
    mut cancel: watch::Receiver<bool>,
    net: Arc<NetSettings>,
    mirror: Option<&MirrorBase>,
    plain_http: bool,
) -> Result<PathBuf, EngineError> {
    let archive = layout.archive_path(&release.asset_name);
    if archive.exists() {
        std::fs::remove_file(&archive).map_err(|e| io("remove stale archive", &e))?;
        let _ = std::fs::remove_file(verified_sidecar_path(&archive));
    }
    let request = DownloadRequest {
        url: release.url(mirror)?,
        dest: archive.clone(),
        expected_size: Some(release.bytes),
        expected_sha256: Some(release.sha256.clone()),
        license_id: None,
    };
    #[cfg(any(test, feature = "testing"))]
    let started = if plain_http {
        download::start_over_plain_http_for_tests(request, net, TransferLimits::default())
    } else {
        download::start(request, net)
    };
    #[cfg(not(any(test, feature = "testing")))]
    let started = {
        // Production has no plain-http path: the flag is never set outside tests.
        let _ = plain_http;
        download::start(request, net)
    };
    let handle = started.map_err(|e| EngineError::Download {
        cause: match &e {
            download::DownloadError::Network(failure) => failure.cause().to_owned(),
            download::DownloadError::CurlMissing => "curl_missing".to_owned(),
            _ => "start".to_owned(),
        },
        detail: e.to_string(),
    })?;
    let outcome = tokio::select! {
        state = handle.wait() => state,
        () = cancelled(&mut cancel) => {
            handle.cancel();
            handle.wait().await
        }
    };
    match outcome {
        DownloadState::Done { .. } => Ok(archive),
        DownloadState::Cancelled => Err(EngineError::Cancelled),
        DownloadState::Failed { cause, detail } => Err(EngineError::Download { cause, detail }),
        DownloadState::Running(_) => Err(EngineError::Download {
            cause: "incomplete".to_owned(),
            detail: "the transfer ended without a terminal state".to_owned(),
        }),
    }
}

/// Unpacks into `scratch` with the OS tar, finds the server, and requires
/// it to report the pinned build. Returns the directory holding it.
async fn unpack_and_verify(
    archive: &Path,
    scratch: &Path,
    release: &EngineRelease,
) -> Result<(PathBuf, String), EngineError> {
    let _ = std::fs::remove_dir_all(scratch);
    create_private_dir(scratch)?;
    unpack(archive, scratch).await?;
    let server_name = release.target.server_file_name();
    let server_dir =
        find_server_dir(scratch, server_name, 3).ok_or_else(|| EngineError::Verify {
            detail: "the archive holds no llama-server".to_owned(),
        })?;
    let version_line = verify_build(&server_dir.join(server_name), release.build).await?;
    Ok((server_dir, version_line))
}

fn write_manifest(
    layout: &EngineLayout,
    release: &EngineRelease,
    version_line: String,
    source: EngineSource,
) -> Result<(), EngineError> {
    let manifest = EngineManifest {
        tag: release.tag.clone(),
        build: release.build,
        target: release.target,
        asset: release.asset_name.clone(),
        sha256: release.sha256.clone(),
        bytes: release.bytes,
        version_line,
        installed_at_ms: now_ms(),
        source: Some(source),
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| EngineError::Io {
        detail: format!("encode manifest: {e}"),
    })?;
    // Through a temporary file and a rename, so a crash mid-write leaves
    // the previous manifest (or none) rather than a truncated one that
    // `status` would report as `manifest_invalid`.
    let path = layout.manifest_path();
    let temp = layout.root().join(".pam-engine.json.tmp");
    std::fs::write(&temp, bytes).map_err(|e| io("write manifest", &e))?;
    std::fs::rename(&temp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        io("publish manifest", &e)
    })
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn create_private_dir(path: &Path) -> Result<(), EngineError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| io("create engine directory", &e))
}

/// The operating system's own `tar`: `/usr/bin/tar` on macOS,
/// `%SystemRoot%\System32\tar.exe` on Windows (it reads zip archives too).
pub fn trusted_tar_path() -> Result<PathBuf, EngineError> {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").ok_or_else(|| EngineError::Unpack {
            detail: "SystemRoot is not set".to_owned(),
        })?;
        let path = PathBuf::from(root).join("System32").join("tar.exe");
        if path.is_file() {
            return Ok(path);
        }
        Err(EngineError::Unpack {
            detail: format!("{} is missing", path.display()),
        })
    }
    #[cfg(not(windows))]
    {
        let path = PathBuf::from("/usr/bin/tar");
        let canonical = std::fs::canonicalize(&path).map_err(|e| EngineError::Unpack {
            detail: format!("/usr/bin/tar unavailable: {e}"),
        })?;
        if canonical.is_file() {
            Ok(path)
        } else {
            Err(EngineError::Unpack {
                detail: "/usr/bin/tar is not a file".to_owned(),
            })
        }
    }
}

async fn unpack(archive: &Path, into: &Path) -> Result<(), EngineError> {
    let tar = trusted_tar_path()?;
    let mut command = tokio::process::Command::new(tar);
    command
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(into)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    #[cfg(not(windows))]
    command.env("PATH", "/usr/bin:/bin");
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| EngineError::Unpack {
            detail: "tar did not finish within 120 s".to_owned(),
        })?
        .map_err(|e| EngineError::Unpack {
            detail: format!("tar could not start: {e}"),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(EngineError::Unpack {
            detail: format!(
                "tar exited with {}: {}",
                output.status,
                stderr.chars().take(400).collect::<String>()
            ),
        })
    }
}

/// The directory holding `server_name`, at most `depth` levels below
/// `root`, shallowest first.
fn find_server_dir(root: &Path, server_name: &str, depth: usize) -> Option<PathBuf> {
    if root.join(server_name).is_file() {
        return Some(root.to_path_buf());
    }
    if depth == 0 {
        return None;
    }
    let mut children: Vec<PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    children.sort();
    children
        .into_iter()
        .find_map(|child| find_server_dir(&child, server_name, depth - 1))
}

/// Runs `llama-server --version` with a scrubbed environment and returns
/// its first line when it names `build`.
async fn verify_build(server: &Path, build: u64) -> Result<String, EngineError> {
    let mut command = tokio::process::Command::new(server);
    command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    // The first launch of a freshly unpacked binary can take tens of
    // seconds on macOS (first-run system checks) and on slow CI hosts;
    // later launches answer in milliseconds.
    let output = tokio::time::timeout(Duration::from_secs(120), command.output())
        .await
        .map_err(|_| EngineError::Verify {
            detail: "llama-server --version did not answer within 120 s".to_owned(),
        })?
        .map_err(|e| EngineError::Verify {
            detail: format!("llama-server could not start: {e}"),
        })?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let needle = format!("(build {build},");
    let line = text
        .lines()
        .find(|line| line.contains(&needle))
        .map(str::trim)
        .map(str::to_owned);
    line.ok_or_else(|| EngineError::Verify {
        detail: format!(
            "llama-server did not report build {build}: {}",
            text.chars().take(200).collect::<String>()
        ),
    })
}

#[cfg(test)]
#[path = "engine_test.rs"]
mod tests;
