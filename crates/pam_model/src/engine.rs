//! The llama.cpp inference engine as a pinned, digest-verified external binary.
//!
//! PAM itself stays pure Rust; the engine is `llama-server` from one exact
//! upstream GitHub release (`ENGINE_TAG`), one asset per supported target,
//! each pinned by the SHA-256 digest the release API publishes. The archive
//! is fetched with the same resumable curl transfer models use, unpacked by
//! the operating system's own `tar` (which also reads the Windows zip), and
//! the unpacked server must report the pinned build number before it is
//! accepted. Nothing here runs a model; that is the supervisor's job.
//!
//! Layout under the private base directory:
//!
//! ```text
//! <base>/engine/<asset archive>          transfer target (removed after install)
//! <base>/engine/llama-<tag>/llama-server unpacked release, plus its libraries
//! <base>/engine/.pam-engine.json         manifest: tag, target, digest, version line
//! ```

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::download::{self, DownloadRequest, DownloadState};

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
    /// Intel macOS.
    MacosX64,
    /// x86-64 Linux built on Ubuntu.
    UbuntuX64,
    /// aarch64 Linux built on Ubuntu.
    UbuntuArm64,
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
            ("macos", "x86_64") => Some(Self::MacosX64),
            ("linux", "x86_64") => Some(Self::UbuntuX64),
            ("linux", "aarch64") => Some(Self::UbuntuArm64),
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
            Self::MacosX64 => "macos-x64",
            Self::UbuntuX64 => "ubuntu-x64",
            Self::UbuntuArm64 => "ubuntu-arm64",
            Self::WinCpuX64 => "win-cpu-x64",
            Self::WinCpuArm64 => "win-cpu-arm64",
        }
    }

    fn server_file_name(self) -> &'static str {
        match self {
            Self::WinCpuX64 | Self::WinCpuArm64 => "llama-server.exe",
            _ => "llama-server",
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
pub const ENGINE_ASSETS: [EngineAsset; 6] = [
    EngineAsset {
        target: Target::MacosArm64,
        name: "llama-b10938-bin-macos-arm64.tar.gz",
        sha256: "69f236c8aa148eb32bfd76774a0a449e2f9b754c595e8f6d90b12cf7fecb8399",
        bytes: 11_146_574,
    },
    EngineAsset {
        target: Target::MacosX64,
        name: "llama-b10938-bin-macos-x64.tar.gz",
        sha256: "13179741dd10cc0642cc5d09a69a08b6e3f59af40e70d4803c9f6f0b5a0bc10a",
        bytes: 11_194_750,
    },
    EngineAsset {
        target: Target::UbuntuX64,
        name: "llama-b10938-bin-ubuntu-x64.tar.gz",
        sha256: "adbd216b2453b79e3874a406bee21e59d1b0ba06df567102ab8a69aa3dd200dd",
        bytes: 16_820_989,
    },
    EngineAsset {
        target: Target::UbuntuArm64,
        name: "llama-b10938-bin-ubuntu-arm64.tar.gz",
        sha256: "647e257dbdd08ebe28143b3ade534d2659a0360e7c82b7505df22a4b6608ccc3",
        bytes: 13_449_176,
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

    fn url(&self) -> String {
        format!("{}{}", self.url_base, self.asset_name)
    }
}

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
    /// Whether a verified server for the pinned tag is present.
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
/// the installed one. `cancel` stops the transfer; a cancelled transfer
/// keeps its part file for a resume.
pub async fn install(
    base: &Path,
    cancel: watch::Receiver<bool>,
) -> Result<EngineStatus, EngineError> {
    let target = Target::current().ok_or_else(|| EngineError::UnsupportedTarget {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
    })?;
    install_release(base, &EngineRelease::pinned(target), cancel).await
}

/// [`install`] for an explicit release; production passes the pinned one.
pub async fn install_release(
    base: &Path,
    release: &EngineRelease,
    cancel: watch::Receiver<bool>,
) -> Result<EngineStatus, EngineError> {
    let layout = EngineLayout::new(base);
    let current = status_for(base, &release.tag, release.build, Some(release.target));
    if current.installed
        && current
            .manifest
            .as_ref()
            .is_some_and(|m| m.sha256 == release.sha256)
    {
        return Ok(current);
    }
    create_private_dir(layout.root())?;
    let archive = fetch_archive(&layout, release, cancel).await?;
    let scratch = layout.root().join(format!(
        ".unpack-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let verified = unpack_and_verify(&archive, &scratch, release).await;
    let _ = std::fs::remove_file(&archive);
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
    write_manifest(&layout, release, version_line)?;
    Ok(status_for(
        base,
        &release.tag,
        release.build,
        Some(release.target),
    ))
}

/// Fetches the archive with the resumable transfer models use; the
/// downloader refuses a digest or size mismatch before the file lands.
async fn fetch_archive(
    layout: &EngineLayout,
    release: &EngineRelease,
    mut cancel: watch::Receiver<bool>,
) -> Result<PathBuf, EngineError> {
    let archive = layout.archive_path(&release.asset_name);
    if archive.exists() {
        std::fs::remove_file(&archive).map_err(|e| io("remove stale archive", &e))?;
    }
    let handle = download::start(DownloadRequest {
        url: release.url(),
        dest: archive.clone(),
        expected_size: Some(release.bytes),
        expected_sha256: Some(release.sha256.clone()),
        license_id: None,
    })
    .map_err(|e| EngineError::Download {
        cause: "start".to_owned(),
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
) -> Result<(), EngineError> {
    let manifest = EngineManifest {
        tag: release.tag.clone(),
        build: release.build,
        target: release.target,
        asset: release.asset_name.clone(),
        sha256: release.sha256.clone(),
        bytes: release.bytes,
        version_line,
        installed_at_ms: i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default(),
        )
        .unwrap_or(i64::MAX),
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| EngineError::Io {
        detail: format!("encode manifest: {e}"),
    })?;
    std::fs::write(layout.manifest_path(), bytes).map_err(|e| io("write manifest", &e))
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

/// The operating system's own `tar`: `/usr/bin/tar` on macOS and Linux,
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
        return Err(EngineError::Unpack {
            detail: format!("{} is missing", path.display()),
        });
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
    #[cfg(target_os = "linux")]
    if let Some(dir) = server.parent() {
        command.env("LD_LIBRARY_PATH", dir);
    }
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
