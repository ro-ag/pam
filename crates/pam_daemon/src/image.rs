//! The daemon's executable image as recorded at boot, and the one question the
//! restart policy asks of it: was the binary on disk replaced?
//!
//! Client and daemon ship as one binary, so a client whose `client_version`
//! differs from the daemon's used to be taken as proof that the binary had been
//! upgraded under the running daemon, and the daemon restarted itself. That made
//! a self-reported string a restart command: any public caller could drain and
//! restart the daemon, and two installed versions restarted each other forever.
//!
//! The rule now: **a claimed version is only the occasion to look.** At boot the
//! daemon records where it was started from and what that file was
//! ([`BootImage`]: the path, the canonical path it resolved to, and the canonical
//! file's length, modification time and — on Unix — device and inode). On a
//! version mismatch [`ImageWatch::verdict`] re-reads those facts and answers:
//! - [`VersionVerdict::Restart`] when a regular file is present at a recorded
//!   path and its canonical path or any recorded attribute differs — the binary
//!   was replaced, the daemon hands over to it;
//! - [`VersionVerdict::Mismatch`] otherwise — the caller is simply a different
//!   build, is refused (`client_version_mismatch`), and the daemon's phase does
//!   not move. A missing file is not a replacement.
//!
//! Replacing the daemon's executable is outside an agent's reach by the
//! deployment assumption (docs/admin-boundary.md), so a restart can no longer be
//! caused by what a client says.
//!
//! The re-check touches the filesystem, so it runs off the async threads, under a
//! timeout, and its answer is cached for [`RECHECK_INTERVAL`]: a flood of
//! mismatched requests costs one check per second. [`ImageProbe`] is the seam
//! tests script file states through; nothing here uses `unsafe`.
//!
//! The respawn after a restart must use [`BootImage::path`] — the path recorded
//! at boot — not `current_exe()` at respawn time, which may name a replaced
//! file after the usual rename-into-place install.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Mutex;

/// How long one "was the image replaced?" answer is reused.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Bound on one re-check: a hung filesystem must not hold a request.
const RECHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// Refusal cause for a client of a different build talking to a daemon whose
/// binary on disk has not changed.
pub const CAUSE_CLIENT_VERSION_MISMATCH: &str = "client_version_mismatch";

/// What the daemon knows about one file on disk: enough to tell that it was
/// replaced, nothing about its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    /// The path the probed path resolves to (symlinks followed).
    pub canonical: PathBuf,
    /// Length in bytes.
    pub len: u64,
    /// Last modification time, when the platform reports one.
    pub modified: Option<SystemTime>,
    /// `(device, inode)` on Unix; `None` elsewhere. A rename-into-place
    /// install changes the inode even when length and mtime are preserved.
    pub identity: Option<(u64, u64)>,
}

/// Reads [`FileFacts`]. The production probe is [`FsProbe`]; tests script one.
pub trait ImageProbe: Send + Sync + 'static {
    /// The facts for the regular file `path` resolves to, or `None` when no
    /// regular file is there (missing, a directory, unreadable).
    fn facts(&self, path: &Path) -> Option<FileFacts>;
}

/// [`ImageProbe`] over the real filesystem, through `std::fs` metadata only.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsProbe;

impl ImageProbe for FsProbe {
    fn facts(&self, path: &Path) -> Option<FileFacts> {
        let canonical = std::fs::canonicalize(path).ok()?;
        let metadata = std::fs::metadata(&canonical).ok()?;
        if !metadata.is_file() {
            return None;
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            Some((metadata.dev(), metadata.ino()))
        };
        #[cfg(not(unix))]
        let identity = None;
        Some(FileFacts {
            identity,
            len: metadata.len(),
            modified: metadata.modified().ok(),
            canonical,
        })
    }
}

/// One path the daemon was started as, with what was there at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedPath {
    path: PathBuf,
    /// `None` when the path could not be read at boot: such a path can never
    /// prove a replacement, because there is nothing to compare against.
    boot: Option<FileFacts>,
}

/// The daemon's executable identity, recorded once at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImage {
    recorded: Vec<RecordedPath>,
}

impl BootImage {
    /// Records the image the running process was started from:
    /// `std::env::current_exe()` and, when it is an absolute path that names
    /// something else, `argv[0]`.
    #[must_use]
    pub fn capture(probe: &dyn ImageProbe) -> Self {
        let mut paths = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            paths.push(exe);
        }
        if let Some(arg0) = std::env::args_os().next().map(PathBuf::from)
            && arg0.is_absolute()
            && !paths.contains(&arg0)
        {
            paths.push(arg0);
        }
        Self::from_paths(paths, probe)
    }

    /// Records `paths` as the image (the first is the respawn path).
    #[must_use]
    pub fn from_paths(paths: Vec<PathBuf>, probe: &dyn ImageProbe) -> Self {
        Self {
            recorded: paths
                .into_iter()
                .map(|path| RecordedPath {
                    boot: probe.facts(&path),
                    path,
                })
                .collect(),
        }
    }

    /// The path the daemon was started as — what a respawn must execute and
    /// what a refusal names. `None` only when the platform could not say.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.recorded
            .first()
            .map(|recorded| recorded.path.as_path())
    }

    /// Whether the image on disk was replaced since boot: a regular file is
    /// present at a recorded path and its canonical path or any recorded
    /// attribute differs. A missing file is not a replacement, and neither
    /// is a path that had no readable file at boot.
    #[must_use]
    pub fn replaced(&self, probe: &dyn ImageProbe) -> bool {
        self.recorded.iter().any(
            |recorded| match (&recorded.boot, probe.facts(&recorded.path)) {
                (Some(boot), Some(now)) => *boot != now,
                _ => false,
            },
        )
    }
}

/// What a `client_version` that differs from the daemon's leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionVerdict {
    /// The versions are equal; nothing was checked.
    Match,
    /// The binary on disk was replaced: restart with it.
    Restart,
    /// The binary on disk is the one that is running: refuse the client.
    Mismatch,
}

/// The boot image plus the cached, off-thread replaced check.
pub struct ImageWatch {
    boot: BootImage,
    probe: Arc<dyn ImageProbe>,
    /// When the image was last checked and what the check said. Held
    /// across the check so concurrent mismatches share one filesystem
    /// read (single flight).
    last: Mutex<Option<(Instant, bool)>>,
}

impl std::fmt::Debug for ImageWatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImageWatch")
            .field("boot", &self.boot)
            .finish_non_exhaustive()
    }
}

impl ImageWatch {
    /// Records the running process's image through `probe`.
    #[must_use]
    pub fn capture(probe: Arc<dyn ImageProbe>) -> Arc<Self> {
        let boot = BootImage::capture(probe.as_ref());
        Self::with_boot(boot, probe)
    }

    /// A watch over an explicit boot record (tests).
    #[must_use]
    pub fn with_boot(boot: BootImage, probe: Arc<dyn ImageProbe>) -> Arc<Self> {
        Arc::new(Self {
            boot,
            probe,
            last: Mutex::new(None),
        })
    }

    /// The image recorded at boot.
    #[must_use]
    pub fn boot(&self) -> &BootImage {
        &self.boot
    }

    /// The path recorded at boot, for refusal text and the respawn.
    #[must_use]
    pub fn boot_path(&self) -> Option<&Path> {
        self.boot.path()
    }

    /// Decides what a request carrying `client_version` means for a daemon
    /// of `daemon_version` (see the module docs).
    pub async fn verdict(&self, client_version: &str, daemon_version: &str) -> VersionVerdict {
        if client_version == daemon_version {
            return VersionVerdict::Match;
        }
        if self.replaced().await {
            VersionVerdict::Restart
        } else {
            VersionVerdict::Mismatch
        }
    }

    /// Whether the image was replaced, re-read at most once per
    /// [`RECHECK_INTERVAL`] and never on an async thread. A check that
    /// cannot finish within its bound answers "not replaced": the daemon
    /// keeps serving rather than restart on a guess. Once a replacement is
    /// seen the answer stays `true` — the daemon is on its way out.
    pub async fn replaced(&self) -> bool {
        let mut last = self.last.lock().await;
        if let Some((at, answer)) = *last
            && (answer || at.elapsed() < RECHECK_INTERVAL)
        {
            return answer;
        }
        let boot = self.boot.clone();
        let probe = Arc::clone(&self.probe);
        let check = tokio::task::spawn_blocking(move || boot.replaced(probe.as_ref()));
        let answer = matches!(
            tokio::time::timeout(RECHECK_TIMEOUT, check).await,
            Ok(Ok(true))
        );
        *last = Some((Instant::now(), answer));
        answer
    }
}
