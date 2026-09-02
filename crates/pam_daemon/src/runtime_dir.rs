//! Runtime directory setup: `<base>/run` and the socket paths inside it.
//!
//! The default base is `~/.pam`; tests point it at a temporary directory.
//! Unix domain socket paths are capped at 104 bytes on macOS (the size of
//! `sun_path` in `sockaddr_un`), so both socket paths are validated here,
//! at boot, before anything binds — a violation is a legible error naming
//! the limit and the offending path instead of a cryptic bind failure.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

/// Maximum unix socket path length in bytes (`sun_path` on macOS).
pub const MAX_SOCKET_PATH_BYTES: usize = 104;

/// Attempts before a persistent `PermissionDenied` is reported.
pub const STALE_REMOVE_ATTEMPTS: u32 = 5;

/// Pause between attempts.
pub const STALE_REMOVE_BACKOFF: Duration = Duration::from_millis(25);

/// Why the runtime directory could not be prepared.
#[derive(Debug, Error)]
pub enum RuntimeDirError {
    /// The home directory could not be resolved.
    #[error("cannot resolve the home directory to place ~/.pam; set $HOME")]
    HomeNotFound,
    /// A socket path exceeds the unix socket path limit.
    #[error(
        "socket path {} is {len} bytes, over the 104-byte unix socket path \
         limit (`sun_path` on macOS); use a shorter pam base directory",
        path.display()
    )]
    SocketPathTooLong {
        /// The offending socket path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
    },
    /// Creating the run directory failed.
    #[error("cannot create runtime directory {}: {source}", path.display())]
    Create {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
}

/// Resolved runtime directory: `<base>/run` plus the two socket paths.
#[derive(Debug, Clone)]
pub struct RuntimeDir {
    run: PathBuf,
    router: PathBuf,
    events: PathBuf,
}

impl RuntimeDir {
    /// Resolves `~/.pam` as the base directory and prepares `~/.pam/run`.
    pub fn from_home() -> Result<Self, RuntimeDirError> {
        let home = std::env::home_dir().ok_or(RuntimeDirError::HomeNotFound)?;
        Self::at_base(&home.join(".pam"))
    }

    /// Prepares `<base>/run` (created with mode `0700` on unix) and computes
    /// the socket paths, validating both against the 104-byte limit before
    /// creating anything.
    pub fn at_base(base: &Path) -> Result<Self, RuntimeDirError> {
        let run = base.join("run");
        let router = run.join("pam.sock");
        let events = run.join("events.sock");
        validate_socket_path(&router)?;
        validate_socket_path(&events)?;
        create_private_dir(&run).map_err(|source| RuntimeDirError::Create {
            path: run.clone(),
            source,
        })?;
        Ok(Self {
            run,
            router,
            events,
        })
    }

    /// The `<base>/run` directory holding the sockets.
    #[must_use]
    pub fn run_dir(&self) -> &Path {
        &self.run
    }

    /// Filesystem path of the `ROUTER` socket (`pam.sock`).
    #[must_use]
    pub fn router_socket(&self) -> &Path {
        &self.router
    }

    /// Filesystem path of the `PUB` socket (`events.sock`).
    #[must_use]
    pub fn events_socket(&self) -> &Path {
        &self.events
    }

    /// `ipc://` endpoint of the `ROUTER` socket.
    #[must_use]
    pub fn router_endpoint(&self) -> String {
        format!("ipc://{}", self.router.display())
    }

    /// `ipc://` endpoint of the `PUB` socket.
    #[must_use]
    pub fn events_endpoint(&self) -> String {
        format!("ipc://{}", self.events.display())
    }
}

/// Removes a stale socket file left behind by a previous daemon, so a fresh
/// bind can succeed. A missing file is fine, and `PermissionDenied` is
/// retried briefly — on Windows, Defender or the search indexer can hold a
/// transient handle on a file we are deleting (issue #3) — and is also fine
/// when the file turns out to be gone after the error.
///
/// This is blind cleanup only: single-instance liveness checking and lock
/// arbitration are a separate concern (task #12) layered on top later.
pub fn remove_stale(path: &Path) -> io::Result<()> {
    // The closure pins the lifetime: `remove_file` is generic over
    // `AsRef<Path>`, so passing it bare cannot satisfy the higher-ranked
    // `FnMut(&Path)` bound.
    remove_stale_with(
        path,
        |target: &Path| std::fs::remove_file(target),
        STALE_REMOVE_ATTEMPTS,
        STALE_REMOVE_BACKOFF,
    )
}

/// The [`remove_stale`] retry policy over an injected remover, so tests can
/// drive every branch without racing a real platform.
///
/// `attempts` is clamped to at least one; `backoff` is the pause between
/// attempts. Only `PermissionDenied` is retried — every other error is
/// reported on the first call.
///
/// # Errors
///
/// Returns the remover's error: a `PermissionDenied` that outlived all
/// attempts while the file was still there, or any other error as it came.
pub fn remove_stale_with(
    path: &Path,
    mut remove: impl FnMut(&Path) -> io::Result<()>,
    attempts: u32,
    backoff: Duration,
) -> io::Result<()> {
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match remove(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                // The holder may have let go as we asked: gone is gone.
                if !path.exists() {
                    return Ok(());
                }
                if attempt == attempts {
                    return Err(err);
                }
                std::thread::sleep(backoff);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn validate_socket_path(path: &Path) -> Result<(), RuntimeDirError> {
    let len = os_str_bytes(path);
    if len > MAX_SOCKET_PATH_BYTES {
        return Err(RuntimeDirError::SocketPathTooLong {
            path: path.to_path_buf(),
            len,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn os_str_bytes(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().len()
}

#[cfg(not(unix))]
fn os_str_bytes(path: &Path) -> usize {
    // Windows named `AF_UNIX` sockets have a similar (108-byte) cap; the
    // encoded length is a close proxy and keeps the check uniform.
    path.as_os_str().len()
}

#[cfg(unix)]
fn create_private_dir(run: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(run)?;
    // A pre-existing directory keeps its old mode; the runtime dir is the
    // security wall, so force it closed either way.
    std::fs::set_permissions(run, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(run: &Path) -> io::Result<()> {
    std::fs::create_dir_all(run)
}
