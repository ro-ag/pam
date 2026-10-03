//! Runtime directory setup: `<base>/run` and the endpoint paths inside it.
//!
//! The run directory is the public plane, and nothing else: it holds the
//! public socket `pam.sock` (unix), the instance lock `daemon.lock`
//! (`crate::lifecycle`), and on Windows the public adapter's control file
//! `public.json`. It is the one directory under the base an agent's sandbox
//! must let the agent traverse, so nothing private is placed in it: the
//! engine's socket, API key file and pid file live under `<base>/engine/run`
//! (`pam_model::engine_server`), and the administration endpoint under
//! `<base>/admin`. A daemon that finds the engine runtime an older version
//! kept here removes it at start (`ModelService::reap_orphan_engine`).
//!
//! The default base is `~/.pam`; tests point it at a temporary directory.
//! A unix domain socket path must fit `sun_path` in `sockaddr_un` with its
//! terminator (104 bytes on macOS), so the public socket path is validated
//! here, at boot, before anything binds — a violation is a legible error
//! naming the limit and the offending path instead of a cryptic bind failure.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

/// Size of `sun_path` on macOS in bytes. A socket path must be shorter: the
/// terminator has to fit as well.
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
    /// A socket path does not fit the unix socket path limit.
    #[error(
        "socket path {} is {len} bytes; a unix socket path must be shorter \
         than 104 bytes (`sun_path` on macOS); use a shorter pam base directory",
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

/// File name of the public socket (unix).
const PUBLIC_SOCKET: &str = "pam.sock";

/// File name of the Windows public adapter's control file (port and nonce).
const PUBLIC_CONTROL: &str = "public.json";

/// Resolved runtime directory: `<base>/run` plus the endpoint paths in it.
#[derive(Debug, Clone)]
pub struct RuntimeDir {
    run: PathBuf,
    public: PathBuf,
    public_control: PathBuf,
}

impl RuntimeDir {
    /// Prepares `<base>/run` (created with mode `0700` on unix) and computes
    /// the endpoint paths, validating the socket path against the unix limit
    /// before creating anything.
    pub fn at_base(base: &Path) -> Result<Self, RuntimeDirError> {
        let dirs = Self::paths_at_base(base)?;
        create_private_dir(&dirs.run).map_err(|source| RuntimeDirError::Create {
            path: dirs.run.clone(),
            source,
        })?;
        Ok(dirs)
    }

    /// Resolve and validate endpoint paths without touching the filesystem.
    /// Clients use this while the daemon alone creates and protects its runtime
    /// directory. Connecting to a running daemon requires no directory writes.
    pub fn paths_at_base(base: &Path) -> Result<Self, RuntimeDirError> {
        Self::paths_at_dir(&base.join("run"))
    }

    /// Resolve and validate endpoint paths for an explicit socket directory
    /// with the same flat layout (`pam.sock` directly inside it). This is
    /// the session relay's (`pam listen`) view of its own directory and the
    /// client's `PAM_SOCKET_DIR` view of it: the `run` field is the directory
    /// itself, so lock-based probes under it answer "no daemon" — callers
    /// that hold the override must skip the daemon probe, which the client's
    /// dial path does.
    pub fn paths_at_dir(dir: &Path) -> Result<Self, RuntimeDirError> {
        let public = dir.join(PUBLIC_SOCKET);
        validate_socket_path(&public)?;
        Ok(Self {
            public,
            public_control: dir.join(PUBLIC_CONTROL),
            run: dir.to_path_buf(),
        })
    }

    /// The `<base>/run` directory holding the public endpoint: `pam.sock`,
    /// `daemon.lock` and, on Windows, `public.json` — nothing private.
    #[must_use]
    pub fn run_dir(&self) -> &Path {
        &self.run
    }

    /// Filesystem path of the public socket (unix): the stream socket
    /// `pam.sock` the framed public listener serves. On Windows nothing is
    /// bound here (see [`Self::public_control`]); a file of this name there
    /// is what a pre-migration daemon left behind.
    #[must_use]
    pub fn public_socket(&self) -> &Path {
        &self.public
    }

    /// Filesystem path of the Windows public adapter's control file
    /// (`public.json`: loopback port and owner nonce).
    #[must_use]
    pub fn public_control(&self) -> &Path {
        &self.public_control
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
    // `sun_path` holds the path and its terminator, so the limit itself is
    // already too long: the same bound the listener applies when it binds.
    if len >= MAX_SOCKET_PATH_BYTES {
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
    // Nothing binds a unix socket here on Windows (the public endpoint is a
    // control file); the check is kept uniform so a base directory that is
    // accepted on one platform is accepted on the other.
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
