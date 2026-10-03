//! The seam between the probes and the operating system.
//!
//! Every OS interaction a probe makes goes through [`Os`], so the engine can
//! run against a fake in tests and so the real implementation is the one
//! place where the side-effect rules are enforced by construction:
//! [`RealOs::open_read`] opens and closes without reading a byte,
//! [`RealOs::open_write`] opens with `create(false)` and `truncate(false)`
//! and never writes, [`RealOs::list_dir`] takes at most one entry,
//! [`RealOs::lock_probe`] is the client's own shared-lock readiness test and
//! releases what it took, [`RealOs::connect_unix`] connects, holds the
//! stream open for a moment and drops it without sending or reading (the
//! hold lets the daemon's accept loop read the kernel peer credentials, so
//! the admin contact is attributable to this run's report instead of a
//! "vanished" peer), and [`RealOs::read_pid_file`] is the
//! only place that reads bytes from under the base — the lock file's pid,
//! bounded, which the ordinary client reads as well.

use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pam_client::transport::{self, Probe};
use pam_daemon::framed;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::Via;

use super::helpers::{Helper, HelperOutcome, run_helper};

/// The most bytes [`Os::read_pid_file`] reads: a pid and a line ending.
pub const MAX_PID_FILE_BYTES: usize = 32;

/// What the shared-lock probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// An exclusive holder exists: a daemon is running.
    Held,
    /// Nobody holds the lock.
    Free,
}

/// What the public hello answered, in a shape a fake can build.
#[derive(Debug)]
pub enum HelloAnswer {
    /// The daemon acknowledged this build's hello.
    Ready {
        /// The daemon's version.
        version: String,
        /// The wire protocol it speaks.
        proto: u32,
        /// Its boot epoch.
        epoch: String,
    },
    /// Nothing accepted the connection, or it ended without an answer.
    Unreachable(io::Error),
    /// A pre-migration daemon greeted in `ZMTP`.
    Legacy,
    /// The daemon refused the hello with an `error` frame.
    Refused {
        /// The refusal's cause.
        cause: String,
        /// Its detail line.
        detail: String,
    },
    /// Something listened and did not answer in time, or not in frames.
    Silent,
}

impl From<Probe> for HelloAnswer {
    fn from(probe: Probe) -> Self {
        match probe {
            Probe::Ready(ack) => Self::Ready {
                version: ack.version,
                proto: ack.proto,
                epoch: ack.epoch,
            },
            Probe::Unreachable(error) => Self::Unreachable(error),
            Probe::Legacy => Self::Legacy,
            Probe::Refused(frame) => Self::Refused {
                cause: frame.cause,
                detail: frame.detail,
            },
            Probe::Silent => Self::Silent,
        }
    }
}

/// What a credential-store read of an absent account answered (Windows:
/// the Credential Manager through the daemon's own keyring backend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringAnswer {
    /// The store answered: no such entry.
    Absent,
    /// The store answered with an entry — impossible for a fresh random
    /// account; reported as unknown.
    Present,
    /// The store refused access.
    Denied,
    /// The store could not be reached.
    Unavailable,
    /// Something else went wrong.
    Failed(String),
}

/// Every operating-system interaction a probe may make.
pub trait Os: Send + Sync {
    /// Opens `path` for reading and closes it without reading a byte.
    fn open_read(&self, path: &Path) -> io::Result<()>;

    /// Opens `path` for writing without creating or truncating it, and
    /// closes it without writing a byte.
    fn open_write(&self, path: &Path) -> io::Result<()>;

    /// Lists `path`, taking at most one entry.
    fn list_dir(&self, path: &Path) -> io::Result<()>;

    /// The client's readiness test: open for read, try a shared lock,
    /// release it.
    fn lock_probe(&self, path: &Path) -> io::Result<LockState>;

    /// Reads at most [`MAX_PID_FILE_BYTES`] of `path`: the lock file's pid.
    fn read_pid_file(&self, path: &Path) -> io::Result<String>;

    /// Connects the unix stream socket at `path`, holds the stream open for
    /// `hold`, and drops it: nothing is sent, nothing is read.
    fn connect_unix(&self, path: &Path, hold: Duration) -> io::Result<()>;

    /// Runs one bounded helper.
    fn run_helper(&self, helper: &Helper) -> HelperOutcome;

    /// Sends this build's hello to the public endpoint of `dirs`.
    fn hello(&self, dirs: &RuntimeDir, via: Via, timeout: Duration) -> HelloAnswer;

    /// Reads `account` under the connector service from the native
    /// credential store.
    fn keyring_get(&self, account: &str) -> KeyringAnswer;

    /// This process's executable.
    fn current_exe(&self) -> io::Result<PathBuf>;

    /// This process's working directory.
    fn current_dir(&self) -> io::Result<PathBuf>;

    /// One environment variable, as set.
    fn env_var(&self, name: &str) -> Option<OsString>;
}

/// The real operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealOs;

impl Os for RealOs {
    fn open_read(&self, path: &Path) -> io::Result<()> {
        File::open(path).map(drop)
    }

    fn open_write(&self, path: &Path) -> io::Result<()> {
        OpenOptions::new()
            .write(true)
            .create(false)
            .truncate(false)
            .open(path)
            .map(drop)
    }

    fn list_dir(&self, path: &Path) -> io::Result<()> {
        let mut entries = std::fs::read_dir(path)?;
        match entries.next() {
            Some(Err(error)) => Err(error),
            Some(Ok(_)) | None => Ok(()),
        }
    }

    fn lock_probe(&self, path: &Path) -> io::Result<LockState> {
        let file = File::open(path)?;
        match file.try_lock_shared() {
            Ok(()) => {
                // Release before answering: a duplicate handle must not
                // keep a shared lock a daemon would then conflict with.
                file.unlock()?;
                Ok(LockState::Free)
            }
            Err(TryLockError::WouldBlock) => Ok(LockState::Held),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }

    fn read_pid_file(&self, path: &Path) -> io::Result<String> {
        let mut text = String::new();
        File::open(path)?
            .take(MAX_PID_FILE_BYTES as u64)
            .read_to_string(&mut text)?;
        Ok(text)
    }

    #[cfg(unix)]
    fn connect_unix(&self, path: &Path, hold: Duration) -> io::Result<()> {
        let stream = std::os::unix::net::UnixStream::connect(path)?;
        // Held, not used: the peer reads our credentials in this window.
        std::thread::sleep(hold);
        drop(stream);
        Ok(())
    }

    #[cfg(not(unix))]
    fn connect_unix(&self, _path: &Path, _hold: Duration) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unix stream sockets are not probed on this platform",
        ))
    }

    fn run_helper(&self, helper: &Helper) -> HelperOutcome {
        run_helper(helper)
    }

    fn hello(&self, dirs: &RuntimeDir, via: Via, timeout: Duration) -> HelloAnswer {
        transport::probe(dirs, &framed::client_hello(via), timeout).into()
    }

    #[cfg(windows)]
    fn keyring_get(&self, account: &str) -> KeyringAnswer {
        use pam_daemon::secrets::{NativeSecretBackend, SecretBackend, SecretError};
        let backend = match NativeSecretBackend::open() {
            Ok(backend) => backend,
            Err(SecretError::Denied) => return KeyringAnswer::Denied,
            Err(SecretError::Unavailable) => return KeyringAnswer::Unavailable,
            Err(error) => return KeyringAnswer::Failed(error.to_string()),
        };
        match backend.get(account) {
            Ok(None) => KeyringAnswer::Absent,
            Ok(Some(_)) => KeyringAnswer::Present,
            Err(SecretError::Denied) => KeyringAnswer::Denied,
            Err(SecretError::Unavailable) => KeyringAnswer::Unavailable,
            Err(error) => KeyringAnswer::Failed(error.to_string()),
        }
    }

    #[cfg(not(windows))]
    fn keyring_get(&self, _account: &str) -> KeyringAnswer {
        // macOS asks the keychain through `/usr/bin/security` instead: the
        // initialization error it prints is the evidence the fixture pins.
        KeyringAnswer::Failed("the credential store is probed through a helper here".to_owned())
    }

    fn current_exe(&self) -> io::Result<PathBuf> {
        std::env::current_exe()
    }

    fn current_dir(&self) -> io::Result<PathBuf> {
        std::env::current_dir()
    }

    fn env_var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}
