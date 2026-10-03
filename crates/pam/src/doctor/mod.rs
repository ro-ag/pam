//! The probe engine behind `pam doctor`: does the OS hold this process to
//! the public socket, or can it reach PAM's private state?
//!
//! The engine walks [`pam_proto::doctor::INVENTORY`] for the current
//! platform, attempts every probe the inventory lists for it from this
//! process's own position, and hands the rows to [`pam_proto::doctor::judge`]
//! through [`DoctorReport::new`]. Each probe obeys the side-effect rules of
//! `docs/specs/2026-10-02-boundary-self-check.md`: nothing is written,
//! created, truncated, unlinked, renamed or sent; no private byte is read
//! (the lock file's pid is the one exception, and the ordinary client reads
//! it too); the admin connect sends nothing; every spawned helper is named by
//! absolute path, runs with a cleared environment and null stdin, and is
//! bounded. Every OS interaction goes through the [`os::Os`] seam so that the
//! classifiers in [`classify`] are pure functions over injected errors and
//! helper output, and so a test can run the whole engine against a fake.
//!
//! Probes run concurrently, each under its own bound (2 s for a file or
//! socket operation, 5 s for a helper, the client's hello bound for the
//! public reach) and all under the run's total deadline; one that overruns
//! is `unknown` with the reason, which fails the verdict (decision 4: a
//! boundary is claimed from evidence only).
//!
//! The CLI (`pam doctor`) builds [`Options`], calls [`run`], prints
//! [`render_human`] or [`render_json`], and sends `report.as_args()` as the
//! `doctor.report` request; the engine itself never dials for anything but
//! the hello.

pub mod classify;
pub mod env;
pub mod helpers;
pub mod inventory;
pub mod os;
#[cfg(unix)]
pub mod probe_unix;
// Built for its tests everywhere: the Windows probes touch the OS through
// the seam only, so their plan is exercised on every host.
#[cfg(any(windows, test))]
pub mod probe_windows;
pub mod profiles;
pub mod render;

#[cfg(test)]
mod classify_test;
#[cfg(test)]
mod engine_test;
#[cfg(test)]
mod env_test;
#[cfg(test)]
mod helpers_test;
#[cfg(test)]
mod inventory_test;
#[cfg(test)]
pub(crate) mod os_test;
#[cfg(test)]
mod probe_windows_test;
// `profiles_test` is declared from `profiles.rs` (its `super` is `profiles`).
#[cfg(test)]
mod render_test;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_daemon::runtime_dir::RuntimeDirError;
use pam_proto::doctor::{DoctorReport, Platform};

pub use render::{profile_name, render_human, render_json};

/// Default total bound of one run (`--timeout-ms`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound of one file or socket operation.
pub const PROBE_BOUND: Duration = Duration::from_secs(2);

/// Bound of one spawned helper.
pub const HELPER_BOUND: Duration = Duration::from_secs(5);

/// Bound of the public hello: the client's own connect bound.
pub const HELLO_BOUND: Duration = Duration::from_secs(5);

/// How one run is configured. The base is the caller's resolved base
/// (`pam::default_base_dir`); the session override and the base override
/// are read from the environment through the seam, so the facts the report
/// carries are the ones the ordinary client would act on.
#[derive(Debug, Clone)]
pub struct Options {
    /// The resolved base directory (`$PAM_BASE_DIR` or `~/.pam`).
    pub base: PathBuf,
    /// Total bound of the run; probes still pending at the deadline are
    /// `unknown`.
    pub timeout: Duration,
    /// Bound of one file or socket operation.
    pub probe_bound: Duration,
    /// Bound of one spawned helper.
    pub helper_bound: Duration,
    /// Bound of the public hello.
    pub hello_bound: Duration,
}

impl Options {
    /// Options for `base` with the default bounds.
    #[must_use]
    pub fn new(base: PathBuf) -> Self {
        Self {
            base,
            timeout: DEFAULT_TIMEOUT,
            probe_bound: PROBE_BOUND,
            helper_bound: HELPER_BOUND,
            hello_bound: HELLO_BOUND,
        }
    }

    /// The same options with a different total bound (`--timeout-ms`).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Why a run could not even start. Both map to `cannot_probe` (exit `1`)
/// at the CLI: there is no position to probe from.
#[derive(Debug)]
pub enum RunError {
    /// The platform is not one the inventory knows.
    UnsupportedPlatform,
    /// The base directory yields no valid endpoint paths.
    Base(RuntimeDirError),
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("pam doctor runs on macOS and Windows only")
            }
            Self::Base(error) => write!(
                formatter,
                "cannot resolve the public endpoint under the base directory: {error}"
            ),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedPlatform => None,
            Self::Base(error) => Some(error),
        }
    }
}

impl From<RuntimeDirError> for RunError {
    fn from(error: RuntimeDirError) -> Self {
        Self::Base(error)
    }
}

/// Runs every probe for the current platform against the real OS and
/// returns the judged report, with `report` left `None` for the CLI to fill
/// after sending it.
///
/// # Errors
///
/// [`RunError`] when there is no position to probe from.
pub fn run(options: &Options) -> Result<DoctorReport, RunError> {
    run_with(options, Arc::new(os::RealOs))
}

/// [`run`] over an injected OS seam.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(options: &Options, os: Arc<dyn os::Os>) -> Result<DoctorReport, RunError> {
    let platform = Platform::current().ok_or(RunError::UnsupportedPlatform)?;
    let context = inventory::Context::new(platform, options, os)?;
    let walk = inventory::walk(&context);
    let facts = env::facts(&context, walk.harness_chain);
    Ok(DoctorReport::new(
        platform,
        unix_now(),
        walk.daemon,
        walk.probes,
        facts,
    ))
}

/// Unix time in seconds, zero before the epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
