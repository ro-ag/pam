//! The inventory walk: one planned operation per probe the inventory lists
//! for the platform, run concurrently under per-probe bounds and the run's
//! total deadline, collected into rows in inventory order.
//!
//! The probes both platforms share (the lock, the private directories, the
//! store files, the executable, the public reach) are planned here from
//! the base layout `crates/pam_daemon/src/runtime_dir.rs` and the spec's
//! table document; the platform files add the mechanisms that differ.
//! Every path is derived from the resolved base, never from the environment
//! directly.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use pam_client::client::SOCKET_DIR_ENV;
use pam_client::request::new_request_id;
use pam_daemon::lifecycle::{LOCK_FILE, LOG_DIR};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::doctor::{DaemonFacts, Platform, Probe, ProbeId, ProbeResult};
use pam_proto::wire::Via;

use super::classify::{classify_io_result, classify_lock, classify_reach, fit_result};
use super::os::Os;
use super::{Options, RunError};

/// `$PAM_BASE_DIR`, reported as the base override.
pub const BASE_DIR_ENV: &str = "PAM_BASE_DIR";

/// The private administration directory under the base.
pub const ADMIN_DIR: &str = "admin";
/// The macOS admin endpoint inside [`ADMIN_DIR`].
pub const ADMIN_SOCKET: &str = "control.sock";
/// The Windows admin control file inside [`ADMIN_DIR`].
pub const ADMIN_CONTROL: &str = "control.json";
/// The store's database file.
pub const STORE_FILE: &str = "state.sqlite3";
/// The store's write-ahead log.
pub const STORE_WAL: &str = "state.sqlite3-wal";
/// The store's shared-memory index.
pub const STORE_SHM: &str = "state.sqlite3-shm";
/// Pre-upgrade store backups.
pub const BACKUP_DIR: &str = "backup";
/// The model trust records.
pub const MODEL_TRUST_DIR: &str = "model-trust";
/// The installed engine and its weights.
pub const ENGINE_DIR: &str = "engine";
/// The run directory under the base.
pub const RUN_DIR: &str = "run";
/// The engine's transient runtime directory (API key, pid) inside the run
/// directory.
pub const ENGINE_RUNTIME_DIR: &str = "engine";
/// The engine's private socket inside the run directory (macOS).
pub const ENGINE_SOCKET: &str = "engine.sock";
/// The flow library.
pub const FLOWS_DIR: &str = "flows";

/// The reason `public.unlink` is never probed (decision 3).
pub const UNLINK_NOT_PROBED: &str = "side effect";

/// Everything one run needs to plan its probes.
pub struct Context {
    /// Where the run happens.
    pub platform: Platform,
    /// The resolved base.
    pub base: PathBuf,
    /// The runtime directories one public dial uses: the session override's
    /// flat layout when set, `<base>/run` otherwise.
    pub dirs: RuntimeDir,
    /// `$PAM_SOCKET_DIR`, when set and non-empty.
    pub session_dir: Option<PathBuf>,
    /// `$PAM_BASE_DIR`, as set.
    pub base_override: Option<OsString>,
    /// The OS seam.
    pub os: Arc<dyn Os>,
    /// The bounds.
    pub options: Options,
    /// This process's pid, for the absent names.
    pub pid: u32,
    /// A random suffix for the absent names: alphanumeric only.
    pub nonce: String,
}

impl Context {
    /// Resolves the endpoint paths for `options.base` and the session
    /// override read through `os`.
    ///
    /// # Errors
    ///
    /// [`RunError::Base`] when the public socket path does not fit.
    pub fn new(platform: Platform, options: &Options, os: Arc<dyn Os>) -> Result<Self, RunError> {
        let session_dir = os
            .env_var(SOCKET_DIR_ENV)
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);
        let dirs = match &session_dir {
            Some(dir) => RuntimeDir::paths_at_dir(dir)?,
            None => RuntimeDir::paths_at_base(&options.base)?,
        };
        Ok(Self {
            platform,
            base: options.base.clone(),
            dirs,
            session_dir,
            base_override: os.env_var(BASE_DIR_ENV),
            os,
            options: options.clone(),
            pid: std::process::id(),
            nonce: nonce(),
        })
    }

    /// How the hello says the daemon is reached.
    #[must_use]
    pub fn via(&self) -> Via {
        if self.session_dir.is_some() {
            Via::Relay
        } else {
            Via::Direct
        }
    }

    /// `<base>/run/daemon.lock`: the daemon's own lock, whatever the dial
    /// goes through.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.base.join(RUN_DIR).join(LOCK_FILE)
    }

    /// The credential-store account that cannot exist:
    /// `pam.doctor.absent.<pid>.<random>`.
    #[must_use]
    pub fn absent_account(&self) -> String {
        format!("pam.doctor.absent.{}.{}", self.pid, self.nonce)
    }
}

/// A random alphanumeric suffix from the request-id generator (a ULID):
/// no character a shell or a credential-store query could read as syntax.
fn nonce() -> String {
    new_request_id()
        .trim_start_matches("req_")
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

/// What one probe attempt produced.
#[derive(Debug, Default)]
pub struct Outcome {
    /// The row's result.
    pub result: ProbeResult,
    /// The daemon facts, from the public reach only.
    pub daemon: Option<DaemonFacts>,
}

impl From<ProbeResult> for Outcome {
    fn from(result: ProbeResult) -> Self {
        Self {
            result,
            daemon: None,
        }
    }
}

/// One probe, planned: what to run and how long it may take.
pub struct Planned {
    /// The probe.
    pub id: ProbeId,
    /// Its bound.
    pub bound: Duration,
    /// The attempt.
    pub op: Box<dyn FnOnce() -> Outcome + Send>,
}

/// What a walk produced.
#[derive(Debug)]
pub struct Walk {
    /// One row per inventory entry, in inventory order.
    pub probes: Vec<Probe>,
    /// The daemon facts when the hello was acknowledged.
    pub daemon: Option<DaemonFacts>,
    /// The parent-process names, nearest first.
    pub harness_chain: Vec<String>,
}

/// Walks the inventory for the context's platform.
#[must_use]
pub fn walk(context: &Context) -> Walk {
    let started = Instant::now();
    let total = context.options.timeout;
    let chain = {
        let os = Arc::clone(&context.os);
        let pid = context.pid;
        let bound = context.options.helper_bound;
        bounded(move || harness_chain(os.as_ref(), pid, bound))
    };
    let mut planned = Vec::new();
    let mut rows = BTreeMap::new();
    for id in ProbeId::all() {
        if id == ProbeId::PublicUnlink {
            rows.insert(id, Probe::not_probed(id, UNLINK_NOT_PROBED));
        } else if !id.applies_to(context.platform) {
            rows.insert(id, Probe::not_applicable(id, context.platform));
        } else if let Some(plan) = plan(id, context) {
            planned.push(plan);
        } else {
            rows.insert(id, Probe::not_applicable(id, context.platform));
        }
    }
    let mut daemon = None;
    for (id, outcome) in run_planned(planned, total) {
        if outcome.daemon.is_some() {
            daemon = outcome.daemon;
        }
        rows.insert(id, Probe::new(id, fit_result(outcome.result)));
    }
    let remaining = total.saturating_sub(started.elapsed());
    let harness_chain = chain.wait(remaining).unwrap_or_default();
    Walk {
        probes: rows.into_values().collect(),
        daemon,
        harness_chain,
    }
}

/// The plan for `id`: the shared mechanism, else the platform's.
#[must_use]
pub fn plan(id: ProbeId, context: &Context) -> Option<Planned> {
    plan_common(id, context).or_else(|| platform_plan(id, context))
}

#[cfg(unix)]
fn platform_plan(id: ProbeId, context: &Context) -> Option<Planned> {
    super::probe_unix::plan(id, context)
}

#[cfg(windows)]
fn platform_plan(id: ProbeId, context: &Context) -> Option<Planned> {
    super::probe_windows::plan(id, context)
}

#[cfg(not(any(unix, windows)))]
fn platform_plan(_id: ProbeId, _context: &Context) -> Option<Planned> {
    None
}

#[cfg(unix)]
fn harness_chain(os: &dyn Os, pid: u32, bound: Duration) -> Vec<String> {
    super::probe_unix::harness_chain(os, pid, bound)
}

#[cfg(windows)]
fn harness_chain(os: &dyn Os, pid: u32, bound: Duration) -> Vec<String> {
    super::probe_windows::harness_chain(os, pid, bound)
}

#[cfg(not(any(unix, windows)))]
fn harness_chain(_os: &dyn Os, _pid: u32, _bound: Duration) -> Vec<String> {
    Vec::new()
}

/// The probes whose mechanism is the same on both platforms.
fn plan_common(id: ProbeId, context: &Context) -> Option<Planned> {
    let base = &context.base;
    let platform = context.platform;
    let run = base.join(RUN_DIR);
    Some(match id {
        ProbeId::PublicReach => reach(context),
        ProbeId::RunLockProbe => {
            let lock = context.lock_path();
            let relayed = context.session_dir.is_some();
            file_op(context, id, move |os| {
                classify_lock(platform, os.lock_probe(&lock), relayed)
            })
        }
        ProbeId::RunLockWrite => open_write(context, id, context.lock_path()),
        ProbeId::AdminDir => list_dir(context, id, base.join(ADMIN_DIR)),
        ProbeId::StoreRead => open_read(context, id, base.join(STORE_FILE)),
        ProbeId::StoreWrite => open_write(context, id, base.join(STORE_FILE)),
        ProbeId::StoreWalRead => open_read(context, id, base.join(STORE_WAL)),
        ProbeId::StoreWalWrite => open_write(context, id, base.join(STORE_WAL)),
        ProbeId::StoreShmRead => open_read(context, id, base.join(STORE_SHM)),
        ProbeId::StoreShmWrite => open_write(context, id, base.join(STORE_SHM)),
        ProbeId::BackupRead => list_dir(context, id, base.join(BACKUP_DIR)),
        ProbeId::ModelTrustRead => list_dir(context, id, base.join(MODEL_TRUST_DIR)),
        ProbeId::EngineRead => list_dir(context, id, base.join(ENGINE_DIR)),
        ProbeId::EngineRuntimeRead => list_dir(context, id, run.join(ENGINE_RUNTIME_DIR)),
        ProbeId::FlowsRead => list_dir(context, id, base.join(FLOWS_DIR)),
        ProbeId::LogRead => list_dir(context, id, base.join(LOG_DIR)),
        ProbeId::ExeWrite => file_op(context, id, move |os| match os.current_exe() {
            Ok(exe) => classify_io_result(platform, os.open_write(&exe)),
            Err(error) => ProbeResult::unknown(format!("current_exe: {:?}", error.kind()))
                .with_os_error(pam_proto::doctor::OsError::from_io(&error)),
        }),
        _ => return None,
    })
}

/// The public hello, bounded by the client's connect bound plus a margin
/// for the thread.
fn reach(context: &Context) -> Planned {
    let os = Arc::clone(&context.os);
    let dirs = context.dirs.clone();
    let via = context.via();
    let bound = context.options.hello_bound;
    let platform = context.platform;
    Planned {
        id: ProbeId::PublicReach,
        bound: bound + Duration::from_secs(1),
        op: Box::new(move || {
            let (result, daemon) =
                classify_reach(platform, via, bound, os.hello(&dirs, via, bound));
            Outcome { result, daemon }
        }),
    }
}

/// A file or socket operation under the probe bound.
#[must_use]
pub fn file_op(
    context: &Context,
    id: ProbeId,
    op: impl FnOnce(&dyn Os) -> ProbeResult + Send + 'static,
) -> Planned {
    let os = Arc::clone(&context.os);
    Planned {
        id,
        bound: context.options.probe_bound,
        op: Box::new(move || op(os.as_ref()).into()),
    }
}

/// Open `path` for reading and close it.
#[must_use]
pub fn open_read(context: &Context, id: ProbeId, path: PathBuf) -> Planned {
    let platform = context.platform;
    file_op(context, id, move |os| {
        classify_io_result(platform, os.open_read(&path))
    })
}

/// Open `path` for writing (never creating or truncating) and close it.
#[must_use]
pub fn open_write(context: &Context, id: ProbeId, path: PathBuf) -> Planned {
    let platform = context.platform;
    file_op(context, id, move |os| {
        classify_io_result(platform, os.open_write(&path))
    })
}

/// List `path`, taking at most one entry.
#[must_use]
pub fn list_dir(context: &Context, id: ProbeId, path: PathBuf) -> Planned {
    let platform = context.platform;
    file_op(context, id, move |os| {
        classify_io_result(platform, os.list_dir(&path))
    })
}

/// The lock file's pid, or the `unknown` its absence classifies to.
///
/// # Errors
///
/// The result to report when the pid could not be read.
pub fn lock_pid(os: &dyn Os, lock: &Path) -> Result<u32, ProbeResult> {
    let text = os.read_pid_file(lock).map_err(|error| {
        ProbeResult::unknown("lock file unreadable: no pid to probe")
            .with_os_error(pam_proto::doctor::OsError::from_io(&error))
    })?;
    super::classify::parse_lock_pid(&text)
        .ok_or_else(|| ProbeResult::unknown("lock file holds no pid: nothing to probe"))
}

/// Runs every planned probe on its own thread and collects what arrives
/// before each probe's bound and the run's `total`; a probe still pending
/// at its bound is `unknown` and its thread is left to finish on its own
/// (its late result is dropped).
#[must_use]
pub fn run_planned(planned: Vec<Planned>, total: Duration) -> Vec<(ProbeId, Outcome)> {
    let started = Instant::now();
    let run_deadline = started + total;
    let (sender, receiver) = mpsc::channel();
    let mut pending: BTreeMap<usize, (ProbeId, Instant, Duration)> = BTreeMap::new();
    let mut results = Vec::new();
    for (index, probe) in planned.into_iter().enumerate() {
        let Planned { id, bound, op } = probe;
        let sender = sender.clone();
        let spawned = thread::Builder::new()
            .name(format!("doctor-{id}"))
            .spawn(move || {
                let begun = Instant::now();
                let mut outcome = op();
                outcome.result.elapsed_ms = Some(millis(begun.elapsed()));
                let _ = sender.send((index, outcome));
            });
        match spawned {
            Ok(_) => {
                pending.insert(index, (id, (started + bound).min(run_deadline), bound));
            }
            Err(error) => results.push((
                id,
                ProbeResult::unknown(format!("cannot start the probe thread: {error}")).into(),
            )),
        }
    }
    drop(sender);
    while !pending.is_empty() {
        let next = pending
            .values()
            .map(|(_, deadline, _)| *deadline)
            .min()
            .unwrap_or(run_deadline);
        match receiver.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Ok((index, outcome)) => {
                if let Some((id, _, _)) = pending.remove(&index) {
                    results.push((id, outcome));
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                let expired: Vec<usize> = pending
                    .iter()
                    .filter(|(_, (_, deadline, _))| *deadline <= now)
                    .map(|(index, _)| *index)
                    .collect();
                for index in expired {
                    if let Some((id, _, bound)) = pending.remove(&index) {
                        results.push((id, timed_out(bound, now >= run_deadline).into()));
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                for (id, _, _) in pending.values() {
                    results.push((
                        *id,
                        ProbeResult::unknown("the probe thread ended without a result").into(),
                    ));
                }
                pending.clear();
            }
        }
    }
    results
}

/// The `unknown` of a probe that overran.
fn timed_out(bound: Duration, run_deadline: bool) -> ProbeResult {
    if run_deadline {
        ProbeResult::unknown("the run deadline passed before the probe answered")
    } else {
        ProbeResult::unknown(format!("timed out after {} ms", bound.as_millis()))
    }
}

/// A value computed on its own thread, collected within a bound.
pub struct Bounded<T> {
    receiver: mpsc::Receiver<T>,
}

impl<T: Send + 'static> Bounded<T> {
    /// The value, or `None` when it did not arrive within `timeout` (the
    /// thread is left to finish on its own).
    #[must_use]
    pub fn wait(self, timeout: Duration) -> Option<T> {
        self.receiver.recv_timeout(timeout).ok()
    }
}

/// Starts `compute` on its own thread.
#[must_use]
pub fn bounded<T: Send + 'static>(compute: impl FnOnce() -> T + Send + 'static) -> Bounded<T> {
    let (sender, receiver) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("doctor-env".to_owned())
        .spawn(move || {
            let _ = sender.send(compute());
        });
    // A thread that could not start leaves the channel to disconnect: the
    // wait answers `None` at once.
    drop(spawned);
    Bounded { receiver }
}

/// Milliseconds of `elapsed`, saturating.
fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}
