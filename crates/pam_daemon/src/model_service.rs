//! The daemon's model layer: settings, registry, runtime, and the jobs
//! that outlive a request.
//!
//! [`ModelService`] is the only thing in the daemon that touches
//! [`pam_model`]. It owns four pieces of state and nothing else:
//!
//! - the **settings** the model layer reads ([`SETTING_MODELS_DIR`] and
//!   friends), all persisted in the store so a restart keeps them;
//! - the **models directory**, rebuilt into a [`Registry`] whenever the
//!   setting changes, so a `Registry` handed out is always current;
//! - the **runtime**, one [`Runtime`] for the process — loading a second
//!   model means unloading the first, strictly old-before-new, because
//!   two sets of weights do not fit the machines this targets;
//! - the **live download handles**, keyed by job id, so a transfer can be
//!   cancelled and a second download of the same file refused.
//!
//! # Jobs are not requests
//!
//! A download runs for an hour; the admin op that started it answers in
//! milliseconds. So the op returns a job id and the transfer's history
//! lives on `model_job` rows ([`pam_store::ModelJobRow`]): a follower task
//! polls the handle every [`DOWNLOAD_POLL`] and writes progress, then the
//! verdict. A `running` row found at boot belonged to a daemon that is
//! gone, and [`ModelService::new`] fails it with
//! [`CAUSE_DAEMON_RESTART`] — the part file on disk still resumes.
//!
//! # Nothing here is agent-facing
//!
//! Administration is GUI-only (see [`crate::admin`]); the ops live in
//! [`crate::admin_models`]. The one daemon-internal entry point is
//! [`ModelService::generate`], which later plans call to spend a tier's
//! model on a job. With no default configured it returns
//! [`ModelUnavailable::NoDefault`] so the caller takes its deterministic
//! path — the model layer never becomes a hard dependency.
//!
//! # Memory comes back on its own
//!
//! A ticker every [`IDLE_TICK`] compares the runtime's `last_used_at`
//! against [`SETTING_IDLE_UNLOAD_MIN`] and unloads when the model has
//! been idle that long (`0` means never). The decision itself is
//! [`should_unload`], a pure function, so it is testable without weights.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_model::download::{DownloadError, DownloadHandle, DownloadRequest, DownloadState};
use pam_model::registry::{ModelEntry, Registry, RegistryError, default_models_dir};
use pam_model::runtime::{
    GenerateRequest, GenerateResult, LoadedModel, Runtime, RuntimeError, RuntimeState,
};
use pam_store::{ModelJobRow, Store, StoreError};
use serde_json::json;
use tokio::sync::{Mutex, watch};

/// Setting key: the directory PAM scans for weights (`~/llm` by default).
pub const SETTING_MODELS_DIR: &str = "model.models_dir";

/// Setting key: the model id the `light` tier resolves to, or unset.
pub const SETTING_DEFAULT_LIGHT: &str = "model.default.light";

/// Setting key: the model id the `heavy` tier resolves to, or unset.
pub const SETTING_DEFAULT_HEAVY: &str = "model.default.heavy";

/// Setting key: minutes of idleness before the weights are dropped;
/// `0` never unloads.
pub const SETTING_IDLE_UNLOAD_MIN: &str = "model.idle_unload_min";

/// Setting key: the vendor agent CLI the curator tier uses, or unset.
pub const SETTING_CURATOR: &str = "curator.agent";

/// Default for [`SETTING_IDLE_UNLOAD_MIN`].
pub const DEFAULT_IDLE_UNLOAD_MIN: u64 = 10;

/// `model_job.kind` for a download.
pub const KIND_DOWNLOAD: &str = "download";

/// `model_job.kind` for a verification.
pub const KIND_VERIFY: &str = "verify";

/// `model_job.state` for a job that finished cleanly.
pub const JOB_DONE: &str = "done";

/// `model_job.state` for a job that failed.
pub const JOB_FAILED: &str = "failed";

/// `model_job.state` for a job the human stopped.
pub const JOB_CANCELLED: &str = "cancelled";

/// `model_job.state` for a job still in flight.
pub const JOB_RUNNING: &str = "running";

/// Detail written on the jobs a dead daemon left `running`.
pub const CAUSE_DAEMON_RESTART: &str = "daemon_restart";

/// How often a download's follower reads its handle and writes progress.
pub const DOWNLOAD_POLL: Duration = Duration::from_millis(500);

/// How often the idle-unload ticker looks at the runtime.
pub const IDLE_TICK: Duration = Duration::from_secs(30);

/// How many settled jobs [`ModelService::status`] reports alongside the
/// running ones.
pub const STATUS_JOB_HISTORY: usize = 20;

/// How many rows the status query reads before trimming (running jobs
/// plus [`STATUS_JOB_HISTORY`] settled ones, with headroom).
const JOB_QUERY_LIMIT: u64 = 100;

/// Which class of work a generation belongs to.
///
/// `light` is classification and short answers, `heavy` is summaries and
/// briefs. Each has its own default model; `heavy` falls back to `light`
/// so a single configured model serves everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Classification, short Ask Pam answers.
    Light,
    /// Summaries, briefs.
    Heavy,
}

impl Tier {
    /// The wire name of this tier.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Heavy => "heavy",
        }
    }

    /// The tier named by `raw`, or `None`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "light" => Some(Self::Light),
            "heavy" => Some(Self::Heavy),
            _ => None,
        }
    }

    /// The setting key holding this tier's default model id.
    #[must_use]
    pub fn setting_key(self) -> &'static str {
        match self {
            Self::Light => SETTING_DEFAULT_LIGHT,
            Self::Heavy => SETTING_DEFAULT_HEAVY,
        }
    }
}

/// Why a tier could not answer.
///
/// Every variant is a legible reason for a caller to take its
/// deterministic path instead — none of them is a daemon failure.
#[derive(Debug, thiserror::Error)]
pub enum ModelUnavailable {
    /// No model is configured for the tier (nor for its fallback).
    #[error("no default model for tier {0:?}")]
    NoDefault(Tier),
    /// The configured model id is not in the models directory.
    #[error("default model {0} is not installed")]
    Missing(String),
    /// The runtime refused or failed.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// Reading the settings failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Why the service refused to start or change a piece of model work.
#[derive(Debug, thiserror::Error)]
pub enum ModelServiceError {
    /// A store write failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The transfer could not be started at all.
    #[error(transparent)]
    Download(#[from] DownloadError),
    /// A download of this file is already running.
    #[error("{0} is already downloading")]
    AlreadyDownloading(String),
    /// The file is already in the models directory.
    #[error("{0} is already installed")]
    AlreadyInstalled(String),
    /// No model in the registry carries that id.
    #[error("no model {0} in the models directory")]
    UnknownModel(String),
    /// The registry could not be read.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

/// The live download handles, keyed by job id, with the destination each
/// is writing to.
type Downloads = Arc<Mutex<HashMap<String, (PathBuf, DownloadHandle)>>>;

/// The daemon's model layer (see the module docs).
pub struct ModelService {
    store: Arc<Store>,
    /// The models directory. Behind a lock because
    /// `admin.models.settings.set` moves it while the daemon serves; a
    /// [`Registry`] is rebuilt from it on every read, so no caller can
    /// hold a stale one.
    models_dir: RwLock<PathBuf>,
    runtime: Runtime,
    downloads: Downloads,
    host_ram_bytes: u64,
}

impl std::fmt::Debug for ModelService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelService")
            .field("models_dir", &self.models_dir())
            .field("host_ram_bytes", &self.host_ram_bytes)
            .finish_non_exhaustive()
    }
}

impl ModelService {
    /// Builds the service over the daemon's store.
    ///
    /// Reads the models directory setting, measures host RAM once, fails
    /// the jobs a previous daemon left `running`
    /// ([`CAUSE_DAEMON_RESTART`]), and spawns the idle-unload ticker.
    /// Needs a tokio runtime.
    pub async fn new(store: Arc<Store>) -> Result<Arc<Self>, StoreError> {
        let models_dir = read_models_dir(&store).await?;
        let recovered = store.fail_running_model_jobs(CAUSE_DAEMON_RESTART).await?;
        if recovered > 0 {
            tracing::info!(
                count = recovered,
                "failed model jobs a previous daemon left running"
            );
        }
        let service = Arc::new(Self {
            store,
            models_dir: RwLock::new(models_dir),
            runtime: Runtime::new(),
            downloads: Downloads::default(),
            host_ram_bytes: host_ram_bytes(),
        });
        tokio::spawn(idle_unload_loop(Arc::downgrade(&service)));
        Ok(service)
    }

    /// A registry over the configured models directory.
    #[must_use]
    pub fn registry(&self) -> Registry {
        Registry::new(self.models_dir())
    }

    /// The inference runtime.
    #[must_use]
    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Total physical RAM, measured once at construction — what the
    /// catalog's `fits_host` check compares against.
    #[must_use]
    pub fn host_ram_bytes(&self) -> u64 {
        self.host_ram_bytes
    }

    /// The configured models directory.
    #[must_use]
    pub fn models_dir(&self) -> PathBuf {
        self.models_dir
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The `(light, heavy)` tier defaults as configured, unresolved.
    pub async fn defaults(&self) -> Result<(Option<String>, Option<String>), StoreError> {
        Ok((
            read_setting_string(&self.store, SETTING_DEFAULT_LIGHT).await?,
            read_setting_string(&self.store, SETTING_DEFAULT_HEAVY).await?,
        ))
    }

    /// The entry a tier resolves to, `heavy` falling back to `light`.
    ///
    /// The fallback is deterministic and one step deep: `heavy` → `light`
    /// → nothing. A `light` tier never borrows the heavy model, because
    /// the point of `light` is that it is cheap.
    pub async fn resolve(&self, tier: Tier) -> Result<ModelEntry, ModelUnavailable> {
        let (light, heavy) = self.defaults().await?;
        let configured = match tier {
            Tier::Light => light,
            Tier::Heavy => heavy.or(light),
        };
        let id = configured.ok_or(ModelUnavailable::NoDefault(tier))?;
        self.find(&id).await.ok_or(ModelUnavailable::Missing(id))
    }

    /// One generation on the tier's model, loading it if needed.
    ///
    /// The load is lazy and the swap is strict: a different model in
    /// memory is unloaded before this one is mapped, because two sets of
    /// weights do not fit.
    pub async fn generate(
        &self,
        tier: Tier,
        request: GenerateRequest,
    ) -> Result<GenerateResult, ModelUnavailable> {
        let entry = self.resolve(tier).await?;
        self.ensure_loaded(&entry).await?;
        // The daemon-internal path has no cancel surface yet: the sender
        // lives as long as the call and never fires.
        let (_never, cancel) = watch::channel(false);
        Ok(self.runtime.generate(request, cancel).await?)
    }

    /// Makes `entry` the loaded model, unloading whatever else was in
    /// memory first. A no-op when it is already loaded.
    pub async fn ensure_loaded(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError> {
        match self.runtime.snapshot().state {
            RuntimeState::Loaded(loaded) if loaded.id == entry.id => return Ok(loaded),
            RuntimeState::Loaded(loaded) => {
                tracing::info!(outgoing = %loaded.id, incoming = %entry.id, "swapping model");
                self.runtime.unload().await?;
            }
            RuntimeState::Idle | RuntimeState::Loading { .. } => {}
        }
        self.runtime.load(entry).await
    }

    /// Starts a transfer and returns its job id.
    ///
    /// Everything refusable is refused before the row exists: a second
    /// download of the same destination, a file already installed, a
    /// missing `curl`. Only once curl is running does a `model_job` row
    /// appear, so the history holds transfers, not rejected clicks.
    pub async fn start_download(
        &self,
        request: DownloadRequest,
        model_id: &str,
    ) -> Result<String, ModelServiceError> {
        let dest = request.dest.clone();
        if self.is_downloading(&dest).await {
            return Err(ModelServiceError::AlreadyDownloading(model_id.to_owned()));
        }
        let source = request.url.clone();
        let total = request
            .expected_size
            .and_then(|bytes| i64::try_from(bytes).ok());
        let handle = pam_model::download::start(request).map_err(|err| match err {
            DownloadError::AlreadyExists(_) => {
                ModelServiceError::AlreadyInstalled(model_id.to_owned())
            }
            DownloadError::Locked(_) => ModelServiceError::AlreadyDownloading(model_id.to_owned()),
            other => ModelServiceError::Download(other),
        })?;

        let job_id = new_job_id();
        self.store
            .insert_model_job(&job_id, KIND_DOWNLOAD, model_id, Some(&source), total)
            .await?;
        self.downloads
            .lock()
            .await
            .insert(job_id.clone(), (dest, handle.clone()));
        tokio::spawn(follow_download(
            Arc::clone(&self.store),
            Arc::clone(&self.downloads),
            job_id.clone(),
            handle,
        ));
        tracing::info!(job = %job_id, model = model_id, "download started");
        Ok(job_id)
    }

    /// Stops a running transfer, keeping its part file for a resume.
    /// `false` means no such job is in flight.
    pub async fn cancel_download(&self, job_id: &str) -> bool {
        let handle = self
            .downloads
            .lock()
            .await
            .get(job_id)
            .map(|(_, handle)| handle.clone());
        match handle {
            Some(handle) => {
                handle.cancel();
                true
            }
            None => false,
        }
    }

    /// Streams `entry`'s SHA-256 behind a job row and returns its id.
    pub async fn start_verify(&self, entry: ModelEntry) -> Result<String, ModelServiceError> {
        let job_id = new_job_id();
        let total = i64::try_from(entry.size_bytes).ok();
        self.store
            .insert_model_job(&job_id, KIND_VERIFY, &entry.id, None, total)
            .await?;
        let store = Arc::clone(&self.store);
        let registry = self.registry();
        let id = job_id.clone();
        tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || registry.verify(&entry)).await;
            let (state, detail) = match outcome {
                Ok(Ok(verified)) => {
                    if let Ok(done) = i64::try_from(verified.size_bytes) {
                        let _ = store.update_model_job_progress(&id, done, total).await;
                    }
                    (
                        JOB_DONE,
                        json!({
                            "sha256": verified.sha256,
                            "size_bytes": verified.size_bytes,
                            "matches_catalog": verified.matches_catalog,
                        }),
                    )
                }
                Ok(Err(err)) => (
                    JOB_FAILED,
                    json!({ "cause": "verify_failed", "detail": err.to_string() }),
                ),
                Err(err) => (
                    JOB_FAILED,
                    json!({ "cause": "verify_failed", "detail": err.to_string() }),
                ),
            };
            let _ = store
                .finish_model_job(&id, state, Some(&detail.to_string()))
                .await;
        });
        Ok(job_id)
    }

    /// The `admin.models.status` body: the runtime, the jobs worth
    /// showing, the tier defaults, and the settings behind them.
    pub async fn status(&self) -> Result<serde_json::Value, StoreError> {
        let (light, heavy) = self.defaults().await?;
        let rows = self.store.list_model_jobs(JOB_QUERY_LIMIT).await?;
        let (running, settled): (Vec<ModelJobRow>, Vec<ModelJobRow>) =
            rows.into_iter().partition(|job| job.state == JOB_RUNNING);
        let jobs: Vec<serde_json::Value> = running
            .iter()
            .chain(settled.iter().take(STATUS_JOB_HISTORY))
            .map(job_json)
            .collect();
        Ok(json!({
            "runtime": self.runtime.snapshot(),
            "jobs": jobs,
            "defaults": { "light": light, "heavy": heavy },
            "idle_unload_min": self.idle_unload_min().await?,
            "models_dir": self.models_dir().display().to_string(),
            "host_ram_bytes": self.host_ram_bytes,
        }))
    }

    /// The entry with `id`, or `None`. Registry failures are reported as
    /// absence — the model is unusable either way — and logged.
    pub(crate) async fn find(&self, id: &str) -> Option<ModelEntry> {
        let registry = self.registry();
        let wanted = id.to_owned();
        match tokio::task::spawn_blocking(move || registry.find(&wanted)).await {
            Ok(Ok(entry)) => entry,
            Ok(Err(err)) => {
                tracing::warn!(model = id, error = %err, "models directory unreadable");
                None
            }
            Err(err) => {
                tracing::warn!(model = id, error = %err, "registry lookup did not finish");
                None
            }
        }
    }

    /// Every entry in the models directory, sorted by id.
    pub(crate) async fn scan(&self) -> Result<Vec<ModelEntry>, RegistryError> {
        let registry = self.registry();
        match tokio::task::spawn_blocking(move || registry.scan()).await {
            Ok(result) => result,
            Err(err) => Err(RegistryError::Io(std::io::Error::other(err))),
        }
    }

    /// Whether a transfer is currently writing to `dest`.
    pub(crate) async fn is_downloading(&self, dest: &Path) -> bool {
        self.downloads
            .lock()
            .await
            .values()
            .any(|(path, _)| path == dest)
    }

    /// The configured idle-unload window in minutes.
    pub(crate) async fn idle_unload_min(&self) -> Result<u64, StoreError> {
        let raw = self.store.get_setting(SETTING_IDLE_UNLOAD_MIN).await?;
        Ok(raw
            .and_then(|value| serde_json::from_str::<u64>(&value).ok())
            .unwrap_or(DEFAULT_IDLE_UNLOAD_MIN))
    }

    /// Persists the idle-unload window.
    pub(crate) async fn set_idle_unload_min(&self, minutes: u64) -> Result<(), StoreError> {
        self.store
            .set_setting(SETTING_IDLE_UNLOAD_MIN, &minutes.to_string())
            .await
    }

    /// Persists a new models directory and rebuilds the registry over it.
    pub(crate) async fn set_models_dir(&self, dir: &Path) -> Result<(), StoreError> {
        let encoded = json!(dir.display().to_string()).to_string();
        self.store.set_setting(SETTING_MODELS_DIR, &encoded).await?;
        *self
            .models_dir
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = dir.to_path_buf();
        Ok(())
    }

    /// Persists (or clears) a tier's default model id.
    pub(crate) async fn set_default(
        &self,
        tier: Tier,
        model_id: Option<&str>,
    ) -> Result<(), StoreError> {
        let encoded = json!(model_id).to_string();
        self.store.set_setting(tier.setting_key(), &encoded).await
    }

    /// Drops the weights if the runtime has been idle long enough.
    async fn maybe_idle_unload(&self) {
        let Ok(idle_min) = self.idle_unload_min().await else {
            return;
        };
        let snapshot = self.runtime.snapshot();
        let RuntimeState::Loaded(loaded) = snapshot.state else {
            return;
        };
        if snapshot.busy || !should_unload(loaded.last_used_at, now_ts(), idle_min) {
            return;
        }
        match self.runtime.unload().await {
            Ok(()) => tracing::info!(model = %loaded.id, idle_min, "idle unload"),
            Err(err) => tracing::warn!(model = %loaded.id, error = %err, "idle unload failed"),
        }
    }
}

/// Whether a model last used at `last_used_ts` should be dropped now.
///
/// `idle_min` of `0` means never. Clock jumps backwards are treated as no
/// idleness rather than as a reason to unload.
#[must_use]
pub(crate) fn should_unload(last_used_ts: i64, now_ts: i64, idle_min: u64) -> bool {
    if idle_min == 0 {
        return false;
    }
    let Ok(window) = i64::try_from(idle_min.saturating_mul(60)) else {
        return false;
    };
    now_ts.saturating_sub(last_used_ts) >= window
}

/// Polls a transfer, writing progress and then its verdict onto the job
/// row, and forgets the handle when it is over.
async fn follow_download(
    store: Arc<Store>,
    downloads: Downloads,
    job_id: String,
    handle: DownloadHandle,
) {
    let mut ticker = tokio::time::interval(DOWNLOAD_POLL);
    let verdict = loop {
        ticker.tick().await;
        match handle.state() {
            DownloadState::Running(progress) => {
                let done = i64::try_from(progress.bytes).unwrap_or(i64::MAX);
                let total = progress.total.and_then(|bytes| i64::try_from(bytes).ok());
                if let Err(err) = store.update_model_job_progress(&job_id, done, total).await {
                    tracing::warn!(job = %job_id, error = %err, "download progress not recorded");
                }
            }
            terminal => break terminal,
        }
    };
    let (state, detail) = match verdict {
        DownloadState::Done { sha256, size_bytes } => {
            if let Ok(done) = i64::try_from(size_bytes) {
                let _ = store
                    .update_model_job_progress(&job_id, done, Some(done))
                    .await;
            }
            (
                JOB_DONE,
                Some(json!({ "sha256": sha256, "size_bytes": size_bytes })),
            )
        }
        DownloadState::Failed { cause, detail } => (
            JOB_FAILED,
            Some(json!({ "cause": cause, "detail": detail })),
        ),
        // `Running` cannot reach here; the loop only breaks on a terminal
        // state.
        DownloadState::Cancelled | DownloadState::Running(_) => (JOB_CANCELLED, None),
    };
    let encoded = detail.map(|value| value.to_string());
    if let Err(err) = store
        .finish_model_job(&job_id, state, encoded.as_deref())
        .await
    {
        tracing::warn!(job = %job_id, error = %err, "download verdict not recorded");
    } else {
        tracing::info!(job = %job_id, state, "download finished");
    }
    downloads.lock().await.remove(&job_id);
}

/// Ticks until the service is dropped, unloading an idle model.
async fn idle_unload_loop(service: Weak<ModelService>) {
    let mut ticker = tokio::time::interval(IDLE_TICK);
    loop {
        ticker.tick().await;
        let Some(service) = service.upgrade() else {
            return;
        };
        service.maybe_idle_unload().await;
    }
}

/// One job row as the GUI reads it, with `detail` parsed back to JSON so
/// the webview renders structure rather than an escaped string.
fn job_json(job: &ModelJobRow) -> serde_json::Value {
    json!({
        "id": job.id,
        "kind": job.kind,
        "model_id": job.model_id,
        "source": job.source,
        "state": job.state,
        "bytes_done": job.bytes_done,
        "bytes_total": job.bytes_total,
        "detail": job.detail,
        "created_ts": job.created_ts,
        "updated_ts": job.updated_ts,
    })
}

/// The models directory from the settings, or the platform default.
async fn read_models_dir(store: &Store) -> Result<PathBuf, StoreError> {
    if let Some(configured) = read_setting_string(store, SETTING_MODELS_DIR).await?
        && !configured.is_empty()
    {
        return Ok(PathBuf::from(configured));
    }
    // A machine with no home directory has nowhere canonical to keep
    // weights; the relative path scans empty, which is the honest answer.
    Ok(default_models_dir().unwrap_or_else(|| PathBuf::from("llm")))
}

/// A setting stored as a JSON string, or `None` when unset or null.
async fn read_setting_string(store: &Store, key: &str) -> Result<Option<String>, StoreError> {
    let Some(raw) = store.get_setting(key).await? else {
        return Ok(None);
    };
    Ok(serde_json::from_str::<Option<String>>(&raw)
        .unwrap_or(Some(raw))
        .filter(|value| !value.is_empty()))
}

/// Total physical RAM on this machine.
fn host_ram_bytes() -> u64 {
    let system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing()
            .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
    );
    system.total_memory()
}

/// A fresh `job_<ulid>` id.
fn new_job_id() -> String {
    format!("job_{}", ulid::Ulid::new())
}

/// Current time as unix seconds.
fn now_ts() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}
