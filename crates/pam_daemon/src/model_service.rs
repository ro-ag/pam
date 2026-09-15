//! The daemon's model layer. [`ModelService`] is the only daemon code touching [`pam_model`],
//! owning four state pieces: the **settings** ([`SETTING_MODELS_DIR`] and friends, persisted across
//! restarts); the **models directory**, rebuilt into a [`Registry`] on every setting change; the
//! **engine**, one [`EngineServer`] over the pinned `llama.cpp` release — a second load unloads the
//! first, strictly old-before-new, since two weight sets don't fit; and the **download handles**,
//! keyed by job id (cancel, dedupe). A download runs an hour vs the admin op's ms response, so it
//! returns a `job_id` and the history lives on `model_job` rows, polled every [`DOWNLOAD_POLL`]; a
//! `running` row found at boot belonged to a dead daemon and [`ModelService::new`] fails it with
//! [`CAUSE_DAEMON_RESTART`] (the part file still resumes). Administration is GUI-only
//! ([`crate::admin_models`]); the only daemon-internal entry point, [`ModelService::generate`],
//! returns [`ModelUnavailable::NoDefault`] with nothing configured so the caller falls back
//! deterministically. An [`IDLE_TICK`] ticker unloads the engine once idle past
//! [`SETTING_IDLE_UNLOAD_MIN`] (`0` = never), via the pure [`should_unload`].
//! The model layer never becomes a hard dependency: with nothing configured every caller falls back
//! deterministically. `last_used_at` (which drives idle unload) is updated after every load and
//! every generation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_model::download::{DownloadError, DownloadHandle, DownloadRequest, DownloadState};
use pam_model::engine;
use pam_model::engine_server::{EngineServer, EngineServerError, ServerOptions};
use pam_model::registry::{ModelEntry, Registry, RegistryError, default_models_dir};
use pam_model::runtime::{
    GenerateRequest, GenerateResult, LoadedModel, RuntimeError, RuntimeSnapshot, RuntimeState,
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

/// Cause written on the jobs a dead daemon left `running`.
pub const CAUSE_DAEMON_RESTART: &str = "daemon_restart";

/// Cause written when a verification could not finish.
pub const CAUSE_VERIFY_FAILED: &str = "verify_failed";

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
    /// Registry lookup could not run or failed; this does not mean the model is absent.
    #[error(transparent)]
    Service(#[from] ModelServiceError),
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
    /// Bounded worker admission or completion failed.
    #[error("{detail}")]
    Blocking {
        /// Stable worker refusal cause.
        cause: &'static str,
        /// Sanitized worker failure detail.
        detail: String,
    },
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

/// Owns the cancellation sender while an admin diagnostic future is alive.
/// Dropping a watch sender alone would leave its final `false` value unchanged.
pub(crate) struct DiagnosticCancellation(watch::Sender<bool>);

impl DiagnosticCancellation {
    pub(crate) fn new() -> (Self, watch::Receiver<bool>) {
        let (sender, receiver) = watch::channel(false);
        (Self(sender), receiver)
    }
}

impl Drop for DiagnosticCancellation {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
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
    /// Where the llama.cpp engine is installed (`<base>/engine`); set by
    /// the daemon from its base directory. Unset (tests) falls back to a
    /// private directory beside the models.
    engine_base: RwLock<Option<PathBuf>>,
    /// The llama.cpp supervisor, built the first time an installed engine
    /// is needed and rebuilt if the installed binary changes.
    engine: std::sync::Mutex<Option<Arc<EngineServer>>>,
    /// True while a generation is in flight on the engine. Status only —
    /// serialization comes from `operation`, held for the duration of
    /// every generate and load.
    busy: AtomicBool,
    /// Unix seconds of the last load or generation; what the idle-unload
    /// ticker compares [`SETTING_IDLE_UNLOAD_MIN`] against.
    last_used_at: AtomicI64,
    pub(crate) operation: Arc<Mutex<()>>,
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
        let recovered = store
            .fail_running_model_jobs(&job_failure_detail(
                CAUSE_DAEMON_RESTART,
                "the daemon restarted while this job was running",
            ))
            .await?;
        if recovered > 0 {
            tracing::info!(
                count = recovered,
                "failed model jobs a previous daemon left running"
            );
        }
        let service = Arc::new(Self {
            store,
            models_dir: RwLock::new(models_dir),
            engine_base: RwLock::new(None),
            engine: std::sync::Mutex::new(None),
            busy: AtomicBool::new(false),
            last_used_at: AtomicI64::new(0),
            operation: Arc::new(Mutex::new(())),
            downloads: Downloads::default(),
            host_ram_bytes: host_ram_bytes(),
        });
        tokio::spawn(idle_unload_loop(Arc::downgrade(&service)));
        Ok(service)
    }

    /// The llama.cpp supervisor when the pinned engine is installed under
    /// the engine base; `None` keeps generation on the in-process runtime.
    pub fn engine_server(&self) -> Option<Arc<EngineServer>> {
        let base = self.engine_base();
        let server = engine::status(&base).server_path?;
        let mut slot = self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = slot.as_ref()
            && existing.binary() == server
        {
            return Some(Arc::clone(existing));
        }
        let built = EngineServer::new(server, &base.join("run"), &base.join("engine")).ok()?;
        let built = Arc::new(built);
        *slot = Some(Arc::clone(&built));
        Some(built)
    }

    /// Unloads whatever holds weights: the engine process.
    pub async fn unload_all(&self) -> Result<(), RuntimeError> {
        if let Some(engine) = self.engine_server() {
            engine.unload().await;
        }
        Ok(())
    }

    /// The current state, read without touching the engine process: `Idle`
    /// when nothing is loaded, `Loaded` with the model the engine holds.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let state = match self.engine_server().and_then(|engine| engine.model()) {
            Some(model) => RuntimeState::Loaded(engine_snapshot_model(
                &model,
                self.last_used_at.load(Ordering::Acquire),
            )),
            None => RuntimeState::Idle,
        };
        RuntimeSnapshot {
            state,
            busy: self.busy.load(Ordering::Acquire),
        }
    }

    /// Marks the engine as used just now — called after every successful
    /// load and every successful generation, and read by the idle-unload
    /// ticker.
    fn touch_last_used(&self) {
        self.last_used_at.store(now_ts(), Ordering::Release);
    }

    /// One bounded completion on the engine, shaped like the runtime-typed
    /// result every caller expects.
    async fn engine_generate(
        &self,
        engine: &EngineServer,
        loaded: &LoadedModel,
        request: &GenerateRequest,
        cancel: watch::Receiver<bool>,
        input_limit: usize,
    ) -> Result<GenerateResult, RuntimeError> {
        self.busy.store(true, Ordering::Release);
        let outcome = engine
            .generate(request, cancel, input_limit, ENGINE_GENERATE_DEADLINE)
            .await;
        self.busy.store(false, Ordering::Release);
        self.touch_last_used();
        let result = outcome.map_err(engine_error)?;
        let decode_ms = result.predicted_ms.max(0.0);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "timings are reported to humans in whole milliseconds"
        )]
        let (prompt_ms, decode_ms_u64, tokens_per_sec) = (
            result.prompt_ms.max(0.0) as u64,
            decode_ms as u64,
            if decode_ms > 0.0 {
                result.completion_tokens as f64 / (decode_ms / 1000.0)
            } else {
                0.0
            },
        );
        Ok(GenerateResult {
            model: pam_model::runtime::GenerationModel::from(loaded),
            text: result.text,
            prompt_tokens: result.prompt_tokens,
            completion_tokens: result.completion_tokens,
            prompt_ms,
            decode_ms: decode_ms_u64,
            tokens_per_sec,
        })
    }

    /// A registry over the configured models directory.
    #[must_use]
    pub fn registry(&self) -> Registry {
        Registry::new(self.models_dir())
    }

    /// Total physical RAM, measured once at construction — what the
    /// catalog's `fits_host` check compares against.
    #[must_use]
    pub fn host_ram_bytes(&self) -> u64 {
        self.host_ram_bytes
    }

    /// Points the engine layout at the daemon's private base directory.
    pub fn set_engine_base(&self, base: PathBuf) {
        *self
            .engine_base
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(base);
    }

    /// The directory `pam_model::engine` installs under: the daemon's
    /// base directory, or a private directory beside the models when the
    /// daemon never set one.
    #[must_use]
    pub fn engine_base(&self) -> PathBuf {
        self.engine_base
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| self.models_dir().join(".pam"))
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
        self.find(&id).await?.ok_or(ModelUnavailable::Missing(id))
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
        self.generate_bounded(tier, request, pam_model::runtime::CONTEXT_TOKENS)
            .await
    }

    /// Applies a task-specific prefill limit using the generator's exact tokenizer.
    pub async fn generate_bounded(
        &self,
        tier: Tier,
        request: GenerateRequest,
        input_limit: usize,
    ) -> Result<GenerateResult, ModelUnavailable> {
        let _operation = self.operation.lock().await;
        let entry = self.resolve(tier).await?;
        let loaded = self.ensure_loaded_inner(&entry).await?;
        // The daemon-internal path has no cancel surface yet: the sender
        // lives as long as the call and never fires.
        let (_never, cancel) = watch::channel(false);
        let engine = self.engine_server().ok_or_else(engine_not_installed)?;
        Ok(self
            .engine_generate(&engine, &loaded, &request, cancel, input_limit)
            .await?)
    }

    /// Diagnose on one explicitly requested installed model without loading or swapping.
    /// Dropping the caller signals cancellation; an in-progress forward pass finishes
    /// before the worker observes that signal, so cancellation is cooperative.
    pub async fn generate_diagnostic(
        &self,
        model_id: &str,
        request: GenerateRequest,
    ) -> Result<GenerateResult, ModelUnavailable> {
        let _operation = self.operation.try_lock().map_err(|_| RuntimeError::Busy)?;
        let entry = self
            .find(model_id)
            .await?
            .ok_or_else(|| ModelServiceError::UnknownModel(model_id.to_owned()))?;
        let (guard, cancel) = DiagnosticCancellation::new();
        let loaded = self.ensure_loaded_inner(&entry).await?;
        let engine = self.engine_server().ok_or_else(engine_not_installed)?;
        let result = self
            .engine_generate(
                &engine,
                &loaded,
                &request,
                cancel,
                pam_model::runtime::CONTEXT_TOKENS,
            )
            .await;
        drop(guard);
        Ok(result?)
    }

    /// Makes `entry` the loaded model, unloading whatever else was in
    /// memory first. A no-op when it is already loaded.
    pub async fn ensure_loaded(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError> {
        let _operation = self.operation.lock().await;
        let current = self
            .find(&entry.id)
            .await
            .map_err(|error| RuntimeError::LoadFailed(error.to_string()))?;
        if current
            .as_ref()
            .is_none_or(|current| current.path != entry.path)
        {
            return Err(RuntimeError::LoadFailed(
                "The installed model entry changed before loading; select it again.".to_owned(),
            ));
        }
        self.ensure_loaded_inner(entry).await
    }

    async fn ensure_loaded_inner(&self, entry: &ModelEntry) -> Result<LoadedModel, RuntimeError> {
        let engine = self.engine_server().ok_or_else(engine_not_installed)?;
        if let Some(current) = engine.model()
            && current.id == entry.id
            && current.path == entry.path
        {
            self.touch_last_used();
            return Ok(engine_loaded_model(entry, &current));
        }
        let current = engine
            .load(&entry.id, &entry.path, &ServerOptions::default())
            .await
            .map_err(engine_error)?;
        self.touch_last_used();
        Ok(engine_loaded_model(entry, &current))
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

    /// Throws away the partial download beside `dest`, returning the
    /// bytes discarded.
    ///
    /// The in-flight check comes first so a running transfer is refused
    /// as [`ModelServiceError::AlreadyDownloading`] — the name of the
    /// thing to cancel — rather than as a lock error the human cannot
    /// map to an action.
    pub async fn discard_partial(
        &self,
        dest: &Path,
        model_id: &str,
    ) -> Result<u64, ModelServiceError> {
        if self.is_downloading(dest).await {
            return Err(ModelServiceError::AlreadyDownloading(model_id.to_owned()));
        }
        let target = dest.to_path_buf();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            pam_model::download::discard_partial(&target)
        })
        .await
        .map_err(ModelServiceError::from)?
        .map_err(ModelServiceError::Download)
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
            let outcome =
                crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                    registry.verify(&entry)
                })
                .await;
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
                    job_failure_value(CAUSE_VERIFY_FAILED, &err.to_string()),
                ),
                Err(err) => (JOB_FAILED, job_failure_value(err.cause(), &err.to_string())),
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
        let engine_status = engine::status(&self.engine_base());
        let engine_loaded = self.engine_server().and_then(|engine| engine.model());
        Ok(json!({
            "runtime": self.snapshot(),
            "engine": {
                "installed": engine_status.installed,
                "expected_tag": engine_status.expected_tag,
                "cause": engine_status.cause,
                "loaded": engine_loaded,
            },
            "jobs": jobs,
            "defaults": { "light": light, "heavy": heavy },
            "idle_unload_min": self.idle_unload_min().await?,
            "models_dir": self.models_dir().display().to_string(),
            "host_ram_bytes": self.host_ram_bytes,
        }))
    }

    /// The entry with `id`, or `None` only when the registry confirms absence.
    pub(crate) async fn find(&self, id: &str) -> Result<Option<ModelEntry>, ModelServiceError> {
        let registry = self.registry();
        let wanted = id.to_owned();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            registry.find(&wanted)
        })
        .await?
        .map_err(ModelServiceError::from)
    }

    /// Every entry in the models directory, sorted by id.
    pub(crate) async fn scan(&self) -> Result<Vec<ModelEntry>, ModelServiceError> {
        let registry = self.registry();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            registry.scan()
        })
        .await?
        .map_err(ModelServiceError::from)
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
    pub(crate) async fn set_models_dir(&self, dir: &Path) -> Result<(), ModelUnavailable> {
        let _operation = self.operation.lock().await;
        if self.models_dir().as_path() == dir {
            return Ok(());
        }
        // Registry IDs repeat across directories. Never leave the previous root's
        // loaded snapshot available under an ID now resolved in a different root.
        self.unload_all().await?;
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
        let Ok(_operation) = self.operation.try_lock() else {
            return;
        };
        let Ok(idle_min) = self.idle_unload_min().await else {
            return;
        };
        if self.busy.load(Ordering::Acquire) {
            return;
        }
        let Some(engine) = self.engine_server() else {
            return;
        };
        let Some(loaded) = engine.model() else {
            return;
        };
        let last_used = self.last_used_at.load(Ordering::Acquire);
        if !should_unload(last_used, now_ts(), idle_min) {
            return;
        }
        engine.unload().await;
        tracing::info!(model = %loaded.id, idle_min, "idle unload");
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
        DownloadState::Failed { cause, detail } => {
            // The cause and curl's own complaint go to the log as well as
            // the row: a human reading daemon.log after a failed download
            // should not have to open the GUI to learn what broke.
            tracing::warn!(job = %job_id, cause = %cause, detail = %detail, "download failed");
            (JOB_FAILED, Some(job_failure_value(&cause, &detail)))
        }
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

/// The `{cause, detail, recovery}` body a failed job carries, in the same
/// shape as an admin refusal — one thing for the GUI to render, whatever
/// went wrong.
pub(crate) fn job_failure_value(cause: &str, detail: &str) -> serde_json::Value {
    json!({
        "cause": cause,
        "detail": detail,
        "recovery": pam_model::download::failure_recovery(cause),
    })
}

/// [`job_failure_value`] as the string the store column holds.
pub(crate) fn job_failure_detail(cause: &str, detail: &str) -> String {
    job_failure_value(cause, detail).to_string()
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

impl From<crate::blocking_jobs::Error> for ModelServiceError {
    fn from(error: crate::blocking_jobs::Error) -> Self {
        Self::Blocking {
            cause: error.cause(),
            detail: error.to_string(),
        }
    }
}

/// How long one engine completion may take end to end.
const ENGINE_GENERATE_DEADLINE: std::time::Duration = std::time::Duration::from_mins(15);

/// The runtime-shaped view of a model the engine holds.
fn engine_loaded_model(
    entry: &ModelEntry,
    model: &pam_model::engine_server::EngineModel,
) -> LoadedModel {
    LoadedModel {
        id: entry.id.clone(),
        quant: entry
            .info
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |info| info.quant_label.clone()),
        architecture: entry
            .info
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |info| info.architecture.clone()),
        context_length: model.context_length,
        weight_bytes: entry.size_bytes,
        device: "llama.cpp".to_owned(),
        loaded_at: model.loaded_at_ms,
        last_used_at: model.loaded_at_ms,
        last_tokens_per_sec: None,
    }
}

fn engine_error(error: EngineServerError) -> RuntimeError {
    match error {
        EngineServerError::NoModelLoaded => RuntimeError::NoModelLoaded,
        EngineServerError::InputTooLong { tokens, limit } => {
            RuntimeError::PromptTooLong { tokens, limit }
        }
        EngineServerError::Cancelled => RuntimeError::Cancelled,
        other => RuntimeError::LoadFailed(other.to_string()),
    }
}

/// The refusal every caller sees when the pinned engine is not installed.
fn engine_not_installed() -> RuntimeError {
    RuntimeError::LoadFailed(
        "the llama.cpp engine is not installed; install it from Models".to_owned(),
    )
}

/// [`snapshot`](ModelService::snapshot)'s view of the model the engine
/// holds, without a registry lookup: `snapshot` is polled every couple of
/// seconds and must never scan the models directory to answer. Quant and
/// architecture are reported as `unknown` here; a caller that already has
/// the [`ModelEntry`] (`ensure_loaded_inner`) uses [`engine_loaded_model`]
/// instead, which fills them in from the registry.
fn engine_snapshot_model(
    model: &pam_model::engine_server::EngineModel,
    last_used_at: i64,
) -> LoadedModel {
    let weight_bytes = std::fs::metadata(&model.path).map_or(0, |meta| meta.len());
    LoadedModel {
        id: model.id.clone(),
        quant: "unknown".to_owned(),
        architecture: "unknown".to_owned(),
        context_length: model.context_length,
        weight_bytes,
        device: "llama.cpp".to_owned(),
        loaded_at: model.loaded_at_ms,
        last_used_at: if last_used_at > 0 {
            last_used_at
        } else {
            model.loaded_at_ms
        },
        last_tokens_per_sec: None,
    }
}
