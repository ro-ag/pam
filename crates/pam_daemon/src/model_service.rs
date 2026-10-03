//! The daemon's model layer. [`ModelService`] is the only daemon code touching [`pam_model`],
//! owning four state pieces: the **settings** ([`SETTING_MODELS_DIR`] and friends, persisted across
//! restarts); the **models directory**, rebuilt into a [`Registry`] on every setting change; the
//! **engine**, one [`EngineServer`] over the pinned `llama.cpp` release — a second load unloads the
//! first, strictly old-before-new, since two weight sets don't fit; and the **download handles**,
//! keyed by job id (cancel, dedupe). A download runs an hour vs the admin op's ms response, so it
//! returns a `job_id` and the history lives on `model_job` rows, polled every [`DOWNLOAD_POLL`]; a
//! `running` row found at boot belonged to a dead daemon and [`ModelService::new`] fails it with
//! [`CAUSE_DAEMON_RESTART`] (the part file still resumes). A daemon that stops in good order does
//! not leave such rows: [`ModelService::shutdown`] cancels the running transfers and joins their
//! followers, which record the same cause, before the store closes. Administration is GUI-only
//! ([`crate::admin_models`]); the only daemon-internal entry point,
//! [`ModelService::generate_bounded`], returns [`ModelUnavailable::NoDefault`] with nothing
//! configured so the caller falls back deterministically. An [`IDLE_TICK`] ticker unloads the engine once idle past
//! [`SETTING_IDLE_UNLOAD_MIN`] (`0` = never), via the pure `should_unload`.
//! The managed policy bounds two of the settings at read time and never rewrites what the human
//! saved: `models.dir` ([`ModelService::models_dir`]: locked, or the policy's default until the human
//! chooses one) and `models.idle_unload_min` (locked, or clamped into `min`/`max`, so a ceiling also
//! turns "never" into the ceiling). The ops that bring weights or the engine in (`allowed_sources`,
//! `engine_source`) and the curator pick (`allowed_curators`) are gated in [`crate::admin_models`]
//! and [`crate::admin_engine`].
//! The model layer never becomes a hard dependency: with nothing configured every caller falls back
//! deterministically. `last_used_at` (which drives idle unload) is updated after every load and
//! every *successful* generation: a caller retrying against a failing engine must not keep it
//! "in use". Verification records live under the daemon's private base (`<base>/model-trust`),
//! never beside the weights: the models directory is not a trust boundary. For the same reason
//! the engine never opens a verified model by its path there: verifying makes PAM's own copy
//! under `<base>/engine/weights/<sha256>.gguf` (a block-sharing clone on APFS, a hashed full copy
//! elsewhere), the digest is the digest of that copy, and that copy is what is loaded. The copy
//! lives as long as the verification behind it (it is swept on delete, on a new digest, when the
//! source file changed or went away; an unload only triggers the sweep). A verification is a job
//! with progress and a cancel, like a download. Qualification is a claim about the capability
//! bench and is bound to what the bench measured: a record counts only while this build starts the
//! model with the engine options the record was measured with ([`pam_model::qualification`]);
//! otherwise the model is unqualified, cause `contract_changed`. The summary's own prompt was never
//! measured separately; its fingerprint ([`summary_disclosure`]) is disclosed in status and
//! readiness and gates nothing. A generation is
//! bounded end to end ([`GENERATE_TOTAL_DEADLINE`], lock wait and load included) and takes a
//! cancel receiver; an engine process found dead surfaces as `engine_exited` and the next
//! request reloads; an engine a `SIGKILL`ed daemon left running is found through its pid file and
//! stopped, after its executable, arguments and start time prove it is ours.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pam_model::download::{
    DownloadError, DownloadHandle, DownloadRequest, DownloadState, ImportRequest, TransferLimits,
};
use pam_model::engine;
use pam_model::engine_server::{
    EngineContract, EngineServer, EngineServerError, LegacyRuntime, ServerOptions,
};
use pam_model::qualification::{PromptContract, QUALIFIED, Qualification};
use pam_model::registry::{
    ModelClass, ModelEntry, Registry, RegistryError, VerifyOutcome, default_models_dir,
};
use pam_model::runtime::{
    FramedEvidence, GenerateRequest, GenerateResult, LoadedModel, RuntimeError, RuntimeSnapshot,
    RuntimeState, frame_evidence_with,
};
use pam_model::weights::{Control, WeightsError};
use pam_net::{NetFailure, NetSettings, NetworkSource};
use pam_store::{ModelJobRow, Store, StoreError};
use serde_json::json;
use tokio::sync::{Mutex, watch};

use crate::managed_policy::{EffectiveEntry, Key};
use crate::managed_policy_service::PolicyHandle;
use crate::network_service::Source;

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

/// `model_job.kind` for an import from a local file: a copy into the
/// models directory with the same progress, verdict and cancel as a
/// download. Its `source` is the absolute path of the file, where a
/// download's is an `https://` address. The store admits the kind since
/// schema version 15.
pub const KIND_IMPORT: &str = "import";

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

/// Cause written when the volume holding PAM's base has no room for the private copy of
/// the weights a verification makes. The detail names the bytes needed.
pub const CAUSE_NO_SPACE: &str = "no_space";

/// `task` of the disclosed prompt contract: the log summary, the one job a qualified
/// model serves today.
pub const SUMMARY_CONTRACT_TASK: &str = "log.summary";

/// The framed-prompt token limit a summary is admitted under. It mirrors the limit
/// `log_service` passes to [`ModelService::generate_bounded_cancellable`]; a unit test
/// holds the two together until that call names this constant.
pub const SUMMARY_INPUT_LIMIT_TOKENS: usize = 2048;

/// The plain statement that travels with every disclosure of the summary's contract.
pub const SUMMARY_DISCLOSURE_NOTE: &str = "Summaries are advisory and labelled untrusted. The summary prompt has not been measured \
     separately: qualification is a capability-bench result.";

/// What PAM discloses about the summary a model writes: the fingerprint of the prompt
/// it is sent, and that no qualification record was measured under that prompt. A
/// disclosure, never a gate: a verified, bench-qualified model summarises whatever this
/// says, and an edit to the summary prompt changes the fingerprint and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SummaryDisclosure {
    /// [`SUMMARY_CONTRACT_TASK`].
    pub task: &'static str,
    /// Fingerprint of the summary's prompt contract under the engine options given;
    /// `None` only if the summary request cannot be built at all.
    pub fingerprint: Option<String>,
    /// Whether a qualification record was measured under this fingerprint. `false`:
    /// none has been.
    pub measured: bool,
    /// [`SUMMARY_DISCLOSURE_NOTE`].
    pub note: &'static str,
}

/// The [`SummaryDisclosure`] for a model started with `engine`.
#[must_use]
pub fn summary_disclosure(engine: &EngineContract) -> SummaryDisclosure {
    SummaryDisclosure {
        task: SUMMARY_CONTRACT_TASK,
        fingerprint: summary_contract().map(|contract| contract.fingerprint(engine)),
        measured: false,
        note: SUMMARY_DISCLOSURE_NOTE,
    }
}

/// Stands in for the log text when the summary request is built for its fingerprint.
const CONTRACT_PROBE_EVIDENCE: &str = "<evidence>";

/// Stands in for the per-call fence token when the summary request is built for its
/// fingerprint.
const CONTRACT_PROBE_TOKEN: &str = "<fence>";

/// The prompt contract of a log summary: the request `log_service` really builds, over
/// placeholder evidence, an unknown exit status and a fixed fence token, with the token
/// limit it is admitted under. Editing the summary instructions, the framing in
/// [`pam_model::runtime::frame_evidence`], the output cap or the temperature changes its
/// fingerprint. That fingerprint is disclosed ([`summary_disclosure`]) and gates nothing:
/// qualification is a capability-bench claim, and no record was measured under this
/// prompt.
///
/// `None` if the request cannot be built at all.
#[must_use]
pub fn summary_contract() -> Option<&'static PromptContract> {
    static CONTRACT: LazyLock<Option<PromptContract>> = LazyLock::new(|| {
        fn probe_frame(
            instructions: &str,
            host_facts: &[(&str, &str)],
            evidence: &str,
        ) -> Option<FramedEvidence> {
            frame_evidence_with(instructions, host_facts, evidence, CONTRACT_PROBE_TOKEN)
        }
        crate::log_service::summary_request_with(CONTRACT_PROBE_EVIDENCE, None, probe_frame)
            .ok()
            .map(|request| {
                PromptContract::of(SUMMARY_CONTRACT_TASK, &request, SUMMARY_INPUT_LIMIT_TOKENS)
            })
    });
    CONTRACT.as_ref()
}

/// How often a download's follower reads its handle and writes progress.
pub const DOWNLOAD_POLL: Duration = Duration::from_millis(500);

/// How long [`ModelService::shutdown`] waits for the transfer followers and
/// the idle-unload ticker to end. A cancelled download ends within a
/// [`DOWNLOAD_POLL`]; a verification stops at its next chunk.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// What the job row of a transfer says when the daemon stopped under it.
const STOPPED_DETAIL: &str = "the daemon stopped while this job was running";

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
    /// The configured model has no verified digest, so nothing vouches for its bytes.
    #[error("default model {0} is not verified")]
    Unverified(String),
    /// The configured model is verified but no qualification record covers its
    /// digest on this target: it proves the wiring, it does not serve a job.
    #[error("default model {0} is not qualified on this target")]
    Unqualified(String),
    /// The runtime refused or failed.
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    /// A diagnostic named a model other than the one the engine holds; a
    /// diagnostic never loads or swaps, so the human loads it first.
    #[error("{requested} is not the loaded model ({})", resident.as_deref().unwrap_or("nothing is loaded"))]
    NotResident {
        /// The model the diagnostic asked for.
        requested: String,
        /// The model the engine holds, if any.
        resident: Option<String>,
    },
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

/// Owns a cancellation sender while an admin future (diagnostic, engine
/// install) is alive, and sends `true` when dropped: an admin deadline
/// drops the future, and dropping a watch sender alone would leave its
/// final `false` in place, so a worker waiting on `changed()` would pend
/// forever on the closed channel instead of stopping.
pub(crate) struct CancelOnDrop(watch::Sender<bool>);

impl CancelOnDrop {
    pub(crate) fn new() -> (Self, watch::Receiver<bool>) {
        let (sender, receiver) = watch::channel(false);
        (Self(sender), receiver)
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}

/// Holds `busy` at `true` for exactly as long as a generation future is
/// alive. A caller's deadline (`admin.models.try`, a bounded summary) drops
/// the future mid-await; a plain store-after-await would then leave `busy`
/// stuck and the idle-unload ticker would never drop the weights.
pub(crate) struct BusyGuard<'a>(&'a AtomicBool);

impl<'a> BusyGuard<'a> {
    pub(crate) fn engage(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Release);
        Self(flag)
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The registry's view of the model the engine holds, cached at load time so
/// [`ModelService::snapshot`] answers without touching the filesystem.
type Resident = Option<(PathBuf, LoadedModel)>;

/// The live download handles, keyed by job id, with the destination each
/// is writing to.
type Downloads = Arc<Mutex<HashMap<String, (PathBuf, DownloadHandle)>>>;

/// The cancel flag of every verification in flight, keyed by job id.
type Verifies = Arc<std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>>;

/// The daemon's model layer (see the module docs).
pub struct ModelService {
    store: Arc<Store>,
    /// The managed policy in force (see [`crate::managed_policy_service`]).
    policy: Arc<PolicyHandle>,
    /// The models directory the human saved (`None`: never set). Behind a
    /// lock because `admin.models.settings.set` moves it while the daemon
    /// serves; a [`Registry`] is rebuilt from the effective directory
    /// ([`Self::models_dir`]: this value under the managed policy's
    /// `models.dir`) on every read, so no caller can hold a stale one.
    stored_models_dir: RwLock<Option<PathBuf>>,
    /// The qualification table every registry read matches against: the
    /// compiled-in one, or a fixture table an in-crate test installed.
    qualifications: RwLock<&'static [Qualification]>,
    /// Where the llama.cpp engine is installed (`<base>/engine`); set by
    /// the daemon from its base directory. Unset (tests) falls back to a
    /// private directory beside the models.
    engine_base: RwLock<Option<PathBuf>>,
    /// Where a transfer's network profile (proxy, no-proxy list, CA
    /// bundle) comes from, asked once per transfer start so a setting the
    /// human saves applies to the next download. Until the daemon sets its
    /// own, a direct connection with the platform's trust.
    network: RwLock<Arc<dyn NetworkSource>>,
    /// The daemon's network settings service, when it has one: where the
    /// engine and models mirrors are read from, per transfer. Unset (tests)
    /// means no mirror.
    mirrors: RwLock<Option<Arc<crate::network_service::NetworkService>>>,
    /// Lets the in-crate tests fetch from a plain-http loopback origin;
    /// production has no such switch.
    #[cfg(test)]
    plain_http_for_tests: AtomicBool,
    /// The release the engine ops install, import and disclose instead of
    /// the pinned one: a fake archive the in-crate tests built. Production
    /// has no such switch; [`Self::engine_release`] is the only reader.
    #[cfg(test)]
    engine_release_for_tests: RwLock<Option<engine::EngineRelease>>,
    /// The llama.cpp supervisor, built the first time an installed engine
    /// is needed and rebuilt if the installed binary changes.
    engine: std::sync::Mutex<Option<Arc<EngineServer>>>,
    /// True while a generation is in flight on the engine. Status only —
    /// serialization comes from `operation`, held for the duration of
    /// every generate and load. Set and cleared by [`BusyGuard`].
    busy: AtomicBool,
    /// What the engine holds, as the registry described it when it was
    /// loaded (weight bytes, quant, architecture); `snapshot` reads this
    /// instead of stat-ing the weights on an async thread.
    resident: RwLock<Resident>,
    /// Unix seconds of the last load or generation; what the idle-unload
    /// ticker compares [`SETTING_IDLE_UNLOAD_MIN`] against.
    last_used_at: AtomicI64,
    pub(crate) operation: Arc<Mutex<()>>,
    downloads: Downloads,
    verifies: Verifies,
    /// Whether the private weights store has been swept since the engine base was set
    /// (`true` once done). Held across the sweep, so a verification started meanwhile
    /// waits instead of having its unfinished copy taken for a dead daemon's.
    weights_swept: Mutex<bool>,
    host_ram_bytes: u64,
    /// Whether the pid file of a previous daemon's engine has been looked at since the
    /// engine base was set.
    orphans_checked: AtomicBool,
    /// Milliseconds one `generate_bounded` may take in total; tests shorten it.
    generate_total_ms: AtomicU64,
    /// Milliseconds the engine itself may take over one completion; tests shorten it.
    generate_step_ms: AtomicU64,
    /// The service's own tasks: the idle-unload ticker and one follower per
    /// running transfer. [`Self::shutdown`] joins them; a sync lock, taken
    /// only to add a handle or to take them all, never across an await.
    /// Plain handles, so a service dropped without a shutdown leaves its
    /// tasks running instead of aborting them.
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// `true` from the moment [`Self::shutdown`] begins. The ticker returns
    /// on it, and a follower whose transfer ends cancelled reads it to tell
    /// the daemon's stop from a human's cancel.
    stopping: watch::Sender<bool>,
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
    /// Needs a tokio runtime. Holds `policy`, the managed policy handle.
    pub async fn new(
        store: Arc<Store>,
        policy: Arc<PolicyHandle>,
    ) -> Result<Arc<Self>, StoreError> {
        let stored_models_dir = read_stored_models_dir(&store).await?;
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
            policy,
            stored_models_dir: RwLock::new(stored_models_dir),
            qualifications: RwLock::new(QUALIFIED),
            engine_base: RwLock::new(None),
            network: RwLock::new(Arc::new(Arc::new(NetSettings::direct()))),
            mirrors: RwLock::new(None),
            #[cfg(test)]
            plain_http_for_tests: AtomicBool::new(false),
            #[cfg(test)]
            engine_release_for_tests: RwLock::new(None),
            engine: std::sync::Mutex::new(None),
            busy: AtomicBool::new(false),
            resident: RwLock::new(None),
            last_used_at: AtomicI64::new(0),
            operation: Arc::new(Mutex::new(())),
            downloads: Downloads::default(),
            verifies: Verifies::default(),
            weights_swept: Mutex::new(false),
            host_ram_bytes: host_ram_bytes(),
            orphans_checked: AtomicBool::new(false),
            generate_total_ms: AtomicU64::new(duration_ms(GENERATE_TOTAL_DEADLINE)),
            generate_step_ms: AtomicU64::new(duration_ms(ENGINE_GENERATE_DEADLINE)),
            tasks: std::sync::Mutex::new(Vec::new()),
            stopping: watch::channel(false).0,
        });
        service.spawn_task(idle_unload_loop(
            Arc::downgrade(&service),
            service.stopping.subscribe(),
        ));
        Ok(service)
    }

    /// The managed policy handle this layer reads through (see
    /// [`crate::managed_policy_service`]).
    #[must_use]
    pub fn policy(&self) -> &Arc<PolicyHandle> {
        &self.policy
    }

    /// Spawns one of the service's own tasks where [`Self::shutdown`] can
    /// join it, forgetting the ones that have already ended. Crate-visible
    /// so a test can plant a task that ends only when it says.
    pub(crate) fn spawn_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|handle| !handle.is_finished());
        tasks.push(tokio::spawn(task));
    }

    /// Stops what the service runs on its own, before the daemon closes the
    /// store: cancels every running download and verification, waits for
    /// their followers to write the job rows' verdicts, and stops the
    /// idle-unload ticker.
    ///
    /// A transfer stopped here is recorded as `failed` with
    /// [`CAUSE_DAEMON_RESTART`], which is what the next boot would have
    /// written for a row left `running`; a download keeps its part file and
    /// resumes. The wait is bounded by [`SHUTDOWN_WAIT`]: a follower that has
    /// not ended by then (a finished download still hashing its private
    /// copy, an engine unload in progress) is logged and left running, never
    /// waited for. Such a task finds the store closed, and its row is failed
    /// by the next boot.
    ///
    /// Call it once no admin operation can arrive: a transfer started
    /// afterwards is not stopped by it. Calling it twice is harmless.
    pub async fn shutdown(&self) {
        self.shutdown_within(SHUTDOWN_WAIT).await;
    }

    /// [`Self::shutdown`] with the bound given, so a test need not wait
    /// [`SHUTDOWN_WAIT`] to see a follower left behind.
    pub(crate) async fn shutdown_within(&self, wait: Duration) {
        self.stopping.send_replace(true);
        for (_, handle) in self.downloads.lock().await.values() {
            handle.cancel();
        }
        for cancel in self
            .verifies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
        {
            cancel.store(true, Ordering::Release);
        }
        let mut tasks = std::mem::take(
            &mut *self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let joined = tokio::time::timeout(wait, async {
            for task in &mut tasks {
                // A task that panicked has ended all the same.
                let _ = task.await;
            }
        })
        .await;
        if joined.is_err() {
            // Dropping a handle detaches its task: it is left to end on its
            // own, not aborted in the middle of a write.
            tracing::warn!(
                left = tasks.iter().filter(|task| !task.is_finished()).count(),
                waited_ms = duration_ms(wait),
                "model tasks did not stop in time and were left running; a job row one of \
                 them leaves unfinished is failed at the next start"
            );
        }
    }

    /// The llama.cpp supervisor when the pinned engine is installed under
    /// the engine base; `None` keeps generation on the in-process runtime.
    /// Reads the engine manifest on the calling thread; a status read that
    /// already holds one passes it to [`Self::engine_server_for`].
    pub fn engine_server(&self) -> Option<Arc<EngineServer>> {
        self.engine_server_for(&engine::status(&self.engine_base()))
    }

    /// [`Self::engine_server`] for an engine status already read, so the
    /// manifest is not read twice (nor on the async thread).
    pub fn engine_server_for(&self, status: &engine::EngineStatus) -> Option<Arc<EngineServer>> {
        let base = self.engine_base();
        let server = status.server_path.clone()?;
        let mut slot = self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = slot.as_ref()
            && existing.binary() == server
        {
            return Some(Arc::clone(existing));
        }
        // The engine's socket, key file and pid file live under
        // `<base>/engine/run`, never in the public `<base>/run` an agent's
        // sandbox must let it traverse.
        let layout = engine::EngineLayout::new(&base);
        let built = EngineServer::new(server, &layout.runtime_dir(), layout.root()).ok()?;
        let built = Arc::new(built);
        *slot = Some(Arc::clone(&built));
        Some(built)
    }

    /// Unloads whatever holds weights: the engine process. The private copies stay (a
    /// reload must not cost a copy of the weights); only the ones no live verification
    /// references any more are swept, now that nothing maps them.
    pub async fn unload_all(&self) -> Result<(), RuntimeError> {
        if let Some(engine) = self.engine_server() {
            engine.unload().await;
        }
        self.set_resident(None);
        self.sweep_private_copies(false).await;
        Ok(())
    }

    /// [`Registry::sweep_private_copies`] on the model lane; what it removed is logged.
    /// `false` when the lane had no room and nothing ran.
    async fn sweep_private_copies(&self, include_unfinished: bool) -> bool {
        let registry = self.registry();
        let swept =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                registry.sweep_private_copies(include_unfinished)
            })
            .await;
        let Ok(report) = swept else {
            return false;
        };
        if !report.removed.is_empty() || report.records_removed > 0 {
            tracing::info!(
                copies = report.removed.len(),
                records = report.records_removed,
                "removed private weight copies no verification references"
            );
        }
        true
    }

    /// The first sweep after the engine base is known, which also removes the copies a
    /// killed daemon left half-made. It runs before any verification of this process can
    /// start one of its own (a verification and a download both wait here first).
    async fn sweep_private_copies_once(&self) {
        let mut swept = self.weights_swept.lock().await;
        if *swept {
            return;
        }
        *swept = self.sweep_private_copies(true).await;
    }

    /// The current state, read without touching the engine process or the
    /// filesystem: `Idle` when nothing is loaded, `Loaded` with the model
    /// the engine holds. Polled every couple of seconds, so it reads the
    /// supervisor already built (never `engine::status`, which reads the
    /// manifest) and the registry view cached at load time (never the
    /// weights' metadata).
    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let engine = self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let state = match engine.and_then(|engine| engine.model()) {
            Some(model) => RuntimeState::Loaded(self.resident_view(&model)),
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

    /// The runtime-shaped view of `model`: the registry entry cached when
    /// it was loaded, or — if the engine holds something this service did
    /// not load — a view with `unknown` quant/architecture and no size.
    fn resident_view(&self, model: &pam_model::engine_server::EngineModel) -> LoadedModel {
        let last_used_at = self.last_used_at.load(Ordering::Acquire);
        let cached = self
            .resident
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut view = match cached.as_ref() {
            Some((path, loaded)) if loaded.id == model.id && *path == model.path => loaded.clone(),
            _ => engine_snapshot_model(model),
        };
        view.loaded_at = model.loaded_at_ms;
        view.last_used_at = if last_used_at > 0 {
            last_used_at
        } else {
            model.loaded_at_ms
        };
        view
    }

    /// Remembers (or forgets) the registry view of what the engine holds.
    fn set_resident(&self, resident: Resident) {
        *self
            .resident
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resident;
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
        let outcome = {
            let _busy = BusyGuard::engage(&self.busy);
            engine
                .generate(
                    request,
                    cancel,
                    input_limit,
                    Duration::from_millis(self.generate_step_ms.load(Ordering::Relaxed)),
                )
                .await
        };
        // Only a completed generation counts as use: callers that keep retrying a
        // failing engine must not hold it loaded past the idle window.
        let result = outcome.map_err(engine_error)?;
        self.touch_last_used();
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

    /// A registry over the configured models directory, keeping its verification
    /// records ([`Self::trust_dir`]) and its copies of verified weights
    /// ([`Self::weights_dir`]) in the daemon's private base.
    #[must_use]
    pub fn registry(&self) -> Registry {
        Registry::with_qualifications(self.models_dir(), *self.qualifications())
            .with_trust_dir(self.trust_dir())
            .with_weights_dir(self.weights_dir())
    }

    /// Where PAM's own copies of verified weights live:
    /// `<daemon base>/engine/weights/<sha256>.gguf`. The engine is started on these
    /// files, never on a path in the models directory.
    #[must_use]
    pub fn weights_dir(&self) -> PathBuf {
        self.engine_base().join("engine").join("weights")
    }

    /// Where verification records live: `<daemon base>/model-trust`, inside the `0700`
    /// base the agent sandbox is assumed to exclude. The models directory is not
    /// assumed protected, so nothing there can vouch for weights. (Before the daemon
    /// sets its base — tests — it falls back to a directory beside the models.)
    #[must_use]
    pub fn trust_dir(&self) -> PathBuf {
        self.engine_base().join("model-trust")
    }

    fn qualifications(&self) -> std::sync::RwLockReadGuard<'_, &'static [Qualification]> {
        self.qualifications
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Qualifies `sha256` on the current target with a leaked one-record table,
    /// so a test can drive the production gate with a fixture it just hashed. The
    /// record is "measured" with the engine options this build starts the verified file
    /// with that digest with (verify it first), so the fixture passes the bench-contract
    /// check the way a real record must.
    #[cfg(test)]
    pub(crate) fn qualify_for_tests(&self, sha256: &str) {
        self.qualify_measured_with_for_tests(sha256, self.engine_contract_for_tests(sha256));
    }

    /// The engine options this build starts the verified file with digest `sha256` with
    /// (the defaults when no such file is verified yet).
    #[cfg(test)]
    pub(crate) fn engine_contract_for_tests(&self, sha256: &str) -> EngineContract {
        let context = self
            .registry()
            .scan()
            .ok()
            .and_then(|entries| {
                entries.into_iter().find(|entry| {
                    entry
                        .verified
                        .as_ref()
                        .is_some_and(|record| record.sha256 == sha256)
                })
            })
            .and_then(|entry| entry.info.and_then(|info| info.context_length));
        EngineContract::of(&ServerOptions::for_model(context))
    }

    /// [`Self::qualify_for_tests`] with the engine options the record was measured with
    /// supplied: options other than the ones this build uses are a record that no longer
    /// describes how the model is run.
    #[cfg(test)]
    pub(crate) fn qualify_measured_with_for_tests(&self, sha256: &str, measured: EngineContract) {
        let record = Qualification {
            artifact: "fixture",
            sha256: Box::leak(sha256.to_owned().into_boxed_str()),
            engine_tag: engine::ENGINE_TAG,
            targets: Box::leak(
                vec![engine::Target::current().expect("a supported target")].into_boxed_slice(),
            ),
            contract: "answer-contract-v2",
            case_set_sha256: "",
            record: "docs/benchmarks/none",
            host: "test",
            accuracy: 1.0,
            false_passes: 0,
            warm_p95_ms: 1,
            decided: "2026-01-01",
            system_sha256: "",
            output_cap: 160,
            input_limit: 640,
            engine: measured,
            bench_contract: "",
        };
        let fingerprint = record.bench().fingerprint(&record.engine);
        let table: &'static [Qualification] = Box::leak(
            vec![Qualification {
                bench_contract: Box::leak(fingerprint.into_boxed_str()),
                ..record
            }]
            .into_boxed_slice(),
        );
        *self
            .qualifications
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = table;
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
        self.orphans_checked.store(false, Ordering::Release);
        // Another base, another private weights store to sweep. Uncontended outside a
        // sweep in flight, which belongs to the previous base anyway.
        if let Ok(mut swept) = self.weights_swept.try_lock() {
            *swept = false;
        }
    }

    /// Points transfers at the daemon's network settings. Read per transfer
    /// start, never cached: the next download runs under whatever the human
    /// last saved.
    pub fn set_network_source(&self, source: Arc<dyn NetworkSource>) {
        *self
            .network
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = source;
    }

    /// Points transfers at the daemon's network settings service: the
    /// profile source and the mirrors in one. What the daemon calls at boot.
    pub fn set_network_service(&self, network: Arc<crate::network_service::NetworkService>) {
        self.set_network_source(Arc::clone(&network) as Arc<dyn NetworkSource>);
        *self
            .mirrors
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(network);
    }

    /// The engine and models mirrors the next transfer would use, read
    /// now from the network settings; `(None, None)` when the daemon set no
    /// service. Settings that cannot be used refuse, never fall back.
    pub async fn mirrors(
        &self,
    ) -> Result<(Option<pam_net::MirrorBase>, Option<pam_net::MirrorBase>), NetFailure> {
        let service = self
            .mirrors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match service {
            Some(network) => network.mirrors().await,
            None => Ok((None, None)),
        }
    }

    /// The source transfers read their network profile from.
    #[must_use]
    pub fn network_source(&self) -> Arc<dyn NetworkSource> {
        Arc::clone(
            &self
                .network
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The network profile the next transfer runs under, resolved now. A
    /// source that cannot produce one refuses; nothing falls back to a
    /// direct connection.
    pub async fn network_settings(&self) -> Result<Arc<NetSettings>, NetFailure> {
        let source = self.network_source();
        source.settings().await
    }

    /// Lets this service's downloads fetch from a plain-`http` loopback
    /// origin, the way the download suite's own fixtures are served. Test
    /// builds only.
    #[cfg(test)]
    pub(crate) fn allow_plain_http_downloads_for_tests(&self) {
        self.plain_http_for_tests.store(true, Ordering::Release);
    }

    /// The release the engine ops work with: the pinned one for this
    /// platform, `None` where the platform has no pinned asset. In test
    /// builds a release pinned through `pin_engine_release_for_tests`
    /// takes its place; production reads only the compiled-in constants.
    #[must_use]
    pub fn engine_release(&self) -> Option<engine::EngineRelease> {
        #[cfg(test)]
        if let Some(release) = self
            .engine_release_for_tests
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Some(release);
        }
        engine::Target::current().map(engine::EngineRelease::pinned)
    }

    /// Makes the engine ops install, import and disclose `release` — a fake
    /// archive the test built — in place of the pinned one. Keep its tag and
    /// build the pinned ones: `engine::status` reads those constants, not
    /// this. Test builds only.
    #[cfg(test)]
    pub(crate) fn pin_engine_release_for_tests(&self, release: engine::EngineRelease) {
        *self
            .engine_release_for_tests
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(release);
    }

    /// Forgets the supervisor built over the installed engine, so the next
    /// use reads the manifest again. Called after the engine is removed;
    /// the caller has made sure nothing is loaded.
    pub fn forget_engine(&self) {
        *self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.set_resident(None);
    }

    /// Stops an engine a previous daemon left running (SIGKILL, crash), once per
    /// engine base. The supervisor's pid file names the process; it is killed only when
    /// the live process with that pid has the recorded executable, was started with the
    /// recorded model and key-file arguments, and started when the record says. Anything
    /// else with that pid is somebody else's: the stale record is removed and nothing is
    /// killed. Returns what happened, for logs and tests.
    ///
    /// The same pass migrates the engine runtime a daemon before the
    /// `<base>/engine/run` layout kept inside the public run directory
    /// (`<base>/run/engine.sock`, `<base>/run/engine/`): its pid record is
    /// adopted first, so an engine that daemon left is still found and
    /// stopped, and the leftovers are then removed — logged, never left
    /// behind silently. With no engine installed there is nothing to reap,
    /// but the leftovers still go.
    pub async fn reap_orphan_engine(&self) -> OrphanReap {
        if self.orphans_checked.swap(true, Ordering::AcqRel) {
            return OrphanReap::NothingToDo;
        }
        let legacy = self.legacy_engine_runtime();
        let Some(engine) = self.engine_server() else {
            // No engine installed yet: look again once there is one.
            self.orphans_checked.store(false, Ordering::Release);
            if legacy.present() {
                let cleanup = crate::blocking_jobs::run(
                    crate::blocking_jobs::Kind::ModelFilesystem,
                    move || legacy.remove(),
                )
                .await;
                if let Ok(cleanup) = cleanup {
                    log_legacy_engine_cleanup(&cleanup);
                }
            }
            return OrphanReap::NothingToDo;
        };
        if engine.model().is_some() {
            return OrphanReap::NothingToDo;
        }
        let outcome =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                // The old record is read for the reap before the old files go.
                let adopted = engine
                    .adopt_pid_record(&legacy)
                    .then(|| (legacy.pid_file(), engine.pid_file()));
                let reaped = reap_recorded_engine(&engine);
                (reaped, adopted, legacy.remove())
            })
            .await;
        let Ok((reaped, adopted, cleanup)) = outcome else {
            return OrphanReap::NothingToDo;
        };
        if let Some((from, to)) = adopted {
            tracing::info!(
                from = %from.display(),
                to = %to.display(),
                "adopted the engine pid record an older daemon kept inside the run directory"
            );
        }
        log_legacy_engine_cleanup(&cleanup);
        reaped
    }

    /// The engine runtime as daemons before the `<base>/engine/run` layout
    /// kept it, inside this base's public run directory.
    fn legacy_engine_runtime(&self) -> LegacyRuntime {
        LegacyRuntime::in_run_dir(&self.engine_base().join("run"))
    }

    /// The daemon's base directory as set by [`Self::set_engine_base`], or
    /// `None` when the daemon never set one (tests); what the models
    /// directory must never overlap.
    #[must_use]
    pub fn daemon_base(&self) -> Option<PathBuf> {
        self.engine_base
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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

    /// The models directory in force: the managed policy's `models.dir`
    /// (locked, or its default while the human has not chosen one), else
    /// what the human saved, else the platform default.
    #[must_use]
    pub fn models_dir(&self) -> PathBuf {
        self.models_dir_entry().0
    }

    /// [`Self::models_dir`] with where it came from, for the `effective`
    /// block of the status and settings replies.
    #[must_use]
    pub fn models_dir_entry(&self) -> (PathBuf, EffectiveEntry) {
        let stored = self
            .stored_models_dir
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (value, entry) = self
            .policy
            .view()
            .effective_string(Key::ModelsDir, stored.map(|dir| dir.display().to_string()));
        // A machine with no home directory has nowhere canonical to keep
        // weights; the relative path scans empty, which is the honest answer.
        let dir = value.map_or_else(
            || default_models_dir().unwrap_or_else(|| PathBuf::from("llm")),
            PathBuf::from,
        );
        (dir, entry)
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
    /// the point of `light` is that it is cheap. The entry must be admitted
    /// ([`Self::admit`]): a configured id that has lost its verification or
    /// was never qualified stays configured and visible, but does not serve.
    pub async fn resolve(&self, tier: Tier) -> Result<ModelEntry, ModelUnavailable> {
        let (light, heavy) = self.defaults().await?;
        let configured = match tier {
            Tier::Light => light,
            Tier::Heavy => heavy.or(light),
        };
        let id = configured.ok_or(ModelUnavailable::NoDefault(tier))?;
        let entry = self.find(&id).await?.ok_or(ModelUnavailable::Missing(id))?;
        Self::admit(&entry)?;
        Ok(entry)
    }

    /// The job gate: verified digest and a qualification on this target whose bench
    /// contract this build's engine options reproduce. Applied where a tier is pointed
    /// at a model and where a tier resolves, so a default seeded past the admin op is
    /// refused at the same line. A record measured with other options refuses like no
    /// record at all, and the refusal says what differs and that the model needs
    /// re-measurement.
    pub fn admit(entry: &ModelEntry) -> Result<(), ModelUnavailable> {
        if entry.class == ModelClass::TestOnly {
            return Err(ModelUnavailable::Unverified(entry.id.clone()));
        }
        if entry.qualification.is_none() {
            return Err(ModelUnavailable::Unqualified(
                match &entry.qualification_issue {
                    Some(issue) => format!("{} ({issue})", entry.id),
                    None => entry.id.clone(),
                },
            ));
        }
        Ok(())
    }

    /// One generation on the tier's model, loading it if needed, with a
    /// task-specific prefill limit enforced by the generator's exact
    /// tokenizer.
    ///
    /// The load is lazy and the swap is strict: a different model in
    /// memory is unloaded before this one is mapped, because two sets of
    /// weights do not fit.
    pub async fn generate_bounded(
        &self,
        tier: Tier,
        request: GenerateRequest,
        input_limit: usize,
    ) -> Result<GenerateResult, ModelUnavailable> {
        // The caller has no cancel surface: the sender lives as long as the call and
        // never fires. The call is still bounded by the total deadline.
        let (_never, cancel) = watch::channel(false);
        self.generate_bounded_cancellable(tier, request, input_limit, cancel)
            .await
    }

    /// [`Self::generate_bounded`] that stops when `cancel` flips to `true`, and in any
    /// case after [`GENERATE_TOTAL_DEADLINE`] counted from this call: waiting for the
    /// service-wide operation lock behind another generation, loading the model and the
    /// completion all spend the same budget. A flow step that was cancelled, or whose
    /// deadline passed, therefore stops holding the lock (and the GPU) instead of
    /// queueing up to fifteen minutes behind a wedged engine.
    ///
    /// Dropping the future on the deadline or the cancel is safe: the engine child is
    /// `kill_on_drop` while loading and a generation in flight is abandoned by closing
    /// its connection.
    pub async fn generate_bounded_cancellable(
        &self,
        tier: Tier,
        request: GenerateRequest,
        input_limit: usize,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<GenerateResult, ModelUnavailable> {
        let total = Duration::from_millis(self.generate_total_ms.load(Ordering::Relaxed));
        let engine_cancel = cancel.clone();
        let work = async {
            let _operation = self.operation.lock().await;
            let entry = self.resolve(tier).await?;
            let loaded = self.ensure_loaded_inner(&entry).await?;
            let engine = self.engine_server().ok_or_else(engine_not_installed)?;
            // The cancel is also handed to the engine so an in-flight completion is
            // abandoned by closing its connection, not merely dropped here.
            Ok(self
                .engine_generate(&engine, &loaded, &request, engine_cancel, input_limit)
                .await?)
        };
        tokio::select! {
            biased;
            () = cancelled(&mut cancel) => Err(RuntimeError::Cancelled.into()),
            outcome = tokio::time::timeout(total, work) => outcome.unwrap_or_else(|_| {
                Err(RuntimeError::GenerationFailed(format!(
                    "no result within {} s; the engine is busy or stuck",
                    total.as_secs()
                ))
                .into())
            }),
        }
    }

    /// Reads and overwrites the last-use stamp, so a test can tell a counted use from
    /// an uncounted one.
    #[cfg(all(test, unix))]
    pub(crate) fn last_used_for_tests(&self, set: Option<i64>) -> i64 {
        if let Some(value) = set {
            self.last_used_at.store(value, Ordering::Release);
        }
        self.last_used_at.load(Ordering::Acquire)
    }

    /// Shortens the generation deadlines so a test can watch them fire.
    #[cfg(test)]
    pub(crate) fn set_generate_deadlines_for_tests(&self, total: Duration, step: Duration) {
        self.generate_total_ms
            .store(duration_ms(total), Ordering::Relaxed);
        self.generate_step_ms
            .store(duration_ms(step), Ordering::Relaxed);
    }

    /// Diagnose on one explicitly requested installed model without loading or swapping:
    /// the engine must already hold exactly that entry (same id and path), otherwise
    /// [`ModelUnavailable::NotResident`]. Dropping the caller signals cancellation; an
    /// in-progress forward pass finishes before the worker observes that signal, so
    /// cancellation is cooperative.
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
        let engine = self.engine_server().ok_or_else(engine_not_installed)?;
        let current = match engine.model() {
            Some(current) if current.id == entry.id && current.path == entry.engine_path() => {
                current
            }
            other => {
                // The same id over another file: it was loaded before it was verified
                // (or before its verification changed), so the engine does not hold
                // the bytes this entry now stands for.
                let resident = other.map(|current| {
                    if current.id == entry.id {
                        format!(
                            "{} is loaded from a file it no longer stands for; load it again",
                            current.id
                        )
                    } else {
                        current.id
                    }
                });
                return Err(ModelUnavailable::NotResident {
                    requested: entry.id,
                    resident,
                });
            }
        };
        let loaded = engine_loaded_model(&entry, &current);
        let (guard, cancel) = CancelOnDrop::new();
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
        if current.as_ref().is_none_or(|current| {
            current.path != entry.path
                || current.fingerprint != entry.fingerprint
                || current.private_copy != entry.private_copy
        }) {
            return Err(RuntimeError::LoadFailed(
                "The installed model entry changed before loading; select it again.".to_owned(),
            ));
        }
        let loaded = self.ensure_loaded_inner(entry).await?;
        self.touch_last_used();
        Ok(loaded)
    }

    /// Loads `entry` as given, without scanning again. The caller holds the operation
    /// lock and vouches that `entry` is what it wants loaded; what protects the load
    /// from a models directory that changed since that scan is that a verified entry is
    /// loaded from PAM's private copy.
    pub(crate) async fn ensure_loaded_inner(
        &self,
        entry: &ModelEntry,
    ) -> Result<LoadedModel, RuntimeError> {
        let engine = self.engine_server().ok_or_else(engine_not_installed)?;
        // An engine left by a SIGKILLed daemon holds the weights' memory and may hold the
        // socket path: stop it before starting another.
        if let OrphanReap::Killed { pid } = self.reap_orphan_engine().await {
            tracing::warn!(pid, "stopped an engine a previous daemon left running");
        }
        // A verified entry is loaded from PAM's private copy of the verified bytes, never
        // from the models directory: whatever is renamed or rewritten there between the
        // scan and the engine's open cannot change what loads. An unverified entry (Try
        // only, never a job) has no such copy and loads the file itself.
        let engine_path = entry.engine_path().to_path_buf();
        if let Some(current) = engine.model()
            && current.id == entry.id
            && current.path == engine_path
        {
            let loaded = engine_loaded_model(entry, &current);
            self.set_resident(Some((engine_path, loaded.clone())));
            // Reusing what is already loaded is not a use: the generation that asked
            // counts itself once it succeeds.
            return Ok(loaded);
        }
        // The swap is about to happen: forget the old view before the old
        // weights go, so a snapshot taken mid-load never pairs the new
        // engine model with the old registry entry.
        self.set_resident(None);
        // The same constructor the qualification fingerprint uses, so the options a
        // record was measured under are the options the model is started with.
        let options =
            ServerOptions::for_model(entry.info.as_ref().and_then(|info| info.context_length));
        // The verification is a claim about the private copy: refuse if it is not the
        // file that was hashed, both before the engine opens it and once it is up.
        self.recheck(entry).await?;
        let current = engine
            .load(&entry.id, &engine_path, &options)
            .await
            .map_err(engine_error)?;
        if let Err(error) = self.recheck(entry).await {
            engine.unload().await;
            return Err(error);
        }
        let loaded = engine_loaded_model(entry, &current);
        self.set_resident(Some((engine_path, loaded.clone())));
        self.touch_last_used();
        Ok(loaded)
    }

    /// [`Registry::recheck`] on the blocking lane, as a load refusal.
    async fn recheck(&self, entry: &ModelEntry) -> Result<(), RuntimeError> {
        let registry = self.registry();
        let checked = entry.clone();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
            registry.recheck(&checked)
        })
        .await
        .map_err(|error| RuntimeError::LoadFailed(error.to_string()))?
        .map_err(|error| RuntimeError::LoadFailed(error.to_string()))
    }

    /// Starts a transfer and returns its job id.
    ///
    /// Everything refusable is refused before the row exists: a second
    /// download of the same destination, a file already installed, a
    /// missing `curl`, a plain-http address, network settings that cannot
    /// be used. Only once curl is running does a `model_job` row appear, so
    /// the history holds transfers, not rejected clicks. The network
    /// profile is resolved here, for this transfer.
    pub async fn start_download(
        &self,
        request: DownloadRequest,
        model_id: &str,
    ) -> Result<String, ModelServiceError> {
        let dest = request.dest.clone();
        let dest_for_record = request.dest.clone();
        let expected_digest = request.expected_sha256.is_some();
        self.sweep_private_copies_once().await;
        if self.is_downloading(&dest).await {
            return Err(ModelServiceError::AlreadyDownloading(model_id.to_owned()));
        }
        let net = self
            .network_settings()
            .await
            .map_err(|failure| ModelServiceError::Download(DownloadError::Network(failure)))?;
        let source = request.url.clone();
        let total = request
            .expected_size
            .and_then(|bytes| i64::try_from(bytes).ok());
        #[cfg(test)]
        let started = if self.plain_http_for_tests.load(Ordering::Acquire) {
            pam_model::download::start_over_plain_http_for_tests(
                request,
                net,
                TransferLimits::default(),
            )
        } else {
            pam_model::download::start_with_limits(request, net, TransferLimits::default())
        };
        #[cfg(not(test))]
        let started =
            pam_model::download::start_with_limits(request, net, TransferLimits::default());
        let handle = started.map_err(|err| match err {
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
        self.spawn_task(follow_download(
            Arc::clone(&self.store),
            Arc::clone(&self.downloads),
            job_id.clone(),
            handle,
            // A download that carried an expected digest and finished has been checked
            // against it; only then is it recorded as verified, in the private store.
            expected_digest.then(|| (self.registry(), dest_for_record)),
            self.stopping.subscribe(),
        ));
        tracing::info!(job = %job_id, model = model_id, "download started");
        Ok(job_id)
    }

    /// Copies weights in from a file on this machine behind a job row
    /// (kind [`KIND_IMPORT`]) and returns its id: the copy runs with the
    /// same handle, progress, cancel and verdict as a download, and lands
    /// recorded as verified when the request carried an expected digest
    /// that the copy matched. Refusals happen before any row exists; no
    /// network profile is resolved, because no network is used.
    pub async fn start_import(
        &self,
        request: ImportRequest,
        model_id: &str,
    ) -> Result<String, ModelServiceError> {
        let dest = request.dest.clone();
        let dest_for_record = request.dest.clone();
        let expected_digest = request.expected_sha256.is_some();
        let source = request.source.display().to_string();
        let total = request
            .expected_size
            .and_then(|bytes| i64::try_from(bytes).ok());
        self.sweep_private_copies_once().await;
        if self.is_downloading(&dest).await {
            return Err(ModelServiceError::AlreadyDownloading(model_id.to_owned()));
        }
        let handle = pam_model::download::start_import(request).map_err(|err| match err {
            DownloadError::AlreadyExists(_) => {
                ModelServiceError::AlreadyInstalled(model_id.to_owned())
            }
            DownloadError::Locked(_) => ModelServiceError::AlreadyDownloading(model_id.to_owned()),
            other => ModelServiceError::Download(other),
        })?;
        let job_id = new_job_id();
        self.store
            .insert_model_job(&job_id, KIND_IMPORT, model_id, Some(&source), total)
            .await?;
        self.downloads
            .lock()
            .await
            .insert(job_id.clone(), (dest, handle.clone()));
        self.spawn_task(follow_download(
            Arc::clone(&self.store),
            Arc::clone(&self.downloads),
            job_id.clone(),
            handle,
            expected_digest.then(|| (self.registry(), dest_for_record)),
            self.stopping.subscribe(),
        ));
        tracing::info!(job = %job_id, model = model_id, "import started");
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

    /// Stops a running verification: its private copy in progress is removed and
    /// nothing is recorded. `false` means no such job is in flight.
    pub fn cancel_verify(&self, job_id: &str) -> bool {
        let flag = self
            .verifies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(job_id)
            .cloned();
        flag.is_some_and(|flag| {
            flag.store(true, Ordering::Release);
            true
        })
    }

    /// Verifies `entry` behind a job row and returns its id.
    ///
    /// The job makes PAM's private copy of the weights and hashes it
    /// ([`Registry::verify_with`]) on the hash lane, never on a request thread: on a
    /// volume that cannot share blocks that is a full copy of the file. The row carries
    /// the bytes done every [`DOWNLOAD_POLL`], the job stops on
    /// [`Self::cancel_verify`], and a volume without room fails it with
    /// [`CAUSE_NO_SPACE`] and the bytes needed.
    pub async fn start_verify(&self, entry: ModelEntry) -> Result<String, ModelServiceError> {
        self.sweep_private_copies_once().await;
        let job_id = new_job_id();
        let total = i64::try_from(entry.size_bytes).ok();
        self.store
            .insert_model_job(&job_id, KIND_VERIFY, &entry.id, None, total)
            .await?;
        let cancel = Arc::new(AtomicBool::new(false));
        self.verifies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(job_id.clone(), Arc::clone(&cancel));
        self.spawn_task(follow_verify(
            Arc::clone(&self.store),
            Arc::clone(&self.verifies),
            job_id.clone(),
            self.registry(),
            entry,
            cancel,
            self.stopping.subscribe(),
        ));
        Ok(job_id)
    }

    /// The `admin.models.status` body: the runtime, the jobs worth
    /// showing, the tier defaults, their readiness, and the settings behind them.
    pub async fn status(&self) -> Result<serde_json::Value, ModelUnavailable> {
        // First status after a daemon start: stop an engine the last daemon left behind,
        // and clear the private weight copies nothing references any more.
        let _ = self.reap_orphan_engine().await;
        self.sweep_private_copies_once().await;
        let (light, heavy) = self.defaults().await?;
        let rows = self.store.list_model_jobs(JOB_QUERY_LIMIT).await?;
        let (running, settled): (Vec<ModelJobRow>, Vec<ModelJobRow>) =
            rows.into_iter().partition(|job| job.state == JOB_RUNNING);
        let jobs: Vec<serde_json::Value> = running
            .iter()
            .chain(settled.iter().take(STATUS_JOB_HISTORY))
            .map(job_json)
            .collect();
        // The manifest read is a filesystem round trip: it runs on the
        // model lane, like every other registry read behind this status.
        let base = self.engine_base();
        let engine_status =
            crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelFilesystem, move || {
                engine::status(&base)
            })
            .await
            .map_err(ModelServiceError::from)?;
        let engine_loaded = self
            .engine_server_for(&engine_status)
            .and_then(|engine| engine.model());
        let engine_exited = self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|engine| engine.last_exit());
        let resident = engine_loaded.as_ref().map(|loaded| loaded.id.clone());
        let (idle_unload_min, idle_entry) = self.idle_unload_min_entry().await?;
        let (models_dir, models_dir_entry) = self.models_dir_entry();
        let readiness = json!({
            "light": self
                .readiness(Tier::Light, &engine_status, resident.as_deref())
                .await?,
            "heavy": self
                .readiness(Tier::Heavy, &engine_status, resident.as_deref())
                .await?,
        });
        Ok(json!({
            "runtime": self.snapshot(),
            "engine": {
                "installed": engine_status.installed,
                "expected_tag": engine_status.expected_tag,
                "cause": engine_status.cause,
                "loaded": engine_loaded,
                // Set when the engine process died on its own (killed for memory, a
                // crash): why, until the model is loaded again.
                "exited": engine_exited,
            },
            "jobs": jobs,
            "defaults": { "light": light, "heavy": heavy },
            "readiness": readiness,
            "idle_unload_min": idle_unload_min,
            "models_dir": models_dir.display().to_string(),
            // Where each of the two settings above came from: the human, the
            // built-in default, or the managed policy (and whether it is locked).
            "effective": {
                "models_dir": models_dir_entry.to_json(),
                "idle_unload_min": idle_entry.to_json(),
            },
            // Where PAM keeps its own copy of every verified model (what the engine loads).
            "weights_dir": self.weights_dir().display().to_string(),
            // A disclosure, not a gate: the fingerprint of the prompt a summary is sent
            // (at the engine's default options; each tier's readiness carries its own
            // model's), and that nothing was measured under it.
            "summary_contract": summary_disclosure(&EngineContract::of(&ServerOptions::default())),
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

    /// The idle-unload window in minutes in force (`0` = never): what the
    /// human saved (else the built-in default) under the managed policy's
    /// `models.idle_unload_min`.
    pub(crate) async fn idle_unload_min(&self) -> Result<u64, StoreError> {
        Ok(self.idle_unload_min_entry().await?.0)
    }

    /// [`Self::idle_unload_min`] with where it came from.
    pub(crate) async fn idle_unload_min_entry(&self) -> Result<(u64, EffectiveEntry), StoreError> {
        let raw = self.store.get_setting(SETTING_IDLE_UNLOAD_MIN).await?;
        // A stored value that does not read is the same as none stored.
        let stored = raw.and_then(|value| serde_json::from_str::<u64>(&value).ok());
        Ok(self
            .policy
            .view()
            .effective_idle_unload_min(stored, DEFAULT_IDLE_UNLOAD_MIN))
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
        let stored = self
            .stored_models_dir
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (current, entry) = self.models_dir_entry();
        // Nothing to do when the human already has this directory, or has
        // none and this is what is in force (but a directory the policy
        // supplied as a default is not the human's until they choose it).
        if stored.as_deref() == Some(dir)
            || (stored.is_none() && current.as_path() == dir && entry.source != Source::Policy)
        {
            return Ok(());
        }
        // Registry IDs repeat across directories. Never leave the previous root's
        // loaded snapshot available under an ID now resolved in a different root.
        if current.as_path() != dir {
            self.unload_all().await?;
        }
        let encoded = json!(dir.display().to_string()).to_string();
        self.store.set_setting(SETTING_MODELS_DIR, &encoded).await?;
        *self
            .stored_models_dir
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(dir.to_path_buf());
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
        // The setting is read before the operation lock is taken: a store
        // read suspends, and holding the lock across it would make a
        // request arriving meanwhile answer `Busy` although nothing is
        // being loaded or unloaded.
        let Ok(idle_min) = self.idle_unload_min().await else {
            return;
        };
        let Ok(_operation) = self.operation.try_lock() else {
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
        self.set_resident(None);
        self.sweep_private_copies(false).await;
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
    record_as_verified: Option<(Registry, PathBuf)>,
    stopping: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(DOWNLOAD_POLL);
    // A store that refuses every progress write would otherwise warn twice
    // a second for an hour: the first failure is a warning, the rest are
    // debug lines with a count until the write succeeds again.
    let mut progress_failures: u64 = 0;
    let verdict = loop {
        ticker.tick().await;
        match handle.state() {
            DownloadState::Running(progress) => {
                let done = i64::try_from(progress.bytes).unwrap_or(i64::MAX);
                let total = progress.total.and_then(|bytes| i64::try_from(bytes).ok());
                match store.update_model_job_progress(&job_id, done, total).await {
                    Ok(()) => {
                        if progress_failures > 0 {
                            tracing::info!(
                                job = %job_id,
                                failures = progress_failures,
                                "download progress recording recovered"
                            );
                        }
                        progress_failures = 0;
                    }
                    Err(err) => {
                        progress_failures += 1;
                        if progress_failures == 1 {
                            tracing::warn!(job = %job_id, error = %err, "download progress not recorded");
                        } else {
                            tracing::debug!(
                                job = %job_id,
                                error = %err,
                                failures = progress_failures,
                                "download progress still not recorded"
                            );
                        }
                    }
                }
            }
            terminal => break terminal,
        }
    };
    let (state, detail) = match verdict {
        DownloadState::Done { sha256, size_bytes } => {
            // `Some(None)`: recorded as verified. `Some(Some(why))`: the file landed but
            // could not be recorded, and the row says why so "unverified" is not a riddle.
            let mut recorded_verified: Option<Option<String>> = None;
            if let Some((registry, dest)) = record_as_verified {
                let digest = sha256.clone();
                // Recording makes and hashes PAM's private copy of the file (the digest
                // curl's pass computed was of a file in the models directory): the hash
                // lane, not the one registry scans wait on.
                let recorded =
                    crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelHash, move || {
                        registry.record_download(&dest, &digest, size_bytes)
                    })
                    .await;
                // The file is there either way; a failed record costs one Verify, and
                // the model stays unverified until then.
                let failure = match recorded {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.to_string()),
                    Err(error) => Some(error.to_string()),
                };
                if let Some(error) = &failure {
                    tracing::warn!(job = %job_id, %error, "download finished but was not recorded as verified");
                }
                recorded_verified = Some(failure);
            }
            if let Ok(done) = i64::try_from(size_bytes) {
                let _ = store
                    .update_model_job_progress(&job_id, done, Some(done))
                    .await;
            }
            let mut detail = json!({ "sha256": sha256, "size_bytes": size_bytes });
            if let Some(failure) = recorded_verified {
                detail["verified"] = json!(failure.is_none());
                if let Some(why) = failure {
                    detail["verify_error"] = json!(format!("{why}. Run Verify on the model."));
                }
            }
            (JOB_DONE, Some(detail))
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
        DownloadState::Cancelled | DownloadState::Running(_) => stopped_or_cancelled(&stopping),
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

/// Runs one verification on the hash lane, writing its progress and then its verdict
/// onto the job row, and forgets its cancel flag when it is over.
async fn follow_verify(
    store: Arc<Store>,
    verifies: Verifies,
    job_id: String,
    registry: Registry,
    entry: ModelEntry,
    cancel: Arc<AtomicBool>,
    stopping: watch::Receiver<bool>,
) {
    let total = i64::try_from(entry.size_bytes).ok();
    let done = Arc::new(AtomicU64::new(0));
    let work = {
        let done = Arc::clone(&done);
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::ModelHash, move || {
            let control = Control {
                progress: &|bytes| done.store(bytes, Ordering::Relaxed),
                cancelled: &|| cancel.load(Ordering::Acquire),
            };
            registry.verify_with(&entry, &control)
        })
    };
    tokio::pin!(work);
    let mut ticker = tokio::time::interval(DOWNLOAD_POLL);
    let outcome = loop {
        tokio::select! {
            outcome = &mut work => break outcome,
            _ = ticker.tick() => {
                let bytes = i64::try_from(done.load(Ordering::Relaxed)).unwrap_or(i64::MAX);
                let _ = store.update_model_job_progress(&job_id, bytes, total).await;
            }
        }
    };
    let (state, detail) = match outcome {
        Ok(Ok(outcome)) => {
            if let Ok(bytes) = i64::try_from(outcome.size_bytes) {
                let _ = store.update_model_job_progress(&job_id, bytes, total).await;
            }
            (JOB_DONE, Some(verify_detail(&outcome)))
        }
        Ok(Err(RegistryError::Weights(WeightsError::Cancelled))) => stopped_or_cancelled(&stopping),
        Ok(Err(error)) => (
            JOB_FAILED,
            Some(job_failure_value(verify_cause(&error), &error.to_string())),
        ),
        Err(error) => (
            JOB_FAILED,
            Some(job_failure_value(error.cause(), &error.to_string())),
        ),
    };
    let encoded = detail.map(|value| value.to_string());
    let _ = store
        .finish_model_job(&job_id, state, encoded.as_deref())
        .await;
    verifies
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&job_id);
}

/// The verdict of a transfer that ended cancelled: the human's cancel, or,
/// once [`ModelService::shutdown`] has begun, the daemon's stop, recorded as
/// the failure the next boot would otherwise have written.
fn stopped_or_cancelled(
    stopping: &watch::Receiver<bool>,
) -> (&'static str, Option<serde_json::Value>) {
    if *stopping.borrow() {
        (
            JOB_FAILED,
            Some(job_failure_value(CAUSE_DAEMON_RESTART, STOPPED_DETAIL)),
        )
    } else {
        (JOB_CANCELLED, None)
    }
}

/// What a finished verification's job row says.
fn verify_detail(verified: &VerifyOutcome) -> serde_json::Value {
    json!({
        "sha256": verified.sha256,
        "size_bytes": verified.size_bytes,
        "matches_catalog": verified.matches_catalog,
        // `cloned` shares the file's blocks, `copied` took its size again on the
        // volume of PAM's base, `reused` found the copy already there.
        "private_copy": verified.private_copy,
    })
}

/// The cause a failed verification's job row carries.
pub(crate) fn verify_cause(error: &RegistryError) -> &'static str {
    match error {
        RegistryError::Weights(WeightsError::NoSpace { .. }) => CAUSE_NO_SPACE,
        RegistryError::Changed { .. } => crate::admin_models::CAUSE_MODEL_CHANGED,
        _ => CAUSE_VERIFY_FAILED,
    }
}

/// Ticks until the service is dropped or shut down, unloading an idle model.
async fn idle_unload_loop(service: Weak<ModelService>, mut stopping: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(IDLE_TICK);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = cancelled(&mut stopping) => return,
        }
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

/// The models directory the human saved, or `None` when they never set one.
async fn read_stored_models_dir(store: &Store) -> Result<Option<PathBuf>, StoreError> {
    Ok(read_setting_string(store, SETTING_MODELS_DIR)
        .await?
        .map(PathBuf::from))
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

/// How long the engine itself may take over one completion. The qualification gate is a
/// ten-second warm p95, so two minutes is generous and no longer a quarter hour.
const ENGINE_GENERATE_DEADLINE: Duration = Duration::from_mins(2);

/// How long one `generate_bounded` call may take in all: the wait for the service-wide
/// operation lock behind another generation, a cold model load (180 s allowed), and the
/// completion.
pub const GENERATE_TOTAL_DEADLINE: Duration = Duration::from_mins(5);

/// `d` in whole milliseconds, saturating.
fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Resolves when `cancel` is (or becomes) `true`; pends forever once every sender is gone.
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

/// What [`ModelService::reap_orphan_engine`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanReap {
    /// No pid file, no engine installed, or already checked.
    NothingToDo,
    /// The pid file named a process that is gone; the record was removed.
    Stale,
    /// The pid file named a live process that is not the recorded engine (the pid was
    /// reused); nothing was killed and the record was removed.
    NotOurs {
        /// The pid that was left alone.
        pid: u32,
    },
    /// A leftover engine proven ours was stopped.
    Killed {
        /// The pid that was stopped.
        pid: u32,
    },
}

/// One line for what the migration of an older daemon's engine runtime did:
/// what went, or what stayed and why. Silent when there was nothing.
fn log_legacy_engine_cleanup(
    cleanup: &Result<Vec<PathBuf>, pam_model::engine_server::LegacyRuntimeError>,
) {
    match cleanup {
        Ok(removed) if removed.is_empty() => {}
        Ok(removed) => {
            let removed: Vec<String> = removed
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            tracing::info!(
                removed = ?removed,
                "removed the engine runtime an older daemon kept inside the run directory; \
                 it now lives under <base>/engine/run"
            );
        }
        Err(error) => {
            tracing::warn!(
                path = %error.path.display(),
                error = %error.source,
                "an older daemon's engine runtime stayed inside the run directory; remove it by hand"
            );
        }
    }
}

/// Reads the supervisor's pid file and stops the process it names — only when that
/// process is provably the engine this daemon family spawned: same executable path, the
/// recorded `-m <model>` and a `--api-key-file` argument on its command line, and a start
/// time not before the recorded spawn. A reused pid fails these and is left alone.
fn reap_recorded_engine(engine: &EngineServer) -> OrphanReap {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let Some(record) = engine.pid_record() else {
        return OrphanReap::NothingToDo;
    };
    let pid = Pid::from_u32(record.pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing()
            .with_exe(UpdateKind::Always)
            .with_cmd(UpdateKind::Always),
    );
    let Some(process) = system.process(pid) else {
        engine.forget_pid_record();
        return OrphanReap::Stale;
    };
    let same_exe = process.exe().is_some_and(|exe| {
        exe == record.exe
            || matches!(
                (exe.canonicalize(), record.exe.canonicalize()),
                (Ok(live), Ok(recorded)) if live == recorded
            )
    });
    let args: Vec<String> = process
        .cmd()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let same_model = args
        .windows(2)
        .any(|pair| pair[0] == "-m" && Path::new(&pair[1]) == record.model_path);
    let supervised = args.iter().any(|arg| arg == "--api-key-file");
    let spawned_s = u64::try_from(record.spawned_ms / 1000).unwrap_or(0);
    let started_after_spawn = process.start_time().saturating_add(2) >= spawned_s;
    if !(same_exe && same_model && supervised && started_after_spawn) {
        engine.forget_pid_record();
        return OrphanReap::NotOurs { pid: record.pid };
    }
    let killed = process.kill_and_wait().is_ok();
    engine.forget_pid_record();
    if killed {
        OrphanReap::Killed { pid: record.pid }
    } else {
        OrphanReap::NotOurs { pid: record.pid }
    }
}

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
        exited @ EngineServerError::Exited { .. } => RuntimeError::EngineExited(exited.to_string()),
        other => RuntimeError::LoadFailed(other.to_string()),
    }
}

/// The refusal every caller sees when the pinned engine is not installed.
fn engine_not_installed() -> RuntimeError {
    RuntimeError::LoadFailed(
        "the llama.cpp engine is not installed; install it from Models".to_owned(),
    )
}

/// [`snapshot`](ModelService::snapshot)'s fallback view of a model the
/// engine holds but this service has no cached registry entry for: no
/// registry lookup and no filesystem access — `snapshot` is polled every
/// couple of seconds and must never scan the models directory or stat the
/// weights to answer. Quant and architecture are `unknown` and the size is
/// `0`; a load through `ensure_loaded_inner` caches the registry's
/// [`engine_loaded_model`] view instead, which fills them in.
fn engine_snapshot_model(model: &pam_model::engine_server::EngineModel) -> LoadedModel {
    LoadedModel {
        id: model.id.clone(),
        quant: "unknown".to_owned(),
        architecture: "unknown".to_owned(),
        context_length: model.context_length,
        weight_bytes: 0,
        device: "llama.cpp".to_owned(),
        loaded_at: model.loaded_at_ms,
        last_used_at: model.loaded_at_ms,
        last_tokens_per_sec: None,
    }
}
