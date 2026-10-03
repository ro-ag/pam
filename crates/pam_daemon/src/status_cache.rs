//! What `status` answers from: a snapshot refreshed in the background, so a poll
//! never waits behind anything slow.
//!
//! `status` is the daemon's liveness answer. It used to compute every figure on
//! the request path: model readiness scans the models directory on the model
//! filesystem lane (held for minutes by a Verify of a multi-gigabyte file), and
//! keyring health can sit behind an unanswered macOS keychain prompt. A GUI polls
//! `status` every couple of seconds from several components, so one slow lane was
//! enough to pin every control slot and make the daemon refuse `status` and
//! `cancel` alike (ptrack issue 35).
//!
//! Now the slow figures — tier defaults, readiness, engine install state, keyring
//! reachability — are produced only by [`StatusCache::refresh`], which a single
//! background task ([`StatusCache::spawn`]) runs with its own per-part timeouts.
//! The task is demand-driven: it refreshes every [`REFRESH_INTERVAL`] while
//! `status` is being polled and sleeps once nobody has asked for
//! [`STALE_AFTER`], so an idle daemon touches neither the keychain nor the models
//! directory on anyone's behalf. The request path ([`StatusCache::body`]) reads
//! the snapshot and adds what is cheap and in memory (version, uptime, runtime
//! state, blocking-job history). It awaits exactly two things, both bounded: a
//! snapshot the sleeping task is about to produce — the first one after boot, or
//! the first after an idle spell ([`FIRST_SNAPSHOT_WAIT`]) — and one indexed
//! store count ([`ACTIVE_COUNT_WAIT`], falling back to the last figure). When the
//! task *is* running and the snapshot is stale all the same, something behind it
//! is hung, and `status` answers at once with what it has. **No model lane and no
//! keychain call is ever awaited on the status path.**
//!
//! Staleness is bounded and visible: the body carries
//! `snapshot: { stale, model_age_ms, keyring_age_ms }`, and `stale` is true once
//! a part is older than [`STALE_AFTER`] (its refresh keeps timing out), was
//! never taken, or the live request count could not be read in time. A stale
//! answer still proves the daemon is serving, which is the question a poll asks.
//!
//! The `boundary` block (the last `pam doctor` report and the daemon's own
//! admin-contact observations) comes from the attached
//! [`crate::boundary::Boundary`], which keeps its census in memory and reloads
//! it after each of its own writes: no row is read on the poll either.
//!
//! The `policy` block is the attached [`crate::managed_policy_service::PolicyHandle`]'s
//! public status ([`crate::managed_policy_service::PolicyStatus::public_json`]): the state,
//! revision, short digest, load time and rejected-leaf count, never a value or a reason. It is
//! held in memory and swapped by the policy's own reloads, so the poll reads no file and no row.
//!
//! The `containment` block is [`crate::command_containment::availability`]: whether this machine can
//! contain command workloads (flow command steps, guarded landing), checked once per process.
//!
//! The `refusals` block is the attached [`crate::refusal_log::RefusalLog`]'s counters: `recorded` (refusals
//! decided before any request row existed and accepted for recording), `dropped` (not recorded, because a
//! flood outran the log's bound; the caller was still answered) and `pending` (not yet written to the
//! store). Counters in memory: the poll reads no row.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use pam_model::runtime::RuntimeState;
use pam_proto::PROTOCOL_VERSION;
use pam_store::Store;
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::boundary::Boundary;
use crate::managed_policy_service::PolicyHandle;
use crate::model_service::{ModelService, Tier};
use crate::refusal_log::RefusalLog;
use crate::secrets::SecretStore;

/// How often the background task refreshes the snapshot while `status` is
/// being polled.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

/// A snapshot part older than this is reported `stale`. Also how long the
/// background task keeps refreshing after the last poll.
pub const STALE_AFTER: Duration = Duration::from_secs(10);

/// Bound on producing one part of the snapshot. A part that cannot be
/// produced in time keeps its previous value and ages towards `stale`.
const PART_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a `status` waits for the snapshot a just-woken background task
/// is producing (the first after boot, or the first after an idle spell).
pub const FIRST_SNAPSHOT_WAIT: Duration = Duration::from_secs(2);

/// How long `status` waits for the live in-flight count before answering
/// with the last one it read.
pub const ACTIVE_COUNT_WAIT: Duration = Duration::from_millis(250);

/// One produced part and when it was taken.
type Part = Option<(Instant, Value)>;

#[derive(Debug, Default, Clone)]
struct Snapshot {
    /// `defaults`, `readiness` and `engine` of the `model` block.
    model: Part,
    /// The `keyring` block.
    keyring: Part,
}

/// The cached slow half of the `status` body. One per daemon.
pub struct StatusCache {
    models: Arc<ModelService>,
    secrets: Arc<SecretStore>,
    snapshot: RwLock<Snapshot>,
    /// Counts finished refreshes (whatever each managed to produce); a
    /// poll waiting for a snapshot watches it move.
    generation: watch::Sender<u64>,
    /// Wakes the background task: somebody asked for `status`.
    demand: Notify,
    /// When `status` was last asked for, and when a refresh last started.
    activity: RwLock<Activity>,
    /// The last in-flight count read from the store; `-1` before any.
    active_requests: AtomicI64,
    /// The boundary observer, attached once at boot: the `boundary` block
    /// is read from its in-memory census, and `doctor.report` records
    /// through it. Absent in a harness that attached none; `status` then
    /// serves the never-checked block.
    boundary: OnceLock<Arc<Boundary>>,
    /// The managed policy, attached once at boot: the `policy` block is its
    /// public status. Absent in a harness that attached none; `status` then
    /// serves the unmanaged block.
    policy: OnceLock<Arc<PolicyHandle>>,
    /// The log of refusals decided before a request row exists, attached once at boot: the
    /// `refusals` block reports what it accepted, dropped and has not yet written.
    refusals: OnceLock<RefusalLog>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Activity {
    last_poll: Option<Instant>,
    last_refresh_started: Option<Instant>,
}

impl std::fmt::Debug for StatusCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StatusCache")
            .finish_non_exhaustive()
    }
}

impl StatusCache {
    /// An empty cache over the model layer and the credential store.
    /// Nothing is read until [`Self::refresh`] runs.
    #[must_use]
    pub fn new(models: Arc<ModelService>, secrets: Arc<SecretStore>) -> Arc<Self> {
        let (generation, _) = watch::channel(0);
        Arc::new(Self {
            models,
            secrets,
            snapshot: RwLock::new(Snapshot::default()),
            generation,
            demand: Notify::new(),
            activity: RwLock::new(Activity::default()),
            active_requests: AtomicI64::new(-1),
            boundary: OnceLock::new(),
            policy: OnceLock::new(),
            refusals: OnceLock::new(),
        })
    }

    /// Attaches the boundary observer. Once: a second attachment is
    /// ignored and answers `false`.
    pub fn attach_boundary(&self, boundary: Arc<Boundary>) -> bool {
        self.boundary.set(boundary).is_ok()
    }

    /// Attaches the managed policy handle. Once: a second attachment is
    /// ignored and answers `false`.
    pub fn attach_policy(&self, policy: Arc<PolicyHandle>) -> bool {
        self.policy.set(policy).is_ok()
    }

    /// Attaches the pre-admission refusal log. Once: a second attachment is
    /// ignored and answers `false`.
    pub fn attach_refusals(&self, refusals: RefusalLog) -> bool {
        self.refusals.set(refusals).is_ok()
    }

    /// The attached boundary observer, if any.
    #[must_use]
    pub fn boundary(&self) -> Option<&Arc<Boundary>> {
        self.boundary.get()
    }

    /// Spawns the one task that keeps the snapshot fresh while `status` is
    /// being polled: woken by a poll, it refreshes, then again every
    /// [`REFRESH_INTERVAL`] until nobody has asked for [`STALE_AFTER`], and
    /// goes back to sleep. Ends when `shutdown` changes or its sender drops.
    pub fn spawn(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = self.demand.notified() => {}
                    _ = shutdown.changed() => return,
                }
                loop {
                    tokio::select! {
                        () = self.refresh() => {}
                        _ = shutdown.changed() => return,
                    }
                    tokio::select! {
                        () = tokio::time::sleep(REFRESH_INTERVAL) => {}
                        _ = shutdown.changed() => return,
                    }
                    let polled_recently = self
                        .activity()
                        .last_poll
                        .is_some_and(|at| at.elapsed() < STALE_AFTER);
                    if !polled_recently {
                        break;
                    }
                }
            }
        })
    }

    fn activity(&self) -> Activity {
        *self
            .activity
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn note(&self, write: impl FnOnce(&mut Activity)) {
        write(
            &mut self
                .activity
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// Produces both parts once, each under its own `PART_TIMEOUT`, and
    /// stores whichever arrived. This is the only place the model lane and
    /// the keychain are touched on behalf of `status`.
    pub async fn refresh(&self) {
        self.note(|activity| activity.last_refresh_started = Some(Instant::now()));
        let model = tokio::time::timeout(PART_TIMEOUT, slow_model_block(&self.models)).await;
        if let Ok(block) = model {
            self.store_part(|snapshot| snapshot.model = Some((Instant::now(), block)));
        }
        let keyring = tokio::time::timeout(PART_TIMEOUT, self.secrets.keyring_health()).await;
        if let Ok(health) = keyring {
            let block = serde_json::to_value(health).unwrap_or(Value::Null);
            self.store_part(|snapshot| snapshot.keyring = Some((Instant::now(), block)));
        }
        self.generation.send_modify(|generation| *generation += 1);
    }

    fn store_part(&self, write: impl FnOnce(&mut Snapshot)) {
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write(&mut snapshot);
    }

    fn current(&self) -> Snapshot {
        self.snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The whole `status` body (see the module docs for what is live and
    /// what is cached, and for the two bounded waits).
    pub async fn body(&self, store: &Store, started_at: std::time::Instant) -> Value {
        let fresh = |part: &Part| {
            part.as_ref()
                .is_some_and(|(taken, _)| taken.elapsed() < STALE_AFTER)
        };
        // Tell the background task somebody is asking, and — only when it
        // was asleep, so a fresh snapshot is one quick pass away — give
        // that pass a bounded moment. A task that is already refreshing
        // and still has nothing fresh is stuck behind something; then the
        // answer is what is known, now.
        let before = self.activity();
        let seen = *self.generation.borrow();
        self.note(|activity| activity.last_poll = Some(Instant::now()));
        self.demand.notify_one();
        let current = self.current();
        let task_was_asleep = before
            .last_refresh_started
            .is_none_or(|at| at.elapsed() >= STALE_AFTER);
        if task_was_asleep && !(fresh(&current.model) && fresh(&current.keyring)) {
            let mut generation = self.generation.subscribe();
            let _ = tokio::time::timeout(
                FIRST_SNAPSHOT_WAIT,
                generation.wait_for(|generation| *generation != seen),
            )
            .await;
        }
        let (active_requests, count_is_live) = if let Ok(Ok(count)) =
            tokio::time::timeout(ACTIVE_COUNT_WAIT, store.count_inflight()).await
        {
            self.active_requests.store(count, Ordering::Relaxed);
            (Some(count), true)
        } else {
            // The store is busy or failing: say what was last known
            // rather than hold a status slot waiting for it.
            let last = self.active_requests.load(Ordering::Relaxed);
            ((last >= 0).then_some(last), false)
        };
        let snapshot = self.current();
        let age_ms = |part: &Part| {
            part.as_ref()
                .map(|(taken, _)| u64::try_from(taken.elapsed().as_millis()).unwrap_or(u64::MAX))
        };
        let stale = !count_is_live || !fresh(&snapshot.model) || !fresh(&snapshot.keyring);
        json!({
            "daemon_version": env!("CARGO_PKG_VERSION"),
            "protocol": PROTOCOL_VERSION,
            "uptime_s": started_at.elapsed().as_secs(),
            "active_requests": active_requests,
            "blocking_jobs": crate::blocking_jobs::snapshot(),
            "model": self.model_block(snapshot.model.as_ref().map(|(_, block)| block)),
            "keyring": snapshot.keyring.as_ref().map_or(Value::Null, |(_, block)| block.clone()),
            "boundary": self.boundary.get().map_or_else(
                crate::boundary::never_checked_block,
                |boundary| boundary.status_block(),
            ),
            // Whether flow command steps and guarded landing can run on this
            // machine; computed once per process, no I/O on the poll.
            "containment": crate::command_containment::availability().status_block(),
            "policy": self.policy.get().map_or_else(
                || PolicyHandle::none().status().public_json(),
                |policy| policy.status().public_json(),
            ),
            // Refusals decided before a request row exists: what was accepted for
            // recording, what was dropped to keep the log bounded (a flood), and
            // what the store does not have yet.
            "refusals": self
                .refusals
                .get()
                .map_or_else(|| RefusalLog::disabled().status_block(), RefusalLog::status_block),
            "snapshot": {
                "stale": stale,
                "model_age_ms": age_ms(&snapshot.model),
                "keyring_age_ms": age_ms(&snapshot.keyring),
            },
        })
    }

    /// The `model` block: the runtime state straight from memory, joined
    /// with the cached slow half (null figures before the first snapshot).
    fn model_block(&self, slow: Option<&Value>) -> Value {
        // The llama.cpp engine, when installed, is what holds the weights;
        // `snapshot` already reports the engine's loaded model directly.
        let runtime = self.models.snapshot();
        let (state, id, tokens_per_sec) = match &runtime.state {
            RuntimeState::Idle => ("idle", None, None),
            RuntimeState::Loading { id, .. } => ("loading", Some(id.clone()), None),
            RuntimeState::Loaded(loaded) => (
                "loaded",
                Some(loaded.id.clone()),
                loaded.last_tokens_per_sec,
            ),
        };
        let part = |key: &str, absent: Value| {
            slow.and_then(|block| block.get(key))
                .cloned()
                .unwrap_or(absent)
        };
        json!({
            "state": state,
            "id": id,
            "tokens_per_sec": tokens_per_sec,
            "defaults": part("defaults", json!({ "light": null, "heavy": null })),
            "readiness": part("readiness", json!({ "light": null, "heavy": null })),
            "engine": part("engine", Value::Null),
        })
    }
}

/// The slow half of the `model` block: tier defaults (a store read), the
/// engine's install state (a filesystem read) and each tier's readiness (a
/// models-directory scan on the model filesystem lane). Read-only, and it
/// degrades to null figures on a machine with no weights or a store that
/// cannot answer: nothing in PAM breaks without a model.
async fn slow_model_block(models: &ModelService) -> Value {
    let engine = pam_model::engine::status(&models.engine_base());
    let engine_model = models.engine_server().and_then(|server| server.model());
    let (light, heavy) = models.defaults().await.unwrap_or((None, None));
    // The same verdict the GUI shows, reduced to what an agent acts on: the
    // stage and, when blocked, the cause. Absent when the store cannot answer.
    let resident = engine_model.as_ref().map(|model| model.id.clone());
    let mut readiness = serde_json::Map::new();
    for tier in [Tier::Light, Tier::Heavy] {
        let verdict = models
            .readiness(tier, &engine, resident.as_deref())
            .await
            .ok()
            .map(|readiness| {
                json!({
                    "stage": readiness.stage,
                    "cause": readiness.blocker.map(|blocker| blocker.cause),
                })
            });
        readiness.insert(tier.as_str().to_owned(), verdict.unwrap_or(Value::Null));
    }
    json!({
        "defaults": { "light": light, "heavy": heavy },
        "readiness": Value::Object(readiness),
        "engine": {
            "installed": engine.installed,
            "tag": engine.expected_tag,
            "cause": engine.cause,
            "build_info": engine_model.as_ref().map(|model| model.build_info.clone()),
        },
    })
}
