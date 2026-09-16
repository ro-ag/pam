//! Built-in capabilities and the context they execute in.
//!
//! The capability registry is static (per spine spec), so dispatch is a plain enum
//! ([`BuiltinCapability`]) rather than a `dyn` trait object — native `async fn` in traits isn't
//! dyn-compatible, and a closed enum needs no `async-trait` boxing or manual future desugaring.
//! Connectors and flows extend this enum when they land. Capabilities receive an [`ExecContext`]
//! and return a [`CapabilityOutput`] (outcome + body + evidence ids) or [`CapabilityFailure`]; they
//! never touch the `request` row or audit trail themselves — terminal bookkeeping is the daemon
//! pipeline's ([`crate::daemon`]), which owns exactly one audit write per terminal path.
//! - `status` (read-only): daemon version, protocol version, uptime, in-flight request count.
//!   Outcome `verified`.
//! - `query` (read-only): the lifecycle state of `args.ticket`'s request, straight from the store —
//!   the authoritative answer `pam wait`/`pam subscribe` reconcile against, since zmq `PUB` has no
//!   replay and a late subscriber would otherwise wait forever on an already-finished ticket.
//!   Outcome `verified`.
//! - `echo` (non-destructive): mirrors its args back; optional `delay_ms` sleeps first, honoring
//!   the cancel signal (used by integration tests as a controllable long-running capability);
//!   optional `fail: true` fails (after any delay) with [`CapabilityFailure::Failed`], a documented
//!   test/diagnostic surface for the execution-failure path. Outcome `solved`.
//! - `cancel` (read-only class — see [`crate::policy::classify`]): backs `pam cancel <ticket>`,
//!   cancelling the queued or running request via [`crate::queue::QueueManager::cancel`]. For a
//!   still-queued cancellation (the queue writes the terminal row/audit) it also releases attached
//!   waiters with a refusal and publishes `refused`; a running request's own executor does that
//!   instead.

use std::sync::Arc;
use std::time::Duration;

use pam_model::runtime::RuntimeState;
use pam_proto::{Caller, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use tokio::sync::watch;

use crate::approval::ApprovalService;
use crate::daemon::CompletionRouter;
use crate::flow_service::{FlowService, RunArgs};
use crate::model_service::ModelService;
use crate::queue::{CAUSE_CANCELLED, CancelOutcome, QueueManager};
use crate::secrets::SecretStore;
use crate::transport::EventPublisher;

/// Recovery line offered when a request was cancelled.
const RECOVERY_CANCELLED: &str = "Re-run the pam command to start a fresh request.";

/// Everything a capability may need while executing one request.
#[derive(Debug)]
pub struct ExecContext {
    /// Shared absolute deadline and cumulative work allowance.
    pub budget: Arc<crate::request_budget::RequestBudget>,
    /// Id of the request being executed.
    pub request_id: String,
    /// The envelope's capability arguments.
    pub args: serde_json::Value,
    /// Flips to `true` when the request is cancelled or its lease is
    /// reaped; long-running capabilities select on it and stop with
    /// [`CapabilityFailure::Cancelled`]. A closed channel means the
    /// lease is gone and counts as cancellation too.
    pub cancel: watch::Receiver<bool>,
    /// Publisher for `progress` (and other) events on this request's
    /// topic.
    pub events: EventPublisher,
    /// The durable store, for evidence writes (later tasks) and the
    /// `status` counters.
    pub store: Arc<Store>,
    /// The queue manager; the `cancel` built-in acts through it.
    pub queue: Arc<QueueManager>,
    /// The model layer, for the read-only `model` block on `status`.
    /// Read-only is the whole point: administration is GUI-only, so an
    /// agent can see what is loaded and can change nothing about it.
    pub models: Arc<ModelService>,
    /// Completion router; the `cancel` built-in releases the waiters of
    /// a queued-cancelled request through it.
    pub router: CompletionRouter,
    /// The approval service; the flow engine pauses a gated step on it
    /// mid-run, which is the one place a capability waits for a human.
    pub approvals: Arc<ApprovalService>,
    /// The flow engine behind `flow.run` / `flow.list` / `flow.show`.
    pub flows: Arc<FlowService>,
    /// The credential store, for the read-only `keyring` block on
    /// `status`. Reachability only: no capability reads a secret.
    pub secrets: Arc<SecretStore>,
    /// Who asked. A flow runs its command steps in
    /// [`Caller::repo`](pam_proto::Caller::repo), so this is not
    /// attribution here — it is where the work happens.
    pub caller: Caller,
    /// The capability being executed, as the envelope named it.
    pub capability: String,
    /// When the daemon started, for the `status` uptime figure.
    pub started_at: std::time::Instant,
}

/// What a capability produced on success.
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityOutput {
    /// How the request turned out.
    pub outcome: Outcome,
    /// Capability-specific result body.
    pub body: serde_json::Value,
    /// Evidence ids (`ev_<ulid>`) backing the result; empty until the
    /// evidence service lands.
    pub evidence: Vec<String>,
}

/// Why a capability did not produce an output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityFailure {
    /// Internal continuation: a bounded watch saved its checkpoint and yields its lane.
    /// Never serialized as a failure or accepted from an agent response.
    Parked {
        /// Earliest next poll in UTC milliseconds, under the original request expiry.
        resume_at_ms: i64,
    },
    /// The cancel signal fired (cancellation or lease reaping) and the
    /// capability stopped cooperatively.
    Cancelled,
    /// The capability ran and failed.
    Failed {
        /// Human-readable failure description.
        detail: String,
    },
    /// The capability refused before doing anything: the request asked
    /// for something that does not exist, or is not usable as asked.
    ///
    /// This is the executor's own refusal, distinct from the policy
    /// gate's — the gate decides whether a *capability* may run, while
    /// this says the capability ran nothing because the request itself
    /// was not answerable (an unknown flow id, a repo that is not a
    /// directory). The pipeline answers it as a
    /// [`Response::Refusal`] with its own terminal audit row (see
    /// [`crate::daemon::ACTION_EXECUTION_REFUSAL`]).
    Refused {
        /// Machine-readable cause.
        cause: String,
        /// What happened, in one sentence.
        detail: String,
        /// The concrete fix.
        recovery: String,
    },
}

/// The static set of built-in capabilities, dispatched by enum (see the
/// module docs for why this is not a trait object).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinCapability {
    /// Daemon health snapshot (read-only).
    Status,
    /// Lifecycle state of another request by ticket (read-only).
    Query,
    /// Mirror the args back, optionally after a cancellable delay.
    Echo,
    /// Cancel another request by ticket.
    Cancel,
    /// Run one flow from the library (see [`crate::flow_service`]).
    FlowRun,
    /// List the flow library.
    FlowList,
    /// Read one flow's YAML, canonical rendering and digest.
    FlowShow,
    /// Inspect bounded flow readiness without executing it.
    FlowInspect,
    /// Retrieve a bounded, scoped durable flow result.
    FlowResult,
    /// Read one scoped, bounded redacted evidence range.
    EvidenceRead,
}

impl BuiltinCapability {
    /// Looks a capability up by its wire name. Must stay in step with
    /// [`crate::policy::classify`]: everything classified there is
    /// dispatchable here.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "status" => Some(Self::Status),
            "query" => Some(Self::Query),
            "echo" => Some(Self::Echo),
            "cancel" => Some(Self::Cancel),
            crate::flow_service::CAP_FLOW_RUN => Some(Self::FlowRun),
            crate::flow_service::CAP_FLOW_LIST => Some(Self::FlowList),
            crate::flow_service::CAP_FLOW_SHOW => Some(Self::FlowShow),
            crate::flow_service::CAP_FLOW_INSPECT => Some(Self::FlowInspect),
            crate::flow_result_service::CAP_FLOW_RESULT => Some(Self::FlowResult),
            crate::evidence_service::CAP_EVIDENCE_READ => Some(Self::EvidenceRead),
            _ => None,
        }
    }

    /// The wire name of this capability.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Query => "query",
            Self::Echo => "echo",
            Self::Cancel => "cancel",
            Self::FlowRun => crate::flow_service::CAP_FLOW_RUN,
            Self::FlowList => crate::flow_service::CAP_FLOW_LIST,
            Self::FlowShow => crate::flow_service::CAP_FLOW_SHOW,
            Self::FlowInspect => crate::flow_service::CAP_FLOW_INSPECT,
            Self::FlowResult => crate::flow_result_service::CAP_FLOW_RESULT,
            Self::EvidenceRead => crate::evidence_service::CAP_EVIDENCE_READ,
        }
    }

    /// Executes this capability for the request in `ctx`.
    pub async fn execute(self, ctx: ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
        match self {
            Self::Status => status(&ctx).await,
            Self::Query => query(&ctx).await,
            Self::Echo => echo(ctx).await,
            Self::Cancel => cancel(&ctx).await,
            Self::FlowRun => flow_run(&ctx).await,
            Self::FlowList => flow_list(&ctx),
            Self::FlowShow => flow_show(&ctx),
            Self::FlowInspect => Ok(ctx.flows.inspect(&ctx, &ctx.args).await?),
            Self::FlowResult => crate::flow_result_service::result(&ctx).await,
            Self::EvidenceRead => crate::evidence_service::read(&ctx).await,
        }
    }
}

/// `flow.run`: hands the request to the flow engine.
async fn flow_run(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let args = RunArgs::from_value(&ctx.args)?;
    Arc::clone(&ctx.flows).run(ctx, args).await
}

/// `flow.list`: the flow library.
fn flow_list(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    Ok(ctx.flows.list_page(&ctx.args)?)
}

/// `flow.show`: one flow's text and canonical rendering.
fn flow_show(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let Some(id) = ctx.args.get("id").and_then(serde_json::Value::as_str) else {
        return Err(CapabilityFailure::Refused {
            cause: crate::flow_service::CAUSE_FLOW_NOT_FOUND.to_owned(),
            detail: "flow.show needs args.id naming the flow to read".to_owned(),
            recovery: crate::flow_service::RECOVERY_FLOW_LIST.to_owned(),
        });
    };
    Ok(ctx.flows.show(id)?)
}

/// The `request.outcome` column value for an [`Outcome`].
#[must_use]
pub fn outcome_str(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Solved => "solved",
        Outcome::Changed => "changed",
        Outcome::Verified => "verified",
        Outcome::Unresolved => "unresolved",
        Outcome::Blocked => "blocked",
    }
}

/// `status`: daemon version, protocol version, uptime, in-flight count,
/// and the model block.
///
/// The in-flight count includes the `status` request itself — its bypass
/// row is `running` while it executes.
///
/// The `model` block is read-only and degrades to `idle` with null
/// figures on a machine with no weights: nothing in PAM breaks without a
/// model, and the honest answer is that nothing is loaded. A settings
/// read that fails leaves the defaults null rather than failing the
/// whole status answer.
async fn status(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let active_requests =
        ctx.store
            .count_inflight()
            .await
            .map_err(|err| CapabilityFailure::Failed {
                detail: format!("cannot count in-flight requests: {err}"),
            })?;
    Ok(CapabilityOutput {
        outcome: Outcome::Verified,
        body: serde_json::json!({
            "daemon_version": env!("CARGO_PKG_VERSION"),
            "protocol": PROTOCOL_VERSION,
            "uptime_s": ctx.started_at.elapsed().as_secs(),
            "active_requests": active_requests,
            "blocking_jobs": crate::blocking_jobs::snapshot(),
            "model": model_block(ctx).await,
            "keyring": ctx.secrets.keyring_health().await,
        }),
        evidence: Vec::new(),
    })
}

/// The `status` body's read-only `model` block.
///
/// The sibling `keyring` block comes straight from
/// [`SecretStore::keyring_health`]: whether the platform credential store
/// answers, and what to do when it does not. It is cached for
/// [`crate::secrets::PROBE_TTL`], so a polling GUI does not wake the
/// keychain on every tick.
async fn model_block(ctx: &ExecContext) -> serde_json::Value {
    // The llama.cpp engine, when installed, is what holds the weights;
    // `snapshot` already reports the engine's loaded model directly.
    let snapshot = ctx.models.snapshot();
    let (state, id, tokens_per_sec) = match &snapshot.state {
        RuntimeState::Idle => ("idle", None, None),
        RuntimeState::Loading { id, .. } => ("loading", Some(id.clone()), None),
        RuntimeState::Loaded(loaded) => (
            "loaded",
            Some(loaded.id.clone()),
            loaded.last_tokens_per_sec,
        ),
    };
    let engine = pam_model::engine::status(&ctx.models.engine_base());
    let engine_model = ctx.models.engine_server().and_then(|server| server.model());
    let (light, heavy) = ctx.models.defaults().await.unwrap_or((None, None));
    // The same verdict the GUI shows, reduced to what an agent acts on: the
    // stage and, when blocked, the cause. Absent when the store cannot answer.
    let resident = engine_model.as_ref().map(|model| model.id.clone());
    let mut readiness = serde_json::Map::new();
    for tier in [
        crate::model_service::Tier::Light,
        crate::model_service::Tier::Heavy,
    ] {
        let verdict = ctx
            .models
            .readiness(tier, &engine, resident.as_deref())
            .await
            .ok()
            .map(|readiness| {
                serde_json::json!({
                    "stage": readiness.stage,
                    "cause": readiness.blocker.map(|blocker| blocker.cause),
                })
            });
        readiness.insert(
            tier.as_str().to_owned(),
            verdict.unwrap_or(serde_json::Value::Null),
        );
    }
    serde_json::json!({
        "state": state,
        "id": id,
        "tokens_per_sec": tokens_per_sec,
        "defaults": { "light": light, "heavy": heavy },
        "readiness": serde_json::Value::Object(readiness),
        "engine": {
            "installed": engine.installed,
            "tag": engine.expected_tag,
            "cause": engine.cause,
            "build_info": engine_model.as_ref().map(|model| model.build_info.clone()),
        },
    })
}

/// `query`: the lifecycle state of the request named by `args.ticket`,
/// as `{ ticket, state, outcome }` straight from the store.
///
/// This is the replay mechanism zmq `PUB` lacks: `pam wait` /
/// `pam subscribe` reconcile their event subscription against this
/// answer, so a follower that subscribed after the ticket's terminal
/// event was published still terminates instead of waiting for an
/// event that will never be re-sent.
async fn query(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    crate::flow_result_service::scoped_query(ctx).await
}

/// `echo`: mirror the args back; `args.delay_ms` sleeps first, honoring
/// the cancel signal, and `args.fail: true` fails after any delay (the
/// test/diagnostic surface for the execution-failure path).
async fn echo(mut ctx: ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    if let Some(delay_ms) = ctx.args.get("delay_ms").and_then(serde_json::Value::as_u64) {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            // An Err means the lease is gone (sender dropped): the
            // request no longer has a right to run, same as a cancel.
            _ = ctx.cancel.wait_for(|cancelled| *cancelled) => {
                return Err(CapabilityFailure::Cancelled);
            }
        }
    }
    if ctx.args.get("fail").and_then(serde_json::Value::as_bool) == Some(true) {
        return Err(CapabilityFailure::Failed {
            detail: "echo was asked to fail (args.fail = true)".to_owned(),
        });
    }
    Ok(CapabilityOutput {
        outcome: Outcome::Solved,
        body: serde_json::json!({ "echo": ctx.args }),
        evidence: Vec::new(),
    })
}

/// `cancel`: cancel the request named by `args.ticket`.
///
/// The audit actor is the caller as the audit vocabulary can name it: a
/// human when the GUI asked (caller agent `pam-gui`), otherwise the daemon
/// acting for an agent's `pam cancel` — there is no per-agent actor.
async fn cancel(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let Some(ticket) = ctx.args.get("ticket").and_then(serde_json::Value::as_str) else {
        return Err(CapabilityFailure::Failed {
            detail: "cancel needs args.ticket naming the request to cancel".to_owned(),
        });
    };
    let actor = if ctx.caller.agent == crate::admin::ADMIN_CALLER_AGENT {
        pam_store::Actor::Human
    } else {
        pam_store::Actor::System
    };
    let outcome =
        ctx.queue
            .cancel(ticket, actor)
            .await
            .map_err(|err| CapabilityFailure::Failed {
                detail: format!("cannot cancel {ticket}: {err}"),
            })?;
    let (result, request_outcome) = match outcome {
        CancelOutcome::CancelledQueued => {
            // The queue already wrote the terminal row and the audit row;
            // what is left is answering anyone waiting on the ticket and
            // telling subscribers.
            ctx.router
                .finish(
                    ticket,
                    Response::Refusal {
                        id: ticket.to_owned(),
                        cause: CAUSE_CANCELLED.to_owned(),
                        detail: format!("request {ticket} was cancelled while queued"),
                        recovery: RECOVERY_CANCELLED.to_owned(),
                    },
                )
                .await;
            let _ = ctx.events.publish(ticket, Event::Refused).await;
            ("cancelled_queued", Outcome::Solved)
        }
        CancelOutcome::SignalledRunning => {
            // The running executor observes the signal and finishes the
            // request (terminal row, audit, events, waiters) itself.
            ("signalled_running", Outcome::Solved)
        }
        CancelOutcome::NotFound => ("not_found", Outcome::Unresolved),
    };
    Ok(CapabilityOutput {
        outcome: request_outcome,
        body: serde_json::json!({ "ticket": ticket, "result": result }),
        evidence: Vec::new(),
    })
}
