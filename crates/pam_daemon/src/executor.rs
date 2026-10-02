//! Built-in capabilities and the context they execute in.
//!
//! The capability registry is static (per spine spec), so dispatch is a plain enum
//! ([`BuiltinCapability`]) rather than a `dyn` trait object — native `async fn` in traits isn't
//! dyn-compatible, and a closed enum needs no `async-trait` boxing or manual future desugaring.
//! Connectors and flows extend this enum when they land. Capabilities receive an [`ExecContext`]
//! and return a [`CapabilityOutput`] (outcome + body + evidence ids) or [`CapabilityFailure`]; they
//! never touch the `request` row or audit trail themselves — terminal bookkeeping is the daemon
//! pipeline's ([`crate::daemon`]), which owns exactly one audit write per terminal path.
//! - `status` (control): daemon version, protocol version, uptime, in-flight request count, and
//!   the model and keyring blocks, served from [`crate::status_cache::StatusCache`] so a poll never
//!   waits behind a slow lane. Outcome `verified`.
//! - `query` (control): the lifecycle state of `args.ticket`'s request, straight from the store —
//!   the authoritative answer, and the authorisation a follow (`pam wait`/`pam subscribe`) opens
//!   with: a follower of an already-finished ticket gets this answer at once instead of waiting
//!   for an event that will not come again. Outcome `verified`.
//! - `echo` (non-destructive): mirrors its args back; optional `delay_ms` sleeps first, honoring
//!   the cancel signal (used by integration tests as a controllable long-running capability);
//!   optional `fail: true` fails (after any delay) with [`CapabilityFailure::Failed`], a documented
//!   test/diagnostic surface for the execution-failure path. Outcome `solved`. It is a diagnostic,
//!   so what it can hold is capped: a delay over [`MAX_ECHO_DELAY_MS`] or arguments over
//!   [`MAX_ECHO_ARGS_BYTES`] are refused ([`CAUSE_ECHO_LIMIT`]) before anything waits — an echo
//!   cannot be used to keep a repository's lane busy for an hour or to park a megabyte reply.
//! - `cancel` (control class — see [`crate::policy::classify`]): backs `pam cancel <ticket>`,
//!   cancelling the queued or running request via [`crate::queue::QueueManager::cancel`]. For a
//!   still-queued cancellation (the queue writes the terminal row/audit) it also releases attached
//!   waiters with a refusal and publishes `refused`; a running request's own executor does that
//!   instead. A public cancel acts only on a ticket admitted under the caller's own repository and
//!   is audited as `system`; the private admin plane's cancel ([`Origin::Admin`]) may cancel any
//!   ticket and is audited as `human`.

use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Event, Outcome, Response};
use pam_store::Store;
use tokio::sync::watch;

use crate::approval::ApprovalService;
use crate::daemon::CompletionRouter;
use crate::flow_service::{FlowService, RunArgs};
use crate::ingress::Origin;
use crate::model_service::ModelService;
use crate::queue::{CAUSE_CANCELLED, CancelOutcome, QueueManager};
use crate::secrets::SecretStore;
use crate::status_cache::StatusCache;
use crate::transport::EventPublisher;

/// Recovery line offered when a request was cancelled.
const RECOVERY_CANCELLED: &str = "Re-run the pam command to start a fresh request.";

/// Longest delay `echo` accepts, in milliseconds.
pub const MAX_ECHO_DELAY_MS: u64 = 60_000;

/// Largest `echo` argument object, as serialized JSON bytes.
pub const MAX_ECHO_ARGS_BYTES: usize = 64 * 1024;

/// Refusal cause for an `echo` that asks for more than the diagnostic allows.
pub const CAUSE_ECHO_LIMIT: &str = "echo_limit_exceeded";

/// Recovery line for [`CAUSE_ECHO_LIMIT`].
const RECOVERY_ECHO_LIMIT: &str =
    "echo is a diagnostic: send at most 64 KiB of arguments and a delay_ms of at most 60000.";

/// Everything a capability may need while executing one request.
#[derive(Debug)]
pub struct ExecContext {
    /// Which plane the request arrived on. The `cancel` built-in decides
    /// its audit actor and its ownership check from this, never from
    /// [`Caller::agent`](pam_proto::Caller::agent).
    pub origin: Origin,
    /// The plane and the connection the request arrived on, exactly as its
    /// request row records them at admission (`ingress`, `peer_uid`,
    /// `peer_pid`, `relayed`): the kernel's view of the peer for a request
    /// from the framed public listener, no peer for one the administration
    /// plane submitted or the legacy listener carried. Read back from the
    /// row, so a bypass and a leased execution see the same thing.
    /// Attribution only: a pid names a short-lived process and can be
    /// reused, and nothing may be authorized by it.
    pub peer: pam_store::RequestOrigin,
    /// The cached slow half of the `status` body (see [`StatusCache`]).
    pub status: Arc<StatusCache>,
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
/// and the model and keyring blocks.
///
/// Everything slow comes from the [`StatusCache`] snapshot a background
/// task keeps fresh; this path reads it and never waits on the model lane
/// or the keychain. The body's `snapshot.stale` says when a figure is older
/// than its bound. `status` cannot fail: a store that will not answer the
/// in-flight count in time yields the last count read, flagged stale.
async fn status(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    Ok(CapabilityOutput {
        outcome: Outcome::Verified,
        body: ctx.status.body(&ctx.store, ctx.started_at).await,
        evidence: Vec::new(),
    })
}

/// `query`: the lifecycle state of the request named by `args.ticket`,
/// as `{ ticket, state, outcome }` straight from the store.
///
/// Events are notifications, this is the record: a follow (`pam wait` /
/// `pam subscribe`) opens with this query and ends with its answer, so a
/// follower that attached after the ticket's terminal event was published
/// still terminates instead of waiting for an event that will never be
/// re-sent.
async fn query(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    crate::flow_result_service::scoped_query(ctx).await
}

/// `echo`: mirror the args back; `args.delay_ms` sleeps first, honoring
/// the cancel signal, and `args.fail: true` fails after any delay (the
/// test/diagnostic surface for the execution-failure path). Both the delay
/// and the payload are capped (see the module docs).
async fn echo(mut ctx: ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let delay_ms = ctx.args.get("delay_ms").and_then(serde_json::Value::as_u64);
    let args_bytes = ctx.args.to_string().len();
    if delay_ms.is_some_and(|delay| delay > MAX_ECHO_DELAY_MS) || args_bytes > MAX_ECHO_ARGS_BYTES {
        return Err(CapabilityFailure::Refused {
            cause: CAUSE_ECHO_LIMIT.to_owned(),
            detail: format!(
                "echo was asked to hold {args_bytes} bytes of arguments for {} ms; the limits \
                 are {MAX_ECHO_ARGS_BYTES} bytes and {MAX_ECHO_DELAY_MS} ms",
                delay_ms.unwrap_or(0)
            ),
            recovery: RECOVERY_ECHO_LIMIT.to_owned(),
        });
    }
    if let Some(delay_ms) = delay_ms {
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
/// Who may cancel what, and who the audit says did it, both follow from
/// where the request entered the daemon ([`ExecContext::origin`]):
/// - [`Origin::Public`]: the ticket must have been admitted under the
///   caller's own repository — the same binding a ticket read enforces
///   (`query`, `flow.result`): the stored admission repository, compared
///   as the immutable canonical string it was recorded as, against the
///   caller's canonicalized repository. Request ids are broadcast on the
///   public event socket, so an id alone must not be a capability. A
///   ticket that is not the caller's answers exactly like one that does
///   not exist. The audit actor is `system`, whatever `caller.agent` says.
/// - [`Origin::Admin`]: the human's surface; any ticket, audited `human`.
async fn cancel(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let Some(ticket) = ctx.args.get("ticket").and_then(serde_json::Value::as_str) else {
        return Err(CapabilityFailure::Failed {
            detail: "cancel needs args.ticket naming the request to cancel".to_owned(),
        });
    };
    let actor = match ctx.origin {
        Origin::Admin => pam_store::Actor::Human,
        Origin::Public => pam_store::Actor::System,
    };
    let outcome = if ctx.origin == Origin::Public && !caller_owns_ticket(ctx, ticket).await? {
        CancelOutcome::NotFound
    } else {
        ctx.queue
            .cancel(ticket, actor)
            .await
            .map_err(|err| CapabilityFailure::Failed {
                detail: format!("cannot cancel {ticket}: {err}"),
            })?
    };
    let (result, request_outcome) = match outcome {
        CancelOutcome::CancelledQueued => {
            // The queue already wrote the terminal row and the audit row;
            // what is left is answering anyone waiting on the ticket and
            // telling subscribers.
            ctx.router
                .finish(
                    ticket,
                    Response::Refusal {
                        retryable: false,
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

/// Whether `ticket` was admitted under the caller's repository (see
/// [`cancel`]). A missing row is "not the caller's": the answer the caller
/// gets is the same `not_found` either way.
async fn caller_owns_ticket(ctx: &ExecContext, ticket: &str) -> Result<bool, CapabilityFailure> {
    if ticket.is_empty() || ticket.len() > 128 {
        return Ok(false);
    }
    let status =
        ctx.store
            .request_status_meta(ticket)
            .await
            .map_err(|err| CapabilityFailure::Failed {
                detail: format!("cannot read {ticket}: {err}"),
            })?;
    Ok(status.is_some_and(|status| status.repository == ctx.caller.repo))
}
