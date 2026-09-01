//! Built-in capabilities and the context they execute in.
//!
//! # Design
//!
//! The capability registry is static by design (see the spine spec), so
//! dispatch is a plain enum — [`BuiltinCapability`] — rather than a
//! `dyn` trait object: native `async fn` in traits is not
//! dyn-compatible, and an enum over a closed set needs neither the
//! `async-trait` boxing detour nor manual future desugaring. Connectors
//! and flows extend this enum when they land.
//!
//! Capabilities receive an [`ExecContext`] and return either a
//! [`CapabilityOutput`] (outcome + body + evidence ids) or a
//! [`CapabilityFailure`]. They never touch the `request` row or the
//! audit trail themselves — terminal bookkeeping belongs to the daemon
//! pipeline ([`crate::daemon`]), which owns exactly one audit write per
//! terminal path.
//!
//! # Built-ins
//!
//! - `status` (read-only): daemon version, protocol version, uptime and
//!   the in-flight request count. Outcome `verified`.
//! - `query` (read-only): the lifecycle state of the request named by
//!   `args.ticket`, straight from the store. This is the authoritative
//!   answer `pam wait` / `pam subscribe` reconcile against: zmq `PUB`
//!   has no replay, so a subscriber that joins after a ticket's
//!   terminal event was published would otherwise wait forever on a
//!   request that already finished. Outcome `verified`.
//! - `echo` (non-destructive): mirrors its args back; an optional
//!   `delay_ms` argument sleeps first, honoring the cancel signal — the
//!   integration tests use it as a controllable long-running capability.
//!   An optional `fail: true` argument makes it fail (after any delay)
//!   with [`CapabilityFailure::Failed`] — a documented test/diagnostic
//!   surface for driving the execution-failure path end to end.
//!   Outcome `solved`.
//! - `cancel` (read-only class, see [`crate::policy::classify`] for why):
//!   the built-in behind `pam cancel <ticket>`. Cancels the queued or
//!   running request named by `args.ticket` via
//!   [`crate::queue::QueueManager::cancel`]. For a request cancelled
//!   while still queued (the queue writes the terminal row and audit),
//!   it also releases any attached waiters with a refusal and publishes
//!   the `refused` event — a running request reaches those through its
//!   own executor instead.

use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use tokio::sync::watch;

use crate::daemon::CompletionRouter;
use crate::queue::{CAUSE_CANCELLED, CancelOutcome, QueueManager};
use crate::transport::EventPublisher;

/// Recovery line offered when a request was cancelled.
const RECOVERY_CANCELLED: &str = "Re-run the pam command to start a fresh request.";

/// Everything a capability may need while executing one request.
#[derive(Debug)]
pub struct ExecContext {
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
    /// Completion router; the `cancel` built-in releases the waiters of
    /// a queued-cancelled request through it.
    pub router: CompletionRouter,
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
    /// The cancel signal fired (cancellation or lease reaping) and the
    /// capability stopped cooperatively.
    Cancelled,
    /// The capability ran and failed.
    Failed {
        /// Human-readable failure description.
        detail: String,
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
        }
    }

    /// Executes this capability for the request in `ctx`.
    pub async fn execute(self, ctx: ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
        match self {
            Self::Status => status(&ctx).await,
            Self::Query => query(&ctx).await,
            Self::Echo => echo(ctx).await,
            Self::Cancel => cancel(&ctx).await,
        }
    }
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

/// `status`: daemon version, protocol version, uptime, in-flight count.
///
/// The in-flight count includes the `status` request itself — its bypass
/// row is `running` while it executes.
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
        }),
        evidence: Vec::new(),
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
    let Some(ticket) = ctx.args.get("ticket").and_then(serde_json::Value::as_str) else {
        return Err(CapabilityFailure::Failed {
            detail: "query needs args.ticket naming the request to look up".to_owned(),
        });
    };
    let row = ctx
        .store
        .get_request(ticket)
        .await
        .map_err(|err| CapabilityFailure::Failed {
            detail: format!("cannot read request {ticket}: {err}"),
        })?;
    let Some(row) = row else {
        return Err(CapabilityFailure::Failed {
            detail: format!("no request {ticket} exists"),
        });
    };
    Ok(CapabilityOutput {
        outcome: Outcome::Verified,
        body: serde_json::json!({
            "ticket": row.id,
            "state": row.state.as_str(),
            "outcome": row.outcome,
        }),
        evidence: Vec::new(),
    })
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
async fn cancel(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let Some(ticket) = ctx.args.get("ticket").and_then(serde_json::Value::as_str) else {
        return Err(CapabilityFailure::Failed {
            detail: "cancel needs args.ticket naming the request to cancel".to_owned(),
        });
    };
    let outcome = ctx
        .queue
        .cancel(ticket, pam_store::Actor::System)
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
