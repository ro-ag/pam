//! The IPC bridge: the Tauri commands the frontend invokes, wrapping the
//! `pam_client` library — status, admin operations, ordinary capability
//! requests, and daemon stop.
//!
//! # Error shape
//!
//! Every command fails with a [`BridgeError`] serialized as
//! `{ cause, detail, recovery }`, mirroring the daemon's `Refusal` wire
//! shape — the frontend renders every failure the same way, whether the
//! daemon refused, the transport broke, or the bridge itself said no.
//! Daemon refusals pass through verbatim; client-side errors are mapped
//! onto the same shape here.
//!
//! # Command surface decisions
//!
//! - **One generic [`admin_call`]** instead of one command per op: the
//!   op names and body shapes live in `pam_daemon::admin`, and the
//!   frontend gets typed wrappers per op (`frontend/src/lib/ipc.ts`).
//!   The bridge whitelists the known `admin.*` op names before touching
//!   the socket, so a typo (or an unexpected op smuggled through the
//!   webview) is refused client-side with the same legible shape the
//!   daemon would answer with.
//! - **[`daemon_status`] never errors on an unreachable daemon** — it
//!   answers `{ connected: false }` so the beacon can render "down"
//!   without treating it as a failure. It calls
//!   `pam_client::client::send_request`, which ensures the daemon first:
//!   opening the GUI (or the status poll) lazily starts the daemon, and
//!   the envelope carries the GUI process's own advisory caller identity
//!   — status is an ordinary read-only capability, not an admin op.
//! - **[`request_capability`] is the thin escape hatch** for future views
//!   (echo/status today). `send_request` refuses `admin.*` structurally;
//!   administration goes through [`admin_call`] and `send_admin` only.

use std::path::PathBuf;
use std::time::Duration;

use pam_client::client::{self, RequestError};
use pam_daemon::admin::{
    OP_ACTIVITY_LIST, OP_APPROVALS_PENDING, OP_APPROVALS_RESOLVE, OP_CALLERS_LIST, OP_GRANTS_ADD,
    OP_GRANTS_LIST, OP_GRANTS_REVOKE, OP_PROFILE_GET, OP_PROFILE_SET,
};
use pam_daemon::admin_connectors::{CONNECTOR_ADMIN_OPS, OP_CONNECTORS_TEST};
use pam_daemon::admin_flows::FLOW_ADMIN_OPS;
use pam_daemon::admin_logs::{LOG_ADMIN_OPS, OP_LOG_COMPRESS};
use pam_daemon::admin_models::{MODEL_ADMIN_OPS, OP_MODELS_TRY};
use pam_proto::Response;
use serde::Serialize;

/// Deadline for the status poll: small so the beacon flips fast.
const STATUS_DEADLINE_MS: u64 = 5_000;

/// Deadline for admin operations (synchronous request/reply).
const ADMIN_DEADLINE_MS: u64 = 30_000;

/// Deadline for the two admin ops that do real work rather than a read:
/// `admin.models.try` runs a generation, and `admin.log.compress` runs a
/// 64 MiB compaction plus a generation. A cold prompt on a large model
/// decodes for minutes, not seconds, so the shared 30 s ceiling would
/// time out a working model.
const LONG_DEADLINE_MS: u64 = 120_000;

/// Deadline for `admin.connectors.test`: the daemon gives the remote
/// service ten seconds (`CONNECTOR_TEST_DEADLINE`), so the bridge waits
/// just long enough to hear the verdict rather than time out over it.
const CONNECTOR_TEST_DEADLINE_MS: u64 = 15_000;

/// How long [`daemon_stop`] waits for the daemon's drain to finish.
const STOP_WAIT: Duration = Duration::from_secs(10);

/// The core admin surface (`pam_daemon::admin`): profile, grants,
/// approvals, activity, callers.
const CORE_ADMIN_OPS: [&str; 9] = [
    OP_PROFILE_GET,
    OP_PROFILE_SET,
    OP_GRANTS_LIST,
    OP_GRANTS_ADD,
    OP_GRANTS_REVOKE,
    OP_APPROVALS_PENDING,
    OP_APPROVALS_RESOLVE,
    OP_ACTIVITY_LIST,
    OP_CALLERS_LIST,
];

/// How many ops the whitelist carries: the core surface plus the model,
/// log, flow and connector surfaces, counted from the daemon's own lists.
const ADMIN_OPS_LEN: usize = CORE_ADMIN_OPS.len()
    + MODEL_ADMIN_OPS.len()
    + LOG_ADMIN_OPS.len()
    + FLOW_ADMIN_OPS.len()
    + CONNECTOR_ADMIN_OPS.len();

/// Splices the five daemon-owned lists into one array at compile time —
/// no op name is retyped here, so the whitelist cannot drift from the
/// daemon's dispatch.
const fn compose_admin_ops() -> [&'static str; ADMIN_OPS_LEN] {
    let mut ops = [""; ADMIN_OPS_LEN];
    let mut index = 0;
    while index < CORE_ADMIN_OPS.len() {
        ops[index] = CORE_ADMIN_OPS[index];
        index += 1;
    }
    let mut model = 0;
    while model < MODEL_ADMIN_OPS.len() {
        ops[index + model] = MODEL_ADMIN_OPS[model];
        model += 1;
    }
    index += MODEL_ADMIN_OPS.len();
    let mut log = 0;
    while log < LOG_ADMIN_OPS.len() {
        ops[index + log] = LOG_ADMIN_OPS[log];
        log += 1;
    }
    index += LOG_ADMIN_OPS.len();
    let mut flow = 0;
    while flow < FLOW_ADMIN_OPS.len() {
        ops[index + flow] = FLOW_ADMIN_OPS[flow];
        flow += 1;
    }
    index += FLOW_ADMIN_OPS.len();
    let mut connector = 0;
    while connector < CONNECTOR_ADMIN_OPS.len() {
        ops[index + connector] = CONNECTOR_ADMIN_OPS[connector];
        connector += 1;
    }
    ops
}

/// Every admin op the bridge forwards; anything else is refused before
/// touching the socket. Composed from `pam_daemon::admin`,
/// `pam_daemon::admin_models`, `pam_daemon::admin_logs`,
/// `pam_daemon::admin_flows` and `pam_daemon::admin_connectors` — the
/// daemon would refuse an unknown op too, this just fails faster and
/// keeps the GUI surface explicit.
pub const ADMIN_OPS: [&str; ADMIN_OPS_LEN] = compose_admin_ops();

/// True when `op` is an admin operation the bridge forwards.
#[must_use]
pub fn is_known_admin_op(op: &str) -> bool {
    ADMIN_OPS.contains(&op)
}

/// How long the bridge waits for `op`'s answer.
///
/// Every admin op is synchronous request/reply inside
/// [`ADMIN_DEADLINE_MS`], except the two that do real work: a generation
/// (`admin.models.try`), or a 64 MiB compaction plus a generation
/// (`admin.log.compress`). `admin.connectors.test` gets its own
/// [`CONNECTOR_TEST_DEADLINE_MS`]: it reaches a remote service the daemon
/// already bounds at ten seconds.
///
/// `admin.flows.run` is *not* long: it answers with a ticket the moment
/// the pipeline admits the run, and the GUI follows that ticket's events.
#[must_use]
pub fn deadline_for(op: &str) -> u64 {
    match op {
        OP_MODELS_TRY | OP_LOG_COMPRESS => LONG_DEADLINE_MS,
        OP_CONNECTORS_TEST => CONNECTOR_TEST_DEADLINE_MS,
        _ => ADMIN_DEADLINE_MS,
    }
}

/// The one failure shape every bridge command speaks: the daemon's
/// `Refusal` fields, so the frontend renders any failure identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeError {
    /// Machine-readable cause.
    pub cause: String,
    /// Human-readable explanation.
    pub detail: String,
    /// Sentence pointing the human at a way out.
    pub recovery: String,
}

impl BridgeError {
    /// Builds an error from its three parts.
    pub(crate) fn new(
        cause: impl Into<String>,
        detail: impl Into<String>,
        recovery: impl Into<String>,
    ) -> Self {
        Self {
            cause: cause.into(),
            detail: detail.into(),
            recovery: recovery.into(),
        }
    }
}

/// Maps a client-side request failure onto the refusal shape.
impl From<RequestError> for BridgeError {
    fn from(err: RequestError) -> Self {
        let detail = err.to_string();
        match err {
            RequestError::AdminOnly { .. } | RequestError::NotAdmin { .. } => Self::new(
                "wrong_channel",
                detail,
                "Admin operations go through admin_call; everything else through \
                 request_capability.",
            ),
            RequestError::Parse { .. } => Self::new(
                "protocol_error",
                detail,
                "Restart the daemon; a version mismatch usually clears on restart.",
            ),
            RequestError::FollowTimeout { .. } | RequestError::ReplyTimeout { .. } => {
                Self::new("reply_timeout", detail, "Retry with a larger deadline.")
            }
            RequestError::Ensure(_)
            | RequestError::RuntimeDir(_)
            | RequestError::Connect { .. } => Self::new(
                "daemon_unreachable",
                detail,
                "Check that the pam daemon can start; see ~/.pam/log/daemon.log.",
            ),
            RequestError::Transport { .. } => Self::new(
                "transport_failure",
                detail,
                "Retry; the daemon may have been restarting.",
            ),
        }
    }
}

/// True when the failure means "no daemon is answering" — the status
/// command reports these as `connected: false` instead of erroring.
#[must_use]
pub fn is_disconnect(err: &RequestError) -> bool {
    matches!(
        err,
        RequestError::Ensure(_)
            | RequestError::Connect { .. }
            | RequestError::Transport { .. }
            | RequestError::ReplyTimeout { .. }
    )
}

/// Unwraps a [`Response`], passing a daemon refusal through verbatim and
/// rejecting the shapes the caller did not ask for.
///
/// Public so the bridge integration tests (`tests/bridge.rs`) can drive
/// the exact unwrap the commands use against a real daemon's answers.
///
/// # Errors
///
/// A refusal maps onto [`BridgeError`] verbatim; a ticket answers with
/// cause `unexpected_ticket` (synchronous ops never queue).
pub fn expect_result(response: Response) -> Result<serde_json::Value, BridgeError> {
    match response {
        Response::Result { body, .. } => Ok(body),
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => Err(BridgeError {
            cause,
            detail,
            recovery,
        }),
        Response::Ticket { ticket, .. } => Err(BridgeError::new(
            "unexpected_ticket",
            format!("the daemon queued the request as {ticket} instead of answering"),
            "Retry; report this if it persists — synchronous ops never queue.",
        )),
    }
}

/// The base directory the bridge works under (`$PAM_BASE_DIR` or
/// `~/.pam`), shared with the CLI via `pam_client`.
pub(crate) fn resolve_base_dir() -> Result<PathBuf, BridgeError> {
    pam_client::default_base_dir().ok_or_else(|| {
        BridgeError::new(
            "no_home",
            "cannot resolve the home directory to place ~/.pam",
            "Set $HOME (or $PAM_BASE_DIR) and reopen the GUI.",
        )
    })
}

/// What [`daemon_status`] answers.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonStatusReply {
    /// True when the daemon answered the status request.
    pub connected: bool,
    /// The `status` capability's result body when connected.
    pub status: Option<serde_json::Value>,
}

/// Daemon health for the beacon and the status views: ensures the daemon
/// (lazy start) and asks the ordinary read-only `status` capability.
/// An unreachable daemon is `{ connected: false }`, not an error.
#[tauri::command]
pub async fn daemon_status() -> Result<DaemonStatusReply, BridgeError> {
    let base = resolve_base_dir()?;
    let sent = client::send_request(
        &base,
        "status",
        serde_json::json!({}),
        true,
        STATUS_DEADLINE_MS,
        None,
    )
    .await;
    match sent {
        Ok(response) => Ok(DaemonStatusReply {
            connected: true,
            status: Some(expect_result(response)?),
        }),
        Err(err) if is_disconnect(&err) => Ok(DaemonStatusReply {
            connected: false,
            status: None,
        }),
        Err(err) => Err(err.into()),
    }
}

/// One generic admin command wrapping `pam_client::client::send_admin`:
/// the op must be on the [`ADMIN_OPS`] whitelist. Returns the op's
/// result body; refusals surface as [`BridgeError`].
#[tauri::command]
pub async fn admin_call(
    op: String,
    args: serde_json::Value,
) -> Result<serde_json::Value, BridgeError> {
    if !is_known_admin_op(&op) {
        return Err(BridgeError::new(
            "unknown_admin_op",
            format!("the bridge forwards no admin operation named {op:?}"),
            "Use one of the admin ops the GUI ships wrappers for.",
        ));
    }
    let base = resolve_base_dir()?;
    let response = client::send_admin(&base, &op, args, deadline_for(&op))
        .await
        .map_err(BridgeError::from)?;
    expect_result(response)
}

/// Thin wrapper over `send_request` for ordinary capabilities (echo and
/// status today; future views grow from here). `admin.*` is refused by
/// `send_request` itself — administration goes through [`admin_call`].
/// Returns the full tagged response (`kind`: result or ticket) so a
/// `wait: false` caller can follow its ticket.
#[tauri::command]
pub async fn request_capability(
    capability: String,
    args: serde_json::Value,
    wait: bool,
) -> Result<serde_json::Value, BridgeError> {
    let base = resolve_base_dir()?;
    let response = client::send_request(
        &base,
        &capability,
        args,
        wait,
        pam_client::request::DEFAULT_DEADLINE_MS,
        None,
    )
    .await
    .map_err(BridgeError::from)?;
    if let Response::Refusal {
        cause,
        detail,
        recovery,
        ..
    } = response
    {
        return Err(BridgeError {
            cause,
            detail,
            recovery,
        });
    }
    serde_json::to_value(&response).map_err(|err| {
        BridgeError::new(
            "protocol_error",
            format!("cannot serialize the daemon's response: {err}"),
            "Retry; report this if it persists.",
        )
    })
}

/// What [`daemon_stop`] answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonStopReply {
    /// `not_running`, `stopped`, or `still_draining`.
    pub outcome: &'static str,
    /// The daemon's pid when one was signalled.
    pub pid: Option<u32>,
}

/// Stops the daemon: SIGTERM to the lock holder, bounded wait for the
/// drain (shared mechanics with `pam daemon stop`). The next
/// [`daemon_status`] poll lazily restarts it.
#[tauri::command]
pub async fn daemon_stop() -> Result<DaemonStopReply, BridgeError> {
    let base = resolve_base_dir()?;
    // stop_daemon blocks (signal + lock-poll wait); keep it off the
    // async workers.
    let stopped =
        tauri::async_runtime::spawn_blocking(move || client::stop_daemon(&base, STOP_WAIT))
            .await
            .map_err(|err| {
                BridgeError::new(
                    "internal_error",
                    format!("the stop task failed: {err}"),
                    "Retry; report this if it persists.",
                )
            })?
            .map_err(|err| {
                BridgeError::new(
                    "stop_failed",
                    err.to_string(),
                    "Stop the pam daemon process manually if this persists.",
                )
            })?;
    Ok(match stopped {
        client::StopOutcome::NotRunning => DaemonStopReply {
            outcome: "not_running",
            pid: None,
        },
        client::StopOutcome::Stopped { pid } => DaemonStopReply {
            outcome: "stopped",
            pid: Some(pid),
        },
        client::StopOutcome::StillDraining { pid } => DaemonStopReply {
            outcome: "still_draining",
            pid: Some(pid),
        },
    })
}
