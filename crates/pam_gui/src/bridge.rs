//! The IPC bridge: the Tauri commands the frontend invokes, wrapping the `pam_client` library —
//! status, admin operations, ordinary capability requests, and daemon stop. Every command fails
//! with a [`BridgeError`] serialized as `{ cause, detail, recovery }`, mirroring the daemon's
//! `Refusal` wire shape, so the frontend renders every failure the same way whether the daemon
//! refused, the transport broke, or the bridge itself said no.
//!
//! **One generic [`admin_call`]** replaces one command per op: the bridge allowlists the known
//! `admin.*` op names ([`ADMIN_OPS`], exactly the set the frontend's `AdminOp` type names — a test
//! reads that file) before touching the socket, so a typo or smuggled op is refused client-side
//! with the same shape the daemon would give. The webview is a full-admin root, so the ops that
//! **expand what agents may do** ([`required_confirmation`]: switching to the relaxed profile, adding
//! a grant, approving with "remember", routing connector traffic through a proxy or a CA bundle)
//! additionally need a typed confirmation that the bridge
//! checks in Rust before the op reaches the socket. Tauri's dialog plugin is not part of this
//! binary and no dependency may be added, so the prompt itself is drawn by the frontend; a webview
//! that is already compromised could supply the phrase itself, which is why this is a second wall
//! against mistakes and blind one-click flows, not against a hostile frontend.
//! **[`daemon_status`] never errors on an unreachable
//! daemon** — it answers `{ connected: false }` and lazily starts the daemon via `send_request`
//! (status is read-only, not an admin op). `send_request` refuses `admin.*` structurally, so the
//! GUI sends no other public capability: cancelling a run is the admin op `admin.requests.cancel`,
//! on the private channel like every other human act.
//! The GUI's own status polls publish no events (the daemon keeps none for control requests), so
//! they never feed back into its refresh loop through the event stream ([`crate::events`]).
//! Daemon refusals pass through verbatim; client-side errors are mapped onto the same shape here.
//! The envelope carries the GUI process's own advisory (not authenticated) caller identity.

use std::path::PathBuf;
use std::time::Duration;

use pam_client::client::{self, ClientError, RequestError};
use pam_daemon::admin::{
    OP_ACTIVITY_LIST, OP_APPROVALS_PENDING, OP_APPROVALS_RESOLVE, OP_AUDIT_REQUEST,
    OP_CALLERS_LIST, OP_GRANTS_ADD, OP_GRANTS_LIST, OP_GRANTS_REVOKE, OP_PROFILE_GET,
    OP_PROFILE_SET, OP_REQUESTS_CANCEL,
};
use pam_daemon::admin_connectors::{CONNECTOR_ADMIN_OPS, OP_CONNECTORS_TEST};
use pam_daemon::admin_engine::OP_ENGINE_INSTALL;
use pam_daemon::admin_flows::FLOW_ADMIN_OPS;
use pam_daemon::admin_logs::{LOG_ADMIN_OPS, OP_LOG_COMPRESS};
use pam_daemon::admin_models::{MODEL_ADMIN_OPS, OP_MODELS_TRY};
use pam_daemon::admin_network::{NETWORK_ADMIN_OPS, OP_NETWORK_SET, OP_NETWORK_TEST};
use pam_daemon::admin_retention::RETENTION_ADMIN_OPS;
use pam_daemon::lifecycle::{LOG_DIR, LOG_FILE};
use pam_proto::Response;
use serde::Serialize;

/// Deadline for the status poll: small so the beacon flips fast.
const STATUS_DEADLINE_MS: u64 = 5_000;

/// Hard client-side bound on one status poll, covering the lazy daemon start and the connect
/// retries around the request's own deadline: a poll that outlives it is a daemon that is not
/// answering, never a hung command that holds a control permit for good.
const STATUS_CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

/// Deadline for admin operations (synchronous request/reply).
const ADMIN_DEADLINE_MS: u64 = 30_000;

/// Deadline for the three admin ops that do real work rather than a read:
/// `admin.models.try` runs a generation, `admin.log.compress` runs a
/// 64 MiB compaction plus a generation, and `admin.models.engine.install`
/// downloads and verifies the pinned inference engine. A cold prompt on a
/// large model decodes for minutes, not seconds, so the shared 30 s
/// ceiling would time out a working model.
const LONG_DEADLINE_MS: u64 = 120_000;

/// Deadline for `admin.connectors.test`: the daemon gives the remote
/// service ten seconds (`CONNECTOR_TEST_DEADLINE`), so the bridge waits
/// just long enough to hear the verdict rather than time out over it.
const CONNECTOR_TEST_DEADLINE_MS: u64 = 15_000;

/// Deadline for `admin.network.test`: the daemon bounds the whole probe
/// run at twenty seconds (`NETWORK_TEST_DEADLINE`), so the bridge waits
/// just past that for the table of results.
const NETWORK_TEST_DEADLINE_MS: u64 = 25_000;

/// How long [`daemon_stop`] waits for the daemon's drain to finish.
const STOP_WAIT: Duration = Duration::from_secs(10);

/// The core admin surface (`pam_daemon::admin`): profile, grants,
/// approvals, activity, callers, audit.
const CORE_ADMIN_OPS: [&str; 11] = [
    OP_PROFILE_GET,
    OP_PROFILE_SET,
    OP_GRANTS_LIST,
    OP_GRANTS_ADD,
    OP_GRANTS_REVOKE,
    OP_APPROVALS_PENDING,
    OP_APPROVALS_RESOLVE,
    OP_ACTIVITY_LIST,
    OP_CALLERS_LIST,
    OP_AUDIT_REQUEST,
    OP_REQUESTS_CANCEL,
];

/// How many ops the whitelist carries: the core surface plus the model,
/// log, flow, connector, retention and network surfaces, counted from the
/// daemon's own lists.
const ADMIN_OPS_LEN: usize = CORE_ADMIN_OPS.len()
    + MODEL_ADMIN_OPS.len()
    + LOG_ADMIN_OPS.len()
    + FLOW_ADMIN_OPS.len()
    + CONNECTOR_ADMIN_OPS.len()
    + RETENTION_ADMIN_OPS.len()
    + NETWORK_ADMIN_OPS.len();

/// Splices the seven daemon-owned lists into one array at compile time —
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
    index += CONNECTOR_ADMIN_OPS.len();
    let mut retention = 0;
    while retention < RETENTION_ADMIN_OPS.len() {
        ops[index + retention] = RETENTION_ADMIN_OPS[retention];
        retention += 1;
    }
    index += RETENTION_ADMIN_OPS.len();
    let mut network = 0;
    while network < NETWORK_ADMIN_OPS.len() {
        ops[index + network] = NETWORK_ADMIN_OPS[network];
        network += 1;
    }
    ops
}

/// Every admin op the bridge forwards; anything else is refused before
/// touching the socket. Composed from `pam_daemon::admin`,
/// `pam_daemon::admin_models`, `pam_daemon::admin_logs`,
/// `pam_daemon::admin_flows`, `pam_daemon::admin_connectors`,
/// `pam_daemon::admin_retention` and `pam_daemon::admin_network` — the
/// daemon would refuse an unknown op too, this just fails faster and keeps
/// the GUI surface explicit.
pub const ADMIN_OPS: [&str; ADMIN_OPS_LEN] = compose_admin_ops();

/// True when `op` is an admin operation the bridge forwards.
#[must_use]
pub fn is_known_admin_op(op: &str) -> bool {
    ADMIN_OPS.contains(&op)
}

/// How long the bridge waits for `op`'s answer.
///
/// Every admin op is synchronous request/reply inside
/// `ADMIN_DEADLINE_MS`, except the three that do real work: a generation
/// (`admin.models.try`), a 64 MiB compaction plus a generation
/// (`admin.log.compress`), or an engine download and verification
/// (`admin.models.engine.install`). `admin.connectors.test` gets its own
/// `CONNECTOR_TEST_DEADLINE_MS`: it reaches a remote service the daemon
/// already bounds at ten seconds; `admin.network.test` likewise gets
/// `NETWORK_TEST_DEADLINE_MS` over the daemon's twenty.
///
/// `admin.flows.run` is *not* long: it answers with a ticket the moment
/// the pipeline admits the run, and the GUI follows that ticket's events.
#[must_use]
pub fn deadline_for(op: &str) -> u64 {
    match op {
        OP_MODELS_TRY | OP_LOG_COMPRESS | OP_ENGINE_INSTALL => LONG_DEADLINE_MS,
        OP_CONNECTORS_TEST => CONNECTOR_TEST_DEADLINE_MS,
        OP_NETWORK_TEST => NETWORK_TEST_DEADLINE_MS,
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

/// What the human does about a daemon of an earlier build that this process
/// could not stop. Windows has no `pam daemon stop`.
const LEGACY_DAEMON_RECOVERY: &str = if cfg!(windows) {
    "End the old pam daemon process (Task Manager), then try again; PAM starts the current \
     daemon by itself."
} else {
    "Run `pam daemon stop` in a terminal, then try again; PAM starts the current daemon by itself."
};

/// Maps a client-side request failure onto the refusal shape.
impl From<RequestError> for BridgeError {
    fn from(err: RequestError) -> Self {
        let detail = err.to_string();
        match err {
            RequestError::AdminOnly { .. } | RequestError::NotAdmin { .. } => Self::new(
                "wrong_channel",
                detail,
                "Admin operations go through admin_call; the bridge sends no other \
                 public capability.",
            ),
            RequestError::FollowRefused {
                cause, recovery, ..
            } => Self::new(cause, detail, recovery),
            RequestError::Parse { .. } => Self::new(
                "protocol_error",
                detail,
                "Restart the daemon; a version mismatch usually clears on restart.",
            ),
            RequestError::FollowTimeout { .. } | RequestError::ReplyTimeout { .. } => {
                Self::new("reply_timeout", detail, "Retry with a larger deadline.")
            }
            // A daemon of an earlier build is there and this process could
            // not stop it. Not "unreachable": starting a daemon would not
            // help, and the human has to act.
            RequestError::Ensure(
                ClientError::LegacyDaemon { .. } | ClientError::LegacyBehindRelay { .. },
            ) => Self::new("legacy_daemon", detail, LEGACY_DAEMON_RECOVERY),
            // The old daemon was told to stop and is still draining.
            RequestError::Ensure(ClientError::LegacyDraining { .. }) => Self::new(
                "daemon_restarting",
                detail,
                "Retry in a few seconds; the old daemon exits when its drain completes.",
            ),
            RequestError::Ensure(_)
            | RequestError::RuntimeDir(_)
            | RequestError::Connect { .. } => Self::new(
                "daemon_unreachable",
                detail,
                format!(
                    "Check that the pam daemon can start; see {}.",
                    daemon_log_path()
                ),
            ),
            RequestError::SessionUnreachable { dir, .. } => Self::new(
                "session_relay_unreachable",
                detail,
                format!(
                    "Start the session relay outside the sandbox with `pam listen {}`.",
                    dir.display()
                ),
            ),
            RequestError::Transport { .. } => Self::new(
                "transport_failure",
                detail,
                "Retry; the daemon may have been restarting.",
            ),
            RequestError::AdminTransport { .. } => Self::new(
                "admin_transport_failed",
                detail,
                "Open the installed PAM GUI on a supported platform and check the daemon log. \
                 Inspect whether the change already took effect before trying again; \
                 administration never falls back to the public socket.",
            ),
        }
    }
}

/// True when the failure means "no daemon is answering" — the status
/// command reports these as `connected: false` instead of erroring.
///
/// A pre-migration daemon this process could not stop is not that: a daemon
/// is answering, in a protocol this build does not speak, and it stays until
/// the human stops it. That surfaces as the `legacy_daemon` error with its
/// instruction instead of a silent "offline". One that was told to stop and
/// is still draining is momentary and does read as disconnected.
#[must_use]
pub fn is_disconnect(err: &RequestError) -> bool {
    match err {
        RequestError::Ensure(
            ClientError::LegacyDaemon { .. } | ClientError::LegacyBehindRelay { .. },
        ) => false,
        RequestError::Ensure(_)
        | RequestError::Connect { .. }
        | RequestError::Transport { .. }
        | RequestError::ReplyTimeout { .. } => true,
        _ => false,
    }
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

/// Where the daemon writes its log, under the resolved base directory
/// (`$PAM_BASE_DIR` or `~/.pam`), for recovery lines that point at it.
/// Falls back to the documented default when no home directory resolves.
pub(crate) fn daemon_log_path() -> String {
    pam_client::default_base_dir().map_or_else(
        || format!("~/.pam/{LOG_DIR}/{LOG_FILE}"),
        |base| base.join(LOG_DIR).join(LOG_FILE).display().to_string(),
    )
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
    /// The base directory the bridge resolved (`$PAM_BASE_DIR` or
    /// `~/.pam`), so the GUI shows the live value instead of the rule.
    pub base_dir: String,
}

/// Daemon health for the beacon and the status views: ensures the daemon
/// (lazy start) and asks the ordinary read-only `status` capability.
/// An unreachable daemon is `{ connected: false }`, not an error. The poll
/// publishes no lifecycle events, so it cannot come back through the event
/// stream, and the whole call is bounded by `STATUS_CLIENT_TIMEOUT`.
#[tauri::command]
pub async fn daemon_status() -> Result<DaemonStatusReply, BridgeError> {
    let base = resolve_base_dir()?;
    let sent = tokio::time::timeout(
        STATUS_CLIENT_TIMEOUT,
        client::send_request(
            &base,
            "status",
            serde_json::json!({}),
            true,
            STATUS_DEADLINE_MS,
            None,
        ),
    )
    .await
    .unwrap_or(Err(RequestError::ReplyTimeout {
        waited: STATUS_CLIENT_TIMEOUT,
    }));
    let base_dir = base.display().to_string();
    match sent {
        Ok(response) => Ok(DaemonStatusReply {
            connected: true,
            status: Some(expect_result(response)?),
            base_dir,
        }),
        Err(err) if is_disconnect(&err) => Ok(DaemonStatusReply {
            connected: false,
            status: None,
            base_dir,
        }),
        Err(err) => Err(err.into()),
    }
}

/// What the human must type to authorise `op` with `args`, or `None` when the op does not expand
/// what agents may do. Fails closed: anything that is not clearly a narrowing needs the phrase.
///
/// - `admin.profile.set` to anything but `standard`/`strict` ([`CONFIRM_RELAXED`]): the relaxed
///   profile lets safe capabilities grant themselves on first use.
/// - `admin.grants.add` ([`CONFIRM_GRANT`]): a grant is global, not per repository.
/// - `admin.approvals.resolve` with `remember` on anything but a denial ([`CONFIRM_GRANT`]):
///   remembering an approval persists the same global grant.
/// - `admin.network.set` that sets a proxy, stores a proxy password or imports a CA bundle
///   ([`CONFIRM_NETWORK`]): a proxy plus a CA bundle is the one configuration that lets a third
///   party read the credentials PAM sends to connectors. Clearing any of them, editing the
///   no-proxy list or setting a mirror is one click. The frontend sends a proxy object only when
///   it differs from the stored one, so every non-null `proxy` counts as a change here.
#[must_use]
pub fn required_confirmation(op: &str, args: &serde_json::Value) -> Option<&'static str> {
    match op {
        OP_NETWORK_SET => {
            let sets = |key: &str| {
                args.get(key)
                    .is_some_and(|value| !value.is_null() && value.get("clear").is_none())
            };
            (sets("proxy") || sets("credential") || sets("ca_bundle")).then_some(CONFIRM_NETWORK)
        }
        OP_PROFILE_SET => match args.get("profile").and_then(serde_json::Value::as_str) {
            Some("standard" | "strict") => None,
            _ => Some(CONFIRM_RELAXED),
        },
        OP_GRANTS_ADD => Some(CONFIRM_GRANT),
        OP_APPROVALS_RESOLVE => {
            let remembered = !matches!(
                args.get("remember"),
                None | Some(serde_json::Value::Null | serde_json::Value::Bool(false))
            );
            let denied =
                args.get("resolution").and_then(serde_json::Value::as_str) == Some("denied");
            (remembered && !denied).then_some(CONFIRM_GRANT)
        }
        _ => None,
    }
}

/// The phrase for switching to the relaxed profile.
pub const CONFIRM_RELAXED: &str = "relaxed";

/// The phrase for adding a global grant, directly or by approving with "remember".
pub const CONFIRM_GRANT: &str = "grant";

/// The phrase for setting a proxy, storing its password or importing a CA bundle.
pub const CONFIRM_NETWORK: &str = "network";

/// Checks `confirmation` against [`required_confirmation`] for this op.
///
/// # Errors
///
/// `confirmation_required` when the op needs a phrase and `confirmation` is not it.
pub fn check_confirmation(
    op: &str,
    args: &serde_json::Value,
    confirmation: Option<&str>,
) -> Result<(), BridgeError> {
    let Some(phrase) = required_confirmation(op, args) else {
        return Ok(());
    };
    if confirmation.is_some_and(|given| given.trim().eq_ignore_ascii_case(phrase)) {
        return Ok(());
    }
    Err(BridgeError::new(
        "confirmation_required",
        format!("{op} expands what agents may do and needs your typed confirmation"),
        format!("Confirm in the prompt by typing {phrase:?}, then retry."),
    ))
}

/// One generic admin command wrapping `pam_client::client::send_admin`:
/// the op must be on the [`ADMIN_OPS`] allowlist, and an op that expands
/// what agents may do needs its typed `confirmation` ([`required_confirmation`])
/// — both checked before anything touches the socket. Returns the op's
/// result body; refusals surface as [`BridgeError`].
#[tauri::command]
pub async fn admin_call(
    op: String,
    args: serde_json::Value,
    confirmation: Option<String>,
) -> Result<serde_json::Value, BridgeError> {
    if !is_known_admin_op(&op) {
        return Err(BridgeError::new(
            "unknown_admin_op",
            format!("the bridge forwards no admin operation named {op:?}"),
            "Use one of the admin ops the GUI ships wrappers for.",
        ));
    }
    check_confirmation(&op, &args, confirmation.as_deref())?;
    let base = resolve_base_dir()?;
    let response = client::send_admin(&base, &op, args, deadline_for(&op))
        .await
        .map_err(BridgeError::from)?;
    expect_result(response)
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
