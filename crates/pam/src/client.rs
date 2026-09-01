//! Client-side daemon lifecycle: lazy auto-start.
//!
//! Any `pam` command may find no daemon behind `pam.sock` — a fresh
//! machine, a crashed daemon, or one that just drained itself away for
//! a self-restart. [`ensure_daemon`] makes the daemon exist before the
//! command talks to it: probe, spawn `pam daemon` detached if nobody is
//! there, and wait (bounded, ~3 s, one respawn retry) for readiness.
//!
//! # Probe
//!
//! "A daemon is running" is read from the same facts the daemon
//! maintains: the `daemon.lock` file is **held** (the probe tries the
//! advisory lock itself — winning it proves nobody else holds it, and
//! the probe releases it immediately) and the `pam.sock` file exists.
//! A stale socket with no lock holder therefore reads as *no daemon*,
//! and the spawned daemon removes and rebinds it under the lock. The
//! lock probe is authoritative in a way pinging the socket is not: it
//! cannot be fooled by a leftover socket file, needs no timeout, and
//! costs one syscall.
//!
//! # Request flow
//!
//! [`send_request`] is the full path every client subcommand takes:
//! ensure the daemon exists, build the envelope ([`crate::request`]),
//! exchange it over a zmq `DEALER` against `pam.sock` with a client-side
//! timeout of `deadline_ms` plus a margin, and retry exactly once after
//! a [`CAUSE_DAEMON_OUTDATED`] refusal (the daemon drains and re-spawns
//! the newer binary; the spec says the client retries).
//!
//! [`follow_ticket`] is the event side: subscribe to `events.sock` on
//! the ticket's topic and stream events until a terminal `done` /
//! `refused` (bounded by a caller-chosen timeout), reconciling against
//! the daemon's store (read-only `query` capability) so a terminal
//! event that predates the subscription still terminates the follow —
//! zmq `PUB` has no replay (see the function docs). `pam wait` follows
//! quietly; `pam subscribe` prints each event — one code path, the
//! callback decides.

use std::fs::{OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pam_daemon::daemon::CAUSE_DAEMON_OUTDATED;
use pam_daemon::lifecycle::LOCK_FILE;
use pam_daemon::runtime_dir::{RuntimeDir, RuntimeDirError};
use pam_proto::{Envelope, Event, Response};
use thiserror::Error;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

use crate::request::build_envelope;

/// How long [`ensure_daemon`] waits for a spawned daemon to become
/// ready, per spawn attempt.
pub const READINESS_WAIT: Duration = Duration::from_secs(3);

/// How often the readiness wait re-probes.
const READINESS_POLL: Duration = Duration::from_millis(50);

/// How many times [`ensure_daemon`] spawns before giving up: the spec's
/// "retry once".
const SPAWN_ATTEMPTS: u32 = 2;

/// Why the daemon could not be ensured.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The runtime directory is unusable (home unresolvable, socket
    /// path too long, or the directory could not be created).
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// The lock-file probe failed at the filesystem level.
    #[error("cannot probe daemon lock {}: {source}", path.display())]
    Probe {
        /// The lock file being probed.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Spawning `pam daemon` failed.
    #[error("cannot spawn the pam daemon: {source}")]
    Spawn {
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The daemon did not become ready within the bounded wait.
    #[error(
        "the pam daemon did not become ready within {waited:?} \
         (after {SPAWN_ATTEMPTS} spawn attempts)"
    )]
    NotReady {
        /// Total time spent waiting across all attempts.
        waited: Duration,
    },
}

/// What [`ensure_daemon`] found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// A daemon already held the lock and served the socket.
    AlreadyRunning,
    /// No daemon was there; one was spawned and became ready.
    Started,
}

/// Makes sure a daemon serves `base_dir` (default `~/.pam` in the real
/// CLI): probes for a live one, otherwise spawns `pam daemon` detached
/// and waits — up to [`READINESS_WAIT`] per attempt, one retry — for it
/// to hold the lock and bind the socket.
pub fn ensure_daemon(base_dir: &Path) -> Result<EnsureOutcome, ClientError> {
    ensure_daemon_with(
        base_dir,
        &mut spawn_detached_daemon,
        READINESS_WAIT,
        READINESS_POLL,
    )
}

/// [`ensure_daemon`] with the spawner and timing injected — the
/// decision logic, unit-testable with a fake spawner (a test binary
/// cannot spawn the real `pam`; the real spawner is the thin
/// [`spawn_detached_daemon`] wrapper).
pub(crate) fn ensure_daemon_with(
    base_dir: &Path,
    spawn: &mut dyn FnMut() -> io::Result<()>,
    wait: Duration,
    poll: Duration,
) -> Result<EnsureOutcome, ClientError> {
    let dirs = RuntimeDir::at_base(base_dir)?;
    if daemon_ready(&dirs)? {
        return Ok(EnsureOutcome::AlreadyRunning);
    }
    for _attempt in 0..SPAWN_ATTEMPTS {
        spawn().map_err(|source| ClientError::Spawn { source })?;
        let deadline = Instant::now() + wait;
        loop {
            if daemon_ready(&dirs)? {
                return Ok(EnsureOutcome::Started);
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(poll);
        }
    }
    Err(ClientError::NotReady {
        waited: wait * SPAWN_ATTEMPTS,
    })
}

/// True when a daemon holds the instance lock **and** the request
/// socket file exists (see the module docs on the probe).
fn daemon_ready(dirs: &RuntimeDir) -> Result<bool, ClientError> {
    if !dirs.router_socket().exists() {
        return Ok(false);
    }
    lock_is_held(&dirs.run_dir().join(LOCK_FILE))
}

/// Probes the advisory lock on `path`: `true` when someone else holds
/// it. Winning the lock proves nobody does; it is released immediately
/// (the handle drops at return).
fn lock_is_held(path: &Path) -> Result<bool, ClientError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // Never truncate: a live daemon's pid lives in this file.
        .truncate(false)
        .open(path)
        .map_err(|source| ClientError::Probe {
            path: path.to_path_buf(),
            source,
        })?;
    match file.try_lock() {
        Ok(()) => Ok(false),
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(source)) => Err(ClientError::Probe {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The real spawner: `current_exe() daemon`, detached (no inherited
/// stdio, never waited on — the daemon self-logs to `~/.pam/log/`).
fn spawn_detached_daemon() -> io::Result<()> {
    let exe = std::env::current_exe()?;
    Command::new(exe)
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_child| ())
}

/// Default bound on `pam wait` / `pam subscribe` (10 minutes).
pub const DEFAULT_FOLLOW_TIMEOUT: Duration = Duration::from_mins(10);

/// Extra client-side budget on top of the envelope's `deadline_ms`
/// before [`send_request`] gives up on a reply: the daemon enforces the
/// deadline itself (it refuses, not hangs), so the margin only covers
/// transport latency around that refusal.
const REPLY_MARGIN: Duration = Duration::from_secs(5);

/// Pause before the single retry after a `daemon_outdated` refusal —
/// long enough for the old daemon to finish its drain and the new
/// binary to take the lock in the common case.
const OUTDATED_RETRY_PAUSE: Duration = Duration::from_millis(750);

/// Why the request flow failed client-side (a daemon-side "no" is a
/// [`Response::Refusal`], not an error).
#[derive(Debug, Error)]
pub enum RequestError {
    /// The daemon could not be ensured.
    #[error(transparent)]
    Ensure(#[from] ClientError),
    /// The runtime directory is unusable.
    #[error(transparent)]
    RuntimeDir(#[from] RuntimeDirError),
    /// Connecting a socket failed.
    #[error("cannot connect to {endpoint}: {source}")]
    Connect {
        /// The `ipc://` endpoint that failed.
        endpoint: String,
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
    /// The zmq exchange itself failed.
    #[error("transport failure talking to the daemon: {source}")]
    Transport {
        /// The underlying zmq error.
        #[source]
        source: zeromq::ZmqError,
    },
    /// The daemon's bytes did not parse as a [`Response`] / [`Event`].
    #[error("cannot parse the daemon's reply: {source}")]
    Parse {
        /// The underlying JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// No reply within the client-side budget.
    #[error("no reply from the daemon within {waited:?} (deadline plus margin)")]
    ReplyTimeout {
        /// How long the client waited.
        waited: Duration,
    },
    /// No terminal event within the follow bound.
    #[error("request {ticket} did not reach a terminal event within {waited:?}")]
    FollowTimeout {
        /// The ticket being followed.
        ticket: String,
        /// How long the client waited.
        waited: Duration,
    },
}

/// True when `response` is the version-handshake refusal after which
/// the spec tells the client to retry once: the daemon found the binary
/// on disk newer than itself and is restarting.
#[must_use]
pub fn should_retry(response: &Response) -> bool {
    matches!(response, Response::Refusal { cause, .. } if cause == CAUSE_DAEMON_OUTDATED)
}

/// Sends one request through the full client flow (see the module docs):
/// ensure the daemon, build the envelope, exchange over `pam.sock`, and
/// retry exactly once after a `daemon_outdated` refusal.
///
/// The daemon's answer — result, refusal, or ticket — is returned as-is;
/// rendering and exit codes are the caller's job ([`crate::render`]).
pub async fn send_request(
    base_dir: &Path,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
    deadline_ms: u64,
    idempotency_key: Option<String>,
) -> Result<Response, RequestError> {
    let envelope = build_envelope(capability, args, wait, deadline_ms, idempotency_key);
    let mut retried = false;
    loop {
        ensure_daemon(base_dir)?;
        let dirs = RuntimeDir::at_base(base_dir)?;
        let response = exchange(&dirs, &envelope).await?;
        if should_retry(&response) && !retried {
            retried = true;
            tokio::time::sleep(OUTDATED_RETRY_PAUSE).await;
            continue;
        }
        return Ok(response);
    }
}

/// One `DEALER` exchange: connect, send the envelope, await its single
/// reply under `deadline_ms` plus [`REPLY_MARGIN`].
async fn exchange(dirs: &RuntimeDir, envelope: &Envelope) -> Result<Response, RequestError> {
    let endpoint = dirs.router_endpoint();
    let mut dealer = DealerSocket::new();
    dealer
        .connect(&endpoint)
        .await
        .map_err(|source| RequestError::Connect { endpoint, source })?;
    let payload = serde_json::to_vec(envelope).map_err(|source| RequestError::Parse { source })?;
    dealer
        .send(ZmqMessage::from(payload))
        .await
        .map_err(|source| RequestError::Transport { source })?;

    let budget = Duration::from_millis(envelope.deadline_ms) + REPLY_MARGIN;
    let reply = tokio::time::timeout(budget, dealer.recv())
        .await
        .map_err(|_elapsed| RequestError::ReplyTimeout { waited: budget })?
        .map_err(|source| RequestError::Transport { source })?;
    let frames = reply.into_vec();
    let payload = frames
        .first()
        .map(|frame| frame.to_vec())
        .unwrap_or_default();
    serde_json::from_slice(&payload).map_err(|source| RequestError::Parse { source })
}

/// Deadline for each store reconciliation `query` request a follow
/// makes (see [`follow_ticket`]); small because the answer is a single
/// indexed row read.
const QUERY_DEADLINE_MS: u64 = 5_000;

/// First pause before a follow re-reconciles against the store; each
/// subsequent reconcile doubles it up to [`RECONCILE_MAX`], so a long
/// quiet follow stays cheap while a lost terminal event is still
/// noticed within seconds.
const RECONCILE_MIN: Duration = Duration::from_secs(1);

/// Cap on the reconcile back-off interval.
const RECONCILE_MAX: Duration = Duration::from_secs(30);

/// Follows a ticket's event stream on `events.sock` until its terminal
/// `done` / `refused` event, calling `on_event` for every event seen
/// (the terminal one included). Returns the terminal event; gives up
/// with [`RequestError::FollowTimeout`] past `timeout`.
///
/// # Why events alone are not enough (issue #1)
///
/// zmq `PUB` has no replay: an event published before the daemon's
/// `PUB` socket registered this subscription is gone for good. Live
/// verification hit exactly that: `pam echo --no-wait` then a separate
/// `pam subscribe` seconds later — by the time the subscriber joined,
/// the request's `done` event (and everything before it) had already
/// been published to nobody, so the follow sat blind until its
/// timeout. Cross-process delivery itself is sound (the same pure-Rust
/// zmq `SUB` over ipc receives reliably once the subscription is
/// registered before the publish); the in-process testkit never sees
/// the failure because its tests subscribe before sending requests. A
/// second, narrower hole has the same shape: `SubSocket::subscribe`
/// only queues the subscription frame to the publisher, so an event
/// published in the instant before the `PUB` side processes it is
/// silently filtered out — fatal when that event is the terminal one.
///
/// # The reconcile loop
///
/// The store is the authority on request state, so the follow never
/// trusts the event stream with the *termination* decision alone:
/// subscribe first, then reconcile by asking the daemon (read-only
/// `query` capability) whether the ticket is already terminal —
/// immediately after subscribing (catches a follower that joined after
/// the finish), and again on a backing-off interval while events are
/// quiet (catches a terminal event lost to the subscription race). A
/// reconciled terminal state is surfaced as the synthesized terminal
/// event. Intermediate events still stream with `PUB` latency; only
/// missed ones fall back to the reconcile cadence. Earlier events
/// published before the subscription (`queued`, `started`) remain
/// unreplayable — the documented `--no-wait` join race — but the
/// terminal event is now guaranteed to arrive.
pub async fn follow_ticket(
    base_dir: &Path,
    ticket: &str,
    timeout: Duration,
    mut on_event: impl FnMut(&Event),
) -> Result<Event, RequestError> {
    ensure_daemon(base_dir)?;
    let dirs = RuntimeDir::at_base(base_dir)?;
    let endpoint = dirs.events_endpoint();
    let mut sub = SubSocket::new();
    sub.connect(&endpoint)
        .await
        .map_err(|source| RequestError::Connect { endpoint, source })?;
    sub.subscribe(ticket)
        .await
        .map_err(|source| RequestError::Transport { source })?;

    let deadline = Instant::now() + timeout;
    let timed_out = || RequestError::FollowTimeout {
        ticket: ticket.to_owned(),
        waited: timeout,
    };
    let mut reconcile_pause = RECONCILE_MIN;
    let mut next_reconcile = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(timed_out());
        }
        if now >= next_reconcile {
            let remaining = deadline.saturating_duration_since(now);
            let queried = tokio::time::timeout(remaining, query_terminal(base_dir, ticket))
                .await
                .map_err(|_elapsed| timed_out())??;
            if let Some(event) = queried {
                on_event(&event);
                return Ok(event);
            }
            next_reconcile = Instant::now() + reconcile_pause;
            reconcile_pause = (reconcile_pause * 2).min(RECONCILE_MAX);
        }
        let wait = deadline
            .min(next_reconcile)
            .saturating_duration_since(Instant::now());
        let Ok(received) = tokio::time::timeout(wait, sub.recv()).await else {
            // Reconcile due or deadline reached; the loop head decides.
            continue;
        };
        let message = received.map_err(|source| RequestError::Transport { source })?;
        let frames = message.into_vec();
        // PUB frames are [topic, payload]; anything shorter is noise.
        let Some(payload) = frames.get(1) else {
            continue;
        };
        let event: Event =
            serde_json::from_slice(payload).map_err(|source| RequestError::Parse { source })?;
        on_event(&event);
        if matches!(event, Event::Done | Event::Refused) {
            return Ok(event);
        }
    }
}

/// One reconcile step of [`follow_ticket`]: asks the daemon (`query`
/// capability, request/reply — reliable, unlike `PUB`) for the ticket's
/// stored state. `Some(event)` maps a terminal state to the terminal
/// event a subscriber would have seen (`done` → [`Event::Done`],
/// `refused`/`failed` → [`Event::Refused`], matching what the daemon
/// publishes); `None` means not terminal yet — or not answerable (a
/// refusal, e.g. an unknown ticket), in which case the follow keeps
/// waiting on events and times out as before rather than guessing.
async fn query_terminal(base_dir: &Path, ticket: &str) -> Result<Option<Event>, RequestError> {
    let args = serde_json::json!({ "ticket": ticket });
    let response = send_request(base_dir, "query", args, true, QUERY_DEADLINE_MS, None).await?;
    let Response::Result { body, .. } = response else {
        return Ok(None);
    };
    Ok(
        match body.get("state").and_then(serde_json::Value::as_str) {
            Some("done") => Some(Event::Done),
            Some("refused" | "failed") => Some(Event::Refused),
            _ => None,
        },
    )
}

/// What the daemon-lock probe found, for `pam daemon stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Nobody holds the instance lock.
    NotRunning,
    /// A daemon holds the lock; `pid` when the lock file was readable.
    Running {
        /// The holder's pid.
        pid: Option<u32>,
    },
}

/// Probes whether a daemon holds the instance lock under `base_dir`,
/// reporting its pid (from the lock file) when it does.
pub fn probe_daemon(base_dir: &Path) -> Result<DaemonStatus, ClientError> {
    let dirs = RuntimeDir::at_base(base_dir)?;
    let path = dirs.run_dir().join(LOCK_FILE);
    if !lock_is_held(&path)? {
        return Ok(DaemonStatus::NotRunning);
    }
    let pid = std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| contents.trim().parse().ok());
    Ok(DaemonStatus::Running { pid })
}

/// Waits (bounded) for the daemon lock under `base_dir` to be released:
/// `true` when it was released within `timeout`.
pub fn wait_for_daemon_exit(base_dir: &Path, timeout: Duration) -> Result<bool, ClientError> {
    let dirs = RuntimeDir::at_base(base_dir)?;
    let path = dirs.run_dir().join(LOCK_FILE);
    let deadline = Instant::now() + timeout;
    loop {
        if !lock_is_held(&path)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(READINESS_POLL);
    }
}
