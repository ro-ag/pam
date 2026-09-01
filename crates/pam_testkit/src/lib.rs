//! Integration-test harness for the pam workspace.
//!
//! Spins up a **real daemon** ([`pam_daemon::daemon::run_daemon_with`])
//! on a temp runtime dir with a short path (unix socket paths are capped
//! at 104 bytes on macOS), talks to it over **real zmq** (`DEALER` for
//! requests, `SUB` for lifecycle events), and inspects the **real
//! `SQLite` store** through the daemon's own [`Store`] handle.
//!
//! # Deadline discipline
//!
//! Every await in the harness is bounded by [`with_deadline`] — a
//! generous **wall** deadline ([`TEST_DEADLINE`]) that tolerates loaded
//! runners but fails genuine hangs (the v1 testkit lesson: classify
//! CPU-bound work by wall budget, never assert on wall *durations*).
//! Ordering assertions should use logical event order, not clocks.
//!
//! # Audit invariant
//!
//! [`TestDaemon::assert_invariant_clean`] combines the store's
//! missing-audit sweep with a per-request exactly-one-terminal-row
//! check over every request id a [`TestClient`] of this daemon sent.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, DAEMON_VERSION, DaemonConfig, DaemonHandle, TERMINAL_ACTIONS,
    run_daemon_with,
};
use pam_daemon::runtime_dir::MAX_SOCKET_PATH_BYTES;
use pam_proto::{Caller, Envelope, Event, PROTOCOL_VERSION, Response};
use pam_store::{AuditRow, RequestRow, RequestState, Store};
use tokio::sync::watch;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

/// Wall deadline for any single harness await. Generous on purpose:
/// loaded CI runners stretch wall time, and the budget only needs to
/// catch hangs, not measure speed.
pub const TEST_DEADLINE: Duration = Duration::from_secs(30);

/// Poll interval for store-observing waits.
const POLL: Duration = Duration::from_millis(25);

/// Settle time for a fresh `SUB` subscription before events matter
/// (zmq `PUB` drops messages published before the subscription
/// registers with the publisher).
const SUB_SETTLE: Duration = Duration::from_millis(300);

/// The repo every [`envelope`] runs under, so same-lane tests need no
/// coordination.
pub const TEST_REPO: &str = "/repo/test";

/// Bounds `fut` by [`TEST_DEADLINE`], panicking legibly on a hang.
pub async fn with_deadline<F: Future>(fut: F) -> F::Output {
    (tokio::time::timeout(TEST_DEADLINE, fut).await).unwrap_or_else(|_| {
        panic!(
            "await exceeded the {TEST_DEADLINE:?} wall deadline — a hang, \
             not runner load (the budget tolerates loaded runners)"
        )
    })
}

/// Temp dir with a short absolute path: macOS caps unix socket paths at
/// 104 bytes and the default temp root can get close.
#[must_use]
pub fn short_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("tempdir")
    }
}

/// The daemon base directory inside a test's temp dir.
#[must_use]
pub fn base_of(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join("pam")
}

/// Opens the store file a daemon on `tmp` uses — for pre-seeding
/// profiles/grants before [`TestDaemon::spawn_at`], or for inspecting
/// state between two daemon lifetimes on the same base dir.
pub async fn open_store(tmp: &tempfile::TempDir) -> Store {
    Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens")
}

/// Guards the 104-byte unix socket path limit before the daemon tries
/// to bind — a failure here means the temp root is too deep, not a
/// daemon bug.
fn assert_socket_paths_fit(base: &std::path::Path) {
    for socket in ["pam.sock", "events.sock"] {
        let path = base.join("run").join(socket);
        let len = path.as_os_str().len();
        assert!(
            len <= MAX_SOCKET_PATH_BYTES,
            "socket path {} is {len} bytes, over the {MAX_SOCKET_PATH_BYTES}-byte \
             unix limit; use short_tempdir()",
            path.display()
        );
    }
}

/// A deterministic request envelope: fixed caller identity (no
/// environment-dependent caller detection), repo [`TEST_REPO`], the
/// daemon's own build version, and a 10 s request deadline.
#[must_use]
pub fn envelope(id: &str, capability: &str, args: serde_json::Value, wait: bool) -> Envelope {
    envelope_for_repo(TEST_REPO, id, capability, args, wait)
}

/// [`envelope`] with an explicit repo, for cross-lane tests.
#[must_use]
pub fn envelope_for_repo(
    repo: &str,
    id: &str,
    capability: &str,
    args: serde_json::Value,
    wait: bool,
) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: capability.to_owned(),
        client_version: DAEMON_VERSION.to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: repo.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 10_000,
        wait,
    }
}

/// A running daemon on its own temp base dir, plus the bookkeeping the
/// assertion helpers need.
pub struct TestDaemon {
    tmp: tempfile::TempDir,
    handle: DaemonHandle,
    shutdown: watch::Sender<bool>,
    /// Every request id sent through a [`TestClient`] of this daemon —
    /// the population [`Self::assert_invariant_clean`] sweeps.
    sent_ids: Arc<Mutex<Vec<String>>>,
}

impl TestDaemon {
    /// Spawns a daemon on a fresh short-path temp dir with the default
    /// [`DaemonConfig`].
    pub async fn spawn() -> Self {
        Self::spawn_at(short_tempdir()).await
    }

    /// [`Self::spawn`] with a config mutator (approval timeout, drain
    /// timeout, …). The base dir stays harness-owned.
    pub async fn spawn_with(mutate: impl FnOnce(&mut DaemonConfig)) -> Self {
        Self::spawn_at_with(short_tempdir(), mutate).await
    }

    /// Spawns on an existing temp dir — for restart tests reusing the
    /// base dir a previous [`Self::stop`] returned, or a dir whose
    /// store was pre-seeded through [`open_store`].
    pub async fn spawn_at(tmp: tempfile::TempDir) -> Self {
        Self::spawn_at_with(tmp, |_| {}).await
    }

    /// [`Self::spawn_at`] with a config mutator.
    pub async fn spawn_at_with(
        tmp: tempfile::TempDir,
        mutate: impl FnOnce(&mut DaemonConfig),
    ) -> Self {
        let base = base_of(&tmp);
        assert_socket_paths_fit(&base);
        let mut config = DaemonConfig {
            base_dir: Some(base),
            ..DaemonConfig::default()
        };
        mutate(&mut config);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = with_deadline(run_daemon_with(config, shutdown_rx))
            .await
            .expect("daemon starts");
        Self {
            tmp,
            handle,
            shutdown,
            sent_ids: Arc::default(),
        }
    }

    /// The daemon's base directory (runtime dir and store live under it).
    #[must_use]
    pub fn base_dir(&self) -> PathBuf {
        base_of(&self.tmp)
    }

    /// The daemon handle, for surfaces the harness does not wrap
    /// (approvals, lifecycle phase, runtime dir).
    #[must_use]
    pub fn handle(&self) -> &DaemonHandle {
        &self.handle
    }

    /// The daemon's own store handle.
    #[must_use]
    pub fn store(&self) -> Arc<Store> {
        self.handle.store()
    }

    /// A connected `DEALER` client speaking [`pam_proto`] envelopes.
    pub async fn client(&self) -> TestClient {
        let mut dealer = DealerSocket::new();
        with_deadline(dealer.connect(&self.handle.runtime_dir().router_endpoint()))
            .await
            .expect("dealer connects");
        TestClient {
            dealer,
            sent_ids: Arc::clone(&self.sent_ids),
        }
    }

    /// A `SUB` socket subscribed to each topic (request id), settled
    /// past the slow-joiner window. Subscribe **before** sending the
    /// requests whose events matter.
    pub async fn subscribe(&self, topics: &[&str]) -> EventStream {
        let mut sub = SubSocket::new();
        with_deadline(sub.connect(&self.handle.runtime_dir().events_endpoint()))
            .await
            .expect("sub connects");
        for topic in topics {
            with_deadline(sub.subscribe(topic))
                .await
                .expect("subscribe");
        }
        tokio::time::sleep(SUB_SETTLE).await;
        EventStream { sub }
    }

    /// Graceful shutdown; returns the temp dir so a follow-up daemon can
    /// relaunch on the same base (restart-persistence tests).
    pub async fn stop(self) -> tempfile::TempDir {
        let _ = self.shutdown.send(true);
        with_deadline(self.handle.shutdown()).await;
        self.tmp
    }

    /// Joins the daemon **without** signalling shutdown — for tests
    /// where the daemon initiated its own drain (version handshake).
    pub async fn join(self) -> tempfile::TempDir {
        with_deadline(self.handle.shutdown()).await;
        self.tmp
    }

    /// Polls the store (bounded by [`TEST_DEADLINE`]) until the request
    /// row satisfies `pred`.
    pub async fn wait_for_row(&self, id: &str, pred: impl Fn(&RequestRow) -> bool) -> RequestRow {
        let store = self.store();
        with_deadline(async move {
            loop {
                if let Some(row) = store.get_request(id).await.expect("get_request ok")
                    && pred(&row)
                {
                    return row;
                }
                tokio::time::sleep(POLL).await;
            }
        })
        .await
    }

    /// Asserts the request row exists and is in `state` right now (no
    /// polling — use [`Self::wait_for_row`] to await a transition).
    pub async fn assert_row_state(&self, id: &str, state: RequestState) {
        let row = self
            .store()
            .get_request(id)
            .await
            .expect("get_request ok")
            .unwrap_or_else(|| panic!("request {id} has no row"));
        assert_eq!(row.state, state, "request {id} state");
    }

    /// All audit rows of `id`, in write order.
    pub async fn audit_rows(&self, id: &str) -> Vec<AuditRow> {
        self.store()
            .audit_for_request(id)
            .await
            .expect("audit query ok")
    }

    /// The request's audit actions that record terminal states
    /// ([`TERMINAL_ACTIONS`]), in write order.
    pub async fn terminal_audit_actions(&self, id: &str) -> Vec<String> {
        self.audit_rows(id)
            .await
            .into_iter()
            .filter(|row| TERMINAL_ACTIONS.contains(&row.action.as_str()))
            .map(|row| row.action)
            .collect()
    }

    /// Asserts `id` carries exactly one terminal audit row.
    ///
    /// The laned deadline path is the documented exception: the
    /// [`ACTION_DEADLINE_REFUSAL`] row records the refusal sent to the
    /// caller *in addition to* the terminal cancellation row, so at
    /// most one such companion row is tolerated alongside (or, on the
    /// bypass deadline path, *as*) the terminal row.
    pub async fn assert_single_terminal_audit(&self, id: &str) {
        let actions = self.terminal_audit_actions(id).await;
        assert!(
            !actions.is_empty(),
            "terminal request {id} has no terminal audit row"
        );
        let primary: Vec<&String> = actions
            .iter()
            .filter(|action| *action != ACTION_DEADLINE_REFUSAL)
            .collect();
        assert!(
            primary.len() <= 1,
            "request {id} has {} terminal audit rows, expected one: {actions:?}",
            primary.len()
        );
        let deadline_rows = actions.len() - primary.len();
        assert!(
            deadline_rows <= 1,
            "request {id} has {deadline_rows} deadline-refusal rows: {actions:?}"
        );
    }

    /// Asserts the audit invariant holds store-wide: no terminal
    /// request is missing its audit row
    /// ([`Store::terminal_requests_missing_audit`]), and every request
    /// a [`TestClient`] of this daemon sent that reached a terminal
    /// state carries exactly one terminal audit row
    /// ([`Self::assert_single_terminal_audit`]). Requests without a row
    /// (attached duplicates, handshake refusals) are skipped.
    pub async fn assert_invariant_clean(&self) {
        let store = self.store();
        let missing = store
            .terminal_requests_missing_audit(TERMINAL_ACTIONS)
            .await
            .expect("invariant query ok");
        assert!(
            missing.is_empty(),
            "terminal requests without a terminal audit row: {missing:?}"
        );
        let ids = self.sent_ids.lock().expect("sent-ids lock").clone();
        for id in ids {
            let Some(row) = store.get_request(&id).await.expect("get_request ok") else {
                continue;
            };
            if row.state.is_terminal() {
                self.assert_single_terminal_audit(&id).await;
            }
        }
    }
}

/// A `DEALER` client that sends [`pam_proto`] envelopes and receives
/// [`Response`]s, recording every sent request id for the daemon's
/// invariant sweep.
pub struct TestClient {
    dealer: DealerSocket,
    sent_ids: Arc<Mutex<Vec<String>>>,
}

impl TestClient {
    /// Sends one envelope.
    pub async fn send(&mut self, envelope: &Envelope) {
        self.sent_ids
            .lock()
            .expect("sent-ids lock")
            .push(envelope.id.clone());
        let payload = serde_json::to_vec(envelope).expect("serialize envelope");
        with_deadline(self.dealer.send(ZmqMessage::from(payload)))
            .await
            .expect("send ok");
    }

    /// Receives one response.
    pub async fn recv(&mut self) -> Response {
        let answer = with_deadline(self.dealer.recv()).await.expect("recv ok");
        let frames = answer.into_vec();
        serde_json::from_slice(&frames[0]).expect("parse response")
    }

    /// Sends `envelope` and awaits its response.
    pub async fn request(&mut self, envelope: &Envelope) -> Response {
        self.send(envelope).await;
        self.recv().await
    }
}

/// A `SUB` stream of `(request id, event)` pairs in publish order. The
/// daemon publishes every event through one loop over one connection,
/// so arrival order **is** publish order — assert on it instead of on
/// wall clocks.
pub struct EventStream {
    sub: SubSocket,
}

impl EventStream {
    /// Receives the next event as `(request id, event)`.
    pub async fn recv(&mut self) -> (String, Event) {
        let message = with_deadline(self.sub.recv()).await.expect("event recv ok");
        let frames = message.into_vec();
        let topic = String::from_utf8(frames[0].to_vec()).expect("utf-8 topic");
        let event = serde_json::from_slice(&frames[1]).expect("parse event");
        (topic, event)
    }

    /// Collects events (all subscribed topics, publish order) until
    /// `count` terminal events ([`Event::Done`] / [`Event::Refused`])
    /// have been observed.
    pub async fn collect_until_terminals(&mut self, count: usize) -> Vec<(String, Event)> {
        let mut events = Vec::new();
        let mut terminals = 0;
        while terminals < count {
            let (topic, event) = self.recv().await;
            if matches!(event, Event::Done | Event::Refused) {
                terminals += 1;
            }
            events.push((topic, event));
        }
        events
    }

    /// Collects `id`'s events until its terminal one, discarding other
    /// topics.
    pub async fn until_terminal(&mut self, id: &str) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let (topic, event) = self.recv().await;
            if topic != id {
                continue;
            }
            let terminal = matches!(event, Event::Done | Event::Refused);
            events.push(event);
            if terminal {
                return events;
            }
        }
    }
}
