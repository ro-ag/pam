//! Integration-test harness for the pam workspace.
//!
//! Spins up a **real daemon** ([`pam_daemon::daemon::run_daemon_with`]) on a temp runtime
//! dir with a short path (unix socket paths cap at 104 bytes on macOS), talks to it over
//! the **real framed public transport** (one connection per request; lifecycle events
//! from the private admin plane's all-events stream), and inspects the
//! **real `SQLite` store** through the daemon's own [`Store`] handle. Every await is
//! bounded by [`with_deadline`] — a generous **wall** deadline ([`TEST_DEADLINE`]) that
//! tolerates loaded runners but fails genuine hangs; classify CPU-bound work by wall
//! budget, never assert on wall *durations*, and use logical event order for ordering
//! assertions, not clocks. [`TestDaemon::assert_invariant_clean`] combines the store's
//! missing-audit sweep with a per-request exactly-one-terminal-row check over every
//! request id a [`TestClient`] of this daemon sent.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, DAEMON_VERSION, DaemonConfig, DaemonHandle, TERMINAL_ACTIONS,
    run_daemon_with,
};
use pam_daemon::event_hub::{PUBLIC_PROGRESS_NOTE, Subscribed, Subscriber};
use pam_daemon::flow_service::{SETTING_ALLOWED_PROGRAMS, SETTING_EXTRA_PATH};
use pam_daemon::framed::{self, DialError};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::runtime_dir::{MAX_SOCKET_PATH_BYTES, RuntimeDir};
use pam_daemon::secrets::SecretBackend;
use pam_proto::wire::{ErrorFrame, EventFrame, Frame, MAX_FRAME_BYTES, Via, cause};
use pam_proto::{Caller, Envelope, Event, PROTOCOL_VERSION, Response};
use pam_store::{AuditRow, RequestRow, RequestState, Store};
use tokio::sync::watch;
use tokio::task::JoinSet;

/// The scripted HTTP transport connector tests answer calls with.
pub use pam_connectors::testing::FakeTransport;
/// The in-memory credential store connector tests run on. Re-exported so a
/// test needs one dependency, not three, to drive the Connectors surface.
pub use pam_daemon::secrets::FakeSecretBackend;

/// Wall deadline for any single harness await. Generous on purpose:
/// loaded CI runners stretch wall time, and the budget only needs to
/// catch hangs, not measure speed.
pub const TEST_DEADLINE: Duration = Duration::from_secs(30);

/// Poll interval for store-observing waits.
const POLL: Duration = Duration::from_millis(25);

/// The repo every [`envelope`] runs under, so same-lane tests need no
/// coordination.
pub const TEST_REPO: &str = "/repo/test";

/// Bounds `fut` by [`TEST_DEADLINE`], panicking legibly on a hang.
///
/// The future is boxed here, once: a test body that spawns a daemon and
/// drives a client is tens of kilobytes of state machine, and every caller
/// would otherwise carry it inline in its own future (and trip
/// `clippy::large_futures` at each call site).
pub fn with_deadline<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let fut = Box::pin(fut);
    async move {
        (tokio::time::timeout(TEST_DEADLINE, fut).await).unwrap_or_else(|_| {
            panic!(
                "await exceeded the {TEST_DEADLINE:?} wall deadline — a hang, \
                 not runner load (the budget tolerates loaded runners)"
            )
        })
    }
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

/// Persists the relaxed profile on a fresh base dir, before any daemon
/// opens it.
///
/// [`pam_daemon::policy::Profile::platform_default`] is `Relaxed` only on
/// macOS and `Standard` everywhere else, and only the relaxed profile
/// auto-grants a non-destructive capability on first use. Harness daemons
/// drive `echo` without granting it, so without this seed the very same
/// test passes on macOS and refuses with `not_granted` on Linux and
/// Windows. Tests that care about a different profile seed it themselves
/// and spawn through [`TestDaemon::spawn_at`].
pub async fn seed_relaxed(tmp: &tempfile::TempDir) {
    let store = Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
}

/// Persists the programs a flow's command steps may run, before any
/// daemon opens the store.
///
/// The default allowlist is a real toolchain (`git`, `cargo`, `npm`, …),
/// which a test must not inherit: a flow test asserts about the programs
/// it named and nothing else. Seed exactly what the flow under test
/// runs.
pub async fn seed_allowed_programs(tmp: &tempfile::TempDir, programs: &[&str]) {
    seed_string_list(tmp, SETTING_ALLOWED_PROGRAMS, programs).await;
}

/// Explicit fixture approval for one real repository and named service roots.
/// This does not alter harness defaults; denial tests omit this helper.
pub async fn seed_repository_scope(
    tmp: &tempfile::TempDir,
    repo: &std::path::Path,
    connectors: &[(&str, &str)],
) {
    let root = repo.canonicalize().expect("fixture repository exists");
    let connectors: Vec<_> = connectors
        .iter()
        .map(|(connector, base_url)| {
            serde_json::json!({"connector": connector, "base_url": base_url,
            "access": "connector_wide", "targets": []})
        })
        .collect();
    open_store(tmp)
        .await
        .set_setting(
            "flows.scope_policy",
            &serde_json::json!({
                "version": 1, "repositories": [{"root": root, "connectors": connectors}]
            })
            .to_string(),
        )
        .await
        .expect("test repository scope persists");
}

/// Persists the directories a flow's command steps resolve programs on,
/// before any daemon opens the store.
///
/// Test binaries live in Cargo's target directory, which is on no
/// `PATH`, so a test that drives `pam-flow-helper` seeds the directory of
/// `env!("CARGO_BIN_EXE_pam-flow-helper")` here.
pub async fn seed_extra_path(tmp: &tempfile::TempDir, dirs: &[&str]) {
    seed_string_list(tmp, SETTING_EXTRA_PATH, dirs).await;
}

/// Writes one JSON string-list setting into a not-yet-opened store.
async fn seed_string_list(tmp: &tempfile::TempDir, key: &str, values: &[&str]) {
    let raw = serde_json::to_string(values).expect("a string list always serializes");
    open_store(tmp)
        .await
        .set_setting(key, &raw)
        .await
        .unwrap_or_else(|error| panic!("setting {key} persists: {error}"));
}

/// Writes one flow file into the library a daemon on `tmp` will read,
/// at `<base>/flows/<id>.yaml`.
///
/// Deliberately a plain file write rather than
/// `pam_flow::Library::save`: a test that wants an *invalid* flow in
/// the library (to prove the list renders its message) could not save
/// one through the validator.
#[must_use]
pub fn seed_flow(tmp: &tempfile::TempDir, id: &str, yaml: &str) -> PathBuf {
    let dir = base_of(tmp).join("flows");
    std::fs::create_dir_all(&dir).expect("the flow library directory is created");
    let path = dir.join(format!("{id}.yaml"));
    std::fs::write(&path, yaml).expect("the flow file is written");
    path
}

/// Guards the unix socket path limit before the daemon tries to bind — a
/// failure here means the temp root is too deep, not a daemon bug.
fn assert_socket_paths_fit(base: &std::path::Path) {
    // The public socket is the one path the daemon binds under the run
    // directory; it must be shorter than the limit (the terminator counts).
    let path = base.join("run").join("pam.sock");
    let len = path.as_os_str().len();
    assert!(
        len < MAX_SOCKET_PATH_BYTES,
        "socket path {} is {len} bytes; a unix socket path must be shorter than \
         {MAX_SOCKET_PATH_BYTES} bytes; use short_tempdir()",
        path.display()
    );
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
    /// [`DaemonConfig`] and the relaxed profile ([`seed_relaxed`]).
    pub async fn spawn() -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        Self::spawn_at(tmp).await
    }

    /// [`Self::spawn`] with a config mutator (approval timeout, drain
    /// timeout, …). The base dir stays harness-owned.
    pub async fn spawn_with(mutate: impl FnOnce(&mut DaemonConfig)) -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        Self::spawn_at_with(tmp, mutate).await
    }

    /// [`Self::spawn`] with the connector host wired to fakes: a
    /// keychain that lives in memory and a transport that answers from a
    /// script.
    ///
    /// The caller keeps its own `Arc` to both, which is how a test reads
    /// back what the daemon stored and what it asked the network for. No
    /// test in this workspace touches a real keychain or a real service.
    pub async fn spawn_with_connectors(
        backend: Arc<FakeSecretBackend>,
        transport: Arc<FakeTransport>,
    ) -> Self {
        Self::spawn_with(move |config| {
            config.secret_backend = Some(backend as Arc<dyn SecretBackend>);
            config.http_transport = Some(transport);
        })
        .await
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

    /// A client of the framed public transport speaking [`pam_proto`]
    /// envelopes. It holds no connection: each request dials its own.
    ///
    /// `async` only to keep the call shape every suite already uses.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "the harness API is `daemon.client().await` in every suite"
    )]
    pub async fn client(&self) -> TestClient {
        let base = self.base_dir();
        TestClient {
            dirs: RuntimeDir::paths_at_base(&base).expect("the runtime paths resolve"),
            base,
            admin: self.handle.admin(),
            ready: VecDeque::new(),
            in_flight: JoinSet::new(),
            hello_version: None,
            sent_ids: Arc::clone(&self.sent_ids),
        }
    }

    /// A stream of the lifecycle events of the tickets named by `topics`
    /// (request ids; an empty list means every ticket), in publish order.
    ///
    /// The stream is the private admin plane's all-events subscription, filtered
    /// here to the requested ids. The daemon answers `subscribed` only once
    /// the subscription is registered, so every event published after this
    /// call returns is delivered: there is nothing to settle, and subscribing
    /// before the ids exist works. A daemon admits four such streams at once;
    /// drop one before opening a fifth. Where the platform has no admin
    /// adapter the stream reads the daemon's event hub in process instead.
    ///
    /// # Panics
    ///
    /// When the daemon refuses the subscription.
    pub async fn subscribe(&self, topics: &[&str]) -> EventStream {
        let source = if pam_daemon::admin_transport::supported() {
            let events = with_deadline(pam_daemon::admin_transport::events(&self.base_dir()))
                .await
                .unwrap_or_else(|error| panic!("the all-events stream opens: {error}"));
            Source::Admin(Box::new(events))
        } else {
            Source::Hub(
                self.handle
                    .event_hub()
                    .subscribe_all()
                    .expect("an in-process subscriber attaches"),
            )
        };
        EventStream {
            source,
            topics: topics.iter().map(|topic| (*topic).to_owned()).collect(),
        }
    }

    /// Starts the daemon's drain without joining it, so a test can probe the
    /// draining daemon. [`Self::stop`] still joins it afterwards.
    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
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

/// A client of the framed public transport that sends [`pam_proto`]
/// envelopes and receives [`Response`]s, recording every sent request id for
/// the daemon's invariant sweep.
///
/// The transport carries one request per connection, so the client keeps no
/// connection: [`Self::send`] dials, says hello, writes the request and hands
/// the connection to a reader task; [`Self::recv`] returns the next reply to
/// complete, **in completion order, not send order**. Several requests can be
/// in flight at once, as on the old single socket. Dropping the client closes
/// every connection it still holds; that never cancels a request.
pub struct TestClient {
    base: PathBuf,
    dirs: RuntimeDir,
    admin: Arc<pam_daemon::admin::AdminService>,
    /// Answers that exist already: admin operations (answered inline) and
    /// hellos the daemon refused. Returned before any in-flight reply.
    ready: VecDeque<Response>,
    /// One reader per request on the public plane.
    in_flight: JoinSet<Response>,
    hello_version: Option<String>,
    sent_ids: Arc<Mutex<Vec<String>>>,
}

impl TestClient {
    /// Makes every later request claim `version` in its hello instead of the
    /// daemon's own, which is what a client of another build would say. The
    /// envelope's `client_version` decides nothing on this transport.
    pub fn claim_version(&mut self, version: &str) {
        self.hello_version = Some(version.to_owned());
    }

    /// Sends an agent envelope through public IPC or explicitly seeds trusted
    /// administration through the native channel. Unsupported platform fixtures
    /// use the in-process service, never an insecure production wire fallback.
    pub async fn send(&mut self, envelope: &Envelope) {
        if envelope.capability.starts_with("admin.") {
            self.sent_ids
                .lock()
                .expect("sent ids")
                .push(envelope.id.clone());
            let response = if pam_daemon::admin_transport::supported() {
                with_deadline(pam_daemon::admin_transport::exchange(&self.base, envelope))
                    .await
                    .expect("private admin exchange")
            } else {
                self.admin.handle(envelope).await
            };
            self.ready.push_back(response);
            return;
        }
        self.send_public(envelope).await;
    }

    /// Raw public ingress, including deliberately forged administration.
    ///
    /// Returns once the daemon has acknowledged the hello, so requests sent
    /// one after another reach the daemon in that order (whatever it then
    /// does with them concurrently). A hello the daemon refuses
    /// (`client_version_mismatch`, `daemon_outdated`, ...) comes back from
    /// [`Self::recv`] as a [`Response::Refusal`] carrying the `error` frame's
    /// cause, detail and recovery; `retryable` is set for the transient ones.
    pub async fn send_public(&mut self, envelope: &Envelope) {
        self.sent_ids
            .lock()
            .expect("sent-ids lock")
            .push(envelope.id.clone());
        let mut stream = with_deadline(framed::connect_public(&self.dirs))
            .await
            .expect("the public socket accepts a connection");
        let mut hello = framed::client_hello(Via::Direct);
        if let Some(version) = &self.hello_version {
            version.clone_into(&mut hello.version);
        }
        let request = Frame::Request {
            envelope: envelope.clone(),
        };
        match with_deadline(framed::open(&mut stream, &hello, &request)).await {
            Ok(_) => {}
            Err(DialError::Refused(error)) => {
                self.ready.push_back(refusal_of(&envelope.id, &error));
                return;
            }
            Err(error) => panic!("the hello for {} failed: {error}", envelope.id),
        }
        let id = envelope.id.clone();
        self.in_flight.spawn(async move {
            match framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await {
                Ok(Frame::Reply { response }) => response,
                Ok(other) => panic!("{id}: expected a reply, got {}", other.type_name()),
                Err(DialError::Refused(error)) => refusal_of(&id, &error),
                Err(error) => panic!("{id}: no reply: {error}"),
            }
        });
    }

    /// Receives the next response to complete: an answer that already
    /// exists, else the first reply to arrive on any connection in flight.
    ///
    /// # Panics
    ///
    /// When nothing is in flight (there is nothing to wait for), when the
    /// wall deadline passes, or when a connection ends without a reply, which
    /// the daemon never does for a request it accepted.
    pub async fn recv(&mut self) -> Response {
        if let Some(response) = self.ready.pop_front() {
            return response;
        }
        let joined = with_deadline(self.in_flight.join_next())
            .await
            .expect("recv with no request in flight");
        match joined {
            Ok(response) => response,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => panic!("a reply reader ended: {error}"),
        }
    }

    /// Sends `envelope` and awaits its response.
    pub async fn request(&mut self, envelope: &Envelope) -> Response {
        self.send(envelope).await;
        self.recv().await
    }
}

/// A hello the daemon refused, as the [`Response::Refusal`] a caller of the
/// old envelope protocol would have seen.
fn refusal_of(id: &str, error: &ErrorFrame) -> Response {
    let transient = [
        cause::DAEMON_OUTDATED,
        cause::DAEMON_SHUTTING_DOWN,
        cause::CONNECTION_CAPACITY_EXHAUSTED,
    ]
    .contains(&error.cause.as_str());
    if transient {
        Response::transient_refusal(id, &error.cause, &error.detail, &error.recovery)
    } else {
        Response::refusal(id, &error.cause, &error.detail, &error.recovery)
    }
}

/// Where an [`EventStream`] reads from.
enum Source {
    /// The private admin plane's all-events stream.
    Admin(Box<pam_daemon::admin_transport::AdminEvents>),
    /// The daemon's own hub, where the platform has no admin adapter.
    Hub(Subscriber),
}

/// `(request id, event)` pairs of the requested tickets in publish order,
/// read from the admin all-events stream. The hub publishes every event
/// through one queue per subscriber, so arrival order **is** publish order
/// across tickets: assert on it instead of on wall clocks.
///
/// [`Self::recv`] and the collectors give the **public** view of an event
/// (a progress note is the constant [`PUBLIC_PROGRESS_NOTE`], what a public
/// follower is shown); [`Self::recv_admin`] gives the whole frame with the
/// real note and the ticket's metadata. Control requests (`status`, `query`,
/// `cancel`) publish no events, so a stream is silent for them.
pub struct EventStream {
    source: Source,
    /// Request ids to deliver; empty delivers every ticket.
    topics: HashSet<String>,
}

impl EventStream {
    /// The next event of a requested ticket, as the admin plane carries it.
    async fn next_frame(&mut self) -> EventFrame {
        loop {
            let frame = match &mut self.source {
                Source::Admin(events) => events
                    .next()
                    .await
                    .unwrap_or_else(|error| panic!("the all-events stream ended: {error}")),
                Source::Hub(subscriber) => match subscriber.next().await {
                    Subscribed::Event(event) => match event.into_frame() {
                        Frame::Event(frame) => frame,
                        other => unreachable!("a hub event is an event frame, not {other:?}"),
                    },
                    Subscribed::Lagged => panic!("the in-process subscriber lagged"),
                    Subscribed::Closed => panic!("the event hub closed"),
                },
            };
            let wanted = frame
                .ticket
                .as_ref()
                .is_some_and(|ticket| self.topics.is_empty() || self.topics.contains(ticket));
            if wanted {
                return frame;
            }
        }
    }

    /// Receives the next event as `(request id, event)`, in its public view.
    pub async fn recv(&mut self) -> (String, Event) {
        let frame = with_deadline(self.next_frame()).await;
        (
            frame.ticket.expect("a filtered frame names its ticket"),
            public_view(frame.event),
        )
    }

    /// Like [`Self::recv`] but `None` when no event of a requested ticket
    /// arrives within `quiet`: how a test shows a ticket stayed silent.
    pub async fn recv_within(&mut self, quiet: Duration) -> Option<(String, Event)> {
        let frame = tokio::time::timeout(quiet, self.next_frame()).await.ok()?;
        Some((
            frame.ticket.expect("a filtered frame names its ticket"),
            public_view(frame.event),
        ))
    }

    /// Receives the next event whole: ticket, the admission metadata
    /// (capability, repository, agent label, ingress), the daemon-wide counter
    /// `n` and the real, unsanitised event.
    pub async fn recv_admin(&mut self) -> EventFrame {
        with_deadline(self.next_frame()).await
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

/// What a public follower is shown of `event`: progress without its prose.
fn public_view(event: Event) -> Event {
    match event {
        Event::Progress { pct, note: _ } => Event::Progress {
            pct,
            note: PUBLIC_PROGRESS_NOTE.to_owned(),
        },
        other => other,
    }
}
