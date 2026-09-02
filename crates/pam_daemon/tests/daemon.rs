//! End-to-end tests: a real daemon ([`run_daemon`]) on a temp base dir,
//! real zmq DEALER/SUB clients, real `SQLite` store — asserting replies,
//! request rows, audit rows, and PUB events.

use std::path::PathBuf;
use std::time::Duration;

use pam_daemon::approval::{ACTION_APPROVAL, Resolution};
use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, ACTION_EXECUTE, ACTION_GATE_REFUSAL, CAUSE_APPROVAL_DENIED,
    CAUSE_APPROVAL_TIMEOUT, CAUSE_DAEMON_OUTDATED, CAUSE_DAEMON_SHUTTING_DOWN,
    CAUSE_DEADLINE_EXCEEDED, DaemonConfig, DaemonError, DaemonHandle, run_daemon, run_daemon_with,
};
use pam_daemon::lifecycle::{
    ACTION_DAEMON_RESTART, CAUSE_DAEMON_RESTART, LifecycleError, LifecyclePhase,
};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::queue::{ACTION_CANCEL, CAUSE_CANCELLED};
use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Actor, ApprovalResolution, Decision, RequestRow, RequestState, Store};
use tokio::sync::watch;
use tokio::time::timeout;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

const DEADLINE: Duration = Duration::from_secs(20);

/// Settle time for a fresh SUB subscription before events matter
/// (zmq PUB drops messages published before the subscription registers).
const SUB_SETTLE: Duration = Duration::from_millis(300);

const REPO: &str = "/repo/test";

/// Temp dir with a short absolute path: macOS caps unix socket paths at
/// 104 bytes and the default temp root can get close.
fn short_tempdir() -> tempfile::TempDir {
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

struct TestDaemon {
    tmp: tempfile::TempDir,
    handle: DaemonHandle,
    shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    async fn start() -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        Self::start_at(tmp).await
    }

    /// Starts the daemon on `tmp`'s `pam` subdirectory (which a test may
    /// have pre-seeded through [`base_of`]).
    async fn start_at(tmp: tempfile::TempDir) -> Self {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = run_daemon(Some(base_of(&tmp)), shutdown_rx)
            .await
            .expect("daemon starts");
        Self {
            tmp,
            handle,
            shutdown,
        }
    }

    /// [`Self::start_at`] with a custom approval timeout.
    async fn start_at_with_approval_timeout(tmp: tempfile::TempDir, timeout: Duration) -> Self {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let config = DaemonConfig {
            base_dir: Some(base_of(&tmp)),
            approval_timeout: timeout,
            ..DaemonConfig::default()
        };
        let handle = run_daemon_with(config, shutdown_rx)
            .await
            .expect("daemon starts");
        Self {
            tmp,
            handle,
            shutdown,
        }
    }

    async fn dealer(&self) -> DealerSocket {
        let mut dealer = DealerSocket::new();
        dealer
            .connect(&self.handle.runtime_dir().router_endpoint())
            .await
            .expect("dealer connects");
        dealer
    }

    /// A SUB socket subscribed to `topic`, settled past the slow-joiner
    /// window.
    async fn subscriber(&self, topic: &str) -> SubSocket {
        let mut sub = SubSocket::new();
        sub.connect(&self.handle.runtime_dir().events_endpoint())
            .await
            .expect("sub connects");
        sub.subscribe(topic).await.expect("subscribe");
        tokio::time::sleep(SUB_SETTLE).await;
        sub
    }

    async fn stop(self) -> tempfile::TempDir {
        let _ = self.shutdown.send(true);
        self.handle.shutdown().await;
        self.tmp
    }

    /// Joins the daemon **without** signalling shutdown — for tests
    /// where the daemon initiated its own drain (version handshake).
    async fn join(self) -> tempfile::TempDir {
        self.handle.shutdown().await;
        self.tmp
    }
}

/// The daemon base directory inside a test's temp dir.
fn base_of(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join("pam")
}

fn envelope(id: &str, capability: &str, args: serde_json::Value, wait: bool) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: capability.to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: REPO.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 10_000,
        wait,
    }
}

async fn send(dealer: &mut DealerSocket, envelope: &Envelope) {
    let payload = serde_json::to_vec(envelope).expect("serialize envelope");
    dealer
        .send(ZmqMessage::from(payload))
        .await
        .expect("send ok");
}

async fn recv_response(dealer: &mut DealerSocket) -> Response {
    let answer = dealer.recv().await.expect("recv ok");
    let frames = answer.into_vec();
    serde_json::from_slice(&frames[0]).expect("parse response")
}

/// Receives one event off the subscription.
async fn recv_event(sub: &mut SubSocket) -> Event {
    let message = sub.recv().await.expect("event recv ok");
    let frames = message.into_vec();
    serde_json::from_slice(&frames[1]).expect("parse event")
}

/// Persists the relaxed profile before the daemon (and thus the gate)
/// opens the store.
///
/// [`pam_daemon::policy::Profile::platform_default`] is `Relaxed` only on
/// macOS and `Standard` everywhere else, and only the relaxed profile
/// auto-grants a non-destructive capability on first use. The tests that
/// drive `echo` without granting it would otherwise pass on macOS and
/// refuse with `not_granted` on Linux and Windows. Tests that want a
/// different profile seed it themselves and use [`TestDaemon::start_at`].
async fn seed_relaxed(tmp: &tempfile::TempDir) {
    let store = Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
}

/// Seeds `tmp`'s store with the strict profile and an active `echo`
/// grant, so every echo request hits the per-operation approval pause.
async fn seed_strict_with_echo_grant(tmp: &tempfile::TempDir) {
    let store = Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"strict\"")
        .await
        .expect("profile set");
    store.insert_grant("echo").await.expect("grant inserted");
}

/// Collects this topic's events until a terminal one (`done`/`refused`).
async fn events_until_terminal(sub: &mut SubSocket) -> Vec<Event> {
    let mut events = Vec::new();
    loop {
        let message = sub.recv().await.expect("event recv ok");
        let frames = message.into_vec();
        let event: Event = serde_json::from_slice(&frames[1]).expect("parse event");
        let terminal = matches!(event, Event::Done | Event::Refused);
        events.push(event);
        if terminal {
            return events;
        }
    }
}

/// Polls the store until the request row satisfies `pred`.
async fn wait_for_row(store: &Store, id: &str, pred: impl Fn(&RequestRow) -> bool) -> RequestRow {
    loop {
        if let Some(row) = store.get_request(id).await.expect("get_request ok")
            && pred(&row)
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn echo_runs_end_to_end_through_lane_audit_and_events() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut sub = daemon.subscriber("req_echo").await;
        let mut dealer = daemon.dealer().await;

        let args = serde_json::json!({ "msg": "hi", "delay_ms": 150 });
        send(
            &mut dealer,
            &envelope("req_echo", "echo", args.clone(), true),
        )
        .await;

        // The reply is the capability's result.
        let response = recv_response(&mut dealer).await;
        let Response::Result {
            id,
            outcome,
            body,
            evidence,
        } = response
        else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(id, "req_echo");
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body, serde_json::json!({ "echo": args }));
        assert!(evidence.is_empty());

        // The row is terminal `done` with the outcome recorded.
        let store = daemon.handle.store();
        let row = store.get_request("req_echo").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("solved"));

        // The execution wrote its audit row (the relaxed profile's
        // first-use auto-grant wrote one of its own before it).
        let audit = store.audit_for_request("req_echo").await.unwrap();
        let execute: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_EXECUTE)
            .collect();
        assert_eq!(execute.len(), 1);
        assert_eq!(execute[0].decision, Decision::Allow);
        assert_eq!(execute[0].actor, Actor::System);
        assert!(audit.iter().any(|row| row.action == "auto_grant"));

        // Lifecycle on PUB: queued (laned capability), started, done.
        let events = events_until_terminal(&mut sub).await;
        assert_eq!(events, [Event::Queued, Event::Started, Event::Done]);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn status_bypasses_the_lanes_and_verifies() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut sub = daemon.subscriber("req_status").await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_status", "status", serde_json::json!({}), true),
        )
        .await;

        let response = recv_response(&mut dealer).await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Verified);
        assert_eq!(body["protocol"], PROTOCOL_VERSION);
        assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert!(body["active_requests"].as_i64().unwrap() >= 1);

        let store = daemon.handle.store();
        let row = store.get_request("req_status").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("verified"));

        // Bypass: started and done, but never queued.
        let events = events_until_terminal(&mut sub).await;
        assert_eq!(events, [Event::Started, Event::Done]);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn unknown_capability_is_refused_and_audited() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_bad", "frobnicate", serde_json::json!({}), true),
        )
        .await;

        let response = recv_response(&mut dealer).await;
        let Response::Refusal {
            id,
            cause,
            recovery,
            ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(id, "req_bad");
        assert_eq!(cause, "unknown_capability");
        assert!(recovery.contains("GUI"), "recovery: {recovery}");

        let store = daemon.handle.store();
        let row = store.get_request("req_bad").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(row.outcome.as_deref(), Some("unknown_capability"));

        let audit = store.audit_for_request("req_bad").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_GATE_REFUSAL);
        assert_eq!(audit[0].decision, Decision::Refuse);
        assert_eq!(audit[0].actor, Actor::Policy);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn standard_profile_refuses_an_ungranted_capability() {
    timeout(DEADLINE, async {
        // Persist the standard profile before the daemon (and thus the
        // gate) starts; run_daemon reads the setting at construction.
        let tmp = short_tempdir();
        {
            let store = Store::open(&base_of(&tmp).join("state.sqlite3"))
                .await
                .expect("store opens");
            store
                .set_setting(PROFILE_SETTING_KEY, "\"standard\"")
                .await
                .expect("profile set");
        }
        let daemon = TestDaemon::start_at(tmp).await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_echo", "echo", serde_json::json!({ "msg": "hi" }), true),
        )
        .await;

        let response = recv_response(&mut dealer).await;
        let Response::Refusal {
            cause, recovery, ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "not_granted");
        assert!(recovery.contains("GUI"), "recovery: {recovery}");

        let store = daemon.handle.store();
        let row = store.get_request("req_echo").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        let audit = store.audit_for_request("req_echo").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_GATE_REFUSAL);
        assert_eq!(audit[0].decision, Decision::Refuse);
        assert_eq!(audit[0].actor, Actor::Policy);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn wait_false_returns_a_ticket_and_completes_in_the_background() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut sub = daemon.subscriber("req_bg").await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope(
                "req_bg",
                "echo",
                serde_json::json!({ "delay_ms": 150 }),
                false,
            ),
        )
        .await;

        let response = recv_response(&mut dealer).await;
        let Response::Ticket {
            id,
            ticket,
            position,
        } = response
        else {
            panic!("expected a ticket, got {response:?}");
        };
        assert_eq!(id, "req_bg");
        assert_eq!(ticket, "req_bg");
        assert_eq!(position, 0);

        // The request still runs to completion.
        let store = daemon.handle.store();
        let row = wait_for_row(&store, "req_bg", |row| row.state == RequestState::Done).await;
        assert_eq!(row.outcome.as_deref(), Some("solved"));
        let events = events_until_terminal(&mut sub).await;
        assert_eq!(events.last(), Some(&Event::Done));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn duplicate_in_flight_request_attaches_and_shares_the_result() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut first = daemon.dealer().await;
        let mut second = daemon.dealer().await;

        let args = serde_json::json!({ "delay_ms": 700, "tag": "dup" });
        send(
            &mut first,
            &envelope("req_dup1", "echo", args.clone(), true),
        )
        .await;
        // Let the first request get admitted before the duplicate lands.
        tokio::time::sleep(Duration::from_millis(200)).await;
        send(&mut second, &envelope("req_dup2", "echo", args, true)).await;

        let first_response = recv_response(&mut first).await;
        let second_response = recv_response(&mut second).await;

        // Attach semantics: one execution, both callers get its result.
        assert_eq!(first_response, second_response);
        let Response::Result { id, .. } = second_response else {
            panic!("expected a result, got {second_response:?}");
        };
        assert_eq!(id, "req_dup1", "the attached caller shares the original");

        // The duplicate never got a row of its own.
        let store = daemon.handle.store();
        assert!(store.get_request("req_dup2").await.unwrap().is_none());

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_builtin_stops_a_running_request() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut sub = daemon.subscriber("req_victim").await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope(
                "req_victim",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ),
        )
        .await;
        let ticket_reply = recv_response(&mut dealer).await;
        assert!(matches!(ticket_reply, Response::Ticket { .. }));

        // Wait for the executor to lease it.
        let store = daemon.handle.store();
        wait_for_row(&store, "req_victim", |row| {
            row.state == RequestState::Running
        })
        .await;

        let mut canceller = daemon.dealer().await;
        send(
            &mut canceller,
            &envelope(
                "req_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_victim" }),
                true,
            ),
        )
        .await;
        let response = recv_response(&mut canceller).await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body["result"], "signalled_running");

        // The victim reaches its terminal state through its executor.
        let row = wait_for_row(&store, "req_victim", |row| {
            row.state == RequestState::Failed
        })
        .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        let audit = store.audit_for_request("req_victim").await.unwrap();
        let cancel: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_CANCEL)
            .collect();
        assert_eq!(cancel.len(), 1);
        assert_eq!(cancel[0].decision, Decision::Deny);
        assert_eq!(cancel[0].actor, Actor::System);

        let events = events_until_terminal(&mut sub).await;
        assert_eq!(events.last(), Some(&Event::Refused));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn approval_approve_resumes_execution_and_audits_the_resolution() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::start_at(tmp).await;
        let mut sub = daemon.subscriber("req_appr").await;
        let mut dealer = daemon.dealer().await;

        let args = serde_json::json!({ "msg": "hi" });
        send(
            &mut dealer,
            &envelope("req_appr", "echo", args.clone(), true),
        )
        .await;

        // The request parks: approval_pending on PUB, waiting_approval
        // in the store, and one entry on the GUI's pending list.
        assert_eq!(recv_event(&mut sub).await, Event::ApprovalPending);
        let store = daemon.handle.store();
        let row = store.get_request("req_appr").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::WaitingApproval);
        let pending = daemon.handle.approvals().pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req_appr");
        assert_eq!(pending[0].capability, "echo");
        assert_eq!(pending[0].repo, REPO);

        // The human approves; the pipeline resumes into execution.
        daemon
            .handle
            .approvals()
            .resolve("req_appr", Resolution::Approve { remember: false })
            .await
            .expect("resolvable");

        let response = recv_response(&mut dealer).await;
        let Response::Result {
            id, outcome, body, ..
        } = response
        else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(id, "req_appr");
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body, serde_json::json!({ "echo": args }));

        // Terminal row, resolved approval row, and both audit rows.
        let row = store.get_request("req_appr").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        let approval = store
            .approval_for_request("req_appr")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Approved));
        let audit = store.audit_for_request("req_appr").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_APPROVAL
            && row.decision == Decision::Approve
            && row.actor == Actor::Human));
        assert!(
            audit
                .iter()
                .any(|row| row.action == ACTION_EXECUTE && row.decision == Decision::Allow)
        );
        assert!(
            daemon
                .handle
                .approvals()
                .pending()
                .await
                .unwrap()
                .is_empty()
        );

        // The rest of the lifecycle follows the approval.
        let events = events_until_terminal(&mut sub).await;
        assert_eq!(events, [Event::Queued, Event::Started, Event::Done]);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn approval_deny_refuses_with_approval_denied() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::start_at(tmp).await;
        let mut sub = daemon.subscriber("req_deny").await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_deny", "echo", serde_json::json!({ "msg": "no" }), true),
        )
        .await;
        assert_eq!(recv_event(&mut sub).await, Event::ApprovalPending);

        daemon
            .handle
            .approvals()
            .resolve("req_deny", Resolution::Deny)
            .await
            .expect("resolvable");

        let response = recv_response(&mut dealer).await;
        let Response::Refusal {
            cause, recovery, ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_DENIED);
        assert!(recovery.contains("GUI"), "recovery: {recovery}");

        let store = daemon.handle.store();
        let row = store.get_request("req_deny").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_APPROVAL_DENIED));
        let approval = store
            .approval_for_request("req_deny")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Denied));
        let audit = store.audit_for_request("req_deny").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_APPROVAL
            && row.decision == Decision::Deny
            && row.actor == Actor::Human));
        assert!(
            audit
                .iter()
                .any(|row| row.action == ACTION_GATE_REFUSAL && row.decision == Decision::Refuse)
        );

        assert_eq!(recv_event(&mut sub).await, Event::Refused);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn unanswered_approval_times_out_into_a_refusal() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon =
            TestDaemon::start_at_with_approval_timeout(tmp, Duration::from_millis(300)).await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_slow", "echo", serde_json::json!({ "msg": "??" }), true),
        )
        .await;

        // Nobody answers within the daemon's (short) approval timeout.
        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_TIMEOUT);

        let store = daemon.handle.store();
        let row = store.get_request("req_slow").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_APPROVAL_TIMEOUT));
        let approval = store
            .approval_for_request("req_slow")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Timeout));
        let audit = store.audit_for_request("req_slow").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_APPROVAL
            && row.decision == Decision::Timeout
            && row.actor == Actor::System));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn elapsed_deadline_refuses_the_waiting_caller_and_ends_the_request() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        let mut request = envelope(
            "req_late",
            "echo",
            serde_json::json!({ "delay_ms": 3000 }),
            true,
        );
        request.deadline_ms = 200;
        send(&mut dealer, &request).await;

        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_DEADLINE_EXCEEDED);

        // The request itself is torn down (cancelled through the queue)
        // and both the deadline refusal and the teardown are audited.
        let store = daemon.handle.store();
        let row = wait_for_row(&store, "req_late", |row| row.state == RequestState::Failed).await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        let audit = store.audit_for_request("req_late").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_DEADLINE_REFUSAL
            && row.decision == Decision::Timeout
            && row.actor == Actor::System));
        assert!(audit.iter().any(|row| row.action == ACTION_CANCEL));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn second_daemon_on_the_same_base_is_refused_with_the_holder_pid() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let (_shutdown, shutdown_rx) = watch::channel(false);
        let err = run_daemon(Some(base_of(&daemon.tmp)), shutdown_rx)
            .await
            .expect_err("second daemon must not start");
        let DaemonError::Lifecycle(LifecycleError::AlreadyRunning { pid, .. }) = err else {
            panic!("expected AlreadyRunning, got {err:?}");
        };
        assert_eq!(pid, Some(std::process::id()));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn crash_recovery_on_boot_fails_stuck_rows_and_rebuilds_lanes() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        {
            let store = Store::open(&base_of(&tmp).join("state.sqlite3"))
                .await
                .expect("store opens");
            // A dead daemon's leftovers: one running, one waiting for an
            // approval nobody can grant any more, one queued (restart-safe).
            for (id, state) in [
                ("req_dead_run", RequestState::Running),
                ("req_dead_wait", RequestState::WaitingApproval),
            ] {
                store
                    .insert_request(id, "echo", REPO, "claude", "{}", None)
                    .await
                    .expect("insert");
                store
                    .update_request_state(id, state, None)
                    .await
                    .expect("state set");
            }
            store
                .insert_approval("req_dead_wait", "echo")
                .await
                .expect("approval row");
            store
                .insert_request("req_survivor", "echo", REPO, "claude", "{}", None)
                .await
                .expect("insert queued");
        }

        let daemon = TestDaemon::start_at(tmp).await;
        let store = daemon.handle.store();

        for id in ["req_dead_run", "req_dead_wait"] {
            let row = store.get_request(id).await.unwrap().unwrap();
            assert_eq!(row.state, RequestState::Failed, "{id} recovered");
            assert_eq!(row.outcome.as_deref(), Some(CAUSE_DAEMON_RESTART));
            let audit = store.audit_for_request(id).await.unwrap();
            assert!(audit.iter().any(|row| row.action == ACTION_DAEMON_RESTART
                && row.decision == Decision::Timeout
                && row.actor == Actor::System));
        }
        let approval = store
            .approval_for_request("req_dead_wait")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Timeout));

        // The queued row was rebuilt into its lane and executes.
        let row = wait_for_row(&store, "req_survivor", |row| {
            row.state == RequestState::Done
        })
        .await;
        assert_eq!(row.outcome.as_deref(), Some("solved"));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn version_mismatch_refuses_outdated_and_the_daemon_restarts_itself() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut lifecycle = daemon.handle.lifecycle();
        let mut dealer = daemon.dealer().await;

        let mut newer = envelope(
            "req_newer",
            "echo",
            serde_json::json!({ "msg": "hi" }),
            true,
        );
        newer.client_version = "999.0.0".to_owned();
        send(&mut dealer, &newer).await;

        let response = recv_response(&mut dealer).await;
        let Response::Refusal {
            id,
            cause,
            detail,
            recovery,
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(id, "req_newer");
        assert_eq!(cause, CAUSE_DAEMON_OUTDATED);
        assert!(detail.contains("999.0.0"), "detail: {detail}");
        assert!(
            detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {detail}"
        );
        assert!(recovery.contains("retry"), "recovery: {recovery}");

        // No request row was recorded for the refused envelope.
        let store = daemon.handle.store();
        assert!(store.get_request("req_newer").await.unwrap().is_none());

        // The daemon drains and stops on its own: the phase flips to
        // Restarting and joining completes without any external signal.
        lifecycle
            .wait_for(|phase| *phase == LifecyclePhase::Restarting)
            .await
            .expect("phase reaches Restarting");
        let tmp = daemon.join().await;

        // A fresh daemon on the same base serves a matching client.
        let daemon = TestDaemon::start_at(tmp).await;
        let mut dealer = daemon.dealer().await;
        send(
            &mut dealer,
            &envelope(
                "req_fresh",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        assert!(
            matches!(response, Response::Result { .. }),
            "expected a result, got {response:?}"
        );

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn graceful_drain_finishes_inflight_work_and_refuses_newcomers() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope(
                "req_drain",
                "echo",
                serde_json::json!({ "delay_ms": 800 }),
                false,
            ),
        )
        .await;
        assert!(matches!(
            recv_response(&mut dealer).await,
            Response::Ticket { .. }
        ));
        let store = daemon.handle.store();
        wait_for_row(&store, "req_drain", |row| {
            row.state == RequestState::Running
        })
        .await;

        // Begin the drain and give the lifecycle task a beat to flip
        // the phase before probing it with a new request.
        let _ = daemon.shutdown.send(true);
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut latecomer = daemon.dealer().await;
        send(
            &mut latecomer,
            &envelope("req_late", "echo", serde_json::json!({}), true),
        )
        .await;
        let response = recv_response(&mut latecomer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_DAEMON_SHUTTING_DOWN);
        assert!(store.get_request("req_late").await.unwrap().is_none());

        // The drain waits for the in-flight echo before the daemon exits.
        daemon.stop().await;
        let row = store.get_request("req_drain").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("solved"));
    })
    .await
    .expect("test within deadline");
}
