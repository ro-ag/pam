//! Audit invariant sweep: every terminal path, driven end to end
//! through a real daemon, must leave its request with exactly the
//! expected terminal audit rows — and
//! [`Store::terminal_requests_missing_audit`] must come back empty (no
//! silent terminal paths; the v1 issue #49 lesson).

use std::path::PathBuf;
use std::time::Duration;

use pam_daemon::approval::Resolution;
use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, ACTION_EXECUTE, ACTION_GATE_REFUSAL, CAUSE_APPROVAL_DENIED,
    CAUSE_APPROVAL_TIMEOUT, CAUSE_DEADLINE_EXCEEDED, CAUSE_EXECUTION_FAILED, DaemonConfig,
    DaemonHandle, TERMINAL_ACTIONS, run_daemon, run_daemon_with,
};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::queue::{ACTION_CANCEL, ACTION_LEASE_REAPED, CAUSE_CANCELLED, CAUSE_LEASE_EXPIRED};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Decision, RequestRow, RequestState, Store};
use tokio::sync::watch;
use tokio::time::timeout;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

const DEADLINE: Duration = Duration::from_secs(20);

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
    _tmp: tempfile::TempDir,
    handle: DaemonHandle,
    shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    async fn start() -> Self {
        let tmp = short_tempdir();
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
            _tmp: tmp,
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
            _tmp: tmp,
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

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.handle.shutdown().await;
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

/// The request's audit actions that record terminal states, in write
/// order — what each scenario asserts its exact expectation against.
async fn terminal_audit_actions(store: &Store, id: &str) -> Vec<String> {
    store
        .audit_for_request(id)
        .await
        .expect("audit query ok")
        .into_iter()
        .filter(|row| TERMINAL_ACTIONS.contains(&row.action.as_str()))
        .map(|row| row.action)
        .collect()
}

/// Asserts the invariant query finds no silent terminal request.
async fn assert_no_silent_terminals(store: &Store) {
    let missing = store
        .terminal_requests_missing_audit(TERMINAL_ACTIONS)
        .await
        .expect("invariant query ok");
    assert!(
        missing.is_empty(),
        "terminal requests without a terminal audit row: {missing:?}"
    );
}

#[tokio::test]
async fn execution_success_writes_one_execute_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_ok", "echo", serde_json::json!({ "msg": "hi" }), true),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        assert!(matches!(response, Response::Result { .. }));

        let store = daemon.handle.store();
        let row = store.get_request("req_ok").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(
            terminal_audit_actions(&store, "req_ok").await,
            [ACTION_EXECUTE]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn wait_false_success_writes_one_execute_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_bg", "echo", serde_json::json!({ "msg": "bg" }), false),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        assert!(matches!(response, Response::Ticket { .. }));

        let store = daemon.handle.store();
        wait_for_row(&store, "req_bg", |row| row.state == RequestState::Done).await;
        assert_eq!(
            terminal_audit_actions(&store, "req_bg").await,
            [ACTION_EXECUTE]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn execution_failure_writes_one_refused_execute_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope(
                "req_fail",
                "echo",
                serde_json::json!({ "fail": true }),
                true,
            ),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_EXECUTION_FAILED);

        let store = daemon.handle.store();
        let row = store.get_request("req_fail").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_EXECUTION_FAILED));
        assert_eq!(
            terminal_audit_actions(&store, "req_fail").await,
            [ACTION_EXECUTE]
        );
        let audit = store.audit_for_request("req_fail").await.unwrap();
        let execute = audit
            .iter()
            .find(|row| row.action == ACTION_EXECUTE)
            .unwrap();
        assert_eq!(execute.decision, Decision::Refuse);
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn unknown_capability_refusal_writes_one_gate_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_bad", "frobnicate", serde_json::json!({}), true),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        assert!(matches!(response, Response::Refusal { .. }));

        let store = daemon.handle.store();
        let row = store.get_request("req_bad").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(
            terminal_audit_actions(&store, "req_bad").await,
            [ACTION_GATE_REFUSAL]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn not_granted_refusal_writes_one_gate_row() {
    timeout(DEADLINE, async {
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
            &envelope("req_ng", "echo", serde_json::json!({ "msg": "hi" }), true),
        )
        .await;
        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "not_granted");

        let store = daemon.handle.store();
        let row = store.get_request("req_ng").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(
            terminal_audit_actions(&store, "req_ng").await,
            [ACTION_GATE_REFUSAL]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
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

#[tokio::test]
async fn approval_denial_writes_one_gate_row() {
    timeout(DEADLINE, async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::start_at(tmp).await;
        let mut dealer = daemon.dealer().await;

        send(
            &mut dealer,
            &envelope("req_deny", "echo", serde_json::json!({ "msg": "no" }), true),
        )
        .await;
        let store = daemon.handle.store();
        wait_for_row(&store, "req_deny", |row| {
            row.state == RequestState::WaitingApproval
        })
        .await;
        daemon
            .handle
            .approvals()
            .resolve("req_deny", Resolution::Deny)
            .await
            .expect("resolvable");

        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_DENIED);

        let row = store.get_request("req_deny").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        // The resolution's `approval` audit row is supplementary; the
        // terminal row is the refusal.
        assert_eq!(
            terminal_audit_actions(&store, "req_deny").await,
            [ACTION_GATE_REFUSAL]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn approval_timeout_writes_one_gate_row() {
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
        let response = recv_response(&mut dealer).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_TIMEOUT);

        let store = daemon.handle.store();
        let row = store.get_request("req_slow").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(
            terminal_audit_actions(&store, "req_slow").await,
            [ACTION_GATE_REFUSAL]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn deadline_teardown_writes_one_cancel_row_plus_the_deadline_row() {
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

        let store = daemon.handle.store();
        let row = wait_for_row(&store, "req_late", |row| row.state == RequestState::Failed).await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));

        // Exactly one terminal cancellation row; the deadline row is its
        // documented companion recording the refusal sent to the caller.
        let mut actions = terminal_audit_actions(&store, "req_late").await;
        actions.sort_unstable();
        assert_eq!(actions, [ACTION_CANCEL, ACTION_DEADLINE_REFUSAL]);
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_of_a_queued_request_writes_one_cancel_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;
        let store = daemon.handle.store();

        // Occupy the lane so the victim stays queued behind it.
        send(
            &mut dealer,
            &envelope(
                "req_head",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ),
        )
        .await;
        assert!(matches!(
            recv_response(&mut dealer).await,
            Response::Ticket { .. }
        ));
        wait_for_row(&store, "req_head", |row| row.state == RequestState::Running).await;

        send(
            &mut dealer,
            &envelope(
                "req_victim",
                "echo",
                serde_json::json!({ "msg": "queued" }),
                false,
            ),
        )
        .await;
        assert!(matches!(
            recv_response(&mut dealer).await,
            Response::Ticket { .. }
        ));
        wait_for_row(&store, "req_victim", |row| {
            row.state == RequestState::Queued
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
        assert_eq!(body["result"], "cancelled_queued");

        let row = store.get_request("req_victim").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        assert_eq!(
            terminal_audit_actions(&store, "req_victim").await,
            [ACTION_CANCEL]
        );
        // The cancel capability's own request finished audited too.
        assert_eq!(
            terminal_audit_actions(&store, "req_cancel").await,
            [ACTION_EXECUTE]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_of_a_running_request_writes_one_cancel_row() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;
        let store = daemon.handle.store();

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
        assert!(matches!(
            recv_response(&mut dealer).await,
            Response::Ticket { .. }
        ));
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
        let Response::Result { body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(body["result"], "signalled_running");

        // The executor observes the signal and finishes the victim.
        let row = wait_for_row(&store, "req_victim", |row| {
            row.state == RequestState::Failed
        })
        .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        assert_eq!(
            terminal_audit_actions(&store, "req_victim").await,
            [ACTION_CANCEL]
        );
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn lease_reaping_writes_one_reaped_row_and_the_late_executor_no_ops() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;
        let mut dealer = daemon.dealer().await;
        let store = daemon.handle.store();

        // A short deadline earns a short lease; nobody waits, so the
        // reaper is the only teardown. The echo keeps running past it.
        let mut request = envelope(
            "req_reaped",
            "echo",
            serde_json::json!({ "delay_ms": 8000 }),
            false,
        );
        request.deadline_ms = 300;
        send(&mut dealer, &request).await;
        assert!(matches!(
            recv_response(&mut dealer).await,
            Response::Ticket { .. }
        ));

        let row = wait_for_row(&store, "req_reaped", |row| {
            row.state == RequestState::Failed
        })
        .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));

        // Give the signalled executor time to run its double-finish
        // no-op, then assert the reaper's row stayed the only one.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            terminal_audit_actions(&store, "req_reaped").await,
            [ACTION_LEASE_REAPED]
        );
        let row = store.get_request("req_reaped").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        assert_no_silent_terminals(&store).await;

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}
