//! Audit invariant sweep: every terminal path, driven end to end
//! through a real daemon, must leave its request with exactly the
//! expected terminal audit rows — and
//! [`pam_store::Store::terminal_requests_missing_audit`] must come back
//! empty (no silent terminal paths; the v1 issue #49 lesson).
//!
//! Daemon setup, wire helpers, and the invariant assertions come from
//! the shared [`pam_testkit`] harness.

use std::time::Duration;

use pam_daemon::approval::Resolution;
use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, ACTION_EXECUTE, ACTION_GATE_REFUSAL, CAUSE_APPROVAL_DENIED,
    CAUSE_APPROVAL_TIMEOUT, CAUSE_DEADLINE_EXCEEDED, CAUSE_EXECUTION_FAILED,
};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::queue::{ACTION_CANCEL, ACTION_LEASE_REAPED, CAUSE_CANCELLED, CAUSE_LEASE_EXPIRED};
use pam_proto::{Outcome, Response};
use pam_store::{Decision, RequestState};
use pam_testkit::{TestDaemon, envelope, open_store, short_tempdir, with_deadline};

#[tokio::test]
async fn execution_success_writes_one_execute_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_ok",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Result { .. }));

        daemon.assert_row_state("req_ok", RequestState::Done).await;
        assert_eq!(
            daemon.terminal_audit_actions("req_ok").await,
            [ACTION_EXECUTE]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn wait_false_success_writes_one_execute_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_bg",
                "echo",
                serde_json::json!({ "msg": "bg" }),
                false,
            ))
            .await;
        assert!(matches!(response, Response::Ticket { .. }));

        daemon
            .wait_for_row("req_bg", |row| row.state == RequestState::Done)
            .await;
        assert_eq!(
            daemon.terminal_audit_actions("req_bg").await,
            [ACTION_EXECUTE]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn execution_failure_writes_one_refused_execute_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_fail",
                "echo",
                serde_json::json!({ "fail": true }),
                true,
            ))
            .await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_EXECUTION_FAILED);

        let store = daemon.store();
        let row = store.get_request("req_fail").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_EXECUTION_FAILED));
        assert_eq!(
            daemon.terminal_audit_actions("req_fail").await,
            [ACTION_EXECUTE]
        );
        let audit = daemon.audit_rows("req_fail").await;
        let execute = audit
            .iter()
            .find(|row| row.action == ACTION_EXECUTE)
            .unwrap();
        assert_eq!(execute.decision, Decision::Refuse);
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn unknown_capability_refusal_writes_one_gate_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_bad",
                "frobnicate",
                serde_json::json!({}),
                true,
            ))
            .await;
        assert!(matches!(response, Response::Refusal { .. }));

        daemon
            .assert_row_state("req_bad", RequestState::Refused)
            .await;
        assert_eq!(
            daemon.terminal_audit_actions("req_bad").await,
            [ACTION_GATE_REFUSAL]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn not_granted_refusal_writes_one_gate_row() {
    with_deadline(async {
        let tmp = short_tempdir();
        {
            let store = open_store(&tmp).await;
            store
                .set_setting(PROFILE_SETTING_KEY, "\"standard\"")
                .await
                .expect("profile set");
        }
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_ng",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "not_granted");

        daemon
            .assert_row_state("req_ng", RequestState::Refused)
            .await;
        assert_eq!(
            daemon.terminal_audit_actions("req_ng").await,
            [ACTION_GATE_REFUSAL]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

/// Seeds `tmp`'s store with the strict profile and an active `echo`
/// grant, so every echo request hits the per-operation approval pause.
async fn seed_strict_with_echo_grant(tmp: &tempfile::TempDir) {
    let store = open_store(tmp).await;
    store
        .set_setting(PROFILE_SETTING_KEY, "\"strict\"")
        .await
        .expect("profile set");
    store.insert_grant("echo").await.expect("grant inserted");
}

#[tokio::test]
async fn approval_denial_writes_one_gate_row() {
    with_deadline(async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_deny",
                "echo",
                serde_json::json!({ "msg": "no" }),
                true,
            ))
            .await;
        daemon
            .wait_for_row("req_deny", |row| row.state == RequestState::WaitingApproval)
            .await;
        daemon
            .handle()
            .approvals()
            .resolve("req_deny", Resolution::Deny)
            .await
            .expect("resolvable");

        let response = client.recv().await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_DENIED);

        daemon
            .assert_row_state("req_deny", RequestState::Refused)
            .await;
        // The resolution's `approval` audit row is supplementary; the
        // terminal row is the refusal.
        assert_eq!(
            daemon.terminal_audit_actions("req_deny").await,
            [ACTION_GATE_REFUSAL]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn approval_timeout_writes_one_gate_row() {
    with_deadline(async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::spawn_at_with(tmp, |config| {
            config.approval_timeout = Duration::from_millis(300);
        })
        .await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_slow",
                "echo",
                serde_json::json!({ "msg": "??" }),
                true,
            ))
            .await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_TIMEOUT);

        daemon
            .assert_row_state("req_slow", RequestState::Refused)
            .await;
        assert_eq!(
            daemon.terminal_audit_actions("req_slow").await,
            [ACTION_GATE_REFUSAL]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn deadline_teardown_writes_one_cancel_row_plus_the_deadline_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let mut request = envelope(
            "req_late",
            "echo",
            serde_json::json!({ "delay_ms": 3000 }),
            true,
        );
        request.deadline_ms = 200;
        let response = client.request(&request).await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_DEADLINE_EXCEEDED);

        let row = daemon
            .wait_for_row("req_late", |row| row.state == RequestState::Failed)
            .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));

        // Exactly one terminal cancellation row; the deadline row is its
        // documented companion recording the refusal sent to the caller.
        let mut actions = daemon.terminal_audit_actions("req_late").await;
        actions.sort_unstable();
        assert_eq!(actions, [ACTION_CANCEL, ACTION_DEADLINE_REFUSAL]);
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn cancel_of_a_queued_request_writes_one_cancel_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        // Occupy the lane so the victim stays queued behind it.
        let response = client
            .request(&envelope(
                "req_head",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ))
            .await;
        assert!(matches!(response, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_head", |row| row.state == RequestState::Running)
            .await;

        let response = client
            .request(&envelope(
                "req_victim",
                "echo",
                serde_json::json!({ "msg": "queued" }),
                false,
            ))
            .await;
        assert!(matches!(response, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_victim", |row| row.state == RequestState::Queued)
            .await;

        let mut canceller = daemon.client().await;
        let response = canceller
            .request(&envelope(
                "req_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_victim" }),
                true,
            ))
            .await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body["result"], "cancelled_queued");

        let store = daemon.store();
        let row = store.get_request("req_victim").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        assert_eq!(
            daemon.terminal_audit_actions("req_victim").await,
            [ACTION_CANCEL]
        );
        // The cancel capability's own request finished audited too.
        assert_eq!(
            daemon.terminal_audit_actions("req_cancel").await,
            [ACTION_EXECUTE]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn cancel_of_a_running_request_writes_one_cancel_row() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope(
                "req_victim",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ))
            .await;
        assert!(matches!(response, Response::Ticket { .. }));
        daemon
            .wait_for_row("req_victim", |row| row.state == RequestState::Running)
            .await;

        let mut canceller = daemon.client().await;
        let response = canceller
            .request(&envelope(
                "req_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_victim" }),
                true,
            ))
            .await;
        let Response::Result { body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(body["result"], "signalled_running");

        // The executor observes the signal and finishes the victim.
        let row = daemon
            .wait_for_row("req_victim", |row| row.state == RequestState::Failed)
            .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        assert_eq!(
            daemon.terminal_audit_actions("req_victim").await,
            [ACTION_CANCEL]
        );
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn lease_reaping_writes_one_reaped_row_and_the_late_executor_no_ops() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        // A short deadline earns a short lease; nobody waits, so the
        // reaper is the only teardown. The echo keeps running past it.
        let mut request = envelope(
            "req_reaped",
            "echo",
            serde_json::json!({ "delay_ms": 8000 }),
            false,
        );
        request.deadline_ms = 300;
        let response = client.request(&request).await;
        assert!(matches!(response, Response::Ticket { .. }));

        let row = daemon
            .wait_for_row("req_reaped", |row| row.state == RequestState::Failed)
            .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));

        // Give the signalled executor time to run its double-finish
        // no-op, then assert the reaper's row stayed the only one.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            daemon.terminal_audit_actions("req_reaped").await,
            [ACTION_LEASE_REAPED]
        );
        let store = daemon.store();
        let row = store.get_request("req_reaped").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        daemon.assert_invariant_clean().await;

        daemon.stop().await;
    })
    .await;
}
