//! End-to-end tests: a real daemon on a temp base dir, the testkit's framed
//! public-transport client and admin all-events stream, real `SQLite` store —
//! asserting replies, request rows, audit rows, and lifecycle events.

use std::time::Duration;

use pam_daemon::admin::{ACTION_ADMIN_DENIED, CAUSE_ADMIN_DENIED};
use pam_daemon::admin_models::{MODEL_ADMIN_OPS, OP_MODELS_LIST};
use pam_daemon::approval::{ACTION_APPROVAL, Resolution};
use pam_daemon::daemon::{
    ACTION_DEADLINE_REFUSAL, ACTION_EXECUTE, ACTION_GATE_REFUSAL, CAUSE_APPROVAL_DENIED,
    CAUSE_APPROVAL_TIMEOUT, CAUSE_DAEMON_OUTDATED, CAUSE_DAEMON_SHUTTING_DOWN,
    CAUSE_DEADLINE_EXCEEDED, DaemonError, run_daemon,
};
use pam_daemon::lifecycle::{
    ACTION_DAEMON_RESTART, CAUSE_DAEMON_RESTART, LifecycleError, LifecyclePhase,
};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::queue::{
    ACTION_CANCEL, ACTION_LEASE_REAPED, ACTION_RECOVERY_REFUSAL, CAUSE_CANCELLED,
    CAUSE_LEASE_EXPIRED,
};
use pam_proto::{Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Actor, ApprovalResolution, Decision, RequestIngress, RequestState, Store};
use pam_testkit::{
    TEST_REPO, TestDaemon, base_of, envelope, open_store, seed_relaxed, short_tempdir,
    with_deadline,
};
use tokio::sync::watch;

const REPO: &str = TEST_REPO;

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
async fn echo_runs_end_to_end_through_lane_audit_and_events() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut events = daemon.subscribe(&["req_echo"]).await;
        let mut client = daemon.client().await;

        let args = serde_json::json!({ "msg": "hi", "delay_ms": 150 });
        client
            .send(&envelope("req_echo", "echo", args.clone(), true))
            .await;

        // The reply is the capability's result.
        let response = client.recv().await;
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
        let store = daemon.store();
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

        // The request row records the connection it arrived on: the public
        // plane and, where the kernel reports it, this very process.
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        #[cfg(unix)]
        assert_eq!(row.origin.peer_pid, Some(std::process::id()));
        assert!(!row.origin.relayed);

        // Lifecycle on the event stream: queued (laned capability), started,
        // done. The stream was opened before the request, so nothing is lost.
        let seen = events.until_terminal("req_echo").await;
        assert_eq!(seen, [Event::Queued, Event::Started, Event::Done]);

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn status_bypasses_the_lanes_and_verifies() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut events = daemon.subscribe(&["req_status", "req_query"]).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_status",
                "status",
                serde_json::json!({}),
                true,
            ))
            .await;

        let response = client.recv().await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Verified);
        assert_eq!(body["protocol"], PROTOCOL_VERSION);
        assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
        // A poll is not an active request: nothing else is in flight.
        assert_eq!(body["active_requests"], 0);
        // The slow half comes from a snapshot; this one is fresh.
        assert_eq!(body["snapshot"]["stale"], false);
        // The read-only model block: a fresh daemon has no weights, and
        // says so rather than failing or inventing figures.
        assert_eq!(body["model"]["state"], "idle");
        assert_eq!(body["model"]["id"], serde_json::Value::Null);
        assert_eq!(body["model"]["tokens_per_sec"], serde_json::Value::Null);
        // The engine block tells a CLI caller whether llama.cpp is on disk
        // and what it holds; a fresh base has neither.
        assert_eq!(body["model"]["engine"]["installed"], false);
        assert_eq!(
            body["model"]["engine"]["tag"],
            pam_model::engine::ENGINE_TAG
        );
        assert_eq!(
            body["model"]["engine"]["build_info"],
            serde_json::Value::Null
        );
        assert_eq!(body["model"]["defaults"]["light"], serde_json::Value::Null);
        assert_eq!(body["model"]["defaults"]["heavy"], serde_json::Value::Null);
        // And the per-tier verdict an agent acts on: stage plus the cause.
        assert_eq!(body["model"]["readiness"]["light"]["stage"], "unconfigured");
        assert_eq!(body["model"]["readiness"]["light"]["cause"], "no_default");
        assert_eq!(body["model"]["readiness"]["heavy"]["stage"], "unconfigured");

        // A poll leaves nothing behind: no request row, no audit row...
        let store = daemon.store();
        assert!(store.get_request("req_status").await.unwrap().is_none());
        assert!(
            store
                .audit_for_request("req_status")
                .await
                .unwrap()
                .is_empty()
        );

        // ...and no lifecycle events. A control request that is audited
        // (`query`) publishes none either: its row is terminal and a
        // subscriber of both ids has heard nothing.
        client
            .send(&envelope(
                "req_query",
                "query",
                serde_json::json!({ "ticket": "no_such_ticket" }),
                true,
            ))
            .await;
        let _ = client.recv().await;
        let row = store.get_request("req_query").await.unwrap().unwrap();
        assert!(row.state.is_terminal(), "query stays an audited request");
        assert_eq!(store.audit_for_request("req_query").await.unwrap().len(), 1);
        assert_eq!(
            events.recv_within(Duration::from_millis(400)).await,
            None,
            "a control request published a lifecycle event"
        );

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn unknown_capability_is_refused_and_audited() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_bad",
                "frobnicate",
                serde_json::json!({}),
                true,
            ))
            .await;

        let response = client.recv().await;
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

        let store = daemon.store();
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
    .await;
}

#[tokio::test]
async fn standard_profile_refuses_an_ungranted_capability() {
    with_deadline(async {
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
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_echo",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;

        let response = client.recv().await;
        let Response::Refusal {
            cause, recovery, ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "not_granted");
        assert!(recovery.contains("GUI"), "recovery: {recovery}");

        let store = daemon.store();
        let row = store.get_request("req_echo").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Refused);
        let audit = store.audit_for_request("req_echo").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_GATE_REFUSAL);
        assert_eq!(audit[0].decision, Decision::Refuse);
        assert_eq!(audit[0].actor, Actor::Policy);

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn wait_false_returns_a_ticket_and_completes_in_the_background() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut events = daemon.subscribe(&["req_bg"]).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_bg",
                "echo",
                serde_json::json!({ "delay_ms": 150 }),
                false,
            ))
            .await;

        let response = client.recv().await;
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
        let row = daemon
            .wait_for_row("req_bg", |row| row.state == RequestState::Done)
            .await;
        assert_eq!(row.outcome.as_deref(), Some("solved"));
        let seen = events.until_terminal("req_bg").await;
        assert_eq!(seen.last(), Some(&Event::Done));

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn duplicate_in_flight_request_attaches_and_shares_the_result() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut first = daemon.client().await;
        let mut second = daemon.client().await;

        let args = serde_json::json!({ "delay_ms": 700, "tag": "dup" });
        first
            .send(&envelope("req_dup1", "echo", args.clone(), true))
            .await;
        // Let the first request get admitted before the duplicate lands.
        tokio::time::sleep(Duration::from_millis(200)).await;
        second.send(&envelope("req_dup2", "echo", args, true)).await;

        let first_response = first.recv().await;
        let second_response = second.recv().await;

        // Attach semantics: one execution, both callers get its result.
        assert_eq!(first_response, second_response);
        let Response::Result { id, .. } = second_response else {
            panic!("expected a result, got {second_response:?}");
        };
        assert_eq!(id, "req_dup1", "the attached caller shares the original");

        // The duplicate never got a row of its own.
        let store = daemon.store();
        assert!(store.get_request("req_dup2").await.unwrap().is_none());

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn cancel_builtin_stops_a_running_request() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut events = daemon.subscribe(&["req_victim"]).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_victim",
                "echo",
                serde_json::json!({ "delay_ms": 8000 }),
                false,
            ))
            .await;
        let ticket_reply = client.recv().await;
        assert!(matches!(ticket_reply, Response::Ticket { .. }));

        // Wait for the executor to lease it.
        let store = daemon.store();
        daemon
            .wait_for_row("req_victim", |row| row.state == RequestState::Running)
            .await;

        let mut canceller = daemon.client().await;
        canceller
            .send(&envelope(
                "req_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_victim" }),
                true,
            ))
            .await;
        let response = canceller.recv().await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Solved);
        assert_eq!(body["result"], "signalled_running");

        // The victim reaches its terminal state through its executor.
        let row = daemon
            .wait_for_row("req_victim", |row| row.state == RequestState::Failed)
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

        let seen = events.until_terminal("req_victim").await;
        assert_eq!(seen.last(), Some(&Event::Refused));

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn approval_approve_resumes_execution_and_audits_the_resolution() {
    with_deadline(async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut events = daemon.subscribe(&["req_appr"]).await;
        let mut client = daemon.client().await;

        let args = serde_json::json!({ "msg": "hi" });
        client
            .send(&envelope("req_appr", "echo", args.clone(), true))
            .await;

        // The request parks: approval_pending published, waiting_approval
        // in the store, and one entry on the GUI's pending list.
        assert_eq!(
            events.recv().await,
            ("req_appr".to_owned(), Event::ApprovalPending)
        );
        let store = daemon.store();
        let row = store.get_request("req_appr").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::WaitingApproval);
        let pending = daemon.handle().approvals().pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "req_appr");
        assert_eq!(pending[0].capability, "echo");
        assert_eq!(pending[0].repo, REPO);

        // The human approves; the pipeline resumes into execution.
        daemon
            .handle()
            .approvals()
            .resolve("req_appr", Resolution::Approve { remember: false })
            .await
            .expect("resolvable");

        let response = client.recv().await;
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
                .handle()
                .approvals()
                .pending()
                .await
                .unwrap()
                .is_empty()
        );

        // The rest of the lifecycle follows the approval.
        let seen = events.until_terminal("req_appr").await;
        assert_eq!(seen, [Event::Queued, Event::Started, Event::Done]);

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn approval_deny_refuses_with_approval_denied() {
    with_deadline(async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut events = daemon.subscribe(&["req_deny"]).await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_deny",
                "echo",
                serde_json::json!({ "msg": "no" }),
                true,
            ))
            .await;
        assert_eq!(
            events.recv().await,
            ("req_deny".to_owned(), Event::ApprovalPending)
        );

        daemon
            .handle()
            .approvals()
            .resolve("req_deny", Resolution::Deny)
            .await
            .expect("resolvable");

        let response = client.recv().await;
        let Response::Refusal {
            cause, recovery, ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_DENIED);
        assert!(recovery.contains("GUI"), "recovery: {recovery}");

        let store = daemon.store();
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

        assert_eq!(events.recv().await, ("req_deny".to_owned(), Event::Refused));

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn unanswered_approval_times_out_into_a_refusal() {
    with_deadline(async {
        let tmp = short_tempdir();
        seed_strict_with_echo_grant(&tmp).await;
        let daemon = TestDaemon::spawn_at_with(tmp, |config| {
            config.approval_timeout = Duration::from_millis(300);
        })
        .await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_slow",
                "echo",
                serde_json::json!({ "msg": "??" }),
                true,
            ))
            .await;

        // Nobody answers within the daemon's (short) approval timeout.
        let response = client.recv().await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_APPROVAL_TIMEOUT);

        let store = daemon.store();
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
    .await;
}

#[tokio::test]
async fn elapsed_deadline_refuses_the_waiting_caller_and_ends_the_request() {
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
        client.send(&request).await;

        let response = client.recv().await;
        let Response::Refusal { cause, .. } = response else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_DEADLINE_EXCEEDED);

        // The request itself is torn down (expired through the queue)
        // and both the deadline refusal and the teardown are audited.
        let store = daemon.store();
        let row = daemon
            .wait_for_row("req_late", |row| row.state == RequestState::Failed)
            .await;
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_LEASE_EXPIRED));
        let audit = store.audit_for_request("req_late").await.unwrap();
        assert!(audit.iter().any(|row| row.action == ACTION_DEADLINE_REFUSAL
            && row.decision == Decision::Timeout
            && row.actor == Actor::System));
        // Which path tears it down is a scheduler race: the reaper ends a
        // running lease, `take_next` refuses a row that expired before it
        // was leased. Either is the one teardown row.
        assert!(
            audit
                .iter()
                .any(|row| row.action == ACTION_LEASE_REAPED
                    || row.action == ACTION_RECOVERY_REFUSAL)
        );

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn second_daemon_on_the_same_base_is_refused_with_the_holder_pid() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;

        let (_shutdown, shutdown_rx) = watch::channel(false);
        let err = run_daemon(Some(daemon.base_dir()), shutdown_rx)
            .await
            .expect_err("second daemon must not start");
        let DaemonError::Lifecycle(LifecycleError::AlreadyRunning { pid, .. }) = err else {
            panic!("expected AlreadyRunning, got {err:?}");
        };
        // The holder's pid is legible to the loser only where the lock is
        // advisory: unix `flock` is, a Windows byte-range lock is
        // mandatory and hides the file from every other handle. Hence the
        // Option on `AlreadyRunning::pid`; the refusal itself is the fact
        // under test and holds on both.
        assert_eq!(
            pid,
            if cfg!(unix) {
                Some(std::process::id())
            } else {
                None
            }
        );

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn crash_recovery_on_boot_fails_stuck_rows_and_rebuilds_lanes() {
    with_deadline(async {
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
            let now_ms = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap();
            store
                .insert_admitted_request(
                    "req_survivor",
                    "echo",
                    REPO,
                    "claude",
                    "{}",
                    None,
                    now_ms + 60_000,
                )
                .await
                .unwrap();
            assert!(
                store
                    .authorize_queued_request("req_survivor", REPO, now_ms)
                    .await
                    .unwrap()
            );
            store
                .insert_request("req_legacy", "echo", REPO, "claude", "{}", None)
                .await
                .unwrap();
        }

        let daemon = TestDaemon::spawn_at(tmp).await;
        let store = daemon.store();

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

        // Unapproved legacy rows fail closed; authorized unexpired work resumes.
        assert_eq!(
            store
                .get_request("req_legacy")
                .await
                .unwrap()
                .unwrap()
                .state,
            RequestState::Failed
        );
        // The authorized queued row was rebuilt into its lane and executes.
        let row = daemon
            .wait_for_row("req_survivor", |row| row.state == RequestState::Done)
            .await;
        assert_eq!(row.outcome.as_deref(), Some("solved"));

        daemon.stop().await;
    })
    .await;
}

/// A probe over one scripted file: the daemon's own executable as a test
/// wants it to look.
#[derive(Default)]
struct ScriptedImage {
    /// Bumped to make the file at every path look replaced.
    generation: std::sync::atomic::AtomicU64,
}

impl ScriptedImage {
    fn replace_on_disk(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl pam_daemon::image::ImageProbe for ScriptedImage {
    fn facts(&self, path: &std::path::Path) -> Option<pam_daemon::image::FileFacts> {
        let generation = self.generation.load(std::sync::atomic::Ordering::SeqCst);
        Some(pam_daemon::image::FileFacts {
            canonical: path.to_path_buf(),
            len: 1_000 + generation,
            modified: None,
            identity: Some((1, 42 + generation)),
        })
    }
}

/// Sends `status` under three claimed versions (in the hello: the envelope's
/// own `client_version` decides nothing on this transport) and asserts each is
/// refused `client_version_mismatch` with the phase still `Serving` and no row.
async fn assert_claims_are_refused(daemon: &TestDaemon, boot_path: &std::path::Path) {
    let lifecycle = daemon.handle().lifecycle();
    for (index, claimed) in ["999.0.0", "0.0.1", "not a version"]
        .into_iter()
        .enumerate()
    {
        let id = format!("req_claims_{index}");
        let mut claimant = daemon.client().await;
        claimant.claim_version(claimed);
        let response = claimant
            .request(&envelope(&id, "status", serde_json::json!({}), true))
            .await;
        let Response::Refusal {
            cause,
            detail,
            retryable,
            ..
        } = &response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "client_version_mismatch");
        assert!(detail.contains(claimed), "detail: {detail}");
        assert!(
            detail.contains(env!("CARGO_PKG_VERSION")),
            "detail: {detail}"
        );
        assert!(
            detail.contains(&boot_path.display().to_string()),
            "the refusal names the daemon's executable: {detail}"
        );
        assert!(!retryable, "sending it again would only repeat");
        assert_eq!(*lifecycle.borrow(), LifecyclePhase::Serving);
        assert!(
            daemon.store().get_request(&id).await.unwrap().is_none(),
            "a refused handshake records no request row"
        );
    }
}

/// A claimed client version used to restart the daemon: any public caller
/// could drain and restart it with one envelope, and two installed
/// versions restarted each other forever. The claim is now only the
/// occasion to look at the binary on disk.
#[tokio::test]
async fn a_claimed_version_never_restarts_the_daemon_but_a_replaced_binary_does() {
    with_deadline(async {
        let image = std::sync::Arc::new(ScriptedImage::default());
        let daemon = TestDaemon::spawn_with(|config| {
            config.image_probe = Some(image.clone());
        })
        .await;
        let mut lifecycle = daemon.handle().lifecycle();
        let mut client = daemon.client().await;
        let boot_path = daemon
            .handle()
            .boot_image_path()
            .expect("the platform names the test binary");

        // An in-flight request that a restart would cancel.
        client
            .send(&envelope(
                "req_survivor",
                "echo",
                serde_json::json!({ "delay_ms": 1_500 }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));

        // The binary on disk is the one that is running. Whatever a client
        // claims — newer, older, nonsense — it is refused and nothing moves.
        assert_claims_are_refused(&daemon, &boot_path).await;
        // The daemon is still serving and the in-flight work finishes.
        let store = daemon.store();
        let survivor = loop {
            let row = store.get_request("req_survivor").await.unwrap().unwrap();
            if row.state.is_terminal() {
                break row;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert_eq!(survivor.state, RequestState::Done, "{survivor:?}");

        // Now the binary really is replaced (the re-check is cached for a
        // second, so the next mismatched request after that sees it).
        image.replace_on_disk();
        tokio::time::sleep(pam_daemon::image::RECHECK_INTERVAL + Duration::from_millis(100)).await;

        let mut newer = daemon.client().await;
        newer.claim_version("999.0.0");
        let response = newer
            .request(&envelope(
                "req_newer",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        let Response::Refusal {
            id,
            cause,
            detail,
            recovery,
            retryable,
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
        assert!(retryable, "the retry lands on the replacement daemon");

        // No request row was recorded for the refused envelope.
        let store = daemon.store();
        assert!(store.get_request("req_newer").await.unwrap().is_none());

        // The daemon drains and stops on its own: the phase flips to
        // Restarting and joining completes without any external signal.
        lifecycle
            .wait_for(|phase| *phase == LifecyclePhase::Restarting)
            .await
            .expect("phase reaches Restarting");
        let tmp = daemon.join().await;

        // A fresh daemon on the same base serves a matching client.
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut client = daemon.client().await;
        client
            .send(&envelope(
                "req_fresh",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        let response = client.recv().await;
        assert!(
            matches!(response, Response::Result { .. }),
            "expected a result, got {response:?}"
        );

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn graceful_drain_finishes_inflight_work_and_refuses_newcomers() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        client
            .send(&envelope(
                "req_drain",
                "echo",
                serde_json::json!({ "delay_ms": 800 }),
                false,
            ))
            .await;
        assert!(matches!(client.recv().await, Response::Ticket { .. }));
        let store = daemon.store();
        daemon
            .wait_for_row("req_drain", |row| row.state == RequestState::Running)
            .await;

        // Begin the drain and give the lifecycle task a beat to flip
        // the phase before probing it with a new request.
        daemon.begin_shutdown();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let mut latecomer = daemon.client().await;
        latecomer
            .send(&envelope("req_late", "echo", serde_json::json!({}), true))
            .await;
        let response = latecomer.recv().await;
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
    .await;
}

#[tokio::test]
async fn a_model_admin_op_from_an_agent_trips_the_wire() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        // Forged on the public socket the op is refused before any row is
        // written: the public listener never lets `admin.*` through.
        client
            .send_public(&envelope(
                "req_models_forged",
                OP_MODELS_LIST,
                serde_json::json!({}),
                true,
            ))
            .await;
        let response = client.recv().await;
        assert!(
            matches!(&response, Response::Refusal { cause, detail, .. }
                if cause == CAUSE_ADMIN_DENIED && detail.contains("private native channel")),
            "expected the public refusal, got {response:?}"
        );
        let store = daemon.store();
        assert!(
            store
                .get_request("req_models_forged")
                .await
                .unwrap()
                .is_none()
        );

        // The default `envelope` helper speaks as `claude`, not as the
        // GUI: the model ops sit behind the same tripwire as every other
        // admin op, so this must never reach the registry even when an
        // agent identity reaches the private channel.
        client
            .send(&envelope(
                "req_models_denied",
                OP_MODELS_LIST,
                serde_json::json!({}),
                true,
            ))
            .await;

        let response = client.recv().await;
        let Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } = response
        else {
            panic!("a model admin op from an agent must be refused");
        };
        assert_eq!(cause, CAUSE_ADMIN_DENIED);
        assert!(detail.contains("GUI-only"), "detail: {detail}");
        assert!(!recovery.is_empty());

        // Audited as the tripwire, not as an ordinary admin refusal, so
        // the attempt stands out in the trail.
        let row = store
            .get_request("req_models_denied")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, RequestState::Refused);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_ADMIN_DENIED));
        let audit = store.audit_for_request("req_models_denied").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_ADMIN_DENIED);
        assert_eq!(audit[0].decision, Decision::Refuse);
        assert_eq!(audit[0].actor, Actor::System);

        // And the ops are not capabilities: none of them classifies, so
        // none can ever be granted, approved, or queued.
        for op in MODEL_ADMIN_OPS {
            assert!(
                pam_daemon::policy::classify(op).is_none(),
                "{op} must not be a capability"
            );
        }

        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn the_model_surface_is_reachable_from_the_daemon_handle() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let models = daemon.handle().models();

        // Defaults start unset, so a tier resolves to nothing and the
        // caller takes its deterministic path.
        assert_eq!(models.defaults().await.unwrap(), (None, None));
        let status = models.status().await.unwrap();
        assert_eq!(status["runtime"]["state"]["state"], "idle");
        assert!(status["host_ram_bytes"].as_u64().unwrap() > 0);

        daemon.stop().await;
    })
    .await;
}
