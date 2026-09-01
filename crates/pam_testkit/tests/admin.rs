//! Admin-surface integration: real daemon, real zmq, real store —
//! exercising the GUI-only `admin.*` envelope path end to end.
//!
//! Admin envelopes are built by hand here (caller agent `pam-gui`, the
//! daemon's tripwire) because the production path to them is the GUI's
//! `pam::client::send_admin`, not the testkit's agent-shaped
//! [`pam_testkit::envelope`] — mirroring the real separation.

use pam_daemon::admin::{
    ADMIN_CALLER_AGENT, ADMIN_REPO, CAUSE_ADMIN_DENIED, OP_ACTIVITY_LIST, OP_APPROVALS_PENDING,
    OP_APPROVALS_RESOLVE, OP_PROFILE_GET, OP_PROFILE_SET,
};
use pam_daemon::daemon::DAEMON_VERSION;
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{RequestState, Store};
use pam_testkit::{TestDaemon, base_of, envelope, short_tempdir, with_deadline};

/// An `admin.*` envelope carrying the GUI tripwire identity.
fn admin_envelope(id: &str, op: &str, args: serde_json::Value) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: op.to_owned(),
        client_version: DAEMON_VERSION.to_owned(),
        caller: Caller {
            agent: ADMIN_CALLER_AGENT.to_owned(),
            repo: ADMIN_REPO.to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 10_000,
        wait: true,
    }
}

/// Unwraps a result body, asserting the outcome.
fn body_of(response: Response, outcome: Outcome) -> serde_json::Value {
    match response {
        Response::Result {
            outcome: got, body, ..
        } => {
            assert_eq!(got, outcome);
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

#[tokio::test]
async fn admin_profile_round_trips_over_the_real_socket() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&admin_envelope(
                "req_pget",
                OP_PROFILE_GET,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        let initial = body["profile"].as_str().expect("profile string").to_owned();
        assert!(["relaxed", "standard", "strict"].contains(&initial.as_str()));

        let response = client
            .request(&admin_envelope(
                "req_pset",
                OP_PROFILE_SET,
                serde_json::json!({ "profile": "strict" }),
            ))
            .await;
        let body = body_of(response, Outcome::Changed);
        assert_eq!(body["applies"], "next_daemon_start");

        let response = client
            .request(&admin_envelope(
                "req_pget2",
                OP_PROFILE_GET,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        assert_eq!(body["profile"], "strict");

        // Admin ops are real request rows and the audit invariant
        // covers them.
        daemon
            .assert_row_state("req_pset", RequestState::Done)
            .await;
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_resolve_drives_a_strict_echo_through_approval_to_completion() {
    with_deadline(async {
        // Strict profile + an active echo grant: every echo pauses for
        // a per-operation approval.
        let tmp = short_tempdir();
        let store = Store::open(&base_of(&tmp).join("state.sqlite3"))
            .await
            .expect("store opens");
        store
            .set_setting(PROFILE_SETTING_KEY, "\"strict\"")
            .await
            .expect("profile set");
        store.insert_grant("echo").await.expect("grant inserted");
        drop(store);

        let daemon = TestDaemon::spawn_at(tmp).await;
        // Subscribe before sending: the approval_pending event is
        // published only once the resolution channel is registered, so
        // waiting for it (not for the row state) makes the resolve
        // race-free.
        let mut events = daemon.subscribe(&["req_echo"]).await;
        let mut agent = daemon.client().await;
        let mut gui = daemon.client().await;

        agent
            .send(&envelope(
                "req_echo",
                "echo",
                serde_json::json!({ "msg": "hi" }),
                true,
            ))
            .await;
        loop {
            let (topic, event) = events.recv().await;
            if topic == "req_echo" && event == pam_proto::Event::ApprovalPending {
                break;
            }
        }

        // The GUI sees it pending and approves it — via admin envelope,
        // not the in-process service handle.
        let response = gui
            .request(&admin_envelope(
                "req_pending",
                OP_APPROVALS_PENDING,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        let pending = body["pending"].as_array().expect("pending array");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["request_id"], "req_echo");

        let response = gui
            .request(&admin_envelope(
                "req_resolve",
                OP_APPROVALS_RESOLVE,
                serde_json::json!({ "request_id": "req_echo", "resolution": "approved" }),
            ))
            .await;
        body_of(response, Outcome::Changed);

        // The approved echo runs to completion for the waiting agent.
        let response = agent.recv().await;
        let body = body_of(response, Outcome::Solved);
        assert_eq!(body["echo"]["msg"], "hi");

        daemon
            .assert_row_state("req_echo", RequestState::Done)
            .await;
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_activity_list_reflects_prior_requests_and_filters() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        let response = client
            .request(&envelope("req_e1", "echo", serde_json::json!({}), true))
            .await;
        assert!(matches!(response, Response::Result { .. }));

        let response = client
            .request(&admin_envelope(
                "req_act",
                OP_ACTIVITY_LIST,
                serde_json::json!({}),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        let requests = body["requests"].as_array().expect("requests array");
        assert!(
            requests.iter().any(|row| row["id"] == "req_e1"),
            "the prior echo shows in the activity feed"
        );
        assert!(
            requests.iter().any(|row| row["id"] == "req_act"),
            "admin ops are themselves on record"
        );

        // Filtering by the agent excludes the admin (gui) rows.
        let response = client
            .request(&admin_envelope(
                "req_act2",
                OP_ACTIVITY_LIST,
                serde_json::json!({ "agent": "claude" }),
            ))
            .await;
        let body = body_of(response, Outcome::Verified);
        let requests = body["requests"].as_array().expect("requests array");
        assert!(requests.iter().all(|row| row["agent"] == "claude"));
        assert!(requests.iter().any(|row| row["id"] == "req_e1"));

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_envelope_from_an_agent_identity_trips_the_wire() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;

        // The testkit envelope self-reports agent "claude" — exactly
        // the identity the tripwire refuses.
        let response = client
            .request(&envelope(
                "req_trip",
                "admin.grants.add",
                serde_json::json!({ "capability": "deploy" }),
                true,
            ))
            .await;

        match response {
            Response::Refusal { cause, .. } => assert_eq!(cause, CAUSE_ADMIN_DENIED),
            other => panic!("expected the tripwire refusal, got {other:?}"),
        }
        daemon
            .assert_row_state("req_trip", RequestState::Refused)
            .await;
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
