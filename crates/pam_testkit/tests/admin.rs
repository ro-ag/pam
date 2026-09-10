//! Administration integration through the trusted native test client.
//!
//! macOS/Linux exercise the private Unix socket. Unsupported platforms use
//! an explicit in-process fixture; GUI tests separately assert unsupported
//! production administration. Forgery tests always use raw public `ZeroMQ`.

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

#[tokio::test]
async fn public_socket_refuses_forged_gui_identity_before_version_handshake() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        for (index, op) in ["admin.grants.add", OP_PROFILE_SET, OP_APPROVALS_RESOLVE,
            "admin.connectors.save", "admin.models.download", "admin.flows.run"].iter().enumerate() {
            let mut forged = admin_envelope(&format!("forged_{index}"), op,
                serde_json::json!({"capability":"deploy", "profile":"strict", "secret":"never-store-this"}));
            forged.client_version = "forged-version".to_owned();
            forged.caller.pid = std::process::id();
            client.send_public(&forged).await;
            assert!(matches!(client.recv().await, Response::Refusal { cause, .. } if cause == CAUSE_ADMIN_DENIED));
            let row = daemon.store().get_request(&forged.id).await.unwrap().unwrap();
            assert_eq!(row.args_json, "{}");
            assert_eq!(row.state, RequestState::Refused);
        }
        assert!(matches!(client.request(&envelope("still_serving", "echo", serde_json::json!({}), true)).await,
            Response::Result { .. }));
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    }).await;
}

#[tokio::test]
async fn replayed_admin_id_cannot_apply_another_mutation() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        let first = admin_envelope(
            "same_admin_id",
            OP_PROFILE_SET,
            serde_json::json!({"profile":"strict"}),
        );
        body_of(client.request(&first).await, Outcome::Changed);
        let replay = admin_envelope(
            "same_admin_id",
            OP_PROFILE_SET,
            serde_json::json!({"profile":"relaxed"}),
        );
        assert!(matches!(
            client.request(&replay).await,
            Response::Refusal { .. }
        ));
        let body = body_of(
            client
                .request(&admin_envelope(
                    "read_after_replay",
                    OP_PROFILE_GET,
                    serde_json::json!({}),
                ))
                .await,
            Outcome::Verified,
        );
        assert_eq!(body["profile"], "strict");
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn oversized_native_frame_is_closed_without_recording_or_stopping_daemon() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    with_deadline(async {
        let tmp = short_tempdir();
        let base = base_of(&tmp);
        let daemon = TestDaemon::spawn_at(tmp).await;
        let mut raw = tokio::net::UnixStream::connect(base.join("admin/control.sock"))
            .await
            .unwrap();
        raw.write_u32(1024 * 1024 + 1).await.unwrap();
        let mut byte = [0];
        assert_eq!(raw.read(&mut byte).await.unwrap(), 0);
        let mut gui = daemon.client().await;
        body_of(
            gui.request(&admin_envelope(
                "native_after_bad_frame",
                OP_PROFILE_GET,
                serde_json::json!({}),
            ))
            .await,
            Outcome::Verified,
        );
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn unsafe_parent_and_symlink_base_are_rejected_before_state_creation() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = short_tempdir();
    let parent = base_of(&tmp).join("unsafe");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let base = parent.join("pam");
    let (_shutdown, receiver) = tokio::sync::watch::channel(false);
    assert!(
        pam_daemon::daemon::run_daemon(Some(base.clone()), receiver)
            .await
            .is_err()
    );
    assert!(!base.join("state.sqlite3").exists());
    let link = base_of(&tmp).join("alias");
    symlink(base_of(&tmp), &link).unwrap();
    let (_shutdown, receiver) = tokio::sync::watch::channel(false);
    assert!(
        pam_daemon::daemon::run_daemon(Some(link), receiver)
            .await
            .is_err()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn native_client_reconnects_after_service_restart_and_interrupted_admin_is_not_replayed() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir();
        let response = pam_daemon::admin_transport::exchange(
            &base,
            &admin_envelope("before_restart", OP_PROFILE_GET, serde_json::json!({})),
        )
        .await
        .unwrap();
        body_of(response, Outcome::Verified);
        daemon
            .store()
            .insert_running_request(
                "interrupted_admin",
                OP_PROFILE_SET,
                ADMIN_REPO,
                ADMIN_CALLER_AGENT,
                "{}",
                None,
            )
            .await
            .unwrap();
        let tmp = daemon.stop().await;
        let restarted = TestDaemon::spawn_at(tmp).await;
        let interrupted = restarted
            .store()
            .get_request("interrupted_admin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(interrupted.state, RequestState::Failed);
        assert_eq!(interrupted.outcome.as_deref(), Some("daemon_restart"));
        let response = pam_daemon::admin_transport::exchange(
            &base,
            &admin_envelope("after_restart", OP_PROFILE_GET, serde_json::json!({})),
        )
        .await
        .unwrap();
        assert_eq!(body_of(response, Outcome::Verified)["profile"], "relaxed");
        restarted.assert_invariant_clean().await;
        restarted.stop().await;
    })
    .await;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn native_version_mismatch_refuses_mutation_and_requests_restart() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut request = admin_envelope(
            "native_bad_version",
            OP_PROFILE_SET,
            serde_json::json!({"profile":"strict"}),
        );
        request.client_version = "different-build".to_owned();
        let response = pam_daemon::admin_transport::exchange(&daemon.base_dir(), &request)
            .await
            .unwrap();
        assert!(matches!(response, Response::Refusal { cause, .. } if cause == "daemon_outdated"));
        assert!(
            daemon
                .store()
                .get_request(&request.id)
                .await
                .unwrap()
                .is_none()
        );
        daemon.stop().await;
    })
    .await;
}
