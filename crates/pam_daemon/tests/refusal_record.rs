//! Refusals decided before a request row exists, end to end on a real daemon:
//! a client dials the framed public socket and is refused, and the human's
//! Activity list (`admin.activity.list`) shows it afterwards, with the count
//! of a client that keeps knocking, the peer the kernel reported, and a
//! survival across a restart.
//!
//! The classes each have their own unit tests next to the code that decides
//! them; what is asserted here is the whole path and the contract: no request
//! row, no audit row, one refusal row, visible to the administration plane.
#![cfg(any(unix, windows))]

use pam_daemon::admin_transport;
use pam_daemon::framed::{self, DialError};
use pam_proto::wire::{Hello, MAX_FRAME_BYTES, Via, WIRE_PROTOCOL, cause};
use pam_proto::{Envelope, Response};
use pam_testkit::{
    TestDaemon, envelope_for_repo, open_store, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};
use serde_json::{Value, json};

struct Fixture {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
}

impl Fixture {
    async fn start() -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let repo = tempfile::tempdir().expect("a repository directory");
        seed_repository_scope(&tmp, repo.path(), &[]).await;
        Self {
            daemon: TestDaemon::spawn_at(tmp).await,
            repo,
        }
    }

    fn repo(&self) -> String {
        self.repo
            .path()
            .canonicalize()
            .expect("the repository exists")
            .to_string_lossy()
            .into_owned()
    }

    fn envelope(&self, id: &str, capability: &str) -> Envelope {
        envelope_for_repo(&self.repo(), id, capability, json!({}), true)
    }

    /// A client of another build dials and is refused at its hello.
    async fn dial_from_another_build(&self, id: &str) -> pam_proto::wire::ErrorFrame {
        let dirs = self.daemon.handle().runtime_dir().clone();
        let mut stream = framed::connect_public(&dirs)
            .await
            .expect("the public listener accepts");
        let hello = Hello {
            proto: WIRE_PROTOCOL,
            version: "0.0.0-other-build".to_owned(),
            via: Via::Direct,
        };
        match framed::call(
            &mut stream,
            &hello,
            &self.envelope(id, "echo"),
            MAX_FRAME_BYTES,
        )
        .await
        {
            Err(DialError::Refused(error)) => error,
            other => panic!("expected the version refusal, got {other:?}"),
        }
    }

    /// The human's Activity list, refusals included.
    async fn activity(&self, id: &str) -> Vec<Value> {
        let mut envelope = self.envelope(id, "admin.activity.list");
        "pam-gui".clone_into(&mut envelope.caller.agent);
        envelope.args = json!({ "include_refusals": true, "hide_probes": true, "limit": 100 });
        let reply = admin_transport::exchange(&self.daemon.base_dir(), &envelope)
            .await
            .expect("the admin plane answers");
        let Response::Result { body, .. } = reply else {
            panic!("expected the activity list, got {reply:?}");
        };
        body["requests"].as_array().expect("requests").clone()
    }
}

fn refusals(entries: &[Value]) -> Vec<&Value> {
    entries
        .iter()
        .filter(|entry| entry["kind"] == "refusal")
        .collect()
}

/// The refusal is on the human's list with its cause, who knocked and how
/// often, and nothing about it is in the request table or the audit trail.
#[tokio::test]
async fn a_refusal_before_admission_reaches_the_human_and_leaves_no_request_row() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        let refused = fixture.dial_from_another_build("req_other_build").await;
        assert_eq!(refused.cause, cause::CLIENT_VERSION_MISMATCH);

        // The same client keeps knocking: one row, counted.
        for n in 0..24 {
            let again = fixture
                .dial_from_another_build(&format!("req_other_build_{n}"))
                .await;
            assert_eq!(again.cause, cause::CLIENT_VERSION_MISMATCH);
        }
        // An admin operation on the public socket is a different refusal.
        let dirs = fixture.daemon.handle().runtime_dir().clone();
        let mut stream = framed::connect_public(&dirs).await.unwrap();
        let mut admin = fixture.envelope("req_admin_on_public", "admin.grants.list");
        "pam-gui".clone_into(&mut admin.caller.agent);
        let (_, denied) = framed::call(
            &mut stream,
            &framed::client_hello(Via::Direct),
            &admin,
            MAX_FRAME_BYTES,
        )
        .await
        .expect("a reply");
        assert!(matches!(denied, Response::Refusal { .. }), "{denied:?}");

        fixture.daemon.handle().refusals().flush().await;
        let listed = fixture.activity("req_activity").await;
        let rows = refusals(&listed);

        let version = rows
            .iter()
            .find(|row| row["cause"] == cause::CLIENT_VERSION_MISMATCH)
            .unwrap_or_else(|| panic!("no version refusal listed: {listed:?}"));
        assert_eq!(version["count"], 25, "{version}");
        assert_eq!(version["ingress"], "public");
        assert!(version["id"].as_str().unwrap().starts_with("refusal_"));
        // The kernel's view of the peer where the platform has one.
        #[cfg(unix)]
        {
            assert_eq!(version["peer_pid"], std::process::id(), "{version}");
            assert!(version["peer_uid"].is_u64(), "{version}");
            assert!(
                version["peer_exe"]
                    .as_str()
                    .is_some_and(|exe| !exe.is_empty()),
                "the daemon resolves the executable off the reply path: {version}"
            );
        }
        #[cfg(windows)]
        assert!(version["peer_pid"].is_null(), "{version}");

        let denied = rows
            .iter()
            .find(|row| row["cause"] == pam_daemon::admin::CAUSE_ADMIN_DENIED)
            .unwrap_or_else(|| panic!("no admin refusal listed: {listed:?}"));
        assert_eq!(denied["capability"], "admin.grants.list");
        assert_eq!(denied["request_id"], "req_admin_on_public");
        assert_eq!(denied["agent"], "pam-gui");

        // Not one of them is a request: nothing admitted, nothing audited.
        let store = fixture.daemon.store();
        for id in ["req_other_build", "req_admin_on_public"] {
            assert!(store.get_request(id).await.unwrap().is_none(), "{id}");
            assert!(
                store.audit_for_request(id).await.unwrap().is_empty(),
                "{id}"
            );
        }
        fixture.daemon.assert_invariant_clean().await;
        fixture.daemon.stop().await;
    })
    .await;
}

/// A refusal recorded an instant before the daemon stops is written by the
/// drain, and is still there for the next daemon on the same base.
#[tokio::test]
async fn refusals_recorded_just_before_a_stop_survive_the_restart() {
    with_deadline(async {
        let fixture = Fixture::start().await;
        for n in 0..3 {
            fixture
                .dial_from_another_build(&format!("req_before_stop_{n}"))
                .await;
        }
        // No flush here: the drain is what writes them.
        let tmp = fixture.daemon.stop().await;

        let store = open_store(&tmp).await;
        let rows = store.list_refusals(10, None, None, None).await.unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].cause, cause::CLIENT_VERSION_MISMATCH);
        assert_eq!(rows[0].count, 3);
    })
    .await;
}
