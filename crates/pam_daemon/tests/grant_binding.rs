//! A flow step's remembered approval is bound to what the step runs, end to
//! end: a real daemon on a temp base dir, a real store, the flow files
//! written straight into the library the daemon reads — the way a human
//! edits one by hand or restores one from a backup, never through
//! `admin.flows.save`, so nothing on the admin surface revokes anything.
//!
//! What the tests watch is the gate: whether a run stops for a human
//! (`waiting_approval`) or goes straight through. The step itself is
//! `git --version`; off macOS a stateful command step is blocked by
//! containment after the gate, which changes nothing here.

use std::path::{Path, PathBuf};

use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::approval::Resolution;
use pam_daemon::daemon::DAEMON_VERSION;
use pam_daemon::flow_service::CAP_FLOW_RUN;
use pam_daemon::policy::ACTION_GRANT_BOUND;
use pam_proto::{Caller, Envelope, PROTOCOL_VERSION, Response};
use pam_store::RequestState;
use pam_testkit::{
    TestClient, TestDaemon, base_of, envelope_for_repo, open_store, seed_allowed_programs,
    seed_extra_path, seed_relaxed, short_tempdir, with_deadline,
};
use serde_json::{Value, json};

/// A flow with one stateful step, the way a human first wrote it.
const BOUND: &str = "schema: 1\n\
id: bound\n\
name: Bound\n\
steps:\n\
\x20 - id: change\n\
\x20   run: [git, --version]\n\
\x20   effect: stateful\n";

/// The same step, reformatted by hand: comments, block lists, another key
/// order, a new description and a note. Nothing about what runs changed.
const BOUND_REFORMATTED: &str = "# restored from the backup, then tidied\n\
schema: 1\n\
id: bound\n\
name: Bound\n\
description: the same step in other words\n\
steps:\n\
\x20   - id: change   # still the one step\n\
\x20     effect: stateful\n\
\x20     note: reformatted, not changed\n\
\x20     run:\n\
\x20       - git\n\
\x20       - --version\n";

/// The step's arguments edited by hand: what runs is not what was approved.
const BOUND_EDITED: &str = "schema: 1\n\
id: bound\n\
name: Bound\n\
steps:\n\
\x20 - id: change\n\
\x20   run: [git, version]\n\
\x20   effect: stateful\n";

/// A second flow, for the revocation scope.
const OTHER: &str = "schema: 1\n\
id: other\n\
name: Other\n\
steps:\n\
\x20 - id: change\n\
\x20   run: [git, --version]\n\
\x20   effect: stateful\n";

/// Pin fixture Git to Apple's installed toolchain on macOS, as the flow
/// tests do (the `/usr/bin/git` shim writes caches containment denies).
fn fixture_extra_path() -> Vec<String> {
    let mut paths = Vec::new();
    if cfg!(target_os = "macos") {
        for directory in [
            "/Library/Developer/CommandLineTools/usr/bin",
            "/Applications/Xcode.app/Contents/Developer/usr/bin",
        ] {
            if PathBuf::from(directory).join("git").is_file() {
                paths.push(directory.to_owned());
                break;
            }
        }
    }
    paths
}

fn canonical(path: &Path) -> String {
    path.canonicalize()
        .expect("fixture repository exists")
        .display()
        .to_string()
}

/// A relaxed daemon whose scope approves two repositories, A and B.
struct Fixture {
    daemon: TestDaemon,
    a: tempfile::TempDir,
    b: tempfile::TempDir,
}

impl Fixture {
    async fn spawn(flows: &[(&str, &str)], legacy_grants: &[&str]) -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        seed_allowed_programs(&tmp, &["git"]).await;
        let extra = fixture_extra_path();
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        seed_extra_path(&tmp, &extra).await;
        let (a, b) = (short_tempdir(), short_tempdir());
        let store = open_store(&tmp).await;
        store
            .set_setting(
                "flows.scope_policy",
                &json!({
                    "version": 1,
                    "repositories": [
                        {"root": canonical(a.path()), "connectors": []},
                        {"root": canonical(b.path()), "connectors": []},
                    ]
                })
                .to_string(),
            )
            .await
            .expect("the scope persists");
        // Grants written by a release that had no binding.
        for capability in legacy_grants {
            store.insert_grant(capability).await.expect("legacy grant");
        }
        drop(store);
        for (id, yaml) in flows {
            write_flow(&base_of(&tmp), id, yaml);
        }
        Self {
            daemon: TestDaemon::spawn_at(tmp).await,
            a,
            b,
        }
    }

    fn repo_a(&self) -> String {
        canonical(self.a.path())
    }

    fn repo_b(&self) -> String {
        canonical(self.b.path())
    }

    /// Writes a flow file straight into the library, as a human would.
    fn edit(&self, id: &str, yaml: &str) {
        write_flow(&self.daemon.base_dir(), id, yaml);
    }

    /// Starts `flow` in `repo` and reports whether it stopped for a human
    /// (`true`, left waiting) or went through the gate on its own.
    async fn starts_asking(
        &self,
        client: &mut TestClient,
        ticket: &str,
        flow: &str,
        repo: &str,
    ) -> bool {
        let mut envelope = envelope_for_repo(
            repo,
            ticket,
            CAP_FLOW_RUN,
            json!({ "id": flow, "inputs": {} }),
            false,
        );
        envelope.deadline_ms = 120_000;
        match client.request(&envelope).await {
            Response::Ticket { .. } => {}
            other => panic!("expected a ticket for {ticket}, got {other:?}"),
        }
        let row = self
            .daemon
            .wait_for_row(ticket, |row| {
                row.state == RequestState::WaitingApproval || row.state.is_terminal()
            })
            .await;
        if row.state.is_terminal() {
            assert_eq!(row.state, RequestState::Done, "{ticket}: {row:?}");
        }
        row.state == RequestState::WaitingApproval
    }

    /// Answers `ticket`'s pending approval and waits for the run to end.
    async fn answer(&self, ticket: &str, resolution: Resolution) {
        self.daemon
            .handle()
            .approvals()
            .resolve(ticket, resolution)
            .await
            .expect("the approval is delivered");
        let row = self
            .daemon
            .wait_for_row(ticket, |row| row.state.is_terminal())
            .await;
        assert_eq!(row.state, RequestState::Done, "{ticket}: {row:?}");
    }

    /// The `admin.approvals.pending` entry of `ticket`.
    async fn pending_entry(&self, client: &mut TestClient, ticket: &str) -> Value {
        let id = format!("pending_{ticket}");
        let body = admin(client, &id, "admin.approvals.pending", json!({})).await;
        body["pending"]
            .as_array()
            .expect("a pending list")
            .iter()
            .find(|entry| entry["request_id"] == ticket)
            .cloned()
            .unwrap_or_else(|| panic!("{ticket} is not pending: {body}"))
    }
}

fn write_flow(base: &Path, id: &str, yaml: &str) {
    let dir = base.join("flows");
    std::fs::create_dir_all(&dir).expect("the flow library exists");
    std::fs::write(dir.join(format!("{id}.yaml")), yaml).expect("the flow file is written");
}

/// Runs one admin op over the GUI's plane and returns its result body.
async fn admin(client: &mut TestClient, id: &str, op: &str, args: Value) -> Value {
    let envelope = Envelope {
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
        deadline_ms: 30_000,
        wait: true,
    };
    match client.request(&envelope).await {
        Response::Result { body, .. } => body,
        other => panic!("{op} failed: {other:?}"),
    }
}

const CAPABILITY: &str = "flow.step:bound/change";

#[tokio::test]
async fn a_hand_edited_step_asks_again_and_a_reformatted_one_does_not() {
    Box::pin(with_deadline(async {
        let fx = Fixture::spawn(&[("bound", BOUND)], &[]).await;
        let mut client = fx.daemon.client().await;
        let repo = fx.repo_a();

        assert!(fx.starts_asking(&mut client, "first", "bound", &repo).await);
        // The card says what Remember records: this step, this repository.
        let entry = fx.pending_entry(&mut client, "first").await;
        assert_eq!(entry["remember"]["flow"], "bound");
        assert_eq!(entry["remember"]["step"], "change");
        assert_eq!(entry["remember"]["repository"], repo.as_str());
        assert_eq!(entry["remember"]["changed"], Value::Null);
        fx.answer("first", Resolution::Approve { remember: true })
            .await;
        let rows = fx.daemon.store().active_grants(CAPABILITY).await.unwrap();
        assert_eq!(rows.len(), 1);
        let binding = rows[0].binding.clone().expect("the grant is bound");
        assert_eq!(binding.repository.as_deref(), Some(repo.as_str()));
        assert_eq!(binding.effect_class, "destructive");

        // Remembered: the same step goes through.
        assert!(!fx.starts_asking(&mut client, "again", "bound", &repo).await);

        // Reformatted by hand, comments and all: still the same step.
        fx.edit("bound", BOUND_REFORMATTED);
        assert!(
            !fx.starts_asking(&mut client, "reformatted", "bound", &repo)
                .await,
            "formatting is not a change to what runs"
        );

        // Its arguments edited by hand: the human is asked again, and told why.
        fx.edit("bound", BOUND_EDITED);
        assert!(
            fx.starts_asking(&mut client, "edited", "bound", &repo)
                .await
        );
        let entry = fx.pending_entry(&mut client, "edited").await;
        assert_eq!(
            entry["remember"]["changed"],
            "the step's command changed since it was approved"
        );
        assert_ne!(
            entry["remember"]["effect_digest"].as_str().unwrap(),
            &binding.effect_digest[..12]
        );
        fx.answer("edited", Resolution::Deny).await;
        // Denying leaves the old binding as it was; nothing new authorizes.
        let rows = fx.daemon.store().active_grants(CAPABILITY).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].binding.as_ref(), Some(&binding));
        assert!(fx.starts_asking(&mut client, "still", "bound", &repo).await);
        fx.answer("still", Resolution::Approve { remember: true })
            .await;
        // Remembering the new step re-points the grant; the old step is gone.
        let rows = fx.daemon.store().active_grants(CAPABILITY).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_ne!(rows[0].binding.as_ref(), Some(&binding));
        assert!(
            !fx.starts_asking(&mut client, "settled", "bound", &repo)
                .await
        );
        fx.edit("bound", BOUND);
        assert!(
            fx.starts_asking(&mut client, "reverted", "bound", &repo)
                .await,
            "the earlier definition is not remembered either"
        );
        fx.answer("reverted", Resolution::Deny).await;

        fx.daemon.assert_invariant_clean().await;
        fx.daemon.stop().await;
    }))
    .await;
}

#[tokio::test]
async fn a_grant_for_one_repository_does_not_authorize_another() {
    Box::pin(with_deadline(async {
        let fx = Fixture::spawn(&[("bound", BOUND)], &[]).await;
        let mut client = fx.daemon.client().await;
        let (a, b) = (fx.repo_a(), fx.repo_b());

        assert!(fx.starts_asking(&mut client, "in_a", "bound", &a).await);
        fx.answer("in_a", Resolution::Approve { remember: true })
            .await;
        assert!(!fx.starts_asking(&mut client, "a_again", "bound", &a).await);

        assert!(
            fx.starts_asking(&mut client, "in_b", "bound", &b).await,
            "a grant for A does not authorize B"
        );
        let entry = fx.pending_entry(&mut client, "in_b").await;
        assert_eq!(
            entry["remember"]["changed"],
            format!("the step was approved for {a}, not for {b}")
        );
        assert_eq!(entry["remember"]["repository"], b.as_str());
        fx.answer("in_b", Resolution::Approve { remember: true })
            .await;

        // Each repository now has its own grant, and both go through.
        let rows = fx.daemon.store().active_grants(CAPABILITY).await.unwrap();
        let mut repositories: Vec<String> = rows
            .iter()
            .filter_map(|row| row.binding.as_ref()?.repository.clone())
            .collect();
        repositories.sort();
        let mut expected = vec![a.clone(), b.clone()];
        expected.sort();
        assert_eq!(repositories, expected);
        assert!(!fx.starts_asking(&mut client, "a_last", "bound", &a).await);
        assert!(!fx.starts_asking(&mut client, "b_last", "bound", &b).await);

        // The list shows each binding.
        let list = admin(&mut client, "list", "admin.grants.list", json!({})).await;
        let bound: Vec<&Value> = list["grants"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["capability"] == CAPABILITY)
            .collect();
        assert_eq!(bound.len(), 2);
        for row in bound {
            assert_eq!(row["binding"]["state"], "bound");
            assert_eq!(row["scope"], "repository");
        }

        fx.daemon.assert_invariant_clean().await;
        fx.daemon.stop().await;
    }))
    .await;
}

#[tokio::test]
async fn a_legacy_grant_binds_on_first_use_and_then_behaves_as_bound() {
    Box::pin(with_deadline(async {
        let fx = Fixture::spawn(&[("bound", BOUND)], &[CAPABILITY]).await;
        let mut client = fx.daemon.client().await;
        let (a, b) = (fx.repo_a(), fx.repo_b());
        let list = admin(&mut client, "before", "admin.grants.list", json!({})).await;
        assert_eq!(list["grants"][0]["binding"]["state"], "legacy");

        // Upgrading breaks nothing: the legacy grant still authorizes...
        assert!(!fx.starts_asking(&mut client, "first", "bound", &a).await);
        // ...and is bound to what ran, with the audit row that says so.
        let rows = fx.daemon.store().active_grants(CAPABILITY).await.unwrap();
        assert_eq!(rows.len(), 1);
        let binding = rows[0].binding.clone().expect("bound on first use");
        assert_eq!(binding.flow_id, "bound");
        assert_eq!(binding.step_id, "change");
        assert_eq!(binding.repository.as_deref(), Some(a.as_str()));
        let audit = fx.daemon.audit_rows("first").await;
        let bound: Vec<_> = audit
            .iter()
            .filter(|row| row.action == ACTION_GRANT_BOUND)
            .collect();
        assert_eq!(bound.len(), 1, "{audit:?}");
        let detail: Value = serde_json::from_str(bound[0].detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["capability"], CAPABILITY);
        assert_eq!(detail["repository"], a.as_str());
        assert_eq!(detail["effect_digest"], binding.effect_digest.as_str());

        // From then on it is a bound grant: the same step goes through
        // without another audit row, another repository asks, an edit asks.
        assert!(!fx.starts_asking(&mut client, "second", "bound", &a).await);
        assert!(
            fx.daemon
                .audit_rows("second")
                .await
                .iter()
                .all(|row| row.action != ACTION_GRANT_BOUND)
        );
        assert!(
            fx.starts_asking(&mut client, "elsewhere", "bound", &b)
                .await
        );
        fx.answer("elsewhere", Resolution::Deny).await;
        fx.edit("bound", BOUND_EDITED);
        assert!(fx.starts_asking(&mut client, "edited", "bound", &a).await);
        fx.answer("edited", Resolution::Deny).await;

        fx.daemon.assert_invariant_clean().await;
        fx.daemon.stop().await;
    }))
    .await;
}

#[tokio::test]
async fn revoking_one_flows_grant_leaves_a_parked_ticket_of_another_flow_alive() {
    Box::pin(with_deadline(async {
        let fx = Fixture::spawn(&[("bound", BOUND), ("other", OTHER)], &[]).await;
        let mut client = fx.daemon.client().await;
        let repo = fx.repo_a();

        assert!(
            fx.starts_asking(&mut client, "x_first", "bound", &repo)
                .await
        );
        fx.answer("x_first", Resolution::Approve { remember: true })
            .await;
        // A ticket of the other flow, parked on its approval.
        assert!(
            fx.starts_asking(&mut client, "y_parked", "other", &repo)
                .await
        );

        admin(
            &mut client,
            "revoke",
            "admin.grants.revoke",
            json!({ "capability": CAPABILITY }),
        )
        .await;

        let store = fx.daemon.store();
        // The revoked flow's ticket is void; the other flow's stands.
        assert!(
            !store
                .request_authorization_current("x_first")
                .await
                .unwrap()
        );
        assert!(
            store
                .request_authorization_current("y_parked")
                .await
                .unwrap()
        );
        fx.answer("y_parked", Resolution::Approve { remember: false })
            .await;
        assert!(
            store
                .request_authorization_current("y_parked")
                .await
                .unwrap()
        );
        // Its result stays readable to its owner.
        let response = client
            .request(&envelope_for_repo(
                &repo,
                "y_result",
                "flow.result",
                json!({ "ticket": "y_parked" }),
                true,
            ))
            .await;
        assert!(
            matches!(response, Response::Result { .. }),
            "the parked ticket's result is still readable: {response:?}"
        );
        // And the revoked flow asks again.
        assert!(
            fx.starts_asking(&mut client, "x_again", "bound", &repo)
                .await
        );
        fx.answer("x_again", Resolution::Deny).await;

        fx.daemon.assert_invariant_clean().await;
        fx.daemon.stop().await;
    }))
    .await;
}
