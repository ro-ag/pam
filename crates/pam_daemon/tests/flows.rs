//! The flow engine end to end: a real daemon on a temp base dir, real
//! zmq, a real `SQLite` store, real child processes.
//!
//! Nothing about a run is faked here except the two things a test must
//! never reach — the OS keychain and the network — which the harness
//! replaces with [`FakeSecretBackend`] and [`FakeTransport`]. The flows
//! themselves are written into the library the daemon reads, the
//! commands are real processes, and the verdicts come back over the
//! socket.
//!
//! # The helper
//!
//! Three endings need a child process that behaves on command — one that
//! outlives its timeout, one that floods the output cap, one that is
//! killed mid-run. `pam-flow-helper` is that process; Cargo builds it
//! with this package and hands its path to integration tests through
//! `CARGO_BIN_EXE_pam-flow-helper`.
//!
//! # Timing
//!
//! Every await is bounded by the harness's wall deadline. Nothing here
//! asserts on a duration: a loaded runner stretches wall time, and the
//! budget only has to catch a hang.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pam_compact::MAX_SOURCE_BYTES;
use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::admin_flows::{
    OP_FLOWS_DELETE, OP_FLOWS_GET, OP_FLOWS_LIST, OP_FLOWS_RUN, OP_FLOWS_SAVE,
};
use pam_daemon::approval::Resolution;
use pam_daemon::daemon::{
    ACTION_EXECUTION_REFUSAL, CAUSE_APPROVAL_DENIED, DAEMON_VERSION, DaemonConfig,
};
use pam_daemon::flow_exec::{CommandOutcome, CommandSpec, run_command};
use pam_daemon::flow_service::{
    CAP_FLOW_LIST, CAP_FLOW_RUN, CAP_FLOW_SHOW, CAUSE_FLOW_NOT_FOUND, CAUSE_OUTPUT_LIMIT,
    CAUSE_PROGRAM_NOT_ALLOWED, CAUSE_REPO_MISSING, CAUSE_TIMEOUT, EVIDENCE_KIND_CONNECTOR_RESULT,
    EVIDENCE_KIND_FLOW_RESULT, step_capability,
};
use pam_daemon::log_service::{EVIDENCE_KIND_LOG_SOURCE, EVIDENCE_KIND_LOG_SUMMARY};
use pam_daemon::model_service::SETTING_DEFAULT_HEAVY;
use pam_daemon::secrets::{SecretBackend, account_for};
use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{EVIDENCE_KIND_LOG_COMPACT, RequestState};
use pam_testkit::{
    FakeSecretBackend, FakeTransport, TestClient, TestDaemon, envelope_for_repo,
    seed_allowed_programs, seed_extra_path, seed_flow, seed_relaxed, short_tempdir, with_deadline,
};
use tokio::sync::watch;

/// The helper binary, for the endings a well-behaved program will not
/// produce on demand.
fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pam-flow-helper"))
}

/// The directory the helper lives in; seeded as the flow extra `PATH` so
/// a step may name `pam-flow-helper` as a bare program.
fn helper_dir() -> String {
    helper()
        .parent()
        .expect("the helper has a directory")
        .display()
        .to_string()
}

/// A daemon whose flow settings allow `git` and the helper, on a repo
/// directory that exists.
struct FlowDaemon {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
}

impl FlowDaemon {
    /// Spawns a daemon with `flows` seeded into its library.
    async fn spawn(flows: &[(&str, &str)]) -> Self {
        Self::spawn_with(flows, |_| {}).await
    }

    /// [`Self::spawn`] with a config mutator (fake keychain, fake
    /// transport, short approval timeout).
    async fn spawn_with(flows: &[(&str, &str)], mutate: impl FnOnce(&mut DaemonConfig)) -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        seed_allowed_programs(&tmp, &["git", "pam-flow-helper"]).await;
        seed_extra_path(&tmp, &[&helper_dir()]).await;
        for (id, yaml) in flows {
            drop(seed_flow(&tmp, id, yaml));
        }
        let repo = short_tempdir();
        Self {
            daemon: TestDaemon::spawn_at_with(tmp, mutate).await,
            repo,
        }
    }

    /// The repo path a flow's command steps run in.
    fn repo(&self) -> String {
        self.repo.path().display().to_string()
    }

    /// A `flow.run` envelope for `id`, waiting for the verdict.
    fn run_envelope(&self, request_id: &str, id: &str, inputs: &serde_json::Value) -> Envelope {
        let mut envelope = envelope_for_repo(
            &self.repo(),
            request_id,
            CAP_FLOW_RUN,
            serde_json::json!({ "id": id, "inputs": inputs }),
            true,
        );
        // A flow that spawns real processes deserves more than the
        // harness's default ten seconds on a loaded runner.
        envelope.deadline_ms = 120_000;
        envelope
    }

    /// Records a grant for one step capability, so a gated step runs
    /// without stopping for a human.
    ///
    /// Under the relaxed profile the gate asks once per destructive or
    /// external capability, and a connector step is external — which is
    /// the point of the approval tests, and noise in the tests that are
    /// about the connector itself.
    async fn grant(&self, capability: &str) {
        self.daemon
            .store()
            .insert_grant(capability)
            .await
            .expect("the grant is recorded");
    }

    /// Runs `id` and returns the verdict body.
    async fn run(&self, client: &mut TestClient, request_id: &str, id: &str) -> serde_json::Value {
        let response = client
            .request(&self.run_envelope(request_id, id, &serde_json::json!({})))
            .await;
        result_body(response)
    }
}

/// A `flow.list` / `flow.show` envelope.
fn read_envelope(id: &str, capability: &str, args: serde_json::Value) -> Envelope {
    envelope_for_repo("/repo/test", id, capability, args, true)
}

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
        deadline_ms: 30_000,
        wait: true,
    }
}

/// Unwraps a result body.
fn result_body(response: Response) -> serde_json::Value {
    match response {
        Response::Result { body, .. } => body,
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Unwraps a result's body and evidence ids.
fn result_parts(response: Response) -> (Outcome, serde_json::Value, Vec<String>) {
    match response {
        Response::Result {
            outcome,
            body,
            evidence,
            ..
        } => (outcome, body, evidence),
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Unwraps a refusal.
fn refusal_parts(response: Response) -> (String, String, String) {
    match response {
        Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } => (cause, detail, recovery),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The step report with this id.
fn step<'a>(body: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    body["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .find(|step| step["id"] == id)
        .unwrap_or_else(|| panic!("no step {id} in {body}"))
}

/// A two-step flow: one command that succeeds, one that verifies.
const TWO_STEP: &str = "schema: 1\n\
id: two-step\n\
name: Two steps\n\
description: proves the engine end to end\n\
steps:\n\
\x20 - id: version\n\
\x20   run: [git, --version]\n\
\x20 - id: prove\n\
\x20   run: [git, --version]\n\
\x20   role: verify\n";

#[tokio::test]
async fn flow_list_and_show_answer_for_the_builtins() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[]).await;
        let mut client = flows.daemon.client().await;

        let body = result_body(
            client
                .request(&read_envelope(
                    "req_list",
                    CAP_FLOW_LIST,
                    serde_json::json!({}),
                ))
                .await,
        );
        let listed = body["flows"].as_array().expect("flows is an array");
        assert_eq!(listed.len(), pam_flow::builtin().len());
        assert!(listed.iter().all(|entry| entry["source"] == "builtin"));

        let body = result_body(
            client
                .request(&read_envelope(
                    "req_show",
                    CAP_FLOW_SHOW,
                    serde_json::json!({ "id": "pr-readiness" }),
                ))
                .await,
        );
        assert_eq!(body["source"], "builtin");
        assert!(
            body["normalized_yaml"]
                .as_str()
                .expect("normalized_yaml is a string")
                .starts_with("schema: 1\n")
        );

        let (cause, _, recovery) = refusal_parts(
            client
                .request(&read_envelope(
                    "req_none",
                    CAP_FLOW_SHOW,
                    serde_json::json!({ "id": "no-such-flow" }),
                ))
                .await,
        );
        assert_eq!(cause, CAUSE_FLOW_NOT_FOUND);
        assert!(recovery.contains("pam flow list"));

        // The refusal wrote exactly one terminal audit row, and it is the
        // executor's own.
        assert_eq!(
            flows.daemon.terminal_audit_actions("req_none").await,
            [ACTION_EXECUTION_REFUSAL]
        );
        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_library_flow_shadows_a_builtin_of_the_same_id() {
    with_deadline(async {
        let shadow = "schema: 1\nid: pr-readiness\nname: My readiness\n\
                      steps:\n  - id: look\n    run: [git, --version]\n";
        let flows = FlowDaemon::spawn(&[("pr-readiness", shadow)]).await;
        let mut client = flows.daemon.client().await;

        let body = result_body(
            client
                .request(&read_envelope(
                    "req_list",
                    CAP_FLOW_LIST,
                    serde_json::json!({}),
                ))
                .await,
        );
        let listed = body["flows"].as_array().expect("flows is an array");
        assert_eq!(listed.len(), pam_flow::builtin().len(), "no duplicate id");
        let entry = listed
            .iter()
            .find(|entry| entry["id"] == "pr-readiness")
            .expect("the shadowed flow is listed");
        assert_eq!(entry["source"], "library");
        assert_eq!(entry["name"], "My readiness");

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_two_step_run_is_verified_and_files_its_verdict_as_evidence() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("two-step", TWO_STEP)]).await;
        let mut client = flows.daemon.client().await;

        let (outcome, body, evidence) = result_parts(
            client
                .request(&flows.run_envelope("req_run", "two-step", &serde_json::json!({})))
                .await,
        );
        assert_eq!(outcome, Outcome::Verified);
        assert_eq!(body["outcome"], "verified");
        assert_eq!(body["flow"]["id"], "two-step");
        assert_eq!(body["flow"]["source"], "library");
        assert_eq!(body["repo"], flows.repo());
        assert_eq!(
            body["summary"].as_str().expect("summary is a string"),
            "2 steps: 2 succeeded"
        );
        for id in ["version", "prove"] {
            let report = step(&body, id);
            assert_eq!(report["status"], "succeeded");
            assert_eq!(report["kind"], "command");
            assert_eq!(report["attempts"], 1);
            assert_eq!(report["exit_status"], 0);
            assert_eq!(
                report["evidence"]
                    .as_array()
                    .expect("evidence is an array")
                    .len(),
                2,
                "each compacted step leaves a source row and a compact row"
            );
        }

        // The verdict is the last evidence row, and its content is the
        // body verbatim.
        let store = flows.daemon.store();
        let rows = store
            .list_evidence("req_run")
            .await
            .expect("evidence list ok");
        let kinds: Vec<&str> = rows.iter().map(|row| row.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                EVIDENCE_KIND_LOG_SOURCE,
                EVIDENCE_KIND_LOG_COMPACT,
                EVIDENCE_KIND_LOG_SOURCE,
                EVIDENCE_KIND_LOG_COMPACT,
                EVIDENCE_KIND_FLOW_RESULT,
            ]
        );
        let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
        assert_eq!(ids, evidence, "the answer lists every row the run left");

        let verdict = store
            .get_evidence(evidence.last().expect("a verdict row"))
            .await
            .expect("evidence get ok")
            .expect("the verdict row exists");
        let stored: serde_json::Value =
            serde_json::from_slice(&verdict.content).expect("the verdict is JSON");
        assert_eq!(stored, body, "the filed verdict is the answered body");
        let meta: serde_json::Value =
            serde_json::from_str(verdict.meta_json.as_deref().expect("the verdict has meta"))
                .expect("the meta is JSON");
        assert_eq!(
            meta,
            serde_json::json!({
                "flow": "two-step",
                "outcome": "verified",
                "steps": 2,
                "failed": 0,
            })
        );

        flows
            .daemon
            .assert_row_state("req_run", RequestState::Done)
            .await;
        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_failing_step_is_unresolved_with_its_exit_status_and_attempts() {
    with_deadline(async {
        let yaml = "schema: 1\nid: failing\nname: Failing\n\
                    steps:\n\
                    \x20 - id: bad\n    run: [pam-flow-helper, exit, '3']\n\
                    \x20   retry: { attempts: 2, backoff: 1ms }\n\
                    \x20 - id: after\n    run: [git, --version]\n    needs: [bad]\n";
        let flows = FlowDaemon::spawn(&[("failing", yaml)]).await;
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "failing").await;
        assert_eq!(body["outcome"], "unresolved");
        let bad = step(&body, "bad");
        assert_eq!(bad["status"], "failed");
        assert_eq!(bad["exit_status"], 3);
        assert_eq!(bad["attempts"], 2, "the retry is counted");
        assert_eq!(bad["error"]["cause"], "exit_status");
        // `needs: [bad]` was not satisfied, so the next step never ran.
        assert_eq!(step(&body, "after")["status"], "skipped");
        assert!(
            body["summary"]
                .as_str()
                .expect("summary is a string")
                .contains("(bad, exit 3)")
        );

        flows
            .daemon
            .assert_row_state("req_run", RequestState::Done)
            .await;
        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_when_failed_step_runs_only_after_a_failure() {
    with_deadline(async {
        let yaml = "schema: 1\nid: conditional\nname: Conditional\n\
                    steps:\n\
                    \x20 - id: bad\n    run: [pam-flow-helper, exit, '1']\n\
                    \x20 - id: rescue\n    run: [git, --version]\n    when: { failed: bad }\n\
                    \x20 - id: never\n    run: [git, --version]\n    when: { succeeded: bad }\n";
        let flows = FlowDaemon::spawn(&[("conditional", yaml)]).await;
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "conditional").await;
        assert_eq!(step(&body, "bad")["status"], "failed");
        assert_eq!(step(&body, "rescue")["status"], "succeeded");
        assert_eq!(step(&body, "never")["status"], "skipped");

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_step_that_outlives_its_timeout_ends_the_run_unresolved() {
    with_deadline(async {
        let yaml = "schema: 1\nid: slow\nname: Slow\n\
                    steps:\n\
                    \x20 - id: nap\n    run: [pam-flow-helper, sleep, '600000']\n\
                    \x20   timeout: 1s\n";
        let flows = FlowDaemon::spawn(&[("slow", yaml)]).await;
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "slow").await;
        assert_eq!(body["outcome"], "unresolved");
        let nap = step(&body, "nap");
        assert_eq!(nap["status"], "failed");
        assert_eq!(nap["error"]["cause"], CAUSE_TIMEOUT);
        assert!(
            nap["error"]["recovery"]
                .as_str()
                .expect("recovery")
                .contains("timeout")
        );

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_step_past_the_output_cap_is_killed() {
    with_deadline(async {
        let bytes = MAX_SOURCE_BYTES + 1;
        let yaml = format!(
            "schema: 1\nid: loud\nname: Loud\n\
             steps:\n\
             \x20 - id: spew\n    run: [pam-flow-helper, spew, '{bytes}']\n\
             \x20   output: discard\n"
        );
        let flows = FlowDaemon::spawn(&[("loud", &yaml)]).await;
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "loud").await;
        assert_eq!(body["outcome"], "unresolved");
        assert_eq!(step(&body, "spew")["error"]["cause"], CAUSE_OUTPUT_LIMIT);

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn cancelling_mid_step_stops_the_run_and_the_child() {
    with_deadline(async {
        let yaml = "schema: 1\nid: napping\nname: Napping\n\
                    steps:\n\
                    \x20 - id: nap\n    run: [pam-flow-helper, sleep, '600000']\n\
                    \x20   timeout: 300s\n";
        let flows = FlowDaemon::spawn(&[("napping", yaml)]).await;
        let mut client = flows.daemon.client().await;
        let mut cancel_client = flows.daemon.client().await;

        // Start the run without waiting, so the cancel has a client of
        // its own to travel on.
        let mut envelope = flows.run_envelope("req_run", "napping", &serde_json::json!({}));
        envelope.wait = false;
        client.request(&envelope).await;
        flows
            .daemon
            .wait_for_row("req_run", |row| row.state == RequestState::Running)
            .await;

        let response = cancel_client
            .request(&envelope_for_repo(
                &flows.repo(),
                "req_cancel",
                "cancel",
                serde_json::json!({ "ticket": "req_run" }),
                true,
            ))
            .await;
        assert_eq!(result_body(response)["result"], "signalled_running");

        let row = flows
            .daemon
            .wait_for_row("req_run", |row| row.state.is_terminal())
            .await;
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some("cancelled"));

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_program_that_is_not_allowed_blocks_the_run() {
    with_deadline(async {
        let yaml = "schema: 1\nid: forbidden\nname: Forbidden\n\
                    steps:\n\
                    \x20 - id: build\n    run: [cargo, --version]\n\
                    \x20 - id: after\n    run: [git, --version]\n    when: always\n";
        let flows = FlowDaemon::spawn(&[("forbidden", yaml)]).await;
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "forbidden").await;
        assert_eq!(body["outcome"], "blocked");
        let build = step(&body, "build");
        assert_eq!(build["status"], "blocked");
        assert_eq!(build["error"]["cause"], CAUSE_PROGRAM_NOT_ALLOWED);
        assert_eq!(
            build["error"]["recovery"],
            "open Pam → Settings → Flows → allowed programs"
        );
        // A block stops the run: the `when: always` step never ran.
        assert_eq!(body["steps"].as_array().expect("steps").len(), 1);

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_missing_repo_refuses_before_anything_runs() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("two-step", TWO_STEP)]).await;
        let mut client = flows.daemon.client().await;
        let mut envelope = envelope_for_repo(
            "/definitely/not/a/directory",
            "req_run",
            CAP_FLOW_RUN,
            serde_json::json!({ "id": "two-step" }),
            true,
        );
        envelope.deadline_ms = 60_000;

        let (cause, _, _) = refusal_parts(client.request(&envelope).await);
        assert_eq!(cause, CAUSE_REPO_MISSING);
        flows
            .daemon
            .assert_row_state("req_run", RequestState::Refused)
            .await;
        assert_eq!(
            flows.daemon.terminal_audit_actions("req_run").await,
            [ACTION_EXECUTION_REFUSAL]
        );

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn every_step_publishes_a_running_note_then_its_settle_note() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("two-step", TWO_STEP)]).await;
        let mut client = flows.daemon.client().await;
        let mut events = flows.daemon.subscribe(&["req_run"]).await;

        let body = flows.run(&mut client, "req_run", "two-step").await;
        assert_eq!(step(&body, "version")["status"], "succeeded");
        assert_eq!(step(&body, "prove")["status"], "succeeded");

        let seen: Vec<Event> = events.until_terminal("req_run").await;
        let notes: Vec<String> = seen
            .into_iter()
            .filter_map(|event| match event {
                Event::Progress { note, .. } => Some(note),
                _ => None,
            })
            .collect();
        assert_eq!(
            notes,
            vec![
                "version: running (1/2)".to_owned(),
                "version: succeeded".to_owned(),
                "prove: running (2/2)".to_owned(),
                "prove: succeeded".to_owned(),
            ]
        );

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

/// A stateful step, which the gate always asks about.
const STATEFUL: &str = "schema: 1\n\
id: stateful\n\
name: Stateful\n\
steps:\n\
\x20 - id: change\n\
\x20   run: [git, --version]\n\
\x20   effect: stateful\n";

#[tokio::test]
async fn a_stateful_step_pauses_and_a_remembered_approval_spares_the_next_run() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("stateful", STATEFUL)]).await;
        let mut client = flows.daemon.client().await;
        let mut events = flows.daemon.subscribe(&["req_run"]).await;

        let mut envelope = flows.run_envelope("req_run", "stateful", &serde_json::json!({}));
        envelope.wait = false;
        client.request(&envelope).await;

        // The run parks the whole request in `waiting_approval`.
        flows
            .daemon
            .wait_for_row("req_run", |row| row.state == RequestState::WaitingApproval)
            .await;
        let pending = flows
            .daemon
            .handle()
            .approvals()
            .pending()
            .await
            .expect("pending approvals");
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].capability,
            step_capability("stateful", "change"),
            "the human is asked about the step, not the flow"
        );
        flows
            .daemon
            .handle()
            .approvals()
            .resolve("req_run", Resolution::Approve { remember: true })
            .await
            .expect("the approval is delivered");

        let row = flows
            .daemon
            .wait_for_row("req_run", |row| row.state.is_terminal())
            .await;
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("changed"));

        let seen: Vec<Event> = events.until_terminal("req_run").await;
        assert!(seen.contains(&Event::ApprovalPending));
        assert!(seen.contains(&Event::Done));

        // Remembered: the second run never pauses.
        let body = flows.run(&mut client, "req_again", "stateful").await;
        assert_eq!(body["outcome"], "changed");
        assert_eq!(step(&body, "change")["status"], "succeeded");
        flows
            .daemon
            .assert_row_state("req_again", RequestState::Done)
            .await;

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_denied_approval_blocks_the_run_with_one_terminal_row() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("stateful", STATEFUL)]).await;
        let mut client = flows.daemon.client().await;

        let mut envelope = flows.run_envelope("req_run", "stateful", &serde_json::json!({}));
        envelope.wait = false;
        client.request(&envelope).await;
        flows
            .daemon
            .wait_for_row("req_run", |row| row.state == RequestState::WaitingApproval)
            .await;
        flows
            .daemon
            .handle()
            .approvals()
            .resolve("req_run", Resolution::Deny)
            .await
            .expect("the denial is delivered");

        let row = flows
            .daemon
            .wait_for_row("req_run", |row| row.state.is_terminal())
            .await;
        // A denied step is a blocked *result*, not a refusal: the run
        // finished and filed a verdict saying which step and why.
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("blocked"));

        let approvals: Vec<_> = flows
            .daemon
            .audit_rows("req_run")
            .await
            .into_iter()
            .filter(|audit| audit.action == "approval")
            .collect();
        assert_eq!(approvals.len(), 1, "one approval row for one question");

        let store = flows.daemon.store();
        let listed = store
            .list_evidence("req_run")
            .await
            .expect("evidence list ok")
            .into_iter()
            .find(|row| row.kind == EVIDENCE_KIND_FLOW_RESULT)
            .expect("the verdict was filed");
        let verdict = store
            .get_evidence(&listed.id)
            .await
            .expect("evidence get ok")
            .expect("the verdict row exists");
        let body: serde_json::Value =
            serde_json::from_slice(&verdict.content).expect("the verdict is JSON");
        assert_eq!(body["outcome"], "blocked");
        assert_eq!(
            step(&body, "change")["error"]["cause"],
            CAUSE_APPROVAL_DENIED
        );
        assert_eq!(
            step(&body, "change")["error"]["recovery"],
            "open Pam → Approvals"
        );

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

/// A connector step feeding the next step's argv.
const CONNECTED: &str = "schema: 1\n\
id: connected\n\
name: Connected\n\
inputs:\n\
\x20 repo:\n\
\x20   description: owner/name on GitHub\n\
\x20   default: ro-ag/pam\n\
steps:\n\
\x20 - id: runs\n\
\x20   connector: github\n\
\x20   call: runs\n\
\x20   with: { repo: '${inputs.repo}', limit: 1 }\n\
\x20 - id: echo\n\
\x20   run: [pam-flow-helper, echo-env, PAM_STEP]\n\
\x20   env: { PAM_MARKER: '${steps.runs.result.runs[0].id}' }\n";

/// Enables GitHub through the admin surface, with a credential in the
/// fake keychain.
async fn enable_github(client: &mut TestClient) {
    let response = client
        .request(&admin_envelope(
            "req_conf",
            "admin.connectors.configure",
            serde_json::json!({
                "id": "github",
                "enabled": true,
                "base_url": "https://api.github.test/",
                "credential": { "set": "ghp_only_the_fake_store_sees_this" },
            }),
        ))
        .await;
    assert!(
        matches!(response, Response::Result { .. }),
        "github is configured: {response:?}"
    );
}

#[tokio::test]
async fn a_connector_step_files_its_result_and_feeds_the_next_step() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new().json(
            200,
            r#"{"workflow_runs":[{"id":4242,"name":"ci","status":"completed","conclusion":"failure"}]}"#,
        ));
        let (backend_arc, transport_arc) = (Arc::clone(&backend), Arc::clone(&transport));
        let flows = FlowDaemon::spawn_with(&[("connected", CONNECTED)], move |config| {
            config.secret_backend = Some(backend_arc as Arc<dyn SecretBackend>);
            config.http_transport = Some(transport_arc);
        })
        .await;
        let mut client = flows.daemon.client().await;
        enable_github(&mut client).await;
        flows.grant(&step_capability("connected", "runs")).await;

        let body = flows.run(&mut client, "req_run", "connected").await;
        assert_eq!(body["outcome"], "solved");
        assert_eq!(body["inputs"]["repo"], "ro-ag/pam");

        let runs = step(&body, "runs");
        assert_eq!(runs["kind"], "connector");
        assert_eq!(runs["status"], "succeeded");
        let evidence = runs["evidence"].as_array().expect("evidence is an array");
        assert_eq!(evidence.len(), 1);

        let store = flows.daemon.store();
        let row = store
            .get_evidence(evidence[0].as_str().expect("an evidence id"))
            .await
            .expect("evidence get ok")
            .expect("the connector result exists");
        assert_eq!(row.kind, EVIDENCE_KIND_CONNECTOR_RESULT);
        let result: serde_json::Value =
            serde_json::from_slice(&row.content).expect("the result is JSON");
        assert_eq!(result["runs"][0]["id"], 4242);
        let meta: serde_json::Value =
            serde_json::from_str(row.meta_json.as_deref().expect("meta")).expect("meta is JSON");
        assert_eq!(meta["connector"], "github");
        assert_eq!(meta["call"], "runs");

        // `${steps.runs.result.runs[0].id}` reached the second step's env.
        assert_eq!(step(&body, "echo")["status"], "succeeded");
        assert!(transport.url(0).contains("/repos/ro-ag/pam/actions/runs"));
        assert!(
            backend
                .get(&account_for("github"))
                .expect("backend ok")
                .is_some()
        );
        // The credential never reaches the verdict.
        assert!(!body.to_string().contains("ghp_"));

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn a_disabled_connector_blocks_the_step_with_the_settings_line() {
    with_deadline(async {
        let backend = Arc::new(FakeSecretBackend::default());
        let transport = Arc::new(FakeTransport::new());
        let flows = FlowDaemon::spawn_with(&[("connected", CONNECTED)], move |config| {
            config.secret_backend = Some(backend as Arc<dyn SecretBackend>);
            config.http_transport = Some(transport);
        })
        .await;
        let mut client = flows.daemon.client().await;
        flows.grant(&step_capability("connected", "runs")).await;

        let body = flows.run(&mut client, "req_run", "connected").await;
        assert_eq!(body["outcome"], "blocked");
        let runs = step(&body, "runs");
        assert_eq!(runs["status"], "blocked");
        assert_eq!(runs["error"]["cause"], "connector_disabled");
        assert_eq!(
            runs["error"]["recovery"],
            "open Pam → Settings → Connectors → GitHub → enable it"
        );

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_flows_run_submits_through_the_pipeline_as_the_gui() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[("two-step", TWO_STEP)]).await;
        let mut client = flows.daemon.client().await;

        let body = result_body(
            client
                .request(&admin_envelope(
                    "req_admin_run",
                    OP_FLOWS_RUN,
                    serde_json::json!({ "id": "two-step", "repo": flows.repo() }),
                ))
                .await,
        );
        let ticket = body["ticket"].as_str().expect("a ticket").to_owned();
        assert!(ticket.starts_with("req_"));

        let row = flows
            .daemon
            .wait_for_row(&ticket, |row| row.state.is_terminal())
            .await;
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.outcome.as_deref(), Some("verified"));
        assert_eq!(row.capability, CAP_FLOW_RUN);
        assert_eq!(row.caller_agent, ADMIN_CALLER_AGENT);
        assert_eq!(row.repo, flows.repo());

        // The run went through the ordinary pipeline, so it carries the
        // ordinary single terminal audit row.
        flows.daemon.assert_single_terminal_audit(&ticket).await;
        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

#[tokio::test]
async fn admin_flows_save_get_and_delete_reach_the_library_the_daemon_reads() {
    with_deadline(async {
        let flows = FlowDaemon::spawn(&[]).await;
        let mut client = flows.daemon.client().await;

        let saved = result_body(
            client
                .request(&admin_envelope(
                    "req_save",
                    OP_FLOWS_SAVE,
                    serde_json::json!({ "id": "two-step", "yaml": TWO_STEP }),
                ))
                .await,
        );
        assert_eq!(saved["source"], "library");

        // The library file is where a daemon on this base dir looks.
        let path = flows.daemon.base_dir().join("flows/two-step.yaml");
        assert!(path.is_file(), "{} was not written", path.display());

        let listed = result_body(
            client
                .request(&admin_envelope(
                    "req_list",
                    OP_FLOWS_LIST,
                    serde_json::json!({}),
                ))
                .await,
        );
        assert!(
            listed["flows"]
                .as_array()
                .expect("flows is an array")
                .iter()
                .any(|entry| entry["id"] == "two-step")
        );

        let got = result_body(
            client
                .request(&admin_envelope(
                    "req_get",
                    OP_FLOWS_GET,
                    serde_json::json!({ "id": "two-step" }),
                ))
                .await,
        );
        assert_eq!(got["flow"]["steps"].as_array().expect("steps").len(), 2);

        // And the running daemon can immediately run what was saved.
        let body = flows.run(&mut client, "req_run", "two-step").await;
        assert_eq!(body["outcome"], "verified");

        let deleted = result_body(
            client
                .request(&admin_envelope(
                    "req_delete",
                    OP_FLOWS_DELETE,
                    serde_json::json!({ "id": "two-step" }),
                ))
                .await,
        );
        assert_eq!(deleted["revealed_builtin"], false);
        assert!(!path.exists());

        flows.daemon.assert_invariant_clean().await;
        flows.daemon.stop().await;
    })
    .await;
}

// --- `run_command` endings that need a purpose-built child ---------------

/// A cancel channel that never fires.
fn live_cancel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// A spec that runs the helper.
fn helper_spec(argv: &[&str], timeout: Duration) -> CommandSpec {
    CommandSpec {
        program: helper(),
        argv: argv.iter().map(|part| (*part).to_owned()).collect(),
        cwd: std::env::temp_dir(),
        env: Vec::new(),
        timeout,
    }
}

#[tokio::test]
async fn run_command_kills_a_child_that_outlives_its_timeout() {
    with_deadline(async {
        let (_alive, mut cancel) = live_cancel();
        let outcome = run_command(
            helper_spec(&["sleep", "600000"], Duration::from_millis(200)),
            &mut cancel,
        )
        .await;
        assert!(
            matches!(outcome, CommandOutcome::TimedOut { .. }),
            "expected a timeout, got {outcome:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn run_command_stops_a_child_past_the_output_cap() {
    with_deadline(async {
        let bytes = MAX_SOURCE_BYTES + 1;
        let outcome = run_command(
            helper_spec(&["spew", &bytes.to_string()], Duration::from_mins(2)),
            &mut live_cancel().1,
        )
        .await;
        match outcome {
            CommandOutcome::OutputLimit { output } => assert_eq!(output.len(), MAX_SOURCE_BYTES),
            other => panic!("expected the output cap, got {other:?}"),
        }
    })
    .await;
}

#[tokio::test]
async fn run_command_stops_on_the_cancel_signal() {
    with_deadline(async {
        let (alive, mut cancel) = live_cancel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = alive.send(true);
        });
        let outcome = run_command(
            helper_spec(&["sleep", "600000"], Duration::from_mins(5)),
            &mut cancel,
        )
        .await;
        assert_eq!(outcome, CommandOutcome::Cancelled);
    })
    .await;
}

#[tokio::test]
async fn the_helper_reads_the_environment_a_step_gives_it() {
    with_deadline(async {
        let mut spec = helper_spec(&["echo-env", "PAM_FLOW"], Duration::from_secs(30));
        spec.env = vec![("PAM_FLOW".to_owned(), "two-step".to_owned())];
        match run_command(spec, &mut live_cancel().1).await {
            CommandOutcome::Exited { status, output } => {
                assert_eq!(status, 0);
                assert_eq!(String::from_utf8_lossy(&output).trim(), "two-step");
            }
            other => panic!("expected a clean exit, got {other:?}"),
        }
    })
    .await;
}

// --- opt-in ------------------------------------------------------------

/// `output: summarize` against a real model, when one is configured.
///
/// Skipped unless `PAM_BENCH_MODEL` names a registry id: the workspace
/// gate must not depend on weights being present.
#[tokio::test]
async fn summarize_asks_the_model_when_pam_bench_model_names_one() {
    let Ok(model) = std::env::var("PAM_BENCH_MODEL") else {
        eprintln!("PAM_BENCH_MODEL is unset; skipping the summarize test");
        return;
    };
    with_deadline(async {
        let yaml = "schema: 1\nid: summarized\nname: Summarized\n\
                    steps:\n\
                    \x20 - id: version\n    run: [git, --version]\n    output: summarize\n";
        let flows = FlowDaemon::spawn(&[("summarized", yaml)]).await;
        flows
            .daemon
            .store()
            .set_setting(SETTING_DEFAULT_HEAVY, &format!("\"{model}\""))
            .await
            .expect("the heavy default persists");
        let mut client = flows.daemon.client().await;

        let body = flows.run(&mut client, "req_run", "summarized").await;
        let version = step(&body, "version");
        assert_eq!(version["status"], "succeeded");
        assert!(
            version["summary"].is_string(),
            "a summarize step reports either a summary or why there is none"
        );
        let rows = flows
            .daemon
            .store()
            .list_evidence("req_run")
            .await
            .expect("evidence list ok");
        assert!(
            rows.iter().any(|row| row.kind == EVIDENCE_KIND_LOG_SUMMARY),
            "the model wrote a summary row"
        );

        flows.daemon.stop().await;
    })
    .await;
}

async fn sonar_test_daemon(yaml: &str, transport: Arc<FakeTransport>) -> FlowDaemon {
    let flows = FlowDaemon::spawn_with(&[("sonar-gate-check", yaml)], move |config| {
        config.secret_backend = Some(Arc::new(FakeSecretBackend::default()));
        config.http_transport = Some(transport);
    })
    .await;
    let mut client = flows.daemon.client().await;
    let response = client
        .request(&admin_envelope(
            "req_conf",
            "admin.connectors.configure",
            serde_json::json!({
                "id": "sonarqube", "enabled": true, "base_url": "https://sonar.test/",
                "credential": { "set": "sonar_test_credential" }
            }),
        ))
        .await;
    assert!(matches!(response, Response::Result { .. }), "{response:?}");
    for id in ["quality-gate", "open-issues"] {
        flows.grant(&step_capability("sonar-gate-check", id)).await;
    }
    flows
}

async fn sonar_run(flows: &FlowDaemon) -> serde_json::Value {
    let mut client = flows.daemon.client().await;
    result_body(
        client
            .request(&flows.run_envelope(
                "req_run",
                "sonar-gate-check",
                &serde_json::json!({"project": "pam"}),
            ))
            .await,
    )
}

async fn assert_sonar_evidence(
    flows: &FlowDaemon,
    body: &serde_json::Value,
    expected_status: Option<&str>,
) {
    let store = flows.daemon.store();
    if let Some(status) = expected_status {
        let id = step(body, "quality-gate")["evidence"][0].as_str().unwrap();
        let evidence = store.get_evidence(id).await.unwrap().unwrap();
        assert_eq!(evidence.kind, EVIDENCE_KIND_CONNECTOR_RESULT);
        let saved: serde_json::Value = serde_json::from_slice(&evidence.content).unwrap();
        assert_eq!(saved["status"], status);
    }
    let verdict = store
        .list_evidence("req_run")
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.kind == EVIDENCE_KIND_FLOW_RESULT)
        .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(
        &store
            .get_evidence(&verdict.id)
            .await
            .unwrap()
            .unwrap()
            .content,
    )
    .unwrap();
    assert_eq!(saved["outcome"], body["outcome"]);
    assert_eq!(
        step(&saved, "quality-gate")["error"],
        step(body, "quality-gate")["error"]
    );
    assert_eq!(step(&saved, "open-issues")["status"], "succeeded");
}

#[tokio::test]
async fn sonar_gate_verification_requires_explicit_ok_and_retains_failure_evidence() {
    for (http, response, status, cause) in [
        (
            200,
            r#"{"projectStatus":{"status":"OK","conditions":[]}}"#,
            Some("OK"),
            None,
        ),
        (
            200,
            r#"{"projectStatus":{"status":"ERROR","conditions":[]}}"#,
            Some("ERROR"),
            Some("status_assertion"),
        ),
        (
            200,
            r#"{"projectStatus":{"status":"UNKNOWN","conditions":[]}}"#,
            Some("UNKNOWN"),
            Some("status_assertion"),
        ),
        (
            200,
            r#"{"projectStatus":{"conditions":[]}}"#,
            None,
            Some("connector_bad_response"),
        ),
        (
            500,
            r#"{"error":"service unavailable"}"#,
            None,
            Some("connector_remote"),
        ),
    ] {
        with_deadline(async {
            let transport = Arc::new(
                FakeTransport::new()
                    .json(http, response)
                    .json(200, r#"{"issues":[],"total":0}"#),
            );
            let flows = sonar_test_daemon(
                pam_flow::builtin_yaml("sonar-gate-check").unwrap(),
                Arc::clone(&transport),
            )
            .await;
            let body = sonar_run(&flows).await;
            assert_eq!(
                body["outcome"],
                if cause.is_none() {
                    "verified"
                } else {
                    "unresolved"
                },
                "{body}"
            );
            let gate = step(&body, "quality-gate");
            assert_eq!(
                gate["status"],
                if cause.is_none() {
                    "succeeded"
                } else {
                    "failed"
                }
            );
            if let Some(cause) = cause {
                assert_eq!(gate["error"]["cause"], cause);
            }
            assert_eq!(step(&body, "open-issues")["status"], "succeeded");
            assert!(transport.url(1).contains("/api/issues/search"));
            assert_sonar_evidence(&flows, &body, status).await;
            flows.daemon.assert_invariant_clean().await;
            flows.daemon.stop().await;
        })
        .await;
    }
}

#[tokio::test]
async fn sonar_failed_status_assertion_retries_before_issues() {
    with_deadline(async {
        let transport = Arc::new(
            FakeTransport::new()
                .json(
                    200,
                    r#"{"projectStatus":{"status":"ERROR","conditions":[]}}"#,
                )
                .json(200, r#"{"projectStatus":{"status":"OK","conditions":[]}}"#)
                .json(200, r#"{"issues":[],"total":0}"#),
        );
        let yaml = pam_flow::builtin_yaml("sonar-gate-check").unwrap().replace(
            "    expect_status: OK",
            "    expect_status: OK\n    retry: { attempts: 2, backoff: 1ms }",
        );
        let flows = sonar_test_daemon(&yaml, Arc::clone(&transport)).await;
        let body = sonar_run(&flows).await;
        assert_eq!(body["outcome"], "verified");
        assert_eq!(step(&body, "quality-gate")["attempts"], 2);
        assert!(
            transport
                .url(1)
                .contains("/api/qualitygates/project_status")
        );
        assert!(transport.url(2).contains("/api/issues/search"));
        assert_sonar_evidence(&flows, &body, Some("OK")).await;
        flows.daemon.stop().await;
    })
    .await;
}

/// Substitute only child executables, keeping the shipped gate order, roles
/// and dependency edges; this proves verdict propagation, not the gate tools.
fn readiness_failure_fixture(fail_at: Option<usize>) -> String {
    let mut flow = pam_flow::parse(pam_flow::builtin_yaml("pam-pr-readiness").unwrap()).unwrap();
    for (index, step) in flow.steps.iter_mut().enumerate() {
        step.action = pam_flow::Action::Command {
            argv: [
                "pam-flow-helper",
                "exit",
                if fail_at == Some(index) { "17" } else { "0" },
            ]
            .map(str::to_owned)
            .to_vec(),
        };
    }
    pam_flow::to_normalized_yaml(&flow)
}

#[tokio::test]
async fn pam_readiness_any_gate_failure_prevents_verified_and_skips_dependents() {
    for fail_at in [None, Some(1), Some(2), Some(3), Some(4), Some(5), Some(6)] {
        with_deadline(async {
            let yaml = readiness_failure_fixture(fail_at);
            let flows = FlowDaemon::spawn(&[("pam-pr-readiness", &yaml)]).await;
            let mut client = flows.daemon.client().await;
            let body = flows.run(&mut client, "req_run", "pam-pr-readiness").await;
            assert_eq!(
                body["outcome"],
                if fail_at.is_none() {
                    "verified"
                } else {
                    "unresolved"
                },
                "{body}"
            );
            for (index, step) in body["steps"].as_array().unwrap().iter().enumerate() {
                let expected = match fail_at {
                    Some(failed) if index == failed => "failed",
                    Some(failed) if index > failed => "skipped",
                    _ => "succeeded",
                };
                assert_eq!(step["status"], expected, "{body}");
                if expected == "failed" {
                    assert_eq!(step["exit_status"], 17);
                    assert_eq!(step["error"]["cause"], "exit_status");
                }
            }
            let evidence = flows.daemon.store().list_evidence("req_run").await.unwrap();
            assert!(
                evidence
                    .iter()
                    .any(|row| row.kind == EVIDENCE_KIND_FLOW_RESULT)
            );
            flows.daemon.assert_invariant_clean().await;
            flows.daemon.stop().await;
        })
        .await;
    }
}

/// Run the already-built integration-test executable directly with --ignored
/// and `PAM_READINESS_REPO` set. Never invoke under an outer Cargo process: the
/// actual shipped flow starts Cargo itself. No command substitution or mocks.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "explicit real PAM repository validation; run compiled test directly without outer Cargo"]
async fn pam_readiness_runs_all_real_project_gates() {
    let repo = std::env::var("PAM_READINESS_REPO")
        .expect("PAM_READINESS_REPO must name the clean PAM checkout");
    let tmp = short_tempdir();
    seed_relaxed(&tmp).await;
    seed_allowed_programs(&tmp, &["git", "cargo", "npm"]).await;
    let daemon = TestDaemon::spawn_at(tmp).await;
    let mut client = daemon.client().await;
    let mut envelope = envelope_for_repo(
        &repo,
        "req_real_readiness",
        CAP_FLOW_RUN,
        serde_json::json!({"id": "pam-pr-readiness"}),
        false,
    );
    envelope.deadline_ms = 7_200_000;
    assert!(matches!(
        client.request(&envelope).await,
        Response::Ticket { .. }
    ));
    tokio::time::timeout(Duration::from_mins(10), async {
        loop {
            let row = daemon
                .store()
                .get_request("req_real_readiness")
                .await
                .unwrap()
                .unwrap();
            if row.state.is_terminal() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("actual readiness finishes within two hours");
    let verdict = daemon
        .store()
        .list_evidence("req_real_readiness")
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.kind == EVIDENCE_KIND_FLOW_RESULT)
        .expect("real flow retains its verdict");
    let evidence = daemon
        .store()
        .get_evidence(&verdict.id)
        .await
        .unwrap()
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&evidence.content).unwrap();
    println!(
        "PAM_READINESS_PROOF {}",
        serde_json::to_string(&body).unwrap()
    );
    daemon.stop().await;
    assert_eq!(body["outcome"], "verified", "{body}");
    let steps = body["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 7);
    for (step, id) in steps.iter().zip([
        "clean-tree",
        "fmt",
        "clippy",
        "tests",
        "frontend-lint",
        "frontend-build",
        "frontend-tests",
    ]) {
        assert_eq!(step["id"], id);
        assert_eq!(step["status"], "succeeded", "{body}");
        assert_eq!(step["exit_status"], 0, "{body}");
    }
}
