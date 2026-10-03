use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, Event, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::daemon::{CompletionRouter, Registration};
use crate::executor::{BuiltinCapability, CapabilityFailure, ExecContext, outcome_str};
use crate::flow_service::FlowService;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::policy::{CapabilityClass, classify};
use crate::queue::{ACTION_CANCEL, AdmitOutcome, CAUSE_CANCELLED, QueueManager};
use crate::secrets::{FakeSecretBackend, SecretStore};
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(5);

struct Fixture {
    store: Arc<Store>,
    queue: Arc<QueueManager>,
    models: Arc<ModelService>,
    approvals: Arc<ApprovalService>,
    flows: Arc<FlowService>,
    /// Over a fake backend: no test in this codebase touches a real
    /// keychain, so `status` reports a reachable one here.
    secrets: Arc<SecretStore>,
    router: CompletionRouter,
    events: EventPublisher,
    events_rx: mpsc::Receiver<(String, Event)>,
}

async fn fixture() -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let queue = Arc::new(QueueManager::new(Arc::clone(&store)));
    let models = ModelService::new(
        Arc::clone(&store),
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
    .unwrap();
    let (events, events_rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events.clone(),
        DEADLINE,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let flows = crate::flow_service_test::flows_for_tests(
        std::path::Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    Fixture {
        store,
        queue,
        models,
        approvals,
        flows,
        secrets: Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default()))),
        router: CompletionRouter::new(),
        events,
        events_rx,
    }
}

impl Fixture {
    fn ctx(
        &self,
        request_id: &str,
        args: serde_json::Value,
        cancel: watch::Receiver<bool>,
    ) -> ExecContext {
        ExecContext {
            origin: crate::ingress::Origin::Public,
            peer: pam_store::RequestOrigin::PUBLIC,
            status: crate::status_cache::StatusCache::new(
                Arc::clone(&self.models),
                Arc::clone(&self.secrets),
            ),
            budget: crate::request_budget::RequestBudget::new(
                std::time::Instant::now() + std::time::Duration::from_hours(1),
            ),
            request_id: request_id.to_owned(),
            args,
            cancel,
            events: self.events.clone(),
            store: Arc::clone(&self.store),
            queue: Arc::clone(&self.queue),
            models: Arc::clone(&self.models),
            router: self.router.clone(),
            approvals: Arc::clone(&self.approvals),
            flows: Arc::clone(&self.flows),
            secrets: Arc::clone(&self.secrets),
            caller: Caller {
                agent: "claude".to_owned(),
                repo: "/repo/test".to_owned(),
                pid: 4242,
            },
            capability: "echo".to_owned(),
            started_at: std::time::Instant::now(),
        }
    }

    /// A context for capabilities that never look at the cancel signal
    /// (the sender is dropped; only `echo` with `delay_ms` polls it).
    fn ctx_uncancelled(&self, request_id: &str, args: serde_json::Value) -> ExecContext {
        let (_tx, rx) = watch::channel(false);
        self.ctx(request_id, args, rx)
    }
}

fn envelope(id: &str, args: serde_json::Value) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "echo".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: "/repo/a".to_owned(),
            pid: 4242,
        },
        args,
        idempotency_key: None,
        deadline_ms: 60_000,
        wait: true,
    }
}

#[test]
fn registry_names_round_trip_and_cover_classify() {
    for name in [
        "status",
        "query",
        "echo",
        "cancel",
        "flow.run",
        "flow.list",
        "flow.show",
        "flow.inspect",
        "flow.result",
        "evidence.read",
    ] {
        let capability = BuiltinCapability::from_name(name).unwrap();
        assert_eq!(capability.name(), name);
        assert!(
            classify(name).is_some(),
            "{name} must be classified as well as dispatchable"
        );
    }
    assert_eq!(BuiltinCapability::from_name("frobnicate"), None);
}

#[test]
fn outcome_str_matches_the_wire_names() {
    assert_eq!(outcome_str(Outcome::Solved), "solved");
    assert_eq!(outcome_str(Outcome::Changed), "changed");
    assert_eq!(outcome_str(Outcome::Verified), "verified");
    assert_eq!(outcome_str(Outcome::Unresolved), "unresolved");
    assert_eq!(outcome_str(Outcome::Blocked), "blocked");
}

#[tokio::test]
async fn status_reports_versions_uptime_and_inflight_count() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        // One in-flight (queued) request on record.
        fx.store
            .insert_request("req_other", "echo", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();

        let ctx = fx.ctx_uncancelled("req_status", serde_json::json!({}));
        // The daemon's background task does this; a bare context has none.
        ctx.status.refresh().await;
        let output = BuiltinCapability::Status.execute(ctx).await.unwrap();

        assert_eq!(output.outcome, Outcome::Verified);
        assert_eq!(output.body["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(output.body["protocol"], PROTOCOL_VERSION);
        assert_eq!(output.body["active_requests"], 1);
        assert!(output.body["uptime_s"].is_u64());
        assert_eq!(output.body["snapshot"]["stale"], false);
        assert_eq!(output.body["keyring"]["state"], "reachable");
        assert!(output.evidence.is_empty());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn query_reports_a_request_row_state_and_outcome() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let directory = tempfile::tempdir().unwrap();
        let repo = directory
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        fx.store
            .set_setting(
                crate::scope_policy::SETTING_SCOPE_POLICY,
                &serde_json::json!({
                    "version": 1, "repositories": [{"root": repo, "connectors": []}]
                })
                .to_string(),
            )
            .await
            .unwrap();
        fx.store
            .insert_admitted_request("req_target", "echo", &repo, "claude", "{}", None, 60_000)
            .await
            .unwrap();

        // Non-terminal: state comes back as-is, no outcome yet.
        let mut ctx =
            fx.ctx_uncancelled("req_query", serde_json::json!({ "ticket": "req_target" }));
        ctx.caller.repo.clone_from(&repo);
        let output = BuiltinCapability::Query.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, Outcome::Blocked);
        assert_eq!(
            output.body,
            serde_json::json!({
                "ticket": "req_target",
                "capability": "echo",
                "state": "running",
                "outcome": null,
            })
        );

        // Terminal: `pam wait` / `pam subscribe` reconcile against this.
        fx.store
            .finish_request(
                "req_target",
                RequestState::Done,
                Some("solved"),
                AuditEntry {
                    action: "execute",
                    decision: Decision::Allow,
                    actor: Actor::System,
                    detail: None,
                },
            )
            .await
            .unwrap();
        let mut ctx =
            fx.ctx_uncancelled("req_query2", serde_json::json!({ "ticket": "req_target" }));
        ctx.caller.repo.clone_from(&repo);
        let output = BuiltinCapability::Query.execute(ctx).await.unwrap();
        assert_eq!(output.body["state"], "done");
        assert_eq!(output.body["outcome"], "solved");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn query_fails_legibly_without_a_ticket_or_row() {
    timeout(DEADLINE, async {
        let fx = fixture().await;

        let ctx = fx.ctx_uncancelled("req_query", serde_json::json!({}));
        let result = BuiltinCapability::Query.execute(ctx).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Refused { ref cause, .. }) if cause == "result_unavailable"),
            "got {result:?}"
        );

        let ctx =
            fx.ctx_uncancelled("req_query", serde_json::json!({ "ticket": "req_ghost" }));
        let result = BuiltinCapability::Query.execute(ctx).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Refused { ref cause, .. }) if cause == "result_unavailable"),
            "got {result:?}"
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_mirrors_its_args() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let args = serde_json::json!({ "hello": "world", "n": 3 });
        let ctx = fx.ctx_uncancelled("req_echo", args.clone());

        let output = BuiltinCapability::Echo.execute(ctx).await.unwrap();

        assert_eq!(output.outcome, Outcome::Solved);
        assert_eq!(output.body, serde_json::json!({ "echo": args }));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_fail_arg_fails_the_execution() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let ctx = fx.ctx_uncancelled("req_echo", serde_json::json!({ "fail": true }));

        let result = BuiltinCapability::Echo.execute(ctx).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Failed { ref detail }) if detail.contains("args.fail")),
            "got {result:?}"
        );

        // Anything but the boolean true still echoes.
        let ctx = fx.ctx_uncancelled("req_echo", serde_json::json!({ "fail": false }));
        assert!(BuiltinCapability::Echo.execute(ctx).await.is_ok());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_delay_stops_on_the_cancel_signal() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let (cancel_tx, cancel) = watch::channel(false);
        let ctx = fx.ctx(
            "req_echo",
            serde_json::json!({ "delay_ms": 60_000 }),
            cancel,
        );

        let task = tokio::spawn(BuiltinCapability::Echo.execute(ctx));
        cancel_tx.send(true).unwrap();

        assert_eq!(task.await.unwrap(), Err(CapabilityFailure::Cancelled));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_delay_treats_a_closed_cancel_channel_as_cancelled() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let (cancel_tx, cancel) = watch::channel(false);
        let ctx = fx.ctx(
            "req_echo",
            serde_json::json!({ "delay_ms": 60_000 }),
            cancel,
        );
        // A dropped sender means the lease is gone.
        drop(cancel_tx);

        let result = BuiltinCapability::Echo.execute(ctx).await;
        assert_eq!(result, Err(CapabilityFailure::Cancelled));
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_of_a_queued_request_releases_waiters_and_tells_subscribers() {
    timeout(DEADLINE, async {
        let mut fx = fixture().await;

        // A queued target on a lane.
        let target = envelope("req_target", serde_json::json!({ "n": 1 }));
        assert_eq!(
            fx.queue
                .admit(&target, CapabilityClass::NonDestructive)
                .await
                .unwrap(),
            AdmitOutcome::Admitted
        );
        fx.queue
            .place_in_lane(&target.id, &target.caller.repo)
            .await
            .unwrap();

        // Someone waits on the target's completion.
        let Registration::Pending(waiter) = fx.router.register("req_target").await else {
            panic!("target must still be pending");
        };

        let mut ctx =
            fx.ctx_uncancelled("req_cancel", serde_json::json!({ "ticket": "req_target" }));
        // The canceller is the ticket's own repository.
        ctx.caller.repo.clone_from(&target.caller.repo);
        let output = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, Outcome::Solved);
        assert_eq!(output.body["result"], "cancelled_queued");
        assert_eq!(output.body["ticket"], "req_target");

        // Terminal row + audit came from the queue...
        let row = fx.store.get_request("req_target").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        let audit = fx.store.audit_for_request("req_target").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_CANCEL);
        assert_eq!(audit[0].decision, Decision::Deny);
        assert_eq!(audit[0].actor, Actor::System);

        // ...while the capability answered the waiter and the topic.
        let Response::Refusal { id, cause, .. } = waiter.await.unwrap() else {
            panic!("waiter must receive a refusal");
        };
        assert_eq!(id, "req_target");
        assert_eq!(cause, CAUSE_CANCELLED);
        let (topic, event) = fx.events_rx.recv().await.unwrap();
        assert_eq!(topic, "req_target");
        assert_eq!(event, Event::Refused);
    })
    .await
    .expect("test within deadline");
}

/// A queued `echo` under `/repo/a`, the repo [`envelope`] names.
async fn queued_target(fx: &Fixture, id: &str) -> Envelope {
    let target = envelope(id, serde_json::json!({ "n": 1 }));
    assert_eq!(
        fx.queue
            .admit(&target, CapabilityClass::NonDestructive)
            .await
            .unwrap(),
        AdmitOutcome::Admitted
    );
    fx.queue
        .place_in_lane(&target.id, &target.caller.repo)
        .await
        .unwrap();
    target
}

/// The audit actor is decided by where the request entered the daemon. A
/// public `cancel` that calls itself the GUI used to be recorded as a
/// human's decision; the label now changes nothing.
#[tokio::test]
async fn a_public_cancel_is_audited_as_system_whatever_label_it_carries() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let target = queued_target(&fx, "req_label_target").await;

        let mut ctx = fx.ctx_uncancelled(
            "req_label_cancel",
            serde_json::json!({ "ticket": "req_label_target" }),
        );
        ctx.caller.agent = crate::admin::ADMIN_CALLER_AGENT.to_owned();
        ctx.caller.repo.clone_from(&target.caller.repo);
        let output = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        assert_eq!(output.body["result"], "cancelled_queued");

        let audit = fx
            .store
            .audit_for_request("req_label_target")
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_CANCEL);
        assert_eq!(
            audit[0].actor,
            Actor::System,
            "a label forged a human actor"
        );
    })
    .await
    .expect("test within deadline");
}

/// The private admin plane's cancel is the human's: any ticket, whatever
/// repository it runs under, audited as `human`.
#[tokio::test]
async fn an_admin_origin_cancel_is_audited_as_human_and_needs_no_repository() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        queued_target(&fx, "req_admin_target").await;

        let mut ctx = fx.ctx_uncancelled(
            "req_admin_cancel",
            serde_json::json!({ "ticket": "req_admin_target" }),
        );
        ctx.origin = crate::ingress::Origin::Admin;
        ctx.caller.repo = crate::admin::ADMIN_REPO.to_owned();
        let output = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        assert_eq!(output.body["result"], "cancelled_queued");

        let audit = fx
            .store
            .audit_for_request("req_admin_target")
            .await
            .unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].actor, Actor::Human);
    })
    .await
    .expect("test within deadline");
}

/// Request ids are broadcast on the public event socket, so an id must not
/// be a capability: a public cancel acts only on a ticket admitted under
/// the caller's own repository, and a foreign ticket answers exactly like a
/// missing one.
#[tokio::test]
async fn a_public_cancel_from_another_repository_cannot_touch_the_ticket() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        queued_target(&fx, "req_foreign_target").await;

        // `ctx` runs under /repo/test; the target was admitted under /repo/a.
        let ctx = fx.ctx_uncancelled(
            "req_foreign_cancel",
            serde_json::json!({ "ticket": "req_foreign_target" }),
        );
        let foreign = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        let ctx = fx.ctx_uncancelled(
            "req_missing_cancel",
            serde_json::json!({ "ticket": "req_does_not_exist" }),
        );
        let missing = BuiltinCapability::Cancel.execute(ctx).await.unwrap();

        assert_eq!(foreign.outcome, Outcome::Unresolved);
        assert_eq!(foreign.body["result"], "not_found");
        assert_eq!(foreign.body["result"], missing.body["result"]);
        assert_eq!(foreign.outcome, missing.outcome);

        // The victim's request is untouched: still queued, nothing audited.
        let row = fx
            .store
            .get_request("req_foreign_target")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.state, RequestState::Queued);
        assert!(
            fx.store
                .audit_for_request("req_foreign_target")
                .await
                .unwrap()
                .is_empty()
        );
    })
    .await
    .expect("test within deadline");
}

/// `echo` is a diagnostic. Without a cap, one caller could keep any
/// repository's lane busy for the full hour a lease allows, or park a
/// megabyte reply per request.
#[tokio::test]
async fn echo_refuses_a_delay_or_a_payload_beyond_the_diagnostic_limits() {
    timeout(DEADLINE, async {
        let fx = fixture().await;

        let ctx = fx.ctx_uncancelled(
            "req_long",
            serde_json::json!({ "delay_ms": crate::executor::MAX_ECHO_DELAY_MS + 1 }),
        );
        let started = std::time::Instant::now();
        let refused = BuiltinCapability::Echo.execute(ctx).await;
        assert!(
            matches!(&refused, Err(CapabilityFailure::Refused { cause, .. })
                if cause == crate::executor::CAUSE_ECHO_LIMIT),
            "got {refused:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "refused before waiting"
        );

        let ctx = fx.ctx_uncancelled(
            "req_big",
            serde_json::json!({ "pad": "x".repeat(crate::executor::MAX_ECHO_ARGS_BYTES) }),
        );
        let refused = BuiltinCapability::Echo.execute(ctx).await;
        assert!(
            matches!(&refused, Err(CapabilityFailure::Refused { cause, .. })
                if cause == crate::executor::CAUSE_ECHO_LIMIT),
            "got {refused:?}"
        );

        // The documented contract still works: a small object comes back.
        let ctx = fx.ctx_uncancelled("req_ok", serde_json::json!({ "msg": "hi" }));
        let output = BuiltinCapability::Echo.execute(ctx).await.unwrap();
        assert_eq!(output.body["echo"]["msg"], "hi");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_without_a_ticket_fails() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let ctx = fx.ctx_uncancelled("req_cancel", serde_json::json!({}));

        let result = BuiltinCapability::Cancel.execute(ctx).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Failed { ref detail }) if detail.contains("ticket")),
            "got {result:?}"
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_of_an_unknown_ticket_is_unresolved() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let ctx = fx.ctx_uncancelled("req_cancel", serde_json::json!({ "ticket": "req_ghost" }));

        let output = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, Outcome::Unresolved);
        assert_eq!(output.body["result"], "not_found");
    })
    .await
    .expect("test within deadline");
}

/// A real repository the scope policy names — what a flow's journal
/// checkpoint authorization insists on.
async fn scoped_repo(fx: &Fixture) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let repo = directory
        .path()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    fx.store
        .set_setting(
            crate::scope_policy::SETTING_SCOPE_POLICY,
            &serde_json::json!({
                "version": 1, "repositories": [{"root": repo, "connectors": []}]
            })
            .to_string(),
        )
        .await
        .unwrap();
    (directory, repo)
}

/// A parked watch holds no lease, so `pam cancel` ends it the queued way:
/// terminal row and audit from the queue, waiters released and subscribers
/// told by the capability, and nothing left for the reaper to wake.
#[tokio::test]
async fn cancel_of_a_parked_ticket_is_cancelled_queued() {
    timeout(DEADLINE, async {
        let mut fx = fixture().await;
        let (_directory, repo) = scoped_repo(&fx).await;
        let mut target = envelope("req_parked", serde_json::json!({ "id": "parked" }));
        target.capability = "flow.run".to_owned();
        target.caller.repo.clone_from(&repo);
        assert_eq!(
            fx.queue
                .admit(&target, CapabilityClass::NonDestructive)
                .await
                .unwrap(),
            AdmitOutcome::Admitted
        );
        fx.queue
            .place_in_lane(&target.id, &target.caller.repo)
            .await
            .unwrap();
        let flow = pam_flow::parse(
            "schema: 1\nid: parked\nname: Parked\nsteps:\n  - id: look\n    run: [git, status]\n",
        )
        .unwrap();
        crate::flow_recovery::Recovery::open(
            &fx.store,
            "req_parked",
            &flow,
            std::path::Path::new(&target.caller.repo),
            &pam_flow::Vars::new(),
        )
        .await
        .unwrap();
        let lease = fx
            .queue
            .take_next(&target.caller.repo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.request_id, "req_parked");
        let resume = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
            + 30_000;
        assert!(fx.queue.park("req_parked", resume).await.unwrap());
        assert!(fx.queue.leased_ids().await.is_empty());

        let Registration::Pending(waiter) = fx.router.register("req_parked").await else {
            panic!("target must still be pending");
        };
        let mut ctx =
            fx.ctx_uncancelled("req_cancel", serde_json::json!({ "ticket": "req_parked" }));
        ctx.caller.repo.clone_from(&target.caller.repo);
        let output = BuiltinCapability::Cancel.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, Outcome::Solved);
        assert_eq!(output.body["result"], "cancelled_queued");

        let row = fx.store.get_request("req_parked").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Failed);
        assert_eq!(row.outcome.as_deref(), Some(CAUSE_CANCELLED));
        let audit = fx.store.audit_for_request("req_parked").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_CANCEL);
        let Response::Refusal { id, cause, .. } = waiter.await.unwrap() else {
            panic!("waiter must receive a refusal");
        };
        assert_eq!(id, "req_parked");
        assert_eq!(cause, CAUSE_CANCELLED);
        let (topic, event) = fx.events_rx.recv().await.unwrap();
        assert_eq!(topic, "req_parked");
        assert_eq!(event, Event::Refused);
        // The due time wakes nothing: the checkpoint is gone from the queue.
        assert_eq!(
            fx.queue
                .wake_due(tokio::time::Instant::now(), resume)
                .await
                .unwrap(),
            0
        );
        assert!(
            fx.queue
                .take_next(&target.caller.repo)
                .await
                .unwrap()
                .is_none()
        );
    })
    .await
    .expect("test within deadline");
}

// ---------------------------------------------------------------------------
// `doctor.report`: the boundary self-check record.
// ---------------------------------------------------------------------------

mod doctor_report {
    use std::path::PathBuf;
    use std::sync::Arc;

    use pam_proto::doctor::{
        DaemonFacts, DoctorReport, EnvFacts, Frontend, OsError, Platform, Probe, ProbeId,
        ProbeResult,
    };
    use pam_proto::wire::Via;
    use pam_store::{
        BoundaryObservationInsert, BoundaryPeer, OBSERVATION_ADMIN_CONTACT, RequestIngress,
        RequestOrigin,
    };
    use serde_json::{Value, json};

    use super::{Fixture, fixture};
    use crate::boundary::{
        ACTION_DOCTOR_REPORT, AdminContact, Boundary, CAP_DOCTOR_REPORT,
        CAUSE_BOUNDARY_UNAVAILABLE, CAUSE_INVALID_REPORT, SystemResolver,
    };
    use crate::executor::{BuiltinCapability, CapabilityFailure, ExecContext};
    use crate::ingress::PeerIdentity;
    use crate::policy::{CapabilityClass, classify};

    const IMAGE: &str = "/Applications/PAM.app/Contents/MacOS/pam";
    const PID: u32 = 4242;
    /// The must-deny probe that stands for reaching the admin plane: the
    /// socket on macOS, the control file on Windows.
    const ADMIN_PROBE: ProbeId = if cfg!(windows) {
        ProbeId::AdminControlRead
    } else {
        ProbeId::AdminEndpoint
    };

    /// A full document for this platform: every probe denied except
    /// the admin probe when `reachable`, which makes it `not_established`.
    pub(crate) fn document(admin_reachable: bool) -> Value {
        let platform = Platform::current().expect("a supported platform");
        let probes = ProbeId::all()
            .map(|id| {
                if !id.applies_to(platform) {
                    return Probe::not_applicable(id, platform);
                }
                match id {
                    ProbeId::PublicUnlink => Probe::not_probed(id, "side effect"),
                    ProbeId::PublicReach | ProbeId::RunLockProbe => {
                        Probe::new(id, ProbeResult::allowed())
                    }
                    id if id == ADMIN_PROBE && admin_reachable => {
                        Probe::new(id, ProbeResult::allowed())
                    }
                    _ => Probe::new(
                        id,
                        ProbeResult::denied(OsError::of_kind("PermissionDenied")),
                    ),
                }
            })
            .collect();
        let env = EnvFacts {
            socket_dir: None,
            base_dir_override: None,
            resolved_base: "/Users/me/.pam".to_owned(),
            resolved_endpoint: "/Users/me/.pam/run/pam.sock".to_owned(),
            client_version: "0.5.0".to_owned(),
            exe: Some("/usr/local/bin/pam".to_owned()),
            cwd_repo: Some("/repo/test".to_owned()),
            frontend: Frontend::Embedded,
            harness_chain: vec!["zsh".to_owned(), "claude".to_owned()],
        };
        let daemon = Some(DaemonFacts {
            version: "0.5.0".to_owned(),
            proto: 2,
            epoch: "01JB".to_owned(),
            via: Via::Direct,
        });
        let report = DoctorReport::new(platform, 1_759_400_000, daemon, probes, env);
        serde_json::to_value(report.as_args()).unwrap()
    }

    fn origin() -> RequestOrigin {
        RequestOrigin {
            ingress: RequestIngress::Public,
            peer_uid: Some(501),
            peer_pid: Some(PID),
            relayed: false,
        }
    }

    async fn boundary(fx: &Fixture) -> Arc<Boundary> {
        let boundary = Boundary::new(
            Arc::clone(&fx.store),
            Some(PathBuf::from(IMAGE)),
            Arc::new(SystemResolver),
        );
        boundary.load().await;
        boundary
    }

    /// A context whose request row exists (admitted on the public plane
    /// from pid 4242) and whose row carries the pipeline's resolution.
    async fn ctx(
        fx: &Fixture,
        id: &str,
        args: Value,
        boundary: Option<&Arc<Boundary>>,
    ) -> ExecContext {
        fx.store
            .insert_admitted_request_from(
                id,
                CAP_DOCTOR_REPORT,
                "/repo/test",
                "claude",
                "{}",
                None,
                9_000_000_000_000,
                &origin(),
            )
            .await
            .unwrap();
        fx.store
            .set_request_peer_facts(id, Some("/usr/local/bin/pam"), Some("claude"))
            .await
            .unwrap();
        let mut ctx = fx.ctx_uncancelled(id, args);
        ctx.peer = origin();
        ctx.capability = CAP_DOCTOR_REPORT.to_owned();
        if let Some(boundary) = boundary {
            assert!(ctx.status.attach_boundary(Arc::clone(boundary)));
        }
        ctx
    }

    #[test]
    fn doctor_report_is_a_control_capability_dispatched_by_name() {
        assert_eq!(
            BuiltinCapability::from_name(CAP_DOCTOR_REPORT),
            Some(BuiltinCapability::DoctorReport)
        );
        assert_eq!(BuiltinCapability::DoctorReport.name(), "doctor.report");
        assert_eq!(classify(CAP_DOCTOR_REPORT), Some(CapabilityClass::Control));
    }

    #[tokio::test]
    async fn a_valid_report_is_stored_under_the_daemon_peer_facts_with_its_audit_row() {
        let fx = fixture().await;
        let boundary = boundary(&fx).await;
        let ctx = ctx(&fx, "req_doc", document(true), Some(&boundary)).await;
        let output = BuiltinCapability::DoctorReport.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, pam_proto::Outcome::Verified);
        let body = output.body;
        assert_eq!(body["accepted"], true);
        assert_eq!(body["request_id"], "req_doc");
        assert_eq!(body["verdict"], "not_established");
        assert_eq!(body["peer"]["uid"], 501);
        assert_eq!(body["peer"]["pid"], PID);
        assert_eq!(body["peer"]["exe"], "/usr/local/bin/pam");
        assert_eq!(body["peer"]["harness"], "claude");
        assert_eq!(body["peer"]["relayed"], false);
        assert_eq!(body["claimed_harness"], "claude");
        assert_eq!(body["harness_agrees"], true);
        assert_eq!(body["attributed_admin_contacts"], 0);
        let report_id = body["report_id"].as_i64().unwrap();

        let rows = fx.store.list_boundary_reports(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.id, report_id);
        assert_eq!(row.request_id.as_deref(), Some("req_doc"));
        assert_eq!(row.verdict, "not_established");
        assert_eq!(row.failed, [ADMIN_PROBE.as_str()]);
        assert!(row.unverified.is_empty());
        assert_eq!(row.agent, "claude");
        assert_eq!(row.repo, "/repo/test");
        assert_eq!(row.report_ts, 1_759_400_000);
        assert_eq!(row.client_version, "0.5.0");
        assert_eq!(
            row.peer,
            BoundaryPeer {
                uid: Some(501),
                pid: Some(PID),
                exe: Some("/usr/local/bin/pam".to_owned()),
                harness: Some("claude".to_owned()),
            }
        );
        let stored: Value = serde_json::from_str(&row.report_json).unwrap();
        assert_eq!(stored, document(true));

        let audit = fx.store.audit_for_request("req_doc").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ACTION_DOCTOR_REPORT);
        assert_eq!(audit[0].decision, pam_store::Decision::Allow);
        assert_eq!(audit[0].actor, pam_store::Actor::System);
        let detail: Value = serde_json::from_str(audit[0].detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["verdict"], "not_established");
        assert_eq!(detail["failed"], json!([ADMIN_PROBE.as_str()]));
        assert_eq!(detail["unverified"], json!([]));
        assert_eq!(detail["peer_harness"], "claude");

        // The status block sees it at once.
        let block = boundary.status_block();
        assert_eq!(block["last_report"]["verdict"], "not_established");
        assert_eq!(block["last_report"]["request_id"], "req_doc");
        assert_eq!(block["last_report"]["peer_pid"], PID);
        assert_eq!(block["last_report"]["peer_harness"], "claude");
        assert_eq!(
            block["last_report"]["failed"],
            json!([ADMIN_PROBE.as_str()])
        );
        assert_eq!(block["last_report"]["ts"], 1_759_400_000);
        assert_eq!(block["reports"]["not_established"], 1);
        assert!(
            block["summary"]
                .as_str()
                .unwrap()
                .starts_with("not_established ")
        );
    }

    #[tokio::test]
    async fn a_report_from_a_relayed_peer_records_the_relay_harness_and_agreement_is_undetermined()
    {
        let fx = fixture().await;
        let boundary = boundary(&fx).await;
        let mut ctx = ctx(&fx, "req_relay", document(false), Some(&boundary)).await;
        // No resolution on the row (the relay's pid is `pam listen`, here
        // a pid nobody holds) and the hello said relay.
        fx.store
            .set_request_peer_facts("req_relay", None, None)
            .await
            .unwrap();
        ctx.peer = RequestOrigin {
            relayed: true,
            peer_pid: Some(u32::MAX - 7),
            ..origin()
        };
        let body = BuiltinCapability::DoctorReport
            .execute(ctx)
            .await
            .unwrap()
            .body;
        assert_eq!(body["verdict"], "established");
        assert_eq!(body["peer"]["harness"], "relay");
        assert_eq!(body["peer"]["exe"], Value::Null);
        assert_eq!(body["peer"]["relayed"], true);
        // The daemon sees the relay, not the client's harness: it cannot
        // say the two disagree.
        assert_eq!(body["harness_agrees"], Value::Null);
        let block = boundary.status_block();
        assert_eq!(block["last_report"]["relayed"], true);
        assert!(block["summary"].as_str().unwrap().contains(", relay)"));
    }

    /// Under a profile that denies `/bin/ps` the client's chain is empty
    /// and it claims `unknown`; the daemon, which resolved the harness
    /// itself, answers undetermined rather than `false`.
    #[tokio::test]
    async fn a_client_that_could_not_walk_its_chain_leaves_the_agreement_undetermined() {
        let fx = fixture().await;
        let boundary = boundary(&fx).await;
        let mut args = document(false);
        args["env"]["harness_chain"] = json!([]);
        let ctx = ctx(&fx, "req_sandboxed", args, Some(&boundary)).await;
        let body = BuiltinCapability::DoctorReport
            .execute(ctx)
            .await
            .unwrap()
            .body;
        assert_eq!(body["accepted"], true);
        assert_eq!(body["peer"]["harness"], "claude");
        assert_eq!(body["claimed_harness"], "unknown");
        assert_eq!(body["harness_agrees"], Value::Null);
    }

    async fn refused(
        fx: &Fixture,
        id: &str,
        args: Value,
        boundary: &Arc<Boundary>,
    ) -> (String, String) {
        let ctx = ctx(fx, id, args, Some(boundary)).await;
        match BuiltinCapability::DoctorReport.execute(ctx).await {
            Err(CapabilityFailure::Refused {
                cause,
                detail,
                recovery,
            }) => {
                assert!(!recovery.is_empty());
                (cause, detail)
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_forged_oversized_or_unrecordable_document_is_refused_and_nothing_is_stored() {
        let fx = fixture().await;
        let boundary = boundary(&fx).await;

        // The verdict says established while a must-deny probe was allowed.
        let mut forged = document(true);
        forged["verdict"] = json!("established");
        forged["failed"] = json!([]);
        let (cause, detail) = refused(&fx, "req_forged", forged, &boundary).await;
        assert_eq!(cause, CAUSE_INVALID_REPORT);
        assert!(
            detail.starts_with("doctor.report was refused: "),
            "{detail}"
        );
        assert!(
            detail.contains("verdict") || detail.contains("inconsisten"),
            "{detail}"
        );

        // Over the 16 KiB bound, refused before parsing.
        let mut oversized = document(false);
        oversized["env"]["cwd_repo"] = json!("x".repeat(20 * 1024));
        let (cause, detail) = refused(&fx, "req_big", oversized, &boundary).await;
        assert_eq!(cause, CAUSE_INVALID_REPORT);
        assert!(detail.contains("16") || detail.contains("byte"), "{detail}");

        // `cannot_probe` could not have arrived over the public socket.
        let mut unreachable = document(false);
        let probes = unreachable["probes"].as_array_mut().unwrap();
        probes[0]["result"] = json!("denied");
        unreachable["verdict"] = json!("cannot_probe");
        let (cause, _) = refused(&fx, "req_cannot", unreachable, &boundary).await;
        assert_eq!(cause, CAUSE_INVALID_REPORT);

        // Not even a document.
        let (cause, _) = refused(&fx, "req_junk", json!({ "hello": 1 }), &boundary).await;
        assert_eq!(cause, CAUSE_INVALID_REPORT);

        assert!(fx.store.list_boundary_reports(10).await.unwrap().is_empty());
        for id in ["req_forged", "req_big", "req_cannot", "req_junk"] {
            assert!(
                fx.store.audit_for_request(id).await.unwrap().is_empty(),
                "{id}"
            );
        }
        assert_eq!(boundary.status_block()["last_report"], Value::Null);
    }

    #[tokio::test]
    async fn without_an_observer_the_capability_refuses_rather_than_dropping_the_report() {
        let fx = fixture().await;
        let ctx = ctx(&fx, "req_none", document(false), None).await;
        match BuiltinCapability::DoctorReport.execute(ctx).await {
            Err(CapabilityFailure::Refused { cause, .. }) => {
                assert_eq!(cause, CAUSE_BOUNDARY_UNAVAILABLE);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admin_contacts_from_the_same_pid_are_attributed_before_and_after_the_report() {
        let fx = fixture().await;
        let boundary = boundary(&fx).await;
        let insert = |pid: u32| BoundaryPeer {
            uid: Some(501),
            pid: Some(pid),
            exe: Some("/usr/local/bin/pam".to_owned()),
            harness: Some("zsh".to_owned()),
        };
        let mine = insert(PID);
        let other = insert(9);
        for peer in [&mine, &other] {
            fx.store
                .insert_boundary_observation(BoundaryObservationInsert {
                    kind: OBSERVATION_ADMIN_CONTACT,
                    expected: false,
                    peer,
                    detail: Some("accepted; the peer sent nothing"),
                    attributed: None,
                })
                .await
                .unwrap();
        }
        let ctx = ctx(&fx, "req_doc", document(true), Some(&boundary)).await;
        let body = BuiltinCapability::DoctorReport
            .execute(ctx)
            .await
            .unwrap()
            .body;
        assert_eq!(body["attributed_admin_contacts"], 1);

        // A contact right after the report, from the same pid: born
        // attributed. From another pid: not.
        boundary
            .observe_admin_contact(AdminContact::Accepted {
                peer: PeerIdentity::Unix {
                    uid: 501,
                    gid: 20,
                    pid: Some(PID),
                },
                spoke: false,
            })
            .await;
        boundary
            .observe_admin_contact(AdminContact::Accepted {
                peer: PeerIdentity::Unix {
                    uid: 501,
                    gid: 20,
                    pid: Some(77),
                },
                spoke: false,
            })
            .await;
        let rows = fx.store.list_boundary_observations(10).await.unwrap();
        assert_eq!(rows.len(), 4);
        let attributed = |pid: u32| -> Vec<Option<String>> {
            rows.iter()
                .filter(|row| row.peer.pid == Some(pid))
                .map(|row| row.attributed.clone())
                .collect()
        };
        assert_eq!(
            attributed(PID),
            [Some("req_doc".to_owned()), Some("req_doc".to_owned())]
        );
        assert_eq!(attributed(9), [None]);
        assert_eq!(attributed(77), [None]);
        let block = boundary.status_block();
        assert_eq!(block["admin_contacts"]["unattributed"], 2);
        assert_eq!(block["admin_contacts"]["total"], 4);
        assert!(
            block["summary"]
                .as_str()
                .unwrap()
                .ends_with("admin contacts unattributed: 2")
        );
    }
}
