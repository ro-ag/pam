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
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let (events, events_rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events.clone(),
        DEADLINE,
    ));
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
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
