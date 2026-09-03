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
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(5);

struct Fixture {
    store: Arc<Store>,
    queue: Arc<QueueManager>,
    models: Arc<ModelService>,
    approvals: Arc<ApprovalService>,
    flows: Arc<FlowService>,
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
    for name in ["status", "query", "echo", "cancel"] {
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
        let output = BuiltinCapability::Status.execute(ctx).await.unwrap();

        assert_eq!(output.outcome, Outcome::Verified);
        assert_eq!(output.body["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(output.body["protocol"], PROTOCOL_VERSION);
        assert_eq!(output.body["active_requests"], 1);
        assert!(output.body["uptime_s"].is_u64());
        assert!(output.evidence.is_empty());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn query_reports_a_request_row_state_and_outcome() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        fx.store
            .insert_request("req_target", "echo", "/repo/a", "claude", "{}", None)
            .await
            .unwrap();

        // Non-terminal: state comes back as-is, no outcome yet.
        let ctx = fx.ctx_uncancelled("req_query", serde_json::json!({ "ticket": "req_target" }));
        let output = BuiltinCapability::Query.execute(ctx).await.unwrap();
        assert_eq!(output.outcome, Outcome::Verified);
        assert_eq!(
            output.body,
            serde_json::json!({
                "ticket": "req_target",
                "state": "queued",
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
        let ctx = fx.ctx_uncancelled("req_query2", serde_json::json!({ "ticket": "req_target" }));
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
            matches!(result, Err(CapabilityFailure::Failed { ref detail }) if detail.contains("args.ticket")),
            "got {result:?}"
        );

        let ctx =
            fx.ctx_uncancelled("req_query", serde_json::json!({ "ticket": "req_ghost" }));
        let result = BuiltinCapability::Query.execute(ctx).await;
        assert!(
            matches!(result, Err(CapabilityFailure::Failed { ref detail }) if detail.contains("req_ghost")),
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
            .place_in_lane(&target.id, &target.caller.repo, target.deadline_ms)
            .await;

        // Someone waits on the target's completion.
        let Registration::Pending(waiter) = fx.router.register("req_target").await else {
            panic!("target must still be pending");
        };

        let ctx = fx.ctx_uncancelled("req_cancel", serde_json::json!({ "ticket": "req_target" }));
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
