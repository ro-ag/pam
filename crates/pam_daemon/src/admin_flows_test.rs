//! Unit tests for the `admin.flows.*` ops.
//!
//! An [`AdminService`] built by hand here, with a real library directory
//! and a pipeline ingress the test owns. `admin.flows.run` is proved end
//! to end (through the real pipeline) in `tests/flows.rs`; what it is
//! held to here is the envelope it builds.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{RequestState, Store};
use serde_json::json;
use tokio::sync::mpsc;

use crate::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService, CAUSE_INVALID_ADMIN_ARGS};
use crate::admin_flows::{
    CAUSE_ID_MISMATCH, CAUSE_NOT_FOUND, FLOW_ADMIN_OPS, FLOW_RUN_DEADLINE_MS, OP_FLOWS_DELETE,
    OP_FLOWS_GET, OP_FLOWS_LIST, OP_FLOWS_NORMALIZE, OP_FLOWS_RUN, OP_FLOWS_SAVE,
    OP_FLOWS_SETTINGS_GET, OP_FLOWS_SETTINGS_SET,
};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::daemon::DAEMON_VERSION;
use crate::flow_service::{CAP_FLOW_RUN, CAUSE_FLOW_INVALID, CAUSE_PROGRAM_NOT_ALLOWED};
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::transport::{EventPublisher, IncomingRequest};

const LONG_TIMEOUT: Duration = Duration::from_mins(1);

/// A valid flow file with `id`.
fn flow_yaml(id: &str) -> String {
    format!(
        "schema: 1\nid: {id}\nname: Local flow\ndescription: looks around\n\
         steps:\n  - id: look\n    run: [git, status, --short]\n"
    )
}

/// An admin service over a fresh temp library, plus the ingress
/// `admin.flows.run` submits through.
async fn service() -> (
    tempfile::TempDir,
    Arc<Store>,
    AdminService,
    mpsc::Receiver<IncomingRequest>,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let models = ModelService::new(Arc::clone(&store))
        .await
        .expect("the model service builds");
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(Arc::clone(&store), None, None));
    let flows = crate::flow_service_test::flows_for_tests(
        tmp.path(),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    let (submit, ingress) = mpsc::channel(4);
    let admin = AdminService::new(
        Arc::clone(&store),
        approvals,
        models,
        logs,
        connectors,
        flows,
        submit,
    );
    (tmp, store, admin, ingress)
}

/// An admin envelope carrying the GUI tripwire identity.
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

/// Unwraps a refusal's cause.
fn cause_of(response: Response) -> String {
    match response {
        Response::Refusal { cause, .. } => cause,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_bridge_whitelist_names_every_op_once() {
    let mut sorted = FLOW_ADMIN_OPS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), FLOW_ADMIN_OPS.len());
    assert_eq!(FLOW_ADMIN_OPS.len(), 8);
    for op in FLOW_ADMIN_OPS {
        assert!(op.starts_with("admin.flows."), "{op} is misnamed");
    }
}

#[tokio::test]
async fn list_carries_the_path_and_digest_the_gui_needs() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_1",
                OP_FLOWS_LIST,
                serde_json::json!({}),
            ))
            .await,
        Outcome::Verified,
    );
    let flows = body["flows"].as_array().expect("flows is an array");
    assert_eq!(flows.len(), pam_flow::builtin().len());
    for entry in flows {
        assert_eq!(entry["source"], "builtin");
        assert!(entry["path"].is_null(), "a builtin has no file");
        assert_eq!(
            entry["digest"].as_str().expect("digest is a string").len(),
            64
        );
    }
}

#[tokio::test]
async fn save_get_delete_round_trip_through_the_library() {
    let (tmp, _store, admin, _ingress) = service().await;

    let saved = body_of(
        admin
            .handle(&admin_envelope(
                "req_save",
                OP_FLOWS_SAVE,
                serde_json::json!({ "id": "local", "yaml": flow_yaml("local") }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(saved["id"], "local");
    assert_eq!(saved["source"], "library");
    assert_eq!(saved["steps"], 1);
    assert!(tmp.path().join("flows/local.yaml").is_file());

    let got = body_of(
        admin
            .handle(&admin_envelope(
                "req_get",
                OP_FLOWS_GET,
                serde_json::json!({ "id": "local" }),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(got["id"], "local");
    assert!(
        got["yaml"]
            .as_str()
            .expect("yaml is a string")
            .contains("id: local")
    );
    assert_eq!(got["flow"]["name"], "Local flow");
    assert!(got["path"].is_string());

    let deleted = body_of(
        admin
            .handle(&admin_envelope(
                "req_del",
                OP_FLOWS_DELETE,
                serde_json::json!({ "id": "local" }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(deleted["revealed_builtin"], false);
    assert!(!tmp.path().join("flows/local.yaml").exists());
}

#[tokio::test]
async fn deleting_a_shadow_reveals_the_builtin_again() {
    let (_tmp, _store, admin, _ingress) = service().await;
    admin
        .handle(&admin_envelope(
            "req_save",
            OP_FLOWS_SAVE,
            serde_json::json!({
                "id": "after-merge-checks",
                "yaml": flow_yaml("after-merge-checks"),
            }),
        ))
        .await;
    let deleted = body_of(
        admin
            .handle(&admin_envelope(
                "req_del",
                OP_FLOWS_DELETE,
                serde_json::json!({ "id": "after-merge-checks" }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(deleted["revealed_builtin"], true);
}

#[tokio::test]
async fn deleting_a_builtin_without_a_shadow_is_not_found() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let response = admin
        .handle(&admin_envelope(
            "req_del",
            OP_FLOWS_DELETE,
            serde_json::json!({ "id": "after-merge-checks" }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_NOT_FOUND);
}

#[tokio::test]
async fn saving_invalid_yaml_names_the_path_that_is_wrong() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let response = admin
        .handle(&admin_envelope(
            "req_save",
            OP_FLOWS_SAVE,
            serde_json::json!({ "id": "local", "yaml": "schema: 1\nid: local\nname: x\n" }),
        ))
        .await;
    match response {
        Response::Refusal { cause, detail, .. } => {
            assert_eq!(cause, CAUSE_FLOW_INVALID);
            assert!(
                detail.contains("steps"),
                "the message names the path: {detail}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn saving_under_a_different_id_is_an_id_mismatch() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let response = admin
        .handle(&admin_envelope(
            "req_save",
            OP_FLOWS_SAVE,
            serde_json::json!({ "id": "renamed", "yaml": flow_yaml("local") }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_ID_MISMATCH);
}

#[tokio::test]
async fn the_settings_round_trip_and_refuse_a_shell() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_get",
                OP_FLOWS_SETTINGS_GET,
                serde_json::json!({}),
            ))
            .await,
        Outcome::Verified,
    );
    assert!(
        body["allowed_programs"]
            .as_array()
            .expect("allowed_programs is an array")
            .contains(&serde_json::json!("git"))
    );

    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_set",
                OP_FLOWS_SETTINGS_SET,
                serde_json::json!({ "allowed_programs": ["git", "cargo"] }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        body["allowed_programs"],
        serde_json::json!(["git", "cargo"])
    );

    let response = admin
        .handle(&admin_envelope(
            "req_shell",
            OP_FLOWS_SETTINGS_SET,
            serde_json::json!({ "allowed_programs": ["bash"] }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_PROGRAM_NOT_ALLOWED);

    let response = admin
        .handle(&admin_envelope(
            "req_bad",
            OP_FLOWS_SETTINGS_SET,
            serde_json::json!({ "extra_path": "not an array" }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_INVALID_ADMIN_ARGS);
}

#[tokio::test]
async fn run_submits_a_flow_run_envelope_and_forwards_the_ticket() {
    let (_tmp, store, admin, mut ingress) = service().await;

    // Stand in for the pipeline: answer the submitted envelope the way an
    // allowed `wait: false` request is answered.
    let pipeline = tokio::spawn(async move {
        let request = ingress.recv().await.expect("the run reaches the ingress");
        let ticket = request.envelope.id.clone();
        request
            .reply
            .send(Response::Ticket {
                id: ticket.clone(),
                ticket,
                position: 3,
            })
            .expect("the reply is delivered");
        request.envelope
    });

    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_run",
                OP_FLOWS_RUN,
                serde_json::json!({
                    "id": "after-merge-checks",
                    "repo": "/work/pam",
                    "inputs": { "who": "world" },
                }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["position"], 3);

    let envelope = pipeline.await.expect("the stand-in pipeline finishes");
    assert_eq!(envelope.capability, CAP_FLOW_RUN);
    assert_eq!(envelope.caller.agent, ADMIN_CALLER_AGENT);
    assert_eq!(envelope.caller.repo, "/work/pam");
    assert_eq!(envelope.caller.pid, std::process::id());
    assert_eq!(envelope.deadline_ms, FLOW_RUN_DEADLINE_MS);
    assert!(
        !envelope.wait,
        "the GUI follows the ticket, it does not wait"
    );
    assert_eq!(envelope.args["id"], "after-merge-checks");
    assert_eq!(envelope.args["inputs"]["who"], "world");
    assert_eq!(body["ticket"], envelope.id);

    // The admin op itself finished cleanly, with its own request row.
    let row = store
        .get_request("req_run")
        .await
        .expect("get_request ok")
        .expect("the admin op has a row");
    assert_eq!(row.state, RequestState::Done);
}

#[tokio::test]
async fn a_gate_refusal_reaches_the_gui_verbatim() {
    let (_tmp, _store, admin, mut ingress) = service().await;
    let pipeline = tokio::spawn(async move {
        let request = ingress.recv().await.expect("the run reaches the ingress");
        request
            .reply
            .send(Response::Refusal {
                id: request.envelope.id.clone(),
                cause: "not_granted".to_owned(),
                detail: "capability \"flow.run\" has no active grant".to_owned(),
                recovery: "Grant this capability in the PAM GUI (Security > Capabilities)."
                    .to_owned(),
            })
            .expect("the reply is delivered");
    });

    let response = admin
        .handle(&admin_envelope(
            "req_run",
            OP_FLOWS_RUN,
            serde_json::json!({ "id": "after-merge-checks", "repo": "/work/pam" }),
        ))
        .await;
    pipeline.await.expect("the stand-in pipeline finishes");
    match response {
        Response::Refusal {
            cause, recovery, ..
        } => {
            assert_eq!(cause, "not_granted");
            assert!(recovery.contains("Security"), "the recovery line survives");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn run_needs_a_repo() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let response = admin
        .handle(&admin_envelope(
            "req_run",
            OP_FLOWS_RUN,
            serde_json::json!({ "id": "after-merge-checks" }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_INVALID_ADMIN_ARGS);
}

#[tokio::test]
async fn every_flow_op_trips_the_wire_for_a_caller_that_is_not_the_gui() {
    let (_tmp, store, admin, _ingress) = service().await;
    for (index, op) in FLOW_ADMIN_OPS.iter().enumerate() {
        let id = format!("req_trip_{index}");
        let mut envelope = admin_envelope(&id, op, serde_json::json!({}));
        envelope.caller.agent = "claude".to_owned();
        let response = admin.handle(&envelope).await;
        assert_eq!(
            cause_of(response),
            crate::admin::CAUSE_ADMIN_DENIED,
            "{op} must trip the wire"
        );
        let row = store
            .get_request(&id)
            .await
            .expect("get_request ok")
            .expect("the tripped op has a row");
        assert_eq!(row.state, RequestState::Refused);
    }
}

#[tokio::test]
async fn the_library_directory_is_created_on_the_first_save() {
    let (tmp, _store, admin, _ingress) = service().await;
    assert!(!tmp.path().join("flows").exists());
    admin
        .handle(&admin_envelope(
            "req_save",
            OP_FLOWS_SAVE,
            serde_json::json!({ "id": "local", "yaml": flow_yaml("local") }),
        ))
        .await;
    assert!(Path::new(&tmp.path().join("flows")).is_dir());
}

#[tokio::test]
async fn normalize_renders_yaml_canonically_and_carries_the_parsed_flow() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let messy = "name: Local flow\nschema: 1\nid: local\nsteps:\n  - run: [git, status]\n    id: look\n    timeout: 5m\n";
    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_n1",
                OP_FLOWS_NORMALIZE,
                json!({ "yaml": messy }),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["valid"], json!(true));
    let yaml = body["yaml"].as_str().unwrap();
    assert!(
        yaml.starts_with("schema: 1\nid: local\nname: Local flow\n"),
        "{yaml}"
    );
    assert!(
        !yaml.contains("timeout"),
        "default timeout is omitted: {yaml}"
    );
    assert_eq!(body["flow"]["steps"][0]["id"], json!("look"));
    assert_eq!(body["flow"]["steps"][0]["action"]["kind"], json!("command"));
    assert_eq!(body["digest"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn normalize_accepts_the_raw_flow_json_and_yields_the_same_digest() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let raw = json!({ "schema": 1, "id": "local", "name": "Local flow",
        "steps": [{ "id": "look", "run": ["git", "status"] }] });
    let from_flow = body_of(
        admin
            .handle(&admin_envelope(
                "req_n2",
                OP_FLOWS_NORMALIZE,
                json!({ "flow": raw }),
            ))
            .await,
        Outcome::Verified,
    );
    let from_yaml = body_of(
        admin
            .handle(&admin_envelope(
                "req_n3",
                OP_FLOWS_NORMALIZE,
                json!({ "yaml": from_flow["yaml"] }),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(from_flow["digest"], from_yaml["digest"]);
    assert_eq!(from_flow["yaml"], from_yaml["yaml"]);
}

#[tokio::test]
async fn normalize_answers_invalid_flows_with_the_path_not_a_refusal() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let raw = json!({ "schema": 1, "id": "local", "name": "Local flow",
        "steps": [{ "id": "look", "run": ["bash", "-c", "ls"] }] });
    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_n4",
                OP_FLOWS_NORMALIZE,
                json!({ "flow": raw }),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["valid"], json!(false));
    assert_eq!(body["error"]["path"], json!("steps[0].run[0]"));
    assert!(body["error"]["message"].as_str().unwrap().contains("shell"));
    assert!(body.get("yaml").is_none());
}

#[tokio::test]
async fn normalize_needs_exactly_one_of_yaml_or_flow() {
    let (_tmp, _store, admin, _ingress) = service().await;
    // Each call is its own request row, so each needs its own id.
    for (index, args) in [json!({}), json!({ "yaml": "schema: 1\n", "flow": {} })]
        .into_iter()
        .enumerate()
    {
        let cause = cause_of(
            admin
                .handle(&admin_envelope(
                    &format!("req_n5_{index}"),
                    OP_FLOWS_NORMALIZE,
                    args,
                ))
                .await,
        );
        assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS);
    }
}

#[tokio::test]
async fn create_options_refuse_collisions_and_restore_only_an_absent_override() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let yaml = flow_yaml("fresh");
    let args = json!({"id":"fresh", "yaml":yaml, "create_only":true});
    body_of(
        admin
            .handle(&admin_envelope("create", OP_FLOWS_SAVE, args.clone()))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        cause_of(
            admin
                .handle(&admin_envelope("collision", OP_FLOWS_SAVE, args))
                .await
        ),
        CAUSE_ID_MISMATCH
    );
    for (index, options) in [
        json!({"create_only":"yes"}),
        json!({"allow_builtin_override":true}),
        json!({"create_only":true,"allow_builtin_override":"yes"}),
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = json!({"id":"fresh", "yaml":yaml});
        args.as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        assert_eq!(
            cause_of(
                admin
                    .handle(&admin_envelope(
                        &format!("invalid{index}"),
                        OP_FLOWS_SAVE,
                        args
                    ))
                    .await
            ),
            CAUSE_INVALID_ADMIN_ARGS
        );
    }
    let builtin = body_of(
        admin
            .handle(&admin_envelope(
                "builtin",
                OP_FLOWS_GET,
                json!({"id":"after-merge-checks"}),
            ))
            .await,
        Outcome::Verified,
    );
    let yaml = builtin["yaml"].as_str().unwrap();
    let mut args = json!({"id":"after-merge-checks","yaml":yaml,"create_only":true});
    assert_eq!(
        cause_of(
            admin
                .handle(&admin_envelope(
                    "builtin-collision",
                    OP_FLOWS_SAVE,
                    args.clone()
                ))
                .await
        ),
        CAUSE_ID_MISMATCH
    );
    args["allow_builtin_override"] = json!(true);
    body_of(
        admin
            .handle(&admin_envelope("restore", OP_FLOWS_SAVE, args.clone()))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        cause_of(
            admin
                .handle(&admin_envelope("restore-collision", OP_FLOWS_SAVE, args))
                .await
        ),
        CAUSE_ID_MISMATCH
    );
    let deleted = body_of(
        admin
            .handle(&admin_envelope(
                "delete",
                OP_FLOWS_DELETE,
                json!({"id":"after-merge-checks"}),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(deleted["revealed_builtin"], true);
}
