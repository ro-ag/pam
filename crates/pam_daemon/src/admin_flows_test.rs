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
    CAUSE_ID_MISMATCH, CAUSE_NOT_FOUND, FLOW_ADMIN_OPS, FLOW_INSPECT_DEADLINE_MS,
    FLOW_RUN_DEADLINE_MS, OP_FLOWS_DELETE, OP_FLOWS_GET, OP_FLOWS_INSPECT, OP_FLOWS_LIST,
    OP_FLOWS_NORMALIZE, OP_FLOWS_RUN, OP_FLOWS_SAVE, OP_FLOWS_SETTINGS_GET, OP_FLOWS_SETTINGS_SET,
};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::daemon::DAEMON_VERSION;
use crate::flow_service::{
    CAP_FLOW_INSPECT, CAP_FLOW_RUN, CAUSE_ARTIFACTS_ROOT_INVALID, CAUSE_FLOW_INVALID,
    CAUSE_PROGRAM_NOT_ALLOWED,
};
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
    managed_service(None).await
}

/// [`service`] under a trusted managed policy `document` (none: unmanaged).
async fn managed_service(
    document: Option<serde_json::Value>,
) -> (
    tempfile::TempDir,
    Arc<Store>,
    AdminService,
    mpsc::Receiver<IncomingRequest>,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.expect("store opens"));
    let policy = match &document {
        Some(document) => {
            crate::flow_service_test::managed_policy(&store, tmp.path(), document).await
        }
        None => crate::managed_policy_service::PolicyHandle::none(),
    };
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let models = ModelService::new(
        Arc::clone(&store),
        crate::managed_policy_service::PolicyHandle::none(),
    )
    .await
    .expect("the model service builds");
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        crate::managed_policy_service::PolicyHandle::none(),
    ));
    let flows = crate::flow_service_test::flows_for_tests_with_policy(
        tmp.path(),
        &store,
        &approvals,
        &connectors,
        &logs,
        Arc::clone(&policy),
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
        policy,
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
    assert_eq!(FLOW_ADMIN_OPS.len(), 11);
    assert!(FLOW_ADMIN_OPS.contains(&"admin.flows.landing.get"));
    assert!(FLOW_ADMIN_OPS.contains(&"admin.flows.landing.set"));
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
async fn inspect_submits_a_waiting_flow_inspect_envelope_and_returns_its_body() {
    let (_tmp, _store, admin, mut ingress) = service().await;
    let pipeline = tokio::spawn(async move {
        let request = ingress
            .recv()
            .await
            .expect("the inspection reaches the ingress");
        request
            .reply
            .send(Response::Result {
                id: request.envelope.id.clone(),
                outcome: Outcome::Verified,
                body: serde_json::json!({
                    "readiness": "blocked",
                    "blockers": [{"step": "capture", "cause": "connector_missing", "recovery": "configure Jenkins"}],
                }),
                evidence: Vec::new(),
            })
            .expect("the reply is delivered");
        request.envelope
    });

    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_inspect",
                OP_FLOWS_INSPECT,
                serde_json::json!({
                    "id": "jenkins-build-investigation",
                    "repo": "/work/pam",
                    "inputs": { "job": "platform/nightly" },
                }),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["readiness"], "blocked");
    assert_eq!(body["blockers"][0]["cause"], "connector_missing");

    let envelope = pipeline.await.expect("the stand-in pipeline finishes");
    assert_eq!(envelope.capability, CAP_FLOW_INSPECT);
    assert_eq!(envelope.caller.agent, ADMIN_CALLER_AGENT);
    assert_eq!(envelope.caller.repo, "/work/pam");
    assert_eq!(envelope.deadline_ms, FLOW_INSPECT_DEADLINE_MS);
    assert!(
        envelope.wait,
        "inspection is a bounded read the GUI waits for"
    );
    assert_eq!(envelope.args["id"], "jenkins-build-investigation");
    assert_eq!(envelope.args["inputs"]["job"], "platform/nightly");
}

#[tokio::test]
async fn a_gate_refusal_reaches_the_gui_verbatim() {
    let (_tmp, _store, admin, mut ingress) = service().await;
    let pipeline = tokio::spawn(async move {
        let request = ingress.recv().await.expect("the run reaches the ingress");
        request
            .reply
            .send(Response::Refusal {
                retryable: false,
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

/// One request carries both settings; a scope policy that cannot be
/// normalized (a root that does not exist) is refused before the other
/// settings are written, so a refusal changes nothing.
#[tokio::test]
async fn a_scope_refusal_leaves_the_other_settings_untouched() {
    let (tmp, _store, admin, _ingress) = service().await;
    // An absolute path on every platform: a POSIX-looking path is refused as
    // invalid on Windows before the root is ever resolved.
    let missing_root = tmp.path().join("does-not-exist");
    let before = body_of(
        admin
            .handle(&admin_envelope(
                "req_before",
                OP_FLOWS_SETTINGS_GET,
                json!({}),
            ))
            .await,
        Outcome::Verified,
    );
    let response = admin
        .handle(&admin_envelope(
            "req_partial",
            OP_FLOWS_SETTINGS_SET,
            json!({
                "allowed_programs": ["git", "cargo", "make"],
                "scope_policy": {
                    "version": 1,
                    "repositories": [{ "root": missing_root, "connectors": [] }],
                },
            }),
        ))
        .await;
    assert_eq!(cause_of(response), crate::scope_policy::CAUSE_SCOPE_DENIED);
    let after = body_of(
        admin
            .handle(&admin_envelope(
                "req_after",
                OP_FLOWS_SETTINGS_GET,
                json!({}),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(after["allowed_programs"], before["allowed_programs"]);
    assert_eq!(after["scope_policy"], before["scope_policy"]);
}

#[tokio::test]
async fn settings_carry_the_artifacts_root_and_a_null_clears_it() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let body = body_of(
        admin
            .handle(&admin_envelope("req_get", OP_FLOWS_SETTINGS_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["artifacts_root"], serde_json::Value::Null);
    assert_eq!(
        body["read_cache_roots"],
        json!(["~/.cargo/registry", "~/.cargo/git"])
    );

    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_set",
                OP_FLOWS_SETTINGS_SET,
                json!({ "artifacts_root": "~/pam-builds", "read_cache_roots": ["~/.cargo/registry"] }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["artifacts_root"], "~/pam-builds");
    assert_eq!(body["read_cache_roots"], json!(["~/.cargo/registry"]));

    let response = admin
        .handle(&admin_envelope(
            "req_relative",
            OP_FLOWS_SETTINGS_SET,
            json!({ "artifacts_root": "builds" }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_ARTIFACTS_ROOT_INVALID);

    let response = admin
        .handle(&admin_envelope(
            "req_number",
            OP_FLOWS_SETTINGS_SET,
            json!({ "artifacts_root": 7 }),
        ))
        .await;
    assert_eq!(cause_of(response), CAUSE_INVALID_ADMIN_ARGS);

    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_clear",
                OP_FLOWS_SETTINGS_SET,
                json!({ "artifacts_root": null }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["artifacts_root"], serde_json::Value::Null);
}

/// A two-step flow whose `change` step runs `argument`, reads the `target`
/// input (default `default`) and carries `note`.
fn two_step_yaml(id: &str, argument: &str, default: &str, note: &str) -> String {
    format!(
        "schema: 1\nid: {id}\nname: Two steps {id}\n\
         inputs:\n  target:\n    description: what to build\n    default: {default}\n\
         steps:\n  - id: look\n    run: [git, status, --short]\n    note: {note}\n  \
         - id: change\n    run: [make, {argument}, \"${{inputs.target}}\"]\n    effect: stateful\n"
    )
}

/// The capabilities with an active grant, sorted.
async fn active_grants(store: &Store) -> Vec<String> {
    let mut active: Vec<String> = store
        .list_grants()
        .await
        .expect("grants list")
        .into_iter()
        .filter(|grant| grant.revoked_ts.is_none())
        .map(|grant| grant.capability)
        .collect();
    active.sort();
    active
}

async fn save(admin: &AdminService, request: &str, id: &str, yaml: &str) -> serde_json::Value {
    body_of(
        admin
            .handle(&admin_envelope(
                request,
                OP_FLOWS_SAVE,
                json!({ "id": id, "yaml": yaml }),
            ))
            .await,
        Outcome::Changed,
    )
}

/// Finding 2 of the 2026-10 design review: a remembered approval is a grant
/// on the step's *name*, so editing what the step runs must take it away.
#[tokio::test]
async fn saving_a_changed_step_revokes_its_remembered_approval_and_says_so() {
    let (_tmp, store, admin, _ingress) = service().await;
    let first = save(
        &admin,
        "save1",
        "local",
        &two_step_yaml("local", "build", "all", "one"),
    )
    .await;
    assert_eq!(first["grants_revoked"], json!([]));
    assert_eq!(first["reapproval_required"], false);
    for step in ["look", "change"] {
        store
            .insert_grant(&crate::flow_service::step_capability("local", step))
            .await
            .unwrap();
    }
    store
        .insert_grant("flow.step:locality/change")
        .await
        .unwrap();
    store.insert_grant("flow.run").await.unwrap();

    // Only a note changed: both approvals still describe what runs.
    let noted = save(
        &admin,
        "save2",
        "local",
        &two_step_yaml("local", "build", "all", "two"),
    )
    .await;
    assert_eq!(noted["grants_revoked"], json!([]));
    assert_eq!(active_grants(&store).await.len(), 4);

    // The approved `make build` now runs `make deploy`.
    let edited = save(
        &admin,
        "save3",
        "local",
        &two_step_yaml("local", "deploy", "all", "two"),
    )
    .await;
    assert_eq!(edited["grants_revoked"], json!(["flow.step:local/change"]));
    assert_eq!(edited["reapproval_required"], true);
    assert_eq!(
        active_grants(&store).await,
        [
            "flow.run",
            "flow.step:local/look",
            "flow.step:locality/change"
        ],
        "only the edited step of this flow loses its grant"
    );
    let audit = store.audit_for_request("save3").await.unwrap();
    let detail: serde_json::Value =
        serde_json::from_str(audit.last().unwrap().detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["grants_revoked"], json!(["flow.step:local/change"]));
    assert_eq!(detail["digest"], edited["digest"]);
    assert_eq!(detail["previous_digest"], noted["digest"]);
    assert_ne!(detail["digest"], detail["previous_digest"]);

    // A default the step reads is part of the command line that was approved.
    store.insert_grant("flow.step:local/change").await.unwrap();
    let defaulted = save(
        &admin,
        "save4",
        "local",
        &two_step_yaml("local", "deploy", "production", "two"),
    )
    .await;
    assert_eq!(
        defaulted["grants_revoked"],
        json!(["flow.step:local/change"])
    );
    assert!(!store.active_grant("flow.step:local/change").await.unwrap());
    assert!(store.active_grant("flow.step:local/look").await.unwrap());
}

#[tokio::test]
async fn a_shadow_keeps_only_the_grants_of_steps_identical_to_the_builtin() {
    let (_tmp, store, admin, _ingress) = service().await;
    let builtin = pam_flow::builtin_yaml("after-merge-checks").unwrap();
    for step in ["fetch", "clean-tree", "recent-commits", "left-behind"] {
        store
            .insert_grant(&crate::flow_service::step_capability(
                "after-merge-checks",
                step,
            ))
            .await
            .unwrap();
    }
    // The shadow keeps the builtin's text except for what `fetch` runs.
    let shadow = builtin.replace("[git, fetch, --prune]", "[git, fetch, --all]");
    assert_ne!(shadow, builtin);
    let created = body_of(
        admin
            .handle(&admin_envelope(
                "shadow",
                OP_FLOWS_SAVE,
                json!({"id":"after-merge-checks","yaml":shadow,"create_only":true,"allow_builtin_override":true}),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        created["grants_revoked"],
        json!([
            "flow.step:after-merge-checks/fetch",
            "flow.step:after-merge-checks/left-behind"
        ]),
        "the changed step and a grant no step answers to are both revoked"
    );
    assert_eq!(
        active_grants(&store).await,
        [
            "flow.step:after-merge-checks/clean-tree",
            "flow.step:after-merge-checks/recent-commits"
        ]
    );

    // Deleting the shadow reveals the builtin: `fetch` changes back, so a
    // grant given to the shadow's `fetch` does not carry over to it.
    store
        .insert_grant("flow.step:after-merge-checks/fetch")
        .await
        .unwrap();
    let deleted = body_of(
        admin
            .handle(&admin_envelope(
                "unshadow",
                OP_FLOWS_DELETE,
                json!({"id":"after-merge-checks"}),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(deleted["revealed_builtin"], true);
    assert_eq!(
        deleted["grants_revoked"],
        json!(["flow.step:after-merge-checks/fetch"])
    );
    assert_eq!(deleted["reapproval_required"], true);
}

#[tokio::test]
async fn deleting_a_flow_revokes_every_step_grant_and_a_refused_save_revokes_none() {
    let (_tmp, store, admin, _ingress) = service().await;
    let yaml = two_step_yaml("local", "build", "all", "one");
    save(&admin, "save", "local", &yaml).await;
    for step in ["look", "change"] {
        store
            .insert_grant(&crate::flow_service::step_capability("local", step))
            .await
            .unwrap();
    }
    // Refused before anything is written: the existing flow keeps its approvals.
    let changed = two_step_yaml("local", "deploy", "all", "one");
    assert_eq!(
        cause_of(
            admin
                .handle(&admin_envelope(
                    "collide",
                    OP_FLOWS_SAVE,
                    json!({"id":"local","yaml":changed,"create_only":true}),
                ))
                .await
        ),
        CAUSE_ID_MISMATCH
    );
    assert_eq!(
        cause_of(
            admin
                .handle(&admin_envelope(
                    "invalid",
                    OP_FLOWS_SAVE,
                    json!({"id":"local","yaml":"schema: 1\nid: local\nname: Broken\nsteps: []\n"}),
                ))
                .await
        ),
        CAUSE_FLOW_INVALID
    );
    assert_eq!(active_grants(&store).await.len(), 2);

    let deleted = body_of(
        admin
            .handle(&admin_envelope(
                "del",
                OP_FLOWS_DELETE,
                json!({"id":"local"}),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(
        deleted["grants_revoked"],
        json!(["flow.step:local/change", "flow.step:local/look"])
    );
    assert!(active_grants(&store).await.is_empty());
    // A new flow under the old id starts with no approval of its own.
    let again = save(&admin, "again", "local", &yaml).await;
    assert_eq!(again["grants_revoked"], json!([]));
    assert!(active_grants(&store).await.is_empty());
}

#[tokio::test]
async fn run_forwards_the_digest_the_human_was_shown() {
    let (_tmp, _store, admin, mut ingress) = service().await;
    let pipeline = tokio::spawn(async move {
        let request = ingress.recv().await.expect("the run reaches the ingress");
        let ticket = request.envelope.id.clone();
        request
            .reply
            .send(Response::Ticket {
                id: ticket.clone(),
                ticket,
                position: 0,
            })
            .expect("the reply is delivered");
        request.envelope
    });
    let digest = "a".repeat(64);
    body_of(
        admin
            .handle(&admin_envelope(
                "req_run",
                OP_FLOWS_RUN,
                json!({"id":"after-merge-checks","repo":"/work/pam","expected_digest":digest}),
            ))
            .await,
        Outcome::Changed,
    );
    let envelope = pipeline.await.unwrap();
    assert_eq!(envelope.args["expected_digest"], digest);
}

// --- The managed policy ------------------------------------------------------

/// A policy over the flow settings and the scopes: programs `allow`
/// `[git, make]`, and repositories only under `allowed_root`.
fn managed_document(allowed_root: &Path) -> serde_json::Value {
    json!({
        "version": 1,
        "revision": "rev-9",
        "contact": "it@example.test",
        "flows": { "programs": { "allow": ["git", "make"] } },
        "scopes": { "allowed_repository_roots": [crate::scope_policy::policy_path(allowed_root)] }
    })
}

/// A refusal's three parts.
fn refusal_of(response: Response) -> (String, String, String) {
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

/// Two directories, `inside` under the allowed root and `outside` not,
/// canonical; the guard owns both.
fn roots() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = tmp.path().canonicalize().unwrap();
    let allowed = canonical.join("allowed");
    let inside = allowed.join("inside");
    let outside = canonical.join("outside");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    (tmp, inside, outside)
}

#[tokio::test]
async fn settings_get_reports_the_effective_values_and_the_scopes_the_policy_drops() {
    let (_dirs, inside, outside) = roots();
    let allowed = inside.parent().unwrap().to_path_buf();
    let (_tmp, store, admin, _ingress) = managed_service(Some(managed_document(&allowed))).await;
    store
        .set_setting(
            crate::flow_service::SETTING_ALLOWED_PROGRAMS,
            &json!(["git", "cargo"]).to_string(),
        )
        .await
        .unwrap();
    store
        .set_setting(
            crate::scope_policy::SETTING_SCOPE_POLICY,
            &json!({"version": 1, "repositories": [
                {"root": inside, "connectors": []},
                {"root": outside, "connectors": []},
            ]})
            .to_string(),
        )
        .await
        .unwrap();
    let body = body_of(
        admin
            .handle(&admin_envelope("req_get", OP_FLOWS_SETTINGS_GET, json!({})))
            .await,
        Outcome::Verified,
    );
    // The named fields are what the human saved, for the panel to edit.
    assert_eq!(body["allowed_programs"], json!(["git", "cargo"]));
    assert_eq!(
        body["scope_policy"]["repositories"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // `effective` is what every consumer reads.
    let effective = &body["effective"];
    assert_eq!(effective["allowed_programs"]["value"], json!(["git"]));
    assert_eq!(effective["allowed_programs"]["source"], "policy");
    assert_eq!(effective["allowed_programs"]["mode"], "allow");
    assert_eq!(effective["extra_path"]["source"], "user");
    assert_eq!(effective["extra_path"]["locked"], false);
    assert_eq!(
        effective["scope_policy"]["value"]["repositories"],
        json!([{"root": inside, "connectors": []}])
    );
    assert_eq!(effective["scope_policy"]["source"], "policy");
    assert_eq!(effective["scope_policy"]["mode"], "forbid");
    assert_eq!(
        body["scope_policy_dropped"],
        json!([{
            "root": outside,
            "connector": null,
            "key": "scopes.allowed_repository_roots",
            "reason": "this repository is outside the repository roots your organisation's policy allows",
        }])
    );
}

#[tokio::test]
async fn a_settings_write_the_policy_forbids_is_refused_and_changes_nothing() {
    let (_dirs, inside, outside) = roots();
    let allowed = inside.parent().unwrap().to_path_buf();
    let (_tmp, store, admin, _ingress) = managed_service(Some(managed_document(&allowed))).await;
    let digest12 = admin.flows.policy().view().digest12().unwrap().to_owned();
    let programs = store
        .get_setting(crate::flow_service::SETTING_ALLOWED_PROGRAMS)
        .await
        .unwrap();
    let scopes = store
        .get_setting(crate::scope_policy::SETTING_SCOPE_POLICY)
        .await
        .unwrap();

    let (cause, detail, recovery) = refusal_of(
        admin
            .handle(&admin_envelope(
                "req_programs",
                OP_FLOWS_SETTINGS_SET,
                json!({ "allowed_programs": ["git", "cargo"] }),
            ))
            .await,
    );
    assert_eq!(cause, crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED);
    assert!(
        detail.contains("(flows.programs)")
            && detail.contains("contact it@example.test")
            && detail.contains(&format!("(policy {digest12}, rev rev-9)")),
        "{detail}"
    );
    assert_eq!(recovery, crate::managed_policy::RECOVERY_MANAGED);

    // A repository outside the allowed roots refuses the whole request:
    // the programs in it are not written either.
    let (cause, detail, _) = refusal_of(
        admin
            .handle(&admin_envelope(
                "req_scopes",
                OP_FLOWS_SETTINGS_SET,
                json!({
                    "allowed_programs": ["git"],
                    "scope_policy": {"version": 1, "repositories": [{"root": outside, "connectors": []}]},
                }),
            ))
            .await,
    );
    assert_eq!(cause, crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED);
    assert!(
        detail.contains("(scopes.allowed_repository_roots)"),
        "{detail}"
    );
    assert_eq!(
        store
            .get_setting(crate::flow_service::SETTING_ALLOWED_PROGRAMS)
            .await
            .unwrap(),
        programs
    );
    assert_eq!(
        store
            .get_setting(crate::scope_policy::SETTING_SCOPE_POLICY)
            .await
            .unwrap(),
        scopes
    );
    // The terminal refusal row is the admin plane's, on the request.
    let rows = store.audit_for_request("req_scopes").await.unwrap();
    assert!(
        rows.iter()
            .any(|row| row.decision == pam_store::Decision::Refuse),
        "{rows:?}"
    );

    // Inside the bounds the same op saves.
    let body = body_of(
        admin
            .handle(&admin_envelope(
                "req_fine",
                OP_FLOWS_SETTINGS_SET,
                json!({
                    "allowed_programs": ["make", "git"],
                    "scope_policy": {"version": 1, "repositories": [{"root": inside, "connectors": []}]},
                }),
            ))
            .await,
        Outcome::Changed,
    );
    assert_eq!(body["allowed_programs"], json!(["make", "git"]));
    assert_eq!(body["scope_policy_dropped"], json!([]));
}

#[tokio::test]
async fn a_refused_settings_write_files_a_policy_locked_write_row_on_its_request() {
    let (_dirs, inside, _outside) = roots();
    let allowed = inside.parent().unwrap().to_path_buf();
    let (_tmp, store, admin, _ingress) = managed_service(Some(managed_document(&allowed))).await;
    let digest = admin.flows.policy().view().digest().unwrap().to_owned();
    store
        .insert_running_request_from(
            "req_locked",
            OP_FLOWS_SETTINGS_SET,
            ADMIN_REPO,
            ADMIN_CALLER_AGENT,
            "{}",
            None,
            &pam_store::RequestOrigin::ADMIN,
        )
        .await
        .unwrap();
    let answer = admin
        .dispatch_flows_for(
            "req_locked",
            OP_FLOWS_SETTINGS_SET,
            &json!({ "allowed_programs": ["cargo"] }),
        )
        .await
        .expect("a flow op")
        .err()
        .expect("refused");
    assert_eq!(
        answer.cause,
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    let rows = store.audit_for_request("req_locked").await.unwrap();
    let row = rows
        .iter()
        .find(|row| row.action == crate::managed_policy_service::ACTION_POLICY_LOCKED_WRITE)
        .expect("the policy.locked_write row");
    assert_eq!(row.decision, pam_store::Decision::Refuse);
    assert_eq!(row.actor, pam_store::Actor::Policy);
    let detail: serde_json::Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
    assert_eq!(
        detail,
        json!({
            "op": OP_FLOWS_SETTINGS_SET,
            "keys": ["flows.programs"],
            "cause": "policy_not_allowed",
            "digest": digest,
            "revision": "rev-9",
        })
    );
}

#[tokio::test]
async fn a_landing_save_above_the_policy_ceiling_is_refused_with_its_audit_row() {
    let (_dirs, inside, _outside) = roots();
    let workspace = inside.parent().unwrap().join("work");
    std::fs::create_dir(&workspace).unwrap();
    let (_tmp, store, admin, _ingress) = managed_service(Some(json!({
        "version": 1,
        "revision": "land-2",
        "landing": { "max_permissions": { "merge": false } }
    })))
    .await;
    let get = body_of(
        admin
            .handle(&admin_envelope(
                "req_landing_get",
                crate::admin_flows::OP_LANDING_GET,
                json!({}),
            ))
            .await,
        Outcome::Verified,
    );
    assert_eq!(get["effective"]["max_permissions"]["value"]["merge"], false);
    assert_eq!(get["landing_policy_dropped"], json!([]));
    store
        .insert_running_request_from(
            "req_landing",
            crate::admin_flows::OP_LANDING_SET,
            ADMIN_REPO,
            ADMIN_CALLER_AGENT,
            "{}",
            None,
            &pam_store::RequestOrigin::ADMIN,
        )
        .await
        .unwrap();
    let update = json!({"expected_revision": get["revision"], "repositories": [{
        "root": inside, "repository": "https://github.com/org/repo",
        "github_server": "https://api.github.com/", "github_repository": "org/repo",
        "base": "main", "branches": ["feature/work"], "workspace_root": workspace,
        "checks": [{"name": "test", "argv": ["cargo", "test"], "timeout_seconds": 300}],
        "required_checks": ["ci"], "main_checks": ["ci"],
        "permissions": {"push": true, "create_pr": true, "merge": true, "sync": false}
    }]});
    let refusal = admin
        .dispatch_flows_for("req_landing", crate::admin_flows::OP_LANDING_SET, &update)
        .await
        .expect("a flow op")
        .err()
        .expect("refused");
    assert_eq!(
        refusal.cause,
        crate::managed_policy::CAUSE_POLICY_NOT_ALLOWED
    );
    assert!(
        refusal.detail.contains("(landing.max_permissions)"),
        "{}",
        refusal.detail
    );
    assert_eq!(refusal.recovery, crate::managed_policy::RECOVERY_MANAGED);
    let rows = store.audit_for_request("req_landing").await.unwrap();
    let row = rows
        .iter()
        .find(|row| row.action == crate::managed_policy_service::ACTION_POLICY_LOCKED_WRITE)
        .expect("the policy.locked_write row");
    let detail: serde_json::Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["keys"], json!(["landing.max_permissions"]));
    assert_eq!(detail["revision"], "land-2");
    assert!(
        store
            .get_setting("flows.landing_policy")
            .await
            .unwrap()
            .is_none(),
        "nothing was written"
    );
}
