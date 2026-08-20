use std::{fs, path::Path};

use crate::{
    app::{
        FlowResponseKind, audit_export, discover_flow_catalog, flow_recovery_cursor,
        flow_response_matches, flow_run_retry, model_import, model_import_resource,
        retention_prune, select_flow,
    },
    command::RetentionScopeArg,
    render::EXIT_OPERATION_FAILED,
    request::RequestContext,
};

use pam_core::{CallerId, ContentDigest, IdempotencyKey, RequestId};
use pam_model::{LicenseSnapshot, ModelDescriptor, ModelKey};
use pam_protocol::{
    CancellationDisposition, CancellationResult, Failure, FailureCode, OperationTruth,
    ReplayResult, ResultBody, ResultPayload,
};
use uuid::Uuid;

#[test]
fn flow_commands_resolve_the_outer_project_root_from_a_subdirectory() {
    let root = std::env::temp_dir().join(format!("pam-cli-root-{}", Uuid::new_v4()));
    let outer_flows = root.join(".pam/flows");
    let nested = root.join("subdirectory/nested");
    let decoy_flows = nested.join(".pam/flows");
    fs::create_dir_all(&outer_flows).unwrap();
    fs::create_dir_all(&decoy_flows).unwrap();
    let project_id = Uuid::new_v4();
    fs::write(
        root.join(".pam/project.toml"),
        format!("version = 1\nproject_id = \"{project_id}\"\n"),
    )
    .unwrap();
    fs::write(
        outer_flows.join("outer-flow.toml"),
        super::flow_test::flow_source("outer-flow", "Outer flow"),
    )
    .unwrap();
    fs::write(
        decoy_flows.join("decoy-flow.toml"),
        super::flow_test::flow_source("decoy-flow", "Nested decoy"),
    )
    .unwrap();

    let (project, catalog) = discover_flow_catalog(&nested).unwrap();

    assert_eq!(project.root(), fs::canonicalize(&root).unwrap());
    assert_eq!(project.id().as_str(), project_id.to_string());
    assert_eq!(catalog.entries().len(), 1);
    let selected = select_flow(&catalog, "outer-flow").unwrap();
    assert_eq!(selected.definition.id(), "outer-flow");
    assert!(catalog.select("decoy-flow").is_err());
    assert!(selected.normalized.contains("id = \"outer-flow\""));
    let request = RequestContext::new_for_project(CallerId::from("cli-1"), &project, None)
        .flow_run(
            selected.source,
            Some(RequestId::from("outer-run")),
            None,
            project.root(),
        )
        .unwrap();
    assert_eq!(request.project_id, project.id().clone());
    let pam_protocol::RequestPayload::FlowRun { project_root, .. } = &request.payload else {
        panic!("expected flow run request")
    };
    assert_eq!(project_root.as_str(), project.root().to_str().unwrap());
    assert!(!format!("{request:?}").contains(project_root.as_str()));

    fs::remove_dir_all(root).unwrap();
}

fn import_descriptor(
    model_name: &str,
    filename: &str,
    size_bytes: u64,
    weights_byte: u8,
    license_id: &str,
    license_url: &str,
    license_byte: u8,
) -> ModelDescriptor {
    ModelDescriptor::new(
        ModelKey::new("vendor", model_name).unwrap(),
        filename,
        ContentDigest::from_sha256([weights_byte; 32]),
        size_bytes,
        LicenseSnapshot::new(
            license_id,
            license_url,
            ContentDigest::from_sha256([license_byte; 32]),
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn administrative_storage_ranges_are_rejected_before_local_authorization() {
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), u64::MAX, None, None, 1).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        audit_export(Path::new("unused-audit-output"), 0, Some(u64::MAX), None, 1,).await,
        EXIT_OPERATION_FAILED
    );
    assert_eq!(
        retention_prune(RetentionScopeArg::Session, u64::MAX, None, 1).await,
        EXIT_OPERATION_FAILED
    );
}

#[tokio::test]
async fn model_import_requires_explicit_license_acceptance_before_path_or_store_access() {
    assert_eq!(
        model_import(
            ModelKey::new("vendor", "model").unwrap(),
            Path::new("/definitely/missing/model.gguf"),
            ContentDigest::from_sha256([1; 32]),
            24,
            "Apache-2.0".to_owned(),
            "https://example.test/LICENSE".to_owned(),
            ContentDigest::from_sha256([2; 32]),
            false,
            None,
        )
        .await,
        EXIT_OPERATION_FAILED
    );
}

#[test]
fn model_import_approval_resource_binds_every_immutable_import_effect_field() {
    let baseline = import_descriptor(
        "model",
        "weights.gguf",
        24,
        1,
        "Apache-2.0",
        "https://example.test/LICENSE",
        2,
    );
    let baseline_resource = model_import_resource(&baseline);
    assert!(
        baseline_resource
            .as_str()
            .contains("model:vendor/model:import-effect=sha256:")
    );
    for sensitive in ["weights.gguf", "Apache-2.0", "https://example.test/LICENSE"] {
        assert!(!baseline_resource.as_str().contains(sensitive));
    }

    for changed in [
        import_descriptor(
            "other",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "other.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            25,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            3,
            "Apache-2.0",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "MIT",
            "https://example.test/LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/OTHER-LICENSE",
            2,
        ),
        import_descriptor(
            "model",
            "weights.gguf",
            24,
            1,
            "Apache-2.0",
            "https://example.test/LICENSE",
            4,
        ),
    ] {
        assert_ne!(baseline_resource, model_import_resource(&changed));
    }
}

#[test]
fn flow_modes_accept_only_their_typed_payload_or_failure() {
    let failure = ResultBody::Failure(Failure {
        code: FailureCode::Internal,
        message: "bounded failure".to_owned(),
        recovery: None,
        approval: None,
    });
    let replay = ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::Replay(ReplayResult {
            target_request_id: RequestId::from("run-1"),
            through_sequence: 4,
            pending: true,
        }),
    };
    let cancellation = ResultBody::Success {
        truth: OperationTruth::Changed,
        payload: ResultPayload::Cancellation(CancellationResult {
            target_request_id: RequestId::from("run-1"),
            disposition: CancellationDisposition::Requested,
        }),
    };
    let terminal = terminal_flow_body();

    for expected in [
        FlowResponseKind::Run,
        FlowResponseKind::Wait,
        FlowResponseKind::Result,
        FlowResponseKind::Replay,
        FlowResponseKind::Cancellation,
    ] {
        assert!(flow_response_matches(&failure, expected));
    }
    assert!(flow_response_matches(&terminal, FlowResponseKind::Run));
    assert!(flow_response_matches(&terminal, FlowResponseKind::Wait));
    assert!(flow_response_matches(&terminal, FlowResponseKind::Result));
    assert!(!flow_response_matches(&terminal, FlowResponseKind::Replay));
    assert!(!flow_response_matches(
        &terminal,
        FlowResponseKind::Cancellation
    ));
    assert!(flow_response_matches(&replay, FlowResponseKind::Replay));
    assert!(!flow_response_matches(&replay, FlowResponseKind::Run));
    assert!(flow_response_matches(
        &cancellation,
        FlowResponseKind::Cancellation
    ));
    assert!(!flow_response_matches(
        &cancellation,
        FlowResponseKind::Replay
    ));
}

#[test]
fn flow_recovery_cursor_never_confuses_observer_events_with_target_events() {
    assert_eq!(flow_recovery_cursor(FlowResponseKind::Cancellation, 42), 0);
    assert_eq!(flow_recovery_cursor(FlowResponseKind::Result, 42), 0);
    assert_eq!(flow_recovery_cursor(FlowResponseKind::Run, 42), 42);
    assert_eq!(flow_recovery_cursor(FlowResponseKind::Wait, 42), 42);
    assert_eq!(flow_recovery_cursor(FlowResponseKind::Replay, 42), 42);
}

#[test]
fn flow_run_recovery_uses_the_canonical_id_and_exact_durable_identity() {
    assert_eq!(
        flow_run_retry(
            "flow-alpha",
            &RequestId::from("stable-run"),
            &IdempotencyKey::from("stable-key"),
        ),
        "pam flow run flow-alpha --run-id stable-run --idempotency-key stable-key"
    );
}

fn terminal_flow_body() -> ResultBody {
    let definition = pam_flow::FlowDefinition::parse_toml(&super::flow_test::flow_source(
        "response-flow",
        "Response flow",
    ))
    .unwrap();
    let mut run =
        pam_flow::FlowRun::start(pam_flow::RunId::parse("response-run").unwrap(), definition)
            .unwrap();
    let update = run.cancel().unwrap();
    let pam_flow::RunDecision::Terminal { result } = update.decision() else {
        panic!("cancel before execution must be terminal")
    };
    ResultBody::Success {
        truth: OperationTruth::Unresolved,
        payload: ResultPayload::FlowRun(result.clone()),
    }
}
