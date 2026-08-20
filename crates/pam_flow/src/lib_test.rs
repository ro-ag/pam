use std::fmt::Write as _;

use super::*;

const FULL_V1: &str = include_str!("../tests/fixtures/full_v1.toml");
const NORMALIZED_V1: &str = include_str!("../tests/fixtures/full_v1.normalized.toml");

fn parsed_full() -> FlowDefinition {
    FlowDefinition::parse_toml(FULL_V1).expect("full version-one fixture should be valid")
}

fn validation_error_from(source: &str) -> FlowValidationError {
    match FlowDefinition::parse_toml(source) {
        Err(FlowParseError::Validation(error)) => error,
        unexpected => panic!("expected validation error, got {unexpected:?}"),
    }
}

fn with_replacement(from: &str, to: &str) -> String {
    let source = FULL_V1.replacen(from, to, 1);
    assert_ne!(source, FULL_V1, "test replacement must change the fixture");
    source
}

fn full_v2() -> String {
    let roles = ["observe", "verify", "observe", "change"];
    let mut role_index = 0;
    let mut source = String::new();
    for line in FULL_V1.lines() {
        if line == "schema_version = 1" {
            source.push_str("schema_version = 2\n");
            continue;
        }
        source.push_str(line);
        source.push('\n');
        if line.starts_with("effect = ") {
            writeln!(source, "semantic = \"{}\"", roles[role_index]).unwrap();
            role_index += 1;
        }
    }
    assert_eq!(role_index, roles.len());
    source
}

#[test]
fn full_v1_golden_parses_with_typed_accessors() {
    let flow = parsed_full();

    assert_eq!(MIN_FLOW_SCHEMA_VERSION, 1);
    assert_eq!(FLOW_SCHEMA_VERSION, 2);
    assert_eq!(flow.schema_version(), 1);
    assert_eq!(flow.id(), "after-merge-checks");
    assert_eq!(flow.name(), "After merge checks");
    assert_eq!(flow.revision(), 7);
    assert_eq!(flow.steps().len(), 4);
    assert_eq!(
        flow.outcome().solved(),
        "State whether the after-merge checks are healthy."
    );

    let command = flow.steps()[0].action().as_command().unwrap();
    assert_eq!(command.program, "git");
    assert_eq!(command.args, ["status", "--short"]);
    assert_eq!(command.working_directory, ".");

    let connector = flow.steps()[3].action().as_connector().unwrap();
    assert_eq!(connector.connector, "github.actions");
    assert_eq!(connector.capability, "runs.rerun");
    assert_eq!(connector.resource.kind(), "workflow_run");
    assert_eq!(connector.resource.id(), "github:ro-ag/pam/runs/12345");
    assert_eq!(flow.steps()[3].approval(), ApprovalMode::Required);
    assert_eq!(flow.steps()[3].effect(), EffectKind::Stateful);
    assert_eq!(flow.steps()[0].semantic_role(), StepSemanticRole::Observe);
    assert_eq!(flow.steps()[1].semantic_role(), StepSemanticRole::Observe);
    assert_eq!(flow.steps()[2].semantic_role(), StepSemanticRole::Observe);
    assert_eq!(flow.steps()[3].semantic_role(), StepSemanticRole::Change);
}

#[test]
fn normalization_matches_golden_and_round_trips_byte_for_byte() {
    let flow = parsed_full();
    let normalized = flow.to_normalized_toml().unwrap();
    assert_eq!(normalized.as_bytes(), NORMALIZED_V1.as_bytes());

    let reparsed = FlowDefinition::parse_toml(&normalized).unwrap();
    assert_eq!(reparsed, flow);
    assert_eq!(
        reparsed.to_normalized_toml().unwrap().as_bytes(),
        normalized.as_bytes()
    );
    assert_eq!(
        reparsed.normalized_digest().unwrap(),
        flow.normalized_digest().unwrap()
    );
    assert!(
        flow.normalized_digest()
            .unwrap()
            .to_string()
            .starts_with("sha256:")
    );
}

#[test]
fn unknown_fields_and_unsupported_versions_are_rejected() {
    let unknown = with_replacement(
        "revision = 7",
        "revision = 7\ncredential_token = \"do-not-store-this\"",
    );
    let error = FlowDefinition::parse_toml(&unknown).unwrap_err();
    assert!(matches!(error, FlowParseError::Toml(_)));
    assert!(
        error
            .to_string()
            .contains("unknown field `credential_token`")
    );

    let unsupported = with_replacement("schema_version = 1", "schema_version = 3");
    let error = validation_error_from(&unsupported);
    assert_eq!(error.path(), "schema_version");
    assert!(error.message().contains("unsupported schema version 3"));
}

#[test]
fn schema_v2_requires_explicit_safe_semantics_and_normalizes_them() {
    let source = full_v2();
    let flow = FlowDefinition::parse_toml(&source).unwrap();
    assert_eq!(flow.schema_version(), 2);
    assert_eq!(flow.steps()[0].semantic_role(), StepSemanticRole::Observe);
    assert_eq!(flow.steps()[1].semantic_role(), StepSemanticRole::Verify);
    assert_eq!(flow.steps()[2].semantic_role(), StepSemanticRole::Observe);
    assert_eq!(flow.steps()[3].semantic_role(), StepSemanticRole::Change);

    let normalized = flow.to_normalized_toml().unwrap();
    assert_eq!(
        normalized.matches("semantic = ").count(),
        flow.steps().len()
    );
    assert!(normalized.contains("semantic = \"verify\""));
    assert_eq!(
        FlowDefinition::parse_toml(&normalized)
            .unwrap()
            .normalized_digest()
            .unwrap(),
        flow.normalized_digest().unwrap()
    );

    let missing = source.replacen("semantic = \"observe\"\n", "", 1);
    let error = validation_error_from(&missing);
    assert_eq!(error.path(), "steps[0].semantic");

    let unsafe_change = source.replacen("semantic = \"observe\"", "semantic = \"change\"", 1);
    let error = validation_error_from(&unsafe_change);
    assert_eq!(error.path(), "steps[0].semantic");
    assert!(error.message().contains("stateful effect"));

    let unsafe_verify = source.replacen("semantic = \"change\"", "semantic = \"verify\"", 1);
    let error = validation_error_from(&unsafe_verify);
    assert_eq!(error.path(), "steps[3].semantic");
    assert!(error.message().contains("must use change"));
}

#[test]
fn schema_v1_rejects_semantics_and_preserves_normalized_digest() {
    let with_semantic = with_replacement(
        "effect = \"read_only\"",
        "effect = \"read_only\"\nsemantic = \"observe\"",
    );
    let error = validation_error_from(&with_semantic);
    assert_eq!(error.path(), "steps[0].semantic");
    assert!(error.message().contains("must omit"));

    let flow = parsed_full();
    assert_eq!(flow.to_normalized_toml().unwrap(), NORMALIZED_V1);
    assert_eq!(
        flow.normalized_digest().unwrap().to_string(),
        "sha256:9c9c1ef52ac220c61c18df68be2a4db3dda5985d57054df230695c8a097b6a26"
    );
}

#[test]
fn empty_oversized_duplicate_and_unknown_step_fields_are_rejected() {
    let empty_name = with_replacement("name = \"After merge checks\"", "name = \"\"");
    assert_eq!(validation_error_from(&empty_name).path(), "name");

    let oversized = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
    let oversized = with_replacement(
        "description = \"Collect CI evidence, diagnose failures, and rerun only with approval.\"",
        &format!("description = \"{oversized}\""),
    );
    assert_eq!(validation_error_from(&oversized).path(), "description");

    let duplicate = with_replacement("id = \"run-tests\"", "id = \"inspect-repository\"");
    let error = validation_error_from(&duplicate);
    assert_eq!(error.path(), "steps[1].id");
    assert!(error.message().contains("duplicates steps[0].id"));

    let dependency = with_replacement(
        "depends_on = [\"inspect-repository\"]",
        "depends_on = [\"missing-step\"]",
    );
    assert_eq!(
        validation_error_from(&dependency).path(),
        "steps[1].depends_on[0]"
    );

    let condition = with_replacement(
        "condition = { step = \"inspect-repository\", kind = \"succeeded\" }",
        "condition = { step = \"missing-step\", kind = \"succeeded\" }",
    );
    assert_eq!(
        validation_error_from(&condition).path(),
        "steps[1].condition.step"
    );
}

#[test]
fn explicit_dependencies_and_conditions_are_both_cycle_checked() {
    let source = with_replacement(
        "action = { working_directory = \".\", args = [\"status\", \"--short\"], type = \"command\", program = \"git\" }",
        "condition = { kind = \"succeeded\", step = \"run-tests\" }\naction = { working_directory = \".\", args = [\"status\", \"--short\"], type = \"command\", program = \"git\" }",
    );
    let error = validation_error_from(&source);
    assert!(error.message().contains(
        "dependency cycle detected: inspect-repository -> run-tests -> inspect-repository"
    ));
}

#[test]
fn command_paths_arguments_timeouts_and_retry_budgets_are_bounded() {
    for invalid in ["../outside", "/tmp", "C:\\\\temp", "nested//directory"] {
        let source = with_replacement(
            "working_directory = \".\"",
            &format!("working_directory = \"{invalid}\""),
        );
        assert_eq!(
            validation_error_from(&source).path(),
            "steps[0].action.working_directory"
        );
    }

    let timeout = with_replacement("timeout_seconds = 30", "timeout_seconds = 0");
    assert_eq!(
        validation_error_from(&timeout).path(),
        "steps[0].timeout_seconds"
    );

    let attempts = with_replacement("max_attempts = 3", "max_attempts = 6");
    assert_eq!(
        validation_error_from(&attempts).path(),
        "steps[1].retry.max_attempts"
    );

    let backoff = with_replacement("max_backoff_ms = 2000", "max_backoff_ms = 100");
    assert_eq!(
        validation_error_from(&backoff).path(),
        "steps[1].retry.max_backoff_ms"
    );

    let oversized_argument = "x".repeat(MAX_COMMAND_ARG_BYTES + 1);
    let argument = with_replacement(
        "args = [\"status\", \"--short\"]",
        &format!("args = [\"{oversized_argument}\"]"),
    );
    assert_eq!(
        validation_error_from(&argument).path(),
        "steps[0].action.args[0]"
    );
}

#[test]
fn stateful_steps_require_approval_and_idempotency() {
    let no_approval = with_replacement("approval = \"required\"", "approval = \"none\"");
    assert_eq!(
        validation_error_from(&no_approval).path(),
        "steps[3].approval"
    );

    let no_key = with_replacement("idempotency_key = \"after-merge-checks:r7:rerun-ci\"\n", "");
    assert_eq!(
        validation_error_from(&no_key).path(),
        "steps[3].idempotency_key"
    );
}

#[test]
fn inline_secrets_and_bad_connector_coordinates_are_rejected() {
    for argument in [
        "--token=plain-text",
        "Bearer abcdefghijklmnop",
        "github_pat_abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
        "https://user:password@example.test/api",
    ] {
        let source = with_replacement(
            "args = [\"status\", \"--short\"]",
            &format!("args = [\"{argument}\"]"),
        );
        assert_eq!(
            validation_error_from(&source).path(),
            "steps[0].action.args[0]"
        );
    }

    let connector = with_replacement(
        "connector = \"github.actions\"",
        "connector = \"GitHub Actions\"",
    );
    assert_eq!(
        validation_error_from(&connector).path(),
        "steps[2].action.connector"
    );

    let capability = with_replacement(
        "capability = \"runs.inspect\"",
        "capability = \"runs..inspect\"",
    );
    assert_eq!(
        validation_error_from(&capability).path(),
        "steps[2].action.capability"
    );

    let resource = with_replacement(
        "id = \"github:ro-ag/pam/runs/12345\"",
        "id = \"https://example.test/runs/12345?token=secret\"",
    );
    assert_eq!(
        validation_error_from(&resource).path(),
        "steps[2].action.resource.id"
    );
}

#[test]
fn document_size_is_rejected_before_toml_parsing() {
    let source = "x".repeat(MAX_FLOW_DOCUMENT_BYTES + 1);
    assert!(matches!(
        FlowDefinition::parse_toml(&source),
        Err(FlowParseError::DocumentTooLarge { .. })
    ));
}
