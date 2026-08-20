use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    CallerCredential, CallerId, EvidenceHandle, GrantId, IdempotencyKey, ProjectId, RequestId,
};
use pam_flow::{
    EffectResult, FlowDefinition, FlowRun, FlowSnapshot, RunDecision, RunId, RunOutcome,
    TransitionKind,
};
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_policy::{ApprovalRequirement, CapabilityName, Effect, Grant, ResourceName, ResourceScope};
use pam_protocol::{
    Event, FailureCode, FlowDefinitionDocument, OperationTruth, RequestEnvelope, RequestPayload,
    ResultBody, ResultPayload, ServerMessage, decode_server_message,
};
use pam_store::{
    AcceptOutcome, AcceptRequest, ApprovalDecision, ApprovalDecisionOutcome, AuthorizationAudit,
    AuthorizeFlowRun, CancelOutcome, FlowAuthorizationOutcome, GrantRevocation, PutGrant,
    RequestState, SaveFlowCheckpoint, Store, StoreError, TerminalState,
};
use tokio::{process::Command, sync::oneshot};

use super::{
    flow::{
        CommandExecution, CommandRejection, FLOW_OPERATION_KIND, FlowProcessing,
        FlowSubmissionError, PreparedCommand, PreparedFlowSubmission, WorkspaceAuthority,
        WorkspaceFingerprint, WorkspaceFingerprintLease, await_workspace_fingerprint_with_lease,
        execute_command, execute_command_in_workspace, flow_policy_resource,
        hash_relative_after_authority_open, persist_update_reconciling_cancellation,
        prepare_command, prepare_flow_submission, process_flow, run_bounded_listing,
        safe_environment_name, validated_git_args, workspace_fingerprint,
    },
    lifecycle::{DaemonConfig, decode_stored_result, serve_until_with_delay},
};
use crate::request_exchange;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

const HEADER: &str = r#"
schema_version = 2
id = "daemon-flow-test"
name = "Daemon flow test"
description = "Exercise the bounded daemon flow adapter."
revision = 1

[outcome]
solved = "Report solved work."
changed = "Report changed state."
verified = "Report verified evidence."
unresolved = "Report unresolved work."
blocked = "Report the exact blocker."
"#;

fn definition(step: &str) -> String {
    format!("{HEADER}{step}")
}

fn command_step(program: &str, args: &str, extra: &str) -> String {
    let semantic = if program == "git" && args.contains("\"diff\"") {
        "verify"
    } else {
        "observe"
    };
    definition(&format!(
        r#"
[[steps]]
id = "command"
description = "Run one bounded command."
{extra}
timeout_seconds = 10
effect = "read_only"
semantic = "{semantic}"
action = {{ type = "command", program = "{program}", args = [{args}], working_directory = "." }}
"#
    ))
}

fn legacy_command_step(program: &str, args: &str, extra: &str) -> String {
    command_step(program, args, extra)
        .replacen("schema_version = 2", "schema_version = 1", 1)
        .replace("semantic = \"observe\"\n", "")
        .replace("semantic = \"verify\"\n", "")
}

fn flow_request(id: &str, source: String, project_root: &Path) -> RequestEnvelope {
    RequestEnvelope::flow_run(
        RequestId::from(id),
        CallerId::from("flow-test-caller"),
        ProjectId::from("11111111-1111-4111-8111-111111111111"),
        IdempotencyKey::new(format!("{id}-key")),
        source,
        project_root.to_str().unwrap(),
    )
    .unwrap()
}

async fn authorize_flow_fixture(
    store: &Store,
    request: &RequestEnvelope,
    operation: Vec<u8>,
    resource: &str,
    now_ms: u64,
) -> AcceptOutcome {
    seed_flow_policy_fixture(store, request, resource, now_ms).await;
    let outcome = store
        .authorize_flow_run(
            flow_authorization_request(request, operation, resource, now_ms),
            now_ms,
            60_000,
        )
        .await
        .unwrap();
    let FlowAuthorizationOutcome::Accepted(accepted) = outcome else {
        panic!("flow fixture was not atomically authorized: {outcome:?}")
    };
    accepted
}

async fn seed_flow_policy_fixture(
    store: &Store,
    request: &RequestEnvelope,
    resource: &str,
    now_ms: u64,
) {
    let credential = CallerCredential::new(format!("{}-credential", request.request_id));
    seed_flow_policy_fixture_with_approval(
        store,
        request,
        resource,
        credential,
        ApprovalRequirement::None,
        now_ms,
    )
    .await;
}

async fn seed_flow_policy_fixture_with_approval(
    store: &Store,
    request: &RequestEnvelope,
    resource: &str,
    credential: CallerCredential,
    approval: ApprovalRequirement,
    now_ms: u64,
) {
    store
        .register_caller(
            request.caller_id.clone(),
            credential,
            now_ms.saturating_sub(2),
        )
        .await
        .unwrap();
    store
        .put_grant(PutGrant {
            grant: Grant {
                id: GrantId::from(format!("{}-grant", request.request_id)),
                caller: request.caller_id.clone(),
                project: request.project_id.clone(),
                capability: CapabilityName::parse("flow.run").unwrap(),
                resource: ResourceScope::Exact(ResourceName::parse(resource).unwrap()),
                effect: Effect::Allow,
                approval,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: now_ms.saturating_sub(1),
        })
        .await
        .unwrap();
}

async fn seed_flow_request_authority(
    state_path: &Path,
    execution_root: &Path,
    request: &RequestEnvelope,
) -> PreparedFlowSubmission {
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, execution_root)
        .await
        .unwrap();
    let store = Store::open(state_path).unwrap();
    seed_flow_policy_fixture(&store, request, &prepared.policy_resource, test_now_ms()).await;
    store.shutdown().await.unwrap();
    prepared
}

fn flow_authorization_request(
    request: &RequestEnvelope,
    operation: Vec<u8>,
    resource: &str,
    now_ms: u64,
) -> AuthorizeFlowRun {
    AuthorizeFlowRun {
        accept: AcceptRequest {
            request_id: request.request_id.clone(),
            caller_id: request.caller_id.clone(),
            project_id: request.project_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            operation_kind: FLOW_OPERATION_KIND.to_owned(),
            operation,
        },
        resource: ResourceName::parse(resource).unwrap(),
        approval_id: request.approval_id.clone(),
        audit: AuthorizationAudit {
            event_id: format!("{}-authorization-{now_ms}", request.request_id),
            action: "flow.run.authorize".to_owned(),
            redacted_detail: "authorized exact flow fixture".to_owned(),
            retain_until_ms: now_ms.saturating_add(60_000),
        },
        schema_approval_required: false,
    }
}

fn test_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn test_runtime(name: &str) -> PathBuf {
    let sequence = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!(
        "pam-daemon-flow-{name}-{}-{sequence}",
        std::process::id()
    ))
}

async fn wait_until_ready(endpoint: &LocalEndpoint) {
    for _ in 0..500 {
        if endpoint.socket_path().is_some_and(Path::exists) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon did not become ready")
}

fn start_daemon(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), crate::DaemonError>>,
) {
    start_daemon_with_delay(endpoint, state_path, Duration::ZERO)
}

fn start_daemon_with_delay(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    delay: Duration,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), crate::DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider: None,
            bypass_authentication: true,
            bypass_policy: true,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    (shutdown_tx, daemon)
}

fn start_secure_daemon(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), crate::DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider: None,
            bypass_authentication: false,
            bypass_policy: false,
            flow_preflight_capacity: super::lifecycle::FLOW_PREFLIGHT_CAPACITY,
            flow_preflight_delay: Duration::ZERO,
        },
        async {
            let _ = shutdown_rx.await;
        },
        Duration::ZERO,
    ));
    (shutdown_tx, daemon)
}

fn start_daemon_with_preflight_limit(
    endpoint: LocalEndpoint,
    state_path: PathBuf,
    capacity: usize,
    preflight_delay: Duration,
) -> (
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<(), crate::DaemonError>>,
) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint,
            recover: false,
            model: None,
            state_path: Some(state_path),
            brief_provider: None,
            bypass_authentication: true,
            bypass_policy: true,
            flow_preflight_capacity: capacity,
            flow_preflight_delay: preflight_delay,
        },
        async {
            let _ = shutdown_rx.await;
        },
        Duration::ZERO,
    ));
    (shutdown_tx, daemon)
}

fn create_workspace(runtime: &Path) -> PathBuf {
    create_workspace_with_project(runtime, "11111111-1111-4111-8111-111111111111")
}

fn create_workspace_with_project(runtime: &Path, project_id: &str) -> PathBuf {
    let workspace = runtime.join("workspace");
    fs::create_dir_all(workspace.join("src")).unwrap();
    fs::create_dir_all(workspace.join(".pam")).unwrap();
    fs::write(
        workspace.join(".pam/project.toml"),
        format!("version = 1\nproject_id = \"{project_id}\"\n"),
    )
    .unwrap();
    fs::write(
        workspace.join("Cargo.toml"),
        b"[package]\nname = \"pam-flow-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(workspace.join("Cargo.lock"), b"version = 4\n").unwrap();
    fs::write(workspace.join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::write(
        workspace.join(".gitignore"),
        b"/target\n/.cargo/config.toml\n",
    )
    .unwrap();
    assert!(
        StdCommand::new("git")
            .args(["init", "--quiet"])
            .current_dir(&workspace)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        StdCommand::new("git")
            .args(["add", "--all"])
            .current_dir(&workspace)
            .status()
            .unwrap()
            .success()
    );
    workspace.canonicalize().unwrap()
}

fn first_effect(source: &str) -> (FlowDefinition, pam_flow::EffectAttempt) {
    let definition = FlowDefinition::parse_toml(source).unwrap();
    let mut run =
        FlowRun::start(RunId::parse("validator-run").unwrap(), definition.clone()).unwrap();
    let update = run.next_decision(1).unwrap();
    let RunDecision::EvaluateEffect { effect, .. } = update.decision() else {
        panic!("expected an effect evaluation")
    };
    (definition, effect.clone())
}

#[test]
fn policy_resource_is_normalized_stable_and_redacts_raw_toml() {
    let marker = "private description bytes never belong in policy";
    let first = command_step("git", r#""status", "--short""#, "")
        .replace("Exercise the bounded daemon flow adapter.", marker);
    let second = format!("\n{first}\n");
    let first = FlowDefinitionDocument::new(first).unwrap();
    let second = FlowDefinitionDocument::new(second).unwrap();
    let first_definition = FlowDefinition::parse_toml(first.as_str()).unwrap();
    let second_definition = FlowDefinition::parse_toml(second.as_str()).unwrap();
    let workspace = WorkspaceFingerprint([7; 32]);
    let resource = flow_policy_resource(&first_definition, workspace).unwrap();

    assert_eq!(
        resource,
        flow_policy_resource(&second_definition, workspace).unwrap()
    );
    assert!(resource.starts_with("flow:daemon-flow-test:revision=1:digest=sha256:"));
    assert!(resource.contains(":workspace=sha256:"));
    assert!(!resource.contains(marker));
    assert_eq!(
        first_definition.to_normalized_toml().unwrap(),
        second_definition.to_normalized_toml().unwrap()
    );
}

#[test]
fn command_allowlist_rejects_shells_and_git_mutation_flags() {
    assert!(validated_git_args(&["status".to_owned(), "--short".to_owned()]).is_ok());
    assert!(validated_git_args(&["diff".to_owned(), "--quiet".to_owned()]).is_ok());
    assert!(validated_git_args(&["diff".to_owned(), "--ext-diff".to_owned()]).is_err());
    assert!(
        validated_git_args(&[
            "diff".to_owned(),
            "--quiet".to_owned(),
            "--cached".to_owned()
        ])
        .is_err()
    );
    assert!(validated_git_args(&["status".to_owned(), "--ignored".to_owned()]).is_err());
    assert!(validated_git_args(&["rev-parse".to_owned(), "HEAD".to_owned()]).is_ok());
    assert!(
        validated_git_args(&["rev-parse".to_owned(), "refs/heads/unbound".to_owned()]).is_err()
    );

    let shell = command_step("sh", r#""-c", "touch owned""#, "");
    let (definition, effect) = first_effect(&shell);
    let root = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(
        prepare_command(&root, &definition, &effect).unwrap_err(),
        CommandRejection::Unsupported
    );
}

#[tokio::test]
async fn git_index_and_head_bytes_are_bound_into_workspace_authority() {
    let runtime = test_runtime("git-authority");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let document =
        FlowDefinitionDocument::new(command_step("git", r#""status", "--short""#, "")).unwrap();
    let accepted = prepare_flow_submission(&document, &workspace)
        .await
        .unwrap();

    assert!(
        StdCommand::new("git")
            .args(["update-index", "--chmod=+x", "src/main.rs"])
            .current_dir(&workspace)
            .status()
            .unwrap()
            .success()
    );
    let changed_index = prepare_flow_submission(&document, &workspace)
        .await
        .unwrap();
    assert_ne!(changed_index.operation, accepted.operation);

    let head = fs::read_to_string(workspace.join(".git/HEAD")).unwrap();
    let head_reference = head.trim().strip_prefix("ref: ").unwrap();
    let head_path = workspace.join(".git").join(head_reference);
    fs::create_dir_all(head_path.parent().unwrap()).unwrap();
    fs::write(head_path, b"1111111111111111111111111111111111111111\n").unwrap();
    let changed_head = prepare_flow_submission(&document, &workspace)
        .await
        .unwrap();
    assert_ne!(changed_head.operation, changed_index.operation);

    fs::write(workspace.join(".gitignore"), b"/target\n/.gitattributes\n").unwrap();
    fs::write(workspace.join(".gitattributes"), b"*.rs -text\n").unwrap();
    let ignored_attributes = prepare_flow_submission(&document, &workspace)
        .await
        .unwrap();
    fs::write(workspace.join(".gitattributes"), b"*.rs text\n").unwrap();
    let changed_ignored_attributes = prepare_flow_submission(&document, &workspace)
        .await
        .unwrap();
    assert_ne!(
        changed_ignored_attributes.operation,
        ignored_attributes.operation
    );

    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[test]
fn capability_hashing_rejects_leaf_and_ancestor_link_or_fifo_swaps() {
    use std::os::unix::fs::symlink;

    fn rejected_quickly(result: Result<(), FlowSubmissionError>, started: Instant) {
        assert!(matches!(
            result,
            Err(FlowSubmissionError::WorkspaceUnavailable)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    let runtime = test_runtime("capability-hash-swaps");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();

    let leaf_link = create_workspace(&runtime.join("leaf-link"));
    let outside = runtime.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("main.rs"), b"outside bytes\n").unwrap();
    let started = Instant::now();
    let result =
        hash_relative_after_authority_open(&leaf_link, false, Path::new("src/main.rs"), || {
            fs::remove_file(leaf_link.join("src/main.rs")).unwrap();
            symlink(outside.join("main.rs"), leaf_link.join("src/main.rs")).unwrap();
        });
    rejected_quickly(result, started);

    let leaf_fifo = create_workspace(&runtime.join("leaf-fifo"));
    let started = Instant::now();
    let result =
        hash_relative_after_authority_open(&leaf_fifo, false, Path::new("src/main.rs"), || {
            fs::remove_file(leaf_fifo.join("src/main.rs")).unwrap();
            assert!(
                StdCommand::new("mkfifo")
                    .arg(leaf_fifo.join("src/main.rs"))
                    .status()
                    .unwrap()
                    .success()
            );
        });
    rejected_quickly(result, started);

    for fifo in [false, true] {
        let workspace = create_workspace(&runtime.join(format!("ancestor-{fifo}")));
        let outside_directory = runtime.join(format!("ancestor-outside-{fifo}"));
        fs::create_dir_all(&outside_directory).unwrap();
        if fifo {
            assert!(
                StdCommand::new("mkfifo")
                    .arg(outside_directory.join("main.rs"))
                    .status()
                    .unwrap()
                    .success()
            );
        } else {
            fs::write(outside_directory.join("main.rs"), b"outside bytes\n").unwrap();
        }
        let started = Instant::now();
        let result =
            hash_relative_after_authority_open(&workspace, false, Path::new("src/main.rs"), || {
                fs::remove_dir_all(workspace.join("src")).unwrap();
                symlink(&outside_directory, workspace.join("src")).unwrap();
            });
        rejected_quickly(result, started);
    }

    let git_ancestor = create_workspace(&runtime.join("git-ancestor"));
    let outside_info = runtime.join("outside-info");
    fs::create_dir_all(&outside_info).unwrap();
    fs::write(outside_info.join("exclude"), b"outside\n").unwrap();
    let started = Instant::now();
    let result =
        hash_relative_after_authority_open(&git_ancestor, true, Path::new("info/exclude"), || {
            fs::remove_dir_all(git_ancestor.join(".git/info")).unwrap();
            symlink(&outside_info, git_ancestor.join(".git/info")).unwrap();
        });
    rejected_quickly(result, started);

    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[test]
fn workspace_authority_detects_root_or_git_directory_replacement() {
    use std::os::unix::fs::symlink;

    let runtime = test_runtime("workspace-identity");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let authority = WorkspaceAuthority::open(&workspace).unwrap();
    assert!(authority.verify_path_identity().is_ok());

    let moved = runtime.join("workspace-moved");
    let replacement = runtime.join("replacement");
    fs::rename(&workspace, &moved).unwrap();
    fs::create_dir_all(&replacement).unwrap();
    symlink(&replacement, &workspace).unwrap();
    assert!(matches!(
        authority.verify_path_identity(),
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));
    fs::remove_file(&workspace).unwrap();
    fs::rename(&moved, &workspace).unwrap();

    let authority = WorkspaceAuthority::open(&workspace).unwrap();
    let moved_git = workspace.join(".git-held");
    fs::rename(workspace.join(".git"), &moved_git).unwrap();
    symlink(&replacement, workspace.join(".git")).unwrap();
    assert!(matches!(
        authority.verify_path_identity(),
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));

    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test]
async fn hostile_git_configuration_is_rejected_before_git_runs() {
    let runtime = test_runtime("hostile-git-config");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let document =
        FlowDefinitionDocument::new(command_step("git", r#""status", "--short""#, "")).unwrap();

    let config_path = workspace.join(".git/config");
    let base_config = fs::read_to_string(&config_path).unwrap();
    let external_worktree = runtime.join("external-worktree");
    fs::create_dir_all(&external_worktree).unwrap();
    fs::write(
        &config_path,
        format!("{base_config}\n[core]\nworktree = {external_worktree:?}\n"),
    )
    .unwrap();
    assert!(matches!(
        prepare_flow_submission(&document, &workspace).await,
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));
    fs::write(
        &config_path,
        format!("{base_config}\n[filter \"hostile\"]\nclean = touch owned\n"),
    )
    .unwrap();
    assert!(matches!(
        prepare_flow_submission(&document, &workspace).await,
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));

    let sentinel = runtime.join("legacy-filter-ran");
    fs::write(
        workspace.join(".gitattributes"),
        b"*.rs filter=legacy-hostile\n",
    )
    .unwrap();
    fs::write(
        &config_path,
        format!(
            "{base_config}\n[filter.legacy-hostile]\nclean = touch {}\n",
            sentinel.display()
        ),
    )
    .unwrap();
    fs::write(
        workspace.join("src/main.rs"),
        b"fn main() { println!(\"changed\"); }\n",
    )
    .unwrap();
    assert!(matches!(
        prepare_flow_submission(&document, &workspace).await,
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));
    assert!(!sentinel.exists(), "legacy Git clean filter executed");

    let worktree_sentinel = runtime.join("worktree-filter-ran");
    fs::write(
        &config_path,
        format!("{base_config}\n[extensions]\nworktreeConfig = true\n"),
    )
    .unwrap();
    fs::write(
        workspace.join(".git/config.worktree"),
        format!(
            "[filter \"legacy-hostile\"]\nclean = touch {}\n",
            worktree_sentinel.display()
        ),
    )
    .unwrap();
    assert!(matches!(
        prepare_flow_submission(&document, &workspace).await,
        Err(FlowSubmissionError::WorkspaceUnavailable)
    ));
    assert!(
        !worktree_sentinel.exists(),
        "worktree Git clean filter executed"
    );

    fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn ignored_or_nested_working_directory_is_rejected() {
    let runtime = test_runtime("nested-working-directory");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    fs::create_dir_all(workspace.join("target/ignored-project")).unwrap();
    let source = command_step("git", r#""status", "--short""#, "").replace(
        "working_directory = \".\"",
        "working_directory = \"target/ignored-project\"",
    );
    let (definition, effect) = first_effect(&source);
    assert_eq!(
        prepare_command(&workspace, &definition, &effect).unwrap_err(),
        CommandRejection::UnsafeWorkingDirectory
    );
    fs::remove_dir_all(runtime).unwrap();
}

#[test]
fn connectors_stateful_classification_and_approval_are_never_prepared_as_commands() {
    let connector = definition(
        r#"
[[steps]]
id = "connector"
description = "Observe a connector."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = { type = "connector", connector = "github.actions", capability = "runs.read", resource = { kind = "workflow_run", id = "github:ro-ag/pam/runs/1" } }
"#,
    );
    let (definition, effect) = first_effect(&connector);
    let root = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(
        prepare_command(&root, &definition, &effect).unwrap_err(),
        CommandRejection::Unsupported
    );

    let approval = command_step("git", r#""status", "--short""#, "approval = \"required\"");
    let definition = FlowDefinition::parse_toml(&approval).unwrap();
    let mut run = FlowRun::start(RunId::parse("approval-run").unwrap(), definition).unwrap();
    assert!(matches!(
        run.next_decision(1).unwrap().decision(),
        RunDecision::AwaitApproval { .. }
    ));
}

#[test]
fn inherited_secret_and_process_override_environment_is_removed() {
    for name in [
        "GITHUB_TOKEN",
        "DATABASE_PASSWORD",
        "AWS_ACCESS_KEY_ID",
        "CLIENT_CREDENTIAL",
        "RUSTC_WRAPPER",
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG_KEY_7",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "SSH_AUTH_SOCK",
        "RUSTC",
        "RUSTDOCFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "GIT_INDEX_FILE",
        "HOME",
        "CARGO_HOME",
        "CC",
    ] {
        assert!(!safe_environment_name(name.as_ref()), "{name}");
    }
    for name in ["PATH", "LANG", "TMPDIR"] {
        assert!(safe_environment_name(name.as_ref()), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_status_runs_end_to_end_with_durable_evidence_and_semantic_replay() {
    let runtime = test_runtime("git-status");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let credential = "credential-must-not-enter-flow-operation";
    let request = flow_request(
        "git-status-flow",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    )
    .authenticated(CallerCredential::new(credential));
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(15))
        .await
        .unwrap();
    assert!(matches!(exchange.events[0].event, Event::Accepted));
    assert!(matches!(exchange.events[1].event, Event::Started));
    let transitions = exchange
        .events
        .iter()
        .filter_map(|event| match &event.event {
            Event::FlowTransition(transition) => Some(transition),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!transitions.is_empty());
    assert!(
        transitions.iter().enumerate().all(|(index, transition)| {
            transition.sequence() == u64::try_from(index + 1).unwrap()
        })
    );
    assert!(matches!(
        transitions.last().unwrap().kind(),
        TransitionKind::RunCompleted {
            outcome: RunOutcome::Solved
        }
    ));
    let ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::FlowRun(result),
    } = &exchange.result.body
    else {
        panic!("expected observed solved flow result")
    };
    assert_eq!(result.outcome(), RunOutcome::Solved);
    assert!(result.report().solved().satisfied());
    assert!(!result.report().changed().satisfied());
    assert!(!result.report().verified().satisfied());
    assert!(transitions.iter().any(|transition| {
        matches!(
            transition.semantic_events(),
            [pam_flow::FlowSemanticEvent::EvidenceFound { step_id, evidence }]
                if step_id == "command" && !evidence.is_empty()
        )
    }));
    let flow_handle = result.steps()[0].result().unwrap().report().evidence()[0]
        .as_str()
        .to_owned();

    let replay = RequestEnvelope::replay(
        RequestId::from("git-status-replay"),
        CallerId::from("flow-test-caller"),
        ProjectId::from("11111111-1111-4111-8111-111111111111"),
        IdempotencyKey::from("git-status-replay-key"),
        request.request_id.clone(),
        0,
    );
    let replayed = request_exchange(&endpoint, &replay, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(replayed.events, exchange.events);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    assert_normalized_operation_and_evidence(
        &state_path,
        &workspace,
        &request,
        &flow_handle,
        credential,
    )
    .await;
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_git_verification_is_verified_and_replays_semantic_evidence() {
    let runtime = test_runtime("git-verify");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "git-verify-flow",
        command_step("git", r#""diff", "--quiet""#, ""),
        &workspace,
    );
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path);
    wait_until_ready(&endpoint).await;

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(15))
        .await
        .unwrap();
    let ResultBody::Success {
        truth: OperationTruth::Verified,
        payload: ResultPayload::FlowRun(result),
    } = &exchange.result.body
    else {
        panic!("expected explicitly verified flow result")
    };
    assert_eq!(result.outcome(), RunOutcome::Solved);
    assert!(result.report().solved().satisfied());
    assert!(result.report().verified().satisfied());
    assert!(!result.report().changed().satisfied());
    assert!(exchange.events.iter().any(|event| {
        matches!(
            &event.event,
            Event::FlowTransition(transition)
                if transition.semantic_events().iter().any(|semantic| matches!(
                    semantic,
                    pam_flow::FlowSemanticEvent::VerificationPassed { step_id, report }
                        if step_id == "command" && !report.evidence().is_empty()
                ))
        )
    }));

    let replay = RequestEnvelope::replay(
        RequestId::from("git-verify-replay"),
        CallerId::from("flow-test-caller"),
        request.project_id.clone(),
        IdempotencyKey::from("git-verify-replay-key"),
        request.request_id.clone(),
        0,
    );
    let replayed = request_exchange(&endpoint, &replay, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(replayed.events, exchange.events);

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_git_diff_continues_as_observation_without_verification_claims() {
    let runtime = test_runtime("legacy-git-diff");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "legacy-git-diff-flow",
        legacy_command_step("git", r#""diff", "--quiet""#, ""),
        &workspace,
    );
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path);
    wait_until_ready(&endpoint).await;

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(15))
        .await
        .unwrap();
    let ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::FlowRun(result),
    } = &exchange.result.body
    else {
        panic!("expected legacy diff to remain observation-only")
    };
    assert!(result.report().solved().satisfied());
    assert!(!result.report().verified().satisfied());
    assert!(exchange.events.iter().all(|event| {
        !matches!(
            &event.event,
            Event::FlowTransition(transition)
                if transition.semantic_events().iter().any(|semantic| matches!(
                    semantic,
                    pam_flow::FlowSemanticEvent::VerificationPassed { .. }
                ))
        )
    }));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_daemon_executes_flows_for_two_explicit_project_roots() {
    let runtime = test_runtime("two-project-roots");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let first_root = create_workspace_with_project(
        &runtime.join("first"),
        "11111111-1111-4111-8111-111111111111",
    );
    let second_project = ProjectId::from("22222222-2222-4222-8222-222222222222");
    let second_root =
        create_workspace_with_project(&runtime.join("second"), second_project.as_str());
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let first = flow_request(
        "first-project-flow",
        command_step("git", r#""status", "--short""#, ""),
        &first_root,
    );
    let mut second = flow_request(
        "second-project-flow",
        command_step("git", r#""status", "--short""#, ""),
        &second_root,
    );
    second.caller_id = CallerId::from("second-flow-test-caller");
    second.project_id = second_project;
    seed_flow_request_authority(&state_path, &first_root, &first).await;
    seed_flow_request_authority(&state_path, &second_root, &second).await;

    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path);
    wait_until_ready(&endpoint).await;
    for request in [&first, &second] {
        let exchange = request_exchange(&endpoint, request, Duration::from_secs(15))
            .await
            .unwrap();
        assert!(matches!(
            exchange.result.body,
            ResultBody::Success {
                truth: OperationTruth::Observed,
                payload: ResultPayload::FlowRun(ref result),
            } if result.outcome() == RunOutcome::Solved
        ));
    }

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Covers challenge rollback, exact replay, and alias rejection.
async fn flow_approval_challenge_rolls_back_and_exact_retry_replays_existing_result() {
    let runtime = test_runtime("flow-approval");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let credential = CallerCredential::new("flow-approval-credential");
    let request = flow_request(
        "flow-approval-request",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    )
    .authenticated(credential.clone());
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let seed = Store::open(&state_path).unwrap();
    seed_flow_policy_fixture_with_approval(
        &seed,
        &request,
        &prepared.policy_resource,
        credential,
        ApprovalRequirement::Once,
        test_now_ms(),
    )
    .await;
    seed.shutdown().await.unwrap();

    let (shutdown, daemon) = start_secure_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    let challenged = request_exchange(&endpoint, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(challenged.events.is_empty());
    let ResultBody::Failure(challenge) = challenged.result.body else {
        panic!("flow should require an exact approval")
    };
    assert_eq!(challenge.code, FailureCode::ApprovalRequired);
    let approval_id = challenge.approval.unwrap().approval_id;

    let control = Store::open(&state_path).unwrap();
    assert!(matches!(
        control.snapshot(request.request_id.clone()).await,
        Err(StoreError::RequestNotFound(_))
    ));
    let reviewer = CallerId::from("flow-approval-reviewer");
    control
        .register_caller(
            reviewer.clone(),
            CallerCredential::new("flow-approval-reviewer-credential"),
            test_now_ms(),
        )
        .await
        .unwrap();
    assert_eq!(
        control
            .decide_approval(
                approval_id.clone(),
                reviewer,
                ApprovalDecision::Approve,
                test_now_ms(),
            )
            .await
            .unwrap(),
        ApprovalDecisionOutcome::Approved
    );
    control.shutdown().await.unwrap();

    let approved = request.clone().with_approval(approval_id);
    let first = request_exchange(&endpoint, &approved, Duration::from_secs(15))
        .await
        .unwrap();
    assert!(matches!(
        first.result.body,
        ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::FlowRun(ref result),
        } if result.outcome() == RunOutcome::Solved
    ));
    let replayed = request_exchange(&endpoint, &approved, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(replayed.events, first.events);
    assert_eq!(replayed.result, first.result);

    let mut alias = approved;
    alias.request_id = RequestId::from("flow-approval-alias");
    let conflict = request_exchange(&endpoint, &alias, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(
        conflict.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));
    let control = Store::open(&state_path).unwrap();
    assert!(matches!(
        control.snapshot(alias.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    control.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_flow_fails_before_workspace_inspection() {
    let runtime = test_runtime("flow-pre-authentication");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "flow-pre-authentication",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let (shutdown, daemon) = start_secure_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    fs::remove_dir_all(workspace.join(".git")).unwrap();

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    assert!(matches!(
        exchange.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Unauthenticated
    ));
    let store = Store::open(&state_path).unwrap();
    assert!(matches!(
        store.snapshot(request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    store.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cross_project_flow_fails_before_workspace_policy_or_acceptance() {
    let runtime = test_runtime("flow-cross-project");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let credential = CallerCredential::new("cross-project-credential");
    let mut request = flow_request(
        "flow-cross-project",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    )
    .authenticated(credential.clone());
    let foreign_project = ProjectId::from("foreign-flow-project");
    request.project_id = foreign_project.clone();
    let seed = Store::open(&state_path).unwrap();
    seed.register_caller(request.caller_id.clone(), credential, test_now_ms())
        .await
        .unwrap();
    seed.shutdown().await.unwrap();
    let (shutdown, daemon) = start_secure_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    fs::remove_dir_all(workspace.join(".git")).unwrap();

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(exchange.events.is_empty());
    assert!(matches!(
        exchange.result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));
    let store = Store::open(&state_path).unwrap();
    assert!(matches!(
        store.snapshot(request.request_id).await,
        Err(StoreError::RequestNotFound(_))
    ));
    assert!(
        store
            .export_audit_events(foreign_project, 0, None, 100)
            .await
            .unwrap()
            .events
            .is_empty()
    );
    assert!(
        store
            .export_audit_events(
                ProjectId::from("11111111-1111-4111-8111-111111111111"),
                0,
                None,
                100,
            )
            .await
            .unwrap()
            .events
            .is_empty()
    );
    store.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_flow_preflight_returns_busy_without_acceptance_and_recovers() {
    let runtime = test_runtime("flow-preflight-admission");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let source = command_step("git", r#""status", "--short""#, "");
    let first = flow_request("preflight-first", source.clone(), &workspace);
    let saturated = flow_request("preflight-saturated", source.clone(), &workspace);
    let recovered = flow_request("preflight-recovered", source, &workspace);
    seed_flow_request_authority(&state_path, &workspace, &first).await;
    let fixture_store = Store::open(&state_path).unwrap();
    for request in [&saturated, &recovered] {
        let RequestPayload::FlowRun { definition, .. } = &request.payload else {
            unreachable!()
        };
        let prepared = prepare_flow_submission(definition, &workspace)
            .await
            .unwrap();
        fixture_store
            .put_grant(PutGrant {
                grant: Grant {
                    id: GrantId::from(format!("{}-grant", request.request_id)),
                    caller: request.caller_id.clone(),
                    project: request.project_id.clone(),
                    capability: CapabilityName::parse("flow.run").unwrap(),
                    resource: ResourceScope::Exact(
                        ResourceName::parse(prepared.policy_resource).unwrap(),
                    ),
                    effect: Effect::Allow,
                    approval: ApprovalRequirement::None,
                    expires_at_ms: None,
                    revoked_at_ms: None,
                },
                created_at_ms: test_now_ms(),
            })
            .await
            .unwrap();
    }
    fixture_store.shutdown().await.unwrap();
    let (shutdown, daemon) = start_daemon_with_preflight_limit(
        endpoint.clone(),
        state_path.clone(),
        1,
        Duration::from_millis(750),
    );
    wait_until_ready(&endpoint).await;

    let first_endpoint = endpoint.clone();
    let first_task = tokio::spawn(async move {
        request_exchange(&first_endpoint, &first, Duration::from_secs(10)).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let busy = request_exchange(&endpoint, &saturated, Duration::from_secs(2))
        .await
        .unwrap();
    let ResultBody::Failure(failure) = busy.result.body else {
        panic!("saturated flow preflight must fail without acceptance")
    };
    assert_eq!(failure.code, FailureCode::Busy);
    assert!(
        failure
            .recovery
            .as_deref()
            .is_some_and(|text| text.contains("retry"))
    );
    let store = Store::open(&state_path).unwrap();
    assert!(matches!(
        store.snapshot(saturated.request_id.clone()).await,
        Err(StoreError::RequestNotFound(_))
    ));
    store.shutdown().await.unwrap();

    assert!(matches!(
        first_task.await.unwrap().unwrap().result.body,
        ResultBody::Success {
            payload: ResultPayload::FlowRun(_),
            ..
        }
    ));
    assert!(matches!(
        request_exchange(&endpoint, &recovered, Duration::from_secs(10))
            .await
            .unwrap()
            .result
            .body,
        ResultBody::Success {
            payload: ResultPayload::FlowRun(_),
            ..
        }
    ));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_queued_flow_is_failed_without_workspace_or_checkpoint_processing() {
    let runtime = test_runtime("queued-flow-cross-project");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let mut request = flow_request(
        "queued-flow-cross-project",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    request.project_id = ProjectId::from("22222222-2222-4222-8222-222222222222");
    let prepared = seed_flow_request_authority(&state_path, &workspace, &request).await;
    let seed = Store::open(&state_path).unwrap();
    let now = test_now_ms();
    let accepted = seed
        .authorize_flow_run(
            flow_authorization_request(
                &request,
                prepared.operation,
                &prepared.policy_resource,
                now,
            ),
            now,
            60_000,
        )
        .await
        .unwrap();
    assert!(matches!(accepted, FlowAuthorizationOutcome::Accepted(_)));
    seed.shutdown().await.unwrap();
    fs::remove_dir_all(workspace.join(".git")).unwrap();

    let (shutdown, daemon) = start_daemon(endpoint, state_path.clone());
    let store = Store::open(&state_path).unwrap();
    let mut terminal = None;
    for _ in 0..200 {
        let snapshot = store.snapshot(request.request_id.clone()).await.unwrap();
        if snapshot.state == RequestState::Failed {
            terminal = Some(snapshot);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snapshot = terminal.expect("mismatched queued flow did not fail promptly");
    assert_eq!(snapshot.state, RequestState::Failed);
    let replay = store.replay(request.request_id.clone(), 0).await.unwrap();
    assert_eq!(
        replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["accepted", "started", "failed"]
    );
    assert!(
        replay
            .events
            .iter()
            .all(|event| !event.kind.starts_with("flow_"))
    );
    let result = replay
        .result
        .expect("mismatched queued flow must be terminal");
    let ServerMessage::Result(result) = decode_server_message(&result.payload).unwrap() else {
        panic!("stored scheduler failure was not a result")
    };
    assert!(matches!(
        result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
    ));
    store.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test]
async fn persisted_operation_root_tamper_cannot_reuse_the_original_authorization() {
    let runtime = test_runtime("operation-root-tamper");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let original_root = create_workspace(&runtime.join("original"));
    let substituted_root = create_workspace(&runtime.join("substituted"));
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request = flow_request(
        "operation-root-tamper",
        command_step("git", r#""status", "--short""#, ""),
        &original_root,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let accepted = prepare_flow_submission(definition, &original_root)
        .await
        .unwrap();
    let substituted = prepare_flow_submission(definition, &substituted_root)
        .await
        .unwrap();
    let now = test_now_ms();
    authorize_flow_fixture(
        &store,
        &request,
        accepted.operation,
        &accepted.policy_resource,
        now,
    )
    .await;
    store.shutdown().await.unwrap();
    {
        let connection = rusqlite::Connection::open(&state_path).unwrap();
        connection
            .execute(
                "UPDATE requests SET operation = ?1 WHERE request_id = ?2",
                rusqlite::params![substituted.operation, request.request_id.as_str()],
            )
            .unwrap();
    }

    let reopened = Store::open(&state_path).unwrap();
    let mut leased = reopened
        .claim("operation-root-tamper", now.saturating_add(1), 60_000)
        .await
        .unwrap()
        .unwrap();
    let processing = process_flow(
        &mut leased,
        &reopened,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let FlowProcessing::Terminal { result, .. } = processing else {
        panic!("operation substitution must fail terminally")
    };
    assert!(matches!(
        result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Internal
    ));
    assert!(
        reopened
            .load_flow_checkpoint(leased.lease, now.saturating_add(2))
            .await
            .unwrap()
            .is_none()
    );

    reopened.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Covers quarantine, replay truth, and FIFO continuation together.
async fn corrupt_flow_authorization_is_quarantined_without_blocking_the_fifo() {
    let runtime = test_runtime("corrupt-flow-authorization");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let corrupt = flow_request(
        "corrupt-flow-authorization",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let healthy = flow_request(
        "healthy-flow-after-corruption",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &corrupt.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let store = Store::open(&state_path).unwrap();
    let now = test_now_ms();
    authorize_flow_fixture(
        &store,
        &corrupt,
        prepared.operation.clone(),
        &prepared.policy_resource,
        now,
    )
    .await;
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(
                    &healthy,
                    prepared.operation,
                    &prepared.policy_resource,
                    now.saturating_add(1),
                ),
                now.saturating_add(1),
                60_000,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Created { .. })
    ));
    store.shutdown().await.unwrap();
    {
        let connection = rusqlite::Connection::open(&state_path).unwrap();
        connection
            .execute(
                "DELETE FROM flow_authorizations WHERE request_id = ?1",
                [corrupt.request_id.as_str()],
            )
            .unwrap();
    }

    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    let probe = Store::open(&state_path).unwrap();
    for _ in 0..1_000 {
        let corrupt_state = probe
            .snapshot(corrupt.request_id.clone())
            .await
            .unwrap()
            .state;
        let healthy_state = probe
            .snapshot(healthy.request_id.clone())
            .await
            .unwrap()
            .state;
        if corrupt_state == RequestState::Failed && healthy_state == RequestState::Succeeded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        probe
            .snapshot(corrupt.request_id.clone())
            .await
            .unwrap()
            .state,
        RequestState::Failed
    );
    assert_eq!(
        probe
            .snapshot(healthy.request_id.clone())
            .await
            .unwrap()
            .state,
        RequestState::Succeeded
    );
    let corrupt_replay = probe.replay(corrupt.request_id.clone(), 0).await.unwrap();
    assert_eq!(
        corrupt_replay
            .events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        ["accepted", "failed"]
    );
    let ServerMessage::Result(corrupt_result) =
        decode_server_message(&corrupt_replay.result.expect("quarantined result").payload).unwrap()
    else {
        panic!("quarantine must persist a result envelope")
    };
    assert!(matches!(
        corrupt_result.body,
        ResultBody::Failure(ref failure) if failure.code == FailureCode::Internal
    ));
    let healthy_replay = probe.replay(healthy.request_id.clone(), 0).await.unwrap();
    assert!(
        healthy_replay
            .events
            .iter()
            .any(|event| event.kind == "started")
    );
    probe.shutdown().await.unwrap();

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

async fn assert_normalized_operation_and_evidence(
    state_path: &Path,
    execution_root: &Path,
    request: &RequestEnvelope,
    flow_handle: &str,
    credential: &str,
) {
    let store = Store::open(state_path).unwrap();
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, execution_root)
        .await
        .unwrap();
    let operation = prepared.operation.clone();
    let root = execution_root.to_str().unwrap().as_bytes();
    assert!(operation.windows(root.len()).any(|window| window == root));
    assert!(
        !prepared
            .policy_resource
            .contains(execution_root.to_str().unwrap())
    );
    assert!(
        !operation
            .windows(credential.len())
            .any(|window| window == credential.as_bytes())
    );
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    assert!(matches!(
        store
            .authorize_flow_run(
                flow_authorization_request(request, operation, &prepared.policy_resource, now_ms,),
                now_ms,
                60_000,
            )
            .await
            .unwrap(),
        FlowAuthorizationOutcome::Accepted(AcceptOutcome::Existing { .. })
    ));
    let handle = EvidenceHandle::parse(flow_handle).unwrap();
    let metadata = store
        .inspect_evidence(
            ProjectId::from("11111111-1111-4111-8111-111111111111"),
            handle.clone(),
        )
        .await
        .unwrap();
    let bytes = store
        .read_evidence_range(
            ProjectId::from("11111111-1111-4111-8111-111111111111"),
            handle,
            0,
            metadata.size_bytes,
        )
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("Cargo.toml"));
    assert!(!String::from_utf8_lossy(&bytes).contains(credential));
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn solved_terminal_checkpoint_resumes_after_store_restart_without_another_save() {
    assert_terminal_checkpoint_restart(false).await;
}

#[tokio::test]
async fn cancelled_terminal_checkpoint_resumes_after_store_restart_without_another_save() {
    assert_terminal_checkpoint_restart(true).await;
}

#[tokio::test]
async fn terminal_checkpoint_truth_wins_a_late_cancellation_before_scheduler_finish() {
    let runtime = test_runtime("terminal-cancel-race");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request = flow_request(
        "terminal-cancel-race",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let mut leased = store
        .claim("terminal-cancel-race", now_ms.saturating_add(1), 60_000)
        .await
        .unwrap()
        .unwrap();
    let terminal = process_flow(
        &mut leased,
        &store,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (outcome, _, _, encoded_result) = terminal_processing(terminal);
    assert_eq!(outcome, RunOutcome::Solved);

    assert_eq!(
        store
            .cancel(
                request.request_id.clone(),
                now_ms.saturating_add(2),
                b"late generic cancellation".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::AlreadyTerminal(RequestState::Succeeded)
    );
    let replay = store.replay(request.request_id, 0).await.unwrap();
    let result = replay
        .result
        .expect("late cancellation must finalize cached truth");
    assert_eq!(result.state, RequestState::Succeeded);
    assert_eq!(result.payload, encoded_result);

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test]
async fn revoked_flow_authorization_blocks_durably_before_effect_start() {
    let runtime = test_runtime("revoked-flow-authorization");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let store = Store::open(runtime.join("state.sqlite3")).unwrap();
    let request = flow_request(
        "revoked-flow-authorization",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let mut leased = store
        .claim(
            "revoked-flow-authorization",
            now_ms.saturating_add(1),
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .revoke_grant(
                GrantId::from(format!("{}-grant", request.request_id)),
                now_ms.saturating_add(2),
            )
            .await
            .unwrap(),
        GrantRevocation::Revoked
    );

    let terminal = process_flow(
        &mut leased,
        &store,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (outcome, _, _, encoded) = terminal_processing(terminal);
    assert_eq!(outcome, RunOutcome::Blocked);
    let replay = store.replay(request.request_id, 0).await.unwrap();
    assert!(replay.events.iter().any(|event| {
        event.kind == "flow_effect_authorization_denied"
            && matches!(
                rmp_serde::from_slice::<pam_flow::RunTransition>(&event.payload),
                Ok(transition)
                    if matches!(
                        transition.kind(),
                        TransitionKind::EffectAuthorizationDenied { replay: false, .. }
                    )
            )
    }));
    assert!(
        !replay
            .events
            .iter()
            .any(|event| event.kind == "flow_effect_started")
    );
    let finished = store
        .finish_terminal_flow(leased.lease, now_ms.saturating_add(3), encoded.clone())
        .await
        .unwrap();
    assert_eq!(finished.state, RequestState::Failed);
    assert_eq!(finished.payload, encoded);

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn cancellation_winning_before_terminal_checkpoint_saves_cancelled_truth() {
    let runtime = test_runtime("cancel-terminal-save-race");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let store = Store::open(runtime.join("state.sqlite3")).unwrap();
    let request = flow_request(
        "cancel-terminal-save-race",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let parsed = FlowDefinition::parse_toml(definition.as_str()).unwrap();
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let leased = store
        .claim(
            "cancel-terminal-save-race",
            now_ms.saturating_add(1),
            60_000,
        )
        .await
        .unwrap()
        .unwrap();
    let run_id = RunId::parse(request.request_id.as_str()).unwrap();
    let mut run = FlowRun::start(run_id, parsed).unwrap();
    let initial = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: leased.lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: now_ms.saturating_add(2),
        })
        .await
        .unwrap();
    let mut revision = initial.checkpoint.checkpoint_revision;

    let previous = run.snapshot().clone();
    let evaluation = run.next_decision(now_ms.saturating_add(3)).unwrap();
    let effect = match evaluation.decision() {
        RunDecision::EvaluateEffect { effect, .. } => effect.clone(),
        other => panic!("expected effect evaluation, got {other:?}"),
    };
    let (_, next_revision, _) = persist_update_reconciling_cancellation(
        &store, &leased, revision, &mut run, previous, evaluation,
    )
    .await
    .unwrap();
    revision = next_revision;
    let previous = run.snapshot().clone();
    let execution = run
        .prepare_effect(&effect, now_ms.saturating_add(4))
        .unwrap();
    let (_, next_revision, _) = persist_update_reconciling_cancellation(
        &store, &leased, revision, &mut run, previous, execution,
    )
    .await
    .unwrap();
    revision = next_revision;

    let previous = run.snapshot().clone();
    let recorded = run
        .record_effect_result(
            &effect,
            EffectResult::succeeded("completed", Vec::new()).unwrap(),
            now_ms.saturating_add(5),
        )
        .unwrap();
    let (_, next_revision, _) = persist_update_reconciling_cancellation(
        &store, &leased, revision, &mut run, previous, recorded,
    )
    .await
    .unwrap();
    revision = next_revision;
    let previous = run.snapshot().clone();
    let completed = run.next_decision(now_ms.saturating_add(6)).unwrap();
    assert!(matches!(completed.decision(), RunDecision::Terminal { .. }));
    assert_eq!(
        store
            .cancel(
                request.request_id.clone(),
                now_ms.saturating_add(7),
                b"generic cancellation placeholder".to_vec(),
            )
            .await
            .unwrap(),
        CancelOutcome::CancellationRequested
    );
    let (decision, _, encoded) = persist_update_reconciling_cancellation(
        &store, &leased, revision, &mut run, previous, completed,
    )
    .await
    .unwrap();
    let RunDecision::Terminal { result } = decision else {
        panic!("cancellation race must become terminal")
    };
    assert_eq!(result.outcome(), RunOutcome::Cancelled);
    let encoded = encoded.expect("cancelled terminal checkpoint must cache exact result");
    let finished = store
        .finish_terminal_flow(leased.lease, now_ms.saturating_add(8), encoded.clone())
        .await
        .unwrap();
    assert_eq!(finished.state, RequestState::Cancelled);
    assert_eq!(finished.payload, encoded);

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[allow(clippy::too_many_lines)]
async fn assert_terminal_checkpoint_restart(cancel_before_run: bool) {
    let label = if cancel_before_run {
        "cancelled-terminal-restart"
    } else {
        "solved-terminal-restart"
    };
    let runtime = test_runtime(label);
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request = flow_request(
        label,
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let mut leased = store
        .claim("terminal-restart-first", now_ms.saturating_add(1), 60_000)
        .await
        .unwrap()
        .unwrap();
    if cancel_before_run {
        assert_eq!(
            store
                .cancel(
                    request.request_id.clone(),
                    now_ms.saturating_add(2),
                    b"generic cancellation placeholder".to_vec(),
                )
                .await
                .unwrap(),
            CancelOutcome::CancellationRequested
        );
    }
    let first = process_flow(
        &mut leased,
        &store,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (first_outcome, first_state, first_truth, first_encoded) = terminal_processing(first);
    let expected = if cancel_before_run {
        RunOutcome::Cancelled
    } else {
        RunOutcome::Solved
    };
    assert_eq!(first_outcome, expected);
    if cancel_before_run {
        assert_eq!(first_state, TerminalState::Cancelled);
        assert_eq!(first_truth, OperationTruth::Unresolved);
    } else {
        assert_eq!(first_state, TerminalState::Succeeded);
        assert_eq!(first_truth, OperationTruth::Observed);
    }
    let first_checkpoint = store
        .load_flow_checkpoint(leased.lease.clone(), now_ms.saturating_add(3))
        .await
        .unwrap()
        .unwrap();
    let first_replay = store.replay(request.request_id.clone(), 0).await.unwrap();
    store.shutdown().await.unwrap();
    fs::remove_dir_all(&workspace).unwrap();

    let reopened = Store::open(&state_path).unwrap();
    let second = process_flow(
        &mut leased,
        &reopened,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (second_outcome, second_state, second_truth, second_encoded) = terminal_processing(second);
    assert_eq!(second_outcome, expected);
    assert_eq!(second_state, first_state);
    assert_eq!(second_truth, first_truth);
    assert_eq!(second_encoded, first_encoded);
    let second_checkpoint = reopened
        .load_flow_checkpoint(leased.lease.clone(), now_ms.saturating_add(4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second_checkpoint.checkpoint_revision,
        first_checkpoint.checkpoint_revision
    );
    assert_eq!(
        reopened.replay(request.request_id, 0).await.unwrap().events,
        first_replay.events
    );

    reopened.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

fn legacy_snapshot_bytes(snapshot: &FlowSnapshot) -> Vec<u8> {
    let mut value = serde_json::to_value(snapshot).unwrap();
    let root = value.as_object_mut().unwrap();
    root.insert("snapshot_version".to_owned(), serde_json::json!(1));
    for step in root.get_mut("steps").unwrap().as_array_mut().unwrap() {
        step.as_object_mut().unwrap().remove("semantic_role");
    }
    rmp_serde::to_vec_named(&value).unwrap()
}

fn legacy_terminal_result_bytes(encoded: &[u8]) -> Vec<u8> {
    let mut value: serde_json::Value = rmp_serde::from_slice(encoded).unwrap();
    let root = value.as_object_mut().unwrap();
    root.insert("protocol_version".to_owned(), serde_json::json!(4));
    let body = root.get_mut("body").unwrap().as_object_mut().unwrap();
    body.insert("truth".to_owned(), serde_json::json!("verified"));
    let payload = body.get_mut("payload").unwrap().as_object_mut().unwrap();
    payload.remove("report");
    for step in payload.get_mut("steps").unwrap().as_array_mut().unwrap() {
        step.as_object_mut().unwrap().remove("semantic_role");
    }
    rmp_serde::to_vec_named(&value).unwrap()
}

fn terminal_result_bytes_with_version(encoded: &[u8], version: u16) -> Vec<u8> {
    let mut value: serde_json::Value = rmp_serde::from_slice(encoded).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("protocol_version".to_owned(), serde_json::json!(version));
    rmp_serde::to_vec_named(&value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Exercises the complete persisted v1 upgrade through daemon execution.
async fn nonterminal_legacy_checkpoint_upgrades_and_advances_after_restart() {
    let runtime = test_runtime("legacy-checkpoint-advance");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request = flow_request(
        "legacy-checkpoint-advance",
        legacy_command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let parsed = FlowDefinition::parse_toml(definition.as_str()).unwrap();
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = test_now_ms();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let mut leased = store
        .claim("legacy-checkpoint-first", now_ms.saturating_add(1), 60_000)
        .await
        .unwrap()
        .unwrap();
    let run = FlowRun::start(RunId::parse(request.request_id.as_str()).unwrap(), parsed).unwrap();
    store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: leased.lease.clone(),
            expected_revision: 0,
            snapshot: run.snapshot().clone(),
            transition: None,
            terminal_result: None,
            updated_at_ms: now_ms.saturating_add(2),
        })
        .await
        .unwrap();
    let legacy = legacy_snapshot_bytes(run.snapshot());
    store.shutdown().await.unwrap();
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    connection
        .execute(
            "UPDATE flow_runs SET snapshot = ?1 WHERE request_id = ?2",
            rusqlite::params![legacy, request.request_id.as_str()],
        )
        .unwrap();
    drop(connection);

    let reopened = Store::open(&state_path).unwrap();
    let processing = process_flow(
        &mut leased,
        &reopened,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (outcome, state, truth, _) = terminal_processing(processing);
    assert_eq!(outcome, RunOutcome::Solved);
    assert_eq!(state, TerminalState::Succeeded);
    assert_eq!(truth, OperationTruth::Observed);
    let checkpoint = reopened
        .load_flow_checkpoint(leased.lease, now_ms.saturating_add(3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        checkpoint.snapshot.snapshot_version(),
        pam_flow::FLOW_SNAPSHOT_VERSION
    );
    assert!(checkpoint.checkpoint_revision > 2);

    reopened.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Recreates a genuine v1 snapshot and v4 terminal envelope.
async fn terminal_legacy_checkpoint_replays_conservative_truth_after_restart() {
    let runtime = test_runtime("legacy-terminal-restart");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request = flow_request(
        "legacy-terminal-restart",
        legacy_command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    let RequestPayload::FlowRun { definition, .. } = &request.payload else {
        unreachable!()
    };
    let prepared = prepare_flow_submission(definition, &workspace)
        .await
        .unwrap();
    let now_ms = test_now_ms();
    authorize_flow_fixture(
        &store,
        &request,
        prepared.operation,
        &prepared.policy_resource,
        now_ms,
    )
    .await;
    let mut leased = store
        .claim("legacy-terminal-first", now_ms.saturating_add(1), 60_000)
        .await
        .unwrap()
        .unwrap();
    let first = process_flow(
        &mut leased,
        &store,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (_, _, _, current_encoded) = terminal_processing(first);
    let checkpoint = store
        .load_flow_checkpoint(leased.lease.clone(), now_ms.saturating_add(2))
        .await
        .unwrap()
        .unwrap();
    let legacy_snapshot = legacy_snapshot_bytes(&checkpoint.snapshot);
    let legacy_result = legacy_terminal_result_bytes(&current_encoded);
    assert!(
        decode_stored_result(&terminal_result_bytes_with_version(
            &current_encoded,
            pam_protocol::PROTOCOL_VERSION + 1,
        ))
        .is_err()
    );
    assert!(decode_stored_result(&terminal_result_bytes_with_version(&legacy_result, 3)).is_err());
    let ServerMessage::Result(decoded_legacy) = decode_stored_result(&legacy_result).unwrap()
    else {
        panic!("legacy terminal bytes must decode as a result")
    };
    assert_eq!(
        decoded_legacy.protocol_version,
        pam_protocol::PROTOCOL_VERSION
    );
    assert!(matches!(
        decoded_legacy.body,
        ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::FlowRun(_),
        }
    ));
    store.shutdown().await.unwrap();
    let connection = rusqlite::Connection::open(&state_path).unwrap();
    connection
        .execute(
            "UPDATE flow_runs SET snapshot = ?1, terminal_result = ?2 WHERE request_id = ?3",
            rusqlite::params![legacy_snapshot, legacy_result, request.request_id.as_str()],
        )
        .unwrap();
    drop(connection);
    fs::remove_dir_all(&workspace).unwrap();

    let reopened = Store::open(&state_path).unwrap();
    let second = process_flow(
        &mut leased,
        &reopened,
        Duration::from_mins(1),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    let (outcome, state, truth, replayed_encoded) = terminal_processing(second);
    assert_eq!(outcome, RunOutcome::Solved);
    assert_eq!(state, TerminalState::Succeeded);
    assert_eq!(truth, OperationTruth::Observed);
    assert_eq!(replayed_encoded, legacy_result);

    reopened.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

fn terminal_processing(
    processing: FlowProcessing,
) -> (RunOutcome, TerminalState, OperationTruth, Vec<u8>) {
    let FlowProcessing::Terminal {
        terminal_state,
        result,
        encoded_result,
        ..
    } = processing
    else {
        panic!("terminal checkpoint processing lost its live lease")
    };
    let ResultBody::Success {
        truth,
        payload: ResultPayload::FlowRun(result),
    } = result.body
    else {
        panic!("terminal checkpoint did not retain its typed flow result")
    };
    (result.outcome(), terminal_state, truth, encoded_result)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Proves every unsupported action fails before durable acceptance.
async fn unsupported_definitions_are_rejected_without_durable_acceptance() {
    let runtime = test_runtime("unsupported-pre-accept");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let sentinel = runtime.join("read-only-build-script-ran");
    fs::write(
        workspace.join("build.rs"),
        format!("fn main() {{ std::fs::write({sentinel:?}, b\"ran\").unwrap(); }}\n"),
    )
    .unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path.clone());
    wait_until_ready(&endpoint).await;
    let requests = [
        flow_request(
            "approval-flow",
            command_step(
                "git",
                r#""status", "--short""#,
                "approval = \"required\"",
            ),
            &workspace,
        ),
        flow_request(
            "stateful-flow",
            command_step(
                "git",
                r#""status", "--short""#,
                "approval = \"required\"\nidempotency_key = \"stateful-effect\"\neffect = \"stateful\"",
            )
            .replace("effect = \"read_only\"", "")
            .replace("semantic = \"observe\"", "semantic = \"change\""),
            &workspace,
        ),
        flow_request(
            "cargo-version-flow",
            command_step("cargo", r#""--version""#, ""),
            &workspace,
        ),
        flow_request(
            "cargo-fmt-flow",
            command_step("cargo", r#""fmt", "--check""#, ""),
            &workspace,
        ),
        flow_request(
            "cargo-check-flow",
            command_step("cargo", r#""check""#, ""),
            &workspace,
        ),
        flow_request(
            "cargo-clippy-flow",
            command_step("cargo", r#""clippy""#, ""),
            &workspace,
        ),
        flow_request(
            "cargo-test-flow",
            command_step("cargo", r#""test""#, ""),
            &workspace,
        ),
        flow_request(
            "cargo-build-flow",
            command_step("cargo", r#""build""#, ""),
            &workspace,
        ),
        flow_request(
            "connector-flow",
            definition(
                r#"
[[steps]]
id = "connector"
description = "Unsupported connector."
timeout_seconds = 10
effect = "read_only"
semantic = "observe"
action = { type = "connector", connector = "github.actions", capability = "runs.read", resource = { kind = "workflow_run", id = "github:ro-ag/pam/runs/1" } }
"#,
            ),
            &workspace,
        ),
    ];

    for request in &requests {
        let exchange = request_exchange(&endpoint, request, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(exchange.events.is_empty());
        assert!(matches!(
            exchange.result.body,
            ResultBody::Failure(ref failure) if failure.code == FailureCode::InvalidRequest
        ));
    }
    assert!(
        !sentinel.exists(),
        "unsupported executable Cargo action executed its build script"
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let store = Store::open(&state_path).unwrap();
    for request in &requests {
        assert!(matches!(
            store.snapshot(request.request_id.clone()).await,
            Err(StoreError::RequestNotFound(_))
        ));
    }
    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retryable_command_failure_exhausts_the_declared_budget() {
    let runtime = test_runtime("retry-exhausted");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    fs::write(
        workspace.join("src/main.rs"),
        b"fn main() { println!(\"dirty\"); }\n",
    )
    .unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "retry-exhausted-flow",
        command_step(
            "git",
            r#""diff", "--quiet""#,
            "retry = { max_attempts = 2, initial_backoff_ms = 1, max_backoff_ms = 1 }",
        ),
        &workspace,
    );
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path);
    wait_until_ready(&endpoint).await;

    let exchange = request_exchange(&endpoint, &request, Duration::from_secs(20))
        .await
        .unwrap();
    let ResultBody::Success {
        truth: OperationTruth::Unresolved,
        payload: ResultPayload::FlowRun(result),
    } = exchange.result.body
    else {
        panic!("expected unresolved flow result")
    };
    assert_eq!(result.outcome(), RunOutcome::Unresolved);
    let transition_kinds = exchange
        .events
        .iter()
        .filter_map(|event| match &event.event {
            Event::FlowTransition(transition) => Some(transition.kind()),
            _ => None,
        });
    assert!(transition_kinds.clone().any(|kind| matches!(
        kind,
        TransitionKind::RetryScheduled {
            next_attempt: 2,
            ..
        }
    )));
    assert!(
        transition_kinds
            .clone()
            .any(|kind| matches!(kind, TransitionKind::RetryExhausted { attempt: 2, .. }))
    );
    assert_eq!(
        transition_kinds
            .filter(|kind| matches!(kind, TransitionKind::EffectStarted { .. }))
            .count(),
        2
    );

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_retry_keeps_the_lease_live_and_finishes_cancelled() {
    let runtime = test_runtime("cancel-retry");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    fs::write(
        workspace.join("src/main.rs"),
        b"fn main() { println!(\"dirty\"); }\n",
    )
    .unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "cancel-retry-flow",
        command_step(
            "git",
            r#""diff", "--quiet""#,
            "retry = { max_attempts = 2, initial_backoff_ms = 5000, max_backoff_ms = 5000 }",
        ),
        &workspace,
    );
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) = start_daemon(endpoint.clone(), state_path);
    wait_until_ready(&endpoint).await;
    let target_id = request.request_id.clone();
    let target_endpoint = endpoint.clone();
    let target = tokio::spawn(async move {
        request_exchange(&target_endpoint, &request, Duration::from_secs(15)).await
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    // Cross the original three-second lease boundary while the worker is waiting.
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    let cancel = RequestEnvelope::cancel(
        RequestId::from("cancel-retry-observer"),
        CallerId::from("flow-test-caller"),
        ProjectId::from("11111111-1111-4111-8111-111111111111"),
        IdempotencyKey::from("cancel-retry-observer-key"),
        target_id,
    );
    let cancelled = request_exchange(&endpoint, &cancel, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(cancelled.result.body, ResultBody::Success { .. }));
    let target = target.await.unwrap().unwrap();
    assert!(matches!(
        target.result.body,
        ResultBody::Success {
            truth: OperationTruth::Unresolved,
            payload: ResultPayload::FlowRun(ref result),
        } if result.outcome() == RunOutcome::Cancelled
    ));
    assert!(
        !target
            .events
            .iter()
            .any(|event| matches!(event.event, Event::LeaseExpired))
    );
    assert!(target.events.iter().any(|event| matches!(
        &event.event,
        Event::FlowTransition(transition)
            if matches!(transition.kind(), TransitionKind::RunCompleted { outcome: RunOutcome::Cancelled })
    )));

    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_flow_cancel_reply_is_recoverable_and_repeat_is_observed() {
    let runtime = test_runtime("lost-cancel-reply");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.join("runtime"));
    let state_path = runtime.join("state.sqlite3");
    let request = flow_request(
        "lost-cancel-target",
        command_step("git", r#""status", "--short""#, ""),
        &workspace,
    );
    seed_flow_request_authority(&state_path, &workspace, &request).await;
    let (shutdown, daemon) =
        start_daemon_with_delay(endpoint.clone(), state_path.clone(), Duration::from_secs(5));
    wait_until_ready(&endpoint).await;
    let target_endpoint = endpoint.clone();
    let target_request = request.clone();
    let target = tokio::spawn(async move {
        request_exchange(&target_endpoint, &target_request, Duration::from_secs(15)).await
    });
    let observer = Store::open(&state_path).unwrap();
    for _ in 0..500 {
        if observer
            .snapshot(request.request_id.clone())
            .await
            .is_ok_and(|snapshot| snapshot.state == RequestState::Leased)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let lost_cancel = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("lost-cancel-observer"),
        request.caller_id.clone(),
        request.project_id.clone(),
        IdempotencyKey::from("lost-cancel-observer-key"),
        request.request_id.clone(),
        pam_protocol::ExpectedTargetKind::FlowRun,
    );
    let mut abandoned = ClientTransport::connect(&endpoint, Duration::from_secs(2))
        .await
        .unwrap();
    abandoned
        .send(pam_protocol::encode(&lost_cancel).unwrap())
        .await
        .unwrap();
    for _ in 0..500 {
        if observer
            .snapshot(request.request_id.clone())
            .await
            .is_ok_and(|snapshot| snapshot.state == RequestState::CancellationRequested)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        observer
            .snapshot(request.request_id.clone())
            .await
            .unwrap()
            .state,
        RequestState::CancellationRequested
    );
    drop(abandoned);

    let repeat = RequestEnvelope::cancel_with_expected_target(
        RequestId::from("repeat-cancel-observer"),
        request.caller_id.clone(),
        request.project_id.clone(),
        IdempotencyKey::from("repeat-cancel-observer-key"),
        request.request_id.clone(),
        pam_protocol::ExpectedTargetKind::FlowRun,
    );
    let repeat = request_exchange(&endpoint, &repeat, Duration::from_secs(2))
        .await
        .unwrap();
    assert!(matches!(
        repeat.result.body,
        ResultBody::Success {
            truth: OperationTruth::Observed,
            payload: ResultPayload::Cancellation(ref result),
        } if result.disposition == pam_protocol::CancellationDisposition::AlreadyRequested
    ));
    let target = target.await.unwrap().unwrap();
    assert!(matches!(
        target.result.body,
        ResultBody::Success {
            truth: OperationTruth::Unresolved,
            payload: ResultPayload::FlowRun(ref result),
        } if result.outcome() == RunOutcome::Cancelled
    ));

    observer.shutdown().await.unwrap();
    shutdown.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[tokio::test]
async fn workspace_fingerprint_wait_renews_the_lease() {
    let runtime = test_runtime("workspace-fingerprint-lease");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let store = Store::open(runtime.join("state.sqlite3")).unwrap();
    let request_id = RequestId::from("workspace-fingerprint-lease");
    let now = test_now_ms();
    store
        .accept(
            AcceptRequest {
                request_id: request_id.clone(),
                caller_id: CallerId::from("flow-test-caller"),
                project_id: ProjectId::from("11111111-1111-4111-8111-111111111111"),
                idempotency_key: IdempotencyKey::from("workspace-fingerprint-lease-key"),
                operation_kind: "workspace_fingerprint_test".to_owned(),
                operation: Vec::new(),
            },
            now,
        )
        .await
        .unwrap();
    let mut leased = store
        // Give parallel test scheduling enough room to enter the helper. The
        // helper immediately renews this to the deliberately short 500 ms
        // duration exercised below.
        .claim(
            "workspace-fingerprint-worker",
            now.saturating_add(1),
            30_000,
        )
        .await
        .unwrap()
        .unwrap();
    let fingerprint = async {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        Ok(WorkspaceFingerprint([9; 32]))
    };
    let outcome = await_workspace_fingerprint_with_lease(
        fingerprint,
        &mut leased,
        &store,
        Duration::from_millis(500),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    match outcome {
        WorkspaceFingerprintLease::Completed(Ok(fingerprint)) => {
            assert_eq!(fingerprint, WorkspaceFingerprint([9; 32]));
        }
        _ => panic!("workspace fingerprint did not complete under the renewed lease"),
    }
    let snapshot = store.snapshot(request_id.clone()).await.unwrap();
    assert_eq!(snapshot.state, RequestState::Leased);
    assert!(snapshot.lease_expires_at_ms.unwrap() > test_now_ms());
    assert!(
        !store
            .replay(request_id, 0)
            .await
            .unwrap()
            .events
            .iter()
            .any(|event| event.kind == "lease_expired")
    );

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn fast_exit_listing_overflow_fails_closed() {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "dd if=/dev/zero bs=4096 count=1 2>/dev/null"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    assert_eq!(
        run_bounded_listing(command, 1_024).await.unwrap_err(),
        FlowSubmissionError::WorkspaceUnavailable
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fast_exit_command_overflow_never_returns_incomplete_evidence() {
    let runtime = test_runtime("command-output-overflow");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request_id = RequestId::from("command-output-overflow-flow");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    store
        .accept(
            AcceptRequest {
                request_id,
                caller_id: CallerId::from("flow-test-caller"),
                project_id: ProjectId::from("11111111-1111-4111-8111-111111111111"),
                idempotency_key: IdempotencyKey::from("command-output-overflow-key"),
                operation_kind: "command_executor_test".to_owned(),
                operation: Vec::new(),
            },
            now_ms,
        )
        .await
        .unwrap();
    let mut leased = store
        .claim("output-overflow-test", now_ms.saturating_add(1), 3_000)
        .await
        .unwrap()
        .unwrap();
    let root = std::env::current_dir().unwrap().canonicalize().unwrap();
    let command = PreparedCommand {
        program: PathBuf::from("/bin/sh").canonicalize().unwrap(),
        args: vec![
            OsString::from("-c"),
            OsString::from("dd if=/dev/zero bs=1024 count=300 2>/dev/null"),
        ],
        working_directory: root.clone(),
        execution_root: root,
    };

    let outcome = execute_command(
        command,
        &mut leased,
        &store,
        Duration::from_secs(3),
        Duration::from_millis(100),
        10,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, CommandExecution::OutputLimit));

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn command_output_is_discarded_when_the_workspace_changes_during_execution() {
    let runtime = test_runtime("command-workspace-mutation");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let workspace = create_workspace(&runtime);
    let accepted_workspace = workspace_fingerprint(&workspace).await.unwrap();
    let authority = WorkspaceAuthority::open(&workspace).unwrap();
    let store = Store::open(runtime.join("state.sqlite3")).unwrap();
    let now_ms = test_now_ms();
    store
        .accept(
            AcceptRequest {
                request_id: RequestId::from("command-workspace-mutation"),
                caller_id: CallerId::from("flow-test-caller"),
                project_id: ProjectId::from("11111111-1111-4111-8111-111111111111"),
                idempotency_key: IdempotencyKey::from("command-workspace-mutation-key"),
                operation_kind: "command_executor_test".to_owned(),
                operation: Vec::new(),
            },
            now_ms,
        )
        .await
        .unwrap();
    let mut leased = store
        .claim("workspace-mutation-worker", now_ms.saturating_add(1), 3_000)
        .await
        .unwrap()
        .unwrap();
    let command = PreparedCommand {
        program: PathBuf::from("/bin/sh").canonicalize().unwrap(),
        args: vec![
            OsString::from("-c"),
            OsString::from("sleep 1; echo observed"),
        ],
        working_directory: workspace.clone(),
        execution_root: workspace.clone(),
    };
    let mutation_path = workspace.join("src/main.rs");
    let mutation = async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        fs::write(mutation_path, b"fn main() { println!(\"changed\"); }\n").unwrap();
    };
    let (outcome, ()) = tokio::join!(
        execute_command_in_workspace(
            command,
            authority,
            accepted_workspace,
            &mut leased,
            &store,
            Duration::from_secs(3),
            Duration::from_millis(100),
            5,
        ),
        mutation,
    );

    assert!(matches!(
        outcome.unwrap(),
        CommandExecution::WorkspaceChanged
    ));

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn completed_leader_cannot_leave_a_grandchild_holding_output_pipes() {
    let runtime = test_runtime("grandchild-pipe");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request_id = RequestId::from("grandchild-pipe-flow");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    store
        .accept(
            AcceptRequest {
                request_id,
                caller_id: CallerId::from("flow-test-caller"),
                project_id: ProjectId::from("11111111-1111-4111-8111-111111111111"),
                idempotency_key: IdempotencyKey::from("grandchild-pipe-key"),
                operation_kind: "command_executor_test".to_owned(),
                operation: Vec::new(),
            },
            now_ms,
        )
        .await
        .unwrap();
    let mut leased = store
        .claim("grandchild-test", now_ms.saturating_add(1), 3_000)
        .await
        .unwrap()
        .unwrap();
    let root = std::env::current_dir().unwrap().canonicalize().unwrap();
    let sentinel = runtime.join("grandchild-survived");
    let script = format!("(sleep 1; touch '{}') & exit 0", sentinel.display());
    let command = PreparedCommand {
        program: PathBuf::from("/bin/sh").canonicalize().unwrap(),
        args: vec![OsString::from("-c"), OsString::from(script)],
        working_directory: root.clone(),
        execution_root: root,
    };

    let started = Instant::now();
    let outcome = execute_command(
        command,
        &mut leased,
        &store,
        Duration::from_secs(3),
        Duration::from_millis(100),
        10,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, CommandExecution::Completed { .. }));
    assert!(started.elapsed() < Duration::from_secs(1));
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert!(!sentinel.exists(), "grandchild escaped process-group kill");

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn command_timeout_kills_the_child_while_heartbeats_keep_the_lease_live() {
    let runtime = test_runtime("command-timeout");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let state_path = runtime.join("state.sqlite3");
    let store = Store::open(&state_path).unwrap();
    let request_id = RequestId::from("command-timeout-flow");
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    store
        .accept(
            AcceptRequest {
                request_id: request_id.clone(),
                caller_id: CallerId::from("flow-test-caller"),
                project_id: ProjectId::from("11111111-1111-4111-8111-111111111111"),
                idempotency_key: IdempotencyKey::from("command-timeout-key"),
                operation_kind: "command_executor_test".to_owned(),
                operation: Vec::new(),
            },
            now_ms,
        )
        .await
        .unwrap();
    let mut leased = store
        .claim("timeout-test", now_ms.saturating_add(1), 3_000)
        .await
        .unwrap()
        .unwrap();
    let initial_expiry = leased.lease.expires_at_ms;
    let root = std::env::current_dir().unwrap().canonicalize().unwrap();
    let sleep = ["/bin/sleep", "/usr/bin/sleep"]
        .into_iter()
        .map(PathBuf::from)
        .find_map(|path| path.canonicalize().ok())
        .expect("the Unix test host must provide sleep");
    let command = PreparedCommand {
        program: sleep,
        args: vec![OsString::from("5")],
        working_directory: root.clone(),
        execution_root: root,
    };

    let outcome = execute_command(
        command,
        &mut leased,
        &store,
        Duration::from_secs(3),
        Duration::from_millis(100),
        1,
    )
    .await
    .unwrap();
    assert!(matches!(
        outcome,
        CommandExecution::TimedOut { ref output } if output.is_empty()
    ));
    assert!(leased.lease.expires_at_ms > initial_expiry);

    store.shutdown().await.unwrap();
    fs::remove_dir_all(runtime).unwrap();
}
