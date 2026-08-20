use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    future::Future,
    io::Read,
    path::{Component, Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
    ambient_authority,
};
use cap_std::fs::{Dir, OpenOptions};
use pam_core::{ContentDigest, EvidenceHandle as StoreEvidenceHandle, ProjectId};
use pam_flow::{
    ApprovalMode, EffectAttempt, EffectKind, EffectReport, EffectResult, EngineUpdate,
    FlowDefinition, FlowRun, FlowRunResult, FlowSnapshot, ReconciliationResult, RunDecision, RunId,
    RunOutcome, RunTransition, StepSemanticRole,
};
use pam_policy::{InvalidResourceName, ResourceName};
use pam_protocol::{
    Failure, FailureCode, FlowDefinitionDocument, OperationTruth, PROTOCOL_VERSION, ResultBody,
    ResultEnvelope, ResultPayload, ServerMessage, decode_server_message_envelope, encode,
};
use pam_store::{
    EvidenceRedaction, EvidenceRetention, FlowEffectAuthorization, FlowTerminalResult,
    LeasedRequest, PutEvidence, RequestState, SaveFlowCheckpoint, Store, StoreError, TerminalState,
};
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::mpsc,
    task::JoinHandle,
};

pub(super) const FLOW_OPERATION_KIND: &str = "flow_run";
const MAX_COMMAND_OUTPUT_BYTES: usize = 256 * 1024;
const COMMAND_OUTPUT_MEDIA_TYPE: &str = "application/vnd.pam.flow-command-output";
const FLOW_OPERATION_HEADER: &[u8] = b"pam-flow-operation-v2\0";
const WORKSPACE_FINGERPRINT_DOMAIN: &[u8] = b"pam-flow-workspace-v1\0";
const MAX_WORKSPACE_ENTRIES: usize = 100_000;
const MAX_WORKSPACE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WORKSPACE_LIST_BYTES: usize = 8 * 1024 * 1024;
const MAX_GIT_CONFIG_BYTES: u64 = 1024 * 1024;
const WORKSPACE_LIST_TIMEOUT: Duration = Duration::from_secs(10);
const WORKSPACE_FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(30);
const POST_KILL_WAIT: Duration = Duration::from_secs(2);
const POST_KILL_DRAIN: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkspaceFingerprint(pub(super) [u8; 32]);

impl WorkspaceFingerprint {
    fn digest(self) -> ContentDigest {
        ContentDigest::from_sha256(self.0)
    }
}

pub(super) struct WorkspaceAuthority {
    canonical_root: PathBuf,
    root: Dir,
    git: Dir,
    root_identity: DirectoryIdentity,
    git_identity: DirectoryIdentity,
}

struct FingerprintedWorkspace {
    fingerprint: WorkspaceFingerprint,
    authority: WorkspaceAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    first: u64,
    second: u64,
}

impl WorkspaceAuthority {
    pub(super) fn open(execution_root: &Path) -> Result<Self, FlowSubmissionError> {
        let canonical_root = execution_root
            .canonicalize()
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        let root = Dir::open_ambient_dir(&canonical_root, ambient_authority())
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        // A `.git` file denotes a linked worktree whose external authority is not
        // yet bound by this executor. Opening the directory without following a
        // link keeps that representation fail-closed.
        let git = root
            .open_dir_nofollow(".git")
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        let root_identity = directory_handle_identity(&root)?;
        let git_identity = directory_handle_identity(&git)?;
        Ok(Self {
            canonical_root,
            root,
            git,
            root_identity,
            git_identity,
        })
    }

    pub(super) fn verify_path_identity(&self) -> Result<(), FlowSubmissionError> {
        let root = std::fs::symlink_metadata(&self.canonical_root)
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        let git = std::fs::symlink_metadata(self.canonical_root.join(".git"))
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        if root.file_type().is_symlink()
            || git.file_type().is_symlink()
            || !root.is_dir()
            || !git.is_dir()
            || directory_metadata_identity(&root)? != self.root_identity
            || directory_metadata_identity(&git)? != self.git_identity
        {
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        }
        Ok(())
    }
}

fn directory_handle_identity(directory: &Dir) -> Result<DirectoryIdentity, FlowSubmissionError> {
    let metadata = directory
        .try_clone()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?
        .into_std_file()
        .metadata()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    directory_metadata_identity(&metadata)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Keeps the fail-closed non-Unix implementation type-identical.
fn directory_metadata_identity(
    metadata: &std::fs::Metadata,
) -> Result<DirectoryIdentity, FlowSubmissionError> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(DirectoryIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn directory_metadata_identity(
    _metadata: &std::fs::Metadata,
) -> Result<DirectoryIdentity, FlowSubmissionError> {
    Err(FlowSubmissionError::WorkspaceUnavailable)
}

pub(super) struct PreparedFlowSubmission {
    pub(super) operation: Vec<u8>,
    pub(super) policy_resource: String,
    pub(super) schema_approval_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FlowSubmissionError {
    InvalidDefinition,
    UnsupportedDefinition,
    WorkspaceUnavailable,
}

pub(super) enum FlowProcessing {
    Terminal {
        terminal_state: TerminalState,
        result: Box<ResultEnvelope>,
        encoded_result: Vec<u8>,
    },
    StaleLease,
}

pub(super) async fn prepare_flow_submission(
    document: &FlowDefinitionDocument,
    execution_root: &Path,
) -> Result<PreparedFlowSubmission, FlowSubmissionError> {
    let definition = FlowDefinition::parse_toml(document.as_str())
        .map_err(|_| FlowSubmissionError::InvalidDefinition)?;
    let schema_approval_required = definition
        .steps()
        .iter()
        .any(|step| step.effect() == EffectKind::Stateful);
    validate_supported_definition(execution_root, &definition)
        .map_err(|_| FlowSubmissionError::UnsupportedDefinition)?;
    let fingerprint = workspace_fingerprint(execution_root).await?;
    let normalized = definition
        .to_normalized_toml()
        .map(String::into_bytes)
        .map_err(|_| FlowSubmissionError::InvalidDefinition)?;
    let operation = encode_flow_operation(&normalized, fingerprint, execution_root)?;
    let policy_resource = flow_policy_resource(&definition, fingerprint)
        .map_err(|_| FlowSubmissionError::InvalidDefinition)?;
    Ok(PreparedFlowSubmission {
        operation,
        policy_resource,
        schema_approval_required,
    })
}

pub(super) fn flow_policy_resource(
    definition: &FlowDefinition,
    workspace: WorkspaceFingerprint,
) -> Result<String, InvalidResourceName> {
    let digest = definition
        .normalized_digest()
        .map_err(|_| InvalidResourceName)?;
    Ok(format!(
        "flow:{}:revision={}:digest={digest}:workspace={}",
        definition.id(),
        definition.revision(),
        workspace.digest()
    ))
}

fn encode_flow_operation(
    normalized_definition: &[u8],
    workspace: WorkspaceFingerprint,
    execution_root: &Path,
) -> Result<Vec<u8>, FlowSubmissionError> {
    let root = execution_root
        .to_str()
        .ok_or(FlowSubmissionError::WorkspaceUnavailable)?
        .as_bytes();
    let root_length =
        u32::try_from(root.len()).map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    let mut operation = Vec::with_capacity(
        FLOW_OPERATION_HEADER.len()
            + size_of::<u32>()
            + root.len()
            + workspace.0.len()
            + normalized_definition.len(),
    );
    operation.extend_from_slice(FLOW_OPERATION_HEADER);
    operation.extend_from_slice(&root_length.to_be_bytes());
    operation.extend_from_slice(root);
    operation.extend_from_slice(&workspace.0);
    operation.extend_from_slice(normalized_definition);
    Ok(operation)
}

pub(super) fn decode_flow_transition(payload: &[u8]) -> Result<RunTransition, StoreError> {
    rmp_serde::from_slice(payload)
        .map_err(|_| StoreError::InvalidState("stored flow transition is corrupt".to_owned()))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn process_flow(
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
    heartbeat_interval: Duration,
) -> Result<FlowProcessing, StoreError> {
    let Some((definition, accepted_workspace, execution_root)) =
        decode_flow_operation(&leased.operation)
    else {
        return Ok(internal_failure(leased, "stored flow operation is invalid"));
    };
    let operation_resource = flow_policy_resource(&definition, accepted_workspace)
        .ok()
        .and_then(|resource| ResourceName::parse(resource).ok());
    let Some(operation_resource) = operation_resource else {
        return Ok(internal_failure(leased, "stored flow operation is invalid"));
    };
    let Ok(run_id) = RunId::parse(leased.lease.request_id.as_str()) else {
        return Ok(internal_failure(leased, "flow run identity is invalid"));
    };
    let checkpoint = match store
        .load_flow_checkpoint(leased.lease.clone(), now_ms())
        .await
    {
        Ok(checkpoint) => checkpoint,
        Err(StoreError::StaleLease(_)) => return Ok(FlowProcessing::StaleLease),
        Err(error) => return Err(error),
    };
    let (mut run, mut revision, needs_initial_save, needs_snapshot_upgrade) =
        if let Some(checkpoint) = checkpoint {
            let legacy_snapshot =
                checkpoint.snapshot.snapshot_version() < pam_flow::FLOW_SNAPSHOT_VERSION;
            let cached_terminal = checkpoint.terminal_result;
            let run = FlowRun::resume(&run_id, definition, checkpoint.snapshot)
                .map_err(flow_engine_error)?;
            if let Some(result) = run.result() {
                let cached = cached_terminal.ok_or_else(|| {
                    StoreError::InvalidState(
                        "terminal flow checkpoint omitted its encoded result".to_owned(),
                    )
                })?;
                return cached_terminal_result(leased, &result, cached);
            }
            if cached_terminal.is_some() {
                return Err(StoreError::InvalidState(
                    "non-terminal flow checkpoint contains a terminal result".to_owned(),
                ));
            }
            (run, checkpoint.checkpoint_revision, false, legacy_snapshot)
        } else {
            let run = FlowRun::start(run_id, definition).map_err(flow_engine_error)?;
            (run, 0, true, false)
        };
    match store
        .validate_flow_operation_resource(leased.lease.clone(), operation_resource, now_ms())
        .await
    {
        Ok(()) => {}
        Err(StoreError::StaleLease(_)) => return Ok(FlowProcessing::StaleLease),
        Err(StoreError::CorruptFlowAuthorization(_)) => {
            return Ok(internal_failure(
                leased,
                "stored flow operation does not match its authorization",
            ));
        }
        Err(error) => return Err(error),
    }
    if verify_flow_project_root(&execution_root, &leased.lease.project_id).is_err() {
        return Ok(unsupported_failure(
            leased,
            FailureCode::InvalidRequest,
            "stored flow project root is unavailable or does not match its project",
        ));
    }
    if needs_snapshot_upgrade {
        let saved = match store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: leased.lease.clone(),
                expected_revision: revision,
                snapshot: run.snapshot().clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: now_ms(),
            })
            .await
        {
            Ok(saved) => saved,
            Err(StoreError::StaleLease(_)) => return Ok(FlowProcessing::StaleLease),
            Err(error) => return Err(error),
        };
        revision = saved.checkpoint.checkpoint_revision;
    }
    if needs_initial_save {
        let saved = match store
            .save_flow_checkpoint(SaveFlowCheckpoint {
                lease: leased.lease.clone(),
                expected_revision: 0,
                snapshot: run.snapshot().clone(),
                transition: None,
                terminal_result: None,
                updated_at_ms: now_ms(),
            })
            .await
        {
            Ok(saved) => saved,
            Err(StoreError::StaleLease(_)) => return Ok(FlowProcessing::StaleLease),
            Err(error) => return Err(error),
        };
        revision = saved.checkpoint.checkpoint_revision;
    }
    let mut pending_decision = None;

    loop {
        if pending_decision.is_none() && request_is_cancelled(store, leased).await? {
            let update = run.cancel().map_err(flow_engine_error)?;
            let (decision, next_revision, terminal_result) =
                persist_update(store, leased, revision, update).await?;
            revision = next_revision;
            pending_decision = Some((decision, terminal_result));
        }

        let (decision, encoded_terminal_result) = if let Some(decision) = pending_decision.take() {
            decision
        } else {
            let previous_snapshot = run.snapshot().clone();
            let update = run.next_decision(now_ms()).map_err(flow_engine_error)?;
            let (decision, next_revision, terminal_result) =
                persist_update_reconciling_cancellation(
                    store,
                    leased,
                    revision,
                    &mut run,
                    previous_snapshot,
                    update,
                )
                .await?;
            revision = next_revision;
            (decision, terminal_result)
        };

        match decision {
            RunDecision::Continue => {}
            RunDecision::AwaitApproval { .. } => {
                return Err(StoreError::InvalidState(
                    "approval-required flow reached a read-only executor".to_owned(),
                ));
            }
            RunDecision::EvaluateEffect { effect, .. } => {
                match effect_boundary_authorization(store, leased).await? {
                    EffectBoundaryAuthorization::Allowed => {}
                    EffectBoundaryAuthorization::Denied => {
                        let previous_snapshot = run.snapshot().clone();
                        let update = run
                            .deny_effect_authorization(&effect)
                            .map_err(flow_engine_error)?;
                        let (decision, next_revision, terminal_result) =
                            persist_update_reconciling_cancellation(
                                store,
                                leased,
                                revision,
                                &mut run,
                                previous_snapshot,
                                update,
                            )
                            .await?;
                        revision = next_revision;
                        pending_decision = Some((decision, terminal_result));
                        continue;
                    }
                    EffectBoundaryAuthorization::Cancelled => {
                        let update = run.cancel().map_err(flow_engine_error)?;
                        let (decision, next_revision, terminal_result) =
                            persist_update(store, leased, revision, update).await?;
                        revision = next_revision;
                        pending_decision = Some((decision, terminal_result));
                        continue;
                    }
                }
                // Classification and the executable allowlist are intentionally checked on
                // every evaluation, including read-only replay after daemon restart.
                let mut prepared = if verify_flow_project_root(
                    &execution_root,
                    &leased.lease.project_id,
                )
                .is_ok()
                {
                    prepare_command(&execution_root, run.definition(), &effect)
                } else {
                    Err(CommandRejection::WorkspaceChanged)
                };
                let previous_snapshot = run.snapshot().clone();
                let update = run
                    .prepare_effect(&effect, now_ms())
                    .map_err(flow_engine_error)?;
                let (execute, next_revision, terminal_result) =
                    persist_update_reconciling_cancellation(
                        store,
                        leased,
                        revision,
                        &mut run,
                        previous_snapshot,
                        update,
                    )
                    .await?;
                revision = next_revision;
                if !matches!(execute, RunDecision::Execute { .. }) {
                    if matches!(execute, RunDecision::Terminal { .. }) && terminal_result.is_some()
                    {
                        pending_decision = Some((execute, terminal_result));
                        continue;
                    }
                    return Err(StoreError::InvalidState(
                        "flow effect preparation did not yield execution".to_owned(),
                    ));
                }
                debug_assert!(terminal_result.is_none());

                // Persist EffectStarted before acting, then bind the actual spawn to the
                // accepted worktree bytes as late as possible. Any listing/read failure or
                // mutation fails closed without invoking the command. This is detection, not
                // an immutable filesystem snapshot: a same-user writer can still mutate a
                // file after this digest completes but before the child opens it.
                let mut execution_authority = None;
                match await_workspace_fingerprint_with_lease(
                    fingerprint_workspace(&execution_root),
                    leased,
                    store,
                    lease_duration,
                    heartbeat_interval,
                )
                .await?
                {
                    WorkspaceFingerprintLease::Completed(Ok(workspace))
                        if workspace.fingerprint == accepted_workspace =>
                    {
                        execution_authority = Some(workspace.authority);
                    }
                    WorkspaceFingerprintLease::Completed(_) => {
                        prepared = Err(CommandRejection::WorkspaceChanged);
                    }
                    WorkspaceFingerprintLease::Cancelled => {
                        let update = run.cancel().map_err(flow_engine_error)?;
                        let (decision, next_revision, terminal_result) =
                            persist_update(store, leased, revision, update).await?;
                        revision = next_revision;
                        pending_decision = Some((decision, terminal_result));
                        continue;
                    }
                    WorkspaceFingerprintLease::StaleLease => {
                        return Ok(FlowProcessing::StaleLease);
                    }
                }

                if prepared.is_ok() {
                    match effect_boundary_authorization(store, leased).await? {
                        EffectBoundaryAuthorization::Allowed => {}
                        EffectBoundaryAuthorization::Denied => {
                            // Close the authorization window after the durable
                            // EffectStarted checkpoint but before the operating-system spawn.
                            let previous_snapshot = run.snapshot().clone();
                            let update = run
                                .deny_effect_authorization(&effect)
                                .map_err(flow_engine_error)?;
                            let (decision, next_revision, terminal_result) =
                                persist_update_reconciling_cancellation(
                                    store,
                                    leased,
                                    revision,
                                    &mut run,
                                    previous_snapshot,
                                    update,
                                )
                                .await?;
                            revision = next_revision;
                            pending_decision = Some((decision, terminal_result));
                            continue;
                        }
                        EffectBoundaryAuthorization::Cancelled => {
                            let update = run.cancel().map_err(flow_engine_error)?;
                            let (decision, next_revision, terminal_result) =
                                persist_update(store, leased, revision, update).await?;
                            revision = next_revision;
                            pending_decision = Some((decision, terminal_result));
                            continue;
                        }
                    }
                }

                let effect_result = match prepared {
                    Ok(command) => match execute_command_in_workspace(
                        command,
                        execution_authority.ok_or_else(|| {
                            StoreError::InvalidState(
                                "flow execution omitted its pinned workspace authority".to_owned(),
                            )
                        })?,
                        accepted_workspace,
                        leased,
                        store,
                        lease_duration,
                        heartbeat_interval,
                        effect.timeout_seconds(),
                    )
                    .await?
                    {
                        CommandExecution::Completed { status, output } => {
                            retain_command_result(
                                store,
                                leased,
                                status,
                                output,
                                effect.effect() == EffectKind::ReadOnly,
                            )
                            .await?
                        }
                        CommandExecution::LaunchFailed => {
                            EffectResult::failed("command could not be started", false, Vec::new())
                                .map_err(flow_engine_error)?
                        }
                        CommandExecution::WorkspaceChanged => EffectResult::failed(
                            "workspace changed while the command was running",
                            false,
                            Vec::new(),
                        )
                        .map_err(flow_engine_error)?,
                        CommandExecution::Cancelled => {
                            let update = run.cancel().map_err(flow_engine_error)?;
                            let (decision, next_revision, terminal_result) =
                                persist_update(store, leased, revision, update).await?;
                            revision = next_revision;
                            pending_decision = Some((decision, terminal_result));
                            continue;
                        }
                        CommandExecution::StaleLease => return Ok(FlowProcessing::StaleLease),
                        CommandExecution::TimedOut { output } => {
                            if effect.effect() == EffectKind::Stateful {
                                let evidence = retain_output(store, leased, output).await?;
                                let previous_snapshot = run.snapshot().clone();
                                let update = unknown_reconciliation_update(
                                    &mut run,
                                    &effect,
                                    vec![evidence],
                                    "stateful command outcome is unknown after timeout",
                                )?;
                                let (decision, next_revision, terminal_result) =
                                    persist_update_reconciling_cancellation(
                                        store,
                                        leased,
                                        revision,
                                        &mut run,
                                        previous_snapshot,
                                        update,
                                    )
                                    .await?;
                                revision = next_revision;
                                pending_decision = Some((decision, terminal_result));
                                continue;
                            }
                            retain_failed_command_result(
                                store,
                                leased,
                                "command timed out",
                                true,
                                output,
                            )
                            .await?
                        }
                        CommandExecution::OutputLimit | CommandExecution::CaptureFailed
                            if effect.effect() == EffectKind::Stateful =>
                        {
                            let previous_snapshot = run.snapshot().clone();
                            let update = unknown_reconciliation_update(
                                &mut run,
                                &effect,
                                Vec::new(),
                                "stateful command outcome is unknown after output capture failed",
                            )?;
                            let (decision, next_revision, terminal_result) =
                                persist_update_reconciling_cancellation(
                                    store,
                                    leased,
                                    revision,
                                    &mut run,
                                    previous_snapshot,
                                    update,
                                )
                                .await?;
                            revision = next_revision;
                            pending_decision = Some((decision, terminal_result));
                            continue;
                        }
                        CommandExecution::OutputLimit => EffectResult::failed(
                            "command output exceeded the limit",
                            false,
                            Vec::new(),
                        )
                        .map_err(flow_engine_error)?,
                        CommandExecution::CaptureFailed => EffectResult::failed(
                            "command output could not be captured exactly",
                            false,
                            Vec::new(),
                        )
                        .map_err(flow_engine_error)?,
                    },
                    Err(_) => EffectResult::failed(
                        "command action is unsupported by this daemon",
                        false,
                        Vec::new(),
                    )
                    .map_err(flow_engine_error)?,
                };
                let previous_snapshot = run.snapshot().clone();
                let update = run
                    .record_effect_result(&effect, effect_result, now_ms())
                    .map_err(flow_engine_error)?;
                let (decision, next_revision, terminal_result) =
                    persist_update_reconciling_cancellation(
                        store,
                        leased,
                        revision,
                        &mut run,
                        previous_snapshot,
                        update,
                    )
                    .await?;
                revision = next_revision;
                pending_decision = Some((decision, terminal_result));
            }
            RunDecision::Execute { .. } | RunDecision::AwaitResult { .. } => {
                return Err(StoreError::InvalidState(
                    "flow executor observed an unowned in-flight effect".to_owned(),
                ));
            }
            RunDecision::Reconcile { effect } => {
                let previous_snapshot = run.snapshot().clone();
                let update = unknown_reconciliation_update(
                    &mut run,
                    &effect,
                    Vec::new(),
                    "stateful command outcome is unknown after execution was interrupted",
                )?;
                let (decision, next_revision, terminal_result) =
                    persist_update_reconciling_cancellation(
                        store,
                        leased,
                        revision,
                        &mut run,
                        previous_snapshot,
                        update,
                    )
                    .await?;
                revision = next_revision;
                pending_decision = Some((decision, terminal_result));
            }
            RunDecision::WaitRetry { not_before_ms, .. } => {
                match wait_for_retry(
                    leased,
                    store,
                    not_before_ms,
                    lease_duration,
                    heartbeat_interval,
                )
                .await?
                {
                    LeaseWait::Ready => {}
                    LeaseWait::Cancelled => {
                        let update = run.cancel().map_err(flow_engine_error)?;
                        let (decision, next_revision, terminal_result) =
                            persist_update(store, leased, revision, update).await?;
                        revision = next_revision;
                        pending_decision = Some((decision, terminal_result));
                    }
                    LeaseWait::StaleLease => return Ok(FlowProcessing::StaleLease),
                }
            }
            RunDecision::Terminal { result } => {
                let encoded_result = encoded_terminal_result.ok_or_else(|| {
                    StoreError::InvalidState(
                        "terminal flow checkpoint omitted its encoded result".to_owned(),
                    )
                })?;
                return Ok(terminal_result(leased, result, encoded_result));
            }
        }
    }
}

fn unknown_reconciliation_update(
    run: &mut FlowRun,
    effect: &EffectAttempt,
    evidence: Vec<pam_flow::EvidenceHandle>,
    summary: &str,
) -> Result<EngineUpdate, StoreError> {
    let report = EffectReport::new(summary, evidence).map_err(flow_engine_error)?;
    run.record_reconciliation(effect, ReconciliationResult::Unknown(report), now_ms())
        .map_err(flow_engine_error)
}

fn decode_flow_operation(
    operation: &[u8],
) -> Option<(FlowDefinition, WorkspaceFingerprint, PathBuf)> {
    let payload = operation.strip_prefix(FLOW_OPERATION_HEADER)?;
    let (root_length, payload) = payload.split_at_checked(size_of::<u32>())?;
    let root_length = usize::try_from(u32::from_be_bytes(root_length.try_into().ok()?)).ok()?;
    let (root, payload) = payload.split_at_checked(root_length)?;
    let root = PathBuf::from(std::str::from_utf8(root).ok()?);
    if !root.is_absolute() {
        return None;
    }
    let (fingerprint, normalized) = payload.split_at_checked(32)?;
    let source = std::str::from_utf8(normalized).ok()?;
    let definition = FlowDefinition::parse_toml(source).ok()?;
    if definition.to_normalized_toml().ok()?.as_bytes() != normalized {
        return None;
    }
    Some((
        definition,
        WorkspaceFingerprint(fingerprint.try_into().ok()?),
        root,
    ))
}

pub(super) fn verify_flow_project_root(
    requested_root: &Path,
    expected_project_id: &ProjectId,
) -> Result<PathBuf, FlowSubmissionError> {
    if !requested_root.is_absolute() {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    let canonical_root = requested_root
        .canonicalize()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    if canonical_root != requested_root {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    let project = pam_platform::discover_project(&canonical_root)
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    let discovered_root = project
        .root()
        .canonicalize()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    if discovered_root != canonical_root || project.id() != expected_project_id {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    Ok(canonical_root)
}

async fn persist_update(
    store: &Store,
    leased: &LeasedRequest,
    revision: u64,
    update: EngineUpdate,
) -> Result<(RunDecision, u64, Option<Vec<u8>>), StoreError> {
    let (snapshot, transition, decision) = update.into_parts();
    let terminal_result = match &decision {
        RunDecision::Terminal { result } => Some(FlowTerminalResult {
            outcome: result.outcome(),
            encoded_result: encode_flow_result(leased, result.clone())?,
        }),
        _ => None,
    };
    let encoded_terminal_result = terminal_result
        .as_ref()
        .map(|terminal| terminal.encoded_result.clone());
    let saved = store
        .save_flow_checkpoint(SaveFlowCheckpoint {
            lease: leased.lease.clone(),
            expected_revision: revision,
            snapshot,
            transition,
            terminal_result,
            updated_at_ms: now_ms(),
        })
        .await?;
    Ok((
        decision,
        saved.checkpoint.checkpoint_revision,
        encoded_terminal_result,
    ))
}

pub(super) async fn persist_update_reconciling_cancellation(
    store: &Store,
    leased: &LeasedRequest,
    revision: u64,
    run: &mut FlowRun,
    previous_snapshot: FlowSnapshot,
    update: EngineUpdate,
) -> Result<(RunDecision, u64, Option<Vec<u8>>), StoreError> {
    let terminal_non_cancelled = matches!(
        update.decision(),
        RunDecision::Terminal { result } if result.outcome() != RunOutcome::Cancelled
    );
    let effect_start = matches!(
        update.transition().map(RunTransition::kind),
        Some(pam_flow::TransitionKind::EffectStarted { .. })
    );
    match persist_update(store, leased, revision, update).await {
        Ok(saved) => Ok(saved),
        Err(error)
            if (terminal_non_cancelled
                && matches!(error, StoreError::FlowTerminalOutcomeConflict(_)))
                || (effect_start && matches!(error, StoreError::FlowEffectStartConflict(_))) =>
        {
            if !request_is_cancelled(store, leased).await? {
                return Err(error);
            }
            // Cancellation won the Store transaction immediately before a
            // non-cancelled terminal save. Resume the last durable snapshot and
            // commit the engine's truthful Cancelled successor instead of
            // surfacing the expected race as a scheduler-fatal error.
            let run_id = previous_snapshot.run_id().clone();
            let definition = run.definition().clone();
            *run = FlowRun::resume(&run_id, definition, previous_snapshot)
                .map_err(flow_engine_error)?;
            let cancelled = run.cancel().map_err(flow_engine_error)?;
            persist_update(store, leased, revision, cancelled).await
        }
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectBoundaryAuthorization {
    Allowed,
    Denied,
    Cancelled,
}

async fn effect_boundary_authorization(
    store: &Store,
    leased: &LeasedRequest,
) -> Result<EffectBoundaryAuthorization, StoreError> {
    match store
        .validate_flow_effect_authorization(leased.lease.clone(), now_ms())
        .await
    {
        Ok(FlowEffectAuthorization::Allowed) => Ok(EffectBoundaryAuthorization::Allowed),
        Ok(FlowEffectAuthorization::Denied) => Ok(EffectBoundaryAuthorization::Denied),
        Err(error @ StoreError::StaleLease(_)) => {
            if request_is_cancelled(store, leased).await? {
                Ok(EffectBoundaryAuthorization::Cancelled)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

async fn request_is_cancelled(store: &Store, leased: &LeasedRequest) -> Result<bool, StoreError> {
    Ok(store.snapshot(leased.lease.request_id.clone()).await?.state
        == RequestState::CancellationRequested)
}

fn terminal_result(
    leased: &LeasedRequest,
    result: FlowRunResult,
    encoded_result: Vec<u8>,
) -> FlowProcessing {
    let terminal_state = terminal_state(&result);
    let truth = flow_result_truth(&result);
    FlowProcessing::Terminal {
        terminal_state,
        result: Box::new(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: leased.lease.request_id.clone(),
            project_id: leased.lease.project_id.clone(),
            body: ResultBody::Success {
                truth,
                payload: ResultPayload::FlowRun(result),
            },
        }),
        encoded_result,
    }
}

const fn terminal_state(result: &FlowRunResult) -> TerminalState {
    match result.outcome() {
        RunOutcome::Solved => TerminalState::Succeeded,
        RunOutcome::Unresolved | RunOutcome::Blocked => TerminalState::Failed,
        RunOutcome::Cancelled => TerminalState::Cancelled,
    }
}

pub(super) fn flow_result_truth(result: &FlowRunResult) -> OperationTruth {
    match result.outcome() {
        RunOutcome::Solved if result.report().verified().satisfied() => OperationTruth::Verified,
        RunOutcome::Solved if result.report().changed().satisfied() => OperationTruth::Changed,
        RunOutcome::Solved => OperationTruth::Observed,
        RunOutcome::Unresolved | RunOutcome::Cancelled => OperationTruth::Unresolved,
        RunOutcome::Blocked => OperationTruth::Blocked,
    }
}

fn cached_terminal_result(
    leased: &LeasedRequest,
    expected: &FlowRunResult,
    cached: FlowTerminalResult,
) -> Result<FlowProcessing, StoreError> {
    if cached.outcome != expected.outcome() {
        return Err(corrupt_cached_terminal_result());
    }
    let ServerMessage::Result(mut envelope) =
        decode_server_message_envelope(&cached.encoded_result)
            .map_err(|_| corrupt_cached_terminal_result())?
    else {
        return Err(corrupt_cached_terminal_result());
    };
    if envelope.request_id != leased.lease.request_id
        || envelope.project_id != leased.lease.project_id
    {
        return Err(corrupt_cached_terminal_result());
    }
    let stored_version = envelope.protocol_version;
    let ResultBody::Success { truth, payload } = &mut envelope.body else {
        return Err(corrupt_cached_terminal_result());
    };
    let ResultPayload::FlowRun(stored) = payload else {
        return Err(corrupt_cached_terminal_result());
    };
    let matches_snapshot = match stored_version {
        PROTOCOL_VERSION => {
            stored == expected
                && cached.encoded_result == encode_flow_result(leased, expected.clone())?
        }
        4 => legacy_flow_result_matches(stored, expected),
        _ => false,
    };
    if !matches_snapshot {
        return Err(corrupt_cached_terminal_result());
    }
    envelope.protocol_version = PROTOCOL_VERSION;
    *truth = flow_result_truth(stored);
    Ok(FlowProcessing::Terminal {
        terminal_state: terminal_state(stored),
        result: Box::new(envelope),
        encoded_result: cached.encoded_result,
    })
}

fn legacy_flow_result_matches(stored: &FlowRunResult, expected: &FlowRunResult) -> bool {
    stored.run_id() == expected.run_id()
        && stored.definition_digest() == expected.definition_digest()
        && stored.outcome() == expected.outcome()
        && stored.steps().len() == expected.steps().len()
        && stored
            .steps()
            .iter()
            .zip(expected.steps())
            .all(|(left, right)| {
                left.step_id() == right.step_id()
                    && left.kind() == right.kind()
                    && left.result() == right.result()
                    && left.blocked_report() == right.blocked_report()
            })
}

fn corrupt_cached_terminal_result() -> StoreError {
    StoreError::InvalidState(
        "terminal flow checkpoint result does not match its snapshot".to_owned(),
    )
}

fn internal_failure(leased: &LeasedRequest, message: &str) -> FlowProcessing {
    unsupported_failure(leased, FailureCode::Internal, message)
}

fn unsupported_failure(leased: &LeasedRequest, code: FailureCode, message: &str) -> FlowProcessing {
    FlowProcessing::Terminal {
        terminal_state: TerminalState::Failed,
        result: Box::new(ResultEnvelope {
            protocol_version: PROTOCOL_VERSION,
            request_id: leased.lease.request_id.clone(),
            project_id: leased.lease.project_id.clone(),
            body: ResultBody::Failure(Failure {
                code,
                message: message.to_owned(),
                recovery: None,
                approval: None,
            }),
        }),
        encoded_result: Vec::new(),
    }
}

fn encode_flow_result(
    leased: &LeasedRequest,
    result: FlowRunResult,
) -> Result<Vec<u8>, StoreError> {
    let processing = terminal_result(leased, result, Vec::new());
    let FlowProcessing::Terminal { result, .. } = processing else {
        unreachable!("terminal result construction always returns a terminal flow")
    };
    encode(&ServerMessage::Result(*result)).map_err(|_| {
        StoreError::InvalidState("terminal flow result exceeded the protocol frame".to_owned())
    })
}

fn flow_engine_error(error: pam_flow::FlowEngineError) -> StoreError {
    let message = format!("flow engine rejected durable state: {error}");
    drop(error);
    StoreError::InvalidState(message)
}

#[derive(Debug)]
pub(super) struct PreparedCommand {
    pub(super) program: PathBuf,
    pub(super) args: Vec<OsString>,
    pub(super) working_directory: PathBuf,
    pub(super) execution_root: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandRejection {
    Unsupported,
    UnsafeWorkingDirectory,
    WorkspaceChanged,
}

fn validate_supported_definition(
    execution_root: &Path,
    definition: &FlowDefinition,
) -> Result<(), CommandRejection> {
    for step in definition.steps() {
        let action = step
            .action()
            .as_command()
            .ok_or(CommandRejection::Unsupported)?;
        canonical_working_directory(execution_root, action.working_directory)?;
        match action.program {
            "git" => {
                drop(validated_git_args(action.args)?);
                if step.effect() != EffectKind::ReadOnly || step.approval() != ApprovalMode::None {
                    return Err(CommandRejection::Unsupported);
                }
                validate_git_semantic_role(
                    action.args,
                    step.semantic_role(),
                    definition.schema_version(),
                )?;
            }
            _ => return Err(CommandRejection::Unsupported),
        }
        drop(resolve_executable(action.program, execution_root)?);
    }
    Ok(())
}

pub(super) async fn workspace_fingerprint(
    execution_root: &Path,
) -> Result<WorkspaceFingerprint, FlowSubmissionError> {
    fingerprint_workspace(execution_root)
        .await
        .map(|workspace| workspace.fingerprint)
}

async fn fingerprint_workspace(
    execution_root: &Path,
) -> Result<FingerprintedWorkspace, FlowSubmissionError> {
    tokio::time::timeout(
        WORKSPACE_FINGERPRINT_TIMEOUT,
        workspace_fingerprint_inner(execution_root),
    )
    .await
    .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?
}

async fn workspace_fingerprint_inner(
    execution_root: &Path,
) -> Result<FingerprintedWorkspace, FlowSubmissionError> {
    let root = execution_root.to_path_buf();
    let authority = tokio::task::spawn_blocking(move || WorkspaceAuthority::open(&root))
        .await
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)??;
    let mut entries =
        git_workspace_paths(&authority, &["--cached", "--others", "--exclude-standard"]).await?;
    entries.extend(
        git_workspace_paths(
            &authority,
            &[
                "--others",
                "--ignored",
                "--exclude-standard",
                "--",
                ".gitattributes",
                ":(glob)**/.gitattributes",
            ],
        )
        .await?,
    );
    tokio::task::spawn_blocking(move || {
        let fingerprint = hash_workspace_entries(&authority, entries)?;
        authority.verify_path_identity()?;
        Ok(FingerprintedWorkspace {
            fingerprint,
            authority,
        })
    })
    .await
    .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?
}

async fn git_workspace_paths(
    authority: &WorkspaceAuthority,
    selectors: &[&str],
) -> Result<Vec<String>, FlowSubmissionError> {
    let program = resolve_executable("git", &authority.canonical_root)
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    authority.verify_path_identity()?;
    let mut command = Command::new(program);
    command
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .arg("-c")
        .arg(format!("core.excludesFile={}", null_device()))
        .arg("ls-files")
        .arg("-z")
        .args(selectors)
        .current_dir(&authority.canonical_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    apply_safe_environment(&mut command, &authority.canonical_root);
    let output = run_bounded_listing_inner(command, MAX_WORKSPACE_LIST_BYTES).await?;
    authority.verify_path_identity()?;
    let listing =
        String::from_utf8(output).map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    Ok(listing.split_terminator('\0').map(str::to_owned).collect())
}

#[cfg(test)]
pub(super) async fn run_bounded_listing(
    command: Command,
    output_limit: usize,
) -> Result<Vec<u8>, FlowSubmissionError> {
    run_bounded_listing_inner(command, output_limit).await
}

async fn run_bounded_listing_inner(
    mut command: Command,
    output_limit: usize,
) -> Result<Vec<u8>, FlowSubmissionError> {
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    let mut group = CommandGroup::for_child(&child);
    let (output_tx, mut output_rx) = mpsc::channel::<OutputMessage>(8);
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(tokio::spawn(read_output(stdout, output_tx.clone())));
    }
    drop(output_tx);
    let mut output = Vec::new();
    let mut deadline = std::pin::pin!(tokio::time::sleep(WORKSPACE_LIST_TIMEOUT));
    loop {
        let Ok(status) = child.try_wait() else {
            let _ = terminate_and_collect(
                &mut child,
                &mut group,
                &mut output_rx,
                &mut output,
                output_limit,
                &mut readers,
            )
            .await;
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        };
        if let Some(status) = status {
            terminate_and_collect(
                &mut child,
                &mut group,
                &mut output_rx,
                &mut output,
                output_limit,
                &mut readers,
            )
            .await
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
            return status
                .success()
                .then_some(output)
                .ok_or(FlowSubmissionError::WorkspaceUnavailable);
        }
        tokio::select! {
            message = output_rx.recv() => {
                match message {
                    Some(OutputMessage::Data(chunk)) if append_output(
                        &mut output,
                        &chunk,
                        output_limit,
                    ).is_err() => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            output_limit,
                            &mut readers,
                        )
                        .await;
                        return Err(FlowSubmissionError::WorkspaceUnavailable);
                    }
                    Some(OutputMessage::ReadFailed) => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            output_limit,
                            &mut readers,
                        )
                        .await;
                        return Err(FlowSubmissionError::WorkspaceUnavailable);
                    }
                    Some(OutputMessage::Data(_)) | None => {}
                }
            }
            () = &mut deadline => {
                terminate_and_collect(
                    &mut child,
                    &mut group,
                    &mut output_rx,
                    &mut output,
                    output_limit,
                    &mut readers,
                )
                .await
                .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
                return Err(FlowSubmissionError::WorkspaceUnavailable);
            }
        }
    }
}

fn hash_workspace_entries(
    authority: &WorkspaceAuthority,
    entries: Vec<String>,
) -> Result<WorkspaceFingerprint, FlowSubmissionError> {
    let entries = entries.into_iter().collect::<BTreeSet<_>>();
    if entries.len() > MAX_WORKSPACE_ENTRIES {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    let mut hasher = Sha256::new();
    hasher.update(WORKSPACE_FINGERPRINT_DOMAIN);
    let root = authority
        .canonical_root
        .to_str()
        .ok_or(FlowSubmissionError::WorkspaceUnavailable)?;
    hash_length_prefixed(&mut hasher, root.as_bytes());
    hasher.update(
        u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    let mut total_bytes = 0_u64;
    for entry in entries {
        let relative = Path::new(&entry);
        if entry.is_empty()
            || relative.is_absolute()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        }
        hash_length_prefixed(&mut hasher, entry.as_bytes());
        let Some(file) = open_regular_relative(&authority.root, relative)? else {
            hasher.update(b"missing\0");
            continue;
        };
        hasher.update(b"file\0");
        drop(hash_regular_file(
            &mut hasher,
            &mut total_bytes,
            file,
            None,
        )?);
    }
    hash_git_authority(&authority.git, &mut hasher, &mut total_bytes)?;
    hasher.update(total_bytes.to_le_bytes());
    Ok(WorkspaceFingerprint(hasher.finalize().into()))
}

fn hash_git_authority(
    git_directory: &Dir,
    hasher: &mut Sha256,
    total_bytes: &mut u64,
) -> Result<(), FlowSubmissionError> {
    hasher.update(b"git-authority\0");
    let mut head = None;
    for relative in [
        "HEAD",
        "index",
        "config",
        "info/exclude",
        "info/attributes",
        "packed-refs",
    ] {
        let capture_limit = matches!(relative, "HEAD" | "config").then_some(MAX_GIT_CONFIG_BYTES);
        let contents = hash_optional_authority_file(
            hasher,
            total_bytes,
            git_directory,
            Path::new(relative),
            capture_limit,
        )?;
        if relative == "config"
            && let Some(contents) = contents.as_deref()
        {
            validate_git_config(contents)?;
        }
        if relative == "HEAD" {
            head = contents;
        }
    }
    let head = String::from_utf8(head.ok_or(FlowSubmissionError::WorkspaceUnavailable)?)
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        let relative = Path::new(reference);
        if !reference.starts_with("refs/")
            || relative.is_absolute()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        }
        hash_optional_authority_file(hasher, total_bytes, git_directory, relative, None)?;
    }
    Ok(())
}

fn hash_optional_authority_file(
    hasher: &mut Sha256,
    total_bytes: &mut u64,
    base: &Dir,
    relative: &Path,
    capture_limit: Option<u64>,
) -> Result<Option<Vec<u8>>, FlowSubmissionError> {
    let encoded = relative
        .to_str()
        .ok_or(FlowSubmissionError::WorkspaceUnavailable)?;
    hash_length_prefixed(hasher, encoded.as_bytes());
    if let Some(file) = open_regular_relative(base, relative)? {
        hasher.update(b"file\0");
        hash_regular_file(hasher, total_bytes, file, capture_limit)
    } else {
        hasher.update(b"missing\0");
        Ok(None)
    }
}

fn validate_git_config(contents: &[u8]) -> Result<(), FlowSubmissionError> {
    let config =
        std::str::from_utf8(contents).map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    let mut section = String::new();
    for line in config.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let normalized = line.to_ascii_lowercase();
        if normalized.starts_with('[') {
            let Some(end) = normalized.find(']') else {
                return Err(FlowSubmissionError::WorkspaceUnavailable);
            };
            normalized[1..end]
                .split(|character: char| character == '.' || character.is_whitespace())
                .next()
                .unwrap_or_default()
                .trim_matches('"')
                .clone_into(&mut section);
            if matches!(
                section.as_str(),
                "include" | "includeif" | "filter" | "diff"
            ) {
                return Err(FlowSubmissionError::WorkspaceUnavailable);
            }
            continue;
        }
        let key = normalized
            .split(['=', ' ', '\t'])
            .next()
            .unwrap_or_default();
        if (section == "core"
            && matches!(
                key,
                "worktree" | "attributesfile" | "hookspath" | "fsmonitor"
            ))
            || (section == "extensions" && key == "worktreeconfig")
            || key == "include.path"
        {
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        }
    }
    Ok(())
}

fn hash_regular_file(
    hasher: &mut Sha256,
    total_bytes: &mut u64,
    mut file: std::fs::File,
    capture_limit: Option<u64>,
) -> Result<Option<Vec<u8>>, FlowSubmissionError> {
    let metadata = file
        .metadata()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    if !metadata.is_file() || capture_limit.is_some_and(|limit| metadata.len() > limit) {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    hash_file_permissions(hasher, &metadata);
    hasher.update(metadata.len().to_le_bytes());
    let mut captured = capture_limit.map(|_| Vec::new());
    let mut read_bytes = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
        if count == 0 {
            break;
        }
        add_workspace_bytes(total_bytes, count)?;
        read_bytes = read_bytes.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        hasher.update(&buffer[..count]);
        if let Some(captured) = &mut captured {
            captured.extend_from_slice(&buffer[..count]);
        }
    }
    let final_metadata = file
        .metadata()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    if read_bytes != metadata.len() || !stable_file_metadata(&metadata, &final_metadata) {
        return Err(FlowSubmissionError::WorkspaceUnavailable);
    }
    hasher.update(b"\0file-end\0");
    Ok(captured)
}

fn open_regular_relative(
    base: &Dir,
    relative: &Path,
) -> Result<Option<std::fs::File>, FlowSubmissionError> {
    let mut components = relative.components().peekable();
    let mut directory = base
        .try_clone()
        .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(FlowSubmissionError::WorkspaceUnavailable);
        };
        if components.peek().is_some() {
            directory = directory
                .open_dir_nofollow(name)
                .map_err(|_| FlowSubmissionError::WorkspaceUnavailable)?;
            continue;
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No).nonblock(true);
        return match directory.open_with(name, &options) {
            Ok(file) => Ok(Some(file.into_std())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(FlowSubmissionError::WorkspaceUnavailable),
        };
    }
    Err(FlowSubmissionError::WorkspaceUnavailable)
}

#[cfg(test)]
pub(super) fn hash_relative_after_authority_open<F>(
    execution_root: &Path,
    git_authority: bool,
    relative: &Path,
    after_open: F,
) -> Result<(), FlowSubmissionError>
where
    F: FnOnce(),
{
    let authority = WorkspaceAuthority::open(execution_root)?;
    after_open();
    let directory = if git_authority {
        &authority.git
    } else {
        &authority.root
    };
    let file = open_regular_relative(directory, relative)?
        .ok_or(FlowSubmissionError::WorkspaceUnavailable)?;
    let mut hasher = Sha256::new();
    let mut total_bytes = 0;
    drop(hash_regular_file(
        &mut hasher,
        &mut total_bytes,
        file,
        None,
    )?);
    Ok(())
}

#[cfg(unix)]
fn stable_file_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.is_file()
        && after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn stable_file_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.is_file()
        && after.is_file()
        && before.len() == after.len()
        && before.permissions().readonly() == after.permissions().readonly()
        && before.modified().ok() == after.modified().ok()
}

#[cfg(unix)]
fn hash_file_permissions(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt as _;

    hasher.update(metadata.mode().to_le_bytes());
}

#[cfg(not(unix))]
fn hash_file_permissions(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    hasher.update([u8::from(metadata.permissions().readonly())]);
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn add_workspace_bytes(total: &mut u64, count: usize) -> Result<(), FlowSubmissionError> {
    *total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
    if *total > MAX_WORKSPACE_BYTES {
        Err(FlowSubmissionError::WorkspaceUnavailable)
    } else {
        Ok(())
    }
}

pub(super) fn prepare_command(
    execution_root: &Path,
    definition: &FlowDefinition,
    effect: &EffectAttempt,
) -> Result<PreparedCommand, CommandRejection> {
    let step = definition
        .steps()
        .get(effect.step_index())
        .filter(|step| step.id() == effect.step_id())
        .ok_or(CommandRejection::Unsupported)?;
    let action = step
        .action()
        .as_command()
        .ok_or(CommandRejection::Unsupported)?;
    let working_directory = canonical_working_directory(execution_root, action.working_directory)?;
    let args = match action.program {
        "git"
            if effect.effect() == EffectKind::ReadOnly && step.approval() == ApprovalMode::None =>
        {
            validate_git_semantic_role(
                action.args,
                step.semantic_role(),
                definition.schema_version(),
            )?;
            validated_git_args(action.args)?
        }
        _ => return Err(CommandRejection::Unsupported),
    };
    let program = resolve_executable(action.program, execution_root)?;
    Ok(PreparedCommand {
        program,
        args,
        working_directory,
        execution_root: execution_root.to_path_buf(),
    })
}

fn resolve_executable(program: &str, execution_root: &Path) -> Result<PathBuf, CommandRejection> {
    let inherited = std::env::var_os("PATH").ok_or(CommandRejection::Unsupported)?;
    std::env::split_paths(&inherited)
        .filter(|directory| directory.is_absolute())
        .filter_map(|directory| directory.join(program).canonicalize().ok())
        .find(|candidate| candidate.is_file() && !candidate.starts_with(execution_root))
        .ok_or(CommandRejection::Unsupported)
}

fn canonical_working_directory(
    execution_root: &Path,
    relative: &str,
) -> Result<PathBuf, CommandRejection> {
    if !matches!(relative, "" | ".") {
        // The workspace authority binds the project root. Supporting nested or
        // ignored projects would require a separately enumerated execution root.
        return Err(CommandRejection::UnsafeWorkingDirectory);
    }
    let candidate = execution_root.join(relative);
    let canonical = candidate
        .canonicalize()
        .map_err(|_| CommandRejection::UnsafeWorkingDirectory)?;
    if canonical.is_dir() && canonical.starts_with(execution_root) {
        Ok(canonical)
    } else {
        Err(CommandRejection::UnsafeWorkingDirectory)
    }
}

pub(super) fn validated_git_args(args: &[String]) -> Result<Vec<OsString>, CommandRejection> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(CommandRejection::Unsupported);
    };
    match command {
        "status"
            if args
                .iter()
                .skip(1)
                .all(|argument| safe_git_status_argument(argument)) =>
        {
            Ok(git_args_with_safe_config(args))
        }
        "rev-parse"
            if args.len() > 1
                && args
                    .iter()
                    .skip(1)
                    .all(|argument| safe_git_revision_argument(argument)) =>
        {
            Ok(git_args_with_safe_config(args))
        }
        "diff"
            if args.iter().any(|argument| argument == "--quiet")
                && args
                    .iter()
                    .skip(1)
                    .all(|argument| safe_git_diff_argument(argument)) =>
        {
            let mut validated = safe_git_config_args(args.len() + 2);
            validated.push(OsString::from("diff"));
            validated.push(OsString::from("--no-ext-diff"));
            validated.push(OsString::from("--no-textconv"));
            validated.extend(args.iter().skip(1).map(OsString::from));
            Ok(validated)
        }
        _ => Err(CommandRejection::Unsupported),
    }
}

fn validate_git_semantic_role(
    args: &[String],
    semantic_role: StepSemanticRole,
    schema_version: u16,
) -> Result<(), CommandRejection> {
    match (args.first().map(String::as_str), semantic_role) {
        (Some("diff"), StepSemanticRole::Verify)
        | (Some("status" | "rev-parse"), StepSemanticRole::Observe) => Ok(()),
        (Some("diff"), StepSemanticRole::Observe) if schema_version == 1 => Ok(()),
        _ => Err(CommandRejection::Unsupported),
    }
}

fn git_args_with_safe_config(args: &[String]) -> Vec<OsString> {
    let mut validated = safe_git_config_args(args.len());
    validated.extend(args.iter().map(OsString::from));
    validated
}

fn safe_git_config_args(additional: usize) -> Vec<OsString> {
    let mut args = Vec::with_capacity(additional + 7);
    args.extend([
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("-c"),
        OsString::from("core.untrackedCache=false"),
        OsString::from("-c"),
        OsString::from(format!("core.excludesFile={}", null_device())),
        OsString::from("--no-pager"),
    ]);
    args
}

fn safe_git_status_argument(argument: &str) -> bool {
    matches!(
        argument,
        "--short" | "-s" | "--porcelain" | "--no-renames" | "--find-renames"
    ) || argument.starts_with("--porcelain=")
        || argument.starts_with("--untracked-files=")
        || argument.starts_with("--find-renames=")
}

fn safe_git_revision_argument(argument: &str) -> bool {
    matches!(
        argument,
        "HEAD"
            | "--verify"
            | "--quiet"
            | "-q"
            | "--short"
            | "--show-toplevel"
            | "--show-prefix"
            | "--show-cdup"
            | "--git-dir"
            | "--absolute-git-dir"
            | "--is-inside-work-tree"
    ) || argument.strip_prefix("--short=").is_some_and(|length| {
        !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn safe_git_diff_argument(argument: &str) -> bool {
    argument == "--quiet"
}

pub(super) enum CommandExecution {
    Completed { status: ExitStatus, output: Vec<u8> },
    LaunchFailed,
    TimedOut { output: Vec<u8> },
    OutputLimit,
    CaptureFailed,
    WorkspaceChanged,
    Cancelled,
    StaleLease,
}

enum OutputMessage {
    Data(Vec<u8>),
    ReadFailed,
}

enum OutputCollectionError {
    Io(std::io::Error),
    Overflow,
    Incomplete,
}

#[cfg(test)]
pub(super) async fn execute_command(
    prepared: PreparedCommand,
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
    heartbeat_interval: Duration,
    timeout_seconds: u32,
) -> Result<CommandExecution, StoreError> {
    execute_command_raw(
        prepared,
        leased,
        store,
        lease_duration,
        heartbeat_interval,
        timeout_seconds,
    )
    .await
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)] // Execution needs explicit lease, authority, and time bounds.
pub(super) async fn execute_command_in_workspace(
    prepared: PreparedCommand,
    authority: WorkspaceAuthority,
    accepted_workspace: WorkspaceFingerprint,
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
    heartbeat_interval: Duration,
    timeout_seconds: u32,
) -> Result<CommandExecution, StoreError> {
    if prepared.working_directory != authority.canonical_root
        || authority.verify_path_identity().is_err()
    {
        return Ok(CommandExecution::WorkspaceChanged);
    }
    let execution_root = prepared.execution_root.clone();
    let outcome = execute_command_raw(
        prepared,
        leased,
        store,
        lease_duration,
        heartbeat_interval,
        timeout_seconds,
    )
    .await?;
    if !matches!(outcome, CommandExecution::Completed { .. }) {
        return Ok(outcome);
    }
    if authority.verify_path_identity().is_err() {
        return Ok(CommandExecution::WorkspaceChanged);
    }
    match await_workspace_fingerprint_with_lease(
        workspace_fingerprint(&execution_root),
        leased,
        store,
        lease_duration,
        heartbeat_interval,
    )
    .await?
    {
        WorkspaceFingerprintLease::Completed(Ok(fingerprint))
            if fingerprint == accepted_workspace && authority.verify_path_identity().is_ok() =>
        {
            Ok(outcome)
        }
        WorkspaceFingerprintLease::Cancelled => Ok(CommandExecution::Cancelled),
        WorkspaceFingerprintLease::StaleLease => Ok(CommandExecution::StaleLease),
        WorkspaceFingerprintLease::Completed(_) => Ok(CommandExecution::WorkspaceChanged),
    }
}

#[allow(clippy::too_many_lines)]
async fn execute_command_raw(
    prepared: PreparedCommand,
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
    heartbeat_interval: Duration,
    timeout_seconds: u32,
) -> Result<CommandExecution, StoreError> {
    let mut command = Command::new(&prepared.program);
    command
        .args(prepared.args)
        .current_dir(prepared.working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    apply_safe_environment(&mut command, &prepared.execution_root);
    configure_process_group(&mut command);
    let Ok(mut child) = command.spawn() else {
        return Ok(CommandExecution::LaunchFailed);
    };
    let mut group = CommandGroup::for_child(&child);
    let (output_tx, mut output_rx) = mpsc::channel::<OutputMessage>(8);
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(tokio::spawn(read_output(stdout, output_tx.clone())));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(tokio::spawn(read_output(stderr, output_tx.clone())));
    }
    drop(output_tx);

    let mut output = Vec::new();
    let mut deadline = std::pin::pin!(tokio::time::sleep(Duration::from_secs(u64::from(
        timeout_seconds,
    ))));
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = terminate_and_collect(
                    &mut child,
                    &mut group,
                    &mut output_rx,
                    &mut output,
                    MAX_COMMAND_OUTPUT_BYTES,
                    &mut readers,
                )
                .await;
                return Err(StoreError::Io(error));
            }
        };
        if let Some(status) = status {
            // A command may exit after leaving a grandchild holding the inherited pipes.
            // Terminate the remaining isolated group and bound collection in that case too.
            match terminate_and_collect(
                &mut child,
                &mut group,
                &mut output_rx,
                &mut output,
                MAX_COMMAND_OUTPUT_BYTES,
                &mut readers,
            )
            .await
            {
                Ok(()) => return Ok(CommandExecution::Completed { status, output }),
                Err(OutputCollectionError::Overflow) => {
                    return Ok(CommandExecution::OutputLimit);
                }
                Err(OutputCollectionError::Incomplete) => {
                    return Ok(CommandExecution::CaptureFailed);
                }
                Err(OutputCollectionError::Io(error)) => return Err(StoreError::Io(error)),
            }
        }
        tokio::select! {
            message = output_rx.recv() => {
                match message {
                    Some(OutputMessage::Data(chunk)) if append_output(
                        &mut output,
                        &chunk,
                        MAX_COMMAND_OUTPUT_BYTES,
                    ).is_err() => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            MAX_COMMAND_OUTPUT_BYTES,
                            &mut readers,
                        )
                        .await;
                        return Ok(CommandExecution::OutputLimit);
                    }
                    Some(OutputMessage::ReadFailed) => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            MAX_COMMAND_OUTPUT_BYTES,
                            &mut readers,
                        )
                        .await;
                        return Ok(CommandExecution::CaptureFailed);
                    }
                    Some(OutputMessage::Data(_)) | None => {}
                }
            }
            () = &mut deadline => {
                return Ok(match terminate_and_collect(
                    &mut child,
                    &mut group,
                    &mut output_rx,
                    &mut output,
                    MAX_COMMAND_OUTPUT_BYTES,
                    &mut readers,
                )
                .await
                {
                    Ok(()) => CommandExecution::TimedOut { output },
                    Err(OutputCollectionError::Overflow) => CommandExecution::OutputLimit,
                    Err(OutputCollectionError::Incomplete) => CommandExecution::CaptureFailed,
                    Err(OutputCollectionError::Io(error)) => return Err(StoreError::Io(error)),
                });
            }
            _ = heartbeat.tick() => {
                let lease_state = match renew_and_poll_cancellation(leased, store, lease_duration).await {
                    Ok(state) => state,
                    Err(error) => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            MAX_COMMAND_OUTPUT_BYTES,
                            &mut readers,
                        )
                        .await;
                        return Err(error);
                    }
                };
                match lease_state {
                    LeaseWait::Ready => {}
                    LeaseWait::Cancelled => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            MAX_COMMAND_OUTPUT_BYTES,
                            &mut readers,
                        )
                        .await;
                        return Ok(CommandExecution::Cancelled);
                    }
                    LeaseWait::StaleLease => {
                        let _ = terminate_and_collect(
                            &mut child,
                            &mut group,
                            &mut output_rx,
                            &mut output,
                            MAX_COMMAND_OUTPUT_BYTES,
                            &mut readers,
                        )
                        .await;
                        return Ok(CommandExecution::StaleLease);
                    }
                }
            }
        }
    }
}

async fn read_output(mut stream: impl AsyncRead + Unpin, output: mpsc::Sender<OutputMessage>) {
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let Ok(count) = stream.read(&mut buffer).await else {
            let _ = output.send(OutputMessage::ReadFailed).await;
            return;
        };
        if count == 0
            || output
                .send(OutputMessage::Data(buffer[..count].to_vec()))
                .await
                .is_err()
        {
            return;
        }
    }
}

async fn terminate_and_collect(
    child: &mut Child,
    group: &mut CommandGroup,
    output_rx: &mut mpsc::Receiver<OutputMessage>,
    output: &mut Vec<u8>,
    output_limit: usize,
    readers: &mut Vec<JoinHandle<()>>,
) -> Result<(), OutputCollectionError> {
    group.terminate(child);
    let wait_result = match tokio::time::timeout(POST_KILL_WAIT, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(OutputCollectionError::Io(error)),
        Err(_) => Err(OutputCollectionError::Incomplete),
    };
    let drain_result = tokio::time::timeout(POST_KILL_DRAIN, async {
        while let Some(message) = output_rx.recv().await {
            match message {
                OutputMessage::Data(chunk) => append_output(output, &chunk, output_limit)?,
                OutputMessage::ReadFailed => return Err(OutputCollectionError::Incomplete),
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| OutputCollectionError::Incomplete)
    .and_then(std::convert::identity);
    for reader in readers.iter() {
        reader.abort();
    }
    let readers_result = tokio::time::timeout(POST_KILL_DRAIN, async {
        for reader in readers.drain(..) {
            if reader.await.is_err() {
                return Err(OutputCollectionError::Incomplete);
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| OutputCollectionError::Incomplete)
    .and_then(std::convert::identity);
    drain_result.and(readers_result).and(wait_result)
}

fn append_output(
    output: &mut Vec<u8>,
    chunk: &[u8],
    output_limit: usize,
) -> Result<(), OutputCollectionError> {
    let remaining = output_limit.saturating_sub(output.len());
    output.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    if chunk.len() > remaining {
        Err(OutputCollectionError::Overflow)
    } else {
        Ok(())
    }
}

struct CommandGroup {
    #[cfg(unix)]
    process_id: Option<u32>,
    #[cfg(unix)]
    armed: bool,
}

impl CommandGroup {
    fn for_child(child: &Child) -> Self {
        #[cfg(unix)]
        {
            Self {
                process_id: child.id(),
                armed: true,
            }
        }

        #[cfg(not(unix))]
        {
            let _ = child;
            Self {}
        }
    }

    fn terminate(&mut self, child: &mut Child) {
        #[cfg(unix)]
        if let Some(process_id) = self.process_id.and_then(|id| i32::try_from(id).ok()) {
            use nix::{errno::Errno, sys::signal::Signal, unistd::Pid};

            if let Err(error) = nix::sys::signal::killpg(Pid::from_raw(process_id), Signal::SIGKILL)
                && error != Errno::ESRCH
            {
                let _ = child.start_kill();
                return;
            }
        }
        #[cfg(unix)]
        {
            self.armed = false;
        }
        let _ = child.start_kill();
    }
}

impl Drop for CommandGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.armed
            && let Some(process_id) = self.process_id.and_then(|id| i32::try_from(id).ok())
        {
            use nix::{sys::signal::Signal, unistd::Pid};

            let _ = nix::sys::signal::killpg(Pid::from_raw(process_id), Signal::SIGKILL);
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.as_std_mut().process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

fn apply_safe_environment(command: &mut Command, execution_root: &Path) {
    let environment = std::env::vars_os().filter(|(name, _)| safe_environment_name(name));
    command.env_clear().envs(environment);
    if let Some(path) = safe_search_path(execution_root) {
        command.env("PATH", path);
    }
    command
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("SSH_ASKPASS", "/usr/bin/false")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device());
}

#[cfg(unix)]
const fn null_device() -> &'static str {
    "/dev/null"
}

#[cfg(windows)]
const fn null_device() -> &'static str {
    "NUL"
}

#[cfg(not(any(unix, windows)))]
const fn null_device() -> &'static str {
    "/dev/null"
}

pub(super) fn safe_environment_name(name: &OsStr) -> bool {
    let uppercase = name.to_string_lossy().to_ascii_uppercase();
    matches!(
        uppercase.as_str(),
        "LANG" | "LC_ALL" | "LC_CTYPE" | "PATH" | "TEMP" | "TMP" | "TMPDIR"
    )
}

fn safe_search_path(execution_root: &Path) -> Option<OsString> {
    let inherited = std::env::var_os("PATH")?;
    let paths = std::env::split_paths(&inherited)
        .filter(|path| path.is_absolute())
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.is_dir() && !path.starts_with(execution_root))
        .collect::<Vec<_>>();
    std::env::join_paths(paths).ok()
}

async fn retain_command_result(
    store: &Store,
    leased: &LeasedRequest,
    status: ExitStatus,
    output: Vec<u8>,
    retryable: bool,
) -> Result<EffectResult, StoreError> {
    let evidence = retain_output(store, leased, output).await?;
    if status.success() {
        EffectResult::succeeded("command completed successfully", vec![evidence])
            .map_err(flow_engine_error)
    } else {
        EffectResult::failed("command exited unsuccessfully", retryable, vec![evidence])
            .map_err(flow_engine_error)
    }
}

async fn retain_failed_command_result(
    store: &Store,
    leased: &LeasedRequest,
    summary: &str,
    retryable: bool,
    output: Vec<u8>,
) -> Result<EffectResult, StoreError> {
    let evidence = retain_output(store, leased, output).await?;
    EffectResult::failed(summary, retryable, vec![evidence]).map_err(flow_engine_error)
}

async fn retain_output(
    store: &Store,
    leased: &LeasedRequest,
    output: Vec<u8>,
) -> Result<pam_flow::EvidenceHandle, StoreError> {
    let digest = ContentDigest::from_sha256(Sha256::digest(&output).into());
    let handle =
        StoreEvidenceHandle::parse(format!("evidence://flow-output/{}", digest.sha256_hex()))
            .map_err(|_| StoreError::InvalidState("flow evidence handle is invalid".to_owned()))?;
    store
        .put_evidence(
            PutEvidence {
                handle: handle.clone(),
                project_id: leased.lease.project_id.clone(),
                media_type: COMMAND_OUTPUT_MEDIA_TYPE.to_owned(),
                retention: EvidenceRetention::Project,
                redaction: EvidenceRedaction::Unredacted,
                bytes: output,
            },
            now_ms(),
        )
        .await?;
    pam_flow::EvidenceHandle::parse(handle.as_str()).map_err(flow_engine_error)
}

enum LeaseWait {
    Ready,
    Cancelled,
    StaleLease,
}

pub(super) enum WorkspaceFingerprintLease<T = WorkspaceFingerprint> {
    Completed(Result<T, FlowSubmissionError>),
    Cancelled,
    StaleLease,
}

pub(super) async fn await_workspace_fingerprint_with_lease<F, T>(
    fingerprint: F,
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
    heartbeat_interval: Duration,
) -> Result<WorkspaceFingerprintLease<T>, StoreError>
where
    F: Future<Output = Result<T, FlowSubmissionError>>,
{
    match renew_and_poll_cancellation(leased, store, lease_duration).await? {
        LeaseWait::Ready => {}
        LeaseWait::Cancelled => return Ok(WorkspaceFingerprintLease::Cancelled),
        LeaseWait::StaleLease => return Ok(WorkspaceFingerprintLease::StaleLease),
    }
    let mut fingerprint = std::pin::pin!(fingerprint);
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            result = &mut fingerprint => {
                return Ok(WorkspaceFingerprintLease::Completed(result));
            }
            _ = heartbeat.tick() => {
                match renew_and_poll_cancellation(leased, store, lease_duration).await? {
                    LeaseWait::Ready => {}
                    LeaseWait::Cancelled => return Ok(WorkspaceFingerprintLease::Cancelled),
                    LeaseWait::StaleLease => return Ok(WorkspaceFingerprintLease::StaleLease),
                }
            }
        }
    }
}

async fn wait_for_retry(
    leased: &mut LeasedRequest,
    store: &Store,
    not_before_ms: u64,
    lease_duration: Duration,
    heartbeat_interval: Duration,
) -> Result<LeaseWait, StoreError> {
    let remaining = not_before_ms.saturating_sub(now_ms());
    let mut delay = std::pin::pin!(tokio::time::sleep(Duration::from_millis(remaining)));
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            () = &mut delay => return Ok(LeaseWait::Ready),
            _ = heartbeat.tick() => {
                match renew_and_poll_cancellation(leased, store, lease_duration).await? {
                    LeaseWait::Ready => {}
                    other => return Ok(other),
                }
            }
        }
    }
}

async fn renew_and_poll_cancellation(
    leased: &mut LeasedRequest,
    store: &Store,
    lease_duration: Duration,
) -> Result<LeaseWait, StoreError> {
    match store
        .renew(leased.lease.clone(), now_ms(), duration_ms(lease_duration))
        .await
    {
        Ok(lease) => leased.lease = lease,
        Err(StoreError::StaleLease(_)) => return Ok(LeaseWait::StaleLease),
        Err(error) => return Err(error),
    }
    if request_is_cancelled(store, leased).await? {
        Ok(LeaseWait::Cancelled)
    } else {
        Ok(LeaseWait::Ready)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
