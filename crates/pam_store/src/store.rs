use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pam_core::{
    ApprovalId, CallerCredential, CallerId, ContentDigest, EvidenceHandle, GrantId, ProjectId,
    RequestId,
};
use pam_flow::{
    FlowSnapshot, RunOutcome, RunStatus, RunTransition, TransitionKind,
    validate_snapshot_successor, validate_snapshot_upgrade,
};
use pam_model::{
    GgufMetadata, LicenseSnapshot, ModelDescriptor, ModelKey, ModelSource, RegisteredModel,
};
use pam_policy::{
    ApprovalRequirement, CapabilityName, Decision, Effect, EffectFingerprint, Grant, ResourceName,
    ResourceScope, evaluate, redact_audit_detail,
};
use pam_skills::{
    AgentArtifact, AgentArtifactId, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent,
    ScanReport,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc as tokio_mpsc, oneshot};
use uuid::Uuid;

use crate::evidence::{self, EvidenceFiles};
use crate::{
    AUDIT_EXPORT_VERSION, AcceptOutcome, AcceptRequest, AppendAuditEvent, ApprovalDecision,
    ApprovalDecisionOutcome, AuditEventRecord, AuditExport, AuditPruneOutcome, AuthorizationAudit,
    AuthorizationOutcome, AuthorizationRequest, AuthorizeFlowRun, CallerAuthentication,
    CallerRegistration, CallerRevocation, CancelOutcome, EventRecord, EvidenceMetadata,
    EvidencePruneOutcome, EvidenceRetention, ExpectedOperationKind, FlowAuthorizationOutcome,
    FlowAuthorizationRecoveryOutcome, FlowCheckpoint, FlowCheckpointDisposition,
    FlowCheckpointSaveOutcome, FlowEffectAuthorization, FlowTerminalResult, GrantRevocation, Lease,
    LeasedRequest, MAX_AUDIT_ACTION_BYTES, MAX_AUDIT_BATCH_SIZE, MAX_AUDIT_CALLER_ID_BYTES,
    MAX_AUDIT_DECISION_BYTES, MAX_AUDIT_DETAIL_BYTES, MAX_AUDIT_EVENT_ID_BYTES,
    MAX_AUDIT_OUTCOME_BYTES, MAX_AUDIT_PROJECT_ID_BYTES, MAX_FLOW_CHECKPOINT_BYTES,
    MAX_FLOW_TERMINAL_RESULT_BYTES, MAX_FLOW_TRANSITION_BYTES, MAX_PROJECT_CURRENT_QUEUED,
    ProjectCurrent, ProjectPolicy, ProjectRequestSummary, ProjectWorkload, PutEvidence, PutGrant,
    Replay, RequestSnapshot, RequestState, SaveFlowCheckpoint, SkillInventoryDrift, StoreError,
    StoredAgentArtifact, StoredResult, TerminalState,
};

const COMMAND_CAPACITY: usize = 64;
const EVIDENCE_COMMAND_CAPACITY: usize = 8;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const FLOW_OPERATION_KIND: &str = "flow_run";
const STATUS_OPERATION_KIND: &str = "status";
const LEGACY_STATUS_OPERATION_KIND: &str = "daemon_status";
const FLOW_CAPABILITY_NAME: &str = "flow.run";
const EFFECT_APPROVAL_AUDIT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub(super) const LATEST_SCHEMA_VERSION: u32 = 10;
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (2, include_str!("../migrations/0002_evidence.sql")),
    (3, include_str!("../migrations/0003_callers.sql")),
    (4, include_str!("../migrations/0004_policy.sql")),
    (5, include_str!("../migrations/0005_audit.sql")),
    (
        6,
        include_str!("../migrations/0006_policy_resource_bound.sql"),
    ),
    (7, include_str!("../migrations/0007_models.sql")),
    (8, include_str!("../migrations/0008_flows.sql")),
    (
        9,
        include_str!("../migrations/0009_flow_authorizations.sql"),
    ),
    (10, include_str!("../migrations/0010_agent_artifacts.sql")),
];

type Response<T> = oneshot::Sender<Result<T, StoreError>>;

#[derive(Clone)]
pub struct Store {
    commands: tokio_mpsc::Sender<Command>,
    evidence_commands: tokio_mpsc::Sender<EvidenceCommand>,
}

/// Store-issued capability for consuming one exact approval at an effect boundary.
///
/// Only [`Store::bind_effect_approval`] can construct this value. It keeps the authenticated
/// caller, project, approval receipt, and originating store together so connector callers cannot
/// substitute a different identity or an unconditional approval implementation.
#[derive(Clone)]
pub struct EffectApprovalCapability {
    store: Store,
    caller_id: CallerId,
    project_id: ProjectId,
    approval_id: ApprovalId,
}

impl EffectApprovalCapability {
    #[must_use]
    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    /// Rechecks current policy and atomically consumes the bound exact approval receipt.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timing, corrupt policy state, or unavailable durable state.
    pub async fn consume(
        &self,
        capability: CapabilityName,
        resource: ResourceName,
    ) -> Result<AuthorizationOutcome, StoreError> {
        let now_ms = system_now_ms();
        let retain_until_ms = now_ms
            .checked_add(EFFECT_APPROVAL_AUDIT_RETENTION_MS)
            .ok_or(StoreError::InvalidAuditEvent("retention overflow"))?;
        let audit = AuthorizationAudit {
            event_id: format!("connector-effect-{}", Uuid::new_v4()),
            action: "connector.effect.authorize".to_owned(),
            redacted_detail: format!(
                "approval={} capability={} resource={}",
                self.approval_id, capability, resource
            ),
            retain_until_ms,
        };
        let (response_tx, response_rx) = oneshot::channel();
        self.store
            .send(Command::Policy(PolicyCommand::ConsumeEffectApproval {
                request: AuthorizationRequest {
                    caller_id: self.caller_id.clone(),
                    project_id: self.project_id.clone(),
                    capability,
                    resource,
                    approval_id: Some(self.approval_id.clone()),
                },
                audit,
                now_ms,
                response: response_tx,
            }))
            .await?;
        receive(response_rx).await
    }
}

impl std::fmt::Debug for EffectApprovalCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectApprovalCapability")
            .field("approval_id", &self.approval_id)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Registers a caller credential. Existing caller IDs are never replaced implicitly.
    ///
    /// Only the SHA-256 verifier is persisted; the credential is not written to `SQLite`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid credential, duplicate caller, invalid timestamp,
    /// or unavailable durable state.
    pub async fn register_caller(
        &self,
        caller_id: CallerId,
        credential: CallerCredential,
        now_ms: u64,
    ) -> Result<CallerRegistration, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Caller(CallerCommand::Register {
            caller_id,
            credential,
            now_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Authenticates one caller without disclosing whether a verifier matched.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable.
    pub async fn authenticate_caller(
        &self,
        caller_id: CallerId,
        credential: CallerCredential,
    ) -> Result<CallerAuthentication, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Caller(CallerCommand::Authenticate {
            caller_id,
            credential,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Revokes a caller immediately and idempotently.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timestamp or unavailable durable state.
    pub async fn revoke_caller(
        &self,
        caller_id: CallerId,
        now_ms: u64,
    ) -> Result<CallerRevocation, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Caller(CallerCommand::Revoke {
            caller_id,
            now_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Adds one project-scoped capability grant and advances the policy version.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate grants, unknown callers, invalid timestamps,
    /// or unavailable durable state.
    pub async fn put_grant(&self, grant: PutGrant) -> Result<ProjectPolicy, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::PutGrant {
            grant,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Revokes a grant idempotently and advances the project policy version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timestamp or unavailable durable state.
    pub async fn revoke_grant(
        &self,
        grant_id: GrantId,
        now_ms: u64,
    ) -> Result<GrantRevocation, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::RevokeGrant {
            grant_id,
            now_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Evaluates default-deny project policy and atomically consumes exact approvals.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timing, corrupt policy state, or unavailable
    /// durable state.
    pub async fn authorize(
        &self,
        request: AuthorizationRequest,
        now_ms: u64,
        approval_ttl_ms: u64,
    ) -> Result<AuthorizationOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::Authorize {
            request,
            now_ms,
            approval_ttl_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Evaluates policy and appends its audit outcome in the same transaction.
    ///
    /// Approval creation, expiry, or one-time consumption is rolled back if the
    /// audit event cannot be persisted.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timing or audit metadata, corrupt policy
    /// state, or unavailable durable state.
    pub async fn authorize_audited(
        &self,
        request: AuthorizationRequest,
        audit: AuthorizationAudit,
        now_ms: u64,
        approval_ttl_ms: u64,
    ) -> Result<AuthorizationOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::AuthorizeAudited {
            request,
            audit,
            now_ms,
            approval_ttl_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Authenticates a caller and binds one approval receipt to that caller, project, and store.
    ///
    /// The returned capability contains the authenticated identity privately. Consuming it
    /// rechecks caller activity, current policy, exact effect coordinates, expiry, and one-use in
    /// one immediate transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed credential or when durable state is unavailable. A
    /// well-formed credential that does not authenticate returns `None` without disclosing whether
    /// the caller exists or has been revoked.
    pub async fn bind_effect_approval(
        &self,
        caller_id: CallerId,
        credential: CallerCredential,
        project_id: ProjectId,
        approval_id: ApprovalId,
    ) -> Result<Option<EffectApprovalCapability>, StoreError> {
        if self
            .authenticate_caller(caller_id.clone(), credential)
            .await?
            != CallerAuthentication::Authenticated
        {
            return Ok(None);
        }
        Ok(Some(EffectApprovalCapability {
            store: self.clone(),
            caller_id,
            project_id,
            approval_id,
        }))
    }

    /// Authorizes one exact flow and accepts it in the same durable transaction.
    ///
    /// Stateful schema approval is enforced even when policy otherwise grants an
    /// unconditional allow. A consumed approval is bound to the accepted request;
    /// ordinary policy approvals remain one-use and are not reusable here.
    ///
    /// # Errors
    ///
    /// Returns an error for inconsistent flow identity, idempotency conflicts,
    /// invalid timing or audit metadata, corrupt policy state, or unavailable storage.
    pub async fn authorize_flow_run(
        &self,
        request: AuthorizeFlowRun,
        now_ms: u64,
        approval_ttl_ms: u64,
    ) -> Result<FlowAuthorizationOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::AuthorizeFlowRun {
            request,
            now_ms,
            approval_ttl_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Rechecks authorization immediately before a flow effect is prepared.
    ///
    /// The caller must still be active and current policy must permit the exact
    /// accepted flow resource. Approval-backed flows additionally require the same
    /// consumed receipt bound to this request. The receipt is validated,
    /// never consumed again.
    ///
    /// # Errors
    ///
    /// Returns an error for stale leases, corrupt durable proof or policy state,
    /// invalid timing, or unavailable storage.
    pub async fn validate_flow_effect_authorization(
        &self,
        lease: Lease,
        now_ms: u64,
    ) -> Result<FlowEffectAuthorization, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(
            PolicyCommand::ValidateFlowEffectAuthorization {
                lease,
                now_ms,
                response: response_tx,
            },
        ))
        .await?;
        receive(response_rx).await
    }

    /// Confirms that a live flow lease remains bound to the exact resource
    /// derived from its immutable operation bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale lease, corrupt durable authorization proof,
    /// or a resource that differs from the one atomically accepted.
    pub async fn validate_flow_operation_resource(
        &self,
        lease: Lease,
        resource: ResourceName,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(
            PolicyCommand::ValidateFlowOperationResource {
                lease,
                resource,
                now_ms,
                response: response_tx,
            },
        ))
        .await?;
        receive(response_rx).await
    }

    /// Applies a human approval decision to a pending exact effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the approval is missing, no longer pending, the
    /// timestamp is invalid, or durable state is unavailable.
    pub async fn decide_approval(
        &self,
        approval_id: ApprovalId,
        approver_id: CallerId,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalDecisionOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::DecideApproval {
            approval_id,
            project_id: None,
            approver_id,
            decision,
            now_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Applies a caller's approval decision only when the approval belongs to that caller and
    /// project.
    ///
    /// This is the remote-control-safe decision boundary: authenticate the caller first, then pass
    /// that exact caller ID and the request-envelope project ID here. The approval-requester match,
    /// project match, and active-caller check are performed atomically with the decision.
    ///
    /// # Errors
    ///
    /// Returns an error when the approval is absent from the project, no longer pending, the
    /// caller did not request the approval or is not active, the timestamp is invalid, or durable
    /// state is unavailable.
    pub async fn decide_project_approval(
        &self,
        approval_id: ApprovalId,
        project_id: ProjectId,
        caller_id: CallerId,
        decision: ApprovalDecision,
        now_ms: u64,
    ) -> Result<ApprovalDecisionOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Policy(PolicyCommand::DecideApproval {
            approval_id,
            project_id: Some(project_id),
            approver_id: caller_id,
            decision,
            now_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Appends one event to the durable audit ledger.
    ///
    /// Callers should redact secrets as close to collection as possible. The
    /// store reapplies bounded audit-detail redaction before validation,
    /// idempotency comparison, and persistence as a final safety boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or oversized fields, a duplicate stable event
    /// ID, invalid timestamps, or unavailable durable state.
    pub async fn append_audit_event(
        &self,
        event: AppendAuditEvent,
    ) -> Result<AuditEventRecord, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Audit(AuditCommand::Append {
            event,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Exports one bounded project-scoped page after an exclusive global cursor.
    ///
    /// Records are returned in ascending global sequence order through a versioned
    /// typed seam suitable for deterministic serialization by protocol adapters.
    /// Pass `None` on the first page to capture a stable high-water sequence, then
    /// pass the returned `through_sequence` on every subsequent page.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid project ID, cursor, batch limit, corrupt
    /// stored state, or unavailable durable state.
    pub async fn export_audit_events(
        &self,
        project_id: ProjectId,
        after_sequence: u64,
        through_sequence: Option<u64>,
        limit: u32,
    ) -> Result<AuditExport, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Audit(AuditCommand::Export {
            project_id,
            after_sequence,
            through_sequence,
            limit,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Prunes at most `limit` retained events for one project.
    ///
    /// Events whose retention timestamp is equal to `now_ms` are eligible. Calls
    /// are deterministic, bounded, project-scoped, and idempotent once no eligible
    /// records remain.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid project ID, timestamp, batch limit, or
    /// unavailable durable state.
    pub async fn prune_audit_events(
        &self,
        project_id: ProjectId,
        now_ms: u64,
        limit: u32,
    ) -> Result<AuditPruneOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Audit(AuditCommand::Prune {
            project_id,
            now_ms,
            limit,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Opens a file-backed store and starts isolated scheduler and evidence workers.
    ///
    /// # Errors
    ///
    /// Returns a store error when the directory, database, configuration, or
    /// embedded migrations cannot be prepared. Existing corrupt or future-version
    /// databases are left in place.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let (command_tx, command_rx) = tokio_mpsc::channel(COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let scheduler_path = path.clone();

        thread::Builder::new()
            .name("pam-sqlite-scheduler".to_owned())
            .spawn(move || match open_connection(&scheduler_path) {
                Ok(connection) => {
                    let _ = ready_tx.send(Ok(()));
                    run_worker(connection, command_rx);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            })?;

        ready_rx.recv().map_err(|_| StoreError::WorkerStopped)??;
        let (evidence_tx, evidence_rx) = tokio_mpsc::channel(EVIDENCE_COMMAND_CAPACITY);
        let (evidence_ready_tx, evidence_ready_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("pam-evidence".to_owned())
            .spawn(move || match open_evidence_worker(&path) {
                Ok((connection, files)) => {
                    let _ = evidence_ready_tx.send(Ok(()));
                    run_evidence_worker(connection, files, evidence_rx);
                }
                Err(error) => {
                    let _ = evidence_ready_tx.send(Err(error));
                }
            })?;
        evidence_ready_rx
            .recv()
            .map_err(|_| StoreError::WorkerStopped)??;
        Ok(Self {
            commands: command_tx,
            evidence_commands: evidence_tx,
        })
    }

    /// Registers verified model metadata without copying weight bytes into PAM state.
    ///
    /// An identical record is idempotent. The same model identity or path is never
    /// replaced implicitly with different metadata.
    ///
    /// # Errors
    ///
    /// Returns an error for conflicting, invalid, out-of-range, or unavailable
    /// durable state.
    pub async fn put_model(&self, model: RegisteredModel) -> Result<RegisteredModel, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Model(ModelCommand::Put {
            model,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Looks up one model's metadata by stable vendor/name identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is absent, corrupt, or durable state is
    /// unavailable.
    pub async fn model(&self, key: ModelKey) -> Result<RegisteredModel, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Model(ModelCommand::Get {
            key,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Atomically replaces one project's active skill inventory with a complete scan.
    ///
    /// The store rejects incomplete reports before they reach the durable worker, so
    /// partial filesystem failures can never remove previously known artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error for an incomplete report, invalid timestamp, corrupt prior
    /// state, timestamp regression, or unavailable durable state.
    pub async fn rescan_skill_inventory(
        &self,
        project_id: ProjectId,
        report: ScanReport,
        observed_at_ms: u64,
    ) -> Result<SkillInventoryDrift, StoreError> {
        if !report.complete() {
            return Err(StoreError::IncompleteSkillInventory(
                report.diagnostics().to_vec(),
            ));
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Inventory(InventoryCommand::Rescan {
            project_id,
            artifacts: report.into_artifacts(),
            observed_at_ms,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Lists the active skill inventory for one project in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns an error for corrupt or unavailable durable state.
    pub async fn skill_artifacts(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<StoredAgentArtifact>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Inventory(InventoryCommand::List {
            project_id,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Returns one active skill artifact by its exact stable identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is absent, removed, corrupt, or durable
    /// state is unavailable.
    pub async fn skill_artifact(
        &self,
        project_id: ProjectId,
        artifact_id: AgentArtifactId,
    ) -> Result<StoredAgentArtifact, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Inventory(InventoryCommand::Get {
            project_id,
            artifact_id,
            response: response_tx,
        }))
        .await?;
        receive(response_rx).await
    }

    /// Durably accepts an operation or returns its canonical idempotent request.
    ///
    /// # Errors
    ///
    /// Returns an idempotency conflict when the scoped key was used for different
    /// operation bytes, or a store error when persistence fails.
    pub async fn accept(
        &self,
        request: AcceptRequest,
        now_ms: u64,
    ) -> Result<AcceptOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Accept {
            request,
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Claims the oldest eligible request while preserving per-project FIFO.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::CorruptFlowAuthorization`] without leasing or
    /// appending `started` when the FIFO head is a flow with invalid durable
    /// authorization. Call [`Self::fail_corrupt_flow_authorization`] with an
    /// encoded failure result to quarantine that exact head and continue.
    /// Returns another store error for invalid lease time or database failure.
    pub async fn claim(
        &self,
        owner: impl Into<String>,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Option<LeasedRequest>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Claim {
            owner: owner.into(),
            now_ms,
            lease_duration_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Renews a live lease and returns its updated fencing value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when the lease no longer owns the request.
    pub async fn renew(
        &self,
        lease: Lease,
        now_ms: u64,
        lease_duration_ms: u64,
    ) -> Result<Lease, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Renew {
            lease,
            now_ms,
            lease_duration_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Recovers expired leases without releasing cancellation-requested work early.
    ///
    /// Ordinary leases return to their original FIFO positions. A validated terminal
    /// flow cache is finalized instead of requeued. Cancellation-requested leases become
    /// terminally cancelled unless their validated cache records reconciliation-unknown;
    /// that narrow stateful-effect case becomes failed with its exact blocked result.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_expired(&self, now_ms: u64) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverExpired {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Recovers expired leases and returns every transitioned request in order.
    ///
    /// Ordinary leases are returned after being requeued, terminal flow caches after
    /// being finalized, and cancellation-requested leases after becoming terminally
    /// cancelled or, for reconciliation-unknown, failed with the cached blocked result.
    /// Repeating the call returns an empty vector and creates no duplicate events.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_expired_requests(
        &self,
        now_ms: u64,
    ) -> Result<Vec<RequestId>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverExpiredRequests {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Resolves every active lease at daemon startup.
    ///
    /// This operation is intended to run only after the daemon has acquired
    /// exclusive process ownership. Ordinary leases return to their original FIFO
    /// positions and validated terminal flow caches are finalized. Cancellation-requested
    /// leases become terminally cancelled except for cached reconciliation-unknown, which
    /// becomes failed with its exact blocked result. Repeating it is safe and adds no
    /// duplicate recovery events.
    ///
    /// # Errors
    ///
    /// Returns a store error when recovery cannot be committed atomically.
    pub async fn recover_all_leases(&self, now_ms: u64) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::RecoverAllLeases {
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Appends a durable event while the supplied lease remains live.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when the lease is expired or fenced out.
    pub async fn append_event(
        &self,
        lease: Lease,
        now_ms: u64,
        kind: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<EventRecord, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::AppendEvent {
            lease,
            now_ms,
            kind: kind.into(),
            payload,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Loads a flow checkpoint only while the supplied scheduler lease is live.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] for an expired or fenced lease and
    /// [`StoreError::CorruptFlowCheckpoint`] for invalid durable bytes.
    pub async fn load_flow_checkpoint(
        &self,
        lease: Lease,
        now_ms: u64,
    ) -> Result<Option<FlowCheckpoint>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::LoadFlowCheckpoint {
            lease,
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Saves a typed flow checkpoint with optimistic revision control.
    ///
    /// A new semantic transition, its snapshot, and any exact encoded terminal
    /// result are committed atomically.
    /// Replaying the exact same write is idempotent and does not append another event.
    ///
    /// # Errors
    ///
    /// Returns an error for stale leases, revision or identity conflicts, terminal
    /// outcomes that disagree with request cancellation order, invalid transition
    /// sequencing, oversized payloads, or corrupt durable state.
    pub async fn save_flow_checkpoint(
        &self,
        checkpoint: SaveFlowCheckpoint,
    ) -> Result<FlowCheckpointSaveOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::SaveFlowCheckpoint {
            checkpoint,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Commits a worker acknowledgement and its terminal event together.
    ///
    /// A cancellation request always becomes cancelled with its previously persisted
    /// result; the supplied success or failure cannot override it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] when another terminal transition or
    /// lease recovery won the race.
    pub async fn finish(
        &self,
        lease: Lease,
        now_ms: u64,
        terminal_state: TerminalState,
        result: Vec<u8>,
    ) -> Result<StoredResult, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Finish {
            lease,
            now_ms,
            terminal_state,
            result,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Finishes a flow with the truthful result cached by its terminal checkpoint.
    ///
    /// Unlike [`Self::finish`], this flow-only acknowledgement derives the
    /// request state from the validated terminal checkpoint and requires the
    /// supplied bytes to exactly match its cached result. A cancellation request
    /// may normally finish only as cancelled. The sole exception is a blocked
    /// checkpoint reached through reconciliation-unknown, which preserves the
    /// truthful possibility that a stateful effect was applied. The request
    /// result and its single terminal event commit atomically under the live lease.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::StaleLease`] for an expired, fenced, or already
    /// terminal lease. Returns [`StoreError::InvalidState`] unless the live
    /// request is a flow with a matching terminal checkpoint whose outcome is
    /// permitted by the durable request state.
    pub async fn finish_terminal_flow(
        &self,
        lease: Lease,
        now_ms: u64,
        terminal_result: Vec<u8>,
    ) -> Result<StoredResult, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::FinishTerminalFlow {
            lease,
            now_ms,
            terminal_result,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Fails one queued flow whose durable authorization proof is corrupt or absent.
    ///
    /// This is the recovery half of [`Self::claim`] returning
    /// [`StoreError::CorruptFlowAuthorization`]. The corruption is revalidated in
    /// the same transaction as the failed result and event, so this method cannot
    /// be used to fail a valid queued flow.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is absent, is not a queued flow, its
    /// authorization is now valid, timing is invalid, or storage is unavailable.
    pub async fn fail_corrupt_flow_authorization(
        &self,
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
    ) -> Result<FlowAuthorizationRecoveryOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::FailCorruptFlowAuthorization {
            request_id,
            now_ms,
            result,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Cancels queued work or durably requests cancellation of leased work.
    ///
    /// A leased request retains its fencing token and project gate until `finish` or
    /// lease recovery acknowledges the cancellation. If a flow already has a
    /// validated terminal checkpoint, that cached terminal truth wins the race
    /// and is finalized atomically instead of recording a cancellation request.
    ///
    /// # Errors
    ///
    /// Returns a store error if the request is absent or the transition fails.
    pub async fn cancel(
        &self,
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
    ) -> Result<CancelOutcome, StoreError> {
        self.cancel_internal(request_id, now_ms, result, None).await
    }

    /// Cancels work only when its immutable operation kind matches `expected_target_kind`.
    ///
    /// A mismatch is deliberately reported as [`StoreError::RequestNotFound`] and does not
    /// mutate the target, preventing callers from using this API to probe unrelated work.
    ///
    /// # Errors
    ///
    /// Returns a store error if the request is absent, has a different operation kind, or the
    /// transition fails.
    pub async fn cancel_with_expected_target(
        &self,
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
        expected_target_kind: ExpectedOperationKind,
    ) -> Result<CancelOutcome, StoreError> {
        self.cancel_internal(request_id, now_ms, result, Some(expected_target_kind))
            .await
    }

    async fn cancel_internal(
        &self,
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
        expected_target_kind: Option<ExpectedOperationKind>,
    ) -> Result<CancelOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Cancel {
            request_id,
            now_ms,
            result,
            expected_target_kind,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Replays events strictly after `after_sequence` and includes a terminal result.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or stored data is invalid.
    pub async fn replay(
        &self,
        request_id: RequestId,
        after_sequence: u64,
    ) -> Result<Replay, StoreError> {
        self.replay_internal(request_id, after_sequence, None).await
    }

    /// Replays a request only when its immutable operation kind matches the expectation.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent, has a different operation kind, or
    /// stored data is invalid.
    pub async fn replay_with_expected_target(
        &self,
        request_id: RequestId,
        after_sequence: u64,
        expected_target_kind: ExpectedOperationKind,
    ) -> Result<Replay, StoreError> {
        self.replay_internal(request_id, after_sequence, Some(expected_target_kind))
            .await
    }

    async fn replay_internal(
        &self,
        request_id: RequestId,
        after_sequence: u64,
        expected_target_kind: Option<ExpectedOperationKind>,
    ) -> Result<Replay, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Replay {
            request_id,
            after_sequence,
            expected_target_kind,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Loads scheduler metadata for one request.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or stored data is invalid.
    pub async fn snapshot(&self, request_id: RequestId) -> Result<RequestSnapshot, StoreError> {
        self.snapshot_internal(request_id, None).await
    }

    /// Loads scheduler metadata only when the immutable operation kind matches the expectation.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent, has a different operation kind, or
    /// stored data is invalid.
    pub async fn snapshot_with_expected_target(
        &self,
        request_id: RequestId,
        expected_target_kind: ExpectedOperationKind,
    ) -> Result<RequestSnapshot, StoreError> {
        self.snapshot_internal(request_id, Some(expected_target_kind))
            .await
    }

    async fn snapshot_internal(
        &self,
        request_id: RequestId,
        expected_target_kind: Option<ExpectedOperationKind>,
    ) -> Result<RequestSnapshot, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::Snapshot {
            request_id,
            expected_target_kind,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Counts later, nonterminal queued requests for the same project.
    ///
    /// # Errors
    ///
    /// Returns a store error when the request is absent or the count cannot be read.
    pub async fn queued_behind(&self, request_id: RequestId) -> Result<u64, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::QueuedBehind {
            request_id,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Loads the current non-status scheduler workload for one project.
    ///
    /// Queued status requests are excluded from the count. A leased or
    /// cancellation-requested non-status request remains active until its worker
    /// acknowledges a terminal result.
    ///
    /// # Errors
    ///
    /// Returns a store error when the transactionally consistent aggregate cannot
    /// be read from durable state.
    pub async fn project_workload(
        &self,
        project_id: ProjectId,
    ) -> Result<ProjectWorkload, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::ProjectWorkload {
            project_id,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Loads a bounded, transactionally consistent current-work view for one project.
    ///
    /// Status requests are excluded. Queued work is FIFO and capped at
    /// [`MAX_PROJECT_CURRENT_QUEUED`]; callers can inspect `queued_truncated` to decide whether to
    /// offer a more targeted follow-up. The view never includes operation payloads, credentials,
    /// approval receipts, results, or evidence content.
    ///
    /// # Errors
    ///
    /// Returns a store error when durable state is invalid or unavailable.
    pub async fn project_current(
        &self,
        project_id: ProjectId,
    ) -> Result<ProjectCurrent, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send(Command::ProjectCurrent {
            project_id,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Stores exact evidence bytes behind an immutable semantic handle.
    ///
    /// Exact content is globally deduplicated by SHA-256 while handle lookup remains
    /// project-scoped. Repeating an identical put is idempotent; reusing a handle for
    /// different bytes or metadata is rejected.
    ///
    /// # Errors
    ///
    /// Returns a store error for invalid or oversized metadata/content, an existing
    /// conflicting handle, an unsafe evidence path, or a persistence failure.
    pub async fn put_evidence(
        &self,
        evidence: PutEvidence,
        now_ms: u64,
    ) -> Result<EvidenceMetadata, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::Put {
            evidence,
            now_ms,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Deletes one bounded page of non-persistent evidence for a project.
    ///
    /// The retention class and inclusive creation-time cutoff are explicit.
    /// Persistent evidence is never eligible through this API. Cleanup after
    /// committed handle deletion is best-effort: exact committed counts,
    /// known pending items, and unresolved cleanup state are returned together.
    ///
    /// # Errors
    ///
    /// Returns an error for persistent retention, an invalid cutoff or limit, or
    /// unavailable durable state before logical deletion commits.
    pub async fn prune_evidence(
        &self,
        project_id: ProjectId,
        retention: EvidenceRetention,
        created_before_unix_ms: u64,
        limit: u32,
    ) -> Result<EvidencePruneOutcome, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::Prune {
            project_id,
            retention,
            created_before_unix_ms,
            limit,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Inspects a project-scoped evidence handle and verifies its exact blob.
    ///
    /// # Errors
    ///
    /// Returns a store error when the handle is absent from the project or its blob
    /// is missing, corrupt, unsafe, or unreadable.
    pub async fn inspect_evidence(
        &self,
        project_id: ProjectId,
        handle: EvidenceHandle,
    ) -> Result<EvidenceMetadata, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::Inspect {
            project_id,
            handle,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Reads at most the requested bounded range from verified exact evidence.
    ///
    /// A range ending beyond the content is truncated at EOF. An offset beyond EOF
    /// or a range above [`crate::MAX_EVIDENCE_RANGE_BYTES`] is rejected.
    ///
    /// # Errors
    ///
    /// Returns a store error when the handle is absent from the project, the range
    /// is invalid, or the exact blob fails verification.
    pub async fn read_evidence_range(
        &self,
        project_id: ProjectId,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.send_evidence(EvidenceCommand::ReadRange {
            project_id,
            handle,
            offset,
            length,
            response: response_tx,
        })
        .await?;
        receive(response_rx).await
    }

    /// Stops both workers after all previously accepted commands have completed.
    ///
    /// # Errors
    ///
    /// Returns a store error when the worker has already stopped.
    pub async fn shutdown(self) -> Result<(), StoreError> {
        let (scheduler_tx, scheduler_rx) = oneshot::channel();
        let scheduler_result = match self.send(Command::Shutdown(scheduler_tx)).await {
            Ok(()) => receive(scheduler_rx).await,
            Err(error) => Err(error),
        };
        let (evidence_tx, evidence_rx) = oneshot::channel();
        let evidence_result = match self
            .send_evidence(EvidenceCommand::Shutdown(evidence_tx))
            .await
        {
            Ok(()) => receive(evidence_rx).await,
            Err(error) => Err(error),
        };
        scheduler_result?;
        evidence_result
    }

    async fn send(&self, command: Command) -> Result<(), StoreError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| StoreError::WorkerStopped)
    }

    async fn send_evidence(&self, command: EvidenceCommand) -> Result<(), StoreError> {
        self.evidence_commands
            .send(command)
            .await
            .map_err(|_| StoreError::WorkerStopped)
    }

    #[cfg(test)]
    pub(super) async fn hold_evidence_worker(
        &self,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Result<(), StoreError> {
        self.send_evidence(EvidenceCommand::Hold { entered, release })
            .await
    }
}

async fn receive<T>(response: oneshot::Receiver<Result<T, StoreError>>) -> Result<T, StoreError> {
    response.await.map_err(|_| StoreError::WorkerStopped)?
}

enum Command {
    Caller(CallerCommand),
    Policy(PolicyCommand),
    Audit(AuditCommand),
    Model(ModelCommand),
    Inventory(InventoryCommand),
    Accept {
        request: AcceptRequest,
        now_ms: u64,
        response: Response<AcceptOutcome>,
    },
    Claim {
        owner: String,
        now_ms: u64,
        lease_duration_ms: u64,
        response: Response<Option<LeasedRequest>>,
    },
    Renew {
        lease: Lease,
        now_ms: u64,
        lease_duration_ms: u64,
        response: Response<Lease>,
    },
    RecoverExpired {
        now_ms: u64,
        response: Response<u64>,
    },
    RecoverExpiredRequests {
        now_ms: u64,
        response: Response<Vec<RequestId>>,
    },
    RecoverAllLeases {
        now_ms: u64,
        response: Response<u64>,
    },
    AppendEvent {
        lease: Lease,
        now_ms: u64,
        kind: String,
        payload: Vec<u8>,
        response: Response<EventRecord>,
    },
    LoadFlowCheckpoint {
        lease: Lease,
        now_ms: u64,
        response: Response<Option<FlowCheckpoint>>,
    },
    SaveFlowCheckpoint {
        checkpoint: SaveFlowCheckpoint,
        response: Response<FlowCheckpointSaveOutcome>,
    },
    Finish {
        lease: Lease,
        now_ms: u64,
        terminal_state: TerminalState,
        result: Vec<u8>,
        response: Response<StoredResult>,
    },
    FinishTerminalFlow {
        lease: Lease,
        now_ms: u64,
        terminal_result: Vec<u8>,
        response: Response<StoredResult>,
    },
    FailCorruptFlowAuthorization {
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
        response: Response<FlowAuthorizationRecoveryOutcome>,
    },
    Cancel {
        request_id: RequestId,
        now_ms: u64,
        result: Vec<u8>,
        expected_target_kind: Option<ExpectedOperationKind>,
        response: Response<CancelOutcome>,
    },
    Replay {
        request_id: RequestId,
        after_sequence: u64,
        expected_target_kind: Option<ExpectedOperationKind>,
        response: Response<Replay>,
    },
    Snapshot {
        request_id: RequestId,
        expected_target_kind: Option<ExpectedOperationKind>,
        response: Response<RequestSnapshot>,
    },
    QueuedBehind {
        request_id: RequestId,
        response: Response<u64>,
    },
    ProjectWorkload {
        project_id: ProjectId,
        response: Response<ProjectWorkload>,
    },
    ProjectCurrent {
        project_id: ProjectId,
        response: Response<ProjectCurrent>,
    },
    Shutdown(Response<()>),
}

enum ModelCommand {
    Put {
        model: RegisteredModel,
        response: Response<RegisteredModel>,
    },
    Get {
        key: ModelKey,
        response: Response<RegisteredModel>,
    },
}

enum InventoryCommand {
    Rescan {
        project_id: ProjectId,
        artifacts: Vec<AgentArtifact>,
        observed_at_ms: u64,
        response: Response<SkillInventoryDrift>,
    },
    List {
        project_id: ProjectId,
        response: Response<Vec<StoredAgentArtifact>>,
    },
    Get {
        project_id: ProjectId,
        artifact_id: AgentArtifactId,
        response: Response<StoredAgentArtifact>,
    },
}

enum CallerCommand {
    Register {
        caller_id: CallerId,
        credential: CallerCredential,
        now_ms: u64,
        response: Response<CallerRegistration>,
    },
    Authenticate {
        caller_id: CallerId,
        credential: CallerCredential,
        response: Response<CallerAuthentication>,
    },
    Revoke {
        caller_id: CallerId,
        now_ms: u64,
        response: Response<CallerRevocation>,
    },
}

enum PolicyCommand {
    PutGrant {
        grant: PutGrant,
        response: Response<ProjectPolicy>,
    },
    RevokeGrant {
        grant_id: GrantId,
        now_ms: u64,
        response: Response<GrantRevocation>,
    },
    Authorize {
        request: AuthorizationRequest,
        now_ms: u64,
        approval_ttl_ms: u64,
        response: Response<AuthorizationOutcome>,
    },
    AuthorizeAudited {
        request: AuthorizationRequest,
        audit: AuthorizationAudit,
        now_ms: u64,
        approval_ttl_ms: u64,
        response: Response<AuthorizationOutcome>,
    },
    ConsumeEffectApproval {
        request: AuthorizationRequest,
        audit: AuthorizationAudit,
        now_ms: u64,
        response: Response<AuthorizationOutcome>,
    },
    AuthorizeFlowRun {
        request: AuthorizeFlowRun,
        now_ms: u64,
        approval_ttl_ms: u64,
        response: Response<FlowAuthorizationOutcome>,
    },
    ValidateFlowEffectAuthorization {
        lease: Lease,
        now_ms: u64,
        response: Response<FlowEffectAuthorization>,
    },
    ValidateFlowOperationResource {
        lease: Lease,
        resource: ResourceName,
        now_ms: u64,
        response: Response<()>,
    },
    DecideApproval {
        approval_id: ApprovalId,
        project_id: Option<ProjectId>,
        approver_id: CallerId,
        decision: ApprovalDecision,
        now_ms: u64,
        response: Response<ApprovalDecisionOutcome>,
    },
}

enum AuditCommand {
    Append {
        event: AppendAuditEvent,
        response: Response<AuditEventRecord>,
    },
    Export {
        project_id: ProjectId,
        after_sequence: u64,
        through_sequence: Option<u64>,
        limit: u32,
        response: Response<AuditExport>,
    },
    Prune {
        project_id: ProjectId,
        now_ms: u64,
        limit: u32,
        response: Response<AuditPruneOutcome>,
    },
}

enum EvidenceCommand {
    Put {
        evidence: PutEvidence,
        now_ms: u64,
        response: Response<EvidenceMetadata>,
    },
    Inspect {
        project_id: ProjectId,
        handle: EvidenceHandle,
        response: Response<EvidenceMetadata>,
    },
    ReadRange {
        project_id: ProjectId,
        handle: EvidenceHandle,
        offset: u64,
        length: u64,
        response: Response<Vec<u8>>,
    },
    Prune {
        project_id: ProjectId,
        retention: EvidenceRetention,
        created_before_unix_ms: u64,
        limit: u32,
        response: Response<EvidencePruneOutcome>,
    },
    #[cfg(test)]
    Hold {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    },
    Shutdown(Response<()>),
}

#[allow(clippy::too_many_lines)] // Keep the exhaustive command dispatcher in one auditable match.
fn run_worker(mut connection: Connection, mut commands: tokio_mpsc::Receiver<Command>) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            Command::Caller(command) => run_caller_command(&mut connection, command),
            Command::Policy(command) => run_policy_command(&mut connection, command),
            Command::Audit(command) => run_audit_command(&mut connection, command),
            Command::Model(command) => run_model_command(&mut connection, command),
            Command::Inventory(command) => run_inventory_command(&mut connection, command),
            Command::Accept {
                request,
                now_ms,
                response,
            } => respond(response, accept(&mut connection, request, now_ms)),
            Command::Claim {
                owner,
                now_ms,
                lease_duration_ms,
                response,
            } => respond(
                response,
                claim(&mut connection, owner, now_ms, lease_duration_ms),
            ),
            Command::Renew {
                lease,
                now_ms,
                lease_duration_ms,
                response,
            } => respond(
                response,
                renew(&mut connection, lease, now_ms, lease_duration_ms),
            ),
            Command::RecoverExpired { now_ms, response } => {
                respond(response, recover_expired(&mut connection, now_ms));
            }
            Command::RecoverExpiredRequests { now_ms, response } => {
                respond(response, recover_expired_requests(&mut connection, now_ms));
            }
            Command::RecoverAllLeases { now_ms, response } => {
                respond(response, recover_all_leases(&mut connection, now_ms));
            }
            Command::AppendEvent {
                lease,
                now_ms,
                kind,
                payload,
                response,
            } => respond(
                response,
                append_leased_event(&mut connection, &lease, now_ms, &kind, &payload),
            ),
            Command::LoadFlowCheckpoint {
                lease,
                now_ms,
                response,
            } => respond(
                response,
                load_flow_checkpoint(&mut connection, &lease, now_ms),
            ),
            Command::SaveFlowCheckpoint {
                checkpoint,
                response,
            } => respond(response, save_flow_checkpoint(&mut connection, checkpoint)),
            Command::Finish {
                lease,
                now_ms,
                terminal_state,
                result,
                response,
            } => respond(
                response,
                finish(&mut connection, &lease, now_ms, terminal_state, &result),
            ),
            Command::FinishTerminalFlow {
                lease,
                now_ms,
                terminal_result,
                response,
            } => respond(
                response,
                finish_terminal_flow(&mut connection, &lease, now_ms, &terminal_result),
            ),
            Command::FailCorruptFlowAuthorization {
                request_id,
                now_ms,
                result,
                response,
            } => respond(
                response,
                fail_corrupt_flow_authorization(&mut connection, &request_id, now_ms, &result),
            ),
            Command::Cancel {
                request_id,
                now_ms,
                result,
                expected_target_kind,
                response,
            } => respond(
                response,
                cancel(
                    &mut connection,
                    &request_id,
                    now_ms,
                    &result,
                    expected_target_kind,
                ),
            ),
            Command::Replay {
                request_id,
                after_sequence,
                expected_target_kind,
                response,
            } => respond(
                response,
                replay(
                    &connection,
                    &request_id,
                    after_sequence,
                    expected_target_kind,
                ),
            ),
            Command::Snapshot {
                request_id,
                expected_target_kind,
                response,
            } => respond(
                response,
                snapshot(&connection, &request_id, expected_target_kind),
            ),
            Command::QueuedBehind {
                request_id,
                response,
            } => respond(response, queued_behind(&mut connection, &request_id)),
            Command::ProjectWorkload {
                project_id,
                response,
            } => respond(response, project_workload(&connection, &project_id)),
            Command::ProjectCurrent {
                project_id,
                response,
            } => respond(response, project_current(&mut connection, &project_id)),
            Command::Shutdown(response) => {
                drop(connection);
                respond(response, Ok(()));
                return;
            }
        }
    }
}

fn run_caller_command(connection: &mut Connection, command: CallerCommand) {
    match command {
        CallerCommand::Register {
            caller_id,
            credential,
            now_ms,
            response,
        } => respond(
            response,
            register_caller(connection, caller_id, &credential, now_ms),
        ),
        CallerCommand::Authenticate {
            caller_id,
            credential,
            response,
        } => respond(
            response,
            authenticate_caller(connection, &caller_id, &credential),
        ),
        CallerCommand::Revoke {
            caller_id,
            now_ms,
            response,
        } => respond(response, revoke_caller(connection, &caller_id, now_ms)),
    }
}

fn run_policy_command(connection: &mut Connection, command: PolicyCommand) {
    match command {
        PolicyCommand::PutGrant { grant, response } => {
            respond(response, put_grant(connection, grant));
        }
        PolicyCommand::RevokeGrant {
            grant_id,
            now_ms,
            response,
        } => respond(response, revoke_grant(connection, &grant_id, now_ms)),
        PolicyCommand::Authorize {
            request,
            now_ms,
            approval_ttl_ms,
            response,
        } => respond(
            response,
            authorize(connection, &request, now_ms, approval_ttl_ms),
        ),
        PolicyCommand::AuthorizeAudited {
            request,
            audit,
            now_ms,
            approval_ttl_ms,
            response,
        } => respond(
            response,
            authorize_audited(connection, &request, audit, now_ms, approval_ttl_ms),
        ),
        PolicyCommand::ConsumeEffectApproval {
            request,
            audit,
            now_ms,
            response,
        } => respond(
            response,
            consume_effect_approval_audited(connection, &request, audit, now_ms),
        ),
        PolicyCommand::AuthorizeFlowRun {
            request,
            now_ms,
            approval_ttl_ms,
            response,
        } => respond(
            response,
            authorize_flow_run(connection, request, now_ms, approval_ttl_ms),
        ),
        PolicyCommand::ValidateFlowEffectAuthorization {
            lease,
            now_ms,
            response,
        } => respond(
            response,
            validate_flow_effect_authorization(connection, &lease, now_ms),
        ),
        PolicyCommand::ValidateFlowOperationResource {
            lease,
            resource,
            now_ms,
            response,
        } => respond(
            response,
            validate_flow_operation_resource(connection, &lease, &resource, now_ms),
        ),
        PolicyCommand::DecideApproval {
            approval_id,
            project_id,
            approver_id,
            decision,
            now_ms,
            response,
        } => respond(
            response,
            decide_approval(
                connection,
                &approval_id,
                project_id.as_ref(),
                &approver_id,
                decision,
                now_ms,
            ),
        ),
    }
}

fn run_audit_command(connection: &mut Connection, command: AuditCommand) {
    match command {
        AuditCommand::Append { event, response } => {
            respond(response, append_audit_event(connection, event));
        }
        AuditCommand::Export {
            project_id,
            after_sequence,
            through_sequence,
            limit,
            response,
        } => respond(
            response,
            export_audit_events(
                connection,
                &project_id,
                after_sequence,
                through_sequence,
                limit,
            ),
        ),
        AuditCommand::Prune {
            project_id,
            now_ms,
            limit,
            response,
        } => respond(
            response,
            prune_audit_events(connection, &project_id, now_ms, limit),
        ),
    }
}

fn run_model_command(connection: &mut Connection, command: ModelCommand) {
    match command {
        ModelCommand::Put { model, response } => {
            respond(response, put_model(connection, model));
        }
        ModelCommand::Get { key, response } => {
            respond(response, get_model(connection, &key));
        }
    }
}

fn put_model(
    connection: &mut Connection,
    model: RegisteredModel,
) -> Result<RegisteredModel, StoreError> {
    validate_model_record(&model)?;
    let path = model
        .path
        .to_str()
        .ok_or(StoreError::InvalidModelRecord("path must be Unicode"))?;
    let model_id = model.key.id();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing = transaction
        .query_row(
            "SELECT
                 vendor, name, path, digest, size_bytes, gguf_version,
                 gguf_tensor_count, gguf_metadata_kv_count,
                 license_id, license_url, license_digest,
                 source_kind, source_identity, registered_at_ms
             FROM models WHERE model_id = ?1 OR path = ?2",
            params![model_id, path],
            model_row,
        )
        .optional()?
        .map(decode_model)
        .transpose()?;
    if let Some(existing) = existing {
        if existing == model {
            return Ok(existing);
        }
        return Err(StoreError::ModelConflict(model.key.id()));
    }
    let (source_kind, source_identity) = model_source_columns(&model.source)?;
    transaction.execute(
        "INSERT INTO models(
             model_id, vendor, name, path, digest, size_bytes, gguf_version,
             gguf_tensor_count, gguf_metadata_kv_count,
             license_id, license_url, license_digest,
             source_kind, source_identity, registered_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            model.key.id(),
            model.key.vendor(),
            model.key.name(),
            path,
            model.digest.as_str(),
            sql_integer(model.size_bytes)?,
            model.gguf.version,
            sql_integer(model.gguf.tensor_count)?,
            sql_integer(model.gguf.metadata_kv_count)?,
            model.license.identifier(),
            model.license.notice_url(),
            model.license.notice_digest().as_str(),
            source_kind,
            source_identity,
            sql_integer(model.registered_at_ms)?,
        ],
    )?;
    transaction.commit()?;
    Ok(model)
}

fn get_model(connection: &Connection, key: &ModelKey) -> Result<RegisteredModel, StoreError> {
    connection
        .query_row(
            "SELECT
                 vendor, name, path, digest, size_bytes, gguf_version,
                 gguf_tensor_count, gguf_metadata_kv_count,
                 license_id, license_url, license_digest,
                 source_kind, source_identity, registered_at_ms
             FROM models WHERE model_id = ?1",
            params![key.id()],
            model_row,
        )
        .optional()?
        .ok_or_else(|| StoreError::ModelNotFound(key.id()))
        .and_then(decode_model)
}

type StoredModelRow = (
    String,
    String,
    String,
    String,
    i64,
    u32,
    i64,
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
);

fn model_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredModelRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    ))
}

fn decode_model(row: StoredModelRow) -> Result<RegisteredModel, StoreError> {
    let (
        vendor,
        name,
        path,
        digest,
        size_bytes,
        gguf_version,
        gguf_tensor_count,
        gguf_metadata_kv_count,
        license_id,
        license_url,
        license_digest,
        source_kind,
        source_identity,
        registered_at_ms,
    ) = row;
    let key = ModelKey::new(vendor, name).map_err(|_| invalid_model_record())?;
    let digest = ContentDigest::parse(digest).map_err(|_| invalid_model_record())?;
    let license_digest =
        ContentDigest::parse(license_digest).map_err(|_| invalid_model_record())?;
    let license = LicenseSnapshot::new(license_id, license_url, license_digest)
        .map_err(|_| invalid_model_record())?;
    let source = match (source_kind.as_str(), source_identity) {
        ("local", None) => ModelSource::Local,
        ("https", Some(canonical_url)) => {
            ModelSource::https(canonical_url).map_err(|_| invalid_model_record())?
        }
        _ => return Err(invalid_model_record()),
    };
    let size_bytes = u64::try_from(size_bytes).map_err(|_| invalid_model_record())?;
    let tensor_count = u64::try_from(gguf_tensor_count).map_err(|_| invalid_model_record())?;
    let metadata_kv_count =
        u64::try_from(gguf_metadata_kv_count).map_err(|_| invalid_model_record())?;
    let registered_at_ms = u64::try_from(registered_at_ms).map_err(|_| invalid_model_record())?;
    let model = RegisteredModel {
        key,
        path: PathBuf::from(path),
        digest,
        size_bytes,
        gguf: GgufMetadata {
            version: gguf_version,
            tensor_count,
            metadata_kv_count,
        },
        license,
        source,
        registered_at_ms,
    };
    validate_model_record(&model)?;
    Ok(model)
}

fn validate_model_record(model: &RegisteredModel) -> Result<(), StoreError> {
    let path = model
        .path
        .to_str()
        .filter(|path| {
            model.path.is_absolute()
                && !path.is_empty()
                && path.len() <= 4096
                && !model
                    .path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
        })
        .ok_or_else(invalid_model_record)?;
    if path.chars().any(char::is_control)
        || !(ModelDescriptor::MIN_SIZE_BYTES..=ModelDescriptor::MAX_SIZE_BYTES)
            .contains(&model.size_bytes)
        || !matches!(model.gguf.version, 2 | 3)
        || !(GgufMetadata::MIN_TENSOR_COUNT..=GgufMetadata::MAX_TENSOR_COUNT)
            .contains(&model.gguf.tensor_count)
        || model.gguf.metadata_kv_count > GgufMetadata::MAX_METADATA_KV_COUNT
        || i64::try_from(model.registered_at_ms).is_err()
        || ModelKey::new(model.key.vendor(), model.key.name()).is_err()
        || LicenseSnapshot::new(
            model.license.identifier(),
            model.license.notice_url(),
            model.license.notice_digest().clone(),
        )
        .is_err()
    {
        return Err(invalid_model_record());
    }
    model_source_columns(&model.source)?;
    Ok(())
}

fn model_source_columns(source: &ModelSource) -> Result<(&'static str, Option<&str>), StoreError> {
    match source {
        ModelSource::Local => Ok(("local", None)),
        ModelSource::Https { canonical_url } if safe_stored_source(canonical_url) => {
            Ok(("https", Some(canonical_url)))
        }
        ModelSource::Https { .. } => Err(invalid_model_record()),
    }
}

fn safe_stored_source(source: &str) -> bool {
    ModelSource::https(source).is_ok()
}

fn invalid_model_record() -> StoreError {
    StoreError::InvalidModelRecord("model metadata failed validation")
}

fn run_inventory_command(connection: &mut Connection, command: InventoryCommand) {
    match command {
        InventoryCommand::Rescan {
            project_id,
            artifacts,
            observed_at_ms,
            response,
        } => respond(
            response,
            rescan_skill_inventory(connection, &project_id, artifacts, observed_at_ms),
        ),
        InventoryCommand::List {
            project_id,
            response,
        } => respond(response, list_skill_artifacts(connection, &project_id)),
        InventoryCommand::Get {
            project_id,
            artifact_id,
            response,
        } => respond(
            response,
            get_skill_artifact(connection, &project_id, &artifact_id),
        ),
    }
}

fn rescan_skill_inventory(
    connection: &mut Connection,
    project_id: &ProjectId,
    artifacts: Vec<AgentArtifact>,
    observed_at_ms: u64,
) -> Result<SkillInventoryDrift, StoreError> {
    let observed_at = sql_integer(observed_at_ms)?;
    let current = current_skill_artifacts(artifacts)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO projects(project_id) VALUES (?1)
         ON CONFLICT(project_id) DO NOTHING",
        [project_id.as_str()],
    )?;
    let existing = all_skill_artifacts(&transaction, project_id)?;
    let mut existing = existing
        .into_iter()
        .map(|record| (record.id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let mut drift = SkillInventoryDrift::default();

    for (id, artifact) in current {
        match existing.remove(&id) {
            None => add_skill_artifact(
                &transaction,
                project_id,
                id,
                artifact,
                observed_at,
                observed_at_ms,
                &mut drift,
            )?,
            Some(stored) => reconcile_skill_artifact(
                &transaction,
                project_id,
                artifact,
                stored,
                observed_at,
                observed_at_ms,
                &mut drift,
            )?,
        }
    }
    for stored in existing
        .into_values()
        .filter(|stored| stored.removed_at_ms.is_none())
    {
        remove_skill_artifact(
            &transaction,
            project_id,
            stored,
            observed_at,
            observed_at_ms,
            &mut drift,
        )?;
    }
    transaction.commit()?;
    sort_inventory_drift(&mut drift);
    Ok(drift)
}

fn current_skill_artifacts(
    artifacts: Vec<AgentArtifact>,
) -> Result<BTreeMap<AgentArtifactId, AgentArtifact>, StoreError> {
    let mut current = BTreeMap::new();
    for artifact in artifacts {
        let id = artifact.id();
        if current.insert(id, artifact).is_some() {
            return Err(StoreError::InvalidSkillInventory(
                "snapshot contains a duplicate artifact identity",
            ));
        }
    }
    Ok(current)
}

fn add_skill_artifact(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    id: AgentArtifactId,
    artifact: AgentArtifact,
    observed_at: i64,
    observed_at_ms: u64,
    drift: &mut SkillInventoryDrift,
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO agent_artifacts(
             project_id, artifact_id, name, logical_path, kind, scope, origin,
             load_semantics, content_hash, first_seen_at_ms, last_changed_at_ms,
             removed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL)",
        params![
            project_id.as_str(),
            id.as_str(),
            artifact.name(),
            artifact.logical_path(),
            artifact.kind().as_str(),
            artifact.scope().as_str(),
            artifact.origin().as_str(),
            artifact.load_semantics().as_str(),
            artifact.content_hash().as_str(),
            observed_at,
        ],
    )?;
    drift.added.push(StoredAgentArtifact {
        id,
        artifact,
        first_seen_at_ms: observed_at_ms,
        last_changed_at_ms: observed_at_ms,
        removed_at_ms: None,
    });
    Ok(())
}

fn reconcile_skill_artifact(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    artifact: AgentArtifact,
    mut stored: StoredAgentArtifact,
    observed_at: i64,
    observed_at_ms: u64,
    drift: &mut SkillInventoryDrift,
) -> Result<(), StoreError> {
    if let Some(removed_at_ms) = stored.removed_at_ms {
        ensure_inventory_time(&stored.id, observed_at_ms, removed_at_ms)?;
        let changed = stored.artifact != artifact;
        if changed {
            ensure_inventory_time(&stored.id, observed_at_ms, stored.last_changed_at_ms)?;
            stored.last_changed_at_ms = observed_at_ms;
        }
        update_skill_artifact(
            transaction,
            project_id,
            &stored.id,
            &artifact,
            if changed {
                observed_at
            } else {
                sql_integer(stored.last_changed_at_ms)?
            },
            None,
        )?;
        stored.artifact = artifact;
        stored.removed_at_ms = None;
        drift.resurrected.push(stored);
    } else if stored.artifact != artifact {
        ensure_inventory_time(&stored.id, observed_at_ms, stored.last_changed_at_ms)?;
        update_skill_artifact(
            transaction,
            project_id,
            &stored.id,
            &artifact,
            observed_at,
            None,
        )?;
        stored.artifact = artifact;
        stored.last_changed_at_ms = observed_at_ms;
        drift.changed.push(stored);
    }
    Ok(())
}

fn remove_skill_artifact(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    mut stored: StoredAgentArtifact,
    observed_at: i64,
    observed_at_ms: u64,
    drift: &mut SkillInventoryDrift,
) -> Result<(), StoreError> {
    ensure_inventory_time(&stored.id, observed_at_ms, stored.last_changed_at_ms)?;
    transaction.execute(
        "UPDATE agent_artifacts SET removed_at_ms = ?3
         WHERE project_id = ?1 AND artifact_id = ?2 AND removed_at_ms IS NULL",
        params![project_id.as_str(), stored.id.as_str(), observed_at],
    )?;
    stored.removed_at_ms = Some(observed_at_ms);
    drift.removed.push(stored);
    Ok(())
}

fn update_skill_artifact(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    id: &AgentArtifactId,
    artifact: &AgentArtifact,
    last_changed_at: i64,
    removed_at: Option<i64>,
) -> Result<(), StoreError> {
    transaction.execute(
        "UPDATE agent_artifacts SET
             name = ?3, load_semantics = ?4, content_hash = ?5,
             last_changed_at_ms = ?6, removed_at_ms = ?7
         WHERE project_id = ?1 AND artifact_id = ?2",
        params![
            project_id.as_str(),
            id.as_str(),
            artifact.name(),
            artifact.load_semantics().as_str(),
            artifact.content_hash().as_str(),
            last_changed_at,
            removed_at,
        ],
    )?;
    Ok(())
}

fn ensure_inventory_time(
    id: &AgentArtifactId,
    observed_at_ms: u64,
    stored_at_ms: u64,
) -> Result<(), StoreError> {
    if observed_at_ms < stored_at_ms {
        Err(StoreError::SkillInventoryTimestampRegression {
            artifact_id: id.clone(),
            observed_at_ms,
            stored_at_ms,
        })
    } else {
        Ok(())
    }
}

fn sort_inventory_drift(drift: &mut SkillInventoryDrift) {
    for records in [
        &mut drift.added,
        &mut drift.changed,
        &mut drift.removed,
        &mut drift.resurrected,
    ] {
        records.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    }
}

fn list_skill_artifacts(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<StoredAgentArtifact>, StoreError> {
    query_skill_artifacts(
        connection,
        "SELECT artifact_id, name, logical_path, kind, scope, origin,
                load_semantics, content_hash, first_seen_at_ms,
                last_changed_at_ms, removed_at_ms
         FROM agent_artifacts
         WHERE project_id = ?1 AND removed_at_ms IS NULL
         ORDER BY origin, scope, kind, logical_path",
        project_id,
    )
}

fn all_skill_artifacts(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Vec<StoredAgentArtifact>, StoreError> {
    query_skill_artifacts(
        connection,
        "SELECT artifact_id, name, logical_path, kind, scope, origin,
                load_semantics, content_hash, first_seen_at_ms,
                last_changed_at_ms, removed_at_ms
         FROM agent_artifacts
         WHERE project_id = ?1
         ORDER BY artifact_id",
        project_id,
    )
}

fn query_skill_artifacts(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
) -> Result<Vec<StoredAgentArtifact>, StoreError> {
    let mut statement = connection.prepare_cached(sql)?;
    let rows = statement.query_map([project_id.as_str()], stored_skill_artifact_row)?;
    rows.map(|row| {
        row.map_err(StoreError::from)
            .and_then(decode_skill_artifact)
    })
    .collect()
}

fn get_skill_artifact(
    connection: &Connection,
    project_id: &ProjectId,
    artifact_id: &AgentArtifactId,
) -> Result<StoredAgentArtifact, StoreError> {
    connection
        .query_row(
            "SELECT artifact_id, name, logical_path, kind, scope, origin,
                    load_semantics, content_hash, first_seen_at_ms,
                    last_changed_at_ms, removed_at_ms
             FROM agent_artifacts
             WHERE project_id = ?1 AND artifact_id = ?2 AND removed_at_ms IS NULL",
            params![project_id.as_str(), artifact_id.as_str()],
            stored_skill_artifact_row,
        )
        .optional()?
        .ok_or_else(|| StoreError::SkillArtifactNotFound {
            project_id: project_id.clone(),
            artifact_id: artifact_id.clone(),
        })
        .and_then(decode_skill_artifact)
}

type StoredSkillArtifactRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<i64>,
);

fn stored_skill_artifact_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSkillArtifactRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn decode_skill_artifact(row: StoredSkillArtifactRow) -> Result<StoredAgentArtifact, StoreError> {
    let (id, name, path, kind, scope, origin, semantics, hash, first, changed, removed) = row;
    let id = AgentArtifactId::parse(id).map_err(|_| StoreError::CorruptSkillArtifact)?;
    let kind = kind
        .parse::<ArtifactKind>()
        .map_err(|_| StoreError::CorruptSkillArtifact)?;
    let scope = scope
        .parse::<ArtifactScope>()
        .map_err(|_| StoreError::CorruptSkillArtifact)?;
    let origin = origin
        .parse::<OriginAgent>()
        .map_err(|_| StoreError::CorruptSkillArtifact)?;
    let semantics = semantics
        .parse::<LoadSemantics>()
        .map_err(|_| StoreError::CorruptSkillArtifact)?;
    let hash = ContentDigest::parse(hash).map_err(|_| StoreError::CorruptSkillArtifact)?;
    let artifact = AgentArtifact::new(name, path, kind, scope, origin, semantics, hash)
        .map_err(|_| StoreError::CorruptSkillArtifact)?;
    if artifact.id() != id {
        return Err(StoreError::CorruptSkillArtifact);
    }
    let first_seen_at_ms = inventory_integer(first)?;
    let last_changed_at_ms = inventory_integer(changed)?;
    let removed_at_ms = removed.map(inventory_integer).transpose()?;
    if last_changed_at_ms < first_seen_at_ms
        || removed_at_ms.is_some_and(|removed| removed < last_changed_at_ms)
    {
        return Err(StoreError::CorruptSkillArtifact);
    }
    Ok(StoredAgentArtifact {
        id,
        artifact,
        first_seen_at_ms,
        last_changed_at_ms,
        removed_at_ms,
    })
}

fn inventory_integer(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptSkillArtifact)
}

fn append_audit_event(
    connection: &mut Connection,
    event: AppendAuditEvent,
) -> Result<AuditEventRecord, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = append_audit_event_tx(&transaction, event)?;
    transaction.commit()?;
    Ok(record)
}

fn append_audit_event_tx(
    transaction: &Transaction<'_>,
    mut event: AppendAuditEvent,
) -> Result<AuditEventRecord, StoreError> {
    event.redacted_detail = redact_audit_detail(event.redacted_detail.as_bytes());
    validate_audit_event(&event)?;
    let occurred_at = sql_integer(event.occurred_at_ms)?;
    let retain_until = sql_integer(event.retain_until_ms)?;
    let existing = transaction
        .query_row(
            "SELECT sequence, event_id, project_id, caller_id, action, decision, outcome,
                    redacted_detail, occurred_at_ms, retain_until_ms
             FROM audit_events WHERE event_id = ?1",
            [event.event_id.as_str()],
            stored_audit_event,
        )
        .optional()?;
    if let Some(existing) = existing {
        let existing = existing.into_record()?;
        if audit_event_matches(&existing, &event) {
            return Ok(existing);
        }
        return Err(StoreError::AuditEventAlreadyExists);
    }
    transaction.execute(
        "INSERT INTO audit_events(
            event_id, project_id, caller_id, action, decision, outcome,
            redacted_detail, occurred_at_ms, retain_until_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            event.event_id,
            event.project_id.as_str(),
            event.caller_id.as_str(),
            event.action,
            event.decision,
            event.outcome,
            event.redacted_detail,
            occurred_at,
            retain_until,
        ],
    )?;
    let sequence = unsigned_integer(transaction.last_insert_rowid())?;
    Ok(AuditEventRecord {
        sequence,
        event_id: event.event_id,
        project_id: event.project_id,
        caller_id: event.caller_id,
        action: event.action,
        decision: event.decision,
        outcome: event.outcome,
        redacted_detail: event.redacted_detail,
        occurred_at_ms: event.occurred_at_ms,
        retain_until_ms: event.retain_until_ms,
    })
}

fn export_audit_events(
    connection: &Connection,
    project_id: &ProjectId,
    after_sequence: u64,
    through_sequence: Option<u64>,
    limit: u32,
) -> Result<AuditExport, StoreError> {
    validate_audit_identifier(
        project_id.as_str(),
        MAX_AUDIT_PROJECT_ID_BYTES,
        "project ID",
    )?;
    validate_audit_limit(limit)?;
    let after = i64::try_from(after_sequence)
        .map_err(|_| StoreError::AuditCursorOutOfRange(after_sequence))?;
    if through_sequence.is_some_and(|through| through < after_sequence) {
        return Err(StoreError::InvalidAuditCursorRange {
            after: after_sequence,
            through: through_sequence.expect("checked optional high-water"),
        });
    }
    let maximum: i64 = connection.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM audit_events",
        [],
        |row| row.get(0),
    )?;
    let maximum_sequence = unsigned_integer(maximum)?;
    let (through_sequence, through) = if let Some(sequence) = through_sequence {
        if sequence > maximum_sequence {
            return Err(StoreError::AuditHighWaterAhead {
                through: sequence,
                maximum: maximum_sequence,
            });
        }
        (
            sequence,
            i64::try_from(sequence).map_err(|_| StoreError::AuditCursorOutOfRange(sequence))?,
        )
    } else {
        (maximum_sequence, maximum)
    };
    if through_sequence < after_sequence {
        return Err(StoreError::InvalidAuditCursorRange {
            after: after_sequence,
            through: through_sequence,
        });
    }
    let fetch_limit = i64::from(limit) + 1;
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, project_id, caller_id, action, decision, outcome,
                redacted_detail, occurred_at_ms, retain_until_ms
         FROM audit_events
         WHERE project_id = ?1 AND sequence > ?2 AND sequence <= ?3
         ORDER BY sequence ASC
         LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![project_id.as_str(), after, through, fetch_limit],
        stored_audit_event,
    )?;
    let mut events = rows
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(StoredAuditEvent::into_record)
        .collect::<Result<Vec<_>, _>>()?;
    let page_length = usize::try_from(limit).expect("u32 fits usize on supported platforms");
    let has_more = events.len() > page_length;
    events.truncate(page_length);
    let next_after_sequence = events.last().map_or(after_sequence, |event| event.sequence);
    Ok(AuditExport {
        version: AUDIT_EXPORT_VERSION,
        project_id: project_id.clone(),
        after_sequence,
        through_sequence,
        next_after_sequence,
        has_more,
        events,
    })
}

struct StoredAuditEvent {
    sequence: i64,
    event_id: String,
    project_id: String,
    caller_id: String,
    action: String,
    decision: String,
    outcome: String,
    redacted_detail: String,
    occurred_at_ms: i64,
    retain_until_ms: i64,
}

fn stored_audit_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAuditEvent> {
    Ok(StoredAuditEvent {
        sequence: row.get(0)?,
        event_id: row.get(1)?,
        project_id: row.get(2)?,
        caller_id: row.get(3)?,
        action: row.get(4)?,
        decision: row.get(5)?,
        outcome: row.get(6)?,
        redacted_detail: row.get(7)?,
        occurred_at_ms: row.get(8)?,
        retain_until_ms: row.get(9)?,
    })
}

impl StoredAuditEvent {
    fn into_record(self) -> Result<AuditEventRecord, StoreError> {
        Ok(AuditEventRecord {
            sequence: unsigned_integer(self.sequence)?,
            event_id: self.event_id,
            project_id: ProjectId::from(self.project_id),
            caller_id: CallerId::from(self.caller_id),
            action: self.action,
            decision: self.decision,
            outcome: self.outcome,
            redacted_detail: self.redacted_detail,
            occurred_at_ms: unsigned_integer(self.occurred_at_ms)?,
            retain_until_ms: unsigned_integer(self.retain_until_ms)?,
        })
    }
}

fn audit_event_matches(record: &AuditEventRecord, event: &AppendAuditEvent) -> bool {
    record.event_id == event.event_id
        && record.project_id == event.project_id
        && record.caller_id == event.caller_id
        && record.action == event.action
        && record.decision == event.decision
        && record.outcome == event.outcome
        && record.redacted_detail == event.redacted_detail
        && record.occurred_at_ms == event.occurred_at_ms
        && record.retain_until_ms == event.retain_until_ms
}

fn prune_audit_events(
    connection: &mut Connection,
    project_id: &ProjectId,
    now_ms: u64,
    limit: u32,
) -> Result<AuditPruneOutcome, StoreError> {
    validate_audit_identifier(
        project_id.as_str(),
        MAX_AUDIT_PROJECT_ID_BYTES,
        "project ID",
    )?;
    validate_audit_limit(limit)?;
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let deleted = transaction.execute(
        "DELETE FROM audit_events
         WHERE sequence IN (
             SELECT sequence FROM audit_events
             WHERE project_id = ?1 AND retain_until_ms <= ?2
             ORDER BY sequence ASC
             LIMIT ?3
         )",
        params![project_id.as_str(), now, i64::from(limit)],
    )?;
    let has_more = transaction
        .query_row(
            "SELECT 1 FROM audit_events
             WHERE project_id = ?1 AND retain_until_ms <= ?2
             LIMIT 1",
            params![project_id.as_str(), now],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    transaction.commit()?;
    Ok(AuditPruneOutcome {
        deleted: u32::try_from(deleted).expect("bounded audit deletion count fits u32"),
        has_more,
    })
}

fn validate_audit_event(event: &AppendAuditEvent) -> Result<(), StoreError> {
    validate_audit_identifier(&event.event_id, MAX_AUDIT_EVENT_ID_BYTES, "event ID")?;
    validate_audit_identifier(
        event.project_id.as_str(),
        MAX_AUDIT_PROJECT_ID_BYTES,
        "project ID",
    )?;
    validate_audit_identifier(
        event.caller_id.as_str(),
        MAX_AUDIT_CALLER_ID_BYTES,
        "caller ID",
    )?;
    validate_audit_identifier(&event.action, MAX_AUDIT_ACTION_BYTES, "action")?;
    validate_audit_identifier(&event.decision, MAX_AUDIT_DECISION_BYTES, "decision")?;
    validate_audit_identifier(&event.outcome, MAX_AUDIT_OUTCOME_BYTES, "outcome")?;
    if event.redacted_detail.len() > MAX_AUDIT_DETAIL_BYTES
        || event.redacted_detail.chars().any(is_unsafe_audit_character)
    {
        return Err(StoreError::InvalidAuditEvent("detail"));
    }
    if event.retain_until_ms < event.occurred_at_ms {
        return Err(StoreError::InvalidAuditEvent(
            "retention precedes occurrence",
        ));
    }
    Ok(())
}

fn validate_audit_identifier(
    value: &str,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.chars().any(is_unsafe_audit_character)
    {
        Err(StoreError::InvalidAuditEvent(field))
    } else {
        Ok(())
    }
}

fn is_unsafe_audit_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

fn validate_audit_limit(limit: u32) -> Result<(), StoreError> {
    if limit == 0 || limit > MAX_AUDIT_BATCH_SIZE {
        Err(StoreError::InvalidAuditBatchLimit {
            limit,
            maximum: MAX_AUDIT_BATCH_SIZE,
        })
    } else {
        Ok(())
    }
}

fn put_grant(connection: &mut Connection, put: PutGrant) -> Result<ProjectPolicy, StoreError> {
    let created_at = sql_integer(put.created_at_ms)?;
    let grant = put.grant;
    let expires_at = grant.expires_at_ms.map(sql_integer).transpose()?;
    let revoked_at = grant.revoked_at_ms.map(sql_integer).transpose()?;
    let (resource_kind, resource) = match &grant.resource {
        ResourceScope::Any => ("any", None),
        ResourceScope::Exact(resource) => ("exact", Some(resource.as_str())),
    };
    let effect = match grant.effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    };
    let approval = match grant.approval {
        ApprovalRequirement::None => "none",
        ApprovalRequirement::Once => "once",
    };
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists = transaction
        .query_row(
            "SELECT 1 FROM capability_grants WHERE grant_id = ?1",
            [grant.id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        return Err(StoreError::GrantAlreadyExists(grant.id));
    }
    transaction.execute(
        "INSERT INTO projects(project_id) VALUES (?1)
         ON CONFLICT(project_id) DO NOTHING",
        [grant.project.as_str()],
    )?;
    transaction.execute(
        "INSERT INTO project_policies(project_id, version, default_effect, updated_at_ms)
         VALUES (?1, 1, 'deny', ?2)
         ON CONFLICT(project_id) DO UPDATE SET
             version = project_policies.version + 1,
             updated_at_ms = excluded.updated_at_ms",
        params![grant.project.as_str(), created_at],
    )?;
    transaction.execute(
        "INSERT INTO capability_grants(
            grant_id, caller_id, project_id, capability, resource_kind, resource,
            effect, approval, expires_at_ms, revoked_at_ms, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            grant.id.as_str(),
            grant.caller.as_str(),
            grant.project.as_str(),
            grant.capability.as_str(),
            resource_kind,
            resource,
            effect,
            approval,
            expires_at,
            revoked_at,
            created_at,
        ],
    )?;
    let version: i64 = transaction.query_row(
        "SELECT version FROM project_policies WHERE project_id = ?1",
        [grant.project.as_str()],
        |row| row.get(0),
    )?;
    transaction.commit()?;
    Ok(ProjectPolicy {
        project_id: grant.project,
        version: unsigned_integer(version)?,
        updated_at_ms: put.created_at_ms,
    })
}

fn revoke_grant(
    connection: &mut Connection,
    grant_id: &GrantId,
    now_ms: u64,
) -> Result<GrantRevocation, StoreError> {
    let revoked_at = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let grant = transaction
        .query_row(
            "SELECT project_id, revoked_at_ms FROM capability_grants WHERE grant_id = ?1",
            [grant_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let Some((project_id, previous_revocation)) = grant else {
        return Ok(GrantRevocation::UnknownGrant);
    };
    if previous_revocation.is_some() {
        return Ok(GrantRevocation::AlreadyRevoked);
    }
    transaction.execute(
        "UPDATE capability_grants SET revoked_at_ms = ?2 WHERE grant_id = ?1",
        params![grant_id.as_str(), revoked_at],
    )?;
    transaction.execute(
        "UPDATE project_policies SET version = version + 1, updated_at_ms = ?2
         WHERE project_id = ?1",
        params![project_id, revoked_at],
    )?;
    transaction.commit()?;
    Ok(GrantRevocation::Revoked)
}

fn authorize(
    connection: &mut Connection,
    request: &AuthorizationRequest,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = authorize_tx(&transaction, request, now, now_ms, approval_ttl_ms)?;
    transaction.commit()?;
    Ok(outcome)
}

fn authorize_audited(
    connection: &mut Connection,
    request: &AuthorizationRequest,
    audit: AuthorizationAudit,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = authorize_tx(&transaction, request, now, now_ms, approval_ttl_ms)?;
    let (decision, audit_outcome) = authorization_audit_outcome(&outcome);
    append_audit_event_tx(
        &transaction,
        AppendAuditEvent {
            event_id: audit.event_id,
            project_id: request.project_id.clone(),
            caller_id: request.caller_id.clone(),
            action: audit.action,
            decision: decision.to_owned(),
            outcome: audit_outcome.to_owned(),
            redacted_detail: audit.redacted_detail,
            occurred_at_ms: now_ms,
            retain_until_ms: audit.retain_until_ms,
        },
    )?;
    transaction.commit()?;
    Ok(outcome)
}

fn consume_effect_approval_audited(
    connection: &mut Connection,
    request: &AuthorizationRequest,
    audit: AuthorizationAudit,
    now_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = if caller_is_active(&transaction, &request.caller_id)? {
        let grants = load_grants(&transaction, request)?;
        if evaluate(
            &grants,
            &request.caller_id,
            &request.project_id,
            &request.capability,
            &request.resource,
            now_ms,
        ) == Decision::Denied
        {
            AuthorizationOutcome::Denied
        } else {
            let approval_id = request.approval_id.as_ref().ok_or_else(|| {
                StoreError::InvalidState(
                    "connector effect capability is missing its approval receipt".to_owned(),
                )
            })?;
            let fingerprint = EffectFingerprint::compute(
                &request.caller_id,
                &request.project_id,
                &request.capability,
                &request.resource,
            );
            resolve_approval(
                &transaction,
                approval_id,
                request,
                &fingerprint,
                now,
                now_ms,
            )?
        }
    } else {
        AuthorizationOutcome::Denied
    };
    let (decision, audit_outcome) = authorization_audit_outcome(&outcome);
    append_audit_event_tx(
        &transaction,
        AppendAuditEvent {
            event_id: audit.event_id,
            project_id: request.project_id.clone(),
            caller_id: request.caller_id.clone(),
            action: audit.action,
            decision: decision.to_owned(),
            outcome: audit_outcome.to_owned(),
            redacted_detail: audit.redacted_detail,
            occurred_at_ms: now_ms,
            retain_until_ms: audit.retain_until_ms,
        },
    )?;
    transaction.commit()?;
    Ok(outcome)
}

fn authorize_flow_run(
    connection: &mut Connection,
    request: AuthorizeFlowRun,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<FlowAuthorizationOutcome, StoreError> {
    if request.accept.operation_kind != FLOW_OPERATION_KIND {
        return Err(StoreError::InvalidState(
            "flow authorization requires an exact flow operation".to_owned(),
        ));
    }
    let now = sql_integer(now_ms)?;
    let capability = flow_capability();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = if let Some(existing) = existing_acceptance_tx(&transaction, &request.accept)? {
        let request_id = accept_outcome_request_id(&existing);
        if request_id != &request.accept.request_id {
            return Err(StoreError::RequestIdConflict(
                request.accept.request_id.clone(),
            ));
        }
        let terminal_existing = matches!(
            existing,
            AcceptOutcome::Existing {
                state: RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled,
                ..
            }
        );
        match validate_flow_authorization_integrity(&transaction, request_id) {
            Err(StoreError::CorruptFlowAuthorization(_)) if terminal_existing => {
                FlowAuthorizationOutcome::Accepted(existing)
            }
            Err(error) => return Err(error),
            Ok(proof)
                if proof.capability == capability
                    && proof.resource == request.resource
                    && proof.schema_approval_required == request.schema_approval_required
                    && validate_loaded_flow_authorization(
                        &transaction,
                        request_id,
                        &proof,
                        now_ms,
                    )? == FlowEffectAuthorization::Allowed =>
            {
                FlowAuthorizationOutcome::Accepted(existing)
            }
            Ok(_) => FlowAuthorizationOutcome::Denied,
        }
    } else {
        authorize_new_flow_run(&transaction, &request, now, now_ms, approval_ttl_ms)?
    };
    let (decision, audit_outcome) = flow_authorization_audit_outcome(&outcome);
    append_audit_event_tx(
        &transaction,
        AppendAuditEvent {
            event_id: request.audit.event_id,
            project_id: request.accept.project_id,
            caller_id: request.accept.caller_id,
            action: request.audit.action,
            decision: decision.to_owned(),
            outcome: audit_outcome.to_owned(),
            redacted_detail: request.audit.redacted_detail,
            occurred_at_ms: now_ms,
            retain_until_ms: request.audit.retain_until_ms,
        },
    )?;
    transaction.commit()?;
    Ok(outcome)
}

fn authorize_new_flow_run(
    transaction: &Transaction<'_>,
    request: &AuthorizeFlowRun,
    now: i64,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<FlowAuthorizationOutcome, StoreError> {
    if !caller_is_active(transaction, &request.accept.caller_id)? {
        return Ok(FlowAuthorizationOutcome::Denied);
    }
    let capability = flow_capability();
    let policy_request = AuthorizationRequest {
        caller_id: request.accept.caller_id.clone(),
        project_id: request.accept.project_id.clone(),
        capability: capability.clone(),
        resource: request.resource.clone(),
        approval_id: request.approval_id.clone(),
    };
    let grants = load_grants(transaction, &policy_request)?;
    let decision = evaluate(
        &grants,
        &policy_request.caller_id,
        &policy_request.project_id,
        &policy_request.capability,
        &policy_request.resource,
        now_ms,
    );
    if decision == Decision::Denied {
        return Ok(FlowAuthorizationOutcome::Denied);
    }
    let approval_required =
        request.schema_approval_required || decision == Decision::ApprovalRequired;
    if approval_required {
        let approval = authorize_flow_with_approval(
            transaction,
            &policy_request,
            &request.accept.request_id,
            now,
            now_ms,
            approval_ttl_ms,
        )?;
        if approval != AuthorizationOutcome::Allowed {
            return Ok(flow_authorization_outcome(approval));
        }
    }

    let accepted = accept_tx(transaction, request.accept.clone(), now)?;
    let approval_id = if approval_required {
        Some(request.approval_id.clone().ok_or_else(|| {
            StoreError::InvalidState("approved flow omitted its consumed receipt".to_owned())
        })?)
    } else {
        None
    };
    insert_flow_authorization(
        transaction,
        accept_outcome_request_id(&accepted),
        request,
        &capability,
        approval_id.as_ref(),
        now,
    )?;
    Ok(FlowAuthorizationOutcome::Accepted(accepted))
}

fn flow_capability() -> CapabilityName {
    CapabilityName::parse(FLOW_CAPABILITY_NAME)
        .expect("flow capability name is a static valid policy identifier")
}

fn insert_flow_authorization(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    request: &AuthorizeFlowRun,
    capability: &CapabilityName,
    approval_id: Option<&ApprovalId>,
    now: i64,
) -> Result<(), StoreError> {
    let fingerprint = EffectFingerprint::compute(
        &request.accept.caller_id,
        &request.accept.project_id,
        capability,
        &request.resource,
    );
    transaction.execute(
        "INSERT INTO flow_authorizations(
             request_id, capability, resource, effect_fingerprint,
             authorization_kind, approval_id, schema_approval_required, authorized_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            request_id.as_str(),
            capability.as_str(),
            request.resource.as_str(),
            fingerprint.as_bytes().as_slice(),
            if approval_id.is_some() {
                "approved"
            } else {
                "unconditional"
            },
            approval_id.map(ApprovalId::as_str),
            request.schema_approval_required,
            now,
        ],
    )?;
    Ok(())
}

fn accept_outcome_request_id(outcome: &AcceptOutcome) -> &RequestId {
    match outcome {
        AcceptOutcome::Created { request_id, .. } | AcceptOutcome::Existing { request_id, .. } => {
            request_id
        }
    }
}

const fn flow_authorization_audit_outcome(
    outcome: &FlowAuthorizationOutcome,
) -> (&'static str, &'static str) {
    match outcome {
        FlowAuthorizationOutcome::Accepted(_) => ("allow", "authorized"),
        FlowAuthorizationOutcome::Denied => ("deny", "forbidden"),
        FlowAuthorizationOutcome::ApprovalRequired { .. } => ("challenge", "approval_required"),
        FlowAuthorizationOutcome::ApprovalDenied => ("deny", "approval_denied"),
        FlowAuthorizationOutcome::ApprovalExpired => ("deny", "approval_expired"),
    }
}

fn flow_authorization_outcome(outcome: AuthorizationOutcome) -> FlowAuthorizationOutcome {
    match outcome {
        AuthorizationOutcome::Allowed => {
            unreachable!("allowed flow authorization is accepted atomically")
        }
        AuthorizationOutcome::Denied => FlowAuthorizationOutcome::Denied,
        AuthorizationOutcome::ApprovalRequired {
            approval_id,
            expires_at_ms,
        } => FlowAuthorizationOutcome::ApprovalRequired {
            approval_id,
            expires_at_ms,
        },
        AuthorizationOutcome::ApprovalDenied => FlowAuthorizationOutcome::ApprovalDenied,
        AuthorizationOutcome::ApprovalExpired => FlowAuthorizationOutcome::ApprovalExpired,
    }
}

struct StoredFlowAuthorization {
    caller_id: CallerId,
    project_id: ProjectId,
    capability: CapabilityName,
    resource: ResourceName,
    fingerprint: Vec<u8>,
    approval_id: Option<ApprovalId>,
    schema_approval_required: bool,
}

fn validate_flow_effect_authorization(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
) -> Result<FlowEffectAuthorization, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if ensure_live_flow_lease(&transaction, lease, now)? != RequestState::Leased {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    let proof = validate_flow_authorization_integrity(&transaction, &lease.request_id)?;
    if proof.project_id != lease.project_id {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    let outcome =
        validate_loaded_flow_authorization(&transaction, &lease.request_id, &proof, now_ms)?;
    transaction.commit()?;
    Ok(outcome)
}

fn validate_flow_operation_resource(
    connection: &mut Connection,
    lease: &Lease,
    resource: &ResourceName,
    now_ms: u64,
) -> Result<(), StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !matches!(
        ensure_live_flow_lease(&transaction, lease, now)?,
        RequestState::Leased | RequestState::CancellationRequested
    ) {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    let proof = validate_flow_authorization_integrity(&transaction, &lease.request_id)?;
    if proof.project_id != lease.project_id || proof.resource != *resource {
        return Err(StoreError::CorruptFlowAuthorization(
            lease.request_id.clone(),
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn validate_loaded_flow_authorization(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    proof: &StoredFlowAuthorization,
    now_ms: u64,
) -> Result<FlowEffectAuthorization, StoreError> {
    if let Some(approval_id) = &proof.approval_id {
        validate_consumed_flow_receipt(transaction, request_id, proof, approval_id)?;
    }
    if !caller_is_active(transaction, &proof.caller_id)? {
        return Ok(FlowEffectAuthorization::Denied);
    }
    let policy_request = AuthorizationRequest {
        caller_id: proof.caller_id.clone(),
        project_id: proof.project_id.clone(),
        capability: proof.capability.clone(),
        resource: proof.resource.clone(),
        approval_id: proof.approval_id.clone(),
    };
    let grants = load_grants(transaction, &policy_request)?;
    let decision = evaluate(
        &grants,
        &proof.caller_id,
        &proof.project_id,
        &proof.capability,
        &proof.resource,
        now_ms,
    );
    let allowed = match (&proof.approval_id, decision) {
        (_, Decision::Denied) | (None, Decision::ApprovalRequired) => false,
        (None, Decision::Allowed) => !proof.schema_approval_required,
        (Some(_), Decision::Allowed | Decision::ApprovalRequired) => true,
    };
    Ok(if allowed {
        FlowEffectAuthorization::Allowed
    } else {
        FlowEffectAuthorization::Denied
    })
}

fn validate_flow_authorization_integrity(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
) -> Result<StoredFlowAuthorization, StoreError> {
    let proof = load_flow_authorization(transaction, request_id)?;
    if let Some(approval_id) = &proof.approval_id {
        validate_consumed_flow_receipt(transaction, request_id, &proof, approval_id)?;
    }
    Ok(proof)
}

fn load_flow_authorization(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
) -> Result<StoredFlowAuthorization, StoreError> {
    let stored = transaction
        .query_row(
            "SELECT requests.caller_id, requests.project_id,
                    flow_authorizations.capability, flow_authorizations.resource,
                    flow_authorizations.effect_fingerprint,
                    flow_authorizations.authorization_kind,
                    flow_authorizations.approval_id,
                    flow_authorizations.schema_approval_required,
                    requests.accepted_at_ms, flow_authorizations.authorized_at_ms
             FROM requests
             LEFT JOIN flow_authorizations
               ON flow_authorizations.request_id = requests.request_id
             WHERE requests.request_id = ?1 AND requests.operation_kind = 'flow_run'",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<bool>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        caller,
        project,
        capability,
        resource,
        fingerprint,
        kind,
        approval,
        schema_required,
        accepted_at,
        authorized_at,
    )) = stored
    else {
        return Err(StoreError::CorruptFlowAuthorization(request_id.clone()));
    };
    let (
        Some(capability),
        Some(resource),
        Some(fingerprint),
        Some(kind),
        Some(schema_required),
        Some(authorized_at),
    ) = (
        capability,
        resource,
        fingerprint,
        kind,
        schema_required,
        authorized_at,
    )
    else {
        return Err(StoreError::CorruptFlowAuthorization(request_id.clone()));
    };
    let capability = CapabilityName::parse(capability)
        .map_err(|_| StoreError::CorruptFlowAuthorization(request_id.clone()))?;
    let resource = ResourceName::parse(resource)
        .map_err(|_| StoreError::CorruptFlowAuthorization(request_id.clone()))?;
    let caller_id = CallerId::from(caller);
    let project_id = ProjectId::from(project);
    let expected = EffectFingerprint::compute(&caller_id, &project_id, &capability, &resource);
    let kind_matches = matches!((kind.as_str(), approval.as_ref()), ("unconditional", None))
        || matches!((kind.as_str(), approval.as_ref()), ("approved", Some(_)));
    if capability.as_str() != FLOW_CAPABILITY_NAME
        || !kind_matches
        || (schema_required && approval.is_none())
        || authorized_at != accepted_at
        || !constant_time_equal(&fingerprint, expected.as_bytes())
    {
        return Err(StoreError::CorruptFlowAuthorization(request_id.clone()));
    }
    Ok(StoredFlowAuthorization {
        caller_id,
        project_id,
        capability,
        resource,
        fingerprint,
        approval_id: approval.map(ApprovalId::from),
        schema_approval_required: schema_required,
    })
}

fn validate_consumed_flow_receipt(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    proof: &StoredFlowAuthorization,
    approval_id: &ApprovalId,
) -> Result<(), StoreError> {
    let receipt = transaction
        .query_row(
            "SELECT caller_id, project_id, capability, resource,
                    effect_fingerprint, state, flow_request_id,
                    decided_at_ms, consumed_at_ms, expires_at_ms
             FROM approvals WHERE approval_id = ?1",
            [approval_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        caller,
        project,
        capability,
        resource,
        fingerprint,
        state,
        bound_request,
        decided_at,
        consumed_at,
        expires_at,
    )) = receipt
    else {
        return Err(StoreError::CorruptFlowAuthorization(request_id.clone()));
    };
    if caller != proof.caller_id.as_str()
        || project != proof.project_id.as_str()
        || capability != proof.capability.as_str()
        || resource != proof.resource.as_str()
        || state != "consumed"
        || bound_request.as_deref() != Some(request_id.as_str())
        || !matches!((decided_at, consumed_at), (Some(decided), Some(consumed)) if decided <= consumed && consumed < expires_at)
        || !constant_time_equal(&fingerprint, &proof.fingerprint)
    {
        return Err(StoreError::CorruptFlowAuthorization(request_id.clone()));
    }
    Ok(())
}

fn authorize_tx(
    transaction: &Transaction<'_>,
    request: &AuthorizationRequest,
    now: i64,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    if !caller_is_active(transaction, &request.caller_id)? {
        return Ok(AuthorizationOutcome::Denied);
    }
    let grants = load_grants(transaction, request)?;
    let decision = evaluate(
        &grants,
        &request.caller_id,
        &request.project_id,
        &request.capability,
        &request.resource,
        now_ms,
    );
    let outcome = match decision {
        Decision::Allowed => AuthorizationOutcome::Allowed,
        Decision::Denied => AuthorizationOutcome::Denied,
        Decision::ApprovalRequired => {
            authorize_with_approval(transaction, request, now, now_ms, approval_ttl_ms)?
        }
    };
    Ok(outcome)
}

fn caller_is_active(
    transaction: &Transaction<'_>,
    caller_id: &CallerId,
) -> Result<bool, StoreError> {
    let active = transaction
        .query_row(
            "SELECT 1 FROM callers WHERE caller_id = ?1 AND revoked_at_ms IS NULL",
            [caller_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(active)
}

const fn authorization_audit_outcome(
    outcome: &AuthorizationOutcome,
) -> (&'static str, &'static str) {
    match outcome {
        AuthorizationOutcome::Allowed => ("allow", "authorized"),
        AuthorizationOutcome::Denied => ("deny", "forbidden"),
        AuthorizationOutcome::ApprovalRequired { .. } => ("challenge", "approval_required"),
        AuthorizationOutcome::ApprovalDenied => ("deny", "approval_denied"),
        AuthorizationOutcome::ApprovalExpired => ("deny", "approval_expired"),
    }
}

fn load_grants(
    transaction: &Transaction<'_>,
    request: &AuthorizationRequest,
) -> Result<Vec<Grant>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT grant_id, resource_kind, resource, effect, approval,
                expires_at_ms, revoked_at_ms
         FROM capability_grants
         WHERE caller_id = ?1 AND project_id = ?2 AND capability = ?3",
    )?;
    let rows = statement.query_map(
        params![
            request.caller_id.as_str(),
            request.project_id.as_str(),
            request.capability.as_str(),
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        },
    )?;
    let mut grants = Vec::new();
    for row in rows {
        let (id, resource_kind, resource, effect, approval, expires_at, revoked_at) = row?;
        grants.push(Grant {
            id: GrantId::from(id),
            caller: request.caller_id.clone(),
            project: request.project_id.clone(),
            capability: request.capability.clone(),
            resource: parse_resource_scope(&resource_kind, resource)?,
            effect: parse_effect(&effect)?,
            approval: parse_approval_requirement(&approval)?,
            expires_at_ms: expires_at.map(unsigned_integer).transpose()?,
            revoked_at_ms: revoked_at.map(unsigned_integer).transpose()?,
        });
    }
    Ok(grants)
}

fn parse_resource_scope(kind: &str, resource: Option<String>) -> Result<ResourceScope, StoreError> {
    match (kind, resource) {
        ("any", None) => Ok(ResourceScope::Any),
        ("exact", Some(resource)) => ResourceName::parse(resource)
            .map(ResourceScope::Exact)
            .map_err(|_| StoreError::InvalidState("invalid stored policy resource".to_owned())),
        _ => Err(StoreError::InvalidState(
            "invalid stored policy resource scope".to_owned(),
        )),
    }
}

fn parse_effect(effect: &str) -> Result<Effect, StoreError> {
    match effect {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        _ => Err(StoreError::InvalidState(
            "invalid stored grant effect".to_owned(),
        )),
    }
}

fn parse_approval_requirement(value: &str) -> Result<ApprovalRequirement, StoreError> {
    match value {
        "none" => Ok(ApprovalRequirement::None),
        "once" => Ok(ApprovalRequirement::Once),
        _ => Err(StoreError::InvalidState(
            "invalid stored approval requirement".to_owned(),
        )),
    }
}

fn authorize_with_approval(
    transaction: &Transaction<'_>,
    request: &AuthorizationRequest,
    now: i64,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let fingerprint = EffectFingerprint::compute(
        &request.caller_id,
        &request.project_id,
        &request.capability,
        &request.resource,
    );
    let Some(approval_id) = &request.approval_id else {
        if approval_ttl_ms == 0 {
            return Err(StoreError::InvalidState(
                "approval lifetime must be non-zero".to_owned(),
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(approval_ttl_ms)
            .ok_or(StoreError::ApprovalExpiryOverflow)?;
        let expires_at = sql_integer(expires_at_ms)?;
        let approval_id = ApprovalId::new(Uuid::new_v4().to_string());
        transaction.execute(
            "INSERT INTO approvals(
                approval_id, caller_id, project_id, capability, resource,
                effect_fingerprint, state, requested_at_ms, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?8)",
            params![
                approval_id.as_str(),
                request.caller_id.as_str(),
                request.project_id.as_str(),
                request.capability.as_str(),
                request.resource.as_str(),
                fingerprint.as_bytes().as_slice(),
                now,
                expires_at,
            ],
        )?;
        return Ok(AuthorizationOutcome::ApprovalRequired {
            approval_id,
            expires_at_ms,
        });
    };
    resolve_approval(transaction, approval_id, request, &fingerprint, now, now_ms)
}

fn authorize_flow_with_approval(
    transaction: &Transaction<'_>,
    request: &AuthorizationRequest,
    request_id: &RequestId,
    now: i64,
    now_ms: u64,
    approval_ttl_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let fingerprint = EffectFingerprint::compute(
        &request.caller_id,
        &request.project_id,
        &request.capability,
        &request.resource,
    );
    let Some(approval_id) = &request.approval_id else {
        if let Some((approval_id, expires_at_ms)) =
            reusable_flow_approval(transaction, request, request_id, &fingerprint, now_ms)?
        {
            return Ok(AuthorizationOutcome::ApprovalRequired {
                approval_id,
                expires_at_ms,
            });
        }
        if approval_ttl_ms == 0 {
            return Err(StoreError::InvalidState(
                "approval lifetime must be non-zero".to_owned(),
            ));
        }
        let expires_at_ms = now_ms
            .checked_add(approval_ttl_ms)
            .ok_or(StoreError::ApprovalExpiryOverflow)?;
        let expires_at = sql_integer(expires_at_ms)?;
        let approval_id = ApprovalId::new(Uuid::new_v4().to_string());
        transaction.execute(
            "INSERT INTO approvals(
                approval_id, caller_id, project_id, capability, resource,
                effect_fingerprint, state, requested_at_ms, expires_at_ms,
                flow_request_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'requested', ?7, ?8, ?9)",
            params![
                approval_id.as_str(),
                request.caller_id.as_str(),
                request.project_id.as_str(),
                request.capability.as_str(),
                request.resource.as_str(),
                fingerprint.as_bytes().as_slice(),
                now,
                expires_at,
                request_id.as_str(),
            ],
        )?;
        return Ok(AuthorizationOutcome::ApprovalRequired {
            approval_id,
            expires_at_ms,
        });
    };
    resolve_flow_approval(
        transaction,
        approval_id,
        request,
        request_id,
        &fingerprint,
        now,
        now_ms,
    )
}

fn reusable_flow_approval(
    transaction: &Transaction<'_>,
    request: &AuthorizationRequest,
    request_id: &RequestId,
    fingerprint: &EffectFingerprint,
    now_ms: u64,
) -> Result<Option<(ApprovalId, u64)>, StoreError> {
    let approval = transaction
        .query_row(
            "SELECT approval_id, expires_at_ms
             FROM approvals
             WHERE caller_id = ?1 AND project_id = ?2 AND capability = ?3
               AND resource = ?4 AND effect_fingerprint = ?5
               AND flow_request_id = ?6 AND state IN ('requested', 'approved')
               AND expires_at_ms > ?7
             ORDER BY requested_at_ms DESC, approval_id DESC LIMIT 1",
            params![
                request.caller_id.as_str(),
                request.project_id.as_str(),
                request.capability.as_str(),
                request.resource.as_str(),
                fingerprint.as_bytes().as_slice(),
                request_id.as_str(),
                sql_integer(now_ms)?,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    approval
        .map(|(approval_id, expires_at)| {
            Ok((ApprovalId::from(approval_id), unsigned_integer(expires_at)?))
        })
        .transpose()
}

fn resolve_flow_approval(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    request: &AuthorizationRequest,
    request_id: &RequestId,
    fingerprint: &EffectFingerprint,
    now: i64,
    now_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let approval = transaction
        .query_row(
            "SELECT caller_id, project_id, capability, resource,
                    effect_fingerprint, state, expires_at_ms, flow_request_id
             FROM approvals WHERE approval_id = ?1",
            [approval_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((caller, project, capability, resource, stored_fingerprint, state, expires_at, bound)) =
        approval
    else {
        return Ok(AuthorizationOutcome::Denied);
    };
    if caller != request.caller_id.as_str()
        || project != request.project_id.as_str()
        || capability != request.capability.as_str()
        || resource != request.resource.as_str()
        || bound.as_deref() != Some(request_id.as_str())
        || !constant_time_equal(&stored_fingerprint, fingerprint.as_bytes())
    {
        return Ok(AuthorizationOutcome::Denied);
    }
    let expires_at_ms = unsigned_integer(expires_at)?;
    if now_ms >= expires_at_ms && matches!(state.as_str(), "requested" | "approved") {
        transaction.execute(
            "UPDATE approvals SET state = 'expired' WHERE approval_id = ?1",
            [approval_id.as_str()],
        )?;
        return Ok(AuthorizationOutcome::ApprovalExpired);
    }
    match state.as_str() {
        "requested" => Ok(AuthorizationOutcome::ApprovalRequired {
            approval_id: approval_id.clone(),
            expires_at_ms,
        }),
        "approved" => {
            let updated = transaction.execute(
                "UPDATE approvals SET state = 'consumed', consumed_at_ms = ?3
                 WHERE approval_id = ?1 AND state = 'approved' AND flow_request_id = ?2",
                params![approval_id.as_str(), request_id.as_str(), now],
            )?;
            if updated == 1 {
                Ok(AuthorizationOutcome::Allowed)
            } else {
                Ok(AuthorizationOutcome::Denied)
            }
        }
        "denied" => Ok(AuthorizationOutcome::ApprovalDenied),
        "expired" => Ok(AuthorizationOutcome::ApprovalExpired),
        "consumed" => Ok(AuthorizationOutcome::Denied),
        _ => Err(StoreError::InvalidState(
            "invalid stored approval state".to_owned(),
        )),
    }
}

fn resolve_approval(
    transaction: &Transaction<'_>,
    approval_id: &ApprovalId,
    request: &AuthorizationRequest,
    fingerprint: &EffectFingerprint,
    now: i64,
    now_ms: u64,
) -> Result<AuthorizationOutcome, StoreError> {
    let approval = transaction
        .query_row(
            "SELECT caller_id, project_id, capability, resource,
                    effect_fingerprint, state, expires_at_ms, flow_request_id
             FROM approvals WHERE approval_id = ?1",
            [approval_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        caller,
        project,
        capability,
        resource,
        stored_fingerprint,
        state,
        expires_at,
        flow_request_id,
    )) = approval
    else {
        return Ok(AuthorizationOutcome::Denied);
    };
    if caller != request.caller_id.as_str()
        || project != request.project_id.as_str()
        || capability != request.capability.as_str()
        || resource != request.resource.as_str()
        || flow_request_id.is_some()
        || !constant_time_equal(&stored_fingerprint, fingerprint.as_bytes())
    {
        return Ok(AuthorizationOutcome::Denied);
    }
    let expires_at_ms = unsigned_integer(expires_at)?;
    if now_ms >= expires_at_ms && matches!(state.as_str(), "requested" | "approved") {
        transaction.execute(
            "UPDATE approvals SET state = 'expired' WHERE approval_id = ?1",
            [approval_id.as_str()],
        )?;
        return Ok(AuthorizationOutcome::ApprovalExpired);
    }
    match state.as_str() {
        "requested" => Ok(AuthorizationOutcome::ApprovalRequired {
            approval_id: approval_id.clone(),
            expires_at_ms,
        }),
        "approved" => {
            let updated = transaction.execute(
                "UPDATE approvals SET state = 'consumed', consumed_at_ms = ?2
                 WHERE approval_id = ?1 AND state = 'approved'",
                params![approval_id.as_str(), now],
            )?;
            if updated == 1 {
                Ok(AuthorizationOutcome::Allowed)
            } else {
                Ok(AuthorizationOutcome::Denied)
            }
        }
        "denied" => Ok(AuthorizationOutcome::ApprovalDenied),
        "expired" => Ok(AuthorizationOutcome::ApprovalExpired),
        "consumed" => Ok(AuthorizationOutcome::Denied),
        _ => Err(StoreError::InvalidState(
            "invalid stored approval state".to_owned(),
        )),
    }
}

fn decide_approval(
    connection: &mut Connection,
    approval_id: &ApprovalId,
    project_id: Option<&ProjectId>,
    approver_id: &CallerId,
    decision: ApprovalDecision,
    now_ms: u64,
) -> Result<ApprovalDecisionOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active_approver = transaction
        .query_row(
            "SELECT 1 FROM callers WHERE caller_id = ?1 AND revoked_at_ms IS NULL",
            [approver_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !active_approver {
        return Err(StoreError::InvalidApprovalState);
    }
    let approval = transaction
        .query_row(
            "SELECT state, expires_at_ms, decided_by
             FROM approvals
             WHERE approval_id = ?1
               AND (?2 IS NULL OR (project_id = ?2 AND caller_id = ?3))",
            params![
                approval_id.as_str(),
                project_id.map(ProjectId::as_str),
                approver_id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((state, expires_at, decided_by)) = approval else {
        return Err(StoreError::ApprovalNotFound(approval_id.clone()));
    };
    match (state.as_str(), decision, decided_by.as_deref()) {
        ("approved", ApprovalDecision::Approve, Some(decider))
            if decider == approver_id.as_str() =>
        {
            return Ok(ApprovalDecisionOutcome::Approved);
        }
        ("denied", ApprovalDecision::Deny, Some(decider)) if decider == approver_id.as_str() => {
            return Ok(ApprovalDecisionOutcome::Denied);
        }
        ("expired", _, _) => return Ok(ApprovalDecisionOutcome::Expired),
        ("requested", _, None) => {}
        _ => return Err(StoreError::InvalidApprovalState),
    }
    if now_ms >= unsigned_integer(expires_at)? {
        transaction.execute(
            "UPDATE approvals SET state = 'expired' WHERE approval_id = ?1",
            [approval_id.as_str()],
        )?;
        transaction.commit()?;
        return Ok(ApprovalDecisionOutcome::Expired);
    }
    let (state, outcome) = match decision {
        ApprovalDecision::Approve => ("approved", ApprovalDecisionOutcome::Approved),
        ApprovalDecision::Deny => ("denied", ApprovalDecisionOutcome::Denied),
    };
    transaction.execute(
        "UPDATE approvals
         SET state = ?2, decided_by = ?3, decided_at_ms = ?4
         WHERE approval_id = ?1 AND state = 'requested'",
        params![approval_id.as_str(), state, approver_id.as_str(), now],
    )?;
    transaction.commit()?;
    Ok(outcome)
}

fn open_evidence_worker(path: &Path) -> Result<(Connection, EvidenceFiles), StoreError> {
    let connection = open_connection(path)?;
    let files = EvidenceFiles::open(path)?;
    Ok((connection, files))
}

fn run_evidence_worker(
    mut connection: Connection,
    files: EvidenceFiles,
    mut commands: tokio_mpsc::Receiver<EvidenceCommand>,
) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            EvidenceCommand::Put {
                evidence,
                now_ms,
                response,
            } => respond(
                response,
                evidence::put(&mut connection, &files, evidence, now_ms),
            ),
            EvidenceCommand::Inspect {
                project_id,
                handle,
                response,
            } => respond(
                response,
                evidence::inspect(&connection, &files, &project_id, &handle),
            ),
            EvidenceCommand::ReadRange {
                project_id,
                handle,
                offset,
                length,
                response,
            } => respond(
                response,
                evidence::read_range(&connection, &files, &project_id, &handle, offset, length),
            ),
            EvidenceCommand::Prune {
                project_id,
                retention,
                created_before_unix_ms,
                limit,
                response,
            } => respond(
                response,
                evidence::prune(
                    &mut connection,
                    &files,
                    &project_id,
                    retention,
                    created_before_unix_ms,
                    limit,
                )
                .map(|outcome| EvidencePruneOutcome {
                    handles_deleted: outcome.handles_deleted,
                    blobs_deleted: outcome.blobs_deleted,
                    blobs_pending: outcome.blobs_pending,
                    cleanup_unresolved: outcome.cleanup_unresolved,
                    has_more: outcome.has_more,
                }),
            ),
            #[cfg(test)]
            EvidenceCommand::Hold { entered, release } => {
                let _ = entered.send(());
                let _ = release.recv();
            }
            EvidenceCommand::Shutdown(response) => {
                drop(connection);
                drop(files);
                respond(response, Ok(()));
                return;
            }
        }
    }
}

fn respond<T>(response: Response<T>, result: Result<T, StoreError>) {
    let _ = response.send(result);
}

fn register_caller(
    connection: &mut Connection,
    caller_id: CallerId,
    credential: &CallerCredential,
    now_ms: u64,
) -> Result<CallerRegistration, StoreError> {
    if !credential.is_valid() {
        return Err(StoreError::InvalidCallerCredential);
    }
    let registered_at = sql_integer(now_ms)?;
    let digest = credential_digest(credential);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let existing_revocation = transaction
        .query_row(
            "SELECT revoked_at_ms FROM callers WHERE caller_id = ?1",
            [caller_id.as_str()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?;
    match existing_revocation {
        None => {
            transaction.execute(
                "INSERT INTO callers(
                    caller_id, credential_digest, registered_at_ms, revoked_at_ms
                 ) VALUES (?1, ?2, ?3, NULL)",
                params![caller_id.as_str(), digest.as_slice(), registered_at],
            )?;
        }
        Some(None) => return Err(StoreError::CallerAlreadyRegistered(caller_id)),
        Some(Some(_)) => {
            transaction.execute(
                "UPDATE callers
                 SET credential_digest = ?2, registered_at_ms = ?3, revoked_at_ms = NULL
                 WHERE caller_id = ?1",
                params![caller_id.as_str(), digest.as_slice(), registered_at],
            )?;
        }
    }
    transaction.commit()?;
    Ok(CallerRegistration {
        caller_id,
        registered_at_ms: now_ms,
        revoked_at_ms: None,
    })
}

fn authenticate_caller(
    connection: &Connection,
    caller_id: &CallerId,
    credential: &CallerCredential,
) -> Result<CallerAuthentication, StoreError> {
    if !credential.is_valid() {
        return Ok(CallerAuthentication::InvalidCredential);
    }
    let registration = connection
        .query_row(
            "SELECT credential_digest, revoked_at_ms FROM callers WHERE caller_id = ?1",
            [caller_id.as_str()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let Some((expected, revoked_at)) = registration else {
        return Ok(CallerAuthentication::UnknownCaller);
    };
    if revoked_at.is_some() {
        return Ok(CallerAuthentication::Revoked);
    }
    let supplied = credential_digest(credential);
    if constant_time_equal(&expected, supplied.as_slice()) {
        Ok(CallerAuthentication::Authenticated)
    } else {
        Ok(CallerAuthentication::InvalidCredential)
    }
}

fn revoke_caller(
    connection: &mut Connection,
    caller_id: &CallerId,
    now_ms: u64,
) -> Result<CallerRevocation, StoreError> {
    let revoked_at = sql_integer(now_ms)?;
    let state = connection
        .query_row(
            "SELECT registered_at_ms, revoked_at_ms FROM callers WHERE caller_id = ?1",
            [caller_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let Some((registered_at, previous_revocation)) = state else {
        return Ok(CallerRevocation::UnknownCaller);
    };
    if previous_revocation.is_some() {
        return Ok(CallerRevocation::AlreadyRevoked);
    }
    if revoked_at < registered_at {
        return Err(StoreError::InvalidState(
            "caller revocation predates registration".to_owned(),
        ));
    }
    connection.execute(
        "UPDATE callers SET revoked_at_ms = ?2
         WHERE caller_id = ?1 AND revoked_at_ms IS NULL",
        params![caller_id.as_str(), revoked_at],
    )?;
    Ok(CallerRevocation::Revoked)
}

fn credential_digest(credential: &CallerCredential) -> [u8; 32] {
    Sha256::digest(credential.expose_secret().as_bytes()).into()
}

fn constant_time_equal(expected: &[u8], supplied: &[u8]) -> bool {
    if expected.len() != supplied.len() {
        return false;
    }
    expected
        .iter()
        .zip(supplied)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(super) fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut connection = Connection::open(path)?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    ensure_integrity(&connection)?;
    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::InvalidState(format!(
            "journal mode {journal_mode}"
        )));
    }
    apply_migrations(&mut connection)?;
    ensure_integrity(&connection)?;
    ensure_foreign_keys(&connection)?;
    Ok(connection)
}

fn ensure_integrity(connection: &Connection) -> Result<(), StoreError> {
    let result: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(StoreError::IntegrityCheckFailed(result))
    }
}

fn ensure_foreign_keys(connection: &Connection) -> Result<(), StoreError> {
    let violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .optional()?;
    if let Some((table, row_id, parent)) = violation {
        Err(StoreError::ForeignKeyCheckFailed(format!(
            "table={table} row_id={row_id:?} parent={parent}"
        )))
    } else {
        Ok(())
    }
}

fn apply_migrations(connection: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchema {
            found,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    for &(version, sql) in MIGRATIONS.iter().filter(|(version, _)| *version > found) {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(sql)?;
        transaction.pragma_update(None, "user_version", version)?;
        transaction.commit()?;
    }
    Ok(())
}

fn accept(
    connection: &mut Connection,
    request: AcceptRequest,
    now_ms: u64,
) -> Result<AcceptOutcome, StoreError> {
    if request.operation_kind == FLOW_OPERATION_KIND {
        return Err(StoreError::InvalidState(
            "flow requests require atomic authorization and acceptance".to_owned(),
        ));
    }
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = accept_tx(&transaction, request, now)?;
    transaction.commit()?;
    Ok(outcome)
}

fn accept_tx(
    transaction: &Transaction<'_>,
    request: AcceptRequest,
    now: i64,
) -> Result<AcceptOutcome, StoreError> {
    if let Some(existing) = existing_acceptance_tx(transaction, &request)? {
        return Ok(existing);
    }

    let request_id_exists = transaction
        .query_row(
            "SELECT 1 FROM requests WHERE request_id = ?1",
            [request.request_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if request_id_exists {
        return Err(StoreError::RequestIdConflict(request.request_id));
    }

    transaction.execute(
        "INSERT OR IGNORE INTO projects(project_id) VALUES (?1)",
        [request.project_id.as_str()],
    )?;
    transaction.execute(
        "UPDATE projects
         SET next_queue_sequence = next_queue_sequence + 1
         WHERE project_id = ?1",
        [request.project_id.as_str()],
    )?;
    let queue_sequence: i64 = transaction.query_row(
        "SELECT next_queue_sequence - 1 FROM projects WHERE project_id = ?1",
        [request.project_id.as_str()],
        |row| row.get(0),
    )?;

    transaction.execute(
        "INSERT INTO requests(
            request_id, caller_id, project_id, idempotency_key,
            operation_kind, operation, queue_sequence, state, accepted_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8)",
        params![
            request.request_id.as_str(),
            request.caller_id.as_str(),
            request.project_id.as_str(),
            request.idempotency_key.as_str(),
            request.operation_kind,
            request.operation,
            queue_sequence,
            now
        ],
    )?;
    append_event_tx(transaction, &request.request_id, now, "accepted", &[])?;
    Ok(AcceptOutcome::Created {
        request_id: request.request_id,
        queue_sequence: unsigned_integer(queue_sequence)?,
    })
}

fn existing_acceptance_tx(
    transaction: &Transaction<'_>,
    request: &AcceptRequest,
) -> Result<Option<AcceptOutcome>, StoreError> {
    let existing = transaction
        .query_row(
            "SELECT request_id, operation_kind, operation, state
             FROM requests
             WHERE caller_id = ?1 AND project_id = ?2 AND idempotency_key = ?3",
            params![
                request.caller_id.as_str(),
                request.project_id.as_str(),
                request.idempotency_key.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;

    if let Some((request_id, operation_kind, operation, state)) = existing {
        let canonical_request_id = RequestId::from(request_id);
        if operation_kind == request.operation_kind && operation == request.operation {
            return Ok(Some(AcceptOutcome::Existing {
                request_id: canonical_request_id,
                state: parse_state(&state)?,
            }));
        }
        return Err(StoreError::IdempotencyConflict {
            canonical_request_id,
        });
    }

    Ok(None)
}

struct ClaimCandidate {
    request_id: String,
    project_id: String,
    operation_kind: String,
    operation: Vec<u8>,
    queue_sequence: i64,
    attempt: i64,
}

fn claim(
    connection: &mut Connection,
    owner: String,
    now_ms: u64,
    lease_duration_ms: u64,
) -> Result<Option<LeasedRequest>, StoreError> {
    let now = sql_integer(now_ms)?;
    let expires_at_ms = lease_expiry(now_ms, lease_duration_ms)?;
    let expires_at = sql_integer(expires_at_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let candidate = transaction
        .query_row(
            "SELECT
                queued.request_id,
                queued.project_id,
                queued.operation_kind,
                queued.operation,
                queued.queue_sequence,
                queued.attempt
             FROM requests AS queued
             WHERE queued.state = 'queued'
               AND NOT EXISTS (
                   SELECT 1
                   FROM requests AS earlier
                   WHERE earlier.project_id = queued.project_id
                     AND earlier.state IN ('queued', 'leased', 'cancellation_requested')
                     AND earlier.queue_sequence < queued.queue_sequence
               )
               AND NOT EXISTS (
                   SELECT 1
                   FROM requests AS active
                   WHERE active.project_id = queued.project_id
                     AND active.state IN ('leased', 'cancellation_requested')
               )
             ORDER BY queued.accepted_at_ms, queued.rowid
             LIMIT 1",
            [],
            |row| {
                Ok(ClaimCandidate {
                    request_id: row.get(0)?,
                    project_id: row.get(1)?,
                    operation_kind: row.get(2)?,
                    operation: row.get(3)?,
                    queue_sequence: row.get(4)?,
                    attempt: row.get(5)?,
                })
            },
        )
        .optional()?;
    let Some(candidate) = candidate else {
        transaction.commit()?;
        return Ok(None);
    };

    let request_id = RequestId::from(candidate.request_id.clone());
    if candidate.operation_kind == FLOW_OPERATION_KIND {
        validate_flow_authorization_integrity(&transaction, &request_id)?;
    }

    let attempt = candidate
        .attempt
        .checked_add(1)
        .ok_or(StoreError::InvalidState("attempt overflow".to_owned()))?;
    let token = Uuid::new_v4().to_string();
    let changed = transaction.execute(
        "UPDATE requests
         SET state = 'leased', attempt = ?2, lease_owner = ?3,
             lease_token = ?4, lease_expires_at_ms = ?5
         WHERE request_id = ?1 AND state = 'queued'",
        params![candidate.request_id, attempt, owner, token, expires_at],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidState(
            "claim candidate changed state".to_owned(),
        ));
    }
    append_event_tx(&transaction, &request_id, now, "started", &[])?;
    transaction.commit()?;

    Ok(Some(LeasedRequest {
        lease: Lease {
            request_id,
            project_id: ProjectId::from(candidate.project_id),
            owner,
            token,
            attempt: unsigned_integer(attempt)?,
            expires_at_ms,
        },
        queue_sequence: unsigned_integer(candidate.queue_sequence)?,
        operation_kind: candidate.operation_kind,
        operation: candidate.operation,
    }))
}

fn renew(
    connection: &mut Connection,
    mut lease: Lease,
    now_ms: u64,
    lease_duration_ms: u64,
) -> Result<Lease, StoreError> {
    let now = sql_integer(now_ms)?;
    let expires_at_ms = lease_expiry(now_ms, lease_duration_ms)?;
    let expires_at = sql_integer(expires_at_ms)?;
    let changed = connection.execute(
        "UPDATE requests
         SET lease_expires_at_ms = ?5
         WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')
           AND lease_owner = ?2 AND lease_token = ?3
           AND lease_expires_at_ms > ?4",
        params![
            lease.request_id.as_str(),
            lease.owner,
            lease.token,
            now,
            expires_at
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::StaleLease(lease.request_id));
    }
    lease.expires_at_ms = expires_at_ms;
    Ok(lease)
}

fn recover_expired(connection: &mut Connection, now_ms: u64) -> Result<u64, StoreError> {
    let recovered = recover_expired_requests(connection, now_ms)?;
    u64::try_from(recovered.len())
        .map_err(|_| StoreError::InvalidState("recovery count overflow".to_owned()))
}

fn recover_expired_requests(
    connection: &mut Connection,
    now_ms: u64,
) -> Result<Vec<RequestId>, StoreError> {
    recover_leases(connection, now_ms, LeaseRecovery::Expired)
}

fn recover_all_leases(connection: &mut Connection, now_ms: u64) -> Result<u64, StoreError> {
    let recovered = recover_leases(connection, now_ms, LeaseRecovery::All)?;
    u64::try_from(recovered.len())
        .map_err(|_| StoreError::InvalidState("recovery count overflow".to_owned()))
}

#[derive(Clone, Copy)]
enum LeaseRecovery {
    Expired,
    All,
}

fn recover_leases(
    connection: &mut Connection,
    now_ms: u64,
    recovery: LeaseRecovery,
) -> Result<Vec<RequestId>, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let active_leases = active_leases(&transaction, now, recovery)?;

    let mut recovered = Vec::with_capacity(active_leases.len());
    for active in active_leases {
        let changed = match active.state {
            RequestState::Leased => {
                let terminal = validated_terminal_flow_result(
                    &transaction,
                    &RequestId::from(active.request_id.clone()),
                    &active.operation_kind,
                )?;
                let (changed, event_kind) = if let Some(terminal) = terminal.as_ref() {
                    finalize_recovered_terminal_flow(
                        &transaction,
                        &active.request_id,
                        now,
                        recovery,
                        terminal,
                    )?
                } else {
                    (
                        release_lease(&transaction, &active.request_id, now, recovery)?,
                        "lease_expired",
                    )
                };
                if changed == 1 {
                    append_event_tx(
                        &transaction,
                        &RequestId::from(active.request_id.clone()),
                        now,
                        event_kind,
                        &[],
                    )?;
                }
                changed
            }
            RequestState::CancellationRequested => {
                let terminal = recovered_cancellation_flow_result(&transaction, &active)?;
                let (changed, event_kind) = finalize_recovered_cancellation(
                    &transaction,
                    &active.request_id,
                    now,
                    recovery,
                    terminal.as_ref(),
                )?;
                if changed == 1 {
                    append_event_tx(
                        &transaction,
                        &RequestId::from(active.request_id.clone()),
                        now,
                        event_kind,
                        &[],
                    )?;
                }
                changed
            }
            state => {
                return Err(StoreError::InvalidState(format!(
                    "recovery selected {}",
                    state.as_str()
                )));
            }
        };
        if changed == 1 {
            recovered.push(RequestId::from(active.request_id));
        }
    }
    transaction.commit()?;
    Ok(recovered)
}

struct ActiveLease {
    request_id: String,
    state: RequestState,
    operation_kind: String,
}

fn active_leases(
    transaction: &Transaction<'_>,
    now: i64,
    recovery: LeaseRecovery,
) -> Result<Vec<ActiveLease>, StoreError> {
    let stored = match recovery {
        LeaseRecovery::Expired => {
            let mut statement = transaction.prepare(
                "SELECT request_id, state, operation_kind
                 FROM requests
                 WHERE state IN ('leased', 'cancellation_requested')
                   AND lease_expires_at_ms <= ?1
                 ORDER BY accepted_at_ms, rowid",
            )?;
            statement
                .query_map([now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        }
        LeaseRecovery::All => {
            let mut statement = transaction.prepare(
                "SELECT request_id, state, operation_kind
                 FROM requests
                 WHERE state IN ('leased', 'cancellation_requested')
                 ORDER BY accepted_at_ms, rowid",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        }
    };
    stored
        .into_iter()
        .map(|(request_id, state, operation_kind)| {
            Ok(ActiveLease {
                request_id,
                state: parse_state(&state)?,
                operation_kind,
            })
        })
        .collect()
}

#[derive(Clone)]
struct ValidatedTerminalFlowResult {
    terminal: FlowTerminalResult,
    cancellation_override: bool,
}

fn recovered_cancellation_flow_result(
    transaction: &Transaction<'_>,
    active: &ActiveLease,
) -> Result<Option<ValidatedTerminalFlowResult>, StoreError> {
    let request_id = RequestId::from(active.request_id.clone());
    Ok(
        validated_terminal_flow_result(transaction, &request_id, &active.operation_kind)?
            .filter(terminal_may_override_cancellation),
    )
}

fn validated_terminal_flow_result(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    operation_kind: &str,
) -> Result<Option<ValidatedTerminalFlowResult>, StoreError> {
    if operation_kind != FLOW_OPERATION_KIND {
        return Ok(None);
    }
    let Some(stored) = read_flow_checkpoint(transaction, request_id)? else {
        return Ok(None);
    };
    decode_and_validate_flow_checkpoint(transaction, request_id, &stored)?;
    Ok(stored
        .terminal_result
        .map(|terminal| ValidatedTerminalFlowResult {
            terminal,
            cancellation_override: stored.terminal_cancellation_override,
        }))
}

fn terminal_may_override_cancellation(terminal: &ValidatedTerminalFlowResult) -> bool {
    terminal.terminal.outcome == RunOutcome::Cancelled
        || (terminal.terminal.outcome == RunOutcome::Blocked && terminal.cancellation_override)
}

fn finalize_recovered_cancellation(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
    recovery: LeaseRecovery,
    terminal: Option<&ValidatedTerminalFlowResult>,
) -> Result<(usize, &'static str), StoreError> {
    let (state, event_kind, terminal_result) =
        terminal.map_or((RequestState::Cancelled, "cancelled", None), |terminal| {
            let (state, event_kind, _) = terminal_request_resolution(terminal.terminal.outcome);
            (
                state,
                event_kind,
                Some(terminal.terminal.encoded_result.as_slice()),
            )
        });
    let changed = match recovery {
        LeaseRecovery::Expired => transaction.execute(
            "UPDATE requests
             SET state = ?3, lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2,
                 result = COALESCE(?4, result)
             WHERE request_id = ?1 AND state = 'cancellation_requested'
               AND lease_expires_at_ms <= ?2",
            params![request_id, now, state.as_str(), terminal_result],
        )?,
        LeaseRecovery::All => transaction.execute(
            "UPDATE requests
             SET state = ?3, lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2,
                 result = COALESCE(?4, result)
             WHERE request_id = ?1 AND state = 'cancellation_requested'",
            params![request_id, now, state.as_str(), terminal_result],
        )?,
    };
    Ok((changed, event_kind))
}

fn finalize_recovered_terminal_flow(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
    recovery: LeaseRecovery,
    terminal: &ValidatedTerminalFlowResult,
) -> Result<(usize, &'static str), StoreError> {
    let (state, event_kind, _) = terminal_request_resolution(terminal.terminal.outcome);
    let changed = match recovery {
        LeaseRecovery::Expired => transaction.execute(
            "UPDATE requests
             SET state = ?3, lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2, result = ?4
             WHERE request_id = ?1 AND state = 'leased'
               AND lease_expires_at_ms <= ?2",
            params![
                request_id,
                now,
                state.as_str(),
                terminal.terminal.encoded_result.as_slice()
            ],
        )?,
        LeaseRecovery::All => transaction.execute(
            "UPDATE requests
             SET state = ?3, lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?2, result = ?4
             WHERE request_id = ?1 AND state = 'leased'",
            params![
                request_id,
                now,
                state.as_str(),
                terminal.terminal.encoded_result.as_slice()
            ],
        )?,
    };
    Ok((changed, event_kind))
}

fn release_lease(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
    recovery: LeaseRecovery,
) -> Result<usize, StoreError> {
    let changed = match recovery {
        LeaseRecovery::Expired => transaction.execute(
            "UPDATE requests
             SET state = 'queued', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL
             WHERE request_id = ?1 AND state = 'leased'
               AND lease_expires_at_ms <= ?2",
            params![request_id, now],
        )?,
        LeaseRecovery::All => transaction.execute(
            "UPDATE requests
             SET state = 'queued', lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL
             WHERE request_id = ?1 AND state = 'leased'",
            [request_id],
        )?,
    };
    Ok(changed)
}

fn append_leased_event(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
    kind: &str,
    payload: &[u8],
) -> Result<EventRecord, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_live_lease(&transaction, lease, now)?;
    let sequence = append_event_tx(&transaction, &lease.request_id, now, kind, payload)?;
    transaction.commit()?;
    Ok(EventRecord {
        sequence,
        kind: kind.to_owned(),
        payload: payload.to_vec(),
        recorded_at_ms: now_ms,
    })
}

struct StoredFlowCheckpoint {
    definition_digest: Vec<u8>,
    snapshot_bytes: Vec<u8>,
    checkpoint_revision: u64,
    updated_at_ms: u64,
    terminal_result: Option<FlowTerminalResult>,
    terminal_cancellation_override: bool,
}

type FlowPersistenceOutcome = (u64, u64, FlowCheckpointDisposition, Option<EventRecord>);

fn load_flow_checkpoint(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
) -> Result<Option<FlowCheckpoint>, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_live_flow_lease(&transaction, lease, now)?;
    let stored = read_flow_checkpoint(&transaction, &lease.request_id)?;
    let checkpoint = stored
        .map(|stored| decode_and_validate_flow_checkpoint(&transaction, &lease.request_id, &stored))
        .transpose()?;
    transaction.commit()?;
    Ok(checkpoint)
}

fn save_flow_checkpoint(
    connection: &mut Connection,
    save: SaveFlowCheckpoint,
) -> Result<FlowCheckpointSaveOutcome, StoreError> {
    validate_flow_request_identity(&save.lease.request_id, &save.snapshot)?;
    validate_flow_terminal_result(
        &save.snapshot,
        save.transition.as_ref(),
        save.terminal_result.as_ref(),
    )?;
    let snapshot_bytes = encode_snapshot(&save.snapshot)?;
    let encoded_transition = save
        .transition
        .as_ref()
        .map(encode_transition)
        .transpose()?;
    let now = sql_integer(save.updated_at_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let request_state = ensure_live_flow_lease(&transaction, &save.lease, now)?;
    if request_state == RequestState::CancellationRequested
        && matches!(
            save.transition.as_ref().map(RunTransition::kind),
            Some(TransitionKind::EffectStarted { .. })
        )
    {
        return Err(StoreError::FlowEffectStartConflict(
            save.lease.request_id.clone(),
        ));
    }
    let terminal_cancellation_override = terminal_cancellation_override(&save, request_state)?;

    let existing = read_flow_checkpoint(&transaction, &save.lease.request_id)?;
    let (checkpoint_revision, checkpoint_updated_at_ms, disposition, event) =
        persist_flow_checkpoint(
            &transaction,
            &save,
            &snapshot_bytes,
            encoded_transition.as_deref(),
            now,
            existing,
            terminal_cancellation_override,
        )?;

    transaction.commit()?;
    Ok(FlowCheckpointSaveOutcome {
        checkpoint: FlowCheckpoint {
            request_id: save.lease.request_id,
            snapshot: save.snapshot,
            checkpoint_revision,
            updated_at_ms: checkpoint_updated_at_ms,
            terminal_result: save.terminal_result,
        },
        disposition,
        event,
    })
}

fn terminal_cancellation_override(
    save: &SaveFlowCheckpoint,
    request_state: RequestState,
) -> Result<bool, StoreError> {
    let Some(terminal) = save.terminal_result.as_ref() else {
        return Ok(false);
    };
    match (request_state, terminal.outcome) {
        (
            RequestState::Leased,
            RunOutcome::Solved | RunOutcome::Unresolved | RunOutcome::Blocked,
        )
        | (RequestState::CancellationRequested, RunOutcome::Cancelled) => Ok(false),
        (RequestState::CancellationRequested, RunOutcome::Blocked)
            if save.snapshot.cancel_requested()
                && matches!(
                    save.transition.as_ref().map(RunTransition::kind),
                    Some(TransitionKind::ReconciliationUnknown { .. })
                ) =>
        {
            Ok(true)
        }
        _ => Err(StoreError::FlowTerminalOutcomeConflict(
            save.lease.request_id.clone(),
        )),
    }
}

#[allow(clippy::too_many_lines)] // Keep the create/update CAS and exact replay checks together.
fn persist_flow_checkpoint(
    transaction: &Transaction<'_>,
    save: &SaveFlowCheckpoint,
    snapshot_bytes: &[u8],
    transition_bytes: Option<&[u8]>,
    now: i64,
    existing: Option<StoredFlowCheckpoint>,
    terminal_cancellation_override: bool,
) -> Result<FlowPersistenceOutcome, StoreError> {
    match existing {
        None => {
            if save.expected_revision != 0 {
                return Err(StoreError::FlowCheckpointRevisionConflict {
                    request_id: save.lease.request_id.clone(),
                    expected: save.expected_revision,
                    actual: 0,
                });
            }
            validate_flow_successor(None, &save.snapshot, save.transition.as_ref())?;
            insert_flow_checkpoint(
                transaction,
                save,
                snapshot_bytes,
                terminal_cancellation_override,
            )?;
            let event = append_flow_transition(
                transaction,
                &save.lease.request_id,
                now,
                save.transition.as_ref(),
                transition_bytes,
            )?;
            Ok((
                1,
                save.updated_at_ms,
                FlowCheckpointDisposition::Created,
                event,
            ))
        }
        Some(stored) => {
            validate_stored_digest(&save.lease.request_id, &stored, &save.snapshot)?;
            let previous =
                decode_and_validate_flow_checkpoint(transaction, &save.lease.request_id, &stored)?;
            if stored.snapshot_bytes == snapshot_bytes {
                if stored.terminal_result != save.terminal_result
                    || stored.terminal_cancellation_override != terminal_cancellation_override
                {
                    return Err(StoreError::FlowCheckpointConflict(
                        save.lease.request_id.clone(),
                    ));
                }
                let repeats_last_write =
                    save.expected_revision.checked_add(1) == Some(stored.checkpoint_revision);
                if save.expected_revision != stored.checkpoint_revision && !repeats_last_write {
                    return Err(StoreError::FlowCheckpointRevisionConflict {
                        request_id: save.lease.request_id.clone(),
                        expected: save.expected_revision,
                        actual: stored.checkpoint_revision,
                    });
                }
                validate_flow_successor(Some(&previous.snapshot), &save.snapshot, None)?;
                if save.transition.is_some() {
                    validate_transition_alignment(&save.snapshot, save.transition.as_ref())?;
                }
                validate_exact_flow_replay(
                    transaction,
                    &save.lease.request_id,
                    save.transition.as_ref(),
                    transition_bytes,
                )?;
                Ok((
                    stored.checkpoint_revision,
                    stored.updated_at_ms,
                    FlowCheckpointDisposition::Unchanged,
                    None,
                ))
            } else {
                if save.expected_revision != stored.checkpoint_revision {
                    return Err(StoreError::FlowCheckpointRevisionConflict {
                        request_id: save.lease.request_id.clone(),
                        expected: save.expected_revision,
                        actual: stored.checkpoint_revision,
                    });
                }
                if save.transition.is_none()
                    && previous.snapshot.snapshot_version() == 1
                    && save.snapshot.snapshot_version() == pam_flow::FLOW_SNAPSHOT_VERSION
                {
                    if stored.terminal_result != save.terminal_result
                        || stored.terminal_cancellation_override != terminal_cancellation_override
                    {
                        return Err(StoreError::FlowCheckpointConflict(
                            save.lease.request_id.clone(),
                        ));
                    }
                    validate_snapshot_upgrade(&previous.snapshot, &save.snapshot).map_err(
                        |_| {
                            StoreError::InvalidFlowCheckpoint(
                                "legacy snapshot upgrade changed durable flow state",
                            )
                        },
                    )?;
                } else {
                    validate_flow_successor(
                        Some(&previous.snapshot),
                        &save.snapshot,
                        save.transition.as_ref(),
                    )?;
                }
                let revision = save
                    .expected_revision
                    .checked_add(1)
                    .ok_or(StoreError::FlowCheckpointRevisionOverflow)?;
                update_flow_checkpoint(
                    transaction,
                    save,
                    snapshot_bytes,
                    revision,
                    terminal_cancellation_override,
                )?;
                let event = append_flow_transition(
                    transaction,
                    &save.lease.request_id,
                    now,
                    save.transition.as_ref(),
                    transition_bytes,
                )?;
                Ok((
                    revision,
                    save.updated_at_ms,
                    FlowCheckpointDisposition::Updated,
                    event,
                ))
            }
        }
    }
}

fn validate_flow_successor(
    previous: Option<&FlowSnapshot>,
    snapshot: &FlowSnapshot,
    transition: Option<&RunTransition>,
) -> Result<(), StoreError> {
    validate_snapshot_successor(previous, snapshot, transition).map_err(|_| {
        StoreError::InvalidFlowCheckpoint(
            "snapshot and transition do not form a valid semantic successor",
        )
    })
}

fn read_flow_checkpoint(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
) -> Result<Option<StoredFlowCheckpoint>, StoreError> {
    transaction
        .query_row(
            "SELECT definition_digest, snapshot, checkpoint_revision, updated_at_ms,
                    terminal_outcome, terminal_result, terminal_cancellation_override
             FROM flow_runs WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                definition_digest,
                snapshot_bytes,
                checkpoint_revision,
                updated_at_ms,
                terminal_outcome,
                terminal_result,
                terminal_cancellation_override,
            )| {
                Ok(StoredFlowCheckpoint {
                    definition_digest,
                    snapshot_bytes,
                    checkpoint_revision: unsigned_integer(checkpoint_revision)?,
                    updated_at_ms: unsigned_integer(updated_at_ms)?,
                    terminal_result: decode_stored_terminal_result(
                        request_id,
                        terminal_outcome,
                        terminal_result,
                    )?,
                    terminal_cancellation_override,
                })
            },
        )
        .transpose()
}

fn decode_flow_checkpoint(
    request_id: &RequestId,
    stored: &StoredFlowCheckpoint,
) -> Result<FlowCheckpoint, StoreError> {
    if stored.snapshot_bytes.is_empty() || stored.snapshot_bytes.len() > MAX_FLOW_CHECKPOINT_BYTES {
        return Err(StoreError::CorruptFlowCheckpoint(request_id.clone()));
    }
    let snapshot: FlowSnapshot = rmp_serde::from_slice(&stored.snapshot_bytes)
        .map_err(|_| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
    validate_flow_request_identity(request_id, &snapshot)
        .map_err(|_| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
    if stored.definition_digest.as_slice() != snapshot.definition_digest().as_bytes() {
        return Err(StoreError::CorruptFlowCheckpoint(request_id.clone()));
    }
    validate_flow_terminal_result(&snapshot, None, stored.terminal_result.as_ref())
        .map_err(|_| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
    if stored.terminal_cancellation_override
        && (!snapshot.cancel_requested()
            || !matches!(
                stored
                    .terminal_result
                    .as_ref()
                    .map(|terminal| terminal.outcome),
                Some(RunOutcome::Blocked)
            ))
    {
        return Err(StoreError::CorruptFlowCheckpoint(request_id.clone()));
    }
    Ok(FlowCheckpoint {
        request_id: request_id.clone(),
        snapshot,
        checkpoint_revision: stored.checkpoint_revision,
        updated_at_ms: stored.updated_at_ms,
        terminal_result: stored.terminal_result.clone(),
    })
}

fn decode_and_validate_flow_checkpoint(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    stored: &StoredFlowCheckpoint,
) -> Result<FlowCheckpoint, StoreError> {
    let checkpoint = decode_flow_checkpoint(request_id, stored)?;
    if !stored.terminal_cancellation_override {
        return Ok(checkpoint);
    }
    let transition_bytes = transaction
        .query_row(
            "SELECT payload FROM events
             WHERE request_id = ?1 AND kind = 'flow_reconciliation_unknown'
             ORDER BY sequence DESC LIMIT 1",
            [request_id.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
    let transition: RunTransition = rmp_serde::from_slice(&transition_bytes)
        .map_err(|_| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
    if transition.sequence() != checkpoint.snapshot.transition_sequence()
        || !matches!(
            transition.kind(),
            TransitionKind::ReconciliationUnknown { .. }
        )
    {
        return Err(StoreError::CorruptFlowCheckpoint(request_id.clone()));
    }
    Ok(checkpoint)
}

fn encode_snapshot(snapshot: &FlowSnapshot) -> Result<Vec<u8>, StoreError> {
    let bytes = rmp_serde::to_vec_named(snapshot)
        .map_err(|_| StoreError::InvalidFlowCheckpoint("snapshot cannot be encoded"))?;
    if bytes.is_empty() || bytes.len() > MAX_FLOW_CHECKPOINT_BYTES {
        return Err(StoreError::FlowCheckpointTooLarge {
            size_bytes: bytes.len(),
            maximum_bytes: MAX_FLOW_CHECKPOINT_BYTES,
        });
    }
    let decoded: FlowSnapshot = rmp_serde::from_slice(&bytes)
        .map_err(|_| StoreError::InvalidFlowCheckpoint("snapshot cannot be decoded"))?;
    if decoded != *snapshot {
        return Err(StoreError::InvalidFlowCheckpoint(
            "snapshot encoding is not lossless",
        ));
    }
    Ok(bytes)
}

fn encode_transition(transition: &RunTransition) -> Result<Vec<u8>, StoreError> {
    let bytes = rmp_serde::to_vec_named(transition)
        .map_err(|_| StoreError::InvalidFlowCheckpoint("transition cannot be encoded"))?;
    if bytes.is_empty() || bytes.len() > MAX_FLOW_TRANSITION_BYTES {
        return Err(StoreError::FlowTransitionTooLarge {
            size_bytes: bytes.len(),
            maximum_bytes: MAX_FLOW_TRANSITION_BYTES,
        });
    }
    let decoded: RunTransition = rmp_serde::from_slice(&bytes)
        .map_err(|_| StoreError::InvalidFlowCheckpoint("transition cannot be decoded"))?;
    if decoded != *transition {
        return Err(StoreError::InvalidFlowCheckpoint(
            "transition encoding is not lossless",
        ));
    }
    Ok(bytes)
}

fn validate_flow_terminal_result(
    snapshot: &FlowSnapshot,
    transition: Option<&RunTransition>,
    terminal_result: Option<&FlowTerminalResult>,
) -> Result<(), StoreError> {
    let snapshot_outcome = terminal_outcome_for_status(snapshot.status());
    match (snapshot_outcome, terminal_result) {
        (Some(expected), Some(terminal)) if expected == terminal.outcome => {
            if terminal.encoded_result.is_empty() {
                return Err(StoreError::InvalidFlowCheckpoint(
                    "terminal result cannot be empty",
                ));
            }
            if terminal.encoded_result.len() > MAX_FLOW_TERMINAL_RESULT_BYTES {
                return Err(StoreError::FlowTerminalResultTooLarge {
                    size_bytes: terminal.encoded_result.len(),
                    maximum_bytes: MAX_FLOW_TERMINAL_RESULT_BYTES,
                });
            }
        }
        (Some(_), Some(_)) => {
            return Err(StoreError::InvalidFlowCheckpoint(
                "terminal result outcome does not match snapshot status",
            ));
        }
        (Some(_), None) => {
            return Err(StoreError::InvalidFlowCheckpoint(
                "terminal snapshot requires its encoded result",
            ));
        }
        (None, Some(_)) => {
            return Err(StoreError::InvalidFlowCheckpoint(
                "non-terminal snapshot cannot cache a terminal result",
            ));
        }
        (None, None) => {}
    }

    if let Some(transition) = transition {
        match (transition.kind(), terminal_result) {
            (TransitionKind::RunCompleted { outcome }, Some(terminal))
                if *outcome == terminal.outcome => {}
            (TransitionKind::RunCompleted { .. }, _) => {
                return Err(StoreError::InvalidFlowCheckpoint(
                    "run completion and terminal result outcomes do not match",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

const fn terminal_outcome_for_status(status: RunStatus) -> Option<RunOutcome> {
    match status {
        RunStatus::Succeeded => Some(RunOutcome::Solved),
        RunStatus::Unresolved => Some(RunOutcome::Unresolved),
        RunStatus::Blocked => Some(RunOutcome::Blocked),
        RunStatus::Cancelled => Some(RunOutcome::Cancelled),
        RunStatus::Running
        | RunStatus::WaitingApproval
        | RunStatus::WaitingRetry
        | RunStatus::AwaitingEffectEvaluation
        | RunStatus::EffectInFlight
        | RunStatus::Cancelling => None,
    }
}

const fn flow_outcome_name(outcome: RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Solved => "solved",
        RunOutcome::Unresolved => "unresolved",
        RunOutcome::Blocked => "blocked",
        RunOutcome::Cancelled => "cancelled",
    }
}

fn parse_flow_outcome(value: &str) -> Option<RunOutcome> {
    match value {
        "solved" => Some(RunOutcome::Solved),
        "unresolved" => Some(RunOutcome::Unresolved),
        "blocked" => Some(RunOutcome::Blocked),
        "cancelled" => Some(RunOutcome::Cancelled),
        _ => None,
    }
}

fn decode_stored_terminal_result(
    request_id: &RequestId,
    outcome: Option<String>,
    result: Option<Vec<u8>>,
) -> Result<Option<FlowTerminalResult>, StoreError> {
    match (outcome, result) {
        (None, None) => Ok(None),
        (Some(outcome), Some(encoded_result)) => {
            let outcome = parse_flow_outcome(&outcome)
                .ok_or_else(|| StoreError::CorruptFlowCheckpoint(request_id.clone()))?;
            Ok(Some(FlowTerminalResult {
                outcome,
                encoded_result,
            }))
        }
        _ => Err(StoreError::CorruptFlowCheckpoint(request_id.clone())),
    }
}

fn validate_flow_request_identity(
    request_id: &RequestId,
    snapshot: &FlowSnapshot,
) -> Result<(), StoreError> {
    if snapshot.run_id().as_str() == request_id.as_str() {
        Ok(())
    } else {
        Err(StoreError::FlowCheckpointRequestMismatch(
            request_id.clone(),
        ))
    }
}

fn validate_transition_alignment(
    snapshot: &FlowSnapshot,
    transition: Option<&RunTransition>,
) -> Result<(), StoreError> {
    match transition {
        Some(transition) if transition.sequence() == snapshot.transition_sequence() => Ok(()),
        Some(_) => Err(StoreError::InvalidFlowCheckpoint(
            "transition sequence does not match snapshot",
        )),
        None if snapshot.transition_sequence() == 0 => Ok(()),
        None => Err(StoreError::InvalidFlowCheckpoint(
            "non-initial snapshot requires its transition",
        )),
    }
}

fn validate_stored_digest(
    request_id: &RequestId,
    stored: &StoredFlowCheckpoint,
    snapshot: &FlowSnapshot,
) -> Result<(), StoreError> {
    if stored.definition_digest.as_slice() == snapshot.definition_digest().as_bytes() {
        Ok(())
    } else {
        Err(StoreError::FlowDefinitionDigestMismatch(request_id.clone()))
    }
}

fn insert_flow_checkpoint(
    transaction: &Transaction<'_>,
    save: &SaveFlowCheckpoint,
    snapshot_bytes: &[u8],
    terminal_cancellation_override: bool,
) -> Result<(), StoreError> {
    let terminal_outcome = save
        .terminal_result
        .as_ref()
        .map(|terminal| flow_outcome_name(terminal.outcome));
    let terminal_result = save
        .terminal_result
        .as_ref()
        .map(|terminal| terminal.encoded_result.as_slice());
    transaction.execute(
        "INSERT INTO flow_runs(
             request_id, definition_digest, snapshot, checkpoint_revision, updated_at_ms,
             terminal_outcome, terminal_result, terminal_cancellation_override
         ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
        params![
            save.lease.request_id.as_str(),
            save.snapshot.definition_digest().as_bytes().as_slice(),
            snapshot_bytes,
            sql_integer(save.updated_at_ms)?,
            terminal_outcome,
            terminal_result,
            terminal_cancellation_override,
        ],
    )?;
    Ok(())
}

fn update_flow_checkpoint(
    transaction: &Transaction<'_>,
    save: &SaveFlowCheckpoint,
    snapshot_bytes: &[u8],
    revision: u64,
    terminal_cancellation_override: bool,
) -> Result<(), StoreError> {
    let terminal_outcome = save
        .terminal_result
        .as_ref()
        .map(|terminal| flow_outcome_name(terminal.outcome));
    let terminal_result = save
        .terminal_result
        .as_ref()
        .map(|terminal| terminal.encoded_result.as_slice());
    let changed = transaction.execute(
        "UPDATE flow_runs
         SET snapshot = ?3, checkpoint_revision = ?4, updated_at_ms = ?5,
             terminal_outcome = ?7, terminal_result = ?8,
             terminal_cancellation_override = ?9
         WHERE request_id = ?1 AND definition_digest = ?2 AND checkpoint_revision = ?6",
        params![
            save.lease.request_id.as_str(),
            save.snapshot.definition_digest().as_bytes().as_slice(),
            snapshot_bytes,
            sql_integer(revision)?,
            sql_integer(save.updated_at_ms)?,
            sql_integer(save.expected_revision)?,
            terminal_outcome,
            terminal_result,
            terminal_cancellation_override,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::FlowCheckpointConflict(
            save.lease.request_id.clone(),
        ))
    }
}

fn append_flow_transition(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    now: i64,
    transition: Option<&RunTransition>,
    transition_bytes: Option<&[u8]>,
) -> Result<Option<EventRecord>, StoreError> {
    let Some(transition) = transition else {
        return Ok(None);
    };
    let payload = transition_bytes.ok_or(StoreError::InvalidFlowCheckpoint(
        "transition bytes are missing",
    ))?;
    let kind = flow_event_kind(transition.kind());
    let sequence = append_event_tx(transaction, request_id, now, kind, payload)?;
    Ok(Some(EventRecord {
        sequence,
        kind: kind.to_owned(),
        payload: payload.to_vec(),
        recorded_at_ms: unsigned_integer(now)?,
    }))
}

fn validate_exact_flow_replay(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    transition: Option<&RunTransition>,
    transition_bytes: Option<&[u8]>,
) -> Result<(), StoreError> {
    let Some(transition) = transition else {
        return Ok(());
    };
    let payload = transition_bytes.ok_or(StoreError::InvalidFlowCheckpoint(
        "transition bytes are missing",
    ))?;
    let exists = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM events WHERE request_id = ?1 AND kind = ?2 AND payload = ?3
         )",
        params![
            request_id.as_str(),
            flow_event_kind(transition.kind()),
            payload
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::FlowCheckpointConflict(request_id.clone()))
    }
}

const fn flow_event_kind(kind: &TransitionKind) -> &'static str {
    match kind {
        TransitionKind::StepSkipped { .. } => "flow_step_skipped",
        TransitionKind::ApprovalRequested { .. } => "flow_approval_required",
        TransitionKind::ApprovalGranted { .. } => "flow_approval_granted",
        TransitionKind::ApprovalDenied { .. } => "flow_approval_denied",
        TransitionKind::EffectEvaluationRequired { .. } => "flow_effect_evaluation_required",
        TransitionKind::EffectStarted { .. } => "flow_effect_started",
        TransitionKind::EffectAuthorizationDenied { .. } => "flow_effect_authorization_denied",
        TransitionKind::EffectSucceeded { .. } => "flow_effect_succeeded",
        TransitionKind::RetryScheduled { .. } => "flow_retry_scheduled",
        TransitionKind::RetryExhausted { .. } => "flow_retry_exhausted",
        TransitionKind::EffectFailed { .. } => "flow_effect_failed",
        TransitionKind::ReconciledNotApplied { .. } => "flow_reconciled_not_applied",
        TransitionKind::ReconciliationUnknown { .. } => "flow_reconciliation_unknown",
        TransitionKind::CancellationRequested => "flow_cancellation_requested",
        TransitionKind::RunCompleted { .. } => "flow_completed",
    }
}

fn finish(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
    terminal_state: TerminalState,
    result: &[u8],
) -> Result<StoredResult, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let live = transaction
        .query_row(
            "SELECT state, result
             FROM requests
             WHERE request_id = ?1
               AND state IN ('leased', 'cancellation_requested')
               AND lease_owner = ?2 AND lease_token = ?3
               AND lease_expires_at_ms > ?4",
            params![lease.request_id.as_str(), lease.owner, lease.token, now],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::StaleLease(lease.request_id.clone()))?;
    let active_state = parse_state(&live.0)?;
    let (state, payload, event_kind, changed) = match (active_state, live.1) {
        (RequestState::Leased, None) if terminal_state == TerminalState::Cancelled => {
            return Err(StoreError::InvalidState(
                "a leased request cannot finish cancelled without a durable cancellation request"
                    .to_owned(),
            ));
        }
        (RequestState::Leased, None) => {
            let state = terminal_state.request_state();
            let changed = transaction.execute(
                "UPDATE requests
                 SET state = ?5, lease_owner = NULL, lease_token = NULL,
                     lease_expires_at_ms = NULL, completed_at_ms = ?4, result = ?6
                 WHERE request_id = ?1 AND state = 'leased'
                   AND lease_owner = ?2 AND lease_token = ?3
                   AND lease_expires_at_ms > ?4",
                params![
                    lease.request_id.as_str(),
                    lease.owner,
                    lease.token,
                    now,
                    state.as_str(),
                    result
                ],
            )?;
            (state, result.to_vec(), terminal_state.event_kind(), changed)
        }
        (RequestState::CancellationRequested, Some(cancellation_result)) => {
            let changed = transaction.execute(
                "UPDATE requests
                 SET state = 'cancelled', lease_owner = NULL, lease_token = NULL,
                     lease_expires_at_ms = NULL, completed_at_ms = ?4
                 WHERE request_id = ?1 AND state = 'cancellation_requested'
                   AND lease_owner = ?2 AND lease_token = ?3
                   AND lease_expires_at_ms > ?4",
                params![lease.request_id.as_str(), lease.owner, lease.token, now],
            )?;
            (
                RequestState::Cancelled,
                cancellation_result,
                "cancelled",
                changed,
            )
        }
        (state, _) => {
            return Err(StoreError::InvalidState(format!(
                "active request has {} result shape",
                state.as_str()
            )));
        }
    };
    if changed != 1 {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    append_event_tx(&transaction, &lease.request_id, now, event_kind, &[])?;
    transaction.commit()?;

    Ok(StoredResult {
        state,
        payload,
        completed_at_ms: now_ms,
    })
}

fn fail_corrupt_flow_authorization(
    connection: &mut Connection,
    request_id: &RequestId,
    now_ms: u64,
    result: &[u8],
) -> Result<FlowAuthorizationRecoveryOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = transaction
        .query_row(
            "SELECT state, operation_kind, result, completed_at_ms
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    if stored.1 != FLOW_OPERATION_KIND {
        return Err(StoreError::InvalidState(
            "corrupt flow authorization recovery requires a flow request".to_owned(),
        ));
    }
    let state = parse_state(&stored.0)?;
    if matches!(
        state,
        RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled
    ) {
        let (Some(payload), Some(completed_at)) = (stored.2, stored.3) else {
            return Err(StoreError::InvalidState(
                "terminal corrupt flow recovery omitted its result".to_owned(),
            ));
        };
        transaction.commit()?;
        return Ok(FlowAuthorizationRecoveryOutcome::AlreadyTerminal(
            StoredResult {
                state,
                payload,
                completed_at_ms: unsigned_integer(completed_at)?,
            },
        ));
    }
    if state != RequestState::Queued {
        transaction.commit()?;
        return Ok(FlowAuthorizationRecoveryOutcome::NoLongerEligible);
    }
    match validate_flow_authorization_integrity(&transaction, request_id) {
        Err(StoreError::CorruptFlowAuthorization(corrupt)) if corrupt == *request_id => {}
        Err(error) => return Err(error),
        Ok(_) => {
            transaction.commit()?;
            return Ok(FlowAuthorizationRecoveryOutcome::NoLongerEligible);
        }
    }
    let changed = transaction.execute(
        "UPDATE requests
         SET state = 'failed', completed_at_ms = ?2, result = ?3,
             lease_owner = NULL, lease_token = NULL, lease_expires_at_ms = NULL
         WHERE request_id = ?1 AND state = 'queued' AND operation_kind = 'flow_run'",
        params![request_id.as_str(), now, result],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidState(
            "corrupt flow authorization recovery lost its queued state".to_owned(),
        ));
    }
    append_event_tx(&transaction, request_id, now, "failed", &[])?;
    transaction.commit()?;
    Ok(FlowAuthorizationRecoveryOutcome::Failed(StoredResult {
        state: RequestState::Failed,
        payload: result.to_vec(),
        completed_at_ms: now_ms,
    }))
}

fn finish_terminal_flow(
    connection: &mut Connection,
    lease: &Lease,
    now_ms: u64,
    terminal_result: &[u8],
) -> Result<StoredResult, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let live = transaction
        .query_row(
            "SELECT state, result, operation_kind
             FROM requests
             WHERE request_id = ?1
               AND state IN ('leased', 'cancellation_requested')
               AND lease_owner = ?2 AND lease_token = ?3
               AND lease_expires_at_ms > ?4",
            params![lease.request_id.as_str(), lease.owner, lease.token, now],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::StaleLease(lease.request_id.clone()))?;
    let request_state = parse_state(&live.0)?;
    if live.2 != FLOW_OPERATION_KIND {
        return Err(StoreError::InvalidState(
            "terminal flow completion requires a flow request".to_owned(),
        ));
    }
    let cached = validated_terminal_flow_result(&transaction, &lease.request_id, &live.2)?
        .ok_or_else(|| StoreError::InvalidState("flow has no terminal checkpoint".to_owned()))?;
    let state_allows_outcome = request_state == RequestState::Leased
        || (request_state == RequestState::CancellationRequested
            && terminal_may_override_cancellation(&cached));
    if !state_allows_outcome
        || (request_state == RequestState::CancellationRequested && live.1.is_none())
        || cached.terminal.encoded_result.as_slice() != terminal_result
    {
        return Err(StoreError::InvalidState(
            "flow completion does not match its terminal checkpoint or request state".to_owned(),
        ));
    }
    let (state, event_kind, _) = terminal_request_resolution(cached.terminal.outcome);

    let changed = transaction.execute(
        "UPDATE requests
         SET state = ?5, lease_owner = NULL, lease_token = NULL,
             lease_expires_at_ms = NULL, completed_at_ms = ?4, result = ?7
         WHERE request_id = ?1 AND state = ?6
           AND lease_owner = ?2 AND lease_token = ?3
           AND lease_expires_at_ms > ?4",
        params![
            lease.request_id.as_str(),
            lease.owner,
            lease.token,
            now,
            state.as_str(),
            request_state.as_str(),
            terminal_result,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::StaleLease(lease.request_id.clone()));
    }
    append_event_tx(&transaction, &lease.request_id, now, event_kind, &[])?;
    transaction.commit()?;

    Ok(StoredResult {
        state,
        payload: terminal_result.to_vec(),
        completed_at_ms: now_ms,
    })
}

fn cancel(
    connection: &mut Connection,
    request_id: &RequestId,
    now_ms: u64,
    result: &[u8],
    expected_target_kind: Option<ExpectedOperationKind>,
) -> Result<CancelOutcome, StoreError> {
    let now = sql_integer(now_ms)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored = transaction
        .query_row(
            "SELECT state, operation_kind FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    ensure_expected_target_kind(request_id, &stored.1, expected_target_kind)?;
    let state = parse_state(&stored.0)?;
    if matches!(
        state,
        RequestState::Leased | RequestState::CancellationRequested
    ) && let Some(terminal) =
        validated_terminal_flow_result(&transaction, request_id, &stored.1)?
        && (state == RequestState::Leased || terminal_may_override_cancellation(&terminal))
    {
        let (terminal_state, event_kind, outcome) =
            terminal_request_resolution(terminal.terminal.outcome);
        let changed = transaction.execute(
            "UPDATE requests
             SET state = ?2, lease_owner = NULL, lease_token = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?3, result = ?4
             WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')",
            params![
                request_id.as_str(),
                terminal_state.as_str(),
                now,
                terminal.terminal.encoded_result
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::InvalidState(
                "terminal flow cancellation race changed no request".to_owned(),
            ));
        }
        append_event_tx(&transaction, request_id, now, event_kind, &[])?;
        transaction.commit()?;
        return Ok(outcome);
    }
    let (changed, event_kind, outcome) = match state {
        RequestState::Queued => (
            transaction.execute(
                "UPDATE requests
                 SET state = 'cancelled', completed_at_ms = ?2, result = ?3
                 WHERE request_id = ?1 AND state = 'queued'",
                params![request_id.as_str(), now, result],
            )?,
            "cancelled",
            CancelOutcome::Cancelled,
        ),
        RequestState::Leased => (
            transaction.execute(
                "UPDATE requests
                 SET state = 'cancellation_requested', result = ?2
                 WHERE request_id = ?1 AND state = 'leased'",
                params![request_id.as_str(), result],
            )?,
            "cancellation_requested",
            CancelOutcome::CancellationRequested,
        ),
        RequestState::CancellationRequested => {
            return Ok(CancelOutcome::AlreadyRequested);
        }
        RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled => {
            return Ok(CancelOutcome::AlreadyTerminal(state));
        }
    };
    if changed != 1 {
        return Err(StoreError::InvalidState(
            "cancellation transition changed no request".to_owned(),
        ));
    }
    append_event_tx(&transaction, request_id, now, event_kind, &[])?;
    transaction.commit()?;
    Ok(outcome)
}

const fn terminal_request_resolution(
    outcome: RunOutcome,
) -> (RequestState, &'static str, CancelOutcome) {
    match outcome {
        RunOutcome::Solved => (
            RequestState::Succeeded,
            "completed",
            CancelOutcome::AlreadyTerminal(RequestState::Succeeded),
        ),
        RunOutcome::Unresolved | RunOutcome::Blocked => (
            RequestState::Failed,
            "failed",
            CancelOutcome::AlreadyTerminal(RequestState::Failed),
        ),
        RunOutcome::Cancelled => (
            RequestState::Cancelled,
            "cancelled",
            CancelOutcome::Cancelled,
        ),
    }
}

fn replay(
    connection: &Connection,
    request_id: &RequestId,
    after_sequence: u64,
    expected_target_kind: Option<ExpectedOperationKind>,
) -> Result<Replay, StoreError> {
    let stored = connection
        .query_row(
            "SELECT state, result, completed_at_ms, operation_kind
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    ensure_expected_target_kind(request_id, &stored.3, expected_target_kind)?;
    let state = parse_state(&stored.0)?;
    let result = match (state, stored.1, stored.2) {
        (
            RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled,
            Some(payload),
            Some(completed_at_ms),
        ) => Some(StoredResult {
            state,
            payload,
            completed_at_ms: unsigned_integer(completed_at_ms)?,
        }),
        (RequestState::Queued | RequestState::Leased, None, None)
        | (RequestState::CancellationRequested, Some(_), None) => None,
        _ => {
            return Err(StoreError::InvalidState(
                "result does not match request state".to_owned(),
            ));
        }
    };

    let after = sql_integer(after_sequence)?;
    let mut statement = connection.prepare(
        "SELECT sequence, kind, payload, recorded_at_ms
         FROM events
         WHERE request_id = ?1 AND sequence > ?2
         ORDER BY sequence",
    )?;
    let events = statement
        .query_map(params![request_id.as_str(), after], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .map(|event| {
            let (sequence, kind, payload, recorded_at_ms) = event?;
            Ok(EventRecord {
                sequence: unsigned_integer(sequence)?,
                kind,
                payload,
                recorded_at_ms: unsigned_integer(recorded_at_ms)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(Replay { events, result })
}

fn snapshot(
    connection: &Connection,
    request_id: &RequestId,
    expected_target_kind: Option<ExpectedOperationKind>,
) -> Result<RequestSnapshot, StoreError> {
    let stored = connection
        .query_row(
            "SELECT project_id, queue_sequence, state, attempt, lease_expires_at_ms,
                    operation_kind
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    ensure_expected_target_kind(request_id, &stored.5, expected_target_kind)?;

    Ok(RequestSnapshot {
        request_id: request_id.clone(),
        project_id: ProjectId::from(stored.0),
        queue_sequence: unsigned_integer(stored.1)?,
        state: parse_state(&stored.2)?,
        attempt: unsigned_integer(stored.3)?,
        lease_expires_at_ms: stored.4.map(unsigned_integer).transpose()?,
    })
}

fn ensure_expected_target_kind(
    request_id: &RequestId,
    operation_kind: &str,
    expected_target_kind: Option<ExpectedOperationKind>,
) -> Result<(), StoreError> {
    let matches = match expected_target_kind {
        None => true,
        Some(ExpectedOperationKind::FlowRun) => operation_kind == FLOW_OPERATION_KIND,
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::RequestNotFound(request_id.clone()))
    }
}

fn queued_behind(connection: &mut Connection, request_id: &RequestId) -> Result<u64, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let position = transaction
        .query_row(
            "SELECT project_id, queue_sequence
             FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::RequestNotFound(request_id.clone()))?;
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*)
         FROM requests
         WHERE project_id = ?1 AND queue_sequence > ?2 AND state = 'queued'",
        params![position.0, position.1],
        |row| row.get(0),
    )?;
    transaction.commit()?;
    unsigned_integer(count)
}

fn project_workload(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<ProjectWorkload, StoreError> {
    let (queued, active): (i64, bool) = connection.query_row(
        "SELECT
             COUNT(*) FILTER (WHERE state = 'queued'),
             EXISTS(
                 SELECT 1
                 FROM requests AS active
                 WHERE active.project_id = ?1
                   AND active.operation_kind NOT IN (?2, ?3)
                   AND active.state IN ('leased', 'cancellation_requested')
             )
         FROM requests
         WHERE project_id = ?1 AND operation_kind NOT IN (?2, ?3)",
        params![
            project_id.as_str(),
            STATUS_OPERATION_KIND,
            LEGACY_STATUS_OPERATION_KIND
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(ProjectWorkload {
        queued: unsigned_integer(queued)?,
        active,
    })
}

fn project_current(
    connection: &mut Connection,
    project_id: &ProjectId,
) -> Result<ProjectCurrent, StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let mut queued = {
        let mut statement = transaction.prepare(
            "SELECT request_id, operation_kind, state, queue_sequence,
                    accepted_at_ms, completed_at_ms
             FROM requests
             WHERE project_id = ?1 AND operation_kind NOT IN (?2, ?3)
               AND state = 'queued'
             ORDER BY queue_sequence ASC, request_id ASC
             LIMIT 65",
        )?;
        statement
            .query_map(
                params![
                    project_id.as_str(),
                    STATUS_OPERATION_KIND,
                    LEGACY_STATUS_OPERATION_KIND
                ],
                project_request_row,
            )?
            .map(|row| decode_project_request(row?))
            .collect::<Result<Vec<_>, StoreError>>()?
    };
    let queued_truncated = queued.len() > MAX_PROJECT_CURRENT_QUEUED;
    queued.truncate(MAX_PROJECT_CURRENT_QUEUED);

    let active = transaction
        .query_row(
            "SELECT request_id, operation_kind, state, queue_sequence,
                    accepted_at_ms, completed_at_ms
             FROM requests
             WHERE project_id = ?1 AND operation_kind NOT IN (?2, ?3)
               AND state IN ('leased', 'cancellation_requested')
             ORDER BY queue_sequence ASC, request_id ASC
             LIMIT 1",
            params![
                project_id.as_str(),
                STATUS_OPERATION_KIND,
                LEGACY_STATUS_OPERATION_KIND
            ],
            project_request_row,
        )
        .optional()?
        .map(decode_project_request)
        .transpose()?;
    let latest_terminal = transaction
        .query_row(
            "SELECT request_id, operation_kind, state, queue_sequence,
                    accepted_at_ms, completed_at_ms
             FROM requests
             WHERE project_id = ?1 AND operation_kind NOT IN (?2, ?3)
               AND state IN ('succeeded', 'failed', 'cancelled')
             ORDER BY completed_at_ms DESC, queue_sequence DESC, request_id DESC
             LIMIT 1",
            params![
                project_id.as_str(),
                STATUS_OPERATION_KIND,
                LEGACY_STATUS_OPERATION_KIND
            ],
            project_request_row,
        )
        .optional()?
        .map(decode_project_request)
        .transpose()?;
    transaction.commit()?;

    Ok(ProjectCurrent {
        queued,
        queued_truncated,
        active,
        latest_terminal,
    })
}

type ProjectRequestRow = (String, String, String, i64, i64, Option<i64>);

fn project_request_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRequestRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_project_request(row: ProjectRequestRow) -> Result<ProjectRequestSummary, StoreError> {
    let (request_id, operation_kind, state, queue_sequence, accepted_at_ms, completed_at_ms) = row;
    let state = parse_state(&state)?;
    let completed_at_ms = completed_at_ms.map(unsigned_integer).transpose()?;
    match (state, completed_at_ms) {
        (
            RequestState::Queued | RequestState::Leased | RequestState::CancellationRequested,
            None,
        )
        | (RequestState::Succeeded | RequestState::Failed | RequestState::Cancelled, Some(_)) => {}
        _ => {
            return Err(StoreError::InvalidState(
                "request summary completion does not match state".to_owned(),
            ));
        }
    }
    Ok(ProjectRequestSummary {
        request_id: RequestId::from(request_id),
        operation_kind,
        state,
        queue_sequence: unsigned_integer(queue_sequence)?,
        accepted_at_ms: unsigned_integer(accepted_at_ms)?,
        completed_at_ms,
    })
}

fn ensure_live_lease(
    transaction: &Transaction<'_>,
    lease: &Lease,
    now: i64,
) -> Result<(), StoreError> {
    let live = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM requests
            WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')
              AND lease_owner = ?2 AND lease_token = ?3
              AND lease_expires_at_ms > ?4
         )",
        params![lease.request_id.as_str(), lease.owner, lease.token, now],
        |row| row.get::<_, bool>(0),
    )?;
    if live {
        Ok(())
    } else {
        Err(StoreError::StaleLease(lease.request_id.clone()))
    }
}

fn ensure_live_flow_lease(
    transaction: &Transaction<'_>,
    lease: &Lease,
    now: i64,
) -> Result<RequestState, StoreError> {
    let live = transaction
        .query_row(
            "SELECT state, operation_kind
             FROM requests
             WHERE request_id = ?1 AND state IN ('leased', 'cancellation_requested')
               AND lease_owner = ?2 AND lease_token = ?3
               AND lease_expires_at_ms > ?4",
            params![lease.request_id.as_str(), lease.owner, lease.token, now],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::StaleLease(lease.request_id.clone()))?;
    if live.1 != FLOW_OPERATION_KIND {
        return Err(StoreError::InvalidState(
            "flow checkpoint requires a flow request".to_owned(),
        ));
    }
    parse_state(&live.0)
}

fn append_event_tx(
    transaction: &Transaction<'_>,
    request_id: &RequestId,
    recorded_at_ms: i64,
    kind: &str,
    payload: &[u8],
) -> Result<u64, StoreError> {
    let sequence: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1
         FROM events WHERE request_id = ?1",
        [request_id.as_str()],
        |row| row.get(0),
    )?;
    transaction.execute(
        "INSERT INTO events(request_id, sequence, kind, payload, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![request_id.as_str(), sequence, kind, payload, recorded_at_ms],
    )?;
    unsigned_integer(sequence)
}

fn parse_state(state: &str) -> Result<RequestState, StoreError> {
    match state {
        "queued" => Ok(RequestState::Queued),
        "leased" => Ok(RequestState::Leased),
        "cancellation_requested" => Ok(RequestState::CancellationRequested),
        "succeeded" => Ok(RequestState::Succeeded),
        "failed" => Ok(RequestState::Failed),
        "cancelled" => Ok(RequestState::Cancelled),
        _ => Err(StoreError::InvalidState(state.to_owned())),
    }
}

pub(super) fn sql_integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::TimestampOutOfRange(value))
}

pub(super) fn unsigned_integer(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::InvalidState(format!("negative integer {value}")))
}

fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn lease_expiry(now_ms: u64, duration_ms: u64) -> Result<u64, StoreError> {
    if duration_ms == 0 {
        return Err(StoreError::LeaseDurationZero);
    }
    now_ms
        .checked_add(duration_ms)
        .ok_or(StoreError::LeaseExpiryOverflow)
}

#[cfg(test)]
pub(super) fn migration_versions() -> Vec<u32> {
    MIGRATIONS.iter().map(|(version, _)| *version).collect()
}

#[cfg(test)]
pub(super) fn busy_timeout_ms() -> u64 {
    u64::try_from(BUSY_TIMEOUT.as_millis()).expect("busy timeout fits u64")
}

#[cfg(test)]
pub(super) fn database_path(name: &str) -> (PathBuf, PathBuf) {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NONCE: AtomicU64 = AtomicU64::new(0);
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "pam-store-{name}-{}-{clock}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let path = directory.join("pam.sqlite3");
    (directory, path)
}
