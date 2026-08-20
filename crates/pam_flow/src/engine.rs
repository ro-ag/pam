use std::{collections::HashSet, error::Error, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    ApprovalMode, EffectKind, FlowDefinition, FlowDigest, FlowValidationError,
    MAX_OUTCOME_EVIDENCE_HANDLES, OutcomeTemplate, StepCondition, StepSemanticRole,
};

pub const FLOW_SNAPSHOT_VERSION: u16 = 2;
pub const MAX_RUN_ID_BYTES: usize = 128;
pub const MAX_EFFECT_SUMMARY_BYTES: usize = 4_096;
pub const MAX_EVIDENCE_HANDLES: usize = 4;
pub const MAX_EVIDENCE_HANDLE_BYTES: usize = 256;
pub const MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION: usize = 3;

/// A validated caller-supplied identity for one durable run.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RunId(String);

impl RunId {
    /// Parses an opaque, log-safe run identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is empty, oversized, secret-like, or
    /// contains characters outside the portable identity alphabet.
    pub fn parse(value: impl Into<String>) -> Result<Self, FlowEngineError> {
        let value = value.into();
        validate_engine_identity("run_id", &value, MAX_RUN_ID_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for RunId {
    type Error = FlowEngineError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<RunId> for String {
    fn from(value: RunId) -> Self {
        value.0
    }
}

/// Stable per-step idempotency identity, independent of retry attempt.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct IdempotencyIdentity([u8; 32]);

impl IdempotencyIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for IdempotencyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, "sha256:", &self.0)
    }
}

impl fmt::Debug for IdempotencyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "IdempotencyIdentity({self})")
    }
}

/// Exact non-secret token which binds an approval to one step effect.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ApprovalToken([u8; 32]);

impl ApprovalToken {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ApprovalToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, "approval:", &self.0)
    }
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ApprovalToken({self})")
    }
}

/// A validated evidence reference. It is a handle, never inline evidence.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct EvidenceHandle(String);

impl EvidenceHandle {
    /// Parses a bounded, terminal-safe evidence handle.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or secret-like values.
    pub fn parse(value: impl Into<String>) -> Result<Self, FlowEngineError> {
        let value = value.into();
        validate_engine_identity("evidence_handle", &value, MAX_EVIDENCE_HANDLE_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EvidenceHandle {
    type Error = FlowEngineError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<EvidenceHandle> for String {
    fn from(value: EvidenceHandle) -> Self {
        value.0
    }
}

/// Bounded effect output retained by the state machine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, try_from = "RawEffectReport")]
pub struct EffectReport {
    summary: String,
    #[serde(default)]
    evidence: Vec<EvidenceHandle>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEffectReport {
    summary: String,
    #[serde(default)]
    evidence: Vec<EvidenceHandle>,
}

impl TryFrom<RawEffectReport> for EffectReport {
    type Error = FlowEngineError;

    fn try_from(value: RawEffectReport) -> Result<Self, Self::Error> {
        Self::new(value.summary, value.evidence)
    }
}

impl EffectReport {
    /// Creates a secret-safe report from compact text and evidence handles.
    ///
    /// # Errors
    ///
    /// Returns an error when either bound or safety policy is violated.
    pub fn new(
        summary: impl Into<String>,
        evidence: Vec<EvidenceHandle>,
    ) -> Result<Self, FlowEngineError> {
        let report = Self {
            summary: summary.into(),
            evidence,
        };
        report.validate("effect_report")?;
        Ok(report)
    }

    fn trusted(summary: &str) -> Self {
        Self {
            summary: summary.to_owned(),
            evidence: Vec::new(),
        }
    }

    fn validate(&self, path: &str) -> Result<(), FlowEngineError> {
        validate_engine_text(
            &format!("{path}.summary"),
            &self.summary,
            MAX_EFFECT_SUMMARY_BYTES,
        )?;
        if self.evidence.len() > MAX_EVIDENCE_HANDLES {
            return engine_invalid(
                format!("{path}.evidence"),
                format!("must contain at most {MAX_EVIDENCE_HANDLES} handles"),
            );
        }
        for (index, handle) in self.evidence.iter().enumerate() {
            validate_engine_identity(
                &format!("{path}.evidence[{index}]"),
                handle.as_str(),
                MAX_EVIDENCE_HANDLE_BYTES,
            )?;
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceHandle] {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectResultKind {
    Succeeded,
    Failed { retryable: bool },
}

/// A validated result for one exact effect attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, try_from = "RawEffectResult")]
pub struct EffectResult {
    kind: EffectResultKind,
    report: EffectReport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEffectResult {
    kind: EffectResultKind,
    report: EffectReport,
}

impl TryFrom<RawEffectResult> for EffectResult {
    type Error = FlowEngineError;

    fn try_from(value: RawEffectResult) -> Result<Self, Self::Error> {
        value.report.validate("effect_result.report")?;
        Ok(Self {
            kind: value.kind,
            report: value.report,
        })
    }
}

impl EffectResult {
    /// Creates a successful effect result.
    ///
    /// # Errors
    ///
    /// Returns an error if the report is unsafe or exceeds its bounds.
    pub fn succeeded(
        summary: impl Into<String>,
        evidence: Vec<EvidenceHandle>,
    ) -> Result<Self, FlowEngineError> {
        Ok(Self {
            kind: EffectResultKind::Succeeded,
            report: EffectReport::new(summary, evidence)?,
        })
    }

    /// Creates a failed effect result.
    ///
    /// # Errors
    ///
    /// Returns an error if the report is unsafe or exceeds its bounds.
    pub fn failed(
        summary: impl Into<String>,
        retryable: bool,
        evidence: Vec<EvidenceHandle>,
    ) -> Result<Self, FlowEngineError> {
        Ok(Self {
            kind: EffectResultKind::Failed { retryable },
            report: EffectReport::new(summary, evidence)?,
        })
    }

    fn validate(&self, path: &str) -> Result<(), FlowEngineError> {
        self.report.validate(&format!("{path}.report"))
    }

    #[must_use]
    pub const fn kind(&self) -> EffectResultKind {
        self.kind
    }

    #[must_use]
    pub const fn report(&self) -> &EffectReport {
        &self.report
    }
}

/// The exact effect attempt passed across the persistence/executor boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAttempt {
    step_index: usize,
    step_id: String,
    attempt: u8,
    idempotency_identity: IdempotencyIdentity,
    effect: EffectKind,
    timeout_seconds: u32,
}

impl EffectAttempt {
    #[must_use]
    pub const fn step_index(&self) -> usize {
        self.step_index
    }

    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    #[must_use]
    pub const fn idempotency_identity(&self) -> IdempotencyIdentity {
        self.idempotency_identity
    }

    #[must_use]
    pub const fn effect(&self) -> EffectKind {
        self.effect
    }

    /// Executor-owned deadline budget from the validated definition.
    #[must_use]
    pub const fn timeout_seconds(&self) -> u32 {
        self.timeout_seconds
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// Result of reconciling an uncertain in-flight stateful effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReconciliationResult {
    NotApplied,
    Completed(EffectResult),
    Unknown(EffectReport),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    WaitingApproval,
    WaitingRetry,
    AwaitingEffectEvaluation,
    EffectInFlight,
    Cancelling,
    Succeeded,
    Unresolved,
    Blocked,
    Cancelled,
}

impl RunStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Unresolved | Self::Blocked | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StepApprovalState {
    NotRequired,
    NotRequested,
    Pending { token: ApprovalToken },
    Granted { token: ApprovalToken },
    Denied { token: ApprovalToken },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum StepState {
    Pending,
    AwaitingEffect {
        attempt: u8,
    },
    InFlight {
        attempt: u8,
        started_at_ms: u64,
    },
    WaitingRetry {
        next_attempt: u8,
        not_before_ms: u64,
    },
    Succeeded {
        attempt: u8,
    },
    Skipped,
    Failed {
        attempt: u8,
    },
    Blocked,
    Cancelled,
}

impl StepState {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded { .. }
                | Self::Skipped
                | Self::Failed { .. }
                | Self::Blocked
                | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedEffectResult {
    attempt: u8,
    result: EffectResult,
}

/// Serializable state for one declared flow step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepSnapshot {
    id: String,
    idempotency_identity: IdempotencyIdentity,
    #[serde(default)]
    semantic_role: StepSemanticRole,
    approval: StepApprovalState,
    state: StepState,
    results: Vec<RecordedEffectResult>,
    blocked_report: Option<EffectReport>,
}

impl StepSnapshot {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn idempotency_identity(&self) -> IdempotencyIdentity {
        self.idempotency_identity
    }

    #[must_use]
    pub const fn semantic_role(&self) -> StepSemanticRole {
        self.semantic_role
    }

    #[must_use]
    pub const fn approval(&self) -> &StepApprovalState {
        &self.approval
    }

    #[must_use]
    pub const fn state(&self) -> &StepState {
        &self.state
    }

    #[must_use]
    pub fn results(&self) -> impl ExactSizeIterator<Item = (u8, &EffectResult)> {
        self.results
            .iter()
            .map(|record| (record.attempt, &record.result))
    }

    #[must_use]
    pub const fn blocked_report(&self) -> Option<&EffectReport> {
        self.blocked_report.as_ref()
    }
}

/// Complete durable engine state. Store this with the emitted transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSnapshot {
    snapshot_version: u16,
    run_id: RunId,
    definition_digest: FlowDigest,
    status: RunStatus,
    cancel_requested: bool,
    transition_sequence: u64,
    steps: Vec<StepSnapshot>,
}

impl FlowSnapshot {
    #[must_use]
    pub const fn snapshot_version(&self) -> u16 {
        self.snapshot_version
    }

    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    #[must_use]
    pub const fn definition_digest(&self) -> FlowDigest {
        self.definition_digest
    }

    #[must_use]
    pub const fn status(&self) -> RunStatus {
        self.status
    }

    #[must_use]
    pub const fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    #[must_use]
    pub const fn transition_sequence(&self) -> u64 {
        self.transition_sequence
    }

    #[must_use]
    pub fn steps(&self) -> &[StepSnapshot] {
        &self.steps
    }
}

/// Proves that a candidate snapshot is an exact structural successor.
///
/// This validation deliberately does not require a [`FlowDefinition`]. The
/// immutable run identity, definition digest, step identities, bounded result
/// history, and every transition-owned mutation are all present in the two
/// snapshots. Definition-dependent scheduling policy remains the engine's
/// responsibility when producing the update.
///
/// `None` as the previous snapshot permits only the exact sequence-zero run
/// shape emitted by [`FlowRun::start`], with no transition. With a previous
/// snapshot, an absent transition permits only an exact idempotent replay;
/// otherwise the candidate must advance exactly one sequence and match the
/// supplied transition field-for-field.
///
/// # Errors
///
/// Returns an error for an invalid initial shape, changed immutable identity,
/// invalid sequence, missing or unexpected mutation, or a transition whose
/// kind and data do not exactly explain the candidate snapshot.
pub fn validate_snapshot_successor(
    previous: Option<&FlowSnapshot>,
    candidate: &FlowSnapshot,
    transition: Option<&RunTransition>,
) -> Result<(), FlowEngineError> {
    validate_standalone_snapshot(candidate)?;
    let Some(previous) = previous else {
        if transition.is_some()
            || candidate.transition_sequence != 0
            || candidate.status != RunStatus::Running
            || candidate.cancel_requested
            || candidate.steps.is_empty()
            || candidate.steps.iter().any(|step| {
                !matches!(step.state, StepState::Pending)
                    || !matches!(
                        step.approval,
                        StepApprovalState::NotRequired | StepApprovalState::NotRequested
                    )
                    || !step.results.is_empty()
                    || step.blocked_report.is_some()
            })
        {
            return Err(FlowEngineError::InvalidInitialSnapshot);
        }
        return Ok(());
    };

    validate_standalone_snapshot(previous)?;
    validate_successor_identity(previous, candidate)?;
    let Some(transition) = transition else {
        return if previous == candidate {
            Ok(())
        } else {
            Err(FlowEngineError::SnapshotTransitionMismatch)
        };
    };
    let expected_sequence = previous
        .transition_sequence
        .checked_add(1)
        .ok_or(FlowEngineError::TransitionSequenceOverflow)?;
    if candidate.transition_sequence != expected_sequence
        || transition.sequence != expected_sequence
    {
        return Err(FlowEngineError::SnapshotSequenceMismatch);
    }
    validate_transition_successor(previous, candidate, transition)
}

/// Proves that a legacy snapshot was upgraded without changing run state.
///
/// Snapshot version one did not persist semantic roles. The engine restores
/// those roles from the digest-bound definition before asking the Store to
/// replace the checkpoint. This validator permits exactly that one-time,
/// transition-free rewrite: all durable state must remain byte-for-byte
/// equivalent apart from the snapshot version and the newly materialized
/// observation/change roles. Version-one flows cannot claim verification.
///
/// # Errors
///
/// Returns an error unless `candidate` is the exact version-two materialization
/// of `previous` with no state, result, sequence, or identity mutation.
pub fn validate_snapshot_upgrade(
    previous: &FlowSnapshot,
    candidate: &FlowSnapshot,
) -> Result<(), FlowEngineError> {
    if previous.snapshot_version != 1 || candidate.snapshot_version != FLOW_SNAPSHOT_VERSION {
        return Err(FlowEngineError::SnapshotIdentityMismatch);
    }
    if previous.steps.len() != candidate.steps.len()
        || candidate
            .steps
            .iter()
            .any(|step| step.semantic_role == StepSemanticRole::Verify)
    {
        return Err(FlowEngineError::SnapshotShapeMismatch);
    }

    let mut expected = previous.clone();
    expected.snapshot_version = FLOW_SNAPSHOT_VERSION;
    for (stored, upgraded) in expected.steps.iter_mut().zip(&candidate.steps) {
        stored.semantic_role = upgraded.semantic_role;
    }
    validate_standalone_snapshot(candidate)?;
    if expected == *candidate {
        Ok(())
    } else {
        Err(FlowEngineError::SnapshotTransitionMismatch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Solved,
    Unresolved,
    Blocked,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepRunResultKind {
    Succeeded,
    Skipped,
    Failed,
    Blocked,
    Cancelled,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepRunResult {
    step_id: String,
    #[serde(default)]
    semantic_role: StepSemanticRole,
    kind: StepRunResultKind,
    result: Option<EffectResult>,
    blocked_report: Option<EffectReport>,
}

impl StepRunResult {
    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    #[must_use]
    pub const fn kind(&self) -> StepRunResultKind {
        self.kind
    }

    #[must_use]
    pub const fn semantic_role(&self) -> StepSemanticRole {
        self.semantic_role
    }

    #[must_use]
    pub const fn result(&self) -> Option<&EffectResult> {
        self.result.as_ref()
    }

    #[must_use]
    pub const fn blocked_report(&self) -> Option<&EffectReport> {
        self.blocked_report.as_ref()
    }

    /// The compact report which explains this terminal step, if one exists.
    #[must_use]
    pub fn report(&self) -> Option<&EffectReport> {
        self.blocked_report
            .as_ref()
            .or_else(|| self.result.as_ref().map(EffectResult::report))
    }
}

/// One explicit field of the terminal flow outcome contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FlowOutcomeSection {
    summary: String,
    satisfied: bool,
    step_ids: Vec<String>,
    evidence: Vec<EvidenceHandle>,
    evidence_truncated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFlowOutcomeSection {
    summary: String,
    satisfied: bool,
    step_ids: Vec<String>,
    evidence: Vec<EvidenceHandle>,
    evidence_truncated: bool,
}

impl TryFrom<RawFlowOutcomeSection> for FlowOutcomeSection {
    type Error = FlowEngineError;

    fn try_from(raw: RawFlowOutcomeSection) -> Result<Self, Self::Error> {
        validate_engine_text(
            "flow_outcome.summary",
            &raw.summary,
            super::MAX_TEMPLATE_BYTES,
        )?;
        if raw.step_ids.len() > super::MAX_FLOW_STEPS {
            return engine_invalid(
                "flow_outcome.step_ids",
                format!("must contain at most {} step IDs", super::MAX_FLOW_STEPS),
            );
        }
        let mut step_ids = HashSet::with_capacity(raw.step_ids.len());
        for (index, step_id) in raw.step_ids.iter().enumerate() {
            super::validate_slug(
                &format!("flow_outcome.step_ids[{index}]"),
                step_id,
                super::MAX_FLOW_ID_BYTES,
            )?;
            if !step_ids.insert(step_id.as_str()) {
                return engine_invalid(
                    "flow_outcome.step_ids",
                    "must not contain duplicate step IDs",
                );
            }
        }
        if raw.evidence.len() > MAX_OUTCOME_EVIDENCE_HANDLES {
            return engine_invalid(
                "flow_outcome.evidence",
                format!("must contain at most {MAX_OUTCOME_EVIDENCE_HANDLES} handles"),
            );
        }
        Ok(Self {
            summary: raw.summary,
            satisfied: raw.satisfied,
            step_ids: raw.step_ids,
            evidence: raw.evidence,
            evidence_truncated: raw.evidence_truncated,
        })
    }
}

impl<'de> Deserialize<'de> for FlowOutcomeSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawFlowOutcomeSection::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

impl FlowOutcomeSection {
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub const fn satisfied(&self) -> bool {
        self.satisfied
    }

    #[must_use]
    pub fn step_ids(&self) -> &[String] {
        &self.step_ids
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceHandle] {
        &self.evidence
    }

    #[must_use]
    pub const fn evidence_truncated(&self) -> bool {
        self.evidence_truncated
    }
}

/// The five bounded, independently truthful fields of a terminal flow report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowOutcomeReport {
    solved: FlowOutcomeSection,
    changed: FlowOutcomeSection,
    verified: FlowOutcomeSection,
    unresolved: FlowOutcomeSection,
    blocked: FlowOutcomeSection,
}

impl FlowOutcomeReport {
    #[must_use]
    pub const fn solved(&self) -> &FlowOutcomeSection {
        &self.solved
    }

    #[must_use]
    pub const fn changed(&self) -> &FlowOutcomeSection {
        &self.changed
    }

    #[must_use]
    pub const fn verified(&self) -> &FlowOutcomeSection {
        &self.verified
    }

    #[must_use]
    pub const fn unresolved(&self) -> &FlowOutcomeSection {
        &self.unresolved
    }

    #[must_use]
    pub const fn blocked(&self) -> &FlowOutcomeSection {
        &self.blocked
    }
}

/// Compact truthful terminal result assembled only from recorded state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FlowRunResult {
    run_id: RunId,
    definition_digest: FlowDigest,
    outcome: RunOutcome,
    report: Box<FlowOutcomeReport>,
    steps: Vec<StepRunResult>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFlowRunResult {
    run_id: RunId,
    definition_digest: FlowDigest,
    outcome: RunOutcome,
    #[serde(default)]
    report: Option<Box<FlowOutcomeReport>>,
    steps: Vec<StepRunResult>,
}

impl<'de> Deserialize<'de> for FlowRunResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawFlowRunResult::deserialize(deserializer)?;
        validate_terminal_steps(raw.outcome, &raw.steps).map_err(serde::de::Error::custom)?;
        let report = raw
            .report
            .unwrap_or_else(|| Box::new(build_legacy_outcome_report(raw.outcome, &raw.steps)));
        validate_outcome_report(&report, raw.outcome, &raw.steps)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            run_id: raw.run_id,
            definition_digest: raw.definition_digest,
            outcome: raw.outcome,
            report,
            steps: raw.steps,
        })
    }
}

impl FlowRunResult {
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    #[must_use]
    pub const fn definition_digest(&self) -> FlowDigest {
        self.definition_digest
    }

    #[must_use]
    pub const fn outcome(&self) -> RunOutcome {
        self.outcome
    }

    #[must_use]
    pub fn report(&self) -> &FlowOutcomeReport {
        self.report.as_ref()
    }

    #[must_use]
    pub fn steps(&self) -> &[StepRunResult] {
        &self.steps
    }
}

/// External work or wait requested by the deterministic engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RunDecision {
    Continue,
    AwaitApproval {
        step_id: String,
        token: ApprovalToken,
    },
    EvaluateEffect {
        effect: EffectAttempt,
        replay: bool,
    },
    Execute {
        effect: EffectAttempt,
        replay: bool,
    },
    Reconcile {
        effect: EffectAttempt,
    },
    AwaitResult {
        effect: EffectAttempt,
    },
    WaitRetry {
        effect: EffectAttempt,
        not_before_ms: u64,
    },
    Terminal {
        result: FlowRunResult,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowWaitReason {
    Approval,
    EffectResult,
    Retry,
    Reconciliation,
}

/// One bounded user-visible fact carried atomically with an engine transition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowSemanticEvent {
    Waiting {
        step_id: String,
        reason: FlowWaitReason,
        not_before_ms: Option<u64>,
    },
    ApprovalRequired {
        step_id: String,
    },
    EvidenceFound {
        step_id: String,
        evidence: Vec<EvidenceHandle>,
    },
    FixApplied {
        step_id: String,
        report: EffectReport,
    },
    VerificationPassed {
        step_id: String,
        report: EffectReport,
    },
    Unresolved {
        step_id: String,
        report: EffectReport,
    },
    Blocked {
        step_id: String,
        report: EffectReport,
    },
}

impl FlowSemanticEvent {
    #[must_use]
    pub fn step_id(&self) -> &str {
        match self {
            Self::Waiting { step_id, .. }
            | Self::ApprovalRequired { step_id }
            | Self::EvidenceFound { step_id, .. }
            | Self::FixApplied { step_id, .. }
            | Self::VerificationPassed { step_id, .. }
            | Self::Unresolved { step_id, .. }
            | Self::Blocked { step_id, .. } => step_id,
        }
    }

    fn validate(&self, index: usize) -> Result<(), FlowEngineError> {
        super::validate_slug(
            &format!("transition.semantic_events[{index}].step_id"),
            self.step_id(),
            super::MAX_FLOW_ID_BYTES,
        )?;
        match self {
            Self::Waiting {
                reason: FlowWaitReason::Retry,
                not_before_ms: Some(_),
                ..
            }
            | Self::Waiting {
                reason:
                    FlowWaitReason::Approval
                    | FlowWaitReason::EffectResult
                    | FlowWaitReason::Reconciliation,
                not_before_ms: None,
                ..
            }
            | Self::ApprovalRequired { .. } => Ok(()),
            Self::Waiting { .. } => engine_invalid(
                format!("transition.semantic_events[{index}].not_before_ms"),
                "must be present only for a retry wait",
            ),
            Self::EvidenceFound { evidence, .. } => {
                if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_HANDLES {
                    engine_invalid(
                        format!("transition.semantic_events[{index}].evidence"),
                        format!("must contain between 1 and {MAX_EVIDENCE_HANDLES} handles"),
                    )
                } else {
                    Ok(())
                }
            }
            Self::FixApplied { report, .. }
            | Self::VerificationPassed { report, .. }
            | Self::Unresolved { report, .. }
            | Self::Blocked { report, .. } => {
                report.validate(&format!("transition.semantic_events[{index}].report"))
            }
        }
    }
}

/// Append-only state transition paired with bounded semantic progress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunTransition {
    sequence: u64,
    kind: TransitionKind,
    semantic_events: Vec<FlowSemanticEvent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunTransition {
    sequence: u64,
    kind: TransitionKind,
    #[serde(default)]
    semantic_events: Vec<FlowSemanticEvent>,
}

impl<'de> Deserialize<'de> for RunTransition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRunTransition::deserialize(deserializer)?;
        if raw.semantic_events.len() > MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION {
            return Err(serde::de::Error::custom(format!(
                "flow transition contains more than {MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION} semantic events"
            )));
        }
        for (index, event) in raw.semantic_events.iter().enumerate() {
            event.validate(index).map_err(serde::de::Error::custom)?;
        }
        Ok(Self {
            sequence: raw.sequence,
            kind: raw.kind,
            semantic_events: raw.semantic_events,
        })
    }
}

impl RunTransition {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn kind(&self) -> &TransitionKind {
        &self.kind
    }

    #[must_use]
    pub fn semantic_events(&self) -> &[FlowSemanticEvent] {
        &self.semantic_events
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TransitionKind {
    StepSkipped {
        step_id: String,
    },
    ApprovalRequested {
        step_id: String,
    },
    ApprovalGranted {
        step_id: String,
    },
    ApprovalDenied {
        step_id: String,
    },
    EffectEvaluationRequired {
        step_id: String,
        attempt: u8,
    },
    EffectAuthorizationDenied {
        step_id: String,
        attempt: u8,
        replay: bool,
    },
    EffectStarted {
        step_id: String,
        attempt: u8,
        replay: bool,
    },
    EffectSucceeded {
        step_id: String,
        attempt: u8,
    },
    RetryScheduled {
        step_id: String,
        next_attempt: u8,
        not_before_ms: u64,
    },
    RetryExhausted {
        step_id: String,
        attempt: u8,
    },
    EffectFailed {
        step_id: String,
        attempt: u8,
    },
    ReconciledNotApplied {
        step_id: String,
        attempt: u8,
    },
    ReconciliationUnknown {
        step_id: String,
        attempt: u8,
    },
    CancellationRequested,
    RunCompleted {
        outcome: RunOutcome,
    },
}

/// One engine response. Persist `snapshot` and append `transition` atomically
/// before acting on an `Execute` decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineUpdate {
    snapshot: FlowSnapshot,
    transition: Option<RunTransition>,
    decision: RunDecision,
}

impl EngineUpdate {
    #[must_use]
    pub const fn snapshot(&self) -> &FlowSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn transition(&self) -> Option<&RunTransition> {
        self.transition.as_ref()
    }

    #[must_use]
    pub const fn decision(&self) -> &RunDecision {
        &self.decision
    }

    #[must_use]
    pub fn into_parts(self) -> (FlowSnapshot, Option<RunTransition>, RunDecision) {
        (self.snapshot, self.transition, self.decision)
    }
}

/// Pure deterministic coordinator. It never executes or persists effects.
pub struct FlowRun {
    definition: FlowDefinition,
    snapshot: FlowSnapshot,
    issued_attempt: Option<EffectAttempt>,
}

impl FlowRun {
    /// Starts a new flow run from a validated definition.
    ///
    /// # Errors
    ///
    /// Returns an error if the definition is invalid.
    pub fn start(run_id: RunId, definition: FlowDefinition) -> Result<Self, FlowEngineError> {
        definition.validate()?;
        validate_engine_identity("run_id", run_id.as_str(), MAX_RUN_ID_BYTES)?;
        let definition_digest = definition.normalized_digest()?;
        let steps = definition
            .steps()
            .iter()
            .map(|step| StepSnapshot {
                id: step.id().to_owned(),
                idempotency_identity: idempotency_identity(
                    &run_id,
                    definition_digest,
                    step.id(),
                    step.idempotency_key(),
                ),
                semantic_role: step.semantic_role(),
                approval: match step.approval() {
                    ApprovalMode::None => StepApprovalState::NotRequired,
                    ApprovalMode::Required => StepApprovalState::NotRequested,
                },
                state: StepState::Pending,
                results: Vec::new(),
                blocked_report: None,
            })
            .collect();
        Ok(Self {
            definition,
            snapshot: FlowSnapshot {
                snapshot_version: FLOW_SNAPSHOT_VERSION,
                run_id,
                definition_digest,
                status: RunStatus::Running,
                cancel_requested: false,
                transition_sequence: 0,
                steps,
            },
            issued_attempt: None,
        })
    }

    /// Restores a run after validating its run identity, definition digest, and
    /// every state invariant.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched or malformed snapshots.
    pub fn resume(
        expected_run_id: &RunId,
        definition: FlowDefinition,
        mut snapshot: FlowSnapshot,
    ) -> Result<Self, FlowEngineError> {
        definition.validate()?;
        if snapshot.run_id != *expected_run_id {
            return Err(FlowEngineError::RunIdMismatch);
        }
        let digest = definition.normalized_digest()?;
        if snapshot.definition_digest != digest {
            return Err(FlowEngineError::DefinitionDigestMismatch);
        }
        if snapshot.snapshot_version == 1 {
            if snapshot.steps.len() != definition.steps().len() {
                return Err(FlowEngineError::SnapshotShapeMismatch);
            }
            for (stored, declared) in snapshot.steps.iter_mut().zip(definition.steps()) {
                stored.semantic_role = declared.semantic_role();
            }
            snapshot.snapshot_version = FLOW_SNAPSHOT_VERSION;
        }
        validate_snapshot(&definition, &snapshot)?;
        Ok(Self {
            definition,
            snapshot,
            issued_attempt: None,
        })
    }

    #[must_use]
    pub const fn definition(&self) -> &FlowDefinition {
        &self.definition
    }

    #[must_use]
    pub const fn snapshot(&self) -> &FlowSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub const fn status(&self) -> RunStatus {
        self.snapshot.status
    }

    #[must_use]
    pub fn result(&self) -> Option<FlowRunResult> {
        self.snapshot
            .status
            .is_terminal()
            .then(|| self.build_result())
    }

    /// Advances scheduling by one deterministic persisted transition.
    ///
    /// The caller should loop on `Continue`. An `EvaluateEffect` decision is a
    /// mandatory policy/effect re-evaluation boundary; call [`Self::prepare_effect`]
    /// only after that evaluation succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if the transition sequence overflows or the restored
    /// state cannot be scheduled.
    pub fn next_decision(&mut self, now_ms: u64) -> Result<EngineUpdate, FlowEngineError> {
        if self.snapshot.status.is_terminal() {
            return Ok(self.observed(RunDecision::Terminal {
                result: self.build_result(),
            }));
        }

        if self.snapshot.cancel_requested {
            if let Some(effect) = self.in_flight_effect() {
                if effect.effect == EffectKind::ReadOnly {
                    return self.finish_cancelled();
                }
                return Ok(self.observed(RunDecision::Reconcile { effect }));
            }
            return self.finish_cancelled();
        }

        if let Some((index, state)) = self
            .snapshot
            .steps
            .iter()
            .enumerate()
            .find(|(_, step)| {
                !matches!(step.state, StepState::Pending) && !step.state.is_terminal()
            })
            .map(|(index, step)| (index, step.state))
        {
            return self.decision_for_active(index, state, now_ms);
        }

        for index in 0..self.snapshot.steps.len() {
            if !matches!(self.snapshot.steps[index].state, StepState::Pending)
                || !self.prerequisites_complete(index)
            {
                continue;
            }
            if !self.condition_is_true(index) {
                self.ensure_can_change()?;
                self.snapshot.steps[index].state = StepState::Skipped;
                let step_id = self.snapshot.steps[index].id.clone();
                return self.changed(
                    TransitionKind::StepSkipped { step_id },
                    RunDecision::Continue,
                );
            }
            return self.schedule_step(index, 1);
        }

        if self
            .snapshot
            .steps
            .iter()
            .all(|step| step.state.is_terminal())
        {
            self.ensure_can_change()?;
            let outcome = if self
                .snapshot
                .steps
                .iter()
                .any(|step| matches!(step.state, StepState::Failed { .. }))
            {
                RunOutcome::Unresolved
            } else {
                RunOutcome::Solved
            };
            self.snapshot.status = match outcome {
                RunOutcome::Solved => RunStatus::Succeeded,
                RunOutcome::Unresolved => RunStatus::Unresolved,
                RunOutcome::Blocked | RunOutcome::Cancelled => unreachable!(),
            };
            return self.changed(
                TransitionKind::RunCompleted { outcome },
                RunDecision::Terminal {
                    result: self.build_result(),
                },
            );
        }

        Err(FlowEngineError::SchedulerStalled)
    }

    /// Resolves the one pending approval using its exact token.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/wrong token or when no approval is pending.
    pub fn resolve_approval(
        &mut self,
        token: ApprovalToken,
        decision: ApprovalDecision,
    ) -> Result<EngineUpdate, FlowEngineError> {
        let Some(index) = self.snapshot.steps.iter().position(|step| {
            matches!(step.approval, StepApprovalState::Pending { token: expected } if expected == token)
        }) else {
            if self
                .snapshot
                .steps
                .iter()
                .any(|step| matches!(step.approval, StepApprovalState::Pending { .. }))
            {
                return Err(FlowEngineError::ApprovalTokenMismatch);
            }
            return Err(FlowEngineError::NoApprovalPending);
        };
        let step_id = self.snapshot.steps[index].id.clone();
        self.ensure_can_change()?;
        match decision {
            ApprovalDecision::Approve => {
                self.snapshot.steps[index].approval = StepApprovalState::Granted { token };
                self.snapshot.status = RunStatus::Running;
                self.changed(
                    TransitionKind::ApprovalGranted { step_id },
                    RunDecision::Continue,
                )
            }
            ApprovalDecision::Deny => {
                self.snapshot.steps[index].approval = StepApprovalState::Denied { token };
                self.snapshot.steps[index].state = StepState::Blocked;
                self.snapshot.steps[index].blocked_report = Some(EffectReport::trusted(
                    "the exact effect approval was denied",
                ));
                self.snapshot.status = RunStatus::Blocked;
                self.changed(
                    TransitionKind::ApprovalDenied { step_id },
                    RunDecision::Terminal {
                        result: self.build_result(),
                    },
                )
            }
        }
    }

    /// Commits an effect attempt as in-flight and returns the execution decision.
    ///
    /// The returned snapshot and transition must be durably committed together
    /// before invoking the external executor. Calling this method represents a
    /// successful fresh policy/effect evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale attempt or an unsafe stateful replay.
    pub fn prepare_effect(
        &mut self,
        effect: &EffectAttempt,
        now_ms: u64,
    ) -> Result<EngineUpdate, FlowEngineError> {
        self.validate_effect(effect)?;
        let state = self.snapshot.steps[effect.step_index].state;
        self.ensure_can_change()?;
        let replay = match state {
            StepState::AwaitingEffect { attempt } if attempt == effect.attempt => {
                self.snapshot.steps[effect.step_index].state = StepState::InFlight {
                    attempt,
                    started_at_ms: now_ms,
                };
                false
            }
            StepState::InFlight { attempt, .. }
                if attempt == effect.attempt && effect.effect == EffectKind::ReadOnly =>
            {
                true
            }
            StepState::InFlight { .. } => {
                return Err(FlowEngineError::StatefulReplayRequiresReconcile);
            }
            _ => return Err(FlowEngineError::UnexpectedStepState),
        };
        self.snapshot.status = RunStatus::EffectInFlight;
        self.issued_attempt = Some(effect.clone());
        self.changed(
            TransitionKind::EffectStarted {
                step_id: effect.step_id.clone(),
                attempt: effect.attempt,
                replay,
            },
            RunDecision::Execute {
                effect: effect.clone(),
                replay,
            },
        )
    }

    /// Records that fresh authorization was denied before an effect could execute.
    ///
    /// This terminally blocks the exact evaluated attempt without recording
    /// `EffectStarted` or an effect result. For a resumed read-only in-flight
    /// attempt, `replay` records that authorization prevented re-execution.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale effect identity, cancellation, or a step that
    /// is not awaiting evaluation (including an unrelated in-flight attempt).
    pub fn deny_effect_authorization(
        &mut self,
        effect: &EffectAttempt,
    ) -> Result<EngineUpdate, FlowEngineError> {
        self.validate_effect(effect)?;
        if self.snapshot.cancel_requested {
            return Err(FlowEngineError::UnexpectedStepState);
        }
        let replay = match self.snapshot.steps[effect.step_index].state {
            StepState::AwaitingEffect { attempt }
                if attempt == effect.attempt
                    && self.snapshot.status == RunStatus::AwaitingEffectEvaluation =>
            {
                false
            }
            StepState::InFlight { attempt, .. }
                if attempt == effect.attempt
                    && self.snapshot.status == RunStatus::EffectInFlight
                    && effect.effect == EffectKind::ReadOnly =>
            {
                true
            }
            _ => return Err(FlowEngineError::UnexpectedStepState),
        };
        self.ensure_can_change()?;
        self.snapshot.steps[effect.step_index].state = StepState::Blocked;
        self.snapshot.steps[effect.step_index].blocked_report = Some(EffectReport::trusted(
            "fresh authorization for the exact effect was denied",
        ));
        self.snapshot.status = RunStatus::Blocked;
        self.issued_attempt = None;
        self.changed(
            TransitionKind::EffectAuthorizationDenied {
                step_id: effect.step_id.clone(),
                attempt: effect.attempt,
                replay,
            },
            RunDecision::Terminal {
                result: self.build_result(),
            },
        )
    }

    /// Records one exact effect result, idempotently for identical duplicates.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed output, a stale attempt, a conflicting
    /// duplicate, timestamp overflow, or a non-in-flight step.
    #[allow(clippy::too_many_lines)]
    pub fn record_effect_result(
        &mut self,
        effect: &EffectAttempt,
        result: EffectResult,
        now_ms: u64,
    ) -> Result<EngineUpdate, FlowEngineError> {
        result.validate("effect_result")?;
        self.validate_effect(effect)?;
        let index = effect.step_index;
        if let Some(recorded) = self.snapshot.steps[index]
            .results
            .iter()
            .find(|record| record.attempt == effect.attempt)
        {
            if recorded.result == result {
                return Ok(self.observed(self.decision_for_current_state(index)?));
            }
            return Err(FlowEngineError::ConflictingEffectResult {
                step_id: effect.step_id.clone(),
                attempt: effect.attempt,
            });
        }
        if !matches!(
            self.snapshot.steps[index].state,
            StepState::InFlight { attempt, .. } if attempt == effect.attempt
        ) {
            return Err(FlowEngineError::UnexpectedStepState);
        }

        let result_kind = result.kind;
        let retry_schedule = self.retry_schedule(index, effect, result_kind, now_ms)?;
        self.ensure_can_change()?;
        self.snapshot.steps[index]
            .results
            .push(RecordedEffectResult {
                attempt: effect.attempt,
                result,
            });
        self.issued_attempt = None;

        if self.snapshot.cancel_requested {
            self.snapshot.status = RunStatus::Cancelling;
            let transition = match result_kind {
                EffectResultKind::Succeeded => {
                    self.snapshot.steps[index].state = StepState::Succeeded {
                        attempt: effect.attempt,
                    };
                    TransitionKind::EffectSucceeded {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    }
                }
                EffectResultKind::Failed { .. } => {
                    self.snapshot.steps[index].state = StepState::Failed {
                        attempt: effect.attempt,
                    };
                    TransitionKind::EffectFailed {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    }
                }
            };
            return self.changed(transition, RunDecision::Continue);
        }

        match (result_kind, retry_schedule) {
            (EffectResultKind::Succeeded, _) => {
                self.snapshot.steps[index].state = StepState::Succeeded {
                    attempt: effect.attempt,
                };
                self.snapshot.status = RunStatus::Running;
                self.changed(
                    TransitionKind::EffectSucceeded {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    },
                    RunDecision::Continue,
                )
            }
            (EffectResultKind::Failed { .. }, Some((next_attempt, not_before_ms))) => {
                self.snapshot.steps[index].state = StepState::WaitingRetry {
                    next_attempt,
                    not_before_ms,
                };
                self.snapshot.status = RunStatus::WaitingRetry;
                self.changed(
                    TransitionKind::RetryScheduled {
                        step_id: effect.step_id.clone(),
                        next_attempt,
                        not_before_ms,
                    },
                    RunDecision::WaitRetry {
                        effect: self.effect_attempt(index, next_attempt),
                        not_before_ms,
                    },
                )
            }
            (EffectResultKind::Failed { retryable }, None) => {
                self.snapshot.steps[index].state = StepState::Failed {
                    attempt: effect.attempt,
                };
                self.snapshot.status = RunStatus::Running;
                let transition = if retryable {
                    TransitionKind::RetryExhausted {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    }
                } else {
                    TransitionKind::EffectFailed {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    }
                };
                self.changed(transition, RunDecision::Continue)
            }
        }
    }

    /// Resolves an uncertain stateful in-flight effect without blind replay.
    ///
    /// # Errors
    ///
    /// Returns an error for non-stateful/stale attempts or unsafe reports.
    pub fn record_reconciliation(
        &mut self,
        effect: &EffectAttempt,
        reconciliation: ReconciliationResult,
        now_ms: u64,
    ) -> Result<EngineUpdate, FlowEngineError> {
        self.validate_effect(effect)?;
        if effect.effect != EffectKind::Stateful
            || !matches!(
                self.snapshot.steps[effect.step_index].state,
                StepState::InFlight { attempt, .. } if attempt == effect.attempt
            )
        {
            return Err(FlowEngineError::UnexpectedStepState);
        }
        if !matches!(reconciliation, ReconciliationResult::Completed(_)) {
            self.ensure_can_change()?;
        }
        match reconciliation {
            ReconciliationResult::Completed(result) => {
                self.record_effect_result(effect, result, now_ms)
            }
            ReconciliationResult::NotApplied => {
                if self.snapshot.cancel_requested {
                    return self.finish_cancelled();
                }
                self.snapshot.steps[effect.step_index].state = StepState::AwaitingEffect {
                    attempt: effect.attempt,
                };
                self.snapshot.status = RunStatus::AwaitingEffectEvaluation;
                self.changed(
                    TransitionKind::ReconciledNotApplied {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    },
                    RunDecision::EvaluateEffect {
                        effect: effect.clone(),
                        replay: false,
                    },
                )
            }
            ReconciliationResult::Unknown(report) => {
                report.validate("reconciliation.unknown")?;
                self.snapshot.steps[effect.step_index].state = StepState::Blocked;
                self.snapshot.steps[effect.step_index].blocked_report = Some(report);
                self.snapshot.status = RunStatus::Blocked;
                self.changed(
                    TransitionKind::ReconciliationUnknown {
                        step_id: effect.step_id.clone(),
                        attempt: effect.attempt,
                    },
                    RunDecision::Terminal {
                        result: self.build_result(),
                    },
                )
            }
        }
    }

    /// Requests cancellation. Repeated calls are idempotent. An in-flight
    /// stateful effect remains `Cancelling` until its exact result or
    /// reconciliation is recorded. Read-only work is safely abandoned and late
    /// results must be discarded by the executor because it cannot change state.
    ///
    /// # Errors
    ///
    /// Returns an error only if the transition sequence overflows.
    pub fn cancel(&mut self) -> Result<EngineUpdate, FlowEngineError> {
        if self.snapshot.status.is_terminal() {
            return Ok(self.observed(RunDecision::Terminal {
                result: self.build_result(),
            }));
        }
        if self.snapshot.cancel_requested {
            if let Some(effect) = self.in_flight_effect() {
                if effect.effect == EffectKind::ReadOnly {
                    return self.finish_cancelled();
                }
                return Ok(self.observed(RunDecision::Reconcile { effect }));
            }
            return self.finish_cancelled();
        }
        self.ensure_can_change()?;
        self.snapshot.cancel_requested = true;
        if let Some(effect) = self.in_flight_effect() {
            if effect.effect == EffectKind::ReadOnly {
                return self.finish_cancelled();
            }
            self.snapshot.status = RunStatus::Cancelling;
            return self.changed(
                TransitionKind::CancellationRequested,
                RunDecision::Reconcile { effect },
            );
        }
        self.finish_cancelled()
    }

    fn decision_for_active(
        &mut self,
        index: usize,
        state: StepState,
        now_ms: u64,
    ) -> Result<EngineUpdate, FlowEngineError> {
        match state {
            StepState::AwaitingEffect { attempt } => {
                let effect = self.effect_attempt(index, attempt);
                Ok(self.observed(RunDecision::EvaluateEffect {
                    effect,
                    replay: false,
                }))
            }
            StepState::InFlight { attempt, .. } => {
                let effect = self.effect_attempt(index, attempt);
                if self.issued_attempt.as_ref() == Some(&effect) {
                    Ok(self.observed(RunDecision::AwaitResult { effect }))
                } else if effect.effect == EffectKind::ReadOnly {
                    Ok(self.observed(RunDecision::EvaluateEffect {
                        effect,
                        replay: true,
                    }))
                } else {
                    Ok(self.observed(RunDecision::Reconcile { effect }))
                }
            }
            StepState::WaitingRetry {
                next_attempt,
                not_before_ms,
            } if now_ms < not_before_ms => Ok(self.observed(RunDecision::WaitRetry {
                effect: self.effect_attempt(index, next_attempt),
                not_before_ms,
            })),
            StepState::WaitingRetry { next_attempt, .. } => {
                self.ensure_can_change()?;
                self.snapshot.steps[index].state = StepState::AwaitingEffect {
                    attempt: next_attempt,
                };
                self.snapshot.status = RunStatus::AwaitingEffectEvaluation;
                let effect = self.effect_attempt(index, next_attempt);
                self.changed(
                    TransitionKind::EffectEvaluationRequired {
                        step_id: effect.step_id.clone(),
                        attempt: next_attempt,
                    },
                    RunDecision::EvaluateEffect {
                        effect,
                        replay: false,
                    },
                )
            }
            _ => Err(FlowEngineError::UnexpectedStepState),
        }
    }

    fn schedule_step(
        &mut self,
        index: usize,
        attempt: u8,
    ) -> Result<EngineUpdate, FlowEngineError> {
        self.ensure_can_change()?;
        match self.snapshot.steps[index].approval.clone() {
            StepApprovalState::NotRequested => {
                let token = approval_token(self.snapshot.steps[index].idempotency_identity);
                self.snapshot.steps[index].approval = StepApprovalState::Pending { token };
                self.snapshot.status = RunStatus::WaitingApproval;
                let step_id = self.snapshot.steps[index].id.clone();
                self.changed(
                    TransitionKind::ApprovalRequested {
                        step_id: step_id.clone(),
                    },
                    RunDecision::AwaitApproval { step_id, token },
                )
            }
            StepApprovalState::Pending { token } => Ok(self.observed(RunDecision::AwaitApproval {
                step_id: self.snapshot.steps[index].id.clone(),
                token,
            })),
            StepApprovalState::Denied { .. } => Err(FlowEngineError::UnexpectedStepState),
            StepApprovalState::NotRequired | StepApprovalState::Granted { .. } => {
                self.snapshot.steps[index].state = StepState::AwaitingEffect { attempt };
                self.snapshot.status = RunStatus::AwaitingEffectEvaluation;
                let effect = self.effect_attempt(index, attempt);
                self.changed(
                    TransitionKind::EffectEvaluationRequired {
                        step_id: effect.step_id.clone(),
                        attempt,
                    },
                    RunDecision::EvaluateEffect {
                        effect,
                        replay: false,
                    },
                )
            }
        }
    }

    fn prerequisites_complete(&self, index: usize) -> bool {
        let step = &self.definition.steps()[index];
        step.dependencies()
            .iter()
            .map(String::as_str)
            .chain(step.condition().referenced_step())
            .all(|reference| {
                let referenced = self
                    .definition
                    .steps()
                    .iter()
                    .position(|candidate| candidate.id() == reference)
                    .expect("validated references are present");
                self.snapshot.steps[referenced].state.is_terminal()
            })
    }

    fn condition_is_true(&self, index: usize) -> bool {
        match self.definition.steps()[index].condition() {
            StepCondition::Always => true,
            StepCondition::Succeeded { step } => {
                matches!(self.state_by_id(step), StepState::Succeeded { .. })
            }
            StepCondition::Failed { step } => {
                matches!(self.state_by_id(step), StepState::Failed { .. })
            }
        }
    }

    fn state_by_id(&self, id: &str) -> &StepState {
        let index = self
            .definition
            .steps()
            .iter()
            .position(|step| step.id() == id)
            .expect("validated references are present");
        &self.snapshot.steps[index].state
    }

    fn effect_attempt(&self, index: usize, attempt: u8) -> EffectAttempt {
        EffectAttempt {
            step_index: index,
            step_id: self.snapshot.steps[index].id.clone(),
            attempt,
            idempotency_identity: self.snapshot.steps[index].idempotency_identity,
            effect: self.definition.steps()[index].effect(),
            timeout_seconds: self.definition.steps()[index].timeout_seconds(),
        }
    }

    fn validate_effect(&self, effect: &EffectAttempt) -> Result<(), FlowEngineError> {
        let Some(step) = self.snapshot.steps.get(effect.step_index) else {
            return Err(FlowEngineError::EffectIdentityMismatch);
        };
        if effect.step_id != step.id
            || effect.idempotency_identity != step.idempotency_identity
            || effect.effect != self.definition.steps()[effect.step_index].effect()
            || effect.timeout_seconds
                != self.definition.steps()[effect.step_index].timeout_seconds()
            || effect.attempt == 0
            || effect.attempt
                > self.definition.steps()[effect.step_index]
                    .retry()
                    .max_attempts()
        {
            return Err(FlowEngineError::EffectIdentityMismatch);
        }
        Ok(())
    }

    fn retry_schedule(
        &self,
        index: usize,
        effect: &EffectAttempt,
        result_kind: EffectResultKind,
        now_ms: u64,
    ) -> Result<Option<(u8, u64)>, FlowEngineError> {
        if !matches!(result_kind, EffectResultKind::Failed { retryable: true })
            || self.snapshot.cancel_requested
            || effect.attempt >= self.definition.steps()[index].retry().max_attempts()
        {
            return Ok(None);
        }
        let retry = self.definition.steps()[index].retry();
        let backoff = retry_backoff_ms(
            retry.initial_backoff_ms(),
            retry.max_backoff_ms(),
            effect.attempt,
        );
        let not_before_ms = now_ms
            .checked_add(backoff)
            .ok_or(FlowEngineError::TimestampOverflow)?;
        Ok(Some((effect.attempt + 1, not_before_ms)))
    }

    fn in_flight_effect(&self) -> Option<EffectAttempt> {
        self.snapshot
            .steps
            .iter()
            .enumerate()
            .find_map(|(index, step)| match step.state {
                StepState::InFlight { attempt, .. } => Some(self.effect_attempt(index, attempt)),
                _ => None,
            })
    }

    fn decision_for_current_state(&self, index: usize) -> Result<RunDecision, FlowEngineError> {
        if self.snapshot.status.is_terminal() {
            return Ok(RunDecision::Terminal {
                result: self.build_result(),
            });
        }
        match self.snapshot.steps[index].state {
            StepState::WaitingRetry {
                next_attempt,
                not_before_ms,
            } => Ok(RunDecision::WaitRetry {
                effect: self.effect_attempt(index, next_attempt),
                not_before_ms,
            }),
            StepState::Succeeded { .. }
            | StepState::Failed { .. }
            | StepState::Skipped
            | StepState::Cancelled => Ok(RunDecision::Continue),
            StepState::Blocked if self.snapshot.status == RunStatus::Blocked => {
                Ok(RunDecision::Terminal {
                    result: self.build_result(),
                })
            }
            StepState::AwaitingEffect { attempt } => Ok(RunDecision::EvaluateEffect {
                effect: self.effect_attempt(index, attempt),
                replay: false,
            }),
            StepState::InFlight { attempt, .. } => Ok(RunDecision::AwaitResult {
                effect: self.effect_attempt(index, attempt),
            }),
            _ => Err(FlowEngineError::UnexpectedStepState),
        }
    }

    fn finish_cancelled(&mut self) -> Result<EngineUpdate, FlowEngineError> {
        self.ensure_can_change()?;
        for step in &mut self.snapshot.steps {
            if !step.state.is_terminal() {
                step.state = StepState::Cancelled;
            }
            if matches!(step.approval, StepApprovalState::Pending { .. }) {
                step.approval = StepApprovalState::NotRequested;
            }
        }
        self.snapshot.cancel_requested = true;
        self.snapshot.status = RunStatus::Cancelled;
        self.issued_attempt = None;
        self.changed(
            TransitionKind::RunCompleted {
                outcome: RunOutcome::Cancelled,
            },
            RunDecision::Terminal {
                result: self.build_result(),
            },
        )
    }

    fn build_result(&self) -> FlowRunResult {
        let outcome = match self.snapshot.status {
            RunStatus::Succeeded => RunOutcome::Solved,
            RunStatus::Unresolved => RunOutcome::Unresolved,
            RunStatus::Blocked => RunOutcome::Blocked,
            RunStatus::Cancelled => RunOutcome::Cancelled,
            _ => {
                if self
                    .snapshot
                    .steps
                    .iter()
                    .any(|step| matches!(step.state, StepState::Blocked))
                {
                    RunOutcome::Blocked
                } else if self.snapshot.cancel_requested {
                    RunOutcome::Cancelled
                } else if self
                    .snapshot
                    .steps
                    .iter()
                    .any(|step| matches!(step.state, StepState::Failed { .. }))
                {
                    RunOutcome::Unresolved
                } else {
                    RunOutcome::Solved
                }
            }
        };
        let steps = self
            .snapshot
            .steps
            .iter()
            .map(|step| StepRunResult {
                step_id: step.id.clone(),
                semantic_role: step.semantic_role,
                kind: match step.state {
                    StepState::Succeeded { .. } => StepRunResultKind::Succeeded,
                    StepState::Skipped => StepRunResultKind::Skipped,
                    StepState::Failed { .. } => StepRunResultKind::Failed,
                    StepState::Blocked => StepRunResultKind::Blocked,
                    StepState::Cancelled => StepRunResultKind::Cancelled,
                    StepState::Pending
                    | StepState::AwaitingEffect { .. }
                    | StepState::InFlight { .. }
                    | StepState::WaitingRetry { .. } => StepRunResultKind::NotRun,
                },
                result: step.results.last().map(|record| record.result.clone()),
                blocked_report: step.blocked_report.clone(),
            })
            .collect::<Vec<_>>();
        let report = build_outcome_report(self.definition.outcome(), outcome, &steps);
        FlowRunResult {
            run_id: self.snapshot.run_id.clone(),
            definition_digest: self.snapshot.definition_digest,
            outcome,
            report: Box::new(report),
            steps,
        }
    }

    fn changed(
        &mut self,
        kind: TransitionKind,
        decision: RunDecision,
    ) -> Result<EngineUpdate, FlowEngineError> {
        let sequence = self
            .snapshot
            .transition_sequence
            .checked_add(1)
            .ok_or(FlowEngineError::TransitionSequenceOverflow)?;
        self.snapshot.transition_sequence = sequence;
        let semantic_events = semantic_events_for_transition(&self.snapshot, &kind)?;
        Ok(EngineUpdate {
            snapshot: self.snapshot.clone(),
            transition: Some(RunTransition {
                sequence,
                kind,
                semantic_events,
            }),
            decision,
        })
    }

    fn ensure_can_change(&self) -> Result<(), FlowEngineError> {
        if self.snapshot.transition_sequence == u64::MAX {
            Err(FlowEngineError::TransitionSequenceOverflow)
        } else {
            Ok(())
        }
    }

    fn observed(&self, decision: RunDecision) -> EngineUpdate {
        EngineUpdate {
            snapshot: self.snapshot.clone(),
            transition: None,
            decision,
        }
    }
}

fn build_outcome_report(
    template: &OutcomeTemplate,
    outcome: RunOutcome,
    steps: &[StepRunResult],
) -> FlowOutcomeReport {
    let solved = outcome == RunOutcome::Solved;
    FlowOutcomeReport {
        solved: build_outcome_section(template.solved(), solved, steps, |step| {
            solved && step.kind == StepRunResultKind::Succeeded
        }),
        changed: build_outcome_section(
            template.changed(),
            steps.iter().any(|step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Change
            }),
            steps,
            |step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Change
            },
        ),
        verified: build_outcome_section(
            template.verified(),
            steps.iter().any(|step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Verify
            }),
            steps,
            |step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Verify
            },
        ),
        unresolved: build_outcome_section(
            template.unresolved(),
            outcome == RunOutcome::Unresolved,
            steps,
            |step| step.kind == StepRunResultKind::Failed,
        ),
        blocked: build_outcome_section(
            template.blocked(),
            outcome == RunOutcome::Blocked,
            steps,
            |step| step.kind == StepRunResultKind::Blocked,
        ),
    }
}

fn build_legacy_outcome_report(outcome: RunOutcome, steps: &[StepRunResult]) -> FlowOutcomeReport {
    let solved = outcome == RunOutcome::Solved;
    FlowOutcomeReport {
        solved: build_outcome_section("Flow work completed successfully.", solved, steps, |step| {
            solved && step.kind == StepRunResultKind::Succeeded
        }),
        changed: build_outcome_section(
            "State changes completed by the flow.",
            false,
            steps,
            |_| false,
        ),
        verified: build_outcome_section(
            "Verification checks completed by the flow.",
            false,
            steps,
            |_| false,
        ),
        unresolved: build_outcome_section(
            "Work that remains unresolved.",
            outcome == RunOutcome::Unresolved,
            steps,
            |step| step.kind == StepRunResultKind::Failed,
        ),
        blocked: build_outcome_section(
            "Work stopped at an explicit boundary.",
            outcome == RunOutcome::Blocked,
            steps,
            |step| step.kind == StepRunResultKind::Blocked,
        ),
    }
}

fn validate_terminal_steps(
    outcome: RunOutcome,
    steps: &[StepRunResult],
) -> Result<(), FlowEngineError> {
    if steps.is_empty() || steps.len() > super::MAX_FLOW_STEPS {
        return engine_invalid(
            "flow_result.steps",
            format!("must contain between 1 and {} steps", super::MAX_FLOW_STEPS),
        );
    }
    let mut ids = HashSet::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        super::validate_slug(
            &format!("flow_result.steps[{index}].step_id"),
            &step.step_id,
            super::MAX_FLOW_ID_BYTES,
        )?;
        if !ids.insert(step.step_id.as_str()) {
            return engine_invalid("flow_result.steps", "must not contain duplicate step IDs");
        }
        let shape_valid = match step.kind {
            StepRunResultKind::Succeeded => step.result.as_ref().is_some_and(|result| {
                result.kind == EffectResultKind::Succeeded && step.blocked_report.is_none()
            }),
            StepRunResultKind::Failed => step.result.as_ref().is_some_and(|result| {
                matches!(result.kind, EffectResultKind::Failed { .. })
                    && step.blocked_report.is_none()
            }),
            StepRunResultKind::Blocked => step.result.is_none() && step.blocked_report.is_some(),
            StepRunResultKind::Cancelled => {
                step.blocked_report.is_none()
                    && step
                        .result
                        .as_ref()
                        .is_none_or(|result| matches!(result.kind, EffectResultKind::Failed { .. }))
            }
            StepRunResultKind::Skipped | StepRunResultKind::NotRun => {
                step.result.is_none() && step.blocked_report.is_none()
            }
        };
        if !shape_valid {
            return engine_invalid(
                format!("flow_result.steps[{index}]"),
                "terminal kind does not match its report",
            );
        }
    }
    let outcome_valid = match outcome {
        RunOutcome::Solved => steps.iter().all(|step| {
            matches!(
                step.kind,
                StepRunResultKind::Succeeded | StepRunResultKind::Skipped
            )
        }),
        RunOutcome::Unresolved => {
            steps
                .iter()
                .any(|step| step.kind == StepRunResultKind::Failed)
                && steps.iter().all(|step| {
                    !matches!(
                        step.kind,
                        StepRunResultKind::Blocked
                            | StepRunResultKind::Cancelled
                            | StepRunResultKind::NotRun
                    )
                })
        }
        RunOutcome::Blocked => {
            steps
                .iter()
                .any(|step| step.kind == StepRunResultKind::Blocked)
                && steps
                    .iter()
                    .all(|step| step.kind != StepRunResultKind::Cancelled)
        }
        RunOutcome::Cancelled => steps.iter().all(|step| {
            !matches!(
                step.kind,
                StepRunResultKind::Blocked | StepRunResultKind::NotRun
            )
        }),
    };
    if outcome_valid {
        Ok(())
    } else {
        engine_invalid(
            "flow_result.outcome",
            "does not match its terminal step results",
        )
    }
}

fn validate_outcome_report(
    report: &FlowOutcomeReport,
    outcome: RunOutcome,
    steps: &[StepRunResult],
) -> Result<(), FlowEngineError> {
    let solved = outcome == RunOutcome::Solved;
    let expected = FlowOutcomeReport {
        solved: build_outcome_section(report.solved.summary(), solved, steps, |step| {
            solved && step.kind == StepRunResultKind::Succeeded
        }),
        changed: build_outcome_section(
            report.changed.summary(),
            steps.iter().any(|step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Change
            }),
            steps,
            |step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Change
            },
        ),
        verified: build_outcome_section(
            report.verified.summary(),
            steps.iter().any(|step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Verify
            }),
            steps,
            |step| {
                step.kind == StepRunResultKind::Succeeded
                    && step.semantic_role == StepSemanticRole::Verify
            },
        ),
        unresolved: build_outcome_section(
            report.unresolved.summary(),
            outcome == RunOutcome::Unresolved,
            steps,
            |step| step.kind == StepRunResultKind::Failed,
        ),
        blocked: build_outcome_section(
            report.blocked.summary(),
            outcome == RunOutcome::Blocked,
            steps,
            |step| step.kind == StepRunResultKind::Blocked,
        ),
    };
    if expected == *report {
        Ok(())
    } else {
        engine_invalid(
            "flow_result.report",
            "does not match the terminal step evidence and truth",
        )
    }
}

fn build_outcome_section(
    summary: &str,
    satisfied: bool,
    steps: &[StepRunResult],
    include: impl Fn(&StepRunResult) -> bool,
) -> FlowOutcomeSection {
    let matching = steps
        .iter()
        .filter(|step| include(step))
        .collect::<Vec<_>>();
    let step_ids = matching.iter().map(|step| step.step_id.clone()).collect();
    let mut evidence = Vec::new();
    let mut evidence_truncated = false;
    for handle in matching
        .iter()
        .filter_map(|step| step.report())
        .flat_map(EffectReport::evidence)
    {
        if evidence.contains(handle) {
            continue;
        }
        if evidence.len() == MAX_OUTCOME_EVIDENCE_HANDLES {
            evidence_truncated = true;
        } else {
            evidence.push(handle.clone());
        }
    }
    FlowOutcomeSection {
        summary: summary.to_owned(),
        satisfied,
        step_ids,
        evidence,
        evidence_truncated,
    }
}

fn semantic_events_for_transition(
    snapshot: &FlowSnapshot,
    kind: &TransitionKind,
) -> Result<Vec<FlowSemanticEvent>, FlowEngineError> {
    let mut events = Vec::new();
    match kind {
        TransitionKind::ApprovalRequested { step_id } => {
            events.push(waiting_event(step_id, FlowWaitReason::Approval, None));
            events.push(FlowSemanticEvent::ApprovalRequired {
                step_id: step_id.clone(),
            });
        }
        TransitionKind::EffectStarted { step_id, .. } => {
            events.push(waiting_event(step_id, FlowWaitReason::EffectResult, None));
        }
        TransitionKind::RetryScheduled {
            step_id,
            not_before_ms,
            ..
        } => {
            let report = transition_step_report(snapshot, step_id)?;
            push_evidence_event(&mut events, step_id, report);
            events.push(waiting_event(
                step_id,
                FlowWaitReason::Retry,
                Some(*not_before_ms),
            ));
        }
        TransitionKind::EffectSucceeded { step_id, .. } => {
            let step = transition_step_snapshot(snapshot, step_id)?;
            let report = step
                .results
                .last()
                .map(|record| &record.result.report)
                .ok_or(FlowEngineError::SnapshotTransitionMismatch)?;
            push_evidence_event(&mut events, step_id, report);
            match step.semantic_role {
                StepSemanticRole::Observe => {}
                StepSemanticRole::Verify => {
                    events.push(FlowSemanticEvent::VerificationPassed {
                        step_id: step_id.clone(),
                        report: report.clone(),
                    });
                }
                StepSemanticRole::Change => {
                    events.push(FlowSemanticEvent::FixApplied {
                        step_id: step_id.clone(),
                        report: report.clone(),
                    });
                }
            }
        }
        TransitionKind::RetryExhausted { step_id, .. }
        | TransitionKind::EffectFailed { step_id, .. } => {
            let report = transition_step_report(snapshot, step_id)?;
            push_evidence_event(&mut events, step_id, report);
            events.push(FlowSemanticEvent::Unresolved {
                step_id: step_id.clone(),
                report: report.clone(),
            });
        }
        TransitionKind::ApprovalDenied { step_id }
        | TransitionKind::EffectAuthorizationDenied { step_id, .. }
        | TransitionKind::ReconciliationUnknown { step_id, .. } => {
            let report = transition_step_snapshot(snapshot, step_id)?
                .blocked_report
                .as_ref()
                .ok_or(FlowEngineError::SnapshotTransitionMismatch)?;
            push_evidence_event(&mut events, step_id, report);
            events.push(FlowSemanticEvent::Blocked {
                step_id: step_id.clone(),
                report: report.clone(),
            });
        }
        TransitionKind::CancellationRequested => {
            let step = snapshot
                .steps
                .iter()
                .find(|step| matches!(step.state, StepState::InFlight { .. }))
                .ok_or(FlowEngineError::SnapshotTransitionMismatch)?;
            events.push(waiting_event(
                &step.id,
                FlowWaitReason::Reconciliation,
                None,
            ));
        }
        TransitionKind::StepSkipped { .. }
        | TransitionKind::ApprovalGranted { .. }
        | TransitionKind::EffectEvaluationRequired { .. }
        | TransitionKind::ReconciledNotApplied { .. }
        | TransitionKind::RunCompleted { .. } => {}
    }
    if events.len() > MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION {
        return Err(FlowEngineError::SnapshotTransitionMismatch);
    }
    Ok(events)
}

fn transition_step_snapshot<'a>(
    snapshot: &'a FlowSnapshot,
    step_id: &str,
) -> Result<&'a StepSnapshot, FlowEngineError> {
    snapshot
        .steps
        .iter()
        .find(|step| step.id == step_id)
        .ok_or(FlowEngineError::SnapshotTransitionMismatch)
}

fn transition_step_report<'a>(
    snapshot: &'a FlowSnapshot,
    step_id: &str,
) -> Result<&'a EffectReport, FlowEngineError> {
    transition_step_snapshot(snapshot, step_id)?
        .results
        .last()
        .map(|record| &record.result.report)
        .ok_or(FlowEngineError::SnapshotTransitionMismatch)
}

fn push_evidence_event(events: &mut Vec<FlowSemanticEvent>, step_id: &str, report: &EffectReport) {
    if !report.evidence.is_empty() {
        events.push(FlowSemanticEvent::EvidenceFound {
            step_id: step_id.to_owned(),
            evidence: report.evidence.clone(),
        });
    }
}

fn waiting_event(
    step_id: &str,
    reason: FlowWaitReason,
    not_before_ms: Option<u64>,
) -> FlowSemanticEvent {
    FlowSemanticEvent::Waiting {
        step_id: step_id.to_owned(),
        reason,
        not_before_ms,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowEngineError {
    InvalidValue { path: String, message: String },
    InvalidDefinition(FlowValidationError),
    UnsupportedSnapshotVersion(u16),
    InvalidInitialSnapshot,
    RunIdMismatch,
    DefinitionDigestMismatch,
    SnapshotShapeMismatch,
    SnapshotStatusMismatch,
    SnapshotIdentityMismatch,
    SnapshotSequenceMismatch,
    SnapshotTransitionMismatch,
    EffectIdentityMismatch,
    ApprovalTokenMismatch,
    NoApprovalPending,
    UnexpectedStepState,
    StatefulReplayRequiresReconcile,
    ConflictingEffectResult { step_id: String, attempt: u8 },
    TimestampOverflow,
    TransitionSequenceOverflow,
    SchedulerStalled,
}

impl fmt::Display for FlowEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue { path, message } => {
                write!(formatter, "invalid flow engine value at {path}: {message}")
            }
            Self::InvalidDefinition(error) => error.fmt(formatter),
            Self::UnsupportedSnapshotVersion(version) => write!(
                formatter,
                "unsupported flow snapshot version {version}; only version {FLOW_SNAPSHOT_VERSION} is supported"
            ),
            Self::InvalidInitialSnapshot => {
                formatter.write_str("initial flow snapshot shape is invalid")
            }
            Self::RunIdMismatch => formatter.write_str("flow snapshot run identity does not match"),
            Self::DefinitionDigestMismatch => {
                formatter.write_str("flow snapshot definition digest does not match")
            }
            Self::SnapshotShapeMismatch => {
                formatter.write_str("flow snapshot step shape or state is invalid")
            }
            Self::SnapshotStatusMismatch => {
                formatter.write_str("flow snapshot status does not match its step states")
            }
            Self::SnapshotIdentityMismatch => formatter
                .write_str("flow snapshot successor changed immutable run or step identity"),
            Self::SnapshotSequenceMismatch => formatter
                .write_str("flow snapshot successor did not advance exactly one transition"),
            Self::SnapshotTransitionMismatch => {
                formatter.write_str("flow snapshot mutation does not match its semantic transition")
            }
            Self::EffectIdentityMismatch => {
                formatter.write_str("effect attempt identity does not match the run")
            }
            Self::ApprovalTokenMismatch => {
                formatter.write_str("approval token does not match the pending exact effect")
            }
            Self::NoApprovalPending => formatter.write_str("no flow approval is pending"),
            Self::UnexpectedStepState => {
                formatter.write_str("flow step is not in the state required for this operation")
            }
            Self::StatefulReplayRequiresReconcile => {
                formatter.write_str("an in-flight stateful effect must be reconciled before retry")
            }
            Self::ConflictingEffectResult { step_id, attempt } => write!(
                formatter,
                "conflicting duplicate result for step `{step_id}` attempt {attempt}"
            ),
            Self::TimestampOverflow => formatter.write_str("flow retry timestamp overflowed"),
            Self::TransitionSequenceOverflow => {
                formatter.write_str("flow transition sequence overflowed")
            }
            Self::SchedulerStalled => formatter.write_str("validated flow scheduler stalled"),
        }
    }
}

impl Error for FlowEngineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidDefinition(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FlowValidationError> for FlowEngineError {
    fn from(error: FlowValidationError) -> Self {
        Self::InvalidDefinition(error)
    }
}

fn validate_standalone_snapshot(snapshot: &FlowSnapshot) -> Result<(), FlowEngineError> {
    if snapshot.snapshot_version != FLOW_SNAPSHOT_VERSION {
        return Err(FlowEngineError::UnsupportedSnapshotVersion(
            snapshot.snapshot_version,
        ));
    }
    validate_engine_identity(
        "snapshot.run_id",
        snapshot.run_id.as_str(),
        MAX_RUN_ID_BYTES,
    )?;
    if snapshot.steps.is_empty() || snapshot.steps.len() > super::MAX_FLOW_STEPS {
        return Err(FlowEngineError::SnapshotShapeMismatch);
    }

    let mut ids = HashSet::with_capacity(snapshot.steps.len());
    let mut active = 0_usize;
    for (index, step) in snapshot.steps.iter().enumerate() {
        if super::validate_slug(
            &format!("snapshot.steps[{index}].id"),
            &step.id,
            super::MAX_FLOW_ID_BYTES,
        )
        .is_err()
            || !ids.insert(step.id.as_str())
            || step.results.len() > usize::from(super::MAX_RETRY_ATTEMPTS)
        {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        let approval_shape_valid = match step.approval {
            StepApprovalState::NotRequested => {
                matches!(step.state, StepState::Pending | StepState::Cancelled)
                    && step.results.is_empty()
                    && step.blocked_report.is_none()
            }
            StepApprovalState::Pending { .. } => {
                matches!(step.state, StepState::Pending)
                    && step.results.is_empty()
                    && step.blocked_report.is_none()
            }
            StepApprovalState::NotRequired | StepApprovalState::Granted { .. } => true,
            StepApprovalState::Denied { .. } => {
                matches!(step.state, StepState::Blocked) && step.blocked_report.is_some()
            }
        };
        let expected_token = approval_token(step.idempotency_identity);
        if !approval_shape_valid
            || matches!(
                step.approval,
                StepApprovalState::Pending { token }
                    | StepApprovalState::Granted { token }
                    | StepApprovalState::Denied { token }
                    if token != expected_token
            )
        {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        for (result_index, record) in step.results.iter().enumerate() {
            if usize::from(record.attempt) != result_index + 1 {
                return Err(FlowEngineError::SnapshotShapeMismatch);
            }
            record
                .result
                .validate(&format!("snapshot.steps[{index}].results[{result_index}]"))?;
        }
        if let Some(report) = &step.blocked_report {
            report.validate(&format!("snapshot.steps[{index}].blocked_report"))?;
        }
        validate_structural_step_state(step)?;
        if (!matches!(step.state, StepState::Pending) && !step.state.is_terminal())
            || matches!(step.approval, StepApprovalState::Pending { .. })
        {
            active += 1;
        }
    }
    if active > 1 || computed_status(snapshot) != snapshot.status {
        return Err(FlowEngineError::SnapshotStatusMismatch);
    }
    if snapshot.status == RunStatus::Cancelled
        && !snapshot.steps.iter().all(|step| step.state.is_terminal())
    {
        return Err(FlowEngineError::SnapshotStatusMismatch);
    }
    Ok(())
}

fn validate_structural_step_state(step: &StepSnapshot) -> Result<(), FlowEngineError> {
    let completed =
        u8::try_from(step.results.len()).map_err(|_| FlowEngineError::SnapshotShapeMismatch)?;
    let retry_prefix_length = match step.state {
        StepState::Succeeded { .. } | StepState::Failed { .. } => {
            step.results.len().saturating_sub(1)
        }
        StepState::Pending | StepState::Skipped => 0,
        StepState::AwaitingEffect { .. }
        | StepState::InFlight { .. }
        | StepState::WaitingRetry { .. }
        | StepState::Blocked
        | StepState::Cancelled => step.results.len(),
    };
    let retry_history_valid = step.results[..retry_prefix_length].iter().all(|record| {
        matches!(
            record.result.kind,
            EffectResultKind::Failed { retryable: true }
        )
    });
    let previous_retryable_failure = || {
        step.results.last().is_some_and(|record| {
            matches!(
                record.result.kind,
                EffectResultKind::Failed { retryable: true }
            )
        })
    };
    let shape_valid = match step.state {
        StepState::Pending | StepState::Skipped => {
            step.results.is_empty() && step.blocked_report.is_none()
        }
        StepState::AwaitingEffect { attempt } | StepState::InFlight { attempt, .. } => {
            attempt == completed + 1
                && attempt <= super::MAX_RETRY_ATTEMPTS
                && (attempt == 1 || previous_retryable_failure())
                && step.blocked_report.is_none()
        }
        StepState::WaitingRetry { next_attempt, .. } => {
            next_attempt == completed + 1
                && next_attempt <= super::MAX_RETRY_ATTEMPTS
                && previous_retryable_failure()
                && step.blocked_report.is_none()
        }
        StepState::Succeeded { attempt } => {
            attempt == completed
                && step
                    .results
                    .last()
                    .is_some_and(|record| record.result.kind == EffectResultKind::Succeeded)
                && step.blocked_report.is_none()
        }
        StepState::Failed { attempt } => {
            attempt == completed
                && step.results.last().is_some_and(|record| {
                    matches!(record.result.kind, EffectResultKind::Failed { .. })
                })
                && step.blocked_report.is_none()
        }
        StepState::Blocked => step.blocked_report.is_some(),
        StepState::Cancelled => step.blocked_report.is_none(),
    };
    if shape_valid && retry_history_valid {
        Ok(())
    } else {
        Err(FlowEngineError::SnapshotShapeMismatch)
    }
}

fn validate_successor_identity(
    previous: &FlowSnapshot,
    candidate: &FlowSnapshot,
) -> Result<(), FlowEngineError> {
    if previous.snapshot_version != candidate.snapshot_version
        || previous.run_id != candidate.run_id
        || previous.definition_digest != candidate.definition_digest
        || previous.steps.len() != candidate.steps.len()
        || previous
            .steps
            .iter()
            .zip(&candidate.steps)
            .any(|(before, after)| {
                before.id != after.id
                    || before.idempotency_identity != after.idempotency_identity
                    || before.semantic_role != after.semantic_role
            })
    {
        return Err(FlowEngineError::SnapshotIdentityMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_transition_successor(
    previous: &FlowSnapshot,
    candidate: &FlowSnapshot,
    transition: &RunTransition,
) -> Result<(), FlowEngineError> {
    let mut expected = previous.clone();
    expected.transition_sequence = transition.sequence;
    match &transition.kind {
        TransitionKind::StepSkipped { step_id } => {
            require_transition(
                !previous.cancel_requested && previous.status == RunStatus::Running,
            )?;
            let index = transition_step(previous, step_id)?;
            require_transition(
                matches!(previous.steps[index].state, StepState::Pending)
                    && matches!(
                        previous.steps[index].approval,
                        StepApprovalState::NotRequired | StepApprovalState::Granted { .. }
                    ),
            )?;
            expected.steps[index].state = StepState::Skipped;
        }
        TransitionKind::ApprovalRequested { step_id } => {
            require_transition(
                !previous.cancel_requested && previous.status == RunStatus::Running,
            )?;
            let index = transition_step(previous, step_id)?;
            require_transition(
                matches!(previous.steps[index].state, StepState::Pending)
                    && matches!(
                        previous.steps[index].approval,
                        StepApprovalState::NotRequested
                    ),
            )?;
            expected.steps[index].approval = StepApprovalState::Pending {
                token: approval_token(previous.steps[index].idempotency_identity),
            };
            expected.status = RunStatus::WaitingApproval;
        }
        TransitionKind::ApprovalGranted { step_id } => {
            require_transition(
                !previous.cancel_requested && previous.status == RunStatus::WaitingApproval,
            )?;
            let index = transition_step(previous, step_id)?;
            let StepApprovalState::Pending { token } = previous.steps[index].approval else {
                return Err(FlowEngineError::SnapshotTransitionMismatch);
            };
            expected.steps[index].approval = StepApprovalState::Granted { token };
            expected.status = RunStatus::Running;
        }
        TransitionKind::ApprovalDenied { step_id } => {
            require_transition(
                !previous.cancel_requested && previous.status == RunStatus::WaitingApproval,
            )?;
            let index = transition_step(previous, step_id)?;
            let StepApprovalState::Pending { token } = previous.steps[index].approval else {
                return Err(FlowEngineError::SnapshotTransitionMismatch);
            };
            expected.steps[index].approval = StepApprovalState::Denied { token };
            expected.steps[index].state = StepState::Blocked;
            expected.steps[index].blocked_report = Some(EffectReport::trusted(
                "the exact effect approval was denied",
            ));
            expected.status = RunStatus::Blocked;
        }
        TransitionKind::EffectEvaluationRequired { step_id, attempt } => {
            require_transition(!previous.cancel_requested)?;
            let index = transition_step(previous, step_id)?;
            let valid_origin = match previous.steps[index].state {
                StepState::Pending => {
                    *attempt == 1
                        && previous.status == RunStatus::Running
                        && matches!(
                            previous.steps[index].approval,
                            StepApprovalState::NotRequired | StepApprovalState::Granted { .. }
                        )
                }
                StepState::WaitingRetry { next_attempt, .. } => {
                    *attempt == next_attempt && previous.status == RunStatus::WaitingRetry
                }
                _ => false,
            };
            require_transition(valid_origin)?;
            expected.steps[index].state = StepState::AwaitingEffect { attempt: *attempt };
            expected.status = RunStatus::AwaitingEffectEvaluation;
        }
        TransitionKind::EffectAuthorizationDenied {
            step_id,
            attempt,
            replay,
        } => {
            require_transition(!previous.cancel_requested)?;
            let index = transition_step(previous, step_id)?;
            if *replay {
                require_transition(
                    previous.status == RunStatus::EffectInFlight
                        && matches!(
                            previous.steps[index].state,
                            StepState::InFlight {
                                attempt: current,
                                ..
                            } if current == *attempt
                        ),
                )?;
            } else {
                require_transition(
                    previous.status == RunStatus::AwaitingEffectEvaluation
                        && matches!(
                            previous.steps[index].state,
                            StepState::AwaitingEffect { attempt: current } if current == *attempt
                        ),
                )?;
            }
            expected.steps[index].state = StepState::Blocked;
            expected.steps[index].blocked_report = Some(EffectReport::trusted(
                "fresh authorization for the exact effect was denied",
            ));
            expected.status = RunStatus::Blocked;
        }
        TransitionKind::EffectStarted {
            step_id,
            attempt,
            replay,
        } => {
            require_transition(!previous.cancel_requested)?;
            let index = transition_step(previous, step_id)?;
            if *replay {
                require_transition(
                    previous.status == RunStatus::EffectInFlight
                        && matches!(
                            previous.steps[index].state,
                            StepState::InFlight {
                                attempt: current,
                                ..
                            } if current == *attempt
                        ),
                )?;
            } else {
                require_transition(
                    previous.status == RunStatus::AwaitingEffectEvaluation
                        && matches!(
                            previous.steps[index].state,
                            StepState::AwaitingEffect { attempt: current } if current == *attempt
                        ),
                )?;
                let StepState::InFlight {
                    attempt: candidate_attempt,
                    started_at_ms,
                } = candidate.steps[index].state
                else {
                    return Err(FlowEngineError::SnapshotTransitionMismatch);
                };
                require_transition(candidate_attempt == *attempt)?;
                expected.steps[index].state = StepState::InFlight {
                    attempt: *attempt,
                    started_at_ms,
                };
            }
            expected.status = RunStatus::EffectInFlight;
        }
        TransitionKind::EffectSucceeded { step_id, attempt } => {
            let index = result_transition_origin(previous, step_id, *attempt)?;
            let record = candidate_result(candidate, index, *attempt)?;
            require_transition(record.result.kind == EffectResultKind::Succeeded)?;
            expected.steps[index].results.push(record);
            expected.steps[index].state = StepState::Succeeded { attempt: *attempt };
            expected.status = if previous.cancel_requested {
                RunStatus::Cancelling
            } else {
                RunStatus::Running
            };
        }
        TransitionKind::RetryScheduled {
            step_id,
            next_attempt,
            not_before_ms,
        } => {
            require_transition(!previous.cancel_requested)?;
            let attempt = next_attempt
                .checked_sub(1)
                .ok_or(FlowEngineError::SnapshotTransitionMismatch)?;
            let index = result_transition_origin(previous, step_id, attempt)?;
            let record = candidate_result(candidate, index, attempt)?;
            require_transition(
                matches!(
                    record.result.kind,
                    EffectResultKind::Failed { retryable: true }
                ) && *next_attempt <= super::MAX_RETRY_ATTEMPTS,
            )?;
            expected.steps[index].results.push(record);
            expected.steps[index].state = StepState::WaitingRetry {
                next_attempt: *next_attempt,
                not_before_ms: *not_before_ms,
            };
            expected.status = RunStatus::WaitingRetry;
        }
        TransitionKind::RetryExhausted { step_id, attempt } => {
            require_transition(!previous.cancel_requested)?;
            let index = result_transition_origin(previous, step_id, *attempt)?;
            let record = candidate_result(candidate, index, *attempt)?;
            require_transition(matches!(
                record.result.kind,
                EffectResultKind::Failed { retryable: true }
            ))?;
            expected.steps[index].results.push(record);
            expected.steps[index].state = StepState::Failed { attempt: *attempt };
            expected.status = RunStatus::Running;
        }
        TransitionKind::EffectFailed { step_id, attempt } => {
            let index = result_transition_origin(previous, step_id, *attempt)?;
            let record = candidate_result(candidate, index, *attempt)?;
            require_transition(matches!(
                record.result.kind,
                EffectResultKind::Failed { retryable } if previous.cancel_requested || !retryable
            ))?;
            expected.steps[index].results.push(record);
            expected.steps[index].state = StepState::Failed { attempt: *attempt };
            expected.status = if previous.cancel_requested {
                RunStatus::Cancelling
            } else {
                RunStatus::Running
            };
        }
        TransitionKind::ReconciledNotApplied { step_id, attempt } => {
            require_transition(
                !previous.cancel_requested && previous.status == RunStatus::EffectInFlight,
            )?;
            let index = transition_step(previous, step_id)?;
            require_transition(matches!(
                previous.steps[index].state,
                StepState::InFlight {
                    attempt: current,
                    ..
                } if current == *attempt
            ))?;
            expected.steps[index].state = StepState::AwaitingEffect { attempt: *attempt };
            expected.status = RunStatus::AwaitingEffectEvaluation;
        }
        TransitionKind::ReconciliationUnknown { step_id, attempt } => {
            require_transition(matches!(
                previous.status,
                RunStatus::EffectInFlight | RunStatus::Cancelling
            ))?;
            let index = transition_step(previous, step_id)?;
            require_transition(matches!(
                previous.steps[index].state,
                StepState::InFlight {
                    attempt: current,
                    ..
                } if current == *attempt
            ))?;
            let report = candidate.steps[index]
                .blocked_report
                .clone()
                .ok_or(FlowEngineError::SnapshotTransitionMismatch)?;
            expected.steps[index].state = StepState::Blocked;
            expected.steps[index].blocked_report = Some(report);
            expected.status = RunStatus::Blocked;
        }
        TransitionKind::CancellationRequested => {
            require_transition(
                !previous.cancel_requested
                    && previous.status == RunStatus::EffectInFlight
                    && previous
                        .steps
                        .iter()
                        .any(|step| matches!(step.state, StepState::InFlight { .. })),
            )?;
            expected.cancel_requested = true;
            expected.status = RunStatus::Cancelling;
        }
        TransitionKind::RunCompleted { outcome } => match outcome {
            RunOutcome::Solved => {
                require_transition(
                    !previous.cancel_requested
                        && previous.status == RunStatus::Running
                        && previous.steps.iter().all(|step| step.state.is_terminal())
                        && !previous.steps.iter().any(|step| {
                            matches!(
                                step.state,
                                StepState::Failed { .. }
                                    | StepState::Blocked
                                    | StepState::Cancelled
                            )
                        }),
                )?;
                expected.status = RunStatus::Succeeded;
            }
            RunOutcome::Unresolved => {
                require_transition(
                    !previous.cancel_requested
                        && previous.status == RunStatus::Running
                        && previous.steps.iter().all(|step| step.state.is_terminal())
                        && previous
                            .steps
                            .iter()
                            .any(|step| matches!(step.state, StepState::Failed { .. }))
                        && !previous.steps.iter().any(|step| {
                            matches!(step.state, StepState::Blocked | StepState::Cancelled)
                        }),
                )?;
                expected.status = RunStatus::Unresolved;
            }
            RunOutcome::Cancelled => {
                require_transition(!previous.status.is_terminal())?;
                expected.cancel_requested = true;
                expected.status = RunStatus::Cancelled;
                for step in &mut expected.steps {
                    if !step.state.is_terminal() {
                        step.state = StepState::Cancelled;
                    }
                    if matches!(step.approval, StepApprovalState::Pending { .. }) {
                        step.approval = StepApprovalState::NotRequested;
                    }
                }
            }
            RunOutcome::Blocked => {
                return Err(FlowEngineError::SnapshotTransitionMismatch);
            }
        },
    }
    let expected_semantic_events = semantic_events_for_transition(&expected, &transition.kind)?;
    require_transition(transition.semantic_events == expected_semantic_events)?;
    if expected == *candidate {
        Ok(())
    } else {
        Err(FlowEngineError::SnapshotTransitionMismatch)
    }
}

fn transition_step(snapshot: &FlowSnapshot, step_id: &str) -> Result<usize, FlowEngineError> {
    snapshot
        .steps
        .iter()
        .position(|step| step.id == step_id)
        .ok_or(FlowEngineError::SnapshotTransitionMismatch)
}

fn result_transition_origin(
    snapshot: &FlowSnapshot,
    step_id: &str,
    attempt: u8,
) -> Result<usize, FlowEngineError> {
    require_transition(matches!(
        snapshot.status,
        RunStatus::EffectInFlight | RunStatus::Cancelling
    ))?;
    let index = transition_step(snapshot, step_id)?;
    require_transition(matches!(
        snapshot.steps[index].state,
        StepState::InFlight {
            attempt: current,
            ..
        } if current == attempt
    ))?;
    Ok(index)
}

fn candidate_result(
    snapshot: &FlowSnapshot,
    step_index: usize,
    attempt: u8,
) -> Result<RecordedEffectResult, FlowEngineError> {
    snapshot.steps[step_index]
        .results
        .last()
        .filter(|record| record.attempt == attempt)
        .cloned()
        .ok_or(FlowEngineError::SnapshotTransitionMismatch)
}

fn require_transition(condition: bool) -> Result<(), FlowEngineError> {
    if condition {
        Ok(())
    } else {
        Err(FlowEngineError::SnapshotTransitionMismatch)
    }
}

#[allow(clippy::too_many_lines)]
fn validate_snapshot(
    definition: &FlowDefinition,
    snapshot: &FlowSnapshot,
) -> Result<(), FlowEngineError> {
    if snapshot.snapshot_version != FLOW_SNAPSHOT_VERSION {
        return Err(FlowEngineError::UnsupportedSnapshotVersion(
            snapshot.snapshot_version,
        ));
    }
    if snapshot.transition_sequence == u64::MAX && !snapshot.status.is_terminal() {
        return Err(FlowEngineError::TransitionSequenceOverflow);
    }
    validate_engine_identity(
        "snapshot.run_id",
        snapshot.run_id.as_str(),
        MAX_RUN_ID_BYTES,
    )?;
    if snapshot.steps.len() != definition.steps().len() {
        return Err(FlowEngineError::SnapshotShapeMismatch);
    }
    let mut active = 0_usize;
    for (index, (stored, declared)) in snapshot.steps.iter().zip(definition.steps()).enumerate() {
        if stored.id != declared.id()
            || stored.semantic_role != declared.semantic_role()
            || stored.idempotency_identity
                != idempotency_identity(
                    &snapshot.run_id,
                    snapshot.definition_digest,
                    declared.id(),
                    declared.idempotency_key(),
                )
            || stored.results.len() > usize::from(declared.retry().max_attempts())
        {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        match (&stored.approval, declared.approval()) {
            (StepApprovalState::NotRequired, ApprovalMode::None)
            | (
                StepApprovalState::NotRequested
                | StepApprovalState::Pending { .. }
                | StepApprovalState::Granted { .. }
                | StepApprovalState::Denied { .. },
                ApprovalMode::Required,
            ) => {}
            _ => return Err(FlowEngineError::SnapshotShapeMismatch),
        }
        let approval_state_valid = match stored.approval {
            StepApprovalState::NotRequested => {
                matches!(stored.state, StepState::Pending | StepState::Cancelled)
                    && stored.results.is_empty()
                    && stored.blocked_report.is_none()
            }
            StepApprovalState::Pending { .. } => {
                matches!(stored.state, StepState::Pending)
                    && stored.results.is_empty()
                    && stored.blocked_report.is_none()
            }
            StepApprovalState::NotRequired | StepApprovalState::Granted { .. } => true,
            StepApprovalState::Denied { .. } => {
                matches!(stored.state, StepState::Blocked) && stored.blocked_report.is_some()
            }
        };
        if !approval_state_valid {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        let expected_token = approval_token(stored.idempotency_identity);
        if matches!(
            stored.approval,
            StepApprovalState::Pending { token }
                | StepApprovalState::Granted { token }
                | StepApprovalState::Denied { token }
                if token != expected_token
        ) {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        for (result_index, record) in stored.results.iter().enumerate() {
            if usize::from(record.attempt) != result_index + 1 {
                return Err(FlowEngineError::SnapshotShapeMismatch);
            }
            record
                .result
                .validate(&format!("snapshot.steps[{index}].results[{result_index}]"))?;
        }
        if let Some(report) = &stored.blocked_report {
            report.validate(&format!("snapshot.steps[{index}].blocked_report"))?;
        }
        validate_step_state(
            stored,
            declared.retry().max_attempts(),
            snapshot.cancel_requested,
        )?;
        if (!matches!(stored.state, StepState::Pending) && !stored.state.is_terminal())
            || matches!(stored.approval, StepApprovalState::Pending { .. })
        {
            active += 1;
        }
    }
    if active > 1 || computed_status(snapshot) != snapshot.status {
        return Err(FlowEngineError::SnapshotStatusMismatch);
    }
    if snapshot.status == RunStatus::Cancelled
        && !snapshot.steps.iter().all(|step| step.state.is_terminal())
    {
        return Err(FlowEngineError::SnapshotStatusMismatch);
    }
    validate_snapshot_graph(definition, snapshot)?;
    Ok(())
}

fn validate_snapshot_graph(
    definition: &FlowDefinition,
    snapshot: &FlowSnapshot,
) -> Result<(), FlowEngineError> {
    for (index, (stored, declared)) in snapshot.steps.iter().zip(definition.steps()).enumerate() {
        if matches!(stored.state, StepState::Cancelled) {
            if !snapshot.cancel_requested {
                return Err(FlowEngineError::SnapshotShapeMismatch);
            }
            continue;
        }
        let ready_approval = matches!(
            stored.approval,
            StepApprovalState::Pending { .. } | StepApprovalState::Granted { .. }
        ) && matches!(stored.state, StepState::Pending);
        if matches!(stored.state, StepState::Pending) && !ready_approval {
            continue;
        }
        let prerequisites_complete = declared
            .dependencies()
            .iter()
            .map(String::as_str)
            .chain(declared.condition().referenced_step())
            .all(|reference| {
                definition
                    .steps()
                    .iter()
                    .position(|step| step.id() == reference)
                    .is_some_and(|dependency| snapshot.steps[dependency].state.is_terminal())
            });
        if !prerequisites_complete {
            return Err(FlowEngineError::SnapshotShapeMismatch);
        }
        let condition_true = match declared.condition() {
            StepCondition::Always => true,
            StepCondition::Succeeded { step } => snapshot_state_by_id(definition, snapshot, step)
                .is_some_and(|state| matches!(state, StepState::Succeeded { .. })),
            StepCondition::Failed { step } => snapshot_state_by_id(definition, snapshot, step)
                .is_some_and(|state| matches!(state, StepState::Failed { .. })),
        };
        if matches!(stored.state, StepState::Skipped) == condition_true {
            return engine_invalid(
                format!("snapshot.steps[{index}].state"),
                "does not match the declared condition outcome",
            );
        }
    }
    Ok(())
}

fn snapshot_state_by_id<'a>(
    definition: &FlowDefinition,
    snapshot: &'a FlowSnapshot,
    id: &str,
) -> Option<&'a StepState> {
    definition
        .steps()
        .iter()
        .position(|step| step.id() == id)
        .map(|index| &snapshot.steps[index].state)
}

fn validate_step_state(
    step: &StepSnapshot,
    max_attempts: u8,
    cancel_requested: bool,
) -> Result<(), FlowEngineError> {
    let completed =
        u8::try_from(step.results.len()).map_err(|_| FlowEngineError::SnapshotShapeMismatch)?;
    let retry_prefix_length = match step.state {
        StepState::AwaitingEffect { .. }
        | StepState::InFlight { .. }
        | StepState::WaitingRetry { .. }
        | StepState::Blocked => step.results.len(),
        StepState::Succeeded { .. } | StepState::Failed { .. } | StepState::Cancelled => {
            step.results.len().saturating_sub(1)
        }
        StepState::Pending | StepState::Skipped => 0,
    };
    let retry_history_valid = step.results[..retry_prefix_length].iter().all(|record| {
        matches!(
            record.result.kind,
            EffectResultKind::Failed { retryable: true }
        )
    });
    let previous_retryable_failure = || {
        step.results.last().is_some_and(|record| {
            matches!(
                record.result.kind,
                EffectResultKind::Failed { retryable: true }
            )
        })
    };
    let shape_valid = match step.state {
        StepState::Pending | StepState::Skipped => {
            step.results.is_empty() && step.blocked_report.is_none()
        }
        StepState::AwaitingEffect { attempt } | StepState::InFlight { attempt, .. } => {
            attempt == completed + 1
                && attempt <= max_attempts
                && (attempt == 1 || previous_retryable_failure())
        }
        StepState::WaitingRetry { next_attempt, .. } => {
            next_attempt == completed + 1
                && next_attempt <= max_attempts
                && previous_retryable_failure()
        }
        StepState::Succeeded { attempt } => {
            attempt == completed
                && step
                    .results
                    .last()
                    .is_some_and(|record| record.result.kind == EffectResultKind::Succeeded)
        }
        StepState::Failed { attempt } => {
            attempt == completed
                && step
                    .results
                    .last()
                    .is_some_and(|record| match record.result.kind {
                        EffectResultKind::Failed { retryable: false } => true,
                        EffectResultKind::Failed { retryable: true } => {
                            cancel_requested || attempt == max_attempts
                        }
                        EffectResultKind::Succeeded => false,
                    })
        }
        StepState::Blocked => step.blocked_report.is_some(),
        StepState::Cancelled => step.blocked_report.is_none(),
    };
    if !shape_valid || !retry_history_valid {
        return Err(FlowEngineError::SnapshotShapeMismatch);
    }
    Ok(())
}

fn computed_status(snapshot: &FlowSnapshot) -> RunStatus {
    if snapshot.cancel_requested {
        if snapshot.status == RunStatus::Blocked {
            return RunStatus::Blocked;
        }
        if snapshot.status == RunStatus::Cancelled {
            return RunStatus::Cancelled;
        }
        return RunStatus::Cancelling;
    }
    if snapshot
        .steps
        .iter()
        .any(|step| matches!(step.state, StepState::Blocked))
    {
        return RunStatus::Blocked;
    }
    if snapshot
        .steps
        .iter()
        .any(|step| matches!(step.approval, StepApprovalState::Pending { .. }))
    {
        return RunStatus::WaitingApproval;
    }
    if snapshot
        .steps
        .iter()
        .any(|step| matches!(step.state, StepState::WaitingRetry { .. }))
    {
        return RunStatus::WaitingRetry;
    }
    if snapshot
        .steps
        .iter()
        .any(|step| matches!(step.state, StepState::AwaitingEffect { .. }))
    {
        return RunStatus::AwaitingEffectEvaluation;
    }
    if snapshot
        .steps
        .iter()
        .any(|step| matches!(step.state, StepState::InFlight { .. }))
    {
        return RunStatus::EffectInFlight;
    }
    if snapshot.steps.iter().all(|step| step.state.is_terminal()) {
        if snapshot.status == RunStatus::Running {
            return RunStatus::Running;
        }
        if snapshot
            .steps
            .iter()
            .any(|step| matches!(step.state, StepState::Failed { .. }))
        {
            RunStatus::Unresolved
        } else {
            RunStatus::Succeeded
        }
    } else {
        RunStatus::Running
    }
}

fn idempotency_identity(
    run_id: &RunId,
    definition_digest: FlowDigest,
    step_id: &str,
    declared_key: Option<&str>,
) -> IdempotencyIdentity {
    let mut hasher = Sha256::new();
    hasher.update(b"pam-flow-step-idempotency-v1\0");
    update_length_prefixed(&mut hasher, run_id.as_str().as_bytes());
    hasher.update(definition_digest.as_bytes());
    update_length_prefixed(&mut hasher, step_id.as_bytes());
    update_length_prefixed(&mut hasher, declared_key.unwrap_or(step_id).as_bytes());
    IdempotencyIdentity(hasher.finalize().into())
}

fn approval_token(identity: IdempotencyIdentity) -> ApprovalToken {
    let mut hasher = Sha256::new();
    hasher.update(b"pam-flow-step-approval-v1\0");
    hasher.update(identity.as_bytes());
    ApprovalToken(hasher.finalize().into())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length =
        u64::try_from(value.len()).expect("an in-memory value cannot exceed u64::MAX bytes");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn retry_backoff_ms(initial: u64, maximum: u64, failed_attempt: u8) -> u64 {
    let shift = u32::from(failed_attempt.saturating_sub(1));
    initial.checked_shl(shift).unwrap_or(u64::MAX).min(maximum)
}

fn validate_engine_text(path: &str, value: &str, maximum: usize) -> Result<(), FlowEngineError> {
    if value.is_empty() {
        return engine_invalid(path, "must not be empty");
    }
    if value.len() > maximum {
        return engine_invalid(path, format!("must be at most {maximum} UTF-8 bytes"));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return engine_invalid(path, "must be trimmed and contain no control characters");
    }
    super::reject_secret_like(path, value).map_err(|error| FlowEngineError::InvalidValue {
        path: path.to_owned(),
        message: error.message().to_owned(),
    })
}

fn validate_engine_identity(
    path: &str,
    value: &str,
    maximum: usize,
) -> Result<(), FlowEngineError> {
    validate_engine_text(path, value, maximum)?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric()
            || index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return engine_invalid(
            path,
            "must use ASCII letters, digits, and internal `-_.:/` separators",
        );
    }
    Ok(())
}

fn engine_invalid<T>(
    path: impl Into<String>,
    message: impl Into<String>,
) -> Result<T, FlowEngineError> {
    Err(FlowEngineError::InvalidValue {
        path: path.into(),
        message: message.into(),
    })
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, prefix: &str, bytes: &[u8]) -> fmt::Result {
    formatter.write_str(prefix)?;
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
