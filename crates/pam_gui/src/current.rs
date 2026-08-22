use std::{collections::HashSet, time::Duration};

use pam_core::{CallerCredential, CallerId, EvidenceHandle, IdempotencyKey, ProjectId, RequestId};
use pam_daemon::request_exchange;
use pam_flow::{FlowRunResult, FlowSemanticEvent, FlowWaitReason, RunOutcome, TransitionKind};
use pam_platform::LocalEndpoint;
use pam_protocol::{
    ApprovalChallenge, ApprovalDecision, ApprovalDecisionDisposition, Event, EventEnvelope,
    EvidenceMetadata, ExpectedTargetKind, Failure, FailureCode, OperationTruth,
    ProjectCurrentResult, ProjectRequestSummary, RequestEnvelope, ResultBody, ResultPayload,
};
use uuid::Uuid;

const CURRENT_TIMEOUT: Duration = Duration::from_secs(2);
const EVIDENCE_PREVIEW_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CurrentState {
    Available(CurrentView),
    ApprovalRequired(PendingApproval),
    Blocked {
        code: FailureCode,
        detail: String,
        recovery: Option<String>,
    },
    Degraded {
        code: Option<CurrentUnavailableCode>,
        detail: String,
        recovery: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CurrentUnavailableCode {
    GuiRegistrationRequired,
}

impl CurrentUnavailableCode {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::GuiRegistrationRequired => "gui_registration_required",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CurrentView {
    pub(crate) queued: Vec<ProjectRequestSummary>,
    pub(crate) truncated: bool,
    pub(crate) run: Option<RunView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunView {
    pub(crate) request: ProjectRequestSummary,
    pub(crate) timeline: Vec<TimelineFact>,
    pub(crate) outcome: Option<OutcomeView>,
    pub(crate) detail_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TimelineFact {
    pub(crate) kind: TimelineKind,
    pub(crate) label: String,
    pub(crate) summary: String,
    pub(crate) verified: bool,
    pub(crate) evidence: Vec<EvidenceHandle>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimelineKind {
    Request,
    Evidence,
    Change,
    Verification,
    Failure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutcomeSectionView {
    pub(crate) label: &'static str,
    pub(crate) summary: String,
    pub(crate) satisfied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutcomeView {
    pub(crate) heading: &'static str,
    pub(crate) solved: bool,
    pub(crate) sections: Vec<OutcomeSectionView>,
    pub(crate) evidence: Vec<EvidenceHandle>,
    pub(crate) evidence_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingApproval {
    pub(crate) challenge: ApprovalChallenge,
    request: Box<RequestEnvelope>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApprovalDecisionView {
    pub(crate) disposition: ApprovalDecisionDisposition,
    pub(crate) current: CurrentState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApprovalDecisionFailure {
    pub(crate) detail: String,
    pub(crate) recovery: Option<String>,
}

impl PendingApproval {
    #[must_use]
    #[cfg(test)]
    pub(crate) fn approval_id(&self) -> &pam_core::ApprovalId {
        &self.challenge.approval_id
    }

    #[must_use]
    pub(crate) fn project_id(&self) -> &ProjectId {
        &self.request.project_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceState {
    Available(EvidencePreview),
    Failed {
        handle: EvidenceHandle,
        detail: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidencePreview {
    pub(crate) handle: EvidenceHandle,
    pub(crate) digest: String,
    pub(crate) size_bytes: u64,
    pub(crate) media_type: String,
    pub(crate) body: Option<String>,
    pub(crate) truncated: bool,
    pub(crate) truth: OperationTruth,
}

pub(crate) async fn load_current(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
) -> CurrentState {
    let request = RequestEnvelope::project_current(
        unique_request_id("gui-current"),
        caller_id,
        project_id,
        unique_idempotency("gui-current"),
    )
    .authenticated(credential);
    load_current_request(request).await
}

pub(crate) async fn decide_current_approval(
    pending: PendingApproval,
    decision: ApprovalDecision,
) -> Result<ApprovalDecisionView, ApprovalDecisionFailure> {
    let Some(credential) = pending.request.authentication.clone() else {
        return Err(approval_decision_failure(
            "The retained approval request is no longer authenticated.",
            None,
        ));
    };
    let request = RequestEnvelope::approval_decide(
        unique_request_id("gui-approval"),
        pending.request.caller_id.clone(),
        pending.request.project_id.clone(),
        unique_idempotency("gui-approval"),
        pending.challenge.approval_id.clone(),
        decision,
    )
    .authenticated(credential);
    let exchange = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &request,
        CURRENT_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(error) => {
            return Err(approval_decision_failure(
                error.to_string(),
                error.recovery_action().map(str::to_owned),
            ));
        }
    };
    if !exchange.events.is_empty() {
        return Err(approval_decision_failure(
            "PAM returned events for an approval decision.",
            None,
        ));
    }
    match exchange.result.body {
        ResultBody::Success {
            payload: ResultPayload::ApprovalDecision(result),
            ..
        } if result.approval_id == pending.challenge.approval_id => {
            let current = match result.disposition {
                ApprovalDecisionDisposition::Approved => {
                    let retry = (*pending.request).with_approval(result.approval_id);
                    load_current_request(retry).await
                }
                ApprovalDecisionDisposition::Denied => {
                    degraded("This exact project-current request was denied.", None)
                }
                ApprovalDecisionDisposition::Expired => degraded(
                    "This approval expired before the decision was applied.",
                    Some(
                        "Retry the project-current request to receive a new challenge.".to_owned(),
                    ),
                ),
            };
            Ok(ApprovalDecisionView {
                disposition: result.disposition,
                current,
            })
        }
        ResultBody::Failure(failure) => {
            Err(approval_decision_failure(failure.message, failure.recovery))
        }
        ResultBody::Success { .. } => Err(approval_decision_failure(
            "PAM returned an unexpected approval response.",
            None,
        )),
    }
}

fn approval_decision_failure(
    detail: impl Into<String>,
    recovery: Option<String>,
) -> ApprovalDecisionFailure {
    ApprovalDecisionFailure {
        detail: detail.into(),
        recovery,
    }
}

pub(crate) async fn load_evidence(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
    handle: EvidenceHandle,
) -> EvidenceState {
    let (truth, metadata) = match inspect_evidence(
        caller_id.clone(),
        credential.clone(),
        project_id.clone(),
        handle.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(detail) => return EvidenceState::Failed { handle, detail },
    };
    let (body, truncated) = if metadata.media_type.starts_with("text/") && metadata.size_bytes > 0 {
        match read_text_evidence(
            caller_id,
            credential,
            project_id,
            handle.clone(),
            metadata.size_bytes.min(EVIDENCE_PREVIEW_BYTES),
        )
        .await
        {
            Ok(value) => value,
            Err(detail) => return EvidenceState::Failed { handle, detail },
        }
    } else {
        (None, false)
    };
    EvidenceState::Available(EvidencePreview {
        handle,
        digest: metadata.digest.as_str().to_owned(),
        size_bytes: metadata.size_bytes,
        media_type: metadata.media_type,
        body,
        truncated,
        truth,
    })
}

async fn inspect_evidence(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
    handle: EvidenceHandle,
) -> Result<(OperationTruth, EvidenceMetadata), String> {
    let inspect = RequestEnvelope::inspect_evidence(
        unique_request_id("gui-evidence-inspect"),
        caller_id.clone(),
        project_id.clone(),
        unique_idempotency("gui-evidence-inspect"),
        handle.clone(),
    )
    .authenticated(credential.clone());
    let exchange = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &inspect,
        CURRENT_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(error) => return Err(error.to_string()),
    };
    match exchange.result.body {
        ResultBody::Success {
            truth,
            payload: ResultPayload::EvidenceMetadata(metadata),
        } if exchange.events.is_empty() && metadata.handle == handle => Ok((truth, metadata)),
        ResultBody::Failure(failure) => Err(failure.message),
        ResultBody::Success { .. } => {
            Err("PAM returned an unexpected evidence metadata response.".to_owned())
        }
    }
}

async fn read_text_evidence(
    caller_id: CallerId,
    credential: CallerCredential,
    project_id: ProjectId,
    handle: EvidenceHandle,
    length: u64,
) -> Result<(Option<String>, bool), String> {
    let read = RequestEnvelope::read_evidence(
        unique_request_id("gui-evidence-read"),
        caller_id,
        project_id,
        unique_idempotency("gui-evidence-read"),
        handle.clone(),
        0,
        length,
    )
    .map_err(|error| error.to_string())?
    .authenticated(credential);
    let exchange = request_exchange(&LocalEndpoint::default_for_user(), &read, CURRENT_TIMEOUT)
        .await
        .map_err(|error| error.to_string())?;
    match exchange.result.body {
        ResultBody::Success {
            payload: ResultPayload::EvidenceChunk(chunk),
            ..
        } if exchange.events.is_empty() && chunk.handle == handle && chunk.offset == 0 => {
            Ok((String::from_utf8(chunk.bytes().to_vec()).ok(), !chunk.eof))
        }
        ResultBody::Failure(failure) => Err(failure.message),
        ResultBody::Success { .. } => {
            Err("PAM returned an unexpected evidence content response.".to_owned())
        }
    }
}

async fn load_current_request(request: RequestEnvelope) -> CurrentState {
    let exchange = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &request,
        CURRENT_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => exchange,
        Err(error) => {
            return degraded(
                error.to_string(),
                error.recovery_action().map(str::to_owned),
            );
        }
    };
    if !exchange.events.is_empty() {
        return degraded("PAM returned events for a project-current read.", None);
    }
    let current = match exchange.result.body {
        ResultBody::Success {
            payload: ResultPayload::ProjectCurrent(current),
            ..
        } => current,
        ResultBody::Failure(Failure {
            code: FailureCode::ApprovalRequired,
            approval: Some(challenge),
            ..
        }) => {
            return CurrentState::ApprovalRequired(PendingApproval {
                challenge,
                request: Box::new(request),
            });
        }
        ResultBody::Failure(failure) => return failure_state(failure),
        ResultBody::Success { .. } => {
            return degraded("PAM returned an unexpected project-current response.", None);
        }
    };
    build_current_view(current, &request).await
}

async fn build_current_view(
    current: ProjectCurrentResult,
    request: &RequestEnvelope,
) -> CurrentState {
    let focus = current.active.clone().or_else(|| current.latest.clone());
    let run = match focus {
        Some(summary) => Some(load_run(summary, request).await),
        None => None,
    };
    CurrentState::Available(CurrentView {
        queued: current.queued().to_vec(),
        truncated: current.truncated,
        run,
    })
}

async fn load_run(summary: ProjectRequestSummary, base: &RequestEnvelope) -> RunView {
    if summary.operation_kind() != "flow_run" {
        return RunView {
            request: summary,
            timeline: Vec::new(),
            outcome: None,
            detail_error: None,
        };
    }
    let target = summary.request_id.clone();
    let replay = RequestEnvelope::replay_with_expected_target(
        unique_request_id("gui-current-replay"),
        base.caller_id.clone(),
        base.project_id.clone(),
        unique_idempotency("gui-current-replay"),
        target.clone(),
        0,
        ExpectedTargetKind::FlowRun,
    )
    .authenticated(
        base.authentication
            .clone()
            .expect("authenticated current request"),
    );
    let (timeline, mut detail_error) = match request_exchange(
        &LocalEndpoint::default_for_user(),
        &replay,
        CURRENT_TIMEOUT,
    )
    .await
    {
        Ok(exchange) => match exchange.result.body {
            ResultBody::Failure(failure) => (Vec::new(), Some(failure.message)),
            ResultBody::Success {
                payload: ResultPayload::Replay(_),
                ..
            } => (timeline_from_events(&exchange.events), None),
            ResultBody::Success { .. } => (
                Vec::new(),
                Some("PAM returned an unexpected replay response.".to_owned()),
            ),
        },
        Err(error) => (Vec::new(), Some(error.to_string())),
    };

    let mut outcome = None;
    if summary.completed_at_ms.is_some() {
        let result_request = RequestEnvelope::get_result_with_expected_target(
            unique_request_id("gui-current-result"),
            base.caller_id.clone(),
            base.project_id.clone(),
            unique_idempotency("gui-current-result"),
            target,
            ExpectedTargetKind::FlowRun,
        )
        .authenticated(
            base.authentication
                .clone()
                .expect("authenticated current request"),
        );
        match request_exchange(
            &LocalEndpoint::default_for_user(),
            &result_request,
            CURRENT_TIMEOUT,
        )
        .await
        {
            Ok(exchange) => match exchange.result.body {
                ResultBody::Success {
                    payload: ResultPayload::FlowRun(result),
                    ..
                } if exchange.events.is_empty() => outcome = Some(outcome_view(&result)),
                ResultBody::Failure(failure) => detail_error = Some(failure.message),
                ResultBody::Success { .. } => {
                    detail_error = Some("PAM returned an unexpected flow result.".to_owned());
                }
            },
            Err(error) => detail_error = Some(error.to_string()),
        }
    }
    RunView {
        request: summary,
        timeline,
        outcome,
        detail_error,
    }
}

pub(crate) fn timeline_from_events(events: &[EventEnvelope]) -> Vec<TimelineFact> {
    let mut facts = Vec::new();
    for envelope in events {
        match &envelope.event {
            Event::Accepted => facts.push(fact(
                TimelineKind::Request,
                "Request received",
                "PAM accepted the run.",
                false,
            )),
            Event::Started => facts.push(fact(
                TimelineKind::Request,
                "Run started",
                "PAM began the run.",
                false,
            )),
            Event::LeaseExpired => facts.push(fact(
                TimelineKind::Failure,
                "Lease expired",
                "PAM will recover this run from durable state.",
                false,
            )),
            Event::CancellationRequested => facts.push(fact(
                TimelineKind::Request,
                "Cancellation requested",
                "PAM is stopping at a safe boundary.",
                false,
            )),
            Event::Cancelled => facts.push(fact(
                TimelineKind::Failure,
                "Run cancelled",
                "The run was cancelled.",
                false,
            )),
            Event::Completed => facts.push(fact(
                TimelineKind::Request,
                "Run completed",
                "A terminal result is available.",
                false,
            )),
            Event::Failed => facts.push(fact(
                TimelineKind::Failure,
                "Run failed",
                "The run ended with a failure.",
                false,
            )),
            Event::FlowTransition(transition) if transition.semantic_events().is_empty() => {
                facts.push(transition_fact(transition.kind()));
            }
            Event::FlowTransition(transition) => {
                facts.extend(transition.semantic_events().iter().map(semantic_fact));
            }
        }
    }
    facts
}

pub(crate) fn outcome_view(result: &FlowRunResult) -> OutcomeView {
    let (heading, solved) = outcome_heading(result.outcome());
    let report = result.report();
    let sections = [
        ("SOLVED", report.solved()),
        ("CHANGED", report.changed()),
        ("VERIFIED", report.verified()),
        ("UNRESOLVED", report.unresolved()),
        ("BLOCKED", report.blocked()),
    ]
    .into_iter()
    .map(|(label, section)| OutcomeSectionView {
        label,
        summary: section.summary().to_owned(),
        satisfied: section.satisfied(),
    })
    .collect();
    let mut seen = HashSet::new();
    let mut evidence = Vec::new();
    let mut evidence_truncated = false;
    for section in [
        report.solved(),
        report.changed(),
        report.verified(),
        report.unresolved(),
        report.blocked(),
    ] {
        evidence_truncated |= section.evidence_truncated();
        for handle in section.evidence() {
            if seen.insert(handle.as_str().to_owned())
                && let Ok(handle) = EvidenceHandle::parse(handle.as_str())
            {
                evidence.push(handle);
            }
        }
    }
    OutcomeView {
        heading,
        solved,
        sections,
        evidence,
        evidence_truncated,
    }
}

const fn outcome_heading(outcome: RunOutcome) -> (&'static str, bool) {
    match outcome {
        RunOutcome::Solved => ("Ready for the next agent", true),
        RunOutcome::Unresolved => ("Run needs follow-up", false),
        RunOutcome::Blocked => ("Run is blocked", false),
        RunOutcome::Cancelled => ("Run was cancelled", false),
    }
}

fn semantic_fact(event: &FlowSemanticEvent) -> TimelineFact {
    match event {
        FlowSemanticEvent::Waiting {
            step_id, reason, ..
        } => fact(
            TimelineKind::Request,
            "Waiting",
            &format!("Step {step_id} is waiting for {}.", wait_reason(*reason)),
            false,
        ),
        FlowSemanticEvent::ApprovalRequired { step_id } => fact(
            TimelineKind::Request,
            "Approval required",
            &format!("Step {step_id} requires a human decision."),
            false,
        ),
        FlowSemanticEvent::EvidenceFound { step_id, evidence } => TimelineFact {
            kind: TimelineKind::Evidence,
            label: "Evidence found".to_owned(),
            summary: format!(
                "Step {step_id} recorded {} evidence item(s).",
                evidence.len()
            ),
            verified: false,
            evidence: core_evidence(evidence),
        },
        FlowSemanticEvent::FixApplied { report, .. } => TimelineFact {
            kind: TimelineKind::Change,
            label: "Fix applied".to_owned(),
            summary: report.summary().to_owned(),
            verified: false,
            evidence: core_evidence(report.evidence()),
        },
        FlowSemanticEvent::VerificationPassed { report, .. } => TimelineFact {
            kind: TimelineKind::Verification,
            label: "Verification passed".to_owned(),
            summary: report.summary().to_owned(),
            verified: true,
            evidence: core_evidence(report.evidence()),
        },
        FlowSemanticEvent::Unresolved { report, .. } => TimelineFact {
            kind: TimelineKind::Failure,
            label: "Unresolved".to_owned(),
            summary: report.summary().to_owned(),
            verified: false,
            evidence: core_evidence(report.evidence()),
        },
        FlowSemanticEvent::Blocked { report, .. } => TimelineFact {
            kind: TimelineKind::Failure,
            label: "Blocked".to_owned(),
            summary: report.summary().to_owned(),
            verified: false,
            evidence: core_evidence(report.evidence()),
        },
    }
}

fn transition_fact(kind: &TransitionKind) -> TimelineFact {
    let (timeline_kind, label, summary) = match kind {
        TransitionKind::StepSkipped { .. } => (
            TimelineKind::Change,
            "Step skipped",
            "A flow step was skipped by its declared condition.",
        ),
        TransitionKind::ApprovalRequested { .. } => (
            TimelineKind::Request,
            "Approval required",
            "A step requires a human decision.",
        ),
        TransitionKind::ApprovalGranted { .. } => (
            TimelineKind::Change,
            "Approval granted",
            "The exact step effect was approved.",
        ),
        TransitionKind::ApprovalDenied { .. }
        | TransitionKind::EffectAuthorizationDenied { .. } => (
            TimelineKind::Failure,
            "Approval denied",
            "The exact step effect was denied.",
        ),
        TransitionKind::EffectEvaluationRequired { .. } => (
            TimelineKind::Request,
            "Evaluation required",
            "A flow effect requires evaluation.",
        ),
        TransitionKind::EffectStarted { .. } => (
            TimelineKind::Change,
            "Work started",
            "A flow effect started.",
        ),
        TransitionKind::EffectSucceeded { .. } => (
            TimelineKind::Change,
            "Work completed",
            "A flow effect completed.",
        ),
        TransitionKind::RetryScheduled { .. } => (
            TimelineKind::Request,
            "Retry scheduled",
            "PAM scheduled another bounded attempt.",
        ),
        TransitionKind::RetryExhausted { .. } => (
            TimelineKind::Failure,
            "Retries exhausted",
            "The flow exhausted its bounded attempts.",
        ),
        TransitionKind::EffectFailed { .. } => (
            TimelineKind::Failure,
            "Work failed",
            "A flow effect failed.",
        ),
        TransitionKind::ReconciledNotApplied { .. } => (
            TimelineKind::Change,
            "Effect reconciled",
            "PAM verified that the effect was not applied.",
        ),
        TransitionKind::ReconciliationUnknown { .. } => (
            TimelineKind::Failure,
            "Reconciliation unknown",
            "PAM could not verify the prior effect state.",
        ),
        TransitionKind::CancellationRequested => (
            TimelineKind::Request,
            "Cancellation requested",
            "PAM is stopping at a safe boundary.",
        ),
        TransitionKind::RunCompleted { outcome } => (
            if *outcome == RunOutcome::Solved {
                TimelineKind::Request
            } else {
                TimelineKind::Failure
            },
            "Run completed",
            "The flow reached a terminal result.",
        ),
    };
    fact(timeline_kind, label, summary, false)
}

fn core_evidence(handles: &[pam_flow::EvidenceHandle]) -> Vec<EvidenceHandle> {
    handles
        .iter()
        .filter_map(|handle| EvidenceHandle::parse(handle.as_str()).ok())
        .collect()
}

const fn wait_reason(reason: FlowWaitReason) -> &'static str {
    match reason {
        FlowWaitReason::Approval => "approval",
        FlowWaitReason::EffectResult => "an effect result",
        FlowWaitReason::Retry => "a retry boundary",
        FlowWaitReason::Reconciliation => "reconciliation",
    }
}

fn fact(kind: TimelineKind, label: &str, summary: &str, verified: bool) -> TimelineFact {
    TimelineFact {
        kind,
        label: label.to_owned(),
        summary: summary.to_owned(),
        verified,
        evidence: Vec::new(),
    }
}

fn degraded(detail: impl Into<String>, recovery: Option<String>) -> CurrentState {
    CurrentState::Degraded {
        code: None,
        detail: detail.into(),
        recovery,
    }
}

fn failure_state(failure: Failure) -> CurrentState {
    if matches!(
        failure.code,
        FailureCode::Forbidden | FailureCode::ApprovalRequired
    ) {
        CurrentState::Blocked {
            code: failure.code,
            detail: failure.message,
            recovery: failure.recovery,
        }
    } else {
        degraded(failure.message, failure.recovery)
    }
}

#[cfg(test)]
pub(crate) fn failure_state_for_test(failure: Failure) -> CurrentState {
    failure_state(failure)
}

pub(crate) fn unique_request_id(prefix: &str) -> RequestId {
    RequestId::new(format!("{prefix}-{}", Uuid::new_v4()))
}

pub(crate) fn unique_idempotency(prefix: &str) -> IdempotencyKey {
    IdempotencyKey::new(format!("{prefix}-{}", Uuid::new_v4()))
}

#[cfg(test)]
pub(crate) fn pending_approval_for_test(
    request: RequestEnvelope,
    challenge: ApprovalChallenge,
) -> PendingApproval {
    PendingApproval {
        challenge,
        request: Box::new(request),
    }
}

#[cfg(test)]
pub(crate) fn timeline_semantic_for_test(event: &FlowSemanticEvent) -> TimelineFact {
    semantic_fact(event)
}

#[cfg(test)]
pub(crate) fn timeline_transition_for_test(kind: &TransitionKind) -> TimelineFact {
    transition_fact(kind)
}

#[cfg(test)]
pub(crate) const fn outcome_heading_for_test(outcome: RunOutcome) -> (&'static str, bool) {
    outcome_heading(outcome)
}
