use std::fmt::Write as _;

use pam_protocol::{
    BriefItem, BriefProvenance, BriefResult, CancellationDisposition, ConfigurationPresence, Event,
    EventEnvelope, EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure, FailureCode,
    ModelFinishReason, OperationTruth, PacState, ResultBody, ResultPayload, SourceAvailability,
};

pub(crate) const EXIT_OK: i32 = 0;
pub(crate) const EXIT_OPERATION_FAILED: i32 = 2;
pub(crate) const EXIT_PENDING: i32 = 3;
pub(crate) const EXIT_NOT_FOUND: i32 = 4;
const EVIDENCE_PREVIEW_BYTES: usize = 4 * 1024;

pub(crate) struct Presentation {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
}

pub(crate) fn present_result(body: &ResultBody) -> Presentation {
    match body {
        ResultBody::Failure(failure) => present_failure(failure),
        ResultBody::Success { truth, payload } => Presentation {
            stdout: render_success(payload, truth),
            stderr: String::new(),
            exit_code: truth_exit_code(truth),
        },
    }
}

pub(crate) fn render_events(events: &[EventEnvelope]) -> String {
    let mut rendered = String::new();
    for event in events {
        if let Event::FlowTransition(transition) = &event.event {
            if transition.semantic_events().is_empty() {
                write!(
                    rendered,
                    "sequence={} event=flow_transition flow_sequence={} ",
                    event.sequence,
                    transition.sequence()
                )
                .expect("writing to a String cannot fail");
                render_flow_transition(&mut rendered, transition.kind());
                rendered.push('\n');
            } else {
                for (semantic_index, semantic) in transition.semantic_events().iter().enumerate() {
                    write!(
                        rendered,
                        "sequence={} event=flow_progress flow_sequence={} semantic_index={} ",
                        event.sequence,
                        transition.sequence(),
                        semantic_index + 1
                    )
                    .expect("writing to a String cannot fail");
                    render_flow_semantic_event(&mut rendered, semantic);
                    rendered.push('\n');
                }
            }
        } else {
            writeln!(
                rendered,
                "sequence={} event={}",
                event.sequence,
                event_label(&event.event)
            )
            .expect("writing to a String cannot fail");
        }
    }
    rendered
}

fn render_flow_semantic_event(rendered: &mut String, event: &pam_flow::FlowSemanticEvent) {
    use pam_flow::FlowSemanticEvent;
    match event {
        FlowSemanticEvent::Waiting {
            step_id,
            reason,
            not_before_ms,
        } => {
            write!(
                rendered,
                "progress=waiting step={} reason={}",
                escape_text(step_id),
                flow_wait_reason_label(*reason)
            )
            .expect("writing to a String cannot fail");
            if let Some(not_before_ms) = not_before_ms {
                write!(rendered, " not_before_ms={not_before_ms}")
                    .expect("writing to a String cannot fail");
            }
        }
        FlowSemanticEvent::ApprovalRequired { step_id } => write!(
            rendered,
            "progress=approval_required step={}",
            escape_text(step_id)
        )
        .expect("writing to a String cannot fail"),
        FlowSemanticEvent::EvidenceFound { step_id, evidence } => {
            write!(
                rendered,
                "progress=evidence_found step={} evidence=",
                escape_text(step_id)
            )
            .expect("writing to a String cannot fail");
            render_flow_evidence(rendered, evidence);
        }
        FlowSemanticEvent::FixApplied { step_id, report } => {
            render_semantic_report(rendered, "fix_applied", step_id, report);
        }
        FlowSemanticEvent::VerificationPassed { step_id, report } => {
            render_semantic_report(rendered, "verification_passed", step_id, report);
        }
        FlowSemanticEvent::Unresolved { step_id, report } => {
            render_semantic_report(rendered, "unresolved", step_id, report);
        }
        FlowSemanticEvent::Blocked { step_id, report } => {
            render_semantic_report(rendered, "blocked", step_id, report);
        }
    }
}

fn render_semantic_report(
    rendered: &mut String,
    progress: &str,
    step_id: &str,
    report: &pam_flow::EffectReport,
) {
    write!(
        rendered,
        "progress={progress} step={} summary={} evidence=",
        escape_text(step_id),
        escape_text(report.summary())
    )
    .expect("writing to a String cannot fail");
    render_flow_evidence(rendered, report.evidence());
}

fn render_flow_transition(rendered: &mut String, kind: &pam_flow::TransitionKind) {
    use pam_flow::TransitionKind;
    match kind {
        TransitionKind::StepSkipped { step_id } => {
            write!(rendered, "transition=step_skipped step={}", escape_text(step_id))
        }
        TransitionKind::ApprovalRequested { step_id } => write!(
            rendered,
            "transition=approval_requested step={}",
            escape_text(step_id)
        ),
        TransitionKind::ApprovalGranted { step_id } => write!(
            rendered,
            "transition=approval_granted step={}",
            escape_text(step_id)
        ),
        TransitionKind::ApprovalDenied { step_id } => write!(
            rendered,
            "transition=approval_denied step={}",
            escape_text(step_id)
        ),
        TransitionKind::EffectEvaluationRequired { step_id, attempt } => write!(
            rendered,
            "transition=effect_evaluation_required step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::EffectAuthorizationDenied {
            step_id,
            attempt,
            replay,
        } => write!(
            rendered,
            "transition=effect_authorization_denied step={} attempt={attempt} replay={replay}",
            escape_text(step_id)
        ),
        TransitionKind::EffectStarted {
            step_id,
            attempt,
            replay,
        } => write!(
            rendered,
            "transition=effect_started step={} attempt={attempt} replay={replay}",
            escape_text(step_id)
        ),
        TransitionKind::EffectSucceeded { step_id, attempt } => write!(
            rendered,
            "transition=effect_succeeded step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::RetryScheduled {
            step_id,
            next_attempt,
            not_before_ms,
        } => write!(
            rendered,
            "transition=retry_scheduled step={} next_attempt={next_attempt} not_before_ms={not_before_ms}",
            escape_text(step_id)
        ),
        TransitionKind::RetryExhausted { step_id, attempt } => write!(
            rendered,
            "transition=retry_exhausted step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::EffectFailed { step_id, attempt } => write!(
            rendered,
            "transition=effect_failed step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::ReconciledNotApplied { step_id, attempt } => write!(
            rendered,
            "transition=reconciled_not_applied step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::ReconciliationUnknown { step_id, attempt } => write!(
            rendered,
            "transition=reconciliation_unknown step={} attempt={attempt}",
            escape_text(step_id)
        ),
        TransitionKind::CancellationRequested => {
            rendered.write_str("transition=cancellation_requested")
        }
        TransitionKind::RunCompleted { outcome } => write!(
            rendered,
            "transition=run_completed outcome={}",
            run_outcome_label(*outcome)
        ),
    }
    .expect("writing to a String cannot fail");
}

pub(crate) fn render_brief(brief: &BriefResult) -> String {
    let mut rendered = String::new();
    let availability = aggregate_availability(&brief.provenance);
    rendered.push_str("Goal\n");
    if let Some(goal) = &brief.goal {
        render_brief_item(&mut rendered, goal);
    } else {
        render_empty_brief_section(&mut rendered, availability);
    }

    rendered.push_str("Decisions\n");
    render_brief_items(&mut rendered, &brief.decisions, availability);
    rendered.push_str("Verified\n");
    render_brief_items(&mut rendered, &brief.verified, availability);
    rendered.push_str("Next\n");
    render_brief_items(&mut rendered, &brief.next, availability);

    rendered.push_str("Provenance\n");
    if brief.provenance.is_empty() {
        rendered.push_str("- [unresolved] unavailable\n");
    } else {
        for provenance in &brief.provenance {
            write!(
                rendered,
                "- {} [availability={} truth={}]",
                escape_text(&provenance.source),
                availability_label(&provenance.availability),
                truth_label(&provenance.truth)
            )
            .expect("writing to a String cannot fail");
            if let Some(evidence) = &provenance.evidence {
                write!(rendered, " evidence={evidence}").expect("writing to a String cannot fail");
            }
            if let Some(detail) = &provenance.detail {
                write!(rendered, " detail={}", escape_text(detail))
                    .expect("writing to a String cannot fail");
            }
            rendered.push('\n');
        }
    }
    rendered
}

pub(crate) fn render_evidence_preview(
    metadata: &EvidenceMetadata,
    bytes: &[u8],
    truth: &OperationTruth,
) -> String {
    let preview_length = bytes.len().min(EVIDENCE_PREVIEW_BYTES);
    let mut rendered = format!(
        "Handle: {}\nDigest: {}\nSize: {}\nMedia-Type: {}\nRetention: {}\nRedaction: {}\nCreated-at-unix-ms: {}\nTruth: {}\nPreview:\n{}",
        metadata.handle,
        metadata.digest,
        metadata.size_bytes,
        escape_text(&metadata.media_type),
        retention_label(&metadata.retention),
        redaction_label(&metadata.redaction),
        metadata.created_at_unix_ms,
        truth_label(truth),
        escape_preview_bytes(&bytes[..preview_length])
    );
    if preview_length < bytes.len() {
        write!(
            rendered,
            "\n[{} bytes omitted]",
            bytes.len() - preview_length
        )
        .expect("writing to a String cannot fail");
    }
    rendered.push('\n');
    rendered
}

pub(crate) fn escape_text(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() || !character.is_ascii() => {
                write!(escaped, "\\u{{{:x}}}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

fn escape_preview_bytes(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len());
    for byte in bytes {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            b' '..=b'~' => escaped.push(char::from(*byte)),
            byte => write!(escaped, "\\x{byte:02x}").expect("writing to a String cannot fail"),
        }
    }
    escaped
}

fn render_brief_items(
    rendered: &mut String,
    items: &[BriefItem],
    availability: AggregateAvailability,
) {
    if items.is_empty() {
        render_empty_brief_section(rendered, availability);
    } else {
        for item in items {
            render_brief_item(rendered, item);
        }
    }
}

#[derive(Clone, Copy)]
enum AggregateAvailability {
    Available,
    Partial,
    Unavailable,
}

fn aggregate_availability(provenance: &[BriefProvenance]) -> AggregateAvailability {
    if provenance.is_empty()
        || provenance
            .iter()
            .all(|source| source.availability == SourceAvailability::Unavailable)
    {
        AggregateAvailability::Unavailable
    } else if provenance
        .iter()
        .all(|source| source.availability == SourceAvailability::Available)
    {
        AggregateAvailability::Available
    } else {
        AggregateAvailability::Partial
    }
}

fn render_empty_brief_section(rendered: &mut String, availability: AggregateAvailability) {
    match availability {
        AggregateAvailability::Available => {
            rendered.push_str("- empty [source-availability=available]\n");
        }
        AggregateAvailability::Partial => {
            rendered.push_str("- unresolved [source-availability=partial]\n");
        }
        AggregateAvailability::Unavailable => {
            rendered.push_str("- unavailable [source-availability=unavailable]\n");
        }
    }
}

fn render_brief_item(rendered: &mut String, item: &BriefItem) {
    writeln!(
        rendered,
        "- [{}] {}",
        truth_label(&item.truth),
        escape_text(&item.text)
    )
    .expect("writing to a String cannot fail");
    if !item.evidence.is_empty() {
        rendered.push_str("  Evidence: ");
        for (index, evidence) in item.evidence.iter().enumerate() {
            if index > 0 {
                rendered.push_str(", ");
            }
            write!(rendered, "{evidence}").expect("writing to a String cannot fail");
        }
        rendered.push('\n');
    }
}

fn present_failure(failure: &Failure) -> Presentation {
    let mut stderr = format!(
        "Failure: {}\nMessage: {}\n",
        failure_code_label(&failure.code),
        escape_text(&failure.message)
    );
    if let Some(recovery) = &failure.recovery {
        writeln!(stderr, "Recovery: {}", escape_text(recovery))
            .expect("writing to a String cannot fail");
    }
    if let Some(approval) = &failure.approval {
        writeln!(
            stderr,
            "Approval: {} expires_at_unix_ms={}",
            approval.approval_id, approval.expires_at_unix_ms
        )
        .expect("writing to a String cannot fail");
    }
    let exit_code = match failure.code {
        FailureCode::Pending => EXIT_PENDING,
        FailureCode::NotFound => EXIT_NOT_FOUND,
        _ => EXIT_OPERATION_FAILED,
    };
    Presentation {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

fn render_success(payload: &ResultPayload, truth: &OperationTruth) -> String {
    match payload {
        ResultPayload::Status(status) => format!(
            "ready={} healthy={} daemon_version={} protocol_version={} queue_depth={} truth={}\n",
            status.ready,
            status.healthy,
            escape_text(&status.daemon_version),
            status.protocol_version,
            status.queue_depth,
            truth_label(truth)
        ),
        ResultPayload::Cancellation(cancellation) => format!(
            "target_request_id={} disposition={} truth={}\n",
            escape_text(cancellation.target_request_id.as_str()),
            cancellation_label(&cancellation.disposition),
            truth_label(truth)
        ),
        ResultPayload::Replay(replay) => format!(
            "target_request_id={} through_sequence={} pending={} truth={}\n",
            escape_text(replay.target_request_id.as_str()),
            replay.through_sequence,
            replay.pending,
            truth_label(truth)
        ),
        ResultPayload::Brief(brief) => render_brief(brief),
        ResultPayload::NetworkDiagnostics(diagnostics) => format!(
            "platform_roots_enabled={} system_proxy_discovery_enabled={} proxy_environment={} no_proxy={} pac={} truth={}\n",
            diagnostics.platform_roots_enabled,
            diagnostics.system_proxy_discovery_enabled,
            configuration_presence_label(diagnostics.proxy_environment_presence),
            configuration_presence_label(diagnostics.no_proxy_presence),
            pac_state_label(diagnostics.pac_state),
            truth_label(truth)
        ),
        ResultPayload::EvidenceMetadata(metadata) => format!(
            "handle={} digest={} size_bytes={} media_type={} retention={} redaction={} created_at_unix_ms={} truth={}\n",
            metadata.handle,
            metadata.digest,
            metadata.size_bytes,
            escape_text(&metadata.media_type),
            retention_label(&metadata.retention),
            redaction_label(&metadata.redaction),
            metadata.created_at_unix_ms,
            truth_label(truth)
        ),
        ResultPayload::EvidenceChunk(chunk) => format!(
            "handle={} offset={} size_bytes={} eof={} truth={}\n",
            chunk.handle,
            chunk.offset,
            chunk.bytes().len(),
            chunk.eof,
            truth_label(truth)
        ),
        ResultPayload::ModelGeneration(result) => format!(
            "model={} finish_reason={} input_tokens={} sampled_output_tokens={} emitted_output_tokens={} truth={}\nOutput:\n{}\n",
            escape_text(&result.model),
            model_finish_reason_label(result.finish_reason),
            result.usage.input_tokens,
            result.usage.sampled_output_tokens,
            result.usage.emitted_output_tokens,
            truth_label(truth),
            escape_text(result.text())
        ),
        ResultPayload::FlowRun(result) => render_flow_result(result, truth),
    }
}

fn render_flow_result(result: &pam_flow::FlowRunResult, truth: &OperationTruth) -> String {
    let mut rendered = format!(
        "run_id={} definition_digest={} outcome={} steps={} truth={}\n",
        escape_text(result.run_id().as_str()),
        result.definition_digest(),
        run_outcome_label(result.outcome()),
        result.steps().len(),
        truth_label(truth)
    );
    for (name, section) in [
        ("solved", result.report().solved()),
        ("changed", result.report().changed()),
        ("verified", result.report().verified()),
        ("unresolved", result.report().unresolved()),
        ("blocked", result.report().blocked()),
    ] {
        render_flow_outcome_section(&mut rendered, name, section);
    }
    for step in result.steps() {
        write!(
            rendered,
            "step={} semantic={} status={}",
            escape_text(step.step_id()),
            step_semantic_label(step.semantic_role()),
            step_result_label(step.kind())
        )
        .expect("writing to a String cannot fail");
        if let Some(effect_result) = step.result() {
            match effect_result.kind() {
                pam_flow::EffectResultKind::Succeeded => rendered.push_str(" result=succeeded"),
                pam_flow::EffectResultKind::Failed { retryable } => {
                    write!(rendered, " result=failed retryable={retryable}")
                        .expect("writing to a String cannot fail");
                }
            }
        }
        if let Some(report) = step.report() {
            write!(
                rendered,
                " summary={} evidence=",
                escape_text(report.summary())
            )
            .expect("writing to a String cannot fail");
            render_flow_evidence(&mut rendered, report.evidence());
        }
        rendered.push('\n');
    }
    rendered
}

fn render_flow_outcome_section(
    rendered: &mut String,
    name: &str,
    section: &pam_flow::FlowOutcomeSection,
) {
    write!(
        rendered,
        "outcome_section={name} satisfied={} summary={} steps=",
        section.satisfied(),
        escape_text(section.summary())
    )
    .expect("writing to a String cannot fail");
    if section.step_ids().is_empty() {
        rendered.push('-');
    } else {
        for (index, step_id) in section.step_ids().iter().enumerate() {
            if index > 0 {
                rendered.push(',');
            }
            rendered.push_str(&escape_text(step_id));
        }
    }
    rendered.push_str(" evidence=");
    render_flow_evidence(rendered, section.evidence());
    writeln!(
        rendered,
        " evidence_truncated={}",
        section.evidence_truncated()
    )
    .expect("writing to a String cannot fail");
}

fn render_flow_evidence(rendered: &mut String, evidence: &[pam_flow::EvidenceHandle]) {
    if evidence.is_empty() {
        rendered.push('-');
        return;
    }
    for (index, handle) in evidence.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        rendered.push_str(handle.as_str());
    }
}

const fn model_finish_reason_label(reason: ModelFinishReason) -> &'static str {
    match reason {
        ModelFinishReason::Stop => "stop",
        ModelFinishReason::Length => "length",
    }
}

const fn configuration_presence_label(presence: ConfigurationPresence) -> &'static str {
    match presence {
        ConfigurationPresence::NotConfigured => "not_configured",
        ConfigurationPresence::Configured => "configured",
        ConfigurationPresence::Invalid => "invalid",
    }
}

const fn pac_state_label(state: PacState) -> &'static str {
    match state {
        PacState::NotDetected => "not_detected",
        PacState::DetectedUnsupported => "detected_unsupported",
        PacState::InspectionUnavailable => "inspection_unavailable",
    }
}

fn truth_exit_code(truth: &OperationTruth) -> i32 {
    match truth {
        OperationTruth::Observed | OperationTruth::Changed | OperationTruth::Verified => EXIT_OK,
        OperationTruth::Unresolved | OperationTruth::Blocked => EXIT_OPERATION_FAILED,
    }
}

pub(crate) fn truth_label(truth: &OperationTruth) -> &'static str {
    match truth {
        OperationTruth::Observed => "observed",
        OperationTruth::Changed => "changed",
        OperationTruth::Verified => "verified",
        OperationTruth::Unresolved => "unresolved",
        OperationTruth::Blocked => "blocked",
    }
}

fn availability_label(availability: &SourceAvailability) -> &'static str {
    match availability {
        SourceAvailability::Available => "available",
        SourceAvailability::Partial => "partial",
        SourceAvailability::Unavailable => "unavailable",
    }
}

fn cancellation_label(disposition: &CancellationDisposition) -> &'static str {
    match disposition {
        CancellationDisposition::Requested => "requested",
        CancellationDisposition::AlreadyRequested => "already_requested",
        CancellationDisposition::AlreadyCancelled => "already_cancelled",
        CancellationDisposition::AlreadyTerminal => "already_terminal",
    }
}

fn retention_label(retention: &EvidenceRetention) -> &'static str {
    match retention {
        EvidenceRetention::Session => "session",
        EvidenceRetention::Project => "project",
        EvidenceRetention::Persistent => "persistent",
    }
}

fn redaction_label(redaction: &EvidenceRedaction) -> &'static str {
    match redaction {
        EvidenceRedaction::Unredacted => "unredacted",
        EvidenceRedaction::Redacted => "redacted",
    }
}

fn event_label(event: &Event) -> &'static str {
    match event {
        Event::Accepted => "accepted",
        Event::Started => "started",
        Event::LeaseExpired => "lease_expired",
        Event::CancellationRequested => "cancellation_requested",
        Event::Cancelled => "cancelled",
        Event::Completed => "completed",
        Event::Failed => "failed",
        Event::FlowTransition(_) => "flow_transition",
    }
}

const fn run_outcome_label(outcome: pam_flow::RunOutcome) -> &'static str {
    match outcome {
        pam_flow::RunOutcome::Solved => "solved",
        pam_flow::RunOutcome::Unresolved => "unresolved",
        pam_flow::RunOutcome::Blocked => "blocked",
        pam_flow::RunOutcome::Cancelled => "cancelled",
    }
}

const fn flow_wait_reason_label(reason: pam_flow::FlowWaitReason) -> &'static str {
    match reason {
        pam_flow::FlowWaitReason::Approval => "approval",
        pam_flow::FlowWaitReason::EffectResult => "effect_result",
        pam_flow::FlowWaitReason::Retry => "retry",
        pam_flow::FlowWaitReason::Reconciliation => "reconciliation",
    }
}

const fn step_semantic_label(semantic: pam_flow::StepSemanticRole) -> &'static str {
    match semantic {
        pam_flow::StepSemanticRole::Observe => "observe",
        pam_flow::StepSemanticRole::Verify => "verify",
        pam_flow::StepSemanticRole::Change => "change",
    }
}

const fn step_result_label(kind: pam_flow::StepRunResultKind) -> &'static str {
    match kind {
        pam_flow::StepRunResultKind::Succeeded => "succeeded",
        pam_flow::StepRunResultKind::Skipped => "skipped",
        pam_flow::StepRunResultKind::Failed => "failed",
        pam_flow::StepRunResultKind::Blocked => "blocked",
        pam_flow::StepRunResultKind::Cancelled => "cancelled",
        pam_flow::StepRunResultKind::NotRun => "not_run",
    }
}

fn failure_code_label(code: &FailureCode) -> &'static str {
    match code {
        FailureCode::Unauthenticated => "unauthenticated",
        FailureCode::Forbidden => "forbidden",
        FailureCode::ApprovalRequired => "approval_required",
        FailureCode::ApprovalDenied => "approval_denied",
        FailureCode::ApprovalExpired => "approval_expired",
        FailureCode::UnsupportedProtocolVersion => "unsupported_protocol_version",
        FailureCode::InvalidRequest => "invalid_request",
        FailureCode::FrameTooLarge => "frame_too_large",
        FailureCode::NotFound => "not_found",
        FailureCode::Pending => "pending",
        FailureCode::IdempotencyConflict => "idempotency_conflict",
        FailureCode::Cancelled => "cancelled",
        FailureCode::LeaseConflict => "lease_conflict",
        FailureCode::Busy => "busy",
        FailureCode::Internal => "internal",
    }
}
