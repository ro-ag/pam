use std::fmt::Write as _;

use pam_protocol::{
    BriefItem, BriefProvenance, BriefResult, CancellationDisposition, Event, EventEnvelope,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure, FailureCode, OperationTruth,
    ResultBody, ResultPayload, SourceAvailability,
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
        writeln!(
            rendered,
            "sequence={} event={}",
            event.sequence,
            event_label(&event.event)
        )
        .expect("writing to a String cannot fail");
    }
    rendered
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
    }
}

fn failure_code_label(code: &FailureCode) -> &'static str {
    match code {
        FailureCode::UnsupportedProtocolVersion => "unsupported_protocol_version",
        FailureCode::InvalidRequest => "invalid_request",
        FailureCode::FrameTooLarge => "frame_too_large",
        FailureCode::NotFound => "not_found",
        FailureCode::Pending => "pending",
        FailureCode::IdempotencyConflict => "idempotency_conflict",
        FailureCode::Cancelled => "cancelled",
        FailureCode::LeaseConflict => "lease_conflict",
        FailureCode::Internal => "internal",
    }
}
