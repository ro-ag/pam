use pam_core::{ContentDigest, EvidenceHandle, ProjectId, RequestId};
use pam_protocol::{
    BriefItem, BriefProvenance, BriefResult, ConfigurationPresence, Event, EventEnvelope,
    EvidenceMetadata, EvidenceRedaction, EvidenceRetention, Failure, FailureCode,
    NetworkDiagnosticsResult, OperationTruth, PROTOCOL_VERSION, PacState, ResultBody,
    ResultPayload, SourceAvailability,
};

use super::render::{
    EXIT_NOT_FOUND, EXIT_OPERATION_FAILED, EXIT_PENDING, present_result, render_brief,
    render_events, render_evidence_preview,
};

fn handle() -> EvidenceHandle {
    EvidenceHandle::parse("evidence://ci/1842/failure").unwrap()
}

#[test]
fn network_diagnostics_renders_only_sanitized_configuration_facts() {
    let presentation = present_result(&ResultBody::Success {
        truth: OperationTruth::Observed,
        payload: ResultPayload::NetworkDiagnostics(NetworkDiagnosticsResult {
            platform_roots_enabled: true,
            system_proxy_discovery_enabled: true,
            proxy_environment_presence: ConfigurationPresence::Configured,
            no_proxy_presence: ConfigurationPresence::Invalid,
            pac_state: PacState::DetectedUnsupported,
        }),
    });

    assert_eq!(
        presentation.stdout,
        "platform_roots_enabled=true system_proxy_discovery_enabled=true proxy_environment=configured no_proxy=invalid pac=detected_unsupported truth=observed\n"
    );
    assert!(presentation.stderr.is_empty());
}

#[test]
fn brief_renders_only_the_stable_sections_in_order_with_truth_and_availability() {
    let brief = BriefResult {
        goal: Some(BriefItem {
            text: "Ship\u{1b}[31m continuity".to_owned(),
            truth: OperationTruth::Observed,
            evidence: vec![handle()],
        }),
        decisions: Vec::new(),
        verified: vec![BriefItem {
            text: "tests pass".to_owned(),
            truth: OperationTruth::Verified,
            evidence: Vec::new(),
        }],
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "pam".to_owned(),
            availability: SourceAvailability::Partial,
            truth: OperationTruth::Observed,
            evidence: Some(handle()),
            detail: Some("connector\noffline".to_owned()),
        }],
    };

    assert_eq!(
        render_brief(&brief),
        concat!(
            "Goal\n",
            "- [observed] Ship\\u{1b}[31m continuity\n",
            "  Evidence: evidence://ci/1842/failure\n",
            "Decisions\n",
            "- unresolved [source-availability=partial]\n",
            "Verified\n",
            "- [verified] tests pass\n",
            "Next\n",
            "- unresolved [source-availability=partial]\n",
            "Provenance\n",
            "- pam [availability=partial truth=observed] evidence=evidence://ci/1842/failure detail=connector\\noffline\n",
        )
    );
}

#[test]
fn unavailable_brief_fields_are_explicit() {
    let brief = BriefResult {
        goal: None,
        decisions: Vec::new(),
        verified: Vec::new(),
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "planning-context".to_owned(),
            availability: SourceAvailability::Unavailable,
            truth: OperationTruth::Unresolved,
            evidence: None,
            detail: Some("not configured".to_owned()),
        }],
    };
    let rendered = render_brief(&brief);

    assert!(rendered.starts_with("Goal\n- unavailable [source-availability=unavailable]\n"));
    assert!(rendered.ends_with(
        "Provenance\n- planning-context [availability=unavailable truth=unresolved] detail=not configured\n"
    ));
}

#[test]
fn available_sources_distinguish_empty_sections_from_unavailable_ones() {
    let rendered = render_brief(&BriefResult {
        goal: None,
        decisions: Vec::new(),
        verified: Vec::new(),
        next: Vec::new(),
        provenance: vec![BriefProvenance {
            source: "planning-context".to_owned(),
            availability: SourceAvailability::Available,
            truth: OperationTruth::Observed,
            evidence: None,
            detail: None,
        }],
    });

    assert!(rendered.contains("Decisions\n- empty [source-availability=available]\n"));
    assert!(!rendered.contains("source-availability=unavailable"));
}

#[test]
fn event_rendering_preserves_gap_free_input_order() {
    let event = |sequence, event| EventEnvelope {
        protocol_version: PROTOCOL_VERSION,
        request_id: RequestId::from("target-1"),
        project_id: ProjectId::from("project-1"),
        sequence,
        event,
    };

    assert_eq!(
        render_events(&[event(8, Event::Started), event(9, Event::Completed)]),
        "sequence=8 event=started\nsequence=9 event=completed\n"
    );
}

#[test]
fn pending_not_found_and_unresolved_have_deterministic_nonzero_exits() {
    let failure = |code| {
        present_result(&ResultBody::Failure(Failure {
            code,
            message: "not ready".to_owned(),
            recovery: None,
            approval: None,
        }))
    };

    assert_eq!(failure(FailureCode::Pending).exit_code, EXIT_PENDING);
    assert_eq!(failure(FailureCode::NotFound).exit_code, EXIT_NOT_FOUND);
    assert_eq!(
        present_result(&ResultBody::Success {
            truth: OperationTruth::Unresolved,
            payload: ResultPayload::Brief(BriefResult {
                goal: None,
                decisions: Vec::new(),
                verified: Vec::new(),
                next: Vec::new(),
                provenance: Vec::new(),
            }),
        })
        .exit_code,
        EXIT_OPERATION_FAILED
    );
}

#[test]
fn evidence_preview_escapes_every_control_and_non_ascii_byte() {
    let metadata = EvidenceMetadata {
        handle: handle(),
        digest: ContentDigest::from_sha256([0xab; 32]),
        size_bytes: 8,
        media_type: "text/plain\u{1b}\u{202e}\u{00e9}".to_owned(),
        retention: EvidenceRetention::Project,
        redaction: EvidenceRedaction::Unredacted,
        created_at_unix_ms: 42,
    };
    let rendered =
        render_evidence_preview(&metadata, b"ok\n\x1b[31m\xff", &OperationTruth::Observed);

    assert!(rendered.contains("Media-Type: text/plain\\u{1b}\\u{202e}\\u{e9}\n"));
    assert!(rendered.contains("Truth: observed\n"));
    assert!(rendered.ends_with("Preview:\nok\\n\\x1b[31m\\xff\n"));
    assert!(!rendered.as_bytes().contains(&0x1b));
}
