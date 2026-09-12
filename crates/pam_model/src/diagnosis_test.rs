use super::diagnosis::*;

/// One task with a two-byte-character evidence item and one offered read:
/// the fixture every validation test starts from.
fn task() -> DiagnosisTask {
    let hypotheses = vec![
        Hypothesis {
            name: "code".into(),
            definition: "compiler, assertion or program failure evidence".into(),
        },
        Hypothesis {
            name: UNKNOWN_HYPOTHESIS.into(),
            definition: "insufficient or competing evidence".into(),
        },
    ];
    let data = DiagnosisData {
        statuses: serde_json::json!({"build": "FAILURE"}),
        complete: true,
        completeness_notes: vec!["node 6 log tail omitted earlier content".into()],
        evidence: vec![
            EvidenceItem {
                id: "ev_ascii".into(),
                name: "stage.log".into(),
                tags: vec!["program_failure".into()],
                text: "error: assertion failed in publish at line 41".into(),
            },
            EvidenceItem {
                id: "ev_utf8".into(),
                name: "notes.log".into(),
                tags: vec![],
                text: "café décor — résumé of the failed run".into(),
            },
        ],
        reads: vec![AllowedRead {
            operation_id: "read_failed_stage".into(),
            target_ref: "target_7".into(),
            description: "the failed stage's node log".into(),
        }],
    };
    DiagnosisTask::new(
        "jenkins-build-failure/v1",
        "What failed and why?",
        hypotheses,
        data,
    )
    .expect("the fixture task is in bounds")
}

#[test]
fn unknown_hypothesis_is_required() {
    let result = DiagnosisTask::new(
        "recipe/v1",
        "Why?",
        vec![Hypothesis {
            name: "code".into(),
            definition: "d".into(),
        }],
        DiagnosisData::default(),
    );
    assert_eq!(result.unwrap_err().cause, "hypotheses");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the bound table is one exhaustive pass over every refusal cause; splitting it \
              would hide which bounds are covered"
)]
fn task_bounds_are_enforced() {
    let long = "x".repeat(600);
    let hypotheses = vec![Hypothesis {
        name: UNKNOWN_HYPOTHESIS.into(),
        definition: "d".into(),
    }];
    assert_eq!(
        DiagnosisTask::new("", "q", hypotheses.clone(), DiagnosisData::default())
            .unwrap_err()
            .cause,
        "recipe_identity"
    );
    assert_eq!(
        DiagnosisTask::new(&long, "q", hypotheses.clone(), DiagnosisData::default())
            .unwrap_err()
            .cause,
        "recipe_identity"
    );
    assert_eq!(
        DiagnosisTask::new("r/v1", "", hypotheses.clone(), DiagnosisData::default())
            .unwrap_err()
            .cause,
        "question"
    );
    assert_eq!(
        DiagnosisTask::new("r/v1", &long, hypotheses.clone(), DiagnosisData::default())
            .unwrap_err()
            .cause,
        "question"
    );
    let duplicated = vec![
        Hypothesis {
            name: UNKNOWN_HYPOTHESIS.into(),
            definition: "d".into(),
        },
        Hypothesis {
            name: UNKNOWN_HYPOTHESIS.into(),
            definition: "d again".into(),
        },
    ];
    assert_eq!(
        DiagnosisTask::new("r/v1", "q", duplicated, DiagnosisData::default())
            .unwrap_err()
            .cause,
        "hypotheses"
    );
    let oversized = DiagnosisData {
        evidence: vec![EvidenceItem {
            id: "ev_big".into(),
            name: "big.log".into(),
            tags: vec![],
            text: "y".repeat(MAX_EVIDENCE_ITEM_BYTES + 1),
        }],
        ..DiagnosisData::default()
    };
    assert_eq!(
        DiagnosisTask::new("r/v1", "q", hypotheses.clone(), oversized)
            .unwrap_err()
            .cause,
        "evidence_set"
    );
    let too_many = DiagnosisData {
        evidence: (0..=MAX_EVIDENCE_ITEMS)
            .map(|index| EvidenceItem {
                id: format!("ev_{index}"),
                name: format!("{index}.log"),
                tags: vec![],
                text: "t".into(),
            })
            .collect(),
        ..DiagnosisData::default()
    };
    assert_eq!(
        DiagnosisTask::new("r/v1", "q", hypotheses.clone(), too_many)
            .unwrap_err()
            .cause,
        "evidence_set"
    );
    let duplicated_ids = DiagnosisData {
        evidence: vec![
            EvidenceItem {
                id: "ev_x".into(),
                name: "a".into(),
                tags: vec![],
                text: "t".into(),
            },
            EvidenceItem {
                id: "ev_x".into(),
                name: "b".into(),
                tags: vec![],
                text: "u".into(),
            },
        ],
        ..DiagnosisData::default()
    };
    assert_eq!(
        DiagnosisTask::new("r/v1", "q", hypotheses.clone(), duplicated_ids)
            .unwrap_err()
            .cause,
        "evidence_set"
    );
    let oversized_statuses = DiagnosisData {
        statuses: serde_json::json!({ "blob": "s".repeat(MAX_EVIDENCE_ITEM_BYTES + 1) }),
        ..DiagnosisData::default()
    };
    assert_eq!(
        DiagnosisTask::new("r/v1", "q", hypotheses, oversized_statuses)
            .unwrap_err()
            .cause,
        "statuses"
    );
}

#[test]
#[allow(
    clippy::float_cmp,
    reason = "greedy decoding is exactly temperature 0.0; the contract requires the exact \
              value, not an approximation"
)]
fn the_request_carries_the_spec_framing() {
    let request = task().request();
    assert_eq!(request.system.as_deref(), Some(SYSTEM_PROMPT));
    assert_eq!(request.temperature, 0.0);
    assert_eq!(request.max_tokens, RESPONSE_MAX_TOKENS);
    assert!(request.stop.is_empty());
    let prompt = request.prompt;
    assert!(prompt.starts_with("TASK: jenkins-build-failure/v1\n"));
    assert!(prompt.contains("\nQUESTION: What failed and why?\n"));
    assert!(prompt.contains("- code: compiler, assertion or program failure evidence\n"));
    assert!(prompt.contains(&format!(
        "- {UNKNOWN_HYPOTHESIS}: insufficient or competing evidence\n"
    )));
    assert!(prompt.contains("RESPONSE_SCHEMA: "));
    assert!(prompt.contains("\"offset_basis\":\"each evidence item's text, UTF-8 bytes\""));
    assert!(prompt.contains("read_failed_stage"));
    assert!(prompt.contains("target_7"));
    // Evidence text is in DATA so offsets mean something to the model.
    assert!(prompt.contains("assertion failed in publish"));
}

#[test]
fn the_illustrative_read_request_is_admitted() {
    let raw = r#"{
        "hypothesis": "unknown",
        "confidence": "low",
        "summary": "Build output does not identify the failed stage.",
        "citations": [],
        "next": {"operation_id": "read_failed_stage", "target_ref": "target_7"}
    }"#;
    let verdict = validate(raw, &task()).expect("the spec's illustrative response is valid");
    assert_eq!(verdict.hypothesis, UNKNOWN_HYPOTHESIS);
    assert_eq!(verdict.confidence, Confidence::Low);
    assert!(verdict.citations.is_empty());
    assert_eq!(
        verdict.next,
        NextStep::Read {
            operation_id: "read_failed_stage".into(),
            target_ref: "target_7".into(),
        }
    );
}

#[test]
fn byte_offsets_index_multibyte_text() {
    // "café" spans bytes 0..5 — the é alone is two bytes (3..5).
    let raw = r#"{
        "hypothesis": "unknown",
        "confidence": "medium",
        "summary": "s",
        "citations": [{"evidence": "ev_utf8", "start": 0, "end": 5, "quote": "café"}],
        "next": "finish"
    }"#;
    let verdict = validate(raw, &task()).expect("a byte-offset citation over multibyte text");
    assert_eq!(verdict.citations[0].quote, "café");
    assert_eq!(verdict.next, NextStep::Finish);
}

#[test]
fn surrounding_prose_is_never_repaired() {
    let wrapped = format!(
        "Here is my analysis:\n{}\nHope that helps!",
        r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],"next":"finish"}"#
    );
    assert_eq!(validate(&wrapped, &task()).unwrap_err().cause, "not_json");
    assert_eq!(
        validate("{\"hypothesis\":", &task()).unwrap_err().cause,
        "not_json"
    );
    assert_eq!(validate("", &task()).unwrap_err().cause, "empty_response");
    assert_eq!(
        validate("   \n\t ", &task()).unwrap_err().cause,
        "empty_response"
    );
}

#[test]
fn the_field_set_is_exact() {
    let base = |fields: &str| {
        format!(
            r#"{{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],"next":"finish"{fields}}}"#
        )
    };
    assert_eq!(
        validate(&base(r#","extra":1"#), &task()).unwrap_err().cause,
        "schema_violation"
    );
    let missing = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[]}"#;
    assert_eq!(
        validate(missing, &task()).unwrap_err().cause,
        "schema_violation"
    );
    // A JSON array is not the declared object.
    assert_eq!(
        validate("[]", &task()).unwrap_err().cause,
        "schema_violation"
    );
}

#[test]
fn answers_outside_the_closed_sets_are_refused() {
    let merge = r#"{"hypothesis":"merge","confidence":"high","summary":"s","citations":[],"next":"finish"}"#;
    assert_eq!(
        validate(merge, &task()).unwrap_err().cause,
        "hypothesis_not_listed"
    );
    let confidence = r#"{"hypothesis":"unknown","confidence":"certain","summary":"s","citations":[],"next":"finish"}"#;
    assert_eq!(
        validate(confidence, &task()).unwrap_err().cause,
        "confidence_invalid"
    );
}

#[test]
fn summary_bound_counts_characters_not_bytes() {
    let ok: String = "é".repeat(MAX_SUMMARY_CHARS);
    let raw = serde_json::json!({
        "hypothesis": "unknown", "confidence": "low", "summary": ok,
        "citations": [], "next": "finish"
    })
    .to_string();
    assert!(
        validate(&raw, &task()).is_ok(),
        "{} bytes is {} chars",
        ok.len(),
        MAX_SUMMARY_CHARS
    );
    let long: String = "é".repeat(MAX_SUMMARY_CHARS + 1);
    let raw = serde_json::json!({
        "hypothesis": "unknown", "confidence": "low", "summary": long,
        "citations": [], "next": "finish"
    })
    .to_string();
    assert_eq!(
        validate(&raw, &task()).unwrap_err().cause,
        "summary_too_long"
    );
    let empty = r#"{"hypothesis":"unknown","confidence":"low","summary":"","citations":[],"next":"finish"}"#;
    assert_eq!(
        validate(empty, &task()).unwrap_err().cause,
        "schema_violation"
    );
}

#[test]
fn citation_discipline_is_enforced() {
    let four = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":1,"quote":"e"},
        {"evidence":"ev_ascii","start":1,"end":2,"quote":"r"},
        {"evidence":"ev_ascii","start":2,"end":3,"quote":"r"},
        {"evidence":"ev_ascii","start":3,"end":4,"quote":"o"}],"next":"finish"}"#;
    assert_eq!(
        validate(four, &task()).unwrap_err().cause,
        "too_many_citations"
    );

    let forged = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_absent","start":0,"end":1,"quote":"e"}],"next":"finish"}"#;
    assert_eq!(
        validate(forged, &task()).unwrap_err().cause,
        "evidence_not_in_scope"
    );

    let past_end = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":999,"quote":"e"}],"next":"finish"}"#;
    assert_eq!(
        validate(past_end, &task()).unwrap_err().cause,
        "offset_out_of_range"
    );

    let empty_span = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":7,"end":7,"quote":""}],"next":"finish"}"#;
    assert_eq!(
        validate(empty_span, &task()).unwrap_err().cause,
        "offset_out_of_range"
    );

    let wrong_bytes = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":5,"quote":"fatal"}],"next":"finish"}"#;
    assert_eq!(
        validate(wrong_bytes, &task()).unwrap_err().cause,
        "quote_mismatch"
    );

    // The same span with the exact bytes is admitted.
    let honest = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":5,"quote":"error"}],"next":"finish"}"#;
    let verdict = validate(honest, &task()).expect("an exact quote proves the span");
    assert_eq!(verdict.citations[0].quote, "error");

    // A quote whose JSON escaping decodes to the real bytes is honest too.
    let escaped = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_utf8","start":0,"end":9,"quote":"caf\u00e9 d\u00e9"}],"next":"finish"}"#;
    assert!(validate(escaped, &task()).is_ok());

    let extra_field = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":5,"quote":"error","note":"x"}],"next":"finish"}"#;
    assert_eq!(
        validate(extra_field, &task()).unwrap_err().cause,
        "schema_violation"
    );
}

#[test]
fn forged_read_pairs_are_refused() {
    let unknown_operation = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],
        "next":{"operation_id":"run_deploy","target_ref":"target_7"}}"#;
    assert_eq!(
        validate(unknown_operation, &task()).unwrap_err().cause,
        "read_not_offered"
    );
    let unknown_target = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],
        "next":{"operation_id":"read_failed_stage","target_ref":"target_9"}}"#;
    assert_eq!(
        validate(unknown_target, &task()).unwrap_err().cause,
        "read_not_offered"
    );
    let extra_field = r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],
        "next":{"operation_id":"read_failed_stage","target_ref":"target_7","args":{"job":"x"}}}"#;
    assert_eq!(
        validate(extra_field, &task()).unwrap_err().cause,
        "schema_violation"
    );
}

#[test]
fn whitespace_around_the_object_is_tolerated() {
    let raw = format!(
        "\n  {}  \n",
        r#"{"hypothesis":"unknown","confidence":"low","summary":"s","citations":[],"next":"finish"}"#
    );
    assert!(validate(&raw, &task()).is_ok());
}

#[test]
fn verbatim_quotes_resolve_their_own_offsets() {
    // `end < start` and a span past the end: the counting is wrong, the
    // quote is exact. The host resolves the span; validate() still checks it.
    let miscounted = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":30,"end":12,"quote":"assertion failed"},
        {"evidence":"ev_utf8","start":900,"end":950,"quote":"décor"}],"next":"finish"}"#;
    assert_eq!(
        validate(miscounted, &task()).unwrap_err().cause,
        "offset_out_of_range"
    );

    let resolved = resolve_citation_offsets(miscounted, &task());
    assert_eq!(resolved.resolved, 2);
    let verdict = validate(&resolved.text, &task()).expect("resolved spans are byte-exact");
    assert_eq!(
        verdict.citations[0],
        Citation {
            evidence: "ev_ascii".into(),
            start: 7,
            end: 23,
            quote: "assertion failed".into(),
        }
    );
    // Multibyte text resolves to byte offsets, not character offsets.
    assert_eq!(
        (verdict.citations[1].start, verdict.citations[1].end),
        (6, 12)
    );
    assert_eq!(verdict.citations[1].quote, "décor");
}

#[test]
fn already_exact_offsets_pass_through_untouched() {
    let honest = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":5,"quote":"error"}],"next":"finish"}"#;
    let resolved = resolve_citation_offsets(honest, &task());
    assert_eq!(resolved.resolved, 0);
    assert_eq!(resolved.text, honest);
}

#[test]
fn repeated_quotes_resolve_to_the_occurrence_nearest_the_claimed_start() {
    // 'e' occurs at bytes 0, 10, 21 and 41 of the ASCII item; a claimed
    // start of 20 lands on 21.
    let repeated = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":20,"end":20,"quote":"e"}],"next":"finish"}"#;
    let resolved = resolve_citation_offsets(repeated, &task());
    assert_eq!(resolved.resolved, 1);
    let verdict = validate(&resolved.text, &task()).expect("a real occurrence was chosen");
    assert_eq!(
        (verdict.citations[0].start, verdict.citations[0].end),
        (21, 22)
    );
}

#[test]
fn resolution_never_invents_or_repairs_anything_else() {
    // A quote absent from the evidence stays a quote_mismatch.
    let absent = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":0,"end":5,"quote":"fatal"}],"next":"finish"}"#;
    let resolved = resolve_citation_offsets(absent, &task());
    assert_eq!(resolved.resolved, 0);
    assert_eq!(resolved.text, absent);
    assert_eq!(
        validate(&resolved.text, &task()).unwrap_err().cause,
        "quote_mismatch"
    );

    // Evidence outside the call is not searched.
    let foreign = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_absent","start":0,"end":1,"quote":"error"}],"next":"finish"}"#;
    let resolved = resolve_citation_offsets(foreign, &task());
    assert_eq!(resolved.resolved, 0);
    assert_eq!(
        validate(&resolved.text, &task()).unwrap_err().cause,
        "evidence_not_in_scope"
    );

    // Offsets that do not respect the schema are not rewritten into shape.
    let typed_wrong = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":"0","end":5,"quote":"error"}],"next":"finish"}"#;
    let resolved = resolve_citation_offsets(typed_wrong, &task());
    assert_eq!(resolved.resolved, 0);
    assert_eq!(
        validate(&resolved.text, &task()).unwrap_err().cause,
        "schema_violation"
    );

    // Empty quotes match nothing.
    let empty = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[
        {"evidence":"ev_ascii","start":3,"end":3,"quote":""}],"next":"finish"}"#;
    assert_eq!(resolve_citation_offsets(empty, &task()).resolved, 0);

    // Non-JSON and non-object completions pass through byte-for-byte.
    let truncated = r#"{"hypothesis":"code","confidence":"high","summary":"s","citations":[{"evidence":"ev_ascii","#;
    assert_eq!(resolve_citation_offsets(truncated, &task()).text, truncated);
    assert_eq!(resolve_citation_offsets("[1,2]", &task()).text, "[1,2]");
    assert_eq!(validate(truncated, &task()).unwrap_err().cause, "not_json");
}
