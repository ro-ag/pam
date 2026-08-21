use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{
    AgentArtifactId,
    verdict::{
        MAX_VERDICT_ARTIFACT_IDS_PER_FINDING, MAX_VERDICT_FINDING_TEXT_BYTES,
        MAX_VERDICT_FINDINGS_PER_CATEGORY, MAX_VERDICT_OVERALL_SUMMARY_BYTES,
        MIN_VERDICT_ARTIFACT_IDS_PER_FINDING, SaturationGrade, VerdictParseError,
        parse_skills_audit_verdict, skills_audit_verdict_json_schema,
    },
};

fn artifact_id(number: u64) -> AgentArtifactId {
    AgentArtifactId::parse(format!("artifact:sha256:{number:064x}")).unwrap()
}

fn artifact_id_text(number: u64) -> String {
    artifact_id(number).to_string()
}

fn allowed_ids(count: u64) -> BTreeSet<AgentArtifactId> {
    (0..count).map(artifact_id).collect()
}

fn empty_verdict() -> Value {
    json!({
        "overlaps": [],
        "conflicts": [],
        "staleCandidates": [],
        "saturationGrade": "healthy",
        "overallSummary": "No material saturation."
    })
}

fn parse(value: &Value, allowed: &BTreeSet<AgentArtifactId>) -> VerdictParseError {
    parse_skills_audit_verdict(&serde_json::to_string(value).unwrap(), allowed).unwrap_err()
}

#[test]
fn valid_verdict_is_canonicalized_and_round_trips_as_camel_case_json() {
    let allowed = allowed_ids(8);
    let value = json!({
        "overlaps": [
            {
                "artifactIds": [artifact_id_text(4), artifact_id_text(1)],
                "summary": "Later overlap"
            },
            {
                "artifactIds": [artifact_id_text(3), artifact_id_text(1)],
                "summary": "Earlier overlap"
            }
        ],
        "conflicts": [{
            "artifactIds": [artifact_id_text(6), artifact_id_text(2), artifact_id_text(1)],
            "summary": "Conflicting requirements"
        }],
        "staleCandidates": [
            {"artifactId": artifact_id_text(5), "reason": "Older guidance"},
            {"artifactId": artifact_id_text(2), "reason": "Superseded guidance"}
        ],
        "saturationGrade": "elevated",
        "overallSummary": "Some consolidation is warranted."
    });

    let verdict = parse_skills_audit_verdict(&value.to_string(), &allowed).unwrap();

    assert_eq!(verdict.saturation_grade(), SaturationGrade::Elevated);
    assert_eq!(verdict.saturation_grade().as_str(), "elevated");
    assert_eq!(
        verdict.overall_summary(),
        "Some consolidation is warranted."
    );
    assert_eq!(
        verdict.overlaps()[0].artifact_ids(),
        &[artifact_id(1), artifact_id(3)]
    );
    assert_eq!(verdict.overlaps()[0].summary(), "Earlier overlap");
    assert_eq!(
        verdict.overlaps()[1].artifact_ids(),
        &[artifact_id(1), artifact_id(4)]
    );
    assert_eq!(
        verdict.conflicts()[0].artifact_ids(),
        &[artifact_id(1), artifact_id(2), artifact_id(6)]
    );
    assert_eq!(verdict.conflicts()[0].summary(), "Conflicting requirements");
    assert_eq!(verdict.stale_candidates()[0].artifact_id(), &artifact_id(2));
    assert_eq!(
        verdict.stale_candidates()[0].reason(),
        "Superseded guidance"
    );

    let serialized = serde_json::to_string(&verdict).unwrap();
    assert!(serialized.contains("\"staleCandidates\""));
    assert!(serialized.contains("\"saturationGrade\""));
    assert!(serialized.contains("\"overallSummary\""));
    assert!(!serialized.contains("stale_candidates"));
    let round_trip = parse_skills_audit_verdict(&serialized, &allowed).unwrap();
    assert_eq!(verdict, round_trip);
}

#[test]
fn unknown_root_and_finding_fields_are_rejected() {
    let allowed = allowed_ids(3);
    let mut root_unknown = empty_verdict();
    root_unknown["unexpected"] = json!(true);
    assert_eq!(
        parse(&root_unknown, &allowed),
        VerdictParseError::MalformedJson
    );

    let mut finding_unknown = empty_verdict();
    finding_unknown["overlaps"] = json!([{
        "artifactIds": [artifact_id_text(0), artifact_id_text(1)],
        "summary": "Overlap",
        "unexpected": "private"
    }]);
    assert_eq!(
        parse(&finding_unknown, &allowed),
        VerdictParseError::MalformedJson
    );
}

#[test]
fn malformed_unknown_duplicate_and_miscounted_ids_are_rejected() {
    let allowed = allowed_ids(20);

    let mut malformed = empty_verdict();
    malformed["staleCandidates"] =
        json!([{"artifactId": "artifact:sha256:not-canonical", "reason": "Old"}]);
    assert_eq!(
        parse(&malformed, &allowed),
        VerdictParseError::MalformedArtifactId
    );

    let mut unknown = empty_verdict();
    unknown["staleCandidates"] = json!([{"artifactId": artifact_id_text(99), "reason": "Old"}]);
    assert_eq!(
        parse(&unknown, &allowed),
        VerdictParseError::UnknownArtifactId
    );

    let mut duplicate = empty_verdict();
    duplicate["overlaps"] = json!([{
        "artifactIds": [artifact_id_text(1), artifact_id_text(1)],
        "summary": "Duplicate"
    }]);
    assert_eq!(
        parse(&duplicate, &allowed),
        VerdictParseError::DuplicateArtifactId
    );

    for artifact_ids in [
        vec![artifact_id_text(1)],
        (0..=MAX_VERDICT_ARTIFACT_IDS_PER_FINDING as u64)
            .map(artifact_id_text)
            .collect(),
    ] {
        let mut miscounted = empty_verdict();
        miscounted["conflicts"] = json!([{
            "artifactIds": artifact_ids,
            "summary": "Wrong count"
        }]);
        assert_eq!(
            parse(&miscounted, &allowed),
            VerdictParseError::InvalidArtifactIdCount
        );
    }
}

#[test]
fn every_text_field_rejects_blanks_controls_and_utf8_byte_overflow() {
    let allowed = allowed_ids(3);
    for invalid_summary in [
        " \u{2003}".to_owned(),
        "private\nsummary".to_owned(),
        "é".repeat(MAX_VERDICT_OVERALL_SUMMARY_BYTES / 2 + 1),
    ] {
        let mut value = empty_verdict();
        value["overallSummary"] = json!(invalid_summary);
        assert_eq!(parse(&value, &allowed), VerdictParseError::InvalidText);
    }

    let oversized = "é".repeat(MAX_VERDICT_FINDING_TEXT_BYTES / 2 + 1);
    for (category, text_field) in [
        ("overlaps", "summary"),
        ("conflicts", "summary"),
        ("staleCandidates", "reason"),
    ] {
        let mut value = empty_verdict();
        let mut finding = if category == "staleCandidates" {
            json!({"artifactId": artifact_id_text(0)})
        } else {
            json!({"artifactIds": [artifact_id_text(0), artifact_id_text(1)]})
        };
        finding[text_field] = json!(oversized);
        value[category] = json!([finding]);
        assert_eq!(parse(&value, &allowed), VerdictParseError::InvalidText);
    }

    let mut exact_bounds = empty_verdict();
    exact_bounds["overallSummary"] = json!("x".repeat(MAX_VERDICT_OVERALL_SUMMARY_BYTES));
    exact_bounds["overlaps"] = json!([{
        "artifactIds": [artifact_id_text(0), artifact_id_text(1)],
        "summary": "x".repeat(MAX_VERDICT_FINDING_TEXT_BYTES)
    }]);
    parse_skills_audit_verdict(&exact_bounds.to_string(), &allowed).unwrap();
}

#[test]
fn each_finding_array_is_capped_and_semantic_duplicates_are_rejected() {
    let allowed = allowed_ids(MAX_VERDICT_FINDINGS_PER_CATEGORY as u64 + 2);
    for category in ["overlaps", "conflicts", "staleCandidates"] {
        let findings = (1..=MAX_VERDICT_FINDINGS_PER_CATEGORY as u64 + 1)
            .map(|number| {
                if category == "staleCandidates" {
                    json!({"artifactId": artifact_id_text(number), "reason": "Old"})
                } else {
                    json!({
                        "artifactIds": [artifact_id_text(0), artifact_id_text(number)],
                        "summary": "Related"
                    })
                }
            })
            .collect::<Vec<_>>();
        let mut value = empty_verdict();
        value[category] = Value::Array(findings);
        assert_eq!(parse(&value, &allowed), VerdictParseError::TooManyFindings);
    }

    for category in ["overlaps", "conflicts"] {
        let mut value = empty_verdict();
        value[category] = json!([
            {
                "artifactIds": [artifact_id_text(0), artifact_id_text(1)],
                "summary": "First wording"
            },
            {
                "artifactIds": [artifact_id_text(1), artifact_id_text(0)],
                "summary": "Second wording"
            }
        ]);
        assert_eq!(parse(&value, &allowed), VerdictParseError::DuplicateFinding);
    }

    let mut stale_duplicates = empty_verdict();
    stale_duplicates["staleCandidates"] = json!([
        {"artifactId": artifact_id_text(1), "reason": "First wording"},
        {"artifactId": artifact_id_text(1), "reason": "Second wording"}
    ]);
    assert_eq!(
        parse(&stale_duplicates, &allowed),
        VerdictParseError::DuplicateFinding
    );
}

#[test]
fn json_schema_exactly_exposes_runtime_shape_and_bounds() {
    let schema = skills_audit_verdict_json_schema();

    assert_eq!(schema["type"], "object");
    assert_eq!(
        schema["x-maxJsonUtf8Bytes"],
        super::verdict::MAX_VERDICT_JSON_BYTES
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        json!([
            "overlaps",
            "conflicts",
            "staleCandidates",
            "saturationGrade",
            "overallSummary"
        ])
    );
    for category in ["overlaps", "conflicts", "staleCandidates"] {
        assert_eq!(schema["properties"][category]["type"], "array");
        assert_eq!(schema["properties"][category]["minItems"], 0);
        assert_eq!(
            schema["properties"][category]["maxItems"],
            MAX_VERDICT_FINDINGS_PER_CATEGORY
        );
        assert_eq!(schema["properties"][category]["uniqueItems"], true);
    }
    assert_eq!(
        schema["properties"]["overlaps"]["items"]["$ref"],
        "#/$defs/overlap"
    );
    assert_eq!(
        schema["properties"]["conflicts"]["items"]["$ref"],
        "#/$defs/conflict"
    );
    assert_eq!(
        schema["properties"]["staleCandidates"]["items"]["$ref"],
        "#/$defs/staleCandidate"
    );
    assert_eq!(
        schema["properties"]["saturationGrade"]["enum"],
        json!(["healthy", "elevated", "high", "critical"])
    );
    assert_eq!(schema["$defs"]["artifactId"]["minLength"], 80);
    assert_eq!(schema["$defs"]["artifactId"]["maxLength"], 80);
    assert_eq!(
        schema["$defs"]["artifactId"]["pattern"],
        r"^artifact:sha256:[0-9a-f]{64}$"
    );
    for finding in ["overlap", "conflict"] {
        assert_eq!(schema["$defs"][finding]["additionalProperties"], false);
        assert_eq!(
            schema["$defs"][finding]["required"],
            json!(["artifactIds", "summary"])
        );
        assert_eq!(
            schema["$defs"][finding]["properties"]["artifactIds"]["minItems"],
            MIN_VERDICT_ARTIFACT_IDS_PER_FINDING
        );
        assert_eq!(
            schema["$defs"][finding]["properties"]["artifactIds"]["maxItems"],
            MAX_VERDICT_ARTIFACT_IDS_PER_FINDING
        );
        assert_eq!(
            schema["$defs"][finding]["properties"]["artifactIds"]["uniqueItems"],
            true
        );
        assert_eq!(
            schema["$defs"][finding]["properties"]["artifactIds"]["items"]["$ref"],
            "#/$defs/artifactId"
        );
        assert_eq!(
            schema["$defs"][finding]["properties"]["summary"]["x-maxUtf8Bytes"],
            MAX_VERDICT_FINDING_TEXT_BYTES
        );
    }
    assert_eq!(
        schema["$defs"]["staleCandidate"]["required"],
        json!(["artifactId", "reason"])
    );
    assert_eq!(
        schema["$defs"]["staleCandidate"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["staleCandidate"]["properties"]["reason"]["maxLength"],
        MAX_VERDICT_FINDING_TEXT_BYTES
    );
    assert_eq!(
        schema["properties"]["overallSummary"]["x-maxUtf8Bytes"],
        MAX_VERDICT_OVERALL_SUMMARY_BYTES
    );
    assert_eq!(
        schema["properties"]["overallSummary"]["maxLength"],
        MAX_VERDICT_OVERALL_SUMMARY_BYTES
    );
    assert_eq!(
        schema["properties"]["overallSummary"]["pattern"],
        r"^(?=.*\S)[^\u0000-\u001F\u007F-\u009F]*$"
    );
}

#[test]
fn errors_never_include_rejected_json_ids_text_or_paths() {
    let allowed = allowed_ids(2);
    let private_path = "/private/project/secret/AGENTS.md";
    let mut value = empty_verdict();
    value["staleCandidates"] = json!([{
        "artifactId": private_path,
        "reason": "private evaluator explanation"
    }]);

    let error = parse(&value, &allowed);
    let rendered = format!("{error:?} {error}");

    assert_eq!(error, VerdictParseError::MalformedArtifactId);
    assert!(!rendered.contains(private_path));
    assert!(!rendered.contains("private evaluator explanation"));
    assert!(!rendered.contains("AGENTS.md"));
}
