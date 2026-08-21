use std::{ffi::OsStr, fs, path::PathBuf};

use pam_core::{ContentDigest, ProjectId};
use pam_skills::{
    AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent,
    SKILLS_AUDIT_REPORT_SCHEMA_VERSION, ScanLimits,
};
use pam_store::Store;
use serde_json::json;
use uuid::Uuid;

use crate::{
    SkillAuditEvaluationDto, SkillAuditSaturationGradeDto,
    skill_audit::{
        MAX_SKILL_AUDIT_RANKED_ARTIFACTS, load_persisted_skill_audit,
        run_skill_audit_with_path_for_test,
    },
    skill_inventory::SkillInventoryEnvironment,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pam-gui-audit-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn empty_report(schema_version: u32) -> String {
    serde_json::to_string_pretty(&json!({
        "schemaVersion": schema_version,
        "footprint": {
            "schemaVersion": 1,
            "estimator": "raw_bytes_div_4_ceil_v1",
            "alwaysLoadedArtifactCount": 0,
            "allSessionRawBytes": 0,
            "allSessionEstimatedTokens": 0,
            "artifacts": [],
            "originAgentSessionTotals": [],
            "allSessionScopeTotals": []
        },
        "evaluation": { "status": "no_evaluator" }
    }))
    .unwrap()
}

fn footprint_artifact(
    rank: u64,
    name: &str,
    logical_path: &str,
    kind: ArtifactKind,
    origin: OriginAgent,
    digest_byte: u8,
    raw_bytes: u64,
) -> serde_json::Value {
    let artifact = AgentArtifact::new(
        name,
        logical_path,
        kind,
        ArtifactScope::Project,
        origin,
        LoadSemantics::Always,
        ContentDigest::from_sha256([digest_byte; 32]),
    )
    .unwrap();
    json!({
        "rank": rank,
        "id": artifact.id().to_string(),
        "name": name,
        "logicalPath": logical_path,
        "kind": kind.as_str(),
        "scope": "project",
        "origin": origin.as_str(),
        "loadSemantics": "always",
        "contentHash": artifact.content_hash().to_string(),
        "rawBytes": raw_bytes,
        "estimatedTokens": raw_bytes / 4 + u64::from(!raw_bytes.is_multiple_of(4))
    })
}

async fn persist_report(
    state_path: &std::path::Path,
    project_id: ProjectId,
    observed_at_ms: u64,
    report_json: String,
) {
    let store = Store::open(state_path).unwrap();
    store
        .put_skills_audit_report(
            project_id,
            observed_at_ms,
            SKILLS_AUDIT_REPORT_SCHEMA_VERSION,
            report_json,
        )
        .await
        .unwrap();
    store.shutdown().await.unwrap();
}

fn environment(
    directory: &TestDirectory,
    observed_at_ms: u64,
) -> (PathBuf, PathBuf, SkillInventoryEnvironment) {
    let home = directory.path().join("home");
    let project = directory.path().join("project");
    let state = directory.path().join("state.sqlite3");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();
    let environment =
        SkillInventoryEnvironment::for_test(home, project.clone(), state.clone(), observed_at_ms);
    (project, state, environment)
}

#[tokio::test]
async fn load_returns_none_when_no_audit_has_been_persisted() {
    let directory = TestDirectory::new("missing");
    let state = directory.path().join("state.sqlite3");

    let loaded = load_persisted_skill_audit(ProjectId::new("missing-audit"), &state)
        .await
        .unwrap();

    assert!(loaded.is_none());
}

#[tokio::test]
async fn deterministic_only_stored_report_loads_as_typed_metadata() {
    let directory = TestDirectory::new("deterministic-load");
    let state = directory.path().join("state.sqlite3");
    let project_id = ProjectId::new("deterministic-audit");
    persist_report(&state, project_id.clone(), 42, empty_report(1)).await;

    let loaded = load_persisted_skill_audit(project_id, &state)
        .await
        .unwrap()
        .unwrap();
    let encoded = serde_json::to_value(&loaded).unwrap();

    assert_eq!(loaded.observed_at_ms, 42);
    assert_eq!(loaded.footprint.always_loaded_artifact_count, 0);
    assert!(matches!(
        loaded.evaluation,
        SkillAuditEvaluationDto::NoEvaluator
    ));
    assert!(encoded.get("reportJson").is_none());
    assert!(encoded.get("projectId").is_none());
}

#[tokio::test]
async fn explicit_empty_path_run_persists_pretty_json_and_exposes_no_sources() {
    let directory = TestDirectory::new("empty-path");
    let (project, state, environment) = environment(&directory, 100);
    let rule = project.join(".cursor/rules/project.mdc");
    fs::create_dir_all(rule.parent().unwrap()).unwrap();
    let source_marker = "PRIVATE-SKILL-SOURCE-MARKER";
    fs::write(
        &rule,
        format!("---\nalwaysApply: true\n---\n{source_marker}\n"),
    )
    .unwrap();
    let project_id = ProjectId::new("empty-path-audit");

    let ran = run_skill_audit_with_path_for_test(project_id.clone(), environment, OsStr::new(""))
        .await
        .unwrap();
    let loaded = load_persisted_skill_audit(project_id.clone(), &state)
        .await
        .unwrap()
        .unwrap();
    let store = Store::open(&state).unwrap();
    let stored = store
        .skills_audit_report(project_id)
        .await
        .unwrap()
        .unwrap();
    store.shutdown().await.unwrap();
    let response = serde_json::to_string(&ran).unwrap();

    assert_eq!(ran, loaded);
    assert!(matches!(
        ran.evaluation,
        SkillAuditEvaluationDto::NoEvaluator
    ));
    assert_eq!(ran.footprint.always_loaded_artifact_count, 1);
    assert!(stored.report_json.starts_with("{\n"));
    assert!(!response.contains(source_marker));
    assert!(!response.contains(project.to_string_lossy().as_ref()));
    for forbidden in ["sourceBody", "reportJson", "executable", "stderr", "prompt"] {
        assert!(!response.contains(forbidden));
    }
}

#[tokio::test]
async fn malformed_and_column_mismatched_stored_reports_are_rejected() {
    let malformed_directory = TestDirectory::new("malformed");
    let malformed_state = malformed_directory.path().join("state.sqlite3");
    let malformed_project = ProjectId::new("malformed-audit");
    persist_report(
        &malformed_state,
        malformed_project.clone(),
        1,
        r#"{"schemaVersion":1}"#.to_owned(),
    )
    .await;

    assert!(
        load_persisted_skill_audit(malformed_project, &malformed_state)
            .await
            .is_err()
    );

    let mismatch_directory = TestDirectory::new("schema-mismatch");
    let mismatch_state = mismatch_directory.path().join("state.sqlite3");
    let mismatch_project = ProjectId::new("schema-mismatch-audit");
    persist_report(
        &mismatch_state,
        mismatch_project.clone(),
        1,
        empty_report(2),
    )
    .await;

    assert!(
        load_persisted_skill_audit(mismatch_project, &mismatch_state)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stored_footprints_cannot_exceed_the_production_scan_limits() {
    let directory = TestDirectory::new("stored-limit");
    let state = directory.path().join("state.sqlite3");
    let project_id = ProjectId::new("stored-limit-audit");
    let raw_bytes = u64::try_from(ScanLimits::default().max_file_bytes).unwrap() + 1;
    let estimated_tokens = raw_bytes / 4 + u64::from(!raw_bytes.is_multiple_of(4));
    let report = json!({
        "schemaVersion": 1,
        "footprint": {
            "schemaVersion": 1,
            "estimator": "raw_bytes_div_4_ceil_v1",
            "alwaysLoadedArtifactCount": 1,
            "allSessionRawBytes": raw_bytes,
            "allSessionEstimatedTokens": estimated_tokens,
            "artifacts": [footprint_artifact(
                1,
                "oversized",
                "AGENTS.md",
                ArtifactKind::Instruction,
                OriginAgent::Codex,
                1,
                raw_bytes,
            )],
            "originAgentSessionTotals": [{
                "origin": "codex",
                "artifactCount": 1,
                "rawBytes": raw_bytes,
                "estimatedTokens": estimated_tokens
            }],
            "allSessionScopeTotals": [{
                "scope": "project",
                "artifactCount": 1,
                "rawBytes": raw_bytes,
                "estimatedTokens": estimated_tokens
            }]
        },
        "evaluation": { "status": "no_evaluator" }
    });
    persist_report(
        &state,
        project_id.clone(),
        1,
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .await;

    assert!(
        load_persisted_skill_audit(project_id, &state)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stored_footprint_aggregate_rows_must_be_in_canonical_order() {
    let directory = TestDirectory::new("stored-order");
    let state = directory.path().join("state.sqlite3");
    let project_id = ProjectId::new("stored-order-audit");
    let report = json!({
        "schemaVersion": 1,
        "footprint": {
            "schemaVersion": 1,
            "estimator": "raw_bytes_div_4_ceil_v1",
            "alwaysLoadedArtifactCount": 2,
            "allSessionRawBytes": 12,
            "allSessionEstimatedTokens": 3,
            "artifacts": [
                footprint_artifact(
                    1,
                    "cursor-rule",
                    ".cursor/rules/a.mdc",
                    ArtifactKind::Rule,
                    OriginAgent::Cursor,
                    1,
                    8,
                ),
                footprint_artifact(
                    2,
                    "codex-instructions",
                    "AGENTS.md",
                    ArtifactKind::Instruction,
                    OriginAgent::Codex,
                    2,
                    4,
                )
            ],
            "originAgentSessionTotals": [
                {
                    "origin": "cursor",
                    "artifactCount": 1,
                    "rawBytes": 8,
                    "estimatedTokens": 2
                },
                {
                    "origin": "codex",
                    "artifactCount": 1,
                    "rawBytes": 4,
                    "estimatedTokens": 1
                }
            ],
            "allSessionScopeTotals": [{
                "scope": "project",
                "artifactCount": 2,
                "rawBytes": 12,
                "estimatedTokens": 3
            }]
        },
        "evaluation": { "status": "no_evaluator" }
    });
    persist_report(
        &state,
        project_id.clone(),
        1,
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .await;

    assert!(
        load_persisted_skill_audit(project_id, &state)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stored_evaluator_verdict_is_revalidated_against_the_footprint_corpus() {
    let directory = TestDirectory::new("validated-verdict");
    let (project, state, environment) = environment(&directory, 1);
    let rule = project.join(".cursor/rules/project.mdc");
    fs::create_dir_all(rule.parent().unwrap()).unwrap();
    fs::write(&rule, "---\nalwaysApply: true\n---\nReview carefully.\n").unwrap();
    let project_id = ProjectId::new("validated-verdict-audit");
    run_skill_audit_with_path_for_test(project_id.clone(), environment, OsStr::new(""))
        .await
        .unwrap();
    let store = Store::open(&state).unwrap();
    let stored = store
        .skills_audit_report(project_id.clone())
        .await
        .unwrap()
        .unwrap();
    store.shutdown().await.unwrap();
    let mut report = serde_json::from_str::<serde_json::Value>(&stored.report_json).unwrap();
    report["evaluation"] = json!({
        "status": "evaluated",
        "evaluator": "codex",
        "verdict": {
            "overlaps": [],
            "conflicts": [],
            "staleCandidates": [],
            "saturationGrade": "healthy",
            "overallSummary": "The bounded corpus is healthy."
        }
    });
    persist_report(
        &state,
        project_id.clone(),
        2,
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .await;

    let loaded = load_persisted_skill_audit(project_id.clone(), &state)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        loaded.evaluation,
        SkillAuditEvaluationDto::Evaluated {
            verdict: crate::SkillAuditVerdictDto {
                saturation_grade: SkillAuditSaturationGradeDto::Healthy,
                ..
            },
            ..
        }
    ));

    report["evaluation"]["verdict"]["staleCandidates"] = json!([{
        "artifactId": format!("artifact:sha256:{}", "0".repeat(64)),
        "reason": "This ID is not in the corpus."
    }]);
    persist_report(
        &state,
        project_id.clone(),
        3,
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .await;

    assert!(
        load_persisted_skill_audit(project_id, &state)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn incomplete_scan_does_not_persist_an_audit_report() {
    let directory = TestDirectory::new("incomplete");
    let (project, state, environment) = environment(&directory, 10);
    fs::write(project.join("AGENTS.md"), vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let project_id = ProjectId::new("incomplete-audit");

    assert!(
        run_skill_audit_with_path_for_test(project_id.clone(), environment, OsStr::new(""))
            .await
            .is_err()
    );
    assert!(
        load_persisted_skill_audit(project_id, &state)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn ranked_response_rows_are_capped_with_truthful_total() {
    let directory = TestDirectory::new("rank-cap");
    let (project, _state, environment) = environment(&directory, 10);
    let rules = project.join(".cursor/rules");
    fs::create_dir_all(&rules).unwrap();
    for index in 0..=MAX_SKILL_AUDIT_RANKED_ARTIFACTS {
        fs::write(
            rules.join(format!("rule-{index:03}.mdc")),
            format!("---\nalwaysApply: true\n---\nRule {index}.\n"),
        )
        .unwrap();
    }

    let report = run_skill_audit_with_path_for_test(
        ProjectId::new("rank-cap-audit"),
        environment,
        OsStr::new(""),
    )
    .await
    .unwrap();

    assert_eq!(
        report.footprint.ranked_artifacts.len(),
        MAX_SKILL_AUDIT_RANKED_ARTIFACTS
    );
    assert_eq!(
        report.footprint.ranked_artifacts_total,
        MAX_SKILL_AUDIT_RANKED_ARTIFACTS + 1
    );
    assert!(report.footprint.ranked_artifacts_truncated);
}

#[test]
fn audit_dtos_reject_unknown_fields() {
    let mut value = serde_json::to_value(json!({
        "observedAtMs": 1,
        "footprint": {
            "estimator": "raw_bytes_div_4_ceil_v1",
            "alwaysLoadedArtifactCount": 0,
            "allSessionRawBytes": 0,
            "allSessionEstimatedTokens": 0,
            "originSessions": [],
            "scopeTotals": [],
            "rankedArtifacts": [],
            "rankedArtifactsTotal": 0,
            "rankedArtifactsTruncated": false
        },
        "evaluation": { "status": "no_evaluator" }
    }))
    .unwrap();
    value["ambientAuthority"] = json!("/tmp/untrusted");

    assert!(serde_json::from_value::<crate::SkillAuditDataDto>(value).is_err());
}
