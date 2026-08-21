use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    path::Path,
};

use pam_core::ProjectId;
use pam_skills::{
    AgentArtifact, AgentArtifactId, ArtifactScope, EvaluatorRunConfig, LoadSemantics, OriginAgent,
    SKILLS_AUDIT_REPORT_SCHEMA_VERSION, STATIC_FOOTPRINT_SCHEMA_VERSION, SaturationGrade,
    ScanLimits, SkillsAuditVerdict, StaticFootprintArtifact, StaticFootprintReport,
    parse_skills_audit_verdict, run_skills_audit, scan_local_inventory,
};
use pam_store::{Store, StoredSkillsAuditReport};
use serde::{Deserialize, Serialize};

use crate::{
    CommandFence,
    desktop::{DesktopErrorDto, DesktopResult},
    skill_inventory::SkillInventoryEnvironment,
};

pub(crate) const MAX_SKILL_AUDIT_RANKED_ARTIFACTS: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditDto {
    pub fence: CommandFence,
    pub data: Option<SkillAuditDataDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditDataDto {
    pub observed_at_ms: u64,
    pub footprint: SkillAuditFootprintDto,
    pub evaluation: SkillAuditEvaluationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditFootprintDto {
    pub estimator: String,
    pub always_loaded_artifact_count: u64,
    pub all_session_raw_bytes: u64,
    pub all_session_estimated_tokens: u64,
    pub origin_sessions: Vec<SkillAuditOriginSessionDto>,
    pub scope_totals: Vec<SkillAuditScopeTotalDto>,
    pub ranked_artifacts: Vec<SkillAuditArtifactDto>,
    pub ranked_artifacts_total: usize,
    pub ranked_artifacts_truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditOriginSessionDto {
    pub origin: String,
    pub artifact_count: u64,
    pub raw_bytes: u64,
    pub estimated_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditScopeTotalDto {
    pub scope: String,
    pub artifact_count: u64,
    pub raw_bytes: u64,
    pub estimated_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditArtifactDto {
    pub rank: u64,
    pub id: String,
    pub name: String,
    pub logical_path: String,
    pub kind: String,
    pub scope: String,
    pub origin: String,
    pub load_semantics: String,
    pub content_hash: String,
    pub raw_bytes: u64,
    pub estimated_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SkillAuditEvaluationDto {
    Evaluated {
        evaluator: SkillAuditEvaluatorDto,
        verdict: SkillAuditVerdictDto,
    },
    NoEvaluator,
    Failed {
        evaluator: SkillAuditEvaluatorDto,
        failure: SkillAuditFailureDto,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuditEvaluatorDto {
    Claude,
    Codex,
    CursorAgent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuditFailureDto {
    InvalidCorpus,
    PromptTooLarge,
    InvocationFailed,
    InvalidVerdict,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditVerdictDto {
    pub overlaps: Vec<SkillAuditMultiArtifactFindingDto>,
    pub conflicts: Vec<SkillAuditMultiArtifactFindingDto>,
    pub stale_candidates: Vec<SkillAuditStaleCandidateDto>,
    pub saturation_grade: SkillAuditSaturationGradeDto,
    pub overall_summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditMultiArtifactFindingDto {
    pub artifact_ids: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillAuditStaleCandidateDto {
    pub artifact_id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAuditSaturationGradeDto {
    Healthy,
    Elevated,
    High,
    Critical,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredReportDto {
    schema_version: u32,
    footprint: StaticFootprintReport,
    evaluation: StoredEvaluationDto,
}

#[derive(Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum StoredEvaluationDto {
    Evaluated {
        evaluator: SkillAuditEvaluatorDto,
        verdict: SkillAuditVerdictDto,
    },
    NoEvaluator,
    Failed {
        evaluator: SkillAuditEvaluatorDto,
        reason: SkillAuditFailureDto,
    },
}

struct GeneratedAudit {
    inventory: pam_skills::LocalInventoryReport,
    report_json: String,
    schema_version: u32,
}

pub(crate) async fn load_persisted_skill_audit(
    project_id: ProjectId,
    state_path: &Path,
) -> DesktopResult<Option<SkillAuditDataDto>> {
    let store = Store::open(state_path).map_err(store_error)?;
    let operation = store.skills_audit_report(project_id).await;
    let shutdown = store.shutdown().await;
    let stored = operation.map_err(store_error)?;
    shutdown.map_err(store_error)?;
    stored.as_ref().map(decode_stored_report).transpose()
}

pub(crate) async fn run_skill_audit_report(
    project_id: ProjectId,
    environment: SkillInventoryEnvironment,
) -> DesktopResult<SkillAuditDataDto> {
    run_skill_audit_with_path(
        project_id,
        environment,
        env::var_os("PATH").unwrap_or_default(),
    )
    .await
}

async fn run_skill_audit_with_path(
    project_id: ProjectId,
    environment: SkillInventoryEnvironment,
    injected_path: OsString,
) -> DesktopResult<SkillAuditDataDto> {
    let scan_environment = environment.clone();
    let generated = tokio::task::spawn_blocking(move || {
        let inventory = scan_local_inventory(scan_environment.roots(), ScanLimits::default())
            .map_err(|_| audit_scan_error())?;
        if !inventory.complete() {
            return Err(DesktopErrorDto::unavailable(
                format!(
                    "The skill audit scan stopped after {} bounded filesystem diagnostics.",
                    inventory.diagnostics().len()
                ),
                Some(
                    "Review local agent file permissions and boundaries, then retry the audit."
                        .to_owned(),
                ),
            ));
        }
        let report = run_skills_audit(
            inventory.scan_report(),
            scan_environment.project_root(),
            &injected_path,
            EvaluatorRunConfig::default(),
        )
        .map_err(|_| audit_run_error())?;
        let schema_version = report.schema_version();
        let report_json = serde_json::to_string_pretty(&report).map_err(|_| audit_run_error())?;
        Ok::<_, DesktopErrorDto>(GeneratedAudit {
            inventory,
            report_json,
            schema_version,
        })
    })
    .await
    .map_err(|_| {
        DesktopErrorDto::unavailable(
            "PAM could not join the bounded skill audit worker.",
            Some("Retry the skill audit.".to_owned()),
        )
    })??;

    let GeneratedAudit {
        inventory,
        report_json,
        schema_version,
    } = generated;
    let store = Store::open(environment.state_path()).map_err(store_error)?;
    let operation = store
        .put_skills_audit_snapshot(
            project_id,
            inventory.into_scan_report(),
            environment.observed_at_ms(),
            schema_version,
            report_json,
        )
        .await;
    let shutdown = store.shutdown().await;
    let stored = operation.map_err(store_error)?;
    shutdown.map_err(store_error)?;
    decode_stored_report(&stored)
}

#[cfg(test)]
pub(crate) async fn run_skill_audit_with_path_for_test(
    project_id: ProjectId,
    environment: SkillInventoryEnvironment,
    injected_path: &std::ffi::OsStr,
) -> DesktopResult<SkillAuditDataDto> {
    run_skill_audit_with_path(project_id, environment, injected_path.to_os_string()).await
}

fn decode_stored_report(stored: &StoredSkillsAuditReport) -> DesktopResult<SkillAuditDataDto> {
    let report = serde_json::from_str::<StoredReportDto>(&stored.report_json)
        .map_err(|_| stored_report_error())?;
    if stored.schema_version != SKILLS_AUDIT_REPORT_SCHEMA_VERSION
        || report.schema_version != stored.schema_version
    {
        return Err(stored_report_error());
    }
    let (footprint, allowed_artifact_ids) = footprint_dto(&report.footprint)?;
    let evaluation = evaluation_dto(report.evaluation, &allowed_artifact_ids)?;
    Ok(SkillAuditDataDto {
        observed_at_ms: stored.observed_at_ms,
        footprint,
        evaluation,
    })
}

fn footprint_dto(
    report: &StaticFootprintReport,
) -> DesktopResult<(SkillAuditFootprintDto, BTreeSet<AgentArtifactId>)> {
    if report.schema_version() != STATIC_FOOTPRINT_SCHEMA_VERSION {
        return Err(stored_report_error());
    }
    let artifacts = report.artifacts();
    let limits = ScanLimits::default();
    if artifacts.len() > limits.max_artifacts
        || report.always_loaded_artifact_count() != artifacts.len() as u64
    {
        return Err(stored_report_error());
    }
    let max_file_bytes = u64::try_from(limits.max_file_bytes).map_err(|_| stored_report_error())?;
    let max_aggregate_bytes =
        u64::try_from(limits.max_aggregate_bytes).map_err(|_| stored_report_error())?;

    let mut raw_bytes = 0_u64;
    let mut estimated_tokens = 0_u64;
    let mut by_origin = BTreeMap::<OriginAgent, (u64, u64, u64)>::new();
    let mut by_scope = BTreeMap::<ArtifactScope, (u64, u64, u64)>::new();
    let mut allowed_artifact_ids = BTreeSet::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        if artifact.raw_bytes() > max_file_bytes {
            return Err(stored_report_error());
        }
        validate_ranked_artifact(artifacts, index, artifact)?;
        if !allowed_artifact_ids.insert(artifact.id().clone()) {
            return Err(stored_report_error());
        }
        raw_bytes = raw_bytes
            .checked_add(artifact.raw_bytes())
            .ok_or_else(stored_report_error)?;
        estimated_tokens = estimated_tokens
            .checked_add(artifact.estimated_tokens())
            .ok_or_else(stored_report_error)?;
        add_totals(by_origin.entry(artifact.origin()).or_default(), artifact)?;
        add_totals(by_scope.entry(artifact.scope()).or_default(), artifact)?;
    }
    if raw_bytes > max_aggregate_bytes
        || raw_bytes != report.all_session_raw_bytes()
        || estimated_tokens != report.all_session_estimated_tokens()
        || !origin_totals_match(report, &by_origin)
        || !scope_totals_match(report, &by_scope)
    {
        return Err(stored_report_error());
    }

    let ranked_artifacts_total = artifacts.len();
    Ok((
        SkillAuditFootprintDto {
            estimator: report.estimator().as_str().to_owned(),
            always_loaded_artifact_count: report.always_loaded_artifact_count(),
            all_session_raw_bytes: report.all_session_raw_bytes(),
            all_session_estimated_tokens: report.all_session_estimated_tokens(),
            origin_sessions: report
                .origin_agent_session_totals()
                .iter()
                .map(|total| SkillAuditOriginSessionDto {
                    origin: total.origin().as_str().to_owned(),
                    artifact_count: total.artifact_count(),
                    raw_bytes: total.raw_bytes(),
                    estimated_tokens: total.estimated_tokens(),
                })
                .collect(),
            scope_totals: report
                .all_session_scope_totals()
                .iter()
                .map(|total| SkillAuditScopeTotalDto {
                    scope: total.scope().as_str().to_owned(),
                    artifact_count: total.artifact_count(),
                    raw_bytes: total.raw_bytes(),
                    estimated_tokens: total.estimated_tokens(),
                })
                .collect(),
            ranked_artifacts: artifacts
                .iter()
                .take(MAX_SKILL_AUDIT_RANKED_ARTIFACTS)
                .map(artifact_dto)
                .collect(),
            ranked_artifacts_total,
            ranked_artifacts_truncated: ranked_artifacts_total > MAX_SKILL_AUDIT_RANKED_ARTIFACTS,
        },
        allowed_artifact_ids,
    ))
}

fn validate_ranked_artifact(
    artifacts: &[StaticFootprintArtifact],
    index: usize,
    artifact: &StaticFootprintArtifact,
) -> DesktopResult<()> {
    let expected_rank = u64::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(stored_report_error)?;
    let expected_tokens =
        artifact.raw_bytes() / 4 + u64::from(!artifact.raw_bytes().is_multiple_of(4));
    let normalized = AgentArtifact::new(
        artifact.name(),
        artifact.logical_path(),
        artifact.kind(),
        artifact.scope(),
        artifact.origin(),
        artifact.load_semantics(),
        artifact.content_hash().clone(),
    )
    .map_err(|_| stored_report_error())?;
    if artifact.rank() != expected_rank
        || artifact.load_semantics() != LoadSemantics::Always
        || artifact.estimated_tokens() != expected_tokens
        || normalized.id() != *artifact.id()
    {
        return Err(stored_report_error());
    }
    if let Some(previous) = index.checked_sub(1).and_then(|prior| artifacts.get(prior)) {
        let out_of_order = previous.estimated_tokens() < artifact.estimated_tokens()
            || (previous.estimated_tokens() == artifact.estimated_tokens()
                && previous.raw_bytes() < artifact.raw_bytes())
            || (previous.estimated_tokens() == artifact.estimated_tokens()
                && previous.raw_bytes() == artifact.raw_bytes()
                && previous.id() > artifact.id());
        if out_of_order {
            return Err(stored_report_error());
        }
    }
    Ok(())
}

fn add_totals(
    totals: &mut (u64, u64, u64),
    artifact: &StaticFootprintArtifact,
) -> DesktopResult<()> {
    totals.0 = totals.0.checked_add(1).ok_or_else(stored_report_error)?;
    totals.1 = totals
        .1
        .checked_add(artifact.raw_bytes())
        .ok_or_else(stored_report_error)?;
    totals.2 = totals
        .2
        .checked_add(artifact.estimated_tokens())
        .ok_or_else(stored_report_error)?;
    Ok(())
}

fn origin_totals_match(
    report: &StaticFootprintReport,
    expected: &BTreeMap<OriginAgent, (u64, u64, u64)>,
) -> bool {
    let mut observed = BTreeMap::new();
    let mut previous = None;
    for total in report.origin_agent_session_totals() {
        if previous.is_some_and(|origin| origin >= total.origin()) {
            return false;
        }
        previous = Some(total.origin());
        if observed
            .insert(
                total.origin(),
                (
                    total.artifact_count(),
                    total.raw_bytes(),
                    total.estimated_tokens(),
                ),
            )
            .is_some()
        {
            return false;
        }
    }
    &observed == expected
}

fn scope_totals_match(
    report: &StaticFootprintReport,
    expected: &BTreeMap<ArtifactScope, (u64, u64, u64)>,
) -> bool {
    let mut observed = BTreeMap::new();
    let mut previous = None;
    for total in report.all_session_scope_totals() {
        if previous.is_some_and(|scope| scope >= total.scope()) {
            return false;
        }
        previous = Some(total.scope());
        if observed
            .insert(
                total.scope(),
                (
                    total.artifact_count(),
                    total.raw_bytes(),
                    total.estimated_tokens(),
                ),
            )
            .is_some()
        {
            return false;
        }
    }
    &observed == expected
}

fn artifact_dto(artifact: &StaticFootprintArtifact) -> SkillAuditArtifactDto {
    SkillAuditArtifactDto {
        rank: artifact.rank(),
        id: artifact.id().to_string(),
        name: artifact.name().to_owned(),
        logical_path: artifact.logical_path().to_owned(),
        kind: artifact.kind().as_str().to_owned(),
        scope: artifact.scope().as_str().to_owned(),
        origin: artifact.origin().as_str().to_owned(),
        load_semantics: artifact.load_semantics().as_str().to_owned(),
        content_hash: artifact.content_hash().to_string(),
        raw_bytes: artifact.raw_bytes(),
        estimated_tokens: artifact.estimated_tokens(),
    }
}

fn evaluation_dto(
    evaluation: StoredEvaluationDto,
    allowed_artifact_ids: &BTreeSet<AgentArtifactId>,
) -> DesktopResult<SkillAuditEvaluationDto> {
    match evaluation {
        StoredEvaluationDto::Evaluated { evaluator, verdict } => {
            let encoded = serde_json::to_string(&verdict).map_err(|_| stored_report_error())?;
            let validated = parse_skills_audit_verdict(&encoded, allowed_artifact_ids)
                .map_err(|_| stored_report_error())?;
            Ok(SkillAuditEvaluationDto::Evaluated {
                evaluator,
                verdict: validated_verdict_dto(&validated),
            })
        }
        StoredEvaluationDto::NoEvaluator => Ok(SkillAuditEvaluationDto::NoEvaluator),
        StoredEvaluationDto::Failed { evaluator, reason } => Ok(SkillAuditEvaluationDto::Failed {
            evaluator,
            failure: reason,
        }),
    }
}

fn validated_verdict_dto(verdict: &SkillsAuditVerdict) -> SkillAuditVerdictDto {
    SkillAuditVerdictDto {
        overlaps: verdict
            .overlaps()
            .iter()
            .map(|finding| SkillAuditMultiArtifactFindingDto {
                artifact_ids: finding
                    .artifact_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                summary: finding.summary().to_owned(),
            })
            .collect(),
        conflicts: verdict
            .conflicts()
            .iter()
            .map(|finding| SkillAuditMultiArtifactFindingDto {
                artifact_ids: finding
                    .artifact_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                summary: finding.summary().to_owned(),
            })
            .collect(),
        stale_candidates: verdict
            .stale_candidates()
            .iter()
            .map(|finding| SkillAuditStaleCandidateDto {
                artifact_id: finding.artifact_id().to_string(),
                reason: finding.reason().to_owned(),
            })
            .collect(),
        saturation_grade: match verdict.saturation_grade() {
            SaturationGrade::Healthy => SkillAuditSaturationGradeDto::Healthy,
            SaturationGrade::Elevated => SkillAuditSaturationGradeDto::Elevated,
            SaturationGrade::High => SkillAuditSaturationGradeDto::High,
            SaturationGrade::Critical => SkillAuditSaturationGradeDto::Critical,
        },
        overall_summary: verdict.overall_summary().to_owned(),
    }
}

fn audit_scan_error() -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not safely read the local agent inventory configuration.",
        Some("Repair the configured agent registry, then retry the audit.".to_owned()),
    )
}

fn audit_run_error() -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not produce a bounded skill audit report.",
        Some("Review the local agent inventory and retry the audit.".to_owned()),
    )
}

fn stored_report_error() -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not validate the durable skill audit report.",
        Some("Run a fresh skill audit to replace the invalid report.".to_owned()),
    )
}

fn store_error(_error: pam_store::StoreError) -> DesktopErrorDto {
    DesktopErrorDto::unavailable(
        "PAM could not access its durable skill audit report.",
        Some("Verify the local PAM state directory and retry the audit.".to_owned()),
    )
}
