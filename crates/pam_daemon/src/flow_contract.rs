//! Bounded public flow projections. Observations are data, never instructions.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::executor::outcome_str;
use crate::flow_exec::RunReport;

/// Leaves room for the outer wire response and persisted metadata.
pub const MAX_RESULT_BYTES: usize = 14 * 1024;
/// Combined UTF-8 observation text ceiling.
pub const MAX_OBSERVATION_BYTES: usize = 6000;

/// A malformed or unrepresentable public contract.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{0}")]
pub struct ContractError(pub &'static str);

/// The persisted public result; never a prefix of the full report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResult {
    pub schema_version: u8,
    pub ticket: String,
    pub flow: FlowIdentity,
    pub workflow: Workflow,
    pub diagnosis: Diagnosis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<CorrelationSummary>,
    pub observations: Vec<Observation>,
    pub evidence: Vec<String>,
    pub omitted: Omissions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<Handoff>,
}

/// Reusable evidence handoff, with no generated diagnosis or inferred target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub state: String,
    pub reason: String,
    pub target: Option<pam_flow::CorrelationTarget>,
    pub target_state: String,
    pub decisive_citations: Vec<String>,
    pub citation_state: String,
    pub missing_facts: Vec<String>,
    pub next_action: Value,
    pub measurements: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationSummary {
    pub status: String,
    pub target_id: String,
    pub commit: Option<String>,
}

impl AgentResult {
    pub fn with_handoff_target(
        mut self,
        target: Option<pam_flow::CorrelationTarget>,
    ) -> Result<Self, ContractError> {
        if let Some(target) = &target {
            target
                .validate()
                .map_err(|_| ContractError("invalid frozen handoff target"))?;
        }
        if let Some(handoff) = &mut self.handoff {
            handoff.target_state = if target.is_some() {
                "frozen"
            } else {
                "not_declared"
            }
            .into();
            handoff.target = target;
        }
        fit_result(&mut self)?;
        Ok(self)
    }

    pub fn with_correlation(
        mut self,
        correlation: CorrelationSummary,
    ) -> Result<Self, ContractError> {
        self.correlation = Some(correlation);
        fit_result(&mut self)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowIdentity {
    pub id: String,
    pub digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub outcome: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnosis {
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductObservation {
    pub connector: String,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub step: String,
    pub status: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<ProductObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub evidence_refs_omitted: usize,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Omissions {
    pub observations: usize,
    pub evidence: usize,
    pub observation_bytes: usize,
}

/// Build a complete bounded projection, redacting whole strings before limiting them.
/// Product status must come from the validated adapter, never prose inference.
pub fn project_result(
    ticket: &str,
    flow_id: &str,
    digest: &str,
    report: &RunReport,
    evidence: &[String],
    products: &BTreeMap<String, ProductObservation>,
) -> Result<AgentResult, ContractError> {
    if ticket.len() > 128 || flow_id.len() > 128 || digest.len() > 128 {
        return Err(ContractError("flow result identity exceeds its limit"));
    }
    let mut result = AgentResult {
        schema_version: 1,
        ticket: ticket.to_owned(),
        flow: FlowIdentity {
            id: flow_id.to_owned(),
            digest: digest.to_owned(),
        },
        workflow: Workflow {
            outcome: outcome_str(report.outcome).to_owned(),
        },
        diagnosis: Diagnosis {
            status: "not_attempted".to_owned(),
        },
        correlation: None,
        observations: Vec::new(),
        evidence: Vec::new(),
        omitted: Omissions::default(),
        handoff: None,
    };
    let mut remaining = MAX_OBSERVATION_BYTES;
    for step in &report.steps {
        let source = step
            .summary
            .as_deref()
            .or_else(|| step.error.as_ref().map(|error| error.detail.as_str()))
            .unwrap_or("");
        let view = crate::evidence_view::redact(source.as_bytes())
            .map_err(|_| ContractError("observation redaction failed"))?;
        let source = String::from_utf8(view.bytes)
            .map_err(|_| ContractError("observation view is not UTF-8"))?;
        if result.observations.len() == 64 {
            result.omitted.observations += 1;
            result.omitted.observation_bytes += source.len();
            continue;
        }
        let text = bounded_text(&source, remaining);
        remaining -= text.len();
        result.omitted.observation_bytes += source.len().saturating_sub(text.len());
        let status = serde_json::to_value(step.status)
            .map_err(|_| ContractError("step status cannot serialize"))?;
        result.observations.push(Observation {
            step: step.id.clone(),
            status: status.as_str().unwrap_or("unknown").to_owned(),
            text,
            product: products.get(&step.id).cloned(),
            evidence_refs: step
                .evidence
                .iter()
                .filter(|id| id.len() <= 128)
                .take(4)
                .cloned()
                .collect(),
            evidence_refs_omitted: step.evidence.len().saturating_sub(
                step.evidence
                    .iter()
                    .filter(|id| id.len() <= 128)
                    .take(4)
                    .count(),
            ),
        });
    }
    for id in evidence {
        if id.len() > 128 || result.evidence.len() >= 64 {
            result.omitted.evidence += 1;
        } else {
            result.evidence.push(id.clone());
        }
    }
    result.handoff = Some(handoff(report, &result));
    fit_result(&mut result)?;
    Ok(result)
}

fn handoff(report: &RunReport, result: &AgentResult) -> Handoff {
    let completed = matches!(
        report.outcome,
        pam_proto::Outcome::Solved | pam_proto::Outcome::Verified | pam_proto::Outcome::Changed
    );
    let mut missing = vec![
        "decisive_quote_attribution_not_recorded".to_owned(),
        "product_execution_identity_requires_evidence_read".to_owned(),
    ];
    if report
        .steps
        .iter()
        .any(|step| !step.evidence_unavailable.is_empty())
    {
        missing.push("one_or_more_evidence_views_unavailable".to_owned());
    }
    if report
        .steps
        .iter()
        .any(|step| step.status == crate::flow_exec::StepStatus::Skipped)
    {
        missing.push("one_or_more_steps_not_executed".to_owned());
    }
    Handoff {
        state: if completed {
            "local_workflow_completed"
        } else {
            "escalation_required"
        }
        .into(),
        reason: if completed {
            "workflow_outcome_recorded_diagnosis_not_attempted"
        } else {
            "workflow_not_completed"
        }
        .into(),
        target: None,
        target_state: "not_declared".into(),
        decisive_citations: Vec::new(),
        citation_state: "not_attributed_use_retained_evidence".into(),
        missing_facts: missing,
        next_action: result.evidence.first().map_or_else(
            || serde_json::json!({"kind":"review_missing_evidence","automatic":false}),
            |id| {
                serde_json::json!({"kind":"evidence_read","capability":"evidence.read",
                "args":{"request_id":result.ticket,"evidence_id":id,"offset":0,"length":16384},
                "authorization":"rechecked_per_read","automatic":false})
            },
        ),
        measurements: serde_json::json!({"frontier_tokens":null,"correction_turns":null,
            "realized_token_savings":null,"benefit_status":"not_measured_requires_paired_experiment"}),
    }
}

fn fit_result(result: &mut AgentResult) -> Result<(), ContractError> {
    while serialized_len(result)? > MAX_RESULT_BYTES {
        if let Some(observation) = result.observations.pop() {
            result.omitted.observations += 1;
            result.omitted.observation_bytes += observation.text.len();
        } else if result.evidence.pop().is_some() {
            result.omitted.evidence += 1;
        } else {
            return Err(ContractError("flow result cannot fit its identity"));
        }
    }
    Ok(())
}

fn serialized_len(value: &impl Serialize) -> Result<usize, ContractError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| ContractError("flow contract cannot serialize"))
}

/// UTF-8 safe prefix; omissions are reported separately, never silently.
pub(crate) fn bounded_text(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Strict discovery pagination. Invalid values are refused, not clamped.
pub fn pagination(args: &Value) -> Result<(usize, usize), ContractError> {
    if !args.is_object() {
        return Err(ContractError("pagination must be an object"));
    }
    let number = |key, default| match args.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .ok_or(ContractError("offset/limit must be unsigned integers")),
    };
    let offset = number("offset", 0)?;
    let limit = number("limit", 20)?;
    if !(1..=50).contains(&limit) {
        return Err(ContractError("limit must be between 1 and 50"));
    }
    Ok((offset, limit))
}

/// Resolve only local/input variables; never git, prior steps, or network state.
pub(crate) fn inspect_vars(
    flow: &pam_flow::Flow,
    supplied: &BTreeMap<String, String>,
    repo: &std::path::Path,
) -> (pam_flow::Vars, Vec<String>) {
    let mut vars = pam_flow::Vars::new();
    vars.set("repo.path", repo.to_string_lossy().into_owned());
    if let Some(name) = repo.file_name().and_then(|value| value.to_str()) {
        vars.set("repo.name", name);
    }
    let mut missing = Vec::new();
    for name in supplied
        .keys()
        .filter(|name| !flow.inputs.contains_key(*name))
    {
        missing.push(name.clone());
    }
    for (name, input) in &flow.inputs {
        let value = supplied.get(name).cloned().or_else(|| {
            input
                .default
                .as_ref()
                .and_then(|value| pam_flow::substitute(value, &vars).ok())
        });
        if let Some(value) = value {
            vars.set(&format!("inputs.{name}"), value);
        } else {
            missing.push(name.clone());
        }
    }
    (vars, missing)
}

/// Read-only preview of `PolicyGate`'s classification rules; does not auto-grant.
/// This snapshot never substitutes for the execution-time gate.
pub(crate) fn inspect_gate(
    profile: crate::policy::Profile,
    granted: bool,
    class: crate::policy::CapabilityClass,
) -> &'static str {
    use crate::policy::{CapabilityClass, Profile};
    if class == CapabilityClass::ReadOnly {
        return "allowed";
    }
    match (profile, granted, class) {
        (Profile::Relaxed, true, _)
        | (Profile::Standard, true, CapabilityClass::NonDestructive) => "allowed",
        (Profile::Relaxed, false, CapabilityClass::NonDestructive) => "auto_grant_on_execution",
        (Profile::Standard | Profile::Strict, false, _) => "not_granted",
        (Profile::Relaxed, false, _) | (Profile::Standard | Profile::Strict, true, _) => {
            "approval_required"
        }
    }
}
