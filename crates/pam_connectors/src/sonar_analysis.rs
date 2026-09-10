//! Exact CE task → stored analysis gate, with independently reported revision.
//!
//! Source contracts: SonarSource `ws-ce.proto`, `projectanalysis/ws/SearchAction`,
//! and `qualitygate/ws/ProjectStatusAction`. History has no advertised PR selector.
//! A reported revision can be overridden by the scanner; this is association,
//! not attestation of analyzed bytes. Repository identity belongs to GUI policy.

use std::collections::BTreeMap;
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId, validate_full_commit};
use serde_json::{Value, json};

use crate::transport::{
    Connection, HttpTransport, array_field, endpoint, get_json, int_arg, opt_text_arg, text_arg,
};
use crate::{CallResult, ConnectorError};

const ID: ConnectorId = ConnectorId::Sonarqube;
const PAGE_SIZE: usize = 100;
const MAX_TEXT: usize = 4096;

struct Request<'a> {
    project: &'a str,
    task: &'a str,
    selector: Option<(&'static str, &'a str)>,
    page: i64,
}

impl<'a> Request<'a> {
    fn parse(args: &'a BTreeMap<String, ArgValue>) -> Result<Self, ConnectorError> {
        let project = text_arg(args, "project")?;
        let task = text_arg(args, "ce_task")?;
        let branch = opt_text_arg(args, "branch")?;
        let pr = opt_text_arg(args, "pullRequest")?;
        if project.contains(',') || !valid_text(project) || !valid_id(task) {
            return Err(ConnectorError::BadArgs(
                "invalid project or CE task identifier".to_owned(),
            ));
        }
        let selector = match (branch, pr) {
            (Some(_), Some(_)) => {
                return Err(ConnectorError::BadArgs(
                    "`branch` and `pullRequest` are mutually exclusive".to_owned(),
                ));
            }
            (Some(v), None) => Some(("branch", v)),
            (None, Some(v)) => Some(("pullRequest", v)),
            (None, None) => None,
        };
        if selector.is_some_and(|(_, v)| !valid_text(v)) {
            return Err(ConnectorError::BadArgs(
                "invalid analysis selector".to_owned(),
            ));
        }
        Ok(Self {
            project,
            task,
            selector,
            page: int_arg(args, "page", 1, (1, 10_000))?,
        })
    }

    fn requested(&self) -> Value {
        let mut value = json!({"project": self.project});
        if let Some((key, text)) = self.selector {
            value[key] = json!(text);
        }
        value
    }
}

/// At most four bounded reads; no internal polling or latest-analysis fallback.
pub(crate) async fn call(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let request = Request::parse(args)?;
    let mut url = endpoint(&conn.base_url, &["api", "webservices", "list"])?;
    url.query_pairs_mut()
        .append_pair("include_internals", "true");
    let catalog = get_json(conn, ID, url, transport, deadline).await?;
    require(&catalog, "api/ce", "task", &["id"])?;
    let mut url = endpoint(&conn.base_url, &["api", "ce", "task"])?;
    url.query_pairs_mut().append_pair("id", request.task);
    let body = get_json(conn, ID, url, transport, deadline).await?;
    let task = body.get("task").ok_or_else(|| bad("missing CE task"))?;
    let mut report = task_report(&request, task)?;
    if report["ce_status"] != "SUCCESS" {
        report["summary"] = json!(summary(&report));
        return Ok(CallResult::Json(report));
    }
    let analysis = report["analysis_id"]
        .as_str()
        .ok_or_else(|| bad("missing analysis ID"))?
        .to_owned();
    require(
        &catalog,
        "api/qualitygates",
        "project_status",
        &["analysisId"],
    )?;
    if request
        .selector
        .is_some_and(|(key, _)| key == "pullRequest")
    {
        report["revision_basis"] = json!("pull_request_unsupported");
        report["gaps"] = json!(["pull_request_revision_unavailable"]);
    } else {
        let mut params = vec!["project", "p", "ps"];
        if request.selector.is_some() {
            params.push("branch");
        }
        require(&catalog, "api/project_analyses", "search", &params)?;
        let mut url = endpoint(&conn.base_url, &["api", "project_analyses", "search"])?;
        url.query_pairs_mut()
            .append_pair("project", request.project)
            .append_pair("p", &request.page.to_string())
            .append_pair("ps", "100");
        if let Some((key, value)) = request.selector {
            url.query_pairs_mut().append_pair(key, value);
        }
        let history = get_json(conn, ID, url, transport, deadline).await?;
        apply_history(&mut report, &history, &analysis, request.page)?;
    }
    let mut url = endpoint(&conn.base_url, &["api", "qualitygates", "project_status"])?;
    url.query_pairs_mut().append_pair("analysisId", &analysis);
    let gate = get_json(conn, ID, url, transport, deadline).await?;
    apply_gate(&mut report, &gate, &analysis)?;
    report["summary"] = json!(summary(&report));
    Ok(CallResult::Json(report))
}

fn task_report(request: &Request<'_>, task: &Value) -> Result<Value, ConnectorError> {
    if task.get("id").and_then(Value::as_str) != Some(request.task)
        || task.get("componentKey").and_then(Value::as_str) != Some(request.project)
        || task.get("type").and_then(Value::as_str) != Some("REPORT")
    {
        return Err(bad("CE task identity is missing or conflicting"));
    }
    let branch = optional_text(task, "branch")?;
    let pr = optional_text(task, "pullRequest")?;
    let matches = match request.selector {
        Some(("branch", expected)) => branch.as_str() == Some(expected) && pr.is_null(),
        Some(("pullRequest", expected)) => pr.as_str() == Some(expected) && branch.is_null(),
        _ => pr.is_null(), // Main branch may be explicitly echoed by the server.
    };
    if !matches {
        return Err(bad(
            "CE task branch or pull request conflicts with the request",
        ));
    }
    let status = task
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing CE status"))?;
    if !matches!(
        status,
        "PENDING" | "IN_PROGRESS" | "SUCCESS" | "FAILED" | "CANCELED"
    ) {
        return Err(bad("unknown CE status"));
    }
    let analysis = optional_text(task, "analysisId")?;
    if status == "SUCCESS" && !analysis.as_str().is_some_and(valid_id) {
        return Err(bad("successful CE task has no valid analysis ID"));
    }
    if status != "SUCCESS" && !analysis.is_null() {
        return Err(bad(
            "incomplete CE task unexpectedly carries an analysis ID",
        ));
    }
    Ok(json!({
        "project": request.project, "ce_task": request.task, "ce_status": status,
        "status": status, "analysis_basis": "exact_analysis", "analysis_id": analysis,
        "revision": null, "revision_basis": "ce_not_complete", "partial": true,
        "requested": request.requested(),
        "identity": {"component_key":request.project,"branch":branch,"pull_request":pr},
        "coverage": {"page":request.page,"page_size":PAGE_SIZE,"total":null,"returned":0,"partial":true,"analysis_found":false},
        "conditions": [], "period": null, "ignored_conditions": null,
        "cayc_status_current": null, "gaps": ["ce_not_complete"],
        "ce_error": optional_text(task, "errorMessage")?,
    }))
}

fn apply_history(
    report: &mut Value,
    body: &Value,
    analysis: &str,
    page: i64,
) -> Result<(), ConnectorError> {
    let records = array_field(body, "analyses")?;
    for (key, expected) in [("pageIndex", page), ("pageSize", 100)] {
        if let Some(value) = body.get("paging").and_then(|paging| paging.get(key))
            && value.as_i64() != Some(expected)
        {
            return Err(bad("history page identity conflicts with the request"));
        }
    }
    let total = body.pointer("/paging/total").and_then(Value::as_u64);
    let retained = records.len().min(PAGE_SIZE);
    let oversized = records.len() > PAGE_SIZE;
    let matches: Vec<&Value> = records
        .iter()
        .take(PAGE_SIZE)
        .filter(|r| r.get("key").and_then(Value::as_str) == Some(analysis))
        .collect();
    if matches.len() > 1 {
        return Err(bad("history repeats the exact analysis ID"));
    }
    let revision = matches
        .first()
        .and_then(|r| r.get("revision"))
        .and_then(Value::as_str)
        .and_then(|s| validate_full_commit(s).ok())
        .filter(|_| !oversized);
    let end = u64::try_from((page - 1) * 100)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(retained).unwrap_or(u64::MAX));
    let inconsistent = total.is_some_and(|n| n < end && retained > 0);
    if inconsistent {
        return Err(bad("history total contradicts the returned page"));
    }
    report["coverage"] = json!({"page":page,"page_size":PAGE_SIZE,"total":total,"returned":retained,
        "partial": oversized || page > 1 || total.is_none_or(|n| n > end), "analysis_found":!matches.is_empty()});
    let gap = if oversized {
        "history_page_oversized"
    } else if matches.is_empty() {
        "analysis_not_on_history_page"
    } else {
        "analysis_revision_missing_or_invalid"
    };
    report["partial"] = json!(revision.is_none());
    report["revision_basis"] = json!(if revision.is_some() {
        "analysis_history"
    } else {
        "missing"
    });
    report["gaps"] = if revision.is_some() {
        json!([])
    } else {
        json!([gap])
    };
    report["revision"] = json!(revision);
    Ok(())
}

fn apply_gate(report: &mut Value, body: &Value, analysis: &str) -> Result<(), ConnectorError> {
    let gate = body
        .get("projectStatus")
        .filter(|v| v.is_object())
        .ok_or_else(|| bad("missing quality gate"))?;
    for value in [body, gate] {
        for key in ["project", "projectKey", "branch", "pullRequest"] {
            let expected = if matches!(key, "project" | "projectKey") {
                report["project"].as_str()
            } else {
                report["requested"][key].as_str()
            };
            if let Some(echo) = value.get(key)
                && (echo.as_str().is_none() || echo.as_str() != expected)
            {
                return Err(bad("gate project or selector conflicts with the request"));
            }
        }
        if let Some(echo) = value.get("analysisId")
            && echo.as_str() != Some(analysis)
        {
            return Err(bad("gate analysis identity conflicts with the request"));
        }
    }
    let status = gate
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("missing gate status"))?;
    if !matches!(status, "OK" | "ERROR" | "WARN" | "NONE") {
        return Err(bad("unknown gate status"));
    }
    let conditions = if status == "NONE" && gate.get("conditions").is_none() {
        &[][..]
    } else {
        array_field(gate, "conditions")?.as_slice()
    };
    if conditions.len() > PAGE_SIZE {
        return Err(bad(
            "quality gate conditions exceed the 100-condition bound",
        ));
    }
    let conditions: Vec<Value> = conditions.iter().map(condition).collect::<Result<_, _>>()?;
    report["status"] = json!(status);
    report["conditions"] = json!(conditions);
    report["period"] = period(gate.get("period"))?;
    report["ignored_conditions"] = match gate.get("ignoredConditions") {
        None => Value::Null,
        Some(v) if v.is_boolean() => v.clone(),
        _ => return Err(bad("invalid ignoredConditions flag")),
    };
    report["cayc_status_current"] = optional_text(gate, "caycStatus")?;
    Ok(())
}

fn condition(value: &Value) -> Result<Value, ConnectorError> {
    if !value.is_object() {
        return Err(bad("invalid quality gate condition"));
    }
    if !matches!(
        value.get("status").and_then(Value::as_str),
        Some("OK" | "WARN" | "ERROR" | "NONE")
    ) {
        return Err(bad("missing or unknown quality gate condition status"));
    }
    let mut out = json!({});
    for (source, target) in [
        ("metricKey", "metric"),
        ("status", "status"),
        ("comparator", "comparator"),
        ("actualValue", "actual"),
        ("errorThreshold", "threshold"),
        ("warningThreshold", "warning_threshold"),
    ] {
        out[target] = optional_text(value, source)?;
    }
    out["period_index"] = match value.get("periodIndex") {
        None => Value::Null,
        Some(v) if v.as_u64().is_some() => v.clone(),
        _ => return Err(bad("invalid condition period index")),
    };
    Ok(out)
}

fn period(value: Option<&Value>) -> Result<Value, ConnectorError> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    if !value.is_object() {
        return Err(bad("invalid new-code period"));
    }
    Ok(
        json!({"mode":optional_text(value,"mode")?,"date":optional_text(value,"date")?,"parameter":optional_text(value,"parameter")?}),
    )
}

fn require(
    catalog: &Value,
    path: &str,
    action: &str,
    required: &[&str],
) -> Result<(), ConnectorError> {
    let supported = catalog
        .get("webServices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|w| w.get("path").and_then(Value::as_str) == Some(path))
        .filter_map(|w| w.get("actions").and_then(Value::as_array))
        .flatten()
        .filter(|a| a.get("key").and_then(Value::as_str) == Some(action))
        .filter_map(|a| a.get("params").and_then(Value::as_array))
        .any(|params| {
            required.iter().all(|key| {
                params
                    .iter()
                    .any(|p| p.get("key").and_then(Value::as_str) == Some(*key))
            })
        });
    if !supported {
        return Err(ConnectorError::Policy {
            cause: "sonarqube_contract_unavailable",
            detail: "SonarQube does not advertise the required exact-analysis API parameters"
                .to_owned(),
        });
    }
    Ok(())
}

fn optional_text(value: &Value, key: &str) -> Result<Value, ConnectorError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(s)) if s.len() <= MAX_TEXT => Ok(json!(s)),
        _ => Err(bad("invalid or oversized analysis text field")),
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn bad(detail: &str) -> ConnectorError {
    ConnectorError::BadResponse(detail.to_owned())
}

/// Labels and observations remain untrusted data; the daemon redacts this view.
fn summary(report: &Value) -> String {
    let label = |key: &str| {
        short(
            report
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("unavailable"),
            160,
        )
    };
    let mut lines = vec![
        format!(
            "Sonar project {}; CE task {}: {}; analysis {}; gate/workflow status {}.",
            label("project"),
            label("ce_task"),
            label("ce_status"),
            label("analysis_id"),
            label("status")
        ),
        format!(
            "Revision {} ({}).",
            label("revision"),
            label("revision_basis")
        ),
    ];
    if let Some(error) = report.get("ce_error").and_then(Value::as_str) {
        lines.push(format!("Observed CE error: {}", short(error, 512)));
    }
    let conditions = report
        .get("conditions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let failures: Vec<_> = conditions
        .iter()
        .filter(|c| matches!(c["status"].as_str(), Some("ERROR" | "WARN")))
        .collect();
    lines.push(format!(
        "{} reported conditions; {} failing/warning conditions.",
        conditions.len(),
        failures.len()
    ));
    for condition in failures.iter().take(8) {
        let field = |key: &str| {
            short(
                condition
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or("unavailable"),
                80,
            )
        };
        lines.push(format!(
            "Observed {}: {} actual={} comparator={} error-threshold={} warning-threshold={}.",
            field("metric"),
            field("status"),
            field("actual"),
            field("comparator"),
            field("threshold"),
            field("warning_threshold")
        ));
    }
    if failures.len() > 8 {
        lines.push(format!("{} further failing/warning conditions omitted from summary; preserved in structured evidence.", failures.len() - 8));
    }
    if report["partial"] == true {
        lines.push(
            "Revision attribution unresolved; this gate cannot verify the requested commit."
                .to_owned(),
        );
    }
    if let Some(gaps) = report.get("gaps").and_then(Value::as_array) {
        for gap in gaps.iter().take(8).filter_map(Value::as_str) {
            lines.push(format!("Coverage gap: {}.", short(gap, 160)));
        }
    }
    short(&lines.join("\n"), 6000)
}

fn short(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let marker = " [truncated]";
    let mut end = limit.saturating_sub(marker.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{marker}", &text[..end])
}
