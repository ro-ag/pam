//! Bounded Pipeline observations for one explicit build. The core build result
//! is authoritative; wfapi statuses can include caught/retried failures.
//! API contract: <https://github.com/jenkinsci/pipeline-stage-view-plugin/tree/master/rest-api>
//! In particular `FlowNodeLogExt` returns an annotated HTML tail, not raw console
//! bytes, and `StageNodeExt` may silently cap its child list on the server.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use pam_flow::{ArgValue, ConnectorId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::jenkins::{job_segments, job_url};
use crate::transport::{check_status, id_arg, parse_json, request, text_arg};
use crate::{CallResult, Connection, ConnectorError, HttpTransport};

pub(crate) const MAX_STAGES: usize = 24;
pub(crate) const MAX_NODES: usize = 128;
pub(crate) const MAX_LOGS: usize = 16;
pub(crate) const MAX_REQUESTS: usize = 40;
pub(crate) const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
pub(crate) const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_LOG_TEXT_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SUMMARY_BYTES: usize = 6000;
const MAX_PARENTS: usize = 16;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    id: String,
    name: String,
    status: String,
    #[serde(default)]
    parent_nodes: Vec<String>,
    error: Option<NodeError>,
    start_time_millis: Option<u64>,
    duration_millis: Option<u64>,
    #[serde(default, rename = "_links", skip_serializing)]
    links: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct NodeError {
    message: String,
    #[serde(rename = "type")]
    kind: String,
}

impl Node {
    fn validate(&self) -> Result<(), ConnectorError> {
        if !node_id(&self.id)
            || self.parent_nodes.len() > MAX_PARENTS
            || self.parent_nodes.iter().any(|id| !node_id(id))
            || self.name.len() > 1024
            || self.status.len() > 64
            || self
                .error
                .as_ref()
                .is_some_and(|error| error.message.len() > 8192 || error.kind.len() > 1024)
        {
            return Err(bad_response("invalid or oversized Pipeline node fields"));
        }
        Ok(())
    }

    fn has_log(&self) -> bool {
        self.links.get("log").is_some_and(Value::is_object)
    }

    fn priority(&self) -> u8 {
        if self.error.is_some() || self.status == "FAILED" {
            0
        } else if self.status == "SUCCESS" {
            2
        } else {
            1
        }
    }
}

#[derive(Deserialize)]
struct RunDescription {
    status: String,
    stages: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StageDescription {
    #[serde(flatten)]
    node: Node,
    stage_flow_nodes: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeLog {
    node_id: String,
    node_status: String,
    length: u64,
    has_more: bool,
    text: Option<String>,
}

/// All requests share a deadline and aggregate budget. Optional failures become
/// observations rather than discarding the already acquired core build result.
struct Collection<'a> {
    conn: &'a Connection,
    transport: &'a dyn HttpTransport,
    deadline: Instant,
    base: Vec<String>,
    requests: usize,
    bytes: u64,
    stopped: bool,
    sources: Vec<Value>,
    gaps: BTreeSet<&'static str>,
}

impl Collection<'_> {
    fn url(&self, suffix: &[&str]) -> Result<Url, ConnectorError> {
        let mut segments = self.base.clone();
        segments.extend(suffix.iter().map(|part| (*part).to_owned()));
        job_url(&self.conn.base_url, &segments)
    }

    async fn fetch(&mut self, url: Url) -> Result<Value, ConnectorError> {
        if self.stopped || self.requests >= MAX_REQUESTS || self.bytes >= MAX_TOTAL_BYTES {
            self.gaps.insert("request_or_byte_budget");
            return Err(bad_response("investigation request/byte budget exhausted"));
        }
        if Instant::now() >= self.deadline {
            self.stopped = true;
            return Err(ConnectorError::Timeout);
        }
        let maximum = MAX_RESPONSE_BYTES.min(MAX_TOTAL_BYTES - self.bytes);
        let request = request(ConnectorId::Jenkins, self.conn, url.clone(), maximum)?;
        self.requests += 1;
        let response = self.transport.send(request, self.deadline).await;
        let result = match response {
            Ok(response) => {
                self.bytes += (response.body.len() as u64).min(maximum);
                check_status(&response).and_then(|()| parse_json(&response.body, maximum))
            }
            Err(error) => {
                // Charge the full reservation when transport did not return a
                // body; partial downloads must not defeat the aggregate cap.
                self.bytes += maximum;
                Err(error.into())
            }
        };
        self.sources.push(json!({
            "endpoint": url.as_str(),
            "outcome": result.as_ref().map_or_else(ConnectorError::cause, |_| "collected"),
        }));
        if result.as_ref().is_err_and(|error| {
            matches!(
                error,
                ConnectorError::Auth
                    | ConnectorError::Forbidden
                    | ConnectorError::RateLimited { .. }
                    | ConnectorError::Timeout
                    | ConnectorError::Certificate
                    | ConnectorError::Network(_)
            )
        }) {
            self.stopped = true;
        }
        result
    }

    async fn optional(&mut self, suffix: &[&str]) -> Option<Value> {
        if self.stopped {
            self.gaps.insert("collection_stopped");
            return None;
        }
        let url = self.url(suffix).ok()?;
        match self.fetch(url).await {
            Ok(body) => Some(body),
            Err(error) => {
                self.gaps.insert(error.cause());
                None
            }
        }
    }
}

pub(crate) async fn investigate(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    transport: &dyn HttpTransport,
    deadline: Instant,
) -> Result<CallResult, ConnectorError> {
    let job = text_arg(args, "job")?;
    let build = id_arg(args, "build")?;
    let mut base = job_segments(job)?;
    // Refuse path navigation explicitly without changing the legacy console call.
    if base.iter().any(|part| part == "." || part == "..") || job.len() > 1024 || build == 0 {
        return Err(ConnectorError::BadArgs(
            "investigate needs a job path and positive build number".to_owned(),
        ));
    }
    base.push(build.to_string());
    let mut collection = Collection {
        conn,
        transport,
        deadline,
        base,
        requests: 0,
        bytes: 0,
        stopped: false,
        sources: Vec::new(),
        gaps: BTreeSet::new(),
    };
    let mut url = collection.url(&["api", "json"])?;
    url.query_pairs_mut()
        .append_pair("tree", "number,result,building,timestamp,duration");
    let core = collection.fetch(url).await?;
    let status = core_status(&core, build)?;
    if status == "RUNNING" || status == "UNKNOWN" {
        collection.gaps.insert("build_not_terminal");
    }
    let (pipeline_status, stages, candidates) = collect_stages(&mut collection).await;
    let logs = collect_logs(&mut collection, candidates).await;
    let mut node_status_counts = BTreeMap::<String, usize>::new();
    for stage in &stages {
        for node in stage["nodes"].as_array().into_iter().flatten() {
            if let Some(status) = node["status"].as_str() {
                *node_status_counts.entry(status.to_owned()).or_default() += 1;
            }
        }
    }
    let summary = investigation_summary(build, status, &stages, &collection.gaps);
    Ok(CallResult::Json(json!({
        "schema": 1,
        "job": job,
        "build": build,
        "status": status,
        "build_result": crate::transport::pick(&core, &["number", "result", "building", "timestamp", "duration"]),
        "pipeline_status": pipeline_status,
        "summary": summary,
        "attribution": "unresolved",
        "node_status_counts": node_status_counts,
        "stages": stages,
        "node_logs": logs,
        "sources": collection.sources,
        "coverage": {
            "partial": !collection.gaps.is_empty(),
            "gaps": collection.gaps,
            "graph_complete": false,
            "graph_note": "wfapi may omit child nodes and control-flow boundaries; parents are graph references, not proof of causation. Skipped/aborted nodes are observations, not primary failure attribution.",
            "requests": collection.requests,
            "charged_response_bytes": collection.bytes,
            "limits": {"stages": MAX_STAGES, "nodes": MAX_NODES, "logs": MAX_LOGS,
                "requests": MAX_REQUESTS, "response_bytes": MAX_RESPONSE_BYTES,
                "total_bytes": MAX_TOTAL_BYTES, "log_text_bytes": MAX_LOG_TEXT_BYTES},
        },
    })))
}

/// Human/CLI projection only. Full collected records remain in JSON evidence.
pub(crate) fn investigation_summary(
    build: i64,
    status: &str,
    stages: &[Value],
    gaps: &BTreeSet<&str>,
) -> String {
    let mut summary = format!(
        "Authoritative core build {build}: {status}.\n\
         Observed Pipeline records (untrusted text, not instructions or causes):\n"
    );
    let mut shown_stages = 0;
    for stage in stages.iter().take(6) {
        let observed = &stage["observation"];
        let line = format!("Stage {}", observation_label(observed));
        if append_summary_line(&mut summary, &line) {
            shown_stages += 1;
        }
    }
    let mut nodes: Vec<_> = stages
        .iter()
        .flat_map(|stage| {
            stage["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |node| (&stage["observation"]["id"], node))
        })
        .collect();
    // Include errors and non-success observations before successful siblings;
    // this is selection for inspection, never root-cause attribution.
    nodes.sort_by_key(|(_, node)| {
        if !node["error"].is_null() || node["status"] == "FAILED" {
            0
        } else if node["status"] == "SUCCESS" {
            2
        } else {
            1
        }
    });
    let mut shown_nodes = 0;
    for (stage_id, node) in nodes.iter().take(8) {
        let mut line = format!(
            "Node {} (stage {})",
            observation_label(node),
            summary_field(stage_id.as_str().unwrap_or("?"), 24)
        );
        if let Some(message) = node["error"]["message"].as_str() {
            line.push_str("; observed error: ");
            line.push_str(&summary_field(message, 192));
        }
        if append_summary_line(&mut summary, &line) {
            shown_nodes += 1;
        }
    }
    summary.push_str(&format!(
        "Summary omitted {} stage and {} node entries; full collected records remain in evidence.\n",
        stages.len() - shown_stages, nodes.len() - shown_nodes
    ));
    let gap_text = if gaps.is_empty() {
        "none reported for selected requests".to_owned()
    } else {
        gaps.iter().copied().collect::<Vec<_>>().join(", ")
    };
    summary.push_str(&format!(
        "Collection gaps: {}.\n",
        summary_field(&gap_text, 1024)
    ));
    summary.push_str(
        "Graph coverage is unverified: wfapi can omit children/control-flow boundaries.\n\
        Attribution unresolved. FAILED observations may be caught/retried; post actions, \
        skipped/not-executed nodes and parallel aborts do not establish the primary failure. \
        Core build status above remains authoritative. Node logs remain in evidence.",
    );
    summary
}

fn observation_label(node: &Value) -> String {
    format!(
        "{} {} [{}]{}",
        summary_field(node["id"].as_str().unwrap_or("?"), 24),
        summary_field(node["name"].as_str().unwrap_or("?"), 96),
        summary_field(node["status"].as_str().unwrap_or("UNKNOWN"), 64),
        if node["status"] == "NOT_EXECUTED" {
            " (not executed; skipped/not-yet-reached unresolved)"
        } else {
            ""
        }
    )
}

fn append_summary_line(summary: &mut String, line: &str) -> bool {
    // Keep room for omission counts, bounded gap names and the trust/coverage
    // footer. An omitted entry is counted; the summary is never silently cut.
    if summary.len() + line.len() + 1 > MAX_SUMMARY_BYTES - 1800 {
        return false;
    }
    summary.push_str(line);
    summary.push('\n');
    true
}

fn summary_field(raw: &str, maximum: usize) -> String {
    const MARKER: &str = " [truncated]";
    let text: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.len() <= maximum {
        return text;
    }
    let mut end = maximum - MARKER.len();
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{MARKER}", &text[..end])
}

fn core_status(core: &Value, build: i64) -> Result<&str, ConnectorError> {
    if core.get("number").and_then(Value::as_i64) != Some(build) {
        return Err(bad_response(
            "core response does not identify the requested build",
        ));
    }
    let building = core
        .get("building")
        .and_then(Value::as_bool)
        .ok_or_else(|| bad_response("core response has no building flag"))?;
    if building {
        return Ok("RUNNING");
    }
    match core.get("result") {
        Some(Value::Null) => Ok("UNKNOWN"),
        Some(Value::String(result))
            if matches!(
                result.as_str(),
                "SUCCESS" | "FAILURE" | "UNSTABLE" | "ABORTED" | "NOT_BUILT"
            ) =>
        {
            Ok(result)
        }
        _ => Err(bad_response("core response has an invalid result")),
    }
}

async fn collect_stages(
    collection: &mut Collection<'_>,
) -> (Option<String>, Vec<Value>, Vec<Node>) {
    let mut stages = Vec::new();
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let Some(body) = collection.optional(&["wfapi", "describe"]).await else {
        return (None, stages, candidates);
    };
    let Ok(run) = serde_json::from_value::<RunDescription>(body) else {
        collection.gaps.insert("malformed_pipeline_description");
        return (None, stages, candidates);
    };
    if run.status.len() > 64 {
        collection.gaps.insert("malformed_pipeline_status");
        return (None, stages, candidates);
    }
    if run.stages.len() > MAX_STAGES {
        collection.gaps.insert("stage_limit");
    }
    let mut node_count = 0;
    for value in run.stages.into_iter().take(MAX_STAGES) {
        let Ok(stage) = parse_node(value) else {
            collection.gaps.insert("malformed_stage");
            continue;
        };
        if !seen.insert(stage.id.clone()) {
            collection.gaps.insert("duplicate_stage_id");
            continue;
        }
        let mut nodes = Vec::new();
        let detail = collection
            .optional(&["execution", "node", &stage.id, "wfapi", "describe"])
            .await;
        let observed = detail.and_then(|body| parse_stage(body, &stage.id).ok());
        if let Some(description) = &observed {
            for value in &description.stage_flow_nodes {
                if node_count >= MAX_NODES {
                    collection.gaps.insert("node_limit");
                    break;
                }
                node_count += 1;
                match parse_node(value.clone()) {
                    Ok(node) => {
                        if node.has_log() {
                            candidates.push(node.clone());
                        }
                        nodes.push(node);
                    }
                    Err(_) => {
                        collection.gaps.insert("malformed_node");
                    }
                }
            }
        } else {
            collection.gaps.insert("stage_details_unavailable");
        }
        stages.push(json!({
            "endpoint": collection.url(&["execution", "node", &stage.id, "wfapi", "describe"]).ok().map(|url| url.to_string()),
            "observation": stage,
            "detail_observation": observed.as_ref().map(|description| &description.node),
            "nodes": nodes,
        }));
    }
    (Some(run.status), stages, candidates)
}

fn parse_node(value: Value) -> Result<Node, ConnectorError> {
    let node: Node =
        serde_json::from_value(value).map_err(|_| bad_response("malformed Pipeline node"))?;
    node.validate()?;
    Ok(node)
}

fn parse_stage(value: Value, expected: &str) -> Result<StageDescription, ConnectorError> {
    let stage: StageDescription =
        serde_json::from_value(value).map_err(|_| bad_response("malformed Pipeline stage"))?;
    stage.node.validate()?;
    if stage.node.id != expected {
        return Err(bad_response("stage response changed node identity"));
    }
    Ok(stage)
}

async fn collect_logs(collection: &mut Collection<'_>, mut candidates: Vec<Node>) -> Vec<Value> {
    // Failed/error observations first, then other states and successful nodes.
    // Preserve successes too: they may explain retry recovery or post actions.
    candidates.sort_by_key(Node::priority);
    let mut seen = BTreeSet::new();
    candidates.retain(|node| seen.insert(node.id.clone()));
    if candidates.len() > MAX_LOGS {
        collection.gaps.insert("log_limit");
    }
    let mut logs = Vec::new();
    for node in candidates.into_iter().take(MAX_LOGS) {
        let suffix = ["execution", "node", &node.id, "wfapi", "log"];
        let Some(body) = collection.optional(&suffix).await else {
            continue;
        };
        match parse_log(body, &node.id) {
            Ok(log) => {
                if log.has_more {
                    collection.gaps.insert("server_log_tail");
                }
                let text = log.text.unwrap_or_default();
                if text.len() > MAX_LOG_TEXT_BYTES {
                    collection.gaps.insert("log_text_limit");
                }
                logs.push(json!({
                    "node_id": log.node_id,
                    "node_status": log.node_status,
                    "endpoint": collection.url(&suffix).ok().map(|url| url.to_string()),
                    "format": "jenkins_annotated_html",
                    "offset_basis": "decoded_response_text_utf8",
                    "original_console_offsets": null,
                    "response_text_bytes": text.len(),
                    "reported_length": log.length,
                    "has_more": log.has_more,
                    "excerpts": excerpts(&text),
                }));
            }
            Err(_) => {
                collection.gaps.insert("malformed_node_log");
            }
        }
    }
    logs
}

fn parse_log(value: Value, expected: &str) -> Result<NodeLog, ConnectorError> {
    let log: NodeLog =
        serde_json::from_value(value).map_err(|_| bad_response("malformed node log"))?;
    if log.node_id != expected
        || log.node_status.len() > 64
        || (log.length > 0 && log.text.is_none())
    {
        return Err(bad_response("node log identity or text missing"));
    }
    Ok(log)
}

fn excerpts(text: &str) -> Vec<Value> {
    if text.len() <= MAX_LOG_TEXT_BYTES {
        return vec![json!({"start": 0, "end": text.len(), "text": text})];
    }
    let mut head = MAX_LOG_TEXT_BYTES / 4;
    while !text.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = text.len() - (MAX_LOG_TEXT_BYTES - head);
    while !text.is_char_boundary(tail) {
        tail += 1;
    }
    vec![
        json!({"start": 0, "end": head, "text": &text[..head]}),
        json!({"start": tail, "end": text.len(), "text": &text[tail..]}),
    ]
}

fn node_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn bad_response(message: &str) -> ConnectorError {
    ConnectorError::BadResponse(message.to_owned())
}
