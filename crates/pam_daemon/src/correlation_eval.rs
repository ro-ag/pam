//! Pure comparison of declared targets with bounded product-reported identities.
//! This module neither grants authority nor persists an association.
use std::collections::BTreeMap;

use pam_flow::{
    ArgValue, ConnectorId, CorrelationTarget, canonical_repository_url, validate_full_commit,
};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Matched,
    Missing,
    Conflicting,
    Unbound,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Decision {
    pub status: Status,
    pub detail: String,
}

impl Decision {
    pub fn is_matched(&self) -> bool {
        self.status == Status::Matched
    }
    pub fn is_unbound(&self) -> bool {
        self.status == Status::Unbound
    }
    pub fn cause(&self) -> Option<&'static str> {
        match self.status {
            Status::Matched | Status::Unbound => None,
            Status::Missing => Some("correlation_missing"),
            Status::Conflicting => Some("correlation_conflicting"),
        }
    }
}

fn decision(status: Status, detail: &'static str) -> Decision {
    Decision {
        status,
        detail: detail.to_owned(),
    }
}
fn missing() -> Decision {
    decision(
        Status::Missing,
        "Product evidence does not establish an exact repository and revision association.",
    )
}
fn conflicting() -> Decision {
    decision(
        Status::Conflicting,
        "Product evidence reports a different repository, revision, or pull-request identity.",
    )
}

pub(crate) fn evaluate(
    target: &CorrelationTarget,
    connector: ConnectorId,
    call: &str,
    result: Option<&Value>,
) -> Decision {
    if connector == ConnectorId::Sonarqube
        && matches!(call, "quality_gate" | "issues" | "live_measure")
    {
        return decision(
            Status::Missing,
            "Latest Sonar project or branch evidence does not prove the declared revision.",
        );
    }
    if !matches!(
        (connector, call),
        (ConnectorId::Github, "run") | (ConnectorId::Jenkins, "investigate")
    ) {
        return decision(
            Status::Unbound,
            "This operation supplies no revision association.",
        );
    }
    if target.validate().is_err() {
        return missing();
    }
    let Some(result) = result else {
        return missing();
    };
    let Some(source) = result.get("source_identity") else {
        return missing();
    };
    if source.get("status").and_then(Value::as_str) != Some("unambiguous")
        || source.get("partial").and_then(Value::as_bool) != Some(false)
        || source.get("invalid_metadata").and_then(Value::as_bool) != Some(false)
    {
        return missing();
    }
    let (Some(urls), Some(revisions)) = (
        source.get("repository_urls").and_then(Value::as_array),
        source.get("revisions").and_then(Value::as_array),
    ) else {
        return missing();
    };
    if urls.len() != 1 || revisions.len() != 1 {
        return missing();
    }
    let (Some(url), Some(revision)) = (urls[0].as_str(), revisions[0].as_str()) else {
        return missing();
    };
    let (Ok(url), Ok(revision)) = (
        canonical_repository_url(url),
        validate_full_commit(revision),
    ) else {
        return missing();
    };
    if url != target.repository || revision != target.commit {
        return conflicting();
    }
    if connector == ConnectorId::Github
        && (target.pull_request.is_some() || target.pull_request_head.is_some())
    {
        return evaluate_pull_request(target, result);
    }
    if target.pull_request.is_some() || target.pull_request_head.is_some() {
        return missing();
    }
    decision(
        Status::Matched,
        "Reported repository and full revision match the declared target.",
    )
}

fn evaluate_pull_request(target: &CorrelationTarget, result: &Value) -> Decision {
    let Some(run) = result.get("run") else {
        return missing();
    };
    if run.get("pull_requests_partial").and_then(Value::as_bool) != Some(false) {
        return missing();
    }
    let Some(prs) = run.get("pull_requests").and_then(Value::as_array) else {
        return missing();
    };
    if prs.is_empty() || prs.len() > 16 {
        return missing();
    }
    if prs.iter().any(|pr| {
        pr.get("number")
            .and_then(Value::as_u64)
            .is_none_or(|n| n == 0)
    }) {
        return missing();
    }
    let matching: Vec<_> = prs
        .iter()
        .filter(|pr| pr.get("number").and_then(Value::as_u64) == target.pull_request)
        .collect();
    if matching.is_empty() {
        return conflicting();
    }
    if matching.len() != 1 {
        return missing();
    }
    if let Some(expected) = &target.pull_request_head {
        let Some(sha) = matching[0].pointer("/head/sha").and_then(Value::as_str) else {
            return missing();
        };
        let Ok(sha) = validate_full_commit(sha) else {
            return missing();
        };
        if &sha != expected {
            return conflicting();
        }
    }
    decision(
        Status::Matched,
        "Reported source revision and pull-request pins match the declared target.",
    )
}

/// Stable reported IDs only. Mutable statuses and timestamps are deliberately absent.
/// Malformed or omitted identity stays explicitly incomplete, never inferred.
pub(crate) fn product_identity(
    connector: ConnectorId,
    call: &str,
    args: &BTreeMap<String, ArgValue>,
    result: Option<&Value>,
) -> Value {
    let mut identity = json!({"connector":connector.as_str(),"call":call});
    let Some(result) = result else {
        return identity;
    };
    if connector == ConnectorId::Github && call == "run" {
        if let Some(ArgValue::Text(repo)) = args
            .get("repo")
            .filter(|value| matches!(value,ArgValue::Text(text) if text.len()<=512))
        {
            identity["repository"] = json!(repo);
        }
        for key in ["run_id", "run_attempt"] {
            identity[key] = positive_id(result.get(key));
        }
        let jobs = result.get("jobs").and_then(Value::as_array);
        identity["job_ids"] = json!(
            jobs.into_iter()
                .flatten()
                .take(100)
                .filter_map(|job| job.get("id").and_then(Value::as_u64).filter(|id| *id > 0))
                .collect::<Vec<_>>()
        );
    } else if connector == ConnectorId::Jenkins && call == "investigate" {
        if let Some(job) = result
            .get("job")
            .and_then(Value::as_str)
            .filter(|job| job.len() <= 1024)
        {
            identity["job"] = json!(job);
        }
        identity["build"] = positive_id(result.get("build"));
    }
    if let Some(source) = result.get("source_identity") {
        identity["source_identity"] = bounded_source(source);
    }
    identity
}

fn positive_id(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_u64)
        .filter(|id| *id > 0)
        .map_or(Value::Null, |id| json!(id))
}
fn bounded_source(source: &Value) -> Value {
    // At most two full URLs and sixteen hashes keep the entire record below8KiB.
    let mut partial = source.get("partial").and_then(Value::as_bool) != Some(false);
    let mut retained = |key: &str, count: usize, bytes: usize| {
        let Some(values) = source.get(key).and_then(Value::as_array) else {
            partial = true;
            return Vec::new();
        };
        partial |= values.len() > count;
        values
            .iter()
            .take(count)
            .filter_map(|value| {
                let text = value
                    .as_str()
                    .filter(|text| text.len() <= bytes && !text.chars().any(char::is_control));
                partial |= text.is_none();
                text.map(str::to_owned)
            })
            .collect::<Vec<_>>()
    };
    let urls = retained("repository_urls", 2, 2048);
    let revisions = retained("revisions", 16, 64);
    json!({"status":match source.get("status").and_then(Value::as_str) {Some("unambiguous") if !partial=>"unambiguous",Some("missing")=>"missing",_=>"ambiguous"},
        "repository_urls":urls,"revisions":revisions,"partial":partial,
        "invalid_metadata":source.get("invalid_metadata").and_then(Value::as_bool)!=Some(false)})
}
