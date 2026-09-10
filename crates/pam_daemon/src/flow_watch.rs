//! Pure, bounded watch observations and scheduling checks. No I/O or authority grants.
use std::time::Duration;

use pam_flow::ConnectorId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    Pending,
    Terminal,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Observation {
    pub state: State,
    pub payload: Value,
    pub digest: String,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{detail}")]
pub(crate) struct WatchError {
    pub cause: &'static str,
    pub detail: &'static str,
}

fn invalid() -> WatchError {
    WatchError {
        cause: "watch_observation_invalid",
        detail: "The product observation is missing, malformed, or inconsistent",
    }
}

/// Stable product fields only: counters, timestamps and mutable run titles do not affect the digest.
pub(crate) fn normalize(connector: ConnectorId, value: &Value) -> Result<Observation, WatchError> {
    let status = string(value, "status", 64)?;
    let state = match connector {
        ConnectorId::Github => match status {
            "queued" | "requested" | "waiting" | "pending" | "in_progress"
                if value["conclusion"].is_null() =>
            {
                State::Pending
            }
            "completed"
                if value["conclusion"].as_str().is_some_and(|v| {
                    matches!(
                        v,
                        "success"
                            | "failure"
                            | "neutral"
                            | "cancelled"
                            | "skipped"
                            | "timed_out"
                            | "action_required"
                            | "stale"
                            | "startup_failure"
                    )
                }) =>
            {
                State::Terminal
            }
            _ => return Err(invalid()),
        },
        ConnectorId::Jenkins => match status {
            "RUNNING" => State::Pending,
            "UNKNOWN" => State::Unavailable,
            "SUCCESS" | "FAILURE" | "UNSTABLE" | "ABORTED" | "NOT_BUILT" => State::Terminal,
            _ => return Err(invalid()),
        },
        ConnectorId::Sonarqube => match status {
            "PENDING" | "IN_PROGRESS" => State::Pending,
            "SUCCESS" | "FAILED" | "CANCELED" => State::Terminal,
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    if serde_json::to_value(state).map_err(|_| invalid())? != value["watch_state"] {
        return Err(invalid());
    }
    let mut payload = json!({"connector":connector,"status":status,"watch_state":state});
    match connector {
        ConnectorId::Github => {
            for key in ["run_id", "run_attempt"] {
                payload[key] = json!(positive(value, key)?);
            }
            payload["conclusion"] = value["conclusion"].clone();
            payload["source_identity"] = source_identity(&value["source_identity"])?;
        }
        ConnectorId::Jenkins => {
            payload["job"] = json!(string(value, "job", 1024)?);
            payload["build"] = json!(positive(value, "build")?);
            payload["source_identity"] = source_identity(&value["source_identity"])?;
        }
        ConnectorId::Sonarqube => {
            for key in ["project", "ce_task"] {
                payload[key] = json!(string(value, key, 4096)?);
            }
            let identity = &value["identity"];
            let mut selected = json!({"component_key":string(identity,"component_key",4096)?});
            for key in ["branch", "pull_request"] {
                selected[key] = optional_string(identity, key, 4096)?;
            }
            payload["identity"] = selected;
            payload["analysis_id"] = optional_string(value, "analysis_id", 4096)?;
            if (status == "SUCCESS") != payload["analysis_id"].is_string() {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    let bytes = serde_json::to_vec(&payload).map_err(|_| invalid())?;
    if bytes.len() > 16_384 {
        return Err(invalid());
    }
    Ok(Observation {
        state,
        payload,
        digest: pam_compact::sha256_hex(&bytes),
    })
}

fn source_identity(value: &Value) -> Result<Value, WatchError> {
    let status = string(value, "status", 32)?;
    if !matches!(status, "missing" | "unambiguous" | "ambiguous") {
        return Err(invalid());
    }
    let mut source = json!({"status":status});
    for (key, maximum) in [("repository_urls", 2048), ("revisions", 64)] {
        let values = value[key]
            .as_array()
            .filter(|v| v.len() <= 16)
            .ok_or_else(invalid)?;
        if values.iter().any(|v| {
            !v.as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= maximum)
        }) {
            return Err(invalid());
        }
        let mut strings: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
        strings.sort_unstable();
        strings.dedup();
        source[key] = json!(strings);
    }
    for key in ["partial", "invalid_metadata"] {
        source[key] = json!(value[key].as_bool().ok_or_else(invalid)?);
    }
    Ok(source)
}
fn string<'a>(value: &'a Value, key: &str, maximum: usize) -> Result<&'a str, WatchError> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= maximum && !s.chars().any(char::is_control))
        .ok_or_else(invalid)
}
fn optional_string(value: &Value, key: &str, maximum: usize) -> Result<Value, WatchError> {
    if value[key].is_null() {
        Ok(Value::Null)
    } else {
        Ok(json!(string(value, key, maximum)?))
    }
}
fn positive(value: &Value, key: &str) -> Result<i64, WatchError> {
    value[key].as_i64().filter(|v| *v > 0).ok_or_else(invalid)
}

/// A terminal collector cannot replace the immutable target or previously observed source proof.
pub(crate) fn validate_pins(
    connector: ConnectorId,
    previous: &Value,
    current: &Value,
) -> Result<(), WatchError> {
    let keys: &[&str] = match connector {
        ConnectorId::Github => &["run_id", "run_attempt"],
        ConnectorId::Jenkins => &["job", "build"],
        ConnectorId::Sonarqube => &["project", "ce_task", "identity"],
        _ => return Err(invalid()),
    };
    if keys
        .iter()
        .any(|key| previous[*key].is_null() || previous[*key] != current[*key])
    {
        return Err(conflict());
    }
    if connector == ConnectorId::Sonarqube {
        if !previous["analysis_id"].is_null() && previous["analysis_id"] != current["analysis_id"] {
            return Err(conflict());
        }
    } else if previous["source_identity"]["status"] == "unambiguous" {
        let old = source_identity(&previous["source_identity"])?;
        let new = source_identity(&current["source_identity"])?;
        if old != new {
            return Err(conflict());
        }
    }
    Ok(())
}
fn conflict() -> WatchError {
    WatchError {
        cause: "watch_target_changed",
        detail: "The product target or its observed source identity changed",
    }
}

/// Exponential policy delay, with server Retry-After as a floor even beyond the normal ceiling.
pub(crate) fn next_delay(
    interval: Duration,
    max_interval: Duration,
    polls: u32,
    retry_after: Option<Duration>,
) -> Duration {
    let base = interval.clamp(Duration::from_secs(5), Duration::from_mins(5));
    let cap = max_interval.clamp(base, Duration::from_mins(5));
    base.saturating_mul(1_u32 << polls.saturating_sub(1).min(6))
        .min(cap)
        .max(retry_after.unwrap_or_default())
}

/// Keep one cheap send plus terminal collection capacity inside the original admission.
pub(crate) fn admit_next(
    connector: ConnectorId,
    polls: u32,
    max_polls: u32,
    outages: u32,
    remaining_http: u64,
    remaining: Duration,
    delay: Duration,
) -> Result<(), WatchError> {
    if polls >= max_polls.min(100) {
        return Err(WatchError {
            cause: "watch_poll_limit",
            detail: "The watch exhausted its poll allowance",
        });
    }
    if outages >= 3 {
        return Err(WatchError {
            cause: "watch_outage_limit",
            detail: "The watch exhausted its consecutive outage allowance",
        });
    }
    let headroom = match connector {
        ConnectorId::Github => 2,
        ConnectorId::Jenkins => 40,
        ConnectorId::Sonarqube => 4,
        _ => return Err(invalid()),
    };
    if remaining_http < headroom + 1 {
        return Err(WatchError {
            cause: "watch_collection_budget",
            detail: "Insufficient HTTP allowance remains for polling and terminal evidence",
        });
    }
    if delay >= remaining {
        return Err(WatchError {
            cause: "watch_deadline",
            detail: "The next poll would exceed the original request deadline",
        });
    }
    Ok(())
}
