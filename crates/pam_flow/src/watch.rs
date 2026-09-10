//! Polling is limited to exact product identities and adapter-owned terminal states.
use crate::schema::RawWatch;
use crate::validate::FlowError;
use crate::{Action, ArgValue, ConnectorId, Effect, Retry, Watch, parse_duration};
use std::time::Duration;

pub(crate) fn validate(
    raw: Option<RawWatch>,
    action: &Action,
    effect: Effect,
    retry: Retry,
    at: &str,
) -> Result<Option<Watch>, FlowError> {
    let Some(raw) = raw else { return Ok(None) };
    let invalid = || {
        FlowError::Invalid {
        path: format!("{at}.watch"),
        message: "watch requires an exact read-only supported collector, fixed identifiers, default retry and bounded sampling intervals".to_owned(),
    }
    };
    if effect != Effect::ReadOnly || retry != Retry::default() {
        return Err(invalid());
    }
    let Action::Connector {
        connector,
        call,
        with,
    } = action
    else {
        return Err(invalid());
    };
    let required: &[(&str, bool)] = match (*connector, call.as_str()) {
        (ConnectorId::Github, "run") => &[("repo", false), ("run_id", true), ("run_attempt", true)],
        (ConnectorId::Jenkins, "investigate") => &[("job", false), ("build", true)],
        (ConnectorId::Sonarqube, "analysis") => &[("project", false), ("ce_task", false)],
        _ => return Err(invalid()),
    };
    if required
        .iter()
        .any(|(key, numeric)| with.get(*key).is_none_or(|value| !fixed(value, *numeric)))
        || with.values().any(|value| !fixed(value, false))
    {
        return Err(invalid());
    }
    if with.contains_key("branch") && with.contains_key("pullRequest") {
        return Err(invalid());
    }
    let defaults = Watch::default();
    let interval = raw
        .interval
        .as_deref()
        .map(parse_duration)
        .transpose()
        .map_err(|_| invalid())?
        .unwrap_or(defaults.interval);
    let max_interval = raw
        .max_interval
        .as_deref()
        .map(parse_duration)
        .transpose()
        .map_err(|_| invalid())?
        .unwrap_or(defaults.max_interval);
    let max_polls = raw.max_polls.unwrap_or(defaults.max_polls);
    if !(1..=100).contains(&max_polls)
        || interval < Duration::from_secs(5)
        || max_interval < interval
        || max_interval > Duration::from_mins(5)
    {
        return Err(invalid());
    }
    Ok(Some(Watch {
        max_polls,
        interval,
        max_interval,
    }))
}
fn fixed(value: &ArgValue, numeric: bool) -> bool {
    match value {
        ArgValue::Int(value) => !numeric || *value > 0,
        ArgValue::Text(text) => {
            if text.starts_with("${inputs.")
                && text.ends_with('}')
                && crate::vars::references(text).len() == 1
            {
                return text
                    .strip_prefix("${")
                    .and_then(|s| s.strip_suffix('}'))
                    .is_some_and(|key| !key.contains(['{', '}', '$']));
            }
            !text.contains("${")
                && !text.trim().is_empty()
                && (!numeric || text.parse::<i64>().is_ok_and(|value| value > 0))
        }
    }
}
