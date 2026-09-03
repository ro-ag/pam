//! The canonical rendering of a flow, and its digest.
//!
//! [`to_normalized_yaml`] writes a validated [`Flow`] back as YAML in one
//! fixed key order with every default left out, so two files that mean the
//! same thing render identically. That is what makes the designer canvas
//! safe to round-trip through (plan #6), what the GUI diffs an edit
//! against, and what [`digest`] fingerprints — a flow's digest changes when
//! its meaning changes and not when its formatting does.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::duration::format_duration;
use crate::schema::{
    Action, Approval, ArgValue, ConnectorId, Effect, Flow, OutputPolicy, Retry, Role,
    SCHEMA_VERSION, Step, When,
};
use crate::validate::DEFAULT_TIMEOUT;

/// The domain separator hashed in front of the normalized YAML.
const DIGEST_DOMAIN: &[u8] = b"pam-flow-v1\0";

/// Renders a flow in canonical form: `schema`, `id`, `name`, `description`,
/// `inputs`, `steps`, and per step `id`, the action, then only the fields
/// that differ from their defaults.
///
/// # Panics
///
/// Never in practice: a [`Flow`] holds only strings, numbers and maps, all
/// of which YAML can express.
#[must_use]
pub fn to_normalized_yaml(flow: &Flow) -> String {
    serde_yaml_ng::to_string(&NormalFlow::from(flow))
        .expect("a validated flow always renders as YAML")
}

/// The flow's fingerprint: `sha256("pam-flow-v1\0" ++ normalized yaml)`, hex.
#[must_use]
pub fn digest(flow: &Flow) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(to_normalized_yaml(flow).as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Serialize)]
struct NormalFlow<'a> {
    schema: u16,
    id: &'a str,
    name: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    description: &'a str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    inputs: BTreeMap<&'a str, NormalInput<'a>>,
    steps: Vec<NormalStep<'a>>,
}

impl<'a> From<&'a Flow> for NormalFlow<'a> {
    fn from(flow: &'a Flow) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            id: &flow.id,
            name: &flow.name,
            description: &flow.description,
            inputs: flow
                .inputs
                .iter()
                .map(|(name, input)| {
                    (
                        name.as_str(),
                        NormalInput {
                            description: &input.description,
                            default: input.default.as_deref(),
                        },
                    )
                })
                .collect(),
            steps: flow.steps.iter().map(NormalStep::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct NormalInput<'a> {
    #[serde(skip_serializing_if = "str::is_empty")]
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<&'a str>,
}

#[derive(Serialize)]
struct NormalStep<'a> {
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connector: Option<ConnectorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    with: Option<&'a BTreeMap<String, ArgValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effect: Option<Effect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<Role>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<OutputPolicy>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    needs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    when: Option<&'a When>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry: Option<NormalRetry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<Approval>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    env: &'a BTreeMap<String, String>,
}

impl<'a> From<&'a Step> for NormalStep<'a> {
    fn from(step: &'a Step) -> Self {
        let (run, connector, call, with) = match &step.action {
            Action::Command { argv } => (Some(argv.as_slice()), None, None, None),
            Action::Connector {
                connector,
                call,
                with,
            } => (
                None,
                Some(*connector),
                Some(call.as_str()),
                (!with.is_empty()).then_some(with),
            ),
        };
        Self {
            id: &step.id,
            run,
            connector,
            call,
            with,
            timeout: (step.timeout != DEFAULT_TIMEOUT).then(|| format_duration(step.timeout)),
            effect: (step.effect != Effect::default()).then_some(step.effect),
            role: (step.role != Role::default_for(step.effect)).then_some(step.role),
            output: (step.output != OutputPolicy::default()).then_some(step.output),
            needs: &step.needs,
            when: (step.when != When::default()).then_some(&step.when),
            retry: (step.retry != Retry::default()).then(|| NormalRetry {
                attempts: step.retry.attempts,
                backoff: format_duration(step.retry.backoff),
            }),
            approval: (step.approval != Approval::default()).then_some(step.approval),
            env: &step.env,
        }
    }
}

#[derive(Serialize)]
struct NormalRetry {
    attempts: u8,
    backoff: String,
}
