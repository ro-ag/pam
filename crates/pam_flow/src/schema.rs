//! The flow types, and the raw YAML shape they are built from.
//!
//! Two layers live here. The public types ([`Flow`], [`Step`], [`Action`],
//! …) are what the rest of pam works with: every default is already
//! resolved, durations are real [`Duration`]s, and an action is either a
//! command or a connector call — never both and never neither. The private
//! `Raw*` types mirror the YAML file one key at a time, reject unknown keys,
//! and keep `timeout`/`retry.backoff` as strings; [`crate::validate::parse`]
//! turns one into the other and is the only place the conversion happens.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize, Serializer};

use crate::duration::format_duration;

/// The only schema version this crate understands.
pub const SCHEMA_VERSION: u16 = 1;

/// The connectors a flow step may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorId {
    /// GitHub Actions.
    Github,
    /// Jenkins.
    Jenkins,
    /// `SonarQube`.
    Sonarqube,
    /// Jira Data Center.
    Jira,
    /// Confluence Cloud.
    Confluence,
    /// `SharePoint` through Microsoft Graph.
    Sharepoint,
    /// Allowlisted read-only AWS CLI passthrough.
    Aws,
}

impl ConnectorId {
    /// Every connector, in the order the GUI lists them.
    pub const ALL: [Self; 7] = [
        Self::Github,
        Self::Jenkins,
        Self::Sonarqube,
        Self::Jira,
        Self::Confluence,
        Self::Sharepoint,
        Self::Aws,
    ];

    /// The wire name, as it appears in YAML and in the store.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Jenkins => "jenkins",
            Self::Sonarqube => "sonarqube",
            Self::Jira => "jira",
            Self::Confluence => "confluence",
            Self::Sharepoint => "sharepoint",
            Self::Aws => "aws",
        }
    }

    /// Reads a wire name back. Matching is exact — no case folding, so a
    /// typo in a flow file is a validation error rather than a surprise.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.as_str() == name)
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value passed to a connector call: YAML scalars only, string or integer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArgValue {
    /// A string argument.
    Text(String),
    /// An integer argument (`limit: 20`).
    Int(i64),
}

impl fmt::Display for ArgValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Int(value) => write!(f, "{value}"),
        }
    }
}

/// What a step does once its gate has passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Run a local program. `argv[0]` is a bare program name, never a shell
    /// string.
    Command {
        /// Program and arguments, already split.
        argv: Vec<String>,
    },
    /// Call one read-only connector operation.
    Connector {
        /// Which connector.
        connector: ConnectorId,
        /// The call name, one of [`crate::connector_calls`].
        call: String,
        /// The call's arguments.
        with: BTreeMap<String, ArgValue>,
    },
}

/// Whether a step changes anything outside pam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Reads only; the default.
    #[default]
    ReadOnly,
    /// Changes state, so the policy gate treats it as destructive.
    Stateful,
}

/// What a step contributes to the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Gathers context.
    Observe,
    /// Proves something; read-only steps only.
    Verify,
    /// Changes something; the default for stateful steps.
    Change,
}

impl Role {
    /// The role a step gets when the YAML does not name one.
    #[must_use]
    pub fn default_for(effect: Effect) -> Self {
        match effect {
            Effect::ReadOnly => Self::Observe,
            Effect::Stateful => Self::Change,
        }
    }
}

/// What happens to a step's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    /// Compress it into evidence; the default.
    #[default]
    Compact,
    /// Compress it and ask the model for a summary.
    Summarize,
    /// Keep nothing.
    Discard,
}

/// When a step runs.
///
/// YAML spells the two keywords as plain scalars (`when: always`) and the
/// two references as one-entry maps (`when: { succeeded: build }`), so the
/// serde impls are written by hand: serde's own enum representations would
/// demand a YAML tag (`!succeeded build`), which is not what a human writes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum When {
    /// Every step in `needs` succeeded; the default.
    #[default]
    NeedsSucceeded,
    /// Always, whatever came before.
    Always,
    /// The named earlier step succeeded.
    Succeeded(String),
    /// The named earlier step failed.
    Failed(String),
}

const WHEN_SHAPES: &str =
    "`needs_succeeded`, `always`, `{ succeeded: <step> }` or `{ failed: <step> }`";

impl Serialize for When {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::NeedsSucceeded => serializer.serialize_str("needs_succeeded"),
            Self::Always => serializer.serialize_str("always"),
            Self::Succeeded(step) => serializer.collect_map([("succeeded", step)]),
            Self::Failed(step) => serializer.collect_map([("failed", step)]),
        }
    }
}

impl<'de> Deserialize<'de> for When {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Keyword(String),
            Reference(BTreeMap<String, String>),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Keyword(word) => match word.as_str() {
                "needs_succeeded" => Ok(Self::NeedsSucceeded),
                "always" => Ok(Self::Always),
                other => Err(serde::de::Error::custom(format!(
                    "unknown `when` value `{other}`; expected {WHEN_SHAPES}"
                ))),
            },
            Repr::Reference(map) => {
                let mut entries = map.into_iter();
                let (Some((key, step)), None) = (entries.next(), entries.next()) else {
                    return Err(serde::de::Error::custom(format!(
                        "`when` takes exactly one condition; expected {WHEN_SHAPES}"
                    )));
                };
                match key.as_str() {
                    "succeeded" => Ok(Self::Succeeded(step)),
                    "failed" => Ok(Self::Failed(step)),
                    other => Err(serde::de::Error::custom(format!(
                        "unknown `when` condition `{other}`; expected {WHEN_SHAPES}"
                    ))),
                }
            }
        }
    }
}

/// How often a failed step is retried, and how long between attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Retry {
    /// Total attempts, including the first (1 means no retry).
    pub attempts: u8,
    /// Delay before the second attempt; it doubles after each failure.
    #[serde(serialize_with = "serialize_duration")]
    pub backoff: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            attempts: 1,
            backoff: Duration::from_millis(500),
        }
    }
}

/// Whether a step waits for a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// No approval of its own; the default.
    #[default]
    None,
    /// Always asks, whatever the profile allows.
    Required,
}

/// One flow input, filled by the caller or by its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Input {
    /// What the value means, shown in the GUI.
    pub description: String,
    /// The value used when the caller passes none. May reference `repo.*`.
    pub default: Option<String>,
}

/// One step of a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Unique within the flow, `[a-z0-9-]{1,64}`.
    pub id: String,
    /// The command or connector call.
    pub action: Action,
    /// Wall-clock limit for one attempt.
    #[serde(serialize_with = "serialize_duration")]
    pub timeout: Duration,
    /// Read-only or stateful.
    pub effect: Effect,
    /// Observe, verify or change.
    pub role: Role,
    /// Require no stdout or stderr bytes, in addition to a zero command exit.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub expect_empty_output: bool,
    /// What happens to the output.
    pub output: OutputPolicy,
    /// Earlier step ids this one waits for.
    pub needs: Vec<String>,
    /// The condition guarding the step.
    pub when: When,
    /// Retry policy.
    pub retry: Retry,
    /// Whether the step always asks a human.
    pub approval: Approval,
    /// Environment additions for a command step.
    pub env: BTreeMap<String, String>,
    /// Free text beside the step — what the designer draws as a tethered
    /// note card. Never a secret; empty when the file has none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Step {
    /// `"command"` or `"connector"` — the word the verdict body uses.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self.action {
            Action::Command { .. } => "command",
            Action::Connector { .. } => "connector",
        }
    }

    /// Whether the step goes through the policy gate before it runs: every
    /// stateful step, every step that asks for approval, and every connector
    /// step (it leaves the machine).
    #[must_use]
    pub fn gated(&self) -> bool {
        self.effect == Effect::Stateful
            || self.approval == Approval::Required
            || matches!(self.action, Action::Connector { .. })
    }
}

/// A validated flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flow {
    /// The flow id; equals the library file stem.
    pub id: String,
    /// Human name.
    pub name: String,
    /// What the flow is for, in plain English.
    pub description: String,
    /// Declared inputs, keyed by name.
    pub inputs: BTreeMap<String, Input>,
    /// Steps in execution order.
    pub steps: Vec<Step>,
}

fn serialize_duration<S: Serializer>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_duration(*value))
}

/// The flow file exactly as YAML spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFlow {
    pub(crate) schema: u16,
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) inputs: BTreeMap<String, RawInput>,
    pub(crate) steps: Vec<RawStep>,
}

/// One input exactly as YAML spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawInput {
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) default: Option<String>,
}

/// One step exactly as YAML spells it: every field optional but `id`, so
/// validation can name the missing or conflicting key itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawStep {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) run: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) connector: Option<String>,
    #[serde(default)]
    pub(crate) call: Option<String>,
    #[serde(default)]
    pub(crate) with: Option<BTreeMap<String, ArgValue>>,
    #[serde(default)]
    pub(crate) timeout: Option<String>,
    #[serde(default)]
    pub(crate) effect: Option<Effect>,
    #[serde(default)]
    pub(crate) role: Option<Role>,
    #[serde(default)]
    pub(crate) output: Option<OutputPolicy>,
    #[serde(default)]
    pub(crate) expect_empty_output: Option<bool>,
    #[serde(default)]
    pub(crate) needs: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) when: Option<When>,
    #[serde(default)]
    pub(crate) retry: Option<RawRetry>,
    #[serde(default)]
    pub(crate) approval: Option<Approval>,
    #[serde(default)]
    pub(crate) env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub(crate) note: Option<String>,
}

/// A retry block exactly as YAML spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRetry {
    pub(crate) attempts: u8,
    #[serde(default)]
    pub(crate) backoff: Option<String>,
}
