#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod engine;

#[cfg(test)]
mod engine_test;
#[cfg(test)]
mod lib_test;

pub use engine::{
    ApprovalDecision, ApprovalToken, EffectAttempt, EffectReport, EffectResult, EffectResultKind,
    EngineUpdate, EvidenceHandle, FLOW_SNAPSHOT_VERSION, FlowEngineError, FlowOutcomeReport,
    FlowOutcomeSection, FlowRun, FlowRunResult, FlowSemanticEvent, FlowSnapshot, FlowWaitReason,
    IdempotencyIdentity, MAX_EFFECT_SUMMARY_BYTES, MAX_EVIDENCE_HANDLE_BYTES, MAX_EVIDENCE_HANDLES,
    MAX_FLOW_SEMANTIC_EVENTS_PER_TRANSITION, MAX_RUN_ID_BYTES, ReconciliationResult, RunDecision,
    RunId, RunOutcome, RunStatus, RunTransition, StepApprovalState, StepRunResult,
    StepRunResultKind, StepSnapshot, StepState, TransitionKind, validate_snapshot_successor,
    validate_snapshot_upgrade,
};

pub const FLOW_SCHEMA_VERSION: u16 = 2;
pub const MIN_FLOW_SCHEMA_VERSION: u16 = 1;
pub const MAX_FLOW_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_FLOW_STEPS: usize = 128;
pub const MAX_FLOW_ID_BYTES: usize = 64;
pub const MAX_COMMAND_ARGS: usize = 64;
pub const MAX_COMMAND_ARG_BYTES: usize = 4_096;
pub const MAX_COMMAND_ARGS_BYTES: usize = 32 * 1_024;
pub const MAX_TIMEOUT_SECONDS: u32 = 3_600;
pub const MAX_RETRY_ATTEMPTS: u8 = 5;
pub const MAX_INITIAL_BACKOFF_MS: u64 = 60_000;
pub const MAX_BACKOFF_MS: u64 = 300_000;
pub const MAX_OUTCOME_EVIDENCE_HANDLES: usize = 4;

const MAX_NAME_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 2_048;
const MAX_TEMPLATE_BYTES: usize = 4_096;
const MAX_WORKING_DIRECTORY_BYTES: usize = 512;
const MAX_PROGRAM_BYTES: usize = 128;
const MAX_CONNECTOR_BYTES: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 128;
const MAX_RESOURCE_KIND_BYTES: usize = 64;
const MAX_RESOURCE_ID_BYTES: usize = 1_024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// A validated, versioned declarative flow definition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FlowDefinition {
    schema_version: u16,
    id: String,
    name: String,
    description: String,
    revision: u64,
    steps: Vec<FlowStep>,
    outcome: OutcomeTemplate,
}

impl FlowDefinition {
    /// Parses and validates one TOML flow document.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized or malformed TOML and for every schema or
    /// graph validation failure. Unknown fields are always rejected.
    pub fn parse_toml(source: &str) -> Result<Self, FlowParseError> {
        if source.len() > MAX_FLOW_DOCUMENT_BYTES {
            return Err(FlowParseError::DocumentTooLarge {
                actual: source.len(),
                maximum: MAX_FLOW_DOCUMENT_BYTES,
            });
        }

        let definition: Self = toml::from_str(source).map_err(FlowParseError::Toml)?;
        definition.validate().map_err(FlowParseError::Validation)?;
        Ok(definition)
    }

    /// Validates the schema, safety invariants, and complete dependency graph.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic field-addressed validation failure.
    pub fn validate(&self) -> Result<(), FlowValidationError> {
        if !(MIN_FLOW_SCHEMA_VERSION..=FLOW_SCHEMA_VERSION).contains(&self.schema_version) {
            return validation_error(
                "schema_version",
                format!(
                    "unsupported schema version {}; supported versions are {MIN_FLOW_SCHEMA_VERSION} through {FLOW_SCHEMA_VERSION}",
                    self.schema_version
                ),
            );
        }
        validate_slug("id", &self.id, MAX_FLOW_ID_BYTES)?;
        validate_text("name", &self.name, MAX_NAME_BYTES)?;
        validate_text("description", &self.description, MAX_DESCRIPTION_BYTES)?;
        if self.revision == 0 {
            return validation_error("revision", "must be greater than zero");
        }
        if self.steps.is_empty() {
            return validation_error("steps", "must contain at least one step");
        }
        if self.steps.len() > MAX_FLOW_STEPS {
            return validation_error(
                "steps",
                format!("must contain at most {MAX_FLOW_STEPS} steps"),
            );
        }

        self.outcome.validate()?;

        let mut step_indices = HashMap::with_capacity(self.steps.len());
        for (index, step) in self.steps.iter().enumerate() {
            let path = format!("steps[{index}].id");
            validate_slug(&path, &step.id, MAX_FLOW_ID_BYTES)?;
            if let Some(first) = step_indices.insert(step.id.as_str(), index) {
                return validation_error(
                    path,
                    format!("duplicates steps[{first}].id `{}`", step.id),
                );
            }
        }

        for (index, step) in self.steps.iter().enumerate() {
            step.validate(index, self.schema_version, &step_indices)?;
        }
        validate_acyclic(&self.steps, &step_indices)
    }

    /// Returns a stable, complete TOML representation for version comparison.
    ///
    /// All optional/defaulted values are materialized, fields retain a fixed
    /// order, and steps retain their declared execution order.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the value was constructed through a raw
    /// deserializer instead of [`Self::parse_toml`] and is invalid.
    pub fn to_normalized_toml(&self) -> Result<String, FlowValidationError> {
        self.validate()?;
        let mut output = String::new();
        push_key_integer(
            &mut output,
            "schema_version",
            u64::from(self.schema_version),
        );
        push_key_string(&mut output, "id", &self.id);
        push_key_string(&mut output, "name", &self.name);
        push_key_string(&mut output, "description", &self.description);
        push_key_integer(&mut output, "revision", self.revision);
        output.push_str("\n[outcome]\n");
        push_key_string(&mut output, "solved", &self.outcome.solved);
        push_key_string(&mut output, "changed", &self.outcome.changed);
        push_key_string(&mut output, "verified", &self.outcome.verified);
        push_key_string(&mut output, "unresolved", &self.outcome.unresolved);
        push_key_string(&mut output, "blocked", &self.outcome.blocked);

        for step in &self.steps {
            output.push_str("\n[[steps]]\n");
            push_key_string(&mut output, "id", &step.id);
            push_key_string(&mut output, "description", &step.description);
            push_key_array(&mut output, "depends_on", &step.depends_on);
            output.push_str("condition = ");
            step.condition.write_inline_toml(&mut output);
            output.push('\n');
            output.push_str("retry = ");
            step.retry.write_inline_toml(&mut output);
            output.push('\n');
            push_key_string(&mut output, "approval", step.approval.as_str());
            if let Some(key) = &step.idempotency_key {
                push_key_string(&mut output, "idempotency_key", key);
            }
            push_key_integer(
                &mut output,
                "timeout_seconds",
                u64::from(step.timeout_seconds),
            );
            push_key_string(&mut output, "effect", step.effect.as_str());
            if self.schema_version >= 2 {
                push_key_string(&mut output, "semantic", step.semantic_role().as_str());
            }
            output.push_str("action = ");
            step.action.write_inline_toml(&mut output);
            output.push('\n');
        }

        Ok(output)
    }

    /// Returns the domain-separated SHA-256 identity of normalized TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid in-memory definition.
    pub fn normalized_digest(&self) -> Result<FlowDigest, FlowValidationError> {
        let normalized = self.to_normalized_toml()?;
        let mut hasher = Sha256::new();
        hasher.update(b"pam-flow-definition-v1\0");
        hasher.update(normalized.as_bytes());
        Ok(FlowDigest(hasher.finalize().into()))
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn steps(&self) -> &[FlowStep] {
        &self.steps
    }

    #[must_use]
    pub const fn outcome(&self) -> &OutcomeTemplate {
        &self.outcome
    }
}

/// The five explicit report templates a flow run must be able to populate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutcomeTemplate {
    solved: String,
    changed: String,
    verified: String,
    unresolved: String,
    blocked: String,
}

impl OutcomeTemplate {
    fn validate(&self) -> Result<(), FlowValidationError> {
        validate_template("outcome.solved", &self.solved)?;
        validate_template("outcome.changed", &self.changed)?;
        validate_template("outcome.verified", &self.verified)?;
        validate_template("outcome.unresolved", &self.unresolved)?;
        validate_template("outcome.blocked", &self.blocked)
    }

    #[must_use]
    pub fn solved(&self) -> &str {
        &self.solved
    }

    #[must_use]
    pub fn changed(&self) -> &str {
        &self.changed
    }

    #[must_use]
    pub fn verified(&self) -> &str {
        &self.verified
    }

    #[must_use]
    pub fn unresolved(&self) -> &str {
        &self.unresolved
    }

    #[must_use]
    pub fn blocked(&self) -> &str {
        &self.blocked
    }
}

/// One ordered node in the flow graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FlowStep {
    id: String,
    description: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    condition: StepCondition,
    #[serde(default)]
    retry: RetryPolicy,
    #[serde(default)]
    approval: ApprovalMode,
    #[serde(default)]
    idempotency_key: Option<String>,
    timeout_seconds: u32,
    effect: EffectKind,
    #[serde(default)]
    semantic: Option<StepSemanticRole>,
    action: StepAction,
}

impl FlowStep {
    fn validate(
        &self,
        index: usize,
        schema_version: u16,
        step_indices: &HashMap<&str, usize>,
    ) -> Result<(), FlowValidationError> {
        let base = format!("steps[{index}]");
        validate_text(
            &format!("{base}.description"),
            &self.description,
            MAX_DESCRIPTION_BYTES,
        )?;
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return validation_error(
                format!("{base}.timeout_seconds"),
                format!("must be between 1 and {MAX_TIMEOUT_SECONDS}"),
            );
        }
        self.retry.validate(&format!("{base}.retry"))?;

        let mut dependencies = HashSet::with_capacity(self.depends_on.len());
        for (dependency_index, dependency) in self.depends_on.iter().enumerate() {
            let path = format!("{base}.depends_on[{dependency_index}]");
            validate_slug(&path, dependency, MAX_FLOW_ID_BYTES)?;
            if !step_indices.contains_key(dependency.as_str()) {
                return validation_error(path, format!("references unknown step `{dependency}`"));
            }
            if dependency == &self.id {
                return validation_error(path, "cannot reference the step itself");
            }
            if !dependencies.insert(dependency.as_str()) {
                return validation_error(path, format!("duplicates dependency `{dependency}`"));
            }
        }

        if let Some(reference) = self.condition.referenced_step() {
            let path = format!("{base}.condition.step");
            validate_slug(&path, reference, MAX_FLOW_ID_BYTES)?;
            if !step_indices.contains_key(reference) {
                return validation_error(path, format!("references unknown step `{reference}`"));
            }
            if reference == self.id {
                return validation_error(path, "cannot reference the step itself");
            }
        }

        if self.effect == EffectKind::Stateful {
            if self.approval != ApprovalMode::Required {
                return validation_error(
                    format!("{base}.approval"),
                    "stateful actions require approval = `required`",
                );
            }
            if self.idempotency_key.is_none() {
                return validation_error(
                    format!("{base}.idempotency_key"),
                    "stateful actions require an idempotency key",
                );
            }
        }
        match (schema_version, self.semantic) {
            (1, Some(_)) => {
                return validation_error(
                    format!("{base}.semantic"),
                    "schema version 1 derives semantics and must omit this field",
                );
            }
            (2, None) => {
                return validation_error(
                    format!("{base}.semantic"),
                    "schema version 2 requires an explicit semantic role",
                );
            }
            (1 | 2, _) => {}
            _ => unreachable!("the flow schema version is validated before its steps"),
        }
        match (self.effect, self.semantic_role()) {
            (EffectKind::ReadOnly, StepSemanticRole::Observe | StepSemanticRole::Verify)
            | (EffectKind::Stateful, StepSemanticRole::Change) => {}
            (EffectKind::ReadOnly, StepSemanticRole::Change) => {
                return validation_error(
                    format!("{base}.semantic"),
                    "change semantics require a stateful effect",
                );
            }
            (EffectKind::Stateful, StepSemanticRole::Observe | StepSemanticRole::Verify) => {
                return validation_error(
                    format!("{base}.semantic"),
                    "stateful effects must use change semantics",
                );
            }
        }
        if let Some(key) = &self.idempotency_key {
            validate_identity(
                &format!("{base}.idempotency_key"),
                key,
                MAX_IDEMPOTENCY_KEY_BYTES,
            )?;
        }
        self.action.validate(&base)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.depends_on
    }

    #[must_use]
    pub const fn condition(&self) -> &StepCondition {
        &self.condition
    }

    #[must_use]
    pub const fn retry(&self) -> &RetryPolicy {
        &self.retry
    }

    #[must_use]
    pub const fn approval(&self) -> ApprovalMode {
        self.approval
    }

    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    #[must_use]
    pub const fn timeout_seconds(&self) -> u32 {
        self.timeout_seconds
    }

    #[must_use]
    pub const fn effect(&self) -> EffectKind {
        self.effect
    }

    #[must_use]
    pub const fn semantic_role(&self) -> StepSemanticRole {
        match self.semantic {
            Some(role) => role,
            None => match self.effect {
                EffectKind::ReadOnly => StepSemanticRole::Observe,
                EffectKind::Stateful => StepSemanticRole::Change,
            },
        }
    }

    #[must_use]
    pub const fn action(&self) -> &StepAction {
        &self.action
    }
}

/// A structured condition over a completed step outcome.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepCondition {
    #[default]
    Always,
    Succeeded {
        step: String,
    },
    Failed {
        step: String,
    },
}

impl StepCondition {
    #[must_use]
    pub fn referenced_step(&self) -> Option<&str> {
        match self {
            Self::Always => None,
            Self::Succeeded { step } | Self::Failed { step } => Some(step),
        }
    }

    fn write_inline_toml(&self, output: &mut String) {
        match self {
            Self::Always => output.push_str("{ kind = \"always\" }"),
            Self::Succeeded { step } => {
                output.push_str("{ kind = \"succeeded\", step = ");
                push_quoted(output, step);
                output.push_str(" }");
            }
            Self::Failed { step } => {
                output.push_str("{ kind = \"failed\", step = ");
                push_quoted(output, step);
                output.push_str(" }");
            }
        }
    }
}

/// A bounded retry budget. One attempt means retries are disabled.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    max_attempts: u8,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
        }
    }
}

impl RetryPolicy {
    fn validate(&self, path: &str) -> Result<(), FlowValidationError> {
        if self.max_attempts == 0 || self.max_attempts > MAX_RETRY_ATTEMPTS {
            return validation_error(
                format!("{path}.max_attempts"),
                format!("must be between 1 and {MAX_RETRY_ATTEMPTS}"),
            );
        }
        if self.max_attempts == 1 {
            if self.initial_backoff_ms != 0 || self.max_backoff_ms != 0 {
                return validation_error(path, "backoff must be zero when max_attempts is 1");
            }
            return Ok(());
        }
        if self.initial_backoff_ms == 0 || self.initial_backoff_ms > MAX_INITIAL_BACKOFF_MS {
            return validation_error(
                format!("{path}.initial_backoff_ms"),
                format!("must be between 1 and {MAX_INITIAL_BACKOFF_MS} when retrying"),
            );
        }
        if self.max_backoff_ms < self.initial_backoff_ms || self.max_backoff_ms > MAX_BACKOFF_MS {
            return validation_error(
                format!("{path}.max_backoff_ms"),
                format!("must be at least initial_backoff_ms and at most {MAX_BACKOFF_MS}"),
            );
        }
        Ok(())
    }

    #[must_use]
    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }

    #[must_use]
    pub const fn initial_backoff_ms(self) -> u64 {
        self.initial_backoff_ms
    }

    #[must_use]
    pub const fn max_backoff_ms(self) -> u64 {
        self.max_backoff_ms
    }

    fn write_inline_toml(self, output: &mut String) {
        use fmt::Write as _;
        write!(
            output,
            "{{ max_attempts = {}, initial_backoff_ms = {}, max_backoff_ms = {} }}",
            self.max_attempts, self.initial_backoff_ms, self.max_backoff_ms
        )
        .expect("writing to a String cannot fail");
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    None,
    Required,
}

impl ApprovalMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    ReadOnly,
    Stateful,
}

impl EffectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Stateful => "stateful",
        }
    }
}

/// The truthful user-visible meaning of a successful step.
///
/// Observation records evidence without claiming verification. Verification is
/// reserved for read-only checks, while change is reserved for stateful effects.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepSemanticRole {
    #[default]
    Observe,
    Verify,
    Change,
}

impl StepSemanticRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Verify => "verify",
            Self::Change => "change",
        }
    }
}

/// A typed, non-executable description of a supported effect boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum StepAction {
    Command {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        working_directory: String,
    },
    Connector {
        connector: String,
        capability: String,
        resource: ConnectorResource,
    },
}

impl StepAction {
    fn validate(&self, step_path: &str) -> Result<(), FlowValidationError> {
        match self {
            Self::Command {
                program,
                args,
                working_directory,
            } => {
                validate_command_name(&format!("{step_path}.action.program"), program)?;
                validate_working_directory(
                    &format!("{step_path}.action.working_directory"),
                    working_directory,
                )?;
                if args.len() > MAX_COMMAND_ARGS {
                    return validation_error(
                        format!("{step_path}.action.args"),
                        format!("must contain at most {MAX_COMMAND_ARGS} arguments"),
                    );
                }
                let mut total_bytes = 0_usize;
                for (argument_index, argument) in args.iter().enumerate() {
                    let path = format!("{step_path}.action.args[{argument_index}]");
                    validate_text(&path, argument, MAX_COMMAND_ARG_BYTES)?;
                    reject_secret_like(&path, argument)?;
                    reject_sensitive_argument_name(&path, argument)?;
                    total_bytes = total_bytes.saturating_add(argument.len());
                }
                if total_bytes > MAX_COMMAND_ARGS_BYTES {
                    return validation_error(
                        format!("{step_path}.action.args"),
                        format!("must total at most {MAX_COMMAND_ARGS_BYTES} UTF-8 bytes"),
                    );
                }
            }
            Self::Connector {
                connector,
                capability,
                resource,
            } => {
                validate_connector_name(&format!("{step_path}.action.connector"), connector)?;
                validate_capability_name(&format!("{step_path}.action.capability"), capability)?;
                resource.validate(&format!("{step_path}.action.resource"))?;
            }
        }
        Ok(())
    }

    fn write_inline_toml(&self, output: &mut String) {
        match self {
            Self::Command {
                program,
                args,
                working_directory,
            } => {
                output.push_str("{ type = \"command\", program = ");
                push_quoted(output, program);
                output.push_str(", args = ");
                push_array(output, args);
                output.push_str(", working_directory = ");
                push_quoted(output, working_directory);
                output.push_str(" }");
            }
            Self::Connector {
                connector,
                capability,
                resource,
            } => {
                output.push_str("{ type = \"connector\", connector = ");
                push_quoted(output, connector);
                output.push_str(", capability = ");
                push_quoted(output, capability);
                output.push_str(", resource = { kind = ");
                push_quoted(output, &resource.kind);
                output.push_str(", id = ");
                push_quoted(output, &resource.id);
                output.push_str(" } }");
            }
        }
    }

    #[must_use]
    pub fn as_command(&self) -> Option<CommandActionRef<'_>> {
        match self {
            Self::Command {
                program,
                args,
                working_directory,
            } => Some(CommandActionRef {
                program,
                args,
                working_directory,
            }),
            Self::Connector { .. } => None,
        }
    }

    #[must_use]
    pub fn as_connector(&self) -> Option<ConnectorActionRef<'_>> {
        match self {
            Self::Connector {
                connector,
                capability,
                resource,
            } => Some(ConnectorActionRef {
                connector,
                capability,
                resource,
            }),
            Self::Command { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorResource {
    kind: String,
    id: String,
}

impl ConnectorResource {
    fn validate(&self, path: &str) -> Result<(), FlowValidationError> {
        validate_slug(&format!("{path}.kind"), &self.kind, MAX_RESOURCE_KIND_BYTES)?;
        validate_resource_id(&format!("{path}.id"), &self.id)
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandActionRef<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub working_directory: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorActionRef<'a> {
    pub connector: &'a str,
    pub capability: &'a str,
    pub resource: &'a ConnectorResource,
}

/// A stable algorithm-qualified flow-definition digest.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FlowDigest([u8; 32]);

impl FlowDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for FlowDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for FlowDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "FlowDigest({self})")
    }
}

#[derive(Debug)]
pub enum FlowParseError {
    DocumentTooLarge { actual: usize, maximum: usize },
    Toml(toml::de::Error),
    Validation(FlowValidationError),
}

impl fmt::Display for FlowParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { actual, maximum } => write!(
                formatter,
                "flow document is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::Toml(error) => write!(formatter, "invalid flow TOML: {error}"),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl Error for FlowParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Toml(error) => Some(error),
            Self::Validation(error) => Some(error),
            Self::DocumentTooLarge { .. } => None,
        }
    }
}

/// A field-addressed semantic schema violation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowValidationError {
    path: String,
    message: String,
}

impl FlowValidationError {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FlowValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "flow validation failed at {}: {}",
            self.path, self.message
        )
    }
}

impl Error for FlowValidationError {}

fn validation_error<T>(
    path: impl Into<String>,
    message: impl Into<String>,
) -> Result<T, FlowValidationError> {
    Err(FlowValidationError {
        path: path.into(),
        message: message.into(),
    })
}

fn validate_text(path: &str, value: &str, maximum: usize) -> Result<(), FlowValidationError> {
    if value.is_empty() {
        return validation_error(path, "must not be empty");
    }
    if value.len() > maximum {
        return validation_error(path, format!("must be at most {maximum} UTF-8 bytes"));
    }
    if value.chars().any(char::is_control) {
        return validation_error(path, "must not contain control characters");
    }
    if value.trim() != value {
        return validation_error(path, "must not have leading or trailing whitespace");
    }
    reject_secret_like(path, value)
}

fn validate_template(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_TEMPLATE_BYTES)
}

fn validate_slug(path: &str, value: &str, maximum: usize) -> Result<(), FlowValidationError> {
    validate_text(path, value, maximum)?;
    let mut previous_separator = false;
    for (index, byte) in value.bytes().enumerate() {
        let separator = matches!(byte, b'-' | b'_');
        let valid = byte.is_ascii_lowercase() || byte.is_ascii_digit() || separator;
        if !valid
            || index == 0 && !byte.is_ascii_lowercase()
            || separator && previous_separator
            || separator && index + 1 == value.len()
        {
            return validation_error(path, "must be a lowercase slug beginning with a letter");
        }
        previous_separator = separator;
    }
    Ok(())
}

fn validate_identity(path: &str, value: &str, maximum: usize) -> Result<(), FlowValidationError> {
    validate_text(path, value, maximum)?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric()
            || index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return validation_error(
            path,
            "must contain only ASCII letters, digits, and internal `-_.:/` separators",
        );
    }
    Ok(())
}

fn validate_command_name(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_PROGRAM_BYTES)?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'-' | b'_' | b'.' | b'+')
    }) {
        return validation_error(
            path,
            "must be a command name, not a path, with only ASCII letters, digits, `-_.+`",
        );
    }
    Ok(())
}

fn validate_connector_name(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_CONNECTOR_BYTES)?;
    validate_dotted_name(path, value, "connector")
}

fn validate_capability_name(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_CAPABILITY_BYTES)?;
    validate_dotted_name(path, value, "capability")
}

fn validate_dotted_name(path: &str, value: &str, label: &str) -> Result<(), FlowValidationError> {
    let valid = value.split('.').all(|segment| {
        !segment.is_empty()
            && segment.as_bytes()[0].is_ascii_lowercase()
            && segment.as_bytes()[segment.len() - 1].is_ascii_alphanumeric()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    });
    if !valid {
        return validation_error(path, format!("must be a lowercase dotted {label} identity"));
    }
    Ok(())
}

fn validate_working_directory(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_WORKING_DIRECTORY_BYTES)?;
    if value == "." {
        return Ok(());
    }
    if value.starts_with(['/', '\\'])
        || value.contains(':')
        || value.ends_with(['/', '\\'])
        || value.split(['/', '\\']).any(|part| {
            part.is_empty() || part == "." || part == ".." || part.chars().any(char::is_whitespace)
        })
    {
        return validation_error(
            path,
            "must be a normalized relative path without root, drive, `.` or `..` segments",
        );
    }
    Ok(())
}

fn validate_resource_id(path: &str, value: &str) -> Result<(), FlowValidationError> {
    validate_text(path, value, MAX_RESOURCE_ID_BYTES)?;
    if value.contains("//")
        || value.contains(['\\', '?', '#', '@'])
        || value
            .split([':', '/'])
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return validation_error(
            path,
            "must be a canonical opaque resource identity using ASCII alphanumerics and `-_.:/`",
        );
    }
    reject_secret_like(path, value)
}

fn reject_sensitive_argument_name(path: &str, value: &str) -> Result<(), FlowValidationError> {
    let lowercase = value.to_ascii_lowercase();
    let name = lowercase
        .split_once('=')
        .map_or(lowercase.as_str(), |(name, _)| name);
    let normalized = name.trim_start_matches('-').replace(['-', '_'], "");
    if matches!(
        normalized.as_str(),
        "token"
            | "accesstoken"
            | "authtoken"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "apikey"
            | "accesskey"
            | "privatekey"
            | "credential"
    ) {
        return validation_error(
            path,
            "must not contain an inline secret option or assignment",
        );
    }
    Ok(())
}

fn reject_secret_like(path: &str, value: &str) -> Result<(), FlowValidationError> {
    let lowercase = value.to_ascii_lowercase();
    let token_prefix = [
        "bearer ",
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "sk_live_",
        "sk_test_",
    ]
    .iter()
    .any(|prefix| lowercase.contains(prefix));
    if token_prefix
        || contains_aws_access_key(value)
        || contains_jwt(value)
        || contains_url_userinfo(value)
    {
        return validation_error(path, "must not contain inline secret-like material");
    }
    Ok(())
}

fn contains_aws_access_key(value: &str) -> bool {
    value.as_bytes().windows(20).any(|window| {
        matches!(&window[..4], b"AKIA" | b"ASIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn contains_jwt(value: &str) -> bool {
    value.split_ascii_whitespace().any(|word| {
        let word = word.trim_matches(|character: char| {
            matches!(character, '"' | '\'' | ',' | ';' | '(' | ')')
        });
        let mut parts = word.split('.');
        let (Some(first), Some(second), Some(third), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        first.len() >= 8
            && second.len() >= 8
            && third.len() >= 8
            && [first, second, third].iter().all(|part| {
                part.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
            })
    })
}

fn contains_url_userinfo(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split('/').next())
        .is_some_and(|authority| authority.contains('@'))
}

fn validate_acyclic(
    steps: &[FlowStep],
    step_indices: &HashMap<&str, usize>,
) -> Result<(), FlowValidationError> {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Visit {
        Visiting,
        Complete,
    }

    fn visit<'a>(
        step_index: usize,
        steps: &'a [FlowStep],
        step_indices: &HashMap<&'a str, usize>,
        states: &mut [Option<Visit>],
        stack: &mut Vec<usize>,
    ) -> Result<(), FlowValidationError> {
        match states[step_index] {
            Some(Visit::Complete) => return Ok(()),
            Some(Visit::Visiting) => {
                let cycle_start = stack
                    .iter()
                    .position(|index| *index == step_index)
                    .unwrap_or(0);
                let mut cycle = stack[cycle_start..]
                    .iter()
                    .map(|index| steps[*index].id.as_str())
                    .collect::<Vec<_>>();
                cycle.push(steps[step_index].id.as_str());
                return validation_error(
                    format!("steps[{step_index}]"),
                    format!("dependency cycle detected: {}", cycle.join(" -> ")),
                );
            }
            None => {}
        }
        states[step_index] = Some(Visit::Visiting);
        stack.push(step_index);

        let step = &steps[step_index];
        for reference in step
            .depends_on
            .iter()
            .map(String::as_str)
            .chain(step.condition.referenced_step())
        {
            visit(step_indices[reference], steps, step_indices, states, stack)?;
        }

        stack.pop();
        states[step_index] = Some(Visit::Complete);
        Ok(())
    }

    let mut states = vec![None; steps.len()];
    let mut stack = Vec::with_capacity(steps.len());
    for step_index in 0..steps.len() {
        visit(step_index, steps, step_indices, &mut states, &mut stack)?;
    }
    Ok(())
}

fn push_key_integer(output: &mut String, key: &str, value: u64) {
    use fmt::Write as _;
    writeln!(output, "{key} = {value}").expect("writing to a String cannot fail");
}

fn push_key_string(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push_str(" = ");
    push_quoted(output, value);
    output.push('\n');
}

fn push_key_array(output: &mut String, key: &str, values: &[String]) {
    output.push_str(key);
    output.push_str(" = ");
    push_array(output, values);
    output.push('\n');
}

fn push_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        push_quoted(output, value);
    }
    output.push(']');
}

fn push_quoted(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            _ => output.push(character),
        }
    }
    output.push('"');
}
