//! The flow engine: the library a human edits, the settings that bound
//! what a step may run, and one run of a flow end to end.
//!
//! `flow.run` classifies `NonDestructive`; each step that could change
//! something is gated on its own under [`step_capability`]
//! (`flow.step:<flow>/<step>`), which is what approvals show and remember.
//! A remembered step is bound to what it runs ([`step_binding`]: the step's
//! [`step_effect_digest`], its gate class and the run's canonical
//! repository), so a step edited outside the GUI, or run in another
//! repository, asks again (see [`crate::policy::PolicyGate::evaluate_step`]).
//! A step is gated ([`pam_flow::Step::gated`]) when it is stateful or asks
//! for approval (`Destructive`) or calls a connector (`External`); a
//! read-only local command never touches the gate.
//!
//! A denied/expired approval, gate refusal, disabled connector or
//! non-allowlisted program ends the run `blocked` with the step naming why:
//! the request finishes `done` and the verdict is filed as evidence. Only
//! [`CAUSE_FLOW_NOT_FOUND`], [`CAUSE_FLOW_INVALID`], [`CAUSE_FLOW_CHANGED`],
//! [`CAUSE_INPUT_MISSING`], [`CAUSE_INPUT_UNKNOWN`], [`CAUSE_INPUT_INVALID`] and
//! [`CAUSE_REPO_MISSING`] are refusals ([`CapabilityFailure::Refused`]).
//! Step output goes through [`LogService::compress`](crate::log_service::LogService::compress)
//! (`compact` default, `summarize` adds a model paragraph, `discard` keeps
//! nothing; empty output is not filed). The verdict body is written verbatim
//! as one [`EVIDENCE_KIND_FLOW_RESULT`] row so run history and
//! `pam flow run --no-wait` callers can read it later.

#[path = "flow_watch_runtime.rs"]
mod watch_runtime;
#[cfg(test)]
#[path = "flow_watch_runtime_test.rs"]
mod watch_runtime_test;

#[path = "flow_artifacts.rs"]
mod artifacts;
#[path = "landing_checks.rs"]
mod landing_checks;
#[cfg(all(test, target_os = "macos"))]
#[path = "flow_landing_integration_test.rs"]
mod landing_integration_test;
#[path = "flow_landing_runtime.rs"]
mod landing_runtime;
#[cfg(test)]
#[path = "flow_landing_runtime_test.rs"]
mod landing_runtime_test;
pub(crate) use landing_runtime::{landing_workspace, release_workspace};

#[path = "flow_step.rs"]
mod step;
#[path = "flow_step_command.rs"]
mod step_command;
#[path = "flow_step_connector.rs"]
mod step_connector;
#[path = "flow_step_landing.rs"]
mod step_landing;
use step::{Attempt, InspectScope, StepExecutor, step_kind};
#[cfg(test)]
pub(crate) use step_connector::apply_connector_assertion;
use step_connector::rate_limit_wait;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::{CallResult, ConnectorId};
use pam_flow::{
    Action, ArgValue, ArgvError, Entry, Flow, Library, OutputPolicy, Prior, Retry, Role, Step,
    Vars, digest, is_shell, references, substitute, substitute_argv, to_normalized_yaml,
};
use pam_proto::Outcome;
use pam_store::{GrantBinding, RequestState, Store, StoreError};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::approval::{ApprovalOutcome, ApprovalService, RememberScope, StepSnapshot};
use crate::connector_service::{ConnectorService, InvokeError};
use crate::daemon::{CAUSE_APPROVAL_DENIED, CAUSE_APPROVAL_TIMEOUT};
use crate::executor::{CapabilityFailure, CapabilityOutput, ExecContext, outcome_str};
use crate::flow_exec::{
    CommandOutcome, CommandSpec, EffectRecord, RunReport, StepReport, StepStatus, SummaryModel,
    cancelled, effects_for, effects_note, outcome_for, resolve_program, run_command_budgeted,
    scrub_env, sleep_or_cancel, summary_for,
};
use crate::flow_intent::EffectIntent;
use crate::flow_recovery::Prepare;
use crate::log_service::{CompressInput, LogService, new_evidence_id};
use crate::managed_policy::{
    CAUSE_POLICY_DENIED, EffectiveEntry, Key, PolicyView, RECOVERY_MANAGED, WriteRefusal,
};
use crate::managed_policy_service::PolicyHandle;
use crate::model_readiness::Stage;
use crate::model_service::Tier;
use crate::policy::{CapabilityClass, GateDecision, GrantStanding, PolicyGate, StepGrant};
use crate::scope_policy::{RECOVERY_SCOPE, ScopeError, ScopePolicy};

/// `setting` key holding the programs a command step may run.
pub const SETTING_ALLOWED_PROGRAMS: &str = "flows.allowed_programs";

/// `setting` key holding the directories prepended to a step's `PATH`.
pub const SETTING_EXTRA_PATH: &str = "flows.extra_path";

/// `setting` key holding the private directory build outputs go under
/// (a JSON string, or `null` while no human has named one).
pub const SETTING_ARTIFACTS_ROOT: &str = "flows.artifacts_root";

/// `setting` key holding the toolchain caches a step may read but not
/// write (`~/.cargo/registry`, `~/.cargo/git`).
pub const SETTING_READ_CACHE_ROOTS: &str = "flows.read_cache_roots";

/// Capability name: run a flow.
pub const CAP_FLOW_RUN: &str = "flow.run";

/// Capability name: list the flow library.
pub const CAP_FLOW_LIST: &str = "flow.list";

/// Capability name: read one flow.
pub const CAP_FLOW_SHOW: &str = "flow.show";

/// Read-only readiness inspection; never executes the recipe.
pub const CAP_FLOW_INSPECT: &str = "flow.inspect";

/// Prefix of the per-step capability names the gate sees.
pub const STEP_CAPABILITY_PREFIX: &str = "flow.step:";

/// Evidence kind holding one run's verdict body.
pub const EVIDENCE_KIND_FLOW_RESULT: &str = "flow.result";

/// Evidence kind holding one connector call's JSON answer.
pub const EVIDENCE_KIND_CONNECTOR_RESULT: &str = "connector.result";

/// Refusal cause: no flow, builtin or library, carries that id.
pub const CAUSE_FLOW_NOT_FOUND: &str = "flow_not_found";

/// Refusal cause: the flow file does not validate.
pub const CAUSE_FLOW_INVALID: &str = "flow_invalid";

/// Refusal cause: a declared input has neither a value nor a default.
pub const CAUSE_INPUT_MISSING: &str = "input_missing";

/// Refusal cause: the run was handed an input name the flow does not declare.
pub const CAUSE_INPUT_UNKNOWN: &str = "input_unknown";

/// Refusal cause: an input value is present but is not a string or number.
pub const CAUSE_INPUT_INVALID: &str = "input_invalid";

/// Refusal cause: the caller's repo is not a directory on this machine.
pub const CAUSE_REPO_MISSING: &str = "repo_missing";

/// Refusal cause: the run pinned a flow digest (`expected_digest`) and the
/// library's flow no longer has it — it was edited after `flow.inspect`.
pub const CAUSE_FLOW_CHANGED: &str = "flow_changed";

/// Recovery line for [`CAUSE_FLOW_CHANGED`].
pub const RECOVERY_FLOW_CHANGED: &str = "run `pam flow inspect` again, review what the flow does now, and re-run with the digest it reports";

/// Step cause: a supplied value would have become a command-line option.
pub const CAUSE_ARGUMENT_OPTION: &str = "argument_option_refused";

/// Recovery line for [`CAUSE_ARGUMENT_OPTION`].
pub const RECOVERY_ARGUMENT_OPTION: &str = "pass a value that does not start with `-`, or edit the flow so a literal `--` comes before the argument";

/// Refusal cause: the flow library directory could not be read.
pub const CAUSE_LIBRARY_UNREADABLE: &str = "library_unreadable";

/// Step cause: the program is not in `flows.allowed_programs`.
pub const CAUSE_PROGRAM_NOT_ALLOWED: &str = "program_not_allowed";

/// Step cause: the program keeps state in a home or cache directory and no
/// private build output directory is configured to hold it.
pub const CAUSE_ARTIFACTS_ROOT_UNSET: &str = "artifacts_root_unset";

/// Settings or step cause: the configured build output directory cannot be
/// used (relative, inside the repository or the private base, not private).
pub const CAUSE_ARTIFACTS_ROOT_INVALID: &str = "artifacts_root_invalid";

/// Step cause: the program is allowed but not installed.
pub const CAUSE_PROGRAM_MISSING: &str = "program_missing";

/// Step cause: a `${…}` reference had no value at run time.
pub const CAUSE_VARIABLE_UNAVAILABLE: &str = "variable_unavailable";

/// Step cause: the step outlived its `timeout`.
pub const CAUSE_TIMEOUT: &str = "timeout";

/// Step cause: the step wrote more than `pam_compact::MAX_SOURCE_BYTES`.
pub const CAUSE_OUTPUT_LIMIT: &str = "output_limit";

/// Step cause: the program exited non-zero.
pub const CAUSE_EXIT_STATUS: &str = "exit_status";
/// Refusal cause: a command expected to be silent emitted output.
pub const CAUSE_OUTPUT_ASSERTION: &str = "output_assertion";
/// A retrieved connector result did not meet the explicit status assertion.
pub const CAUSE_STATUS_ASSERTION: &str = "status_assertion";
/// A connector verifier did not declare what result establishes a pass.
pub const CAUSE_STATUS_ASSERTION_REQUIRED: &str = "status_assertion_required";

/// Step cause: the program could not be started at all.
pub const CAUSE_SPAWN_FAILED: &str = "spawn_failed";

/// Step cause: the program ran but the OS would not report how it ended.
pub const CAUSE_WAIT_FAILED: &str = "wait_failed";

/// Step cause: daemon-side bookkeeping failed mid-step.
pub const CAUSE_INTERNAL: &str = "internal_error";

/// Recovery line for a flow id nothing answers to.
pub const RECOVERY_FLOW_LIST: &str = "run `pam flow list` to see the flows this machine has";

/// Recovery line for a flow file that does not validate.
pub const RECOVERY_FLOW_EDIT: &str =
    "open Pam → Flows → the flow → YAML and fix the line the message names";

/// Recovery line for a program the allowlist does not carry.
pub const RECOVERY_ALLOWED_PROGRAMS: &str = "open Pam → Settings → Flows → allowed programs";

/// Recovery for [`CAUSE_ARTIFACTS_ROOT_UNSET`] and [`CAUSE_ARTIFACTS_ROOT_INVALID`].
pub const RECOVERY_ARTIFACTS_ROOT: &str = "open Pam → Settings → Flows → build output directory and name a private directory outside every repository";

/// Recovery line for a program that is allowed but not installed.
pub const RECOVERY_EXTRA_PATH: &str =
    "install the program, or add its directory under open Pam → Settings → Flows → extra PATH";

/// Recovery line for a step waiting on a human.
pub const RECOVERY_APPROVALS: &str = "open Pam → Approvals";

/// How long `git remote get-url origin` may take before `${repo.origin}`
/// counts as unavailable.
const ORIGIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on one retry backoff, per the spec's doubling rule.
const MAX_BACKOFF: Duration = Duration::from_mins(1);

/// The programs a fresh install lets a command step run.
const DEFAULT_ALLOWED_PROGRAMS: &[&str] = &[
    "git", "cargo", "rustup", "npm", "npx", "pnpm", "yarn", "node", "make", "go", "python3",
    "pytest", "uv", "mvn", "gradle", "dotnet", "gh",
];

/// A refusal the flow surface decided before (or instead of) running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRefusal {
    /// Machine-readable cause.
    pub cause: &'static str,
    /// What happened, in one sentence.
    pub detail: String,
    /// The concrete fix.
    pub recovery: String,
}

impl FlowRefusal {
    /// A refusal with a `'static` recovery line.
    #[must_use]
    pub fn new(cause: &'static str, detail: String, recovery: &str) -> Self {
        Self {
            cause,
            detail,
            recovery: recovery.to_owned(),
        }
    }
}

impl From<FlowRefusal> for CapabilityFailure {
    fn from(refusal: FlowRefusal) -> Self {
        Self::Refused {
            cause: refusal.cause.to_owned(),
            detail: refusal.detail,
            recovery: refusal.recovery,
        }
    }
}

/// The per-step capability name the policy gate evaluates.
#[must_use]
pub fn step_capability(flow: &str, step: &str) -> String {
    format!("{STEP_CAPABILITY_PREFIX}{flow}/{step}")
}

/// The gate class of a gated step: a connector call leaves the machine
/// (`External`); every other gated step is `Destructive`.
#[must_use]
pub fn step_class(step: &Step) -> CapabilityClass {
    step_kind(step).class()
}

/// The effect digest of `step`: SHA-256 over what the step does, read off
/// the parsed (normalized) step, never the file's bytes — the program and
/// argument templates of a command, the environment it sets (names and
/// value templates: a value such as `GIT_SSH_COMMAND` changes what runs),
/// whether it is stateful and whether it always asks, the connector, call
/// and argument templates of a connector step, the operation of a landing
/// step. Formatting, comments, the note, the name and the step's place in
/// the file change nothing; anything that changes what runs changes the
/// digest, and a grant bound to the old one no longer covers the step.
#[must_use]
pub fn step_effect_digest(step: &Step) -> String {
    let action = step_kind(step).effect();
    let env: Vec<Value> = step
        .env
        .iter()
        .map(|(name, value)| json!([name, value]))
        .collect();
    // Positional and versioned: two different steps cannot encode alike,
    // and a later encoding can never collide with this one.
    let encoded = json!([
        1,
        action,
        env,
        step.effect == pam_flow::Effect::Stateful,
        step.approval == pam_flow::Approval::Required,
    ]);
    pam_compact::sha256_hex(encoded.to_string().as_bytes())
}

/// What a grant of `step` of `flow` is bound to when it is given for
/// `repository` (canonical; `None` for every repository): see
/// [`pam_store::GrantBinding`].
#[must_use]
pub fn step_binding(flow: &Flow, step: &Step, repository: Option<String>) -> GrantBinding {
    GrantBinding {
        flow_id: flow.id.clone(),
        step_id: step.id.clone(),
        effect_digest: step_effect_digest(step),
        effect_class: crate::policy::class_name(step_class(step)).to_owned(),
        repository,
    }
}

/// What a command step may run, and where its programs are found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSettings {
    /// Bare program names a command step's `run[0]` may name.
    pub allowed_programs: Vec<String>,
    /// Directories prepended to the inherited `PATH`. Stored as the human
    /// typed them, `~` and `%USERPROFILE%` included.
    pub extra_path: Vec<String>,
    /// The private directory build outputs go under, as the human typed
    /// it; `None` until one is named, and a build tool refuses until then.
    pub artifacts_root: Option<String>,
    /// Toolchain caches a step may read but never write, as typed.
    pub read_cache_roots: Vec<String>,
}

impl FlowSettings {
    /// What a fresh install starts with.
    ///
    /// The extra `PATH` differs per platform because a launchd
    /// daemon inherits a minimal one: without these, `cargo` simply does
    /// not exist as far as a flow step is concerned.
    #[must_use]
    pub fn platform_default() -> Self {
        let extra_path = if cfg!(target_os = "windows") {
            vec![r"%USERPROFILE%\.cargo\bin"]
        } else {
            vec!["~/.cargo/bin", "/opt/homebrew/bin", "/usr/local/bin"]
        };
        Self {
            allowed_programs: DEFAULT_ALLOWED_PROGRAMS
                .iter()
                .map(|program| (*program).to_owned())
                .collect(),
            extra_path: extra_path
                .into_iter()
                .map(std::borrow::ToOwned::to_owned)
                .collect(),
            artifacts_root: None,
            read_cache_roots: vec!["~/.cargo/registry".to_owned(), "~/.cargo/git".to_owned()],
        }
    }

    /// [`Self::artifacts_root`] as a real directory, `~` expanded.
    #[must_use]
    pub fn artifacts_root_dir(&self) -> Option<PathBuf> {
        self.artifacts_root.as_deref().and_then(expand_home)
    }

    /// [`Self::read_cache_roots`] as the directories that exist right now;
    /// a cache that is not there is simply not linked.
    #[must_use]
    pub fn read_cache_dirs(&self) -> Vec<PathBuf> {
        self.read_cache_roots
            .iter()
            .filter_map(|raw| expand_home(raw))
            .filter(|dir| dir.is_dir())
            .collect()
    }

    /// [`Self::extra_path`] as real directories, `~` and `%USERPROFILE%`
    /// expanded against the daemon user's home. An entry whose home
    /// cannot be found is dropped rather than passed through with a
    /// literal tilde in it.
    #[must_use]
    pub fn extra_path_dirs(&self) -> Vec<PathBuf> {
        self.extra_path
            .iter()
            .filter_map(|raw| expand_home(raw))
            .collect()
    }

    /// Whether a command step may run `program`.
    #[must_use]
    pub fn allows(&self, program: &str) -> bool {
        !is_shell(program)
            && self
                .allowed_programs
                .iter()
                .any(|allowed| allowed == program)
    }

    /// These (stored) settings under the managed policy `view`: the
    /// effective settings and one `effective` entry per field, in
    /// [`SETTINGS_FIELDS`] order. `flows.programs` is an exact-name
    /// allowlist (or a locked list), `flows.extra_path` and
    /// `flows.read_cache_roots` are path-prefix allowlists compared by
    /// component after `~` expansion, and `flows.artifacts_root` is locked
    /// or a default. Nothing here is persisted: the human's rows stay as
    /// they were saved.
    #[must_use]
    pub fn managed(&self, view: &PolicyView) -> (Self, [EffectiveEntry; 4]) {
        let home = std::env::home_dir();
        let home = home.as_deref();
        let (allowed_programs, programs) = view.effective_programs(&self.allowed_programs);
        let (extra_path, path) =
            view.effective_path_list(Key::FlowsExtraPath, &self.extra_path, home);
        let (artifacts_root, artifacts) =
            view.effective_string(Key::FlowsArtifactsRoot, self.artifacts_root.clone());
        let (read_cache_roots, caches) =
            view.effective_path_list(Key::FlowsReadCacheRoots, &self.read_cache_roots, home);
        (
            Self {
                allowed_programs,
                extra_path,
                artifacts_root,
                read_cache_roots,
            },
            [programs, path, artifacts, caches],
        )
    }

    /// The `effective` block of a settings reply: `{ value, source, locked,
    /// mode?, constraint?, reason?, state?, clamped? }` per field, from
    /// [`Self::managed`].
    #[must_use]
    pub fn effective_json(&self, entries: &[EffectiveEntry; 4]) -> Value {
        let values = [
            json!(self.allowed_programs),
            json!(self.extra_path),
            json!(self.artifacts_root),
            json!(self.read_cache_roots),
        ];
        let mut block = serde_json::Map::new();
        for ((field, entry), value) in SETTINGS_FIELDS.iter().zip(entries).zip(values) {
            let mut item = entry.to_json();
            item["value"] = value;
            block.insert((*field).to_owned(), item);
        }
        Value::Object(block)
    }
}

/// The settings fields, in the order [`FlowSettings::managed`] reports them.
pub const SETTINGS_FIELDS: [&str; 4] = [
    "allowed_programs",
    "extra_path",
    "artifacts_root",
    "read_cache_roots",
];

/// Whether the managed policy forbids a command step from running
/// `program` (a name its exact-name allowlist or locked list leaves out).
#[must_use]
pub fn policy_forbids_program(view: &PolicyView, program: &str) -> bool {
    let (kept, _) = view.effective_programs(&[program.to_owned()]);
    !kept.iter().any(|allowed| allowed == program)
}

/// Whether the managed policy lets the human save `patch`: one snapshot,
/// checked before any write. A field the patch leaves out is not checked.
///
/// # Errors
///
/// `policy_frozen` for a held key, `setting_locked` for a locked one and
/// `policy_not_allowed` for an entry outside an allowlist (see
/// [`PolicyView::check_list`]).
pub fn check_settings_patch(view: &PolicyView, patch: &SettingsPatch) -> Result<(), WriteRefusal> {
    let home = std::env::home_dir();
    let home = home.as_deref();
    for (key, list) in [
        (Key::FlowsPrograms, patch.allowed_programs.as_deref()),
        (Key::FlowsExtraPath, patch.extra_path.as_deref()),
        (Key::FlowsReadCacheRoots, patch.read_cache_roots.as_deref()),
    ] {
        if let Some(list) = list {
            view.check_list(key, &clean_list(list), home)?;
        }
    }
    if !matches!(patch.artifacts_root, ArtifactsRootPatch::Keep) {
        view.guard_locked(Key::FlowsArtifactsRoot)?;
    }
    Ok(())
}

/// Expands a leading `~` or `%USERPROFILE%` in a stored path.
fn expand_home(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    for prefix in ["~", "%USERPROFILE%"] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            let rest = rest.trim_start_matches(['/', '\\']);
            let home = std::env::home_dir()?;
            return Some(if rest.is_empty() {
                home
            } else {
                home.join(rest)
            });
        }
    }
    Some(PathBuf::from(raw))
}

/// What [`FlowService::set_settings`] changes; an absent field is left
/// alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingsPatch {
    /// Replaces the allowlist.
    pub allowed_programs: Option<Vec<String>>,
    /// Replaces the extra `PATH`.
    pub extra_path: Option<Vec<String>>,
    /// Names, clears, or leaves alone the build output directory.
    pub artifacts_root: ArtifactsRootPatch,
    /// Replaces the read-only cache list.
    pub read_cache_roots: Option<Vec<String>>,
}

/// What a settings patch does to the build output directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ArtifactsRootPatch {
    /// Leave it as it is.
    #[default]
    Keep,
    /// Forget it; build tools refuse again until a new one is named.
    Clear,
    /// Name it, as the human typed it.
    Set(String),
}

/// What one `flow.run` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// The flow id.
    pub id: String,
    /// Values for the flow's declared inputs.
    pub inputs: BTreeMap<String, String>,
    /// The digest `flow.inspect` reported, when the caller pins the run to
    /// what it inspected; the run refuses [`CAUSE_FLOW_CHANGED`] otherwise.
    pub expected_digest: Option<String>,
}

impl RunArgs {
    /// Reads the arguments off a `flow.run` envelope.
    ///
    /// # Errors
    ///
    /// [`CAUSE_FLOW_NOT_FOUND`] when no id was named — there is nothing to
    /// look up, and the recovery is the same list command. [`CAUSE_INPUT_INVALID`]
    /// when `inputs` is present but is not an object of scalar values: a value
    /// that cannot reach a `${…}` substitution is refused, never dropped. The
    /// same cause refuses an `expected_digest` that is not a flow digest: a
    /// pin that could never match must not read as "the flow changed".
    pub fn from_value(args: &Value) -> Result<Self, FlowRefusal> {
        let id = args
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                FlowRefusal::new(
                    CAUSE_FLOW_NOT_FOUND,
                    "flow.run needs a non-empty string argument \"id\" naming the flow".to_owned(),
                    RECOVERY_FLOW_LIST,
                )
            })?;
        let mut inputs = BTreeMap::new();
        match args.get("inputs") {
            None => {}
            Some(Value::Object(map)) => {
                for (name, value) in map {
                    let Some(text) = scalar_text(value) else {
                        return Err(FlowRefusal::new(
                            CAUSE_INPUT_INVALID,
                            format!("input {name:?} must be a string or number, not {value}"),
                            "re-run with each input as a string, e.g. name=value",
                        ));
                    };
                    inputs.insert(name.clone(), text);
                }
            }
            Some(other) => {
                return Err(FlowRefusal::new(
                    CAUSE_INPUT_INVALID,
                    format!("flow.run inputs must be an object of scalars, not {other}"),
                    "re-run with an inputs object of string values",
                ));
            }
        }
        let expected_digest = match args.get("expected_digest") {
            None | Some(Value::Null) => None,
            Some(Value::String(digest)) if is_flow_digest(digest) => Some(digest.clone()),
            Some(_) => {
                return Err(FlowRefusal::new(
                    CAUSE_INPUT_INVALID,
                    "expected_digest must be the 64 lower-case hex characters `pam flow inspect` \
                     reports as the flow's digest"
                        .to_owned(),
                    RECOVERY_FLOW_CHANGED,
                ));
            }
        };
        Ok(Self {
            id: id.to_owned(),
            inputs,
            expected_digest,
        })
    }
}

/// Whether `text` has the shape of [`pam_flow::digest`]'s output.
/// The state an approved step's run carries on in: the state table's
/// [`RequestEvent::Resume`](crate::request_state::RequestEvent::Resume)
/// target (never refused; the fallback is the same state).
fn resume_state() -> RequestState {
    crate::request_state::target(crate::request_state::RequestEvent::Resume)
        .unwrap_or(RequestState::Running)
}

fn is_flow_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A JSON scalar as the text a `${…}` substitution would insert.
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// The flow engine (see the module docs).
#[derive(Debug)]
pub struct FlowService {
    protected_base: PathBuf,
    library: Library,
    store: Arc<Store>,
    approvals: Arc<ApprovalService>,
    connectors: Arc<ConnectorService>,
    logs: Arc<LogService>,
    gate: Arc<PolicyGate>,
    /// The managed policy in force (see [`crate::managed_policy_service`]).
    policy: Arc<PolicyHandle>,
}

impl FlowService {
    /// The policy gate this engine evaluates steps through — the daemon's
    /// one live copy of the profile (see [`crate::policy`]).
    pub(crate) fn gate(&self) -> &Arc<PolicyGate> {
        &self.gate
    }

    pub(crate) fn protected_base(&self) -> &Path {
        &self.protected_base
    }

    /// Builds the engine over the library at `<base_dir>/flows`.
    #[must_use]
    pub fn new(
        base_dir: &Path,
        store: Arc<Store>,
        approvals: Arc<ApprovalService>,
        connectors: Arc<ConnectorService>,
        logs: Arc<LogService>,
        gate: Arc<PolicyGate>,
        policy: Arc<PolicyHandle>,
    ) -> Self {
        Self {
            protected_base: base_dir.to_path_buf(),
            library: Library::new(base_dir.join("flows")),
            store,
            approvals,
            connectors,
            logs,
            gate,
            policy,
        }
    }

    /// The managed policy handle this engine reads through (see
    /// [`crate::managed_policy_service`]).
    #[must_use]
    pub fn policy(&self) -> &Arc<PolicyHandle> {
        &self.policy
    }

    /// The flow library this engine reads and writes.
    #[must_use]
    pub fn library(&self) -> &Library {
        &self.library
    }

    /// The effective flow settings: what the human saved under the managed
    /// policy in force (see [`FlowSettings::managed`]). Every consumer reads
    /// these; only the admin edit path reads `user_settings`.
    pub async fn settings(&self) -> Result<FlowSettings, StoreError> {
        let view = self.policy.view();
        Ok(self.user_settings().await?.managed(&view).0)
    }

    /// The flow settings as the human saved them, persisting the platform
    /// default the first time they are read so the GUI always has
    /// something concrete to edit. No policy applied: for the admin edit
    /// path, which shows and edits what the human saved.
    pub(crate) async fn user_settings(&self) -> Result<FlowSettings, StoreError> {
        let defaults = FlowSettings::platform_default();
        Ok(FlowSettings {
            allowed_programs: self
                .setting_list(SETTING_ALLOWED_PROGRAMS, &defaults.allowed_programs)
                .await?,
            extra_path: self
                .setting_list(SETTING_EXTRA_PATH, &defaults.extra_path)
                .await?,
            artifacts_root: self.setting_optional_string(SETTING_ARTIFACTS_ROOT).await?,
            read_cache_roots: self
                .setting_list(SETTING_READ_CACHE_ROOTS, &defaults.read_cache_roots)
                .await?,
        })
    }

    /// One optional string setting; unset, `null` and anything that is not
    /// a string all read as `None`.
    async fn setting_optional_string(&self, key: &str) -> Result<Option<String>, StoreError> {
        let Some(raw) = self.store.get_setting(key).await? else {
            return Ok(None);
        };
        match serde_json::from_str::<Option<String>>(&raw) {
            Ok(value) => Ok(value),
            Err(error) => {
                tracing::warn!(
                    setting = key,
                    %error,
                    "the stored flow setting is not a string; reading it as unset"
                );
                Ok(None)
            }
        }
    }

    /// The effective GUI-approved scopes (under the managed policy in
    /// force), independently of capability grants.
    pub async fn scope_policy(&self) -> Result<ScopePolicy, FlowRefusal> {
        ScopePolicy::load_effective(&self.store, &self.policy.view())
            .await
            .map_err(|error| scope_refusal(&error))
    }

    /// Replace the scope policy through private administration only.
    pub async fn set_scope_policy(&self, policy: ScopePolicy) -> Result<ScopePolicy, FlowRefusal> {
        let policy = policy
            .normalize_blocking()
            .await
            .map_err(|error| scope_refusal(&error))?;
        policy
            .save(&self.store)
            .await
            .map_err(|error| scope_refusal(&error))?;
        Ok(policy)
    }

    async fn approved_repo(&self, repo: &Path) -> Result<PathBuf, FlowRefusal> {
        self.scope_policy()
            .await?
            .authorize_repo_blocking(repo)
            .await
            .map_err(|error| scope_refusal(&error))
    }

    /// One string-list setting, persisted from `default` when unset (or
    /// when what is stored is not a list of strings at all).
    async fn setting_list(&self, key: &str, default: &[String]) -> Result<Vec<String>, StoreError> {
        if let Some(raw) = self.store.get_setting(key).await? {
            match serde_json::from_str::<Vec<String>>(&raw) {
                Ok(list) => return Ok(list),
                Err(error) => tracing::warn!(
                    setting = key,
                    %error,
                    "the stored flow setting is not a list of strings; falling back to the default"
                ),
            }
        }
        let raw = serde_json::to_string(default).expect("a string list always serializes");
        self.store.set_setting(key, &raw).await?;
        Ok(default.to_vec())
    }

    /// Replaces the named settings and returns them as the human saved
    /// them. The managed policy is checked by the admin op before this
    /// ([`check_settings_patch`]), on the snapshot it audits with.
    ///
    /// # Errors
    ///
    /// [`CAUSE_PROGRAM_NOT_ALLOWED`] for a shell, or for anything that is
    /// not a bare program name: the allowlist is a list of programs, and a
    /// path or a shell would turn it into a list of arbitrary commands.
    pub async fn set_settings(&self, patch: SettingsPatch) -> Result<FlowSettings, FlowRefusal> {
        let allowed = patch.allowed_programs.as_deref().map(clean_list);
        if let Some(programs) = &allowed {
            for program in programs {
                check_allowed_program(program)?;
            }
        }
        let root = match &patch.artifacts_root {
            ArtifactsRootPatch::Keep => None,
            ArtifactsRootPatch::Clear => Some(None),
            ArtifactsRootPatch::Set(raw) => Some(Some(check_artifacts_root(raw.trim())?)),
        };
        if let Some(root) = root {
            let raw = serde_json::to_string(&root).expect("an optional string always serializes");
            self.store
                .set_setting(SETTING_ARTIFACTS_ROOT, &raw)
                .await
                .map_err(|error| store_note(&error))?;
        }
        for (key, list) in [
            (SETTING_ALLOWED_PROGRAMS, allowed.as_ref()),
            (
                SETTING_EXTRA_PATH,
                patch.extra_path.as_deref().map(clean_list).as_ref(),
            ),
            (
                SETTING_READ_CACHE_ROOTS,
                patch.read_cache_roots.as_deref().map(clean_list).as_ref(),
            ),
        ] {
            let Some(list) = list else { continue };
            let raw = serde_json::to_string(list).expect("a string list always serializes");
            self.store
                .set_setting(key, &raw)
                .await
                .map_err(|error| store_note(&error))?;
        }
        self.user_settings()
            .await
            .map_err(|error| store_note(&error))
    }

    /// Every flow, builtins merged with the library, sorted by id.
    ///
    /// # Errors
    ///
    /// [`CAUSE_LIBRARY_UNREADABLE`] when the library directory cannot be
    /// read or holds more flow files than the library allows.
    pub fn entries(&self) -> Result<Vec<Entry>, FlowRefusal> {
        self.library.list().map_err(|error| {
            FlowRefusal::new(
                CAUSE_LIBRARY_UNREADABLE,
                format!(
                    "the flow library at {} could not be read: {error}",
                    self.library.dir().display()
                ),
                RECOVERY_FLOW_EDIT,
            )
        })
    }

    /// Default public discovery page. Private administration uses `entries`.
    pub fn list(&self) -> Result<CapabilityOutput, FlowRefusal> {
        self.list_page(&json!({}))
    }

    /// Bounded public discovery; all list entries retain their historical shape.
    pub fn list_page(&self, args: &Value) -> Result<CapabilityOutput, FlowRefusal> {
        let (offset, limit) = crate::flow_contract::pagination(args).map_err(contract_refusal)?;
        let entries = self.entries()?;
        let total = entries.len();
        let mut flows = Vec::new();
        let mut bytes = 256;
        for entry in entries.iter().skip(offset).take(limit) {
            let mut value = list_entry_json(entry, false);
            // Descriptions and defaults are untrusted, and can contain credentials.
            value = crate::evidence_view::redact_json(&value).map_err(|_| {
                contract_refusal(crate::flow_contract::ContractError(
                    "flow discovery cannot be redacted",
                ))
            })?;
            let size = serde_json::to_vec(&value)
                .map_err(|_| {
                    contract_refusal(crate::flow_contract::ContractError(
                        "flow discovery cannot serialize",
                    ))
                })?
                .len();
            if bytes + size > crate::flow_contract::MAX_RESULT_BYTES {
                if flows.is_empty() {
                    return Err(contract_refusal(crate::flow_contract::ContractError(
                        "flow entry exceeds discovery limit; inspect it by id",
                    )));
                }
                break;
            }
            bytes += size + 1;
            flows.push(value);
        }
        let next = offset.saturating_add(flows.len());
        Ok(CapabilityOutput {
            outcome: Outcome::Verified,
            body: json!({"schema_version": 1, "flows": flows, "offset": offset, "total": total,
                "next_offset": (next < total).then_some(next)}),
            evidence: Vec::new(),
        })
    }

    /// Inspect local configuration only. This snapshot never grants admission.
    pub async fn inspect(
        &self,
        ctx: &ExecContext,
        args: &Value,
    ) -> Result<CapabilityOutput, FlowRefusal> {
        let args = inspect_args(args)?;
        let entry = self.entry(&args.id)?;
        let flow = entry.parsed.as_ref().map_err(|_| {
            FlowRefusal::new(
                CAUSE_FLOW_INVALID,
                "flow does not validate".to_owned(),
                RECOVERY_FLOW_EDIT,
            )
        })?;
        let mut blockers = Vec::new();
        // The effective values, on one snapshot: inspection reports what a
        // run would be held to, the managed policy included.
        let view = self.policy.view();
        let run_granted = self
            .store
            .active_grant(CAP_FLOW_RUN)
            .await
            .map_err(|error| store_note(&error))?;
        let run_admission = inspect_admission(
            &view,
            self.gate.profile(),
            CAP_FLOW_RUN,
            run_granted,
            CapabilityClass::NonDestructive,
        );
        match run_admission {
            CAUSE_POLICY_DENIED => blockers.push(json!({"capability": CAP_FLOW_RUN, "cause": CAUSE_POLICY_DENIED, "recovery": crate::policy::RECOVERY_POLICY_DENIED})),
            "not_granted" | "approval_required" => blockers.push(json!({"capability": CAP_FLOW_RUN, "cause": run_admission, "recovery": "review flow.run in GUI Permissions"})),
            _ => {}
        }
        let repo = PathBuf::from(&ctx.caller.repo);
        // The canonical repository a step's grant is bound to, when the
        // scope admits it; otherwise no grant could cover a step here.
        let canonical = match self.approved_repo(&repo).await {
            Ok(canonical) => Some(canonical),
            Err(error) => {
                blockers.push(json!({"cause": error.cause, "recovery": RECOVERY_SCOPE}));
                None
            }
        };
        let crate::flow_contract::InspectedInputs {
            vars,
            missing,
            unknown,
        } = crate::flow_contract::inspect_vars(flow, &args.inputs, &repo);
        for name in missing {
            blockers.push(json!({"cause": "input_unavailable", "input": name, "recovery": "supply the declared input; runtime-derived values require execution"}));
        }
        for name in unknown {
            blockers.push(json!({"cause": CAUSE_INPUT_UNKNOWN, "input": name, "recovery": "drop the input or declare it under the flow's `inputs:`"}));
        }
        let correlation = match &flow.correlation {
            None => json!({"status":"unbound"}),
            Some(declaration) => match declaration.resolve(&vars) {
                Ok(target) => {
                    json!({"status":"declared","target":target,"frozen_on_execution":true})
                }
                Err(error) => {
                    blockers.push(json!({"cause":crate::correlation::INVALID,"detail":error.to_string(),"recovery":crate::correlation::RECOVERY}));
                    json!({"status":"unresolved"})
                }
            },
        };
        let (allowed, artifacts_root) = self.inspect_settings(&view).await?;
        let (steps, step_blockers) = self
            .inspect_steps(
                flow,
                &vars,
                &repo,
                canonical.as_deref(),
                &allowed,
                artifacts_root,
                &view,
            )
            .await?;
        blockers.extend(step_blockers);
        let model = self.inspect_model(flow).await?;
        let body = json!({"schema_version":1, "flow":{"id":flow.id,"digest":digest(flow)},
            "inputs":flow.inputs.iter().map(|(name,input)| input_json(input, json!({"name":name,"required":input.default.is_none()}))).collect::<Vec<_>>(),
            "steps":steps, "correlation":correlation, "readiness":if blockers.is_empty(){"admission_required"}else{"blocked"},
            "blockers":blockers,"live":"unknown","model":model,
            "output_schema":"pam.flow.result.v1","admission_rechecked":true,"run_admission":run_admission});
        let body = crate::evidence_view::redact_json(&body).map_err(|_| {
            contract_refusal(crate::flow_contract::ContractError(
                "inspection cannot be redacted",
            ))
        })?;
        if body.to_string().len() > crate::flow_contract::MAX_RESULT_BYTES {
            return Err(contract_refusal(crate::flow_contract::ContractError(
                "inspection exceeds its response limit",
            )));
        }
        Ok(CapabilityOutput {
            outcome: Outcome::Verified,
            body,
            evidence: Vec::new(),
        })
    }

    /// The effective allowlist and whether a build output directory is set,
    /// read without persisting a default (inspection writes nothing).
    async fn inspect_settings(
        &self,
        view: &PolicyView,
    ) -> Result<(Vec<String>, bool), FlowRefusal> {
        let configured = self
            .store
            .get_setting(SETTING_ALLOWED_PROGRAMS)
            .await
            .map_err(|error| store_note(&error))?;
        let allowed: Vec<String> = match configured {
            Some(raw) => serde_json::from_str(&raw).map_err(|_| {
                FlowRefusal::new(
                    "flow_settings_invalid",
                    "allowed program setting is malformed".to_owned(),
                    RECOVERY_ALLOWED_PROGRAMS,
                )
            })?,
            None => FlowSettings::platform_default().allowed_programs,
        };
        let (allowed, _) = view.effective_programs(&allowed);
        let artifacts_root = view
            .effective_string(
                Key::FlowsArtifactsRoot,
                self.setting_optional_string(SETTING_ARTIFACTS_ROOT)
                    .await
                    .map_err(|error| store_note(&error))?,
            )
            .0
            .is_some();
        Ok((allowed, artifacts_root))
    }

    /// What the model will do for this flow, from the heavy tier's readiness record.
    ///
    /// A flow needs no model to complete — a summarize step falls back to the
    /// compact evidence — so `required` stays false; what an agent needs to know
    /// before running is whether the summary will come (`summary: model`) or be
    /// skipped with a named cause (`summary: skipped`). A flow with no summarize
    /// step reports `not_assessed`, as before.
    async fn inspect_model(&self, flow: &Flow) -> Result<Value, FlowRefusal> {
        let used_by: Vec<&str> = flow
            .steps
            .iter()
            .filter(|step| step.output == OutputPolicy::Summarize)
            .map(|step| step.id.as_str())
            .collect();
        if used_by.is_empty() {
            return Ok(json!({"required": false, "used_by": [], "qualification": "not_assessed"}));
        }
        let readiness = self
            .logs
            .models
            .readiness_now(Tier::Heavy)
            .await
            .map_err(|error| {
                FlowRefusal::new(
                    "model_readiness_unavailable",
                    error.to_string(),
                    "retry; if it persists, check the daemon log and the Models screen",
                )
            })?;
        let qualification = match readiness.stage {
            Stage::Unconfigured => "none",
            Stage::Missing => "missing",
            Stage::Unverified => "unverified",
            Stage::Unqualified => "unqualified",
            Stage::EngineMissing | Stage::Ready => {
                if readiness.qualification.is_some() {
                    "qualified"
                } else {
                    "unqualified"
                }
            }
        };
        Ok(json!({
            "required": false,
            "used_by": used_by,
            "tier": readiness.tier,
            "model_id": readiness.model_id,
            "qualification": qualification,
            "stage": readiness.stage,
            "summary": if readiness.stage == Stage::Ready { "model" } else { "skipped" },
            "blocker": readiness.blocker,
        }))
    }

    /// The admission inspection reports for one gated step, in the gate's
    /// own decision (see [`inspect_gate`]), with its blocker.
    async fn inspect_step_gate(
        &self,
        view: &PolicyView,
        flow: &Flow,
        step: &pam_flow::Step,
        repo: Option<&Path>,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> Result<(), FlowRefusal> {
        let capability = step_capability(&flow.id, &step.id);
        let rows = self
            .store
            .active_grants(&capability)
            .await
            .map_err(|error| store_note(&error))?;
        let (decision, state) = inspect_gate(flow, step, repo, view, self.gate.profile(), &rows);
        let admission = admission_label(&decision);
        if let StepGrant::Changed(changed) = &state {
            item["grant"] = json!("changed");
            item["grant_changed"] = json!(changed);
        } else {
            let granted = matches!(state, StepGrant::Bound | StepGrant::Legacy(_));
            item["grant"] = json!(if granted { "present" } else { "missing" });
        }
        item["admission"] = json!(admission);
        match admission {
            CAUSE_POLICY_DENIED => blockers.push(json!({"step": step.id, "cause": CAUSE_POLICY_DENIED, "recovery": crate::policy::RECOVERY_POLICY_DENIED})),
            "not_granted" | "approval_required" => blockers.push(json!({"step": step.id, "cause": admission, "recovery": "review this flow step in GUI Permissions"})),
            _ => {}
        }
        Ok(())
    }

    /// Read a recipe's step gates and local connector configuration without execution.
    #[allow(clippy::too_many_arguments)] // The inspection's inputs, each read once up front.
    async fn inspect_steps(
        &self,
        flow: &Flow,
        vars: &Vars,
        repo: &Path,
        canonical: Option<&Path>,
        allowed: &[String],
        artifacts_root: bool,
        view: &PolicyView,
    ) -> Result<(Vec<Value>, Vec<Value>), FlowRefusal> {
        let mut blockers = Vec::new();
        let mut steps = Vec::new();
        let scope = InspectScope {
            vars,
            repo,
            allowed,
            artifacts_root,
            view,
        };
        for step in &flow.steps {
            let mut item = json!({"id": step.id, "effect": step.effect, "role": step.role, "kind": step.kind(), "watch": step.watch, "live": "unknown"});
            if step.gated() {
                self.inspect_step_gate(view, flow, step, canonical, &mut item, &mut blockers)
                    .await?;
            }
            step_kind(step)
                .inspect(self, &scope, step, &mut item, &mut blockers)
                .await?;
            steps.push(item);
        }
        Ok((steps, blockers))
    }

    /// `flow.show`: one flow's text, its canonical rendering, and its
    /// digest.
    ///
    /// # Errors
    ///
    /// [`CAUSE_FLOW_NOT_FOUND`] when nothing carries that id. An invalid
    /// file is *not* an error here — reading a broken flow to fix it is
    /// exactly what this is for, so the body says `valid: false` and
    /// carries the message.
    pub fn show(&self, id: &str) -> Result<CapabilityOutput, FlowRefusal> {
        let entry = self.entry(id)?;
        Ok(CapabilityOutput {
            outcome: Outcome::Verified,
            body: show_json(&entry),
            evidence: Vec::new(),
        })
    }

    /// One flow by id, or [`CAUSE_FLOW_NOT_FOUND`].
    pub fn entry(&self, id: &str) -> Result<Entry, FlowRefusal> {
        self.library
            .get(id)
            .map_err(|error| {
                FlowRefusal::new(
                    CAUSE_LIBRARY_UNREADABLE,
                    format!("the flow library could not be read: {error}"),
                    RECOVERY_FLOW_EDIT,
                )
            })?
            .ok_or_else(|| {
                FlowRefusal::new(
                    CAUSE_FLOW_NOT_FOUND,
                    format!("no flow named {id:?} is installed"),
                    RECOVERY_FLOW_LIST,
                )
            })
    }

    /// `flow.run`: one run of one flow, start to verdict.
    ///
    /// # Errors
    ///
    /// [`CapabilityFailure::Refused`] for the six things that stop a run
    /// before it starts (see the module docs),
    /// [`CapabilityFailure::Cancelled`] when the request is cancelled
    /// mid-step, and [`CapabilityFailure::Failed`] when the daemon's own
    /// bookkeeping fails.
    pub async fn run(
        &self,
        ctx: &ExecContext,
        args: RunArgs,
    ) -> Result<CapabilityOutput, CapabilityFailure> {
        let settings = self.settings().await.map_err(failed)?;
        let entry = self.entry(&args.id)?;
        let flow = entry.parsed.as_ref().map_err(|error| {
            FlowRefusal::new(
                CAUSE_FLOW_INVALID,
                format!("flow {:?} does not validate: {error}", args.id),
                RECOVERY_FLOW_EDIT,
            )
        })?;
        refuse_changed_flow(flow, &args)?;
        refuse_undeclared_inputs(flow, &args)?;

        let repo = PathBuf::from(&ctx.caller.repo);
        if !repo.is_dir() {
            return Err(FlowRefusal::new(
                CAUSE_REPO_MISSING,
                format!(
                    "the caller's repo {} is not a directory on this machine",
                    repo.display()
                ),
                "re-run the flow from inside the repository it should act on",
            )
            .into());
        }

        // Scope precedes variable resolution: repo.origin itself runs git.
        let repo = self.approved_repo(&repo).await?;
        let mut cancel = ctx.cancel.clone();
        let (vars, inputs) = self
            .resolve_vars(
                flow,
                &args.inputs,
                &repo,
                &settings,
                &mut cancel,
                &ctx.budget,
            )
            .await?;

        let mut state = RunState::restore(self, ctx, flow, &settings, repo, vars, cancel).await?;
        let executed = state.execute().await;
        // Anything but a parked continuation makes this ticket terminal, so
        // the private landing workspace is released here, before the verdict.
        state.landing_release(&executed).await;
        executed?;

        if let Err(error) = state.correlation.check_mapping(&self.store).await {
            state.correlation.invalidate(&error);
        }

        let products = product_observations(flow, &state.observed);
        let outcome = state.correlation.outcome(outcome_for(&state.reports, flow));
        // The outcome says how the run ended; what it changed on the way is
        // reported beside it, so a failure never hides an effect.
        let effects = effects_for(&state.reports, flow);
        let mut summary = summary_for(&state.reports);
        if let Some(note) = effects_note(outcome, &effects) {
            summary.push('\n');
            summary.push_str(&note);
        }
        let report = RunReport {
            outcome,
            summary,
            steps: state.reports,
        };
        let body = json!({
            "correlation": state.correlation.report(),
            "effects": effects,
            "budget_usage": ctx.budget.usage(),
            "flow": {
                "id": flow.id,
                "name": flow.name,
                "source": entry.source.as_str(),
                "digest": digest(flow),
            },
            "repo": ctx.caller.repo,
            "inputs": inputs,
            "outcome": outcome_str(report.outcome),
            "summary": report.summary,
            "steps": report.steps,
        });

        let capture = crate::evidence_service::CaptureScope {
            repository: state.repo.to_string_lossy().into_owned(),
            origin: crate::evidence_service::EvidenceOrigin {
                targets: state.all_origins,
            },
        };
        let (verdict_id, body) = self
            .file_verdict(
                ctx,
                flow,
                &report,
                &body,
                &capture,
                &state.evidence,
                &products,
                effects,
                state.correlation.summary(),
                state.correlation.target().cloned(),
            )
            .await?;
        // The projection carries bounded references; the outer wire list names only the verdict.
        let evidence = vec![verdict_id];
        Ok(CapabilityOutput {
            outcome: report.outcome,
            body,
            evidence,
        })
    }

    async fn freeze_correlation(
        &self,
        ctx: &ExecContext,
        repo: &Path,
        flow: &Flow,
        vars: &Vars,
    ) -> Result<crate::correlation::Frozen, FlowRefusal> {
        crate::correlation::Frozen::prepare(
            &self.store,
            &ctx.request_id,
            &repo.to_string_lossy(),
            flow,
            vars,
        )
        .await
        .map_err(|error| FlowRefusal::new(error.cause, error.detail, crate::correlation::RECOVERY))
    }

    #[allow(clippy::too_many_arguments)] // Full private report plus its bounded public projection inputs.
    async fn file_verdict(
        &self,
        ctx: &ExecContext,
        flow: &Flow,
        report: &RunReport,
        body: &Value,
        capture: &crate::evidence_service::CaptureScope,
        evidence: &[String],
        products: &BTreeMap<String, crate::flow_contract::ProductObservation>,
        effects: Vec<EffectRecord>,
        correlation: crate::flow_contract::CorrelationSummary,
        target: Option<pam_flow::CorrelationTarget>,
    ) -> Result<(String, Value), CapabilityFailure> {
        let failed = report
            .steps
            .iter()
            .filter(|step| step.status == StepStatus::Failed)
            .count();
        let verdict_id = new_evidence_id();
        let mut public_evidence = vec![verdict_id.clone()];
        public_evidence.extend(evidence.iter().cloned());
        let projection = crate::flow_contract::project_result(
            &ctx.request_id,
            &flow.id,
            &digest(flow),
            report,
            &public_evidence,
            products,
        )
        .map_err(|error| CapabilityFailure::Failed {
            detail: error.to_string(),
        })?;
        let projection = projection
            .with_handoff_target(target)
            .and_then(|p| p.with_effects(effects))
            .and_then(|p| p.with_correlation(correlation))
            .map_err(|error| CapabilityFailure::Failed {
                detail: error.to_string(),
            })?;
        let meta = json!({
            "agent_result": projection,
            "flow": flow.id,
            "outcome": outcome_str(report.outcome),
            "steps": report.steps.len(),
            "failed": failed,
        });
        if meta.to_string().len() > crate::flow_recovery::MAX_INLINE_BYTES {
            return Err(CapabilityFailure::Failed {
                detail: "flow result metadata exceeds its limit".to_owned(),
            });
        }
        let bytes = serde_json::to_vec(body).map_err(|error| CapabilityFailure::Failed {
            detail: error.to_string(),
        })?;
        self.store
            .insert_evidence(
                &verdict_id,
                &ctx.request_id,
                EVIDENCE_KIND_FLOW_RESULT,
                &bytes,
                Some(&meta.to_string()),
            )
            .await
            .map_err(failed_store)?;

        let public_body =
            serde_json::to_value(projection).map_err(|error| CapabilityFailure::Failed {
                detail: error.to_string(),
            })?;
        let published = match crate::evidence_service::prepare(bytes).await {
            Ok(view) => {
                crate::evidence_service::publish(
                    &self.store,
                    capture,
                    &ctx.request_id,
                    &verdict_id,
                    view,
                    json!({"kind": "protected_flow_result"}),
                )
                .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = published {
            tracing::warn!(%error, "flow result view unavailable");
            // The persisted projection remains stable. Retrieval reports view_unavailable.
        }
        Ok((verdict_id, public_body))
    }

    /// Builds the `${…}` values a run starts with: `repo.*` first, then
    /// every declared input from the caller's value or its default.
    async fn resolve_vars(
        &self,
        flow: &Flow,
        supplied: &BTreeMap<String, String>,
        repo: &Path,
        settings: &FlowSettings,
        cancel: &mut watch::Receiver<bool>,
        budget: &Arc<crate::request_budget::RequestBudget>,
    ) -> Result<(Vars, BTreeMap<String, String>), FlowRefusal> {
        let mut vars = Vars::new();
        vars.set("repo.path", repo.display().to_string());
        if let Some(name) = repo.file_name().and_then(|name| name.to_str()) {
            vars.set("repo.name", name);
        }
        // `git remote get-url origin` costs a child process, so it runs
        // only when the flow actually mentions the variable.
        if flow_references(flow).iter().any(|key| key == "repo.origin")
            && let Some(origin) = repo_origin(repo, &self.protected_base, settings, cancel, budget)
                .await
                .map_err(budget_refusal)?
        {
            vars.set("repo.origin", origin);
        }

        let mut inputs = BTreeMap::new();
        for (name, input) in &flow.inputs {
            let value = if let Some(value) = supplied.get(name) {
                value.clone()
            } else {
                let default = input.default.as_ref().ok_or_else(|| {
                    FlowRefusal::new(
                        CAUSE_INPUT_MISSING,
                        format!(
                            "flow {:?} needs an input {name:?} ({}) and it has no default",
                            flow.id, input.description
                        ),
                        &format!("re-run with {name}=<value>"),
                    )
                })?;
                substitute(default, &vars).map_err(|error| {
                    FlowRefusal::new(
                        CAUSE_INPUT_MISSING,
                        format!("the default for input {name:?} cannot be resolved: {error}"),
                        &format!("re-run with {name}=<value>"),
                    )
                })?
            };
            // The declared type, on the finished value (a `${repo.*}`
            // default included). The message names the input, the type and
            // the rule, never the value.
            input.check(name, &value).map_err(|error| {
                FlowRefusal::new(
                    CAUSE_INPUT_INVALID,
                    error.to_string(),
                    &format!("re-run with {name}=<a value that fits the declared type>"),
                )
            })?;
            vars.set(&format!("inputs.{name}"), value.clone());
            inputs.insert(name.clone(), value);
        }
        Ok((vars, inputs))
    }
}

/// `entry` (an input's JSON in a list or an inspection) with the input's
/// declared `type`, and its `values` when it is an enum.
pub(crate) fn input_json(input: &pam_flow::Input, mut entry: Value) -> Value {
    entry["type"] = json!(input.kind.as_str());
    if !input.values.is_empty() {
        entry["values"] = json!(input.values);
    }
    entry
}

/// Refuses an allowlist entry that is not a bare, non-shell program name.
pub(crate) fn check_allowed_program(program: &str) -> Result<(), FlowRefusal> {
    let program = program.trim();
    if is_shell(program) {
        return Err(FlowRefusal::new(
            CAUSE_PROGRAM_NOT_ALLOWED,
            format!(
                "{program:?} is a shell; a flow step runs one program with \
                 arguments, never a command line"
            ),
            RECOVERY_ALLOWED_PROGRAMS,
        ));
    }
    if program.is_empty() || program.contains(['/', '\\']) {
        return Err(FlowRefusal::new(
            CAUSE_PROGRAM_NOT_ALLOWED,
            format!("{program:?} is not a bare program name"),
            RECOVERY_ALLOWED_PROGRAMS,
        ));
    }
    Ok(())
}

/// Refuses a build output directory that is empty or not absolute once
/// `~` is expanded; whether it is private and outside every boundary is
/// checked against the repository each time a step runs.
fn check_artifacts_root(raw: &str) -> Result<String, FlowRefusal> {
    if raw.is_empty() {
        return Err(FlowRefusal::new(
            CAUSE_ARTIFACTS_ROOT_INVALID,
            "the build output directory is empty".to_owned(),
            RECOVERY_ARTIFACTS_ROOT,
        ));
    }
    match expand_home(raw) {
        Some(dir) if dir.is_absolute() => Ok(raw.to_owned()),
        _ => Err(FlowRefusal::new(
            CAUSE_ARTIFACTS_ROOT_INVALID,
            format!("{raw:?} is not an absolute path"),
            RECOVERY_ARTIFACTS_ROOT,
        )),
    }
}

/// Trims, drops empties, and removes duplicates while keeping order.
fn clean_list(list: &[String]) -> Vec<String> {
    let mut cleaned: Vec<String> = Vec::with_capacity(list.len());
    for value in list {
        let value = value.trim();
        if !value.is_empty() && !cleaned.iter().any(|kept| kept == value) {
            cleaned.push(value.to_owned());
        }
    }
    cleaned
}

/// Every `${…}` key a flow mentions anywhere.
fn flow_references(flow: &Flow) -> Vec<String> {
    let mut found = flow
        .correlation
        .as_ref()
        .map_or_else(Vec::new, pam_flow::Correlation::references);
    for input in flow.inputs.values() {
        if let Some(default) = &input.default {
            found.extend(references(default));
        }
    }
    for step in &flow.steps {
        match &step.action {
            Action::Landing { .. } => {}
            Action::Command { argv } => {
                for argument in argv {
                    found.extend(references(argument));
                }
            }
            Action::Connector { with, .. } => {
                for value in with.values() {
                    if let ArgValue::Text(text) = value {
                        found.extend(references(text));
                    }
                }
            }
        }
        for value in step.env.values() {
            found.extend(references(value));
        }
    }
    found
}

/// `owner/name` from the repo's `origin` remote, when it is a GitHub URL.
///
/// Anything else — no git, no remote, a remote pointing somewhere that is
/// not GitHub — leaves `${repo.origin}` unset, so the step that uses it
/// fails with [`CAUSE_VARIABLE_UNAVAILABLE`] instead of quietly calling
/// GitHub about the wrong repository.
async fn repo_origin(
    repo: &Path,
    protected_base: &Path,
    settings: &FlowSettings,
    cancel: &mut watch::Receiver<bool>,
    budget: &Arc<crate::request_budget::RequestBudget>,
) -> Result<Option<String>, crate::request_budget::BudgetError> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let Some(program) = resolve_program("git", &settings.extra_path_dirs(), &path) else {
        return Ok(None);
    };
    let outcome = run_command_budgeted(
        CommandSpec {
            containment: command_boundary(
                protected_base,
                repo,
                &program,
                pam_flow::Effect::ReadOnly,
            ),
            program,
            argv: vec![
                "remote".to_owned(),
                "get-url".to_owned(),
                "origin".to_owned(),
            ],
            cwd: repo.to_path_buf(),
            env: base_env(settings),
            timeout: ORIGIN_TIMEOUT,
        },
        cancel,
        budget,
    )
    .await?;
    let CommandOutcome::Exited { status: 0, output } = outcome else {
        return Ok(None);
    };
    Ok(origin_from_output(&String::from_utf8_lossy(&output)))
}

/// The one GitHub remote in `git remote get-url` output. The child's stdout
/// and stderr arrive interleaved, so a warning line may sit beside the URL:
/// each line is read on its own, and two lines naming different repositories
/// answer nothing rather than whichever came first.
pub(crate) fn origin_from_output(output: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for candidate in output.lines().filter_map(github_owner_name) {
        if found.as_ref().is_some_and(|earlier| *earlier != candidate) {
            return None;
        }
        found = Some(candidate);
    }
    found
}

/// `owner/name` out of a GitHub remote URL, in any of the shapes git
/// stores one (`https://`, `ssh://`, `git@host:owner/name`). The host must be
/// exactly `github.com`: `evil.github.com.example` and a path that merely
/// contains the name are not GitHub.
fn github_owner_name(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url.strip_suffix(".git").unwrap_or(url);
    let (authority, path) = match url.split_once("://") {
        Some((scheme, rest)) => {
            if !matches!(scheme, "https" | "http" | "ssh" | "git") {
                return None;
            }
            rest.split_once('/')?
        }
        // scp-like: `git@github.com:owner/name`.
        None => url.split_once(':')?,
    };
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    // An explicit port is part of the authority, not of the host.
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    if !host.eq_ignore_ascii_case("github.com") {
        return None;
    }
    let mut segments = path.trim_matches('/').split('/');
    let owner = segments.next().filter(|part| !part.is_empty())?;
    let name = segments.next().filter(|part| !part.is_empty())?;
    segments.next().is_none().then(|| format!("{owner}/{name}"))
}

/// The environment every command step starts from: the daemon's own,
/// scrubbed, with `PATH` rebuilt as `extra_path ++ inherited PATH` and
/// git's interactive prompts wired shut.
fn base_env(settings: &FlowSettings) -> Vec<(String, String)> {
    let mut env = scrub_env(std::env::vars_os());
    // Replace inherited Git config injection coherently; stale count/parameter
    // variables must not override the isolated defaults, including in children.
    env.retain(|(name, _)| name != "GIT_CONFIG" && !name.starts_with("GIT_CONFIG_"));
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs = settings.extra_path_dirs();
    dirs.extend(std::env::split_paths(&inherited));
    if let Ok(path) = std::env::join_paths(dirs)
        && let Ok(path) = path.into_string()
    {
        env.push(("PATH".to_owned(), path));
    }
    // A child that stops on a credential prompt would hang until its
    // timeout with nothing to show for it; these three make git and ssh
    // fail fast instead. The askpass helpers point at a path that cannot
    // exist, which is how git spells "never ask".
    let no_askpass = PathBuf::from("pam-never-asks")
        .join("no-askpass")
        .display()
        .to_string();
    env.push(("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned()));
    env.push(("GIT_ASKPASS".to_owned(), no_askpass.clone()));
    env.push(("SSH_ASKPASS".to_owned(), no_askpass));
    // Personal configuration is outside command authority. Git otherwise treats
    // the sandbox denial as fatal even for --version. Repository config remains
    // readable within the approved root; any helpers still inherit containment.
    env.push(("GIT_CONFIG_GLOBAL".to_owned(), "/dev/null".to_owned()));
    env.push(("GIT_CONFIG_SYSTEM".to_owned(), "/dev/null".to_owned()));
    // Git also consults personal ignore/attribute files independently of its
    // global config. Disable those defaults without granting HOME/XDG access.
    env.push(("GIT_CONFIG_COUNT".to_owned(), "2".to_owned()));
    for (index, key) in ["core.excludesFile", "core.attributesFile"]
        .iter()
        .enumerate()
    {
        env.push((format!("GIT_CONFIG_KEY_{index}"), (*key).to_owned()));
        env.push((format!("GIT_CONFIG_VALUE_{index}"), "/dev/null".to_owned()));
    }
    env
}

/// One flow as the list bodies render it. `full` adds the fields only the
/// GUI needs (the file path and the digest).
fn list_entry_json(entry: &Entry, full: bool) -> Value {
    let mut value = match &entry.parsed {
        Ok(flow) => json!({
            "id": entry.id,
            "name": flow.name,
            "description": flow.description,
            "source": entry.source.as_str(),
            "valid": true,
            "steps": flow.steps.len(),
            "inputs": flow.inputs.iter().map(|(name, input)| input_json(input, json!({
                "name": name,
                "description": input.description,
                "default": input.default,
            }))).collect::<Vec<Value>>(),
        }),
        Err(error) => json!({
            "id": entry.id,
            // A broken file still has to be pickable in the GUI list, so
            // it borrows its id as a name rather than rendering blank.
            "name": entry.id,
            "description": "",
            "source": entry.source.as_str(),
            "valid": false,
            "error": error.to_string(),
            "steps": 0,
            "inputs": Vec::<Value>::new(),
        }),
    };
    if full {
        let object = value.as_object_mut().expect("the entry is a JSON object");
        object.insert(
            "path".to_owned(),
            json!(entry.path.as_ref().map(|path| path.display().to_string())),
        );
        object.insert("digest".to_owned(), json!(entry_digest(entry)));
    }
    value
}

/// The `flow.show` body.
fn show_json(entry: &Entry) -> Value {
    let mut value = json!({
        "id": entry.id,
        "source": entry.source.as_str(),
        "yaml": entry.yaml,
        "normalized_yaml": entry.parsed.as_ref().map(to_normalized_yaml).unwrap_or_default(),
        "digest": entry_digest(entry),
        "valid": entry.parsed.is_ok(),
    });
    if let Err(error) = &entry.parsed {
        value
            .as_object_mut()
            .expect("the show body is a JSON object")
            .insert("error".to_owned(), json!(error.to_string()));
    }
    value
}

/// The digest of a valid flow; an invalid file has none to give.
fn entry_digest(entry: &Entry) -> String {
    entry.parsed.as_ref().map(digest).unwrap_or_default()
}

/// A store failure a flow surface reports as a refusal.
fn scope_refusal(error: &ScopeError) -> FlowRefusal {
    FlowRefusal::new(error.cause(), error.to_string(), RECOVERY_SCOPE)
}

fn store_note(error: &StoreError) -> FlowRefusal {
    FlowRefusal::new(
        CAUSE_INTERNAL,
        format!("the flow settings could not be saved: {error}"),
        "retry; if it persists, restart the daemon from the PAM GUI",
    )
}

/// A store failure a run reports as an execution failure.
fn failed_store(error: StoreError) -> CapabilityFailure {
    failed(error)
}

/// Any error a run cannot recover from.
fn failed(error: impl std::fmt::Display) -> CapabilityFailure {
    CapabilityFailure::Failed {
        detail: format!("flow bookkeeping failed: {error}"),
    }
}

/// One run in progress: the flow, what it may do, and what it has done so
/// far.
struct RunState<'a> {
    service: &'a FlowService,
    ctx: &'a ExecContext,
    flow: &'a Flow,
    settings: &'a FlowSettings,
    repo: PathBuf,
    vars: Vars,
    observed: Vars,
    correlation: crate::correlation::Frozen,
    recovery: crate::flow_recovery::Recovery,
    watch_grant_stamp: Option<(String, i64)>,
    cancel: watch::Receiver<bool>,
    reports: Vec<StepReport>,
    evidence: Vec<String>,
    origins: BTreeMap<String, crate::evidence_service::ConnectorTarget>,
    all_origins: Vec<crate::evidence_service::ConnectorTarget>,
}

impl<'a> RunState<'a> {
    async fn restore(
        service: &'a FlowService,
        ctx: &'a ExecContext,
        flow: &'a Flow,
        settings: &'a FlowSettings,
        repo: PathBuf,
        vars: Vars,
        cancel: watch::Receiver<bool>,
    ) -> Result<Self, CapabilityFailure> {
        let correlation = service.freeze_correlation(ctx, &repo, flow, &vars).await?;
        let (recovery, restored) = crate::flow_recovery::Recovery::open_with_policy(
            &service.store,
            &service.policy.view(),
            &ctx.request_id,
            flow,
            &repo,
            &vars,
        )
        .await?;
        let restored_reports = restored.restore_reports(flow)?;
        let mut state = RunState {
            service,
            ctx,
            flow,
            settings,
            repo,
            observed: restored.observed,
            vars: restored.vars,
            recovery,
            watch_grant_stamp: None,
            correlation,
            cancel,
            reports: restored_reports,
            evidence: restored.evidence,
            origins: restored.origins,
            all_origins: restored.all_origins,
        };
        for report in &state.reports {
            if let Some(error) = &report.error
                && error.cause.starts_with("correlation_")
            {
                state.correlation.invalidate(&crate::correlation::Failure {
                    cause: crate::correlation::CONFLICT,
                    detail: error.detail.clone(),
                });
            }
        }
        Ok(state)
    }
}

impl RunState<'_> {
    /// Walks the steps in file order, stopping at the first blocked one.
    async fn execute(&mut self) -> Result<(), CapabilityFailure> {
        let total = self.flow.steps.len();
        if self
            .reports
            .iter()
            .any(|report| matches!(report.status, StepStatus::Blocked | StepStatus::Cancelled))
        {
            return Ok(());
        }
        for (index, step) in self.flow.steps.iter().enumerate().skip(self.reports.len()) {
            self.watch_due(step)?;
            self.landing_due(step).await?;
            // A state-changing step is journaled as not started while its
            // scope check and approval are outstanding: nothing has run, so a
            // cancel, an expired lease or a restart during that wait is not an
            // uncertain effect. `run_step` arms the effect once the gate has
            // passed. A landing intent left by an earlier attempt is the one
            // exception: the effect may already exist, so it stays effectful.
            let prepare = if !self.should_run(step) {
                Prepare::Skip
            } else if step.effect == pam_flow::Effect::Stateful
                && !self.landing_intent_outstanding(step).await?
            {
                Prepare::Gate
            } else {
                Prepare::Run
            };
            self.recovery
                .prepare(
                    &self.service.store,
                    &self.ctx.request_id,
                    &EffectIntent::attempt(step, prepare),
                )
                .await?;
            if prepare == Prepare::Skip {
                self.reports
                    .push(StepReport::new(&step.id, step.kind(), StepStatus::Skipped));
                self.checkpoint(index + 1 == total).await?;
                self.publish_settled(index, total, &step.id, StepStatus::Skipped)
                    .await;
                continue;
            }
            if self.recovery.watch.is_none() && !matches!(step.action, Action::Landing { .. }) {
                self.publish_progress(index, total, &step.id).await;
            }
            let mut report = self.run_step(step).await?;
            if step.watch.is_some()
                && let Some(watch) = &self.recovery.watch
            {
                if !report.evidence.contains(&watch.last_evidence) {
                    report.evidence.push(watch.last_evidence.clone());
                }
                if !self.evidence.contains(&watch.last_evidence) {
                    self.evidence.push(watch.last_evidence.clone());
                }
                if !self.all_origins.contains(&watch.origin) {
                    self.all_origins.push(watch.origin.clone());
                }
            }
            if step.effect == pam_flow::Effect::Stateful
                && (!report.evidence_unavailable.is_empty()
                    || report
                        .error
                        .as_ref()
                        .is_some_and(|error| error.cause.starts_with("request_budget_")))
            {
                // No trustworthy completion receipt: retain prepared intent so the
                // terminal choke point records uncertainty instead of completion.
                return Err(crate::flow_recovery::failure());
            }
            let blocked = report.status == StepStatus::Blocked;
            let status = report.status;
            self.reports.push(report);
            self.checkpoint(blocked || index + 1 == total).await?;
            self.publish_settled(index, total, &step.id, status).await;
            if blocked {
                break;
            }
        }
        Ok(())
    }

    async fn checkpoint(&mut self, completed: bool) -> Result<(), CapabilityFailure> {
        let reports = self
            .reports
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(failed)?;
        let snapshot = crate::flow_recovery::Snapshot {
            fingerprint: self.recovery.fingerprint.clone(),
            vars: self.vars.clone(),
            observed: self.observed.clone(),
            reports,
            evidence: self.evidence.clone(),
            origins: self.origins.clone(),
            all_origins: self.all_origins.clone(),
        };
        self.recovery
            .settle(
                &self.service.store,
                &self.ctx.request_id,
                &snapshot,
                completed,
            )
            .await
    }

    /// Whether this step's `when` condition holds, given what ran before
    /// ([`Step::should_run`] is the definition).
    fn should_run(&self, step: &Step) -> bool {
        let earlier: Vec<(&str, Prior)> = self
            .reports
            .iter()
            .map(|report| {
                let prior = match report.status {
                    StepStatus::Succeeded => Prior::Succeeded,
                    StepStatus::Failed => Prior::Failed,
                    StepStatus::Skipped | StepStatus::Blocked | StepStatus::Cancelled => {
                        Prior::Other
                    }
                };
                (report.id.as_str(), prior)
            })
            .collect();
        step.should_run(&earlier)
    }

    /// Tells subscribers which step is starting.
    async fn publish_progress(&self, index: usize, total: usize, step: &str) {
        let note = format!("{step}: running ({}/{total})", index + 1);
        self.publish_note(index, total, note).await;
    }

    /// Tells subscribers how a step ended, so a canvas can paint its rim
    /// before the verdict lands.
    async fn publish_settled(&self, index: usize, total: usize, step: &str, status: StepStatus) {
        let note = format!("{step}: {}", status.as_str());
        self.publish_note(index + 1, total, note).await;
    }

    /// One progress event: `done` of `total` steps as a percentage, plus
    /// the note.
    async fn publish_note(&self, done: usize, total: usize, note: String) {
        let done = u64::try_from(done).unwrap_or(0);
        let total_u64 = u64::try_from(total).unwrap_or(1).max(1);
        let pct = u8::try_from(done * 100 / total_u64).unwrap_or(u8::MAX);
        let _ = self
            .ctx
            .events
            .publish(
                &self.ctx.request_id,
                pam_proto::Event::Progress {
                    pct: Some(pct),
                    note,
                },
            )
            .await;
    }

    /// Gates one step, then runs it.
    async fn run_step(&mut self, step: &Step) -> Result<StepReport, CapabilityFailure> {
        let mut report = StepReport::new(&step.id, step.kind(), StepStatus::Failed);
        if matches!(step.action, Action::Command { .. })
            && self.correlation.refuse_unbound_verification(step)
        {
            report.fail(
                StepStatus::Blocked,
                crate::correlation::MISSING,
                "local command verification has no authenticated revision binding".to_owned(),
                crate::correlation::RECOVERY.to_owned(),
            );
            return Ok(report);
        }
        // Do not request or remember a grant for an out-of-scope target.
        if let Err(refusal) = self.check_step_scope(step).await {
            report.fail(
                StepStatus::Blocked,
                refusal.cause,
                refusal.detail,
                refusal.recovery,
            );
            return Ok(report);
        }
        if step.watch.is_some() || matches!(step.action, Action::Landing { .. }) {
            self.watch_grant_stamp = Some(self.watch_stamp().await?);
        }
        if step.gated()
            && let Some(blocked) = self.gate_step(step, &mut report).await?
        {
            return Ok(blocked);
        }
        if step.watch.is_some()
            && let Some(blocked) = self.advance_watch(step).await?
        {
            return Ok(blocked);
        }
        // The gate has passed: from here on the step may change something.
        self.recovery
            .arm_effect(
                &self.service.store,
                &self.ctx.request_id,
                &EffectIntent::armed(step),
            )
            .await?;
        let started = Instant::now();
        step_kind(step).execute(self, step, &mut report).await?;
        report.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }

    async fn check_step_scope(&self, step: &Step) -> Result<(), FlowRefusal> {
        self.service.approved_repo(&self.repo).await?;
        step_kind(step).check_scope(self, step).await
    }

    /// What a gated step will run, as this run resolved it: the hand-off to
    /// [`crate::approval`] for the approval card. A command step shows the
    /// program as found on this machine, its substituted arguments, the
    /// directory and the names of the environment it sets; a connector
    /// step shows its call and substituted arguments; a landing step its
    /// fixed operation. A value that cannot be substituted is shown as
    /// written — the step fails after approval and the card must still say
    /// what was asked. The digest binds all of it to the flow's own digest.
    fn approval_snapshot(&self, step: &Step, capability: &str) -> StepSnapshot {
        let flow_digest = digest(self.flow);
        let cwd = Some(self.repo.display().to_string());
        step_kind(step).approval_snapshot(self, step, capability, &flow_digest, cwd)
    }

    /// The step gate (see the module docs). `Some(report)` means the step
    /// is blocked and the run stops.
    async fn gate_step(
        &mut self,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<Option<StepReport>, CapabilityFailure> {
        let name = step_capability(&self.flow.id, &step.id);
        let class = step_class(step);
        // What this step's grant must cover: the step as defined now, in
        // this run's canonical repository.
        let binding = step_binding(
            self.flow,
            step,
            Some(self.repo.to_string_lossy().into_owned()),
        );
        // One gate for every step: the daemon's live profile (see
        // `crate::policy`), which is also what the watch stamp hashes.
        let (decision, changed) = self
            .service
            .gate
            .evaluate_step(&self.ctx.request_id, &name, class, &binding)
            .await
            .map_err(failed)?;
        match decision {
            GateDecision::Allow { .. } => Ok(None),
            GateDecision::Refuse {
                cause,
                detail,
                recovery,
            } => {
                report.fail(StepStatus::Blocked, &cause, detail, recovery);
                Ok(Some(report.clone()))
            }
            GateDecision::RequireApproval { reason } => {
                if self.watch_approval_valid(step).await?
                    || self.landing_approval_valid(step).await?
                {
                    return Ok(None);
                }
                // What this run will execute, captured now for the human's
                // card: an answer is pinned to this snapshot's digest.
                let snapshot = self.approval_snapshot(step, &name);
                let outcome = self
                    .service
                    .approvals
                    .request_step_approval(
                        &self.ctx.request_id,
                        &name,
                        snapshot,
                        RememberScope { binding, changed },
                        &mut self.cancel,
                    )
                    .await
                    .map_err(failed)?;
                match outcome {
                    ApprovalOutcome::Approved { .. } => {
                        // The approval service parked the request in
                        // `waiting_approval`; the caller of a wait owns
                        // the transition out of it, and here that caller
                        // is this run.
                        self.service
                            .store
                            .update_request_state(&self.ctx.request_id, resume_state(), None)
                            .await
                            .map_err(failed)?;
                        Ok(None)
                    }
                    ApprovalOutcome::Denied => {
                        report.fail(
                            StepStatus::Blocked,
                            CAUSE_APPROVAL_DENIED,
                            format!("a human denied step {:?} ({reason})", step.id),
                            RECOVERY_APPROVALS.to_owned(),
                        );
                        Ok(Some(report.clone()))
                    }
                    ApprovalOutcome::TimedOut => {
                        report.fail(
                            StepStatus::Blocked,
                            CAUSE_APPROVAL_TIMEOUT,
                            format!(
                                "nobody answered the approval for step {:?} in time ({reason})",
                                step.id
                            ),
                            RECOVERY_APPROVALS.to_owned(),
                        );
                        Ok(Some(report.clone()))
                    }
                    ApprovalOutcome::Cancelled => Err(CapabilityFailure::Cancelled),
                }
            }
        }
    }
}

impl RunState<'_> {}

impl RunState<'_> {}

fn budget_refusal(error: crate::request_budget::BudgetError) -> FlowRefusal {
    FlowRefusal::new(
        error.cause,
        error.to_string(),
        crate::request_budget::RECOVERY_BUDGET,
    )
}

fn contract_refusal(error: crate::flow_contract::ContractError) -> FlowRefusal {
    FlowRefusal::new(
        "flow_contract_invalid",
        error.to_string(),
        RECOVERY_FLOW_LIST,
    )
}

/// Refuses a run pinned to a digest the flow no longer has. The flow a run
/// executes is the one in memory from here on; a pin makes it the one the
/// caller inspected, or nothing runs.
fn refuse_changed_flow(flow: &Flow, args: &RunArgs) -> Result<(), CapabilityFailure> {
    let Some(expected) = &args.expected_digest else {
        return Ok(());
    };
    let current = digest(flow);
    if *expected == current {
        return Ok(());
    }
    Err(FlowRefusal::new(
        CAUSE_FLOW_CHANGED,
        format!(
            "flow {:?} now has digest {current}, not the pinned {expected}: it was edited after \
             it was inspected",
            args.id
        ),
        RECOVERY_FLOW_CHANGED,
    )
    .into())
}

/// Refuses supplied input names the flow does not declare — the run-side
/// twin of the `input_unknown` blockers `flow.inspect` reports — so a typo
/// cannot start a run against the declared defaults.
fn refuse_undeclared_inputs(flow: &Flow, args: &RunArgs) -> Result<(), CapabilityFailure> {
    let undeclared: Vec<&str> = args
        .inputs
        .keys()
        .filter(|name| !flow.inputs.contains_key(*name))
        .map(String::as_str)
        .collect();
    if undeclared.is_empty() {
        return Ok(());
    }
    Err(FlowRefusal::new(
        CAUSE_INPUT_UNKNOWN,
        format!(
            "flow {:?} does not declare the supplied input(s) {}",
            args.id,
            undeclared.join(", ")
        ),
        "drop the input or declare it under the flow's `inputs:`",
    )
    .into())
}

/// Validate the inspection request without reading configuration or evaluating gates.
fn inspect_args(args: &Value) -> Result<RunArgs, FlowRefusal> {
    if !args.is_object()
        || args.get("inputs").is_some_and(|value| {
            !value.is_object()
                || value
                    .as_object()
                    .is_some_and(|map| map.values().any(|value| scalar_text(value).is_none()))
        })
    {
        return Err(contract_refusal(crate::flow_contract::ContractError(
            "inspection inputs must be an object of scalar values",
        )));
    }
    RunArgs::from_value(args)
}

/// Adapter-originated product status remains distinct from step retrieval success.
fn product_observations(
    flow: &Flow,
    vars: &Vars,
) -> BTreeMap<String, crate::flow_contract::ProductObservation> {
    flow.steps
        .iter()
        .filter_map(|step| {
            let Action::Connector {
                connector, call, ..
            } = &step.action
            else {
                return None;
            };
            let statuses: &[&str] = match (connector, call.as_str()) {
                (ConnectorId::Jenkins, "investigate" | "node_evidence") => &[
                    "SUCCESS",
                    "FAILURE",
                    "UNSTABLE",
                    "ABORTED",
                    "NOT_BUILT",
                    "RUNNING",
                    "UNKNOWN",
                ],
                (ConnectorId::Sonarqube, "analysis") => &[
                    "OK",
                    "ERROR",
                    "WARN",
                    "NONE",
                    "PENDING",
                    "IN_PROGRESS",
                    "FAILED",
                    "CANCELED",
                ],
                _ => return None,
            };
            let status = vars.resolve(&format!("steps.{}.result.status", step.id))?;
            statuses.contains(&status.as_str()).then(|| {
                (
                    step.id.clone(),
                    crate::flow_contract::ProductObservation {
                        connector: connector.as_str().to_owned(),
                        status,
                    },
                )
            })
        })
        .collect()
}

/// Read grants come from daemon-owned tool locations, never broad HOME access.
/// Only a [`pam_flow::Effect::Stateful`] command may write to the repository.
fn command_boundary(
    protected_base: &Path,
    repo: &Path,
    program: &Path,
    effect: pam_flow::Effect,
) -> crate::command_containment::CommandContainment {
    let daemon_exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    crate::command_containment::CommandContainment {
        protected_base: protected_base.to_path_buf(),
        repository: repo.to_path_buf(),
        read_only_roots: boundary_read_roots(
            protected_base,
            repo,
            program,
            daemon_exe.as_deref(),
            home.as_deref(),
        ),
        allow_repository_writes: effect == pam_flow::Effect::Stateful,
        artifact_roots: Vec::new(),
    }
}

/// The read roots for a command boundary: the immutable system trees, the
/// program's own directory, the daemon's own directory and the rustup
/// toolchain. The last three are conveniences, so one that falls inside the
/// protected base or the repository is dropped rather than declared: the
/// repository is readable already, and the private base is never granted.
/// Declaring it would make the whole boundary invalid (issue #26: a daemon
/// binary living under its own base refused every build flow).
pub(crate) fn boundary_read_roots(
    protected_base: &Path,
    repo: &Path,
    program: &Path,
    daemon_exe: Option<&Path>,
    home: Option<&Path>,
) -> Vec<PathBuf> {
    let protected = protected_base
        .canonicalize()
        .unwrap_or_else(|_| protected_base.to_path_buf());
    let repo = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let separate = |root: &Path| {
        !root.starts_with(&protected)
            && !protected.starts_with(root)
            && !root.starts_with(&repo)
            && !repo.starts_with(root)
    };
    let mut roots: Vec<PathBuf> = ["/System", "/usr", "/bin", "/sbin", "/Library/Developer"]
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .collect();
    if let Ok(executable) = program.canonicalize()
        && let Some(parent) = executable.parent()
        && separate(parent)
    {
        roots.push(parent.to_path_buf());
    }
    if let Some(executable) = daemon_exe
        && let Ok(executable) = executable.canonicalize()
        && let Some(parent) = executable.parent()
        && separate(parent)
    {
        roots.push(parent.to_path_buf());
    }
    if let Some(home) = home {
        let toolchain = home.join(".rustup");
        if toolchain.is_dir() && separate(&toolchain) {
            roots.push(toolchain);
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// The admission inspection reports for `capability`: the run's own gate
/// decision ([`crate::policy::decide`]) for a grant that is present or
/// missing, as a label ([`admission_label`]). A managed never-grant rule
/// refuses first, on every profile and whether or not a grant exists
/// (`policy_denied`, with no rule text); otherwise the profile and grant
/// decide.
pub(crate) fn inspect_admission(
    view: &PolicyView,
    profile: crate::policy::Profile,
    capability: &str,
    granted: bool,
    class: CapabilityClass,
) -> &'static str {
    let grant = if granted {
        GrantStanding::Granted
    } else {
        GrantStanding::Missing
    };
    admission_label(
        &crate::policy::decide(view, profile, capability, class, &grant).decision(capability),
    )
}

/// The gate decision for the gated `step` of `flow` in `repository` (the
/// canonical one the run binds grants to, when the scope admits it), from
/// `grants` — the step capability's active grants as they are now — under
/// the policy `view` and the effective `profile`. It is the run's own
/// decision ([`crate::policy::decide`], whose two halves
/// [`PolicyGate::evaluate_step`] calls around its grant read) with none of
/// its side effects: no `policy.denied` audit row, no legacy binding. The
/// flow settings play no part in it (the program allowlist is a separate
/// blocker). Also returns how the grants stand against the step as it is
/// now, which inspection reports beside the decision.
pub(crate) fn inspect_gate(
    flow: &Flow,
    step: &Step,
    repository: Option<&Path>,
    view: &PolicyView,
    profile: crate::policy::Profile,
    grants: &[pam_store::GrantRow],
) -> (GateDecision, StepGrant) {
    let capability = step_capability(&flow.id, &step.id);
    // Inspection binds nothing: a legacy grant reads as present (the run
    // binds it), a bound one that no longer covers the step as it is now —
    // or this repository — reads as changed.
    let binding = step_binding(
        flow,
        step,
        repository.map(|path| path.to_string_lossy().into_owned()),
    );
    let grant = crate::policy::match_step_grant(grants, &binding);
    let verdict = crate::policy::decide(
        view,
        profile,
        &capability,
        step_class(step),
        &GrantStanding::from(&grant),
    );
    (verdict.decision(&capability), grant)
}

/// The admission label `flow.inspect` reports for a gate decision: an
/// allow that would grant on execution is `auto_grant_on_execution`.
pub(crate) fn admission_label(decision: &GateDecision) -> &'static str {
    match decision {
        GateDecision::Allow {
            auto_granted: false,
        } => "allowed",
        GateDecision::Allow { auto_granted: true } => "auto_grant_on_execution",
        GateDecision::RequireApproval { .. } => "approval_required",
        GateDecision::Refuse { cause, .. } if cause == CAUSE_POLICY_DENIED => CAUSE_POLICY_DENIED,
        GateDecision::Refuse { .. } => crate::policy::CAUSE_NOT_GRANTED,
    }
}
