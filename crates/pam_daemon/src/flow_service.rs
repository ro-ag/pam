//! The flow engine: the library a human edits, the settings that bound
//! what a step may run, and one run of a flow end to end.
//!
//! # What a run is
//!
//! A flow is a recipe, not a privilege. `flow.run` itself classifies
//! [`NonDestructive`](crate::policy::CapabilityClass::NonDestructive) —
//! running a recipe changes nothing — and every step that *could* change
//! something goes through the policy gate on its own, under the capability
//! name [`step_capability`] spells (`flow.step:<flow>/<step>`). That name
//! is what a human sees in the approvals view and what the remember
//! checkbox remembers, which is exactly the granularity a person wants:
//! "yes, this step of this flow may run", not "yes, flows may run".
//!
//! # The three gated shapes
//!
//! A step reaches the gate when it is stateful, when it asks for approval
//! outright, or when it calls a connector (it leaves the machine) — that
//! is [`pam_flow::Step::gated`]. Stateful and approval-required steps
//! evaluate as
//! [`Destructive`](crate::policy::CapabilityClass::Destructive), connector
//! steps as [`External`](crate::policy::CapabilityClass::External). A
//! read-only local command with no approval flag never touches the gate:
//! `git status` in the caller's own repo is not an act pam asks permission
//! for.
//!
//! # Blocked is an answer, not a refusal
//!
//! A denied approval, an expired approval, a gate refusal, a disabled
//! connector, a program that is not on the allowlist — these end the run
//! with outcome `blocked` and a step report saying which step and why.
//! They are *results*: the request finishes `done`, the verdict is filed
//! as evidence, and the caller reads the recovery line off the step. Only
//! the four things that stop a run before it can start —
//! [`CAUSE_FLOW_NOT_FOUND`], [`CAUSE_FLOW_INVALID`],
//! [`CAUSE_INPUT_MISSING`], [`CAUSE_REPO_MISSING`] — are refusals, carried
//! out of the executor as [`CapabilityFailure::Refused`].
//!
//! # Output
//!
//! Every step's output goes through
//! [`LogService::compress`](crate::log_service::LogService::compress),
//! which is where the token odometer's numbers come from. `compact` (the
//! default) files the source and the reduction; `summarize` additionally
//! asks the heavy model for a paragraph and puts it on the step report;
//! `discard` keeps nothing. Empty output is not compressed — an evidence
//! row holding zero bytes tells nobody anything.
//!
//! # The verdict is evidence
//!
//! The body a run answers with is written verbatim as one
//! [`EVIDENCE_KIND_FLOW_RESULT`] row, so the GUI's run history renders a
//! finished run without re-running it and `pam flow run --no-wait`
//! callers can fetch the verdict off the ticket later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_connectors::{CallResult, ConnectorId};
use pam_flow::{
    Action, ArgValue, Entry, Flow, Library, OutputPolicy, Retry, Role, Step, Vars, When, digest,
    is_shell, references, substitute, to_normalized_yaml,
};
use pam_proto::Outcome;
use pam_store::{RequestState, Store, StoreError};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::approval::{ApprovalOutcome, ApprovalService};
use crate::connector_service::{ConnectorService, InvokeError};
use crate::daemon::{CAUSE_APPROVAL_DENIED, CAUSE_APPROVAL_TIMEOUT};
use crate::executor::{CapabilityFailure, CapabilityOutput, ExecContext, outcome_str};
use crate::flow_exec::{
    CommandOutcome, CommandSpec, RunReport, StepReport, StepStatus, cancelled, outcome_for,
    resolve_program, run_command, scrub_env, sleep_or_cancel, summary_for,
};
use crate::log_service::{CompressInput, LogService, new_evidence_id};
use crate::policy::{CapabilityClass, GateDecision, PolicyGate};

/// `setting` key holding the programs a command step may run.
pub const SETTING_ALLOWED_PROGRAMS: &str = "flows.allowed_programs";

/// `setting` key holding the directories prepended to a step's `PATH`.
pub const SETTING_EXTRA_PATH: &str = "flows.extra_path";

/// Capability name: run a flow.
pub const CAP_FLOW_RUN: &str = "flow.run";

/// Capability name: list the flow library.
pub const CAP_FLOW_LIST: &str = "flow.list";

/// Capability name: read one flow.
pub const CAP_FLOW_SHOW: &str = "flow.show";

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

/// Refusal cause: the caller's repo is not a directory on this machine.
pub const CAUSE_REPO_MISSING: &str = "repo_missing";

/// Refusal cause: the flow library directory could not be read.
pub const CAUSE_LIBRARY_UNREADABLE: &str = "library_unreadable";

/// Step cause: the program is not in `flows.allowed_programs`.
pub const CAUSE_PROGRAM_NOT_ALLOWED: &str = "program_not_allowed";

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

/// Step cause: daemon-side bookkeeping failed mid-step.
pub const CAUSE_INTERNAL: &str = "internal_error";

/// Recovery line for a flow id nothing answers to.
pub const RECOVERY_FLOW_LIST: &str = "run `pam flow list` to see the flows this machine has";

/// Recovery line for a flow file that does not validate.
pub const RECOVERY_FLOW_EDIT: &str =
    "open Pam → Flows → the flow → YAML and fix the line the message names";

/// Recovery line for a program the allowlist does not carry.
pub const RECOVERY_ALLOWED_PROGRAMS: &str = "open Pam → Settings → Flows → allowed programs";

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

/// What a command step may run, and where its programs are found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSettings {
    /// Bare program names a command step's `run[0]` may name.
    pub allowed_programs: Vec<String>,
    /// Directories prepended to the inherited `PATH`. Stored as the human
    /// typed them, `~` and `%USERPROFILE%` included.
    pub extra_path: Vec<String>,
}

impl FlowSettings {
    /// What a fresh install starts with.
    ///
    /// The extra `PATH` differs per platform because a launchd or systemd
    /// daemon inherits a minimal one: without these, `cargo` simply does
    /// not exist as far as a flow step is concerned.
    #[must_use]
    pub fn platform_default() -> Self {
        let extra_path = if cfg!(target_os = "macos") {
            vec!["~/.cargo/bin", "/opt/homebrew/bin", "/usr/local/bin"]
        } else if cfg!(target_os = "windows") {
            vec![r"%USERPROFILE%\.cargo\bin"]
        } else {
            vec!["~/.cargo/bin", "~/.local/bin", "/usr/local/bin"]
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
        }
    }

    /// The environment-name pattern a step's inherited environment is
    /// scrubbed against, as the spec writes it.
    #[must_use]
    pub fn secret_env_pattern() -> &'static str {
        "(?i)token|secret|password|passwd|credential|api_key|apikey|private_key"
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
}

/// What one `flow.run` was asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// The flow id.
    pub id: String,
    /// Values for the flow's declared inputs.
    pub inputs: BTreeMap<String, String>,
}

impl RunArgs {
    /// Reads the arguments off a `flow.run` envelope.
    ///
    /// # Errors
    ///
    /// [`CAUSE_FLOW_NOT_FOUND`] when no id was named — there is nothing to
    /// look up, and the recovery is the same list command.
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
        let inputs = args
            .get("inputs")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(name, value)| scalar_text(value).map(|text| (name.clone(), text)))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            id: id.to_owned(),
            inputs,
        })
    }
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
    library: Library,
    store: Arc<Store>,
    approvals: Arc<ApprovalService>,
    connectors: Arc<ConnectorService>,
    logs: Arc<LogService>,
    gate: Arc<PolicyGate>,
}

impl FlowService {
    /// Builds the engine over the library at `<base_dir>/flows`.
    #[must_use]
    pub fn new(
        base_dir: &Path,
        store: Arc<Store>,
        approvals: Arc<ApprovalService>,
        connectors: Arc<ConnectorService>,
        logs: Arc<LogService>,
        gate: Arc<PolicyGate>,
    ) -> Self {
        Self {
            library: Library::new(base_dir.join("flows")),
            store,
            approvals,
            connectors,
            logs,
            gate,
        }
    }

    /// The flow library this engine reads and writes.
    #[must_use]
    pub fn library(&self) -> &Library {
        &self.library
    }

    /// The flow settings, persisting the platform default the first time
    /// they are read so the GUI always has something concrete to edit.
    pub async fn settings(&self) -> Result<FlowSettings, StoreError> {
        let defaults = FlowSettings::platform_default();
        Ok(FlowSettings {
            allowed_programs: self
                .setting_list(SETTING_ALLOWED_PROGRAMS, &defaults.allowed_programs)
                .await?,
            extra_path: self
                .setting_list(SETTING_EXTRA_PATH, &defaults.extra_path)
                .await?,
        })
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

    /// Replaces the named settings.
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
        for (key, list) in [
            (SETTING_ALLOWED_PROGRAMS, allowed.as_ref()),
            (
                SETTING_EXTRA_PATH,
                patch.extra_path.as_deref().map(clean_list).as_ref(),
            ),
        ] {
            let Some(list) = list else { continue };
            let raw = serde_json::to_string(list).expect("a string list always serializes");
            self.store
                .set_setting(key, &raw)
                .await
                .map_err(|error| store_note(&error))?;
        }
        self.settings().await.map_err(|error| store_note(&error))
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

    /// `flow.list`: every flow with enough of its shape to choose one.
    pub fn list(&self) -> Result<CapabilityOutput, FlowRefusal> {
        let flows: Vec<Value> = self
            .entries()?
            .iter()
            .map(|entry| list_entry_json(entry, false))
            .collect();
        Ok(CapabilityOutput {
            outcome: Outcome::Verified,
            body: json!({ "flows": flows }),
            evidence: Vec::new(),
        })
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
    /// [`CapabilityFailure::Refused`] for the four things that stop a run
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
        let flow = match &entry.parsed {
            Ok(flow) => flow.clone(),
            Err(error) => {
                return Err(FlowRefusal::new(
                    CAUSE_FLOW_INVALID,
                    format!("flow {:?} does not validate: {error}", args.id),
                    RECOVERY_FLOW_EDIT,
                )
                .into());
            }
        };

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

        let mut cancel = ctx.cancel.clone();
        let (vars, inputs) = self
            .resolve_vars(&flow, &args.inputs, &repo, &settings, &mut cancel)
            .await?;

        let mut state = RunState {
            service: self,
            ctx,
            flow: &flow,
            settings: &settings,
            repo,
            vars,
            cancel,
            reports: Vec::with_capacity(flow.steps.len()),
            evidence: Vec::new(),
        };
        state.execute().await?;

        let report = RunReport {
            outcome: outcome_for(&state.reports, &flow),
            summary: summary_for(&state.reports),
            steps: state.reports,
        };
        let body = json!({
            "flow": {
                "id": flow.id,
                "name": flow.name,
                "source": entry.source.as_str(),
                "digest": digest(&flow),
            },
            "repo": ctx.caller.repo,
            "inputs": inputs,
            "outcome": outcome_str(report.outcome),
            "summary": report.summary,
            "steps": report.steps,
        });

        let failed = report
            .steps
            .iter()
            .filter(|step| step.status == StepStatus::Failed)
            .count();
        let verdict_id = new_evidence_id();
        let meta = json!({
            "flow": flow.id,
            "outcome": outcome_str(report.outcome),
            "steps": report.steps.len(),
            "failed": failed,
        });
        self.store
            .insert_evidence(
                &verdict_id,
                &ctx.request_id,
                EVIDENCE_KIND_FLOW_RESULT,
                &serde_json::to_vec(&body).map_err(|error| CapabilityFailure::Failed {
                    detail: format!("the flow verdict did not serialize: {error}"),
                })?,
                Some(&meta.to_string()),
            )
            .await
            .map_err(failed_store)?;

        let mut evidence = state.evidence;
        evidence.push(verdict_id);
        Ok(CapabilityOutput {
            outcome: report.outcome,
            body,
            evidence,
        })
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
    ) -> Result<(Vars, BTreeMap<String, String>), FlowRefusal> {
        let mut vars = Vars::new();
        vars.set("repo.path", repo.display().to_string());
        if let Some(name) = repo.file_name().and_then(|name| name.to_str()) {
            vars.set("repo.name", name);
        }
        // `git remote get-url origin` costs a child process, so it runs
        // only when the flow actually mentions the variable.
        if flow_references(flow).iter().any(|key| key == "repo.origin")
            && let Some(origin) = repo_origin(repo, settings, cancel).await
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
            vars.set(&format!("inputs.{name}"), value.clone());
            inputs.insert(name.clone(), value);
        }
        Ok((vars, inputs))
    }
}

/// Refuses an allowlist entry that is not a bare, non-shell program name.
fn check_allowed_program(program: &str) -> Result<(), FlowRefusal> {
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
    let mut found = Vec::new();
    for input in flow.inputs.values() {
        if let Some(default) = &input.default {
            found.extend(references(default));
        }
    }
    for step in &flow.steps {
        match &step.action {
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
    settings: &FlowSettings,
    cancel: &mut watch::Receiver<bool>,
) -> Option<String> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let program = resolve_program("git", &settings.extra_path_dirs(), &path)?;
    let outcome = run_command(
        CommandSpec {
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
    )
    .await;
    let CommandOutcome::Exited { status: 0, output } = outcome else {
        return None;
    };
    github_owner_name(&String::from_utf8_lossy(&output))
}

/// `owner/name` out of a GitHub remote URL, in any of the shapes git
/// stores one (`https://`, `ssh://`, `git@host:owner/name`).
fn github_owner_name(url: &str) -> Option<String> {
    let url = url.trim();
    let url = url.strip_suffix(".git").unwrap_or(url);
    let (_, tail) = url.split_once("github.com")?;
    let mut segments = tail.trim_start_matches([':', '/']).split('/');
    let owner = segments.next().filter(|part| !part.is_empty())?;
    let name = segments.next().filter(|part| !part.is_empty())?;
    segments.next().is_none().then(|| format!("{owner}/{name}"))
}

/// The environment every command step starts from: the daemon's own,
/// scrubbed, with `PATH` rebuilt as `extra_path ++ inherited PATH` and
/// git's interactive prompts wired shut.
fn base_env(settings: &FlowSettings) -> Vec<(String, String)> {
    let mut env = scrub_env(std::env::vars_os());
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
            "inputs": flow.inputs.iter().map(|(name, input)| json!({
                "name": name,
                "description": input.description,
                "default": input.default,
            })).collect::<Vec<Value>>(),
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
    cancel: watch::Receiver<bool>,
    reports: Vec<StepReport>,
    evidence: Vec<String>,
}

impl RunState<'_> {
    /// Walks the steps in file order, stopping at the first blocked one.
    async fn execute(&mut self) -> Result<(), CapabilityFailure> {
        let total = self.flow.steps.len();
        for (index, step) in self.flow.steps.iter().enumerate() {
            if !self.should_run(step) {
                self.reports
                    .push(StepReport::new(&step.id, step.kind(), StepStatus::Skipped));
                self.publish_settled(index, total, &step.id, StepStatus::Skipped)
                    .await;
                continue;
            }
            self.publish_progress(index, total, &step.id).await;
            let report = self.run_step(step).await?;
            let blocked = report.status == StepStatus::Blocked;
            self.publish_settled(index, total, &step.id, report.status)
                .await;
            self.reports.push(report);
            if blocked {
                break;
            }
        }
        Ok(())
    }

    /// Whether this step's `when` condition holds, given what ran before.
    fn should_run(&self, step: &Step) -> bool {
        let is = |id: &str, status: StepStatus| {
            self.reports
                .iter()
                .any(|report| report.id == id && report.status == status)
        };
        match &step.when {
            When::Always => true,
            When::NeedsSucceeded => step.needs.iter().all(|id| is(id, StepStatus::Succeeded)),
            When::Succeeded(id) => is(id, StepStatus::Succeeded),
            When::Failed(id) => is(id, StepStatus::Failed),
        }
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
        if step.gated()
            && let Some(blocked) = self.gate_step(step, &mut report).await?
        {
            return Ok(blocked);
        }
        let started = Instant::now();
        match &step.action {
            Action::Command { argv } => self.run_command_step(step, argv, &mut report).await?,
            Action::Connector {
                connector,
                call,
                with,
            } => {
                self.run_connector_step(step, *connector, call, with, &mut report)
                    .await?;
            }
        }
        report.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(report)
    }

    /// The step gate (see the module docs). `Some(report)` means the step
    /// is blocked and the run stops.
    async fn gate_step(
        &mut self,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<Option<StepReport>, CapabilityFailure> {
        let name = step_capability(&self.flow.id, &step.id);
        let class = if matches!(step.action, Action::Connector { .. }) {
            CapabilityClass::External
        } else {
            CapabilityClass::Destructive
        };
        let decision = self
            .service
            .gate
            .evaluate_classified(&self.ctx.request_id, &name, class)
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
                let outcome = self
                    .service
                    .approvals
                    .request_approval(&self.ctx.request_id, &name, &mut self.cancel)
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
                            .update_request_state(&self.ctx.request_id, RequestState::Running, None)
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
                                "nobody answered the approval for step {:?} in time",
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

/// Retrieval and verification are distinct: preserve the successful response as
/// evidence even when its status fails the flow's explicit assertion.
pub(crate) fn apply_connector_assertion(
    step: &Step,
    result: Option<&Value>,
    report: &mut StepReport,
) {
    if report.status != StepStatus::Succeeded || !matches!(step.action, Action::Connector { .. }) {
        return;
    }
    let Some(expected) = &step.expect_status else {
        if step.role == Role::Verify {
            report.fail(StepStatus::Failed, CAUSE_STATUS_ASSERTION_REQUIRED,
                format!("connector verification step {:?} has no passing-status assertion", step.id),
                "edit the flow to declare `expect_status` for verification, or use `role: observe` for retrieval".to_owned());
        }
        return;
    };
    let actual = result
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    if actual != Some(expected.as_str()) {
        report.fail(StepStatus::Failed, CAUSE_STATUS_ASSERTION,
            format!("step {:?} expected status {expected:?}; inspect its retained connector evidence", step.id),
            "resolve the reported gate conditions and re-run the flow; missing or unknown status never establishes a pass".to_owned());
    }
}

fn assert_connector_attempt(step: &Step, attempt: Attempt) -> Attempt {
    let Attempt::Succeeded {
        exit_status,
        output,
        result,
    } = attempt
    else {
        return attempt;
    };
    let mut report = StepReport::new(&step.id, "connector", StepStatus::Succeeded);
    apply_connector_assertion(step, result.as_ref(), &mut report);
    if let Some(error) = report.error {
        Attempt::Failed {
            exit_status,
            output,
            result,
            status: StepStatus::Failed,
            cause: if step.expect_status.is_some() {
                CAUSE_STATUS_ASSERTION
            } else {
                CAUSE_STATUS_ASSERTION_REQUIRED
            },
            detail: error.detail,
            recovery: error.recovery,
            retry_after: None,
        }
    } else {
        Attempt::Succeeded {
            exit_status,
            output,
            result,
        }
    }
}

/// What one attempt of a step produced.
enum Attempt {
    /// It ran and reported success.
    Succeeded {
        /// The process (or job) status, when there was one.
        exit_status: Option<i32>,
        /// Bytes to file as evidence, when the step produced any.
        output: Vec<u8>,
        /// A connector's JSON answer, when the step was a connector call.
        result: Option<Value>,
    },
    /// It ran and reported failure; another attempt may still follow.
    Failed {
        /// The process (or job) status, when there was one.
        exit_status: Option<i32>,
        /// Whatever it wrote before failing.
        output: Vec<u8>,
        /// Retrieved JSON retained even when its status assertion failed.
        result: Option<Value>,
        /// `Failed`, or `Blocked` when only a human can clear it.
        status: StepStatus,
        /// Machine-readable cause.
        cause: &'static str,
        /// What happened.
        detail: String,
        /// The concrete fix.
        recovery: String,
        /// Honour this wait before retrying instead of the backoff (a
        /// service that named a `Retry-After` knows better than pam).
        retry_after: Option<Duration>,
    },
}

impl RunState<'_> {
    /// Runs one command step, retries included.
    async fn run_command_step(
        &mut self,
        step: &Step,
        argv: &[String],
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        let argv = match self.substitute_all(argv) {
            Ok(argv) => argv,
            Err(error) => {
                report.fail(
                    StepStatus::Failed,
                    CAUSE_VARIABLE_UNAVAILABLE,
                    error,
                    "supply the input the step references, or edit the flow's YAML".to_owned(),
                );
                return Ok(());
            }
        };
        // Validation guarantees a command step has at least its program.
        let program = argv.first().cloned().unwrap_or_default();
        if !self.settings.allows(&program) {
            report.fail(
                StepStatus::Blocked,
                CAUSE_PROGRAM_NOT_ALLOWED,
                format!(
                    "step {:?} runs {program:?}, which is not in the flow allowlist",
                    step.id
                ),
                RECOVERY_ALLOWED_PROGRAMS.to_owned(),
            );
            return Ok(());
        }
        let path = std::env::var_os("PATH").unwrap_or_default();
        let Some(resolved) = resolve_program(&program, &self.settings.extra_path_dirs(), &path)
        else {
            report.fail(
                StepStatus::Failed,
                CAUSE_PROGRAM_MISSING,
                format!("{program:?} is allowed but is not installed on this machine"),
                RECOVERY_EXTRA_PATH.to_owned(),
            );
            return Ok(());
        };

        let mut env = base_env(self.settings);
        for (name, value) in &step.env {
            env.push((name.clone(), value.clone()));
        }
        env.push(("PAM_FLOW".to_owned(), self.flow.id.clone()));
        env.push(("PAM_STEP".to_owned(), step.id.clone()));
        let spec = CommandSpec {
            program: resolved,
            argv: argv[1..].to_vec(),
            cwd: self.repo.clone(),
            env,
            timeout: step.timeout,
        };

        let mut attempt = None;
        for number in 1..=step.retry.attempts {
            report.attempts = number;
            let Some(outcome) = self.attempt_command(&spec, step).await else {
                return Err(CapabilityFailure::Cancelled);
            };
            let done =
                matches!(outcome, Attempt::Succeeded { .. }) || number == step.retry.attempts;
            attempt = Some(outcome);
            if done {
                break;
            }
            if self.wait_before_retry(step.retry, number, None).await {
                return Err(CapabilityFailure::Cancelled);
            }
        }
        self.settle(step, attempt, report).await;
        Ok(())
    }

    /// One child-process attempt, as an [`Attempt`]. `None` means the
    /// request was cancelled.
    async fn attempt_command(&mut self, spec: &CommandSpec, step: &Step) -> Option<Attempt> {
        match run_command(spec.clone(), &mut self.cancel).await {
            CommandOutcome::Exited { status: 0, output }
                if step.expect_empty_output && !output.is_empty() => Some(Attempt::Failed {
                result: None,                    exit_status: Some(0),
                    output,
                    status: StepStatus::Failed,
                    cause: CAUSE_OUTPUT_ASSERTION,
                    detail: format!("step {:?} expected empty output but the command emitted bytes", step.id),
                    recovery: "read the step's evidence, resolve the reported changes or warnings, and re-run the flow".to_owned(),
                    retry_after: None,
                }),
            CommandOutcome::Exited { status: 0, output } => Some(Attempt::Succeeded {
                exit_status: Some(0),
                output,
                result: None,
            }),
            CommandOutcome::Exited { status, output } => Some(Attempt::Failed {
                result: None,                exit_status: Some(status),
                output,
                status: StepStatus::Failed,
                cause: CAUSE_EXIT_STATUS,
                detail: format!("step {:?} exited {status}", step.id),
                recovery: "read the step's evidence, fix what it reports, and re-run the flow"
                    .to_owned(),
                retry_after: None,
            }),
            CommandOutcome::TimedOut { output } => Some(Attempt::Failed {
                result: None,                exit_status: None,
                output,
                status: StepStatus::Failed,
                cause: CAUSE_TIMEOUT,
                detail: format!(
                    "step {:?} was still running after its {} second timeout and was killed",
                    step.id,
                    step.timeout.as_secs()
                ),
                recovery:
                    "raise the step's `timeout:` in the flow's YAML, or make the step do less"
                        .to_owned(),
                retry_after: None,
            }),
            CommandOutcome::OutputLimit { output } => Some(Attempt::Failed {
                result: None,                exit_status: None,
                output,
                status: StepStatus::Failed,
                cause: CAUSE_OUTPUT_LIMIT,
                detail: format!(
                    "step {:?} wrote more than {} bytes and was killed",
                    step.id,
                    pam_compact::MAX_SOURCE_BYTES
                ),
                recovery: "make the step quieter, or send its output to a file the flow reads back"
                    .to_owned(),
                retry_after: None,
            }),
            CommandOutcome::SpawnFailed(detail) => Some(Attempt::Failed {
                result: None,                exit_status: None,
                output: Vec::new(),
                status: StepStatus::Failed,
                cause: CAUSE_SPAWN_FAILED,
                detail: format!("step {:?} could not be started: {detail}", step.id),
                recovery: RECOVERY_EXTRA_PATH.to_owned(),
                retry_after: None,
            }),
            CommandOutcome::Cancelled => None,
        }
    }

    /// Runs one connector step, retries included.
    async fn run_connector_step(
        &mut self,
        step: &Step,
        connector: ConnectorId,
        call: &str,
        with: &BTreeMap<String, ArgValue>,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        let args = match self.substitute_args(with) {
            Ok(args) => args,
            Err(error) => {
                report.fail(
                    StepStatus::Failed,
                    CAUSE_VARIABLE_UNAVAILABLE,
                    error,
                    "supply the input the step references, or edit the flow's YAML".to_owned(),
                );
                return Ok(());
            }
        };

        let mut attempt = None;
        for number in 1..=step.retry.attempts {
            report.attempts = number;
            let Some(outcome) = self.attempt_connector(step, connector, call, &args).await else {
                return Err(CapabilityFailure::Cancelled);
            };
            let retry_after = match &outcome {
                Attempt::Failed { retry_after, .. } => *retry_after,
                Attempt::Succeeded { .. } => None,
            };
            // A blocked connector will still be blocked next attempt.
            let done = matches!(
                outcome,
                Attempt::Succeeded { .. }
                    | Attempt::Failed {
                        status: StepStatus::Blocked,
                        ..
                    }
            ) || number == step.retry.attempts;
            attempt = Some(outcome);
            if done {
                break;
            }
            if self
                .wait_before_retry(step.retry, number, retry_after)
                .await
            {
                return Err(CapabilityFailure::Cancelled);
            }
        }
        self.settle(step, attempt, report).await;
        Ok(())
    }

    /// One connector call, bounded by the step's timeout and the cancel
    /// signal. `None` means the request was cancelled.
    async fn attempt_connector(
        &mut self,
        step: &Step,
        connector: ConnectorId,
        call: &str,
        args: &BTreeMap<String, ArgValue>,
    ) -> Option<Attempt> {
        let deadline = Instant::now() + step.timeout;
        let called = tokio::select! {
            biased;
            () = cancelled(&mut self.cancel) => return None,
            called = tokio::time::timeout(
                step.timeout,
                self.service.connectors.invoke(connector, call, args, deadline),
            ) => called,
        };
        Some(assert_connector_attempt(
            step,
            match called {
                Err(_elapsed) => Attempt::Failed {
                    result: None,
                    exit_status: None,
                    output: Vec::new(),
                    status: StepStatus::Failed,
                    cause: CAUSE_TIMEOUT,
                    detail: format!(
                        "the {connector} call did not answer within step {:?}'s {} second timeout",
                        step.id,
                        step.timeout.as_secs()
                    ),
                    recovery: format!("open Pam → Settings → Connectors → {connector} → Test"),
                    retry_after: None,
                },
                Ok(Ok(CallResult::Json(value))) => Attempt::Succeeded {
                    exit_status: None,
                    output: Vec::new(),
                    result: Some(value),
                },
                Ok(Ok(CallResult::Log {
                    bytes, exit_status, ..
                })) => Attempt::Succeeded {
                    exit_status,
                    output: bytes,
                    result: None,
                },
                Ok(Err(error)) => Attempt::Failed {
                    result: None,
                    exit_status: None,
                    output: Vec::new(),
                    // A connector a human has not finished setting up is a
                    // block (somebody must open Settings); a service that
                    // answered badly is a failure — the step did run.
                    status: if blocks_the_run(&error) {
                        StepStatus::Blocked
                    } else {
                        StepStatus::Failed
                    },
                    cause: error.cause(),
                    detail: format!("the {connector} call failed: {}", error.detail()),
                    recovery: error.recovery(connector),
                    retry_after: rate_limit_wait(&error),
                },
            },
        ))
    }

    /// Files the last attempt's output and writes the step's verdict.
    async fn settle(&mut self, step: &Step, attempt: Option<Attempt>, report: &mut StepReport) {
        let Some(attempt) = attempt else {
            // Unreachable: validation keeps `retry.attempts` at one or
            // more, so the attempt loop always runs at least once.
            report.fail(
                StepStatus::Failed,
                CAUSE_INTERNAL,
                format!("step {:?} made no attempt", step.id),
                "re-run the flow".to_owned(),
            );
            return;
        };
        let (exit_status, output, result) = match attempt {
            Attempt::Succeeded {
                exit_status,
                output,
                result,
            } => {
                report.status = StepStatus::Succeeded;
                report.exit_status = exit_status;
                (exit_status, output, result)
            }
            Attempt::Failed {
                exit_status,
                output,
                result,
                status,
                cause,
                detail,
                recovery,
                ..
            } => {
                report.exit_status = exit_status;
                report.fail(status, cause, detail, recovery);
                (exit_status, output, result)
            }
        };

        if let Some(result) = &result {
            self.file_connector_result(step, result, report).await;
        } else {
            self.file_output(step, output, exit_status, report).await;
        }
        self.vars.set_step(
            &step.id,
            json!({ "exit_status": exit_status, "result": result }),
        );
    }

    /// Files a connector's JSON answer as `connector.result` evidence.
    async fn file_connector_result(
        &mut self,
        step: &Step,
        result: &Value,
        report: &mut StepReport,
    ) {
        let Action::Connector {
            connector,
            call,
            with,
        } = &step.action
        else {
            return;
        };
        let meta = json!({
            "connector": connector.as_str(),
            "call": call,
            "args": with.iter().map(|(name, value)| (name.clone(), value.to_string()))
                .collect::<BTreeMap<String, String>>(),
        });
        let content = match serde_json::to_vec(result) {
            Ok(content) => content,
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "a connector result did not serialize");
                return;
            }
        };
        let id = new_evidence_id();
        match self
            .service
            .store
            .insert_evidence(
                &id,
                &self.ctx.request_id,
                EVIDENCE_KIND_CONNECTOR_RESULT,
                &content,
                Some(&meta.to_string()),
            )
            .await
        {
            Ok(()) => {
                report.evidence.push(id.clone());
                self.evidence.push(id);
            }
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "a connector result could not be filed");
            }
        }
    }

    /// Compresses a step's output per its `output:` policy.
    ///
    /// A compression that fails costs the run its evidence, not its
    /// verdict: the step already did (or did not do) its work, and losing
    /// the log is worth a warning in the daemon log, not a changed answer.
    async fn file_output(
        &mut self,
        step: &Step,
        output: Vec<u8>,
        exit_status: Option<i32>,
        report: &mut StepReport,
    ) {
        if output.is_empty() || step.output == OutputPolicy::Discard {
            return;
        }
        let summarize = step.output == OutputPolicy::Summarize;
        let compressed = self
            .service
            .logs
            .compress(
                &self.ctx.request_id,
                CompressInput {
                    name: format!("{}/{}", self.flow.id, step.id),
                    bytes: output,
                    exit_status,
                    use_model: summarize,
                },
            )
            .await;
        let compressed = match compressed {
            Ok(compressed) => compressed,
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "a step's output could not be compressed");
                return;
            }
        };
        for id in [
            Some(compressed.source.id.clone()),
            Some(compressed.compact.id.clone()),
            compressed.summary.as_ref().map(|row| row.id.clone()),
        ]
        .into_iter()
        .flatten()
        {
            report.evidence.push(id.clone());
            self.evidence.push(id);
        }
        if summarize {
            report.summary = compressed.summary_text.clone().or_else(|| {
                compressed
                    .model_skipped
                    .as_ref()
                    .map(|skipped| format!("model_skipped: {} — {}", skipped.cause, skipped.detail))
            });
        }
    }

    /// Sleeps the doubling backoff (or a service's own `Retry-After`);
    /// `true` means the request was cancelled while waiting.
    async fn wait_before_retry(
        &mut self,
        retry: Retry,
        attempt: u8,
        retry_after: Option<Duration>,
    ) -> bool {
        let delay = retry_after
            .filter(|wait| *wait <= MAX_BACKOFF)
            .unwrap_or_else(|| backoff_for(retry, attempt));
        sleep_or_cancel(delay, &mut self.cancel).await
    }

    /// Substitutes `${…}` in every argument, naming the first that fails.
    fn substitute_all(&self, argv: &[String]) -> Result<Vec<String>, String> {
        argv.iter()
            .map(|argument| substitute(argument, &self.vars).map_err(|error| error.to_string()))
            .collect()
    }

    /// Substitutes `${…}` in every text connector argument; integers pass
    /// through untouched.
    fn substitute_args(
        &self,
        with: &BTreeMap<String, ArgValue>,
    ) -> Result<BTreeMap<String, ArgValue>, String> {
        with.iter()
            .map(|(name, value)| match value {
                ArgValue::Text(text) => substitute(text, &self.vars)
                    .map(|text| (name.clone(), ArgValue::Text(text)))
                    .map_err(|error| format!("`{name}`: {error}")),
                ArgValue::Int(number) => Ok((name.clone(), ArgValue::Int(*number))),
            })
            .collect()
    }
}

/// The backoff before the next attempt: the step's own backoff doubled
/// once per failure, capped at [`MAX_BACKOFF`].
#[must_use]
fn backoff_for(retry: Retry, attempt: u8) -> Duration {
    let doublings = u32::from(attempt.saturating_sub(1)).min(16);
    retry
        .backoff
        .saturating_mul(1_u32 << doublings)
        .min(MAX_BACKOFF)
}

/// Whether this connector failure is something only a human at the
/// Connectors screen can clear, which makes the step `blocked`.
fn blocks_the_run(error: &InvokeError) -> bool {
    matches!(
        error,
        InvokeError::Disabled
            | InvokeError::CredentialMissing
            | InvokeError::BaseUrlMissing
            | InvokeError::BadUrl(_)
            | InvokeError::NotConfigured(_)
            | InvokeError::Secret(_)
            | InvokeError::CurlMissing
    )
}

/// The wait a rate-limited service asked for, when it named one.
fn rate_limit_wait(error: &InvokeError) -> Option<Duration> {
    match error {
        InvokeError::Connector(pam_connectors::ConnectorError::RateLimited { retry_after }) => {
            *retry_after
        }
        _ => None,
    }
}
