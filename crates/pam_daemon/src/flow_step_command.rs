//! The command step: one allowlisted program with arguments, run inside the
//! repository's containment boundary (see `flow_step.rs` for the trait).

use super::step::{InspectScope, StepExecutor};
use super::{
    ArgvError, Attempt, BTreeMap, CAUSE_ARGUMENT_OPTION, CAUSE_ARTIFACTS_ROOT_INVALID,
    CAUSE_ARTIFACTS_ROOT_UNSET, CAUSE_EXIT_STATUS, CAUSE_OUTPUT_ASSERTION, CAUSE_OUTPUT_LIMIT,
    CAUSE_POLICY_DENIED, CAUSE_PROGRAM_MISSING, CAUSE_PROGRAM_NOT_ALLOWED, CAUSE_SPAWN_FAILED,
    CAUSE_TIMEOUT, CAUSE_VARIABLE_UNAVAILABLE, CAUSE_WAIT_FAILED, CapabilityClass,
    CapabilityFailure, CommandOutcome, CommandSpec, FlowRefusal, FlowService, Key, Path, PathBuf,
    RECOVERY_ALLOWED_PROGRAMS, RECOVERY_ARGUMENT_OPTION, RECOVERY_ARTIFACTS_ROOT,
    RECOVERY_EXTRA_PATH, RECOVERY_MANAGED, RunState, Step, StepReport, StepSnapshot, StepStatus,
    Value, Vars, artifacts, base_env, check_allowed_program, command_boundary, json,
    policy_forbids_program, resolve_program, run_command_budgeted, substitute, substitute_argv,
};

/// A `run:` step.
pub(super) struct CommandStep<'s> {
    /// The argument vector as written, `${…}` not yet filled in.
    pub(super) argv: &'s [String],
}

impl StepExecutor for CommandStep<'_> {
    fn class(&self) -> CapabilityClass {
        CapabilityClass::Destructive
    }

    fn effect(&self) -> Value {
        json!(["command", self.argv])
    }

    // Nothing to wait for: the future is ready with the answer.
    fn inspect(
        &self,
        _service: &FlowService,
        scope: &InspectScope<'_>,
        step: &Step,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> impl Future<Output = Result<(), FlowRefusal>> {
        inspect_command_step(
            step,
            self.argv,
            scope.vars,
            scope.allowed,
            scope.artifacts_root,
            item,
            blockers,
        );
        // A run refuses this before spawn with the policy's
        // cause; inspection says so first.
        if item["program"]
            .as_str()
            .is_some_and(|program| policy_forbids_program(scope.view, program))
        {
            blockers.push(json!({"step": step.id, "cause": CAUSE_POLICY_DENIED, "recovery": RECOVERY_MANAGED}));
        }
        std::future::ready(Ok(()))
    }

    fn check_scope(
        &self,
        run: &RunState<'_>,
        step: &Step,
    ) -> impl Future<Output = Result<(), FlowRefusal>> {
        // A program the managed policy forbids never reaches the gate, so no
        // human is asked to approve a step that cannot run. The program is
        // checked again right before spawn, after substitution.
        if let Some(program) = self
            .argv
            .first()
            .and_then(|program| substitute(program, &run.vars).ok())
            && policy_forbids_program(&run.service.policy.view(), &program)
        {
            return std::future::ready(Err(FlowRefusal::new(
                CAUSE_POLICY_DENIED,
                format!(
                    "step {:?} runs {program:?}, which your organization's policy does not \
                     allow on this machine ({})",
                    step.id,
                    Key::FlowsPrograms
                ),
                RECOVERY_MANAGED,
            )));
        }
        std::future::ready(Ok(()))
    }

    /// The program as found on this machine, its substituted arguments, the
    /// directory and the names of the environment it sets.
    fn approval_snapshot(
        &self,
        run: &RunState<'_>,
        step: &Step,
        capability: &str,
        flow_digest: &str,
        cwd: Option<String>,
    ) -> StepSnapshot {
        let mut scratch = StepReport::new(&step.id, step.kind(), StepStatus::Failed);
        let argv = run
            .command_line(step, self.argv, &mut scratch)
            .map_or_else(|| self.argv.to_vec(), |(argv, _env)| argv);
        let program = argv.first().cloned().unwrap_or_default();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let resolved = resolve_program(&program, &run.settings.extra_path_dirs(), &path)
            .map_or(program, |found| found.display().to_string());
        StepSnapshot::new(
            flow_digest,
            capability,
            resolved,
            argv.get(1..).unwrap_or_default().to_vec(),
            cwd,
            step.env.keys().cloned().collect(),
        )
    }

    async fn execute(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        run.run_command_step(step, self.argv, report).await
    }
}

/// What `flow.inspect` says about one command step: containment, the
/// program's allowlist status, and whether its build outputs have a home.
pub(super) fn inspect_command_step(
    step: &Step,
    argv: &[String],
    vars: &Vars,
    allowed: &[String],
    artifacts_root: bool,
    item: &mut Value,
    blockers: &mut Vec<Value>,
) {
    item["containment"] = json!(if cfg!(target_os = "macos") {
        "checked_before_execution"
    } else {
        "unavailable"
    });
    if !cfg!(target_os = "macos") {
        blockers.push(json!({"step": step.id, "cause": crate::command_containment::CAUSE_UNAVAILABLE, "recovery": "command workloads require qualified OS containment; this platform is unsupported"}));
    }
    // The values known now are the caller's inputs: one that would become an
    // option is refused at run time, so inspection says so before anything runs.
    if let Err(error @ ArgvError::Option { .. }) = substitute_argv(argv, vars) {
        blockers.push(json!({"step": step.id, "cause": CAUSE_ARGUMENT_OPTION, "detail": error.to_string(), "recovery": RECOVERY_ARGUMENT_OPTION}));
    }
    let program = argv.first().and_then(|value| substitute(value, vars).ok());
    item["program"] = json!(program);
    if !program
        .as_ref()
        .is_some_and(|program| check_allowed_program(program).is_ok() && allowed.contains(program))
    {
        blockers.push(json!({"step": step.id, "cause": "program_not_allowed_or_unresolved", "recovery": RECOVERY_ALLOWED_PROGRAMS}));
    }
    let needs_artifacts = program.as_deref().is_some_and(artifacts::needs_artifacts);
    item["artifacts"] = json!(match (needs_artifacts, artifacts_root) {
        (false, _) => "not_needed",
        (true, true) => "configured",
        (true, false) => "unset",
    });
    if needs_artifacts && !artifacts_root {
        blockers.push(json!({"step": step.id, "cause": CAUSE_ARTIFACTS_ROOT_UNSET, "recovery": RECOVERY_ARTIFACTS_ROOT}));
    }
}

/// A command step's argument vector and its environment additions, every
/// `${…}` filled in.
pub(super) type CommandLine = (Vec<String>, Vec<(String, String)>);

/// How one child-process ending reads as an [`Attempt`]; `None` is the
/// cancel signal.
pub(super) fn command_attempt(step: &Step, outcome: CommandOutcome) -> Option<Attempt> {
    match outcome {
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
            CommandOutcome::ContainmentUnavailable { detail } => Some(Attempt::Failed {
                result: None,
                exit_status: None,
                output: Vec::new(),
                status: StepStatus::Blocked,
                cause: crate::command_containment::CAUSE_UNAVAILABLE,
                detail,
                recovery: "Use a qualified command-containment platform and a repository outside PAM's protected files; no uncontained fallback is available.".to_owned(),
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
            CommandOutcome::WaitFailed { detail, output } => Some(Attempt::Failed {
                result: None,
                exit_status: None,
                output,
                status: StepStatus::Failed,
                cause: CAUSE_WAIT_FAILED,
                detail: format!(
                    "step {:?} ran but its exit status could not be collected: {detail}",
                    step.id
                ),
                recovery: "read the step's evidence; the outcome of the command itself is unknown, so re-run the flow"
                    .to_owned(),
                retry_after: None,
            }),
            CommandOutcome::Cancelled => None,
    }
}

pub(super) fn budget_attempt(error: crate::request_budget::BudgetError) -> Attempt {
    Attempt::Failed {
        result: None,
        exit_status: None,
        output: Vec::new(),
        status: StepStatus::Blocked,
        cause: error.cause,
        detail: error.to_string(),
        recovery: crate::request_budget::RECOVERY_BUDGET.to_owned(),
        retry_after: None,
    }
}

impl RunState<'_> {
    /// Runs one command step, retries included.
    pub(super) async fn run_command_step(
        &mut self,
        step: &Step,
        argv: &[String],
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        let Some((argv, step_env)) = self.command_line(step, argv, report) else {
            return Ok(());
        };
        // Validation guarantees a command step has at least its program.
        let program = argv.first().cloned().unwrap_or_default();
        // The live policy, not only the settings this run started with: a
        // program the organization's policy removes is never spawned, and
        // the refusal names the policy rather than the human's allowlist.
        if policy_forbids_program(&self.service.policy.view(), &program) {
            report.fail(
                StepStatus::Blocked,
                CAUSE_POLICY_DENIED,
                format!(
                    "step {:?} runs {program:?}, which your organization's policy does not \
                     allow on this machine ({})",
                    step.id,
                    Key::FlowsPrograms
                ),
                RECOVERY_MANAGED.to_owned(),
            );
            return Ok(());
        }
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

        let (containment, mut env) = match self.contain_step(step, &program, &resolved).await {
            Ok(prepared) => prepared,
            Err(refusal) => {
                report.fail(
                    StepStatus::Blocked,
                    refusal.cause,
                    refusal.detail,
                    refusal.recovery,
                );
                return Ok(());
            }
        };
        env.extend(step_env);
        env.push(("PAM_FLOW".to_owned(), self.flow.id.clone()));
        env.push(("PAM_STEP".to_owned(), step.id.clone()));
        let spec = CommandSpec {
            containment,
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
            let done = matches!(
                outcome,
                Attempt::Succeeded { .. }
                    | Attempt::Failed {
                        status: StepStatus::Blocked,
                        ..
                    }
            ) || step.effect == pam_flow::Effect::Stateful
                || number == step.retry.attempts;
            if done {
                attempt = Some(outcome);
                break;
            }
            self.preserve_attempt(step, outcome, report).await;
            if self.wait_before_retry(step.retry, number, None).await {
                return Err(CapabilityFailure::Cancelled);
            }
        }
        self.settle(step, attempt, report).await;
        Ok(())
    }

    /// The step's argument vector and environment additions with every
    /// `${…}` filled in; `None` when the step cannot run, with `report`
    /// already saying why.
    pub(super) fn command_line(
        &self,
        step: &Step,
        argv: &[String],
        report: &mut StepReport,
    ) -> Option<CommandLine> {
        let unavailable = |report: &mut StepReport, detail: String| {
            report.fail(
                StepStatus::Failed,
                CAUSE_VARIABLE_UNAVAILABLE,
                detail,
                "supply the input the step references, or edit the flow's YAML".to_owned(),
            );
        };
        let argv = match substitute_argv(argv, &self.vars) {
            Ok(argv) => argv,
            Err(error @ ArgvError::Unresolved { .. }) => {
                unavailable(report, error.to_string());
                return None;
            }
            // A value that would change what the program is asked to do is a
            // refusal, not a failed attempt: the run stops here.
            Err(error @ ArgvError::Option { .. }) => {
                report.fail(
                    StepStatus::Blocked,
                    CAUSE_ARGUMENT_OPTION,
                    format!("step {:?}: {error}", step.id),
                    RECOVERY_ARGUMENT_OPTION.to_owned(),
                );
                return None;
            }
        };
        // Environment values take the same variables as arguments; validation
        // already counted an input one of them names as read.
        match self.substitute_env(&step.env) {
            Ok(env) => Some((argv, env)),
            Err(error) => {
                unavailable(report, error);
                None
            }
        }
    }

    /// The boundary and environment one command step runs under: the
    /// repository boundary, plus the private artifacts tree and the
    /// read-only caches when a build output directory is configured.
    pub(super) async fn contain_step(
        &self,
        step: &Step,
        program: &str,
        resolved: &Path,
    ) -> Result<
        (
            crate::command_containment::CommandContainment,
            Vec<(String, String)>,
        ),
        FlowRefusal,
    > {
        let mut containment = command_boundary(
            &self.service.protected_base,
            &self.repo,
            resolved,
            step.effect,
        );
        let Some(artifacts) = self.prepare_artifacts(program).await? else {
            return Ok((containment, base_env(self.settings)));
        };
        containment
            .read_only_roots
            .extend(self.settings.read_cache_dirs());
        containment.read_only_roots.sort();
        containment.read_only_roots.dedup();
        containment.artifact_roots.push(artifacts.clone());
        let env = artifacts::build_env(self.settings, &artifacts);
        Ok((containment, env))
    }

    /// The private artifacts tree this step writes to: `None` when no root
    /// is configured and the program does not need one, a refusal when the
    /// program does (`artifacts_root_unset`) or the root is unusable.
    pub(super) async fn prepare_artifacts(
        &self,
        program: &str,
    ) -> Result<Option<PathBuf>, FlowRefusal> {
        let Some(root) = self.settings.artifacts_root_dir() else {
            if artifacts::needs_artifacts(program) {
                return Err(FlowRefusal::new(
                    CAUSE_ARTIFACTS_ROOT_UNSET,
                    format!(
                        "{program:?} keeps its caches and build outputs in a home directory, \
                         and no private build output directory is configured"
                    ),
                    RECOVERY_ARTIFACTS_ROOT,
                ));
            }
            return Ok(None);
        };
        let repo = self.repo.clone();
        let protected = self.service.protected_base.clone();
        let caches = self.settings.read_cache_dirs();
        crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
            artifacts::prepare(&root, &repo, &protected, &caches)
        })
        .await
        .map_err(|error| {
            FlowRefusal::new(
                CAUSE_ARTIFACTS_ROOT_INVALID,
                error.to_string(),
                RECOVERY_ARTIFACTS_ROOT,
            )
        })?
        .map(Some)
    }

    /// One child-process attempt, as an [`Attempt`]. `None` means the
    /// request was cancelled.
    pub(super) async fn attempt_command(
        &mut self,
        spec: &CommandSpec,
        step: &Step,
    ) -> Option<Attempt> {
        if let Err(refusal) = self.service.approved_repo(&self.repo).await {
            return Some(Attempt::Failed {
                result: None,
                exit_status: None,
                output: Vec::new(),
                status: StepStatus::Blocked,
                cause: refusal.cause,
                detail: refusal.detail,
                recovery: refusal.recovery,
                retry_after: None,
            });
        }
        let outcome =
            match run_command_budgeted(spec.clone(), &mut self.cancel, &self.ctx.budget).await {
                Ok(outcome) => outcome,
                Err(error) => return Some(budget_attempt(error)),
            };
        command_attempt(step, outcome)
    }

    /// Substitutes `${…}` in every environment value of a command step,
    /// naming the first variable that fails.
    pub(super) fn substitute_env(
        &self,
        env: &BTreeMap<String, String>,
    ) -> Result<Vec<(String, String)>, String> {
        env.iter()
            .map(|(name, value)| {
                substitute(value, &self.vars)
                    .map(|value| (name.clone(), value))
                    .map_err(|error| format!("env.{name}: {error}"))
            })
            .collect()
    }
}
