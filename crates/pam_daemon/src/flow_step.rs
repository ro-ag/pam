//! How a flow run handles each kind of step.
//!
//! A step's kind is its `action`: a local command, a connector call or a
//! typed landing operation. [`step_kind`] is the one place the kind is
//! matched; everything the engine does differently per kind goes through
//! [`StepExecutor`], with one implementation per kind
//! (`step_command::CommandStep`, `step_connector::ConnectorStep`,
//! `step_landing::LandingStep`) and [`StepKind`] dispatching to them. The
//! engine (`flow_service.rs`) keeps the orchestration: the order of steps,
//! the journal, the gate and the approval wait, the checkpoint, the verdict.
//!
//! Watching (`watch:`) and summarizing (`output: summarize`) are not kinds:
//! a watch is how a connector step polls (`flow_watch_runtime.rs`), and a
//! summary is how a step's output is filed ([`RunState::file_output`]).
//!
//! This module also holds what the command and connector kinds share: the
//! [`Attempt`] one try of a step produced, and settling and filing it.

use super::step_command::CommandStep;
use super::step_connector::ConnectorStep;
use super::step_landing::LandingStep;
use super::{
    Action, CAUSE_INTERNAL, CapabilityClass, CapabilityFailure, CompressInput, Duration,
    FlowRefusal, FlowService, MAX_BACKOFF, OutputPolicy, Path, PolicyView, Retry, RunState, Step,
    StepReport, StepSnapshot, StepStatus, SummaryModel, Value, Vars, json, sleep_or_cancel,
};

/// What inspection knows about the run it previews, read once up front.
pub(super) struct InspectScope<'a> {
    /// The caller's inputs, substituted where they are known.
    pub(super) vars: &'a Vars,
    /// The caller's repository.
    pub(super) repo: &'a Path,
    /// The effective program allowlist.
    pub(super) allowed: &'a [String],
    /// Whether a build output directory is configured.
    pub(super) artifacts_root: bool,
    /// The policy in force.
    pub(super) view: &'a PolicyView,
}

/// What the engine does differently for one kind of step: inspect it,
/// prepare it (the checks before its gate), describe it for the gate's
/// approval card, execute it, and file the evidence of one attempt.
pub(super) trait StepExecutor {
    /// The gate class the step is evaluated under (`flow_service::step_class`).
    fn class(&self) -> CapabilityClass;

    /// What the step runs, as its effect digest encodes it
    /// (`flow_service::step_effect_digest`).
    fn effect(&self) -> Value;

    /// What `flow.inspect` reports about the step beyond its gate.
    async fn inspect(
        &self,
        service: &FlowService,
        scope: &InspectScope<'_>,
        step: &Step,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> Result<(), FlowRefusal>;

    /// The step's own checks before its gate, after the repository scope:
    /// a target, program or landing permission that cannot be allowed never
    /// reaches an approval.
    async fn check_scope(&self, run: &RunState<'_>, step: &Step) -> Result<(), FlowRefusal>;

    /// What a gated step will run, as this run resolved it, for the
    /// approval card (see `RunState::approval_snapshot`).
    fn approval_snapshot(
        &self,
        run: &RunState<'_>,
        step: &Step,
        capability: &str,
        flow_digest: &str,
        cwd: Option<String>,
    ) -> StepSnapshot;

    /// Runs the step, retries included, once its gate has passed.
    async fn execute(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure>;

    /// Files one attempt's evidence: a connector's JSON answer as a
    /// protected `connector.result`, anything else (a process's output, a
    /// connector's log) through the step's `output:` policy.
    async fn file_evidence(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        output: Vec<u8>,
        exit_status: Option<i32>,
        result: Option<&Value>,
        report: &mut StepReport,
    ) {
        if let Some(result) = result {
            run.file_connector_result(step, result, report).await;
        } else {
            run.file_output(step, output, exit_status, report).await;
        }
    }
}

/// A step, by kind.
pub(super) enum StepKind<'s> {
    /// `run:` a local command.
    Command(CommandStep<'s>),
    /// `connector:` a connector call.
    Connector(ConnectorStep<'s>),
    /// `landing:` a typed landing operation.
    Landing(LandingStep),
}

/// The one place a step's kind is matched.
pub(super) fn step_kind(step: &Step) -> StepKind<'_> {
    match &step.action {
        Action::Command { argv } => StepKind::Command(CommandStep { argv }),
        Action::Connector {
            connector,
            call,
            with,
        } => StepKind::Connector(ConnectorStep {
            connector: *connector,
            call,
            with,
        }),
        Action::Landing { operation } => StepKind::Landing(LandingStep {
            operation: *operation,
        }),
    }
}

impl StepExecutor for StepKind<'_> {
    fn class(&self) -> CapabilityClass {
        match self {
            Self::Command(kind) => kind.class(),
            Self::Connector(kind) => kind.class(),
            Self::Landing(kind) => kind.class(),
        }
    }

    fn effect(&self) -> Value {
        match self {
            Self::Command(kind) => kind.effect(),
            Self::Connector(kind) => kind.effect(),
            Self::Landing(kind) => kind.effect(),
        }
    }

    async fn inspect(
        &self,
        service: &FlowService,
        scope: &InspectScope<'_>,
        step: &Step,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> Result<(), FlowRefusal> {
        match self {
            Self::Command(kind) => kind.inspect(service, scope, step, item, blockers).await,
            Self::Connector(kind) => kind.inspect(service, scope, step, item, blockers).await,
            Self::Landing(kind) => kind.inspect(service, scope, step, item, blockers).await,
        }
    }

    async fn check_scope(&self, run: &RunState<'_>, step: &Step) -> Result<(), FlowRefusal> {
        match self {
            Self::Command(kind) => kind.check_scope(run, step).await,
            Self::Connector(kind) => kind.check_scope(run, step).await,
            Self::Landing(kind) => kind.check_scope(run, step).await,
        }
    }

    fn approval_snapshot(
        &self,
        run: &RunState<'_>,
        step: &Step,
        capability: &str,
        flow_digest: &str,
        cwd: Option<String>,
    ) -> StepSnapshot {
        match self {
            Self::Command(kind) => kind.approval_snapshot(run, step, capability, flow_digest, cwd),
            Self::Connector(kind) => {
                kind.approval_snapshot(run, step, capability, flow_digest, cwd)
            }
            Self::Landing(kind) => kind.approval_snapshot(run, step, capability, flow_digest, cwd),
        }
    }

    async fn execute(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        match self {
            Self::Command(kind) => kind.execute(run, step, report).await,
            Self::Connector(kind) => kind.execute(run, step, report).await,
            Self::Landing(kind) => kind.execute(run, step, report).await,
        }
    }

    async fn file_evidence(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        output: Vec<u8>,
        exit_status: Option<i32>,
        result: Option<&Value>,
        report: &mut StepReport,
    ) {
        match self {
            Self::Command(kind) => {
                kind.file_evidence(run, step, output, exit_status, result, report)
                    .await;
            }
            Self::Connector(kind) => {
                kind.file_evidence(run, step, output, exit_status, result, report)
                    .await;
            }
            Self::Landing(kind) => {
                kind.file_evidence(run, step, output, exit_status, result, report)
                    .await;
            }
        }
    }
}

/// What one attempt of a step produced.
pub(super) enum Attempt {
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

/// The backoff before the next attempt: the step's own backoff doubled
/// once per failure, capped at [`MAX_BACKOFF`].
#[must_use]
pub(super) fn backoff_for(retry: Retry, attempt: u8) -> Duration {
    let doublings = u32::from(attempt.saturating_sub(1)).min(16);
    retry
        .backoff
        .saturating_mul(1_u32 << doublings)
        .min(MAX_BACKOFF)
}

impl RunState<'_> {
    /// Persist a completed failed attempt before waiting or starting another.
    pub(super) async fn preserve_attempt(
        &mut self,
        step: &Step,
        attempt: Attempt,
        report: &mut StepReport,
    ) {
        let (output, result, exit_status) = match attempt {
            Attempt::Succeeded {
                output,
                result,
                exit_status,
            }
            | Attempt::Failed {
                output,
                result,
                exit_status,
                ..
            } => (output, result, exit_status),
        };
        step_kind(step)
            .file_evidence(self, step, output, exit_status, result.as_ref(), report)
            .await;
    }

    /// Files the last attempt's output and writes the step's verdict.
    pub(super) async fn settle(
        &mut self,
        step: &Step,
        attempt: Option<Attempt>,
        report: &mut StepReport,
    ) {
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

        step_kind(step)
            .file_evidence(self, step, output, exit_status, result.as_ref(), report)
            .await;
        self.observed.set_step(
            &step.id,
            json!({ "exit_status": exit_status, "result": result }),
        );
        let correlated = report
            .error
            .as_ref()
            .is_none_or(|error| !error.cause.starts_with("correlation_"));
        self.vars.set_step(
            &step.id,
            json!({ "exit_status": if correlated { exit_status } else { None }, "result": if correlated { result } else { None } }),
        );
    }

    /// Files a connector's JSON answer as `connector.result` evidence.
    pub(super) fn capture_scope(
        &self,
        step: &Step,
    ) -> Result<crate::evidence_service::CaptureScope, String> {
        use crate::evidence_service::{CaptureScope, EvidenceOrigin};
        if matches!(step.action, Action::Connector { .. }) {
            self.origins
                .get(&step.id)
                .ok_or("connector capture identity unavailable")?;
        }
        // Later local steps can consume earlier connector values. Conservatively
        // retain every preceding target rather than downgrade derived evidence.
        let origin = EvidenceOrigin {
            targets: self.all_origins.clone(),
        };
        Ok(CaptureScope {
            repository: self.repo.to_string_lossy().into_owned(),
            origin,
        })
    }

    /// Compresses a step's output per its `output:` policy.
    ///
    /// A compression that fails costs the run its evidence, not its
    /// verdict: the step already did (or did not do) its work, and losing
    /// the log is worth a warning in the daemon log, not a changed answer.
    pub(super) async fn file_output(
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
        let capture = match self.capture_scope(step) {
            Ok(capture) => capture,
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "evidence scope could not be captured");
                report
                    .evidence_unavailable
                    .push("capture_scope_unavailable".to_owned());
                return;
            }
        };
        let compressed = self
            .service
            .logs
            .compress_scoped(
                &self.ctx.request_id,
                CompressInput {
                    name: format!("{}/{}/attempt-{}", self.flow.id, step.id, report.attempts),
                    bytes: output,
                    exit_status,
                    use_model: summarize,
                },
                Some(&capture),
                // The step's own cancel: a cancelled run stops its summary too.
                self.cancel.clone(),
            )
            .await;
        let compressed = match compressed {
            Ok(compressed) => compressed,
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "a step's output could not be compressed");
                report
                    .evidence_unavailable
                    .push(format!("log_view_unavailable: {}", error.cause()));
                return;
            }
        };
        for skipped in &compressed.view_skipped {
            report
                .evidence_unavailable
                .push(format!("{}: {}", skipped.detail, skipped.cause));
        }
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
            report.summary_model = compressed.model.as_ref().map(|used| SummaryModel {
                id: used.id.clone(),
                qualification: used.qualification.clone(),
            });
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
    pub(super) async fn wait_before_retry(
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
}
