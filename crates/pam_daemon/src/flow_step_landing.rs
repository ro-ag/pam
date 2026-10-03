//! The landing step: one typed operation of guarded landing, run by the
//! landing runtime (`flow_landing_runtime.rs`) under its own journalled
//! intents and receipts (see `flow_step.rs` for the trait).

use super::step::{InspectScope, StepExecutor};
use super::{
    CapabilityClass, CapabilityFailure, FlowRefusal, FlowService, Path, PolicyView, RunState, Step,
    StepReport, StepSnapshot, Value, json, landing_runtime,
};

/// A `landing:` step.
pub(super) struct LandingStep {
    /// The operation.
    pub(super) operation: pam_flow::LandingOperation,
}

impl StepExecutor for LandingStep {
    fn class(&self) -> CapabilityClass {
        CapabilityClass::Destructive
    }

    fn effect(&self) -> Value {
        json!(["landing", self.operation])
    }

    async fn inspect(
        &self,
        service: &FlowService,
        scope: &InspectScope<'_>,
        step: &Step,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> Result<(), FlowRefusal> {
        service
            .inspect_landing_step(scope.view, scope.repo, step, self.operation, item, blockers)
            .await;
        Ok(())
    }

    async fn check_scope(&self, run: &RunState<'_>, _step: &Step) -> Result<(), FlowRefusal> {
        let view = run.service.policy.view();
        landing_runtime::inspect_policy(&run.service.store, &view, &run.repo, self.operation)
            .await?;
        Ok(())
    }

    /// The fixed operation.
    fn approval_snapshot(
        &self,
        _run: &RunState<'_>,
        _step: &Step,
        capability: &str,
        flow_digest: &str,
        cwd: Option<String>,
    ) -> StepSnapshot {
        let operation = serde_json::to_value(self.operation)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        StepSnapshot::new(
            flow_digest,
            capability,
            format!("landing:{operation}"),
            Vec::new(),
            cwd,
            Vec::new(),
        )
    }

    async fn execute(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        run.run_landing_step(step, self.operation, report).await
    }
}

impl FlowService {
    pub(super) async fn inspect_landing_step(
        &self,
        view: &PolicyView,
        repo: &Path,
        step: &Step,
        operation: pam_flow::LandingOperation,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) {
        item["landing"] = json!(operation);
        item["live_state"] = json!("unknown_until_frozen_and_verified");
        if let Err(error) =
            landing_runtime::inspect_policy(&self.store, view, repo, operation).await
        {
            blockers.push(json!({"step":step.id,"cause":error.cause,"recovery":error.recovery}));
        }
    }
}
