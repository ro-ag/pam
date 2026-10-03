//! The connector step: one typed call to a configured connector, its JSON
//! answer filed as protected evidence (see `flow_step.rs` for the trait).

use super::step::{InspectScope, StepExecutor};
use super::{
    Action, Arc, ArgValue, Attempt, BTreeMap, CAUSE_STATUS_ASSERTION,
    CAUSE_STATUS_ASSERTION_REQUIRED, CAUSE_TIMEOUT, CAUSE_VARIABLE_UNAVAILABLE, CallResult,
    CapabilityClass, CapabilityFailure, ConnectorId, Duration, EVIDENCE_KIND_CONNECTOR_RESULT,
    FlowRefusal, FlowService, Instant, InvokeError, RECOVERY_FLOW_EDIT, Role, RunState, Step,
    StepReport, StepSnapshot, StepStatus, Value, cancelled, json, new_evidence_id, store_note,
    substitute,
};

/// A `connector:` step.
pub(super) struct ConnectorStep<'s> {
    /// The connector called.
    pub(super) connector: ConnectorId,
    /// The call made.
    pub(super) call: &'s str,
    /// Its arguments as written, `${…}` not yet filled in.
    pub(super) with: &'s BTreeMap<String, ArgValue>,
}

impl StepExecutor for ConnectorStep<'_> {
    /// A connector call leaves the machine.
    fn class(&self) -> CapabilityClass {
        CapabilityClass::External
    }

    fn effect(&self) -> Value {
        let with: Vec<Value> = self
            .with
            .iter()
            .map(|(name, value)| match value {
                ArgValue::Text(text) => json!([name, "text", text]),
                ArgValue::Int(number) => json!([name, "int", number]),
            })
            .collect();
        json!(["connector", self.connector.as_str(), self.call, with])
    }

    async fn inspect(
        &self,
        service: &FlowService,
        scope: &InspectScope<'_>,
        step: &Step,
        item: &mut Value,
        blockers: &mut Vec<Value>,
    ) -> Result<(), FlowRefusal> {
        item["product"] = json!(self.connector.as_str());
        item["operation"] = json!(self.call);
        // Named to stay off the redactor's sensitive-key list: a
        // `credential`-shaped key would mask the sentinel itself,
        // and "never probed" must survive redaction to reach agents.
        item["auth_probe"] = json!("unknown_not_probed");
        let row = service
            .store
            .get_connector(self.connector.as_str())
            .await
            .map_err(|error| store_note(&error))?;
        item["configured"] = json!(row.as_ref().is_some_and(|row| row.enabled));
        let resolved = self
            .with
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    ArgValue::Text(text) => ArgValue::Text(substitute(text, scope.vars)?),
                    ArgValue::Int(number) => ArgValue::Int(*number),
                };
                Ok((name.clone(), value))
            })
            .collect::<Result<BTreeMap<_, _>, pam_flow::VarError>>();
        match resolved {
            Ok(resolved) => if let Err(error) = service.connectors.authorize_scope(scope.repo, self.connector, self.call, &resolved).await {
                blockers.push(json!({"step": step.id, "cause": error.cause(), "recovery": error.recovery(self.connector)}));
            },
            Err(_) => blockers.push(json!({"step": step.id, "cause": "target_unresolved", "recovery": "supply declared inputs; prior-step targets are checked during execution"})),
        }
        let shape = pam_connectors::descriptor(self.connector);
        if shape.username_label.is_some()
            && row
                .as_ref()
                .and_then(|row| row.username.as_deref())
                .is_none_or(|value| value.trim().is_empty())
        {
            blockers.push(json!({"step": step.id, "cause": "connector_username_missing", "recovery": "configure the connector in GUI Connectors"}));
        }
        Ok(())
    }

    async fn check_scope(&self, run: &RunState<'_>, _step: &Step) -> Result<(), FlowRefusal> {
        let args = run.substitute_args(self.with).map_err(|detail| {
            FlowRefusal::new(CAUSE_VARIABLE_UNAVAILABLE, detail, RECOVERY_FLOW_EDIT)
        })?;
        run.service
            .connectors
            .authorize_scope(&run.repo, self.connector, self.call, &args)
            .await
            .map_err(|error| {
                FlowRefusal::new(
                    error.cause(),
                    error.detail(),
                    &error.recovery(self.connector),
                )
            })?;
        Ok(())
    }

    /// The call and its substituted arguments.
    fn approval_snapshot(
        &self,
        run: &RunState<'_>,
        _step: &Step,
        capability: &str,
        flow_digest: &str,
        _cwd: Option<String>,
    ) -> StepSnapshot {
        let filled = run
            .substitute_args(self.with)
            .unwrap_or_else(|_| self.with.clone());
        let mut argv = vec![self.call.to_owned()];
        argv.extend(filled.iter().map(|(name, value)| match value {
            ArgValue::Text(text) => format!("{name}={text}"),
            ArgValue::Int(number) => format!("{name}={number}"),
        }));
        StepSnapshot::new(
            flow_digest,
            capability,
            format!("connector:{}", self.connector.as_str()),
            argv,
            None,
            Vec::new(),
        )
    }

    async fn execute(
        &self,
        run: &mut RunState<'_>,
        step: &Step,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        run.run_connector_step(step, self.connector, self.call, self.with, report)
            .await
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
        .and_then(|value| {
            if step.watch.is_some()
                && matches!(
                    step.action,
                    Action::Connector {
                        connector: ConnectorId::Github,
                        ..
                    }
                )
            {
                value.pointer("/run/conclusion")
            } else {
                value.get("status")
            }
        })
        .and_then(Value::as_str);
    if actual != Some(expected.as_str()) {
        report.fail(StepStatus::Failed, CAUSE_STATUS_ASSERTION,
            format!("step {:?} expected status {expected:?}; inspect its retained connector evidence", step.id),
            "resolve the reported gate conditions and re-run the flow; missing or unknown status never establishes a pass".to_owned());
    }
}

pub(super) fn assert_connector_attempt(step: &Step, attempt: Attempt) -> Attempt {
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

/// Whether this connector failure is something only a human at the
/// Connectors screen can clear, which makes the step `blocked`.
pub(super) fn blocks_the_run(error: &InvokeError) -> bool {
    matches!(
        error,
        InvokeError::Disabled
            | InvokeError::Scope(_)
            | InvokeError::Connector(pam_connectors::ConnectorError::Policy { .. })
            | InvokeError::CredentialMissing
            | InvokeError::BaseUrlMissing
            | InvokeError::BadUrl(_)
            | InvokeError::NotConfigured(_)
            | InvokeError::Secret(_)
            | InvokeError::CurlMissing
    )
}

/// The wait a rate-limited service asked for, when it named one.
pub(super) fn rate_limit_wait(error: &InvokeError) -> Option<Duration> {
    match error {
        InvokeError::Connector(pam_connectors::ConnectorError::RateLimited { retry_after }) => {
            *retry_after
        }
        _ => None,
    }
}

impl RunState<'_> {
    /// Runs one connector step, retries included.
    pub(super) async fn run_connector_step(
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
            if done {
                attempt = Some(outcome);
                break;
            }
            self.preserve_attempt(step, outcome, report).await;
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
    pub(super) async fn attempt_connector(
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
                self.service.connectors.invoke_captured(&self.repo, connector, call, args, deadline.min(self.ctx.budget.deadline()), Arc::clone(&self.ctx.budget)),
            ) => called,
        };
        let called = called.map(|result| {
            result.and_then(|(result, origin)| {
                if !self.all_origins.contains(&origin) {
                    self.all_origins.push(origin.clone());
                }
                self.origins.insert(step.id.clone(), origin);
                result
            })
        });
        let attempt = match called {
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
        };
        let attempt = self.check_watch_pins(step, connector, attempt);
        let attempt = self.correlate_attempt(step, attempt).await;
        Some(assert_connector_attempt(step, attempt))
    }

    pub(super) async fn correlate_attempt(&mut self, step: &Step, attempt: Attempt) -> Attempt {
        let Attempt::Succeeded {
            exit_status,
            output,
            mut result,
        } = attempt
        else {
            return attempt;
        };
        let correlated = if let Some(origin) = self.origins.get(&step.id) {
            match self
                .correlation
                .enrich(&self.service.store, origin, result.as_mut())
                .await
            {
                Err(error) => Err(error),
                Ok(()) => {
                    self.correlation
                        .associate(
                            &self.service.store,
                            &self.ctx.request_id,
                            step,
                            origin,
                            result.as_ref(),
                        )
                        .await
                }
            }
        } else {
            Err(crate::correlation::Failure {
                cause: crate::correlation::MISSING,
                detail: "connector origin unavailable for association".to_owned(),
            })
        };
        match correlated {
            Ok(()) => Attempt::Succeeded {
                exit_status,
                output,
                result,
            },
            Err(error) => Attempt::Failed {
                exit_status,
                output,
                result,
                status: StepStatus::Blocked,
                cause: error.cause,
                detail: error.detail,
                recovery: crate::correlation::RECOVERY.to_owned(),
                retry_after: None,
            },
        }
    }

    /// Keep raw connector answers protected and publish their redacted views.
    pub(super) async fn file_connector_result(
        &mut self,
        step: &Step,
        result: &Value,
        report: &mut StepReport,
    ) {
        let Action::Connector {
            connector,
            call,
            with: _,
        } = &step.action
        else {
            return;
        };
        if let Some(summary) = crate::context_summary::summarize(*connector, call, result) {
            report.summary = crate::evidence_view::redact(summary.as_bytes())
                .ok()
                .and_then(|view| String::from_utf8(view.bytes).ok());
        }
        if (*connector == ConnectorId::Jenkins
            && matches!(call.as_str(), "investigate" | "node_evidence"))
            || (*connector == ConnectorId::Sonarqube && call == "analysis")
        {
            report.summary = result
                .get("summary")
                .and_then(Value::as_str)
                .filter(|text| text.len() <= 6000)
                .and_then(|text| crate::evidence_view::redact(text.as_bytes()).ok())
                .and_then(|view| String::from_utf8(view.bytes).ok());
        }
        let meta = json!({
            "connector": connector.as_str(),
            "attempt": report.attempts,
            "call": call,
            "args": self.origins.get(&step.id).map(|origin| &origin.args),
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
                let capture = self.capture_scope(step);
                let view = crate::evidence_service::prepare(content).await;
                if let (Ok(capture), Ok(view)) = (capture, view) {
                    if let Err(error) = crate::evidence_service::publish(
                        &self.service.store,
                        &capture,
                        &self.ctx.request_id,
                        &id,
                        view,
                        json!({"kind": "protected_connector_result"}),
                    )
                    .await
                    {
                        tracing::warn!(step = %step.id, %error, "connector evidence view unavailable");
                        report
                            .evidence_unavailable
                            .push(format!("{id}: view_unavailable"));
                    }
                } else {
                    tracing::warn!(step = %step.id, "connector evidence view could not be prepared");
                    report
                        .evidence_unavailable
                        .push(format!("{id}: view_unavailable"));
                }
                report.evidence.push(id.clone());
                self.evidence.push(id);
            }
            Err(error) => {
                tracing::warn!(step = %step.id, %error, "a connector result could not be filed");
                report
                    .evidence_unavailable
                    .push("connector_source_unavailable".to_owned());
            }
        }
    }

    /// Substitutes `${…}` in every text connector argument; integers pass
    /// through untouched.
    pub(super) fn substitute_args(
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
