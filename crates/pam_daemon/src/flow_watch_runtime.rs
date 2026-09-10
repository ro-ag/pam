//! One bounded remote poll per existing flow journal lease.
use super::*;
use crate::flow_recovery::{WatchState, failure};
use crate::flow_watch::{self, State, WatchError};

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

fn blocked(step: &Step, cause: &str, detail: impl Into<String>) -> StepReport {
    let mut report = StepReport::new(&step.id, step.kind(), StepStatus::Blocked);
    report.fail(
        StepStatus::Blocked,
        cause,
        detail.into(),
        "inspect retained watch evidence; resume troubleshooting with the exact target identifiers"
            .to_owned(),
    );
    report
}

fn status_call(connector: ConnectorId) -> &'static str {
    match connector {
        ConnectorId::Github => "run_status",
        ConnectorId::Jenkins => "build_status",
        ConnectorId::Sonarqube => "ce_status",
        _ => "unsupported",
    }
}

const TARGET_CHANGED: &str = "watch_target_changed";

pub(super) fn conflicting_observation(
    connector: ConnectorId,
    pins: &Value,
    received: &crate::flow_watch::Observation,
) -> Option<crate::flow_watch::Observation> {
    if pins.is_null()
        || received.state == State::Unavailable
        || flow_watch::validate_pins(connector, pins, &received.payload).is_ok()
    {
        return None;
    }
    let payload = json!({"watch_state":"unavailable", "status":"conflicting",
        "cause":TARGET_CHANGED, "received":received.payload});
    Some(crate::flow_watch::Observation {
        state: State::Unavailable,
        digest: pam_compact::sha256_hex(payload.to_string().as_bytes()),
        payload,
    })
}

struct Polled {
    observation: crate::flow_watch::Observation,
    retry_after: Option<Duration>,
    origin: crate::evidence_service::ConnectorTarget,
}

impl RunState<'_> {
    pub(super) fn watch_due(&self, step: &Step) -> Result<(), CapabilityFailure> {
        if let Some(watch) = &self.recovery.watch {
            if watch.step != step.id {
                return Err(failure());
            }
            if !watch.collecting && watch.next_poll_ms > now_ms() {
                return Err(CapabilityFailure::Parked {
                    resume_at_ms: watch.next_poll_ms,
                });
            }
        }
        Ok(())
    }

    pub(super) async fn watch_stamp(&self) -> Result<(String, i64), CapabilityFailure> {
        let profile = self
            .service
            .store
            .get_setting_bounded(crate::policy::PROFILE_SETTING_KEY, 128)
            .await
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        let row = self
            .service
            .store
            .request_status_meta(&self.ctx.request_id)
            .await
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        let revision = row.authorization_revision.ok_or_else(failure)?;
        if self
            .service
            .store
            .grant_revocation_revision()
            .await
            .map_err(|_| failure())?
            != revision
        {
            return Err(failure());
        }
        Ok((pam_compact::sha256_hex(profile.as_bytes()), revision))
    }

    pub(super) async fn watch_approval_valid(
        &self,
        step: &Step,
    ) -> Result<bool, CapabilityFailure> {
        let Some(watch) = &self.recovery.watch else {
            return Ok(false);
        };
        let Action::Connector { with, .. } = &step.action else {
            return Ok(false);
        };
        let args = self.substitute_args(with).map_err(|_| failure())?;
        let fingerprint = pam_compact::sha256_hex(&crate::flow_recovery::encode(&args)?);
        let (stamp, revision) = self.watch_stamp().await?;
        Ok(watch.step == step.id
            && watch.args_fingerprint == fingerprint
            && watch.profile_stamp == stamp
            && watch.authorization_revision == revision)
    }

    pub(super) fn check_watch_pins(
        &self,
        step: &Step,
        connector: ConnectorId,
        attempt: Attempt,
    ) -> Attempt {
        let Some(watch) = &self.recovery.watch else {
            return attempt;
        };
        if step.watch.is_none() || !watch.collecting {
            return attempt;
        }
        let Attempt::Succeeded {
            result: Some(value),
            ..
        } = &attempt
        else {
            return attempt;
        };
        let Err(error) = flow_watch::validate_pins(connector, &watch.observation, value) else {
            return attempt;
        };
        let Attempt::Succeeded {
            result,
            output,
            exit_status,
        } = attempt
        else {
            unreachable!()
        };
        Attempt::Failed {
            result,
            output,
            exit_status,
            status: StepStatus::Blocked,
            cause: error.cause,
            detail: error.detail.to_owned(),
            recovery: crate::correlation::RECOVERY.to_owned(),
            retry_after: None,
        }
    }

    /// `None` authorizes the full collector; pending returns the journal's parked signal.
    pub(super) async fn advance_watch(
        &mut self,
        step: &Step,
    ) -> Result<Option<StepReport>, CapabilityFailure> {
        let Some(policy) = step.watch else {
            return Ok(None);
        };
        let Action::Connector {
            connector, with, ..
        } = &step.action
        else {
            return Err(failure());
        };
        let args = self.substitute_args(with).map_err(|_| failure())?;
        let fingerprint = pam_compact::sha256_hex(&crate::flow_recovery::encode(&args)?);
        if self
            .recovery
            .watch
            .as_ref()
            .is_some_and(|w| w.args_fingerprint != fingerprint)
        {
            return Err(failure());
        }
        if let Some(report) = self.retained_watch_conflict(step) {
            return Ok(Some(report));
        }
        if self.recovery.watch.as_ref().is_some_and(|w| w.collecting) {
            return Ok(None);
        }
        let polls = self.recovery.watch.as_ref().map_or(0, |w| w.polls);
        let errors = self.recovery.watch.as_ref().map_or(0, |w| w.errors);
        if let Err(error) = self.watch_admit(*connector, policy, polls, errors, Duration::ZERO) {
            return Ok(Some(self.watch_blocked(step, &error)));
        }
        let polled = match self.poll_watch(step, *connector, args).await? {
            Ok(polled) => polled,
            Err(report) => return Ok(Some(*report)),
        };
        let conflict = self.recovery.watch.as_ref().and_then(|watch| {
            conflicting_observation(*connector, &watch.pins, &polled.observation)
        });
        if let Some(observation) = conflict {
            return self
                .commit_watch_conflict(step, polled.origin, observation)
                .await
                .map(Some);
        }
        let delay = self.commit_watch(step, fingerprint, polled).await?;
        let watch = self.recovery.watch.as_ref().ok_or_else(failure)?;
        let (collecting, polls, errors, next_poll_ms) = (
            watch.collecting,
            watch.polls,
            watch.errors,
            watch.next_poll_ms,
        );
        // Ready is durable before parking or beginning the terminal collector.
        if collecting {
            self.recovery
                .prepare(&self.service.store, &self.ctx.request_id, step, true)
                .await?;
            return Ok(None);
        }
        if let Err(error) = self.watch_admit(*connector, policy, polls, errors, delay) {
            // Settle a blocked report through the normal prepared->checkpoint path.
            self.recovery
                .prepare(&self.service.store, &self.ctx.request_id, step, true)
                .await?;
            return Ok(Some(self.watch_blocked(step, &error)));
        }
        Err(CapabilityFailure::Parked {
            resume_at_ms: next_poll_ms,
        })
    }

    async fn poll_watch(
        &mut self,
        step: &Step,
        connector: ConnectorId,
        args: BTreeMap<String, ArgValue>,
    ) -> Result<Result<Polled, Box<StepReport>>, CapabilityFailure> {
        let call = status_call(connector);
        let mut status_args = args;
        status_args.retain(|key, _| match connector {
            ConnectorId::Github => matches!(key.as_str(), "repo" | "run_id" | "run_attempt"),
            ConnectorId::Jenkins => matches!(key.as_str(), "job" | "build"),
            ConnectorId::Sonarqube => matches!(
                key.as_str(),
                "project" | "ce_task" | "branch" | "pullRequest"
            ),
            _ => false,
        });
        if let Err(error) = self
            .service
            .connectors
            .authorize_scope(&self.repo, connector, call, &status_args)
            .await
        {
            return Ok(Err(Box::new(blocked(step, error.cause(), error.detail()))));
        }
        let deadline = (Instant::now() + step.timeout).min(self.ctx.budget.deadline());
        let captured = tokio::select! {
            biased;
            () = cancelled(&mut self.cancel) => return Err(CapabilityFailure::Cancelled),
            result = self.service.connectors.invoke_captured(&self.repo, connector, call, &status_args, deadline, Arc::clone(&self.ctx.budget)) => result,
        };
        let (result, origin) = match captured {
            Ok(captured) => captured,
            Err(error) => return Ok(Err(Box::new(blocked(step, error.cause(), error.detail())))),
        };
        let (observation, retry_after) = match result {
            Ok(CallResult::Json(value)) => match flow_watch::normalize(connector, &value) {
                Ok(observation) => (observation, None),
                Err(error) => return Ok(Err(Box::new(self.watch_blocked(step, &error)))),
            },
            Ok(_) => return Err(failure()),
            Err(error) => {
                if blocks_the_run(&error) {
                    return Ok(Err(Box::new(blocked(step, error.cause(), error.detail()))));
                }
                let value = json!({"watch_state":"unavailable", "status":"unavailable"});
                let observation = crate::flow_watch::Observation {
                    state: State::Unavailable,
                    digest: pam_compact::sha256_hex(value.to_string().as_bytes()),
                    payload: value,
                };
                (observation, rate_limit_wait(&error))
            }
        };
        Ok(Ok(Polled {
            observation,
            retry_after,
            origin,
        }))
    }

    fn retained_watch_conflict(&mut self, step: &Step) -> Option<StepReport> {
        if !self
            .recovery
            .watch
            .as_ref()
            .is_some_and(|watch| watch.observation["cause"] == TARGET_CHANGED)
        {
            return None;
        }
        Some(self.watch_blocked(step, &WatchError {
            cause: TARGET_CHANGED,
            detail: "The received product identity differs from the pinned target; conflicting evidence is retained and collection stopped",
        }))
    }

    async fn commit_watch_conflict(
        &mut self,
        step: &Step,
        origin: crate::evidence_service::ConnectorTarget,
        observation: crate::flow_watch::Observation,
    ) -> Result<StepReport, CapabilityFailure> {
        let mut watch = self.recovery.watch.clone().ok_or_else(failure)?;
        let stamp = self.watch_stamp().await?;
        if self.watch_grant_stamp.as_ref() != Some(&stamp) {
            return Err(failure());
        }
        let evidence = self
            .file_watch(step, &origin, &observation, watch.polls + 1, None)
            .await?;
        // The bad observation is evidence, never a replacement for accepted identity pins.
        watch.polls += 1;
        watch.collecting = false;
        watch.next_poll_ms = 0;
        watch.observation = observation.payload;
        watch.last_digest = observation.digest;
        watch.last_evidence = evidence;
        self.recovery
            .settle_watch(
                &self.service.store,
                &self.ctx.request_id,
                watch,
                &self.evidence,
            )
            .await?;
        self.publish_note(
            self.reports.len(),
            self.flow.steps.len(),
            format!("{}: conflicting target; collection stopped", step.id),
        )
        .await;
        // Normal step settlement expects a prepared attempt. A crash before it resumes the
        // persisted conflict marker and produces the same refusal without another HTTP call.
        self.recovery
            .prepare(&self.service.store, &self.ctx.request_id, step, true)
            .await?;
        self.retained_watch_conflict(step).ok_or_else(failure)
    }

    async fn commit_watch(
        &mut self,
        step: &Step,
        fingerprint: String,
        polled: Polled,
    ) -> Result<Duration, CapabilityFailure> {
        let policy = step.watch.ok_or_else(failure)?;
        let Polled {
            observation,
            retry_after,
            origin,
        } = polled;
        let polls = self.recovery.watch.as_ref().map_or(0, |w| w.polls);
        let errors = self.recovery.watch.as_ref().map_or(0, |w| w.errors);
        let mut pins = self
            .recovery
            .watch
            .as_ref()
            .map_or(Value::Null, |watch| watch.pins.clone());
        if observation.state != State::Unavailable {
            if !pins.is_null() {
                flow_watch::validate_pins(origin.connector, &pins, &observation.payload)
                    .map_err(|_| failure())?;
            }
            pins = observation.payload.clone();
        }
        let (profile_stamp, authorization_revision) = self.watch_stamp().await?;
        if self.watch_grant_stamp.as_ref() != Some(&(profile_stamp.clone(), authorization_revision))
        {
            return Err(failure());
        }
        let collecting = observation.state == State::Terminal;
        let polls = polls + 1;
        let errors = if observation.state == State::Unavailable {
            errors + 1
        } else {
            0
        };
        let delay =
            flow_watch::next_delay(policy.interval, policy.max_interval, polls, retry_after);
        let next_poll_ms =
            now_ms().saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX));
        let changed = self
            .recovery
            .watch
            .as_ref()
            .is_none_or(|w| w.last_digest != observation.digest);
        let last_evidence = if changed {
            self.file_watch(
                step,
                &origin,
                &observation,
                polls,
                if collecting { None } else { Some(next_poll_ms) },
            )
            .await?
        } else {
            self.recovery
                .watch
                .as_ref()
                .ok_or_else(failure)?
                .last_evidence
                .clone()
        };
        let watch = WatchState {
            step: step.id.clone(),
            args_fingerprint: fingerprint,
            origin,
            profile_stamp,
            authorization_revision,
            polls,
            errors,
            next_poll_ms,
            collecting,
            observation: observation.payload,
            pins,
            last_digest: observation.digest,
            last_evidence,
        };
        self.recovery
            .settle_watch(
                &self.service.store,
                &self.ctx.request_id,
                watch,
                &self.evidence,
            )
            .await?;
        if changed {
            self.announce_watch(step, collecting, errors).await;
        }
        Ok(delay)
    }

    async fn announce_watch(&self, step: &Step, collecting: bool, errors: u32) {
        self.publish_note(
            self.reports.len(),
            self.flow.steps.len(),
            format!(
                "{}: watch {}",
                step.id,
                if collecting {
                    "terminal; collecting evidence"
                } else if errors > 0 {
                    "service unavailable"
                } else {
                    "pending"
                }
            ),
        )
        .await;
    }

    fn watch_admit(
        &self,
        connector: ConnectorId,
        policy: pam_flow::Watch,
        polls: u32,
        errors: u32,
        delay: Duration,
    ) -> Result<(), WatchError> {
        flow_watch::admit_next(
            connector,
            polls,
            u32::from(policy.max_polls),
            errors,
            128_u64.saturating_sub(self.ctx.budget.usage().http_calls),
            self.ctx
                .budget
                .deadline()
                .saturating_duration_since(Instant::now()),
            delay,
        )
    }

    fn watch_blocked(&mut self, step: &Step, error: &WatchError) -> StepReport {
        let mut report = blocked(step, error.cause, error.detail);
        if let Some(watch) = &self.recovery.watch {
            report.evidence.push(watch.last_evidence.clone());
            if !self.evidence.contains(&watch.last_evidence) {
                self.evidence.push(watch.last_evidence.clone());
            }
            if !self.all_origins.contains(&watch.origin) {
                self.all_origins.push(watch.origin.clone());
            }
        }
        report
    }

    async fn file_watch(
        &self,
        step: &Step,
        origin: &crate::evidence_service::ConnectorTarget,
        observation: &crate::flow_watch::Observation,
        polls: u32,
        next_poll: Option<i64>,
    ) -> Result<String, CapabilityFailure> {
        let id = format!("ev_{}", ulid::Ulid::new());
        let bytes = crate::flow_recovery::encode(&observation.payload)?;
        if bytes.len() > 16 * 1024 {
            return Err(failure());
        }
        let state = match observation.state {
            State::Pending => "pending",
            State::Terminal => "terminal",
            State::Unavailable => "unavailable",
        };
        let status = observation
            .payload
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        let metadata = json!({"watch_progress": {"step":step.id,"connector":origin.connector.as_str(),"status":status,"watch_state":state,"polls":polls,"next_poll_at":next_poll,"evidence_id":id,"omissions":0}}).to_string();
        let view = crate::evidence_service::prepare(bytes.clone())
            .await
            .map_err(|_| failure())?;
        self.service
            .store
            .insert_evidence(
                &id,
                &self.ctx.request_id,
                "flow.watch",
                &bytes,
                Some(&metadata),
            )
            .await
            .map_err(|_| failure())?;
        let scope = crate::evidence_service::CaptureScope {
            repository: self.repo.to_string_lossy().into_owned(),
            origin: crate::evidence_service::EvidenceOrigin {
                targets: vec![origin.clone()],
            },
        };
        crate::evidence_service::publish(
            &self.service.store,
            &scope,
            &self.ctx.request_id,
            &id,
            view,
            json!({"kind":"watch_status"}),
        )
        .await
        .map_err(|_| failure())?;
        Ok(id)
    }
}
