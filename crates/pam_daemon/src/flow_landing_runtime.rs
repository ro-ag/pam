//! Original-ticket typed landing orchestration. Recipes supply no commands or URLs.
use super::{
    Action, Arc, ArgValue, BTreeMap, CapabilityFailure, ConnectorId, Duration, FlowRefusal,
    Instant, Path, PathBuf, RunState, Step, StepReport, StepStatus, Store, Value, digest, failed,
    json, new_evidence_id, resolve_program,
};
use crate::connector_service::LandingGithubOp;
use crate::flow_recovery::failure;
use crate::landing_checkout::{self, CheckoutReceipt, CheckoutRequest};
use crate::landing_policy::{Repository, Snapshot as Policy};
use pam_connectors::github_landing::{CheckState, Checks, PullRequest, Target};
use pam_flow::LandingOperation as Op;
use serde::{Deserialize, Serialize};

const RECOVERY: &str = "Inspect the original landing ticket and retained receipts; reconcile uncertain effects before starting new work.";
const MAX_POLLS: u32 = 20;
const POLL_MS: i64 = 5_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    version: u8,
    flow_digest: String,
    repository: String,
    policy_revision: String,
    manifest_evidence: String,
    manifest_digest: String,
    checktree: PathBuf,
    target: pam_flow::CorrelationTarget,
    receipts: BTreeMap<String, Value>,
    intent: Option<Intent>,
    poll: Option<Poll>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    step_id: String,
    operation: Op,
    state: String,
    expected: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    step: String,
    polls: u32,
    next_poll_ms: i64,
    profile_stamp: String,
    authorization_revision: i64,
    last_digest: String,
    last_evidence: String,
}
struct Loaded {
    revision: i64,
    session: Session,
    receipt: CheckoutReceipt,
    policy: Repository,
}
fn key(operation: Op) -> &'static str {
    match operation {
        Op::Freeze => "freeze",
        Op::Validate => "validate",
        Op::Push => "push",
        Op::EnsurePr => "ensure_pr",
        Op::VerifyPr => "verify_pr",
        Op::Merge => "merge",
        Op::VerifyMain => "verify_main",
        Op::Sync => "sync",
    }
}
fn refused(cause: &str, detail: impl Into<String>) -> CapabilityFailure {
    CapabilityFailure::Refused {
        cause: cause.into(),
        detail: detail.into(),
        recovery: RECOVERY.into(),
    }
}
fn checkout_error(error: landing_checkout::CheckoutError) -> CapabilityFailure {
    refused(error.cause, error.detail)
}
fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}
fn permitted(policy: &Repository, operation: Op) -> bool {
    match operation {
        Op::Push => policy.permissions.push,
        Op::EnsurePr => policy.permissions.create_pr,
        Op::Merge => policy.permissions.merge,
        Op::Sync => policy.permissions.sync,
        _ => true,
    }
}
/// Reject statically unavailable stages before any recipe operation can run.
pub(super) fn available(operation: Op) -> Result<(), FlowRefusal> {
    if operation == Op::Sync {
        return Err(FlowRefusal::new(
            "landing_sync_unavailable",
            "Guarded local synchronization is unavailable; this flow cannot complete safely."
                .to_owned(),
            "Use an explicitly reviewed prefix ending before sync, or wait for supported guarded synchronization; a prefix does not complete landing.",
        ));
    }
    Ok(())
}

pub(super) fn preflight(flow: &pam_flow::Flow) -> Result<(), FlowRefusal> {
    for step in &flow.steps {
        if let Action::Landing { operation } = step.action {
            available(operation)?;
        }
    }
    Ok(())
}

pub(super) async fn inspect_policy(
    store: &Store,
    repo: &Path,
    operation: Op,
) -> Result<(), FlowRefusal> {
    available(operation)?;
    let policy = Policy::load(store)
        .await
        .map_err(|e| FlowRefusal::new(e.cause, e.detail.to_owned(), RECOVERY))?;
    let repository = policy
        .repository(repo)
        .map_err(|e| FlowRefusal::new(e.cause, e.detail.to_owned(), RECOVERY))?;
    if !permitted(repository, operation) {
        return Err(FlowRefusal::new(
            "landing_permission_missing",
            "The GUI landing policy does not authorize this operation.".to_owned(),
            RECOVERY,
        ));
    }
    Ok(())
}
impl RunState<'_> {
    async fn landing_session(&self) -> Result<Option<(i64, Session)>, CapabilityFailure> {
        let Some(row) = self
            .service
            .store
            .read_landing_session(&self.ctx.request_id)
            .await
            .map_err(failed)?
        else {
            return Ok(None);
        };
        let session: Session = serde_json::from_str(&row.document).map_err(|_| failure())?;
        if session.version != 1
            || session.flow_digest != digest(self.flow)
            || session.repository != self.repo.to_string_lossy()
            || Some(&session.target) != self.correlation.target()
            || session.receipts.len() > 8
            || session.poll.as_ref().is_some_and(|p| p.polls > MAX_POLLS)
        {
            return Err(failure());
        }
        Ok(Some((row.revision, session)))
    }
    pub(super) async fn landing_due(&self, step: &Step) -> Result<(), CapabilityFailure> {
        if !matches!(step.action, Action::Landing { .. }) {
            return Ok(());
        }
        if let Some((_, session)) = self.landing_session().await?
            && let Some(poll) = session.poll
            && poll.step == step.id
            && poll.next_poll_ms > now_ms()
        {
            return Err(CapabilityFailure::Parked {
                resume_at_ms: poll.next_poll_ms,
            });
        }
        Ok(())
    }
    pub(super) async fn landing_approval_valid(
        &self,
        step: &Step,
    ) -> Result<bool, CapabilityFailure> {
        if !matches!(step.action, Action::Landing { .. }) {
            return Ok(false);
        }
        let Some((_, session)) = self.landing_session().await? else {
            return Ok(false);
        };
        let Some(poll) = session.poll else {
            return Ok(false);
        };
        let (profile, revision) = self.watch_stamp().await?;
        Ok(poll.step == step.id
            && poll.profile_stamp == profile
            && poll.authorization_revision == revision)
    }
    async fn landing_policy(&self) -> Result<(String, Repository), CapabilityFailure> {
        let policy = Policy::load(&self.service.store)
            .await
            .map_err(|e| refused(e.cause, e.detail))?;
        let repository = policy
            .repository(&self.repo)
            .map_err(|e| refused(e.cause, e.detail))?
            .clone();
        repository
            .authorize_workspace(&self.service.protected_base)
            .map_err(|e| refused(e.cause, e.detail))?;
        Ok((policy.revision, repository))
    }
    fn checkout_request(
        &self,
        policy: &Repository,
        commit: &str,
    ) -> Result<CheckoutRequest, CapabilityFailure> {
        let git_program = resolve_program(
            "git",
            &self.settings.extra_path_dirs(),
            &std::env::var_os("PATH").unwrap_or_default(),
        )
        .ok_or_else(|| refused("program_missing", "Git is unavailable"))?;
        Ok(CheckoutRequest {
            repository: self.repo.clone(),
            protected_base: self.service.protected_base.clone(),
            checkouts_root: policy.workspace_root.clone(),
            git_program,
            expected_commit: commit.into(),
            base_ref: format!("refs/heads/{}", policy.base),
            remote_url: policy.repository.clone(),
        })
    }
    async fn landing_load(&self) -> Result<Loaded, CapabilityFailure> {
        let (revision, session) = self.landing_session().await?.ok_or_else(failure)?;
        let (policy_revision, policy) = self.landing_policy().await?;
        if policy_revision != session.policy_revision {
            return Err(refused(
                "landing_policy_changed",
                "Landing configuration changed",
            ));
        }
        let bytes = self
            .service
            .store
            .read_flow_checkpoint(&self.ctx.request_id, &session.manifest_evidence)
            .await
            .map_err(failed)?
            .ok_or_else(failure)?;
        if bytes.len() > 512 * 1024 || pam_compact::sha256_hex(&bytes) != session.manifest_digest {
            return Err(failure());
        }
        let receipt: CheckoutReceipt = serde_json::from_slice(&bytes).map_err(|_| failure())?;
        let branch = receipt
            .branch
            .strip_prefix("refs/heads/")
            .ok_or_else(failure)?;
        if receipt.repository != self.repo
            || receipt.remote_url != session.target.repository
            || receipt.commit != session.target.commit
            || policy.repository != session.target.repository
            || !policy.branches.iter().any(|b| b == branch)
            || !session.checktree.starts_with(&policy.workspace_root)
        {
            return Err(refused(
                "landing_target_changed",
                "The frozen landing target no longer matches its policy or manifest",
            ));
        }
        if let Some(poll) = &session.poll {
            let view = self
                .service
                .store
                .evidence_view_meta(
                    &self.ctx.request_id,
                    &poll.last_evidence,
                    &session.repository,
                )
                .await
                .map_err(failed)?
                .ok_or_else(failure)?;
            if view.expired_at.is_some() {
                return Err(failure());
            }
            let origin = serde_json::from_str(&view.origin_json).map_err(|_| failure())?;
            let scope = crate::scope_policy::ScopePolicy::load(&self.service.store)
                .await
                .map_err(|_| failure())?;
            crate::evidence_service::authorize_origin(
                &self.service.store,
                &scope,
                &self.repo,
                &origin,
            )
            .await?;
        }
        Ok(Loaded {
            revision,
            session,
            receipt,
            policy,
        })
    }
    async fn landing_save(&self, loaded: &mut Loaded) -> Result<(), CapabilityFailure> {
        let bytes = crate::flow_recovery::encode(&loaded.session)?;
        let document = std::str::from_utf8(&bytes).map_err(|_| failure())?;
        if !self
            .service
            .store
            .save_landing_session(
                &self.ctx.request_id,
                Some(loaded.revision),
                document,
                now_ms(),
            )
            .await
            .map_err(failed)?
        {
            return Err(failure());
        }
        loaded.revision += 1;
        Ok(())
    }
    async fn landing_live(
        &mut self,
        loaded: &Loaded,
        deadline: Instant,
    ) -> Result<(), CapabilityFailure> {
        self.service
            .approved_repo(&self.repo)
            .await
            .map_err(|e| refused(e.cause, e.detail))?;
        let (revision, _) = self.landing_policy().await?;
        if revision != loaded.session.policy_revision {
            return Err(refused(
                "landing_policy_changed",
                "Landing configuration changed",
            ));
        }
        if self.watch_grant_stamp.as_ref() != Some(&self.watch_stamp().await?) {
            return Err(refused(
                "landing_authorization_changed",
                "The admission or policy profile changed after this stage was gated",
            ));
        }
        let request = self.checkout_request(&loaded.policy, &loaded.receipt.commit)?;
        landing_checkout::revalidate(
            &request,
            &loaded.receipt,
            Arc::clone(&self.ctx.budget),
            &mut self.cancel,
            deadline,
        )
        .await
        .map_err(checkout_error)
    }
    pub(super) async fn run_landing_step(
        &mut self,
        step: &Step,
        operation: Op,
        report: &mut StepReport,
    ) -> Result<(), CapabilityFailure> {
        report.attempts = 1;
        let deadline = (Instant::now() + step.timeout).min(self.ctx.budget.deadline());
        let prior_evidence = self.evidence.len();
        let result = self
            .landing_dispatch(step, operation, report, deadline)
            .await;
        for id in &self.evidence[prior_evidence..] {
            if !report.evidence.contains(id) {
                report.evidence.push(id.clone());
            }
        }
        match result {
            Ok(Some(value)) => {
                self.correlation
                    .record_landing_receipt(&self.service.store, &self.ctx.request_id, step, &value)
                    .await
                    .map_err(|e| refused(e.cause, e.detail))?;
                self.landing_evidence(step, &value, "landing.result", None)
                    .await
                    .map(|id| {
                        report.evidence.push(id);
                    })?;
                report.status = StepStatus::Succeeded;
                report.summary = Some(format!(
                    "Landing {} confirmed for frozen commit {}.{}",
                    key(operation),
                    self.correlation.target().ok_or_else(failure)?.commit,
                    if operation == Op::Sync {
                        " Merge, main checks and local synchronization are confirmed."
                    } else {
                        " The complete landing sequence is not yet confirmed."
                    }
                ));
                self.observed.set_step(&step.id, json!({"result":value}));
                self.vars.set_step(&step.id, json!({"result":value}));
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error @ CapabilityFailure::Parked { .. }) => Err(error),
            Err(error) => {
                if self.landing_session().await?.is_some_and(|(_, s)| {
                    s.intent
                        .as_ref()
                        .is_some_and(|i| i.step_id == step.id && i.state == "prepared")
                }) {
                    return Err(error);
                }
                match error {
                    CapabilityFailure::Refused {
                        cause,
                        detail,
                        recovery,
                    } => {
                        report.fail(StepStatus::Blocked, &cause, detail, recovery);
                        Ok(())
                    }
                    error => Err(error),
                }
            }
        }
    }
    async fn landing_dispatch(
        &mut self,
        step: &Step,
        operation: Op,
        report: &mut StepReport,
        deadline: Instant,
    ) -> Result<Option<Value>, CapabilityFailure> {
        if operation == Op::Freeze && self.landing_session().await?.is_none() {
            self.landing_freeze(deadline).await?;
        }
        let mut loaded = self.landing_load().await?;
        self.landing_origin(&loaded);
        if let Some(receipt) = loaded.session.receipts.get(key(operation)) {
            return Ok(Some(receipt.clone()));
        }
        require_predecessor(&loaded.session, operation)?;
        let value = match operation {
            Op::Freeze => return Err(failure()),
            Op::Validate => {
                return self
                    .landing_validate(step, report, &mut loaded, deadline)
                    .await;
            }
            Op::Push => self.landing_push(step, &mut loaded, deadline).await?,
            Op::EnsurePr => self.landing_ensure_pr(step, &mut loaded, deadline).await?,
            Op::VerifyPr | Op::VerifyMain => {
                self.landing_checks(step, operation, &mut loaded, deadline)
                    .await?
            }
            Op::Merge => self.landing_merge(step, &mut loaded, deadline).await?,
            Op::Sync => {
                return Err(refused(
                    "landing_sync_unavailable",
                    "The guarded local synchronization adapter is unavailable; confirmed remote merge receipts remain retained",
                ));
            }
        };
        loaded
            .session
            .receipts
            .insert(key(operation).into(), value.clone());
        loaded.session.poll = None;
        // Keep prepared intent through checkpoint settlement. Its matching receipt
        // makes recovery read-only even if the daemon dies before that settlement.
        self.landing_save(&mut loaded).await?;
        Ok(Some(value))
    }
    async fn landing_freeze(&mut self, deadline: Instant) -> Result<(), CapabilityFailure> {
        let target = self.correlation.target().cloned().ok_or_else(|| {
            refused(
                "correlation_missing",
                "Landing requires a frozen revision target",
            )
        })?;
        let (policy_revision, policy) = self.landing_policy().await?;
        if target.repository != policy.repository {
            return Err(refused(
                "correlation_conflict",
                "Configured repository differs from the declared landing target",
            ));
        }
        if target
            .pull_request_head
            .as_ref()
            .is_some_and(|head| head != &target.commit)
        {
            return Err(refused(
                "correlation_conflict",
                "The declared PR head differs from the frozen landing commit",
            ));
        }
        let request = self.checkout_request(&policy, &target.commit)?;
        let snapshot = landing_checkout::capture(
            &request,
            Arc::clone(&self.ctx.budget),
            &mut self.cancel,
            deadline,
        )
        .await
        .map_err(checkout_error)?;
        let branch = snapshot
            .receipt
            .branch
            .strip_prefix("refs/heads/")
            .ok_or_else(failure)?;
        if !policy.branches.iter().any(|b| b == branch) {
            return Err(refused(
                "landing_branch_denied",
                "The current branch is not approved for landing",
            ));
        }
        let bytes = crate::flow_recovery::encode(&snapshot.receipt)?;
        if bytes.len() > 512 * 1024 {
            return Err(failure());
        }
        let id = new_evidence_id();
        self.service
            .store
            .insert_evidence(&id, &self.ctx.request_id, "flow.checkpoint", &bytes, None)
            .await
            .map_err(failed)?;
        let receipt = json!({"repository":target.repository,"commit":target.commit,"branch":branch,"tree":snapshot.receipt.tree,"manifest_sha256":snapshot.receipt.manifest_sha256});
        let session = Session {
            version: 1,
            flow_digest: digest(self.flow),
            repository: self.repo.to_string_lossy().into_owned(),
            policy_revision,
            manifest_evidence: id,
            manifest_digest: pam_compact::sha256_hex(&bytes),
            checktree: snapshot.checktree,
            target,
            receipts: BTreeMap::from([("freeze".into(), receipt)]),
            intent: None,
            poll: None,
        };
        if !self
            .service
            .store
            .save_landing_session(
                &self.ctx.request_id,
                None,
                &serde_json::to_string(&session).map_err(failed)?,
                now_ms(),
            )
            .await
            .map_err(failed)?
        {
            return Err(failure());
        }
        Ok(())
    }
    async fn landing_validate(
        &mut self,
        step: &Step,
        report: &mut StepReport,
        loaded: &mut Loaded,
        deadline: Instant,
    ) -> Result<Option<Value>, CapabilityFailure> {
        self.landing_live(loaded, deadline).await?;
        let mut checked = Vec::new();
        for (index, check) in loaded.policy.checks.iter().enumerate() {
            let settings = self.service.settings().await.map_err(failed)?;
            let mut spec = super::landing_checks::prepare(
                &loaded.policy,
                index,
                &loaded.session.checktree,
                &settings,
                &self.service.protected_base,
            )
            .await
            .map_err(|e| refused(e.cause, e.detail))?;
            self.landing_live(loaded, deadline).await?;
            if settings != self.service.settings().await.map_err(failed)? {
                return Err(refused(
                    "landing_check_configuration_changed",
                    "The command allowlist or executable search path changed while preparing this check",
                ));
            }
            spec.timeout = spec
                .timeout
                .min(deadline.saturating_duration_since(Instant::now()));
            let attempt = self.attempt_command(&spec, step).await;
            self.settle(step, attempt, report).await;
            if !report.evidence_unavailable.is_empty() {
                report.fail(
                    StepStatus::Blocked,
                    "landing_check_evidence_unavailable",
                    "A mandatory check completed without publishable retained evidence".to_owned(),
                    RECOVERY.to_owned(),
                );
                return Ok(None);
            }
            if report.status != StepStatus::Succeeded {
                return Ok(None);
            }
            checked.push(json!({"name":check.name,"program":spec.program,"argv":spec.argv,"configuration_sha256":pam_compact::sha256_hex(&crate::flow_recovery::encode(check)?)}));
        }
        self.landing_live(loaded, deadline).await?;
        let value = json!({"commit":loaded.receipt.commit,"manifest_sha256":loaded.receipt.manifest_sha256,"checks":checked,"passed":true});
        loaded
            .session
            .receipts
            .insert("validate".into(), value.clone());
        self.landing_save(loaded).await?;
        Ok(Some(value))
    }
    fn landing_origin(&mut self, loaded: &Loaded) {
        if let Some(poll) = &loaded.session.poll
            && !self.evidence.contains(&poll.last_evidence)
        {
            self.evidence.push(poll.last_evidence.clone());
        }
        let origin = crate::evidence_service::ConnectorTarget {
            connector: ConnectorId::Github,
            base_url: loaded.policy.github_server.clone(),
            call: "runs".into(),
            args: BTreeMap::from([(
                "repo".into(),
                ArgValue::Text(loaded.policy.github_repository.clone()),
            )]),
        };
        if !self.all_origins.contains(&origin) {
            self.all_origins.push(origin);
        }
    }
    async fn landing_evidence(
        &mut self,
        step: &Step,
        value: &Value,
        kind: &str,
        metadata: Option<String>,
    ) -> Result<String, CapabilityFailure> {
        let bytes = crate::flow_recovery::encode(value)?;
        if bytes.len() > 16 * 1024 {
            return Err(failure());
        }
        let id = new_evidence_id();
        let view = crate::evidence_service::prepare(bytes.clone())
            .await
            .map_err(|_| failure())?;
        self.service
            .store
            .insert_evidence(&id, &self.ctx.request_id, kind, &bytes, metadata.as_deref())
            .await
            .map_err(failed)?;
        crate::evidence_service::publish(
            &self.service.store,
            &self.capture_scope(step).map_err(|_| failure())?,
            &self.ctx.request_id,
            &id,
            view,
            json!({"kind":"typed_landing"}),
        )
        .await
        .map_err(|_| failure())?;
        if !self.evidence.contains(&id) {
            self.evidence.push(id.clone());
        }
        Ok(id)
    }
    async fn github(
        &self,
        loaded: &Loaded,
        operation: LandingGithubOp,
        deadline: Instant,
    ) -> Result<Value, CapabilityFailure> {
        self.service
            .connectors
            .landing_github(
                &self.repo,
                &self.ctx.request_id,
                &loaded.session.policy_revision,
                &operation,
                Arc::clone(&self.ctx.budget),
                deadline,
            )
            .await
            .map_err(|e| refused(e.cause(), e.detail()))
    }
    async fn intent(
        &self,
        loaded: &mut Loaded,
        step: &Step,
        operation: Op,
        expected: Value,
    ) -> Result<(), CapabilityFailure> {
        if loaded.session.intent.as_ref().is_some_and(|i| {
            i.step_id == step.id || !loaded.session.receipts.contains_key(key(i.operation))
        }) {
            return Err(failure());
        }
        loaded.session.intent = Some(Intent {
            step_id: step.id.clone(),
            operation,
            state: "prepared".into(),
            expected,
        });
        self.landing_save(loaded).await
    }
    async fn landing_ensure_pr(
        &mut self,
        step: &Step,
        loaded: &mut Loaded,
        deadline: Instant,
    ) -> Result<Value, CapabilityFailure> {
        self.landing_live(loaded, deadline).await?;
        let target = github_target(loaded)?;
        let lookup = loaded.session.target.pull_request.map_or_else(
            || LandingGithubOp::FindPr(target.clone()),
            |number| LandingGithubOp::ReadPr(target.clone(), number),
        );
        let found = self.github(loaded, lookup, deadline).await?;
        if !found.is_null() {
            let pr: PullRequest = serde_json::from_value(found.clone()).map_err(|_| failure())?;
            if pr.state == "open" && !pr.merged {
                return Ok(found);
            }
            return Err(refused(
                "landing_pr_conflict",
                "Matching PR is already closed",
            ));
        }
        if has_intent(loaded, step, Op::EnsurePr)? {
            return Err(refused(
                "landing_effect_uncertain",
                "Prepared PR creation is not yet visible; PAM will not resend it",
            ));
        }
        self.intent(loaded, step, Op::EnsurePr, json!({"target":target}))
            .await?;
        self.landing_live(loaded, deadline).await?;
        self.github(
            loaded,
            LandingGithubOp::CreatePr(target, format!("Land {}", loaded.receipt.branch)),
            deadline,
        )
        .await
    }
    async fn landing_push(
        &mut self,
        step: &Step,
        loaded: &mut Loaded,
        deadline: Instant,
    ) -> Result<Value, CapabilityFailure> {
        self.landing_live(loaded, deadline).await?;
        let mut target = crate::landing_git::GitTarget {
            request: self.checkout_request(&loaded.policy, &loaded.receipt.commit)?,
            receipt: loaded.receipt.clone(),
            branch: loaded
                .receipt
                .branch
                .strip_prefix("refs/heads/")
                .ok_or_else(failure)?
                .into(),
            expected_old: None,
        };
        let observed = self
            .service
            .connectors
            .landing_git_observe(
                &self.repo,
                &self.ctx.request_id,
                &loaded.session.policy_revision,
                &target,
                Arc::clone(&self.ctx.budget),
                &mut self.cancel,
                deadline,
            )
            .await
            .map_err(|e| refused(e.cause(), e.detail()))?;
        if has_intent(loaded, step, Op::Push)? {
            let prepared: crate::landing_git::PushObservation = serde_json::from_value(
                loaded
                    .session
                    .intent
                    .as_ref()
                    .ok_or_else(failure)?
                    .expected
                    .clone(),
            )
            .map_err(|_| failure())?;
            if prepared.requested_commit != loaded.receipt.commit {
                return Err(failure());
            }
            if crate::landing_git::reconcile(&observed, &prepared).map_err(checkout_error)?
                != crate::landing_git::Reconciliation::Matched
            {
                return Err(refused(
                    "landing_effect_uncertain",
                    "The prepared push is not confirmed by the exact remote ref; PAM will not resend it",
                ));
            }
            return Ok(
                json!({"ref_name":observed.ref_name,"commit":loaded.receipt.commit,"confirmed_by":"exact_remote_ref"}),
            );
        }
        if observed.oid.as_deref() == Some(loaded.receipt.commit.as_str()) {
            return Ok(
                json!({"ref_name":observed.ref_name,"commit":loaded.receipt.commit,"confirmed_by":"exact_remote_ref"}),
            );
        }
        target.expected_old = observed.oid.clone();
        self.intent(loaded,step,Op::Push,json!({"ref_name":observed.ref_name,"expected_old":target.expected_old,"requested_commit":loaded.receipt.commit,"state":"uncertain"})).await?;
        self.landing_live(loaded, deadline).await?;
        self.service
            .connectors
            .landing_git_push(
                &self.repo,
                &self.ctx.request_id,
                &loaded.session.policy_revision,
                &target,
                Arc::clone(&self.ctx.budget),
                &mut self.cancel,
                deadline,
            )
            .await
            .map_err(|e| refused(e.cause(), e.detail()))?;
        let observed = self
            .service
            .connectors
            .landing_git_observe(
                &self.repo,
                &self.ctx.request_id,
                &loaded.session.policy_revision,
                &target,
                Arc::clone(&self.ctx.budget),
                &mut self.cancel,
                deadline,
            )
            .await
            .map_err(|e| refused(e.cause(), e.detail()))?;
        if observed.oid.as_deref() != Some(loaded.receipt.commit.as_str()) {
            return Err(refused(
                "landing_effect_uncertain",
                "Push response did not yield a confirmed exact remote ref",
            ));
        }
        Ok(
            json!({"ref_name":observed.ref_name,"commit":loaded.receipt.commit,"confirmed_by":"exact_remote_ref"}),
        )
    }
    async fn landing_merge(
        &mut self,
        step: &Step,
        loaded: &mut Loaded,
        deadline: Instant,
    ) -> Result<Value, CapabilityFailure> {
        self.landing_live(loaded, deadline).await?;
        let target = github_target(loaded)?;
        let number = pr_number(loaded)?;
        let pr: PullRequest = serde_json::from_value(
            self.github(
                loaded,
                LandingGithubOp::ReadPr(target.clone(), number),
                deadline,
            )
            .await?,
        )
        .map_err(|_| failure())?;
        if pr.merged {
            return Ok(
                json!({"number":number,"sha":pr.merge_sha.ok_or_else(failure)?,"head_sha":target.head_sha,"base_sha_observed":pr.base_sha}),
            );
        }
        if has_intent(loaded, step, Op::Merge)? {
            return Err(refused(
                "landing_effect_uncertain",
                "Prepared merge is not yet visible; PAM will not resend it",
            ));
        }
        if pr.state != "open" {
            return Err(refused(
                "landing_pr_conflict",
                "The exact PR is no longer open",
            ));
        }
        let checks = self
            .github(loaded, checks_op(loaded, false)?, deadline)
            .await?;
        let checks: Checks = serde_json::from_value(checks).map_err(|_| failure())?;
        if !checks.passed {
            return Err(refused(
                "landing_checks_unconfirmed",
                "Fresh PR checks do not all succeed",
            ));
        }
        self.intent(
            loaded,
            step,
            Op::Merge,
            json!({"number":number,"head_sha":target.head_sha,"base_sha_observed":pr.base_sha}),
        )
        .await?;
        self.landing_live(loaded, deadline).await?;
        let response = self
            .github(
                loaded,
                LandingGithubOp::MergePr(target.clone(), number),
                deadline,
            )
            .await?;
        Ok(
            json!({"number":number,"sha":response["sha"],"head_sha":target.head_sha,"base_sha_observed":pr.base_sha}),
        )
    }
    async fn landing_checks(
        &mut self,
        step: &Step,
        operation: Op,
        loaded: &mut Loaded,
        deadline: Instant,
    ) -> Result<Value, CapabilityFailure> {
        let polls = loaded
            .session
            .poll
            .as_ref()
            .filter(|p| p.step == step.id)
            .map_or(0, |p| p.polls);
        if polls >= MAX_POLLS {
            return Err(refused(
                "landing_poll_budget_exhausted",
                "Required checks did not converge within the persisted polling budget",
            ));
        }
        let value = self
            .github(
                loaded,
                checks_op(loaded, operation == Op::VerifyMain)?,
                deadline,
            )
            .await?;
        let checks: Checks = serde_json::from_value(value.clone()).map_err(|_| failure())?;
        if checks.passed {
            if operation == Op::VerifyPr {
                let pr: PullRequest = serde_json::from_value(
                    self.github(
                        loaded,
                        LandingGithubOp::ReadPr(github_target(loaded)?, pr_number(loaded)?),
                        deadline,
                    )
                    .await?,
                )
                .map_err(|_| failure())?;
                if pr.state != "open" || pr.merged {
                    return Err(refused(
                        "landing_pr_conflict",
                        "The verified PR is no longer open at the exact frozen head",
                    ));
                }
            }
            return Ok(value);
        }
        if checks
            .contexts
            .iter()
            .any(|c| c.state == CheckState::Failure)
        {
            self.landing_evidence(step, &value, "landing.result", None)
                .await?;
            return Err(refused(
                "landing_checks_failed",
                "A required check explicitly failed",
            ));
        }
        self.park_landing_checks(step, loaded, value, polls + 1)
            .await
    }
    async fn park_landing_checks(
        &mut self,
        step: &Step,
        loaded: &mut Loaded,
        value: Value,
        polls: u32,
    ) -> Result<Value, CapabilityFailure> {
        let next = now_ms().saturating_add(POLL_MS);
        if crate::request_budget::Limits::default()
            .http_calls
            .saturating_sub(self.ctx.budget.usage().http_calls)
            < 12
        {
            return Err(refused(
                "landing_poll_budget_exhausted",
                "Insufficient HTTP headroom remains for another poll and exact landing verification",
            ));
        }
        if self
            .ctx
            .budget
            .remaining()
            .map_err(|e| refused(e.cause, e.resource))?
            < Duration::from_millis(u64::try_from(POLL_MS).unwrap_or(5000)) + Duration::from_secs(2)
        {
            return Err(refused(
                "request_deadline_exhausted",
                "No deadline headroom remains for another required-check poll",
            ));
        }
        let digest = pam_compact::sha256_hex(&crate::flow_recovery::encode(&value)?);
        let changed = loaded
            .session
            .poll
            .as_ref()
            .is_none_or(|p| p.last_digest != digest);
        let id = if changed {
            // Evidence ID is filled by the producer after allocation.
            self.landing_progress(step, &value, polls, next).await?
        } else {
            loaded
                .session
                .poll
                .as_ref()
                .ok_or_else(failure)?
                .last_evidence
                .clone()
        };
        let (profile_stamp, authorization_revision) = self.watch_stamp().await?;
        if self.watch_grant_stamp.as_ref() != Some(&(profile_stamp.clone(), authorization_revision))
        {
            return Err(refused(
                "landing_authorization_changed",
                "The admission or policy profile changed during this poll",
            ));
        }
        loaded.session.poll = Some(Poll {
            step: step.id.clone(),
            polls,
            next_poll_ms: next,
            profile_stamp,
            authorization_revision,
            last_digest: digest,
            last_evidence: id.clone(),
        });
        self.landing_save(loaded).await?;
        self.recovery
            .settle_landing_wait(
                &self.service.store,
                &self.ctx.request_id,
                &id,
                &self.evidence,
            )
            .await?;
        if changed {
            self.publish_note(
                self.reports.len(),
                self.flow.steps.len(),
                format!("{}: required checks pending", step.id),
            )
            .await;
        }
        Err(CapabilityFailure::Parked { resume_at_ms: next })
    }
    async fn landing_progress(
        &mut self,
        step: &Step,
        value: &Value,
        polls: u32,
        next: i64,
    ) -> Result<String, CapabilityFailure> {
        let id = new_evidence_id();
        let bytes = crate::flow_recovery::encode(value)?;
        if bytes.len() > 16 * 1024 {
            return Err(failure());
        }
        let metadata=json!({"watch_progress":{"step":step.id,"connector":"github","status":"pending","watch_state":"pending","polls":polls,"next_poll_at":next,"evidence_id":id,"omissions":0}}).to_string();
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
            .map_err(failed)?;
        crate::evidence_service::publish(
            &self.service.store,
            &self.capture_scope(step).map_err(|_| failure())?,
            &self.ctx.request_id,
            &id,
            view,
            json!({"kind":"landing_checks"}),
        )
        .await
        .map_err(|_| failure())?;
        self.evidence.push(id.clone());
        Ok(id)
    }
}
fn require_predecessor(session: &Session, operation: Op) -> Result<(), CapabilityFailure> {
    let index = Op::ORDER
        .iter()
        .position(|value| *value == operation)
        .ok_or_else(failure)?;
    if index > 0 && !session.receipts.contains_key(key(Op::ORDER[index - 1])) {
        return Err(refused(
            "landing_predecessor_missing",
            "The required prior landing receipt is unavailable",
        ));
    }
    Ok(())
}
fn has_intent(loaded: &Loaded, step: &Step, operation: Op) -> Result<bool, CapabilityFailure> {
    match &loaded.session.intent {
        Some(intent) if intent.step_id == step.id => {
            if intent.operation != operation || intent.state != "prepared" {
                return Err(failure());
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}
fn github_target(loaded: &Loaded) -> Result<Target, CapabilityFailure> {
    Ok(Target {
        repository: loaded.policy.github_repository.clone(),
        head: loaded
            .receipt
            .branch
            .strip_prefix("refs/heads/")
            .ok_or_else(failure)?
            .into(),
        base: loaded.policy.base.clone(),
        head_sha: loaded.receipt.commit.clone(),
    })
}
fn pr_number(loaded: &Loaded) -> Result<u64, CapabilityFailure> {
    loaded
        .session
        .receipts
        .get("ensure_pr")
        .and_then(|v| v["number"].as_u64())
        .filter(|v| *v > 0)
        .ok_or_else(failure)
}
fn checks_op(loaded: &Loaded, main: bool) -> Result<LandingGithubOp, CapabilityFailure> {
    let sha = if main {
        loaded
            .session
            .receipts
            .get("merge")
            .and_then(|v| v["sha"].as_str())
            .ok_or_else(failure)?
            .to_owned()
    } else {
        loaded.receipt.commit.clone()
    };
    Ok(LandingGithubOp::Checks {
        repository: loaded.policy.github_repository.clone(),
        sha,
        required: if main {
            loaded.policy.main_checks.clone()
        } else {
            loaded.policy.required_checks.clone()
        },
    })
}
