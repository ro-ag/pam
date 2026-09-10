//! Credentials remain inside the typed Git broker. Every network spawn calls
//! an owned current-authority guard after local preflight and budget reservation.
use super::{
    Arc, ArgValue, BTreeMap, CallSecret, ConnectorError, ConnectorId, ConnectorRow,
    ConnectorService, Future, Instant, InvokeError, Path, Pin, ScopePolicy, Store, configured_url,
};
use crate::{
    landing_checkout::CheckoutError,
    landing_git::{GitAuthorization, GitTarget, GitTransport, PushObservation, RemoteRef},
    request_budget::RequestBudget,
};
use tokio::sync::watch;

fn denied() -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy { cause:"landing_git_denied", detail:"The current ticket, landing policy or exact Git remote/ref does not authorize this operation.".into() })
}
fn git_error(error: CheckoutError) -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy {
        cause: error.cause,
        detail: error.detail.into(),
    })
}
fn sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
pub(super) struct GitGuard {
    store: Arc<Store>,
    repo: std::path::PathBuf,
    ticket: String,
    revision: String,
    remote: String,
    base: String,
    branch: String,
    source_branch: String,
    workspace: std::path::PathBuf,
    push: bool,
}
impl GitGuard {
    pub(super) fn new(
        store: Arc<Store>,
        repo: &Path,
        ticket: &str,
        revision: &str,
        target: &GitTarget,
        push: bool,
    ) -> Result<Self, InvokeError> {
        let source_branch = target
            .receipt
            .branch
            .strip_prefix("refs/heads/")
            .ok_or_else(denied)?;
        if target.request.repository != repo
            || target.receipt.repository != repo
            || target.request.remote_url != target.receipt.remote_url
            || target.request.base_ref != target.receipt.base_ref
            || target.request.expected_commit != target.receipt.commit
            || !sha(&target.receipt.commit)
            || target.expected_old.as_ref().is_some_and(|oid| !sha(oid))
            || (push && target.branch != source_branch)
        {
            return Err(denied());
        }
        Ok(Self {
            store,
            repo: repo.into(),
            ticket: ticket.into(),
            revision: revision.into(),
            remote: target.request.remote_url.clone(),
            base: target.request.base_ref.clone(),
            branch: target.branch.clone(),
            source_branch: source_branch.to_owned(),
            workspace: target.request.checkouts_root.clone(),
            push,
        })
    }
    pub(super) async fn authorize_row(&self) -> Result<Option<ConnectorRow>, InvokeError> {
        let snapshot = crate::landing_policy::Snapshot::load(&self.store)
            .await
            .map_err(|_| denied())?;
        if snapshot.revision != self.revision {
            return Err(denied());
        }
        let policy = snapshot.repository(&self.repo).map_err(|_| denied())?;
        if policy.repository != self.remote
            || policy.workspace_root != self.workspace
            || self.base != format!("refs/heads/{}", policy.base)
            || !policy.branches.contains(&self.source_branch)
            || (self.branch != policy.base && !policy.branches.contains(&self.branch))
            || (self.push && (!policy.permissions.push || self.branch == policy.base))
        {
            return Err(denied());
        }
        let request = self
            .store
            .request_status_meta(&self.ticket)
            .await?
            .ok_or_else(denied)?;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        if request.state != pam_store::RequestState::Running
            || request.capability != "flow.run"
            || request.repository != self.repo.to_string_lossy()
            || request.authorization_revision != Some(self.store.grant_revocation_revision().await?)
            || self
                .store
                .request_admission_expired(&self.ticket, now)
                .await?
        {
            return Err(denied());
        }
        let scope = ScopePolicy::load(&self.store).await?;
        scope.authorize_repo(&self.repo)?;
        let row = self
            .store
            .get_connector(ConnectorId::Github.as_str())
            .await?;
        if !row.as_ref().is_some_and(|row| row.enabled) {
            return Err(denied());
        }
        let url = configured_url(ConnectorId::Github, row.as_ref())?;
        if url != policy.github_server {
            return Err(denied());
        }
        let args = BTreeMap::from([(
            "repo".into(),
            ArgValue::Text(policy.github_repository.clone()),
        )]);
        scope.authorize_connector(&self.repo, ConnectorId::Github, &url, "runs", &args)?;
        Ok(row)
    }
}
impl GitAuthorization for GitGuard {
    fn authorize(&self) -> Pin<Box<dyn Future<Output = Result<(), CheckoutError>> + Send + '_>> {
        Box::pin(async move {
            self.authorize_row()
                .await
                .map(|_| ())
                .map_err(|_| CheckoutError {
                    cause: "landing_git_denied",
                    detail: "Landing authority changed before Git network execution.",
                })
        })
    }
}
impl ConnectorService {
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep original request identity, policy revision, budget and cancellation explicit"
    )]
    pub(crate) async fn landing_git_observe(
        &self,
        repo: &Path,
        ticket: &str,
        policy_revision: &str,
        target: &GitTarget,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<RemoteRef, InvokeError> {
        let (transport, secret, guard) = self
            .landing_git_context(
                repo,
                ticket,
                policy_revision,
                target,
                Arc::clone(&budget),
                cancel,
                deadline,
                false,
            )
            .await?;
        transport
            .observe_ref(target, &secret, budget, cancel, deadline, guard)
            .await
            .map_err(git_error)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep original request identity, policy revision, budget and cancellation explicit"
    )]
    pub(crate) async fn landing_git_push(
        &self,
        repo: &Path,
        ticket: &str,
        policy_revision: &str,
        target: &GitTarget,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<PushObservation, InvokeError> {
        let (transport, secret, guard) = self
            .landing_git_context(
                repo,
                ticket,
                policy_revision,
                target,
                Arc::clone(&budget),
                cancel,
                deadline,
                true,
            )
            .await?;
        transport
            .push_exact(target, &secret, budget, cancel, deadline, guard)
            .await
            .map_err(git_error)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Broker forwards explicit authorization and execution bounds without exposing credentials"
    )]
    async fn landing_git_context(
        &self,
        repo: &Path,
        ticket: &str,
        revision: &str,
        target: &GitTarget,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
        push: bool,
    ) -> Result<(GitTransport, CallSecret, Arc<dyn GitAuthorization>), InvokeError> {
        let guard = Arc::new(GitGuard::new(
            Arc::clone(&self.store),
            repo,
            ticket,
            revision,
            target,
            push,
        )?);
        guard.authorize_row().await?;
        let transport =
            GitTransport::resolve(&target.request, Arc::clone(&budget), cancel, deadline)
                .await
                .map_err(git_error)?;
        let row = guard.authorize_row().await?;
        if Instant::now() >= deadline.min(budget.deadline())
            || *cancel.borrow()
            || cancel.has_changed().is_err()
        {
            return Err(ConnectorError::Timeout.into());
        }
        let connection = self.connection(ConnectorId::Github, row.as_ref()).await?;
        let secret = connection.secret.ok_or(InvokeError::CredentialMissing)?;
        Ok((transport, secret, guard))
    }
}
