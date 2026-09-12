//! Credentials remain inside the typed Git broker. Every network spawn calls
//! an owned current-authority guard after local preflight and budget reservation.
use super::{
    Arc, ArgValue, BTreeMap, CallSecret, ConnectorError, ConnectorId, ConnectorRow,
    ConnectorService, Future, Instant, InvokeError, Path, Pin, ScopePolicy, Store, configured_url,
};
use crate::{
    landing_checkout::CheckoutError,
    landing_git::{
        GitAuthorization, GitTarget, GitTransport, PushObservation, RemoteRef, SyncObservation,
    },
    landing_pack::{self, PackBounds, PackLimits},
    request_budget::RequestBudget,
};
use pam_connectors::{HttpRequest, HttpTransport, Method, Url};
use tokio::sync::watch;

/// What a Git broker call may do; each role has its own policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitRole {
    /// Read one remote ref.
    Observe,
    /// Push the frozen head to its own feature branch.
    Push,
    /// Fetch and install the merge commit on the base branch.
    Sync,
}
/// Bounds every synchronization pack must prove before Git indexes it.
pub(crate) const SYNC_PACK_LIMITS: PackLimits = PackLimits {
    max_objects: 16_384,
    max_object_bytes: 4 * 1024 * 1024,
    max_expanded_bytes: 64 * 1024 * 1024,
};
/// The most compressed pack bytes the transport accepts.
const SYNC_PACK_MAX_BYTES: u64 = 64 * 1024 * 1024;

fn denied() -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy { cause:"landing_git_denied", detail:"The current ticket, landing policy or exact Git remote/ref does not authorize this operation.".into() })
}
fn git_error(error: CheckoutError) -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy {
        cause: error.cause,
        detail: error.detail.into(),
    })
}
fn pack_error(error: landing_pack::PackError) -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy {
        cause: error.cause,
        detail: error.detail,
    })
}
/// `<remote>/git-upload-pack` for the exact approved HTTPS remote.
fn upload_pack_url(remote_url: &str) -> Result<Url, InvokeError> {
    let canonical = pam_flow::canonical_repository_url(remote_url).map_err(|_| denied())?;
    if canonical != remote_url {
        return Err(denied());
    }
    let mut url = Url::parse(remote_url).map_err(|_| denied())?;
    if url.scheme() != "https" || url.query().is_some() || url.fragment().is_some() {
        return Err(denied());
    }
    let path = format!("{}/git-upload-pack", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
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
    role: GitRole,
}
impl GitGuard {
    pub(super) fn new(
        store: Arc<Store>,
        repo: &Path,
        ticket: &str,
        revision: &str,
        target: &GitTarget,
        role: GitRole,
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
            || (role == GitRole::Push && target.branch != source_branch)
            || (role == GitRole::Sync
                && (target.request.base_ref != format!("refs/heads/{}", target.branch)
                    || target.expected_old.is_none()))
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
            role,
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
            || (self.role == GitRole::Push
                && (!policy.permissions.push || self.branch == policy.base))
            || (self.role == GitRole::Sync
                && (!policy.permissions.sync || self.branch != policy.base))
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
                GitRole::Observe,
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
                GitRole::Push,
            )
            .await?;
        transport
            .push_exact(target, &secret, budget, cancel, deadline, guard)
            .await
            .map_err(git_error)
    }
    /// Fetches the synchronization pack for `merge_commit` through the fixed
    /// HTTP broker (never Git) and proves its bounds before returning it.
    /// `haves` name commits the canonical repository already holds, so the
    /// server sends a thin pack of only what is new.
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep original request identity, policy revision, budget and bounds explicit"
    )]
    pub(crate) async fn landing_fetch_pack(
        &self,
        repo: &Path,
        ticket: &str,
        policy_revision: &str,
        target: &GitTarget,
        merge_commit: &str,
        haves: &[&str],
        budget: Arc<RequestBudget>,
        deadline: Instant,
    ) -> Result<(Vec<u8>, PackBounds), InvokeError> {
        let guard = GitGuard::new(
            Arc::clone(&self.store),
            repo,
            ticket,
            policy_revision,
            target,
            GitRole::Sync,
        )?;
        let row = guard.authorize_row().await?;
        let body = landing_pack::upload_pack_request(merge_commit, haves).map_err(pack_error)?;
        budget.attempt_persisted().await.map_err(|error| {
            InvokeError::Connector(ConnectorError::Policy {
                cause: error.cause,
                detail: error.to_string(),
            })
        })?;
        if Instant::now() >= deadline.min(budget.deadline()) {
            return Err(ConnectorError::Timeout.into());
        }
        self.ensure_transport(ConnectorId::Github)?;
        let connection = self.connection(ConnectorId::Github, row.as_ref()).await?;
        let secret = connection.secret.ok_or(InvokeError::CredentialMissing)?;
        let url = upload_pack_url(&target.request.remote_url)?;
        let request = HttpRequest {
            method: Method::Post,
            body: Some(body),
            url,
            headers: vec![
                (
                    "Authorization".into(),
                    format!("Basic {}", crate::landing_git::basic_token(secret.expose())),
                ),
                (
                    "Content-Type".into(),
                    "application/x-git-upload-pack-request".into(),
                ),
                (
                    "Accept".into(),
                    "application/x-git-upload-pack-result".into(),
                ),
            ],
            max_bytes: SYNC_PACK_MAX_BYTES,
            follow_one_https_redirect_without_auth: false,
        };
        // Authority is rechecked immediately before the credential leaves.
        guard.authorize_row().await?;
        let response = crate::request_budget::BudgetTransport {
            inner: self.transport.as_ref(),
            budget,
        }
        .send(request, deadline)
        .await
        .map_err(ConnectorError::from)?;
        if response.status != 200 {
            return Err(InvokeError::Connector(ConnectorError::Policy {
                cause: "landing_sync_remote_error",
                detail: format!(
                    "the Git server answered the pack request with HTTP {}",
                    response.status
                ),
            }));
        }
        let pack = landing_pack::strip_upload_pack_preamble(&response.body).map_err(pack_error)?;
        let bounds = landing_pack::preflight_pack(pack, SYNC_PACK_LIMITS).map_err(pack_error)?;
        Ok((pack.to_vec(), bounds))
    }
    /// Installs a preflighted pack and fast-forwards the base ref; see
    /// [`GitTransport::sync_exact`].
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep original request identity, policy revision, budget and cancellation explicit"
    )]
    pub(crate) async fn landing_git_sync(
        &self,
        repo: &Path,
        ticket: &str,
        policy_revision: &str,
        target: &GitTarget,
        merge_commit: &str,
        pack: Vec<u8>,
        bounds: PackBounds,
        budget: Arc<RequestBudget>,
        cancel: &mut watch::Receiver<bool>,
        deadline: Instant,
    ) -> Result<SyncObservation, InvokeError> {
        let (transport, _secret, guard) = self
            .landing_git_context(
                repo,
                ticket,
                policy_revision,
                target,
                Arc::clone(&budget),
                cancel,
                deadline,
                GitRole::Sync,
            )
            .await?;
        transport
            .sync_exact(
                target,
                merge_commit,
                pack,
                bounds,
                budget,
                cancel,
                deadline,
                guard,
            )
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
        role: GitRole,
    ) -> Result<(GitTransport, CallSecret, Arc<dyn GitAuthorization>), InvokeError> {
        let guard = Arc::new(GitGuard::new(
            Arc::clone(&self.store),
            repo,
            ticket,
            revision,
            target,
            role,
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
