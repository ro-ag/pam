//! Private typed landing bridge; ordinary connector scopes cannot mutate.
use super::{
    Arc, ArgValue, BTreeMap, Connection, ConnectorError, ConnectorId, ConnectorRow,
    ConnectorService, Future, HttpRequest, HttpResponse, HttpTransport, Instant, InvokeError, Path,
    Pin, TransportError, configured_url,
};
use pam_connectors::{
    Method,
    github_landing::{self, Target},
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone)]
pub(crate) enum LandingGithubOp {
    FindPr(Target),
    ReadPr(Target, u64),
    CreatePr(Target, String),
    MergePr(Target, u64),
    Checks {
        repository: String,
        sha: String,
        required: Vec<String>,
    },
}
fn denied() -> InvokeError {
    InvokeError::Connector(ConnectorError::Policy { cause: "landing_github_denied", detail: "The current landing recipe, ticket or exact GitHub target does not authorize this operation.".into() })
}
fn full_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
impl LandingGithubOp {
    fn repository(&self) -> &str {
        match self {
            Self::FindPr(t) | Self::ReadPr(t, _) | Self::CreatePr(t, _) | Self::MergePr(t, _) => {
                &t.repository
            }
            Self::Checks { repository, .. } => repository,
        }
    }
    fn authorize(&self, policy: &crate::landing_policy::Repository) -> Result<(), InvokeError> {
        if self.repository() != policy.github_repository {
            return Err(denied());
        }
        match self {
            Self::Checks { sha, required, .. } => {
                if !full_sha(sha)
                    || required.is_empty()
                    || (required != &policy.required_checks && required != &policy.main_checks)
                {
                    return Err(denied());
                }
            }
            Self::FindPr(t) | Self::ReadPr(t, _) | Self::CreatePr(t, _) | Self::MergePr(t, _) => {
                if t.base != policy.base
                    || !policy.branches.contains(&t.head)
                    || !full_sha(&t.head_sha)
                {
                    return Err(denied());
                }
            }
        }
        match self {
            Self::CreatePr(_, title)
                if !policy.permissions.create_pr
                    || title.is_empty()
                    || title.len() > 256
                    || title.chars().any(char::is_control) =>
            {
                Err(denied())
            }
            Self::MergePr(_, number) if !policy.permissions.merge || *number == 0 => Err(denied()),
            Self::ReadPr(_, 0) => Err(denied()),
            _ => Ok(()),
        }
    }
    async fn execute(
        &self,
        connection: &Connection,
        transport: &dyn HttpTransport,
        deadline: Instant,
    ) -> Result<Value, InvokeError> {
        let value = match self {
            Self::FindPr(target) => serde_json::to_value(
                github_landing::find_pull_request(connection, target, transport, deadline).await?,
            ),
            Self::ReadPr(target, number) => serde_json::to_value(
                github_landing::read_pull_request(connection, target, *number, transport, deadline)
                    .await?,
            ),
            Self::CreatePr(target, title) => serde_json::to_value(
                github_landing::create_pull_request(connection, target, title, transport, deadline)
                    .await?,
            ),
            Self::MergePr(target, number) => serde_json::to_value(
                github_landing::merge_pull_request(
                    connection, target, *number, transport, deadline,
                )
                .await?,
            ),
            Self::Checks {
                repository,
                sha,
                required,
            } => serde_json::to_value(
                github_landing::required_checks(
                    connection, repository, sha, required, transport, deadline,
                )
                .await?,
            ),
        };
        value.map_err(|_| denied())
    }
}
impl ConnectorService {
    /// Caller separately gates and journals mutations; this bridge grants nothing.
    pub(crate) async fn landing_github(
        &self,
        repo: &Path,
        ticket: &str,
        policy_revision: &str,
        op: &LandingGithubOp,
        budget: Arc<crate::request_budget::RequestBudget>,
        deadline: Instant,
    ) -> Result<Value, InvokeError> {
        let row = self
            .authorize_landing_github(repo, ticket, policy_revision, op)
            .await?;
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
        let transport = LandingTransport {
            service: self,
            repo,
            ticket,
            revision: policy_revision,
            op,
            server: connection.base_url.to_string(),
            expected: expected_requests(&connection, op)?,
            next: AtomicUsize::new(0),
            budget,
        };
        op.execute(&connection, &transport, deadline).await
    }
    async fn authorize_landing_github(
        &self,
        repo: &Path,
        ticket: &str,
        revision: &str,
        op: &LandingGithubOp,
    ) -> Result<Option<ConnectorRow>, InvokeError> {
        let snapshot = crate::landing_policy::Snapshot::load(&self.store)
            .await
            .map_err(|_| denied())?;
        if snapshot.revision != revision {
            return Err(denied());
        }
        let policy = snapshot.repository(repo).map_err(|_| denied())?;
        op.authorize(policy)?;
        let request = self
            .store
            .request_status_meta(ticket)
            .await?
            .ok_or_else(denied)?;
        let current = self.store.grant_revocation_revision().await?;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        if request.state != pam_store::RequestState::Running
            || request.capability != "flow.run"
            || request.repository != repo.to_string_lossy()
            || request.authorization_revision != Some(current)
            || self.store.request_admission_expired(ticket, now).await?
        {
            return Err(denied());
        }
        let args = BTreeMap::from([("repo".into(), ArgValue::Text(op.repository().into()))]);
        let row = self
            .scoped_row(repo, ConnectorId::Github, "runs", &args)
            .await?;
        if configured_url(ConnectorId::Github, row.as_ref())? != policy.github_server {
            return Err(denied());
        }
        Ok(row)
    }
}
struct Expected {
    method: Method,
    url: String,
    body: Option<Value>,
}
fn expected_requests(
    connection: &Connection,
    op: &LandingGithubOp,
) -> Result<Vec<Expected>, InvokeError> {
    let (owner, name) = op.repository().split_once('/').ok_or_else(denied)?;
    let make =
        |tail: &[&str], query: &[(&str, &str)], method, body| -> Result<Expected, InvokeError> {
            let mut url = connection.base_url.clone();
            url.path_segments_mut()
                .map_err(|()| denied())?
                .pop_if_empty()
                .extend(["repos", owner, name])
                .extend(tail.iter().copied());
            if !query.is_empty() {
                url.query_pairs_mut().extend_pairs(query.iter().copied());
            }
            Ok(Expected {
                method,
                url: url.to_string(),
                body,
            })
        };
    Ok(match op {
        LandingGithubOp::FindPr(t) => vec![make(
            &["pulls"],
            &[
                ("state", "all"),
                ("head", &format!("{owner}:{}", t.head)),
                ("base", &t.base),
                ("per_page", "100"),
            ],
            Method::Get,
            None,
        )?],
        LandingGithubOp::ReadPr(_, number) => vec![make(
            &["pulls", &number.to_string()],
            &[],
            Method::Get,
            None,
        )?],
        LandingGithubOp::CreatePr(t, title) => vec![make(
            &["pulls"],
            &[],
            Method::Post,
            Some(json!({"head":t.head,"base":t.base,"title":title,"maintainer_can_modify":false})),
        )?],
        LandingGithubOp::MergePr(t, number) => vec![make(
            &["pulls", &number.to_string(), "merge"],
            &[],
            Method::Put,
            Some(json!({"sha":t.head_sha,"merge_method":"squash"})),
        )?],
        LandingGithubOp::Checks { sha, .. } => vec![
            make(
                &["commits", sha, "check-runs"],
                &[("per_page", "100"), ("filter", "latest")],
                Method::Get,
                None,
            )?,
            make(
                &["commits", sha, "status"],
                &[("per_page", "100")],
                Method::Get,
                None,
            )?,
        ],
    })
}
struct LandingTransport<'a> {
    service: &'a ConnectorService,
    repo: &'a Path,
    ticket: &'a str,
    revision: &'a str,
    op: &'a LandingGithubOp,
    server: String,
    expected: Vec<Expected>,
    next: AtomicUsize,
    budget: Arc<crate::request_budget::RequestBudget>,
}
impl HttpTransport for LandingTransport<'_> {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>> {
        Box::pin(async move {
            let refuse = || TransportError::Policy {
                cause: "landing_github_denied",
                detail: "Landing HTTP request exceeds its exact authorized operation.".into(),
            };
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            let expected = self.expected.get(index).ok_or_else(refuse)?;
            let body = match &request.body {
                Some(bytes) if bytes.len() <= 16 * 1024 => {
                    Some(serde_json::from_slice::<Value>(bytes).map_err(|_| refuse())?)
                }
                Some(_) => return Err(refuse()),
                None => None,
            };
            if request.url.as_str() != expected.url
                || request.method != expected.method
                || body != expected.body
                || request.max_bytes > 1024 * 1024
                || request.follow_one_https_redirect_without_auth
            {
                return Err(refuse());
            }
            let row = self
                .service
                .authorize_landing_github(self.repo, self.ticket, self.revision, self.op)
                .await
                .map_err(|_| refuse())?;
            if configured_url(ConnectorId::Github, row.as_ref()).map_err(|_| refuse())?
                != self.server
            {
                return Err(refuse());
            }
            let response = crate::request_budget::BudgetTransport {
                inner: self.service.transport.as_ref(),
                budget: Arc::clone(&self.budget),
            }
            .send(request, deadline)
            .await?;
            if (300..400).contains(&response.status) {
                return Err(TransportError::Policy {
                    cause: "mutation_redirect_refused",
                    detail: "Landing redirects are refused; reconcile the original operation."
                        .into(),
                });
            }
            Ok(response)
        })
    }
}
