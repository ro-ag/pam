//! Typed GitHub Actions read operations.

use std::{collections::BTreeMap, error::Error, fmt, num::NonZeroU64, time::Duration};

use reqwest::{StatusCode, header};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::{
    BoundedSummary, CapabilityName, Connector, ConnectorDescriptor, ConnectorFailure,
    ConnectorFuture, ConnectorOutput, ExactArtifact, FailureMessage, InvocationContext, Operation,
    OperationCoordinates, OperationEffect, ResourceName, Truth,
};

pub const GITHUB_API_VERSION: &str = "2026-03-10";
pub const MAX_DISCOVERED_RUNS: usize = 100;
pub const MAX_COLLECTED_JOBS: usize = 16;
pub const MAX_JOB_STEPS: usize = 64;
pub const MAX_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_LOG_BYTES_PER_JOB: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_LOG_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LOG_REDIRECTS: usize = 3;

const MAX_REPOSITORY_PART_BYTES: usize = 100;
const MAX_REMOTE_TEXT_BYTES: usize = 2048;
const MAX_TOKEN_BYTES: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A validated GitHub repository coordinate.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Repository {
    owner: String,
    name: String,
}

impl Repository {
    /// Parses `OWNER/REPOSITORY` without accepting path separators or traversal.
    ///
    /// # Errors
    ///
    /// Returns an error for anything other than two bounded GitHub path segments.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, InvalidRepository> {
        let mut parts = value.as_ref().split('/');
        let owner = parts.next().ok_or(InvalidRepository)?;
        let name = parts.next().ok_or(InvalidRepository)?;
        if parts.next().is_some() || !valid_repository_part(owner) || !valid_repository_part(name) {
            return Err(InvalidRepository);
        }
        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn as_coordinate(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    fn api_path(&self) -> String {
        format!("repos/{}/{}/actions", self.owner, self.name)
    }

    fn resource(&self) -> ResourceName {
        ResourceName::parse(format!("github:{}/{}", self.owner, self.name))
            .expect("validated GitHub coordinates fit the policy resource bound")
    }

    fn run_resource(&self, run_id: RunId) -> ResourceName {
        ResourceName::parse(format!(
            "github:{}/{}/runs/{}",
            self.owner,
            self.name,
            run_id.get()
        ))
        .expect("validated GitHub run coordinates fit the policy resource bound")
    }
}

impl fmt::Debug for Repository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_coordinate())
    }
}

impl<'de> Deserialize<'de> for Repository {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Repository {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_coordinate())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRepository;

impl fmt::Display for InvalidRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub repository must be two bounded safe path segments")
    }
}

impl Error for InvalidRepository {}

/// A nonzero GitHub workflow-run identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RunId(NonZeroU64);

impl RunId {
    /// # Errors
    ///
    /// Returns an error when the identifier is zero.
    pub fn new(value: u64) -> Result<Self, InvalidRunId> {
        NonZeroU64::new(value).map(Self).ok_or(InvalidRunId)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRunId;

impl fmt::Display for InvalidRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub run identifier must be nonzero")
    }
}

impl Error for InvalidRunId {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DiscoverRunsRequest {
    repository: Repository,
    limit: usize,
}

impl DiscoverRunsRequest {
    /// # Errors
    ///
    /// Returns an error unless the limit is between one and 100.
    pub fn new(repository: Repository, limit: usize) -> Result<Self, InvalidReadBound> {
        if !(1..=MAX_DISCOVERED_RUNS).contains(&limit) {
            return Err(InvalidReadBound);
        }
        Ok(Self { repository, limit })
    }

    #[must_use]
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    fn validate(&self) -> Result<(), ConnectorFailure> {
        if (1..=MAX_DISCOVERED_RUNS).contains(&self.limit) {
            Ok(())
        } else {
            Err(invalid_request("workflow run discovery limit is invalid"))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollectRunLogsRequest {
    repository: Repository,
    run_id: RunId,
    max_jobs: usize,
    max_log_bytes: usize,
    max_total_log_bytes: usize,
}

impl CollectRunLogsRequest {
    /// Creates explicit job and byte budgets for one exact run.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or SDK-exceeding limits.
    pub fn new(
        repository: Repository,
        run_id: RunId,
        max_jobs: usize,
        max_log_bytes: usize,
        max_total_log_bytes: usize,
    ) -> Result<Self, InvalidReadBound> {
        let request = Self {
            repository,
            run_id,
            max_jobs,
            max_log_bytes,
            max_total_log_bytes,
        };
        request
            .bounds_valid()
            .then_some(request)
            .ok_or(InvalidReadBound)
    }

    #[must_use]
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    fn bounds_valid(&self) -> bool {
        (1..=MAX_COLLECTED_JOBS).contains(&self.max_jobs)
            && (1..=MAX_LOG_BYTES_PER_JOB).contains(&self.max_log_bytes)
            && (self.max_log_bytes..=MAX_TOTAL_LOG_BYTES).contains(&self.max_total_log_bytes)
    }

    fn validate(&self) -> Result<(), ConnectorFailure> {
        self.bounds_valid()
            .then_some(())
            .ok_or_else(|| invalid_request("workflow log collection bounds are invalid"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidReadBound;

impl fmt::Display for InvalidReadBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub read limit exceeds the connector SDK bound")
    }
}

impl Error for InvalidReadBound {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowRun {
    id: RunId,
    #[serde(rename = "run_attempt")]
    attempt: u32,
    name: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
    head_branch: Option<String>,
    head_sha: String,
    created_at: String,
    updated_at: String,
}

impl WorkflowRun {
    #[must_use]
    pub const fn id(&self) -> RunId {
        self.id
    }

    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    #[must_use]
    pub fn conclusion(&self) -> Option<&str> {
        self.conclusion.as_deref()
    }

    #[must_use]
    pub fn html_url(&self) -> &str {
        &self.html_url
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowStep {
    number: u32,
    name: String,
    status: String,
    conclusion: Option<String>,
}

impl WorkflowStep {
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn conclusion(&self) -> Option<&str> {
        self.conclusion.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkflowJob {
    id: u64,
    name: String,
    status: String,
    conclusion: Option<String>,
    html_url: String,
    steps: Vec<WorkflowStep>,
}

impl WorkflowJob {
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn conclusion(&self) -> Option<&str> {
        self.conclusion.as_deref()
    }

    #[must_use]
    pub fn steps(&self) -> &[WorkflowStep] {
        &self.steps
    }

    fn failed(&self) -> bool {
        self.conclusion.as_deref() == Some("failure")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobLog {
    job_id: u64,
    artifact_name: String,
    byte_len: usize,
}

impl JobLog {
    #[must_use]
    pub const fn job_id(&self) -> u64 {
        self.job_id
    }

    #[must_use]
    pub fn artifact_name(&self) -> &str {
        &self.artifact_name
    }

    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoverRunsResponse {
    total_count: u64,
    runs: Vec<WorkflowRun>,
}

impl DiscoverRunsResponse {
    #[must_use]
    pub const fn total_count(&self) -> u64 {
        self.total_count
    }

    #[must_use]
    pub fn runs(&self) -> &[WorkflowRun] {
        &self.runs
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollectRunLogsResponse {
    run: WorkflowRun,
    total_jobs: u64,
    jobs: Vec<WorkflowJob>,
    logs: Vec<JobLog>,
}

impl CollectRunLogsResponse {
    #[must_use]
    pub const fn run(&self) -> &WorkflowRun {
        &self.run
    }

    #[must_use]
    pub const fn total_jobs(&self) -> u64 {
        self.total_jobs
    }

    #[must_use]
    pub fn jobs(&self) -> &[WorkflowJob] {
        &self.jobs
    }

    #[must_use]
    pub fn logs(&self) -> &[JobLog] {
        &self.logs
    }
}

pub struct DiscoverFailedRuns;

impl Operation for DiscoverFailedRuns {
    type Request = DiscoverRunsRequest;
    type Response = DiscoverRunsResponse;

    const EFFECT: OperationEffect = OperationEffect::ReadOnly;

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(capability(), request.repository.resource())
    }
}

pub struct CollectRunLogs;

impl Operation for CollectRunLogs {
    type Request = CollectRunLogsRequest;
    type Response = CollectRunLogsResponse;

    const EFFECT: OperationEffect = OperationEffect::ReadOnly;

    fn coordinates(request: &Self::Request) -> OperationCoordinates {
        OperationCoordinates::new(
            capability(),
            request.repository.run_resource(request.run_id),
        )
    }
}

/// GitHub Actions connector over an injected bounded HTTP transport.
pub struct GitHubActions<T> {
    api_base: Url,
    transport: T,
}

impl<T> GitHubActions<T> {
    /// # Errors
    ///
    /// Returns an error unless the API base is a credential-free HTTPS hierarchy.
    pub fn new(api_base: Url, transport: T) -> Result<Self, InvalidGitHubConfiguration> {
        validate_https_url(&api_base, true)?;
        Ok(Self {
            api_base: normalized_base(api_base),
            transport,
        })
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    fn api_request(
        &self,
        path: &str,
        response_limit: usize,
    ) -> Result<TransportRequest, ConnectorFailure> {
        let url = self
            .api_base
            .join(path)
            .map_err(|_| invalid_request("GitHub API request path is invalid"))?;
        Ok(TransportRequest {
            url,
            authenticated: true,
            response_limit,
        })
    }
}

impl<T: GitHubTransport> Connector<DiscoverFailedRuns> for GitHubActions<T> {
    fn descriptor(&self) -> ConnectorDescriptor {
        descriptor()
    }

    fn execute(
        &self,
        request: DiscoverRunsRequest,
        context: InvocationContext,
    ) -> ConnectorFuture<'_, crate::ConnectorResult<DiscoverRunsResponse>> {
        Box::pin(async move {
            context.preflight(OperationEffect::ReadOnly)?;
            request.validate()?;
            let path = format!(
                "{}/runs?status=failure&per_page={}",
                request.repository.api_path(),
                request.limit
            );
            let response = self
                .transport
                .get(self.api_request(&path, MAX_JSON_BYTES)?, &context)
                .await?;
            require_status(&response, StatusCode::OK)?;
            let mut envelope: RunsEnvelope = parse_json(&response.body)?;
            if envelope.workflow_runs.len() > request.limit {
                return Err(remote_failure(
                    "GitHub returned more workflow runs than requested",
                ));
            }
            for run in &envelope.workflow_runs {
                validate_run(run)?;
            }
            envelope.workflow_runs.sort_by_key(|run| run.id);
            let count = envelope.workflow_runs.len();
            let output = DiscoverRunsResponse {
                total_count: envelope.total_count,
                runs: envelope.workflow_runs,
            };
            ConnectorOutput::new(
                output,
                summary(format!("found {count} failed GitHub Actions runs"))?,
                Truth::Complete,
                Vec::new(),
                Vec::new(),
            )
            .map_err(|_| remote_failure("GitHub discovery output exceeded SDK bounds"))
        })
    }
}

impl<T: GitHubTransport> Connector<CollectRunLogs> for GitHubActions<T> {
    fn descriptor(&self) -> ConnectorDescriptor {
        descriptor()
    }

    fn execute(
        &self,
        request: CollectRunLogsRequest,
        context: InvocationContext,
    ) -> ConnectorFuture<'_, crate::ConnectorResult<CollectRunLogsResponse>> {
        Box::pin(async move {
            context.preflight(OperationEffect::ReadOnly)?;
            request.validate()?;
            let root = request.repository.api_path();
            let run_path = format!("{root}/runs/{}", request.run_id.get());
            let run_response = self
                .transport
                .get(self.api_request(&run_path, MAX_JSON_BYTES)?, &context)
                .await?;
            require_status(&run_response, StatusCode::OK)?;
            let run: WorkflowRun = parse_json(&run_response.body)?;
            validate_run(&run)?;
            if run.id != request.run_id {
                return Err(remote_failure("GitHub returned a different workflow run"));
            }

            let jobs_path = format!(
                "{root}/runs/{}/attempts/{}/jobs?per_page={}",
                run.id.get(),
                run.attempt,
                request.max_jobs
            );
            let jobs_response = self
                .transport
                .get(self.api_request(&jobs_path, MAX_JSON_BYTES)?, &context)
                .await?;
            require_status(&jobs_response, StatusCode::OK)?;
            let mut envelope: JobsEnvelope = parse_json(&jobs_response.body)?;
            if envelope.jobs.len() > request.max_jobs {
                return Err(remote_failure("GitHub returned more jobs than requested"));
            }
            for job in &envelope.jobs {
                validate_job(job)?;
            }
            envelope.jobs.sort_by_key(|job| job.id);

            let mut partial_reasons = Vec::new();
            if envelope.total_count > envelope.jobs.len() as u64 {
                partial_reasons.push("job list exceeded the configured job limit".to_owned());
            }
            let mut total_log_bytes = 0_usize;
            let mut logs = Vec::new();
            let mut artifacts = Vec::new();
            for job in envelope.jobs.iter().filter(|job| job.failed()) {
                if context.cancellation().is_cancelled() || context.remaining().is_none() {
                    return context.preflight(OperationEffect::ReadOnly).and_then(|()| {
                        Err(remote_failure("GitHub log collection stopped unexpectedly"))
                    });
                }
                let remaining = request.max_total_log_bytes.saturating_sub(total_log_bytes);
                if remaining == 0 {
                    partial_reasons.push("aggregate log byte limit was reached".to_owned());
                    break;
                }
                let limit = request.max_log_bytes.min(remaining);
                let log_path = format!("{root}/jobs/{}/logs", job.id);
                match self.collect_log(&log_path, limit, &context).await {
                    Ok(bytes) => {
                        total_log_bytes = total_log_bytes.saturating_add(bytes.len());
                        let artifact_name =
                            format!("github-run-{}-job-{}.log", request.run_id.get(), job.id);
                        let artifact = ExactArtifact::new(artifact_name.clone(), bytes)
                            .map_err(|_| remote_failure("GitHub log exceeded SDK bounds"))?;
                        logs.push(JobLog {
                            job_id: job.id,
                            artifact_name,
                            byte_len: artifact.bytes().len(),
                        });
                        artifacts.push(artifact);
                    }
                    Err(failure) => partial_reasons.push(format!(
                        "job {} log unavailable ({:?})",
                        job.id,
                        failure.kind()
                    )),
                }
            }

            let failed_jobs = envelope.jobs.iter().filter(|job| job.failed()).count();
            if logs.len() < failed_jobs && partial_reasons.is_empty() {
                partial_reasons.push("one or more failed job logs were unavailable".to_owned());
            }
            let truth = truth_from_reasons(&partial_reasons)?;
            let collected = logs.len();
            let output = CollectRunLogsResponse {
                run,
                total_jobs: envelope.total_count,
                jobs: envelope.jobs,
                logs,
            };
            ConnectorOutput::new(
                output,
                summary(format!(
                    "collected {collected} of {failed_jobs} failed GitHub Actions job logs"
                ))?,
                truth,
                Vec::new(),
                artifacts,
            )
            .map_err(|_| remote_failure("GitHub log output exceeded SDK bounds"))
        })
    }
}

impl<T: GitHubTransport> GitHubActions<T> {
    async fn collect_log(
        &self,
        api_path: &str,
        response_limit: usize,
        context: &InvocationContext,
    ) -> Result<Vec<u8>, ConnectorFailure> {
        let response = self
            .transport
            .get(self.api_request(api_path, 0)?, context)
            .await?;
        if !is_redirect(response.status) {
            require_status(&response, StatusCode::OK)?;
            return Ok(response.body);
        }
        let mut location = response
            .header("location")
            .ok_or_else(|| remote_failure("GitHub log redirect omitted its destination"))?
            .to_owned();
        for _ in 0..MAX_LOG_REDIRECTS {
            let url = Url::parse(&location)
                .map_err(|_| remote_failure("GitHub log redirect was invalid"))?;
            validate_https_url(&url, false)
                .map_err(|_| remote_failure("GitHub log redirect was not safe HTTPS"))?;
            let response = self
                .transport
                .get(
                    TransportRequest {
                        url,
                        authenticated: false,
                        response_limit,
                    },
                    context,
                )
                .await?;
            if response.status == StatusCode::OK.as_u16() {
                return Ok(response.body);
            }
            if !is_redirect(response.status) {
                require_status(&response, StatusCode::OK)?;
            }
            response
                .header("location")
                .ok_or_else(|| remote_failure("GitHub log redirect omitted its destination"))?
                .clone_into(&mut location);
        }
        Err(remote_failure("GitHub log redirect limit was exceeded"))
    }
}

#[derive(Deserialize)]
struct RunsEnvelope {
    total_count: u64,
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Deserialize)]
struct JobsEnvelope {
    total_count: u64,
    jobs: Vec<WorkflowJob>,
}

/// Transport request kept crate-visible for deterministic connector tests.
pub struct TransportRequest {
    url: Url,
    authenticated: bool,
    response_limit: usize,
}

impl TransportRequest {
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.authenticated
    }

    #[must_use]
    pub const fn response_limit(&self) -> usize {
        self.response_limit
    }
}

/// Bounded HTTP response kept crate-visible for deterministic connector tests.
pub struct TransportResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl TransportResponse {
    pub fn new(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

pub trait GitHubTransport: Send + Sync {
    fn get<'a>(
        &'a self,
        request: TransportRequest,
        context: &'a InvocationContext,
    ) -> ConnectorFuture<'a, Result<TransportResponse, ConnectorFailure>>;
}

/// Production transport with native rustls verification, system proxy support, and no redirects.
pub struct ReqwestGitHubTransport {
    client: reqwest::Client,
    token: Option<String>,
}

impl ReqwestGitHubTransport {
    /// # Errors
    ///
    /// Returns a sanitized error when the token or secure HTTP client is invalid.
    pub fn new(token: Option<String>) -> Result<Self, InvalidGitHubConfiguration> {
        if token.as_ref().is_some_and(|token| {
            token.is_empty() || token.len() > MAX_TOKEN_BYTES || token.chars().any(char::is_control)
        }) {
            return Err(InvalidGitHubConfiguration);
        }
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| InvalidGitHubConfiguration)?;
        Ok(Self { client, token })
    }
}

impl fmt::Debug for ReqwestGitHubTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReqwestGitHubTransport")
            .field("authenticated", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

impl GitHubTransport for ReqwestGitHubTransport {
    fn get<'a>(
        &'a self,
        request: TransportRequest,
        context: &'a InvocationContext,
    ) -> ConnectorFuture<'a, Result<TransportResponse, ConnectorFailure>> {
        Box::pin(async move {
            context.preflight(OperationEffect::ReadOnly)?;
            let remaining = context.remaining().ok_or_else(ConnectorFailure::timeout)?;
            let mut builder = self
                .client
                .get(request.url)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header(header::USER_AGENT, "pam/0.1.0")
                .header("x-github-api-version", GITHUB_API_VERSION)
                .timeout(remaining.min(REQUEST_TIMEOUT));
            if request.authenticated
                && let Some(token) = &self.token
            {
                builder = builder.bearer_auth(token);
            }
            let mut response = builder
                .send()
                .await
                .map_err(|error| map_reqwest_failure(&error))?;
            let status = response.status().as_u16();
            let mut headers = BTreeMap::new();
            for name in [
                header::LOCATION.as_str(),
                header::RETRY_AFTER.as_str(),
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
            ] {
                if let Some(value) = response.headers().get(name)
                    && let Ok(value) = value.to_str()
                    && value.len() <= MAX_REMOTE_TEXT_BYTES
                    && !value.chars().any(char::is_control)
                {
                    headers.insert(name.to_owned(), value.to_owned());
                }
            }
            if request.response_limit == 0 {
                return Ok(TransportResponse {
                    status,
                    headers,
                    body: Vec::new(),
                });
            }
            if response
                .content_length()
                .is_some_and(|length| length > request.response_limit as u64)
            {
                return Err(ConnectorFailure::response_too_large(request.response_limit));
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| map_reqwest_failure(&error))?
            {
                context.preflight(OperationEffect::ReadOnly)?;
                if body.len().saturating_add(chunk.len()) > request.response_limit {
                    return Err(ConnectorFailure::response_too_large(request.response_limit));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(TransportResponse {
                status,
                headers,
                body,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGitHubConfiguration;

impl fmt::Display for InvalidGitHubConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GitHub connector configuration is invalid")
    }
}

impl Error for InvalidGitHubConfiguration {}

fn descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor::new("github.actions", "rest-2026-03-10")
        .expect("static GitHub connector descriptor is valid")
}

fn capability() -> CapabilityName {
    CapabilityName::parse("runs.inspect").expect("static GitHub capability is valid")
}

fn summary(value: String) -> Result<BoundedSummary, ConnectorFailure> {
    BoundedSummary::new(value)
        .map_err(|_| remote_failure("GitHub connector summary exceeded SDK bounds"))
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ConnectorFailure> {
    serde_json::from_slice(bytes)
        .map_err(|_| remote_failure("GitHub returned malformed JSON metadata"))
}

fn require_status(
    response: &TransportResponse,
    expected: StatusCode,
) -> Result<(), ConnectorFailure> {
    if response.status == expected.as_u16() {
        return Ok(());
    }
    let message = safe_message("GitHub API request failed");
    match response.status {
        401 => Err(ConnectorFailure::authentication(message)),
        403 if response.header("x-ratelimit-remaining") == Some("0") => {
            Err(ConnectorFailure::rate_limit(message, retry_delay(response)))
        }
        403 => Err(ConnectorFailure::forbidden(message)),
        404 => Err(ConnectorFailure::not_found(message)),
        429 => Err(ConnectorFailure::rate_limit(message, retry_delay(response))),
        500..=599 => Err(ConnectorFailure::remote(message, true)),
        _ => Err(ConnectorFailure::remote(message, false)),
    }
}

fn retry_delay(response: &TransportResponse) -> Option<Duration> {
    response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.min(24 * 60 * 60)))
}

fn map_reqwest_failure(error: &reqwest::Error) -> ConnectorFailure {
    if error.is_timeout() {
        ConnectorFailure::timeout()
    } else if error.is_connect() {
        ConnectorFailure::network(safe_message("GitHub network connection failed"))
    } else {
        ConnectorFailure::remote(safe_message("GitHub HTTP request failed"), true)
    }
}

fn validate_run(run: &WorkflowRun) -> Result<(), ConnectorFailure> {
    if run.attempt == 0
        || !valid_remote_text(&run.name)
        || !valid_remote_text(&run.status)
        || run
            .conclusion
            .as_deref()
            .is_some_and(|value| !valid_remote_text(value))
        || !valid_https_text(&run.html_url)
        || run
            .head_branch
            .as_deref()
            .is_some_and(|value| !valid_remote_text(value))
        || !valid_remote_text(&run.head_sha)
        || !valid_remote_text(&run.created_at)
        || !valid_remote_text(&run.updated_at)
    {
        return Err(remote_failure("GitHub workflow run metadata was invalid"));
    }
    Ok(())
}

fn validate_job(job: &WorkflowJob) -> Result<(), ConnectorFailure> {
    if job.id == 0
        || !valid_remote_text(&job.name)
        || !valid_remote_text(&job.status)
        || job
            .conclusion
            .as_deref()
            .is_some_and(|value| !valid_remote_text(value))
        || !valid_https_text(&job.html_url)
        || job.steps.len() > MAX_JOB_STEPS
        || job.steps.iter().any(|step| {
            !valid_remote_text(&step.name)
                || !valid_remote_text(&step.status)
                || step
                    .conclusion
                    .as_deref()
                    .is_some_and(|value| !valid_remote_text(value))
        })
    {
        return Err(remote_failure("GitHub workflow job metadata was invalid"));
    }
    Ok(())
}

fn valid_remote_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REMOTE_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_https_text(value: &str) -> bool {
    value.len() <= MAX_REMOTE_TEXT_BYTES
        && Url::parse(value)
            .ok()
            .is_some_and(|url| validate_https_url(&url, false).is_ok())
}

fn validate_https_url(url: &Url, require_base: bool) -> Result<(), InvalidGitHubConfiguration> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (require_base && url.query().is_some())
        || url.fragment().is_some()
        || (require_base && url.cannot_be_a_base())
    {
        return Err(InvalidGitHubConfiguration);
    }
    Ok(())
}

fn normalized_base(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

fn valid_repository_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REPOSITORY_PART_BYTES
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn invalid_request(message: &str) -> ConnectorFailure {
    ConnectorFailure::invalid_request(safe_message(message))
}

fn remote_failure(message: &str) -> ConnectorFailure {
    ConnectorFailure::remote(safe_message(message), false)
}

fn truth_from_reasons(reasons: &[String]) -> Result<Truth, ConnectorFailure> {
    if reasons.is_empty() {
        Ok(Truth::Complete)
    } else {
        Ok(Truth::Partial {
            reason: summary(reasons.join("; "))?,
        })
    }
}

fn safe_message(value: &str) -> FailureMessage {
    FailureMessage::new(value).expect("static GitHub failure message is valid")
}
