use std::{
    collections::VecDeque,
    env,
    error::Error,
    fmt, fs,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pam_core::{ApprovalId, CallerCredential, CallerId, GrantId, IdempotencyKey, ProjectId};
use pam_policy::{ApprovalRequirement, Effect, Grant, ResourceScope};
use pam_store::{
    ApprovalDecision, ApprovalDecisionOutcome, AuthorizationOutcome, AuthorizationRequest,
    PutGrant, Store,
};
use url::Url;

use super::{
    CancellationToken, Connector, EffectApproval, FailureKind, InvocationContext, Operation,
    RetryGuidance,
};
use crate::github::{
    CollectRunLogs, CollectRunLogsRequest, DiscoverFailedRuns, DiscoverRunsRequest, GitHubActions,
    GitHubTransport, MAX_DISCOVERED_RUNS, MAX_JOB_STEPS, MAX_LOG_BYTES_PER_JOB,
    MAX_MUTATION_RESPONSE_BYTES, Repository, ReqwestGitHubTransport, RerunDisposition,
    RerunFailedJobs, RerunFailedJobsRequest, RunId, TransportRequest, TransportResponse,
    classify_transport_failure, rate_limit_delay_at,
};

#[derive(Debug)]
struct SyntheticTransportError(&'static str);

impl fmt::Display for SyntheticTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for SyntheticTransportError {}

static NEXT_APPROVAL_FIXTURE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum TestApprovalState {
    Requested,
    Approved,
    Denied,
    Expired,
}

struct ApprovalFixture {
    approval: EffectApproval,
    store: Store,
    root: PathBuf,
}

impl ApprovalFixture {
    async fn close(self) {
        let Self {
            approval,
            store,
            root,
        } = self;
        drop(approval);
        store.shutdown().await.unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

#[derive(Debug)]
struct SeenRequest {
    method: &'static str,
    url: String,
    authenticated: bool,
    response_limit: usize,
}

enum Reply {
    Response(TransportResponse),
    Failure(super::ConnectorFailure),
}

struct FakeTransport {
    replies: Mutex<VecDeque<Reply>>,
    seen: Mutex<Vec<SeenRequest>>,
}

impl FakeTransport {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into_iter().collect()),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<SeenRequest> {
        self.seen
            .lock()
            .expect("seen request lock must not be poisoned")
            .drain(..)
            .collect()
    }

    fn is_empty(&self) -> bool {
        self.replies
            .lock()
            .expect("reply lock must not be poisoned")
            .is_empty()
    }

    fn perform<'a>(
        &'a self,
        method: &'static str,
        request: TransportRequest,
    ) -> super::ConnectorFuture<'a, Result<TransportResponse, super::ConnectorFailure>> {
        Box::pin(async move {
            self.seen
                .lock()
                .expect("seen request lock must not be poisoned")
                .push(SeenRequest {
                    method,
                    url: request.url().as_str().to_owned(),
                    authenticated: request.authenticated(),
                    response_limit: request.response_limit(),
                });
            match self
                .replies
                .lock()
                .expect("reply lock must not be poisoned")
                .pop_front()
                .expect("fake transport must have a reply")
            {
                Reply::Response(response) => Ok(response),
                Reply::Failure(failure) => Err(failure),
            }
        })
    }
}

impl GitHubTransport for FakeTransport {
    fn get<'a>(
        &'a self,
        request: TransportRequest,
        _context: &'a InvocationContext,
    ) -> super::ConnectorFuture<'a, Result<TransportResponse, super::ConnectorFailure>> {
        self.perform("GET", request)
    }

    fn post<'a>(
        &'a self,
        request: TransportRequest,
        _context: &'a InvocationContext,
    ) -> super::ConnectorFuture<'a, Result<TransportResponse, super::ConnectorFailure>> {
        self.perform("POST", request)
    }
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> Reply {
    Reply::Response(TransportResponse::new(status, Vec::new(), body.into()))
}

fn redirect(location: &str) -> Reply {
    Reply::Response(TransportResponse::new(
        302,
        vec![("Location".to_owned(), location.to_owned())],
        Vec::new(),
    ))
}

fn context() -> InvocationContext {
    InvocationContext::new(
        Instant::now() + Duration::from_mins(1),
        CancellationToken::new(),
        1,
        None,
    )
    .unwrap()
}

fn stateful_context(attempt: u32, approval: Option<EffectApproval>) -> InvocationContext {
    let context = InvocationContext::new(
        Instant::now() + Duration::from_mins(1),
        CancellationToken::new(),
        attempt,
        Some(IdempotencyKey::from("rerun-run-42")),
    )
    .unwrap();
    match approval {
        Some(approval) => context.with_effect_approval(approval),
        None => context,
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

async fn approval_fixture(
    request: &RerunFailedJobsRequest,
    state: TestApprovalState,
) -> ApprovalFixture {
    let fixture_id = NEXT_APPROVAL_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!(
        "pam-connectors-github-approval-{}-{fixture_id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let store = Store::open(root.join("pam.sqlite3")).unwrap();
    let caller = CallerId::from(format!("developer-{fixture_id}"));
    let reviewer = CallerId::from(format!("reviewer-{fixture_id}"));
    let project = ProjectId::from(format!("pam-{fixture_id}"));
    let credential = CallerCredential::new(format!("credential-{fixture_id}"));
    let now_ms = if matches!(state, TestApprovalState::Expired) {
        0
    } else {
        unix_time_ms()
    };
    for (identity, secret) in [
        (caller.clone(), credential.clone()),
        (
            reviewer.clone(),
            CallerCredential::new(format!("reviewer-credential-{fixture_id}")),
        ),
    ] {
        store
            .register_caller(identity, secret, now_ms)
            .await
            .unwrap();
    }
    let coordinates = RerunFailedJobs::coordinates(request);
    store
        .put_grant(PutGrant {
            grant: Grant {
                id: GrantId::from(format!("rerun-grant-{fixture_id}")),
                caller: caller.clone(),
                project: project.clone(),
                capability: coordinates.capability().clone(),
                resource: ResourceScope::Exact(coordinates.resource().clone()),
                effect: Effect::Allow,
                approval: ApprovalRequirement::Once,
                expires_at_ms: None,
                revoked_at_ms: None,
            },
            created_at_ms: now_ms,
        })
        .await
        .unwrap();
    let outcome = store
        .authorize(
            AuthorizationRequest {
                caller_id: caller.clone(),
                project_id: project.clone(),
                capability: coordinates.capability().clone(),
                resource: coordinates.resource().clone(),
                approval_id: None,
            },
            now_ms,
            if matches!(state, TestApprovalState::Expired) {
                1
            } else {
                60_000
            },
        )
        .await
        .unwrap();
    let AuthorizationOutcome::ApprovalRequired { approval_id, .. } = outcome else {
        panic!("approval-required grant must issue a receipt")
    };
    decide_fixture_approval(&store, state, &approval_id, reviewer, now_ms).await;
    let capability = store
        .bind_effect_approval(caller, credential, project, approval_id)
        .await
        .unwrap()
        .expect("registered credential must issue a store-bound capability");
    ApprovalFixture {
        approval: EffectApproval::from_store(capability),
        store,
        root,
    }
}

async fn decide_fixture_approval(
    store: &Store,
    state: TestApprovalState,
    approval_id: &ApprovalId,
    reviewer: CallerId,
    now_ms: u64,
) {
    match state {
        TestApprovalState::Requested => {}
        TestApprovalState::Approved | TestApprovalState::Expired => {
            assert_eq!(
                store
                    .decide_approval(
                        approval_id.clone(),
                        reviewer,
                        ApprovalDecision::Approve,
                        now_ms,
                    )
                    .await
                    .unwrap(),
                ApprovalDecisionOutcome::Approved
            );
        }
        TestApprovalState::Denied => {
            assert_eq!(
                store
                    .decide_approval(
                        approval_id.clone(),
                        reviewer,
                        ApprovalDecision::Deny,
                        now_ms,
                    )
                    .await
                    .unwrap(),
                ApprovalDecisionOutcome::Denied
            );
        }
    }
}

fn connector(transport: FakeTransport) -> GitHubActions<FakeTransport> {
    GitHubActions::new(Url::parse("https://api.github.com/").unwrap(), transport).unwrap()
}

fn run_json(id: u64, attempt: u32, name: &str) -> String {
    format!(
        r#"{{"id":{id},"run_attempt":{attempt},"name":"{name}","status":"completed","conclusion":"failure","html_url":"https://github.com/ro-ag/pam/actions/runs/{id}","head_branch":"main","head_sha":"0123456789abcdef","created_at":"2026-08-20T00:00:00Z","updated_at":"2026-08-20T00:01:00Z"}}"#
    )
}

fn job_json(id: u64, name: &str, conclusion: &str) -> String {
    format!(
        r#"{{"id":{id},"name":"{name}","status":"completed","conclusion":"{conclusion}","html_url":"https://github.com/ro-ag/pam/actions/runs/42/job/{id}","steps":[{{"number":1,"name":"build","status":"completed","conclusion":"{conclusion}"}}]}}"#
    )
}

#[test]
fn repository_bounds_and_policy_coordinates_are_exact() {
    let repository = Repository::parse("ro-ag/pam").unwrap();
    assert_eq!(repository.owner(), "ro-ag");
    assert_eq!(repository.name(), "pam");
    assert_eq!(
        serde_json::to_string(&repository).unwrap(),
        r#""ro-ag/pam""#
    );
    assert_eq!(
        serde_json::from_str::<Repository>(r#""ro-ag/pam""#).unwrap(),
        repository
    );
    for invalid in ["", "owner", "owner/repo/extra", "../repo", "owner/re po"] {
        assert!(Repository::parse(invalid).is_err());
    }
    assert!(DiscoverRunsRequest::new(repository.clone(), 0).is_err());
    assert!(DiscoverRunsRequest::new(repository.clone(), MAX_DISCOVERED_RUNS + 1).is_err());
    assert!(
        CollectRunLogsRequest::new(
            repository.clone(),
            RunId::new(42).unwrap(),
            1,
            MAX_LOG_BYTES_PER_JOB + 1,
            MAX_LOG_BYTES_PER_JOB + 1,
        )
        .is_err()
    );
    assert!(RunId::new(0).is_err());

    let discovery = DiscoverRunsRequest::new(repository.clone(), 5).unwrap();
    let discovery_coordinates = DiscoverFailedRuns::coordinates(&discovery);
    assert_eq!(discovery_coordinates.capability().as_str(), "runs.inspect");
    assert_eq!(
        discovery_coordinates.resource().as_str(),
        "github:ro-ag/pam"
    );
    let collection =
        CollectRunLogsRequest::new(repository, RunId::new(42).unwrap(), 4, 1024, 4096).unwrap();
    assert_eq!(
        CollectRunLogs::coordinates(&collection).resource().as_str(),
        "github:ro-ag/pam/runs/42"
    );
}

#[tokio::test]
async fn failed_run_discovery_is_bounded_sorted_and_authenticated() {
    let body = format!(
        r#"{{"total_count":2,"workflow_runs":[{},{}]}}"#,
        run_json(9, 1, "later"),
        run_json(3, 2, "earlier")
    );
    let connector = connector(FakeTransport::new([response(200, body)]));
    let request = DiscoverRunsRequest::new(Repository::parse("ro-ag/pam").unwrap(), 2).unwrap();
    let output = Connector::<DiscoverFailedRuns>::execute(&connector, request, context())
        .await
        .unwrap();
    assert!(output.truth().is_complete());
    assert_eq!(
        output
            .value()
            .runs()
            .iter()
            .map(|run| run.id().get())
            .collect::<Vec<_>>(),
        vec![3, 9]
    );
    assert_eq!(output.value().total_count(), 2);
    let seen = connector.transport().seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].url,
        "https://api.github.com/repos/ro-ag/pam/actions/runs?status=failure&per_page=2"
    );
    assert!(seen[0].authenticated);
    assert_eq!(seen[0].response_limit, 1024 * 1024);
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn failed_job_logs_follow_https_redirects_without_forwarding_auth() {
    let jobs = format!(
        r#"{{"total_count":2,"jobs":[{},{}]}}"#,
        job_json(7, "second", "failure"),
        job_json(3, "first", "failure")
    );
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 2, "CI")),
        response(200, jobs),
        redirect("https://results.example.test/job-3"),
        response(200, b"job three failed".to_vec()),
        redirect("https://results.example.test/job-7"),
        response(200, b"job seven failed".to_vec()),
    ]));
    let request = CollectRunLogsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        2,
        1024,
        2048,
    )
    .unwrap();
    let output = Connector::<CollectRunLogs>::execute(&connector, request, context())
        .await
        .unwrap();
    assert!(output.truth().is_complete());
    assert_eq!(
        output
            .value()
            .jobs()
            .iter()
            .map(crate::github::WorkflowJob::id)
            .collect::<Vec<_>>(),
        vec![3, 7]
    );
    assert_eq!(output.value().logs().len(), 2);
    assert_eq!(output.artifacts()[0].bytes(), b"job three failed");
    assert_eq!(output.artifacts()[1].bytes(), b"job seven failed");
    let seen = connector.transport().seen();
    assert_eq!(seen.len(), 6);
    assert!(seen[2].authenticated);
    assert!(!seen[3].authenticated);
    assert!(seen[4].authenticated);
    assert!(!seen[5].authenticated);
    assert!(seen[2].url.ends_with("/jobs/3/logs"));
    assert_eq!(seen[3].url, "https://results.example.test/job-3");
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn missing_or_oversized_logs_preserve_metadata_as_partial_truth() {
    let jobs = format!(
        r#"{{"total_count":3,"jobs":[{}]}}"#,
        job_json(3, "first", "failure")
    );
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(200, jobs),
        redirect("https://results.example.test/job-3"),
        Reply::Failure(super::ConnectorFailure::response_too_large(8)),
    ]));
    let request = CollectRunLogsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
        8,
        8,
    )
    .unwrap();
    let output = Connector::<CollectRunLogs>::execute(&connector, request, context())
        .await
        .unwrap();
    assert!(!output.truth().is_complete());
    assert_eq!(output.value().total_jobs(), 3);
    assert_eq!(output.value().logs().len(), 0);
    assert!(output.artifacts().is_empty());
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn rate_limits_and_unsafe_log_redirects_are_typed_without_leaking_targets() {
    let rate_limited = Reply::Response(TransportResponse::new(
        403,
        vec![
            ("X-RateLimit-Remaining".to_owned(), "0".to_owned()),
            ("Retry-After".to_owned(), "42".to_owned()),
        ],
        Vec::new(),
    ));
    let rate_limited_connector = connector(FakeTransport::new([rate_limited]));
    let request = DiscoverRunsRequest::new(Repository::parse("ro-ag/pam").unwrap(), 1).unwrap();
    let Err(failure) =
        Connector::<DiscoverFailedRuns>::execute(&rate_limited_connector, request, context()).await
    else {
        panic!("rate-limited discovery must fail");
    };
    assert_eq!(failure.kind(), FailureKind::RateLimit);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::AfterBackoff {
            delay: Some(Duration::from_secs(42))
        }
    );

    let jobs = format!(
        r#"{{"total_count":1,"jobs":[{}]}}"#,
        job_json(3, "first", "failure")
    );
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(200, jobs),
        redirect("http://token.example.test/job-3?signature=secret"),
    ]));
    let request = CollectRunLogsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
        1024,
        1024,
    )
    .unwrap();
    let output = Connector::<CollectRunLogs>::execute(&connector, request, context())
        .await
        .unwrap();
    assert!(!output.truth().is_complete());
    assert!(!format!("{:?}", output.truth()).contains("signature=secret"));
}

#[tokio::test]
async fn secondary_rate_limits_and_reset_deadlines_produce_bounded_backoff() {
    let reset = TransportResponse::new(
        403,
        vec![("X-RateLimit-Reset".to_owned(), "150".to_owned())],
        Vec::new(),
    );
    assert_eq!(
        rate_limit_delay_at(&reset, 100),
        Some(Duration::from_secs(50))
    );
    assert_eq!(
        rate_limit_delay_at(&reset, 200),
        Some(Duration::from_secs(0))
    );
    let capped = TransportResponse::new(
        403,
        vec![("X-RateLimit-Reset".to_owned(), u64::MAX.to_string())],
        Vec::new(),
    );
    assert_eq!(
        rate_limit_delay_at(&capped, 0),
        Some(Duration::from_hours(24))
    );

    let header_connector = connector(FakeTransport::new([Reply::Response(
        TransportResponse::new(
            403,
            vec![("Retry-After".to_owned(), "7".to_owned())],
            Vec::new(),
        ),
    )]));
    let request = DiscoverRunsRequest::new(Repository::parse("ro-ag/pam").unwrap(), 1).unwrap();
    let result =
        Connector::<DiscoverFailedRuns>::execute(&header_connector, request, context()).await;
    let Err(failure) = result else {
        panic!("secondary rate limit must fail with backoff")
    };
    assert_eq!(failure.kind(), FailureKind::RateLimit);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::AfterBackoff {
            delay: Some(Duration::from_secs(7))
        }
    );

    let connector = connector(FakeTransport::new([response(
        403,
        br#"{"message":"You have exceeded a secondary rate limit."}"#.to_vec(),
    )]));
    let request = DiscoverRunsRequest::new(Repository::parse("ro-ag/pam").unwrap(), 1).unwrap();
    let result = Connector::<DiscoverFailedRuns>::execute(&connector, request, context()).await;
    let Err(failure) = result else {
        panic!("headerless secondary rate limit must fail with fallback backoff")
    };
    assert_eq!(failure.kind(), FailureKind::RateLimit);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::AfterBackoff {
            delay: Some(Duration::from_mins(1))
        }
    );
}

#[tokio::test]
async fn rerun_retains_a_bounded_error_body_for_headerless_secondary_rate_limits() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();
    let fixture = approval_fixture(&request, TestApprovalState::Approved).await;
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(
            403,
            br#"{"message":"You have exceeded a secondary rate limit."}"#.to_vec(),
        ),
    ]));

    let result = Connector::<RerunFailedJobs>::execute(
        &connector,
        request,
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await;
    let Err(failure) = result else {
        panic!("headerless rerun secondary limit must fail with backoff")
    };
    assert_eq!(failure.kind(), FailureKind::RateLimit);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::AfterBackoff {
            delay: Some(Duration::from_mins(1))
        }
    );
    let seen = connector.transport().seen();
    assert_eq!(
        seen.iter()
            .map(|request| request.method)
            .collect::<Vec<_>>(),
        vec!["GET", "POST"]
    );
    assert_eq!(seen[1].response_limit, MAX_MUTATION_RESPONSE_BYTES);
    fixture.close().await;
}

#[test]
fn timeout_certificate_network_and_remote_failures_are_distinct() {
    let certificate = SyntheticTransportError("invalid peer certificate: unknown issuer");
    let network = SyntheticTransportError("connection refused");
    assert_eq!(
        classify_transport_failure(&certificate, false, true),
        FailureKind::Certificate
    );
    assert_eq!(
        classify_transport_failure(&network, true, true),
        FailureKind::Timeout
    );
    assert_eq!(
        classify_transport_failure(&network, false, true),
        FailureKind::Network
    );
    assert_eq!(
        classify_transport_failure(&network, false, false),
        FailureKind::Remote
    );
}

#[tokio::test]
async fn certificate_and_timeout_log_failures_preserve_successful_partial_data() {
    let jobs = format!(
        r#"{{"total_count":3,"jobs":[{},{},{}]}}"#,
        job_json(3, "first", "failure"),
        job_json(5, "second", "failure"),
        job_json(7, "third", "failure")
    );
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(200, jobs),
        redirect("https://results.example.test/job-3"),
        response(200, b"exact first log".to_vec()),
        redirect("https://results.example.test/job-5"),
        Reply::Failure(super::ConnectorFailure::certificate(
            super::FailureMessage::new("certificate verification failed").unwrap(),
        )),
        redirect("https://results.example.test/job-7"),
        Reply::Failure(super::ConnectorFailure::timeout()),
    ]));
    let request = CollectRunLogsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        3,
        1024,
        3072,
    )
    .unwrap();

    let output = Connector::<CollectRunLogs>::execute(&connector, request, context())
        .await
        .unwrap();

    assert!(!output.truth().is_complete());
    assert_eq!(output.value().jobs().len(), 3);
    assert_eq!(output.value().logs().len(), 1);
    assert_eq!(output.artifacts().len(), 1);
    assert_eq!(output.artifacts()[0].bytes(), b"exact first log");
    let partial = format!("{:?}", output.truth());
    assert!(partial.contains("Certificate"));
    assert!(partial.contains("Timeout"));
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn cancellation_during_log_collection_is_never_downgraded_to_partial_success() {
    let jobs = format!(
        r#"{{"total_count":1,"jobs":[{}]}}"#,
        job_json(3, "first", "failure")
    );
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(200, jobs),
        redirect("https://results.example.test/job-3"),
        Reply::Failure(super::ConnectorFailure::cancelled()),
    ]));
    let request = CollectRunLogsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
        1024,
        1024,
    )
    .unwrap();

    let result = Connector::<CollectRunLogs>::execute(&connector, request, context()).await;
    let Err(failure) = result else {
        panic!("cancelled log collection must fail")
    };
    assert_eq!(failure.kind(), FailureKind::Cancelled);
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn exact_approval_gates_rerun_and_incremented_attempt_verifies_it() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();
    assert_eq!(
        RerunFailedJobs::coordinates(&request).resource().as_str(),
        "github:ro-ag/pam/runs/42/attempts/1"
    );
    let fixture = approval_fixture(&request, TestApprovalState::Approved).await;
    let approval_id = fixture.approval.id();
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(201, Vec::new()),
        response(200, run_json(42, 2, "CI")),
    ]));

    let output = Connector::<RerunFailedJobs>::execute(
        &connector,
        request,
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await
    .unwrap();

    assert!(output.truth().is_complete());
    assert_eq!(output.value().disposition(), RerunDisposition::Started);
    assert_eq!(output.value().run().attempt(), 2);
    assert_eq!(
        output.value().approval_id().map(ApprovalId::as_str),
        Some(approval_id.as_str())
    );
    let seen = connector.transport().seen();
    assert_eq!(
        seen.iter()
            .map(|request| request.method)
            .collect::<Vec<_>>(),
        vec!["GET", "POST", "GET"]
    );
    assert!(seen[1].authenticated);
    assert_eq!(seen[1].response_limit, MAX_MUTATION_RESPONSE_BYTES);
    assert!(seen[1].url.ends_with("/runs/42/rerun-failed-jobs"));
    assert!(connector.transport().is_empty());
    fixture.close().await;
}

#[tokio::test]
async fn unapproved_or_mismatched_reruns_never_post() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();

    let mismatched_request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        2,
    )
    .unwrap();
    let fixtures = [
        approval_fixture(&request, TestApprovalState::Requested).await,
        approval_fixture(&request, TestApprovalState::Denied).await,
        approval_fixture(&request, TestApprovalState::Expired).await,
        approval_fixture(&mismatched_request, TestApprovalState::Approved).await,
    ];

    for fixture in fixtures {
        let connector = connector(FakeTransport::new([response(200, run_json(42, 1, "CI"))]));
        let result = Connector::<RerunFailedJobs>::execute(
            &connector,
            request.clone(),
            stateful_context(1, Some(fixture.approval.clone())),
        )
        .await;
        let Err(failure) = result else {
            panic!("unapproved rerun must fail")
        };
        assert_eq!(failure.kind(), FailureKind::Forbidden);
        assert_eq!(
            connector
                .transport()
                .seen()
                .iter()
                .map(|request| request.method)
                .collect::<Vec<_>>(),
            vec!["GET"]
        );
        assert!(connector.transport().is_empty());
        fixture.close().await;
    }

    let connector = connector(FakeTransport::new([response(200, run_json(42, 1, "CI"))]));
    let result =
        Connector::<RerunFailedJobs>::execute(&connector, request, stateful_context(1, None)).await;
    let Err(failure) = result else {
        panic!("missing approval must fail")
    };
    assert_eq!(failure.kind(), FailureKind::Forbidden);
    assert_eq!(connector.transport().seen()[0].method, "GET");
    assert!(connector.transport().is_empty());
}

#[tokio::test]
async fn uncertain_rerun_is_reconciled_without_a_blind_second_post() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();
    let fixture = approval_fixture(&request, TestApprovalState::Approved).await;
    let first = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        Reply::Failure(super::ConnectorFailure::timeout()),
        response(200, run_json(42, 1, "CI")),
    ]));
    let result = Connector::<RerunFailedJobs>::execute(
        &first,
        request.clone(),
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await;
    let Err(failure) = result else {
        panic!("unverified rerun must remain uncertain")
    };
    assert_eq!(failure.kind(), FailureKind::UncertainEffect);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::ReconcileBeforeRetry
    );
    assert_eq!(
        first
            .transport()
            .seen()
            .iter()
            .map(|request| request.method)
            .collect::<Vec<_>>(),
        vec!["GET", "POST", "GET"]
    );

    let retry = connector(FakeTransport::new([response(200, run_json(42, 1, "CI"))]));
    let result =
        Connector::<RerunFailedJobs>::execute(&retry, request.clone(), stateful_context(2, None))
            .await;
    let Err(failure) = result else {
        panic!("unchanged reconciliation must remain uncertain")
    };
    assert_eq!(failure.kind(), FailureKind::UncertainEffect);
    assert_eq!(retry.transport().seen()[0].method, "GET");

    let reconciled = connector(FakeTransport::new([response(200, run_json(42, 2, "CI"))]));
    let output = Connector::<RerunFailedJobs>::execute(
        &reconciled,
        request.clone(),
        stateful_context(2, None),
    )
    .await
    .unwrap();
    assert_eq!(
        output.value().disposition(),
        RerunDisposition::AlreadyStarted
    );
    assert!(output.value().approval_id().is_none());
    assert_eq!(reconciled.transport().seen()[0].method, "GET");

    let over_advanced = connector(FakeTransport::new([response(200, run_json(42, 3, "CI"))]));
    let result =
        Connector::<RerunFailedJobs>::execute(&over_advanced, request, stateful_context(2, None))
            .await;
    let Err(failure) = result else {
        panic!("over-advanced reconciliation must remain uncertain")
    };
    assert_eq!(failure.kind(), FailureKind::UncertainEffect);
    assert_eq!(over_advanced.transport().seen()[0].method, "GET");
    fixture.close().await;
}

#[tokio::test]
async fn post_success_with_failed_verification_remains_uncertain() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();
    let fixture = approval_fixture(&request, TestApprovalState::Approved).await;
    let connector = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(201, Vec::new()),
        Reply::Failure(super::ConnectorFailure::timeout()),
    ]));

    let result = Connector::<RerunFailedJobs>::execute(
        &connector,
        request,
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await;
    let Err(failure) = result else {
        panic!("failed post-effect verification must remain uncertain")
    };
    assert_eq!(failure.kind(), FailureKind::UncertainEffect);
    assert_eq!(
        failure.retry_guidance(),
        RetryGuidance::ReconcileBeforeRetry
    );
    assert_eq!(
        connector
            .transport()
            .seen()
            .iter()
            .map(|request| request.method)
            .collect::<Vec<_>>(),
        vec!["GET", "POST", "GET"]
    );
    assert!(connector.transport().is_empty());
    fixture.close().await;
}

#[tokio::test]
async fn one_approval_cannot_authorize_two_posts() {
    let request = RerunFailedJobsRequest::new(
        Repository::parse("ro-ag/pam").unwrap(),
        RunId::new(42).unwrap(),
        1,
    )
    .unwrap();
    let fixture = approval_fixture(&request, TestApprovalState::Approved).await;
    let first = connector(FakeTransport::new([
        response(200, run_json(42, 1, "CI")),
        response(201, Vec::new()),
        response(200, run_json(42, 2, "CI")),
    ]));
    Connector::<RerunFailedJobs>::execute(
        &first,
        request.clone(),
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await
    .unwrap();

    let second = connector(FakeTransport::new([response(200, run_json(42, 1, "CI"))]));
    let result = Connector::<RerunFailedJobs>::execute(
        &second,
        request,
        stateful_context(1, Some(fixture.approval.clone())),
    )
    .await;
    let Err(failure) = result else {
        panic!("consumed approval must not authorize a second rerun")
    };
    assert_eq!(failure.kind(), FailureKind::Forbidden);
    assert_eq!(second.transport().seen()[0].method, "GET");
    assert!(second.transport().is_empty());
    fixture.close().await;
}

#[test]
fn production_transport_debug_never_contains_the_token() {
    let token = "github_pat_top_secret_value";
    let transport = ReqwestGitHubTransport::new(Some(token.to_owned())).unwrap();
    let debug = format!("{transport:?}");
    assert!(debug.contains("authenticated"));
    assert!(!debug.contains(token));
    assert!(GitHubActions::new(Url::parse("http://api.github.com/").unwrap(), transport).is_err());
    assert_eq!(MAX_JOB_STEPS, 64);
}

#[tokio::test]
#[ignore = "requires PAM_GITHUB_TOKEN, PAM_GITHUB_REPOSITORY, and PAM_GITHUB_RUN_ID"]
async fn live_failed_run_discovery_and_log_collection() {
    let token = env::var("PAM_GITHUB_TOKEN").expect("PAM_GITHUB_TOKEN must be set");
    let repository = Repository::parse(
        env::var("PAM_GITHUB_REPOSITORY").expect("PAM_GITHUB_REPOSITORY must be set"),
    )
    .unwrap();
    let run_id = env::var("PAM_GITHUB_RUN_ID")
        .expect("PAM_GITHUB_RUN_ID must be set")
        .parse::<u64>()
        .ok()
        .and_then(|value| RunId::new(value).ok())
        .expect("PAM_GITHUB_RUN_ID must be a nonzero integer");
    let transport = ReqwestGitHubTransport::new(Some(token)).unwrap();
    let connector =
        GitHubActions::new(Url::parse("https://api.github.com/").unwrap(), transport).unwrap();

    let discovery = Connector::<DiscoverFailedRuns>::execute(
        &connector,
        DiscoverRunsRequest::new(repository.clone(), 10).unwrap(),
        context(),
    )
    .await
    .unwrap();
    assert!(!discovery.value().runs().is_empty());

    let collection = Connector::<CollectRunLogs>::execute(
        &connector,
        CollectRunLogsRequest::new(
            repository,
            run_id,
            16,
            MAX_LOG_BYTES_PER_JOB,
            16 * 1024 * 1024,
        )
        .unwrap(),
        context(),
    )
    .await
    .unwrap();
    assert_eq!(collection.value().run().id(), run_id);
    assert!(!collection.value().jobs().is_empty());
    assert!(!collection.value().logs().is_empty());
    assert_eq!(
        collection.value().logs().len(),
        collection.artifacts().len()
    );
}
