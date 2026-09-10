use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret};
use crate::{CallResult, ConnectorError, MAX_JSON_BYTES, TransportError, call, verify};

#[tokio::test]
async fn runs_asks_for_failed_runs_and_keeps_the_named_fields() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"total_count":1,"workflow_runs":[{"id":9,"name":"ci","status":"completed",
            "conclusion":"failure","html_url":"https://github.com/ro-ag/pam/actions/runs/9",
            "head_sha":"abc","created_at":"2026-09-01T00:00:00Z","run_attempt":2,"extra":"dropped"}]}"#,
    );
    let result = run_call("runs", &[("repo", "ro-ag/pam")], &transport)
        .await
        .unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://api.github.com/repos/ro-ag/pam/actions/runs?"),
        "{url}"
    );
    assert!(url.contains("status=failure"), "{url}");
    assert!(url.contains("per_page=5"), "{url}");
    assert_eq!(
        transport.header(0, "authorization"),
        Some("Bearer ghp_secret".to_owned())
    );
    assert_eq!(
        transport.header(0, "x-github-api-version"),
        Some("2022-11-28".to_owned())
    );

    let CallResult::Json(value) = result else {
        panic!("runs answers with JSON");
    };
    assert_eq!(value["runs"][0]["id"], 9);
    assert_eq!(value["runs"][0]["conclusion"], "failure");
    assert_eq!(value["runs"][0]["head_sha"], "abc");
    assert!(value["runs"][0].get("extra").is_none());
}

#[tokio::test]
async fn runs_honours_an_explicit_status_and_limit() {
    let transport = FakeTransport::new().json(200, r#"{"workflow_runs":[]}"#);
    let mut args = args(&[("repo", "ro-ag/pam"), ("status", "success")]);
    args.insert("limit".to_owned(), ArgValue::Int(2));
    call(
        ConnectorId::Github,
        &connection(),
        "runs",
        &args,
        &transport,
        deadline(),
    )
    .await
    .unwrap();
    let url = transport.url(0);
    assert!(url.contains("status=success"), "{url}");
    assert!(url.contains("per_page=2"), "{url}");
}

#[tokio::test]
async fn run_lists_the_failing_jobs_first() {
    let transport = FakeTransport::new()
        .json(
            200,
            r#"{"id":9,"name":"ci","run_attempt":3,"conclusion":"failure"}"#,
        )
        .json(
            200,
            r#"{"total_count":4,"jobs":[
                {"id":1,"name":"lint","status":"completed","conclusion":"success"},
                {"id":2,"name":"docs","status":"completed","conclusion":"cancelled"},
                {"id":3,"name":"test","status":"completed","conclusion":"failure"},
                {"id":4,"name":"bench","status":"completed","conclusion":"skipped"}]}"#,
        );
    let mut args = args(&[("repo", "ro-ag/pam")]);
    args.insert("run_id".to_owned(), ArgValue::Int(9));
    let result = call(
        ConnectorId::Github,
        &connection(),
        "run",
        &args,
        &transport,
        deadline(),
    )
    .await
    .unwrap();

    assert_eq!(
        transport.url(0),
        "https://api.github.com/repos/ro-ag/pam/actions/runs/9"
    );
    // The attempt the run reports, not a guess.
    assert!(
        transport
            .url(1)
            .starts_with("https://api.github.com/repos/ro-ag/pam/actions/runs/9/attempts/3/jobs?"),
        "{}",
        transport.url(1)
    );

    let CallResult::Json(value) = result else {
        panic!("run answers with JSON");
    };
    assert_eq!(value["run"]["id"], 9);
    let names: Vec<&str> = value["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|job| job["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["test", "docs", "lint", "bench"]);
}

fn successful_jobs(count: u64) -> Vec<serde_json::Value> {
    (1..=count).map(|id| serde_json::json!({
        "id": id, "name": format!("job-{id}"), "status": "completed", "conclusion": "success",
    })).collect()
}

fn json_result(result: CallResult) -> serde_json::Value {
    let CallResult::Json(value) = result else {
        panic!("expected JSON")
    };
    value
}

#[tokio::test]
async fn failure_on_page_two_never_makes_page_one_complete() {
    let metadata = r#"{"id":9,"run_attempt":3,"status":"completed","conclusion":"failure"}"#;
    let first = serde_json::json!({"total_count":101,"jobs":successful_jobs(100)});
    let last = serde_json::json!({"total_count":101,"jobs":[{
        "id":101,"name":"last-job","status":"completed","conclusion":"failure",
    }]});
    let transport = FakeTransport::new()
        .json(200, metadata)
        .json(200, &first.to_string())
        .json(200, metadata)
        .json(200, &last.to_string());
    let first = json_result(
        run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport)
            .await
            .unwrap(),
    );
    assert_eq!(first["jobs"].as_array().unwrap().len(), 100);
    assert_eq!(first["jobs"][0]["conclusion"], "success");
    assert_eq!(
        first["run"]["conclusion"], "failure",
        "core run result survives page-local success"
    );
    assert_eq!(first["run_attempt"], 3);
    assert_eq!(first["total_count"], 101);
    assert_eq!(first["partial"], true);
    assert_eq!(first["coverage"]["complete"], false);
    assert_eq!(first["next_page"], 2);
    assert_eq!(transport.requests().len(), 2, "no hidden pagination");
    let last = json_result(
        run_call(
            "run",
            &[
                ("repo", "ro-ag/pam"),
                ("run_id", "9"),
                ("page", "2"),
                ("run_attempt", "3"),
            ],
            &transport,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        transport.url(2),
        "https://api.github.com/repos/ro-ag/pam/actions/runs/9/attempts/3"
    );
    assert!(
        transport
            .url(3)
            .contains("/attempts/3/jobs?per_page=100&page=2")
    );
    assert_eq!(last["jobs"][0]["id"], 101);
    assert_eq!(last["run_attempt"], 3);
    assert_eq!(last["page"], 2);
    assert_eq!(last["ordering"], "failure_first_within_page");
    assert_eq!(
        last["partial"], true,
        "earlier pages are not in this response"
    );
    assert_eq!(last["coverage"]["has_more"], false);
    assert!(last["next_page"].is_null());
    assert_eq!(
        last["coverage"]["gaps"],
        serde_json::json!(["previous_pages_not_included"])
    );
}

#[tokio::test]
async fn absent_or_invalid_attempt_is_rejected_before_fetching_jobs() {
    for attempt in [
        None,
        Some(serde_json::json!(null)),
        Some(serde_json::json!(0)),
        Some(serde_json::json!(-1)),
        Some(serde_json::json!("3")),
        Some(serde_json::json!(1.5)),
    ] {
        let mut metadata = serde_json::json!({"id":9});
        if let Some(attempt) = attempt {
            metadata["run_attempt"] = attempt;
        }
        let transport = FakeTransport::new().json(200, &metadata.to_string());
        let result = run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport).await;
        assert!(
            matches!(result, Err(ConnectorError::BadResponse(_))),
            "{result:?}"
        );
        assert_eq!(transport.requests().len(), 1);
    }
}

#[tokio::test]
async fn mismatched_run_attempt_or_repository_is_rejected_before_jobs() {
    for metadata in [
        serde_json::json!({"id":10,"run_attempt":3}),
        serde_json::json!({"id":9,"run_attempt":2}),
        serde_json::json!({"id":9,"run_attempt":3,"repository":{"full_name":"other/private"}}),
    ] {
        let transport = FakeTransport::new().json(200, &metadata.to_string());
        let result = run_call(
            "run",
            &[("repo", "ro-ag/pam"), ("run_id", "9"), ("run_attempt", "3")],
            &transport,
        )
        .await;
        assert!(
            matches!(result, Err(ConnectorError::BadResponse(_))),
            "{result:?}"
        );
        assert_eq!(transport.requests().len(), 1);
    }
}

#[tokio::test]
async fn subsequent_pages_need_a_pinned_attempt_and_pages_are_bounded() {
    for (page, attempt) in [
        ("2", None),
        ("0", Some("3")),
        ("10001", Some("3")),
        ("1", Some("0")),
    ] {
        let transport = FakeTransport::new();
        let mut pairs = vec![("repo", "ro-ag/pam"), ("run_id", "9"), ("page", page)];
        if let Some(attempt) = attempt {
            pairs.push(("run_attempt", attempt));
        }
        let result = run_call("run", &pairs, &transport).await;
        assert!(
            matches!(result, Err(ConnectorError::BadArgs(_))),
            "{result:?}"
        );
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test]
async fn oversized_jobs_are_capped_before_page_local_sorting() {
    let mut jobs = successful_jobs(100);
    jobs.push(serde_json::json!({"id":101,"conclusion":"failure"}));
    let transport = FakeTransport::new()
        .json(200, r#"{"id":9,"run_attempt":3}"#)
        .json(
            200,
            &serde_json::json!({"total_count":101,"jobs":jobs}).to_string(),
        );
    let result = json_result(
        run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport)
            .await
            .unwrap(),
    );
    assert_eq!(result["jobs"].as_array().unwrap().len(), 100);
    assert_eq!(
        result["jobs"][0]["id"], 1,
        "discarded record cannot reorder this page"
    );
    assert_eq!(result["partial"], true);
    assert_eq!(result["coverage"]["received"], 101);
    assert_eq!(result["coverage"]["omitted"], 1);
    assert!(
        result["coverage"]["gaps"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("response_array_truncated"))
    );
}

#[tokio::test]
async fn missing_malformed_and_inconsistent_totals_never_claim_complete_coverage() {
    for total in [
        None,
        Some(serde_json::json!(null)),
        Some(serde_json::json!(-1)),
        Some(serde_json::json!("2")),
        Some(serde_json::json!(3)),
    ] {
        let mut body = serde_json::json!({"jobs":successful_jobs(2)});
        if let Some(total) = total {
            body["total_count"] = total;
        }
        let transport = FakeTransport::new()
            .json(200, r#"{"id":9,"run_attempt":3}"#)
            .json(200, &body.to_string());
        let result = json_result(
            run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport)
                .await
                .unwrap(),
        );
        assert_eq!(result["partial"], true, "{result}");
        assert_eq!(result["coverage"]["complete"], false);
        assert!(!result["coverage"]["gaps"].as_array().unwrap().is_empty());
    }
    for count in [0, 2] {
        let body = serde_json::json!({"total_count":count,"jobs":successful_jobs(count)});
        let transport = FakeTransport::new()
            .json(200, r#"{"id":9,"run_attempt":3}"#)
            .json(200, &body.to_string());
        let result = json_result(
            run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport)
                .await
                .unwrap(),
        );
        assert_eq!(result["partial"], false);
        assert_eq!(result["coverage"]["complete"], true);
        assert!(result["next_page"].is_null());
    }
}

#[tokio::test]
async fn runs_enforces_decoded_limit_and_reports_page_coverage() {
    let transport = FakeTransport::new().json(
        200,
        &serde_json::json!({
            "total_count":5,"workflow_runs":[{"id":1},{"id":2},{"id":3}],
        })
        .to_string(),
    );
    let result = json_result(
        run_call(
            "runs",
            &[("repo", "ro-ag/pam"), ("limit", "2"), ("page", "2")],
            &transport,
        )
        .await
        .unwrap(),
    );
    assert!(transport.url(0).contains("per_page=2&page=2"));
    assert_eq!(result["runs"].as_array().unwrap().len(), 2);
    assert_eq!(result["runs"][0]["id"], 1, "server order is retained");
    assert_eq!(result["coverage"]["omitted"], 1);
    assert_eq!(result["next_page"], 3);
    assert_eq!(result["partial"], true);
}

#[tokio::test]
async fn unknown_total_and_page_limit_are_explicit() {
    let body = serde_json::json!({"jobs":successful_jobs(100)});
    let transport = FakeTransport::new()
        .json(200, r#"{"id":9,"run_attempt":3}"#)
        .json(200, &body.to_string());
    let result = json_result(
        run_call("run", &[("repo", "ro-ag/pam"), ("run_id", "9")], &transport)
            .await
            .unwrap(),
    );
    assert!(result["total_count"].is_null());
    assert!(result["coverage"]["has_more"].is_null());
    assert_eq!(
        result["next_page"], 2,
        "a full page permits an explicit bounded probe"
    );
    let transport = FakeTransport::new()
        .json(200, r#"{"id":9,"run_attempt":3}"#)
        .json(200, r#"{"total_count":1000001,"jobs":[]}"#);
    let result = json_result(
        run_call(
            "run",
            &[
                ("repo", "ro-ag/pam"),
                ("run_id", "9"),
                ("page", "10000"),
                ("run_attempt", "3"),
            ],
            &transport,
        )
        .await
        .unwrap(),
    );
    assert!(result["next_page"].is_null());
    assert_eq!(result["partial"], true);
    assert!(
        result["coverage"]["gaps"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("page_limit_reached"))
    );
}

#[tokio::test]
async fn job_log_reads_the_conclusion_first_and_then_the_log() {
    let transport = FakeTransport::new()
        .json(200, r#"{"id":7,"name":"test","conclusion":"failure"}"#)
        .bytes(200, b"error[E0308]: mismatched types".to_vec());
    let result = job_log(&transport, 7).await.unwrap();

    assert_eq!(
        transport.url(0),
        "https://api.github.com/repos/ro-ag/pam/actions/jobs/7"
    );
    assert_eq!(
        transport.url(1),
        "https://api.github.com/repos/ro-ag/pam/actions/jobs/7/logs"
    );
    assert!(!transport.requests()[0].follow_one_https_redirect_without_auth);
    assert!(transport.requests()[1].follow_one_https_redirect_without_auth);

    let CallResult::Log {
        name,
        bytes,
        exit_status,
    } = result
    else {
        panic!("job_log answers with a log");
    };
    assert_eq!(name, "github-job-7.log");
    assert_eq!(bytes, b"error[E0308]: mismatched types");
    assert_eq!(exit_status, Some(1));
}

#[tokio::test]
async fn a_jobs_conclusion_decides_the_logs_exit_status() {
    for (conclusion, expected) in [
        ("failure", Some(1)),
        ("cancelled", Some(1)),
        ("timed_out", Some(1)),
        ("success", Some(0)),
        ("skipped", None),
        ("neutral", None),
    ] {
        let transport = FakeTransport::new()
            .json(200, &format!(r#"{{"id":7,"conclusion":"{conclusion}"}}"#))
            .bytes(200, b"log".to_vec());
        let CallResult::Log { exit_status, .. } = job_log(&transport, 7).await.unwrap() else {
            panic!("job_log answers with a log");
        };
        assert_eq!(exit_status, expected, "{conclusion}");
    }

    let transport = FakeTransport::new()
        .json(200, r#"{"id":7,"status":"in_progress"}"#)
        .bytes(200, b"log".to_vec());
    let CallResult::Log { exit_status, .. } = job_log(&transport, 7).await.unwrap() else {
        panic!("job_log answers with a log");
    };
    assert_eq!(exit_status, None);
}

#[tokio::test]
async fn http_failures_become_the_shared_refusals() {
    /// A status, the headers that came with it, and the refusal it becomes.
    type Case = (u16, Vec<(&'static str, &'static str)>, ConnectorError);

    let cases: Vec<Case> = vec![
        (401, vec![], ConnectorError::Auth),
        (403, vec![], ConnectorError::Forbidden),
        (404, vec![], ConnectorError::NotFound),
        (500, vec![], ConnectorError::Remote { status: 500 }),
        (
            429,
            vec![("Retry-After", "17")],
            ConnectorError::RateLimited {
                retry_after: Some(Duration::from_secs(17)),
            },
        ),
    ];
    for (status, headers, expected) in cases {
        let transport = FakeTransport::new().with_headers(status, &headers, "{}");
        let error = run_call("runs", &[("repo", "ro-ag/pam")], &transport)
            .await
            .unwrap_err();
        assert_eq!(error, expected, "HTTP {status}");
    }
}

#[tokio::test]
async fn an_exhausted_rate_limit_budget_reads_the_reset_clock() {
    let reset = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 90;
    let transport = FakeTransport::new().with_headers(
        403,
        &[
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", &reset.to_string()),
        ],
        "{}",
    );
    let error = run_call("runs", &[("repo", "ro-ag/pam")], &transport)
        .await
        .unwrap_err();
    let ConnectorError::RateLimited { retry_after } = error else {
        panic!("an exhausted budget is throttling, got {error:?}");
    };
    let wait = retry_after.expect("the reset clock gives a wait").as_secs();
    assert!((80..=90).contains(&wait), "{wait}");
}

#[tokio::test]
async fn an_answer_over_a_megabyte_is_refused() {
    let body = format!(
        r#"{{"workflow_runs":[],"pad":"{}"}}"#,
        "x".repeat(usize::try_from(MAX_JSON_BYTES).expect("the cap fits a usize"))
    );
    let transport = FakeTransport::new().json(200, &body);
    let error = run_call("runs", &[("repo", "ro-ag/pam")], &transport)
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "connector_response_too_large");
}

#[tokio::test]
async fn a_repo_that_is_not_owner_slash_name_is_refused_before_any_request() {
    let transport = FakeTransport::new();
    for repo in ["pam", "a/b/c", "ro-ag /pam", ""] {
        let error = run_call("runs", &[("repo", repo)], &transport)
            .await
            .unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{repo}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn a_transport_failure_reaches_the_caller_unchanged() {
    let transport = FakeTransport::new().failure(TransportError::Certificate);
    let error = run_call("runs", &[("repo", "ro-ag/pam")], &transport)
        .await
        .unwrap_err();
    assert_eq!(error, ConnectorError::Certificate);
}

#[tokio::test]
async fn verify_names_the_authenticated_login() {
    let transport = FakeTransport::new().json(200, r#"{"login":"octocat","id":1}"#);
    let report = verify(ConnectorId::Github, &connection(), &transport, deadline())
        .await
        .unwrap();
    assert_eq!(report.detail, "authenticated as octocat");
    assert_eq!(transport.url(0), "https://api.github.com/user");
}

#[tokio::test]
async fn verify_refuses_an_answer_that_names_nobody() {
    let transport = FakeTransport::new().json(200, r#"{"id":1}"#);
    let error = verify(ConnectorId::Github, &connection(), &transport, deadline())
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

#[tokio::test]
async fn an_unknown_call_names_what_github_offers() {
    let transport = FakeTransport::new();
    let error = run_call("workflows", &[], &transport).await.unwrap_err();
    assert!(error.detail().contains("job_log"), "{error:?}");
}

async fn job_log(transport: &FakeTransport, job_id: i64) -> Result<CallResult, ConnectorError> {
    let mut args = args(&[("repo", "ro-ag/pam")]);
    args.insert("job_id".to_owned(), ArgValue::Int(job_id));
    call(
        ConnectorId::Github,
        &connection(),
        "job_log",
        &args,
        transport,
        deadline(),
    )
    .await
}

async fn run_call(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Github,
        &connection(),
        name,
        &args(pairs),
        transport,
        deadline(),
    )
    .await
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, ArgValue> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), ArgValue::Text((*value).to_owned())))
        .collect()
}

fn connection() -> Connection {
    Connection {
        base_url: Url::parse("https://api.github.com/").expect("the base URL parses"),
        username: None,
        secret: Some(Secret::new("ghp_secret".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[tokio::test]
async fn fork_head_identity_remains_distinct_from_same_named_workflow_repository() {
    let sha = "a".repeat(40);
    let run = serde_json::json!({"id":9,"run_attempt":1,"head_sha":sha,
        "repository":{"id":1,"full_name":"base/app","html_url":"https://github.com/base/app","clone_url":"https://github.com/base/app.git"},
        "head_repository":{"id":2,"full_name":"fork/app","html_url":"https://github.com/fork/app","clone_url":"https://github.com/fork/app.git"},
        "pull_requests":[{"number":7,"head":{"sha":sha,"ref":"fix","repo":{"id":2,"full_name":"fork/app","url":"https://api.github.com/repos/fork/app"}}}]});
    let transport = FakeTransport::new()
        .json(200, &run.to_string())
        .json(200, r#"{"total_count":0,"jobs":[]}"#);
    let CallResult::Json(result) =
        run_call("run", &[("repo", "base/app"), ("run_id", "9")], &transport)
            .await
            .unwrap()
    else {
        panic!("JSON");
    };
    assert_eq!(result["source_identity"]["status"], "unambiguous");
    assert_eq!(
        result["source_identity"]["repository_urls"],
        serde_json::json!(["https://github.com/fork/app.git"])
    );
    assert_eq!(result["run"]["repository"]["full_name"], "base/app");
    assert_eq!(
        result["run"]["pull_requests"][0]["head"]["repo"]["full_name"],
        "fork/app"
    );
    assert_eq!(result["run"]["pull_requests"][0]["number"], 7);
    let mut absent = run;
    absent.as_object_mut().unwrap().remove("head_repository");
    let transport = FakeTransport::new()
        .json(200, &absent.to_string())
        .json(200, r#"{"total_count":0,"jobs":[]}"#);
    let CallResult::Json(result) =
        run_call("run", &[("repo", "base/app"), ("run_id", "9")], &transport)
            .await
            .unwrap()
    else {
        panic!("JSON");
    };
    assert_eq!(
        result["source_identity"]["status"], "missing",
        "base repository never substitutes for fork head"
    );
}
