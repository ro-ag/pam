use crate::github_landing::{self as landing, CheckState, Target};
use crate::{Connection, Method, Secret, testing::FakeTransport};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
fn conn() -> Connection {
    Connection {
        base_url: url::Url::parse("https://api.github.com/").unwrap(),
        username: None,
        secret: Some(Secret::new("private-token".into())),
    }
}
fn target() -> Target {
    Target {
        repository: "org/repo".into(),
        head: "feature/work".into(),
        base: "main".into(),
        head_sha: "a".repeat(40),
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn pr() -> Value {
    json!({"number":7,"state":"open","merged":false,"head":{"ref":"feature/work","sha":"a".repeat(40),"repo":{"full_name":"org/repo"}},"base":{"ref":"main","sha":"b".repeat(40),"repo":{"full_name":"org/repo"}}})
}
#[tokio::test]
async fn exact_read_and_find_validate_identity_without_mutation() {
    let fake = FakeTransport::new()
        .json(200, &pr().to_string())
        .json(200, &json!([pr()]).to_string());
    assert_eq!(
        landing::read_pull_request(&conn(), &target(), 7, &fake, deadline())
            .await
            .unwrap()
            .base_sha,
        "b".repeat(40)
    );
    assert_eq!(
        landing::find_pull_request(&conn(), &target(), &fake, deadline())
            .await
            .unwrap()
            .unwrap()
            .number,
        7
    );
    assert!(
        fake.requests()
            .iter()
            .all(|request| request.method == Method::Get && request.body.is_none())
    );
    assert!(fake.url(1).contains("head=org%3Afeature%2Fwork"));
}
#[tokio::test]
async fn absent_complete_find_is_distinct_from_truncated_or_duplicate_membership() {
    let empty = FakeTransport::new().json(200, "[]");
    assert!(
        landing::find_pull_request(&conn(), &target(), &empty, deadline())
            .await
            .unwrap()
            .is_none()
    );
    for fake in [
        FakeTransport::new().json(200, &json!([pr(), pr()]).to_string()),
        FakeTransport::new().with_headers(
            200,
            &[("Link", "<https://evil.example/>; rel=\"next\"")],
            "[]",
        ),
        FakeTransport::new().json(200, &Value::Array(vec![pr(); 100]).to_string()),
    ] {
        assert!(
            landing::find_pull_request(&conn(), &target(), &fake, deadline())
                .await
                .is_err()
        );
        assert_eq!(fake.requests().len(), 1);
    }
}
#[tokio::test]
async fn create_and_merge_emit_fixed_guarded_json_and_check_receipts() {
    let fake = FakeTransport::new().json(201, &pr().to_string()).json(
        200,
        &json!({"merged":true,"sha":"c".repeat(40)}).to_string(),
    );
    landing::create_pull_request(&conn(), &target(), "Land this change", &fake, deadline())
        .await
        .unwrap();
    assert_eq!(
        landing::merge_pull_request(&conn(), &target(), 7, &fake, deadline())
            .await
            .unwrap()
            .sha,
        "c".repeat(40)
    );
    let requests = fake.requests();
    assert_eq!(requests[0].method, Method::Post);
    assert_eq!(requests[1].method, Method::Put);
    let body: Value = serde_json::from_slice(requests[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(body, json!({"sha":"a".repeat(40),"merge_method":"squash"}));
    assert!(
        requests
            .iter()
            .all(|r| !r.follow_one_https_redirect_without_auth
                && !r.url.as_str().contains("private-token"))
    );
}
#[tokio::test]
async fn stale_identity_mutation_error_and_redirect_never_establish_success() {
    let mut wrong = pr();
    wrong["head"]["sha"] = json!("d".repeat(40));
    let fake = FakeTransport::new().json(201, &wrong.to_string());
    assert!(
        landing::create_pull_request(&conn(), &target(), "Title", &fake, deadline())
            .await
            .is_err()
    );
    for fake in [
        FakeTransport::new().json(409, "private-token"),
        FakeTransport::new().with_headers(
            307,
            &[("Location", "https://evil.example/?private-token")],
            "private-token",
        ),
        FakeTransport::new().json(200, r#"{"merged":false,"sha":"bad"}"#),
    ] {
        let error = landing::merge_pull_request(&conn(), &target(), 7, &fake, deadline())
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(fake.requests().len(), 1);
    }
}
#[tokio::test]
async fn exact_commit_requires_every_configured_context_and_excludes_cancelled() {
    for (conclusion, passed) in [("success", true), ("cancelled", false), ("neutral", false)] {
        let fake=FakeTransport::new().json(200,&json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":"a".repeat(40),"status":"completed","conclusion":conclusion}]}).to_string()).json(200,&json!({"sha":"a".repeat(40),"total_count":1,"statuses":[{"context":"review","state":"success"}]}).to_string());
        let result = landing::required_checks(
            &conn(),
            "org/repo",
            &"a".repeat(40),
            &["ci".into(), "review".into()],
            &fake,
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(result.passed, passed);
        assert_eq!(fake.requests().len(), 2);
    }
    let fake = FakeTransport::new()
        .json(200, r#"{"total_count":0,"check_runs":[]}"#)
        .json(
            200,
            &json!({"sha":"a".repeat(40),"total_count":0,"statuses":[]}).to_string(),
        );
    let result = landing::required_checks(
        &conn(),
        "org/repo",
        &"a".repeat(40),
        &["missing".into()],
        &fake,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(result.contexts[0].state, CheckState::Unknown);
    assert!(!result.passed);
}
#[tokio::test]
async fn incomplete_checks_wrong_sha_and_unbounded_inputs_refuse() {
    for body in [
        json!({"total_count":1,"check_runs":[]}),
        json!({"total_count":1,"check_runs":[{"name":"ci","head_sha":"b".repeat(40),"status":"completed","conclusion":"success"}]}),
    ] {
        let fake = FakeTransport::new().json(200, &body.to_string());
        assert!(
            landing::required_checks(
                &conn(),
                "org/repo",
                &"a".repeat(40),
                &["ci".into()],
                &fake,
                deadline()
            )
            .await
            .is_err()
        );
    }
    let fake = FakeTransport::new();
    assert!(
        landing::required_checks(&conn(), "org/repo", &"a".repeat(40), &[], &fake, deadline())
            .await
            .is_err()
    );
    let mut bad = target();
    bad.head = "../bad".into();
    assert!(
        landing::find_pull_request(&conn(), &bad, &fake, deadline())
            .await
            .is_err()
    );
    assert!(fake.requests().is_empty());
}
