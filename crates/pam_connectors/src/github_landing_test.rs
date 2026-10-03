use crate::github_landing::{
    self as landing, CheckState, MergeMethod, MergeMethods, RequiredCheck, Target,
};
use crate::{Connection, ConnectorError, Method, Secret, TransportError, testing::FakeTransport};
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
        landing::merge_pull_request(
            &conn(),
            &target(),
            7,
            MergeMethod::Squash,
            &fake,
            deadline()
        )
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
        let error = landing::merge_pull_request(
            &conn(),
            &target(),
            7,
            MergeMethod::Squash,
            &fake,
            deadline(),
        )
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
            &[RequiredCheck::named("ci"), RequiredCheck::named("review")],
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
        &[RequiredCheck::named("missing")],
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
                &[RequiredCheck::named("ci")],
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

/// Every GitHub refusal of a PR creation or merge is a definite refusal with
/// its own cause and recovery; none echoes the response body.
#[tokio::test]
async fn github_rejections_of_mutations_are_definite_and_typed() {
    let body = |message: &str, error: &str| {
        json!({"message": message, "errors": [{"resource": "PullRequest", "code": "custom", "message": error}], "documentation_url": "https://docs.github.com/private-token"}).to_string()
    };
    let create = [
        (
            422,
            body(
                "Validation Failed",
                "A pull request already exists for org:feature/work.",
            ),
            "landing_pr_already_exists",
        ),
        (
            422,
            body(
                "Validation Failed",
                "No commits between main and feature/work",
            ),
            "landing_pr_no_commits",
        ),
        (
            422,
            body("Validation Failed", "private-token"),
            "landing_pr_rejected",
        ),
    ];
    for (status, text, cause) in create {
        let fake = FakeTransport::new().json(status, &text);
        let error = landing::create_pull_request(&conn(), &target(), "Land", &fake, deadline())
            .await
            .unwrap_err();
        assert_eq!(error.cause(), cause, "{text}");
        assert!(landing::definite_refusal(&error), "{cause}");
        assert!(!error.detail().contains("private-token"));
        assert!(!error.recovery(pam_flow::ConnectorId::Github).is_empty());
        assert_eq!(fake.requests().len(), 1);
    }
    let merge = [
        (
            405,
            json!({"message": "Pull Request is not mergeable"}).to_string(),
            "landing_merge_not_mergeable",
        ),
        (
            405,
            json!({"message": "Merge commits are not allowed on this repository."}).to_string(),
            "landing_merge_method_not_allowed",
        ),
        (
            405,
            json!({"message": "Required status check \"ci\" is expected."}).to_string(),
            "landing_merge_checks_required",
        ),
        (
            422,
            json!({"message": "2 of 2 required status checks are expected."}).to_string(),
            "landing_merge_checks_required",
        ),
        (
            422,
            json!({"message": "Merge conflict"}).to_string(),
            "landing_merge_conflict",
        ),
        (
            409,
            json!({"message": "Head branch was modified. Review and try the merge again."})
                .to_string(),
            "landing_merge_head_modified",
        ),
        (
            409,
            "private-token".to_owned(),
            "landing_merge_head_modified",
        ),
        (
            422,
            "not json private-token".to_owned(),
            "landing_merge_rejected",
        ),
    ];
    for (status, text, cause) in merge {
        let fake = FakeTransport::new().json(status, &text);
        let error = landing::merge_pull_request(
            &conn(),
            &target(),
            7,
            MergeMethod::Squash,
            &fake,
            deadline(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.cause(), cause, "{text}");
        assert!(landing::definite_refusal(&error), "{cause}");
        assert!(!error.detail().contains("private-token"));
        assert_eq!(fake.requests().len(), 1);
    }
}
/// A failure after the request left, with no answer that proves a refusal,
/// keeps the outcome unknown.
#[tokio::test]
async fn ambiguous_mutation_failures_stay_uncertain() {
    for fake in [
        FakeTransport::new().failure(TransportError::Network("connection reset".into())),
        FakeTransport::new().failure(TransportError::Timeout),
        FakeTransport::new().json(502, "{}"),
        FakeTransport::new().json(200, r#"{"merged":true}"#),
    ] {
        let error = landing::merge_pull_request(
            &conn(),
            &target(),
            7,
            MergeMethod::Squash,
            &fake,
            deadline(),
        )
        .await
        .unwrap_err();
        assert!(!landing::definite_refusal(&error), "{error:?}");
    }
    let fake = FakeTransport::new().failure(TransportError::Network("connection reset".into()));
    let error = landing::create_pull_request(&conn(), &target(), "Land", &fake, deadline())
        .await
        .unwrap_err();
    assert!(matches!(error, ConnectorError::Network(_)));
    assert!(!landing::definite_refusal(&error));
}
#[tokio::test]
async fn merge_carries_the_chosen_method_and_reads_the_repository_allowlist() {
    let fake = FakeTransport::new().json(
        200,
        &json!({"merged":true,"sha":"c".repeat(40)}).to_string(),
    );
    landing::merge_pull_request(
        &conn(),
        &target(),
        7,
        MergeMethod::Rebase,
        &fake,
        deadline(),
    )
    .await
    .unwrap();
    let body: Value = serde_json::from_slice(fake.requests()[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body, json!({"sha":"a".repeat(40),"merge_method":"rebase"}));
    let fake = FakeTransport::new().json(
        200,
        &json!({"full_name":"org/repo","allow_squash_merge":false,"allow_merge_commit":true})
            .to_string(),
    );
    let methods = landing::merge_methods(&conn(), "org/repo", &fake, deadline())
        .await
        .unwrap();
    assert_eq!(
        methods,
        MergeMethods {
            squash: Some(false),
            merge: Some(true),
            rebase: None
        }
    );
    assert_eq!(methods.reported(MergeMethod::Squash), Some(false));
    assert_eq!(fake.requests()[0].method, Method::Get);
    assert!(fake.url(0).ends_with("/repos/org/repo"));
    for body in [
        json!({"full_name":"org/other","allow_squash_merge":true}),
        json!({"full_name":"org/repo","allow_squash_merge":"yes"}),
    ] {
        let fake = FakeTransport::new().json(200, &body.to_string());
        assert!(
            landing::merge_methods(&conn(), "org/repo", &fake, deadline())
                .await
                .is_err()
        );
    }
    assert_eq!(MergeMethod::parse("merge"), Some(MergeMethod::Merge));
    assert_eq!(MergeMethod::parse("fast-forward"), None);
}
/// A pinned requirement is satisfied only by its own app; a same-named check
/// run from another app is ignored and counted, and a fully pinned list never
/// reads commit statuses (which carry no app identity).
#[tokio::test]
async fn a_same_named_check_from_another_app_does_not_satisfy_a_pinned_requirement() {
    let run = |app: Option<u64>| {
        let mut run = json!({"name":"ci","head_sha":"a".repeat(40),"status":"completed","conclusion":"success"});
        if let Some(app) = app {
            run["app"] = json!({"id": app, "slug": "app"});
        }
        run
    };
    let pinned = [RequiredCheck::pinned("ci", 15368)];
    for runs in [vec![run(Some(999))], vec![run(None)]] {
        let fake = FakeTransport::new().json(
            200,
            &json!({"total_count":runs.len(),"check_runs":runs}).to_string(),
        );
        let result = landing::required_checks(
            &conn(),
            "org/repo",
            &"a".repeat(40),
            &pinned,
            &fake,
            deadline(),
        )
        .await
        .unwrap();
        assert!(!result.passed);
        assert_eq!(result.contexts[0].state, CheckState::Unknown);
        assert_eq!(result.contexts[0].other_apps, 1);
        assert_eq!(result.contexts[0].app_id, Some(15368));
        assert_eq!(fake.requests().len(), 1, "no status read for pinned checks");
    }
    let fake = FakeTransport::new().json(
        200,
        &json!({"total_count":2,"check_runs":[run(Some(999)), run(Some(15368))]}).to_string(),
    );
    let result = landing::required_checks(
        &conn(),
        "org/repo",
        &"a".repeat(40),
        &pinned,
        &fake,
        deadline(),
    )
    .await
    .unwrap();
    assert!(result.passed);
    assert_eq!(result.contexts[0].other_apps, 1);
    // The same impostor still satisfies a name-only (legacy) requirement.
    let fake = FakeTransport::new()
        .json(
            200,
            &json!({"total_count":1,"check_runs":[run(Some(999))]}).to_string(),
        )
        .json(
            200,
            &json!({"sha":"a".repeat(40),"total_count":0,"statuses":[]}).to_string(),
        );
    let result = landing::required_checks(
        &conn(),
        "org/repo",
        &"a".repeat(40),
        &[RequiredCheck::named("ci")],
        &fake,
        deadline(),
    )
    .await
    .unwrap();
    assert!(result.passed);
    assert_eq!(fake.requests().len(), 2);
}
#[test]
fn required_checks_round_trip_legacy_names_as_plain_strings() {
    let list: Vec<RequiredCheck> =
        serde_json::from_value(json!(["ci", {"name": "build", "app_id": 15368}])).unwrap();
    assert_eq!(
        list,
        vec![
            RequiredCheck::named("ci"),
            RequiredCheck::pinned("build", 15368)
        ]
    );
    assert_eq!(
        serde_json::to_value(&list).unwrap(),
        json!(["ci", {"name": "build", "app_id": 15368}])
    );
    for bad in [
        json!({"name": "ci", "app_id": 0}),
        json!({"name": "ci", "app_id": 1, "slug": "x"}),
        json!(7),
    ] {
        assert!(serde_json::from_value::<RequiredCheck>(bad).is_err());
    }
}
