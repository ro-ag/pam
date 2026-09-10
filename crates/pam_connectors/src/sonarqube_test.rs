use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret, base64};
use crate::{CallResult, ConnectorError, call, verify};

#[tokio::test]
async fn the_token_goes_where_the_user_name_goes() {
    let transport =
        FakeTransport::new().json(200, r#"{"projectStatus":{"status":"OK","conditions":[]}}"#);
    run("quality_gate", &[("project", "ro-ag_pam")], &transport)
        .await
        .unwrap();
    assert_eq!(
        transport.header(0, "authorization"),
        Some(format!("Basic {}", base64(b"squ_abc:")))
    );
}

#[tokio::test]
async fn quality_gate_flattens_the_conditions() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"projectStatus":{"status":"ERROR","conditions":[
            {"status":"ERROR","metricKey":"new_coverage","comparator":"LT",
             "errorThreshold":"80","actualValue":"61.4"}]}}"#,
    );
    let result = run("quality_gate", &[("project", "ro-ag_pam")], &transport)
        .await
        .unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://sonar.example.com/api/qualitygates/project_status?"),
        "{url}"
    );
    assert!(url.contains("projectKey=ro-ag_pam"), "{url}");

    let CallResult::Json(value) = result else {
        panic!("quality_gate answers with JSON");
    };
    assert_eq!(value["status"], "ERROR");
    assert_eq!(value["project"], "ro-ag_pam");
    assert_eq!(value["conditions"][0]["metric"], "new_coverage");
    assert_eq!(value["conditions"][0]["actual"], "61.4");
    assert_eq!(value["conditions"][0]["threshold"], "80");
    assert_eq!(value["conditions"][0]["status"], "ERROR");
}

#[tokio::test]
async fn quality_gate_refuses_an_answer_without_a_project_status() {
    let transport = FakeTransport::new().json(200, r#"{"errors":[{"msg":"nope"}]}"#);
    let error = run("quality_gate", &[("project", "p")], &transport)
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

#[tokio::test]
async fn issues_asks_for_unresolved_issues_and_reports_what_it_could_not_fit() {
    let transport = advertised().json(
        200,
        r#"{"total":120,"issues":[{"key":"K1","rule":"rust:S1","severity":"MAJOR",
            "project":"ro-ag_pam","component":"pam:src/lib.rs","line":12,"message":"tidy this","type":"CODE_SMELL",
            "author":"dropped"}]}"#,
    );
    let mut args = args(&[("project", "ro-ag_pam")]);
    args.insert("limit".to_owned(), ArgValue::Int(1));
    let result = call(
        ConnectorId::Sonarqube,
        &connection(),
        "issues",
        &args,
        &transport,
        deadline(),
    )
    .await
    .unwrap();

    let url = transport.url(1);
    assert!(url.contains("components=ro-ag_pam"), "{url}");
    assert!(url.contains("resolved=false"), "{url}");
    assert!(url.contains("ps=1"), "{url}");

    let CallResult::Json(value) = result else {
        panic!("issues answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(value["total"], 120);
    assert_eq!(value["issues"][0]["key"], "K1");
    assert_eq!(value["issues"][0]["line"], 12);
    assert!(value["issues"][0].get("author").is_none());
}

#[tokio::test]
async fn a_complete_page_is_not_partial() {
    let transport = advertised().json(200, r#"{"total":1,"issues":[{"key":"K1","project":"p"}]}"#);
    let CallResult::Json(value) = run("issues", &[("project", "p")], &transport)
        .await
        .unwrap()
    else {
        panic!("issues answers with JSON");
    };
    assert_eq!(value["partial"], false);
}

#[tokio::test]
async fn verify_needs_valid_true_not_just_a_200() {
    let transport = FakeTransport::new().json(200, r#"{"valid":false}"#);
    let error = verify(
        ConnectorId::Sonarqube,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::Auth);
    assert_eq!(
        transport.url(0),
        "https://sonar.example.com/api/authentication/validate"
    );

    let transport = FakeTransport::new().json(200, r#"{"valid":true}"#);
    let report = verify(
        ConnectorId::Sonarqube,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        report.detail.contains("sonar.example.com"),
        "{}",
        report.detail
    );
}

#[tokio::test]
async fn an_unknown_call_names_what_sonarqube_offers() {
    let transport = FakeTransport::new();
    let error = run("measures", &[], &transport).await.unwrap_err();
    assert!(error.detail().contains("quality_gate"), "{error:?}");
}

async fn run(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Sonarqube,
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
        base_url: Url::parse("https://sonar.example.com/").expect("the base URL parses"),
        username: None,
        secret: Some(Secret::new("squ_abc".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn advertised() -> FakeTransport {
    FakeTransport::new().json(
        200,
        r#"{"webServices":[
        {"path":"api/issues","actions":[{"key":"search","params":[
            {"key":"components"},{"key":"resolved"},{"key":"ps"},
            {"key":"branch"},{"key":"pullRequest"}]}]},
        {"path":"api/qualitygates","actions":[{"key":"project_status","params":[
            {"key":"projectKey"},{"key":"branch"},{"key":"pullRequest"}]}]}]}"#,
    )
}

#[tokio::test]
async fn conflicting_selectors_and_project_lists_never_send_http() {
    for name in ["issues", "quality_gate"] {
        let transport = FakeTransport::new();
        assert!(matches!(
            run(
                name,
                &[("project", "p"), ("branch", "main"), ("pullRequest", "12")],
                &transport
            )
            .await,
            Err(ConnectorError::BadArgs(_))
        ));
        assert!(matches!(
            run(name, &[("project", "p,other")], &transport).await,
            Err(ConnectorError::BadArgs(_))
        ));
        assert!(transport.requests().is_empty());
    }
}

#[tokio::test]
async fn selectors_are_encoded_and_preserved_as_requested_not_analysis_identity() {
    for name in ["issues", "quality_gate"] {
        for key in ["branch", "pullRequest"] {
            let body = if name == "issues" {
                r#"{"paging":{"total":0},"issues":[]}"#
            } else {
                r#"{"projectStatus":{"status":"NONE","conditions":[]}}"#
            };
            let transport = advertised().json(200, body);
            let CallResult::Json(value) = run(
                name,
                &[("project", "org:p"), (key, "feature/a & b")],
                &transport,
            )
            .await
            .unwrap() else {
                panic!("JSON expected")
            };
            let url = Url::parse(&transport.url(1)).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(k, v)| k == key && v == "feature/a & b")
            );
            assert_eq!(value["requested"][key], "feature/a & b");
            assert_eq!(value["requested"]["project"], "org:p");
            assert!(value.get("analysis_id").is_none());
        }
    }
}

#[tokio::test]
async fn old_or_unknown_api_contract_cannot_issue_an_unfiltered_search() {
    for metadata in [
        r#"{"webServices":[]}"#,
        r#"{"webServices":[{"path":"api/issues","actions":[{"key":"search","params":[{"key":"componentKeys"},{"key":"resolved"},{"key":"ps"}]}]}]}"#,
    ] {
        let transport = FakeTransport::new().json(200, metadata);
        assert_eq!(
            run("issues", &[("project", "p")], &transport)
                .await
                .unwrap_err()
                .cause(),
            "sonarqube_contract_unavailable"
        );
        assert_eq!(transport.requests().len(), 1);
    }
}

#[tokio::test]
async fn missing_or_conflicting_issue_identity_is_not_returned() {
    for body in [
        r#"{"issues":[{"key":"K"}]}"#,
        r#"{"issues":[{"project":"other"}]}"#,
        r#"{"issues":[{"project":"p","branch":"other"}]}"#,
    ] {
        let transport = advertised().json(200, body);
        assert!(matches!(
            run(
                "issues",
                &[("project", "p"), ("branch", "main")],
                &transport
            )
            .await,
            Err(ConnectorError::BadResponse(_))
        ));
    }
}

#[tokio::test]
async fn modern_paging_and_unknown_totals_keep_coverage_honest() {
    for (body, partial) in [
        (
            r#"{"paging":{"total":2},"total":0,"issues":[{"project":"p"}]}"#,
            true,
        ),
        (r#"{"issues":[]}"#, true),
        (r#"{"paging":{"total":0},"issues":[]}"#, false),
    ] {
        let transport = advertised().json(200, body);
        let CallResult::Json(value) = run("issues", &[("project", "p")], &transport)
            .await
            .unwrap()
        else {
            panic!("JSON expected")
        };
        assert_eq!(value["partial"], partial);
    }
}

#[tokio::test]
async fn gate_unknown_status_and_conflicting_echo_fail_honestly() {
    for body in [
        r#"{"projectStatus":{"status":"PASS","conditions":[]}}"#,
        r#"{"project":"other","projectStatus":{"status":"OK","conditions":[]}}"#,
    ] {
        let transport = FakeTransport::new().json(200, body);
        assert!(matches!(
            run("quality_gate", &[("project", "p")], &transport).await,
            Err(ConnectorError::BadResponse(_))
        ));
    }
    for status in [401, 403, 404, 500] {
        let transport = advertised().json(status, "{}");
        assert!(
            run("issues", &[("project", "p")], &transport)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn unadvertised_gate_selector_is_never_sent() {
    let transport = FakeTransport::new().json(200, r#"{"webServices":[{"path":"api/qualitygates","actions":[{"key":"project_status","params":[{"key":"projectKey"}]}]}]}"#);
    assert_eq!(
        run(
            "quality_gate",
            &[("project", "p"), ("branch", "main")],
            &transport
        )
        .await
        .unwrap_err()
        .cause(),
        "sonarqube_contract_unavailable"
    );
    assert_eq!(transport.requests().len(), 1);
}
