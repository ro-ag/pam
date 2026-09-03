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
    let transport = FakeTransport::new().json(
        200,
        r#"{"total":120,"issues":[{"key":"K1","rule":"rust:S1","severity":"MAJOR",
            "component":"pam:src/lib.rs","line":12,"message":"tidy this","type":"CODE_SMELL",
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

    let url = transport.url(0);
    assert!(url.contains("componentKeys=ro-ag_pam"), "{url}");
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
    let transport = FakeTransport::new().json(200, r#"{"total":1,"issues":[{"key":"K1"}]}"#);
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
