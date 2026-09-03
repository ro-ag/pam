use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret, base64};
use crate::{CallResult, ConnectorError, call, verify};

#[tokio::test]
async fn jobs_asks_for_a_bounded_tree_with_basic_auth() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"jobs":[{"name":"platform","url":"https://ci.example.com/job/platform/","color":"red","health":"drop"}]}"#,
    );
    let result = run("jobs", &[], &transport).await.unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://ci.example.com/jenkins/api/json?"),
        "{url}"
    );
    assert!(url.contains("tree=jobs"), "{url}");
    assert!(
        url.contains("%7B0%2C50%7D") || url.contains("{0,50}"),
        "{url}"
    );
    assert_eq!(
        transport.header(0, "authorization"),
        Some(format!("Basic {}", base64(b"ci-bot:t0ken")))
    );

    let CallResult::Json(value) = result else {
        panic!("jobs answers with JSON");
    };
    assert_eq!(value["jobs"][0]["name"], "platform");
    assert_eq!(value["jobs"][0]["color"], "red");
    assert!(value["jobs"][0].get("health").is_none());
}

#[tokio::test]
async fn a_folder_path_becomes_a_job_path() {
    let transport = FakeTransport::new().json(200, r#"{"builds":[]}"#);
    run("builds", &[("job", "platform/nightly")], &transport)
        .await
        .unwrap();
    let url = transport.url(0);
    assert!(
        url.starts_with("https://ci.example.com/jenkins/job/platform/job/nightly/api/json?"),
        "{url}"
    );
}

#[tokio::test]
async fn builds_keeps_the_named_fields_and_echoes_the_job() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"builds":[{"number":41,"result":"FAILURE","timestamp":1,"duration":2,
            "url":"https://ci.example.com/job/platform/41/","culprits":["nobody"]}]}"#,
    );
    let result = run("builds", &[("job", "platform")], &transport)
        .await
        .unwrap();
    let CallResult::Json(value) = result else {
        panic!("builds answers with JSON");
    };
    assert_eq!(value["job"], "platform");
    assert_eq!(value["builds"][0]["number"], 41);
    assert_eq!(value["builds"][0]["result"], "FAILURE");
    assert!(value["builds"][0].get("culprits").is_none());
}

#[tokio::test]
async fn console_reads_the_result_then_the_text() {
    let transport = FakeTransport::new()
        .json(200, r#"{"result":"FAILURE","building":false}"#)
        .bytes(200, b"Started by user pam\nBUILD FAILURE".to_vec());
    let result = console(&transport, "platform", 41).await.unwrap();

    assert!(
        transport
            .url(0)
            .starts_with("https://ci.example.com/jenkins/job/platform/41/api/json?"),
        "{}",
        transport.url(0)
    );
    assert_eq!(
        transport.url(1),
        "https://ci.example.com/jenkins/job/platform/41/consoleText"
    );

    let CallResult::Log {
        name,
        bytes,
        exit_status,
    } = result
    else {
        panic!("console answers with a log");
    };
    assert_eq!(name, "jenkins-platform-41.log");
    assert!(bytes.ends_with(b"BUILD FAILURE"));
    assert_eq!(exit_status, Some(1));
}

#[tokio::test]
async fn a_builds_result_decides_the_exit_status() {
    for (result, expected) in [
        ("\"SUCCESS\"", Some(0)),
        ("\"FAILURE\"", Some(1)),
        ("\"ABORTED\"", Some(1)),
        ("\"UNSTABLE\"", Some(1)),
        ("null", None),
    ] {
        let transport = FakeTransport::new()
            .json(200, &format!(r#"{{"result":{result}}}"#))
            .bytes(200, b"log".to_vec());
        let CallResult::Log { exit_status, .. } = console(&transport, "platform", 1).await.unwrap()
        else {
            panic!("console answers with a log");
        };
        assert_eq!(exit_status, expected, "{result}");
    }
}

#[tokio::test]
async fn a_nested_log_name_flattens_the_folder_path() {
    let transport = FakeTransport::new()
        .json(200, r#"{"result":"SUCCESS"}"#)
        .bytes(200, b"log".to_vec());
    let CallResult::Log { name, .. } = console(&transport, "platform/nightly", 3).await.unwrap()
    else {
        panic!("console answers with a log");
    };
    assert_eq!(name, "jenkins-platform-nightly-3.log");
}

#[tokio::test]
async fn a_job_argument_that_is_not_a_path_is_refused() {
    let transport = FakeTransport::new();
    for job in ["", "a//b", "with space"] {
        let error = run("builds", &[("job", job)], &transport)
            .await
            .unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{job}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn verify_names_the_authenticated_user() {
    let transport = FakeTransport::new().json(200, r#"{"id":"ci-bot","fullName":"CI Bot"}"#);
    let report = verify(ConnectorId::Jenkins, &connection(), &transport, deadline())
        .await
        .unwrap();
    assert_eq!(report.detail, "authenticated as ci-bot");
    assert_eq!(
        transport.url(0),
        "https://ci.example.com/jenkins/me/api/json"
    );
}

#[tokio::test]
async fn verify_refuses_an_answer_without_an_id() {
    let transport = FakeTransport::new().json(200, r#"{"fullName":"CI Bot"}"#);
    let error = verify(ConnectorId::Jenkins, &connection(), &transport, deadline())
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

#[tokio::test]
async fn a_missing_credential_is_refused_before_any_request() {
    let transport = FakeTransport::new();
    let bare = Connection {
        base_url: Url::parse("https://ci.example.com/jenkins/").unwrap(),
        username: Some("ci-bot".to_owned()),
        secret: None,
    };
    let error = call(
        ConnectorId::Jenkins,
        &bare,
        "jobs",
        &BTreeMap::new(),
        &transport,
        deadline(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::Auth);
    assert!(transport.requests().is_empty());
}

async fn console(
    transport: &FakeTransport,
    job: &str,
    build: i64,
) -> Result<CallResult, ConnectorError> {
    let mut args = args(&[("job", job)]);
    args.insert("build".to_owned(), ArgValue::Int(build));
    call(
        ConnectorId::Jenkins,
        &connection(),
        "console",
        &args,
        transport,
        deadline(),
    )
    .await
}

async fn run(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Jenkins,
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
        base_url: Url::parse("https://ci.example.com/jenkins/").expect("the base URL parses"),
        username: Some("ci-bot".to_owned()),
        secret: Some(Secret::new("t0ken".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
