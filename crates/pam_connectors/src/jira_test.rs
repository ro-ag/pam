use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::jira::cut_at;
use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret};
use crate::{CallResult, ConnectorError, call, verify};

#[tokio::test]
async fn search_sends_the_jql_the_page_size_and_the_field_list() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"total":9,"issues":[{"key":"PAM-1","fields":{"summary":"flaky test",
            "status":{"name":"Open"},"issuetype":{"name":"Bug"},"priority":{"name":"High"},
            "assignee":{"displayName":"Ada"},"updated":"2026-09-01T10:00:00Z"}}]}"#,
    );
    let mut args = args(&[("jql", "project = PAM AND status = Open")]);
    args.insert("limit".to_owned(), ArgValue::Int(1));
    let result = call(
        ConnectorId::Jira,
        &connection(),
        "search",
        &args,
        &transport,
        deadline(),
    )
    .await
    .unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://jira.example.com/rest/api/2/search?"),
        "{url}"
    );
    assert!(url.contains("jql=project+%3D+PAM"), "{url}");
    assert!(url.contains("maxResults=1"), "{url}");
    assert!(url.contains("fields=summary%2Cstatus"), "{url}");
    assert_eq!(
        transport.header(0, "authorization"),
        Some("Bearer pat_abc".to_owned())
    );

    let CallResult::Json(value) = result else {
        panic!("search answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(value["total"], 9);
    assert_eq!(value["issues"][0]["key"], "PAM-1");
    assert_eq!(value["issues"][0]["summary"], "flaky test");
    assert_eq!(value["issues"][0]["status"], "Open");
    assert_eq!(value["issues"][0]["issuetype"], "Bug");
    assert_eq!(value["issues"][0]["assignee"], "Ada");
}

#[tokio::test]
async fn a_page_that_holds_everything_is_not_partial() {
    let transport = FakeTransport::new().json(200, r#"{"total":1,"issues":[{"key":"PAM-1"}]}"#);
    let CallResult::Json(value) = run("search", &[("jql", "project = PAM")], &transport)
        .await
        .unwrap()
    else {
        panic!("search answers with JSON");
    };
    assert_eq!(value["partial"], false);
    assert!(value["issues"][0]["summary"].is_null());
}

#[tokio::test]
async fn issue_asks_for_the_description_too() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"key":"PAM-7","fields":{"summary":"crash","description":"a stack trace",
            "status":{"name":"Done"}}}"#,
    );
    let result = run("issue", &[("key", "PAM-7")], &transport).await.unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://jira.example.com/rest/api/2/issue/PAM-7?"),
        "{url}"
    );
    assert!(url.contains("description"), "{url}");

    let CallResult::Json(value) = result else {
        panic!("issue answers with JSON");
    };
    assert_eq!(value["partial"], false);
    assert_eq!(value["issue"]["key"], "PAM-7");
    assert_eq!(value["issue"]["description"], "a stack trace");
    assert_eq!(value["issue"]["status"], "Done");
}

#[tokio::test]
async fn a_long_description_is_cut_and_the_answer_says_so() {
    let description = "x".repeat(20 * 1024);
    let transport = FakeTransport::new().json(
        200,
        &format!(r#"{{"key":"PAM-7","fields":{{"description":"{description}"}}}}"#),
    );
    let CallResult::Json(value) = run("issue", &[("key", "PAM-7")], &transport).await.unwrap()
    else {
        panic!("issue answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(
        value["issue"]["description"].as_str().unwrap().len(),
        16 * 1024
    );
}

#[tokio::test]
async fn a_key_that_is_not_an_issue_key_is_refused() {
    let transport = FakeTransport::new();
    for key in ["PAM", "../admin", "PAM 7", ""] {
        let error = run("issue", &[("key", key)], &transport).await.unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{key}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn verify_needs_a_name_or_a_key() {
    let transport = FakeTransport::new().json(200, r#"{"name":"ada","emailAddress":"a@b.c"}"#);
    let report = verify(ConnectorId::Jira, &connection(), &transport, deadline())
        .await
        .unwrap();
    assert_eq!(report.detail, "authenticated as ada");
    assert_eq!(
        transport.url(0),
        "https://jira.example.com/rest/api/2/myself"
    );

    let transport = FakeTransport::new().json(200, r#"{"key":"JIRAUSER1"}"#);
    assert_eq!(
        verify(ConnectorId::Jira, &connection(), &transport, deadline())
            .await
            .unwrap()
            .detail,
        "authenticated as JIRAUSER1"
    );

    let transport = FakeTransport::new().json(200, r#"{"self":"https://jira.example.com/x"}"#);
    let error = verify(ConnectorId::Jira, &connection(), &transport, deadline())
        .await
        .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

#[test]
fn cutting_text_stops_on_a_character_boundary() {
    assert_eq!(cut_at("hello", 16), ("hello".to_owned(), false));
    let (cut, was_cut) = cut_at("héllo", 2);
    assert!(was_cut);
    assert_eq!(cut, "h");
}

async fn run(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Jira,
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
        base_url: Url::parse("https://jira.example.com/").expect("the base URL parses"),
        username: None,
        secret: Some(Secret::new("pat_abc".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
