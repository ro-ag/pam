use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret, base64};
use crate::{CallResult, ConnectorError, call, verify};

#[tokio::test]
async fn search_sends_the_cql_and_authenticates_with_the_account_email() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"totalSize":1,"results":[{"id":"42","type":"page","title":"Runbook",
            "status":"current","space":{"key":"OPS"},"version":{"number":7}}],"_links":{}}"#,
    );
    let result = run("search", &[("cql", "space = OPS")], &transport)
        .await
        .unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://acme.atlassian.net/wiki/rest/api/content/search?"),
        "{url}"
    );
    assert!(url.contains("cql=space+%3D+OPS"), "{url}");
    assert!(url.contains("limit=20"), "{url}");
    assert!(url.contains("expand=space%2Cversion"), "{url}");
    assert_eq!(
        transport.header(0, "authorization"),
        Some(format!("Basic {}", base64(b"ada@example.com:api_token")))
    );

    let CallResult::Json(value) = result else {
        panic!("search answers with JSON");
    };
    assert_eq!(value["partial"], false);
    assert_eq!(value["results"][0]["id"], "42");
    assert_eq!(value["results"][0]["space"], "OPS");
    assert_eq!(value["results"][0]["version"], 7);
}

#[tokio::test]
async fn a_next_link_or_a_bigger_total_makes_the_answer_partial() {
    let with_next = FakeTransport::new().json(
        200,
        r#"{"totalSize":1,"results":[{"id":"1"}],"_links":{"next":"/rest/api/content/search?cursor=2"}}"#,
    );
    let CallResult::Json(value) = run("search", &[("cql", "type = page")], &with_next)
        .await
        .unwrap()
    else {
        panic!("search answers with JSON");
    };
    assert_eq!(value["partial"], true);

    let with_total = FakeTransport::new().json(
        200,
        r#"{"totalSize":80,"results":[{"id":"1"}],"_links":{}}"#,
    );
    let CallResult::Json(value) = run("search", &[("cql", "type = page")], &with_total)
        .await
        .unwrap()
    else {
        panic!("search answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(value["total"], 80);
}

#[tokio::test]
async fn page_expands_the_storage_body() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"id":"42","type":"page","title":"Runbook","space":{"key":"OPS"},
            "version":{"number":7},"body":{"storage":{"value":"<p>steps</p>"}}}"#,
    );
    let result = run("page", &[("id", "42")], &transport).await.unwrap();

    let url = transport.url(0);
    assert!(
        url.starts_with("https://acme.atlassian.net/wiki/rest/api/content/42?"),
        "{url}"
    );
    assert!(url.contains("body.storage"), "{url}");

    let CallResult::Json(value) = result else {
        panic!("page answers with JSON");
    };
    assert_eq!(value["partial"], false);
    assert_eq!(value["page"]["body"], "<p>steps</p>");
    assert_eq!(value["page"]["title"], "Runbook");
}

#[tokio::test]
async fn a_long_page_body_is_cut_and_the_answer_says_so() {
    let body = "y".repeat(100 * 1024);
    let transport = FakeTransport::new().json(
        200,
        &format!(r#"{{"id":"42","body":{{"storage":{{"value":"{body}"}}}}}}"#),
    );
    let CallResult::Json(value) = run("page", &[("id", "42")], &transport).await.unwrap() else {
        panic!("page answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(value["page"]["body"].as_str().unwrap().len(), 64 * 1024);
}

#[tokio::test]
async fn a_content_id_that_is_not_an_id_is_refused() {
    let transport = FakeTransport::new();
    for id in ["../secrets", "42/child", "", "a b"] {
        let error = run("page", &[("id", id)], &transport).await.unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{id}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn verify_needs_an_account_id_or_a_display_name() {
    let transport = FakeTransport::new().json(200, r#"{"displayName":"Ada","accountId":"5b1"}"#);
    let report = verify(
        ConnectorId::Confluence,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(report.detail, "authenticated as Ada");
    assert_eq!(
        transport.url(0),
        "https://acme.atlassian.net/wiki/rest/api/user/current"
    );

    let transport = FakeTransport::new().json(200, r#"{"accountId":"5b1"}"#);
    assert_eq!(
        verify(
            ConnectorId::Confluence,
            &connection(),
            &transport,
            deadline()
        )
        .await
        .unwrap()
        .detail,
        "authenticated as 5b1"
    );

    let transport = FakeTransport::new().json(200, r#"{"type":"known"}"#);
    let error = verify(
        ConnectorId::Confluence,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

#[tokio::test]
async fn a_missing_email_is_an_auth_failure_before_any_request() {
    let transport = FakeTransport::new();
    let bare = Connection {
        base_url: Url::parse("https://acme.atlassian.net/wiki/").unwrap(),
        username: None,
        secret: Some(Secret::new("api_token".to_owned())),
    };
    let error = call(
        ConnectorId::Confluence,
        &bare,
        "page",
        &args(&[("id", "42")]),
        &transport,
        deadline(),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ConnectorError::Auth);
}

async fn run(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Confluence,
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
        base_url: Url::parse("https://acme.atlassian.net/wiki/").expect("the base URL parses"),
        username: Some("ada@example.com".to_owned()),
        secret: Some(Secret::new("api_token".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
