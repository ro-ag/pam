use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret};
use crate::{CallResult, ConnectorError, call, verify};

const SITE: &str = "contoso.sharepoint.com,7e1a,9b2c";

#[tokio::test]
async fn documents_embeds_the_search_term_in_the_path_and_bounds_the_page() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"value":[{"id":"01A","name":"runbook.docx","webUrl":"https://contoso/x",
            "size":4096,"lastModifiedDateTime":"2026-09-01T00:00:00Z","cTag":"dropped"}]}"#,
    );
    let result = run(
        "documents",
        &[("site", SITE), ("query", "runbook")],
        &transport,
    )
    .await
    .unwrap();

    let url = transport.url(0);
    assert!(
        url.contains("/sites/contoso.sharepoint.com,7e1a,9b2c/drive/root/"),
        "{url}"
    );
    assert!(url.contains("search(q='runbook')"), "{url}");
    assert!(url.contains("$top=20"), "{url}");
    assert_eq!(
        transport.header(0, "authorization"),
        Some("Bearer graph_token".to_owned())
    );

    let CallResult::Json(value) = result else {
        panic!("documents answers with JSON");
    };
    assert_eq!(value["documents"][0]["name"], "runbook.docx");
    assert_eq!(value["documents"][0]["size"], 4096);
    assert!(value["documents"][0].get("cTag").is_none());
    assert_eq!(value["partial"], false);
}

#[tokio::test]
async fn a_single_quote_in_the_query_is_refused_before_any_request() {
    let transport = FakeTransport::new();
    let error = run(
        "documents",
        &[("site", SITE), ("query", "o'brien')/children?x=")],
        &transport,
    )
    .await
    .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_args");
    assert!(error.detail().contains("single quote"), "{error:?}");
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn a_site_that_could_grow_path_separators_is_refused() {
    let transport = FakeTransport::new();
    for site in ["contoso.sharepoint.com:/sites/ops:", "../me", "", "a b"] {
        let error = run("lists", &[("site", site)], &transport)
            .await
            .unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{site}");
    }
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn lists_reports_partial_from_a_next_link() {
    let transport = FakeTransport::new().json(
        200,
        r#"{"@odata.nextLink":"https://graph.microsoft.com/v1.0/sites/x/lists?$skiptoken=2",
            "value":[{"id":"L1","name":"docs","displayName":"Documents","webUrl":"https://c/x"}]}"#,
    );
    let result = run("lists", &[("site", SITE)], &transport).await.unwrap();
    let url = transport.url(0);
    assert!(url.contains("/lists?"), "{url}");
    assert!(url.contains("$top=20"), "{url}");

    let CallResult::Json(value) = result else {
        panic!("lists answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert_eq!(value["lists"][0]["displayName"], "Documents");
}

#[tokio::test]
async fn a_full_page_is_partial_even_without_a_next_link() {
    let transport = FakeTransport::new().json(200, r#"{"value":[{"id":"L1"},{"id":"L2"}]}"#);
    let mut args = args(&[("site", SITE)]);
    args.insert("limit".to_owned(), ArgValue::Int(2));
    let CallResult::Json(value) = call(
        ConnectorId::Sharepoint,
        &connection(),
        "lists",
        &args,
        &transport,
        deadline(),
    )
    .await
    .unwrap() else {
        panic!("lists answers with JSON");
    };
    assert_eq!(value["partial"], true);
}

#[tokio::test]
async fn verify_names_the_root_site() {
    let transport = FakeTransport::new().json(200, r#"{"id":"contoso.sharepoint.com,1,2"}"#);
    let report = verify(
        ConnectorId::Sharepoint,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(report.detail, "site id contoso.sharepoint.com,1,2");
    assert_eq!(
        transport.url(0),
        "https://graph.microsoft.com/v1.0/sites/root"
    );

    let transport = FakeTransport::new().json(200, r#"{"displayName":"Contoso"}"#);
    let error = verify(
        ConnectorId::Sharepoint,
        &connection(),
        &transport,
        deadline(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.cause(), "connector_bad_response");
}

async fn run(
    name: &str,
    pairs: &[(&str, &str)],
    transport: &FakeTransport,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Sharepoint,
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
        base_url: Url::parse("https://graph.microsoft.com/v1.0/").expect("the base URL parses"),
        username: None,
        secret: Some(Secret::new("graph_token".to_owned())),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
