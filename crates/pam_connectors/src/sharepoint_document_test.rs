use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use pam_flow::ArgValue;
use serde_json::{Value, json};
use url::Url;

use crate::testing::FakeTransport;
use crate::transport::{Connection, Secret};
use crate::{CallResult, ConnectorError};

const SITE: &str = "contoso.sharepoint.com,site,web";
fn meta() -> Value {
    json!({"id":"item", "parentReference":{"driveId":"drive"},"name":"runbook.txt","webUrl":"https://contoso.sharepoint.com/sites/team/runbook.txt","size":5,"lastModifiedDateTime":"2026-09-10T00:00:00Z","eTag":"etag-1","cTag":"ctag-1","file":{"mimeType":"text/plain"}})
}
fn start() -> FakeTransport {
    FakeTransport::new().json(
        200,
        &json!({"id":SITE,"webUrl":"https://contoso.sharepoint.com/sites/team"}).to_string(),
    )
}
fn prepared(metadata: &Value) -> FakeTransport {
    start()
        .json(200, r#"{"value":[{"id":"drive"}]}"#)
        .json(200, &metadata.to_string())
}
fn redirect(t: FakeTransport, location: &str) -> FakeTransport {
    t.with_headers(302, &[("Location", location)], "")
}
async fn run(t: &FakeTransport) -> Result<Value, ConnectorError> {
    let conn = Connection {
        base_url: Url::parse("https://graph.microsoft.com/v1.0/").unwrap(),
        username: None,
        secret: Some(Secret::new("secret".to_owned())),
    };
    let args: BTreeMap<_, _> = [("site", SITE), ("drive", "drive"), ("item", "item")]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), ArgValue::Text(v.to_owned())))
        .collect();
    let CallResult::Json(value) = super::sharepoint_document::document(
        &conn,
        &args,
        t,
        Instant::now() + Duration::from_secs(10),
    )
    .await?
    else {
        panic!("JSON expected")
    };
    Ok(value)
}

#[tokio::test]
async fn captures_text_after_site_membership_and_version_recheck_without_leaking_download_secret() {
    let t = redirect(
        prepared(&meta()),
        "https://contoso.sharepoint.com/download?signature=do-not-persist",
    )
    .bytes(200, b"hello".to_vec())
    .json(200, &meta().to_string());
    let result = run(&t).await.unwrap();
    assert_eq!(result["content"]["text"], "hello");
    assert_eq!(result["content"]["consistency"], "metadata_rechecked");
    assert_eq!(result["content"]["retained_bytes"], 5);
    assert_eq!(result["partial"], false);
    assert!(!result.to_string().contains("do-not-persist"));
    assert_eq!(t.requests().len(), 6);
    assert!(
        t.url(1)
            .contains("/sites/contoso.sharepoint.com,site,web/drives?$top=100")
    );
    assert!(t.url(2).ends_with("/drives/drive/items/item"));
    assert_eq!(
        t.header(3, "authorization"),
        Some("Bearer secret".to_owned())
    );
    assert_eq!(t.header(4, "authorization"), None);
    assert!(
        t.requests()
            .iter()
            .all(|r| !r.follow_one_https_redirect_without_auth)
    );
}

#[tokio::test]
async fn refuses_unproved_drive_before_global_drive_endpoint_even_with_next_page() {
    let t = start().json(
        200,
        r#"{"value":[{"id":"other"}],"@odata.nextLink":"https://evil.test/page"}"#,
    );
    assert!(run(&t).await.is_err());
    assert_eq!(t.requests().len(), 2);
}

#[tokio::test]
async fn mismatched_site_item_drive_or_remote_alias_cannot_capture() {
    let t = FakeTransport::new().json(200, r#"{"id":"other","webUrl":"https://evil.test/site"}"#);
    assert!(run(&t).await.is_err());
    assert_eq!(t.requests().len(), 1);
    for (key, value) in [
        ("id", json!("other")),
        ("parentReference", json!({"driveId":"other"})),
        ("remoteItem", json!({"id":"remote"})),
        ("webUrl", json!("https://evil.test/file")),
    ] {
        let mut metadata = meta();
        metadata[key] = value;
        let t = prepared(&metadata);
        assert!(run(&t).await.is_err(), "{key}");
        assert_eq!(t.requests().len(), 3);
    }
}

#[tokio::test]
async fn signed_redirect_is_exact_host_https_without_credentials_or_second_hop() {
    for url in [
        "https://contoso.sharepoint.com.evil.test/file",
        "https://files.1drv.com/file",
        "http://contoso.sharepoint.com/file",
        "https://user@contoso.sharepoint.com/file",
        "https://contoso.sharepoint.com:444/file",
        "https://contoso.sharepoint.com/file#fragment",
    ] {
        let t = redirect(prepared(&meta()), url);
        assert_eq!(
            run(&t).await.unwrap()["content"]["state"],
            "unsupported_download_host"
        );
        assert_eq!(t.requests().len(), 4);
    }
    let t = redirect(
        redirect(prepared(&meta()), "https://contoso.sharepoint.com/file"),
        "https://evil.test/next",
    );
    assert_eq!(
        run(&t).await.unwrap()["content"]["state"],
        "download_unavailable"
    );
    assert_eq!(t.requests().len(), 5);
}

#[tokio::test]
async fn unsupported_or_oversize_metadata_is_retained_without_downloading() {
    for (key, value, state) in [
        ("size", json!(65537), "too_large"),
        (
            "file",
            json!({"mimeType":"application/pdf"}),
            "unsupported_format",
        ),
    ] {
        let mut metadata = meta();
        metadata[key] = value;
        let t = prepared(&metadata);
        let result = run(&t).await.unwrap();
        assert_eq!(result["content"]["state"], state);
        assert!(result["content"]["text"].is_null());
        assert_eq!(result["metadata"]["id"], "item");
        assert_eq!(t.requests().len(), 3);
    }
}

#[tokio::test]
async fn refuses_oversize_and_invalid_utf8_downloads_without_lossy_text() {
    for (bytes, state) in [
        (vec![b'x'; 65537], "too_large"),
        (vec![0xff], "unsupported_encoding"),
        (vec![0], "unsupported_encoding"),
    ] {
        let t =
            redirect(prepared(&meta()), "https://contoso.sharepoint.com/file").bytes(200, bytes);
        let result = run(&t).await.unwrap();
        assert_eq!(result["content"]["state"], state);
        assert!(result["content"]["text"].is_null());
        assert_eq!(t.requests().len(), 5);
    }
}

#[tokio::test]
async fn discards_text_when_version_or_identity_changes() {
    for (key, value) in [
        ("eTag", json!("etag-2")),
        ("cTag", json!("ctag-2")),
        ("size", json!(6)),
        ("id", json!("other")),
        ("parentReference", json!({"driveId":"other"})),
    ] {
        let mut after = meta();
        after[key] = value;
        let t = redirect(prepared(&meta()), "https://contoso.sharepoint.com/file")
            .bytes(200, b"hello".to_vec())
            .json(200, &after.to_string());
        let result = run(&t).await.unwrap();
        assert_eq!(result["content"]["state"], "changed_during_read", "{key}");
        assert!(result["content"]["text"].is_null());
        assert_eq!(result["content"]["retained_bytes"], 0);
    }
}

#[tokio::test]
async fn signed_url_never_leaks_in_transport_errors_and_policy_refusals_propagate() {
    let t = redirect(
        prepared(&meta()),
        "https://contoso.sharepoint.com/file?secret=sentinel",
    )
    .failure(crate::TransportError::Network(
        "failed https://contoso.sharepoint.com/file?secret=sentinel".to_owned(),
    ));
    let result = run(&t).await.unwrap();
    assert_eq!(result["content"]["state"], "download_unavailable");
    assert!(!result.to_string().contains("sentinel"));
    let t = redirect(prepared(&meta()), "https://contoso.sharepoint.com/file").failure(
        crate::TransportError::Policy {
            cause: "scope_revoked",
            detail: "scope was revoked".to_owned(),
        },
    );
    assert_eq!(run(&t).await.unwrap_err().cause(), "scope_revoked");
}

#[tokio::test]
async fn drive_membership_is_bounded_and_does_not_guess_beyond_first_hundred() {
    let mut drives = vec![json!({"id":"other"}); 100];
    drives.push(json!({"id":"drive"}));
    let t = start().json(200, &json!({"value":drives}).to_string());
    assert!(run(&t).await.is_err());
    assert_eq!(t.requests().len(), 2);
}
