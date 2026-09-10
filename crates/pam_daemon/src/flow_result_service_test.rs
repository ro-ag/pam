use pam_proto::Outcome;
use pam_store::Store;
use serde_json::json;

use crate::flow_result_service::{authorized_metadata, bounded_output, validated_projection};

async fn fixture() -> (tempfile::TempDir, Store, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir
        .path()
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let store = Store::open_in_memory().await.unwrap();
    store
        .set_setting(
            "flows.scope_policy",
            &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string(),
        )
        .await
        .unwrap();
    store
        .insert_admitted_request("r", "echo", &repo, "test", "{}", None, i64::MAX)
        .await
        .unwrap();
    (dir, store, repo)
}

#[tokio::test]
async fn status_authorization_denies_cross_repo_legacy_and_revoked_tickets() {
    let (_dir, store, repo) = fixture().await;
    assert!(authorized_metadata(&store, &repo, "r").await.is_ok());
    let other = tempfile::tempdir().unwrap();
    assert!(
        authorized_metadata(&store, &other.path().to_string_lossy(), "r")
            .await
            .is_err()
    );
    store
        .insert_request("legacy", "echo", &repo, "test", "{}", None)
        .await
        .unwrap();
    assert!(authorized_metadata(&store, &repo, "legacy").await.is_err());
    store.insert_grant("echo").await.unwrap();
    store.revoke_grant("echo").await.unwrap();
    assert!(authorized_metadata(&store, &repo, "r").await.is_err());
}

#[test]
fn raw_legacy_projection_and_oversized_response_are_refused() {
    assert!(validated_projection(&json!({"steps":[{"stdout":"secret"}]}), "r").is_err());
    assert!(validated_projection(&json!({"schema_version":1,"ticket":"other"}), "r").is_err());
    assert!(bounded_output("r", Outcome::Verified, json!({"text":"x".repeat(16384)})).is_err());
    assert!(bounded_output("r", Outcome::Blocked, json!({"state":"done"})).is_ok());
}

#[tokio::test]
async fn captured_product_scope_is_required_even_for_persisted_status() {
    let (_dir, store, repo) = fixture().await;
    let base = "https://jenkins.example.test/";
    store
        .upsert_connector(
            "jenkins",
            pam_store::ConnectorPatch {
                enabled: Some(true),
                base_url: Some(Some(base)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    store
        .insert_evidence(
            "verdict",
            "r",
            "flow.result",
            b"protected raw verdict",
            Some("{\"agent_result\":{}}"),
        )
        .await
        .unwrap();
    store.insert_evidence_view(&pam_store::EvidenceViewInsert {evidence_id:"verdict".into(),request_id:"r".into(),repository:repo.clone(),origin_json:json!({"targets":[{"connector":"jenkins","base_url":base,"call":"builds","args":{"job":pam_connectors::ArgValue::Text("team/build".into())}}]}).to_string(),identity_json:"{}".into(),map_json:"[]".into(),view_id:"v".into(),view_bytes:vec![]}).await.unwrap();
    assert!(authorized_metadata(&store, &repo, "r").await.is_err());
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":repo,"connectors":[{"connector":"jenkins","base_url":base,"access":"connector_wide","targets":[]}]}]}).to_string()).await.unwrap();
    assert!(authorized_metadata(&store, &repo, "r").await.is_ok());
    store
        .upsert_connector(
            "jenkins",
            pam_store::ConnectorPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(authorized_metadata(&store, &repo, "r").await.is_err());
}
