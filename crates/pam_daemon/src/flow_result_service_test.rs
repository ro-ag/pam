use pam_proto::Outcome;
use pam_store::Store;
use serde_json::json;

use crate::flow_result_service::{
    authorized_metadata, bounded_output, fit_optional, validated_projection,
};

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

#[tokio::test]
async fn a_running_request_with_an_unpublished_view_reads_as_pending_not_unavailable() {
    let (_dir, store, repo) = fixture().await;
    // The window a follower's query can land in: the evidence row exists,
    // its view is not written yet.
    store
        .insert_evidence("src", "r", "log.source", b"captured", None)
        .await
        .unwrap();
    let (status, result) = authorized_metadata(&store, &repo, "r")
        .await
        .expect("a running request is readable while its view catches up");
    assert!(!status.state.is_terminal());
    assert!(result.is_none());

    // Terminal with the view still missing is the incomplete publication the
    // strict answer exists for.
    store
        .finish_request(
            "r",
            pam_store::RequestState::Done,
            Some("solved"),
            pam_store::AuditEntry {
                action: "execute",
                actor: pam_store::Actor::System,
                decision: pam_store::Decision::Allow,
                detail: None,
            },
        )
        .await
        .unwrap();
    assert!(authorized_metadata(&store, &repo, "r").await.is_err());
}

#[tokio::test]
async fn admitted_flow_lifecycle_survives_missing_final_projection() {
    let (_dir, store, repo) = fixture().await;
    store
        .insert_admitted_request("flow", "flow.run", &repo, "test", "{}", None, i64::MAX)
        .await
        .unwrap();
    let (status, result) = authorized_metadata(&store, &repo, "flow").await.unwrap();
    let output =
        crate::flow_result_service::result_output("read", "flow", &status, result.as_ref())
            .unwrap();
    assert_eq!(output.body["state"], "running");
    assert_eq!(output.body["ticket"], "flow");
    assert_eq!(output.body["result_unavailable"]["cause"], "not_ready");
    assert_eq!(output.outcome, Outcome::Blocked);
    store
        .finish_request(
            "flow",
            pam_store::RequestState::Failed,
            Some("cancelled"),
            pam_store::AuditEntry {
                action: "cancel",
                decision: pam_store::Decision::Refuse,
                actor: pam_store::Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
    let (status, result) = authorized_metadata(&store, &repo, "flow").await.unwrap();
    let output =
        crate::flow_result_service::result_output("read", "flow", &status, result.as_ref())
            .unwrap();
    assert_eq!(output.body["state"], "failed");
    assert_eq!(output.body["outcome"], "cancelled");
    assert_eq!(
        output.body["result_unavailable"]["cause"],
        "projection_unavailable"
    );
    assert!(output.body["agent_result"].is_null());
    assert_eq!(output.outcome, Outcome::Blocked);
}

#[test]
fn near_cap_result_drops_optional_sections_before_refusing_the_primary_result() {
    // A primary projection that fits its own 14 KiB envelope must stay
    // readable even when the optional watch and accounting no longer fit the
    // 16 KiB response cap; omissions are marked, never silent.
    let primary = json!({"schema_version":1,"ticket":"r","state":"succeeded",
        "agent_result":{"schema_version":1,"ticket":"r","text":"x".repeat(13 * 1024)}});
    assert!(bounded_output("r", Outcome::Verified, primary.clone()).is_ok());
    let watch = json!({"observations":"w".repeat(2 * 1024)});
    let availability = json!({"evidence_reads":{"state":"active","detail":"a".repeat(2 * 1024)}});

    let both = fit_optional(
        "r",
        Outcome::Verified,
        &primary,
        Some(&watch),
        &json!({"evidence_reads":{"state":"active"}}),
    )
    .unwrap();
    assert_eq!(both.body["watch"], watch);
    assert_eq!(
        both.body["read_availability"]["evidence_reads"]["state"],
        "active"
    );

    // Accounting is the first section to collapse.
    let accounting_dropped = fit_optional(
        "r",
        Outcome::Verified,
        &primary,
        Some(&watch),
        &availability,
    )
    .unwrap();
    assert_eq!(accounting_dropped.body["watch"], watch);
    assert_eq!(
        accounting_dropped.body["read_availability"]["omitted"],
        "response_limit"
    );

    // The watch collapses only after the accounting marker is not enough.
    let wide_watch = json!({"observations":"w".repeat(15 * 1024)});
    let watch_dropped = fit_optional(
        "r",
        Outcome::Verified,
        &primary,
        Some(&wide_watch),
        &availability,
    )
    .unwrap();
    assert_eq!(watch_dropped.body["watch"]["omitted"], "response_limit");
    assert_eq!(
        watch_dropped.body["read_availability"]["omitted"],
        "response_limit"
    );
    assert_eq!(
        watch_dropped.body["agent_result"]["ticket"], "r",
        "the primary projection must survive every degradation"
    );
}
