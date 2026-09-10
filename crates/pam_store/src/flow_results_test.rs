use crate::{EvidenceViewInsert, Store};

#[tokio::test]
async fn status_lookup_does_not_require_loading_large_request_arguments() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "echo", "/repo", "test", &"x".repeat(1024 * 1024), None)
        .await
        .unwrap();
    let meta = store.request_status_meta("r").await.unwrap().unwrap();
    assert_eq!(meta.capability, "echo");
    assert!(meta.authorization_revision.is_none());
    assert!(store.request_status_meta("absent").await.unwrap().is_none());
}

#[tokio::test]
async fn result_lookup_is_scoped_and_refuses_large_legacy_metadata() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    for (id, metadata) in [
        ("valid", "{\"agent_result\":{}}".to_owned()),
        ("oversized", "x".repeat(16385)),
    ] {
        store
            .insert_evidence(
                id,
                "r",
                "flow.result",
                &vec![42; 1024 * 1024],
                Some(&metadata),
            )
            .await
            .unwrap();
        store
            .insert_evidence_view(&EvidenceViewInsert {
                evidence_id: id.into(),
                request_id: "r".into(),
                repository: format!("/{id}"),
                origin_json: "{\"targets\":[]}".into(),
                identity_json: "{}".into(),
                map_json: "[]".into(),
                view_id: format!("view-{id}"),
                view_bytes: vec![],
            })
            .await
            .unwrap();
    }
    assert!(
        store
            .flow_result_meta("r", "/valid")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .flow_result_meta("r", "/oversized")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .flow_result_meta("r", "/other")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .flow_result_meta("other", "/valid")
            .await
            .unwrap()
            .is_none()
    );
}
