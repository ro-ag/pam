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

#[tokio::test]
async fn partial_evidence_without_captured_origin_is_not_treated_as_empty() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    assert_eq!(
        store.request_evidence_origins("r", "/repo").await.unwrap(),
        Some(vec![])
    );
    store
        .insert_evidence("partial", "r", "log.source", b"private partial", None)
        .await
        .unwrap();
    assert!(
        store
            .request_evidence_origins("r", "/repo")
            .await
            .unwrap()
            .is_none()
    );
    store
        .insert_evidence_view(&EvidenceViewInsert {
            evidence_id: "partial".into(),
            request_id: "r".into(),
            repository: "/repo".into(),
            origin_json: "{\"targets\":[]}".into(),
            identity_json: "{}".into(),
            map_json: "[]".into(),
            view_id: "partial-view".into(),
            view_bytes: vec![],
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .request_evidence_origins("r", "/repo")
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert!(
        store
            .request_evidence_origins("r", "/other")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn origin_overflow_refuses_whole_set_instead_of_authorizing_prefix() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    for index in 0..257 {
        let id = format!("e{index}");
        store
            .insert_evidence(&id, "r", "log.source", b"input", None)
            .await
            .unwrap();
        store
            .insert_evidence_view(&EvidenceViewInsert {
                evidence_id: id.clone(),
                request_id: "r".into(),
                repository: "/repo".into(),
                origin_json: serde_json::json!({"tag":index}).to_string(),
                identity_json: "{}".into(),
                map_json: "[]".into(),
                view_id: format!("v{index}"),
                view_bytes: vec![],
            })
            .await
            .unwrap();
        if index == 255 {
            assert_eq!(
                store
                    .request_evidence_origins("r", "/repo")
                    .await
                    .unwrap()
                    .unwrap()
                    .len(),
                256
            );
        }
    }
    assert!(
        store
            .request_evidence_origins("r", "/repo")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn private_checkpoint_does_not_block_public_result_but_other_missing_views_do() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence(
            "result",
            "r",
            "flow.result",
            b"public",
            Some(r#"{"agent_result":{}}"#),
        )
        .await
        .unwrap();
    store
        .insert_evidence_view(&EvidenceViewInsert {
            evidence_id: "result".into(),
            request_id: "r".into(),
            repository: "/repo".into(),
            origin_json: r#"{"targets":[]}"#.into(),
            identity_json: "{}".into(),
            map_json: "[]".into(),
            view_id: "result-view".into(),
            view_bytes: b"public".to_vec(),
        })
        .await
        .unwrap();
    store
        .insert_evidence(
            "private",
            "r",
            "flow.checkpoint",
            b"private checkpoint sentinel",
            None,
        )
        .await
        .unwrap();
    assert!(
        store
            .flow_result_meta("r", "/repo")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store.request_evidence_origins("r", "/repo").await.unwrap(),
        Some(vec![r#"{"targets":[]}"#.to_owned()])
    );
    // A known protected handle is insufficient: evidence.read requires a view.
    assert!(
        store
            .evidence_view_meta("r", "private", "/repo")
            .await
            .unwrap()
            .is_none()
    );
    // The exception is the exact private checkpoint kind, not all flow-prefixed evidence.
    store
        .insert_evidence(
            "missing",
            "r",
            "flow.checkpoint.other",
            b"unpublished",
            None,
        )
        .await
        .unwrap();
    assert!(
        store
            .request_evidence_origins("r", "/repo")
            .await
            .unwrap()
            .is_none()
    );
}
