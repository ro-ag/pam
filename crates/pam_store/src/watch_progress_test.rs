use crate::{EvidenceViewInsert, Store};
use serde_json::json;

async fn seed(store: &Store, id: &str, metadata: &str, publish: bool) {
    store
        .insert_evidence(id, "r", "flow.watch", b"observed", Some(metadata))
        .await
        .unwrap();
    if publish {
        store
            .insert_evidence_view(&EvidenceViewInsert {
                evidence_id: id.to_owned(),
                request_id: "r".to_owned(),
                repository: "/repo".to_owned(),
                origin_json: r#"{"targets":[]}"#.to_owned(),
                identity_json: "{}".to_owned(),
                map_json: "[]".to_owned(),
                view_id: format!("v-{id}"),
                view_bytes: b"observed".to_vec(),
            })
            .await
            .unwrap();
    }
}
fn meta(id: &str) -> String {
    json!({"watch_progress":{"step":"ci","connector":"github","status":"queued","watch_state":"pending","polls":1,"next_poll_at":123,"evidence_id":id,"omissions":0},"private":"never returned"}).to_string()
}

#[tokio::test]
async fn progress_requires_matching_published_view_and_projects_metadata_only() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    seed(&store, "e", &meta("e"), false).await;
    assert!(
        store
            .flow_watch_progress("r", "/repo")
            .await
            .unwrap()
            .is_none()
    );
    store
        .insert_evidence_view(&EvidenceViewInsert {
            evidence_id: "e".to_owned(),
            request_id: "r".to_owned(),
            repository: "/repo".to_owned(),
            origin_json: r#"{"targets":[]}"#.to_owned(),
            identity_json: "{}".to_owned(),
            map_json: "[]".to_owned(),
            view_id: "view".to_owned(),
            view_bytes: b"observed".to_vec(),
        })
        .await
        .unwrap();
    let progress = store
        .flow_watch_progress("r", "/repo")
        .await
        .unwrap()
        .unwrap();
    assert!(!progress.contains("private"));
    assert!(!progress.contains("observed"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&progress).unwrap()["evidence_id"],
        "e"
    );
    assert!(
        store
            .flow_watch_progress("other", "/repo")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .flow_watch_progress("r", "/other")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn invalid_and_oversized_progress_cannot_expose_metadata() {
    for metadata in [
        "x".repeat(16385),
        meta("wrong-id"),
        json!({"watch_progress":{"raw":"secret"}}).to_string(),
    ] {
        let store = Store::open_in_memory().await.unwrap();
        store
            .insert_request("r", "flow.run", "/repo", "test", "{}", None)
            .await
            .unwrap();
        seed(&store, "e", &metadata, true).await;
        assert!(
            store
                .flow_watch_progress("r", "/repo")
                .await
                .unwrap()
                .is_none()
        );
    }
}
