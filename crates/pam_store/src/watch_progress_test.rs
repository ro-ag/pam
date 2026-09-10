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
    pin(&store, "e", false).await;
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
        pin(&store, "e", false).await;
        assert!(
            store
                .flow_watch_progress("r", "/repo")
                .await
                .unwrap()
                .is_none()
        );
    }
}

async fn pin(store: &Store, id: &str, completed: bool) {
    store
        .begin_flow_journal(
            &crate::FlowJournalIdentity {
                request_id: "r".into(),
                flow_digest: "a".repeat(64),
                repository: "/repo".into(),
                input_fingerprint: "b".repeat(64),
            },
            "{}",
        )
        .await
        .unwrap();
    let journal = store.read_flow_journal("r").await.unwrap().unwrap();
    assert!(
        store
            .prepare_flow_attempt("r", journal.revision, "ci", 1, false)
            .await
            .unwrap()
    );
    let cursor = if completed {
        json!({"last_watch_evidence":id})
    } else {
        json!({"watch":{"last_evidence":id,"polls":1,"next_poll_ms":123}})
    };
    assert!(
        store
            .settle_flow_attempt(
                "r",
                journal.revision + 1,
                &cursor.to_string(),
                &[id.to_owned()],
                completed
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn uncommitted_newer_publication_is_invisible_and_completed_pointer_survives() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    seed(&store, "a-committed", &meta("a-committed"), true).await;
    store
        .begin_flow_journal(
            &crate::FlowJournalIdentity {
                request_id: "r".into(),
                flow_digest: "a".repeat(64),
                repository: "/repo".into(),
                input_fingerprint: "b".repeat(64),
            },
            "{}",
        )
        .await
        .unwrap();
    assert!(
        store
            .flow_watch_progress("r", "/repo")
            .await
            .unwrap()
            .is_none()
    );
    pin(&store, "a-committed", false).await;
    seed(&store, "z-uncommitted", &meta("z-uncommitted"), true).await;
    let value = store
        .flow_watch_progress("r", "/repo")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&value).unwrap()["evidence_id"],
        "a-committed"
    );
    pin(&store, "a-committed", true).await;
    assert_eq!(
        store
            .flow_watch_progress("r", "/repo")
            .await
            .unwrap()
            .unwrap(),
        value
    );
}

#[tokio::test]
async fn unchanged_observation_uses_committed_schedule_without_exposing_checkpoint_fields() {
    let store = Store::open_in_memory().await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    seed(&store, "e", &meta("e"), true).await;
    pin(&store, "e", false).await;
    let row = store.read_flow_journal("r").await.unwrap().unwrap();
    assert!(
        store
            .prepare_flow_attempt("r", row.revision, "ci", 1, false)
            .await
            .unwrap()
    );
    let cursor =
        json!({"watch":{"last_evidence":"e","polls":5,"next_poll_ms":999,"private":"not public"}});
    assert!(
        store
            .settle_flow_attempt(
                "r",
                row.revision + 1,
                &cursor.to_string(),
                &["e".into()],
                false
            )
            .await
            .unwrap()
    );
    let raw = store
        .flow_watch_progress("r", "/repo")
        .await
        .unwrap()
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(value["polls"], 5);
    assert_eq!(value["next_poll_at"], 999);
    assert_eq!(value["status"], "queued");
    assert!(!raw.contains("private"));
}
