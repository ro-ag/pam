use sha2::{Digest, Sha256};

use crate::store::evidence_views::META_LIMIT;
use crate::{EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert, Store};

async fn fixture() -> (tempfile::TempDir, Store, EvidenceRangeRequest) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.db")).await.unwrap();
    store
        .insert_request("r", "flow.run", "/repo-alias", "test", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("e", "r", "log", b"private source", None)
        .await
        .unwrap();
    let view = EvidenceViewInsert {
        evidence_id: "e".into(),
        request_id: "r".into(),
        repository: "/canonical/repo".into(),
        origin_json: "{}".into(),
        identity_json: "{}".into(),
        map_json: "[]".into(),
        view_id: "v".into(),
        view_bytes: vec![0, 255, 195, 169, 10],
    };
    assert!(store.insert_evidence_view(&view).await.unwrap());
    let sha = hex::encode(Sha256::digest(&view.view_bytes));
    (
        dir,
        store,
        EvidenceRangeRequest {
            request_id: "r".into(),
            evidence_id: "e".into(),
            repository: "/canonical/repo".into(),
            expected_view_id: "v".into(),
            expected_sha256: sha,
            offset: 1,
            length: 2,
            now: 100,
        },
    )
}

#[tokio::test]
async fn exact_binary_ranges_and_complete_identity_binding() {
    let (_dir, store, mut r) = fixture().await;
    let EvidenceRangeOutcome::Range(page) = store.read_evidence_view_range(&r).await.unwrap()
    else {
        panic!("range")
    };
    assert_eq!(page.bytes, vec![255, 195]);
    assert_eq!(page.next_offset, Some(3));
    assert_eq!(page.remaining_bytes, 67_108_862);
    assert_eq!(page.allowance_expires_at, 3700);
    r.repository = "/elsewhere".into();
    assert!(
        store
            .evidence_view_meta("r", "e", &r.repository)
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::Unavailable
    ));
    r.repository = "/canonical/repo".into();
    r.expected_sha256 = "forged".into();
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::Unavailable
    ));
    r.expected_sha256 = page.view_sha256;
    r.offset = 6;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::InvalidRange
    ));
    r.offset = 0;
    r.length = 65_537;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::InvalidRange
    ));
}

#[tokio::test]
async fn allowance_persists_on_reopen_and_never_renews() {
    let (dir, store, mut r) = fixture().await;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::Range(_)
    ));
    drop(store);
    let store = Store::open(&dir.path().join("state.db")).await.unwrap();
    let EvidenceRangeOutcome::Range(page) = store.read_evidence_view_range(&r).await.unwrap()
    else {
        panic!("range")
    };
    assert_eq!(page.remaining_pages, 4094);
    assert_eq!(page.remaining_bytes, 67_108_860);
    r.now = 3700;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::BudgetExhausted
    ));
    r.now = 10_000;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::BudgetExhausted
    ));
}

#[tokio::test]
async fn byte_and_page_caps_are_shared_across_evidence() {
    let (_dir, store, mut r) = fixture().await;
    let _ = store.read_evidence_view_range(&r).await.unwrap();
    {
        let _guard = store.conn_lock.lock().await;
        store
            .conn
            .execute("UPDATE evidence_read_allowance SET remaining_bytes=1", ())
            .await
            .unwrap();
    }
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::BudgetExhausted
    ));
    store
        .insert_evidence("other", "r", "log", b"another source", None)
        .await
        .unwrap();
    let view = EvidenceViewInsert {
        evidence_id: "other".into(),
        request_id: "r".into(),
        repository: r.repository.clone(),
        origin_json: "{}".into(),
        identity_json: "{}".into(),
        map_json: "[]".into(),
        view_id: "other-view".into(),
        view_bytes: b"safe".to_vec(),
    };
    assert!(store.insert_evidence_view(&view).await.unwrap());
    r.evidence_id = "other".into();
    r.expected_view_id = "other-view".into();
    r.expected_sha256 = hex::encode(Sha256::digest(b"safe"));
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::BudgetExhausted
    ));
    r.length = 1;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::Range(_)
    ));
    {
        let _guard = store.conn_lock.lock().await;
        store
            .conn
            .execute(
                "UPDATE evidence_read_allowance SET remaining_bytes=100,remaining_pages=0",
                (),
            )
            .await
            .unwrap();
    }
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::BudgetExhausted
    ));
}

#[tokio::test]
async fn pruning_preserves_authorized_tombstone_until_request_retention() {
    let (_dir, store, r) = fixture().await;
    let _ = store.read_evidence_view_range(&r).await.unwrap();
    {
        let _guard = store.conn_lock.lock().await;
        store
            .conn
            .execute(
                "UPDATE request SET state='done',updated_ts=1 WHERE id='r'",
                (),
            )
            .await
            .unwrap();
    }
    store
        .prune_evidence_before(i64::MAX, "verdict")
        .await
        .unwrap();
    assert!(store.get_evidence("e").await.unwrap().is_none());
    let meta = store
        .evidence_view_meta("r", "e", "/canonical/repo")
        .await
        .unwrap()
        .unwrap();
    assert!(meta.expired_at.is_some());
    assert_eq!(meta.view_bytes, 5);
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::Expired
    ));
    store.prune_requests_before(i64::MAX).await.unwrap();
    assert!(
        store
            .evidence_view_meta("r", "e", "/canonical/repo")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn view_insertion_is_immutable_owned_and_metadata_bounded() {
    let (_dir, store, _r) = fixture().await;
    let mut view = EvidenceViewInsert {
        evidence_id: "e".into(),
        request_id: "wrong".into(),
        repository: "/repo".into(),
        origin_json: "{}".into(),
        identity_json: "{}".into(),
        map_json: "[]".into(),
        view_id: "second".into(),
        view_bytes: vec![],
    };
    assert!(!store.insert_evidence_view(&view).await.unwrap());
    view.request_id = "r".into();
    assert!(store.insert_evidence_view(&view).await.is_err());
    view.origin_json = format!("\"{}\"", "x".repeat(META_LIMIT));
    assert!(store.insert_evidence_view(&view).await.is_err());
}

#[tokio::test]
async fn protected_identity_overwrites_forgery_and_rechecks_augmented_bound() {
    let (_dir, store, _r) = fixture().await;
    let protected = br#"{"records":["logical text"]}"#;
    store
        .insert_evidence("source", "r", "log.compact", protected, None)
        .await
        .unwrap();
    let mut view = EvidenceViewInsert {
        evidence_id: "source".into(), request_id: "r".into(), repository: "/repo".into(),
        origin_json: "{}".into(), map_json: "[]".into(), view_id: "protected-view".into(),
        view_bytes: b"logical text".to_vec(),
        identity_json: serde_json::json!({"protected_evidence_sha256":"forged", "protected_evidence_bytes":999, "input_sha256":"logical-input"}).to_string(),
    };
    assert!(store.insert_evidence_view(&view).await.unwrap());
    let meta = store
        .evidence_view_meta("r", "source", "/repo")
        .await
        .unwrap()
        .unwrap();
    let identity: serde_json::Value = serde_json::from_str(&meta.identity_json).unwrap();
    assert_eq!(
        identity["protected_evidence_sha256"],
        hex::encode(Sha256::digest(protected))
    );
    assert_eq!(identity["protected_evidence_bytes"], protected.len());
    assert_eq!(identity["input_sha256"], "logical-input");
    store
        .insert_evidence("too-large", "r", "log", b"input", None)
        .await
        .unwrap();
    view.evidence_id = "too-large".into();
    view.view_id = "too-large-view".into();
    view.identity_json = serde_json::json!({"padding":"x".repeat(META_LIMIT - 32)}).to_string();
    assert!(view.identity_json.len() < META_LIMIT);
    assert!(store.insert_evidence_view(&view).await.is_err());
    assert!(
        store
            .evidence_view_meta("r", "too-large", "/repo")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_range_starting_at_the_end_is_invalid_and_charges_nothing() {
    let (_dir, store, mut r) = fixture().await;
    r.offset = 5;
    r.length = 1;
    assert!(matches!(
        store.read_evidence_view_range(&r).await.unwrap(),
        EvidenceRangeOutcome::InvalidRange
    ));
    // No allowance row was opened by the refused read: the first valid
    // read still sees the full budget.
    r.offset = 4;
    let EvidenceRangeOutcome::Range(page) = store.read_evidence_view_range(&r).await.unwrap()
    else {
        panic!("range")
    };
    assert_eq!(page.bytes, vec![10]);
    assert_eq!(page.next_offset, None);
    assert_eq!(page.remaining_pages, 4095);
    assert_eq!(page.remaining_bytes, 67_108_863);
}
