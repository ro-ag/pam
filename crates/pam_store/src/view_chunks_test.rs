//! Chunked view storage (schema 20): pages cut from the chunks they cover,
//! every served byte checked against its chunk's digest, and a view that
//! cannot point at missing evidence.

use sha2::{Digest, Sha256};

use crate::view_chunks::CHUNK_BYTES;
use crate::{EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert, Store};

/// Three whole chunks and a short fourth: every boundary case in one view.
const VIEW_LEN: usize = 3 * CHUNK_BYTES + 17;

fn view_bytes() -> Vec<u8> {
    (0..VIEW_LEN)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect()
}

async fn fixture() -> (tempfile::TempDir, Store, Vec<u8>, EvidenceRangeRequest) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    store
        .insert_request("r", "flow.run", "/repo", "test", "{}", None)
        .await
        .unwrap();
    store
        .insert_evidence("e", "r", "log", b"private source", None)
        .await
        .unwrap();
    let bytes = view_bytes();
    assert!(
        store
            .insert_evidence_view(&EvidenceViewInsert {
                evidence_id: "e".into(),
                request_id: "r".into(),
                repository: "/repo".into(),
                origin_json: "{}".into(),
                identity_json: "{}".into(),
                map_json: "[]".into(),
                view_id: "v".into(),
                view_bytes: bytes.clone(),
            })
            .await
            .unwrap()
    );
    let request = EvidenceRangeRequest {
        request_id: "r".into(),
        evidence_id: "e".into(),
        repository: "/repo".into(),
        expected_view_id: "v".into(),
        expected_sha256: hex::encode(Sha256::digest(&bytes)),
        offset: 0,
        length: 65_536,
        now: 100,
    };
    (dir, store, bytes, request)
}

async fn page(store: &Store, request: &EvidenceRangeRequest) -> EvidenceRangeOutcome {
    store.read_evidence_view_range(request).await.unwrap()
}

/// Lifts the chunk triggers, the way a hand edit or a damaged file would
/// get past them.
async fn without_chunk_guards(store: &Store) {
    store
        .raw(|conn| {
            conn.execute_batch(
                "DROP TRIGGER evidence_view_chunk_immutable; DROP TRIGGER evidence_view_chunk_kept;",
            )
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn a_view_is_stored_as_fixed_size_chunks_each_with_its_digest() {
    let (_dir, store, bytes, _) = fixture().await;
    let chunks: Vec<(i64, String, Vec<u8>)> = store
        .raw(|conn| {
            let mut stmt = conn.prepare(
                "SELECT seq, sha256, bytes FROM evidence_view_chunk WHERE evidence_id='e' ORDER BY seq",
            )?;
            stmt.query_map((), |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect()
        })
        .await
        .unwrap();
    assert_eq!(chunks.len(), 4);
    for (index, (seq, digest, chunk)) in chunks.iter().enumerate() {
        assert_eq!(*seq, i64::try_from(index).unwrap());
        let start = index * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(VIEW_LEN);
        assert_eq!(chunk, &bytes[start..end]);
        assert_eq!(digest, &hex::encode(Sha256::digest(chunk)));
    }
    assert_eq!(chunks[3].2.len(), 17);
    let chunk_bytes: i64 = store
        .raw_scalar(
            "SELECT chunk_bytes FROM evidence_view WHERE evidence_id='e'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(chunk_bytes, i64::try_from(CHUNK_BYTES).unwrap());
}

#[tokio::test]
async fn pages_across_chunk_boundaries_are_the_exact_bytes() {
    let (_dir, store, bytes, mut request) = fixture().await;
    let cases = [
        (0, 65_536),
        (1, 65_536),
        (CHUNK_BYTES - 10, 100),
        (CHUNK_BYTES, 16_384),
        (2 * CHUNK_BYTES - 1, 65_536),
        (3 * CHUNK_BYTES - 5, 65_536),
        (VIEW_LEN - 1, 65_536),
    ];
    for (offset, length) in cases {
        request.offset = u64::try_from(offset).unwrap();
        request.length = length;
        let EvidenceRangeOutcome::Range(range) = page(&store, &request).await else {
            panic!("no page at {offset}");
        };
        let end = (offset + usize::try_from(length).unwrap()).min(VIEW_LEN);
        assert_eq!(range.bytes, bytes[offset..end], "offset {offset}");
        assert_eq!(range.total_bytes, u64::try_from(VIEW_LEN).unwrap());
        assert_eq!(
            range.next_offset,
            (end < VIEW_LEN).then(|| u64::try_from(end).unwrap())
        );
    }
}

#[tokio::test]
async fn a_byte_changed_on_disk_is_refused_as_corrupt_and_only_where_it_is() {
    let (_dir, store, bytes, mut request) = fixture().await;
    without_chunk_guards(&store).await;
    // Overwrite the third chunk with as many other bytes; its recorded
    // digest stays.
    store
        .raw_execute(
            "UPDATE evidence_view_chunk SET bytes = zeroblob(65536) WHERE evidence_id='e' AND seq=2",
            (),
        )
        .await
        .unwrap();
    request.offset = u64::try_from(2 * CHUNK_BYTES + 100).unwrap();
    request.length = 10;
    assert!(matches!(
        page(&store, &request).await,
        EvidenceRangeOutcome::Corrupt
    ));
    // A page that spans into the damaged chunk is refused whole.
    request.offset = u64::try_from(2 * CHUNK_BYTES - 5).unwrap();
    assert!(matches!(
        page(&store, &request).await,
        EvidenceRangeOutcome::Corrupt
    ));
    // The chunks a page does not touch are not read, so the rest of the view
    // still serves, each byte checked.
    request.offset = 0;
    request.length = 65_536;
    let EvidenceRangeOutcome::Range(range) = page(&store, &request).await else {
        panic!("the first chunk is sound");
    };
    assert_eq!(range.bytes, bytes[..65_536]);
}

#[tokio::test]
async fn a_forged_digest_a_short_chunk_or_a_missing_chunk_is_corrupt() {
    for tamper in [
        "UPDATE evidence_view_chunk SET sha256 = printf('%064d', 0) WHERE evidence_id='e' AND seq=1",
        "UPDATE evidence_view_chunk SET bytes = x'00' WHERE evidence_id='e' AND seq=1",
        "DELETE FROM evidence_view_chunk WHERE evidence_id='e' AND seq=1",
    ] {
        let (_dir, store, _, mut request) = fixture().await;
        without_chunk_guards(&store).await;
        store.raw_execute(tamper, ()).await.unwrap();
        request.offset = u64::try_from(CHUNK_BYTES + 1).unwrap();
        request.length = 4;
        assert!(
            matches!(page(&store, &request).await, EvidenceRangeOutcome::Corrupt),
            "{tamper}"
        );
    }
}

#[tokio::test]
async fn a_live_views_chunks_cannot_be_rewritten_deleted_or_added_to() {
    let (_dir, store, _, _) = fixture().await;
    for (tamper, refusal) in [
        (
            "UPDATE evidence_view_chunk SET bytes = x'00' WHERE evidence_id='e'",
            "evidence view chunks are immutable",
        ),
        (
            "DELETE FROM evidence_view_chunk WHERE evidence_id='e'",
            "a live evidence view keeps its chunks",
        ),
        (
            "UPDATE evidence_view SET chunk_bytes = 1",
            "evidence views are immutable",
        ),
    ] {
        let error = store.raw_execute(tamper, ()).await.unwrap_err();
        assert!(error.to_string().contains(refusal), "{tamper}: {error}");
    }
    // A chunk for a view that does not exist, or no longer serves, is refused.
    let error = store
        .raw_execute(
            "INSERT INTO evidence_view_chunk (evidence_id, seq, sha256, bytes) \
             VALUES ('nobody', 0, printf('%064d', 0), x'00')",
            (),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("chunks belong to a live evidence view"),
        "{error}"
    );
}

#[tokio::test]
async fn a_view_cannot_point_at_missing_evidence() {
    let (_dir, store, _, _) = fixture().await;
    // Deleting the evidence of a view that was not tombstoned first fails:
    // the view would be live with nothing behind it.
    let error = store
        .raw_execute("DELETE FROM evidence WHERE id='e'", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("CHECK"), "{error}");
    // A view row naming evidence that is not there is refused by the key.
    let error = store
        .raw_execute(
            "INSERT INTO evidence_view (evidence_id, request_id, source_id, repository, \
             origin_json, identity_json, map_json, view_id, view_sha256, view_bytes, chunk_bytes) \
             VALUES ('ghost', 'r', 'ghost', '/repo', '{}', '{}', '[]', 'vg', 'x', 0, 65536)",
            (),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("FOREIGN KEY"), "{error}");
    // Nor can a live view claim no evidence at all.
    let error = store
        .raw_execute(
            "INSERT INTO evidence_view (evidence_id, request_id, source_id, repository, \
             origin_json, identity_json, map_json, view_id, view_sha256, view_bytes, chunk_bytes) \
             VALUES ('ghost', 'r', NULL, '/repo', '{}', '{}', '[]', 'vg', 'x', 0, 65536)",
            (),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("CHECK"), "{error}");
    // And a view's link is to its own evidence row only.
    store
        .insert_evidence("other", "r", "log", b"other", None)
        .await
        .unwrap();
    let error = store
        .raw_execute("UPDATE evidence_view SET source_id='other'", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("CHECK") || error.to_string().contains("immutable"));
}

#[tokio::test]
async fn retention_tombstones_the_view_drops_its_chunks_and_clears_its_link() {
    let (_dir, store, _, request) = fixture().await;
    store
        .raw_execute(
            "UPDATE request SET state='done', updated_ts=1 WHERE id='r'",
            (),
        )
        .await
        .unwrap();
    store
        .prune_evidence_before(i64::MAX, "verdict")
        .await
        .unwrap();
    let (chunks, source, expired): (i64, Option<String>, Option<i64>) = store
        .raw(|conn| {
            conn.query_row(
                "SELECT (SELECT count(*) FROM evidence_view_chunk), source_id, expired_at \
                 FROM evidence_view WHERE evidence_id='e'",
                (),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
        })
        .await
        .unwrap();
    assert_eq!(chunks, 0);
    assert_eq!(source, None);
    assert!(expired.is_some());
    assert!(matches!(
        page(&store, &request).await,
        EvidenceRangeOutcome::Expired
    ));
    // A tombstone is final.
    let error = store
        .raw_execute("UPDATE evidence_view SET expired_at = NULL", ())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("evidence views are immutable"));
    // Request retention removes the record whole, chunks with it.
    store.prune_requests_before(i64::MAX).await.unwrap();
    let views: i64 = store
        .raw_scalar("SELECT count(*) FROM evidence_view", ())
        .await
        .unwrap();
    assert_eq!(views, 0);
}

#[tokio::test]
async fn request_retention_of_a_live_view_takes_its_chunks() {
    let (_dir, store, _, _) = fixture().await;
    store
        .raw_execute(
            "UPDATE request SET state='done', updated_ts=1 WHERE id='r'",
            (),
        )
        .await
        .unwrap();
    store.prune_requests_before(i64::MAX).await.unwrap();
    let chunks: i64 = store
        .raw_scalar("SELECT count(*) FROM evidence_view_chunk", ())
        .await
        .unwrap();
    assert_eq!(chunks, 0);
}

#[tokio::test]
async fn a_view_whose_chunks_failed_to_land_is_not_inserted() {
    let (_dir, store, _, _) = fixture().await;
    store
        .insert_evidence("e2", "r", "log", b"source", None)
        .await
        .unwrap();
    // The view id collides, so the row insert fails; nothing of it is left.
    let duplicate = EvidenceViewInsert {
        evidence_id: "e2".into(),
        request_id: "r".into(),
        repository: "/repo".into(),
        origin_json: "{}".into(),
        identity_json: "{}".into(),
        map_json: "[]".into(),
        view_id: "v".into(),
        view_bytes: vec![1; 3 * CHUNK_BYTES],
    };
    assert!(store.insert_evidence_view(&duplicate).await.is_err());
    let chunks: i64 = store
        .raw_scalar(
            "SELECT count(*) FROM evidence_view_chunk WHERE evidence_id='e2'",
            (),
        )
        .await
        .unwrap();
    assert_eq!(chunks, 0);
}
