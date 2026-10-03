//! What one evidence page read costs on a large view: a 64 KiB page cut out
//! of a 32 MiB view on a file-backed store, at the start, the middle and the
//! end. Ignored by default; run it with
//! `cargo test -p pam_store --test view_page_read -- --ignored --nocapture`
//! (add `--release` for the figures the store spec records).

use std::time::{Duration, Instant};

use pam_store::{EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert, Store};
use sha2::{Digest, Sha256};

const VIEW_BYTES: usize = 32 * 1024 * 1024;
const PAGE: u32 = 64 * 1024;
const ROUNDS: usize = 20;

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement, not a check: run with --ignored --nocapture"]
async fn a_page_of_a_32_mib_view() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    let view_bytes: Vec<u8> = (0..VIEW_BYTES)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let digest = hex::encode(Sha256::digest(&view_bytes));
    let offsets = [
        0,
        (VIEW_BYTES / 2) as u64,
        (VIEW_BYTES - PAGE as usize) as u64,
    ];
    let mut figures = Vec::new();
    for (index, offset) in offsets.iter().enumerate() {
        // One request per offset: the allowance (4,096 pages) is per request.
        let request = format!("r{index}");
        store
            .insert_request(&request, "flow.run", "/repo", "bench", "{}", None)
            .await
            .unwrap();
        let evidence = format!("e{index}");
        store
            .insert_evidence(&evidence, &request, "log", b"source", None)
            .await
            .unwrap();
        let insert = Instant::now();
        assert!(
            store
                .insert_evidence_view(&EvidenceViewInsert {
                    evidence_id: evidence.clone(),
                    request_id: request.clone(),
                    repository: "/repo".into(),
                    origin_json: "{}".into(),
                    identity_json: "{}".into(),
                    map_json: "[]".into(),
                    view_id: format!("v{index}"),
                    view_bytes: view_bytes.clone(),
                })
                .await
                .unwrap()
        );
        let inserted = insert.elapsed();
        let mut samples = Vec::new();
        for round in 0..ROUNDS {
            let read = EvidenceRangeRequest {
                request_id: request.clone(),
                evidence_id: evidence.clone(),
                repository: "/repo".into(),
                expected_view_id: format!("v{index}"),
                expected_sha256: digest.clone(),
                offset: *offset,
                length: PAGE,
                now: 100 + i64::try_from(round).unwrap(),
            };
            let started = Instant::now();
            let outcome = store.read_evidence_view_range(&read).await.unwrap();
            samples.push(started.elapsed());
            let EvidenceRangeOutcome::Range(page) = outcome else {
                panic!("no page at {offset}");
            };
            let start = usize::try_from(*offset).unwrap();
            assert_eq!(page.bytes, view_bytes[start..start + PAGE as usize]);
        }
        figures.push(format!(
            "offset {offset:>9}: median {:?}, min {:?}, max {:?} over {ROUNDS} reads (insert {inserted:?})",
            median(samples.clone()),
            samples.iter().min().unwrap(),
            samples.iter().max().unwrap(),
        ));
    }
    store.close().await.unwrap();
    for line in figures {
        println!("{line}");
    }
}
