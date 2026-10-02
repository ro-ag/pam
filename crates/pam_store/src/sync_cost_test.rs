//! A measurement, not a check: what syncing each commit through to the
//! drive costs on the machine it runs on. Kept so the decision recorded in
//! `open::apple_sync` can be re-examined on other hardware.
//!
//! ```text
//! cargo test -p pam_store --lib sync_cost -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use crate::{Actor, AuditEntry, Decision, RequestState, Store};

const REQUESTS: u32 = 1000;

/// Inserts and finishes [`REQUESTS`] requests (two commits each) on a new
/// file-backed store and answers the time per commit.
async fn per_commit(fullfsync: bool) -> Duration {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("state.sqlite3"))
        .await
        .unwrap();
    store
        .raw(move |conn| conn.pragma_update(None, "fullfsync", fullfsync))
        .await
        .unwrap();
    let started = Instant::now();
    for index in 0..REQUESTS {
        let id = format!("r_{index}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        store
            .finish_request(
                &id,
                RequestState::Done,
                Some("ok"),
                AuditEntry {
                    action: "execute",
                    decision: Decision::Allow,
                    actor: Actor::System,
                    detail: None,
                },
            )
            .await
            .unwrap();
    }
    let elapsed = started.elapsed();
    store.close().await.unwrap();
    elapsed / (REQUESTS * 2)
}

#[tokio::test]
#[ignore = "a measurement: prints the cost of fsync and F_FULLFSYNC per commit"]
async fn sync_cost_per_commit() {
    for round in 1..=3 {
        for (label, fullfsync) in [("fsync", false), ("F_FULLFSYNC", true)] {
            let cost = per_commit(fullfsync).await;
            println!(
                "round {round}: {label:<11} {:>8.3} ms per commit ({REQUESTS} requests, 2 commits each)",
                cost.as_secs_f64() * 1000.0
            );
        }
    }
}
