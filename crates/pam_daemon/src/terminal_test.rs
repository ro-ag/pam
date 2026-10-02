use std::sync::Arc;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};

use crate::terminal::{MAX_PARKED, RETRY_BACKOFF, TerminalWriter, Written};
use crate::test_log::Captured;

const ACTION: &str = "execute";

fn audit(detail: &str) -> AuditEntry<'_> {
    AuditEntry {
        action: ACTION,
        decision: Decision::Allow,
        actor: Actor::System,
        detail: Some(detail),
    }
}

async fn store_with_running(ids: &[&str]) -> Arc<Store> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    for id in ids {
        store
            .insert_running_request(id, "query", "/repo", "agent", "{}", None)
            .await
            .unwrap();
    }
    store
}

async fn state_of(store: &Store, id: &str) -> RequestState {
    store.get_request(id).await.unwrap().unwrap().state
}

#[tokio::test]
async fn a_healthy_store_takes_the_terminal_row_and_its_audit_row() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    let written = writer
        .finish("req", RequestState::Done, Some("verified"), audit("{}"))
        .await;
    assert_eq!(written, Written::Durable);
    assert_eq!(state_of(&store, "req").await, RequestState::Done);
    let rows = store.audit_for_request("req").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, ACTION);
    assert_eq!(writer.parked_count(), 0);
}

#[tokio::test]
async fn a_transient_store_failure_is_retried_within_the_call() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    // Two refusals, then the store takes it: the third attempt lands.
    writer.fail_next(2);
    let written = writer
        .finish("req", RequestState::Done, Some("verified"), audit("{}"))
        .await;
    assert_eq!(written, Written::Durable);
    assert_eq!(state_of(&store, "req").await, RequestState::Done);
    assert_eq!(writer.parked_count(), 0);
}

#[tokio::test]
async fn a_write_the_store_keeps_refusing_is_parked_and_recorded_later() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    writer.fail_next(3);
    let written = writer
        .finish(
            "req",
            RequestState::Failed,
            Some("execution_failed"),
            audit("{\"why\":\"boom\"}"),
        )
        .await;
    // The caller is told the row is not durable — and the verdict was not
    // dropped, which is what `let _ = finish_request(..)` used to do.
    assert_eq!(written, Written::Parked { overloaded: false });
    assert!(!written.is_durable());
    assert_eq!(state_of(&store, "req").await, RequestState::Running);
    assert_eq!(writer.parked_count(), 1);

    // The store still refuses on the next maintenance tick: it stays parked.
    writer.fail_next(1);
    assert_eq!(writer.retry_parked().await, 0);
    assert_eq!(writer.parked_count(), 1);

    // Then it recovers: the exact verdict that was parked is recorded.
    assert_eq!(writer.retry_parked().await, 1);
    assert_eq!(writer.parked_count(), 0);
    let row = store.get_request("req").await.unwrap().unwrap();
    assert_eq!(row.state, RequestState::Failed);
    assert_eq!(row.outcome.as_deref(), Some("execution_failed"));
    let rows = store.audit_for_request("req").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].detail.as_deref(), Some("{\"why\":\"boom\"}"));
}

#[tokio::test]
async fn a_parked_verdict_yields_to_whoever_finished_the_row_first() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    writer.fail_next(3);
    writer
        .finish("req", RequestState::Done, Some("verified"), audit("{}"))
        .await;
    // The reconciler closes the row while the verdict is parked.
    store
        .finish_request(
            "req",
            RequestState::Failed,
            Some("lease_expired"),
            AuditEntry {
                action: "lease_reaped",
                decision: Decision::Timeout,
                actor: Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
    // First finisher wins: the parked verdict leaves the queue, no second
    // terminal audit row is written.
    assert_eq!(writer.retry_parked().await, 1);
    assert_eq!(writer.parked_count(), 0);
    let row = store.get_request("req").await.unwrap().unwrap();
    assert_eq!(row.outcome.as_deref(), Some("lease_expired"));
    assert_eq!(store.audit_for_request("req").await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_request_with_no_row_has_nothing_to_finish_and_nothing_to_park() {
    let store = store_with_running(&[]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    let written = writer
        .finish("never_admitted", RequestState::Failed, None, audit("{}"))
        .await;
    assert_eq!(written, Written::Durable);
    assert_eq!(writer.parked_count(), 0);
}

#[tokio::test]
async fn the_parked_queue_is_bounded() {
    let store = store_with_running(&[]).await;
    let writer = TerminalWriter::new(store);
    for index in 0..MAX_PARKED + 40 {
        writer.park(
            &format!("req_{index}"),
            RequestState::Failed,
            Some("execution_failed"),
            audit("{}"),
        );
    }
    assert_eq!(writer.parked_count(), MAX_PARKED);
}

/// A write the store turns down at its queue bound is parked like any other
/// refused write, and the caller is told which refusal it was.
#[tokio::test(start_paused = true)]
async fn a_write_refused_at_the_store_queue_bound_is_parked_as_overloaded() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    writer.fail_next_overloaded(3);
    let written = writer
        .finish("req", RequestState::Done, Some("verified"), audit("{}"))
        .await;
    assert_eq!(written, Written::Parked { overloaded: true });
    assert_eq!(writer.parked_count(), 1);
    // The store is keeping up again: the verdict is recorded.
    assert_eq!(writer.retry_parked().await, 1);
    assert_eq!(state_of(&store, "req").await, RequestState::Done);
}

/// The daemon closes its store at the very end of shutdown. A terminal write
/// that arrives after that cannot succeed on any later attempt and nothing
/// will drain a parked verdict: it used to cost two retries (175 ms) and an
/// error line saying "parked for retry", which was not true.
#[tokio::test(start_paused = true)]
async fn a_closed_store_is_neither_retried_nor_parked_and_says_so_once() {
    let store = store_with_running(&["req"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    store.close().await.unwrap();

    let (log, logging) = Captured::start();
    let before = tokio::time::Instant::now();
    let written = writer
        .finish("req", RequestState::Done, Some("verified"), audit("{}"))
        .await;
    drop(logging);

    assert_eq!(written, Written::Closed);
    assert!(!written.is_durable());
    // No backoff was slept: on the paused clock a retry would have advanced
    // the time by the first pause at least.
    assert!(
        before.elapsed() < RETRY_BACKOFF[0],
        "{:?}",
        before.elapsed()
    );
    assert_eq!(writer.parked_count(), 0);

    let lines = log.lines_with("pam_daemon::terminal");
    assert_eq!(lines.len(), 1, "{}", log.text());
    assert!(lines[0].contains("DEBUG"), "{}", lines[0]);
    assert!(lines[0].contains("the store is closed"), "{}", lines[0]);
    assert!(lines[0].contains("next boot"), "{}", lines[0]);
    assert!(!log.text().contains("parked for retry"), "{}", log.text());
}

/// Verdicts parked while the store was failing stay parked, quietly, once
/// the store is closed: one debug line for the lot, not a warning each.
#[tokio::test(start_paused = true)]
async fn parked_verdicts_wait_quietly_once_the_store_is_closed() {
    let store = store_with_running(&["one", "two"]).await;
    let writer = TerminalWriter::new(Arc::clone(&store));
    for id in ["one", "two"] {
        writer.fail_next(3);
        let written = writer
            .finish(id, RequestState::Done, Some("verified"), audit("{}"))
            .await;
        assert_eq!(written, Written::Parked { overloaded: false });
    }
    store.close().await.unwrap();

    let (log, logging) = Captured::start();
    assert_eq!(writer.retry_parked().await, 0);
    drop(logging);

    assert_eq!(writer.parked_count(), 2);
    let lines = log.lines_with("pam_daemon::terminal");
    assert_eq!(lines.len(), 1, "{}", log.text());
    assert!(lines[0].contains("DEBUG"), "{}", lines[0]);
    assert!(lines[0].contains("parked=2"), "{}", lines[0]);
    assert!(!log.text().contains("still refused"), "{}", log.text());
}
