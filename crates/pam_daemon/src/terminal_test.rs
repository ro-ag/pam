use std::sync::Arc;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};

use crate::terminal::{MAX_PARKED, TerminalWriter, Written};

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
    assert_eq!(written, Written::Parked);
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
