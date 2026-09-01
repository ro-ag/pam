use std::time::Duration;

use pam_store::{Actor, ApprovalResolution, Decision, RequestState, Store};
use tokio::time::timeout;
use tracing::subscriber::with_default;

use crate::daemon::TERMINAL_ACTIONS;
use crate::lifecycle::{
    ACTION_DAEMON_RESTART, CAUSE_DAEMON_RESTART, LifecycleError, acquire_instance_lock,
    daemon_log_writer, recover_stuck_rows,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[test]
fn lock_is_exclusive_and_released_on_drop() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let first = acquire_instance_lock(tmp.path()).expect("first acquire succeeds");
    assert!(first.path().is_file());
    let recorded: u32 = std::fs::read_to_string(first.path())
        .expect("lock file readable")
        .trim()
        .parse()
        .expect("lock file holds a pid");
    assert_eq!(recorded, std::process::id());

    // A second acquire loses and names the holder.
    let err = acquire_instance_lock(tmp.path()).expect_err("second acquire fails");
    let LifecycleError::AlreadyRunning { pid, .. } = err else {
        panic!("expected AlreadyRunning, got {err:?}");
    };
    assert_eq!(pid, Some(std::process::id()));

    // Dropping the lock releases it for the next daemon.
    drop(first);
    let again = acquire_instance_lock(tmp.path()).expect("reacquire after drop");
    drop(again);
}

/// Seeds one request row in `state` (via the non-terminal transition
/// helper, since rows are born `queued`).
async fn seed_request(store: &Store, id: &str, state: RequestState) {
    store
        .insert_request(id, "echo", "/repo/a", "claude", "{}", None)
        .await
        .expect("insert");
    if state != RequestState::Queued {
        store
            .update_request_state(id, state, None)
            .await
            .expect("state set");
    }
}

#[tokio::test]
async fn recover_fails_stuck_rows_and_leaves_queued_alone() {
    timeout(DEADLINE, async {
        let store = Store::open_in_memory().await.expect("store opens");
        seed_request(&store, "req_running", RequestState::Running).await;
        seed_request(&store, "req_waiting", RequestState::WaitingApproval).await;
        store
            .insert_approval("req_waiting", "echo")
            .await
            .expect("approval row");
        seed_request(&store, "req_queued", RequestState::Queued).await;

        let recovered = recover_stuck_rows(&store).await.expect("recovery runs");
        assert_eq!(recovered, ["req_running", "req_waiting"]);

        for id in ["req_running", "req_waiting"] {
            let row = store.get_request(id).await.unwrap().unwrap();
            assert_eq!(row.state, RequestState::Failed, "{id} failed");
            assert_eq!(row.outcome.as_deref(), Some(CAUSE_DAEMON_RESTART));
            let audit = store.audit_for_request(id).await.unwrap();
            assert_eq!(audit.len(), 1, "{id} audited once");
            assert_eq!(audit[0].action, ACTION_DAEMON_RESTART);
            assert_eq!(audit[0].decision, Decision::Timeout);
            assert_eq!(audit[0].actor, Actor::System);
            let detail = audit[0].detail.as_deref().expect("detail present");
            assert!(detail.contains("retry"), "retry hint in {detail}");
        }

        // The queued row is restart-safe and untouched.
        let queued = store.get_request("req_queued").await.unwrap().unwrap();
        assert_eq!(queued.state, RequestState::Queued);
        assert!(queued.outcome.is_none());
        assert!(
            store
                .audit_for_request("req_queued")
                .await
                .unwrap()
                .is_empty()
        );

        // The dangling approval was resolved, so the GUI pending list
        // no longer advertises it.
        let approval = store
            .approval_for_request("req_waiting")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approval.resolution, Some(ApprovalResolution::Timeout));
        assert_eq!(approval.note.as_deref(), Some(CAUSE_DAEMON_RESTART));
        assert!(store.list_pending_approvals().await.unwrap().is_empty());

        // The audit invariant holds over the recovered rows.
        assert!(
            store
                .terminal_requests_missing_audit(TERMINAL_ACTIONS)
                .await
                .unwrap()
                .is_empty()
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn recover_is_a_no_op_when_nothing_is_stuck() {
    timeout(DEADLINE, async {
        let store = Store::open_in_memory().await.expect("store opens");
        seed_request(&store, "req_queued", RequestState::Queued).await;
        let recovered = recover_stuck_rows(&store).await.expect("recovery runs");
        assert!(recovered.is_empty());
        let row = store.get_request("req_queued").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Queued);
    })
    .await
    .expect("test within deadline");
}

#[test]
fn log_writer_writes_into_the_base_log_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (writer, guard) = daemon_log_writer(tmp.path()).expect("writer builds");
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(false)
        .finish();
    with_default(subscriber, || {
        tracing::info!(marker = "lifecycle-test", "daemon log line");
    });
    // Dropping the guard flushes the background writer.
    drop(guard);

    let log_dir = tmp.path().join(crate::lifecycle::LOG_DIR);
    let mut contents = String::new();
    for entry in std::fs::read_dir(&log_dir).expect("log dir exists") {
        let path = entry.expect("dir entry").path();
        contents.push_str(&std::fs::read_to_string(path).expect("log file readable"));
    }
    assert!(
        contents.contains("daemon log line"),
        "log contents: {contents:?}"
    );
}
