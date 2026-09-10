use pam_proto::{Caller, Envelope, PROTOCOL_VERSION};
use serde_json::json;

fn envelope(repo: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: "request".into(),
        capability: "echo".into(),
        client_version: env!("CARGO_PKG_VERSION").into(),
        caller: Caller {
            agent: "test".into(),
            repo: repo.into(),
            pid: 1,
        },
        args: json!({}),
        idempotency_key: Some("same-work".into()),
        deadline_ms: 60000,
        wait: true,
    }
}

#[tokio::test]
async fn unresolved_global_repository_remains_usable_but_deadline_is_charged() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent").to_string_lossy().into_owned();
    let request = crate::daemon::normalize_repository(envelope(&missing))
        .await
        .unwrap();
    assert_eq!(request.caller.repo, missing);
    assert!(request.deadline_ms < 60000);
    let mut expired = envelope(&missing);
    expired.deadline_ms = 0;
    assert!(
        matches!(crate::daemon::normalize_repository(expired).await,Err(pam_proto::Response::Refusal {cause,..}) if cause=="deadline_exceeded")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_retarget_cannot_change_admitted_lane_or_ticket_owner() {
    use crate::policy::CapabilityClass;
    use crate::queue::{AdmitOutcome, QueueManager};
    use pam_store::Store;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let alias = dir.path().join("alias");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let a = a.canonicalize().unwrap();
    let b = b.canonicalize().unwrap();
    std::os::unix::fs::symlink(&a, &alias).unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[{"root":a,"connectors":[]},{"root":b,"connectors":[]}]}).to_string()).await.unwrap();
    // Simulate an old admission that persisted the alias rather than its owner.
    store
        .insert_admitted_request(
            "old",
            "echo",
            &alias.to_string_lossy(),
            "test",
            "{}",
            None,
            i64::MAX,
        )
        .await
        .unwrap();
    let normalized = crate::daemon::normalize_repository(envelope(&alias.to_string_lossy()))
        .await
        .unwrap();
    assert_eq!(normalized.caller.repo, a.to_string_lossy());
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&b, &alias).unwrap();
    let queue = QueueManager::new(Arc::clone(&store));
    assert!(matches!(
        queue
            .admit(&normalized, CapabilityClass::NonDestructive)
            .await
            .unwrap(),
        AdmitOutcome::Admitted
    ));
    let mut duplicate = crate::daemon::normalize_repository(envelope(&a.to_string_lossy()))
        .await
        .unwrap();
    duplicate.id = "duplicate".into();
    assert!(
        matches!(queue.admit(&duplicate, CapabilityClass::NonDestructive).await.unwrap(),
        AdmitOutcome::Attached {existing_request_id} if existing_request_id=="request")
    );
    let stored = store.get_request("request").await.unwrap().unwrap();
    assert_eq!(stored.repo, a.to_string_lossy());
    queue
        .place_in_lane("request", &normalized.caller.repo, normalized.deadline_ms)
        .await
        .unwrap();
    assert!(
        queue
            .take_next(&b.to_string_lossy())
            .await
            .unwrap()
            .is_none()
    );
    let work = queue
        .take_next(&a.to_string_lossy())
        .await
        .unwrap()
        .unwrap();
    let executor_row = store.get_request(&work.request_id).await.unwrap().unwrap();
    assert_eq!(executor_row.repo, a.to_string_lossy());
    assert!(
        crate::flow_result_service::authorized_metadata(&store, &b.to_string_lossy(), "old")
            .await
            .is_err()
    );
    assert!(
        crate::flow_result_service::authorized_metadata(&store, &b.to_string_lossy(), "request")
            .await
            .is_err()
    );
    assert!(
        crate::flow_result_service::authorized_metadata(&store, &a.to_string_lossy(), "request")
            .await
            .is_ok()
    );
}
