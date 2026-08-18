use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use pam_core::{CallerId, IdempotencyKey, ProjectId, RequestId};
use pam_platform::{ClientTransport, LocalEndpoint};
use pam_protocol::{RequestEnvelope, encode};
use tokio::sync::oneshot;

use super::lifecycle::{DaemonConfig, Ownership, prepare_endpoint, serve_until_with_delay};
use crate::{DaemonError, request_status};

fn test_runtime(name: &str) -> PathBuf {
    let base = if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    };
    base.join(format!("pam-test-{name}-{}", std::process::id()))
}

#[test]
fn ownership_rejects_a_second_daemon() {
    let runtime = test_runtime("ownership");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let first = Ownership::acquire(&endpoint).unwrap();

    assert!(matches!(
        Ownership::acquire(&endpoint),
        Err(DaemonError::AlreadyRunning)
    ));

    drop(first);
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn an_unlocked_persistent_lock_file_is_reclaimed_normally() {
    let runtime = test_runtime("persistent-lock");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::create_dir_all(&runtime).unwrap();
    fs::write(endpoint.ownership_path(), b"stopped-daemon\n").unwrap();

    let ownership = Ownership::acquire(&endpoint).unwrap();
    assert_eq!(
        fs::read_to_string(endpoint.ownership_path()).unwrap(),
        format!("{}\n", std::process::id())
    );

    drop(ownership);
    let _ = fs::remove_dir_all(runtime);
}

#[test]
fn stale_socket_reports_recovery_command() {
    let runtime = test_runtime("stale");
    let _ = fs::remove_dir_all(&runtime);
    fs::create_dir_all(&runtime).unwrap();
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    fs::write(endpoint.socket_path().unwrap(), b"stale").unwrap();

    let error = prepare_endpoint(&DaemonConfig {
        endpoint,
        recover: false,
    })
    .unwrap_err();
    assert!(matches!(error, DaemonError::StaleState(_)));
    assert_eq!(error.recovery_action(), Some("pam daemon --recover"));

    let _ = fs::remove_dir_all(runtime);
}

fn request(project: &str, suffix: &str) -> RequestEnvelope {
    RequestEnvelope::status(
        RequestId::new(format!("request-{suffix}")),
        CallerId::from("queue-test"),
        ProjectId::new(project),
        IdempotencyKey::new(format!("status-{suffix}")),
    )
}

async fn wait_until_ready(endpoint: &LocalEndpoint) {
    for _ in 0..50 {
        if endpoint.socket_path().is_some_and(std::path::Path::exists) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon did not create its endpoint")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_parallelizes_projects_but_serializes_each_project() {
    let runtime = test_runtime("concurrency");
    let _ = fs::remove_dir_all(&runtime);
    let endpoint = LocalEndpoint::ipc(runtime.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let delay = Duration::from_millis(150);
    let daemon = tokio::spawn(serve_until_with_delay(
        DaemonConfig {
            endpoint: endpoint.clone(),
            recover: false,
        },
        async {
            let _ = shutdown_rx.await;
        },
        delay,
    ));
    wait_until_ready(&endpoint).await;

    let different_a = request("project-a", "different-a");
    let different_b = request("project-b", "different-b");
    let different_started = Instant::now();
    let different = tokio::join!(
        request_status(&endpoint, &different_a, Duration::from_secs(2)),
        request_status(&endpoint, &different_b, Duration::from_secs(2))
    );
    assert!(different.0.is_ok());
    assert!(different.1.is_ok());
    let different_elapsed = different_started.elapsed();

    let same_a = request("project-c", "same-a");
    let same_b = request("project-c", "same-b");
    let same_started = Instant::now();
    let same = tokio::join!(
        request_status(&endpoint, &same_a, Duration::from_secs(2)),
        request_status(&endpoint, &same_b, Duration::from_secs(2))
    );
    assert!(same.0.is_ok());
    assert!(same.1.is_ok());
    let same_elapsed = same_started.elapsed();

    assert!(
        same_elapsed >= different_elapsed + Duration::from_millis(100),
        "same-project elapsed {same_elapsed:?}, different-project elapsed {different_elapsed:?}"
    );

    let abandoned = request("project-abandoned", "abandoned");
    let mut abandoned_client = ClientTransport::connect(&endpoint, Duration::from_secs(1))
        .await
        .unwrap();
    abandoned_client
        .send(encode(&abandoned).unwrap())
        .await
        .unwrap();
    drop(abandoned_client);
    tokio::time::sleep(delay + Duration::from_millis(50)).await;
    assert!(
        request_status(
            &endpoint,
            &request("project-after-disconnect", "after-disconnect"),
            Duration::from_secs(2)
        )
        .await
        .is_ok()
    );

    shutdown_tx.send(()).unwrap();
    daemon.await.unwrap().unwrap();
    let _ = fs::remove_dir_all(runtime);
}
