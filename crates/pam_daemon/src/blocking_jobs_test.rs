use std::sync::{Arc, mpsc};
use std::time::Duration;

use crate::blocking_jobs::{BlockingJobs, Error, Kind};

#[tokio::test]
async fn cancelled_waiter_does_not_release_running_work_capacity() {
    let jobs = BlockingJobs::new(1);
    let worker_jobs = Arc::clone(&jobs);
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let waiter = tokio::spawn(async move {
        worker_jobs
            .run(Kind::Keychain, move || {
                let _ = started.send(());
                blocked
                    .recv_timeout(Duration::from_secs(5))
                    .expect("released");
            })
            .await
    });
    running.await.expect("worker started");
    waiter.abort();
    let _ = waiter.await;
    assert!(matches!(
        jobs.run(Kind::LogCompaction, || ()).await,
        Err(Error::Busy)
    ));
    release.send(()).expect("release work");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if jobs.run(Kind::LogCompaction, || ()).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("work releases permit when it actually finishes");
    let status = serde_json::to_value(jobs.snapshot()).unwrap();
    assert!(
        status["completed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| { job["kind"] == "keychain" && job["state"] == "returned" })
    );
}

#[tokio::test]
async fn conflicting_mutation_waits_after_first_caller_is_cancelled() {
    let jobs = BlockingJobs::new(2);
    let first_jobs = Arc::clone(&jobs);
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let first = tokio::spawn(async move {
        first_jobs
            .run(Kind::ModelFilesystem, move || {
                let _ = started.send(());
                blocked
                    .recv_timeout(Duration::from_secs(5))
                    .expect("released");
            })
            .await
    });
    running.await.expect("first mutation started");
    first.abort();
    let _ = first.await;
    let second_jobs = Arc::clone(&jobs);
    let (second_started, mut second_running) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        second_jobs
            .run(Kind::ModelFilesystem, move || {
                let _ = second_started.send(());
            })
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut second_running)
            .await
            .is_err()
    );
    release.send(()).expect("release first mutation");
    tokio::time::timeout(Duration::from_secs(2), second_running)
        .await
        .unwrap()
        .unwrap();
    second.await.unwrap().unwrap();
}

#[tokio::test]
async fn panics_release_capacity_and_completion_history_is_bounded() {
    let jobs = BlockingJobs::new(1);
    assert!(matches!(
        jobs.run(Kind::AgentDetection, || panic!("fixture")).await,
        Err(Error::Join)
    ));
    let status = serde_json::to_value(jobs.snapshot()).unwrap();
    assert_eq!(status["completed"][0]["state"], "panicked");
    for _ in 0..70 {
        jobs.run(Kind::LogCompaction, || ()).await.unwrap();
    }
    let status = serde_json::to_value(jobs.snapshot()).unwrap();
    assert_eq!(status["completed"].as_array().unwrap().len(), 64);
    assert!(status["outstanding"].as_array().unwrap().is_empty());
}
