use std::sync::Arc;

use tokio::sync::{Mutex, mpsc, oneshot};

use super::{ProjectId, ProjectQueue};

#[tokio::test]
async fn same_project_entries_run_in_fifo_order() {
    let queue = ProjectQueue::default();
    let project = ProjectId::from("project-1");
    let order = Arc::new(Mutex::new(Vec::new()));
    let (release_first, first_released) = oneshot::channel();
    let (first_entered, mut entered) = mpsc::channel(2);

    let first_queue = queue.clone();
    let first_project = project.clone();
    let first_order = order.clone();
    let first = tokio::spawn(async move {
        let _permit = first_queue.enter(&first_project).await;
        first_order.lock().await.push(1);
        first_entered.send(()).await.unwrap();
        first_released.await.unwrap();
    });
    entered.recv().await.unwrap();

    let second_queue = queue.clone();
    let second_order = order.clone();
    let second = tokio::spawn(async move {
        let _permit = second_queue.enter(&project).await;
        second_order.lock().await.push(2);
    });

    tokio::task::yield_now().await;
    assert_eq!(*order.lock().await, vec![1]);
    release_first.send(()).unwrap();
    first.await.unwrap();
    second.await.unwrap();
    assert_eq!(*order.lock().await, vec![1, 2]);
}

#[tokio::test]
async fn different_projects_do_not_share_a_gate() {
    let queue = ProjectQueue::default();
    let first = queue.enter(&ProjectId::from("project-1")).await;

    let second = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        queue.enter(&ProjectId::from("project-2")),
    )
    .await;

    assert!(second.is_ok());
    drop(first);
}
