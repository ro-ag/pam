use super::*;
use futures::{stream, task::noop_waker};

#[test]
fn repeated_and_stale_wakes_are_bounded_and_cannot_replace_peers() {
    let mut queue = FairQueue::new(false);
    let inner = queue.inner();
    inner.lock().insert(7_u64, stream::pending::<()>());
    let event = inner.lock().ready_queue.peek().unwrap().clone();
    let waker = Arc::new(StreamWaker {
        inner: inner.clone(),
        event,
    });
    let noop = noop_waker();
    assert!(Pin::new(&mut queue)
        .poll_next(&mut Context::from_waker(&noop))
        .is_pending());
    for _ in 0..10_000 {
        StreamWaker::wake_by_ref(&waker);
    }
    assert_eq!(inner.lock().ready_queue.len(), 1);
    inner.lock().remove(&7);
    for _ in 0..100 {
        StreamWaker::wake_by_ref(&waker);
    }
    assert!(inner.lock().ready_queue.is_empty());
    inner.lock().insert(7, stream::pending());
    let replacement = inner.lock().ready_queue.peek().unwrap().token.clone();
    for _ in 0..100 {
        StreamWaker::wake_by_ref(&waker);
    }
    assert_eq!(inner.lock().ready_queue.len(), 1);
    assert!(Arc::ptr_eq(
        &inner.lock().ready_queue.peek().unwrap().token,
        &replacement
    ));
    for id in 0..1_000 {
        inner.lock().insert(id, stream::pending());
        inner.lock().remove(&id);
    }
    assert!(inner.lock().ready_queue.is_empty());
}
