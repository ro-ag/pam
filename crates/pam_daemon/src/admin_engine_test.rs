use std::time::Duration;

use crate::admin_engine::install_cancellation;

/// The install future lives under the admin deadline; when the deadline
/// drops it, the cancel receiver the transfer polls must observe `true` —
/// a dropped sender alone leaves `false` behind and `changed()` would then
/// pend forever on the closed channel, with curl running detached.
#[tokio::test(start_paused = true)]
async fn dropping_the_install_future_signals_its_cancel_receiver() {
    let (guard, mut cancel) = install_cancellation();
    let install = async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(120), install)
            .await
            .is_err(),
        "the deadline dropped the install"
    );
    assert!(*cancel.borrow(), "cancellation was requested on drop");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), cancel.changed())
            .await
            .is_ok(),
        "a waiter on changed() wakes rather than pending forever"
    );
}
