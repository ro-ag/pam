use crate::admission_rate::RateWindow;
use std::time::{Duration, Instant};

#[test]
fn exhausted_work_rate_does_not_consume_control_allowance_and_recovers() {
    let now = Instant::now();
    let mut work = RateWindow::new(2);
    let mut control = RateWindow::new(1);
    assert!(work.admit(now));
    assert!(work.admit(now));
    assert!(!work.admit(now));
    assert!(control.admit(now));
    assert!(!work.admit(now + Duration::from_millis(999)));
    assert!(work.admit(now + Duration::from_secs(1)));
}
