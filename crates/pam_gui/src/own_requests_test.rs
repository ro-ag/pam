use std::time::Instant;

use crate::own_requests::{CAPACITY, OwnRequests, TTL};

#[test]
fn a_registered_id_is_own_until_it_expires() {
    let registry = OwnRequests::new();
    let start = Instant::now();
    registry.register_at("req_status", start);
    assert!(registry.contains_at("req_status", start));
    assert!(!registry.contains_at("req_other", start));
    assert!(registry.contains_at("req_status", start + TTL / 2));
    assert!(
        !registry.contains_at("req_status", start + TTL),
        "an expired id stops matching, so the registry cannot grow with uptime"
    );
}

#[test]
fn the_registry_is_bounded_and_drops_the_oldest_first() {
    let registry = OwnRequests::new();
    let now = Instant::now();
    for index in 0..=CAPACITY {
        registry.register_at(&format!("req_{index}"), now);
    }
    assert!(
        !registry.contains_at("req_0", now),
        "the oldest id was evicted"
    );
    assert!(registry.contains_at(&format!("req_{CAPACITY}"), now));
    assert!(registry.contains_at("req_1", now));
}
