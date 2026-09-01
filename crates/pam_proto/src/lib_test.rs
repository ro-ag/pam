use super::PROTOCOL_VERSION;

#[test]
fn protocol_version_is_stamped() {
    assert_eq!(PROTOCOL_VERSION, 1);
}
