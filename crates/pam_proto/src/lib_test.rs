use super::PROTOCOL_VERSION;

#[test]
fn protocol_version_is_stamped() {
    assert_eq!(PROTOCOL_VERSION, 2);
    assert_eq!(PROTOCOL_VERSION, super::wire::WIRE_PROTOCOL);
}
