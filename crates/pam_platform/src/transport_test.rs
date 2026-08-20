use super::{PlatformTransport, TransportError, TransportErrorKind, selected_transport};

#[test]
fn every_supported_platform_selects_local_ipc() {
    assert_eq!(selected_transport(), PlatformTransport::UnixIpc);
}

#[test]
fn unavailable_transport_has_exact_recovery_action() {
    let error = TransportError::new(TransportErrorKind::Unavailable, "connection refused");

    assert_eq!(error.recovery_action(), Some("pam daemon"));
    assert_eq!(
        error.to_string(),
        "PAM daemon is not reachable. Start it with `pam daemon`."
    );
    assert_eq!(error.diagnostic(), "connection refused");
}

#[test]
fn stale_endpoint_has_explicit_recovery_action() {
    let error = TransportError::new(TransportErrorKind::StaleEndpoint, "address in use");

    assert_eq!(error.recovery_action(), Some("pam daemon --recover"));
}
