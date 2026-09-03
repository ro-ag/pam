use std::time::Duration;

use pam_flow::ConnectorId;

use crate::ConnectorError;
use crate::transport::TransportError;

#[test]
fn every_variant_has_its_own_cause() {
    let causes: Vec<&str> = variants().iter().map(ConnectorError::cause).collect();
    let mut unique = causes.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), causes.len(), "causes collide: {causes:?}");
    assert!(
        causes.iter().all(|cause| cause.starts_with("connector_")),
        "{causes:?}"
    );
}

#[test]
fn causes_are_the_names_the_spec_fixes() {
    assert_eq!(ConnectorError::Auth.cause(), "connector_auth");
    assert_eq!(ConnectorError::Forbidden.cause(), "connector_forbidden");
    assert_eq!(ConnectorError::NotFound.cause(), "connector_not_found");
    assert_eq!(
        ConnectorError::RateLimited { retry_after: None }.cause(),
        "connector_rate_limited"
    );
    assert_eq!(ConnectorError::Timeout.cause(), "connector_timeout");
    assert_eq!(ConnectorError::Certificate.cause(), "connector_certificate");
    assert_eq!(
        ConnectorError::Network(String::new()).cause(),
        "connector_network"
    );
    assert_eq!(
        ConnectorError::Remote { status: 503 }.cause(),
        "connector_remote"
    );
    assert_eq!(
        ConnectorError::TooLarge {
            bytes: 2,
            maximum: 1
        }
        .cause(),
        "connector_response_too_large"
    );
    assert_eq!(
        ConnectorError::BadArgs(String::new()).cause(),
        "connector_bad_args"
    );
    assert_eq!(
        ConnectorError::BadResponse(String::new()).cause(),
        "connector_bad_response"
    );
    assert_eq!(ConnectorError::Cli(String::new()).cause(), "connector_cli");
    assert_eq!(ConnectorError::CliMissing.cause(), "connector_cli_missing");
}

#[test]
fn every_variant_carries_a_detail_and_a_recovery() {
    for error in variants() {
        for id in ConnectorId::ALL {
            let recovery = error.recovery(id);
            assert!(!error.detail().trim().is_empty(), "{error:?}");
            assert!(!recovery.trim().is_empty(), "{error:?}");
            // A recovery line never hands an agent a command that would
            // widen its own access.
            assert!(!recovery.contains("chmod"), "{recovery}");
            assert!(!recovery.contains("sudo"), "{recovery}");
        }
    }
}

#[test]
fn auth_recovery_names_the_connectors_screen_and_the_connector() {
    let recovery = ConnectorError::Auth.recovery(ConnectorId::Github);
    assert_eq!(
        recovery,
        "open Pam → Settings → Connectors → GitHub → replace the credential and Test"
    );
    assert!(
        ConnectorError::Auth
            .recovery(ConnectorId::Sonarqube)
            .contains("SonarQube")
    );
}

#[test]
fn network_and_certificate_recoveries_point_at_the_base_url() {
    for error in [
        ConnectorError::Certificate,
        ConnectorError::Network("dns".to_owned()),
    ] {
        assert_eq!(
            error.recovery(ConnectorId::Jenkins),
            "check the base URL in Pam → Settings → Connectors → Jenkins"
        );
    }
}

#[test]
fn rate_limit_recovery_names_the_wait_it_was_given() {
    let error = ConnectorError::RateLimited {
        retry_after: Some(Duration::from_secs(45)),
    };
    assert_eq!(
        error.recovery(ConnectorId::Github),
        "wait 45s and re-run the flow"
    );
    assert!(error.detail().contains("45s"));
    assert!(
        !ConnectorError::RateLimited { retry_after: None }
            .detail()
            .contains('0')
    );
}

#[test]
fn cli_missing_recovery_names_the_install() {
    assert_eq!(
        ConnectorError::CliMissing.recovery(ConnectorId::Aws),
        "install the aws CLI and make sure it is on the daemon's PATH"
    );
}

#[test]
fn only_transient_failures_are_retryable() {
    assert!(ConnectorError::Timeout.retryable());
    assert!(ConnectorError::RateLimited { retry_after: None }.retryable());
    assert!(ConnectorError::Network("reset".to_owned()).retryable());
    assert!(ConnectorError::Remote { status: 503 }.retryable());

    assert!(!ConnectorError::Remote { status: 418 }.retryable());
    assert!(!ConnectorError::Auth.retryable());
    assert!(!ConnectorError::Forbidden.retryable());
    assert!(!ConnectorError::NotFound.retryable());
    assert!(!ConnectorError::Certificate.retryable());
    assert!(!ConnectorError::BadArgs("no".to_owned()).retryable());
    assert!(!ConnectorError::BadResponse("no".to_owned()).retryable());
    assert!(!ConnectorError::Cli("no".to_owned()).retryable());
    assert!(!ConnectorError::CliMissing.retryable());
    assert!(
        !ConnectorError::TooLarge {
            bytes: 2,
            maximum: 1
        }
        .retryable()
    );
}

#[test]
fn transport_failures_map_onto_connector_failures() {
    assert_eq!(
        ConnectorError::from(TransportError::Timeout),
        ConnectorError::Timeout
    );
    assert_eq!(
        ConnectorError::from(TransportError::Certificate),
        ConnectorError::Certificate
    );
    assert_eq!(
        ConnectorError::from(TransportError::TooLarge { maximum: 64 }),
        ConnectorError::TooLarge {
            bytes: 64,
            maximum: 64
        }
    );
    assert_eq!(
        ConnectorError::from(TransportError::Network("reset".to_owned())),
        ConnectorError::Network("reset".to_owned())
    );
    let spawned = ConnectorError::from(TransportError::Spawn("no such file".to_owned()));
    assert_eq!(spawned.cause(), "connector_network");
    assert!(spawned.detail().contains("curl could not run"));
}

fn variants() -> Vec<ConnectorError> {
    vec![
        ConnectorError::Auth,
        ConnectorError::Forbidden,
        ConnectorError::NotFound,
        ConnectorError::RateLimited {
            retry_after: Some(Duration::from_secs(30)),
        },
        ConnectorError::Timeout,
        ConnectorError::Certificate,
        ConnectorError::Network("connection reset".to_owned()),
        ConnectorError::Remote { status: 502 },
        ConnectorError::TooLarge {
            bytes: 4096,
            maximum: 1024,
        },
        ConnectorError::BadArgs("`repo` is required".to_owned()),
        ConnectorError::BadResponse("not JSON".to_owned()),
        ConnectorError::Cli("exited 255".to_owned()),
        ConnectorError::CliMissing,
    ]
}
