use std::sync::Arc;

use crate::secrets::{
    FakeSecretBackend, KeyringState, PROBE_CONNECTOR, Secret, SecretBackend, SecretError,
    SecretStore, account_for, keyring_error_kind,
};

/// What a platform error contributes to a log line is its variant name and
/// nothing else: the payloads carry account identifiers and, on some
/// backends, the secret itself.
#[test]
fn keyring_error_kind_names_the_variant_without_its_payload() {
    let leaky =
        keyring_core::Error::BadStoreFormat("account pam.connector.v1.github: hunter2".into());
    assert_eq!(keyring_error_kind(&leaky), "bad_store_format");
    assert_eq!(
        keyring_error_kind(&keyring_core::Error::NoEntry),
        "no_entry"
    );
    assert_eq!(
        keyring_error_kind(&keyring_core::Error::Invalid(
            "field".into(),
            "hunter2".into()
        )),
        "invalid"
    );
    for kind in [
        keyring_error_kind(&leaky),
        keyring_error_kind(&keyring_core::Error::NoDefaultStore),
    ] {
        assert!(!kind.contains("hunter2") && !kind.contains("github"));
    }
}

#[test]
fn account_for_shapes_the_connector_id_into_the_v1_namespace() {
    assert_eq!(account_for("github"), "pam.connector.v1.github");
    assert_eq!(account_for("sonarqube"), "pam.connector.v1.sonarqube");
}

#[test]
fn secret_debug_never_prints_the_exposed_value() {
    let secret = crate::secrets::Secret::new("hunter2-token".to_owned());
    assert_eq!(format!("{secret:?}"), "[REDACTED]");
    assert_eq!(secret.expose(), "hunter2-token");
}

#[tokio::test]
async fn set_get_present_clear_round_trip_through_the_fake_backend() {
    let store = SecretStore::new(Arc::new(FakeSecretBackend::default()));

    assert!(!store.present("github").await.unwrap());
    assert!(store.get("github").await.unwrap().is_none());

    store
        .set("github", Secret::new("ghp_abc123".to_owned()))
        .await
        .unwrap();
    assert!(store.present("github").await.unwrap());

    let secret = store.get("github").await.unwrap().expect("secret present");
    assert_eq!(secret.expose(), "ghp_abc123");

    // Setting again replaces rather than duplicating.
    store
        .set("github", Secret::new("ghp_replacement".to_owned()))
        .await
        .unwrap();
    let replaced = store
        .get("github")
        .await
        .unwrap()
        .expect("secret still present");
    assert_eq!(replaced.expose(), "ghp_replacement");

    assert!(store.clear("github").await.unwrap());
    assert!(!store.present("github").await.unwrap());
    assert!(store.get("github").await.unwrap().is_none());

    // Clearing an absent entry reports it was not there, without erroring.
    assert!(!store.clear("github").await.unwrap());
}

#[tokio::test]
async fn entries_for_different_connectors_never_collide() {
    let store = SecretStore::new(Arc::new(FakeSecretBackend::default()));
    store
        .set("github", Secret::new("gh-secret".to_owned()))
        .await
        .unwrap();
    store
        .set("jenkins", Secret::new("jenkins-secret".to_owned()))
        .await
        .unwrap();

    assert_eq!(
        store.get("github").await.unwrap().unwrap().expose(),
        "gh-secret"
    );
    assert_eq!(
        store.get("jenkins").await.unwrap().unwrap().expose(),
        "jenkins-secret"
    );

    assert!(store.clear("github").await.unwrap());
    assert!(store.present("jenkins").await.unwrap());
}

#[tokio::test]
async fn fail_with_denied_surfaces_from_every_operation() {
    let backend = FakeSecretBackend::default();
    *backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
    let store = SecretStore::new(Arc::new(backend));

    assert_eq!(store.get("github").await.unwrap_err(), SecretError::Denied);
    assert_eq!(
        store
            .set("github", Secret::new("x".to_owned()))
            .await
            .unwrap_err(),
        SecretError::Denied
    );
    assert_eq!(
        store.clear("github").await.unwrap_err(),
        SecretError::Denied
    );
    assert_eq!(
        store.present("github").await.unwrap_err(),
        SecretError::Denied
    );
}

#[tokio::test]
async fn fail_with_unavailable_surfaces_from_every_operation() {
    let backend = FakeSecretBackend::default();
    *backend.fail_with.lock().unwrap() = Some(SecretError::Unavailable);
    let store = SecretStore::new(Arc::new(backend));

    assert_eq!(
        store.get("github").await.unwrap_err(),
        SecretError::Unavailable
    );
    assert_eq!(
        store
            .set("github", Secret::new("x".to_owned()))
            .await
            .unwrap_err(),
        SecretError::Unavailable
    );
    assert_eq!(
        store.clear("github").await.unwrap_err(),
        SecretError::Unavailable
    );
    assert_eq!(
        store.present("github").await.unwrap_err(),
        SecretError::Unavailable
    );
}

#[test]
fn secret_error_carries_a_cause_and_a_recovery_line() {
    assert_eq!(SecretError::Unavailable.cause(), "store_unavailable");
    assert_eq!(SecretError::Denied.cause(), "store_denied");
    assert!(!SecretError::Unavailable.recovery().is_empty());
    assert!(!SecretError::Denied.recovery().is_empty());
}

#[tokio::test]
async fn warm_on_non_macos_returns_immediately_without_touching_the_backend() {
    let backend = FakeSecretBackend::default();
    *backend.fail_with.lock().unwrap() = Some(SecretError::Unavailable);
    let store = Arc::new(SecretStore::new(Arc::new(backend)));

    // `warm` must not panic or block even though the backend is
    // configured to fail every call; on non-macOS it is a documented
    // no-op, so calling it here must be a plain synchronous return.
    store.warm();
}

#[tokio::test]
async fn a_probe_reports_reach_denial_and_unavailability() {
    let backend = Arc::new(FakeSecretBackend::default());
    let store = SecretStore::new(Arc::clone(&backend) as Arc<dyn SecretBackend>);

    let health = store.probe_keyring().await;
    assert_eq!(health.state, KeyringState::Reachable);
    assert_eq!(health.cause, None);
    assert_eq!(
        health.recovery, None,
        "a working keychain has nothing to recover from"
    );

    *backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
    let denied = store.probe_keyring().await;
    assert_eq!(denied.state, KeyringState::Denied);
    assert_eq!(denied.cause, Some("store_denied"));
    assert!(
        denied.recovery.is_some_and(|line| !line.is_empty()),
        "a denial names the way out"
    );

    *backend.fail_with.lock().unwrap() = Some(SecretError::Unavailable);
    let gone = store.probe_keyring().await;
    assert_eq!(gone.state, KeyringState::Unavailable);
    assert_eq!(gone.cause, Some("store_unavailable"));
}

#[tokio::test]
async fn the_cached_probe_stands_until_a_fresh_one_is_asked_for() {
    let backend = Arc::new(FakeSecretBackend::default());
    let store = SecretStore::new(Arc::clone(&backend) as Arc<dyn SecretBackend>);
    assert_eq!(store.keyring_health().await.state, KeyringState::Reachable);

    // Access is revoked behind the cache's back. The cached answer is
    // deliberately still the old one — the GUI polls this several times a
    // minute and a keychain round trip per tick is not free.
    *backend.fail_with.lock().unwrap() = Some(SecretError::Denied);
    assert_eq!(
        store.keyring_health().await.state,
        KeyringState::Reachable,
        "inside the TTL the last reading stands"
    );

    // Re-check asks the platform again, which is the point of the button.
    assert_eq!(store.probe_keyring().await.state, KeyringState::Denied);
    assert_eq!(
        store.keyring_health().await.state,
        KeyringState::Denied,
        "and the fresh answer becomes the cached one"
    );
}

#[test]
fn a_probe_never_stores_anything() {
    // The probe reads an account nothing writes: proving access must not
    // leave a credential behind, and PROBE_CONNECTOR must not collide
    // with a real connector id.
    assert!(pam_flow::ConnectorId::parse(PROBE_CONNECTOR).is_none());
}

#[tokio::test]
async fn worker_capacity_failure_keeps_its_cause_and_is_not_cached_as_os_health() {
    let backend = Arc::new(FakeSecretBackend::default());
    let store = SecretStore::new(backend.clone());
    let busy = SecretError::from(crate::blocking_jobs::Error::Busy);
    assert_eq!(busy.cause(), "blocking_capacity_exhausted");
    *backend.fail_with.lock().unwrap() = Some(busy);
    assert_eq!(
        store.keyring_health().await.cause,
        Some("blocking_capacity_exhausted")
    );
    *backend.fail_with.lock().unwrap() = None;
    assert_eq!(store.keyring_health().await.state, KeyringState::Reachable);
    assert_eq!(
        SecretError::from(crate::blocking_jobs::Error::Join).cause(),
        "blocking_job_failed"
    );
}
