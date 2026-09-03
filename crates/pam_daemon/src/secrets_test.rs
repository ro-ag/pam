use std::sync::Arc;

use crate::secrets::{FakeSecretBackend, SecretError, SecretStore, account_for};

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

    store.set("github", "ghp_abc123").await.unwrap();
    assert!(store.present("github").await.unwrap());

    let secret = store.get("github").await.unwrap().expect("secret present");
    assert_eq!(secret.expose(), "ghp_abc123");

    // Setting again replaces rather than duplicating.
    store.set("github", "ghp_replacement").await.unwrap();
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
    store.set("github", "gh-secret").await.unwrap();
    store.set("jenkins", "jenkins-secret").await.unwrap();

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
        store.set("github", "x").await.unwrap_err(),
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
        store.set("github", "x").await.unwrap_err(),
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
