use std::{collections::HashMap, sync::Mutex};

use pam_core::{CallerCredential, CallerId};

use crate::secrets::{
    MAX_SECRET_CONTEXT_BYTES, NativeSecretBackend, SecretBackend, SecretBackendError,
    SecretLocator, SecretStore, SecretStoreErrorKind,
};

#[derive(Default)]
struct MemoryBackend {
    values: Mutex<HashMap<String, CallerCredential>>,
    failure: Mutex<Option<SecretBackendError>>,
}

#[test]
fn native_adapter_uses_the_injected_keyring_without_exposing_it() {
    let backend = NativeSecretBackend::from_store(keyring_core::mock::Store::new().unwrap());
    let store = SecretStore::new(backend);
    let locator = locator("native-mock-caller");

    store
        .set(&locator, &CallerCredential::new("native-mock-secret"))
        .unwrap();
    assert_eq!(
        store.get(&locator).unwrap().expose_secret(),
        "native-mock-secret"
    );
    assert_eq!(
        format!("{:?}", store.backend()),
        "NativeSecretBackend([REDACTED])"
    );
    store.delete(&locator).unwrap();
}

impl MemoryBackend {
    fn fail_with(&self, failure: SecretBackendError) {
        *self.failure.lock().unwrap() = Some(failure);
    }

    fn failure(&self) -> Result<(), SecretBackendError> {
        if let Some(failure) = *self.failure.lock().unwrap() {
            Err(failure)
        } else {
            Ok(())
        }
    }
}

impl SecretBackend for MemoryBackend {
    fn get(&self, locator: &SecretLocator) -> Result<Option<CallerCredential>, SecretBackendError> {
        self.failure()?;
        Ok(self.values.lock().unwrap().get(locator.as_str()).cloned())
    }

    fn set(
        &self,
        locator: &SecretLocator,
        credential: &CallerCredential,
    ) -> Result<(), SecretBackendError> {
        self.failure()?;
        self.values
            .lock()
            .unwrap()
            .insert(locator.as_str().to_owned(), credential.clone());
        Ok(())
    }

    fn delete(&self, locator: &SecretLocator) -> Result<bool, SecretBackendError> {
        self.failure()?;
        Ok(self
            .values
            .lock()
            .unwrap()
            .remove(locator.as_str())
            .is_some())
    }
}

fn locator(caller: &str) -> SecretLocator {
    SecretLocator::for_caller(&CallerId::new(caller)).unwrap()
}

#[test]
fn credentials_round_trip_update_delete_and_report_missing() {
    let store = SecretStore::new(MemoryBackend::default());
    let locator = locator("caller-one");

    assert_eq!(
        store.get(&locator).unwrap_err().kind(),
        SecretStoreErrorKind::NotFound
    );

    store
        .set(&locator, &CallerCredential::new("first-secret"))
        .unwrap();
    assert_eq!(store.get(&locator).unwrap().expose_secret(), "first-secret");

    store
        .set(&locator, &CallerCredential::new("replacement-secret"))
        .unwrap();
    assert_eq!(
        store.get(&locator).unwrap().expose_secret(),
        "replacement-secret"
    );

    store.delete(&locator).unwrap();
    assert_eq!(
        store.get(&locator).unwrap_err().kind(),
        SecretStoreErrorKind::NotFound
    );
    assert_eq!(
        store.delete(&locator).unwrap_err().kind(),
        SecretStoreErrorKind::NotFound
    );
}

#[test]
fn locator_rejects_empty_and_oversized_context() {
    let oversized = "x".repeat(MAX_SECRET_CONTEXT_BYTES + 1);

    for result in [
        SecretLocator::for_caller(&CallerId::new("")),
        SecretLocator::for_caller(&CallerId::new(oversized)),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            SecretStoreErrorKind::InvalidLocator
        );
    }
}

#[test]
fn locator_is_stable_bounded_and_distinguishes_adjacent_callers() {
    let first = locator("ab");
    let repeated = locator("ab");
    let adjacent = locator("abc");

    assert_eq!(first, repeated);
    assert_ne!(first, adjacent);
    assert_eq!(
        first.as_str(),
        "pam.caller.v1.8972f3645daf4b782ef6fde9622de01dd1c305fccb94201713af2240e5669b00"
    );
    assert_eq!(first.as_str().len(), "pam.caller.v1.".len() + 64);
    assert!(first.as_str().starts_with("pam.caller.v1."));
}

#[test]
fn locators_separate_callers_at_the_length_boundary() {
    let maximum = "x".repeat(MAX_SECRET_CONTEXT_BYTES);

    assert_ne!(locator("caller-one"), locator("caller-two"));
    assert!(SecretLocator::for_caller(&CallerId::new(maximum)).is_ok());
}

#[test]
fn invalid_secrets_and_error_output_never_reveal_secret_material() {
    let store = SecretStore::new(MemoryBackend::default());
    let locator = locator("caller-sensitive");
    let invalid_secret = "";

    let error = store
        .set(&locator, &CallerCredential::new(invalid_secret))
        .unwrap_err();
    assert_eq!(error.kind(), SecretStoreErrorKind::InvalidCredential);

    let rendered = format!("{error} {error:?} {locator:?}");
    assert!(!rendered.contains("caller-sensitive"));
    assert!(rendered.contains("[REDACTED]"));
}

#[test]
fn backend_failures_are_mapped_to_sanitized_error_kinds() {
    let backend = MemoryBackend::default();
    let locator = locator("caller");
    backend.fail_with(SecretBackendError::Unavailable);
    let store = SecretStore::new(backend);

    let error = store.get(&locator).unwrap_err();
    assert_eq!(error.kind(), SecretStoreErrorKind::Unavailable);
    assert_eq!(
        error.to_string(),
        "PAM's native credential store is unavailable."
    );

    let backend = MemoryBackend::default();
    backend.fail_with(SecretBackendError::Denied);
    let store = SecretStore::new(backend);
    let error = store
        .set(&locator, &CallerCredential::new("must-not-leak"))
        .unwrap_err();
    assert_eq!(error.kind(), SecretStoreErrorKind::BackendDenied);
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("must-not-leak"));
}
