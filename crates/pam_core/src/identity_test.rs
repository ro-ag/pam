use super::{CallerId, IdempotencyKey, ProjectId, RequestId};
use crate::identity::{CallerCredential, MAX_CALLER_CREDENTIAL_LENGTH};

#[test]
fn identifiers_preserve_their_text_values() {
    assert_eq!(CallerId::from("cli").as_str(), "cli");
    assert_eq!(IdempotencyKey::from("status-1").as_str(), "status-1");
    assert_eq!(ProjectId::from("project").as_str(), "project");
    assert_eq!(RequestId::from("request").as_str(), "request");
}

#[test]
fn caller_credential_debug_output_is_redacted() {
    let credential = CallerCredential::new("credential-secret");

    assert_eq!(format!("{credential:?}"), "[REDACTED]");
}

#[test]
fn caller_credentials_support_equality_and_explicit_secret_access() {
    let credential = CallerCredential::new(String::from("credential-secret"));

    assert_eq!(credential, CallerCredential::new("credential-secret"));
    assert_eq!(credential.expose_secret(), "credential-secret");
}

#[test]
fn caller_credential_validation_enforces_byte_length_boundaries() {
    assert!(!CallerCredential::new("").is_valid());
    assert!(CallerCredential::new("x").is_valid());
    assert!(CallerCredential::new("x".repeat(MAX_CALLER_CREDENTIAL_LENGTH)).is_valid());
    assert!(!CallerCredential::new("x".repeat(MAX_CALLER_CREDENTIAL_LENGTH + 1)).is_valid());

    let multibyte_credential = "é".repeat(MAX_CALLER_CREDENTIAL_LENGTH / 2 + 1);
    assert!(!CallerCredential::new(multibyte_credential).is_valid());
}
