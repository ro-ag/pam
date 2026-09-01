use pam_proto::PROTOCOL_VERSION;

use crate::request::{ArgsError, DEFAULT_DEADLINE_MS, build_envelope, new_request_id};

#[test]
fn request_ids_are_ulid_prefixed_and_unique() {
    let first = new_request_id();
    let second = new_request_id();
    for id in [&first, &second] {
        assert!(id.starts_with("req_"), "id: {id}");
        // A ULID is 26 Crockford base32 characters.
        assert_eq!(id.len(), "req_".len() + 26, "id: {id}");
    }
    assert_ne!(first, second);
}

#[test]
fn the_envelope_stamps_caller_version_and_id() {
    let args = serde_json::json!({ "msg": "hi" });
    let envelope = build_envelope(
        "echo",
        args.clone(),
        true,
        DEFAULT_DEADLINE_MS,
        Some("idem-1".to_owned()),
    );

    assert_eq!(envelope.v, PROTOCOL_VERSION);
    assert!(envelope.id.starts_with("req_"), "id: {}", envelope.id);
    assert_eq!(envelope.capability, "echo");
    assert_eq!(envelope.client_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(envelope.caller.pid, std::process::id());
    assert!(!envelope.caller.agent.is_empty());
    assert!(!envelope.caller.repo.is_empty());
    assert_eq!(envelope.args, args);
    assert_eq!(envelope.idempotency_key.as_deref(), Some("idem-1"));
    assert_eq!(envelope.deadline_ms, DEFAULT_DEADLINE_MS);
    assert!(envelope.wait);
}

#[test]
fn missing_args_default_to_the_empty_object() {
    let args = crate::request::parse_args_object(None).expect("defaults to {}");
    assert_eq!(args, serde_json::json!({}));
}

#[test]
fn object_args_pass_through() {
    let args =
        crate::request::parse_args_object(Some(r#"{ "delay_ms": 5 }"#)).expect("object parses");
    assert_eq!(args, serde_json::json!({ "delay_ms": 5 }));
}

#[test]
fn non_object_args_are_rejected_with_the_type_named() {
    let err = crate::request::parse_args_object(Some("[1, 2]")).expect_err("arrays rejected");
    assert!(matches!(err, ArgsError::NotAnObject { found: "an array" }));
    assert!(err.to_string().contains("JSON object"), "err: {err}");

    let err = crate::request::parse_args_object(Some("42")).expect_err("numbers rejected");
    assert!(matches!(err, ArgsError::NotAnObject { found: "a number" }));
}

#[test]
fn invalid_json_args_are_rejected() {
    let err = crate::request::parse_args_object(Some("{ nope")).expect_err("bad JSON rejected");
    assert!(matches!(err, ArgsError::Invalid { .. }));
}
