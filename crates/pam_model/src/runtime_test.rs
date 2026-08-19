use super::{
    CancellationSignal, CancellationToken, RuntimeError, RuntimeFinishReason, RuntimeMessage,
    RuntimeMessageRole, RuntimeRequest, RuntimeResponse, RuntimeUsage,
};

#[test]
fn runtime_request_requires_explicit_bounded_user_completion() {
    let user = RuntimeMessage::new(RuntimeMessageRole::User, "explain this").unwrap();
    let request = RuntimeRequest::new(vec![user], 128).unwrap();
    assert_eq!(request.max_output_tokens(), 128);

    let assistant = RuntimeMessage::new(RuntimeMessageRole::Assistant, "partial").unwrap();
    assert!(matches!(
        RuntimeRequest::new(vec![assistant], 1),
        Err(RuntimeError::InvalidRequest(_))
    ));
    assert!(matches!(
        RuntimeRequest::new(Vec::new(), 1),
        Err(RuntimeError::InvalidRequest(_))
    ));
    assert!(matches!(
        RuntimeRequest::new(
            vec![RuntimeMessage::new(RuntimeMessageRole::User, "prompt").unwrap()],
            0,
        ),
        Err(RuntimeError::InvalidRequest(_))
    ));
}

#[test]
fn runtime_message_rejects_native_string_hazards() {
    for content in ["", "nul\0byte"] {
        assert!(matches!(
            RuntimeMessage::new(RuntimeMessageRole::User, content),
            Err(RuntimeError::InvalidRequest(_))
        ));
    }
}

#[test]
fn runtime_request_rejects_excess_aggregate_message_bytes() {
    let messages = (0..5)
        .map(|_| RuntimeMessage::new(RuntimeMessageRole::System, "a".repeat(1024 * 1024)).unwrap())
        .chain(std::iter::once(
            RuntimeMessage::new(RuntimeMessageRole::User, "final").unwrap(),
        ))
        .collect();
    assert!(matches!(
        RuntimeRequest::new(messages, 1),
        Err(RuntimeError::InvalidRequest(_))
    ));
}

#[test]
fn cancellation_token_is_cloneable_shared_state() {
    let token = CancellationToken::default();
    let worker_view = token.clone();
    assert!(!worker_view.is_cancelled());
    token.cancel();
    assert!(worker_view.is_cancelled());
}

#[test]
fn runtime_diagnostics_redact_prompt_and_output_text() {
    let message = RuntimeMessage::new(RuntimeMessageRole::User, "private prompt").unwrap();
    let request = RuntimeRequest::new(vec![message.clone()], 1).unwrap();
    let response = RuntimeResponse {
        text: "private output".to_owned(),
        finish_reason: RuntimeFinishReason::Stop,
        usage: RuntimeUsage {
            input_tokens: 2,
            sampled_output_tokens: 3,
            emitted_output_tokens: 2,
        },
    };

    assert!(!format!("{message:?}").contains("private prompt"));
    assert!(!format!("{request:?}").contains("private prompt"));
    assert!(!format!("{response:?}").contains("private output"));
}
