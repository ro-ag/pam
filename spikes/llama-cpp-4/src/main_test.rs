use super::{MIN_CONTEXT_TOKENS, select_context_tokens};

#[test]
fn default_context_respects_the_model_training_ceiling() {
    assert!(select_context_tokens(None, 128, MIN_CONTEXT_TOKENS - 1).is_err());
    assert_eq!(
        select_context_tokens(None, 128, MIN_CONTEXT_TOKENS).unwrap(),
        MIN_CONTEXT_TOKENS
    );
}

#[test]
fn explicit_context_must_cover_the_request_and_fit_training() {
    assert!(select_context_tokens(Some(512), 513, 1_024).is_err());
    assert!(select_context_tokens(Some(1_025), 513, 1_024).is_err());
    assert_eq!(select_context_tokens(Some(768), 513, 1_024).unwrap(), 768);
}
