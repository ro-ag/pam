use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    Config, MAX_CHAT_TEMPLATE_BYTES, MIN_CONTEXT_TOKENS, ParsedArgs,
    bounded_chat_template_retry_size, checked_projected_memory_sum, enforce_projected_memory_cap,
    select_context_tokens, validate_prompt_batch_size,
};

static TEST_FILE_ID: AtomicU64 = AtomicU64::new(0);

struct TestModelFile(PathBuf);

impl TestModelFile {
    fn new() -> Self {
        let id = TEST_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pam-llama-cpp-4-main-test-{}-{id}.gguf",
            std::process::id()
        ));
        File::create(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestModelFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn parse_run(arguments: &[&str]) -> super::AppResult<Config> {
    let arguments = std::iter::once(OsString::from("pam-llama-cpp-4-spike"))
        .chain(arguments.iter().map(|argument| OsString::from(*argument)));
    match Config::parse(arguments)? {
        ParsedArgs::Run(config) => Ok(config),
        ParsedArgs::Help => panic!("expected run configuration"),
    }
}

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

#[test]
fn projected_byte_cap_parses_with_explicit_context() {
    let model = TestModelFile::new();
    let config = parse_run(&[
        "--model",
        model.0.to_str().unwrap(),
        "--context",
        "8192",
        "--max-projected-bytes",
        "20000000000",
    ])
    .unwrap();

    assert_eq!(config.context_tokens, Some(8_192));
    assert_eq!(config.max_projected_bytes, Some(20_000_000_000));
}

#[test]
fn chat_mode_is_explicit_and_raw_mode_remains_default() {
    let raw_model = TestModelFile::new();
    let raw = parse_run(&["--model", raw_model.0.to_str().unwrap()]).unwrap();
    assert!(!raw.chat);

    let chat_model = TestModelFile::new();
    let chat = parse_run(&["--model", chat_model.0.to_str().unwrap(), "--chat"]).unwrap();
    assert!(chat.chat);
}

#[test]
fn chat_mode_may_only_be_specified_once() {
    let model = TestModelFile::new();
    let error = parse_run(&["--model", model.0.to_str().unwrap(), "--chat", "--chat"]).unwrap_err();

    assert_eq!(error.to_string(), "--chat may only be specified once");
}

#[test]
fn recommended_sampling_is_explicit_and_duplicate_rejected() {
    let raw_model = TestModelFile::new();
    let raw = parse_run(&["--model", raw_model.0.to_str().unwrap()]).unwrap();
    assert!(!raw.recommended_sampling);

    let sampled_model = TestModelFile::new();
    let sampled = parse_run(&[
        "--model",
        sampled_model.0.to_str().unwrap(),
        "--recommended-sampling",
    ])
    .unwrap();
    assert!(sampled.recommended_sampling);

    let duplicate_model = TestModelFile::new();
    let error = parse_run(&[
        "--model",
        duplicate_model.0.to_str().unwrap(),
        "--recommended-sampling",
        "--recommended-sampling",
    ])
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "--recommended-sampling may only be specified once"
    );
}

#[test]
fn chat_template_retry_size_is_positive_and_bounded() {
    assert_eq!(bounded_chat_template_retry_size(4_097).unwrap(), 4_097);

    let zero = bounded_chat_template_retry_size(0).unwrap_err();
    assert_eq!(
        zero.to_string(),
        "embedded chat template reported an invalid required buffer size of zero"
    );

    let too_large = bounded_chat_template_retry_size(MAX_CHAT_TEMPLATE_BYTES + 1).unwrap_err();
    assert_eq!(
        too_large.to_string(),
        format!(
            "embedded chat template requires {} bytes, exceeding the {MAX_CHAT_TEMPLATE_BYTES}-byte safety limit",
            MAX_CHAT_TEMPLATE_BYTES + 1
        )
    );
}

#[test]
fn projected_byte_cap_must_be_positive() {
    let model = TestModelFile::new();
    let error = parse_run(&[
        "--model",
        model.0.to_str().unwrap(),
        "--context",
        "8192",
        "--max-projected-bytes",
        "0",
    ])
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "--max-projected-bytes must be greater than zero"
    );
}

#[test]
fn projected_byte_cap_requires_explicit_context() {
    let model = TestModelFile::new();
    let error = parse_run(&[
        "--model",
        model.0.to_str().unwrap(),
        "--max-projected-bytes",
        "20000000000",
    ])
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "--max-projected-bytes requires an explicit --context"
    );
}

#[test]
fn projected_memory_cap_accepts_equal_or_lower_totals() {
    assert!(enforce_projected_memory_cap(19, 20).is_ok());
    assert!(enforce_projected_memory_cap(20, 20).is_ok());
}

#[test]
fn projected_memory_cap_rejects_excess_total() {
    let error = enforce_projected_memory_cap(21, 20).unwrap_err();
    assert_eq!(
        error.to_string(),
        "projected runtime memory 21 bytes exceeds --max-projected-bytes cap of 20 bytes"
    );
}

#[test]
fn fixed_runtime_batch_rejects_oversized_prompt() {
    assert!(validate_prompt_batch_size(512).is_ok());
    let error = validate_prompt_batch_size(513).unwrap_err();
    assert_eq!(
        error.to_string(),
        "prompt tokenization produced 513 tokens, but the fixed runtime batch supports at most 512 prompt tokens"
    );
}

#[test]
fn projected_memory_sum_aggregates_multiple_entries() {
    assert_eq!(checked_projected_memory_sum([3, 5, 7]).unwrap(), 15);
}

#[test]
fn projected_memory_sum_rejects_aggregate_overflow() {
    let error = checked_projected_memory_sum([usize::MAX, 1]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "total projected memory exceeded the platform integer range"
    );
}
