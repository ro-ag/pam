//! Runtime tests that never load weights.
//!
//! Everything the runtime decides *before* candle gets involved is testable
//! without a gigabyte on disk: the architecture refusal, the idle answers,
//! the state the mirror shows after a failed load, and the cause table the
//! GUI matches on. What is left — a real forward pass — is the opt-in bench
//! in `tests/bench.rs`, because there is no honest way to fake one.

use std::path::PathBuf;

use tokio::sync::watch;

use crate::gguf::GgufInfo;
use crate::qwen3_moe::GGUFQWenMoE;
use crate::registry::{ModelClass, ModelEntry};
use crate::runtime::{GenerateRequest, Runtime, RuntimeError, RuntimeState};

/// A registry entry pointing at `path`, claiming `architecture` when one is
/// given and claiming nothing when it is not.
fn entry(path: PathBuf, architecture: Option<&str>) -> ModelEntry {
    ModelEntry {
        id: "qwen/test".to_string(),
        vendor: "qwen".to_string(),
        file_name: "test.gguf".to_string(),
        path,
        size_bytes: 1024,
        info: architecture.map(|architecture| GgufInfo {
            architecture: architecture.to_string(),
            name: None,
            quant_label: "Q8_0".to_string(),
            parameter_count: 1,
            context_length: Some(4096),
            expert_count: None,
            tensor_count: 1,
            version: 3,
        }),
        info_error: None,
        class: ModelClass::TestOnly,
        verified: None,
        catalog_id: None,
    }
}

/// A cancel watch that is not cancelled.
fn live() -> watch::Receiver<bool> {
    watch::channel(false).1
}

/// A request that would generate a little, if there were anything loaded.
fn request() -> GenerateRequest {
    GenerateRequest {
        system: None,
        prompt: "hello".to_string(),
        max_tokens: 8,
        temperature: 0.0,
        stop: Vec::new(),
    }
}

#[test]
fn starts_idle_and_not_busy() {
    let runtime = Runtime::new();
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.state, RuntimeState::Idle);
    assert!(!snapshot.busy);
}

#[tokio::test]
async fn generate_with_nothing_loaded_is_refused() {
    let runtime = Runtime::default();
    let err = runtime
        .generate(request(), live())
        .await
        .expect_err("nothing is loaded");
    assert_eq!(err, RuntimeError::NoModelLoaded);
    assert_eq!(runtime.snapshot().state, RuntimeState::Idle);
}

#[tokio::test]
async fn unload_when_idle_is_ok() {
    let runtime = Runtime::new();
    runtime.unload().await.expect("unloading nothing is fine");
    assert_eq!(runtime.snapshot().state, RuntimeState::Idle);
}

#[tokio::test]
async fn an_unsupported_architecture_is_refused_before_candle() {
    let runtime = Runtime::new();
    // The path does not exist: reaching candle at all would fail with
    // `LoadFailed` instead, so this doubles as proof the header decided it.
    let entry = entry(PathBuf::from("/nonexistent/llama.gguf"), Some("llama"));

    let err = runtime.load(&entry).await.expect_err("llama is not ours");
    assert_eq!(
        err,
        RuntimeError::UnsupportedArchitecture("llama".to_string())
    );
    assert_eq!(runtime.snapshot().state, RuntimeState::Idle);
}

#[tokio::test]
async fn a_supported_architecture_still_has_to_be_a_gguf() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.gguf");
    std::fs::write(&path, b"not a gguf at all").expect("write the fixture");
    let runtime = Runtime::new();

    let err = runtime
        .load(&entry(path, Some("qwen3")))
        .await
        .expect_err("the bytes are not a model");
    assert!(
        matches!(err, RuntimeError::LoadFailed(_)),
        "expected LoadFailed, got {err:?}"
    );
    assert_eq!(
        runtime.snapshot().state,
        RuntimeState::Idle,
        "a failed load leaves the runtime idle, not half-loaded"
    );
    assert!(!runtime.snapshot().busy);
}

#[tokio::test]
async fn a_file_with_no_header_facts_is_refused_on_the_thread() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("mystery.gguf");
    std::fs::write(&path, b"GGUF-ish, but not really").expect("write the fixture");
    let runtime = Runtime::new();

    let err = runtime
        .load(&entry(path, None))
        .await
        .expect_err("an unparsed header cannot be pre-checked, so the thread refuses");
    assert!(
        matches!(err, RuntimeError::LoadFailed(_)),
        "expected LoadFailed, got {err:?}"
    );
}

#[tokio::test]
async fn the_thread_survives_a_failed_load_and_takes_the_next_command() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("test.gguf");
    std::fs::write(&path, b"nope").expect("write the fixture");
    let runtime = Runtime::new();

    runtime
        .load(&entry(path, Some("qwen3")))
        .await
        .expect_err("the load fails");
    runtime.unload().await.expect("the thread is still there");
    let err = runtime
        .generate(request(), live())
        .await
        .expect_err("and still answers");
    assert_eq!(err, RuntimeError::NoModelLoaded);
}

#[test]
fn the_cause_table_is_the_one_the_gui_matches_on() {
    let table = [
        (RuntimeError::NoModelLoaded, "no_model_loaded"),
        (
            RuntimeError::UnsupportedArchitecture("llama".to_string()),
            "unsupported_architecture",
        ),
        (RuntimeError::LoadFailed("boom".to_string()), "load_failed"),
        (
            RuntimeError::PromptTooLong {
                tokens: 9000,
                limit: crate::runtime::CONTEXT_TOKENS,
            },
            "prompt_too_long",
        ),
        (RuntimeError::Busy, "busy"),
        (RuntimeError::Cancelled, "cancelled"),
        (
            RuntimeError::GenerationFailed("boom".to_string()),
            "generation_failed",
        ),
        (RuntimeError::Crashed, "runtime_crashed"),
    ];
    for (error, cause) in table {
        assert_eq!(error.cause(), cause, "cause for {error:?}");
    }
}

#[test]
fn the_prompt_budget_message_names_both_numbers() {
    let err = RuntimeError::PromptTooLong {
        tokens: 9000,
        limit: crate::runtime::CONTEXT_TOKENS,
    };
    assert_eq!(
        err.to_string(),
        "prompt is 9000 tokens; the context allows 8192"
    );
}

#[test]
fn the_snapshot_serializes_with_a_tagged_state() {
    let runtime = Runtime::new();
    let json = serde_json::to_value(runtime.snapshot()).expect("snapshots serialize");
    assert_eq!(json["state"]["state"], "idle");
    assert_eq!(json["busy"], false);
}

#[test]
fn the_vendored_moe_model_can_clear_its_kv_cache() {
    // `GGUFQWenMoE` cannot be built without real weights, so this is a
    // compile-time proof rather than a behavioural one: the method has to
    // exist, take `&mut self`, and return nothing, or this does not build.
    // It is the whole reason `qwen3_moe.rs` is vendored — upstream 0.9.2 has
    // no such method, and without it every generation would have to rebuild
    // the model from its file. The behavioural half is `tests/bench.rs`,
    // which generates twice from one loaded model.
    let clear: fn(&mut GGUFQWenMoE) = GGUFQWenMoE::clear_kv_cache;
    let dense: fn(&mut candle_transformers::models::quantized_qwen3::ModelWeights) =
        candle_transformers::models::quantized_qwen3::ModelWeights::clear_kv_cache;
    // Both architectures reset the same way, which is what lets
    // `Loaded::reset_cache` be a two-line match with no rebuild in it.
    assert_eq!(
        std::mem::size_of_val(&clear),
        std::mem::size_of_val(&dense),
        "both clears are plain fn(&mut _) pointers"
    );
}
