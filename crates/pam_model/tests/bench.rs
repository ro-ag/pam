//! Opt-in proof that the runtime really runs a model.
//!
//! Every other runtime test stops at the edge of candle. This one crosses
//! it: it loads real weights, generates real tokens, and prints the rate. It
//! is opt-in because the weights are gigabytes the repository will never
//! carry and CI will never download.
//!
//! ```text
//! PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf \
//!     cargo test -p pam_model --test bench -- --nocapture
//! ```
//!
//! The path must sit in the registry layout — `<models dir>/<vendor>/<file>.gguf`
//! — because the bench goes through [`Registry::scan`] rather than around it,
//! which is the point: it exercises the same path the daemon takes.
//!
//! With the variable unset the test prints how to enable it and passes.
//! Skipping loudly beats failing on a machine that was never going to have
//! the weights.

use std::path::PathBuf;

use pam_model::registry::Registry;
use pam_model::runtime::{GenerateRequest, Runtime};
use tokio::sync::watch;

/// Environment variable naming the GGUF to bench.
const BENCH_MODEL_ENV: &str = "PAM_BENCH_MODEL";

/// Tokens the bench asks for. Small enough to finish on CPU, large enough
/// that the rate means something.
const BENCH_MAX_TOKENS: usize = 32;

#[tokio::test]
async fn generates_from_real_weights() {
    let Ok(raw) = std::env::var(BENCH_MODEL_ENV) else {
        println!("bench skipped: set {BENCH_MODEL_ENV}=<gguf>");
        return;
    };
    let path = PathBuf::from(&raw);
    let vendor_dir = path
        .parent()
        .expect("PAM_BENCH_MODEL must sit under <models dir>/<vendor>/");
    let models_dir = vendor_dir
        .parent()
        .expect("PAM_BENCH_MODEL must sit under <models dir>/<vendor>/");
    let file_name = path
        .file_name()
        .expect("PAM_BENCH_MODEL must name a file")
        .to_string_lossy()
        .into_owned();

    let entries = Registry::new(models_dir)
        .scan()
        .expect("the models dir scans");
    let entry = entries
        .into_iter()
        .find(|entry| entry.file_name == file_name)
        .unwrap_or_else(|| panic!("{raw} was not found by a scan of {}", models_dir.display()));

    let runtime = Runtime::new();
    let loaded = runtime.load(&entry).await.expect("the weights load");
    println!(
        "bench model: {} ({}, {}) on {}",
        loaded.id, loaded.architecture, loaded.quant, loaded.device
    );

    let (_tx, cancel) = watch::channel(false);
    let result = runtime
        .generate(
            GenerateRequest {
                system: None,
                prompt: "Say hello in five words.".to_string(),
                max_tokens: BENCH_MAX_TOKENS,
                temperature: 0.0,
                stop: Vec::new(),
            },
            cancel,
        )
        .await
        .expect("the model generates");

    println!(
        "bench: {} prompt tokens in {} ms, {} completion tokens in {} ms, {:.2} tok/s",
        result.prompt_tokens,
        result.prompt_ms,
        result.completion_tokens,
        result.decode_ms,
        result.tokens_per_sec
    );
    println!("bench reply: {}", result.text.trim());

    assert!(!result.text.trim().is_empty(), "the model said nothing");
    assert!(result.completion_tokens > 0, "no tokens were generated");
    assert!(
        result.tokens_per_sec > 0.0,
        "the decode rate is not positive"
    );

    runtime.unload().await.expect("unload is clean");
}
