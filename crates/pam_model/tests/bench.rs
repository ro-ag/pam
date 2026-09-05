//! Opt-in proof that the runtime really runs a model.
//!
//! Every other runtime test stops at the edge of candle. This one crosses
//! it: it loads real weights, generates real tokens, and prints the rate. It
//! is opt-in because the weights are gigabytes the repository will never
//! carry and CI will never download.
//!
//! ```text
//! PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf \
//!     PAM_BENCH_BACKEND=metal cargo test -p pam_model --test bench -- --ignored --nocapture
//! ```
//!
//! The path must sit in the registry layout — `<models dir>/<vendor>/<file>.gguf`
//! — because the bench goes through [`Registry::scan`] rather than around it,
//! which is the point: it exercises the same path the daemon takes.
//!
//! It also generates *twice* from the one loaded model and asserts the two
//! answers are identical. At temperature 0 this checks that generation state,
//! including the KV cache, is reset on whichever architecture is exercised.
//!
//! Explicitly ignored by default: a skipped run is not inference evidence.
//! An opted-in run requires a real model path and explicit cpu/metal backend.
//! Cancellation and prompt-budget failure must both leave the model usable.
//! These checks prove inference and recovery, not task quality or a RAM baseline.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use pam_model::registry::Registry;
use pam_model::runtime::{Backend, CONTEXT_TOKENS, GenerateRequest, Runtime, RuntimeError};
use tokio::sync::watch;

/// Environment variable naming the GGUF to bench.
const BENCH_MODEL_ENV: &str = "PAM_BENCH_MODEL";

/// Tokens the bench asks for. Small enough to finish on CPU, large enough
/// that the rate means something.
const BENCH_MAX_TOKENS: usize = 32;

#[tokio::test]
#[ignore = "requires real GGUF weights and an explicit PAM_BENCH_BACKEND=cpu|metal"]
async fn generates_from_real_weights() {
    let raw = std::env::var(BENCH_MODEL_ENV).expect("set PAM_BENCH_MODEL to a real GGUF path");
    let backend_name = std::env::var("PAM_BENCH_BACKEND").expect("set PAM_BENCH_BACKEND=cpu|metal");
    let backend = match backend_name.as_str() {
        "cpu" => Backend::Cpu,
        "metal" => Backend::Metal,
        _ => panic!("PAM_BENCH_BACKEND must be cpu or metal"),
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
    let load_started = Instant::now();
    let loaded = runtime
        .load_on_backend(&entry, backend)
        .await
        .expect("the weights load");
    println!(
        "bench load: {} ms; weights: {} bytes",
        load_started.elapsed().as_millis(),
        std::fs::metadata(&path).unwrap().len()
    );
    assert_eq!(loaded.device, backend_name);
    println!(
        "bench model: {} ({}, {}) on {}",
        loaded.id, loaded.architecture, loaded.quant, loaded.device
    );

    let (_tx, cancel) = watch::channel(false);
    let request = GenerateRequest {
        system: None,
        prompt: "Say hello in five words.".to_string(),
        max_tokens: BENCH_MAX_TOKENS,
        temperature: 0.0,
        stop: Vec::new(),
    };
    let cold_started = Instant::now();
    let result = runtime
        .generate(request.clone(), cancel.clone())
        .await
        .expect("the model generates");

    println!(
        "bench cold generation wall: {} ms",
        cold_started.elapsed().as_millis()
    );
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

    // Same prompt, model and temperature: check that generation state resets.
    let warm_started = Instant::now();
    let again = runtime
        .generate(request.clone(), cancel.clone())
        .await
        .expect("the model generates a second time");
    println!(
        "bench warm generation wall: {} ms",
        warm_started.elapsed().as_millis()
    );
    println!(
        "bench second pass: {} completion tokens in {} ms, {:.2} tok/s",
        again.completion_tokens, again.decode_ms, again.tokens_per_sec
    );
    assert_eq!(
        again.text, result.text,
        "the second generation diverged; inspect KV cache reset and backend determinism"
    );
    assert_eq!(again.prompt_tokens, result.prompt_tokens);

    check_recovery(&runtime, request, cancel, &result.text).await;
    runtime.unload().await.expect("unload is clean");
}

async fn check_recovery(
    runtime: &Runtime,
    request: GenerateRequest,
    cancel: watch::Receiver<bool>,
    expected: &str,
) {
    // Cancel an in-flight request, then demand the same deterministic answer.
    // A cancelled decode may leave a partial KV cache behind.
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let mut long_request = request.clone();
    long_request.max_tokens = 1024;
    let cancel_runtime = runtime.clone();
    let interrupt = async move {
        while !cancel_runtime.snapshot().busy {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel_tx
            .send(true)
            .expect("generation still owns the cancellation watch");
    };
    let (cancelled, ()) = tokio::time::timeout(Duration::from_mins(10), async {
        tokio::join!(runtime.generate(long_request, cancel_rx), interrupt)
    })
    .await
    .expect("in-flight cancellation finishes within ten minutes");
    assert!(
        matches!(cancelled, Err(RuntimeError::Cancelled)),
        "expected actual cancellation, got {cancelled:?}"
    );
    assert!(!runtime.snapshot().busy);
    let recovered = runtime
        .generate(request.clone(), cancel.clone())
        .await
        .expect("generation after cancellation");
    assert_eq!(
        recovered.text, expected,
        "cancellation contaminated the next generation"
    );

    let mut too_long = request.clone();
    too_long.max_tokens = CONTEXT_TOKENS;
    assert!(matches!(
        runtime.generate(too_long, cancel.clone()).await,
        Err(RuntimeError::PromptTooLong { .. })
    ));
    assert!(!runtime.snapshot().busy);
    let recovered = runtime
        .generate(request, cancel)
        .await
        .expect("generation after prompt error");
    assert_eq!(
        recovered.text, expected,
        "prompt failure contaminated the next generation"
    );
    println!(
        "bench recovery: cancellation and prompt-budget failure both followed by identical real generations"
    );
}
