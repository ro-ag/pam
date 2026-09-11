//! Opt-in probe for issue #21: unload reports success but the measured
//! working set stayed resident (~17.8 GB after a 64 ms unload). This probe
//! names the holder instead of assuming one: it loads a real artifact,
//! generates once, samples its own RSS, unloads, and samples again.
//!
//! The numbers are the evidence. The assertion is deliberately loose —
//! "unload returns at least half the loaded working set" — so a genuine
//! allocator-retention problem fails here loudly rather than being excused
//! by a bound chosen to pass.
//!
//! ```text
//! PAM_UNLOAD_MODEL=/tmp/pam-candidate-screen/models/qwen/Qwen3-14B-Q5_K_M.gguf \
//!   cargo test -p pam_model --release --test unload_working_set -- --ignored --nocapture
//! ```

use pam_model::{
    registry::{Registry, sha256_file},
    runtime::{Backend, GenerateRequest, Runtime},
};
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;

fn emit(value: &serde_json::Value) {
    println!("PAM_UNLOAD_PROBE {}", serde_json::to_string(value).unwrap());
}

/// Resident set of this process in bytes, sampled through `ps` so the probe
/// stays dependency-free and measures what the screen harness measured.
fn rss_bytes() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    let text = String::from_utf8(output.stdout).expect("ps output is text");
    let kilobytes: u64 = text
        .split_whitespace()
        .next()
        .expect("ps printed an rss column")
        .parse()
        .expect("rss is numeric");
    kilobytes * 1024
}

#[tokio::test]
#[ignore = "requires a pinned local GGUF at PAM_UNLOAD_MODEL in registry layout"]
async fn unload_returns_the_working_set() {
    let path = PathBuf::from(
        std::env::var("PAM_UNLOAD_MODEL").expect("set PAM_UNLOAD_MODEL to a pinned GGUF"),
    );
    let directory = path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("registry vendor/file layout");
    let entry = Registry::new(directory)
        .scan()
        .expect("the models dir scans")
        .into_iter()
        .find(|entry| entry.path == path)
        .expect("artifact in registry");
    let (sha, bytes) = sha256_file(&path).expect("artifact readable");

    let runtime = Runtime::new();
    runtime
        .load_on_backend(&entry, Backend::Cpu)
        .await
        .expect("load");

    // One small generation so the KV cache and decode state exist too —
    // unload must release the steady state, not an untouched load.
    let (_sender, cancel) = watch::channel(false);
    runtime
        .generate_bounded(
            GenerateRequest {
                system: None,
                prompt: "Reply with exactly: PONG".into(),
                max_tokens: 8,
                temperature: 0.0,
                stop: vec![],
            },
            cancel,
            64,
        )
        .await
        .expect("generation");

    let loaded_rss = rss_bytes();
    emit(
        &json!({"phase":"loaded","artifact_sha256":sha,"artifact_bytes":bytes,
        "rss_bytes":loaded_rss}),
    );

    let started = std::time::Instant::now();
    runtime.unload().await.expect("unload");
    let unload_ms = started.elapsed().as_millis();

    // Give the allocator and the kernel a moment to reclaim before sampling.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after_rss = rss_bytes();
    let returned = loaded_rss.saturating_sub(after_rss);
    emit(&json!({"phase":"unloaded","unload_ms":unload_ms,
        "rss_bytes":after_rss,"returned_bytes":returned}));

    assert!(
        unload_ms < 5_000,
        "unload itself took {unload_ms} ms; the envelope is the whole return, not the reply"
    );
    assert!(
        after_rss * 2 < loaded_rss,
        "unload returned only {returned} of {loaded_rss} bytes; more than half the working set is still resident"
    );
}
