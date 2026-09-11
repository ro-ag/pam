//! Opt-in behavioural proof that a pinned artifact's runtime framing matches
//! what the artifact itself declares. See docs/model-resource-screen.md for
//! the resource sibling; this file answers one question only: does the model,
//! loaded through the production runtime, answer as its declared template
//! says it should — no stray think block, deterministic at temperature 0.
//!
//! Run against the pinned dense artifact with:
//! ```text
//! PAM_FRAMING_MODEL=/tmp/pam-candidate-screen/models/qwen/Qwen3-14B-Q5_K_M.gguf \
//! PAM_FRAMING_EXPECT=qwen3_thinking_disabled \
//!   cargo test -p pam_model --test framing_verification -- --ignored --nocapture
//! ```

use candle_core::quantized::gguf_file;
use pam_model::{
    registry::{Registry, sha256_file},
    runtime::{Backend, GenerateRequest, Runtime},
    tokenizer,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Instant};
use tokio::sync::watch;

const OUTPUT: usize = 64;
const INPUT_LIMIT: usize = 512;
const SYSTEM: &str = "Answer with the exact requested token and nothing else.";
const PROMPT: &str = "Reply with exactly: PONG";

fn required(name: &str) -> String {
    let value = std::env::var(name)
        .unwrap_or_else(|_| panic!("set {name}; see framing verification documentation"));
    assert!(!value.is_empty() && value.len() <= 4096, "invalid {name}");
    value
}

fn emit(value: &Value) {
    let encoded = serde_json::to_string(value).unwrap();
    println!("PAM_FRAMING_VERIFICATION {encoded}");
}

#[tokio::test]
#[ignore = "requires an explicitly pinned local GGUF artifact"]
async fn framed_generation_matches_the_declared_template() {
    let path = PathBuf::from(required("PAM_FRAMING_MODEL"));
    let expected = required("PAM_FRAMING_EXPECT");
    let expected_sha = required("PAM_FRAMING_SHA256");
    let expected_bytes: u64 = required("PAM_FRAMING_BYTES").parse().expect("byte count");

    let (actual_sha, actual_len) = sha256_file(&path).expect("artifact readable");
    assert_eq!(actual_sha, expected_sha, "artifact is not the pinned file");
    assert_eq!(actual_len, expected_bytes, "artifact byte count drifted");

    let content = gguf_file::Content::read(&mut std::fs::File::open(&path).unwrap()).unwrap();
    let tokenizer = tokenizer::from_gguf(&content).unwrap();
    assert_eq!(
        tokenizer.framing.label(),
        expected,
        "the artifact's declared template did not classify as expected"
    );
    assert!(
        tokenizer.framing.template_qualified(),
        "framing verification is meaningless for an undeclared template"
    );
    let framing = tokenizer.framing;
    drop(tokenizer);
    drop(content);

    let directory = path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("registry vendor/file layout");
    let entry = Registry::new(directory)
        .scan()
        .unwrap()
        .into_iter()
        .find(|entry| entry.path == path)
        .expect("artifact in registry");

    let runtime = Runtime::new();
    let started = Instant::now();
    let _loaded = runtime
        .load_on_backend(&entry, Backend::Cpu)
        .await
        .expect("load");
    emit(
        &json!({"schema_version":1,"phase":"load","framing":framing.label(),
        "template_qualified":framing.template_qualified(),"wall_ms":started.elapsed().as_millis()}),
    );

    let request = GenerateRequest {
        system: Some(SYSTEM.into()),
        prompt: PROMPT.into(),
        max_tokens: OUTPUT,
        temperature: 0.0,
        stop: vec![],
    };
    let mut outputs = Vec::new();
    for repeat in 0..2 {
        let (_sender, cancel) = watch::channel(false);
        let started = Instant::now();
        let result = runtime
            .generate_bounded(request.clone(), cancel, INPUT_LIMIT)
            .await
            .expect("generation");
        let digest = hex::encode(Sha256::digest(result.text.as_bytes()));
        emit(
            &json!({"schema_version":1,"phase":"generate","repeat":repeat,
            "prompt_tokens":result.prompt_tokens,"completion_tokens":result.completion_tokens,
            "wall_ms":started.elapsed().as_millis(),"output_sha256":digest}),
        );
        assert!(
            !result.text.contains("<think"),
            "the model emitted a think block; the declared framing did not reach generation"
        );
        outputs.push(digest);
    }
    assert_eq!(
        outputs[0], outputs[1],
        "temperature-0 repeats diverged; determinism contract broken"
    );
}
