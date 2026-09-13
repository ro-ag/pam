//! Live engine integration, on every CI target when `PAM_ENGINE_LIVE=1`.
//!
//! Installs the pinned llama.cpp release for this platform from GitHub,
//! fetches the smallest GGUF llama.cpp itself tests with (tinyllamas
//! `stories260K`, 1.2 MB), runs it under the supervisor — Unix socket on
//! macOS/Linux, loopback TCP on Windows — and asks for one bounded
//! completion. This proves the acquisition, the transport and the server
//! contract on the real binary; it proves nothing about model quality.

use std::path::PathBuf;
use std::time::Duration;

use pam_model::download::{self, DownloadRequest, DownloadState};
use pam_model::engine;
use pam_model::engine_server::{EngineServer, ServerOptions};
use pam_model::runtime::GenerateRequest;

/// The smallest model llama.cpp's own CI uses, pinned by digest.
const MODEL_URL: &str =
    "https://huggingface.co/ggml-org/models/resolve/main/tinyllamas/stories260K.gguf";
const MODEL_SHA256: &str = "270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d";
const MODEL_BYTES: u64 = 1_185_376;

fn short_base() -> tempfile::TempDir {
    // Unix socket paths are capped at 104 bytes; keep the base short where
    // the platform has Unix sockets at all.
    let mut builder = tempfile::Builder::new();
    builder.prefix("pam-el-");
    if cfg!(unix) {
        builder.tempdir_in("/tmp").expect("short temp dir")
    } else {
        builder.tempdir().expect("temp dir")
    }
}

#[tokio::test]
async fn the_pinned_engine_serves_the_smallest_model_on_this_platform() {
    if std::env::var_os("PAM_ENGINE_LIVE").is_none() {
        eprintln!("PAM_ENGINE_LIVE unset; skipping the live engine integration");
        return;
    }
    let base = short_base();
    let (_keep, cancel) = tokio::sync::watch::channel(false);

    let installed = engine::install(base.path(), cancel.clone())
        .await
        .expect("the pinned engine installs on this platform");
    let server_binary: PathBuf = installed.server_path.clone().expect("server path");
    let manifest = installed.manifest.clone().expect("manifest");
    println!(
        "PAM_ENGINE_LIVE_INSTALL {}",
        serde_json::json!({"target": manifest.target, "tag": manifest.tag, "sha256": manifest.sha256, "version": manifest.version_line})
    );

    let model_path = base.path().join("stories260K.gguf");
    let handle = download::start(DownloadRequest {
        url: MODEL_URL.to_owned(),
        dest: model_path.clone(),
        expected_size: Some(MODEL_BYTES),
        expected_sha256: Some(MODEL_SHA256.to_owned()),
        license_id: None,
    })
    .expect("the model transfer starts");
    match handle.wait().await {
        DownloadState::Done { sha256, size_bytes } => {
            assert_eq!(sha256, MODEL_SHA256);
            assert_eq!(size_bytes, MODEL_BYTES);
        }
        other => panic!("model transfer did not finish: {other:?}"),
    }

    let run = base.path().join("run");
    std::fs::create_dir_all(&run).unwrap();
    let server = EngineServer::new(server_binary, &run, base.path()).unwrap();
    let options = ServerOptions {
        context_tokens: 512,
        threads: Some(2),
        gpu_layers: None,
        reasoning_budget: 0,
        load_timeout: Duration::from_secs(120),
        extra_env: Vec::new(),
    };
    let started = std::time::Instant::now();
    let loaded = server
        .load("tinyllamas/stories260K", &model_path, &options)
        .await
        .expect("the real server loads the smallest model");
    let endpoint = server.endpoint().expect("endpoint");
    let result = server
        .generate(
            &GenerateRequest {
                system: Some("You tell a short story.".into()),
                prompt: "Once upon a time".into(),
                max_tokens: 12,
                temperature: 0.0,
                stop: Vec::new(),
            },
            cancel,
            512,
            Duration::from_secs(60),
        )
        .await
        .expect("one bounded completion");
    println!(
        "PAM_ENGINE_LIVE_RESULT {}",
        serde_json::json!({
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "endpoint": format!("{endpoint:?}"), "build_info": loaded.build_info,
            "load_ms": started.elapsed().as_millis(),
            "prompt_tokens": result.prompt_tokens, "completion_tokens": result.completion_tokens,
            "finish_reason": result.finish_reason, "predicted_ms": result.predicted_ms,
        })
    );
    assert_eq!(
        loaded.build_info,
        format!("{}-f1e44dcc1", engine::ENGINE_TAG)
    );
    assert!(!result.text.is_empty());
    assert!(result.prompt_tokens > 0 && result.completion_tokens > 0);
    assert!(matches!(result.finish_reason.as_str(), "stop" | "length"));
    if cfg!(windows) {
        assert!(matches!(
            endpoint,
            pam_model::engine_http::Endpoint::Loopback(_)
        ));
    } else {
        assert!(matches!(
            endpoint,
            pam_model::engine_http::Endpoint::Unix(_)
        ));
    }
    server.unload().await;
    assert!(server.model().is_none());
}
