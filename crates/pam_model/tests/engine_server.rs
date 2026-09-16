//! The llama-server supervisor against the fake server binary, and (opt-in)
//! against the real installed engine.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use pam_model::engine_server::{EngineServer, EngineServerError, ServerOptions};
use pam_model::runtime::GenerateRequest;

fn fake_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pam-fake-llama-server"))
}

fn short_dir() -> tempfile::TempDir {
    // Unix socket paths are capped at 104 bytes; keep the run dir short.
    tempfile::Builder::new()
        .prefix("pam-es-")
        .tempdir_in("/tmp")
        .unwrap()
}

fn request(prompt: &str, max_tokens: usize) -> GenerateRequest {
    GenerateRequest {
        system: Some("You echo.".into()),
        prompt: prompt.into(),
        max_tokens,
        temperature: 0.0,
        stop: Vec::new(),
    }
}

#[tokio::test]
async fn load_generate_bound_cancel_and_unload_through_the_fake_server() {
    let dir = short_dir();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    assert!(server.model().is_none());
    let model = Path::new("/models/fake.gguf");
    let options = ServerOptions {
        context_tokens: 4096,
        threads: Some(2),
        gpu_layers: Some(99),
        reasoning_budget: 0,
        load_timeout: Duration::from_secs(20),
        extra_env: Vec::new(),
    };
    let args = server.launch_args(
        model,
        &pam_model::engine_http::Endpoint::Unix(server.socket().to_path_buf()),
        &options,
    );
    assert_eq!(args[0..2], ["-m", "/models/fake.gguf"]);
    assert!(args.contains(&"--no-webui".to_owned()));
    assert!(args.contains(&"--jinja".to_owned()));
    assert!(args.windows(2).any(|w| w == ["-c", "4096"]));
    assert!(args.windows(2).any(|w| w == ["-t", "2"]));
    assert!(args.windows(2).any(|w| w == ["-ngl", "99"]));
    assert!(args.windows(2).any(|w| w == ["--reasoning-budget", "0"]));
    assert!(
        !args.iter().any(|a| a == "--api-key"),
        "the key is added at spawn only"
    );
    let tcp = server.launch_args(
        model,
        &pam_model::engine_http::Endpoint::Loopback(4321),
        &options,
    );
    assert!(tcp.windows(2).any(|w| w == ["--host", "127.0.0.1"]));
    assert!(tcp.windows(2).any(|w| w == ["--port", "4321"]));

    let loaded = server.load("fake/model", model, &options).await.unwrap();
    assert_eq!(loaded.id, "fake/model");
    assert_eq!(loaded.context_length, 4096);
    assert_eq!(loaded.build_info, "bfake-000");
    assert!(loaded.pid > 0);
    assert!(server.socket().exists());
    assert_eq!(server.model().map(|m| m.id), Some("fake/model".into()));

    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let result = server
        .generate(
            &request("one two three", 16),
            cancel.clone(),
            4096,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one two three");
    assert_eq!(result.finish_reason, "stop");
    assert_eq!(result.prompt_tokens, 6);
    assert_eq!(result.completion_tokens, 4);
    assert!(result.prompt_ms > 0.0);

    // The framed prompt is counted before generation and refused above the limit.
    let too_long = server
        .generate(
            &request("a b c d e f g h", 16),
            cancel.clone(),
            4,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(too_long, EngineServerError::InputTooLong { tokens, limit: 4 } if tokens > 4),
        "{too_long:?}"
    );

    // max_tokens is honoured and reported as a length stop; a budget of 2
    // reaches the server as the 16-token floor (`output_budget`), so a
    // twenty-word prompt is cut at sixteen.
    let words: Vec<String> = (1..=20).map(|n| format!("w{n}")).collect();
    let cut = server
        .generate(
            &request(&words.join(" "), 2),
            cancel,
            4096,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(cut.finish_reason, "length");
    assert_eq!(cut.text, format!("echo: {}", words[..16].join(" ")));

    // A cancel that is already set never reaches the server.
    let (stop, cancelled) = tokio::sync::watch::channel(true);
    let refused = server
        .generate(&request("x", 1), cancelled, 4096, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(refused, EngineServerError::Cancelled);
    drop(stop);

    server.unload().await;
    assert!(server.model().is_none());
    assert!(!server.socket().exists());
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    assert_eq!(
        server
            .generate(&request("x", 1), cancel, 4096, Duration::from_secs(2))
            .await
            .unwrap_err(),
        EngineServerError::NoModelLoaded
    );
}

#[tokio::test]
async fn a_server_that_exits_or_never_becomes_healthy_is_reported_and_reaped() {
    let dir = short_dir();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    let options = ServerOptions {
        load_timeout: Duration::from_secs(2),
        ..ServerOptions::default()
    };
    let exiting = ServerOptions {
        extra_env: vec![("PAM_FAKE_EXIT_EARLY".into(), "1".into())],
        ..options.clone()
    };
    let crashed = server
        .load("fake/model", Path::new("/models/fake.gguf"), &exiting)
        .await
        .unwrap_err();
    assert!(
        matches!(crashed, EngineServerError::Crashed { .. }),
        "{crashed:?}"
    );
    assert!(server.model().is_none());

    let stalled = ServerOptions {
        extra_env: vec![("PAM_FAKE_HEALTH_DELAY_MS".into(), "10000".into())],
        ..options.clone()
    };
    let slow = server
        .load("fake/model", Path::new("/models/fake.gguf"), &stalled)
        .await
        .unwrap_err();
    assert_eq!(slow, EngineServerError::LoadTimeout(Duration::from_secs(2)));
    assert!(server.model().is_none());
    assert!(
        !server.socket().exists(),
        "a timed-out server leaves no socket"
    );

    let missing = EngineServer::new(dir.path().join("nope"), dir.path(), dir.path()).unwrap();
    assert!(matches!(
        missing
            .load("fake/model", Path::new("/models/fake.gguf"), &options)
            .await
            .unwrap_err(),
        EngineServerError::BinaryMissing(_)
    ));
    let long = "x".repeat(120);
    assert!(matches!(
        EngineServer::new(fake_binary(), Path::new(&long), dir.path()).unwrap_err(),
        EngineServerError::SocketPath(_)
    ));
}

#[tokio::test]
async fn a_healthy_server_that_serves_another_model_is_refused_and_stopped() {
    let dir = short_dir();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    let squatter = ServerOptions {
        load_timeout: Duration::from_secs(10),
        extra_env: vec![("PAM_FAKE_MODEL_PATH".into(), "/models/other.gguf".into())],
        ..ServerOptions::default()
    };
    let refused = server
        .load("fake/model", Path::new("/models/fake.gguf"), &squatter)
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, EngineServerError::Spawn(detail) if detail.contains("reports model")),
        "{refused:?}"
    );
    assert!(server.model().is_none(), "nothing is trusted");
    assert!(!server.socket().exists(), "the stranger's socket is gone");
}

/// Opt-in: the real installed engine with a real GGUF. Set
/// `PAM_ENGINE_SERVER` (the llama-server binary) and `PAM_ENGINE_MODEL`.
#[tokio::test]
#[ignore = "needs a real llama-server and a real model"]
async fn the_real_engine_answers_a_bounded_prompt() {
    let binary = PathBuf::from(std::env::var("PAM_ENGINE_SERVER").expect("PAM_ENGINE_SERVER"));
    let model = PathBuf::from(std::env::var("PAM_ENGINE_MODEL").expect("PAM_ENGINE_MODEL"));
    let dir = short_dir();
    let server = EngineServer::new(binary, dir.path(), dir.path()).unwrap();
    let started = std::time::Instant::now();
    let loaded = server
        .load("real", &model, &ServerOptions::default())
        .await
        .unwrap();
    println!(
        "PAM_ENGINE_SERVER_LOAD {{\"build_info\":\"{}\",\"load_ms\":{}}}",
        loaded.build_info,
        started.elapsed().as_millis()
    );
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let result = server
        .generate(
            &GenerateRequest {
                system: Some("Answer with exactly one word.".into()),
                prompt: "Record:\nstage build: exit=0\nstage test: PASS (exit=1)\nDid the final stage pass? Answer PASS, FAIL or INCOMPLETE.".into(),
                max_tokens: 8,
                temperature: 0.0,
                stop: vec!["\n".into()],
            },
            cancel,
            2048,
            Duration::from_secs(120),
        )
        .await
        .unwrap();
    println!(
        "PAM_ENGINE_SERVER_RESULT {}",
        serde_json::to_string(&result).unwrap()
    );
    // Mechanics only: the smallest models talk nonsense, and quality is the
    // capability bench's job.
    assert!(!result.text.is_empty(), "{result:?}");
    assert!(
        result.prompt_tokens > 0 && result.completion_tokens > 0,
        "{result:?}"
    );
    assert!(
        matches!(result.finish_reason.as_str(), "stop" | "length"),
        "{result:?}"
    );
    server.unload().await;
    assert!(server.model().is_none());
}
