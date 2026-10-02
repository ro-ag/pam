//! The llama-server supervisor against the fake server binary, and (opt-in)
//! against the real installed engine.
//!
//! The supervisor picks a private Unix socket wherever the platform has
//! them and a loopback port elsewhere, so the socket-mode `load` tests run
//! on Unix and the loopback-mode `load` test on every other platform. The
//! fake server's loopback mode itself is exercised everywhere.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pam_model::engine_http::{self, Endpoint, HttpError};
use pam_model::engine_server::{EngineServer, EngineServerError, ServerOptions};
use pam_model::runtime::GenerateRequest;

fn fake_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pam-fake-llama-server"))
}

#[cfg(unix)]
fn short_dir() -> tempfile::TempDir {
    // Unix socket paths are capped at 104 bytes; keep the run dir short.
    tempfile::Builder::new()
        .prefix("pam-es-")
        .tempdir_in("/tmp")
        .unwrap()
}

/// A free loopback port, probed and released the way the supervisor does.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    probe.local_addr().unwrap().port()
}

/// A child process that dies with the test, pass or fail.
struct Reaped(std::process::Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Polls `/health` on `endpoint` until the server says `ok`, within
/// `patience`; returns how many answers came back before it did.
async fn wait_healthy(endpoint: &Endpoint, key: &str, patience: Duration) -> usize {
    let deadline = std::time::Instant::now() + patience;
    let mut earlier = 0;
    loop {
        match engine_http::request(
            endpoint,
            "GET",
            "/health",
            key,
            None,
            Duration::from_secs(2),
        )
        .await
        {
            Ok(reply) if reply.status == 200 => {
                let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
                assert_eq!(body["status"], "ok");
                return earlier;
            }
            Ok(reply) => {
                assert_eq!(reply.status, 503, "{reply:?}");
                earlier += 1;
            }
            Err(HttpError::Connect(_)) => earlier += 1,
            Err(other) => panic!("health probe failed: {other:?}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the fake server never reported healthy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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

#[cfg(unix)]
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end walk through the supervisor's load, generate and unload"
)]
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
    let record = server
        .pid_record()
        .expect("a running server has a pid record");
    assert_eq!(record.pid, loaded.pid);
    assert_eq!(record.model_path, model);
    assert_eq!(record.exe, fake_binary());
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
    assert!(
        server.pid_record().is_none(),
        "unload clears the pid record"
    );
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    assert_eq!(
        server
            .generate(&request("x", 1), cancel, 4096, Duration::from_secs(2))
            .await
            .unwrap_err(),
        EngineServerError::NoModelLoaded
    );
}

/// The process's argument vector as `ps` shows it to any same-user process.
#[cfg(unix)]
fn ps_arguments(pid: u32) -> Vec<String> {
    let out = std::process::Command::new("ps")
        .args(["-o", "args=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn the_api_key_reaches_the_server_in_a_file_and_never_in_its_arguments() {
    let dir = short_dir();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    let loaded = server
        .load(
            "fake/model",
            Path::new("/models/fake.gguf"),
            &ServerOptions {
                load_timeout: Duration::from_secs(20),
                ..ServerOptions::default()
            },
        )
        .await
        .unwrap();

    let args = ps_arguments(loaded.pid);
    assert!(!args.is_empty(), "the server is running: {args:?}");
    assert!(
        args.iter().any(|a| a == "--api-key-file"),
        "the key is handed over as a file: {args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "--api-key"),
        "no --api-key flag: {args:?}"
    );
    assert!(
        !args
            .iter()
            .any(|a| a.len() == 64 && a.bytes().all(|b| b.is_ascii_hexdigit())),
        "the key itself is not visible to ps: {args:?}"
    );
    assert!(
        !server.key_file().exists(),
        "the key file is gone once the server is healthy"
    );
    // The key the server never saw on its command line still authenticates PAM.
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let result = server
        .generate(
            &request("one two", 16),
            cancel,
            4096,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one two");
    server.unload().await;
    assert!(!server.key_file().exists());
}

/// A server killed from outside (jetsam, a crash, a human) is noticed: nothing is
/// "loaded" any more, generation says the engine exited rather than failing on a
/// dead socket, and loading again starts a working one.
#[cfg(unix)]
#[tokio::test]
async fn a_server_that_dies_after_loading_is_noticed_and_can_be_loaded_again() {
    let dir = short_dir();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    let model = Path::new("/models/fake.gguf");
    let options = ServerOptions {
        load_timeout: Duration::from_secs(20),
        ..ServerOptions::default()
    };
    let loaded = server.load("fake/model", model, &options).await.unwrap();
    assert!(server.model().is_some());

    let status = std::process::Command::new("kill")
        .args(["-9", &loaded.pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let started = std::time::Instant::now();
    while server.model().is_some() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the dead server is still reported as loaded"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let exit = server.last_exit().expect("the exit is recorded");
    assert_eq!(exit.model_id, "fake/model");
    assert!(!server.socket().exists(), "its socket is cleaned up");
    assert!(server.pid_record().is_none(), "its pid record is cleared");

    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let error = server
        .generate(
            &request("x", 1),
            cancel.clone(),
            4096,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineServerError::Exited { .. }),
        "{error:?}"
    );

    let again = server.load("fake/model", model, &options).await.unwrap();
    assert_ne!(again.pid, loaded.pid);
    assert!(
        server.last_exit().is_none(),
        "a fresh load clears the old exit"
    );
    let result = server
        .generate(&request("one", 16), cancel, 4096, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one");
    server.unload().await;
}

/// Another process squatting a loopback port: it answers `/health` and `/props` as
/// a server for `model` would, whatever key it is sent.
async fn squat(model: &'static str) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = if head.starts_with("GET /health") {
                r#"{"status":"ok"}"#.to_owned()
            } else {
                serde_json::json!({"model_path": model, "build_info": "impostor"}).to_string()
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (port, task)
}

/// ptrack issue 36: the port is probed and released before the spawn, so a stranger
/// can bind it first. It answers health and props perfectly; the real child dies on
/// the taken port. The load must not return the stranger as the engine: it notices
/// the dead child and retries on a fresh port.
#[tokio::test]
async fn a_stranger_that_takes_the_probed_port_is_not_mistaken_for_the_engine() {
    let model = "/models/fake.gguf";
    let (taken_port, impostor) = squat(model).await;
    let free = free_port();
    let ports = std::sync::Mutex::new(vec![free, taken_port]);
    let dir = tempfile::tempdir().unwrap();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path())
        .unwrap()
        .with_loopback_ports(move || ports.lock().unwrap().pop());

    let loaded = server
        .load(
            "fake/model",
            Path::new(model),
            &ServerOptions {
                load_timeout: Duration::from_secs(30),
                ..ServerOptions::default()
            },
        )
        .await
        .expect("the retry lands on the free port");
    assert_eq!(
        server.endpoint(),
        Some(Endpoint::Loopback(free)),
        "the engine is the child on the free port, not the stranger"
    );
    assert_eq!(
        loaded.build_info, "bfake-000",
        "answers came from the real child"
    );
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let result = server
        .generate(
            &request("one two", 16),
            cancel,
            4096,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one two");
    server.unload().await;
    impostor.abort();
}

#[tokio::test]
async fn when_every_port_is_taken_the_load_fails_instead_of_trusting_a_stranger() {
    let model = "/models/fake.gguf";
    let mut ports = Vec::new();
    let mut squatters = Vec::new();
    for _ in 0..3 {
        let (port, task) = squat(model).await;
        ports.push(port);
        squatters.push(task);
    }
    let ports = std::sync::Mutex::new(ports);
    let dir = tempfile::tempdir().unwrap();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path())
        .unwrap()
        .with_loopback_ports(move || ports.lock().unwrap().pop());

    let error = server
        .load(
            "fake/model",
            Path::new(model),
            &ServerOptions {
                load_timeout: Duration::from_secs(30),
                ..ServerOptions::default()
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineServerError::Crashed { .. }),
        "the child that lost every race is what is reported: {error:?}"
    );
    assert!(server.model().is_none(), "nothing is trusted");
    assert!(server.endpoint().is_none());
    assert!(server.pid_record().is_none());
    for task in squatters {
        task.abort();
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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
#[cfg(unix)]
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

/// The fake server in loopback mode, driven exactly as the supervisor
/// drives a real one on a port: the port is probed and released first,
/// health is polled over TCP until `ok`, every other route needs the bearer
/// key, and `/props` names the model `-m` loaded. Runs everywhere, since
/// the loopback client and the fake's TCP listener are platform-neutral.
#[tokio::test]
async fn the_fake_server_serves_the_supervisor_routes_over_a_loopback_port() {
    let port = free_port();
    let child = std::process::Command::new(fake_binary())
        .args([
            "-m",
            "/models/fake.gguf",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "-c",
            "2048",
            "--api-key",
            "loopback-secret",
        ])
        .env("PAM_FAKE_HEALTH_DELAY_MS", "300")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let _child = Reaped(child);
    let endpoint = Endpoint::Loopback(port);
    wait_healthy(&endpoint, "loopback-secret", Duration::from_secs(30)).await;

    // The key gates every route but health.
    let refused = engine_http::request(
        &endpoint,
        "GET",
        "/props",
        "wrong-key",
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(refused.status, 401);
    let props = engine_http::request(
        &endpoint,
        "GET",
        "/props",
        "loopback-secret",
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(props.status, 200);
    let props: serde_json::Value = serde_json::from_slice(&props.body).unwrap();
    assert_eq!(props["model_path"], "/models/fake.gguf");
    assert_eq!(props["build_info"], "bfake-000");
    assert_eq!(props["default_generation_settings"]["n_ctx"], 2048);

    let completion = engine_http::request(
        &endpoint,
        "POST",
        "/v1/chat/completions",
        "loopback-secret",
        Some(br#"{"messages":[{"role":"user","content":"one two"}],"max_tokens":16}"#),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(completion.status, 200);
    let completion: serde_json::Value = serde_json::from_slice(&completion.body).unwrap();
    assert_eq!(
        completion["choices"][0]["message"]["content"],
        "echo: one two"
    );
    assert_eq!(completion["choices"][0]["finish_reason"], "stop");
}

/// `PAM_FAKE_TCP_PORT` selects the loopback mode through the environment,
/// overriding a socket-shaped `--host`.
#[tokio::test]
async fn the_environment_can_select_the_fake_server_port() {
    let port = free_port();
    let child = std::process::Command::new(fake_binary())
        .args([
            "-m",
            "/models/env.gguf",
            "--host",
            "/nonexistent/engine.sock",
        ])
        .env("PAM_FAKE_TCP_PORT", port.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let _child = Reaped(child);
    let endpoint = Endpoint::Loopback(port);
    wait_healthy(&endpoint, "", Duration::from_secs(30)).await;
    let props = engine_http::request(&endpoint, "GET", "/props", "", None, Duration::from_secs(5))
        .await
        .unwrap();
    let props: serde_json::Value = serde_json::from_slice(&props.body).unwrap();
    assert_eq!(props["model_path"], "/models/env.gguf");
    assert!(
        !Path::new("/nonexistent/engine.sock").exists(),
        "no socket is bound in loopback mode"
    );
}

/// The supervisor's own loopback path: `choose_endpoint` probes a free
/// port where Unix sockets do not exist, so `load` polls health over TCP,
/// sends the bearer key, and trusts the server only after `/props` names
/// the model it was asked to load. Unreachable on Unix, where the
/// supervisor always binds the private socket.
#[cfg(not(unix))]
#[tokio::test]
async fn load_over_loopback_probes_a_port_polls_health_and_trusts_only_its_model() {
    let dir = tempfile::tempdir().unwrap();
    let server = EngineServer::new(fake_binary(), dir.path(), dir.path()).unwrap();
    let model = Path::new("/models/fake.gguf");
    let options = ServerOptions {
        context_tokens: 4096,
        load_timeout: Duration::from_secs(60),
        extra_env: vec![("PAM_FAKE_HEALTH_DELAY_MS".into(), "300".into())],
        ..ServerOptions::default()
    };
    let loaded = server.load("fake/model", model, &options).await.unwrap();
    assert_eq!(loaded.id, "fake/model");
    assert_eq!(loaded.build_info, "bfake-000");
    assert_eq!(loaded.context_length, 4096);
    assert!(loaded.pid > 0);
    let Some(Endpoint::Loopback(port)) = server.endpoint() else {
        panic!("a loopback endpoint was chosen: {:?}", server.endpoint());
    };
    assert!(port > 0);
    assert!(!server.socket().exists(), "no socket file in loopback mode");
    // Without the bearer key the server that `load` trusts refuses.
    let refused = engine_http::request(
        &Endpoint::Loopback(port),
        "GET",
        "/props",
        "not-the-key",
        None,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(refused.status, 401);
    // Generation goes over the same port with the key the supervisor holds.
    let (_keep, cancel) = tokio::sync::watch::channel(false);
    let result = server
        .generate(
            &request("one two three", 16),
            cancel,
            4096,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one two three");
    server.unload().await;
    assert!(server.model().is_none());
    assert!(server.endpoint().is_none());

    // A healthy server on the probed port that reports another model is a
    // stranger: refused and stopped, nothing trusted.
    let squatter = ServerOptions {
        load_timeout: Duration::from_secs(60),
        extra_env: vec![("PAM_FAKE_MODEL_PATH".into(), "/models/other.gguf".into())],
        ..ServerOptions::default()
    };
    let refused = server
        .load("fake/model", model, &squatter)
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, EngineServerError::Spawn(detail) if detail.contains("reports model")),
        "{refused:?}"
    );
    assert!(server.model().is_none());
    assert!(server.endpoint().is_none());
}
