//! A stand-in for `llama-server` used by the engine supervisor tests.
//!
//! Accepts the supervisor's argument vector (`-m`, `--host`, `--api-key`,
//! `-c`, …), listens on the Unix socket `--host` names, and answers the
//! handful of routes the supervisor uses with deterministic JSON:
//! `/health`, `/props`, `/apply-template`, `/tokenize`,
//! `/v1/chat/completions`. `PAM_FAKE_HEALTH_DELAY_MS` delays readiness;
//! `PAM_FAKE_EXIT_EARLY=1` exits at once, like a crashed server;
//! `PAM_FAKE_MODEL_PATH` makes `/props` report that path instead of `-m`,
//! like a stranger squatting the endpoint.
#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "a deliberately flat test double; counts are tiny"
)]

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let args: Vec<String> = std::env::args().collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let socket = value("--host").expect("--host <socket>");
    let api_key = value("--api-key").unwrap_or_default();
    let model = std::env::var("PAM_FAKE_MODEL_PATH")
        .ok()
        .or_else(|| value("-m"))
        .unwrap_or_default();
    let ctx = value("-c").unwrap_or_else(|| "0".into());
    if std::env::var_os("PAM_FAKE_EXIT_EARLY").is_some() {
        eprintln!("fake llama-server: exiting early as instructed");
        std::process::exit(3);
    }
    let delay: u64 = std::env::var("PAM_FAKE_HEALTH_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind fake socket");
    let ready_at = std::time::Instant::now() + std::time::Duration::from_millis(delay);
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let mut raw = Vec::new();
        let mut buf = vec![0_u8; 8192];
        let (head_end, body_len) = loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break (raw.len(), 0);
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..pos]).to_string();
                let len = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                break (pos + 4, len);
            }
        };
        while raw.len() < head_end + body_len {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        let head = String::from_utf8_lossy(&raw[..head_end.min(raw.len())]).to_string();
        let path = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let body = raw
            .get(head_end..head_end + body_len)
            .unwrap_or(&[])
            .to_vec();
        let authorized = api_key.is_empty()
            || head
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("Authorization: Bearer {api_key}")));
        let (status, reply) = if path == "/health" {
            if std::time::Instant::now() < ready_at {
                (503, r#"{"error":{"code":503,"message":"Loading model","type":"unavailable_error"}}"#.to_string())
            } else {
                (200, r#"{"status":"ok"}"#.to_string())
            }
        } else if !authorized {
            (401, r#"{"error":{"code":401,"message":"Invalid API Key","type":"authentication_error"}}"#.to_string())
        } else if path == "/props" {
            (
                200,
                format!(
                    r#"{{"model_path":"{model}","build_info":"bfake-000","total_slots":1,"default_generation_settings":{{"n_ctx":{ctx}}}}}"#
                ),
            )
        } else if path == "/apply-template" {
            let messages: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let mut prompt = String::new();
            for m in messages["messages"].as_array().cloned().unwrap_or_default() {
                prompt.push_str(m["role"].as_str().unwrap_or(""));
                prompt.push(':');
                prompt.push_str(m["content"].as_str().unwrap_or(""));
                prompt.push('\n');
            }
            (200, serde_json::json!({"prompt": prompt}).to_string())
        } else if path == "/tokenize" {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let tokens: Vec<u32> = v["content"]
                .as_str()
                .unwrap_or("")
                .split_whitespace()
                .enumerate()
                .map(|(i, _)| i as u32)
                .collect();
            (200, serde_json::json!({"tokens": tokens}).to_string())
        } else if path == "/v1/chat/completions" {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let last = v["messages"]
                .as_array()
                .and_then(|m| m.last())
                .and_then(|m| m["content"].as_str())
                .unwrap_or("")
                .to_string();
            let max = v["max_tokens"].as_u64().unwrap_or(16);
            let words: Vec<&str> = last.split_whitespace().collect();
            let prompt_n = words.len() as u64 + 3;
            let text = format!(
                "echo: {}",
                words
                    .iter()
                    .take(max as usize)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let finish = if (words.len() as u64) > max {
                "length"
            } else {
                "stop"
            };
            let completion_n = words.len().min(max as usize) as u64 + 1;
            (200, serde_json::json!({
                "choices":[{"index":0,"finish_reason":finish,"message":{"role":"assistant","content":text}}],
                "usage":{"prompt_tokens":prompt_n,"completion_tokens":completion_n,"total_tokens":prompt_n+completion_n},
                "timings":{"prompt_ms":12.5,"predicted_ms":30.0,"predicted_per_second":33.3}
            }).to_string())
        } else {
            (404, r#"{"error":"no route"}"#.to_string())
        };
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("the fake llama-server needs Unix sockets");
    std::process::exit(2);
}
