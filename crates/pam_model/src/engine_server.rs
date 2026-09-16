//! Supervises one `llama-server` process: the pinned engine binary, one
//! loaded model, a private Unix socket, and bounded generation over it.
//!
//! The server is spawned with a scrubbed environment, an API key only PAM
//! knows, no web UI, the GGUF's own chat template (`--jinja`), thinking
//! disabled by budget, and the context size from the admission envelope.
//! PAM talks to it with [`crate::engine_http`]; a cancel drops the
//! connection, which stops decoding on the server side. Unloading kills
//! the process. Nothing here downloads or verifies the engine — that is
//! [`crate::engine`].

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::engine_http::{self, Endpoint, HttpError, HttpReply};
use crate::runtime::GenerateRequest;

/// The longest a Unix socket path may be on macOS (`sun_path`).
pub const MAX_SOCKET_PATH_BYTES: usize = 104;

/// How the server is started for one model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOptions {
    /// `-c`: the prompt context in tokens; the admission envelope.
    pub context_tokens: usize,
    /// `-t`: CPU threads for generation; `None` keeps the server default.
    pub threads: Option<usize>,
    /// `-ngl`: layers offloaded to the GPU; `None` keeps the server default
    /// (everything that fits on Metal, nothing on a CPU-only build).
    pub gpu_layers: Option<u32>,
    /// `--reasoning-budget`: 0 disables thinking for bounded tasks.
    pub reasoning_budget: i64,
    /// How long the server may take to report healthy after spawn.
    pub load_timeout: Duration,
    /// Extra environment for the server process (the fake server's test
    /// knobs); production leaves it empty and the child sees nothing else.
    pub extra_env: Vec<(String, String)>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            context_tokens: 8192,
            threads: None,
            gpu_layers: None,
            reasoning_budget: 0,
            load_timeout: Duration::from_secs(180),
            extra_env: Vec::new(),
        }
    }
}

/// The model the running server holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineModel {
    /// Registry id of the model.
    pub id: String,
    /// The GGUF the server loaded.
    pub path: PathBuf,
    /// The context the server was started with.
    pub context_length: usize,
    /// `build_info` from `/props`, e.g. `b10938-f1e44dcc1`.
    pub build_info: String,
    /// Unix milliseconds when the server reported healthy.
    pub loaded_at_ms: i64,
    /// Operating-system process id of the server.
    pub pid: u32,
}

/// One bounded completion the server produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineResult {
    /// The assistant text.
    pub text: String,
    /// Prompt tokens the server counted (chat template included).
    pub prompt_tokens: usize,
    /// Tokens generated.
    pub completion_tokens: usize,
    /// Prompt processing time the server reported.
    pub prompt_ms: f64,
    /// Decoding time the server reported.
    pub predicted_ms: f64,
    /// `stop` or `length`.
    pub finish_reason: String,
}

/// Why the supervisor refused or failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineServerError {
    /// The engine binary is not at the path the supervisor was given.
    #[error("engine binary missing at {0}")]
    BinaryMissing(PathBuf),
    /// The socket path is too long or its directory is unusable.
    #[error("engine socket path invalid: {0}")]
    SocketPath(String),
    /// The server process could not start.
    #[error("engine could not start: {0}")]
    Spawn(String),
    /// The server exited before it reported healthy.
    #[error("engine exited during load ({status}): {log_tail}")]
    Crashed {
        /// The exit status text.
        status: String,
        /// The end of the server log.
        log_tail: String,
    },
    /// The server did not report healthy within the load timeout.
    #[error("engine did not become healthy within {0:?}")]
    LoadTimeout(Duration),
    /// No model is loaded.
    #[error("no model is loaded in the engine")]
    NoModelLoaded,
    /// Transport failure talking to the server.
    #[error("engine transport: {0}")]
    Http(#[from] HttpError),
    /// The server answered with an error status.
    #[error("engine answered HTTP {status}: {detail}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Body excerpt.
        detail: String,
    },
    /// The framed prompt exceeds the caller's input limit.
    #[error("prompt is {tokens} tokens; the limit is {limit}")]
    InputTooLong {
        /// Tokens the server counted.
        tokens: usize,
        /// The caller's limit.
        limit: usize,
    },
    /// The caller cancelled.
    #[error("generation cancelled")]
    Cancelled,
    /// The server's JSON did not have the expected shape.
    #[error("engine reply malformed: {0}")]
    Malformed(String),
}

struct Live {
    child: tokio::process::Child,
    api_key: String,
    model: EngineModel,
    /// The reasoning budget the server was started with; 0 also switches
    /// thinking off through the chat template for models that gate it there.
    reasoning_budget: i64,
}

/// One supervised `llama-server`.
pub struct EngineServer {
    binary: PathBuf,
    socket: PathBuf,
    log: PathBuf,
    live: Arc<Mutex<Option<Live>>>,
    /// The endpoint the running server was started on.
    endpoint: Mutex<Option<Endpoint>>,
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "the live child handle is summarised as the loaded model id"
)]
impl std::fmt::Debug for EngineServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineServer")
            .field("binary", &self.binary)
            .field("socket", &self.socket)
            .field("log", &self.log)
            .field("loaded", &self.model().map(|m| m.id))
            .finish()
    }
}

impl EngineServer {
    /// A supervisor for `binary`, listening on `run_dir/engine.sock` and
    /// logging to `log_dir/llama-server.log`.
    pub fn new(binary: PathBuf, run_dir: &Path, log_dir: &Path) -> Result<Self, EngineServerError> {
        let socket = run_dir.join("engine.sock");
        if socket.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
            return Err(EngineServerError::SocketPath(format!(
                "{} exceeds {MAX_SOCKET_PATH_BYTES} bytes",
                socket.display()
            )));
        }
        Ok(Self {
            binary,
            socket,
            log: log_dir.join("llama-server.log"),
            live: Arc::new(Mutex::new(None)),
            endpoint: Mutex::new(None),
        })
    }

    /// The socket the server listens on (Unix hosts).
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The server binary this supervisor spawns.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// The endpoint the running server listens on, if one runs.
    #[must_use]
    pub fn endpoint(&self) -> Option<Endpoint> {
        self.endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Picks the endpoint for a new server: the private Unix socket where
    /// the platform has them, otherwise a free loopback port.
    fn choose_endpoint(&self) -> Result<Endpoint, EngineServerError> {
        if cfg!(unix) {
            return Ok(Endpoint::Unix(self.socket.clone()));
        }
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| EngineServerError::SocketPath(format!("no free loopback port: {e}")))?;
        let port = probe
            .local_addr()
            .map_err(|e| EngineServerError::SocketPath(e.to_string()))?
            .port();
        drop(probe);
        Ok(Endpoint::Loopback(port))
    }

    /// The loaded model, if any.
    #[must_use]
    pub fn model(&self) -> Option<EngineModel> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|live| live.model.clone())
    }

    /// The argument vector one load would spawn the server with.
    #[must_use]
    pub fn launch_args(
        &self,
        model_path: &Path,
        endpoint: &Endpoint,
        options: &ServerOptions,
    ) -> Vec<String> {
        let mut args = vec![
            "-m".to_owned(),
            model_path.to_string_lossy().into_owned(),
            "--host".to_owned(),
            endpoint.host_arg(),
        ];
        if let Some(port) = endpoint.port_arg() {
            args.push("--port".to_owned());
            args.push(port);
        }
        args.extend([
            "--no-webui".to_owned(),
            "--jinja".to_owned(),
            "-np".to_owned(),
            "1".to_owned(),
            "-c".to_owned(),
            options.context_tokens.to_string(),
            "--reasoning-budget".to_owned(),
            options.reasoning_budget.to_string(),
            "--log-file".to_owned(),
            self.log.to_string_lossy().into_owned(),
        ]);
        if let Some(threads) = options.threads {
            args.push("-t".to_owned());
            args.push(threads.to_string());
        }
        if let Some(layers) = options.gpu_layers {
            args.push("-ngl".to_owned());
            args.push(layers.to_string());
        }
        args
    }

    /// Starts the server on `model_path` and waits for it to report
    /// healthy. An already loaded model is unloaded first.
    pub async fn load(
        &self,
        model_id: &str,
        model_path: &Path,
        options: &ServerOptions,
    ) -> Result<EngineModel, EngineServerError> {
        if !self.binary.is_file() {
            return Err(EngineServerError::BinaryMissing(self.binary.clone()));
        }
        self.unload().await;
        if let Some(dir) = self.socket.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| EngineServerError::SocketPath(format!("{}: {e}", dir.display())))?;
        }
        let _ = std::fs::remove_file(&self.socket);
        let endpoint = self.choose_endpoint()?;
        let api_key = fresh_api_key(model_path)?;
        let mut child = self.spawn(model_path, &endpoint, options, &api_key)?;
        let pid = child.id().unwrap_or_default();
        let deadline = Instant::now() + options.load_timeout;
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(EngineServerError::Crashed {
                    status: status.to_string(),
                    log_tail: log_tail(&self.log),
                });
            }
            if Instant::now() >= deadline {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let _ = std::fs::remove_file(&self.socket);
                return Err(EngineServerError::LoadTimeout(options.load_timeout));
            }
            if matches!(endpoint, Endpoint::Loopback(_)) || self.socket.exists() {
                let health = engine_http::request(
                    &endpoint,
                    "GET",
                    "/health",
                    &api_key,
                    None,
                    Duration::from_secs(2),
                )
                .await;
                if let Ok(reply) = health
                    && reply.status == 200
                    && serde_json::from_slice::<serde_json::Value>(&reply.body)
                        .is_ok_and(|v| v["status"] == "ok")
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let props = engine_http::request(
            &endpoint,
            "GET",
            "/props",
            &api_key,
            None,
            Duration::from_secs(10),
        )
        .await
        .ok()
        .and_then(|reply| serde_json::from_slice::<serde_json::Value>(&reply.body).ok());
        // Health alone does not prove the peer is our child: on a loopback
        // port the number was probed and released before the spawn, and
        // another local process could have taken it in between — in which
        // case it now holds the bearer key. The server's own `/props`
        // names the model it loaded; anything but our path is a stranger,
        // and the child is stopped rather than trusted.
        let served_path = props.as_ref().and_then(|p| p["model_path"].as_str());
        if served_path != Some(model_path.to_string_lossy().as_ref()) {
            let _ = child.start_kill();
            let _ = child.wait().await;
            let _ = std::fs::remove_file(&self.socket);
            return Err(EngineServerError::Spawn(format!(
                "the server at {} reports model {:?}, not {}; refusing to trust it",
                endpoint.host_arg(),
                served_path.unwrap_or("<none>"),
                model_path.display()
            )));
        }
        let model = EngineModel {
            id: model_id.to_owned(),
            path: model_path.to_path_buf(),
            context_length: options.context_tokens,
            build_info: props
                .as_ref()
                .and_then(|p| p["build_info"].as_str())
                .unwrap_or("unknown")
                .to_owned(),
            loaded_at_ms: now_ms(),
            pid,
        };
        *self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Live {
            child,
            api_key,
            model: model.clone(),
            reasoning_budget: options.reasoning_budget,
        });
        *self
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(endpoint);
        Ok(model)
    }

    fn spawn(
        &self,
        model_path: &Path,
        endpoint: &Endpoint,
        options: &ServerOptions,
        api_key: &str,
    ) -> Result<tokio::process::Child, EngineServerError> {
        let mut args = self.launch_args(model_path, endpoint, options);
        args.push("--api-key".to_owned());
        args.push(api_key.to_owned());
        let mut command = tokio::process::Command::new(&self.binary);
        command
            .args(&args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        if let Some(dir) = self.binary.parent() {
            command.env("LD_LIBRARY_PATH", dir);
        }
        #[cfg(windows)]
        if let Some(root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", root);
        }
        for (name, value) in &options.extra_env {
            command.env(name, value);
        }
        command
            .spawn()
            .map_err(|e| EngineServerError::Spawn(e.to_string()))
    }

    /// Stops the server, if one runs, and removes its socket.
    pub async fn unload(&self) {
        let live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(mut live) = live {
            let _ = live.child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(10), live.child.wait()).await;
        }
        *self
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let _ = std::fs::remove_file(&self.socket);
    }

    /// One bounded chat completion. The framed prompt is counted first and
    /// refused above `input_limit`; `cancel` aborts by closing the
    /// connection; `deadline` bounds the whole exchange.
    pub async fn generate(
        &self,
        request: &GenerateRequest,
        mut cancel: watch::Receiver<bool>,
        input_limit: usize,
        deadline: Duration,
    ) -> Result<EngineResult, EngineServerError> {
        let (api_key, thinking_off) = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|live| (live.api_key.clone(), live.reasoning_budget == 0))
            .ok_or(EngineServerError::NoModelLoaded)?;
        let endpoint = self.endpoint().ok_or(EngineServerError::NoModelLoaded)?;
        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(serde_json::json!({"role": "system", "content": system}));
        }
        messages.push(serde_json::json!({"role": "user", "content": request.prompt}));

        let work = async {
            let framed = self
                .post(
                    &endpoint,
                    &api_key,
                    "/apply-template",
                    &serde_json::json!({"messages": messages}),
                    Duration::from_secs(30),
                )
                .await?;
            let prompt = framed["prompt"]
                .as_str()
                .ok_or_else(|| EngineServerError::Malformed("apply-template has no prompt".into()))?
                .to_owned();
            let counted = self
                .post(
                    &endpoint,
                    &api_key,
                    "/tokenize",
                    &serde_json::json!({"content": prompt, "add_special": true}),
                    Duration::from_secs(30),
                )
                .await?;
            let tokens = counted["tokens"]
                .as_array()
                .map(Vec::len)
                .ok_or_else(|| EngineServerError::Malformed("tokenize has no tokens".into()))?;
            if tokens > input_limit {
                return Err(EngineServerError::InputTooLong {
                    tokens,
                    limit: input_limit,
                });
            }
            let reply = self
                .post(
                    &endpoint,
                    &api_key,
                    "/v1/chat/completions",
                    &serde_json::json!({
                        "messages": messages,
                        "max_tokens": output_budget(request.max_tokens),
                        "temperature": request.temperature,
                        "stop": request.stop,
                        "stream": false,
                        // Bounded tasks are scored on reproducibility: no
                        // prompt-cache reuse and a fixed seed keep two runs
                        // of one request on one server identical.
                        "cache_prompt": false,
                        "seed": 7,
                        // Qwen-style templates gate thinking here; a budget
                        // of 0 alone leaves them emitting an empty answer.
                        "chat_template_kwargs": {"enable_thinking": !thinking_off},
                    }),
                    deadline,
                )
                .await?;
            let choice = reply["choices"]
                .get(0)
                .ok_or_else(|| EngineServerError::Malformed("no choices".into()))?;
            Ok(EngineResult {
                text: choice["message"]["content"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                prompt_tokens: usize::try_from(
                    reply["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
                )
                .unwrap_or(usize::MAX),
                completion_tokens: usize::try_from(
                    reply["usage"]["completion_tokens"].as_u64().unwrap_or(0),
                )
                .unwrap_or(usize::MAX),
                prompt_ms: reply["timings"]["prompt_ms"].as_f64().unwrap_or(0.0),
                predicted_ms: reply["timings"]["predicted_ms"].as_f64().unwrap_or(0.0),
                finish_reason: choice["finish_reason"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_owned(),
            })
        };
        tokio::select! {
            biased;
            () = cancelled(&mut cancel) => Err(EngineServerError::Cancelled),
            result = Box::pin(work) => result,
        }
    }

    async fn post(
        &self,
        endpoint: &Endpoint,
        api_key: &str,
        path: &str,
        body: &serde_json::Value,
        deadline: Duration,
    ) -> Result<serde_json::Value, EngineServerError> {
        let payload = serde_json::to_vec(body)
            .map_err(|e| EngineServerError::Malformed(format!("encode {path}: {e}")))?;
        let HttpReply { status, body } =
            engine_http::request(endpoint, "POST", path, api_key, Some(&payload), deadline).await?;
        if status != 200 {
            return Err(EngineServerError::Server {
                status,
                detail: String::from_utf8_lossy(&body).chars().take(300).collect(),
            });
        }
        serde_json::from_slice(&body)
            .map_err(|e| EngineServerError::Malformed(format!("{path}: {e}")))
    }
}

impl Drop for EngineServer {
    fn drop(&mut self) {
        if let Some(mut live) = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = live.child.start_kill();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// A per-load bearer token. The socket is already private to PAM's user;
/// the key stops any other local process that can reach the path from
/// driving the server, and it never leaves this process.
///
/// Entropy, on every platform without a new dependency: the standard
/// library's `RandomState` keys are seeded per thread from the operating
/// system's CSPRNG (`getrandom` / `BCryptGenRandom` / `getentropy`), and
/// hashing distinct inputs under several fresh states yields independent
/// 64-bit `SipHash` outputs of those secret keys. Four such words (256
/// bits) go into the digest, plus 32 bytes read straight from
/// `/dev/urandom` where the device exists (an exact `read_exact`, never a
/// read to end — the device is endless), plus the pid, the time and the
/// model path so two loads never share a key even under a broken RNG. The
/// result is 64 lowercase hex characters; an empty key is refused.
fn fresh_api_key(model_path: &Path) -> Result<String, EngineServerError> {
    use std::hash::{BuildHasher, RandomState};
    let mut hasher = Sha256::new();
    hasher.update(model_path.to_string_lossy().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
            .to_le_bytes(),
    );
    for round in 0_u64..4 {
        let word = RandomState::new().hash_one((round, model_path));
        hasher.update(word.to_le_bytes());
    }
    let mut entropy = [0_u8; 32];
    if let Ok(mut device) = std::fs::File::open("/dev/urandom") {
        use std::io::Read as _;
        let _ = device.read_exact(&mut entropy);
    }
    hasher.update(entropy);
    let key = format!("{:x}", hasher.finalize());
    if key.len() != 64 || key.bytes().all(|b| b == b'0') {
        return Err(EngineServerError::Spawn(
            "no entropy for the engine API key; refusing to start the server".to_owned(),
        ));
    }
    Ok(key)
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default(),
    )
    .unwrap_or(i64::MAX)
}

/// The last [`LOG_TAIL_BYTES`] of the server log, read by seeking to the
/// end rather than loading a log that may have grown for days.
fn log_tail(log: &Path) -> String {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let Ok(mut file) = std::fs::File::open(log) else {
        return String::new();
    };
    let Ok(len) = file.metadata().map(|meta| meta.len()) else {
        return String::new();
    };
    let start = len.saturating_sub(LOG_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    let _ = file.take(LOG_TAIL_BYTES).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

/// How much of the server log a crash report carries.
const LOG_TAIL_BYTES: u64 = 600;

/// The smallest explicit output budget a generation is given. gpt-oss's
/// harmony template opens an analysis channel before the answer; under
/// about sixteen tokens the parser never closes it and the reply is raw
/// control tokens (`<|channel|>analysis…`). Zero is left alone: it is the
/// engine's own "no explicit cap".
pub const MIN_OUTPUT_TOKENS: usize = 16;

/// `requested`, raised to [`MIN_OUTPUT_TOKENS`] when it is a positive
/// budget below it.
#[must_use]
pub fn output_budget(requested: usize) -> usize {
    if requested == 0 {
        0
    } else {
        requested.max(MIN_OUTPUT_TOKENS)
    }
}

#[cfg(test)]
#[path = "engine_server_test.rs"]
mod tests;
