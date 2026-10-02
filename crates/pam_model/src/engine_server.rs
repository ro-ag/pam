//! Supervises one `llama-server` process: the pinned engine binary, one
//! loaded model, a private Unix socket, and bounded generation over it.
//!
//! The server is spawned with a scrubbed environment, an API key only PAM
//! knows (handed over as a `0600` key file, `--api-key-file`, never on the
//! argument vector where `ps` would show it), no web UI, the GGUF's own chat
//! template (`--jinja`), thinking disabled by budget, and the context size
//! from the admission envelope. PAM talks to it with [`crate::engine_http`];
//! a cancel drops the connection, which stops decoding on the server side.
//! Unloading kills the process. Nothing here downloads or verifies the
//! engine — that is [`crate::engine`].
//!
//! The supervisor does not trust its endpoint or its child blindly. A free
//! loopback port is probed and released before the spawn, so another process
//! can take it first: every health poll re-checks that the child is still
//! alive, a healthy reply is accepted only after the child has survived a
//! short bind grace, the peer must refuse a wrong key and name our model, and
//! a child that exits early on a loopback port is retried on a fresh one. A
//! child that dies later is noticed ([`EngineServer::model`] goes `None`,
//! [`EngineServer::last_exit`] says why, generation reports
//! [`EngineServerError::Exited`]) and the next load starts a new one. A pid
//! file in the private runtime directory lets the next daemon find an engine
//! its predecessor left behind.

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

/// How long a freshly spawned server must have stayed alive before a healthy
/// answer on its endpoint is believed. A server that cannot bind (another
/// process took the port or the socket path first) exits within moments of the
/// spawn; until it has survived this long, the answer may be that other
/// process's.
const BIND_GRACE: Duration = Duration::from_millis(500);

/// How many times a load tries a fresh loopback port after the child died or
/// its endpoint turned out to be someone else's.
const MAX_LOAD_ATTEMPTS: usize = 3;

/// A key that is certainly not the server's, sent once to prove the peer
/// enforces `--api-key-file` before the real key goes anywhere.
const WRONG_KEY_PROBE: &str = "pam-engine-identity-probe-not-the-key";

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
    /// The server process died after it had loaded (killed for memory, crashed,
    /// stopped by hand). Nothing is loaded now; loading the model again starts a
    /// new one.
    #[error("engine exited ({status}); load the model again: {log_tail}")]
    Exited {
        /// The exit status text.
        status: String,
        /// The end of the server log.
        log_tail: String,
    },
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

/// Why a server that had loaded is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineExit {
    /// Registry id of the model it held.
    pub model_id: String,
    /// The exit status text.
    pub status: String,
    /// The end of the server log.
    pub log_tail: String,
    /// Unix milliseconds when the exit was noticed.
    pub noticed_at_ms: i64,
}

/// What the supervisor writes to `engine.pid` after spawning a server, so a later
/// daemon can recognise a server its predecessor left running. The reader must
/// verify the live process against `exe` and `started_ms`/the arguments before
/// treating it as ours: a pid alone is reused by the operating system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginePidRecord {
    /// Operating-system process id of the server.
    pub pid: u32,
    /// The engine binary that was spawned.
    pub exe: PathBuf,
    /// The GGUF it was asked to load (`-m`).
    pub model_path: PathBuf,
    /// Unix milliseconds just before the spawn; a live process that started before
    /// this cannot be the one that was spawned.
    pub spawned_ms: i64,
}

/// Source of loopback ports, for tests that need to know the port in advance.
type PortSource = Arc<dyn Fn() -> Option<u16> + Send + Sync>;

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
    /// Private directory for the key file and the pid file (`<run dir>/engine`).
    runtime: PathBuf,
    log: PathBuf,
    live: Arc<Mutex<Option<Live>>>,
    /// The endpoint the running server was started on.
    endpoint: Mutex<Option<Endpoint>>,
    /// Why the last server that had loaded is gone, until the next load or unload.
    exited: Mutex<Option<EngineExit>>,
    /// Forces loopback endpoints with ports from this source; tests only.
    port_source: Mutex<Option<PortSource>>,
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
            runtime: run_dir.join("engine"),
            log: log_dir.join("llama-server.log"),
            live: Arc::new(Mutex::new(None)),
            endpoint: Mutex::new(None),
            exited: Mutex::new(None),
            port_source: Mutex::new(None),
        })
    }

    /// Makes every load use a loopback endpoint on the port `source` returns instead
    /// of the private socket. Exists so a test can occupy the port the supervisor is
    /// about to pick; production never calls it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_loopback_ports(
        self,
        source: impl Fn() -> Option<u16> + Send + Sync + 'static,
    ) -> Self {
        *self
            .port_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(source));
        self
    }

    /// Where the per-load API key file is written (removed once the server is
    /// healthy, and on every exit path).
    #[must_use]
    pub fn key_file(&self) -> PathBuf {
        self.runtime.join("api.key")
    }

    /// Where the pid record of the running server is kept.
    #[must_use]
    pub fn pid_file(&self) -> PathBuf {
        self.runtime.join("engine.pid")
    }

    /// The pid record a previous supervisor left, if one is there and parses.
    #[must_use]
    pub fn pid_record(&self) -> Option<EnginePidRecord> {
        let bytes = std::fs::read(self.pid_file()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Removes the pid record (the process it named is gone or was never ours).
    pub fn forget_pid_record(&self) {
        let _ = std::fs::remove_file(self.pid_file());
    }

    /// Why the last server that had loaded is gone, when it died on its own.
    /// Cleared by the next load or unload.
    #[must_use]
    pub fn last_exit(&self) -> Option<EngineExit> {
        self.exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
        let source = self
            .port_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(source) = source {
            return source().map(Endpoint::Loopback).ok_or_else(|| {
                EngineServerError::SocketPath("no loopback port to try".to_owned())
            });
        }
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

    /// Notices a server that died on its own: takes it out of service, records why
    /// ([`Self::last_exit`]), and removes its socket and pid file. `None` when the
    /// server is alive, or none runs.
    fn poll_exit(&self) -> Option<EngineExit> {
        let exit = {
            let mut live = self
                .live
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = match live.as_mut()?.child.try_wait() {
                Ok(Some(status)) => status.to_string(),
                Ok(None) => return None,
                Err(error) => format!("status unreadable: {error}"),
            };
            let gone = live.take()?;
            EngineExit {
                model_id: gone.model.id,
                status,
                log_tail: log_tail(&self.log),
                noticed_at_ms: now_ms(),
            }
        };
        *self
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let _ = std::fs::remove_file(&self.socket);
        self.forget_pid_record();
        *self
            .exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(exit.clone());
        Some(exit)
    }

    /// The loaded model, if any. A server found dead is noticed here and reported
    /// as nothing loaded ([`Self::last_exit`] says why).
    #[must_use]
    pub fn model(&self) -> Option<EngineModel> {
        self.poll_exit();
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
    ///
    /// On a loopback endpoint a child that exits early, or an endpoint whose answer
    /// is not ours, is retried on a fresh port (up to `MAX_LOAD_ATTEMPTS`): the
    /// port was probed and released before the spawn, and another process may have
    /// taken it in between.
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
        crate::private::create_private_dir(&self.runtime).map_err(|e| {
            EngineServerError::SocketPath(format!("{}: {e}", self.runtime.display()))
        })?;
        let mut last = None;
        for _ in 0..MAX_LOAD_ATTEMPTS {
            match self.load_once(model_id, model_path, options).await {
                Ok(model) => return Ok(model),
                Err(attempt) if attempt.retry => last = Some(attempt.error),
                Err(attempt) => return Err(attempt.error),
            }
        }
        Err(last.unwrap_or_else(|| EngineServerError::Spawn("no load attempt ran".to_owned())))
    }

    /// One spawn-and-wait. `retry` says whether a fresh endpoint could change the
    /// outcome (the child died early, or the peer was a stranger).
    async fn load_once(
        &self,
        model_id: &str,
        model_path: &Path,
        options: &ServerOptions,
    ) -> Result<EngineModel, LoadAttempt> {
        let _ = std::fs::remove_file(&self.socket);
        let endpoint = self.choose_endpoint()?;
        let retryable = matches!(endpoint, Endpoint::Loopback(_));
        let api_key = fresh_api_key(model_path)?;
        let key_file = self.key_file();
        crate::private::write_private_file(&key_file, format!("{api_key}\n").as_bytes())
            .map_err(|e| EngineServerError::Spawn(format!("write the API key file: {e}")))?;
        // The key file goes away on every path out of here, success included
        // (the server read it at startup; generation uses the key in memory).
        let _key_file = RemoveOnDrop(key_file.clone());
        let spawned_ms = now_ms();
        let mut child = self.spawn(model_path, &endpoint, options, &key_file)?;
        let pid = child.id().unwrap_or_default();
        self.write_pid_record(&EnginePidRecord {
            pid,
            exe: self.binary.clone(),
            model_path: model_path.to_path_buf(),
            spawned_ms,
        });
        let started = Instant::now();
        self.wait_healthy(&mut child, &endpoint, &api_key, options, started, retryable)
            .await?;
        let props = self
            .prove_peer(&mut child, &endpoint, &api_key, model_path, retryable)
            .await?;
        let model = EngineModel {
            id: model_id.to_owned(),
            path: model_path.to_path_buf(),
            context_length: options.context_tokens,
            build_info: props["build_info"].as_str().unwrap_or("unknown").to_owned(),
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
        *self
            .exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(model)
    }

    /// The attempt a child's early exit is.
    fn crashed(&self, status: std::process::ExitStatus, retry: bool) -> LoadAttempt {
        self.abandon_files();
        LoadAttempt {
            error: EngineServerError::Crashed {
                status: status.to_string(),
                log_tail: log_tail(&self.log),
            },
            retry,
        }
    }

    /// Polls until the server reports healthy, the child dies, or the load times out.
    async fn wait_healthy(
        &self,
        child: &mut tokio::process::Child,
        endpoint: &Endpoint,
        api_key: &str,
        options: &ServerOptions,
        started: Instant,
        retryable: bool,
    ) -> Result<(), LoadAttempt> {
        let deadline = started + options.load_timeout;
        loop {
            // Checked on every poll, before the health request: another process
            // answering on the endpoint must never mask a child that has died.
            if let Ok(Some(status)) = child.try_wait() {
                return Err(self.crashed(status, retryable));
            }
            if Instant::now() >= deadline {
                self.abandon(child).await;
                return Err(EngineServerError::LoadTimeout(options.load_timeout).into());
            }
            if (matches!(endpoint, Endpoint::Loopback(_)) || self.socket.exists())
                && self.healthy(endpoint, api_key, started, deadline).await
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Health alone does not prove the peer is our child. The peer must refuse a key it
    /// was not started with (a real server enforces `--api-key-file`; a stranger that
    /// answers everything is caught before the real key goes to it), must name the model
    /// we asked for, and the child must still be alive afterwards: a child that lost the
    /// race for its endpoint is dead by now and the answers were someone else's.
    /// Answers the server's `/props`.
    async fn prove_peer(
        &self,
        child: &mut tokio::process::Child,
        endpoint: &Endpoint,
        api_key: &str,
        model_path: &Path,
        retryable: bool,
    ) -> Result<serde_json::Value, LoadAttempt> {
        let wrong = engine_http::request(
            endpoint,
            "GET",
            "/props",
            WRONG_KEY_PROBE,
            None,
            Duration::from_secs(10),
        )
        .await;
        if wrong.as_ref().is_ok_and(|reply| reply.status < 400) {
            self.abandon(child).await;
            return Err(LoadAttempt {
                error: EngineServerError::Spawn(format!(
                    "the server at {} answered without the API key; refusing to trust it",
                    endpoint.host_arg()
                )),
                retry: retryable,
            });
        }
        let props = engine_http::request(
            endpoint,
            "GET",
            "/props",
            api_key,
            None,
            Duration::from_secs(10),
        )
        .await
        .ok()
        .and_then(|reply| (reply.status == 200).then_some(reply))
        .and_then(|reply| serde_json::from_slice::<serde_json::Value>(&reply.body).ok());
        // The server's own `/props` names the model it loaded; anything but our
        // path is a stranger, and the child is stopped rather than trusted.
        let served_path = props.as_ref().and_then(|p| p["model_path"].as_str());
        if served_path != Some(model_path.to_string_lossy().as_ref()) {
            self.abandon(child).await;
            return Err(LoadAttempt {
                error: EngineServerError::Spawn(format!(
                    "the server at {} reports model {:?}, not {}; refusing to trust it",
                    endpoint.host_arg(),
                    served_path.unwrap_or("<none>"),
                    model_path.display()
                )),
                retry: retryable,
            });
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(self.crashed(status, retryable));
        }
        Ok(props.unwrap_or_default())
    }

    /// One health poll: `true` only for an `ok` answer from a server that has been
    /// alive for the bind grace.
    async fn healthy(
        &self,
        endpoint: &Endpoint,
        api_key: &str,
        started: Instant,
        deadline: Instant,
    ) -> bool {
        let patience =
            Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now()));
        let health =
            engine_http::request(endpoint, "GET", "/health", api_key, None, patience).await;
        let ok = health.is_ok_and(|reply| {
            reply.status == 200
                && serde_json::from_slice::<serde_json::Value>(&reply.body)
                    .is_ok_and(|v| v["status"] == "ok")
        });
        ok && started.elapsed() >= BIND_GRACE
    }

    fn write_pid_record(&self, record: &EnginePidRecord) {
        if let Ok(json) = serde_json::to_vec(record) {
            let _ = crate::private::write_private_file(&self.pid_file(), &json);
        }
    }

    /// Stops a child that is not being trusted and removes what it left.
    async fn abandon(&self, child: &mut tokio::process::Child) {
        let _ = child.start_kill();
        let _ = child.wait().await;
        self.abandon_files();
    }

    fn abandon_files(&self) {
        let _ = std::fs::remove_file(&self.socket);
        self.forget_pid_record();
    }

    fn spawn(
        &self,
        model_path: &Path,
        endpoint: &Endpoint,
        options: &ServerOptions,
        key_file: &Path,
    ) -> Result<tokio::process::Child, EngineServerError> {
        let mut args = self.launch_args(model_path, endpoint, options);
        // The key travels as a file only the daemon's user can read; an argument
        // would show it to every process that can list this one's arguments.
        args.push("--api-key-file".to_owned());
        args.push(key_file.to_string_lossy().into_owned());
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

    /// Stops the server, if one runs, and removes its socket and pid file.
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
        *self
            .exited
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.abandon_files();
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
        // A server that died since the last call is reported as exited, not as a
        // transport failure to a socket nobody listens on.
        self.poll_exit();
        let Some((api_key, thinking_off)) = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|live| (live.api_key.clone(), live.reasoning_budget == 0))
        else {
            return Err(self
                .exited_error()
                .unwrap_or(EngineServerError::NoModelLoaded));
        };
        let endpoint = self.endpoint().ok_or(EngineServerError::NoModelLoaded)?;
        let work = self.complete(
            &endpoint,
            &api_key,
            thinking_off,
            request,
            input_limit,
            deadline,
        );
        let outcome = tokio::select! {
            biased;
            () = cancelled(&mut cancel) => return Err(EngineServerError::Cancelled),
            result = Box::pin(work) => result,
        };
        if matches!(outcome, Err(EngineServerError::Http(_))) {
            // A dead server and a broken connection look the same from here; the
            // process knows which. The exit lands a moment after the socket closes.
            for _ in 0..3 {
                if self.poll_exit().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if let Some(error) = self.exited_error() {
                return Err(error);
            }
        }
        outcome
    }

    /// The three requests of one completion: frame, count, generate.
    async fn complete(
        &self,
        endpoint: &Endpoint,
        api_key: &str,
        thinking_off: bool,
        request: &GenerateRequest,
        input_limit: usize,
        deadline: Duration,
    ) -> Result<EngineResult, EngineServerError> {
        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(serde_json::json!({"role": "system", "content": system}));
        }
        messages.push(serde_json::json!({"role": "user", "content": request.prompt}));
        let framed = self
            .post(
                endpoint,
                api_key,
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
                endpoint,
                api_key,
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
                endpoint,
                api_key,
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
            prompt_tokens: usize::try_from(reply["usage"]["prompt_tokens"].as_u64().unwrap_or(0))
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
    }

    /// [`EngineServerError::Exited`] for the last server that died, if one did.
    fn exited_error(&self) -> Option<EngineServerError> {
        self.last_exit().map(|exit| EngineServerError::Exited {
            status: exit.status,
            log_tail: exit.log_tail,
        })
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

/// A failed load attempt and whether a fresh endpoint could change the outcome.
struct LoadAttempt {
    error: EngineServerError,
    retry: bool,
}

impl From<EngineServerError> for LoadAttempt {
    fn from(error: EngineServerError) -> Self {
        Self {
            error,
            retry: false,
        }
    }
}

/// Removes a file when dropped: the API key file, on every path out of a load.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
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
            // Only a server this supervisor started owns the pid file: one that
            // never loaded must leave a predecessor's record for the reaper.
            self.forget_pid_record();
        }
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(self.key_file());
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
/// driving the server. It reaches the server through a `0600` key file
/// (`--api-key-file`), never the argument vector, and is held in memory by
/// the supervisor for the requests it makes.
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
