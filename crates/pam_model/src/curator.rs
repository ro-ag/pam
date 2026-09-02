//! The curator tier: the vendor agent CLIs already installed on the machine.
//!
//! PAM holds no API keys. When a job wants a frontier model rather than the
//! local weights, it borrows one the human is already paying for by running
//! their own `claude`, `codex`, `copilot` or `gemini` binary the way a shell
//! script would — one turn, no tools, no session left behind. That is the
//! whole tier: [`detect`] finds what is installed, [`invoke`] asks it one
//! question.
//!
//! # What "non-interactive" has to mean
//!
//! These CLIs are agents. Run carelessly they will read files, run commands
//! and write session state, none of which PAM asked for. So every
//! invocation is pinned three ways: the working directory is a fresh empty
//! temp dir that dies with the call, `PATH` is narrowed to the agent's own
//! directory plus the daemon's, and the flags that disable tools and
//! session persistence are mandatory rather than nice to have
//! ([`invoke_args`] is the single place they live). Output is read into
//! bounded buffers ([`INVOKE_MAX_OUTPUT`]) because a runaway agent printing
//! forever must cost memory that is capped, not memory that is available.
//!
//! # The invocation forms
//!
//! Flags were read off `--help` and exercised against the binaries
//! installed on the owner's machine on 2026-09-01. A CLI that later drops
//! or renames one of them fails visibly — its own stderr comes back inside
//! [`CuratorError::Failed`] — rather than silently starting an interactive
//! session that never returns.
//!
//! | agent | form | status |
//! | --- | --- | --- |
//! | `claude` | `--print --output-format text --no-session-persistence --permission-mode plan --tools ""`, prompt on stdin | verified against 2.1.220 |
//! | `codex` | `exec --skip-git-repo-check --ephemeral --sandbox read-only --color never`, prompt on stdin | verified against codex-cli 0.151.0 |
//! | `copilot` | `-p <prompt> --silent --no-color --output-format text --available-tools=` | verified against 1.0.82 |
//! | `gemini` | `--prompt <prompt>` | **unverified** — not installed on the reference machine; taken from the CLI's README |
//!
//! Notes on the ones that surprised us:
//!
//! - `claude` 2.1.220 has no `--max-turns`. The spec's draft named it; the
//!   installed CLI does not list it under `--help`, so passing it would be
//!   an immediate parse error. `--print` is already single-turn, and
//!   `--permission-mode plan` plus `--tools ""` is what actually keeps the
//!   session from touching the machine.
//! - `codex exec` reads the prompt from stdin when no `PROMPT` argument is
//!   given, and a bare `-` is only an alias for that. It writes its banner,
//!   the transcript and the token count to **stderr**; stdout carries the
//!   final assistant message and nothing else, so `-o <file>` buys nothing
//!   and is left out.
//! - `copilot` refuses `--deny-tool '*'` (`Invalid rule format: *`) — that
//!   flag takes `kind(argument)` patterns, not globs. The filter that
//!   actually empties the model's toolbox is `--available-tools=`, passed
//!   as one argument with an empty value.
//! - `claude` reports an expired login on **stdout** with exit 1 and an
//!   empty stderr, which is why [`invoke`] falls back to the stdout tail
//!   for the failure detail when stderr is empty: the human needs to read
//!   "OAuth session expired", not "exited with 1: ".
//!
//! # Blocking
//!
//! [`detect`] is synchronous — it stats directories and waits on
//! `--version` — so async callers wrap it in `spawn_blocking`. [`invoke`]
//! is async and drives the child with `tokio::process`.

use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Hard cap on how much of a child's stdout (and, separately, stderr) is
/// kept: 256 KiB.
///
/// The rest is drained and dropped rather than left in the pipe — a full
/// pipe would wedge the child until the deadline, turning a chatty agent
/// into a timeout instead of an answer.
pub const INVOKE_MAX_OUTPUT: usize = 256 * 1024;

/// How much of the failing child's error output rides along in
/// [`CuratorError::Failed`].
///
/// The tail, not the head: CLIs print their banner first and their
/// complaint last.
const FAILURE_DETAIL_BYTES: usize = 1024;

/// Read buffer for draining a child pipe. Heap-allocated per call rather
/// than a stack array: [`invoke`] holds two of these across an `await`, and
/// a future that carries 16 KiB of buffer is a future every caller pays to
/// move.
const PIPE_CHUNK_BYTES: usize = 8192;

/// How often [`detect`] looks in on a `--version` child while waiting for
/// it.
const VERSION_POLL: Duration = Duration::from_millis(10);

/// Cap on the bytes read from a `--version` child. Every one of these
/// prints a line or two; anything past this is not a version string.
const VERSION_MAX_OUTPUT: u64 = 4096;

/// One of the four vendor agent CLIs PAM knows how to borrow.
///
/// The list is closed on purpose. Each entry carries a hand-checked
/// non-interactive invocation ([`invoke_args`]); an agent PAM cannot
/// invoke safely is an agent PAM does not offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentId {
    /// Anthropic's Claude Code.
    Claude,
    /// The Codex CLI from `OpenAI`.
    Codex,
    /// GitHub Copilot CLI.
    Copilot,
    /// Google's Gemini CLI.
    Gemini,
}

impl AgentId {
    /// Every agent, in detection order.
    pub const ALL: [AgentId; 4] = [
        AgentId::Claude,
        AgentId::Codex,
        AgentId::Copilot,
        AgentId::Gemini,
    ];

    /// The wire name: what the setting `curator.agent` stores and what the
    /// GUI radio list sends back.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AgentId::Claude => "claude",
            AgentId::Codex => "codex",
            AgentId::Copilot => "copilot",
            AgentId::Gemini => "gemini",
        }
    }

    /// The inverse of [`as_str`](Self::as_str). Unknown names are `None`
    /// rather than an error — a stored setting from a newer PAM is a thing
    /// to ignore, not to crash on.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        AgentId::ALL.into_iter().find(|id| id.as_str() == s)
    }

    /// The executable's stem on `PATH`.
    ///
    /// Windows spells the same thing four ways, so detection probes this
    /// name plus `.exe`, `.cmd` and `.bat`; the stem alone is only
    /// executable on Unix.
    #[must_use]
    pub fn binary_name(self) -> &'static str {
        self.as_str()
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An agent CLI found on `PATH`.
///
/// `path` is canonicalized, so the record survives a `PATH` change and
/// names the binary that will actually run. `version` is `None` when the
/// CLI is there but would not say what it is — old build, wrapper script,
/// or a `--version` that hung past the deadline. That is worth showing as
/// a blank version rather than hiding the agent.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentCli {
    /// Which agent this is.
    pub id: AgentId,
    /// Canonical path to the executable.
    pub path: PathBuf,
    /// First line of `<cli> --version`, trimmed.
    pub version: Option<String>,
}

/// Everything that can go wrong asking an agent a question.
///
/// There is no "not installed" variant: an agent that is not installed
/// never becomes an [`AgentCli`], so [`invoke`] cannot be called with one.
/// The daemon turns each of these into a refusal triple; the strings here
/// are the `detail` half.
#[derive(Debug, thiserror::Error)]
pub enum CuratorError {
    /// The CLI ran and exited non-zero. Carries its exit code and the tail
    /// of what it complained about.
    #[error("{0} exited with {1}: {2}")]
    Failed(AgentId, i32, String),
    /// The CLI was still running when the deadline passed; it has been
    /// killed.
    #[error("{0} produced no output within {1:?}")]
    Timeout(AgentId, Duration),
    /// The child could not be spawned, or its pipes could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Find the vendor agent CLIs on the given `PATH`.
///
/// `path_env` is passed in rather than read from the environment so the
/// caller — the daemon, which knows what environment it wants agents to
/// see — decides, and so tests can point detection at a directory they
/// control.
///
/// A candidate has to be a regular file (a directory named `codex` is not
/// a CLI) and executable (on Unix, some `x` bit; on Windows, one of the
/// executable extensions). The first match wins per agent, the way a shell
/// would resolve it. Each survivor is asked `--version` under
/// `version_deadline`; a CLI that misses the deadline is killed and
/// reported with `version: None` rather than dropped.
///
/// Blocking: stats the filesystem and waits on child processes.
#[must_use]
pub fn detect(path_env: &OsStr, version_deadline: Duration) -> Vec<AgentCli> {
    let dirs: Vec<PathBuf> = std::env::split_paths(path_env)
        .filter(|dir| !dir.as_os_str().is_empty())
        .collect();

    let mut found = Vec::new();
    for id in AgentId::ALL {
        if let Some(path) = locate(&dirs, id) {
            let version = probe_version(&path, version_deadline);
            found.push(AgentCli { id, path, version });
        }
    }
    found
}

/// The argument vector for one non-interactive, tool-free, single-turn
/// question, and whether the prompt goes on stdin.
///
/// `true` means the returned arguments do **not** contain the prompt and
/// [`invoke`] must pipe it; `false` means the prompt is already in there as
/// an argument. Splitting it this way keeps the per-CLI knowledge in one
/// table that a test can read back, instead of scattering it through the
/// spawn code.
///
/// See the module docs for where each form comes from and which one is
/// still unverified.
#[must_use]
pub fn invoke_args(id: AgentId, prompt: &str) -> (Vec<String>, bool) {
    let owned = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    match id {
        AgentId::Claude => (
            owned(&[
                "--print",
                "--output-format",
                "text",
                "--no-session-persistence",
                "--permission-mode",
                "plan",
                "--tools",
                "",
            ]),
            true,
        ),
        AgentId::Codex => (
            owned(&[
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--sandbox",
                "read-only",
                "--color",
                "never",
            ]),
            true,
        ),
        AgentId::Copilot => (
            vec![
                "-p".to_owned(),
                prompt.to_owned(),
                "--silent".to_owned(),
                "--no-color".to_owned(),
                "--output-format".to_owned(),
                "text".to_owned(),
                "--available-tools=".to_owned(),
            ],
            false,
        ),
        AgentId::Gemini => (vec!["--prompt".to_owned(), prompt.to_owned()], false),
    }
}

/// Ask an agent one question and return what it said.
///
/// The child runs in a fresh empty temp directory that is removed when the
/// call ends, with `PATH` pinned to the agent's own directory followed by
/// the daemon's — enough for the CLI to find its own helpers, not enough
/// for it to inherit a surprise. stdout and stderr are drained
/// concurrently with the stdin write, so neither a large prompt nor a
/// chatty agent can deadlock the call.
///
/// The answer is stdout, trimmed. A non-zero exit is
/// [`CuratorError::Failed`] carrying the tail of stderr — or of stdout,
/// when stderr is empty, because at least one of these CLIs reports its
/// login trouble there. Missing the deadline kills the child and is
/// [`CuratorError::Timeout`].
pub async fn invoke(
    cli: &AgentCli,
    prompt: &str,
    deadline: Duration,
) -> Result<String, CuratorError> {
    let workdir = tempfile::Builder::new().prefix("pam-curator-").tempdir()?;
    let (args, prompt_on_stdin) = invoke_args(cli.id, prompt);

    let mut command = tokio::process::Command::new(&cli.path);
    command
        .args(&args)
        .current_dir(workdir.path())
        .env("PATH", pinned_path(&cli.path))
        .stdin(if prompt_on_stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().ok_or_else(|| missing_pipe("stdout"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| missing_pipe("stderr"))?;

    let bytes = prompt.as_bytes();
    let run = async {
        let feed = async {
            // `take` rather than a borrow: dropping the handle closes the
            // pipe, and a CLI reading to EOF waits for exactly that.
            if let Some(mut handle) = stdin.take() {
                handle.write_all(bytes).await?;
                handle.shutdown().await?;
            }
            Ok::<(), std::io::Error>(())
        };
        let (written, out, err) = tokio::join!(feed, drain(&mut stdout), drain(&mut stderr));
        written?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status, out?, err?))
    };
    let finished = tokio::time::timeout(deadline, run).await;

    let (status, out, err) = match finished {
        // `kill_on_drop` would do this at the end of the call anyway; doing
        // it here means the process is gone before the caller sees the error.
        Err(_elapsed) => {
            let _ = child.kill().await;
            return Err(CuratorError::Timeout(cli.id, deadline));
        }
        Ok(result) => result?,
    };

    if status.success() {
        return Ok(String::from_utf8_lossy(&out).trim().to_owned());
    }
    let mut detail = tail(&err);
    if detail.is_empty() {
        detail = tail(&out);
    }
    Err(CuratorError::Failed(
        cli.id,
        status.code().unwrap_or(-1),
        detail,
    ))
}

/// First candidate for `id` on `dirs`, canonicalized — shell resolution
/// order, minus the shell.
fn locate(dirs: &[PathBuf], id: AgentId) -> Option<PathBuf> {
    for dir in dirs {
        for name in candidate_names(id) {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return candidate.canonicalize().ok();
            }
        }
    }
    None
}

/// File names that would run `id` on this platform, in the order the
/// platform prefers them.
#[cfg(windows)]
fn candidate_names(id: AgentId) -> Vec<String> {
    let stem = id.binary_name();
    vec![
        format!("{stem}.exe"),
        format!("{stem}.cmd"),
        format!("{stem}.bat"),
    ]
}

/// File names that would run `id` on this platform.
#[cfg(not(windows))]
fn candidate_names(id: AgentId) -> Vec<String> {
    vec![id.binary_name().to_owned()]
}

/// Whether `path` is something the OS would actually execute.
///
/// Metadata follows symlinks on purpose: `~/.local/bin/claude` is very
/// often a link into a version directory.
#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Whether `path` is something the OS would actually execute. On Windows
/// the extension is the permission, and [`candidate_names`] has already
/// applied it.
#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

/// Run `<path> --version` under a deadline and keep the first line.
///
/// Anything short of a clean exit with a non-empty first line is `None`:
/// the version is decoration, and a CLI that will not report one is still
/// a CLI PAM can call.
fn probe_version(path: &Path, deadline: Duration) -> Option<String> {
    let mut child = std::process::Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => return None,
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(VERSION_POLL);
    };
    if !status.success() {
        return None;
    }

    let mut text = String::new();
    child
        .stdout
        .take()?
        .take(VERSION_MAX_OUTPUT)
        .read_to_string(&mut text)
        .ok()?;
    let first = text.lines().next()?.trim();
    if first.is_empty() {
        None
    } else {
        Some(first.to_owned())
    }
}

/// `PATH` for a curator child: the agent's own directory first, then
/// whatever the daemon inherited.
///
/// The agent's directory has to be there — several of these CLIs shell out
/// to siblings installed next to them — and the daemon's `PATH` has to be
/// there because that is where `git`, `node` and the platform's own tools
/// live. Nothing beyond those two is added.
fn pinned_path(binary: &Path) -> std::ffi::OsString {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(parent) = binary.parent() {
        dirs.push(parent.to_path_buf());
    }
    if let Some(inherited) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&inherited));
    }
    std::env::join_paths(dirs).unwrap_or_else(|_| {
        binary
            .parent()
            .map(Path::as_os_str)
            .unwrap_or_default()
            .to_os_string()
    })
}

/// Read a child pipe to EOF, keeping at most [`INVOKE_MAX_OUTPUT`] bytes.
///
/// Reading past the cap and throwing the excess away is deliberate: the
/// alternative is to stop reading, which fills the pipe and blocks the
/// child until the deadline.
async fn drain<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut kept: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; PIPE_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(kept);
        }
        if kept.len() < INVOKE_MAX_OUTPUT {
            let room = INVOKE_MAX_OUTPUT - kept.len();
            kept.extend_from_slice(&chunk[..read.min(room)]);
        }
    }
}

/// Last [`FAILURE_DETAIL_BYTES`] of a child's output, as trimmed lossy
/// UTF-8.
fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(FAILURE_DETAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).trim().to_owned()
}

/// A piped stdio handle that `tokio` did not hand back. Not reachable in
/// practice; it exists so the spawn path has no `unwrap`.
fn missing_pipe(which: &str) -> std::io::Error {
    std::io::Error::other(format!("child {which} pipe was not captured"))
}
