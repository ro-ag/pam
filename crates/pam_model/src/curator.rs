//! The curator tier: the vendor agent CLIs already installed on the machine.
//!
//! PAM holds no API keys; it borrows the human's own `claude`, `codex`,
//! `copilot`, or `gemini` CLI for one turn, no tools, no session left
//! behind. [`detect`] finds what's installed; [`invoke`] asks one question,
//! run in a fresh empty temp dir with `PATH` narrowed to the agent's own
//! directory plus the daemon's. Flags disabling tools/session persistence
//! are mandatory, kept in [`invoke_args`]. Output is capped at
//! [`INVOKE_MAX_OUTPUT`] for bounded memory; `gemini`'s form is unverified.
//! On Windows a deleted CLI fails through `cmd.exe` as
//! [`CuratorError::Failed`] with its exit 1, not a spawn error.
//! [`detect`] is synchronous (`spawn_blocking`); [`invoke`] is async via
//! `tokio::process`.

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
/// `path_env` is passed in (not read from the environment) so the
/// daemon decides what agents see, and tests can point detection at a
/// directory they control. A candidate must be a regular file (a
/// directory named `codex` is not a CLI) and executable (Unix: any `x`
/// bit; Windows: a recognized executable extension); the first match
/// per agent wins, the way a shell would resolve it. Each survivor is
/// asked `--version` under `version_deadline` — one that misses it is
/// killed and reported with `version: None`, not dropped.
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
/// Verified forms (`claude` 2.1.220, `codex` 0.151.0, `copilot` 1.0.82; `gemini` unverified):
/// `claude` has no `--max-turns` (a parse error) — `--print --permission-mode plan --tools ""`
/// is what keeps it off the machine, and an expired login is reported on stdout with exit 1 and
/// empty stderr, so [`invoke`] falls back to the stdout tail for detail; `codex exec` writes its
/// banner, transcript and token count to stderr and only the final message to stdout, so
/// `-o <file>` buys nothing; `copilot` refuses `--deny-tool '*'` ("Invalid rule format") and
/// `--available-tools=` is the flag that actually empties its toolbox.
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
