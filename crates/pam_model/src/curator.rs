//! The curator tier: the vendor agent CLIs already installed on the machine.
//!
//! PAM holds no API keys; it borrows the human's own `claude`, `codex`,
//! `copilot`, or `gemini` CLI for one turn, no tools, no session left
//! behind. [`detect`] finds what's installed; [`invoke`] asks one question,
//! run in a fresh empty temp dir. Flags disabling tools/session persistence
//! are mandatory, kept in [`invoke_args`]. Output is capped at
//! [`INVOKE_MAX_OUTPUT`] for bounded memory; `gemini`'s form is unverified.
//!
//! The daemon may have been started lazily by an agent, so its `PATH` and
//! environment are agent-influenced and neither is trusted here, the same
//! policy the connector transport applies to `curl`. A CLI is looked up only in
//! [`trusted_dirs`] (system directories, Homebrew prefixes and the user's
//! well-known install directories), and a candidate counts only when it and
//! every directory above it are owned by root or the daemon's user and are not
//! group- or world-writable (sticky shared directories are fine as ancestors).
//! The check runs at detection and again at every [`invoke`]. A CLI that exists only
//! somewhere else on `PATH` is reported as [`UntrustedCli`] and never run. Children
//! get an explicit minimal environment ([`child_env`]) and nothing inherited.
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

/// An agent CLI found in a trusted directory.
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
    /// The executable is no longer in a trusted place (replaced, moved under a
    /// writable directory) since it was detected.
    #[error("{0} is not trusted to run: {1}")]
    Untrusted(AgentId, String),
    /// The child could not be spawned, or its pipes could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A CLI that is on the daemon's `PATH` (or in a known directory) but not somewhere
/// PAM will run it from. Reported so the human learns why it was not offered.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UntrustedCli {
    /// Which agent this is.
    pub id: AgentId,
    /// Where it was found.
    pub path: PathBuf,
    /// Why it is not run, with how to fix it.
    pub reason: String,
}

/// What [`detect`] found: CLIs it will run, and CLIs it refused with the reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Detection {
    /// CLIs in a trusted directory, verified and version-probed.
    pub found: Vec<AgentCli>,
    /// Candidates seen but not trusted; never executed.
    pub untrusted: Vec<UntrustedCli>,
}

/// The directories a vendor CLI may be run from: the operating system's and the
/// package managers' fixed locations, plus the user's well-known install directories
/// under `home` when it is known. The daemon's `PATH` never adds to this list.
#[must_use]
pub fn trusted_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = if cfg!(windows) {
        ["ProgramFiles", "ProgramFiles(x86)"]
            .iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .collect()
    } else {
        [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
            "/home/linuxbrew/.linuxbrew/bin",
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    };
    if let Some(home) = home.filter(|home| home.is_absolute()) {
        if cfg!(windows) {
            dirs.push(home.join("AppData").join("Roaming").join("npm"));
        }
        for relative in [
            ".local/bin",
            ".cargo/bin",
            ".claude/local",
            ".npm-global/bin",
            ".bun/bin",
        ] {
            dirs.push(home.join(relative));
        }
    }
    dirs
}

/// Find the vendor agent CLIs in `trusted` directories.
///
/// `trusted` is passed in (see [`trusted_dirs`]) so the daemon decides what is
/// trusted and tests can point detection at a directory they control. A candidate
/// must be a regular file (a directory named `codex` is not a CLI), executable
/// (Unix: any `x` bit; Windows: a recognized executable extension), and trusted
/// ([`untrusted_reason`]); the first trusted match per agent wins. Each survivor is
/// asked `--version` under `version_deadline` with the minimal [`child_env`] — one
/// that misses it is killed and reported with `version: None`, not dropped.
///
/// `path_env` (the daemon's `PATH`) is only *looked at*, never executed from: an agent
/// with no trusted match whose name is found there, or found in a trusted directory
/// that fails the ownership check, is reported in [`Detection::untrusted`] with the
/// reason, so a refusal can say why instead of "not installed".
///
/// Blocking: stats the filesystem and waits on child processes.
#[must_use]
pub fn detect(trusted: &[PathBuf], path_env: &OsStr, version_deadline: Duration) -> Detection {
    let mut detection = Detection::default();
    let on_path: Vec<PathBuf> = std::env::split_paths(path_env)
        .filter(|dir| !dir.as_os_str().is_empty())
        .collect();
    for id in AgentId::ALL {
        let mut refused: Option<UntrustedCli> = None;
        let mut accepted = None;
        for dir in trusted {
            let Some(candidate) = first_candidate(dir, id) else {
                continue;
            };
            match untrusted_reason(&candidate) {
                None => {
                    accepted = candidate.canonicalize().ok();
                    break;
                }
                Some(reason) => {
                    refused.get_or_insert(UntrustedCli {
                        id,
                        path: candidate,
                        reason,
                    });
                }
            }
        }
        if let Some(path) = accepted {
            let version = probe_version(&path, version_deadline);
            detection.found.push(AgentCli { id, path, version });
            continue;
        }
        if refused.is_none() {
            // Not in any trusted directory: say so if the daemon's PATH has one.
            refused = on_path
                .iter()
                .filter(|dir| !trusted.contains(dir))
                .find_map(|dir| first_candidate(dir, id))
                .map(|path| UntrustedCli {
                    id,
                    path,
                    reason: format!(
                        "it is outside the directories PAM runs CLIs from; install {id} under \
                         /usr/local/bin, a Homebrew prefix or your own ~/.local/bin and try again"
                    ),
                });
        }
        detection.untrusted.extend(refused);
    }
    detection
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
/// call ends, with only the minimal [`child_env`] — nothing of the daemon's
/// environment is inherited, and the executable is re-checked as trusted
/// right before it is spawned. stdout and stderr are drained
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
    // Checked at use, not just at detection: the listing may be minutes old.
    let canonical = cli.path.canonicalize()?;
    if let Some(reason) = untrusted_reason(&canonical) {
        return Err(CuratorError::Untrusted(cli.id, reason));
    }

    let mut command = tokio::process::Command::new(&canonical);
    command
        .args(&args)
        .current_dir(workdir.path())
        .env_clear()
        .envs(child_env(&canonical, workdir.path()))
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

/// The first file in `dir` that would run as `id` (a regular, executable file),
/// not yet canonicalized or trust-checked.
fn first_candidate(dir: &Path, id: AgentId) -> Option<PathBuf> {
    candidate_names(id)
        .into_iter()
        .map(|name| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
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
    let workdir = tempfile::Builder::new()
        .prefix("pam-curator-")
        .tempdir()
        .ok()?;
    let mut child = std::process::Command::new(path)
        .arg("--version")
        .current_dir(workdir.path())
        .env_clear()
        .envs(child_env(path, workdir.path()))
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

/// The whole environment a curator child gets: the user's identity (`HOME`, `USER`,
/// `LOGNAME`, so the CLI finds its own login), a fixed `PATH` (the CLI's own directory,
/// then the system directories), `TMPDIR` pointing at the call's private directory and
/// a fixed `LANG`. Nothing else is inherited: the daemon's variables may have been set
/// by whatever started it.
#[must_use]
pub fn child_env(binary: &Path, workdir: &Path) -> Vec<(String, std::ffi::OsString)> {
    let mut env: Vec<(String, std::ffi::OsString)> = Vec::new();
    for name in ["HOME", "USER", "LOGNAME"] {
        if let Some(value) = std::env::var_os(name).filter(|value| !value.is_empty()) {
            env.push((name.to_owned(), value));
        }
    }
    let mut dirs: Vec<PathBuf> = binary.parent().map(Path::to_path_buf).into_iter().collect();
    if cfg!(windows) {
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.push(root.join("System32"));
            dirs.push(root);
        }
        for name in ["SystemRoot", "ComSpec", "PATHEXT", "USERPROFILE", "APPDATA"] {
            if let Some(value) = std::env::var_os(name) {
                env.push((name.to_owned(), value));
            }
        }
    } else {
        dirs.extend(
            [
                "/usr/bin",
                "/bin",
                "/usr/sbin",
                "/sbin",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            ]
            .iter()
            .map(PathBuf::from),
        );
    }
    env.push((
        "PATH".to_owned(),
        std::env::join_paths(&dirs).unwrap_or_default(),
    ));
    env.push(("TMPDIR".to_owned(), workdir.as_os_str().to_owned()));
    if cfg!(windows) {
        env.push(("TEMP".to_owned(), workdir.as_os_str().to_owned()));
    }
    env.push(("LANG".to_owned(), "en_US.UTF-8".into()));
    env
}

/// Why `candidate` must not be run, or `None` when it may be.
///
/// Unix: the canonical file must be a regular file owned by root or the daemon's
/// user and not group- or world-writable, and every directory above it must be a
/// directory owned by root or that user, not group- or world-writable (a sticky shared
/// directory such as `/tmp` is allowed above the file's own directory, since entries
/// in it are protected from other users). Windows has no ownership model readable
/// without a platform crate, so the fixed directory list is the whole policy there.
#[cfg(unix)]
#[must_use]
pub fn untrusted_reason(candidate: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;
    let Some(owner) = current_uid() else {
        return Some("cannot establish which user the daemon runs as".to_owned());
    };
    let canonical = match candidate.canonicalize() {
        Ok(path) => path,
        Err(error) => return Some(format!("cannot resolve {}: {error}", candidate.display())),
    };
    let Ok(file) = canonical.symlink_metadata() else {
        return Some(format!("cannot stat {}", canonical.display()));
    };
    if !file.is_file() {
        return Some(format!("{} is not a regular file", canonical.display()));
    }
    let owned_by_us_or_root = |uid: u32| uid == 0 || uid == owner;
    if !owned_by_us_or_root(file.uid()) {
        return Some(format!(
            "{} is owned by uid {}, not root or you",
            canonical.display(),
            file.uid()
        ));
    }
    if file.mode() & 0o022 != 0 {
        return Some(format!(
            "{} is writable by group or others; run chmod go-w on it",
            canonical.display()
        ));
    }
    for (depth, dir) in canonical.ancestors().skip(1).enumerate() {
        let Ok(meta) = dir.symlink_metadata() else {
            return Some(format!("cannot stat {}", dir.display()));
        };
        if !meta.is_dir() {
            return Some(format!("{} is not a directory", dir.display()));
        }
        if !owned_by_us_or_root(meta.uid()) {
            return Some(format!(
                "{} is owned by uid {}, not root or you",
                dir.display(),
                meta.uid()
            ));
        }
        let sticky = meta.mode() & 0o1000 != 0;
        if meta.mode() & 0o022 != 0 && !(sticky && depth > 0) {
            return Some(format!(
                "{} is writable by group or others; run chmod go-w on it",
                dir.display()
            ));
        }
    }
    None
}

/// See the Unix version; here the fixed directory list is the policy.
#[cfg(not(unix))]
#[must_use]
pub fn untrusted_reason(candidate: &Path) -> Option<String> {
    candidate
        .canonicalize()
        .err()
        .map(|error| format!("cannot resolve {}: {error}", candidate.display()))
}

/// The user id the daemon runs as: the owner of a file it just created, which needs
/// neither `unsafe` nor the process environment.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    static UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *UID.get_or_init(|| {
        tempfile::tempfile()
            .ok()?
            .metadata()
            .ok()
            .map(|meta| meta.uid())
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
