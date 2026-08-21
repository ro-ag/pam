use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::{
    io::{self, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::Instant,
};

const DEFAULT_EVALUATOR_DEADLINE: Duration = Duration::from_secs(15);
const MAX_EVALUATOR_DEADLINE: Duration = Duration::from_mins(1);
const DEFAULT_PROMPT_BYTES: usize = 256 * 1024;
const DEFAULT_STREAM_BYTES: usize = 256 * 1024;
const MAX_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(5);
#[cfg(unix)]
static TEMP_WORKSPACE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvaluatorKind {
    Claude,
    Codex,
    CursorAgent,
}

impl EvaluatorKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::CursorAgent => "cursor-agent",
        }
    }

    #[cfg(unix)]
    const fn executable_name(self) -> &'static str {
        self.as_str()
    }

    #[cfg(unix)]
    const fn arguments(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Claude => Some(&[
                "--print",
                "--output-format",
                "text",
                "--safe-mode",
                "--no-session-persistence",
                "--permission-mode",
                "plan",
                "--max-turns",
                "1",
                "--tools",
                "",
            ]),
            // PAM retains these stable enum values for persisted report compatibility, but does
            // not execute these evaluators: their current headless interfaces cannot guarantee a
            // tool-free audit invocation.
            Self::Codex | Self::CursorAgent => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DetectedEvaluator {
    kind: EvaluatorKind,
    executable: PathBuf,
    search_path: OsString,
}

impl DetectedEvaluator {
    #[must_use]
    pub const fn kind(&self) -> EvaluatorKind {
        self.kind
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl fmt::Debug for DetectedEvaluator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectedEvaluator")
            .field("kind", &self.kind)
            .field("executable", &"[REDACTED]")
            .field("search_path", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluatorDetectionError {
    InvalidAuditedProject,
}

impl fmt::Display for EvaluatorDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAuditedProject => {
                formatter.write_str("the audited project directory is unavailable")
            }
        }
    }
}

impl Error for EvaluatorDetectionError {}

/// Detects a supported evaluator using an injected `PATH` value.
///
/// Only absolute, canonical directories and canonical regular executable files are considered.
/// Entries and executable targets inside the audited project are ignored. On Unix, Claude is the
/// only evaluator whose current headless interface provides PAM's required tool-free mode. Other
/// platforms return no evaluator because `std` alone cannot contain the complete descendant tree.
///
/// # Errors
///
/// Returns [`EvaluatorDetectionError::InvalidAuditedProject`] when the audited project cannot be
/// resolved to a canonical directory.
pub fn detect_evaluator(
    injected_path: &OsStr,
    audited_project: &Path,
) -> Result<Option<DetectedEvaluator>, EvaluatorDetectionError> {
    let canonical_project = fs::canonicalize(audited_project)
        .map_err(|_| EvaluatorDetectionError::InvalidAuditedProject)?;
    if !canonical_project.is_dir() {
        return Err(EvaluatorDetectionError::InvalidAuditedProject);
    }

    #[cfg(not(unix))]
    {
        let _ = injected_path;
        return Ok(None);
    }

    #[cfg(unix)]
    {
        let directories = env::split_paths(injected_path)
            .filter(|directory| directory.is_absolute())
            .filter_map(|directory| fs::canonicalize(directory).ok())
            .filter(|directory| directory.is_dir() && !directory.starts_with(&canonical_project))
            // A single entry that cannot be represented in PATH would make join_paths fail for the
            // entire accepted set. Discard it before both detection and execution.
            .filter(|directory| env::join_paths([directory]).is_ok())
            .collect::<Vec<_>>();
        let search_path = env::join_paths(&directories).unwrap_or_default();

        for kind in [EvaluatorKind::Claude] {
            for directory in &directories {
                let candidate = directory.join(kind.executable_name());
                let Ok(executable) = fs::canonicalize(candidate) else {
                    continue;
                };
                if executable.starts_with(&canonical_project) || !is_regular_executable(&executable)
                {
                    continue;
                }
                return Ok(Some(DetectedEvaluator {
                    kind,
                    executable,
                    search_path,
                }));
            }
        }

        Ok(None)
    }
}

#[cfg(unix)]
fn is_regular_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluatorRunConfig {
    deadline: Duration,
    max_prompt_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
}

impl EvaluatorRunConfig {
    /// Creates bounded evaluator-run limits.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluatorRunError::InvalidConfig`] for a zero or excessive deadline, or for
    /// stream bounds above the fixed safety caps.
    pub fn new(
        deadline: Duration,
        max_prompt_bytes: usize,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
    ) -> Result<Self, EvaluatorRunError> {
        if deadline.is_zero()
            || deadline > MAX_EVALUATOR_DEADLINE
            || max_prompt_bytes > MAX_PROMPT_BYTES
            || max_stdout_bytes > MAX_STREAM_BYTES
            || max_stderr_bytes > MAX_STREAM_BYTES
        {
            return Err(EvaluatorRunError::InvalidConfig);
        }
        Ok(Self {
            deadline,
            max_prompt_bytes,
            max_stdout_bytes,
            max_stderr_bytes,
        })
    }

    #[must_use]
    pub const fn deadline(self) -> Duration {
        self.deadline
    }

    #[must_use]
    pub const fn max_prompt_bytes(self) -> usize {
        self.max_prompt_bytes
    }

    #[must_use]
    pub const fn max_stdout_bytes(self) -> usize {
        self.max_stdout_bytes
    }

    #[must_use]
    pub const fn max_stderr_bytes(self) -> usize {
        self.max_stderr_bytes
    }
}

impl Default for EvaluatorRunConfig {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_EVALUATOR_DEADLINE,
            max_prompt_bytes: DEFAULT_PROMPT_BYTES,
            max_stdout_bytes: DEFAULT_STREAM_BYTES,
            max_stderr_bytes: DEFAULT_STREAM_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluatorRunError {
    InvalidConfig,
    UnsupportedEvaluator,
    PromptTooLarge,
    TemporaryWorkspaceUnavailable,
    ProcessSpawn,
    ProcessPipeUnavailable,
    WorkerSpawn,
    WorkerFailure,
    StdinWrite,
    ProcessWait,
    DeadlineExceeded,
    StdoutRead,
    StderrRead,
    StdoutTooLarge,
    StderrTooLarge,
    NonZeroExit,
    InvalidUtf8Stdout,
}

impl fmt::Display for EvaluatorRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "invalid evaluator run limits",
            Self::UnsupportedEvaluator => "the evaluator cannot be executed safely",
            Self::PromptTooLarge => "evaluator prompt exceeds its byte limit",
            Self::TemporaryWorkspaceUnavailable => {
                "a temporary evaluator workspace could not be created"
            }
            Self::ProcessSpawn => "the evaluator process could not be started",
            Self::ProcessPipeUnavailable => "an evaluator process pipe is unavailable",
            Self::WorkerSpawn => "an evaluator I/O worker could not be started",
            Self::WorkerFailure => "an evaluator I/O worker failed",
            Self::StdinWrite => "the evaluator prompt could not be delivered",
            Self::ProcessWait => "the evaluator process could not be observed",
            Self::DeadlineExceeded => "the evaluator deadline elapsed",
            Self::StdoutRead => "evaluator standard output could not be read",
            Self::StderrRead => "evaluator standard error could not be read",
            Self::StdoutTooLarge => "evaluator standard output exceeds its byte limit",
            Self::StderrTooLarge => "evaluator standard error exceeds its byte limit",
            Self::NonZeroExit => "the evaluator exited unsuccessfully",
            Self::InvalidUtf8Stdout => "evaluator standard output is not valid UTF-8",
        })
    }
}

impl Error for EvaluatorRunError {}

/// Runs exactly one non-interactive evaluator process with the prompt delivered over standard
/// input from a fresh empty temporary working directory.
///
/// # Errors
///
/// Returns a typed [`EvaluatorRunError`] when the configured bounds are invalid, process setup or
/// I/O fails, the deadline elapses, the process exits unsuccessfully, or standard output is not
/// bounded valid UTF-8. Errors never retain or display prompt, output, or executable path data.
pub fn run_evaluator(
    evaluator: &DetectedEvaluator,
    prompt: &str,
    config: EvaluatorRunConfig,
) -> Result<String, EvaluatorRunError> {
    #[cfg(unix)]
    {
        run_evaluator_contained(evaluator, prompt, config)
    }

    #[cfg(not(unix))]
    {
        let _ = (evaluator, prompt, config);
        Err(EvaluatorRunError::UnsupportedEvaluator)
    }
}

#[cfg(unix)]
fn run_evaluator_contained(
    evaluator: &DetectedEvaluator,
    prompt: &str,
    config: EvaluatorRunConfig,
) -> Result<String, EvaluatorRunError> {
    if prompt.len() > config.max_prompt_bytes {
        return Err(EvaluatorRunError::PromptTooLarge);
    }
    let arguments = evaluator
        .kind
        .arguments()
        .ok_or(EvaluatorRunError::UnsupportedEvaluator)?;
    let workspace = TemporaryWorkspace::create()?;
    let deadline = Instant::now()
        .checked_add(config.deadline)
        .ok_or(EvaluatorRunError::InvalidConfig)?;
    let mut command = Command::new(&evaluator.executable);
    command
        .args(arguments)
        .current_dir(workspace.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_safe_environment(&mut command, evaluator, workspace.path());
    configure_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| EvaluatorRunError::ProcessSpawn)?;
    let mut group = CommandGroup::for_child(&child);

    let Some(mut stdin) = child.stdin.take() else {
        terminate_and_reap(&mut group, &mut child);
        return Err(EvaluatorRunError::ProcessPipeUnavailable);
    };
    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut group, &mut child);
        return Err(EvaluatorRunError::ProcessPipeUnavailable);
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut group, &mut child);
        return Err(EvaluatorRunError::ProcessPipeUnavailable);
    };

    let prompt = prompt.as_bytes().to_vec();
    let stdin_worker = thread::Builder::new()
        .name("pam-evaluator-stdin".to_owned())
        .spawn(move || stdin.write_all(&prompt));
    let Ok(stdin_worker) = stdin_worker else {
        terminate_and_reap(&mut group, &mut child);
        return Err(EvaluatorRunError::WorkerSpawn);
    };
    let stdout_worker = thread::Builder::new()
        .name("pam-evaluator-stdout".to_owned())
        .spawn(move || read_bounded(stdout, config.max_stdout_bytes));
    let Ok(stdout_worker) = stdout_worker else {
        terminate_and_reap(&mut group, &mut child);
        let _ = join_worker_until(stdin_worker, deadline);
        return Err(EvaluatorRunError::WorkerSpawn);
    };
    let stderr_worker = thread::Builder::new()
        .name("pam-evaluator-stderr".to_owned())
        .spawn(move || read_bounded(stderr, config.max_stderr_bytes));
    let Ok(stderr_worker) = stderr_worker else {
        terminate_and_reap(&mut group, &mut child);
        let _ = join_worker_until(stdin_worker, deadline);
        let _ = join_worker_until(stdout_worker, deadline);
        return Err(EvaluatorRunError::WorkerSpawn);
    };

    let status = match wait_until(&mut child, deadline) {
        Ok(status) => status,
        Err(EvaluatorRunError::DeadlineExceeded) => {
            terminate_and_reap(&mut group, &mut child);
            join_after_termination(stdin_worker, stdout_worker, stderr_worker, deadline);
            return Err(EvaluatorRunError::DeadlineExceeded);
        }
        Err(error) => {
            terminate_and_reap(&mut group, &mut child);
            join_after_termination(stdin_worker, stdout_worker, stderr_worker, deadline);
            return Err(error);
        }
    };

    // The evaluator leader may exit while descendants retain its standard-I/O handles. Terminate
    // the isolated group before joining readers so those inherited handles cannot outlive the
    // configured deadline.
    group.terminate(&mut child);
    let stdin_result = join_worker_until(stdin_worker, deadline)?;
    let stdout_result = join_worker_until(stdout_worker, deadline)?;
    let stderr_result = join_worker_until(stderr_worker, deadline)?;
    if !status.success() {
        return Err(EvaluatorRunError::NonZeroExit);
    }
    stdin_result.map_err(|_| EvaluatorRunError::StdinWrite)?;
    let stdout = stdout_result.map_err(|_| EvaluatorRunError::StdoutRead)?;
    let stderr = stderr_result.map_err(|_| EvaluatorRunError::StderrRead)?;
    if stdout.oversized {
        return Err(EvaluatorRunError::StdoutTooLarge);
    }
    if stderr.oversized {
        return Err(EvaluatorRunError::StderrTooLarge);
    }
    String::from_utf8(stdout.bytes).map_err(|_| EvaluatorRunError::InvalidUtf8Stdout)
}

#[cfg(unix)]
pub(crate) fn safe_evaluator_environment_name(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some("ANTHROPIC_API_KEY" | "ANTHROPIC_AUTH_TOKEN" | "CLAUDE_CODE_OAUTH_TOKEN")
    )
}

#[cfg(unix)]
pub(crate) fn retained_evaluator_auth_environment(
    variables: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    variables
        .into_iter()
        .filter(|(name, _)| safe_evaluator_environment_name(name))
        .collect()
}

#[cfg(unix)]
fn apply_safe_environment(command: &mut Command, evaluator: &DetectedEvaluator, workspace: &Path) {
    let inherited = retained_evaluator_auth_environment(env::vars_os());
    command
        .env_clear()
        .envs(inherited)
        .env("PATH", &evaluator.search_path)
        .env("HOME", workspace)
        .env("TMPDIR", workspace)
        .env("XDG_CACHE_HOME", workspace)
        .env("XDG_CONFIG_HOME", workspace)
        .env("XDG_DATA_HOME", workspace)
        .env("XDG_STATE_HOME", workspace);
}

#[cfg(unix)]
fn wait_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus, EvaluatorRunError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(EvaluatorRunError::DeadlineExceeded);
                }
                thread::sleep(WAIT_POLL_INTERVAL.min(deadline.duration_since(now)));
            }
            Err(_) => return Err(EvaluatorRunError::ProcessWait),
        }
    }
}

#[cfg(unix)]
fn terminate_and_reap(group: &mut CommandGroup, child: &mut Child) {
    group.terminate(child);
    let _ = child.wait();
}

#[cfg(unix)]
fn join_after_termination(
    stdin_worker: JoinHandle<io::Result<()>>,
    stdout_worker: JoinHandle<io::Result<BoundedBytes>>,
    stderr_worker: JoinHandle<io::Result<BoundedBytes>>,
    deadline: Instant,
) {
    let _ = join_worker_until(stdin_worker, deadline);
    let _ = join_worker_until(stdout_worker, deadline);
    let _ = join_worker_until(stderr_worker, deadline);
}

#[cfg(unix)]
fn join_worker_until<T>(worker: JoinHandle<T>, deadline: Instant) -> Result<T, EvaluatorRunError> {
    while !worker.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err(EvaluatorRunError::DeadlineExceeded);
        }
        thread::sleep(WAIT_POLL_INTERVAL.min(deadline.duration_since(now)));
    }
    worker.join().map_err(|_| EvaluatorRunError::WorkerFailure)
}

#[cfg(unix)]
struct CommandGroup {
    process_id: Option<u32>,
    armed: bool,
}

#[cfg(unix)]
impl CommandGroup {
    fn for_child(child: &Child) -> Self {
        Self {
            process_id: Some(child.id()),
            armed: true,
        }
    }

    fn terminate(&mut self, child: &mut Child) {
        if let Some(process_id) = self.process_id.and_then(|id| i32::try_from(id).ok()) {
            use nix::{errno::Errno, sys::signal::Signal, unistd::Pid};

            if let Err(error) = nix::sys::signal::killpg(Pid::from_raw(process_id), Signal::SIGKILL)
                && error != Errno::ESRCH
            {
                let _ = child.kill();
                return;
            }
            self.armed = false;
        }
        let _ = child.kill();
    }
}

#[cfg(unix)]
impl Drop for CommandGroup {
    fn drop(&mut self) {
        if self.armed
            && let Some(process_id) = self.process_id.and_then(|id| i32::try_from(id).ok())
        {
            use nix::{sys::signal::Signal, unistd::Pid};

            let _ = nix::sys::signal::killpg(Pid::from_raw(process_id), Signal::SIGKILL);
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

#[cfg(unix)]
struct BoundedBytes {
    bytes: Vec<u8>,
    oversized: bool,
}

#[cfg(unix)]
fn read_bounded(mut reader: impl Read, limit: usize) -> io::Result<BoundedBytes> {
    let mut bytes = Vec::with_capacity(limit.min(8 * 1024));
    let mut oversized = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let retained = limit.saturating_sub(bytes.len()).min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        oversized |= retained < read;
    }
    Ok(BoundedBytes { bytes, oversized })
}

#[cfg(unix)]
struct TemporaryWorkspace {
    path: PathBuf,
}

#[cfg(unix)]
impl TemporaryWorkspace {
    fn create() -> Result<Self, EvaluatorRunError> {
        let base = env::temp_dir();
        for _ in 0..128 {
            let sequence = TEMP_WORKSPACE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!("pam-evaluator-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    if restrict_workspace_permissions(&path).is_err() {
                        let _ = fs::remove_dir(&path);
                        return Err(EvaluatorRunError::TemporaryWorkspaceUnavailable);
                    }
                    let Ok(canonical_path) = fs::canonicalize(&path) else {
                        let _ = fs::remove_dir(&path);
                        return Err(EvaluatorRunError::TemporaryWorkspaceUnavailable);
                    };
                    return Ok(Self {
                        path: canonical_path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(EvaluatorRunError::TemporaryWorkspaceUnavailable),
            }
        }
        Err(EvaluatorRunError::TemporaryWorkspaceUnavailable)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for TemporaryWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn restrict_workspace_permissions(path: &Path) -> Result<(), EvaluatorRunError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| EvaluatorRunError::TemporaryWorkspaceUnavailable)
}
