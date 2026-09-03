//! The mechanical half of a flow run: what one step reports, how the
//! verdict is computed from those reports, and how a command step's child
//! process is spawned, read, bounded and killed.
//!
//! Everything here is deliberately free of daemon state — no store, no
//! gate, no approvals — so the fiddly parts (the outcome matrix, the
//! summary sentence, the environment scrub, program resolution, and the
//! child-process lifecycle) are unit-tested without a daemon.
//! [`crate::flow_service`] owns the policy: it decides *whether* a step
//! runs, and calls in here to run it.
//!
//! # The child process contract
//!
//! [`run_command`] gives a step's program a cwd (the caller's repo), a
//! scrubbed environment ([`scrub_env`]), a null stdin, and one interleaved
//! output buffer: stdout and stderr are read concurrently into a single
//! `Vec<u8>` in arrival order, because a build log that separates the two
//! is unreadable and `pam_compact` reduces the interleaving a human would
//! have seen. Four things can end the run — the process exits, the step's
//! timeout elapses, the output passes [`MAX_SOURCE_BYTES`], or the request
//! is cancelled — and the last three kill the child.
//!
//! # What is killed, and what is not
//!
//! On unix the child is placed in its own process group
//! (`process_group(0)`), which detaches it from the daemon's: a terminal
//! signal aimed at pam never reaches a flow's `cargo test`. The kill path
//! signals **the child only** (`Child::start_kill`, plus `kill_on_drop`
//! for the paths that return early). A program that forks and detaches its
//! own grandchildren therefore leaks them, exactly as a shell's `Ctrl-C`
//! would; chasing a process tree needs per-OS process-group and job-object
//! code that this plan does not carry. The buffer is still closed and the
//! step still ends on time — a surviving grandchild delays nothing.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use pam_compact::MAX_SOURCE_BYTES;
use pam_flow::{Effect, Flow, Role};
use pam_proto::Outcome;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};

/// Environment variable name fragments that mark a value as a secret, as
/// the spec's `(?i)token|secret|password|passwd|credential|api_key|apikey|private_key`
/// pattern spells them. Matching is a case-insensitive substring test —
/// pam carries no regex engine, and the pattern is a plain alternation.
pub const SECRET_ENV_FRAGMENTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "api_key",
    "apikey",
    "private_key",
];

/// Bytes read from a pipe per `read` call.
const PUMP_CHUNK: usize = 64 * 1024;

/// How many output chunks may queue between the pipe readers and the
/// collector before the readers wait.
const CHUNK_QUEUE: usize = 64;

/// The exit status recorded for a child that ended on a signal rather
/// than with a code of its own (unix has no code in that case).
pub const SIGNALLED_EXIT_STATUS: i32 = -1;

/// How one step of a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// It ran and reported success.
    Succeeded,
    /// It ran (possibly several times) and reported failure.
    Failed,
    /// Its `when` condition was not met.
    Skipped,
    /// A human, or the policy gate, would not let it run.
    Blocked,
    /// The request was cancelled while it ran.
    Cancelled,
}

impl StepStatus {
    /// The wire word the verdict body carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Why a step did not succeed, in the shape every pam refusal uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepError {
    /// Machine-readable cause.
    pub cause: String,
    /// What happened, in one sentence.
    pub detail: String,
    /// The concrete fix — a GUI screen or an edit, never a security
    /// command.
    pub recovery: String,
}

/// What one step of a run produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepReport {
    /// The step id, as the flow file spells it.
    pub id: String,
    /// `"command"` or `"connector"`.
    pub kind: &'static str,
    /// How it ended.
    pub status: StepStatus,
    /// Attempts made, including the first (retries count).
    pub attempts: u8,
    /// Wall time the step took, in milliseconds.
    pub duration_ms: u64,
    /// The process (or job) exit status, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// Evidence rows this step left, in write order.
    pub evidence: Vec<String>,
    /// The model's summary, for an `output: summarize` step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Why it did not succeed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<StepError>,
}

impl StepReport {
    /// A fresh report for `id`, in the status a step starts life in.
    #[must_use]
    pub fn new(id: &str, kind: &'static str, status: StepStatus) -> Self {
        Self {
            id: id.to_owned(),
            kind,
            status,
            attempts: 0,
            duration_ms: 0,
            exit_status: None,
            evidence: Vec::new(),
            summary: None,
            error: None,
        }
    }

    /// Records why the step did not succeed.
    pub fn fail(&mut self, status: StepStatus, cause: &str, detail: String, recovery: String) {
        self.status = status;
        self.error = Some(StepError {
            cause: cause.to_owned(),
            detail,
            recovery,
        });
    }
}

/// The verdict of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// The flow's outcome, per [`outcome_for`].
    pub outcome: Outcome,
    /// The deterministic summary sentence, per [`summary_for`].
    pub summary: String,
    /// One report per step, in file order.
    pub steps: Vec<StepReport>,
}

/// The flow's outcome, from its steps.
///
/// Precedence, highest first: a blocked (or cancelled) step makes the run
/// `blocked`; a failed step — after its retries — makes it `unresolved`;
/// otherwise a stateful step that ran makes it `changed`, a `verify` step
/// that ran makes it `verified`, and a run of pure observation is
/// `solved`. Skipped steps count for nothing in either direction: a step
/// whose `when` was not met neither proves nor changes anything.
#[must_use]
pub fn outcome_for(steps: &[StepReport], flow: &Flow) -> Outcome {
    if steps
        .iter()
        .any(|step| matches!(step.status, StepStatus::Blocked | StepStatus::Cancelled))
    {
        return Outcome::Blocked;
    }
    if steps.iter().any(|step| step.status == StepStatus::Failed) {
        return Outcome::Unresolved;
    }
    let succeeded = |id: &str| {
        steps
            .iter()
            .any(|step| step.id == id && step.status == StepStatus::Succeeded)
    };
    if flow
        .steps
        .iter()
        .any(|step| step.effect == Effect::Stateful && succeeded(&step.id))
    {
        return Outcome::Changed;
    }
    if flow
        .steps
        .iter()
        .any(|step| step.role == Role::Verify && succeeded(&step.id))
    {
        return Outcome::Verified;
    }
    Outcome::Solved
}

/// The run's summary sentence: `"7 steps: 6 succeeded, 1 failed (clippy,
/// exit 101)"`.
///
/// Counts appear in a fixed order (succeeded, failed, blocked, cancelled,
/// skipped) and zero counts are left out, except `succeeded`, which is
/// always stated so the sentence never starts with bad news alone. The
/// parenthesis names the first step that did not succeed and why; when
/// that step carries a summary, it follows on its own line.
#[must_use]
pub fn summary_for(steps: &[StepReport]) -> String {
    let total = steps.len();
    let count = |status: StepStatus| steps.iter().filter(|step| step.status == status).count();
    let mut parts = vec![format!("{} succeeded", count(StepStatus::Succeeded))];
    for (status, word) in [
        (StepStatus::Failed, "failed"),
        (StepStatus::Blocked, "blocked"),
        (StepStatus::Cancelled, "cancelled"),
        (StepStatus::Skipped, "skipped"),
    ] {
        let found = count(status);
        if found > 0 {
            parts.push(format!("{found} {word}"));
        }
    }
    let noun = if total == 1 { "step" } else { "steps" };
    let mut sentence = format!("{total} {noun}: {}", parts.join(", "));

    let culprit = steps.iter().find(|step| {
        matches!(
            step.status,
            StepStatus::Failed | StepStatus::Blocked | StepStatus::Cancelled
        )
    });
    if let Some(step) = culprit {
        let why = match (step.exit_status, step.error.as_ref()) {
            (Some(status), _) => format!("exit {status}"),
            (None, Some(error)) => error.cause.clone(),
            (None, None) => step.status.as_str().to_owned(),
        };
        let _ = write!(sentence, " ({}, {why})", step.id);
        if let Some(summary) = step.summary.as_ref() {
            sentence.push('\n');
            sentence.push_str(summary);
        }
    }
    sentence
}

/// Everything one command step needs to become a child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// The resolved program, from [`resolve_program`].
    pub program: PathBuf,
    /// The arguments after the program (the flow's `run[1..]`).
    pub argv: Vec<String>,
    /// Working directory: the caller's repo.
    pub cwd: PathBuf,
    /// The complete environment; nothing is inherited implicitly.
    pub env: Vec<(String, String)>,
    /// Wall-clock limit for this one attempt.
    pub timeout: Duration,
}

/// How one child process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// It exited on its own.
    Exited {
        /// Its exit code, or [`SIGNALLED_EXIT_STATUS`] when a signal
        /// ended it.
        status: i32,
        /// Everything it wrote, stdout and stderr interleaved.
        output: Vec<u8>,
    },
    /// It outlived the step's timeout and was killed.
    TimedOut {
        /// What it had written by then.
        output: Vec<u8>,
    },
    /// It wrote more than [`MAX_SOURCE_BYTES`] and was killed.
    OutputLimit {
        /// The first [`MAX_SOURCE_BYTES`] bytes.
        output: Vec<u8>,
    },
    /// The request was cancelled; the child was killed and its output
    /// dropped (nothing is filed for a run nobody is waiting on).
    Cancelled,
    /// The process could never be started.
    SpawnFailed(
        /// The operating system's reason.
        String,
    ),
}

/// Why the collector loop stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Both pipes reached end of file.
    Eof,
    /// The timeout elapsed.
    TimedOut,
    /// The output passed the cap.
    OutputLimit,
    /// The cancel signal fired.
    Cancelled,
}

/// Runs one command step's child process to one of [`CommandOutcome`]'s
/// four endings (see the module docs for the contract and the kill
/// caveat).
pub async fn run_command(spec: CommandSpec, cancel: &mut watch::Receiver<bool>) -> CommandOutcome {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.argv)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .kill_on_drop(true);
    for (name, value) in &spec.env {
        command.env(name, value);
    }
    // Own process group: a signal aimed at the daemon's group never
    // reaches a flow's child (see the module docs).
    #[cfg(unix)]
    command.process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return CommandOutcome::SpawnFailed(error.to_string()),
    };
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let (chunks, mut incoming) = mpsc::channel::<Vec<u8>>(CHUNK_QUEUE);
    let pumps = [
        tokio::spawn(pump(stdout, chunks.clone())),
        tokio::spawn(pump(stderr, chunks)),
    ];

    let mut output: Vec<u8> = Vec::new();
    let deadline = tokio::time::sleep(spec.timeout);
    tokio::pin!(deadline);

    let ending = loop {
        tokio::select! {
            biased;
            // A closed cancel channel means the lease is gone, which is
            // cancellation too — the same reading every capability uses.
            () = cancelled(cancel) => break Ending::Cancelled,
            () = &mut deadline => break Ending::TimedOut,
            chunk = incoming.recv() => match chunk {
                Some(chunk) => {
                    output.extend_from_slice(&chunk);
                    if output.len() > MAX_SOURCE_BYTES {
                        output.truncate(MAX_SOURCE_BYTES);
                        break Ending::OutputLimit;
                    }
                }
                None => break Ending::Eof,
            },
        }
    };
    for pump in pumps {
        pump.abort();
    }

    if ending != Ending::Eof {
        kill(&mut child).await;
        return match ending {
            Ending::TimedOut => CommandOutcome::TimedOut { output },
            Ending::OutputLimit => CommandOutcome::OutputLimit { output },
            _ => CommandOutcome::Cancelled,
        };
    }

    // Both pipes are closed, so the child is exiting; the timeout and the
    // cancel signal still bound the reap in case a grandchild held the
    // pipes and the child itself is still running.
    tokio::select! {
        biased;
        () = cancelled(cancel) => {
            kill(&mut child).await;
            CommandOutcome::Cancelled
        }
        () = &mut deadline => {
            kill(&mut child).await;
            CommandOutcome::TimedOut { output }
        }
        status = child.wait() => match status {
            Ok(status) => CommandOutcome::Exited {
                status: status.code().unwrap_or(SIGNALLED_EXIT_STATUS),
                output,
            },
            Err(error) => CommandOutcome::SpawnFailed(error.to_string()),
        }
    }
}

/// Resolves when the request is cancelled — the flag flipping, or the
/// channel closing (the lease is gone, which is cancellation too).
///
/// A plain `cancel.wait_for(…)` branch yields a `watch::Ref`, whose read
/// guard is not `Send`; parking it inside a `select!` arm would make
/// every future that contains the select unspawnable. Resolving to `()`
/// keeps the guard out of the select's own state.
pub async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    let _ = cancel.wait_for(|flag| *flag).await;
}

/// Signals the child and reaps it, so no zombie outlives the step.
async fn kill(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// Reads one pipe to end of file, handing every chunk to the collector.
async fn pump<R: AsyncRead + Unpin>(mut reader: R, chunks: mpsc::Sender<Vec<u8>>) {
    let mut buffer = vec![0_u8; PUMP_CHUNK];
    loop {
        match reader.read(&mut buffer).await {
            // End of file, or a pipe error that end of file would follow
            // anyway — either way this reader is done.
            Ok(0) | Err(_) => return,
            Ok(read) => {
                if chunks.send(buffer[..read].to_vec()).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// The daemon's own environment, minus everything a flow step must not
/// see: names that look like a credential, and `PATH` (which
/// [`crate::flow_service`] rebuilds from the flow settings).
///
/// Variables whose name or value is not UTF-8 are dropped rather than
/// lossily converted: a mangled value is worse than a missing one, and
/// nothing in a flow depends on one.
#[must_use]
pub fn scrub_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = vars
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            let value = value.into_string().ok()?;
            (!name.eq_ignore_ascii_case("PATH") && !is_secret_env_name(&name))
                .then_some((name, value))
        })
        .collect();
    // Sorted so a step's environment — and therefore a test's assertion
    // about it — does not depend on the daemon's own env ordering.
    kept.sort();
    kept
}

/// Whether this environment variable name looks like it holds a secret.
#[must_use]
pub fn is_secret_env_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SECRET_ENV_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

/// Finds `program` on `extra_path` first, then on `path`.
///
/// The extra directories win, which is the whole point of the setting: a
/// daemon started by launchd or systemd inherits a minimal `PATH` where
/// `cargo` does not exist, and the human's answer is `~/.cargo/bin`.
/// A program name carrying a path separator resolves to nothing —
/// validation refuses those, and this is the second line of that fence.
#[must_use]
pub fn resolve_program(program: &str, extra_path: &[PathBuf], path: &OsStr) -> Option<PathBuf> {
    if program.is_empty() || program.contains(['/', '\\']) {
        return None;
    }
    let inherited: Vec<PathBuf> = std::env::split_paths(path).collect();
    extra_path
        .iter()
        .chain(inherited.iter())
        .find_map(|dir| candidate_in(dir, program))
}

/// The first name of `program` that exists as a file in `dir`.
fn candidate_in(dir: &Path, program: &str) -> Option<PathBuf> {
    if dir.as_os_str().is_empty() {
        return None;
    }
    candidate_names(program)
        .into_iter()
        .map(|name| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The file names `program` could have on this platform.
#[cfg(windows)]
fn candidate_names(program: &str) -> Vec<String> {
    let mut names = vec![program.to_owned()];
    names.extend([".exe", ".cmd", ".bat", ".com"].map(|ext| format!("{program}{ext}")));
    names
}

/// The file names `program` could have on this platform.
#[cfg(not(windows))]
fn candidate_names(program: &str) -> Vec<String> {
    vec![program.to_owned()]
}

/// Sleeps for `delay` unless the request is cancelled first; `true` means
/// it was cancelled. The retry backoff waits through this so a cancel
/// never has to outlast a minute of sleeping.
pub async fn sleep_or_cancel(delay: Duration, cancel: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        biased;
        () = cancelled(cancel) => true,
        () = tokio::time::sleep(delay) => false,
    }
}
