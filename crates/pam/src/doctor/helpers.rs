//! The bounded helper runner: how a probe asks the OS a question it cannot
//! ask through the standard library (`security`, `kill -0`, `open -b`,
//! `osascript`, `where`, `PowerShell`).
//!
//! A helper is named by absolute path only — under `/usr/bin` and `/bin` on
//! macOS, under `%SystemRoot%\System32` on Windows — and runs with a cleared
//! environment plus [`HELPER_ENV_ALLOWLIST`], null stdin, both output pipes
//! captured and capped at [`MAX_HELPER_OUTPUT_BYTES`], and the bound the
//! probe gives it. A helper that cannot start, or that overruns, is reported
//! as such and classifies to `unknown`; the runner never panics.

use std::ffi::OsString;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The most bytes kept of each of a helper's stdout and stderr.
pub const MAX_HELPER_OUTPUT_BYTES: usize = 64 * 1024;

/// How often a running helper is polled for exit.
const EXIT_POLL: Duration = Duration::from_millis(10);

/// Environment variables a helper keeps from this process: identity, home
/// and temp locations the OS tools need to find the session's keychain and
/// their own state. No `PATH`: every helper is named by absolute path.
pub const HELPER_ENV_ALLOWLIST: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    // Windows: the system root the helpers live under, the profile and temp
    // locations `PowerShell` and the credential APIs need.
    "SystemRoot",
    "SystemDrive",
    "windir",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "PATHEXT",
    "ComSpec",
];

/// One helper invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Helper {
    /// The program, by absolute path.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// How long it may run before it is killed.
    pub timeout: Duration,
}

impl Helper {
    /// A helper at `program` with `args`, bounded by `timeout`.
    #[must_use]
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        timeout: Duration,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            timeout,
        }
    }
}

/// A helper that ran to completion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HelperRun {
    /// Its exit code, when it exited rather than being killed by a signal.
    pub code: Option<i32>,
    /// Its standard output, lossily decoded and capped.
    pub stdout: String,
    /// Its standard error, lossily decoded and capped.
    pub stderr: String,
    /// Whether either stream exceeded the cap.
    pub truncated: bool,
}

impl HelperRun {
    /// A completed run with `code` and the two streams, for classifier tests.
    #[must_use]
    pub fn new(code: Option<i32>, stdout: &str, stderr: &str) -> Self {
        Self {
            code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            truncated: false,
        }
    }
}

/// What running a helper came to.
#[derive(Debug)]
pub enum HelperOutcome {
    /// It ran and exited.
    Ran(HelperRun),
    /// It could not be started.
    SpawnFailed(io::Error),
    /// It did not exit within its bound and was killed.
    TimedOut(Duration),
}

/// The helper's environment from this process's: the allowlisted names,
/// matched case-insensitively (Windows names are case-insensitive, and the
/// list carries the canonical spelling of each), plus every `LC_*` locale
/// variable.
#[must_use]
pub fn helper_env(vars: impl Iterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    vars.filter(|(name, _)| {
        name.to_str().is_some_and(|text| {
            text.starts_with("LC_")
                || HELPER_ENV_ALLOWLIST
                    .iter()
                    .any(|allowed| text.eq_ignore_ascii_case(allowed))
        })
    })
    .collect()
}

/// Runs `helper` under its rules and bound.
#[must_use]
pub fn run_helper(helper: &Helper) -> HelperOutcome {
    let mut command = Command::new(&helper.program);
    command
        .args(&helper.args)
        .env_clear()
        .envs(helper_env(std::env::vars_os()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return HelperOutcome::SpawnFailed(error),
    };
    let stdout = child
        .stdout
        .take()
        .map(|pipe| thread::spawn(move || drain_capped(pipe)));
    let stderr = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || drain_capped(pipe)));
    let deadline = Instant::now() + helper.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                // Killing closes the pipes, so the readers finish.
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(EXIT_POLL),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return HelperOutcome::SpawnFailed(error);
            }
        }
    };
    let (stdout, out_truncated) = collect(stdout);
    let (stderr, err_truncated) = collect(stderr);
    match status {
        Some(status) => HelperOutcome::Ran(HelperRun {
            code: status.code(),
            stdout,
            stderr,
            truncated: out_truncated || err_truncated,
        }),
        None => HelperOutcome::TimedOut(helper.timeout),
    }
}

/// Joins one capped reader; a reader that panicked counts as empty.
fn collect(reader: Option<thread::JoinHandle<(Vec<u8>, bool)>>) -> (String, bool) {
    let (bytes, truncated) = reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    (String::from_utf8_lossy(&bytes).into_owned(), truncated)
}

/// Reads `pipe` to end of file, keeping the first
/// [`MAX_HELPER_OUTPUT_BYTES`] and draining the rest so the helper never
/// blocks on a full pipe.
fn drain_capped(mut pipe: impl Read) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut chunk = [0_u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let room = MAX_HELPER_OUTPUT_BYTES.saturating_sub(kept.len());
                let take = read.min(room);
                kept.extend_from_slice(&chunk[..take]);
                if take < read {
                    truncated = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, truncated)
}
