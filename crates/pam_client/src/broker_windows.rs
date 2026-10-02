//! Starting the daemon on Windows without handing it the caller's handles.
//!
//! `std::process::Command` creates every child with handle inheritance on, so
//! a daemon spawned straight from `pam.exe` inherits whatever inheritable
//! handles `pam.exe` holds, its stdio pipes included, even though its own
//! stdio is NUL. A harness that captures `pam`'s stdout through a pipe then
//! waits for end-of-file until the daemon, which outlives the command, exits.
//!
//! Safe Rust cannot narrow that, so the daemon is started by a short-lived
//! broker, `powershell.exe -Command "Start-Process …"`. `Start-Process`
//! launches through `ShellExecute`, which passes no handles on. The broker
//! itself inherits them for the instant it lives and is waited for.
//!
//! PowerShell is found by absolute path under `%SystemRoot%\System32`, never
//! through `PATH`, and the daemon gets the environment allowlist through the
//! broker's own environment, which `Start-Process` hands on.

use std::ffi::OsString;
use std::io;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::client::{daemon_cwd, daemon_env};

/// How long the broker may take: it exits as soon as `Start-Process` returns,
/// which is a second or so even when PowerShell starts cold.
const BROKER_BOUND: Duration = Duration::from_secs(30);

/// Pause between two looks at the broker.
const BROKER_POLL: Duration = Duration::from_millis(10);

/// `CREATE_NO_WINDOW`: the broker never flashes a console.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn spawn_error(detail: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "cannot start the pam daemon through PowerShell: {detail}"
    ))
}

/// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, canonicalized
/// inside a canonicalized `System32`. `PATH` is never searched.
pub(crate) fn powershell_path() -> io::Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute() && root.is_dir())
        .ok_or_else(|| spawn_error("%SystemRoot% is not an absolute, existing directory"))?;
    let system32 = std::fs::canonicalize(root.join("System32")).map_err(spawn_error)?;
    let powershell = std::fs::canonicalize(
        system32
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )
    .map_err(spawn_error)?;
    if !powershell.is_file() || !powershell.starts_with(&system32) {
        return Err(spawn_error("powershell.exe is not inside System32"));
    }
    Ok(powershell)
}

/// `text` as the body of a PowerShell single-quoted string: every quote,
/// including the typographic ones PowerShell reads as quotes, is doubled.
///
/// # Errors
///
/// A line break or NUL cannot be carried inside the string and is refused.
pub(crate) fn single_quoted(text: &str) -> io::Result<String> {
    if let Some(bad) = text.chars().find(|c| matches!(c, '\n' | '\r' | '\0')) {
        return Err(spawn_error(format!(
            "the executable path contains {bad:?}, which cannot be quoted for PowerShell"
        )));
    }
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for c in text.chars() {
        quoted.push(c);
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    Ok(quoted)
}

/// The script the broker runs: starts `exe daemon`, hidden.
pub(crate) fn start_script(exe: &Path) -> io::Result<String> {
    let exe = exe
        .to_str()
        .ok_or_else(|| spawn_error("the executable path is not valid Unicode"))?;
    Ok(format!(
        "Start-Process -FilePath {} -ArgumentList 'daemon' -WindowStyle Hidden",
        single_quoted(exe)?
    ))
}

/// The broker command: PowerShell with null stdio, the fixed working
/// directory and the daemon's environment allowlist plus an explicit absolute
/// `PAM_BASE_DIR`, which `Start-Process` passes on to the daemon.
pub(crate) fn broker_command(
    powershell: &Path,
    exe: &Path,
    base_dir: &Path,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> io::Result<Command> {
    let script = start_script(exe)?;
    let base = std::path::absolute(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let mut command = Command::new(powershell);
    command
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .envs(daemon_env(vars))
        .env("PAM_BASE_DIR", base)
        .current_dir(daemon_cwd())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

/// Runs the broker and waits for it, at most `bound`.
pub(crate) fn run_broker(mut command: Command, bound: Duration) -> io::Result<()> {
    let mut child = command.spawn().map_err(spawn_error)?;
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait().map_err(spawn_error)? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                return Err(spawn_error(format!("powershell.exe exited with {status}")));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(spawn_error(format!(
                    "powershell.exe did not finish within {bound:?}"
                )));
            }
            None => std::thread::sleep(BROKER_POLL),
        }
    }
}

/// Starts `exe daemon` for `base_dir` through the broker.
///
/// # Errors
///
/// PowerShell cannot be found, the path cannot be quoted, or the broker
/// fails, exits non-zero or does not finish in time.
pub(crate) fn spawn_daemon(
    exe: &Path,
    base_dir: &Path,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> io::Result<()> {
    run_broker(
        broker_command(&powershell_path()?, exe, base_dir, vars)?,
        BROKER_BOUND,
    )
}
