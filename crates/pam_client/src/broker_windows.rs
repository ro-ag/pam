//! Starting the daemon on Windows without handing it the caller's handles.
//!
//! `std::process::Command` creates every child with handle inheritance on, so
//! a daemon spawned straight from `pam.exe` inherits whatever inheritable
//! handles `pam.exe` holds, its stdio pipes included, even though its own
//! stdio is NUL. A harness that captures `pam`'s stdout through a pipe then
//! waits for end-of-file until the daemon, which outlives the command, exits.
//!
//! Safe Rust cannot narrow that (`CommandExt::inherit_handles` is unstable), so
//! the daemon is started by a short-lived broker, the system's Windows
//! PowerShell running `Start-Process`. `Start-Process` launches through
//! `ShellExecute`, which passes no handles on. The broker itself inherits them
//! for the instant it lives and is waited for.
//!
//! The broker must not make PowerShell look a command up. Started without
//! `PSModulePath`, PowerShell finds `Start-Process` by going through every
//! module on the machine's and the user's module path, which takes tens of
//! seconds where many modules are installed (a hosted CI runner): longer than
//! the broker's bound. So the script imports the one module it needs by its
//! absolute path under `System32` first, and the broker's `PSModulePath` names
//! PowerShell's own module directory.
//!
//! `ShellExecute` has a cost of its own: it asks the user before it starts a
//! file marked as downloaded from the internet, and a hidden broker cannot be
//! answered. Such a start runs into the broker's bound; the error then names
//! the mark and how to remove it.
//!
//! PowerShell is found by absolute path under `%SystemRoot%\System32`, never
//! through `PATH`, and the daemon gets the environment allowlist through the
//! broker's own environment, which `Start-Process` hands on. The script drops
//! `PSModulePath` before it starts the daemon, so the daemon gets the
//! allowlist and the base and nothing the broker needed for itself.

use std::ffi::OsString;
use std::io::{self, Read as _};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::client::{daemon_cwd, daemon_env};

/// How long the broker may take. It exits as soon as `Start-Process` returns:
/// a fraction of a second, a few seconds when PowerShell starts cold. Kept
/// under half a minute so that `pam` reports a broker that hangs before a
/// caller with a thirty-second timeout gives up on the command.
const BROKER_BOUND: Duration = Duration::from_secs(20);

/// Pause between two looks at the broker.
const BROKER_POLL: Duration = Duration::from_millis(10);

/// How long the broker's error output is waited for once it has exited.
const STDERR_WAIT: Duration = Duration::from_secs(1);

/// How much of the broker's error output an error quotes.
const STDERR_QUOTE: usize = 300;

/// `CREATE_NO_WINDOW`: the broker never flashes a console.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn spawn_error(detail: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!(
        "cannot start the pam daemon through PowerShell: {detail}. Where PowerShell is blocked, \
         `pam service install` runs the daemon at login and no command has to start it"
    ))
}

/// The system's Windows PowerShell and the module `Start-Process` lives in.
pub(crate) struct SystemPowerShell {
    /// `powershell.exe`, canonicalized.
    pub(crate) exe: PathBuf,
    /// PowerShell's own module directory.
    pub(crate) modules: PathBuf,
    /// The manifest of `Microsoft.PowerShell.Management` in that directory.
    pub(crate) management: PathBuf,
}

/// `%SystemRoot%\System32\WindowsPowerShell\v1.0`: the executable and the
/// `Microsoft.PowerShell.Management` manifest, each checked to resolve inside
/// a canonicalized `System32`. `PATH` and the module path are never searched.
pub(crate) fn system_powershell() -> io::Result<SystemPowerShell> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute() && root.is_dir())
        .ok_or_else(|| spawn_error("%SystemRoot% is not an absolute, existing directory"))?;
    let system32 = std::fs::canonicalize(root.join("System32")).map_err(spawn_error)?;
    let inside = |path: &Path, what: &str| -> io::Result<PathBuf> {
        let resolved = std::fs::canonicalize(path)
            .map_err(|error| spawn_error(format!("{}: {error}", path.display())))?;
        if !resolved.is_file() || !resolved.starts_with(&system32) {
            return Err(spawn_error(format!("{what} is not inside System32")));
        }
        Ok(resolved)
    };
    let home = root.join("System32").join("WindowsPowerShell").join("v1.0");
    let modules = home.join("Modules");
    let management = modules
        .join("Microsoft.PowerShell.Management")
        .join("Microsoft.PowerShell.Management.psd1");
    inside(&management, "the Microsoft.PowerShell.Management module")?;
    Ok(SystemPowerShell {
        exe: inside(&home.join("powershell.exe"), "powershell.exe")?,
        modules,
        management,
    })
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
            "the path contains {bad:?}, which cannot be quoted for PowerShell"
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

fn quoted_path(path: &Path) -> io::Result<String> {
    single_quoted(
        path.to_str().ok_or_else(|| {
            spawn_error(format!("the path {} is not valid Unicode", path.display()))
        })?,
    )
}

/// The script the broker runs: starts `exe daemon`, hidden.
///
/// `Start-Process` comes from the module at `management`, imported by path:
/// nothing in the script is a name PowerShell has to search its module path
/// for (`Import-Module` is part of the engine). Any failure ends the script
/// with a non-zero exit. `PSModulePath`, which PowerShell sets for itself, is
/// removed before the daemon is started and so never reaches it.
pub(crate) fn start_script(exe: &Path, management: &Path) -> io::Result<String> {
    Ok(format!(
        "$ErrorActionPreference = 'Stop'; Import-Module -Name {}; $env:PSModulePath = $null; \
         Start-Process -FilePath {} -ArgumentList 'daemon' -WindowStyle Hidden",
        quoted_path(management)?,
        quoted_path(exe)?
    ))
}

/// The broker command: PowerShell with null input and output, the fixed
/// working directory and the daemon's environment allowlist plus an explicit
/// absolute `PAM_BASE_DIR`, which `Start-Process` passes on to the daemon.
/// `PSModulePath` is for the broker alone (the script removes it): it keeps
/// PowerShell from composing a module path out of the machine's and the
/// user's.
pub(crate) fn broker_command(
    powershell: &SystemPowerShell,
    exe: &Path,
    base_dir: &Path,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> io::Result<Command> {
    let script = start_script(exe, &powershell.management)?;
    let base = std::path::absolute(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());
    let mut command = Command::new(&powershell.exe);
    command
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_clear()
        .envs(daemon_env(vars))
        .env("PSModulePath", &powershell.modules)
        .env("PAM_BASE_DIR", base)
        .current_dir(daemon_cwd())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

/// The first lines of what the broker wrote to its error output, on one line.
fn quote(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(STDERR_QUOTE) {
        Some((end, _)) => format!("{}...", &line[..end]),
        None => line,
    }
}

/// Runs the broker and waits for it, at most `bound`.
pub(crate) fn run_broker(mut command: Command, bound: Duration) -> io::Result<()> {
    let mut child = command.spawn().map_err(spawn_error)?;
    // Read on a thread that is never joined: the error output must not be
    // able to hold this command up, whoever else ends up with the pipe.
    let (said, stderr) = mpsc::channel();
    if let Some(mut pipe) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = said.send(bytes);
        });
    }
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait().map_err(spawn_error)? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                let reason = quote(&stderr.recv_timeout(STDERR_WAIT).unwrap_or_default());
                let separator = if reason.is_empty() { "" } else { ": " };
                return Err(spawn_error(format!(
                    "powershell.exe exited with {status}{separator}{reason}"
                )));
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

/// Whether Windows marked `exe` as downloaded from the internet or from a
/// restricted site: the `Zone.Identifier` stream a browser writes next to the
/// file's data.
pub(crate) fn marked_as_downloaded(exe: &Path) -> bool {
    let mut stream = exe.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::read_to_string(&stream).is_ok_and(|zone| {
        zone.lines()
            .any(|line| matches!(line.trim(), "ZoneId=3" | "ZoneId=4"))
    })
}

/// `error` with the reason a marked executable adds: `ShellExecute` asks the
/// user before it starts a downloaded file, and here nobody sees the question,
/// so the broker sits until its bound.
pub(crate) fn with_download_hint(error: io::Error, exe: &Path) -> io::Error {
    if !marked_as_downloaded(exe) {
        return error;
    }
    io::Error::other(format!(
        "{error}. {} is marked as downloaded from the internet, and Windows asks before it starts \
         such a file in the background: unblock the file (Properties > Unblock) and run the \
         command again",
        exe.display()
    ))
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
        broker_command(&system_powershell()?, exe, base_dir, vars)?,
        BROKER_BOUND,
    )
    .map_err(|error| with_download_hint(error, exe))
}
