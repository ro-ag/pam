//! Login-start integration for the daemon: one user-scope unit per platform (macOS `LaunchAgent`,
//! Windows per-user scheduled task), rendered and managed here, shared by `pam
//! service …` and the GUI bridge. Every OS call goes through [`Runner`], so tests drive both
//! platforms on any host with a fake; platform managers are compiled everywhere and selected by
//! [`ServiceEnv::platform`]. Never sudo, admin, or root — user scope only.
//!
//! Install semantics: refuse to pin a binary that must not run at every login
//! ([`unsafe_exe_reason`]: a temp dir, a cargo `target/` dir, a group- or world-writable file or
//! directory), write the unit **first** (a failed write leaves the running daemon alone), then stop a
//! loose daemon (bounded, through [`crate::client::stop_daemon`]) so the managed instance takes
//! over, then register and start it. The unit carries a `PAM_BASE_DIR` only when the caller asked
//! for one explicitly (`pam service install --base-dir`), never because the environment happened to
//! hold one: an agent-set variable must not outlive the shell it was set in. `status` reports a
//! pinned executable that is missing or is not the running binary. Uninstall unregisters
//! and removes the unit; on macOS the manager also stops the managed daemon (`launchctl
//! bootout`), and the next pam command starts one lazily. `pam daemon`
//! exits 0 on `already running`, so a manager never restart-loops against a loose instance.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;

use crate::client::{self, StopError, StopOutcome};

/// launchd label and plist file stem.
pub const LAUNCHD_LABEL: &str = "com.github.ro-ag.pam.daemon";
/// Windows Task Scheduler task path.
pub const WINDOWS_TASK: &str = r"pam\daemon";
/// How long `install` waits for a loose daemon to drain before the
/// managed instance is started.
pub const STOP_WAIT: Duration = Duration::from_secs(15);
/// The uninstall report's note on macOS, where unregistering
/// the unit also stops the daemon it was running.
pub const MANAGED_STOPPED_NOTE: &str = "the manager stopped the managed daemon along with its unit; the next pam command starts one lazily";

/// The platforms with a login-start manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// macOS, managed with a `LaunchAgent`.
    Macos,
    /// Windows, managed with a per-user scheduled task.
    Windows,
    /// Anything else: no login-start integration.
    Other,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }

    /// Lowercase name, as the report prints it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Other => "other",
        }
    }
}

/// Whether the unit exists and whether its manager reports it loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceState {
    /// The unit is registered; `loaded` is the manager's own verdict
    /// (launchd print / task exists).
    Installed {
        /// Unit file path, or the task name on Windows.
        unit: String,
        /// The manager's verdict on whether the unit is live.
        loaded: bool,
    },
    /// No unit at the path (or task name) the platform uses.
    NotInstalled {
        /// Where the unit would live.
        unit: String,
    },
    /// This platform or configuration has no login-start integration.
    Unsupported {
        /// Why, in one sentence for the human.
        reason: String,
    },
}

/// What every service command answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceReport {
    /// Lowercase platform name ([`Platform::as_str`]).
    pub platform: &'static str,
    /// The `pam` binary this process is (what `install` pins).
    pub exe: PathBuf,
    /// The executable the installed unit actually runs, read back from the
    /// unit file; `None` when there is no unit or the platform's task
    /// manager does not expose it.
    pub pinned_exe: Option<PathBuf>,
    /// Why the pinned executable is stale (missing, or not this binary);
    /// `None` when it matches or cannot be read.
    pub stale: Option<String>,
    /// Where the unit stands after the command.
    pub state: ServiceState,
    /// Something the human should know (a loose daemon was stopped, or
    /// could not be), never an error.
    pub note: Option<String>,
}

/// Everything the managers need from the process, resolved once by the
/// caller so the module never reads the environment itself.
#[derive(Debug, Clone)]
pub struct ServiceEnv {
    /// Which manager to drive.
    pub platform: Platform,
    /// Absolute path of the `pam` binary the unit will run.
    pub exe: PathBuf,
    /// The user's home directory, where user-scope units live.
    pub home: PathBuf,
    /// The base dir in use (`~/.pam` or `$PAM_BASE_DIR`).
    pub base: PathBuf,
    /// Set only when `$PAM_BASE_DIR` overrides the default.
    pub base_override: Option<PathBuf>,
}

impl ServiceEnv {
    /// Resolves the current process: platform, `current_exe`, home, and
    /// the base the managed daemon will use.
    ///
    /// `requested_base` is a base the **caller asked for** (the CLI's
    /// `--base-dir`, or the GUI's own resolved base); `None` means the
    /// default `~/.pam`. Only an explicit request that differs from the
    /// default becomes a `PAM_BASE_DIR` in the unit — the process
    /// environment is deliberately not consulted here.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NoHome`] when the home directory is unknown,
    /// [`ServiceError::NoExe`] when `current_exe` fails.
    pub fn detect(requested_base: Option<&Path>) -> Result<Self, ServiceError> {
        let home = std::env::home_dir().ok_or(ServiceError::NoHome)?;
        let exe = std::env::current_exe().map_err(ServiceError::NoExe)?;
        let default = home.join(".pam");
        let base = requested_base.map_or_else(|| default.clone(), Path::to_path_buf);
        let base_override = (base != default).then(|| base.clone());
        Ok(Self {
            platform: Platform::current(),
            exe,
            home,
            base,
            base_override,
        })
    }
}

/// Runs one external command and returns its output. The real one is
/// [`CommandRunner`]; tests inject a fake.
pub trait Runner {
    /// # Errors
    ///
    /// Whatever spawning the program produced.
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output>;
}

/// [`Runner`] over `std::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRunner;

impl Runner for CommandRunner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

/// How `install` stops a loose daemon; injected so tests need no daemon.
pub type StopFn<'a> = &'a dyn Fn(&Path) -> Result<StopOutcome, StopError>;

/// Why a service command failed. Every variant names its recovery.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The home directory could not be resolved.
    #[error("cannot resolve the home directory")]
    NoHome,
    /// `current_exe` failed.
    #[error("cannot resolve the pam executable path: {0}")]
    NoExe(#[source] io::Error),
    /// The unit file (or its directory) could not be written.
    #[error("cannot write {path}: {source}")]
    Write {
        /// What could not be written.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The unit file could not be removed.
    #[error("cannot remove {path}: {source}")]
    Remove {
        /// What could not be removed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A manager tool could not be spawned.
    #[error("cannot run {program}: {source}")]
    Spawn {
        /// The program that could not be spawned.
        program: String,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A manager tool ran and refused.
    #[error("`{program} {args}` failed ({status}): {stderr}")]
    Command {
        /// The program that failed.
        program: String,
        /// Its arguments, as they were passed.
        args: String,
        /// Its exit status.
        status: String,
        /// Its trimmed stderr.
        stderr: String,
    },
    /// The platform has no login-start manager.
    #[error("{platform} has no login-start integration")]
    Unsupported {
        /// The platform that has none.
        platform: &'static str,
    },
    /// Stopping the loose daemon before the install failed.
    #[error("stopping the running daemon failed: {0}")]
    Stop(#[from] StopError),
    /// The executable `install` would pin into the login unit is somewhere
    /// a login-start binary must not live.
    #[error("refusing to pin {} into the login unit: {reason}", path.display())]
    UnsafeExe {
        /// The executable that would have been pinned.
        path: PathBuf,
        /// Why it is not acceptable.
        reason: String,
    },
}

impl ServiceError {
    /// One recovery line per failure family, for the CLI and the GUI.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::NoHome => "Set $HOME and retry.",
            Self::NoExe(_) => "Run pam from an installed location and retry.",
            Self::Write { .. } | Self::Remove { .. } => {
                "Check the permissions of the unit directory and retry."
            }
            Self::Spawn { .. } => "Install the platform's service manager tools and retry.",
            Self::Command { .. } => "Read the manager's message above; fix it and retry.",
            Self::Unsupported { .. } => "Start the daemon lazily instead: any pam command does.",
            Self::Stop(_) => "Stop the daemon with `pam daemon stop`, then retry.",
            Self::UnsafeExe { .. } => {
                "Install pam in a stable, user-owned location (the app bundle, or a directory only \
                 you can write) and run `pam service install` from that copy."
            }
        }
    }
}

// --- unit rendering ---------------------------------------------------------

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The `LaunchAgent` plist: run `exe daemon` at load, restart only on a
/// crash (a clean exit — `pam daemon stop`, or `already running` —
/// stays down), log launchd's own capture to `log_dir/launchd.log`.
#[must_use]
pub fn render_launch_agent(exe: &Path, log_dir: &Path, base_override: Option<&Path>) -> String {
    let exe = xml_escape(&exe.display().to_string());
    // A macOS path in a macOS plist: always `/`, whatever host renders it.
    let log = xml_escape(&format!("{}/launchd.log", log_dir.display()));
    let mut plist = String::new();
    plist.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    plist.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    plist.push_str("<plist version=\"1.0\">\n<dict>\n");
    let _ = writeln!(
        plist,
        "\t<key>Label</key>\n\t<string>{LAUNCHD_LABEL}</string>"
    );
    let _ = writeln!(
        plist,
        "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{exe}</string>\n\t\t<string>daemon</string>\n\t</array>"
    );
    plist.push_str("\t<key>RunAtLoad</key>\n\t<true/>\n");
    plist.push_str(
        "\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n",
    );
    plist.push_str("\t<key>ProcessType</key>\n\t<string>Background</string>\n");
    let _ = writeln!(
        plist,
        "\t<key>StandardOutPath</key>\n\t<string>{log}</string>"
    );
    let _ = writeln!(
        plist,
        "\t<key>StandardErrorPath</key>\n\t<string>{log}</string>"
    );
    if let Some(base) = base_override {
        let base = xml_escape(&base.display().to_string());
        let _ = writeln!(
            plist,
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>PAM_BASE_DIR</key>\n\t\t<string>{base}</string>\n\t</dict>"
        );
    }
    plist.push_str("</dict>\n</plist>\n");
    plist
}

/// Reads the `Status:` line of `schtasks /Query /FO LIST` output. A task
/// the scheduler will run at logon reports `Ready` (or `Running` while the
/// daemon is up); `Disabled` — and any status this parser does not know —
/// counts as not loaded, so a task nobody re-enabled is never reported as
/// armed.
#[must_use]
pub fn windows_task_loaded(query_output: &str) -> bool {
    query_output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("status"))
        .is_some_and(|(_, value)| {
            let value = value.trim();
            value.eq_ignore_ascii_case("ready") || value.eq_ignore_ascii_case("running")
        })
}

/// The scheduled task's action: `conhost.exe --headless` runs the console
/// binary without a window.
#[must_use]
pub fn windows_task_action(exe: &Path) -> String {
    format!("conhost.exe --headless \"{}\" daemon", exe.display())
}

// --- the pinned executable --------------------------------------------------

/// Directories whose contents are scratch space by convention, in addition
/// to the platform's [`std::env::temp_dir`].
const SCRATCH_ROOTS: [&str; 6] = [
    "/tmp",
    "/var/tmp",
    "/private/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// Why `exe` must not be pinned into a login unit, or `None` when it may be.
///
/// A login unit launches its binary unsandboxed at every login, so the
/// binary has to be one the human put there: not a build or scratch
/// artifact an agent could have produced (a temp dir, a cargo `target/`
/// directory) and not a file or directory that another account or group
/// could swap. A path that does not exist is not judged by its
/// permissions (there is nothing to stat); `status` reports a missing
/// pinned binary as stale instead.
#[must_use]
pub fn unsafe_exe_reason(exe: &Path) -> Option<String> {
    let temp = std::env::temp_dir();
    let mut scratch: Vec<PathBuf> = SCRATCH_ROOTS.iter().map(PathBuf::from).collect();
    scratch.push(temp.clone());
    scratch.extend(std::fs::canonicalize(&temp).ok());
    unsafe_exe_reason_with(exe, &scratch)
}

/// [`unsafe_exe_reason`] with the scratch roots injected.
#[must_use]
pub fn unsafe_exe_reason_with(exe: &Path, scratch_roots: &[PathBuf]) -> Option<String> {
    let canonical = std::fs::canonicalize(exe).ok();
    for candidate in std::iter::once(exe).chain(canonical.as_deref()) {
        if scratch_roots
            .iter()
            .any(|root| !root.as_os_str().is_empty() && candidate.starts_with(root))
        {
            return Some("it lives in a temporary directory".to_owned());
        }
        if in_cargo_target(candidate) {
            return Some("it is a cargo build artifact (a `target/` directory)".to_owned());
        }
    }
    writable_reason(canonical.as_deref().unwrap_or(exe))
}

/// True for `…/target/…/debug|release/…`: a cargo build output path.
fn in_cargo_target(path: &Path) -> bool {
    let names: Vec<&str> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect();
    names
        .iter()
        .position(|name| *name == "target")
        .is_some_and(|at| {
            names[at + 1..]
                .iter()
                .any(|name| matches!(*name, "debug" | "release"))
        })
}

/// Group- or world-writable executable or containing directory (unix).
#[cfg(unix)]
fn writable_reason(exe: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt as _;
    let loose = |path: &Path| {
        std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o022 != 0)
    };
    if loose(exe) {
        return Some("the file is writable by its group or by everyone".to_owned());
    }
    match exe.parent() {
        Some(dir) if loose(dir) => Some(format!(
            "its directory {} is writable by its group or by everyone",
            dir.display()
        )),
        _ => None,
    }
}

/// Windows ACLs are not inspected here.
#[cfg(not(unix))]
fn writable_reason(_exe: &Path) -> Option<String> {
    None
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The executable a `LaunchAgent` plist runs: the first `<string>` after
/// `ProgramArguments`.
#[must_use]
pub fn pinned_exe_from_plist(plist: &str) -> Option<PathBuf> {
    let after = plist.split_once("<key>ProgramArguments</key>")?.1;
    let start = after.split_once("<string>")?.1;
    let value = start.split_once("</string>")?.0;
    Some(PathBuf::from(xml_unescape(value)))
}

/// Whether the unit's pinned executable still matches this binary: `None`
/// when it does, else why not.
fn stale_reason(pinned: &Path, running: &Path) -> Option<String> {
    if !pinned.exists() {
        return Some(format!(
            "the unit runs {}, which no longer exists; run `pam service install` from the current binary",
            pinned.display()
        ));
    }
    let same = match (
        std::fs::canonicalize(pinned),
        std::fs::canonicalize(running),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => pinned == running,
    };
    (!same).then(|| {
        format!(
            "the unit runs {}, not this binary ({}); run `pam service install` to repoint it",
            pinned.display(),
            running.display()
        )
    })
}

// --- managers ---------------------------------------------------------------

/// Where the unit lives, per platform.
fn unit_path(env: &ServiceEnv) -> PathBuf {
    match env.platform {
        Platform::Macos => env
            .home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist")),
        Platform::Windows | Platform::Other => PathBuf::from(WINDOWS_TASK),
    }
}

fn args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

/// Runs a command that must succeed; a non-zero exit is a legible
/// [`ServiceError::Command`].
fn must(runner: &dyn Runner, program: &str, argv: &[OsString]) -> Result<Output, ServiceError> {
    let output = runner
        .run(program, argv)
        .map_err(|source| ServiceError::Spawn {
            program: program.to_owned(),
            source,
        })?;
    if output.status.success() {
        return Ok(output);
    }
    Err(ServiceError::Command {
        program: program.to_owned(),
        args: argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        status: output.status.to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

/// Runs a command whose failure is informational (a `bootout` of a unit
/// that is not loaded, an `is-active` that answers inactive).
fn probe(runner: &dyn Runner, program: &str, argv: &[OsString]) -> Result<bool, ServiceError> {
    runner
        .run(program, argv)
        .map(|output| output.status.success())
        .map_err(|source| ServiceError::Spawn {
            program: program.to_owned(),
            source,
        })
}

fn write_unit(path: &Path, body: &str) -> Result<(), ServiceError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| ServiceError::Write {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    std::fs::write(path, body).map_err(|source| ServiceError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn remove_unit(path: &Path) -> Result<(), ServiceError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ServiceError::Remove {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn report(env: &ServiceEnv, state: ServiceState, note: Option<String>) -> ServiceReport {
    ServiceReport {
        platform: env.platform.as_str(),
        exe: env.exe.clone(),
        pinned_exe: None,
        stale: None,
        state,
        note,
    }
}

/// [`report`] for an installed unit: reads the pinned executable back from
/// the unit text and says when it is stale.
fn installed_report(
    env: &ServiceEnv,
    state: ServiceState,
    unit_text: Option<&str>,
) -> ServiceReport {
    let pinned_exe = unit_text.and_then(|text| match env.platform {
        Platform::Macos => pinned_exe_from_plist(text),
        Platform::Windows | Platform::Other => None,
    });
    let stale_why = pinned_exe
        .as_deref()
        .and_then(|pinned| stale_reason(pinned, &env.exe));
    ServiceReport {
        pinned_exe,
        stale: stale_why,
        ..report(env, state, None)
    }
}

/// The reason a configuration cannot be managed, or `None`.
fn unsupported(env: &ServiceEnv) -> Option<String> {
    match env.platform {
        Platform::Other => Some(format!(
            "{} has no login-start integration",
            std::env::consts::OS
        )),
        Platform::Windows if env.base_override.is_some() => Some(
            "scheduled tasks carry no environment, so PAM_BASE_DIR cannot be honoured; \
             unset it to install the login task"
                .to_owned(),
        ),
        _ => None,
    }
}

fn macos_uid(runner: &dyn Runner) -> Result<String, ServiceError> {
    let output = must(runner, "id", &args(&["-u"]))?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Reports whether the unit is registered and loaded.
///
/// # Errors
///
/// Manager tools that cannot be spawned; a manager saying "no" is a state,
/// not an error.
pub fn status(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    let unit_text = std::fs::read_to_string(&unit).ok();
    let state = match env.platform {
        Platform::Macos => {
            if unit.is_file() {
                let uid = macos_uid(runner)?;
                let loaded = probe(
                    runner,
                    "launchctl",
                    &args(&["print", &format!("gui/{uid}/{LAUNCHD_LABEL}")]),
                )?;
                ServiceState::Installed {
                    unit: unit_name,
                    loaded,
                }
            } else {
                ServiceState::NotInstalled { unit: unit_name }
            }
        }
        Platform::Windows => {
            let output = runner
                .run(
                    "schtasks",
                    &args(&["/Query", "/TN", WINDOWS_TASK, "/FO", "LIST"]),
                )
                .map_err(|source| ServiceError::Spawn {
                    program: "schtasks".to_owned(),
                    source,
                })?;
            if output.status.success() {
                ServiceState::Installed {
                    unit: WINDOWS_TASK.to_owned(),
                    loaded: windows_task_loaded(&String::from_utf8_lossy(&output.stdout)),
                }
            } else {
                ServiceState::NotInstalled {
                    unit: WINDOWS_TASK.to_owned(),
                }
            }
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    };
    let text = matches!(state, ServiceState::Installed { .. })
        .then_some(unit_text.as_deref())
        .flatten();
    Ok(installed_report(env, state, text))
}

/// Registers the login-start unit and starts it now, stopping a loose
/// daemon first (bounded) so the managed instance takes over.
///
/// # Errors
///
/// Unit write failures, manager command failures, or a stop that failed
/// for a reason other than "not supported here".
pub fn install(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    install_with(env, runner, &|base| client::stop_daemon(base, STOP_WAIT))
}

/// What `install` says about a loose daemon that was in the way.
fn stop_note(stop: StopFn<'_>, base: &Path) -> Result<Option<String>, ServiceError> {
    match stop(base) {
        Ok(StopOutcome::NotRunning) => Ok(None),
        Ok(StopOutcome::Stopped { pid }) => Ok(Some(format!(
            "stopped the running daemon (pid {pid}) so the managed one takes over"
        ))),
        Ok(StopOutcome::StillDraining { pid }) => Ok(Some(format!(
            "the running daemon (pid {pid}) is still draining; the managed one takes over when it exits"
        ))),
        Err(StopError::Unsupported) => Ok(Some(
            "a daemon is already running and keeps running; the login task takes over at the next logon"
                .to_owned(),
        )),
        Err(err) => Err(ServiceError::Stop(err)),
    }
}

/// Writes the `LaunchAgent` file (nothing is registered yet).
fn write_macos_unit(env: &ServiceEnv, unit: &Path) -> Result<(), ServiceError> {
    let log_dir = env.base.join("log");
    write_unit(
        unit,
        &render_launch_agent(&env.exe, &log_dir, env.base_override.as_deref()),
    )
}

/// Hands the written `LaunchAgent` to launchd.
fn register_macos(runner: &dyn Runner, unit: &Path) -> Result<(), ServiceError> {
    let uid = macos_uid(runner)?;
    // A previous registration must go before bootstrap accepts the file again.
    let _ = probe(
        runner,
        "launchctl",
        &args(&["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]),
    )?;
    must(
        runner,
        "launchctl",
        &args(&[
            "bootstrap",
            &format!("gui/{uid}"),
            &unit.display().to_string(),
        ]),
    )?;
    Ok(())
}

/// Creates the per-user logon task and runs it now.
fn install_windows(env: &ServiceEnv, runner: &dyn Runner) -> Result<(), ServiceError> {
    let action = windows_task_action(&env.exe);
    must(
        runner,
        "schtasks",
        &args(&[
            "/Create",
            "/F",
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/TN",
            WINDOWS_TASK,
            "/TR",
            &action,
        ]),
    )?;
    let _ = probe(runner, "schtasks", &args(&["/Run", "/TN", WINDOWS_TASK]))?;
    Ok(())
}

/// [`install`] with the stop step injected.
///
/// The order is the safe one: validate the executable, **write** the unit,
/// stop the loose daemon, then register. A refusal or a failed write leaves
/// the running daemon untouched; only a unit that is already on disk
/// replaces it.
///
/// # Errors
///
/// See [`install`].
pub fn install_with(
    env: &ServiceEnv,
    runner: &dyn Runner,
    stop: StopFn<'_>,
) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    if let Some(reason) = unsafe_exe_reason(&env.exe) {
        return Err(ServiceError::UnsafeExe {
            path: env.exe.clone(),
            reason,
        });
    }
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    match env.platform {
        Platform::Macos => write_macos_unit(env, &unit)?,
        Platform::Windows | Platform::Other => {}
    }
    let note = stop_note(stop, &env.base)?;
    match env.platform {
        Platform::Macos => register_macos(runner, &unit)?,
        Platform::Windows => install_windows(env, runner)?,
        Platform::Other => unreachable!("filtered by unsupported()"),
    }
    let mut done = report(
        env,
        ServiceState::Installed {
            unit: unit_name,
            loaded: true,
        },
        note,
    );
    if env.platform == Platform::Macos {
        done.pinned_exe = Some(env.exe.clone());
    }
    Ok(done)
}

/// Unregisters and removes the unit. On macOS the manager
/// stops the managed daemon with it; the report's note says so, and the
/// next pam command starts one lazily. A loose daemon is never touched.
///
/// # Errors
///
/// Unit removal failures or manager tools that cannot be spawned.
pub fn uninstall(env: &ServiceEnv, runner: &dyn Runner) -> Result<ServiceReport, ServiceError> {
    if let Some(reason) = unsupported(env) {
        return Ok(report(env, ServiceState::Unsupported { reason }, None));
    }
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    let note = match env.platform {
        Platform::Macos => Some(MANAGED_STOPPED_NOTE.to_owned()),
        Platform::Windows | Platform::Other => None,
    };
    match env.platform {
        Platform::Macos => {
            let uid = macos_uid(runner)?;
            let _ = probe(
                runner,
                "launchctl",
                &args(&["bootout", &format!("gui/{uid}/{LAUNCHD_LABEL}")]),
            )?;
            remove_unit(&unit)?;
        }
        Platform::Windows => {
            let _ = probe(
                runner,
                "schtasks",
                &args(&["/Delete", "/TN", WINDOWS_TASK, "/F"]),
            )?;
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    }
    Ok(report(
        env,
        ServiceState::NotInstalled { unit: unit_name },
        note,
    ))
}
