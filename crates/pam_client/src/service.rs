//! Login-start integration for the daemon: one user-scope unit per
//! platform (macOS `LaunchAgent`, systemd user unit, Windows per-user
//! scheduled task), rendered and managed here, shared by
//! `pam service …` and the GUI bridge.
//!
//! Every OS call goes through [`Runner`], so tests drive all three
//! platforms on any host with a fake; the platform managers are compiled
//! everywhere and selected by [`ServiceEnv::platform`]. Never sudo,
//! admin, or root (spine spec: user scope only).
//!
//! Install semantics: stop a loose daemon first (bounded, through
//! [`crate::client::stop_daemon`]) so the managed instance takes over,
//! write the unit, register and start it. Uninstall unregisters and
//! removes the unit; it never stops the daemon. `pam daemon` exits 0 on
//! `already running`, so a manager never restart-loops against a loose
//! instance.

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
/// systemd user unit file name.
pub const SYSTEMD_UNIT: &str = "pam-daemon.service";
/// Windows Task Scheduler task path.
pub const WINDOWS_TASK: &str = r"pam\daemon";
/// How long `install` waits for a loose daemon to drain before the
/// managed instance is started.
pub const STOP_WAIT: Duration = Duration::from_secs(15);

/// The platforms with a login-start manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// macOS, managed with a `LaunchAgent`.
    Macos,
    /// Linux, managed with a systemd user unit.
    Linux,
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
        } else if cfg!(target_os = "linux") {
            Self::Linux
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
            Self::Linux => "linux",
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
    /// (launchd print / systemctl is-active / task exists).
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
    /// The `pam` binary the unit runs.
    pub exe: PathBuf,
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
    /// whether `base` is an override of `~/.pam`.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NoHome`] when the home directory is unknown,
    /// [`ServiceError::NoExe`] when `current_exe` fails.
    pub fn detect(base: &Path) -> Result<Self, ServiceError> {
        let home = std::env::home_dir().ok_or(ServiceError::NoHome)?;
        let exe = std::env::current_exe().map_err(ServiceError::NoExe)?;
        let base_override = (base != home.join(".pam")).then(|| base.to_path_buf());
        Ok(Self {
            platform: Platform::current(),
            exe,
            home,
            base: base.to_path_buf(),
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
    let log = xml_escape(&log_dir.join("launchd.log").display().to_string());
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

/// The systemd user unit: restart on failure only, part of the user's
/// default target.
#[must_use]
pub fn render_systemd_unit(exe: &Path, base_override: Option<&Path>) -> String {
    let mut unit = String::new();
    unit.push_str(
        "[Unit]\nDescription=pam daemon (local lifeguard for developers and AI agents)\n\n",
    );
    unit.push_str("[Service]\n");
    let _ = writeln!(unit, "ExecStart=\"{}\" daemon", exe.display());
    unit.push_str("Restart=on-failure\nRestartSec=2\n");
    if let Some(base) = base_override {
        let _ = writeln!(unit, "Environment=PAM_BASE_DIR={}", base.display());
    }
    unit.push_str("\n[Install]\nWantedBy=default.target\n");
    unit
}

/// The scheduled task's action: `conhost.exe --headless` runs the console
/// binary without a window.
#[must_use]
pub fn windows_task_action(exe: &Path) -> String {
    format!("conhost.exe --headless \"{}\" daemon", exe.display())
}

// --- managers ---------------------------------------------------------------

/// Where the unit lives, per platform.
fn unit_path(env: &ServiceEnv) -> PathBuf {
    match env.platform {
        Platform::Macos => env
            .home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist")),
        Platform::Linux => env.home.join(".config/systemd/user").join(SYSTEMD_UNIT),
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
        state,
        note,
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
        Platform::Linux => {
            if unit.is_file() {
                let loaded = probe(
                    runner,
                    "systemctl",
                    &args(&["--user", "is-active", SYSTEMD_UNIT]),
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
            if probe(runner, "schtasks", &args(&["/Query", "/TN", WINDOWS_TASK]))? {
                ServiceState::Installed {
                    unit: WINDOWS_TASK.to_owned(),
                    loaded: true,
                }
            } else {
                ServiceState::NotInstalled {
                    unit: WINDOWS_TASK.to_owned(),
                }
            }
        }
        Platform::Other => unreachable!("filtered by unsupported()"),
    };
    Ok(report(env, state, None))
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

/// Writes the `LaunchAgent` and hands it to launchd.
fn install_macos(env: &ServiceEnv, runner: &dyn Runner, unit: &Path) -> Result<(), ServiceError> {
    let uid = macos_uid(runner)?;
    let log_dir = env.base.join("log");
    write_unit(
        unit,
        &render_launch_agent(&env.exe, &log_dir, env.base_override.as_deref()),
    )?;
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

/// Writes the systemd user unit and enables it now.
fn install_linux(env: &ServiceEnv, runner: &dyn Runner, unit: &Path) -> Result<(), ServiceError> {
    write_unit(
        unit,
        &render_systemd_unit(&env.exe, env.base_override.as_deref()),
    )?;
    must(runner, "systemctl", &args(&["--user", "daemon-reload"]))?;
    must(
        runner,
        "systemctl",
        &args(&["--user", "enable", "--now", SYSTEMD_UNIT]),
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
    let note = stop_note(stop, &env.base)?;
    let unit = unit_path(env);
    let unit_name = unit.display().to_string();
    match env.platform {
        Platform::Macos => install_macos(env, runner, &unit)?,
        Platform::Linux => install_linux(env, runner, &unit)?,
        Platform::Windows => install_windows(env, runner)?,
        Platform::Other => unreachable!("filtered by unsupported()"),
    }
    Ok(report(
        env,
        ServiceState::Installed {
            unit: unit_name,
            loaded: true,
        },
        note,
    ))
}

/// Unregisters and removes the unit. Never stops a running daemon.
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
        Platform::Linux => {
            let _ = probe(
                runner,
                "systemctl",
                &args(&["--user", "disable", "--now", SYSTEMD_UNIT]),
            )?;
            remove_unit(&unit)?;
            let _ = probe(runner, "systemctl", &args(&["--user", "daemon-reload"]))?;
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
        None,
    ))
}
