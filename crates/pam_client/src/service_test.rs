use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};

use tempfile::TempDir;

use crate::client::{StopError, StopOutcome};
use crate::service::{
    LAUNCHD_LABEL, Platform, Runner, SYSTEMD_UNIT, ServiceEnv, ServiceError, ServiceState, StopFn,
    WINDOWS_TASK, install_with, render_launch_agent, render_systemd_unit, status, uninstall,
    windows_task_action,
};

#[test]
fn launch_agent_runs_the_daemon_at_load_and_restarts_only_on_crash() {
    let plist = render_launch_agent(
        Path::new("/Applications/pam.app/Contents/MacOS/pam"),
        Path::new("/Users/me/.pam/log"),
        None,
    );
    assert!(plist.contains(&format!("<string>{LAUNCHD_LABEL}</string>")));
    assert!(plist.contains("<string>/Applications/pam.app/Contents/MacOS/pam</string>"));
    assert!(plist.contains("<string>daemon</string>"));
    assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
    assert!(plist.contains("<key>SuccessfulExit</key>\n\t\t<false/>"));
    assert!(plist.contains("<string>/Users/me/.pam/log/launchd.log</string>"));
    assert!(!plist.contains("PAM_BASE_DIR"));
}

#[test]
fn launch_agent_carries_the_base_override_and_escapes_xml() {
    let plist = render_launch_agent(
        Path::new("/tmp/a&b/pam"),
        Path::new("/tmp/x/log"),
        Some(Path::new("/tmp/x")),
    );
    assert!(plist.contains("<string>/tmp/a&amp;b/pam</string>"));
    assert!(plist.contains("<key>PAM_BASE_DIR</key>\n\t\t<string>/tmp/x</string>"));
}

#[test]
fn systemd_unit_restarts_on_failure_and_wants_default_target() {
    let unit = render_systemd_unit(Path::new("/home/me/.local/bin/pam"), None);
    assert!(unit.contains("ExecStart=\"/home/me/.local/bin/pam\" daemon\n"));
    assert!(unit.contains("Restart=on-failure\n"));
    assert!(unit.contains("WantedBy=default.target\n"));
    assert!(!unit.contains("Environment="));
    let with_base = render_systemd_unit(Path::new("/opt/pam"), Some(Path::new("/srv/pam")));
    assert!(with_base.contains("Environment=PAM_BASE_DIR=/srv/pam\n"));
}

#[test]
fn windows_task_runs_headless() {
    assert_eq!(
        windows_task_action(Path::new(r"C:\Users\me\AppData\Local\pam\pam.exe")),
        r#"conhost.exe --headless "C:\Users\me\AppData\Local\pam\pam.exe" daemon"#
    );
}

/// An [`ExitStatus`] carrying `code`, on either host family, so these
/// tests run on every target the crate is built for.
#[cfg(unix)]
fn exit(code: i32) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;

    ExitStatus::from_raw(code << 8)
}

/// An [`ExitStatus`] carrying `code`, on either host family, so these
/// tests run on every target the crate is built for.
#[cfg(windows)]
fn exit(code: i32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt as _;

    ExitStatus::from_raw(u32::try_from(code).expect("exit codes here are not negative"))
}

/// Records every call and answers from a table keyed by
/// `"<program> <first arg>"`; unknown calls succeed with empty output.
#[derive(Default)]
struct FakeRunner {
    calls: RefCell<Vec<String>>,
    answers: Vec<(&'static str, i32, &'static str, &'static str)>, // key, code, stdout, stderr
}

impl FakeRunner {
    fn answer(
        mut self,
        key: &'static str,
        code: i32,
        stdout: &'static str,
        stderr: &'static str,
    ) -> Self {
        self.answers.push((key, code, stdout, stderr));
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, program: &str, args: &[OsString]) -> io::Result<Output> {
        let rendered: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let line = format!("{program} {}", rendered.join(" "));
        self.calls.borrow_mut().push(line.clone());
        let key = format!("{program} {}", rendered.first().map_or("", String::as_str));
        let (code, out, err) = self
            .answers
            .iter()
            .find(|(k, ..)| *k == key)
            .map_or((0, "", ""), |(_, c, o, e)| (*c, *o, *e));
        Ok(Output {
            status: exit(code),
            stdout: out.as_bytes().to_vec(),
            stderr: err.as_bytes().to_vec(),
        })
    }
}

fn env(platform: Platform, home: &Path) -> ServiceEnv {
    ServiceEnv {
        platform,
        exe: PathBuf::from("/opt/pam/pam"),
        home: home.to_path_buf(),
        base: home.join(".pam"),
        base_override: None,
    }
}

/// The stop step for tests that do not care about it: nothing was
/// running, so nothing was stopped.
const NOT_RUNNING: StopFn<'static> = &|_| Ok(StopOutcome::NotRunning);

#[test]
fn macos_install_writes_the_plist_then_bootstraps_it() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let report = install_with(&env(Platform::Macos, home.path()), &runner, NOT_RUNNING).unwrap();
    let plist = home
        .path()
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    assert!(plist.is_file());
    assert_eq!(
        report.state,
        ServiceState::Installed {
            unit: plist.display().to_string(),
            loaded: true
        }
    );
    assert_eq!(
        runner.calls(),
        vec![
            "id -u".to_owned(),
            format!("launchctl bootout gui/501/{LAUNCHD_LABEL}"),
            format!("launchctl bootstrap gui/501 {}", plist.display()),
        ]
    );
}

#[test]
fn macos_status_reads_the_plist_and_asks_launchctl() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let absent = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let plist = home
        .path()
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    assert_eq!(
        status(&e, &absent).unwrap().state,
        ServiceState::NotInstalled {
            unit: plist.display().to_string()
        }
    );
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "x").unwrap();
    let unloaded = FakeRunner::default()
        .answer("id -u", 0, "501\n", "")
        .answer("launchctl print", 3, "", "Could not find service");
    assert_eq!(
        status(&e, &unloaded).unwrap().state,
        ServiceState::Installed {
            unit: plist.display().to_string(),
            loaded: false
        }
    );
}

#[test]
fn macos_uninstall_boots_out_and_removes_the_plist() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let plist = home
        .path()
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
    std::fs::write(&plist, "x").unwrap();
    let runner = FakeRunner::default().answer("id -u", 0, "501\n", "");
    let report = uninstall(&e, &runner).unwrap();
    assert!(!plist.exists());
    assert_eq!(
        report.state,
        ServiceState::NotInstalled {
            unit: plist.display().to_string()
        }
    );
    assert_eq!(
        runner.calls()[1],
        format!("launchctl bootout gui/501/{LAUNCHD_LABEL}")
    );
}

#[test]
fn linux_install_reloads_then_enables_now() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default();
    let report = install_with(&env(Platform::Linux, home.path()), &runner, NOT_RUNNING).unwrap();
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    assert!(
        std::fs::read_to_string(&unit)
            .unwrap()
            .contains("ExecStart=\"/opt/pam/pam\" daemon")
    );
    assert_eq!(
        report.state,
        ServiceState::Installed {
            unit: unit.display().to_string(),
            loaded: true
        }
    );
    assert_eq!(
        runner.calls(),
        vec![
            "systemctl --user daemon-reload".to_owned(),
            format!("systemctl --user enable --now {SYSTEMD_UNIT}"),
        ]
    );
}

#[test]
fn linux_status_asks_is_active() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Linux, home.path());
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "x").unwrap();
    let inactive = FakeRunner::default().answer("systemctl --user", 3, "inactive\n", "");
    assert_eq!(
        status(&e, &inactive).unwrap().state,
        ServiceState::Installed {
            unit: unit.display().to_string(),
            loaded: false
        }
    );
    assert_eq!(
        inactive.calls(),
        vec![format!("systemctl --user is-active {SYSTEMD_UNIT}")]
    );
}

#[test]
fn linux_uninstall_disables_removes_reloads() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Linux, home.path());
    let unit = home.path().join(".config/systemd/user").join(SYSTEMD_UNIT);
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    std::fs::write(&unit, "x").unwrap();
    let runner = FakeRunner::default();
    uninstall(&e, &runner).unwrap();
    assert!(!unit.exists());
    assert_eq!(
        runner.calls(),
        vec![
            format!("systemctl --user disable --now {SYSTEMD_UNIT}"),
            "systemctl --user daemon-reload".to_owned(),
        ]
    );
}

#[test]
fn windows_install_creates_the_logon_task_and_runs_it() {
    let home = TempDir::new().unwrap();
    let mut e = env(Platform::Windows, home.path());
    e.exe = PathBuf::from(r"C:\pam\pam.exe");
    let runner = FakeRunner::default();
    let report = install_with(&e, &runner, NOT_RUNNING).unwrap();
    assert_eq!(
        report.state,
        ServiceState::Installed {
            unit: WINDOWS_TASK.to_owned(),
            loaded: true
        }
    );
    assert_eq!(
        runner.calls(),
        vec![
            format!(
                r#"schtasks /Create /F /SC ONLOGON /RL LIMITED /TN {WINDOWS_TASK} /TR conhost.exe --headless "C:\pam\pam.exe" daemon"#
            ),
            format!("schtasks /Run /TN {WINDOWS_TASK}"),
        ]
    );
}

#[test]
fn windows_refuses_a_base_override() {
    let home = TempDir::new().unwrap();
    let mut e = env(Platform::Windows, home.path());
    e.base_override = Some(PathBuf::from(r"D:\pam"));
    let report = status(&e, &FakeRunner::default()).unwrap();
    assert!(
        matches!(report.state, ServiceState::Unsupported { ref reason } if reason.contains("PAM_BASE_DIR"))
    );
    let report = install_with(&e, &FakeRunner::default(), NOT_RUNNING).unwrap();
    assert!(matches!(report.state, ServiceState::Unsupported { .. }));
}

#[test]
fn other_platforms_are_unsupported() {
    let home = TempDir::new().unwrap();
    let report = status(&env(Platform::Other, home.path()), &FakeRunner::default()).unwrap();
    assert!(matches!(report.state, ServiceState::Unsupported { .. }));
}

#[test]
fn a_failing_manager_command_is_legible() {
    let home = TempDir::new().unwrap();
    let runner =
        FakeRunner::default().answer("systemctl --user", 1, "", "Failed to connect to bus\n");
    let err = install_with(&env(Platform::Linux, home.path()), &runner, NOT_RUNNING).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("systemctl --user daemon-reload"), "{text}");
    assert!(text.contains("Failed to connect to bus"), "{text}");
    assert!(matches!(err, ServiceError::Command { .. }));
}

#[test]
fn install_stops_a_loose_daemon_first_and_says_so() {
    let home = TempDir::new().unwrap();
    let stopped =
        |_: &Path| -> Result<StopOutcome, StopError> { Ok(StopOutcome::Stopped { pid: 4242 }) };
    let report = install_with(
        &env(Platform::Linux, home.path()),
        &FakeRunner::default(),
        &stopped,
    )
    .unwrap();
    assert_eq!(
        report.note.as_deref(),
        Some("stopped the running daemon (pid 4242) so the managed one takes over")
    );
    let unsupported = |_: &Path| -> Result<StopOutcome, StopError> { Err(StopError::Unsupported) };
    let report = install_with(
        &env(Platform::Linux, home.path()),
        &FakeRunner::default(),
        &unsupported,
    )
    .unwrap();
    assert!(report.note.as_deref().unwrap().contains("keeps running"));
}
