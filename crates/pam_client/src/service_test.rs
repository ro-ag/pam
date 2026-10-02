use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};

use tempfile::TempDir;

use crate::client::{StopError, StopOutcome};
use crate::service::{
    LAUNCHD_LABEL, MANAGED_STOPPED_NOTE, Platform, Runner, ServiceEnv, ServiceError, ServiceState,
    StopFn, WINDOWS_TASK, install_with, pinned_exe_from_plist, render_launch_agent, status,
    uninstall, unsafe_exe_reason_with, windows_task_action, windows_task_loaded,
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
    assert_eq!(report.note.as_deref(), Some(MANAGED_STOPPED_NOTE));
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
fn windows_status_reads_the_task_status_column() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Windows, home.path());
    let ready = FakeRunner::default().answer(
        "schtasks /Query",
        0,
        "\r\nFolder: \\pam\r\nHostName:      BOX\r\nTaskName:      \\pam\\daemon\r\nStatus:        Ready\r\n",
        "",
    );
    assert_eq!(
        status(&e, &ready).unwrap().state,
        ServiceState::Installed {
            unit: WINDOWS_TASK.to_owned(),
            loaded: true
        }
    );
    assert_eq!(
        ready.calls(),
        vec![format!("schtasks /Query /TN {WINDOWS_TASK} /FO LIST")]
    );
    let disabled = FakeRunner::default().answer(
        "schtasks /Query",
        0,
        "TaskName:      \\pam\\daemon\r\nStatus:        Disabled\r\n",
        "",
    );
    assert_eq!(
        status(&e, &disabled).unwrap().state,
        ServiceState::Installed {
            unit: WINDOWS_TASK.to_owned(),
            loaded: false
        }
    );
    let missing = FakeRunner::default().answer(
        "schtasks /Query",
        1,
        "",
        "ERROR: The system cannot find the file specified.\r\n",
    );
    assert_eq!(
        status(&e, &missing).unwrap().state,
        ServiceState::NotInstalled {
            unit: WINDOWS_TASK.to_owned()
        }
    );
}

#[test]
fn windows_task_status_parses_ready_running_disabled_and_garbage() {
    assert!(windows_task_loaded("Status:        Ready\r\n"));
    assert!(windows_task_loaded("status: running\n"));
    assert!(!windows_task_loaded("Status:        Disabled\r\n"));
    assert!(!windows_task_loaded("Status:        Could not start\r\n"));
    assert!(!windows_task_loaded("TaskName: \\pam\\daemon\r\n"));
    assert!(!windows_task_loaded(""));
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
    let other = env(Platform::Other, home.path());
    let runner = FakeRunner::default();
    // Linux has no manager here any more: it lands on `Other`, and every
    // operation refuses with a stated reason instead of touching the host.
    let reports = [
        status(&other, &runner).unwrap(),
        install_with(&other, &runner, NOT_RUNNING).unwrap(),
        uninstall(&other, &runner).unwrap(),
    ];
    for report in reports {
        assert!(
            matches!(report.state, ServiceState::Unsupported { ref reason } if reason.contains("no login-start integration")),
            "{report:?}"
        );
    }
    assert!(runner.calls().is_empty());
}

#[test]
fn a_failing_manager_command_is_legible() {
    let home = TempDir::new().unwrap();
    let runner = FakeRunner::default()
        .answer("id -u", 0, "501\n", "")
        .answer("launchctl bootstrap", 5, "", "Bootstrap failed: 5\n");
    let err = install_with(&env(Platform::Macos, home.path()), &runner, NOT_RUNNING).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("launchctl bootstrap gui/501"), "{text}");
    assert!(text.contains("Bootstrap failed: 5"), "{text}");
    assert!(matches!(err, ServiceError::Command { .. }));
}

#[test]
fn install_stops_a_loose_daemon_first_and_says_so() {
    let home = TempDir::new().unwrap();
    let stopped =
        |_: &Path| -> Result<StopOutcome, StopError> { Ok(StopOutcome::Stopped { pid: 4242 }) };
    let report = install_with(
        &env(Platform::Macos, home.path()),
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
        &env(Platform::Macos, home.path()),
        &FakeRunner::default(),
        &unsupported,
    )
    .unwrap();
    assert!(report.note.as_deref().unwrap().contains("keeps running"));
}

// --- what may be pinned, and in what order (finding 10) ----------------------

#[test]
fn a_binary_in_a_scratch_or_build_directory_is_never_pinned() {
    let scratch = vec![PathBuf::from("/tmp"), PathBuf::from("/var/folders")];
    for exe in [
        "/tmp/agent-built/pam",
        "/var/folders/ab/cd/T/pam",
        "/home/me/src/pam/target/debug/pam",
        "/home/me/src/pam/target/aarch64-apple-darwin/release/pam",
    ] {
        assert!(
            unsafe_exe_reason_with(Path::new(exe), &scratch).is_some(),
            "{exe} must be refused"
        );
    }
    for exe in [
        "/opt/pam/pam",
        "/Applications/pam.app/Contents/MacOS/pam",
        "/home/me/.local/bin/pam",
        // `target` alone is a legitimate directory name outside a cargo layout.
        "/srv/target/pam",
    ] {
        assert_eq!(
            unsafe_exe_reason_with(Path::new(exe), &scratch),
            None,
            "{exe} is a stable install location"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_group_or_world_writable_binary_or_directory_is_never_pinned() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let exe = dir.path().join("pam");
    std::fs::write(&exe, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        unsafe_exe_reason_with(&exe, &[]),
        None,
        "owner-only write is fine"
    );

    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o775)).unwrap();
    let reason = unsafe_exe_reason_with(&exe, &[]).expect("group-writable file");
    assert!(reason.contains("writable"), "{reason}");

    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let reason = unsafe_exe_reason_with(&exe, &[]).expect("world-writable directory");
    assert!(reason.contains("directory"), "{reason}");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A refused install changes nothing: no unit is written, nothing is
/// stopped, no manager command runs.
#[test]
fn install_refuses_an_unsafe_binary_before_touching_anything() {
    let home = TempDir::new().unwrap();
    let mut e = env(Platform::Macos, home.path());
    e.exe = std::env::temp_dir().join("agent-built").join("pam");
    let runner = FakeRunner::default();
    let stopped = |_: &Path| -> Result<StopOutcome, StopError> {
        panic!("a refused install must not stop the running daemon")
    };
    let error = install_with(&e, &runner, &stopped).expect_err("a temp-dir binary is refused");
    assert!(matches!(error, ServiceError::UnsafeExe { .. }), "{error:?}");
    assert!(error.to_string().contains("temporary directory"), "{error}");
    assert!(error.recovery().contains("pam service install"));
    assert!(runner.calls().is_empty());
    assert!(!home.path().join("Library/LaunchAgents").exists());
}

/// The unit goes to disk **before** the loose daemon is stopped, so a failed
/// write cannot leave the machine with no daemon.
#[test]
fn a_failed_unit_write_never_stops_the_running_daemon() {
    let home = TempDir::new().unwrap();
    // The unit's parent path is a regular file: create_dir_all fails.
    std::fs::write(home.path().join("Library"), "not a directory").unwrap();
    let stopped = |_: &Path| -> Result<StopOutcome, StopError> {
        panic!("the daemon must keep running when the unit cannot be written")
    };
    let error = install_with(
        &env(Platform::Macos, home.path()),
        &FakeRunner::default(),
        &stopped,
    )
    .expect_err("the write fails");
    assert!(matches!(error, ServiceError::Write { .. }), "{error:?}");
}

#[test]
fn install_writes_the_unit_then_stops_the_daemon_then_registers() {
    use std::cell::RefCell;
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let unit = home
        .path()
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    let order = RefCell::new(Vec::new());
    let stopped = |_: &Path| -> Result<StopOutcome, StopError> {
        order
            .borrow_mut()
            .push(format!("stop (unit written: {})", unit.is_file()));
        Ok(StopOutcome::NotRunning)
    };
    let runner = FakeRunner::default();
    install_with(&e, &runner, &stopped).unwrap();
    assert_eq!(
        *order.borrow(),
        vec!["stop (unit written: true)".to_owned()]
    );
    assert_eq!(
        runner.calls()[0],
        "id -u",
        "registration comes after the stop"
    );
}

// --- the base override is explicit only (finding 10) -------------------------

#[test]
fn the_unit_carries_a_base_override_only_when_one_was_requested() {
    let default = ServiceEnv::detect(None).expect("home resolves");
    assert_eq!(default.base_override, None);
    assert_eq!(default.base, default.home.join(".pam"));
    let same = ServiceEnv::detect(Some(&default.base)).unwrap();
    assert_eq!(
        same.base_override, None,
        "asking for the default is not an override"
    );
    let pinned = ServiceEnv::detect(Some(Path::new("/srv/pam-base"))).unwrap();
    assert_eq!(
        pinned.base_override.as_deref(),
        Some(Path::new("/srv/pam-base"))
    );
    assert_eq!(pinned.base, Path::new("/srv/pam-base"));
}

// --- status reports a stale pinned executable (finding 10) -------------------

#[test]
fn the_pinned_executable_is_read_back_from_the_launch_agent() {
    let plist = render_launch_agent(
        Path::new("/Applications/a&b/pam.app/Contents/MacOS/pam"),
        Path::new("/Users/me/.pam/log"),
        None,
    );
    assert_eq!(
        pinned_exe_from_plist(&plist).as_deref(),
        Some(Path::new("/Applications/a&b/pam.app/Contents/MacOS/pam"))
    );
}

#[test]
fn status_names_a_pinned_binary_that_is_missing_or_not_this_one() {
    let home = TempDir::new().unwrap();
    let e = env(Platform::Macos, home.path());
    let unit = home
        .path()
        .join("Library/LaunchAgents")
        .join(format!("{LAUNCHD_LABEL}.plist"));
    std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
    let log_dir = Path::new("/Users/me/.pam/log");

    // Pinned to a binary that no longer exists.
    std::fs::write(
        &unit,
        render_launch_agent(Path::new("/gone/forever/pam"), log_dir, None),
    )
    .unwrap();
    let report = status(&e, &FakeRunner::default()).unwrap();
    assert_eq!(
        report.pinned_exe.as_deref(),
        Some(Path::new("/gone/forever/pam"))
    );
    let stale = report.stale.expect("a missing pinned binary is stale");
    assert!(stale.contains("no longer exists"), "{stale}");

    // Pinned to a real binary that is not the running one.
    let other = home.path().join("other-pam");
    std::fs::write(&other, "x").unwrap();
    std::fs::write(&unit, render_launch_agent(&other, log_dir, None)).unwrap();
    let report = status(&e, &FakeRunner::default()).unwrap();
    assert!(
        report
            .stale
            .as_deref()
            .is_some_and(|text| text.contains("not this binary")),
        "{:?}",
        report.stale
    );

    // Pinned to the running binary: not stale.
    let running = home.path().join("running-pam");
    std::fs::write(&running, "x").unwrap();
    let mut current = env(Platform::Macos, home.path());
    current.exe = running.clone();
    std::fs::write(&unit, render_launch_agent(&running, log_dir, None)).unwrap();
    let report = status(&current, &FakeRunner::default()).unwrap();
    assert_eq!(report.pinned_exe.as_deref(), Some(running.as_path()));
    assert_eq!(report.stale, None);
}
