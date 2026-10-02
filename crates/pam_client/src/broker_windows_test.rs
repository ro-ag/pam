//! The PowerShell broker that starts the daemon on Windows.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::broker_windows::{
    broker_command, powershell_path, run_broker, single_quoted, spawn_daemon, start_script,
};

#[test]
fn a_quote_in_a_path_is_doubled_and_a_line_break_is_refused() {
    assert_eq!(
        single_quoted(r"C:\Program Files\pam.exe").unwrap(),
        r"'C:\Program Files\pam.exe'"
    );
    assert_eq!(single_quoted("it's").unwrap(), "'it''s'");
    // PowerShell reads the typographic single quotes as quotes too.
    assert_eq!(
        single_quoted("a\u{2018}b\u{2019}c\u{201A}d\u{201B}e").unwrap(),
        "'a\u{2018}\u{2018}b\u{2019}\u{2019}c\u{201A}\u{201A}d\u{201B}\u{201B}e'"
    );
    for bad in ["a\nb", "a\rb", "a\0b"] {
        let error = single_quoted(bad).unwrap_err().to_string();
        assert!(error.contains("PowerShell"), "{error}");
    }
}

#[test]
fn the_script_starts_the_quoted_executable_hidden_with_the_daemon_argument() {
    assert_eq!(
        start_script(Path::new(r"C:\a b\o'k\pam.exe")).unwrap(),
        r"Start-Process -FilePath 'C:\a b\o''k\pam.exe' -ArgumentList 'daemon' -WindowStyle Hidden"
    );
}

#[test]
fn powershell_is_the_one_under_system32_never_a_path_search() {
    let path = powershell_path().expect("this host has Windows PowerShell");
    assert!(path.is_absolute() && path.is_file(), "{path:?}");
    assert!(
        path.to_string_lossy()
            .to_ascii_lowercase()
            .contains(r"\system32\windowspowershell\v1.0\powershell.exe"),
        "{path:?}"
    );
}

#[test]
fn a_broker_that_fails_or_hangs_is_a_legible_error_naming_powershell() {
    let mut failing = Command::new("cmd");
    failing.args(["/c", "exit 3"]);
    let error = run_broker(failing, Duration::from_secs(20))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("PowerShell") && error.contains('3'),
        "{error}"
    );

    let mut hanging = Command::new("cmd");
    hanging.args(["/c", "ping -n 60 127.0.0.1 > nul"]);
    let started = Instant::now();
    let error = run_broker(hanging, Duration::from_millis(300))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("PowerShell") && error.contains("did not finish"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_broker_command_is_the_absolute_powershell_with_the_script_as_one_argument() {
    let command = broker_command(
        Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        Path::new(r"C:\x y\pam.exe"),
        Path::new(r"C:\base"),
        std::iter::empty(),
    )
    .unwrap();
    let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy()).collect();
    assert_eq!(args[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
    assert_eq!(args.len(), 4, "{args:?}");
    let base = command
        .get_envs()
        .find(|(name, _)| *name == "PAM_BASE_DIR")
        .and_then(|(_, value)| value);
    assert_eq!(base, Some(std::ffi::OsStr::new(r"C:\base")));
}

/// A stand-in for `pam.exe`: records the environment and working directory it was started with.
/// `cwd.txt` is written last, so its presence says `env.txt` is whole.
fn write_probe(dir: &Path) -> std::path::PathBuf {
    let probe = dir.join("probe dir").join("it's probe.cmd");
    std::fs::create_dir_all(probe.parent().unwrap()).unwrap();
    std::fs::write(
        &probe,
        "@echo off\r\nset > \"%PAM_BASE_DIR%\\env.txt\"\r\ncd > \"%PAM_BASE_DIR%\\cwd.txt\"\r\n",
    )
    .unwrap();
    probe
}

/// The daemon `Start-Process` starts gets the allowlisted environment and the explicit base, and
/// nothing else of the caller's, not even what the test process itself carries.
#[test]
fn the_started_daemon_gets_the_allowlist_and_the_explicit_base_only() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    std::fs::create_dir_all(&base).unwrap();
    let probe = write_probe(tmp.path());
    let vars: Vec<(OsString, OsString)> = std::env::vars_os()
        .chain([
            ("SECRET_TOKEN".into(), "hunter2".into()),
            ("PAM_BASE_DIR".into(), r"C:\agent\chosen\base".into()),
        ])
        .collect();

    spawn_daemon(&probe, &base, vars.into_iter()).expect("the broker starts the probe");

    let cwd_file = base.join("cwd.txt");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cwd_file.is_file() {
        assert!(Instant::now() < deadline, "the probe never ran");
        std::thread::sleep(Duration::from_millis(50));
    }
    let env = std::fs::read_to_string(base.join("env.txt")).unwrap();
    let cwd = std::fs::read_to_string(&cwd_file).unwrap();
    let line = |key: &str| {
        env.lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::to_owned)
    };
    assert_eq!(
        line("PAM_BASE_DIR=").as_deref(),
        base.to_str(),
        "the base is the client's resolved one, not the environment's: {env}"
    );
    assert!(!env.contains("SECRET_TOKEN"), "{env}");
    assert!(
        !env.to_ascii_uppercase().contains("CARGO_"),
        "nothing of the caller's own environment leaks: {env}"
    );
    assert!(
        line("SystemRoot=").is_some(),
        "the allowlist arrives: {env}"
    );
    assert!(
        cwd.trim().trim_end_matches('\\').eq_ignore_ascii_case(
            std::env::temp_dir()
                .to_string_lossy()
                .trim_end_matches('\\')
        ),
        "the daemon's fixed working directory: {cwd}"
    );
}
