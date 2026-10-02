//! The PowerShell broker that starts the daemon on Windows.

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::broker_windows::{
    SystemPowerShell, broker_command, marked_as_downloaded, run_broker, single_quoted,
    spawn_daemon, start_script, system_powershell, with_download_hint,
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

/// PowerShell started without `PSModulePath` finds a command by going through every module
/// installed for the machine and the user, which takes tens of seconds on a hosted CI runner. The
/// script therefore names no command PowerShell would have to search for: it imports the module
/// `Start-Process` lives in by absolute path, and only then calls it.
#[test]
fn the_script_imports_the_module_by_path_before_it_starts_the_quoted_executable_hidden() {
    assert_eq!(
        start_script(
            Path::new(r"C:\a b\o'k\pam.exe"),
            Path::new(r"C:\Windows\System32\M\M.psd1")
        )
        .unwrap(),
        r"$ErrorActionPreference = 'Stop'; Import-Module -Name 'C:\Windows\System32\M\M.psd1'; $env:PSModulePath = $null; Start-Process -FilePath 'C:\a b\o''k\pam.exe' -ArgumentList 'daemon' -WindowStyle Hidden"
    );
}

#[test]
fn powershell_and_its_module_are_the_ones_under_system32_never_a_path_search() {
    let powershell = system_powershell().expect("this host has Windows PowerShell");
    for (path, tail) in [
        (
            &powershell.exe,
            r"\system32\windowspowershell\v1.0\powershell.exe",
        ),
        (
            &powershell.management,
            r"\system32\windowspowershell\v1.0\modules\microsoft.powershell.management\microsoft.powershell.management.psd1",
        ),
    ] {
        assert!(path.is_absolute() && path.is_file(), "{path:?}");
        assert!(
            path.to_string_lossy().to_ascii_lowercase().ends_with(tail),
            "{path:?}"
        );
    }
    assert!(powershell.management.starts_with(&powershell.modules));
}

#[test]
fn a_broker_that_fails_or_hangs_is_a_legible_error_naming_powershell_and_the_login_unit() {
    let mut failing = Command::new("cmd");
    failing.args(["/c", "exit 3"]);
    let error = run_broker(failing, Duration::from_secs(20))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("PowerShell") && error.contains('3'),
        "{error}"
    );
    assert!(error.contains("`pam service install`"), "{error}");

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
    assert!(error.contains("`pam service install`"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// What PowerShell itself said goes into the error: a start that policy or a missing file
/// refuses is told apart from one that merely failed.
#[test]
fn a_broker_whose_start_is_refused_quotes_powershells_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no such pam.exe");
    let error = spawn_daemon(&missing, tmp.path(), std::env::vars_os())
        .unwrap_err()
        .to_string();
    assert!(error.contains("exited with"), "{error}");
    assert!(error.contains("Start-Process"), "{error}");
    assert!(error.contains("`pam service install`"), "{error}");
}

/// `ShellExecute` asks before it starts a file a browser marked as downloaded, and the hidden
/// broker then sits until its bound: the error says so and how to remove the mark.
#[test]
fn a_failed_start_of_a_file_marked_as_downloaded_names_the_mark() {
    let tmp = tempfile::tempdir().unwrap();
    let plain = tmp.path().join("plain.exe");
    let local = tmp.path().join("local.exe");
    let marked = tmp.path().join("marked.exe");
    for path in [&plain, &local, &marked] {
        std::fs::write(path, b"").unwrap();
    }
    let zone = |path: &Path, id: u8| {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        std::fs::write(stream, format!("[ZoneTransfer]\r\nZoneId={id}\r\n")).unwrap();
    };
    zone(&local, 0);
    zone(&marked, 3);
    assert!(!marked_as_downloaded(&plain));
    assert!(!marked_as_downloaded(&local));
    assert!(marked_as_downloaded(&marked));

    let failed = || std::io::Error::other("powershell.exe did not finish within 20s");
    assert_eq!(
        with_download_hint(failed(), &plain).to_string(),
        failed().to_string()
    );
    let hinted = with_download_hint(failed(), &marked).to_string();
    assert!(hinted.starts_with(&failed().to_string()), "{hinted}");
    assert!(
        hinted.contains("marked.exe") && hinted.contains("Unblock"),
        "{hinted}"
    );
}

#[test]
fn the_broker_command_is_the_absolute_powershell_with_the_script_as_one_argument() {
    let powershell = SystemPowerShell {
        exe: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
        modules: r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules".into(),
        management: r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\M\M.psd1".into(),
    };
    let command = broker_command(
        &powershell,
        Path::new(r"C:\x y\pam.exe"),
        Path::new(r"C:\base"),
        std::iter::empty(),
    )
    .unwrap();
    assert_eq!(command.get_program(), powershell.exe.as_os_str());
    let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy()).collect();
    assert_eq!(args[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
    assert_eq!(args.len(), 4, "{args:?}");
    let env = |wanted: &str| {
        command
            .get_envs()
            .find(|(name, _)| *name == wanted)
            .and_then(|(_, value)| value)
    };
    assert_eq!(env("PAM_BASE_DIR"), Some(std::ffi::OsStr::new(r"C:\base")));
    // The broker's own module path: PowerShell's directory, not the machine's and the user's.
    assert_eq!(env("PSModulePath"), Some(powershell.modules.as_os_str()));
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
/// nothing else: not the caller's, not even what the test process itself carries, and not the
/// module path PowerShell sets for itself.
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

    let started = Instant::now();
    spawn_daemon(&probe, &base, vars.into_iter()).expect("the broker starts the probe");
    let broker = started.elapsed();
    // A broker that makes PowerShell search its module path for a command takes tens of seconds
    // on a machine with many modules installed (a hosted CI runner).
    assert!(
        broker < Duration::from_secs(10),
        "the broker took {broker:?}: it must not depend on PowerShell's command discovery"
    );

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
        !env.to_ascii_uppercase().contains("PSMODULEPATH"),
        "what the broker needed for itself stays with the broker: {env}"
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
