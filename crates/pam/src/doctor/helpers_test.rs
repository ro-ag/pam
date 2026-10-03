//! The helper runner: the environment allowlist, and real bounded runs of
//! absolute-path tools.

use std::ffi::OsString;
use std::time::{Duration, Instant};

use super::helpers::{
    HELPER_ENV_ALLOWLIST, Helper, HelperOutcome, MAX_HELPER_OUTPUT_BYTES, helper_env, run_helper,
};

fn var(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

#[test]
fn the_helper_environment_keeps_the_allowlist_and_locale_only() {
    let kept = helper_env(
        [
            var("HOME", "/Users/me"),
            var("PATH", "/evil:/usr/bin"),
            var("ANTHROPIC_API_KEY", "secret"),
            var("LC_ALL", "C"),
            var("systemroot", "C:\\Windows"),
            var("TMPDIR", "/tmp"),
            var("DYLD_INSERT_LIBRARIES", "/evil.dylib"),
        ]
        .into_iter(),
    );
    let names: Vec<String> = kept
        .iter()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["HOME", "LC_ALL", "systemroot", "TMPDIR"]);
    assert!(!HELPER_ENV_ALLOWLIST.contains(&"PATH"));
}

#[cfg(unix)]
#[test]
fn a_helper_runs_with_captured_output_and_an_exit_code() {
    let helper = Helper::new(
        "/bin/sh",
        ["-c", "echo out; echo err >&2; exit 3"],
        Duration::from_secs(5),
    );
    let HelperOutcome::Ran(run) = run_helper(&helper) else {
        panic!("helper did not run");
    };
    assert_eq!(run.code, Some(3));
    assert_eq!(run.stdout, "out\n");
    assert_eq!(run.stderr, "err\n");
    assert!(!run.truncated);
}

#[cfg(unix)]
#[test]
fn a_helper_gets_a_cleared_environment_and_a_null_stdin() {
    let helper = Helper::new("/bin/sh", ["-c", "env; cat"], Duration::from_secs(5));
    let HelperOutcome::Ran(run) = run_helper(&helper) else {
        panic!("helper did not run");
    };
    // `cat` on a null stdin ends at once; the run did not hang on the bound.
    assert_eq!(run.code, Some(0));
    // `sh` exports a few names of its own (`PWD`, `SHLVL`, `_`, `OLDPWD`).
    assert!(
        run.stdout.lines().all(|line| {
            let name = line.split('=').next().unwrap_or("");
            ["PWD", "SHLVL", "_", "OLDPWD"].contains(&name)
                || name.starts_with("LC_")
                || HELPER_ENV_ALLOWLIST
                    .iter()
                    .any(|allowed| name.eq_ignore_ascii_case(allowed))
        }),
        "environment leaked: {}",
        run.stdout
    );
    assert!(!run.stdout.lines().any(|line| line.starts_with("PATH=")));
}

#[cfg(unix)]
#[test]
fn a_helper_that_overruns_is_killed_and_reported() {
    let bound = Duration::from_millis(200);
    let helper = Helper::new("/bin/sleep", ["30"], bound);
    let started = Instant::now();
    let outcome = run_helper(&helper);
    assert!(matches!(outcome, HelperOutcome::TimedOut(waited) if waited == bound));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the helper was not killed"
    );
}

#[test]
fn a_missing_helper_cannot_start() {
    let helper = Helper::new(
        "/nonexistent/pam-doctor-helper",
        ["x"],
        Duration::from_secs(1),
    );
    let HelperOutcome::SpawnFailed(error) = run_helper(&helper) else {
        panic!("a missing helper must fail to spawn");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn helper_output_is_capped_without_blocking_the_helper() {
    let helper = Helper::new(
        "/bin/sh",
        ["-c", "head -c 300000 /dev/zero | tr '\\0' a"],
        Duration::from_secs(10),
    );
    let HelperOutcome::Ran(run) = run_helper(&helper) else {
        panic!("helper did not run");
    };
    assert_eq!(run.code, Some(0));
    assert_eq!(run.stdout.len(), MAX_HELPER_OUTPUT_BYTES);
    assert!(run.truncated);
}
