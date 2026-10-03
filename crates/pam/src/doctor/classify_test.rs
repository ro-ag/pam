//! The classifier tables, per platform, over injected errors and the helper
//! lines captured on the real OS (2026-10-02, macOS 26; see the constants
//! in `classify.rs`).

use std::io;
use std::path::Path;
use std::time::Duration;

use pam_proto::doctor::{MAX_CHAIN_NAMES, MAX_TEXT_BYTES, Platform, ProbeResult, ProbeState};
use pam_proto::wire::Via;

use super::classify::{
    ACCESS_REFUSED_NOTE, EACCES, ENOENT, ENOTDIR, EPERM, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, bounded_chain, bounded_text, bundle_root,
    classify_access_write, classify_appleevents, classify_connect, classify_exists, classify_io,
    classify_io_result, classify_keyring, classify_kill, classify_kind_code,
    classify_launchservices, classify_lock, classify_process_query, classify_reach,
    classify_security, classify_shell_execute, first_line, fit_result, parse_lock_pid,
    parse_ps_line,
};
use super::helpers::{HelperOutcome, HelperRun};
use super::os::{HelloAnswer, KeyringAnswer, LockState};

fn ran(code: Option<i32>, stdout: &str, stderr: &str) -> HelperOutcome {
    HelperOutcome::Ran(HelperRun::new(code, stdout, stderr))
}

fn raw(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

#[test]
fn success_is_allowed_on_both_platforms() {
    for platform in [Platform::Macos, Platform::Windows] {
        assert_eq!(classify_io_result(platform, Ok(())), ProbeResult::allowed());
    }
}

#[test]
fn unix_errno_table() {
    for code in [EPERM, EACCES] {
        let result = classify_io(Platform::Macos, &raw(code));
        assert_eq!(result.state, ProbeState::Denied, "errno {code}");
        let os_error = result.os_error.unwrap();
        assert_eq!(os_error.kind, "PermissionDenied");
        assert_eq!(os_error.code, Some(code));
    }
    for code in [ENOENT, ENOTDIR] {
        let result = classify_io(Platform::Macos, &raw(code));
        assert_eq!(result.state, ProbeState::Absent, "errno {code}");
        assert!(result.os_error.is_none());
    }
    // EIO: unexpected.
    let result = classify_io(Platform::Macos, &raw(5));
    assert_eq!(result.state, ProbeState::Unknown);
    assert_eq!(
        result.note.as_deref(),
        Some("unexpected error: Uncategorized (code 5)")
    );
    assert_eq!(result.os_error.unwrap().code, Some(5));
}

#[test]
fn an_error_without_a_code_classifies_by_kind() {
    let denied = io::Error::new(io::ErrorKind::PermissionDenied, "sandbox");
    assert_eq!(
        classify_io(Platform::Macos, &denied).state,
        ProbeState::Denied
    );
    let gone = io::Error::new(io::ErrorKind::NotFound, "gone");
    assert_eq!(
        classify_io(Platform::Macos, &gone).state,
        ProbeState::Absent
    );
    let other = io::Error::other("something");
    let result = classify_io(Platform::Macos, &other);
    assert_eq!(result.state, ProbeState::Unknown);
    assert_eq!(result.note.as_deref(), Some("unexpected error: Other"));
}

#[test]
fn windows_code_table() {
    // The raw code decides before the kind (the standard library gives a
    // sharing violation an unstable, unnamed kind; `Other` stands in).
    let denied = classify_kind_code(
        Platform::Windows,
        io::ErrorKind::PermissionDenied,
        Some(ERROR_ACCESS_DENIED),
    );
    assert_eq!(denied.state, ProbeState::Denied);
    assert_eq!(denied.os_error.unwrap().code, Some(ERROR_ACCESS_DENIED));
    for code in [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND] {
        let absent = classify_kind_code(Platform::Windows, io::ErrorKind::NotFound, Some(code));
        assert_eq!(absent.state, ProbeState::Absent, "code {code}");
    }
    let sharing = classify_kind_code(
        Platform::Windows,
        io::ErrorKind::Other,
        Some(ERROR_SHARING_VIOLATION),
    );
    assert_eq!(sharing.state, ProbeState::Allowed);
    assert_eq!(
        sharing.os_error.as_ref().unwrap().detail.as_deref(),
        Some("ERROR_SHARING_VIOLATION")
    );
    assert!(sharing.note.unwrap().contains("share mode"));
    let other = classify_kind_code(Platform::Windows, io::ErrorKind::Other, Some(1920));
    assert_eq!(other.state, ProbeState::Unknown);
    assert_eq!(
        other.note.as_deref(),
        Some("unexpected error: Other (code 1920)")
    );
    // Without a code, the kind rules as on unix.
    assert_eq!(
        classify_kind_code(Platform::Windows, io::ErrorKind::PermissionDenied, None).state,
        ProbeState::Denied
    );
    assert_eq!(
        classify_kind_code(Platform::Windows, io::ErrorKind::NotFound, None).state,
        ProbeState::Absent
    );
}

#[test]
fn a_sharing_violation_code_means_nothing_on_macos() {
    // errno 32 is EPIPE on macOS: unexpected, never allowed.
    let result = classify_kind_code(Platform::Macos, io::ErrorKind::BrokenPipe, Some(32));
    assert_eq!(result.state, ProbeState::Unknown);
}

#[test]
fn a_refused_connect_reached_the_socket() {
    let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "nobody listens");
    let result = classify_connect(Platform::Macos, Err(refused));
    assert_eq!(result.state, ProbeState::Allowed);
    assert!(result.note.unwrap().contains("nothing listens"));
    assert_eq!(
        classify_connect(Platform::Macos, Ok(())).state,
        ProbeState::Allowed
    );
    assert_eq!(
        classify_connect(Platform::Macos, Err(raw(EPERM))).state,
        ProbeState::Denied
    );
    assert_eq!(
        classify_connect(Platform::Macos, Err(raw(ENOENT))).state,
        ProbeState::Absent
    );
}

#[test]
fn the_lock_probe_is_information_with_a_note() {
    let held = classify_lock(Platform::Macos, Ok(LockState::Held), false);
    assert_eq!(held.state, ProbeState::Allowed);
    assert_eq!(held.note.as_deref(), Some("held: a daemon is running"));
    let free = classify_lock(Platform::Macos, Ok(LockState::Free), false);
    assert_eq!(free.note.as_deref(), Some("free: no daemon holds the lock"));
    let denied = classify_lock(Platform::Macos, Err(raw(EACCES)), false);
    assert_eq!(denied.state, ProbeState::Denied);
    assert_eq!(denied.note.as_deref(), Some("lazy start unavailable here"));
    let relayed = classify_lock(Platform::Macos, Err(raw(EACCES)), true);
    assert_eq!(
        relayed.note.as_deref(),
        Some("unreadable under the relay; lazy start is not needed here")
    );
    let absent = classify_lock(Platform::Macos, Err(raw(ENOENT)), false);
    assert_eq!(absent.state, ProbeState::Absent);
    assert_eq!(
        absent.note.as_deref(),
        Some("no lock file: no daemon has run here")
    );
    let other = classify_lock(Platform::Macos, Err(io::Error::other("x")), false);
    assert_eq!(other.state, ProbeState::Unknown);
}

#[test]
fn the_reach_table() {
    let bound = Duration::from_secs(5);
    let (ready, facts) = classify_reach(
        Platform::Macos,
        Via::Relay,
        bound,
        HelloAnswer::Ready {
            version: "0.4.3".to_owned(),
            proto: 2,
            epoch: "01J".to_owned(),
        },
    );
    assert_eq!(ready, ProbeResult::allowed());
    let facts = facts.unwrap();
    assert_eq!(
        (facts.version.as_str(), facts.proto, facts.epoch.as_str()),
        ("0.4.3", 2, "01J")
    );
    assert_eq!(facts.via, Via::Relay);

    let (denied, facts) = classify_reach(
        Platform::Macos,
        Via::Direct,
        bound,
        HelloAnswer::Unreachable(raw(EPERM)),
    );
    assert_eq!(denied.state, ProbeState::Denied);
    assert!(facts.is_none());

    let (absent, _) = classify_reach(
        Platform::Macos,
        Via::Direct,
        bound,
        HelloAnswer::Unreachable(raw(ENOENT)),
    );
    assert_eq!(absent.state, ProbeState::Absent);
    assert_eq!(
        absent.note.as_deref(),
        Some("no public endpoint: no daemon is running here")
    );

    let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "stale");
    let (unknown, _) = classify_reach(
        Platform::Macos,
        Via::Direct,
        bound,
        HelloAnswer::Unreachable(refused),
    );
    assert_eq!(unknown.state, ProbeState::Unknown);
    assert!(unknown.note.unwrap().starts_with("connection refused"));

    let (legacy, _) = classify_reach(Platform::Macos, Via::Direct, bound, HelloAnswer::Legacy);
    assert_eq!(legacy.state, ProbeState::Unknown);
    assert!(legacy.note.unwrap().contains("pre-migration"));

    let (refused, _) = classify_reach(
        Platform::Macos,
        Via::Direct,
        bound,
        HelloAnswer::Refused {
            cause: "client_version_mismatch".to_owned(),
            detail: "0.1".to_owned(),
        },
    );
    assert_eq!(
        refused.note.as_deref(),
        Some("hello refused: client_version_mismatch: 0.1")
    );

    let (silent, _) = classify_reach(Platform::Macos, Via::Direct, bound, HelloAnswer::Silent);
    assert_eq!(
        silent.note.as_deref(),
        Some("no hello acknowledgement within 5000 ms")
    );

    // A Windows sharing violation on the control file is never "allowed"
    // for the reach: nothing answered.
    let sharing = io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION);
    let (never_allowed, _) = classify_reach(
        Platform::Windows,
        Via::Direct,
        bound,
        HelloAnswer::Unreachable(sharing),
    );
    assert_eq!(never_allowed.state, ProbeState::Unknown);
}

#[test]
fn helpers_that_could_not_run_are_unknown_with_the_reason() {
    let spawn = HelperOutcome::SpawnFailed(raw(ENOENT));
    for classify in [
        classify_security,
        classify_kill,
        classify_launchservices,
        classify_appleevents,
        classify_process_query,
        classify_access_write,
    ] {
        let result = classify(&spawn);
        assert_eq!(result.state, ProbeState::Unknown);
        assert_eq!(result.note.as_deref(), Some("spawn: NotFound"));
        assert_eq!(result.os_error.unwrap().code, Some(ENOENT));
        let result = classify(&HelperOutcome::TimedOut(Duration::from_secs(5)));
        assert_eq!(result.state, ProbeState::Unknown);
        assert_eq!(
            result.note.as_deref(),
            Some("helper timed out after 5000 ms")
        );
    }
}

#[test]
fn security_table() {
    // Captured 2026-10-02: the keychain answered for an absent item.
    let absent = ran(
        Some(44),
        "",
        "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
    );
    assert_eq!(classify_security(&absent), ProbeResult::allowed());
    // Captured 2026-10-02 under broker-macos.sb: the initialization error
    // comes first, the not-found line after it; the first decides.
    let denied = ran(
        Some(44),
        "",
        "security: SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid.\nsecurity: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
    );
    let result = classify_security(&denied);
    assert_eq!(result.state, ProbeState::Denied);
    let os_error = result.os_error.unwrap();
    assert_eq!(os_error.kind, "KeychainSearchDenied");
    assert!(
        os_error
            .detail
            .unwrap()
            .starts_with("security: SecKeychainSearchCreateFromAttributes:")
    );
    // Exit 44 alone is not evidence of denial: it is the keychain answering.
    assert_eq!(
        classify_security(&ran(Some(44), "", "")).state,
        ProbeState::Allowed
    );
    let other = classify_security(&ran(Some(1), "", "security: unknown failure\n"));
    assert_eq!(other.state, ProbeState::Unknown);
    assert_eq!(
        other.note.as_deref(),
        Some("unrecognised security output (exit 1): security: unknown failure")
    );
}

#[test]
fn kill_table() {
    assert_eq!(classify_kill(&ran(Some(0), "", "")), ProbeResult::allowed());
    let denied = classify_kill(&ran(Some(1), "", "kill: 1: Operation not permitted\n"));
    assert_eq!(denied.state, ProbeState::Denied);
    let os_error = denied.os_error.unwrap();
    assert_eq!(
        (os_error.kind.as_str(), os_error.code),
        ("PermissionDenied", Some(EPERM))
    );
    assert_eq!(
        os_error.detail.as_deref(),
        Some("kill: 1: Operation not permitted")
    );
    let gone = classify_kill(&ran(Some(1), "", "kill: 999999: No such process\n"));
    assert_eq!(gone.state, ProbeState::Unknown);
    assert!(gone.note.unwrap().contains("names no process"));
    let killed = classify_kill(&ran(None, "", ""));
    assert_eq!(
        killed.note.as_deref(),
        Some("unrecognised kill output (killed by a signal): no output")
    );
}

#[test]
fn access_table() {
    // `/bin/test -w`: the exit status is the whole answer (captured
    // 2026-10-02 under `(deny file-write* (literal …))`: 1; outside: 0).
    assert_eq!(
        classify_access_write(&ran(Some(0), "", "")),
        ProbeResult::allowed()
    );
    let denied = classify_access_write(&ran(Some(1), "", ""));
    assert_eq!(denied.state, ProbeState::Denied);
    let os_error = denied.os_error.unwrap();
    assert_eq!(
        (os_error.kind.as_str(), os_error.code),
        ("PermissionDenied", None)
    );
    assert_eq!(denied.note.as_deref(), Some(ACCESS_REFUSED_NOTE));
    let usage = classify_access_write(&ran(Some(2), "", "test: -w: unary operator expected\n"));
    assert_eq!(usage.state, ProbeState::Unknown);
    assert_eq!(
        usage.note.as_deref(),
        Some("unrecognised test output (exit 2): test: -w: unary operator expected")
    );
    // `/bin/test -e` tells a refused path from a missing one.
    assert_eq!(classify_exists(&ran(Some(0), "", "")), Ok(true));
    assert_eq!(classify_exists(&ran(Some(1), "", "")), Ok(false));
    let killed = classify_exists(&ran(None, "", "")).unwrap_err();
    assert_eq!(
        killed.note.as_deref(),
        Some("unrecognised test output (killed by a signal): no output")
    );
    let spawn = classify_exists(&HelperOutcome::SpawnFailed(raw(ENOENT))).unwrap_err();
    assert_eq!(spawn.state, ProbeState::Unknown);
    assert_eq!(spawn.note.as_deref(), Some("spawn: NotFound"));
}

#[test]
fn launchservices_table() {
    // Captured 2026-10-02: outside the profile the server names the login
    // window; under `(deny mach-lookup)` the same query is silent.
    let answered = ran(Some(0), "ASN:0x0-0x1001-\"loginwindow\":\n", "");
    assert_eq!(classify_launchservices(&answered), ProbeResult::allowed());
    let silent = classify_launchservices(&ran(Some(0), "", ""));
    assert_eq!(silent.state, ProbeState::Denied);
    let os_error = silent.os_error.unwrap();
    assert_eq!(os_error.kind, "LaunchServicesUnreachable");
    assert_eq!(
        os_error.detail.as_deref(),
        Some("lsappinfo answered nothing for com.apple.loginwindow")
    );
    // A failure exit or a complaint is neither: fail closed.
    let failed = classify_launchservices(&ran(Some(1), "", ""));
    assert_eq!(failed.state, ProbeState::Unknown);
    let complaint = classify_launchservices(&ran(Some(0), "", "lsappinfo: cannot connect\n"));
    assert_eq!(complaint.state, ProbeState::Unknown);
    assert_eq!(
        complaint.note.as_deref(),
        Some("unrecognised lsappinfo output (exit 0): lsappinfo: cannot connect")
    );
}

#[test]
fn appleevents_table() {
    // Captured 2026-10-02: the running Finder's id outside the profiles;
    // the broker connection refused under both.
    assert_eq!(
        classify_appleevents(&ran(Some(0), "com.apple.finder\n", "")),
        ProbeResult::allowed()
    );
    let denied = classify_appleevents(&ran(
        Some(1),
        "",
        "2026-10-02 18:18:23.907 osascript[26160:255111] Connection Invalid error for service com.apple.hiservices-xpcservice.\n2026-10-02 18:18:23.908 osascript[26160:255109] Error received in message reply handler: Connection invalid\n0:2: execution error: Can’t get application \"Finder\". (-1728)\n",
    ));
    assert_eq!(denied.state, ProbeState::Denied);
    assert_eq!(denied.os_error.unwrap().kind, "AppleEventsUnreachable");
    // Finder not running (no login session): neither answer, fail closed.
    let no_finder = classify_appleevents(&ran(
        Some(1),
        "",
        "0:2: execution error: Can’t get application \"Finder\". (-1728)\n",
    ));
    assert_eq!(no_finder.state, ProbeState::Unknown);
    assert!(
        no_finder
            .note
            .unwrap()
            .starts_with("unrecognised osascript output (exit 1)")
    );
    // Another id on stdout is not the answer either.
    assert_eq!(
        classify_appleevents(&ran(Some(0), "com.apple.other\n", "")).state,
        ProbeState::Unknown
    );
}

#[test]
fn shell_execute_and_process_query_tables() {
    assert_eq!(
        classify_shell_execute(&ran(Some(2), "", "")),
        ProbeResult::allowed()
    );
    let denied = classify_shell_execute(&HelperOutcome::SpawnFailed(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "blocked",
    )));
    assert_eq!(denied.state, ProbeState::Denied);
    let timed_out = classify_shell_execute(&HelperOutcome::TimedOut(Duration::from_secs(5)));
    assert_eq!(timed_out.state, ProbeState::Unknown);

    let visible = classify_process_query(&ran(
        Some(0),
        "PATH=C:\\Program Files\\pam\\pam.exe\r\n",
        "",
    ));
    assert_eq!(visible.state, ProbeState::Allowed);
    assert_eq!(visible.note.as_deref(), Some("query only"));
    let hidden = classify_process_query(&ran(Some(0), "PATH=\r\n", ""));
    assert_eq!(hidden.state, ProbeState::Denied);
    assert_eq!(hidden.os_error.unwrap().kind, "ProcessQueryDenied");
    let gone = classify_process_query(&ran(
        Some(1),
        "",
        "Get-Process : Cannot find a process with the process identifier 4242.\r\n",
    ));
    assert_eq!(gone.state, ProbeState::Unknown);
    let other = classify_process_query(&ran(Some(0), "", ""));
    assert_eq!(other.state, ProbeState::Unknown);
}

#[test]
fn keyring_table() {
    assert_eq!(
        classify_keyring(KeyringAnswer::Absent),
        ProbeResult::allowed()
    );
    let denied = classify_keyring(KeyringAnswer::Denied);
    assert_eq!(denied.state, ProbeState::Denied);
    assert_eq!(denied.os_error.unwrap().kind, "store_denied");
    assert_eq!(
        classify_keyring(KeyringAnswer::Unavailable).state,
        ProbeState::Unknown
    );
    assert_eq!(
        classify_keyring(KeyringAnswer::Present).state,
        ProbeState::Unknown
    );
    let failed = classify_keyring(KeyringAnswer::Failed("busy".to_owned()));
    assert_eq!(failed.note.as_deref(), Some("credential store: busy"));
}

#[test]
fn parsers() {
    assert_eq!(parse_lock_pid("4242\n"), Some(4242));
    assert_eq!(parse_lock_pid(" 7 "), Some(7));
    assert_eq!(parse_lock_pid("0"), None);
    assert_eq!(parse_lock_pid(""), None);
    assert_eq!(parse_lock_pid("-1"), None);
    assert_eq!(parse_lock_pid("pid 12"), None);

    assert_eq!(
        parse_ps_line(" 1669 /bin/zsh\n"),
        Some((1669, "zsh".to_owned()))
    );
    assert_eq!(
        parse_ps_line("  812 /Applications/Claude.app/Contents/MacOS/claude code"),
        Some((812, "claude code".to_owned()))
    );
    assert_eq!(
        parse_ps_line("    0 /sbin/launchd"),
        Some((0, "launchd".to_owned()))
    );
    assert_eq!(parse_ps_line(""), None);
    assert_eq!(parse_ps_line("ps: process id too large: 999999"), None);
    assert_eq!(parse_ps_line("12"), None);

    assert_eq!(first_line("\n  \n hello \nworld"), Some("hello"));
    assert_eq!(first_line("\n"), None);
}

#[test]
fn bundle_root_is_the_nearest_app_ancestor() {
    assert_eq!(
        bundle_root(Path::new("/Applications/PAM.app/Contents/MacOS/pam")),
        Some(Path::new("/Applications/PAM.app").to_path_buf())
    );
    assert_eq!(
        bundle_root(Path::new(
            "/Applications/Outer.APP/Contents/Helpers/Inner.app/Contents/MacOS/pam"
        )),
        Some(Path::new("/Applications/Outer.APP/Contents/Helpers/Inner.app").to_path_buf())
    );
    assert_eq!(bundle_root(Path::new("/usr/local/bin/pam")), None);
    assert_eq!(bundle_root(Path::new("/tmp/pam.app.backup/pam")), None);
    assert_eq!(bundle_root(Path::new("/tmp/pam.application/pam")), None);
}

#[test]
fn texts_are_fitted_to_the_report_bounds() {
    assert_eq!(bounded_text("a\tb\nc\u{1b}d", 10), "a b c d");
    assert_eq!(
        bounded_text("é".repeat(300).as_str(), MAX_TEXT_BYTES).len(),
        MAX_TEXT_BYTES
    );
    let cut = bounded_text(&"é".repeat(300), 255);
    assert_eq!(cut.len(), 254, "cut at a character boundary");
    assert_eq!(bounded_text("short", 256), "short");

    let long = "x".repeat(1000);
    let result = ProbeResult::unknown(long.clone()).with_os_error(
        pam_proto::doctor::OsError::of_kind(long.clone()).with_detail(format!("{long}\n")),
    );
    let fitted = fit_result(result);
    assert_eq!(fitted.note.unwrap().len(), MAX_TEXT_BYTES);
    let os_error = fitted.os_error.unwrap();
    assert_eq!(os_error.kind.len(), MAX_TEXT_BYTES);
    assert!(!os_error.detail.unwrap().contains('\n'));

    let chain = bounded_chain((0..40).map(|index| format!("p{index}\n{long}")));
    assert_eq!(chain.len(), MAX_CHAIN_NAMES);
    assert!(
        chain
            .iter()
            .all(|name| name.len() <= MAX_TEXT_BYTES && !name.contains('\n'))
    );
}
