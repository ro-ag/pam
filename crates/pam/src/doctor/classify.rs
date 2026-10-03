//! Pure classifiers: from what the OS seam returned — an `io::Error`, a
//! helper's exit status and output, a hello's answer, a credential-store
//! answer — to a [`ProbeResult`]. Nothing here touches the OS, so every
//! branch is unit-tested for both platforms from one host.
//!
//! The rules (spec, "Probe inventory"): `PermissionDenied` (`EPERM`,
//! `EACCES`, `ERROR_ACCESS_DENIED`) is `denied`; `NotFound` (`ENOENT`,
//! `ENOTDIR`, `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`) is `absent`;
//! success is `allowed`; on Windows `ERROR_SHARING_VIOLATION` is `allowed`
//! (the ACL granted the access; only the share mode refused it — the access
//! check precedes the share check in `CreateFile`); anything else is
//! `unknown` with the error's kind and raw code. A helper's output is read
//! for the lines pinned on the real OS; an unrecognised output is `unknown`,
//! which fails the verdict — fail closed.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use pam_proto::doctor::{
    DaemonFacts, MAX_CHAIN_NAMES, MAX_PATH_BYTES, MAX_TEXT_BYTES, OsError, Platform, ProbeResult,
    ProbeState,
};
use pam_proto::wire::Via;

use super::helpers::{HelperOutcome, HelperRun};
use super::os::{HelloAnswer, KeyringAnswer, LockState};

/// `EPERM`.
pub const EPERM: i32 = 1;
/// `ENOENT`.
pub const ENOENT: i32 = 2;
/// `EACCES`.
pub const EACCES: i32 = 13;
/// `ENOTDIR`.
pub const ENOTDIR: i32 = 20;
/// `ECONNREFUSED` on macOS.
pub const ECONNREFUSED: i32 = 61;

/// Win32 `ERROR_FILE_NOT_FOUND`.
pub const ERROR_FILE_NOT_FOUND: i32 = 2;
/// Win32 `ERROR_PATH_NOT_FOUND`.
pub const ERROR_PATH_NOT_FOUND: i32 = 3;
/// Win32 `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: i32 = 5;
/// Win32 `ERROR_SHARING_VIOLATION`.
pub const ERROR_SHARING_VIOLATION: i32 = 32;

/// `security find-generic-password`: the keychain refused to initialize a
/// search — the sandbox denies the keychain service. Pinned by the macOS
/// fixture (`crates/pam/tests/sandbox_macos.rs`).
pub const SECURITY_DENIED_MARKER: &str = "SecKeychainSearchCreateFromAttributes:";

/// `security find-generic-password` on an absent item: the keychain
/// answered (exit 44; captured 2026-10-02 on macOS 26 as
/// `security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.`).
pub const SECURITY_ABSENT_EXIT: i32 = 44;

/// The absent-item line, in case the exit code is not 44 on another release.
pub const SECURITY_ABSENT_MARKER: &str = "could not be found";

/// `kill -0` refused by the sandbox (captured 2026-10-02:
/// `kill: 1: Operation not permitted`).
pub const KILL_DENIED_MARKER: &str = "Operation not permitted";

/// `kill -0` on a pid that is gone (captured 2026-10-02:
/// `kill: 999999: No such process`).
pub const KILL_GONE_MARKER: &str = "No such process";

/// `lsappinfo find bundleid=com.apple.loginwindow`: the `LaunchServices`
/// server answered with the session's login window (`ASN:0x0-0x1001-"loginwindow":`,
/// captured 2026-10-02 on macOS 26). Under the fixture profile's
/// `(deny mach-lookup)` the same command prints nothing and exits 0: the
/// server could not be reached. (`open -b <absent id>` and `osascript`
/// against an absent id print the same lines inside and outside that
/// profile — the absent id is resolved in-process before any broker is
/// asked — so they are not evidence; see `probe_unix.rs`.)
pub const LAUNCHSERVICES_ANSWER_MARKER: &str = "ASN:";

/// `osascript -e 'id of application "Finder"'`: the application-services
/// broker resolved the running Finder (stdout `com.apple.finder`, exit 0;
/// captured 2026-10-02 on macOS 26). No event is sent to Finder and nothing
/// is launched: the id comes from the process registry.
pub const APPLEEVENTS_ANSWER_MARKER: &str = "com.apple.finder";

/// The same command under a profile that denies the broker: exit 1, stderr
/// `Connection Invalid error for service com.apple.hiservices-xpcservice.`
/// (and `Error received in message reply handler: Connection invalid`),
/// then `Can’t get application "Finder". (-1728)`. Matched
/// case-insensitively. The bare `(-1728)` without the connection error is
/// a Finder that is not running (no login session) and stays `unknown`.
pub const APPLEEVENTS_DENIED_MARKER: &str = "connection invalid";

/// `PowerShell`'s answer when the lock pid names no process.
pub const PROCESS_GONE_MARKER: &str = "Cannot find a process";

/// The prefix of the process-query helper's one output line.
pub const PROCESS_PATH_PREFIX: &str = "PATH=";

/// The result of a plain open, list or lock operation.
#[must_use]
pub fn classify_io_result(platform: Platform, result: io::Result<()>) -> ProbeResult {
    match result {
        Ok(()) => ProbeResult::allowed(),
        Err(error) => classify_io(platform, &error),
    }
}

/// The result of an operation that failed with `error`.
#[must_use]
pub fn classify_io(platform: Platform, error: &io::Error) -> ProbeResult {
    classify_kind_code(platform, error.kind(), error.raw_os_error())
}

/// The rule itself, over an error's kind and raw OS code.
#[must_use]
pub fn classify_kind_code(
    platform: Platform,
    kind: io::ErrorKind,
    code: Option<i32>,
) -> ProbeResult {
    let os_error = OsError {
        kind: format!("{kind:?}"),
        code,
        detail: None,
    };
    if platform == Platform::Windows {
        match code {
            Some(ERROR_ACCESS_DENIED) => return ProbeResult::denied(os_error),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => return ProbeResult::absent(),
            Some(ERROR_SHARING_VIOLATION) => {
                return ProbeResult::allowed()
                    .with_os_error(os_error.with_detail("ERROR_SHARING_VIOLATION"))
                    .with_note(
                        "sharing violation: the ACL granted the access; only the share mode refused it",
                    );
            }
            _ => {}
        }
    }
    match kind {
        io::ErrorKind::PermissionDenied => ProbeResult::denied(os_error),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => ProbeResult::absent(),
        _ => ProbeResult::unknown(unexpected(kind, code)).with_os_error(os_error),
    }
}

/// The note of an `unknown` from an unexpected error.
fn unexpected(kind: io::ErrorKind, code: Option<i32>) -> String {
    match code {
        Some(code) => format!("unexpected error: {kind:?} (code {code})"),
        None => format!("unexpected error: {kind:?}"),
    }
}

/// The result of a unix-socket connect that sends nothing. A refused
/// connection means the sandbox let the connect reach the socket and
/// nothing listens behind it (a stale socket file): the access was
/// allowed, and that is what the probe asks.
#[must_use]
pub fn classify_connect(platform: Platform, result: io::Result<()>) -> ProbeResult {
    match result {
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => ProbeResult::allowed()
            .with_os_error(OsError::from_io(&error))
            .with_note("the connect reached the socket; nothing listens behind it"),
        other => classify_io_result(platform, other),
    }
}

/// The result of the client's shared-lock readiness test (`info`): what
/// the lock said when it could be probed, and what a refusal means for lazy
/// start — nothing under the relay, no lazy start otherwise.
#[must_use]
pub fn classify_lock(
    platform: Platform,
    result: io::Result<LockState>,
    relayed: bool,
) -> ProbeResult {
    match result {
        Ok(LockState::Held) => ProbeResult::allowed().with_note("held: a daemon is running"),
        Ok(LockState::Free) => ProbeResult::allowed().with_note("free: no daemon holds the lock"),
        Err(error) => {
            let classified = classify_io(platform, &error);
            match classified.state {
                ProbeState::Denied if relayed => classified
                    .with_note("unreadable under the relay; lazy start is not needed here"),
                ProbeState::Denied => classified.with_note("lazy start unavailable here"),
                ProbeState::Absent => classified.with_note("no lock file: no daemon has run here"),
                _ => classified,
            }
        }
    }
}

/// The result of the public hello (`must_allow`), with the daemon facts
/// when it was acknowledged. Anything but an acknowledgement makes the run
/// `cannot_probe`; the state says what was met.
#[must_use]
pub fn classify_reach(
    platform: Platform,
    via: Via,
    bound: Duration,
    answer: HelloAnswer,
) -> (ProbeResult, Option<DaemonFacts>) {
    match answer {
        HelloAnswer::Ready {
            version,
            proto,
            epoch,
        } => (
            ProbeResult::allowed(),
            Some(DaemonFacts {
                version,
                proto,
                epoch,
                via,
            }),
        ),
        HelloAnswer::Unreachable(error) => (classify_unreachable(platform, &error), None),
        HelloAnswer::Legacy => (
            ProbeResult::unknown("a pre-migration daemon answered (ZMTP greeting)"),
            None,
        ),
        HelloAnswer::Refused { cause, detail } => (
            ProbeResult::unknown(format!("hello refused: {cause}: {detail}")),
            None,
        ),
        HelloAnswer::Silent => (
            ProbeResult::unknown(format!(
                "no hello acknowledgement within {} ms",
                bound.as_millis()
            )),
            None,
        ),
    }
}

/// An unreachable public endpoint: never `allowed` (nothing answered).
fn classify_unreachable(platform: Platform, error: &io::Error) -> ProbeResult {
    if error.kind() == io::ErrorKind::ConnectionRefused {
        return ProbeResult::unknown("connection refused: nothing listens on the public endpoint")
            .with_os_error(OsError::from_io(error));
    }
    let classified = classify_io(platform, error);
    match classified.state {
        ProbeState::Allowed => {
            ProbeResult::unknown("the connect failed although access was granted")
                .with_os_error(OsError::from_io(error))
        }
        ProbeState::Absent => classified.with_note("no public endpoint: no daemon is running here"),
        _ => classified,
    }
}

/// A helper that ran, or the `unknown` its failure to run classifies to.
fn ran(outcome: &HelperOutcome) -> Result<&HelperRun, ProbeResult> {
    match outcome {
        HelperOutcome::Ran(run) => Ok(run),
        HelperOutcome::SpawnFailed(error) => {
            Err(ProbeResult::unknown(format!("spawn: {:?}", error.kind()))
                .with_os_error(OsError::from_io(error)))
        }
        HelperOutcome::TimedOut(bound) => Err(ProbeResult::unknown(format!(
            "helper timed out after {} ms",
            bound.as_millis()
        ))),
    }
}

/// `security find-generic-password` on an absent item of the connector
/// service: the initialization error is the denial; exit 44 or the
/// not-found line is the keychain answering.
#[must_use]
pub fn classify_security(outcome: &HelperOutcome) -> ProbeResult {
    let run = match ran(outcome) {
        Ok(run) => run,
        Err(result) => return result,
    };
    if let Some(line) = line_containing(&run.stderr, SECURITY_DENIED_MARKER) {
        return ProbeResult::denied(OsError::of_kind("KeychainSearchDenied").with_detail(line));
    }
    if run.code == Some(SECURITY_ABSENT_EXIT) || run.stderr.contains(SECURITY_ABSENT_MARKER) {
        return ProbeResult::allowed();
    }
    unrecognised("security", run)
}

/// `kill -0 <pid>`: delivers nothing; exit 0 is the right to signal.
#[must_use]
pub fn classify_kill(outcome: &HelperOutcome) -> ProbeResult {
    let run = match ran(outcome) {
        Ok(run) => run,
        Err(result) => return result,
    };
    if run.code == Some(0) {
        return ProbeResult::allowed();
    }
    if let Some(line) = line_containing(&run.stderr, KILL_DENIED_MARKER) {
        return ProbeResult::denied(OsError {
            kind: "PermissionDenied".to_owned(),
            code: Some(EPERM),
            detail: Some(line),
        });
    }
    if run.stderr.contains(KILL_GONE_MARKER) {
        return ProbeResult::unknown("the lock pid names no process: nothing to signal");
    }
    unrecognised("kill", run)
}

/// `lsappinfo find bundleid=com.apple.loginwindow`: an `ASN:` line is the
/// `LaunchServices` server answering (the broker is reachable); a clean exit
/// with no output is the server out of reach — the lookup was refused, or
/// this process has no login session, in which case nothing could be
/// launched through it either. Anything else is `unknown` (fail closed).
#[must_use]
pub fn classify_launchservices(outcome: &HelperOutcome) -> ProbeResult {
    let run = match ran(outcome) {
        Ok(run) => run,
        Err(result) => return result,
    };
    if run.stdout.contains(LAUNCHSERVICES_ANSWER_MARKER) {
        return ProbeResult::allowed();
    }
    if run.code == Some(0) && run.stdout.trim().is_empty() && run.stderr.trim().is_empty() {
        return ProbeResult::denied(
            OsError::of_kind("LaunchServicesUnreachable")
                .with_detail("lsappinfo answered nothing for com.apple.loginwindow"),
        );
    }
    unrecognised("lsappinfo", run)
}

/// `osascript -e 'id of application "Finder"'`: the bundle id on stdout is
/// the application-services broker (`com.apple.hiservices-xpcservice`)
/// answering; the connection-invalid complaint is the broker out of reach.
/// Anything else — including a Finder that is not running — is `unknown`
/// (fail closed).
#[must_use]
pub fn classify_appleevents(outcome: &HelperOutcome) -> ProbeResult {
    let run = match ran(outcome) {
        Ok(run) => run,
        Err(result) => return result,
    };
    if run.stdout.trim() == APPLEEVENTS_ANSWER_MARKER {
        return ProbeResult::allowed();
    }
    if run
        .stderr
        .to_lowercase()
        .contains(APPLEEVENTS_DENIED_MARKER)
    {
        return ProbeResult::denied(
            OsError::of_kind("AppleEventsUnreachable")
                .with_detail("osascript: connection invalid for com.apple.hiservices-xpcservice"),
        );
    }
    unrecognised("osascript", run)
}

/// `where.exe` (Windows): process creation is the broker, so a helper that
/// ran at all is `allowed`; one the OS refused to create is `denied`.
#[must_use]
pub fn classify_shell_execute(outcome: &HelperOutcome) -> ProbeResult {
    match outcome {
        HelperOutcome::Ran(_) => ProbeResult::allowed(),
        HelperOutcome::SpawnFailed(error) => classify_io(Platform::Windows, error),
        HelperOutcome::TimedOut(_) => ran(outcome).err().unwrap_or_default(),
    }
}

/// The Windows process-query helper (`Get-Process -Id <pid>`, printing
/// `PATH=<exe>`): a visible executable path is query rights; an empty path
/// is the right refused. Query only — never termination rights.
#[must_use]
pub fn classify_process_query(outcome: &HelperOutcome) -> ProbeResult {
    let run = match ran(outcome) {
        Ok(run) => run,
        Err(result) => return result,
    };
    if let Some(line) = line_starting(&run.stdout, PROCESS_PATH_PREFIX) {
        let path = line[PROCESS_PATH_PREFIX.len()..].trim();
        return if path.is_empty() {
            ProbeResult::denied(
                OsError::of_kind("ProcessQueryDenied")
                    .with_detail("the executable path of the lock pid is not visible"),
            )
            .with_note("query only")
        } else {
            ProbeResult::allowed().with_note("query only")
        };
    }
    if run.stderr.contains(PROCESS_GONE_MARKER) {
        return ProbeResult::unknown("the lock pid names no process: nothing to query");
    }
    unrecognised("process query", run)
}

/// A credential-store read of an absent account (Windows).
#[must_use]
pub fn classify_keyring(answer: KeyringAnswer) -> ProbeResult {
    match answer {
        KeyringAnswer::Absent => ProbeResult::allowed(),
        KeyringAnswer::Denied => ProbeResult::denied(OsError::of_kind("store_denied")),
        KeyringAnswer::Unavailable => {
            ProbeResult::unknown("the native credential store is unavailable")
        }
        KeyringAnswer::Present => {
            ProbeResult::unknown("an entry answered for a fresh random account")
        }
        KeyringAnswer::Failed(reason) => {
            ProbeResult::unknown(format!("credential store: {reason}"))
        }
    }
}

/// `unknown` for a helper whose output matched no pinned line.
fn unrecognised(helper: &str, run: &HelperRun) -> ProbeResult {
    let exit = run.code.map_or_else(
        || "killed by a signal".to_owned(),
        |code| format!("exit {code}"),
    );
    let line = first_line(&run.stderr)
        .or_else(|| first_line(&run.stdout))
        .unwrap_or("no output");
    ProbeResult::unknown(format!("unrecognised {helper} output ({exit}): {line}"))
}

/// The lock file's pid: a positive decimal, nothing else.
#[must_use]
pub fn parse_lock_pid(text: &str) -> Option<u32> {
    text.trim().parse().ok().filter(|pid| *pid != 0)
}

/// One `ps -o ppid=,comm= -p <pid>` line: the parent pid and the
/// executable's base name.
#[must_use]
pub fn parse_ps_line(line: &str) -> Option<(u32, String)> {
    let line = line.trim();
    let (ppid, command) = line.split_once(char::is_whitespace)?;
    let ppid = ppid.parse().ok()?;
    let name = Path::new(command.trim())
        .file_name()?
        .to_string_lossy()
        .into_owned();
    (!name.is_empty()).then_some((ppid, name))
}

/// The application bundle `exe` sits in: the nearest ancestor with an
/// `.app` extension (case-insensitively, as `pam::launched_from_app_bundle`
/// reads it).
#[must_use]
pub fn bundle_root(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
        })
        .map(Path::to_path_buf)
}

/// The first non-empty line of `text`, trimmed.
#[must_use]
pub fn first_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

/// The first line of `text` containing `marker`, trimmed.
fn line_containing(text: &str, marker: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| line.contains(marker))
        .map(str::to_owned)
}

/// The first line of `text` starting with `prefix`, trimmed.
fn line_starting<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with(prefix))
}

/// `text` fitted to the report's bounds: control characters become spaces
/// (the daemon refuses them) and the text is cut at a character boundary
/// to at most `max` bytes.
#[must_use]
pub fn bounded_text(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    if cleaned.len() <= max {
        return cleaned;
    }
    let mut cut = max;
    while !cleaned.is_char_boundary(cut) {
        cut -= 1;
    }
    cleaned[..cut].to_owned()
}

/// A probe result with every text fitted to the report's bounds.
#[must_use]
pub fn fit_result(mut result: ProbeResult) -> ProbeResult {
    if let Some(os_error) = result.os_error.as_mut() {
        os_error.kind = bounded_text(&os_error.kind, MAX_TEXT_BYTES);
        if let Some(detail) = os_error.detail.as_mut() {
            *detail = bounded_text(detail, MAX_TEXT_BYTES);
        }
    }
    if let Some(note) = result.note.as_mut() {
        *note = bounded_text(note, MAX_TEXT_BYTES);
    }
    result
}

/// A path fitted to the report's path bound.
#[must_use]
pub fn bounded_path(path: &Path) -> String {
    bounded_text(&path.to_string_lossy(), MAX_PATH_BYTES)
}

/// A harness chain fitted to the report's bounds: at most
/// [`MAX_CHAIN_NAMES`] names of at most [`MAX_TEXT_BYTES`] bytes each.
#[must_use]
pub fn bounded_chain(names: impl IntoIterator<Item = String>) -> Vec<String> {
    names
        .into_iter()
        .take(MAX_CHAIN_NAMES)
        .map(|name| bounded_text(&name, MAX_TEXT_BYTES))
        .collect()
}
