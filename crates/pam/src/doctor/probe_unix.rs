//! The macOS probes whose mechanism is unix-specific: the admin and engine
//! sockets (connect, drop, send nothing), the keychain through
//! `/usr/bin/security`, the daemon's signal right through `/bin/kill -0`,
//! the `LaunchServices` broker through a read-only `/usr/bin/lsappinfo`
//! query of the session's login window, the application-services broker
//! behind `AppleEvents` through `/usr/bin/osascript -e 'id of application
//! "Finder"'` (a property read of the running Finder: no event is sent to
//! it, nothing is launched, nothing prompts), the running executable and
//! the bundle's `Info.plist` asked through `/bin/test -w` — `access(2)`,
//! never an open: an open-for-write of a Mach-O that another process is
//! mapped from (the daemon, always, in production) invalidates the kernel's
//! cached code signature for that inode, and every later exec of the file
//! is `SIGKILL`ed until the file is replaced — and the harness chain
//! through `/bin/ps`.
//!
//! The spec's broker methods — `open -b <absent id>` and `osascript`
//! against an absent id — resolve the id in process and fail before any
//! broker is asked, so they print the same line inside and outside a
//! profile that denies the broker (captured 2026-10-02 under
//! `crates/pam/tests/support/broker-macos.sb` and
//! `docs/sandbox/macos/pam-agent.sb`); the two queries above are what
//! discriminates under both profiles.
//!
//! Helper output is classified against the lines captured on the real OS
//! in [`super::classify`]; the acceptance test (`doctor_macos.rs`) re-pins
//! them under `sandbox-exec`.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_daemon::secrets::SECRET_SERVICE;
use pam_proto::caller::MAX_CHAIN_DEPTH;
use pam_proto::doctor::{MAX_CHAIN_NAMES, ProbeId, ProbeResult, ProbeState};

use super::classify::{
    bundle_root, classify_access_write, classify_appleevents, classify_connect, classify_exists,
    classify_kill, classify_launchservices, classify_security, parse_ps_line,
};
use super::helpers::{Helper, HelperOutcome};
use super::inventory::{
    ADMIN_DIR, ADMIN_SOCKET, Context, ENGINE_SOCKET, Planned, RUN_DIR, current_exe, file_op,
    lock_pid,
};
use super::os::Os;

/// How long a connect probe holds the connected socket before dropping it:
/// long enough for the daemon's accept loop to read the kernel peer
/// credentials (a peer gone at once is recorded as an unattributable
/// "vanished" contact), well inside the 2 s probe bound. Nothing is sent or
/// read in the window.
pub const CONNECT_HOLD: Duration = Duration::from_millis(150);

/// The keychain helper.
pub const SECURITY: &str = "/usr/bin/security";
/// The signal helper.
pub const KILL: &str = "/bin/kill";
/// The `LaunchServices` helper: a read-only query of the server.
pub const LSAPPINFO: &str = "/usr/bin/lsappinfo";
/// The application every login session registers with `LaunchServices`.
pub const LOGINWINDOW_BUNDLE_ID: &str = "com.apple.loginwindow";
/// The `AppleEvents` helper: a property read, never a send.
pub const OSASCRIPT: &str = "/usr/bin/osascript";
/// The script: the running Finder's bundle id, resolved through the
/// application-services broker.
pub const APPLEEVENTS_SCRIPT: &str = "id of application \"Finder\"";
/// The process-table helper for the harness chain.
pub const PS: &str = "/bin/ps";
/// The `access(2)` helper: `test -w` and `test -e` ask the kernel the
/// permission and existence questions without opening the path.
pub const TEST: &str = "/bin/test";

/// The plan for a macOS-specific probe; `None` for the shared ones and
/// for the Windows-only ones.
#[must_use]
pub fn plan(id: ProbeId, context: &Context) -> Option<Planned> {
    let base = &context.base;
    let admin_socket = base.join(ADMIN_DIR).join(ADMIN_SOCKET);
    Some(match id {
        ProbeId::AdminEndpoint => connect(context, id, admin_socket),
        ProbeId::AdminEndpointAlias => connect(
            context,
            id,
            base.join(RUN_DIR)
                .join("..")
                .join(ADMIN_DIR)
                .join(ADMIN_SOCKET),
        ),
        ProbeId::EngineSocket => connect(context, id, base.join(RUN_DIR).join(ENGINE_SOCKET)),
        ProbeId::KeychainSearch => helper(
            context,
            id,
            Helper::new(
                SECURITY,
                [
                    "find-generic-password",
                    "-s",
                    SECRET_SERVICE,
                    "-a",
                    &context.absent_account(),
                ],
                context.options.helper_bound,
            ),
            classify_security,
        ),
        ProbeId::DaemonSignal => signal(context),
        ProbeId::BrokerLaunchServices => helper(
            context,
            id,
            Helper::new(
                LSAPPINFO,
                ["find", &format!("bundleid={LOGINWINDOW_BUNDLE_ID}")],
                context.options.helper_bound,
            ),
            classify_launchservices,
        ),
        ProbeId::BrokerAppleEvents => helper(
            context,
            id,
            Helper::new(
                OSASCRIPT,
                ["-e", APPLEEVENTS_SCRIPT],
                context.options.helper_bound,
            ),
            classify_appleevents,
        ),
        ProbeId::ExeWrite => exe_write(context),
        ProbeId::BundleWrite => bundle_write(context),
        _ => return None,
    })
}

/// Connect the unix socket at `path`, hold it for [`CONNECT_HOLD`], drop
/// the stream; send nothing.
fn connect(context: &Context, id: ProbeId, path: PathBuf) -> Planned {
    let platform = context.platform;
    file_op(context, id, move |os| {
        classify_connect(platform, os.connect_unix(&path, CONNECT_HOLD))
    })
}

/// Run `helper` under the helper bound and classify its output.
fn helper(
    context: &Context,
    id: ProbeId,
    helper: Helper,
    classify: fn(&HelperOutcome) -> ProbeResult,
) -> Planned {
    let os = Arc::clone(&context.os);
    Planned {
        id,
        bound: helper.timeout + Duration::from_secs(1),
        op: Box::new(move || classify(&os.run_helper(&helper)).into()),
    }
}

/// `kill -0 <pid>` against the lock file's pid: signal 0 delivers nothing.
fn signal(context: &Context) -> Planned {
    let os = Arc::clone(&context.os);
    let lock = context.lock_path();
    let bound = context.options.helper_bound;
    Planned {
        id: ProbeId::DaemonSignal,
        bound: bound + Duration::from_secs(1),
        op: Box::new(move || match lock_pid(os.as_ref(), &lock) {
            Ok(pid) => {
                let helper = Helper::new(KILL, ["-0", &pid.to_string()], bound);
                classify_kill(&os.run_helper(&helper)).into()
            }
            Err(result) => result.into(),
        }),
    }
}

/// `test -w` on the running executable: never an open. An open-for-write
/// of a Mach-O that another process is mapped from — the daemon, in
/// production, runs from this same binary — makes the kernel drop its
/// cached code signature for that inode, and every later exec of the file
/// is `SIGKILL`ed until the file is replaced; `access(2)` asks the same
/// permission question without touching the file, and Seatbelt honours it.
fn exe_write(context: &Context) -> Planned {
    access_op(context, ProbeId::ExeWrite, |os, bound| {
        Ok(access_write(os, &current_exe(os)?, bound))
    })
}

/// `test -w` on `<bundle>/Contents/Info.plist` when the executable sits in
/// an application bundle — the same shape as `exe.write`: nothing in the
/// bundle is ever opened for write; `absent` otherwise.
fn bundle_write(context: &Context) -> Planned {
    access_op(context, ProbeId::BundleWrite, |os, bound| {
        let exe = current_exe(os)?;
        Ok(match bundle_root(&exe) {
            Some(bundle) => access_write(os, &bundle.join("Contents").join("Info.plist"), bound),
            None => ProbeResult::absent().with_note("not inside an application bundle"),
        })
    })
}

/// A probe answered by the `access(2)` helper, bounded by two helper runs:
/// a refusal is told apart from a missing path by a second one.
fn access_op(
    context: &Context,
    id: ProbeId,
    op: impl FnOnce(&dyn Os, Duration) -> Result<ProbeResult, ProbeResult> + Send + 'static,
) -> Planned {
    let os = Arc::clone(&context.os);
    let bound = context.options.helper_bound;
    Planned {
        id,
        bound: bound * 2 + Duration::from_secs(1),
        op: Box::new(move || {
            match op(os.as_ref(), bound) {
                Ok(result) | Err(result) => result,
            }
            .into()
        }),
    }
}

/// Whether `path` may be written, by `test -w` — `access(2)` with `W_OK`:
/// exit 0 is `allowed`; exit 1 is `denied`, unless `test -e` says the path
/// is not there, which is `absent`. The path is never opened.
#[must_use]
pub fn access_write(os: &dyn Os, path: &Path, bound: Duration) -> ProbeResult {
    let result = classify_access_write(&os.run_helper(&test(path, "-w", bound)));
    if result.state != ProbeState::Denied {
        return result;
    }
    match classify_exists(&os.run_helper(&test(path, "-e", bound))) {
        Ok(true) => result,
        Ok(false) => ProbeResult::absent(),
        Err(unknown) => unknown,
    }
}

/// `/bin/test <flag> <path>`.
fn test(path: &Path, flag: &str, bound: Duration) -> Helper {
    Helper::new(
        TEST,
        [OsString::from(flag), path.as_os_str().to_owned()],
        bound,
    )
}

/// The parent-process names of `pid`, nearest first, through
/// `ps -o ppid=,comm= -p <pid>` one ancestor at a time: bounded by
/// [`MAX_CHAIN_DEPTH`] and cycle-safe, as `pam_client::caller` walks it.
#[must_use]
pub fn harness_chain(os: &dyn Os, pid: u32, bound: Duration) -> Vec<String> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    let mut current = pid;
    for _ in 0..=MAX_CHAIN_DEPTH {
        if !seen.insert(current) || names.len() >= MAX_CHAIN_NAMES {
            break;
        }
        let helper = Helper::new(PS, ["-o", "ppid=,comm=", "-p", &current.to_string()], bound);
        let HelperOutcome::Ran(run) = os.run_helper(&helper) else {
            break;
        };
        let Some((parent, name)) = parse_ps_line(&run.stdout) else {
            break;
        };
        if current != pid {
            names.push(name);
        }
        if parent == 0 {
            break;
        }
        current = parent;
    }
    names
}
