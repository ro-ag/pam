//! The macOS probes whose mechanism is unix-specific: the admin and engine
//! sockets (connect, drop, send nothing), the keychain through
//! `/usr/bin/security`, the daemon's signal right through `/bin/kill -0`,
//! the `LaunchServices` broker through a read-only `/usr/bin/lsappinfo`
//! query of the session's login window, the application-services broker
//! behind `AppleEvents` through `/usr/bin/osascript -e 'id of application
//! "Finder"'` (a property read of the running Finder: no event is sent to
//! it, nothing is launched, nothing prompts), the bundle's `Info.plist`
//! opened for write, and the harness chain through `/bin/ps`.
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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pam_daemon::secrets::SECRET_SERVICE;
use pam_proto::caller::MAX_CHAIN_DEPTH;
use pam_proto::doctor::{MAX_CHAIN_NAMES, ProbeId, ProbeResult};

use super::classify::{
    bundle_root, classify_appleevents, classify_connect, classify_io_result, classify_kill,
    classify_launchservices, classify_security, parse_ps_line,
};
use super::helpers::{Helper, HelperOutcome};
use super::inventory::{
    ADMIN_DIR, ADMIN_SOCKET, Context, ENGINE_SOCKET, Planned, RUN_DIR, file_op, lock_pid,
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

/// `<bundle>/Contents/Info.plist` opened for write when the executable sits
/// in an application bundle; `absent` otherwise.
fn bundle_write(context: &Context) -> Planned {
    let platform = context.platform;
    file_op(context, ProbeId::BundleWrite, move |os| {
        let exe = match os.current_exe() {
            Ok(exe) => exe,
            Err(error) => {
                return ProbeResult::unknown(format!("current_exe: {:?}", error.kind()))
                    .with_os_error(pam_proto::doctor::OsError::from_io(&error));
            }
        };
        match bundle_root(&exe) {
            Some(bundle) => classify_io_result(
                platform,
                os.open_write(&bundle.join("Contents").join("Info.plist")),
            ),
            None => ProbeResult::absent().with_note("not inside an application bundle"),
        }
    })
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
