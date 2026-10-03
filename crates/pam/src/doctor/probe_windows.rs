//! The Windows probes whose mechanism differs from macOS: the admin control
//! file opened for read and closed **without reading a byte** (decision 2:
//! the ACL is evaluated at `CreateFile`; the nonce never enters this
//! process and the admin port is never dialled — this file names no
//! socket), the Credential Manager through the daemon's own keyring backend
//! for an account that cannot exist, the daemon's query rights through a
//! `PowerShell` `Get-Process` (query only, never termination rights: that
//! needs `OpenProcess` through FFI, which the workspace forbids), process
//! creation as the `ShellExecute` broker, the running executable opened
//! for write through the seam (decision below), and the harness chain
//! through `Win32_Process`.
//!
//! The executable keeps the open here, unlike macOS: Windows holds the
//! image section of a running executable, so `CreateFile` with write
//! access is refused at the share check — after the ACL's access check,
//! which is why `ERROR_SHARING_VIOLATION` classifies as `allowed` — before
//! any handle exists, and Windows keeps no code-signature cache that the
//! attempt could invalidate. The non-opening alternatives answer a
//! different question: the read-only attribute is not the ACL, and a
//! directory opened for write is always `ERROR_ACCESS_DENIED` here, which
//! would read `denied` for an unsandboxed process — a false pass.
//!
//! Every helper lives under `%SystemRoot%\System32`; `SystemRoot` is read
//! through the seam with `C:\Windows` as the fallback.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::caller::MAX_CHAIN_DEPTH;
use pam_proto::doctor::ProbeId;

use super::classify::{
    classify_io_result, classify_keyring, classify_process_query, classify_shell_execute,
};
use super::helpers::{Helper, HelperOutcome};
use super::inventory::{
    ADMIN_CONTROL, ADMIN_DIR, Context, Planned, current_exe, daemon_pid, file_op, open_read,
    reach_bound,
};
use super::os::Os;

/// The fallback for `%SystemRoot%`.
pub const DEFAULT_SYSTEM_ROOT: &str = r"C:\Windows";

/// `where.exe`, relative to `System32`: the process-creation probe.
pub const WHERE: &str = "where.exe";

/// Windows `PowerShell`, relative to `System32`.
pub const POWERSHELL: &str = r"WindowsPowerShell\v1.0\powershell.exe";

/// The plan for a Windows-specific probe; `None` for the shared ones and
/// for the macOS-only ones.
#[must_use]
pub fn plan(id: ProbeId, context: &Context) -> Option<Planned> {
    Some(match id {
        ProbeId::AdminControlRead => open_read(
            context,
            id,
            context.base.join(ADMIN_DIR).join(ADMIN_CONTROL),
        ),
        ProbeId::KeychainSearch => {
            let os = Arc::clone(&context.os);
            let account = context.absent_account();
            Planned {
                id,
                bound: context.options.helper_bound,
                op: Box::new(move || classify_keyring(os.keyring_get(&account)).into()),
            }
        }
        ProbeId::DaemonProcessQuery => process_query(context),
        ProbeId::BrokerShellExecute => {
            let os = Arc::clone(&context.os);
            let helper = Helper::new(
                system32(os.as_ref()).join(WHERE),
                ["/?"],
                context.options.helper_bound,
            );
            Planned {
                id,
                bound: helper.timeout + Duration::from_secs(1),
                op: Box::new(move || classify_shell_execute(&os.run_helper(&helper)).into()),
            }
        }
        // Through the seam only: never created or truncated, no byte
        // written; the share check refuses it after the ACL's access check
        // (the module doc says why this is not `access(2)` as on macOS).
        ProbeId::ExeWrite => {
            let platform = context.platform;
            file_op(context, id, move |os| match current_exe(os) {
                Ok(exe) => classify_io_result(platform, os.open_write(&exe)),
                Err(result) => result,
            })
        }
        _ => return None,
    })
}

/// `Get-Process -Id <pid>` of the pid the daemon's hello acknowledgement
/// named, printing `PATH=<exe>`: query rights only. Waits for the reach
/// probe like `daemon.signal` on macOS; `not_probed` when no daemon was
/// reached.
fn process_query(context: &Context) -> Planned {
    let os = Arc::clone(&context.os);
    let cell = Arc::clone(&context.daemon_pid);
    let hello_bound = context.options.hello_bound;
    let bound = context.options.helper_bound;
    Planned {
        id: ProbeId::DaemonProcessQuery,
        bound: reach_bound(hello_bound) + bound + Duration::from_secs(1),
        op: Box::new(move || match daemon_pid(&cell, hello_bound) {
            Ok(pid) => {
                let script = format!(
                    "$p = Get-Process -Id {pid} -ErrorAction Stop; Write-Output ('PATH=' + [string]$p.Path)"
                );
                classify_process_query(&os.run_helper(&powershell(os.as_ref(), &script, bound)))
                    .into()
            }
            Err(result) => result.into(),
        }),
    }
}

/// The parent-process names of `pid`, nearest first, through one
/// `PowerShell` walk of `Win32_Process`: bounded by [`MAX_CHAIN_DEPTH`] and
/// cycle-safe.
#[must_use]
pub fn harness_chain(os: &dyn Os, pid: u32, bound: Duration) -> Vec<String> {
    let script = format!(
        "$id = {pid}; $seen = @{{}}; \
         for ($i = 0; $i -le {MAX_CHAIN_DEPTH} -and $id; $i++) {{ \
           if ($seen.ContainsKey($id)) {{ break }}; $seen[$id] = $true; \
           $p = Get-CimInstance Win32_Process -Filter \"ProcessId = $id\"; \
           if (-not $p) {{ break }}; \
           if ($i -gt 0) {{ Write-Output $p.Name }}; \
           $id = $p.ParentProcessId }}"
    );
    match os.run_helper(&powershell(os, &script, bound)) {
        HelperOutcome::Ran(run) => run
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect(),
        HelperOutcome::SpawnFailed(_) | HelperOutcome::TimedOut(_) => Vec::new(),
    }
}

/// A non-interactive, profile-less `PowerShell` running `script`.
fn powershell(os: &dyn Os, script: &str, bound: Duration) -> Helper {
    Helper::new(
        system32(os).join(POWERSHELL),
        [
            "-NoProfile",
            "-NonInteractive",
            "-NoLogo",
            "-Command",
            script,
        ],
        bound,
    )
}

/// `%SystemRoot%\System32`.
fn system32(os: &dyn Os) -> PathBuf {
    os.env_var("SystemRoot")
        .filter(|root| !root.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_SYSTEM_ROOT), PathBuf::from)
        .join("System32")
}
