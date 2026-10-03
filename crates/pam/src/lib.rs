//! Library side of the `pam` binary: testable modules behind the thin CLI. Client-side modules
//! (`client`, `request`, `caller`, base-dir resolution) live in `pam_client` — shared with the GUI
//! bridge, which cannot depend on this crate — and are re-exported here.
//!
//! CLI surface (v0): client by default, `pam daemon` for the background service, `pam gui` for the
//! desktop control center. Agents see **only static subcommands** — no raw-protocol escape hatch
//! and no security commands (grants, approvals, revocations, profile changes are GUI-only). `echo`
//! is diagnostic-only, not for production. `flow run` defaults to a 30-minute deadline and streams
//! as one request (`--no-wait` + `subscribe` to watch step by step). `service install` writes the
//! unit first and then stops a loose daemon; it refuses a binary in a temp or cargo `target/`
//! directory or a group/world-writable location, and pins a base directory only when `--base-dir` is
//! given; `uninstall` stops the managed daemon on macOS (the next command starts one lazily).
//! `pam doctor` probes the caller's own sandbox boundary and records the verdict with the daemon
//! (`--profile` prints a reference sandbox profile instead). Exit codes: `0` success, `1`
//! transport/client failure (for `doctor`: `cannot_probe`), `2` usage error, `3` refused, `4`
//! unresolved, `5` blocked, `6` boundary not established (`doctor` only), and for `pam policy
//! check` only: `11` not trusted (`--trust`), `12` the file is invalid as a whole, `13` the file
//! is valid but some leaves are rejected.
//!
//! `pam policy check <file>` is the one command about the organization's managed policy, and it
//! is not a security command: it reads the file the administrator names, the way the daemon would
//! ([`check_policy_file`]), and changes nothing — no daemon, no store, no socket, no write. There
//! is no command that sets, applies or installs a policy; the file is the MDM's.

use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use pam_daemon::managed_policy::{self, Inspection, TargetPlatform};
use pam_daemon::managed_policy_trust::{self, TrustRules, Untrusted};
use serde_json::Value;

pub use pam_client::{base_dir_from, caller, client, default_base_dir, request};

pub mod doctor;
pub mod render;

/// The agent playbook, shipped inside the binary (`pam playbook`): the
/// discover/run/read loop, refusal handling, exit codes and the sandbox
/// case, distilled from `docs/agent-workflow-contract.md`, which stays the
/// authoritative long form.
pub const PLAYBOOK: &str = include_str!("../../../docs/pam-playbook.md");

/// True when `exe` sits inside a macOS application bundle
/// (`…/Something.app/Contents/MacOS/pam`): a bare double-click launch,
/// which should open the GUI. A bare terminal launch prints help.
///
/// The check is on a component's *extension*, not a suffix, so
/// `pam.app.backup` and `pam.application` are not bundles; the macOS
/// filesystem is case-insensitive, so the extension match is too.
#[must_use]
pub fn launched_from_app_bundle(exe: &Path) -> bool {
    exe.components().any(|part| {
        Path::new(part.as_os_str())
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
    })
}

/// What `pam policy check` found in one file: the content, checked for
/// one platform, and — with `--trust` — how this machine's production
/// trust rules judge the file where it sits.
#[derive(Debug)]
pub struct PolicyCheck {
    /// The path as the caller named it.
    pub path: PathBuf,
    /// The platform the document's paths were checked for.
    pub platform: TargetPlatform,
    /// The inspected document, or the size of a file refused unread.
    pub content: PolicyContent,
    /// The trust check, when it was asked for.
    pub trust: Option<PolicyTrust>,
}

/// The document half of a [`PolicyCheck`].
#[derive(Debug)]
pub enum PolicyContent {
    /// The bytes went through [`managed_policy::inspect_bytes`].
    Inspected {
        /// What the daemon's reader found.
        inspection: Box<Inspection>,
        /// The document as plain JSON, for printing each applied leaf's
        /// value; `None` when the file is invalid as a whole.
        document: Option<Value>,
    },
    /// The file is larger than [`managed_policy::MAX_POLICY_BYTES`]; it
    /// was not read.
    TooLarge {
        /// Its size in bytes.
        size: u64,
    },
}

/// The trust half of a [`PolicyCheck`].
#[derive(Debug)]
pub struct PolicyTrust {
    /// The path judged: the named file in its own directory, made absolute
    /// with the directory resolved (so `/tmp` reads as `/private/tmp`); the
    /// file itself is never resolved, so a symlink is judged as one.
    pub checked_path: PathBuf,
    /// The fixed path the daemon reads on this machine.
    pub fixed_path: PathBuf,
    /// The verdict of [`managed_policy_trust::verify_and_read`] under
    /// [`TrustRules::production`].
    pub outcome: Result<(), Untrusted>,
    /// The file's owner uid and permission bits, as `lstat` reports them
    /// (unix only; `None` elsewhere or when the file cannot be read).
    pub observed: Option<(u32, u32)>,
}

impl PolicyTrust {
    /// Whether the checked path is the path the daemon reads.
    #[must_use]
    pub fn at_fixed_path(&self) -> bool {
        if cfg!(windows) {
            self.checked_path
                .to_string_lossy()
                .eq_ignore_ascii_case(&self.fixed_path.to_string_lossy())
        } else {
            self.checked_path == self.fixed_path
        }
    }
}

/// `pam policy check`: reads `path` (refusing anything but a regular file,
/// and a file over [`managed_policy::MAX_POLICY_BYTES`] before reading
/// it), inspects it for `platform` exactly as the daemon would, and with
/// `trust` runs this machine's production trust check on the file where it
/// sits. Writes nothing and contacts no daemon.
///
/// # Errors
///
/// The file cannot be opened or read, or is not a regular file.
pub fn check_policy_file(
    path: &Path,
    platform: TargetPlatform,
    trust: bool,
) -> io::Result<PolicyCheck> {
    let content = match read_policy_bytes(path)? {
        PolicyBytes::Read(bytes) => {
            let inspection = managed_policy::inspect_bytes(&bytes, platform);
            let document = inspection.result.is_ok().then(|| plain_document(&bytes));
            PolicyContent::Inspected {
                inspection: Box::new(inspection),
                document: document.flatten(),
            }
        }
        PolicyBytes::TooLarge { size } => PolicyContent::TooLarge { size },
    };
    Ok(PolicyCheck {
        path: path.to_path_buf(),
        platform,
        content,
        trust: trust.then(|| policy_trust(path)),
    })
}

/// A policy file's bytes, or the size of one too large to read.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyBytes {
    /// At most [`managed_policy::MAX_POLICY_BYTES`] bytes.
    Read(Vec<u8>),
    /// Over the bound: refused unread.
    TooLarge {
        /// Its size in bytes.
        size: u64,
    },
}

/// Reads a policy file the caller names, bounded: a path that is not a
/// regular file (a directory, a fifo that would block the open, a device)
/// is refused before it is opened, and a file over the bound is refused on
/// its size, unread. The read itself takes at most one byte more than the
/// bound, so a file that grows during the read is refused too.
///
/// # Errors
///
/// The path cannot be stat'ed or opened, or is not a regular file.
pub fn read_policy_bytes(path: &Path) -> io::Result<PolicyBytes> {
    const MAX: u64 = managed_policy::MAX_POLICY_BYTES as u64;
    let not_regular = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file; a policy is a JSON file",
        )
    };
    if !std::fs::metadata(path)?.is_file() {
        return Err(not_regular());
    }
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > MAX {
        return Ok(PolicyBytes::TooLarge {
            size: metadata.len(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX {
        return Ok(PolicyBytes::TooLarge {
            size: bytes.len() as u64,
        });
    }
    Ok(PolicyBytes::Read(bytes))
}

/// The bytes as plain JSON (a leading byte-order mark dropped), for
/// printing leaf values. Only called once the strict reader accepted the
/// file, so this parse cannot disagree with it.
fn plain_document(bytes: &[u8]) -> Option<Value> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    serde_json::from_slice(bytes).ok()
}

/// The production trust check on the file where it sits ([`PolicyTrust`]).
fn policy_trust(path: &Path) -> PolicyTrust {
    let fixed_path = managed_policy_trust::policy_path();
    let checked_path = trust_check_path(path, &fixed_path);
    let outcome =
        managed_policy_trust::verify_and_read(&checked_path, &TrustRules::production()).map(drop);
    PolicyTrust {
        observed: observed_owner_and_mode(&checked_path),
        checked_path,
        fixed_path,
        outcome,
    }
}

/// The path the trust check judges: absolute, the parent directory
/// resolved (without a verbatim `\\?\` prefix on Windows), the file name
/// kept as named. A parent that cannot be resolved leaves the absolute path
/// as is, and the check then says why. The fixed policy path is never
/// resolved: a link anywhere in it is what the daemon refuses, so a
/// compliance check of the installed file must see it too.
fn trust_check_path(path: &Path, fixed: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    if same_path(&absolute, fixed) {
        return absolute;
    }
    let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return absolute;
    };
    let Ok(parent) = parent.canonicalize() else {
        return absolute;
    };
    let parent = PathBuf::from(
        managed_policy::without_verbatim_prefix(&parent.to_string_lossy()).into_owned(),
    );
    parent.join(name)
}

/// The same path as spelled, without a verbatim prefix; Windows names are
/// compared without regard to case.
fn same_path(left: &Path, right: &Path) -> bool {
    let key = |path: &Path| {
        let text = managed_policy::without_verbatim_prefix(&path.to_string_lossy()).into_owned();
        if cfg!(windows) {
            text.to_ascii_lowercase()
        } else {
            text
        }
    };
    key(left) == key(right)
}

/// The owner uid and permission bits `lstat` reports for `path`.
#[cfg(unix)]
fn observed_owner_and_mode(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::symlink_metadata(path).ok()?;
    Some((metadata.uid(), metadata.mode() & 0o7777))
}

/// Not reported off unix: Windows has no owner read in safe `std`.
#[cfg(not(unix))]
fn observed_owner_and_mode(_path: &Path) -> Option<(u32, u32)> {
    None
}

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod lib_test;
#[cfg(test)]
mod render_test;
