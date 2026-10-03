//! The trust check for the managed policy file and for any file it names.
//!
//! An organisation delivers one policy file to a root- or
//! Administrators-owned location; PAM trusts it only when the operating
//! system says neither the human at the keyboard nor the agent in the
//! sandbox (both run as the daemon's own user) could have written it.
//! [`verify_and_read`] judges that on the opened handle, not on a path that
//! can change between the check and the read, and returns the bytes it read
//! through that same handle.
//!
//! The location is fixed per platform ([`policy_path`]): no environment
//! variable, flag, `<base>` file or admin op can move it. The one input
//! taken from the environment, `ProgramData` on Windows, is accepted only in
//! its plain drive-letter form and the result is trust-checked like any
//! other path ([`windows_policy_path`]).
//!
//! **macOS (any unix)**, with `std` only, in this order:
//!
//! 1. The path is absolute; `symlink_metadata` says a regular file, not a
//!    symlink, not a directory, fifo or device, and the owner and mode of
//!    step 5 already hold (so the cause reported is the file's own).
//! 2. The path is canonical (`canonicalize(path) == path`), so no component
//!    is a symlink.
//! 3. Every ancestor, to `/`, is a real directory owned by an allowed owner
//!    (root in production) and writable by neither its group nor the world.
//!    There is no sticky-directory exemption: a policy has no business in a
//!    temp directory. Checked before the open, so the open itself can only
//!    race a root-controlled directory.
//! 4. Opened read-only; the handle's `(dev, ino)` must equal step 1's. A
//!    swap between the stat and the open (an atomic replace by the delivery
//!    script, most likely) is `busy`: the next poll retries.
//! 5. On the handle: a regular file owned by the expected owner (root in
//!    production), no group or world write, and none of the setuid, setgid,
//!    sticky or execute bits. A policy and a CA bundle are data; refusing an
//!    executable also means the write probe below never opens a Mach-O for
//!    write.
//! 6. A write-open probe (`OpenOptions::write(true)`, never create, truncate
//!    or append, closed at once): when it succeeds an ACL or a privilege the
//!    mode bits did not show lets the daemon's user modify the file. An open
//!    without truncation changes neither content nor mtime. A daemon running
//!    as root passes this probe and the file reads untrusted, by design.
//! 7. At most `max_bytes + 1` bytes are read from the handle; one more byte
//!    than the bound is `too_large`.
//!
//! **Windows** has no owner or DACL read in safe `std`, so the check asks
//! the operating system the question that matters: can this process's own
//! token modify the file or its folder? Each probe is an
//! `OpenOptionsExt::access_mode` open of one right with no write disposition
//! (it changes nothing) that must fail with access denied:
//!
//! 1. Neither the file nor its folder is a symlink or junction, the file is
//!    regular, and the canonical path equals the given one (a junction
//!    anywhere above is caught too).
//! 2. File: `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `FILE_WRITE_ATTRIBUTES`,
//!    `DELETE`, `WRITE_DAC`, `WRITE_OWNER` (`FILE_WRITE_ATTRIBUTES` because a
//!    read-only attribute masks the write rights from a token that may clear
//!    it).
//! 3. Folder: `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_DELETE_CHILD`,
//!    `DELETE`, `WRITE_DAC`, `WRITE_OWNER`; the folder's parent (for the
//!    policy, `%ProgramData%`): `FILE_DELETE_CHILD`, `DELETE`, `WRITE_DAC`.
//! 4. The bytes are read through a handle opened with `FILE_SHARE_READ`, so
//!    no writer holds the file during the read; a sharing violation is
//!    `busy`.
//!
//! What the Windows rule does not prove (it cannot see an ACE for a
//! different account, nor read the owner) is recorded in the spec
//! (`docs/specs/2026-10-02-managed-policy-file.md`, "The trust check") and
//! every rule is verified in the Windows VM before it is relied on.

use std::fmt;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;

/// Where an MDM puts the policy on macOS: `root:wheel`, `0644`, in a
/// `root:wheel 0755` directory.
pub const MACOS_POLICY_PATH: &str = "/Library/Application Support/PAM/policy.json";

/// The `%ProgramData%` used when the environment's value is missing or is
/// not a plain `<drive>:\ProgramData`.
pub const WINDOWS_PROGRAM_DATA_FALLBACK: &str = r"C:\ProgramData";

/// The policy file's place under `%ProgramData%`.
pub const WINDOWS_POLICY_RELATIVE: &str = r"PAM\policy.json";

/// The size bound on a policy file: 64 KiB. One byte more is `too_large`.
pub const MAX_POLICY_BYTES: u64 = 64 * 1024;

/// The fixed policy path of the platform this binary runs on.
///
/// macOS: [`MACOS_POLICY_PATH`]. Windows: [`windows_policy_path`] of the
/// process's `ProgramData`. No other input moves it.
#[must_use]
pub fn policy_path() -> PathBuf {
    #[cfg(windows)]
    {
        windows_policy_path(std::env::var_os("ProgramData").as_deref())
    }
    #[cfg(not(windows))]
    {
        PathBuf::from(MACOS_POLICY_PATH)
    }
}

/// `<ProgramData>\PAM\policy.json`, where `<ProgramData>` is the given value
/// only when it is exactly `<letter>:\ProgramData` (any case) and
/// [`WINDOWS_PROGRAM_DATA_FALLBACK`] otherwise.
///
/// A lazily started daemon inherits `ProgramData` from whoever first called
/// `pam`, an agent included; this rule leaves an agent no choice but the
/// drive, and a drive it controls fails the trust check. Pure, so it is
/// tested on every platform.
#[must_use]
pub fn windows_policy_path(program_data: Option<&std::ffi::OsStr>) -> PathBuf {
    let root = program_data
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| is_plain_program_data(value))
        .unwrap_or(WINDOWS_PROGRAM_DATA_FALLBACK);
    PathBuf::from(format!("{root}\\{WINDOWS_POLICY_RELATIVE}"))
}

/// `^[A-Za-z]:\\ProgramData$`, case-insensitive.
fn is_plain_program_data(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 14
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && value[3..].eq_ignore_ascii_case("ProgramData")
}

/// Why a file is not trusted. Each reason has a stable wire code
/// ([`UntrustedReason::code`]) that `status`, the audit trail, the doctor and
/// `pam policy check` report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UntrustedReason {
    /// The file is not owned by the expected owner (root in production).
    NotOwnedByRoot,
    /// The daemon's user (or its group, or everyone) can modify the file.
    WritableByUser,
    /// The file, or a component of its path, is a symlink or junction.
    Symlink,
    /// A directory above the file can be modified by the daemon's user, or
    /// is owned by someone other than the allowed owners.
    ParentWritable,
    /// Not a plain regular data file: a directory, fifo, device, an
    /// executable, or a file with special mode bits.
    NotRegular,
    /// Larger than the bound.
    TooLarge,
    /// The file changed while it was being checked, or a writer holds it
    /// open. Transient: the previous view stays and the next poll retries.
    Busy,
    /// The file cannot be read (missing, permission, I/O error).
    Unreadable,
}

impl UntrustedReason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 8] = [
        Self::NotOwnedByRoot,
        Self::WritableByUser,
        Self::Symlink,
        Self::ParentWritable,
        Self::NotRegular,
        Self::TooLarge,
        Self::Busy,
        Self::Unreadable,
    ];

    /// The stable code. Never renamed: MDM scripts and audit queries match
    /// on it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotOwnedByRoot => "not_owned_by_root",
            Self::WritableByUser => "writable_by_user",
            Self::Symlink => "symlink",
            Self::ParentWritable => "parent_writable",
            Self::NotRegular => "not_regular",
            Self::TooLarge => "too_large",
            Self::Busy => "busy",
            Self::Unreadable => "unreadable",
        }
    }

    /// What the administrator does about it.
    #[must_use]
    pub const fn recovery(self) -> &'static str {
        match self {
            Self::NotOwnedByRoot | Self::WritableByUser | Self::ParentWritable => {
                "Install the file and its folder with the delivery script in \
                 docs/managed-policy.md, so that only root (macOS) or SYSTEM and Administrators \
                 (Windows) can change them."
            }
            Self::Symlink => {
                "Install the file itself at the fixed path; a symbolic link or junction is never \
                 followed."
            }
            Self::NotRegular => {
                "Install a plain data file (macOS: mode 0644, no execute or setuid bits)."
            }
            Self::TooLarge => "Keep the policy under the size limit; split comments out of it.",
            Self::Busy => {
                "The file was being replaced; PAM reads it again at the next check. Replace it \
                 atomically (write a temporary name, then rename)."
            }
            Self::Unreadable => "Make the file readable by every user (macOS: mode 0644).",
        }
    }

    /// Whether the condition is expected to clear by itself (an atomic
    /// replace in progress).
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Busy)
    }
}

impl fmt::Display for UntrustedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A refusal: the reason, the path it is about, and a detail sentence that
/// names the cause.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{} ({}): {detail}", .path.display(), .reason.code())]
pub struct Untrusted {
    /// The stable reason.
    pub reason: UntrustedReason,
    /// The path the refusal is about: the file, or the ancestor that failed.
    pub path: PathBuf,
    /// One sentence naming the cause.
    pub detail: String,
    absent: bool,
}

impl Untrusted {
    fn new(reason: UntrustedReason, path: &Path, detail: impl Into<String>) -> Self {
        Self {
            reason,
            path: path.to_path_buf(),
            detail: detail.into(),
            absent: false,
        }
    }

    fn absent(path: &Path) -> Self {
        Self {
            absent: true,
            ..Self::new(UntrustedReason::Unreadable, path, "no file at this path")
        }
    }

    /// The stable code of the reason.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.reason.code()
    }

    /// The recovery line for the reason.
    #[must_use]
    pub const fn recovery(&self) -> &'static str {
        self.reason.recovery()
    }

    /// True when there was no file at the path when the check began (the
    /// file or a directory above it does not exist): the caller's `none`
    /// state, not a damaged policy. The reason is then `unreadable`. A file
    /// that disappears after the first look is `busy` instead.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.absent
    }
}

/// Bytes read from a file that passed the trust check, through the handle
/// the check judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedBytes {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl TrustedBytes {
    /// The path that was checked (canonical: the check refuses any other).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The raw bytes, BOM and all.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The raw bytes, owned.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// A test seam run between the first `symlink_metadata` and the open, so a
/// test can swap or remove the file in exactly the window the handle
/// identity check guards.
#[cfg(test)]
pub(crate) type OpenHook = Arc<dyn Fn(&Path) + Send + Sync>;

/// The rules a file is judged by.
///
/// [`TrustRules::production`] is the only constructor non-test code calls:
/// root ownership on unix, the token probes on Windows, the 64 KiB bound.
/// Tests on unix build [`TrustRules::owned_by`] for a temp tree they own,
/// because no test can create a root-owned file.
#[derive(Clone)]
pub struct TrustRules {
    #[cfg(unix)]
    owner_uid: u32,
    #[cfg(unix)]
    ancestor_owners: Vec<u32>,
    max_bytes: u64,
    #[cfg(test)]
    before_open: Option<OpenHook>,
}

impl fmt::Debug for TrustRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("TrustRules");
        #[cfg(unix)]
        out.field("owner_uid", &self.owner_uid)
            .field("ancestor_owners", &self.ancestor_owners);
        out.field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl TrustRules {
    /// The production rule: on unix the file is owned by root and every
    /// ancestor is owned by root; on Windows the daemon's token holds no
    /// modifying right on the file or its folder. Bound: [`MAX_POLICY_BYTES`].
    #[must_use]
    pub fn production() -> Self {
        Self {
            #[cfg(unix)]
            owner_uid: 0,
            #[cfg(unix)]
            ancestor_owners: vec![0],
            max_bytes: MAX_POLICY_BYTES,
            #[cfg(test)]
            before_open: None,
        }
    }

    /// A fixture rule for a tree the test user owns: the file must be owned
    /// by `uid`, and each ancestor by root or by `uid`. Every other rule
    /// (modes, symlinks, the write probe, the size) is the production one.
    /// Production code never calls this; it would trust the user's own
    /// files.
    #[cfg(unix)]
    #[must_use]
    pub fn owned_by(uid: u32) -> Self {
        Self {
            owner_uid: uid,
            ancestor_owners: if uid == 0 { vec![0] } else { vec![0, uid] },
            ..Self::production()
        }
    }

    /// The same rules with another size bound (a CA bundle the policy names
    /// is bounded by the CA import's limit, not the policy's).
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The uid the file must be owned by (0 in production).
    #[cfg(unix)]
    #[must_use]
    pub fn expected_owner(&self) -> u32 {
        self.owner_uid
    }

    /// The uids an ancestor directory may be owned by (`[0]` in production).
    #[cfg(unix)]
    #[must_use]
    pub fn ancestor_owners(&self) -> &[u32] {
        &self.ancestor_owners
    }

    /// The size bound in bytes.
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_ancestor_owners(mut self, owners: Vec<u32>) -> Self {
        self.ancestor_owners = owners;
        self
    }

    // Only the unix tests drive the swap window; on Windows the probes run
    // first and need the VM's ACL fixtures, which the matrix covers.
    #[cfg(test)]
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) fn with_before_open(mut self, hook: OpenHook) -> Self {
        self.before_open = Some(hook);
        self
    }

    fn run_before_open(&self, path: &Path) {
        #[cfg(test)]
        if let Some(hook) = &self.before_open {
            hook(path);
        }
        #[cfg(not(test))]
        let _ = (self, path);
    }
}

/// Judges `path` by `rules` and, when it passes, returns its bytes read
/// through the handle that was judged.
///
/// # Errors
///
/// [`Untrusted`] with the first rule the file broke. A missing file is
/// `unreadable` with [`Untrusted::is_absent`] true.
pub fn verify_and_read(path: &Path, rules: &TrustRules) -> Result<TrustedBytes, Untrusted> {
    if !path.is_absolute() {
        return Err(Untrusted::new(
            UntrustedReason::Unreadable,
            path,
            "the path is not absolute; a trusted file is named by its full path",
        ));
    }
    platform::verify_and_read(path, rules)
}

/// Reads at most `max_bytes + 1` bytes; the extra byte means too large.
fn read_bounded(
    reader: impl io::Read,
    path: &Path,
    max_bytes: u64,
) -> Result<TrustedBytes, Untrusted> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Untrusted::new(
                UntrustedReason::Unreadable,
                path,
                format!("the file could not be read: {error}"),
            )
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(too_large(path, max_bytes));
    }
    Ok(TrustedBytes {
        path: path.to_path_buf(),
        bytes,
    })
}

fn too_large(path: &Path, max_bytes: u64) -> Untrusted {
    Untrusted::new(
        UntrustedReason::TooLarge,
        path,
        format!("the file is larger than {max_bytes} bytes"),
    )
}

fn changed_during_check(path: &Path, what: &str) -> Untrusted {
    Untrusted::new(
        UntrustedReason::Busy,
        path,
        format!("the file changed while it was being checked ({what})"),
    )
}

#[cfg(unix)]
mod platform {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use super::{TrustRules, TrustedBytes, Untrusted, UntrustedReason};

    /// Group or world write.
    const GROUP_OR_WORLD_WRITE: u32 = 0o022;
    /// setuid, setgid, sticky.
    const SPECIAL_BITS: u32 = 0o7000;
    /// Any execute bit.
    const EXECUTE_BITS: u32 = 0o111;

    pub(super) fn verify_and_read(
        path: &Path,
        rules: &TrustRules,
    ) -> Result<TrustedBytes, Untrusted> {
        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(Untrusted::absent(path));
            }
            Err(error) => return Err(unreadable(path, &error)),
        };
        if before.file_type().is_symlink() {
            return Err(Untrusted::new(
                UntrustedReason::Symlink,
                path,
                "the path is a symbolic link; only the file itself is trusted",
            ));
        }
        // Owner and mode first from the stat, so the cause reported is the
        // file's own; they are judged again on the handle below.
        check_handle(path, &before, rules)?;
        check_canonical(path)?;
        check_ancestors(path, rules)?;

        rules.run_before_open(path);
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(super::changed_during_check(path, "it was removed"));
            }
            Err(error) => return Err(unreadable(path, &error)),
        };
        let handle = file.metadata().map_err(|error| unreadable(path, &error))?;
        if (handle.dev(), handle.ino()) != (before.dev(), before.ino()) {
            return Err(super::changed_during_check(path, "it was replaced"));
        }
        check_handle(path, &handle, rules)?;
        probe_write(path)?;
        if handle.len() > rules.max_bytes {
            return Err(super::too_large(path, rules.max_bytes));
        }
        super::read_bounded(file, path, rules.max_bytes)
    }

    fn unreadable(path: &Path, error: &io::Error) -> Untrusted {
        Untrusted::new(
            UntrustedReason::Unreadable,
            path,
            format!("the file cannot be read: {error}"),
        )
    }

    fn not_regular_kind(path: &Path) -> Untrusted {
        Untrusted::new(
            UntrustedReason::NotRegular,
            path,
            "the path is not a regular file (a directory, fifo, socket or device)",
        )
    }

    /// The path must already be canonical: a symlink in any directory
    /// component would make the file someone else's choice.
    fn check_canonical(path: &Path) -> Result<(), Untrusted> {
        match fs::canonicalize(path) {
            Ok(canonical) if canonical == path => Ok(()),
            Ok(canonical) => Err(Untrusted::new(
                UntrustedReason::Symlink,
                path,
                format!(
                    "a directory on the path is a symbolic link (it resolves to {})",
                    canonical.display()
                ),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(super::changed_during_check(path, "it was removed"))
            }
            Err(error) => Err(unreadable(path, &error)),
        }
    }

    /// Every ancestor to `/`: a real directory, an allowed owner, no group or
    /// world write. No sticky exemption.
    fn check_ancestors(path: &Path, rules: &TrustRules) -> Result<(), Untrusted> {
        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                continue;
            }
            let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
                Untrusted::new(
                    UntrustedReason::Unreadable,
                    ancestor,
                    format!("a directory above the file cannot be inspected: {error}"),
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(Untrusted::new(
                    UntrustedReason::Symlink,
                    ancestor,
                    "a directory above the file is a symbolic link",
                ));
            }
            if !metadata.is_dir() {
                return Err(Untrusted::new(
                    UntrustedReason::NotRegular,
                    ancestor,
                    "a component above the file is not a directory",
                ));
            }
            if !rules.ancestor_owners.contains(&metadata.uid()) {
                return Err(Untrusted::new(
                    UntrustedReason::ParentWritable,
                    ancestor,
                    format!(
                        "a directory above the file is owned by uid {}, not root; its owner can \
                         replace the file",
                        metadata.uid()
                    ),
                ));
            }
            if metadata.mode() & GROUP_OR_WORLD_WRITE != 0 {
                return Err(Untrusted::new(
                    UntrustedReason::ParentWritable,
                    ancestor,
                    format!(
                        "a directory above the file is writable by its group or by everyone \
                         (mode {:04o})",
                        metadata.mode() & 0o7777
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Owner, mode and kind, read from the opened handle.
    fn check_handle(
        path: &Path,
        handle: &fs::Metadata,
        rules: &TrustRules,
    ) -> Result<(), Untrusted> {
        if !handle.is_file() {
            return Err(not_regular_kind(path));
        }
        if handle.uid() != rules.owner_uid {
            return Err(Untrusted::new(
                UntrustedReason::NotOwnedByRoot,
                path,
                format!(
                    "the file is owned by uid {}; only a file owned by uid {} is trusted",
                    handle.uid(),
                    rules.owner_uid
                ),
            ));
        }
        let mode = handle.mode() & 0o7777;
        if mode & GROUP_OR_WORLD_WRITE != 0 {
            return Err(Untrusted::new(
                UntrustedReason::WritableByUser,
                path,
                format!("the file mode {mode:04o} lets its group or everyone write it"),
            ));
        }
        if mode & (SPECIAL_BITS | EXECUTE_BITS) != 0 {
            return Err(Untrusted::new(
                UntrustedReason::NotRegular,
                path,
                format!(
                    "the file mode {mode:04o} has setuid, setgid, sticky or execute bits; a \
                     trusted file is plain data"
                ),
            ));
        }
        Ok(())
    }

    /// Opens the file for write without create, truncate or append, and
    /// closes it at once: nothing is written, the mtime does not move. Only
    /// a refusal by permission (or a read-only filesystem) passes; any other
    /// failure is not evidence that the file is safe.
    fn probe_write(path: &Path) -> Result<(), Untrusted> {
        match OpenOptions::new().write(true).open(path) {
            Ok(_probe) => Err(Untrusted::new(
                UntrustedReason::WritableByUser,
                path,
                "the daemon's user can open the file for writing (an ACL or a privilege the \
                 mode bits do not show, or the daemon runs as root)",
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(super::changed_during_check(path, "it was removed"))
            }
            Err(error) => Err(Untrusted::new(
                UntrustedReason::Unreadable,
                path,
                format!("the write-access probe failed for another reason: {error}"),
            )),
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{TrustRules, TrustedBytes, Untrusted, UntrustedReason};

    // Access rights (winnt.h). File and directory names share bits.
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_APPEND_DATA: u32 = 0x0004;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
    const FILE_DELETE_CHILD: u32 = 0x0040;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;

    // Share modes and flags.
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    // Win32 error codes.
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    const FILE_RIGHTS: [(u32, &str); 6] = [
        (FILE_WRITE_DATA, "FILE_WRITE_DATA"),
        (FILE_APPEND_DATA, "FILE_APPEND_DATA"),
        (FILE_WRITE_ATTRIBUTES, "FILE_WRITE_ATTRIBUTES"),
        (DELETE, "DELETE"),
        (WRITE_DAC, "WRITE_DAC"),
        (WRITE_OWNER, "WRITE_OWNER"),
    ];
    const FOLDER_RIGHTS: [(u32, &str); 6] = [
        (FILE_ADD_FILE, "FILE_ADD_FILE"),
        (FILE_ADD_SUBDIRECTORY, "FILE_ADD_SUBDIRECTORY"),
        (FILE_DELETE_CHILD, "FILE_DELETE_CHILD"),
        (DELETE, "DELETE"),
        (WRITE_DAC, "WRITE_DAC"),
        (WRITE_OWNER, "WRITE_OWNER"),
    ];
    const GRANDPARENT_RIGHTS: [(u32, &str); 3] = [
        (FILE_DELETE_CHILD, "FILE_DELETE_CHILD"),
        (DELETE, "DELETE"),
        (WRITE_DAC, "WRITE_DAC"),
    ];

    pub(super) fn verify_and_read(
        path: &Path,
        rules: &TrustRules,
    ) -> Result<TrustedBytes, Untrusted> {
        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if is_not_found(&error) => return Err(Untrusted::absent(path)),
            Err(error) => return Err(io_refusal(path, &error, "inspected")),
        };
        if before.file_type().is_symlink() {
            return Err(Untrusted::new(
                UntrustedReason::Symlink,
                path,
                "the path is a symbolic link or junction; only the file itself is trusted",
            ));
        }
        if !before.file_type().is_file() {
            return Err(Untrusted::new(
                UntrustedReason::NotRegular,
                path,
                "the path is not a regular file",
            ));
        }
        let folder = path.parent().ok_or_else(|| {
            Untrusted::new(
                UntrustedReason::Unreadable,
                path,
                "the path has no parent folder",
            )
        })?;
        let folder_metadata = fs::symlink_metadata(folder)
            .map_err(|error| io_refusal(folder, &error, "inspected"))?;
        if folder_metadata.file_type().is_symlink() {
            return Err(Untrusted::new(
                UntrustedReason::Symlink,
                folder,
                "the folder holding the file is a symbolic link or junction",
            ));
        }
        check_canonical(path)?;

        for (right, name) in FILE_RIGHTS {
            probe(path, right, name, false, UntrustedReason::WritableByUser)?;
        }
        for (right, name) in FOLDER_RIGHTS {
            probe(folder, right, name, true, UntrustedReason::ParentWritable)?;
        }
        if let Some(grandparent) = folder.parent() {
            for (right, name) in GRANDPARENT_RIGHTS {
                probe(
                    grandparent,
                    right,
                    name,
                    true,
                    UntrustedReason::ParentWritable,
                )?;
            }
        }

        rules.run_before_open(path);
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| io_refusal(path, &error, "opened"))?;
        let handle = file
            .metadata()
            .map_err(|error| io_refusal(path, &error, "inspected"))?;
        if handle.file_type().is_symlink() || !handle.is_file() {
            return Err(super::changed_during_check(
                path,
                "it is no longer the regular file that was checked",
            ));
        }
        if handle.len() > rules.max_bytes {
            return Err(super::too_large(path, rules.max_bytes));
        }
        super::read_bounded(file, path, rules.max_bytes)
    }

    fn is_not_found(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound
    }

    fn is_busy(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
    }

    fn io_refusal(path: &Path, error: &io::Error, verb: &str) -> Untrusted {
        if is_busy(error) {
            return Untrusted::new(
                UntrustedReason::Busy,
                path,
                format!("another process holds the file open for writing: {error}"),
            );
        }
        if is_not_found(error) {
            return super::changed_during_check(path, "it was removed");
        }
        Untrusted::new(
            UntrustedReason::Unreadable,
            path,
            format!("the file cannot be {verb}: {error}"),
        )
    }

    /// `\\?\C:\...` -> `C:\...`; `\\?\UNC\server\share` stays verbatim (a
    /// network path never equals a local fixed path).
    fn strip_verbatim(path: &Path) -> PathBuf {
        let text = path.to_string_lossy();
        match text.strip_prefix(r"\\?\") {
            Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
            _ => path.to_path_buf(),
        }
    }

    /// The canonical path equals the given one, compared after
    /// canonicalization and case-insensitively (NTFS names are): a junction
    /// or symlink anywhere above makes them differ.
    fn check_canonical(path: &Path) -> Result<(), Untrusted> {
        let canonical =
            fs::canonicalize(path).map_err(|error| io_refusal(path, &error, "resolved"))?;
        let canonical = strip_verbatim(&canonical);
        let given = path.to_string_lossy().to_ascii_lowercase();
        if canonical.to_string_lossy().to_ascii_lowercase() == given {
            return Ok(());
        }
        Err(Untrusted::new(
            UntrustedReason::Symlink,
            path,
            format!(
                "a folder on the path is a junction or symbolic link (it resolves to {})",
                canonical.display()
            ),
        ))
    }

    /// One right, one open, nothing changed. It must fail with access
    /// denied; a sharing violation is `busy`, any other failure is not
    /// evidence of safety.
    fn probe(
        target: &Path,
        right: u32,
        name: &str,
        directory: bool,
        granted: UntrustedReason,
    ) -> Result<(), Untrusted> {
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        match OpenOptions::new()
            .access_mode(right)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(flags)
            .open(target)
        {
            Ok(_probe) => Err(Untrusted::new(
                granted,
                target,
                format!(
                    "this process's token holds {name} on it, so the daemon's user can change \
                     it (or the daemon runs elevated)"
                ),
            )),
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) => Ok(()),
            Err(error) if is_busy(&error) => Err(Untrusted::new(
                UntrustedReason::Busy,
                target,
                format!("another process holds it exclusively: {error}"),
            )),
            Err(error) if is_not_found(&error) => {
                Err(super::changed_during_check(target, "it was removed"))
            }
            Err(error) => Err(Untrusted::new(
                UntrustedReason::Unreadable,
                target,
                format!("the {name} access probe failed for another reason: {error}"),
            )),
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::path::Path;

    use super::{TrustRules, TrustedBytes, Untrusted, UntrustedReason};

    pub(super) fn verify_and_read(
        path: &Path,
        _rules: &TrustRules,
    ) -> Result<TrustedBytes, Untrusted> {
        Err(Untrusted::new(
            UntrustedReason::Unreadable,
            path,
            "this platform has no trust rule; PAM supports macOS and Windows",
        ))
    }
}
