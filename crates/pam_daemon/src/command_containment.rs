//! OS containment for untrusted command workloads and every descendant.
//!
//! Supported only on macOS with its system sandbox launcher. No network, Mach
//! service lookup, GUI automation, or process control outside the workload is
//! granted. Only the immutable system trees (including the system TLS
//! configuration under `/private/etc/ssl`) and explicitly supplied repository
//! and toolchain reads are allowed; repository writes require a stateful
//! operation, and even then never reach Git's control surface (hooks,
//! configuration, the `.git` entry itself): what an approved step plants there
//! would later run outside this profile. No implicit HOME/cache/temp exception
//! exists. Unsupported configurations never fall back to raw exec.
//!
//! Host provisioning must keep protected assets outside writable repositories,
//! including pre-existing hardlink aliases. New hardlinks are denied. This does
//! not protect against an unconstrained host process changing trusted paths.

#[cfg(any(target_os = "macos", test))]
use std::fmt::Write as _;
use std::path::PathBuf;

/// Stable refusal cause for unavailable command containment.
pub const CAUSE_UNAVAILABLE: &str = "command_containment_unavailable";

/// Immutable, root-owned system trees every workload may read. `/private/etc/ssl`
/// is the system TLS configuration: Apple's `LibreSSL`, which the system libcurl
/// that cargo links loads at start-up, exits the whole process with "Auto
/// configuration failed" when it cannot open `openssl.cnf`, and it ignores
/// `OPENSSL_CONF`. Nothing else under `/etc` is granted.
#[cfg(any(target_os = "macos", test))]
const SYSTEM_READ_ROOTS: &[&str] = &[
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/private/var/db/dyld",
    "/private/etc/ssl",
];

/// Trusted daemon-supplied boundaries; never inferred from the child's environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandContainment {
    /// PAM's private base, including database and administrative endpoint.
    pub protected_base: PathBuf,
    /// Exact approved repository; canonicalized again immediately before spawn.
    pub repository: PathBuf,
    /// Explicit OS/toolchain/executable roots. These confer read access only.
    pub read_only_roots: Vec<PathBuf>,
    /// Repository writes are allowed only for declared stateful operations.
    pub allow_repository_writes: bool,
    /// Explicit private build outputs, separate from immutable source and toolchains.
    pub artifact_roots: Vec<PathBuf>,
}

/// The trusted launcher and arguments preceding the original workload's argv.
#[derive(Debug)]
pub(crate) struct PreparedCommand {
    pub program: PathBuf,
    pub argv: Vec<std::ffi::OsString>,
}

impl CommandContainment {
    /// Validate the trusted boundary and construct a contained command.
    /// A launcher rejection can start the launcher, but cannot start the workload
    /// without first installing the policy. There is no uncontained retry.
    pub(crate) fn prepare(
        &self,
        program: &std::path::Path,
        cwd: &std::path::Path,
        env: &[(String, String)],
    ) -> Result<PreparedCommand, String> {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let launcher = PathBuf::from("/usr/bin/sandbox-exec");
            let metadata = std::fs::metadata(&launcher)
                .map_err(|_| "macOS sandbox launcher is unavailable".to_owned())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o111 == 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err("macOS sandbox launcher is not executable".to_owned());
            }
            let (profile, program) = profile(self, program, cwd)?;
            let mut argv = vec![
                "-p".into(),
                profile.into(),
                "/usr/bin/env".into(),
                "-i".into(),
                "--".into(),
            ];
            for (name, value) in env {
                // env receives operands after `--`; any nonempty name without
                // '=' or NUL is representable, including Cargo's hyphenated names.
                if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
                    return Err("command environment cannot be represented safely".to_owned());
                }
                argv.push(format!("{name}={value}").into());
            }
            argv.push(program.into_os_string());
            Ok(PreparedCommand {
                program: launcher,
                argv,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self, program, cwd, env);
            Err("command containment is supported only on macOS".to_owned())
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn canonical(path: &std::path::Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("containment paths must be absolute".to_owned());
    }
    let path = path
        .canonicalize()
        .map_err(|_| "containment path is unavailable".to_owned())?;
    let text = path
        .to_str()
        .ok_or_else(|| "containment path is not UTF-8".to_owned())?;
    if text.len() > 4096 || text.chars().any(char::is_control) {
        return Err("containment path exceeds its representation limits".to_owned());
    }
    Ok(path)
}

#[cfg(any(target_os = "macos", test))]
fn quoted(path: &std::path::Path) -> String {
    // canonical() established UTF-8 and excluded control characters. JSON and
    // SBPL agree on quoting backslash and double quote; no text becomes syntax.
    serde_json::to_string(path.to_str().expect("validated path")).expect("string serializes")
}

#[cfg(any(target_os = "macos", test))]
fn overlap(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

/// Compile a bounded profile without executing any process.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn profile(
    config: &CommandContainment,
    program: &std::path::Path,
    cwd: &std::path::Path,
) -> Result<(String, PathBuf), String> {
    let protected = canonical(&config.protected_base)?;
    let repo = canonical(&config.repository)?;
    let cwd = canonical(cwd)?;
    let program = canonical(program)?;
    if !protected.is_dir()
        || !repo.is_dir()
        || !cwd.is_dir()
        || !program.is_file()
        || !cwd.starts_with(&repo)
        || overlap(&repo, &protected)
        || (config.allow_repository_writes
            && SYSTEM_READ_ROOTS
                .iter()
                .any(|root| overlap(&repo, std::path::Path::new(root))))
    {
        return Err("repository, program or private boundary is invalid".to_owned());
    }
    if config.read_only_roots.len() > 16 || config.artifact_roots.len() > 8 {
        return Err("too many command read roots".to_owned());
    }
    let mut roots = Vec::new();
    for path in &config.read_only_roots {
        let root = canonical(path)?;
        if !root.is_dir()
            || root.parent().is_none()
            || overlap(&root, &protected)
            || (config.allow_repository_writes && overlap(&root, &repo))
        {
            return Err("command read root overlaps a protected or writable boundary".to_owned());
        }
        roots.push(root);
    }
    if !program.starts_with(&repo) && !roots.iter().any(|root| program.starts_with(root)) {
        return Err("command executable is outside declared read roots".to_owned());
    }
    let mut artifacts = Vec::new();
    for path in &config.artifact_roots {
        let root = canonical(path)?;
        if !root.is_dir()
            || overlap(&root, &protected)
            || overlap(&root, &repo)
            || roots.iter().any(|read| overlap(&root, read))
            || SYSTEM_READ_ROOTS
                .iter()
                .any(|read| overlap(&root, std::path::Path::new(read)))
        {
            return Err(
                "artifact roots must be separate from source, protected data and toolchains"
                    .to_owned(),
            );
        }
        validate_artifact_owner(&root, &protected)?;
        artifacts.push(root);
    }
    // Do not import system/app profiles: they grant services beyond this contract.
    let mut text = String::from(
        "(version 1)\n(deny default)\n(allow process-fork process-exec)\n(allow sysctl-read)\n(allow file-read-metadata)\n(allow signal (target self))\n(allow process-info* (target self))\n(allow file-read-data (literal \"/\") (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n(allow file-write-data (literal \"/dev/null\"))\n",
    );
    // The OS loader and the env trampoline require these immutable system reads.
    for root in SYSTEM_READ_ROOTS {
        let _ = writeln!(
            text,
            "(allow file-read* file-map-executable (subpath {root:?}))"
        );
    }
    let _ = writeln!(
        text,
        "(allow file-read* file-map-executable (subpath {}))",
        quoted(&repo)
    );
    for root in &roots {
        let _ = writeln!(
            text,
            "(allow file-read* file-map-executable (subpath {}))",
            quoted(root)
        );
    }
    if config.allow_repository_writes {
        let _ = writeln!(text, "(allow file-write* (subpath {}))", quoted(&repo));
        // Later rules win: the carve-out must follow the allow it narrows.
        git_control_denies(&mut text, &repo)?;
    }
    for root in &artifacts {
        let _ = writeln!(
            text,
            "(allow file-read* file-write* file-map-executable (subpath {}))",
            quoted(root)
        );
    }
    let _ = writeln!(
        text,
        "(deny file-read* file-write* file-map-executable (subpath {}))",
        quoted(&protected)
    );
    text.push_str("(deny file-read* file-write* file-map-executable (regex #\"^(/.*)?/Library/Keychains(/.*)?$\"))\n(deny file-link)\n(deny network*)\n(deny mach-lookup)\n(deny appleevent-send)\n");
    if text.len() > 32 * 1024 {
        return Err("command containment profile exceeds its limit".to_owned());
    }
    Ok((text, program))
}

/// Git's control surface inside a writable repository, as path regexes. A
/// stateful step may write objects, the index, refs, logs and `HEAD` — an
/// ordinary `git add`/`git commit` — but never what Git later *executes or
/// obeys* outside this profile: hook directories, configuration (`core.hooksPath`,
/// `core.fsmonitor`, `core.sshCommand`, filters, aliases, includes), the
/// `commondir` pointer that selects another configuration, and the `.git`
/// entry itself (replacing it repoints the repository). The optional prefix
/// covers submodule (`.git/modules/<path>/`) and linked-worktree
/// (`.git/worktrees/<name>/`) metadata. Every literal is spelled per letter
/// because the default macOS volume is case-insensitive and a not-yet-existing
/// `HOOKS` directory is reported to the policy as typed.
#[cfg(any(target_os = "macos", test))]
const GIT_CONTROL_PATTERNS: &[&str] = &[
    r"/\.[Gg][Ii][Tt]$",
    r"/\.[Gg][Ii][Tt]/(modules/.+/|worktrees/[^/]+/)?[Hh][Oo][Oo][Kk][Ss](/|$)",
    r"/\.[Gg][Ii][Tt]/(modules/.+/|worktrees/[^/]+/)?([Cc][Oo][Nn][Ff][Ii][Gg](\.[Ww][Oo][Rr][Kk][Tt][Rr][Ee][Ee])?|[Cc][Oo][Mm][Mm][Oo][Nn][Dd][Ii][Rr])$",
];

/// The same surface inside a Git directory that is not at `<repo>/.git`
/// (a gitfile or symlink names it): any `hooks`, `config`, `config.worktree`
/// or `commondir` path component. This over-denies a branch literally named
/// `hooks` or `config` in that layout rather than interpolate a path into a
/// regex.
#[cfg(any(target_os = "macos", test))]
const GIT_REDIRECTED_PATTERN: &str = r"/([Hh][Oo][Oo][Kk][Ss]|[Cc][Oo][Nn][Ff][Ii][Gg](\.[Ww][Oo][Rr][Kk][Tt][Rr][Ee][Ee])?|[Cc][Oo][Mm][Mm][Oo][Nn][Dd][Ii][Rr])(/|$)";

/// Largest gitfile or `commondir` pointer read while building a profile.
#[cfg(any(target_os = "macos", test))]
const MAX_GIT_POINTER_BYTES: u64 = 4096;

/// Deny writes to Git's control surface below a writable repository. The
/// patterns are constants scoped by `subpath`, so no repository text ever
/// becomes regex syntax.
#[cfg(any(target_os = "macos", test))]
fn git_control_denies(text: &mut String, repo: &std::path::Path) -> Result<(), String> {
    let scope = quoted(repo);
    for pattern in GIT_CONTROL_PATTERNS {
        let _ = writeln!(
            text,
            "(deny file-write* (require-all (subpath {scope}) (regex #\"{pattern}\")))"
        );
    }
    for directory in redirected_git_dirs(repo)? {
        let directory = quoted(&directory);
        let _ = writeln!(
            text,
            "(deny file-write* (literal {directory}) (require-all (subpath {directory}) (regex #\"{GIT_REDIRECTED_PATTERN}\")))"
        );
    }
    Ok(())
}

/// Git directories the repository's own `.git` entry redirects to: the target
/// of a gitfile (`gitdir: <path>`, as linked worktrees, submodules and
/// `--separate-git-dir` write it) or of a symlink, plus the common directory
/// each of those names. A pointer that cannot be read or resolved refuses the
/// profile: a stateful step never runs against a control surface PAM could not
/// locate. Directories outside the repository are returned too; they are not
/// writable anyway, and the extra deny is harmless.
#[cfg(any(target_os = "macos", test))]
fn redirected_git_dirs(repo: &std::path::Path) -> Result<Vec<PathBuf>, String> {
    let unresolved = || "repository Git directory pointer cannot be resolved".to_owned();
    let entry = repo.join(".git");
    let Ok(metadata) = std::fs::symlink_metadata(&entry) else {
        // No `.git` at all: creating one is denied by the patterns above.
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    if metadata.is_file() {
        let pointer = read_git_pointer(&entry).ok_or_else(unresolved)?;
        let target = pointer.strip_prefix("gitdir:").ok_or_else(unresolved)?;
        found.push(canonical(&repo.join(target.trim())).map_err(|_| unresolved())?);
    } else if metadata.file_type().is_symlink() {
        found.push(canonical(&entry).map_err(|_| unresolved())?);
    } else if !metadata.is_dir() {
        return Err(unresolved());
    }
    // A linked worktree's hooks and configuration live in its common directory.
    let roots = if found.is_empty() {
        vec![entry]
    } else {
        found.clone()
    };
    for root in roots {
        let pointer = root.join("commondir");
        if std::fs::symlink_metadata(&pointer).is_err() {
            continue;
        }
        let target = read_git_pointer(&pointer).ok_or_else(unresolved)?;
        found.push(canonical(&root.join(target.trim())).map_err(|_| unresolved())?);
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// One bounded, single-line Git pointer file; `None` when it is not that.
#[cfg(any(target_os = "macos", test))]
fn read_git_pointer(path: &std::path::Path) -> Option<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_GIT_POINTER_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    let text = text.trim_end_matches(['\n', '\r']);
    (!text.is_empty()
        && u64::try_from(text.len()).is_ok_and(|length| length <= MAX_GIT_POINTER_BYTES)
        && !text.contains(['\n', '\r', '\0']))
    .then(|| text.to_owned())
}

// Only the macOS profile builder calls this; without the same gate it is dead
// code on other targets and fails the lint gate there but never here.
#[cfg(any(target_os = "macos", test))]
fn validate_artifact_owner(
    root: &std::path::Path,
    protected: &std::path::Path,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(root).map_err(|_| "artifact directory unavailable")?;
        let private = std::fs::metadata(protected).map_err(|_| "private directory unavailable")?;
        if metadata.uid() != private.uid() || metadata.mode() & 0o077 != 0 {
            return Err("artifact directory must be private and owned by PAM's user".to_owned());
        }
    }
    // Under `test` on Windows the function exists for the unit tests but has no
    // ownership check to make; the parameters are still part of its contract.
    #[cfg(not(unix))]
    let _ = (root, protected);
    Ok(())
}
