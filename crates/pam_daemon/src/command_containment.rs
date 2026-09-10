//! OS containment for untrusted command workloads and every descendant.
//!
//! Supported only on macOS with its system sandbox launcher. No network, Mach
//! service lookup, GUI automation, or process control outside the workload is
//! granted. Only explicitly supplied repository and toolchain reads are allowed;
//! repository writes require a stateful operation. No implicit HOME/cache/temp
//! exception exists. Unsupported configurations never fall back to raw exec.
//!
//! Host provisioning must keep protected assets outside writable repositories,
//! including pre-existing hardlink aliases. New hardlinks are denied. This does
//! not protect against an unconstrained host process changing trusted paths.

#[cfg(any(target_os = "macos", test))]
use std::fmt::Write as _;
use std::path::PathBuf;

/// Stable refusal cause for unavailable command containment.
pub const CAUSE_UNAVAILABLE: &str = "command_containment_unavailable";

#[cfg(any(target_os = "macos", test))]
const SYSTEM_READ_ROOTS: &[&str] = &["/System", "/usr", "/bin", "/sbin", "/private/var/db/dyld"];

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
                if name.is_empty()
                    || name.contains(['=', '\0'])
                    || value.contains('\0')
                {
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
    if config.read_only_roots.len() > 16 {
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
