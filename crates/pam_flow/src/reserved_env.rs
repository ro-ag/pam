//! Environment names a flow step may not set.
//!
//! A step's `env:` adds to the environment pam builds for a command: the
//! scrubbed daemon environment, `PATH`, the isolated git configuration and
//! the artifact-tree homes containment points the toolchains at. A flow that
//! could set `PATH`, `GIT_DIR`, `LD_PRELOAD` or `CARGO_HOME` would redirect
//! the toolchain, git's configuration or hooks, or the dynamic loader, or
//! quietly undo what containment set. Those names are refused at validation
//! so the refusal is a legible edit, not a surprise at run time.
//!
//! The rule is deny by default for the families that grow (`GIT_*`, `CARGO_*`
//! pieces that name programs or locations): git and cargo add redirecting
//! variables with new releases, and a list of known-bad names is always
//! behind.

/// Exact names that are reserved, each with the reason.
const EXACT: &[(&str, &str)] = &[
    ("PATH", "it decides which program every step resolves"),
    (
        "PATHEXT",
        "it decides which program a Windows step resolves",
    ),
    ("HOME", "containment points it at the run's artifact tree"),
    ("USER", "it is the account identity pam scrubs"),
    ("LOGNAME", "it is the account identity pam scrubs"),
    ("SHELL", "it names a shell, which flows never run"),
    ("PWD", "it is the step's working directory, set by pam"),
    ("OLDPWD", "it is the step's working directory, set by pam"),
    ("USERPROFILE", "it is the Windows home pam isolates"),
    ("APPDATA", "it is a Windows profile location pam isolates"),
    (
        "LOCALAPPDATA",
        "it is a Windows profile location pam isolates",
    ),
    (
        "PROGRAMDATA",
        "it is a Windows machine location pam isolates",
    ),
    ("COMSPEC", "it names the Windows command interpreter"),
    ("SYSTEMROOT", "it is the Windows system location"),
    ("WINDIR", "it is the Windows system location"),
    (
        "TMPDIR",
        "containment points temporary files at the artifact tree",
    ),
    (
        "TMP",
        "containment points temporary files at the artifact tree",
    ),
    (
        "TEMP",
        "containment points temporary files at the artifact tree",
    ),
    ("PAM_ARTIFACTS", "pam sets it to the run's artifact tree"),
    ("SSH_ASKPASS", "pam points it at a path that never prompts"),
    ("SSH_AUTH_SOCK", "it hands the step the user's ssh agent"),
    ("CARGO", "it names the cargo program"),
    ("CARGO_HOME", "containment points it at the artifact tree"),
    (
        "CARGO_TARGET_DIR",
        "containment points it at the artifact tree",
    ),
    (
        "CARGO_INSTALL_ROOT",
        "it redirects where cargo installs programs",
    ),
    ("RUSTUP_HOME", "it redirects the toolchain pam resolved"),
    (
        "RUSTUP_TOOLCHAIN",
        "it redirects the toolchain pam resolved",
    ),
    ("RUSTC", "it names the compiler program"),
    (
        "RUSTC_WRAPPER",
        "it names a program run in front of every compile",
    ),
    (
        "RUSTC_WORKSPACE_WRAPPER",
        "it names a program run in front of every compile",
    ),
    ("RUSTDOC", "it names the documentation program"),
    ("NODE_OPTIONS", "it injects code into every node process"),
    ("NODE_PATH", "it redirects node's module lookup"),
    ("PYTHONPATH", "it redirects python's module lookup"),
    ("PYTHONHOME", "it redirects the python installation"),
    ("PYTHONSTARTUP", "it runs a file in every python session"),
    ("PERL5OPT", "it injects code into every perl process"),
    ("PERL5LIB", "it redirects perl's module lookup"),
    ("RUBYOPT", "it injects code into every ruby process"),
    ("RUBYLIB", "it redirects ruby's library lookup"),
    ("JAVA_TOOL_OPTIONS", "it injects options into every JVM"),
    ("_JAVA_OPTIONS", "it injects options into every JVM"),
    ("JDK_JAVA_OPTIONS", "it injects options into every JVM"),
    ("BASH_ENV", "it runs a file in every bash startup"),
    ("ENV", "it runs a file in every shell startup"),
    ("IFS", "it changes how shells split words"),
    ("GCONV_PATH", "it loads code through the C library"),
    ("LOCPATH", "it redirects the C library's locale data"),
    ("NLSPATH", "it redirects the C library's message catalogs"),
];

/// Name prefixes that are reserved, each with the reason.
const PREFIXES: &[(&str, &str)] = &[
    ("LD_", "it steers the dynamic loader"),
    ("DYLD_", "it steers the dynamic loader"),
    (
        "XDG_",
        "it redirects the config, cache and data directories",
    ),
    ("CARGO_ALIAS_", "a cargo alias can run any program"),
    (
        "CARGO_BUILD_RUSTC",
        "it names a program run for every compile",
    ),
    ("CARGO_BUILD_TARGET_DIR", "it redirects where cargo builds"),
    (
        "CARGO_TARGET_",
        "a per-target linker or runner is any program",
    ),
    (
        "CARGO_REGISTRIES_",
        "it redirects the registry cargo trusts",
    ),
    ("CARGO_REGISTRY_", "it redirects the registry cargo trusts"),
];

/// `GIT_*` names that stay settable: identity for a commit and a lock
/// hint. Every other `GIT_*` name redirects config, hooks, the object
/// store, the repository or a program git runs.
const GIT_ALLOWED: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "GIT_OPTIONAL_LOCKS",
];

/// A one-line statement of the whole rule, for messages.
pub const RESERVED_ENV_SUMMARY: &str = "PATH, HOME, TMPDIR/TMP/TEMP, USER, SHELL, USERPROFILE and \
     the other account and temp locations; every GIT_* name except GIT_AUTHOR_*, GIT_COMMITTER_* \
     and GIT_OPTIONAL_LOCKS; LD_*, DYLD_* and XDG_*; PAM_ARTIFACTS; CARGO and the CARGO_*, RUSTUP_* and \
     RUSTC* names that move or replace the toolchain; and interpreter hooks such as NODE_OPTIONS, \
     PYTHONPATH, BASH_ENV and JAVA_TOOL_OPTIONS";

/// Why a step may not set `name`, or `None` when it may.
#[must_use]
pub fn reserved_env_reason(name: &str) -> Option<&'static str> {
    if let Some((_, reason)) = EXACT.iter().find(|(reserved, _)| *reserved == name) {
        return Some(reason);
    }
    if name.starts_with("GIT_") {
        return if GIT_ALLOWED.contains(&name) {
            None
        } else if name == "GIT_CONFIG" || name.starts_with("GIT_CONFIG_") {
            Some("it redirects or overrides the isolated git configuration")
        } else {
            Some("it redirects git's configuration, hooks, repository, object store or helpers")
        };
    }
    PREFIXES
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, reason)| *reason)
}
