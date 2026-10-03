use super::reserved_env::{RESERVED_ENV_SUMMARY, reserved_env_reason};

#[test]
fn the_names_that_redirect_toolchains_git_or_the_loader_are_reserved() {
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "USER",
        "SHELL",
        "USERPROFILE",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_TRACE",
        "GIT_SOMETHING_NEW_IN_GIT_3",
        "SSH_ASKPASS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "CARGO_ALIAS_X",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "RUSTUP_HOME",
        "RUSTC_WRAPPER",
        "XDG_CONFIG_HOME",
        "PAM_ARTIFACTS",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "BASH_ENV",
        "JAVA_TOOL_OPTIONS",
    ] {
        let reason = reserved_env_reason(name);
        assert!(
            reason.is_some_and(|reason| !reason.is_empty()),
            "{name} should be reserved"
        );
    }
}

#[test]
fn ordinary_build_variables_stay_settable() {
    for name in [
        "RUST_BACKTRACE",
        "RUSTFLAGS",
        "CARGO_TERM_COLOR",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CI",
        "NO_COLOR",
        "LANG",
        "GREETING",
        "WHO",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
        "GIT_OPTIONAL_LOCKS",
        "GITHUB_REPOSITORY",
        "LDFLAGS",
        "PATHS",
        "HOMEPAGE",
    ] {
        assert_eq!(reserved_env_reason(name), None, "{name}");
    }
}

#[test]
fn the_summary_names_the_headline_cases() {
    for word in ["PATH", "HOME", "GIT_*", "LD_*", "DYLD_*", "CARGO"] {
        assert!(RESERVED_ENV_SUMMARY.contains(word), "{word}");
    }
}
