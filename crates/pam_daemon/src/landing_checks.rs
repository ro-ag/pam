//! Build commands read the sealed source and write only private output directories.
use super::{CommandSpec, FlowRefusal, FlowSettings, base_env, command_boundary, resolve_program};
use crate::landing_policy::Repository;
#[cfg(test)]
#[path = "landing_checks_test.rs"]
mod tests;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

fn invalid(detail: &str) -> FlowRefusal {
    FlowRefusal::new(
        "landing_check_configuration",
        detail.to_owned(),
        "Review the exact check command, approved caches and output paths in PAM Settings → Flows → Landing.",
    )
}

fn private_dir(path: &Path) -> Result<(), FlowRefusal> {
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| invalid("The private build output directory could not be created."))?;
    }
    if path
        .canonicalize()
        .map_err(|_| invalid("Build output directory is unavailable."))?
        != path
        || !path.is_dir()
    {
        return Err(invalid(
            "Build output directories cannot be retargeted through symlinks.",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn cache_link(path: &Path, target: &Path) -> Result<(), FlowRefusal> {
    if std::fs::symlink_metadata(path).is_ok() {
        if std::fs::read_link(path).ok().as_deref() == Some(target) {
            return Ok(());
        }
        return Err(invalid(
            "A cache mount would replace existing source or build data.",
        ));
    }
    std::os::unix::fs::symlink(target, path)
        .map_err(|_| invalid("The approved read-only cache could not be mounted."))
}

fn prepare_sync(
    policy: &Repository,
    index: usize,
    tree: &Path,
    settings: &FlowSettings,
    protected: &Path,
) -> Result<CommandSpec, FlowRefusal> {
    policy
        .authorize_workspace(protected)
        .map_err(|error| invalid(&error.to_string()))?;
    let check = policy
        .checks
        .get(index)
        .ok_or_else(|| invalid("The requested mandatory check is not configured."))?;
    let parent = tree
        .parent()
        .ok_or_else(|| invalid("The sealed source has no private workspace."))?;
    if parent.parent() != Some(policy.workspace_root.as_path())
        || tree.file_name().is_none_or(|name| name != "tree")
        || tree
            .canonicalize()
            .map_err(|_| invalid("The sealed source is unavailable."))?
            != tree
    {
        return Err(invalid(
            "The check must run inside the original private sealed checkout.",
        ));
    }
    let artifacts = parent.join("artifacts");
    private_dir(&artifacts)?;
    for name in ["home", "cargo", "target", "tmp", "npm"] {
        private_dir(&artifacts.join(name))?;
    }
    #[cfg(unix)]
    for cache in &policy.read_cache_roots {
        match cache.file_name().and_then(|name| name.to_str()) {
            Some("registry" | "git") => cache_link(
                &artifacts
                    .join("cargo")
                    .join(cache.file_name().expect("matched name")),
                cache,
            )?,
            Some("node_modules") => cache_link(&tree.join("node_modules"), cache)?,
            _ => {}
        }
    }
    let program = &check.argv[0];
    if !settings.allows(program) {
        return Err(invalid(
            "The check program is not in the GUI command allowlist.",
        ));
    }
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let program = resolve_program(program, &settings.extra_path_dirs(), &inherited)
        .ok_or_else(|| invalid("The check program is unavailable on this workstation."))?;
    let mut containment = command_boundary(protected, tree, &program, false);
    containment
        .read_only_roots
        .extend(policy.read_cache_roots.iter().cloned());
    containment.read_only_roots.sort();
    containment.read_only_roots.dedup();
    containment.artifact_roots.push(artifacts.clone());
    let env = build_env(settings, &artifacts);
    let argv = check.argv[1..]
        .iter()
        .map(|arg| {
            arg.replace("${artifacts}", &artifacts.to_string_lossy())
                .replace("${source}", &tree.to_string_lossy())
        })
        .collect();
    Ok(CommandSpec {
        program,
        argv,
        cwd: tree.to_owned(),
        env,
        timeout: Duration::from_secs(u64::from(check.timeout_seconds)),
        containment,
    })
}

pub(super) async fn prepare(
    policy: &Repository,
    index: usize,
    tree: &Path,
    settings: &FlowSettings,
    protected: &Path,
) -> Result<CommandSpec, FlowRefusal> {
    let policy = policy.clone();
    let tree: PathBuf = tree.to_owned();
    let settings = settings.clone();
    let protected = protected.to_owned();
    crate::blocking_jobs::run(crate::blocking_jobs::Kind::RepositoryIdentity, move || {
        prepare_sync(&policy, index, &tree, &settings, &protected)
    })
    .await
    .map_err(|error| invalid(&error.to_string()))?
}

fn build_env(settings: &FlowSettings, artifacts: &Path) -> Vec<(String, String)> {
    let mut env = base_env(settings);
    let outputs = [
        ("HOME", "home"),
        ("CARGO_HOME", "cargo"),
        ("CARGO_TARGET_DIR", "target"),
        ("TMPDIR", "tmp"),
        ("TMP", "tmp"),
        ("TEMP", "tmp"),
        ("npm_config_cache", "npm"),
    ];
    env.retain(|(name, _)| {
        !outputs.iter().any(|(key, _)| key == name)
            && name != "PAM_ARTIFACTS"
            && name != "RUSTUP_HOME"
    });
    for (name, suffix) in outputs {
        env.push((
            name.to_owned(),
            artifacts.join(suffix).to_string_lossy().into_owned(),
        ));
    }
    env.push((
        "PAM_ARTIFACTS".to_owned(),
        artifacts.to_string_lossy().into_owned(),
    ));
    if let Some(home) = std::env::home_dir() {
        env.push((
            "RUSTUP_HOME".to_owned(),
            home.join(".rustup").to_string_lossy().into_owned(),
        ));
    }
    env
}
