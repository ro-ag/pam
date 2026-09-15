//! Build commands read the sealed source and write only private output directories.
use super::{CommandSpec, FlowRefusal, FlowSettings, artifacts, command_boundary, resolve_program};
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
    let outputs = parent.join("artifacts");
    artifacts::private_dir(&outputs).map_err(invalid)?;
    for name in ["home", "cargo", "target", "tmp", "npm"] {
        artifacts::private_dir(&outputs.join(name)).map_err(invalid)?;
    }
    #[cfg(unix)]
    for cache in &policy.read_cache_roots {
        match cache.file_name().and_then(|name| name.to_str()) {
            Some("registry" | "git") => artifacts::cache_link(
                &outputs
                    .join("cargo")
                    .join(cache.file_name().expect("matched name")),
                cache,
            )
            .map_err(invalid)?,
            Some("node_modules") => {
                artifacts::cache_link(&tree.join("node_modules"), cache).map_err(invalid)?;
            }
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
    containment.artifact_roots.push(outputs.clone());
    let env = artifacts::build_env(settings, &outputs);
    let argv = check.argv[1..]
        .iter()
        .map(|arg| {
            arg.replace("${artifacts}", &outputs.to_string_lossy())
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
