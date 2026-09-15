//! The private build outputs a command step may write.
//!
//! Containment grants no implicit HOME, cache, temp or build-output write
//! (see `docs/command-containment.md`), so a toolchain that keeps state in
//! the user's home — cargo, npm — cannot run in a read-only step at all.
//! `flows.artifacts_root` names one private directory a human chose; under
//! it every repository gets its own tree (`home`, `cargo`, `target`, `tmp`,
//! `npm`) and the approved read-only caches are linked in, exactly as a
//! landing check's workspace is laid out. Nothing here is inferred from the
//! child's environment, and an unset root refuses a build tool before spawn.
use super::{
    CAUSE_ARTIFACTS_ROOT_INVALID, FlowRefusal, FlowSettings, RECOVERY_ARTIFACTS_ROOT, base_env,
};
#[cfg(test)]
#[path = "flow_artifacts_test.rs"]
mod tests;
use std::path::{Path, PathBuf};

/// Programs whose home or cache the artifacts tree redirects; without a
/// configured root these refuse instead of failing on their first write.
const ARTIFACT_PROGRAMS: &[&str] = &["cargo", "rustc", "rustup", "npm", "npx", "pnpm", "yarn"];

/// Whether `program` needs the private artifacts tree to run at all.
pub(super) fn needs_artifacts(program: &str) -> bool {
    ARTIFACT_PROGRAMS.contains(&program)
}

fn invalid(detail: impl Into<String>) -> FlowRefusal {
    FlowRefusal::new(
        CAUSE_ARTIFACTS_ROOT_INVALID,
        detail.into(),
        RECOVERY_ARTIFACTS_ROOT,
    )
}

/// Creates `path` as a private directory when missing, and refuses one
/// that is reachable through a symlink or open to other users.
pub(super) fn private_dir(path: &Path) -> Result<(), &'static str> {
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| "The private build output directory could not be created.")?;
    }
    if path
        .canonicalize()
        .map_err(|_| "Build output directory is unavailable.")?
        != path
        || !path.is_dir()
    {
        return Err("Build output directories cannot be retargeted through symlinks.");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            std::fs::metadata(path).map_err(|_| "Build output directory is unavailable.")?;
        if metadata.mode() & 0o077 != 0 {
            return Err("The build output directory must be private (mode 700).");
        }
    }
    Ok(())
}

/// Links an approved read-only cache at `path`, refusing to replace
/// anything that already exists there.
#[cfg(unix)]
pub(super) fn cache_link(path: &Path, target: &Path) -> Result<(), &'static str> {
    if std::fs::symlink_metadata(path).is_ok() {
        if std::fs::read_link(path).ok().as_deref() == Some(target) {
            return Ok(());
        }
        return Err("A cache mount would replace existing source or build data.");
    }
    std::os::unix::fs::symlink(target, path)
        .map_err(|_| "The approved read-only cache could not be mounted.")
}

/// The per-repository tree under `root` for `repo`: the directory name
/// plus a digest of the canonical path, so two checkouts called `repo`
/// never share a target directory.
fn tree_name(repo: &Path) -> String {
    let canonical = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let digest = pam_compact::sha256_hex(canonical.to_string_lossy().as_bytes());
    let name: String = repo
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    format!("{name}-{}", &digest[..12])
}

/// Prepares the private artifacts tree for `repo` under `root` and returns
/// it. The root must lie outside the repository and the protected base;
/// `read_cache_roots` named `registry` or `git` are linked read-only under
/// `cargo/`, and any other cache is ignored here (a read-only step never
/// writes into the repository, so `node_modules` cannot be mounted).
pub(super) fn prepare(
    root: &Path,
    repo: &Path,
    protected: &Path,
    read_cache_roots: &[PathBuf],
) -> Result<PathBuf, FlowRefusal> {
    if !root.is_absolute() {
        return Err(invalid(
            "The build output directory must be an absolute path.",
        ));
    }
    // The human's spelling may go through a symlinked prefix (`/tmp` on
    // macOS): resolve the existing parent first, create the leaf under the
    // real path, and hold the tree below to that exact, resolved path.
    let root = if root.exists() {
        root.canonicalize()
            .map_err(|_| invalid("Build output directory is unavailable."))?
    } else {
        let parent = root
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .ok_or_else(|| invalid("The parent of the build output directory does not exist."))?;
        let leaf = root
            .file_name()
            .ok_or_else(|| invalid("The build output directory has no name."))?;
        parent.join(leaf)
    };
    let root = root.as_path();
    let repo_canonical = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let protected_canonical = protected
        .canonicalize()
        .unwrap_or_else(|_| protected.to_path_buf());
    let overlaps = |other: &Path| root.starts_with(other) || other.starts_with(root);
    if overlaps(&repo_canonical) || overlaps(&protected_canonical) {
        return Err(invalid(
            "The build output directory must be outside the repository and outside PAM's private base.",
        ));
    }
    private_dir(root).map_err(invalid)?;
    let artifacts = root.join(tree_name(repo));
    private_dir(&artifacts).map_err(invalid)?;
    for name in ["home", "cargo", "target", "tmp", "npm"] {
        private_dir(&artifacts.join(name)).map_err(invalid)?;
    }
    #[cfg(unix)]
    for cache in read_cache_roots {
        if let Some(name @ ("registry" | "git")) = cache.file_name().and_then(|name| name.to_str())
        {
            cache_link(&artifacts.join("cargo").join(name), cache).map_err(invalid)?;
        }
    }
    #[cfg(not(unix))]
    let _ = read_cache_roots;
    Ok(artifacts)
}

/// The step environment with every home, cache and temp location the
/// toolchains honour pointed into `artifacts`, and `PAM_ARTIFACTS` naming
/// the tree so a flow argument can reach it.
pub(super) fn build_env(settings: &FlowSettings, artifacts: &Path) -> Vec<(String, String)> {
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
