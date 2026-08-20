use std::{env, path::PathBuf};

use directories::ProjectDirs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEndpoint {
    address: String,
    runtime_dir: PathBuf,
    socket_path: Option<PathBuf>,
    ownership_path: PathBuf,
}

impl LocalEndpoint {
    /// Returns the default per-user local IPC endpoint.
    ///
    /// # Panics
    ///
    /// Panics when the operating system exposes neither a session runtime
    /// directory nor the per-user local-data directory required by every
    /// supported PAM platform. `PAM_RUNTIME_DIR` can provide an explicit
    /// absolute override for constrained environments.
    #[must_use]
    pub fn default_for_user() -> Self {
        Self::ipc(runtime_dir())
    }

    #[must_use]
    pub fn ipc(runtime_dir: PathBuf) -> Self {
        let socket_path = runtime_dir.join("daemon.sock");
        Self {
            address: format!("ipc://{}", socket_path.display()),
            socket_path: Some(socket_path),
            ownership_path: runtime_dir.join("daemon.lock"),
            runtime_dir,
        }
    }

    #[must_use]
    pub fn loopback(address: impl Into<String>, runtime_dir: PathBuf) -> Self {
        Self {
            address: address.into(),
            socket_path: None,
            ownership_path: runtime_dir.join("daemon.lock"),
            runtime_dir,
        }
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub fn socket_path(&self) -> Option<&std::path::Path> {
        self.socket_path.as_deref()
    }

    #[must_use]
    pub fn ownership_path(&self) -> &std::path::Path {
        &self.ownership_path
    }

    #[must_use]
    pub fn runtime_dir(&self) -> &std::path::Path {
        &self.runtime_dir
    }
}

fn runtime_dir() -> PathBuf {
    if let Some(configured) = env::var_os("PAM_RUNTIME_DIR") {
        return PathBuf::from(configured);
    }

    if !cfg!(windows)
        && let Some(xdg_runtime_dir) = env::var_os("XDG_RUNTIME_DIR")
    {
        return PathBuf::from(xdg_runtime_dir).join("pam");
    }

    private_runtime_dir()
        .expect("supported PAM platforms must provide a private per-user local-data directory")
}

pub(super) fn private_runtime_dir() -> Option<PathBuf> {
    ProjectDirs::from("dev", "PAM", "PAM")
        .map(|project_dirs| project_dirs.data_local_dir().join("runtime"))
}
