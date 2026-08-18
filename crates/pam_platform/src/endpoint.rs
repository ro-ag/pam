use std::{env, path::PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEndpoint {
    address: String,
    runtime_dir: PathBuf,
    socket_path: Option<PathBuf>,
    ownership_path: PathBuf,
}

impl LocalEndpoint {
    #[must_use]
    pub fn default_for_user() -> Self {
        let runtime_dir = runtime_dir();
        if cfg!(windows) {
            Self::loopback("tcp://127.0.0.1:39873", runtime_dir)
        } else {
            Self::ipc(runtime_dir)
        }
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

    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "local".to_owned());
    env::temp_dir().join(format!("pam-{user}"))
}
