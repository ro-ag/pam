use std::path::PathBuf;

use super::{LocalEndpoint, endpoint::private_runtime_dir};

#[test]
fn ipc_endpoint_keeps_transport_and_ownership_paths_together() {
    let endpoint = LocalEndpoint::ipc(PathBuf::from("/tmp/pam-endpoint-test"));

    assert_eq!(
        endpoint.address(),
        "ipc:///tmp/pam-endpoint-test/daemon.sock"
    );
    assert_eq!(
        endpoint.socket_path(),
        Some(std::path::Path::new("/tmp/pam-endpoint-test/daemon.sock"))
    );
    assert_eq!(
        endpoint.ownership_path(),
        std::path::Path::new("/tmp/pam-endpoint-test/daemon.lock")
    );
}

#[test]
fn default_endpoint_uses_local_ipc() {
    let endpoint = LocalEndpoint::default_for_user();
    let socket_path = endpoint
        .socket_path()
        .expect("the default endpoint must use a local IPC socket");

    assert_eq!(socket_path, endpoint.runtime_dir().join("daemon.sock"));
    assert_eq!(
        endpoint.address(),
        format!("ipc://{}", socket_path.display())
    );
}

#[test]
fn fallback_runtime_is_rooted_in_private_per_user_data() {
    let project_dirs = directories::ProjectDirs::from("dev", "PAM", "PAM")
        .expect("the test host must expose a per-user data directory");

    assert_eq!(
        private_runtime_dir(),
        Some(project_dirs.data_local_dir().join("runtime"))
    );
}
