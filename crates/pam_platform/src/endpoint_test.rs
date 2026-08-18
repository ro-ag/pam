use std::path::PathBuf;

use super::LocalEndpoint;

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
