use std::path::PathBuf;

use crate::runtime_dir::{MAX_SOCKET_PATH_BYTES, RuntimeDir, RuntimeDirError, remove_stale};

#[test]
fn too_long_socket_path_is_a_legible_error() {
    // Long enough that `<base>/run/events.sock` blows past 104 bytes.
    let base = PathBuf::from(format!("/tmp/{}", "x".repeat(MAX_SOCKET_PATH_BYTES)));
    let err = RuntimeDir::at_base(&base).expect_err("path must be rejected");
    let RuntimeDirError::SocketPathTooLong { ref path, len } = err else {
        panic!("expected SocketPathTooLong, got {err:?}");
    };
    assert!(len > MAX_SOCKET_PATH_BYTES);
    assert!(path.ends_with("pam.sock") || path.ends_with("events.sock"));
    let message = err.to_string();
    assert!(
        message.contains("104"),
        "message must name the limit: {message}"
    );
    assert!(
        message.contains(&path.display().to_string()),
        "message must name the offending path: {message}"
    );
    // Validation happens before any directory is created.
    assert!(!base.exists());
}

#[test]
fn ok_path_passes_and_creates_run_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dirs = RuntimeDir::at_base(tmp.path()).expect("short path must pass");
    assert!(dirs.run_dir().is_dir());
    assert_eq!(dirs.router_socket(), dirs.run_dir().join("pam.sock"));
    assert_eq!(dirs.events_socket(), dirs.run_dir().join("events.sock"));
    assert!(dirs.router_endpoint().starts_with("ipc://"));
    assert!(dirs.events_endpoint().ends_with("events.sock"));
}

#[cfg(unix)]
#[test]
fn run_dir_is_created_with_0700() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let mode = std::fs::metadata(dirs.run_dir())
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "run dir mode must be 0700");
}

#[cfg(unix)]
#[test]
fn pre_existing_run_dir_is_tightened_to_0700() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let run = tmp.path().join("run");
    std::fs::create_dir_all(&run).expect("pre-create");
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let mode = std::fs::metadata(dirs.run_dir())
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "pre-existing run dir must be forced to 0700"
    );
}

#[test]
fn remove_stale_deletes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sock = tmp.path().join("pam.sock");
    std::fs::write(&sock, b"stale").expect("write stale file");
    remove_stale(&sock).expect("removing an existing file works");
    assert!(!sock.exists());
    remove_stale(&sock).expect("a missing file is not an error");
}
