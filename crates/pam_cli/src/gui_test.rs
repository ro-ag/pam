use std::{env, path::PathBuf};

use super::gui::validate_executable;
use uuid::Uuid;

#[test]
fn desktop_executable_must_be_a_regular_file() {
    let directory = env::temp_dir().join(format!("pam-gui-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();

    assert!(validate_executable(directory.clone()).is_err());
    assert!(validate_executable(directory.join("missing")).is_err());

    let executable = directory.join(if cfg!(windows) {
        "pam-gui.exe"
    } else {
        "pam-gui"
    });
    std::fs::write(&executable, b"test desktop executable").unwrap();
    assert_eq!(validate_executable(executable.clone()).unwrap(), executable);

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn development_override_requires_an_absolute_path() {
    assert!(!PathBuf::from("pam-gui").is_absolute());
}
