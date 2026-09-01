use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::base_dir_from;

#[test]
fn env_override_wins_when_set_and_non_empty() {
    let base = base_dir_from(
        Some(OsString::from("/tmp/pam-test")),
        Some(PathBuf::from("/home/x")),
    );
    assert_eq!(base.as_deref(), Some(Path::new("/tmp/pam-test")));
}

#[test]
fn empty_override_falls_back_to_home() {
    let base = base_dir_from(Some(OsString::new()), Some(PathBuf::from("/home/x")));
    assert_eq!(base.as_deref(), Some(Path::new("/home/x/.pam")));
}

#[test]
fn no_override_uses_home_dot_pam() {
    let base = base_dir_from(None, Some(PathBuf::from("/home/x")));
    assert_eq!(base.as_deref(), Some(Path::new("/home/x/.pam")));
}

#[test]
fn nothing_resolvable_yields_none() {
    assert_eq!(base_dir_from(None, None), None);
    // An empty override does not save the day when home is gone too.
    assert_eq!(base_dir_from(Some(OsString::new()), None), None);
}
