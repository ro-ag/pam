use std::ffi::OsStr;
use std::path::PathBuf;

use crate::managed_policy_trust::{
    MAX_POLICY_BYTES, TrustRules, UntrustedReason, WINDOWS_PROGRAM_DATA_FALLBACK, verify_and_read,
    windows_policy_path,
};

#[test]
fn reason_codes_are_stable_and_unique() {
    let codes: Vec<&str> = UntrustedReason::ALL.iter().map(|r| r.code()).collect();
    assert_eq!(
        codes,
        [
            "not_owned_by_root",
            "writable_by_user",
            "symlink",
            "parent_writable",
            "not_regular",
            "too_large",
            "busy",
            "unreadable",
        ]
    );
    for reason in UntrustedReason::ALL {
        assert_eq!(reason.to_string(), reason.code());
        assert!(
            !reason.recovery().is_empty(),
            "{reason} has no recovery line"
        );
        assert_eq!(reason.is_transient(), reason == UntrustedReason::Busy);
    }
}

#[test]
fn production_rules_are_root_and_the_policy_bound() {
    let rules = TrustRules::production();
    assert_eq!(rules.max_bytes(), MAX_POLICY_BYTES);
    assert_eq!(MAX_POLICY_BYTES, 64 * 1024);
    #[cfg(unix)]
    {
        assert_eq!(rules.expected_owner(), 0);
        assert_eq!(rules.ancestor_owners(), [0]);
        assert_eq!(TrustRules::owned_by(0).ancestor_owners(), [0]);
        assert_eq!(TrustRules::owned_by(501).ancestor_owners(), [0, 501]);
    }
    let bounded = TrustRules::production().with_max_bytes(10);
    assert_eq!(bounded.max_bytes(), 10);
}

#[cfg(not(windows))]
#[test]
fn platform_policy_path_is_the_fixed_macos_path() {
    assert_eq!(
        crate::managed_policy_trust::policy_path(),
        PathBuf::from("/Library/Application Support/PAM/policy.json")
    );
}

#[test]
fn program_data_is_used_only_in_its_plain_drive_letter_form() {
    let fallback = PathBuf::from(r"C:\ProgramData\PAM\policy.json");
    assert_eq!(WINDOWS_PROGRAM_DATA_FALLBACK, r"C:\ProgramData");
    let cases: [(Option<&str>, PathBuf); 10] = [
        (None, fallback.clone()),
        (Some(r"C:\ProgramData"), fallback.clone()),
        (
            Some(r"D:\ProgramData"),
            PathBuf::from(r"D:\ProgramData\PAM\policy.json"),
        ),
        (
            Some(r"d:\programdata"),
            PathBuf::from(r"d:\programdata\PAM\policy.json"),
        ),
        (Some(r"C:\ProgramData\"), fallback.clone()),
        (Some(r"C:\Users\agent\ProgramData"), fallback.clone()),
        (Some(r"\\server\share\ProgramData"), fallback.clone()),
        (Some(r"C:/ProgramData"), fallback.clone()),
        (Some(r"1:\ProgramData"), fallback.clone()),
        (Some(""), fallback.clone()),
    ];
    for (value, expected) in cases {
        assert_eq!(
            windows_policy_path(value.map(OsStr::new)),
            expected,
            "ProgramData = {value:?}"
        );
    }
}

#[test]
fn a_relative_path_is_refused_and_not_absent() {
    let error = verify_and_read(
        std::path::Path::new("PAM/policy.json"),
        &TrustRules::production(),
    )
    .expect_err("a relative path is never trusted");
    assert_eq!(error.code(), "unreadable");
    assert!(!error.is_absent());
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use crate::managed_policy_trust::{
        MAX_POLICY_BYTES, TrustRules, Untrusted, UntrustedReason, verify_and_read,
    };

    /// A temp tree owned by the test user, with canonical paths, that puts
    /// every permission back before it is removed.
    struct Tree {
        base: PathBuf,
        uid: u32,
        _tmp: tempfile::TempDir,
    }

    impl Tree {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("tempdir");
            let base = fs::canonicalize(tmp.path()).expect("canonical tempdir");
            let uid = fs::metadata(&base).expect("tempdir metadata").uid();
            for ancestor in base.ancestors() {
                let metadata = fs::symlink_metadata(ancestor).expect("ancestor metadata");
                assert!(
                    (metadata.uid() == 0 || metadata.uid() == uid) && metadata.mode() & 0o022 == 0,
                    "the temp directory {} sits under {} (uid {}, mode {:o}); point TMPDIR at a \
                     private directory for these tests",
                    base.display(),
                    ancestor.display(),
                    metadata.uid(),
                    metadata.mode()
                );
            }
            Self {
                base,
                uid,
                _tmp: tmp,
            }
        }

        fn rules(&self) -> TrustRules {
            TrustRules::owned_by(self.uid)
        }

        fn dir(&self, rel: &str, mode: u32) -> PathBuf {
            let path = self.base.join(rel);
            fs::create_dir_all(&path).expect("mkdir");
            chmod(&path, mode);
            path
        }

        fn file(&self, rel: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.base.join(rel);
            fs::write(&path, bytes).expect("write fixture");
            chmod(&path, mode);
            path
        }

        /// `PAM/policy.json`, `0444`, in a `0755` folder.
        fn good(&self, bytes: &[u8]) -> PathBuf {
            self.dir("PAM", 0o755);
            self.file("PAM/policy.json", bytes, 0o444)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            restore(&self.base);
        }
    }

    fn restore(dir: &Path) {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(metadata) = fs::symlink_metadata(&path)
                && metadata.is_dir()
            {
                restore(&path);
            }
        }
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn refused(path: &Path, rules: &TrustRules) -> Untrusted {
        match verify_and_read(path, rules) {
            Ok(trusted) => panic!(
                "{} was trusted ({} bytes); a refusal was expected",
                path.display(),
                trusted.bytes().len()
            ),
            Err(error) => error,
        }
    }

    fn assert_refused(path: &Path, rules: &TrustRules, reason: UntrustedReason) -> Untrusted {
        let error = refused(path, rules);
        assert_eq!(error.reason, reason, "{error}");
        assert!(!error.is_absent(), "{error}");
        error
    }

    #[test]
    fn a_0444_file_in_a_0555_folder_owned_by_the_expected_owner_is_trusted() {
        let tree = Tree::new();
        let folder = tree.dir("PAM", 0o755);
        let path = tree.file("PAM/policy.json", b"{\"version\":1}", 0o444);
        chmod(&folder, 0o555);
        let trusted = verify_and_read(&path, &tree.rules()).expect("trusted");
        assert_eq!(trusted.bytes(), b"{\"version\":1}");
        assert_eq!(trusted.path(), path);
        assert_eq!(trusted.into_bytes(), b"{\"version\":1}".to_vec());
    }

    #[test]
    fn a_0444_file_in_a_0755_folder_is_trusted() {
        let tree = Tree::new();
        let path = tree.good(b"{}");
        assert!(verify_and_read(&path, &tree.rules()).is_ok());
    }

    #[test]
    fn the_production_rule_refuses_a_file_the_test_user_owns() {
        let tree = Tree::new();
        let path = tree.good(b"{}");
        let error = assert_refused(
            &path,
            &TrustRules::production(),
            UntrustedReason::NotOwnedByRoot,
        );
        assert!(
            error.detail.contains(&format!("uid {}", tree.uid)),
            "{error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_production_rule_trusts_a_real_root_owned_file() {
        // root:wheel 0644 under /private/etc (root 0755), /private, /.
        let path = Path::new("/private/etc/hosts");
        let trusted = verify_and_read(path, &TrustRules::production()).expect("trusted");
        assert!(!trusted.bytes().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_fixture_rule_refuses_a_root_owned_file() {
        let tree = Tree::new();
        assert_refused(
            Path::new("/private/etc/hosts"),
            &tree.rules(),
            UntrustedReason::NotOwnedByRoot,
        );
    }

    #[test]
    fn a_0644_file_the_user_can_open_for_write_is_refused_by_the_probe() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        let path = tree.file("PAM/policy.json", b"{\"a\":1}", 0o644);
        let before = fs::metadata(&path).expect("metadata");
        let error = assert_refused(&path, &tree.rules(), UntrustedReason::WritableByUser);
        assert!(
            error.detail.contains("open the file for writing"),
            "{error}"
        );
        // The probe wrote nothing and moved nothing.
        let after = fs::metadata(&path).expect("metadata");
        assert_eq!(fs::read(&path).expect("read"), b"{\"a\":1}");
        assert_eq!(after.len(), before.len());
        assert_eq!(after.modified().ok(), before.modified().ok());
    }

    #[test]
    fn group_or_world_writable_files_are_refused_by_the_mode_rule() {
        for mode in [0o664, 0o666, 0o446, 0o464] {
            let tree = Tree::new();
            tree.dir("PAM", 0o755);
            let path = tree.file("PAM/policy.json", b"{}", mode);
            let error = assert_refused(&path, &tree.rules(), UntrustedReason::WritableByUser);
            assert!(
                error.detail.contains("group or everyone"),
                "mode {mode:o}: {error}"
            );
        }
    }

    #[test]
    fn setuid_and_execute_bits_are_refused() {
        for mode in [0o4444, 0o1444, 0o555, 0o544] {
            let tree = Tree::new();
            tree.dir("PAM", 0o755);
            let path = tree.file("PAM/policy.json", b"{}", mode);
            assert_eq!(
                fs::metadata(&path).expect("metadata").mode() & 0o7777,
                mode,
                "the fixture could not set mode {mode:o}"
            );
            assert_refused(&path, &tree.rules(), UntrustedReason::NotRegular);
        }
    }

    #[test]
    fn a_symlink_to_a_good_file_is_refused() {
        let tree = Tree::new();
        let target = tree.good(b"{}");
        let link = tree.base.join("PAM/link.json");
        symlink(&target, &link).expect("symlink");
        assert_refused(&link, &tree.rules(), UntrustedReason::Symlink);
    }

    #[test]
    fn a_symlinked_directory_in_the_chain_is_refused() {
        let tree = Tree::new();
        tree.good(b"{}");
        let link = tree.base.join("linked");
        symlink(tree.base.join("PAM"), &link).expect("symlink");
        let error = assert_refused(
            &link.join("policy.json"),
            &tree.rules(),
            UntrustedReason::Symlink,
        );
        assert!(error.detail.contains("resolves to"), "{error}");
    }

    #[test]
    fn a_writable_parent_is_refused() {
        for mode in [0o775, 0o777, 0o757] {
            let tree = Tree::new();
            let folder = tree.dir("PAM", 0o755);
            let path = tree.file("PAM/policy.json", b"{}", 0o444);
            chmod(&folder, mode);
            let error = assert_refused(&path, &tree.rules(), UntrustedReason::ParentWritable);
            assert_eq!(error.path, folder, "mode {mode:o}");
        }
    }

    #[test]
    fn a_sticky_world_writable_parent_has_no_exemption() {
        let tree = Tree::new();
        let folder = tree.dir("PAM", 0o755);
        let path = tree.file("PAM/policy.json", b"{}", 0o444);
        chmod(&folder, 0o1777);
        assert_refused(&path, &tree.rules(), UntrustedReason::ParentWritable);
    }

    #[test]
    fn a_writable_grandparent_is_refused() {
        let tree = Tree::new();
        let outer = tree.dir("outer", 0o755);
        tree.dir("outer/PAM", 0o755);
        let path = tree.file("outer/PAM/policy.json", b"{}", 0o444);
        chmod(&outer, 0o777);
        let error = assert_refused(&path, &tree.rules(), UntrustedReason::ParentWritable);
        assert_eq!(error.path, outer);
    }

    #[test]
    fn an_ancestor_owned_by_someone_else_is_refused() {
        // The file is the expected owner's, but the folders above it are
        // owned by the test user, whom this rule does not allow for them.
        let tree = Tree::new();
        let path = tree.good(b"{}");
        let rules = tree.rules().with_ancestor_owners(vec![0]);
        let error = assert_refused(&path, &rules, UntrustedReason::ParentWritable);
        assert_eq!(error.path, tree.base.join("PAM"));
        assert!(error.detail.contains("not root"), "{error}");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        let path = tree.dir("PAM/policy.json", 0o555);
        assert_refused(&path, &tree.rules(), UntrustedReason::NotRegular);
    }

    #[test]
    fn a_fifo_is_not_a_regular_file_and_is_never_opened() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        let path = tree.base.join("PAM/policy.json");
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg("-m")
            .arg("0444")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success(), "mkfifo failed");
        // Opening a fifo for read would block: the stat refuses it first.
        assert_refused(&path, &tree.rules(), UntrustedReason::NotRegular);
    }

    #[test]
    fn an_empty_file_is_trusted_as_empty_bytes() {
        let tree = Tree::new();
        let path = tree.good(b"");
        let trusted = verify_and_read(&path, &tree.rules()).expect("trusted");
        assert!(trusted.bytes().is_empty());
    }

    #[test]
    fn exactly_the_bound_is_trusted_and_one_byte_more_is_too_large() {
        let bound = usize::try_from(MAX_POLICY_BYTES).expect("bound fits usize");
        let tree = Tree::new();
        let path = tree.good(&vec![b' '; bound]);
        let trusted = verify_and_read(&path, &tree.rules()).expect("trusted");
        assert_eq!(trusted.bytes().len(), bound);

        let tree = Tree::new();
        let path = tree.good(&vec![b' '; bound + 1]);
        assert_refused(&path, &tree.rules(), UntrustedReason::TooLarge);
    }

    #[test]
    fn a_smaller_bound_applies() {
        let tree = Tree::new();
        let path = tree.good(b"0123456789A");
        let rules = tree.rules().with_max_bytes(10);
        assert_refused(&path, &rules, UntrustedReason::TooLarge);
        let rules = tree.rules().with_max_bytes(11);
        assert!(verify_and_read(&path, &rules).is_ok());
    }

    #[test]
    fn a_file_replaced_between_the_stat_and_the_open_is_busy() {
        let tree = Tree::new();
        let path = tree.good(b"{\"original\":true}");
        let replacement = tree.file("PAM/.policy.json.new", b"{\"swapped\":true}", 0o444);
        let rules = tree
            .rules()
            .with_before_open(Arc::new(move |target: &Path| {
                fs::rename(&replacement, target).expect("swap");
            }));
        let error = assert_refused(&path, &rules, UntrustedReason::Busy);
        assert!(error.detail.contains("replaced"), "{error}");
        assert!(error.reason.is_transient());
        // The next check, with no swap, reads the new file.
        let trusted = verify_and_read(&path, &tree.rules()).expect("trusted");
        assert_eq!(trusted.bytes(), b"{\"swapped\":true}");
    }

    #[test]
    fn a_file_that_vanishes_mid_check_is_busy_not_absent() {
        let tree = Tree::new();
        let path = tree.good(b"{}");
        let rules = tree.rules().with_before_open(Arc::new(|target: &Path| {
            fs::remove_file(target).expect("remove");
        }));
        let error = assert_refused(&path, &rules, UntrustedReason::Busy);
        assert!(!error.is_absent());
    }

    #[test]
    fn an_unreadable_file_is_refused() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        let path = tree.file("PAM/policy.json", b"{}", 0o000);
        assert_refused(&path, &tree.rules(), UntrustedReason::Unreadable);
    }

    #[test]
    fn a_missing_file_or_folder_is_absent() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        for rel in ["PAM/policy.json", "missing/policy.json"] {
            let error = refused(&tree.base.join(rel), &tree.rules());
            assert!(error.is_absent(), "{rel}: {error}");
            assert_eq!(error.code(), "unreadable");
        }
    }

    #[test]
    fn a_refusal_names_the_path_and_the_code() {
        let tree = Tree::new();
        tree.dir("PAM", 0o755);
        let path = tree.file("PAM/policy.json", b"{}", 0o666);
        let error = refused(&path, &tree.rules());
        let text = error.to_string();
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(text.contains("writable_by_user"), "{text}");
        assert!(!error.recovery().is_empty());
    }
}

/// Built and run only in the Windows VM (the only Windows compiler).
#[cfg(windows)]
mod windows {
    use std::path::{Path, PathBuf};

    use crate::managed_policy_trust::{TrustRules, UntrustedReason, policy_path, verify_and_read};

    #[test]
    fn the_platform_path_is_under_a_drive_program_data() {
        let path = policy_path();
        let text = path.to_string_lossy().to_ascii_lowercase();
        assert!(text.ends_with(r"\programdata\pam\policy.json"), "{text}");
        assert_eq!(text.as_bytes()[1], b':', "{text}");
    }

    #[test]
    fn a_file_in_the_users_own_temp_folder_is_writable_by_user() {
        // As the logged-in user and as SYSTEM alike: the token can write it.
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = canonical(tmp.path());
        std::fs::create_dir(base.join("PAM")).expect("mkdir");
        let path = base.join("PAM").join("policy.json");
        std::fs::write(&path, b"{}").expect("write");
        let error = verify_and_read(&path, &TrustRules::production()).expect_err("untrusted");
        assert_eq!(error.reason, UntrustedReason::WritableByUser, "{error}");
    }

    #[test]
    fn a_read_only_file_the_user_owns_is_still_writable_by_user() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = canonical(tmp.path());
        let path = base.join("policy.json");
        std::fs::write(&path, b"{}").expect("write");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions.clone()).expect("readonly");
        let error = verify_and_read(&path, &TrustRules::production()).expect_err("untrusted");
        assert_eq!(error.reason, UntrustedReason::WritableByUser, "{error}");
        // Windows only: clears the read-only attribute so the temp folder can
        // be removed (the unix meaning of this call does not apply here).
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).expect("writable again");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = canonical(tmp.path());
        let path = base.join("policy.json");
        std::fs::create_dir(&path).expect("mkdir");
        let error = verify_and_read(&path, &TrustRules::production()).expect_err("untrusted");
        assert_eq!(error.reason, UntrustedReason::NotRegular, "{error}");
    }

    #[test]
    fn a_missing_file_is_absent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = canonical(tmp.path());
        let error = verify_and_read(
            &base.join("PAM").join("policy.json"),
            &TrustRules::production(),
        )
        .expect_err("absent");
        assert!(error.is_absent(), "{error}");
    }

    fn canonical(path: &Path) -> PathBuf {
        let canonical = std::fs::canonicalize(path).expect("canonical");
        let text = canonical.to_string_lossy();
        PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned())
    }

    /// The ACL matrix. `PAM_TRUST_FIXTURES` names a folder built from SYSTEM
    /// with `icacls` (T13), one subfolder per case, each holding
    /// `PAM\policy.json`; the case folder itself carries the locked ACL so
    /// the grandparent probe passes. Run as the unprivileged user
    /// (`prlctl exec --current-user`); with `PAM_TRUST_FIXTURES_ELEVATED=1`
    /// (the SYSTEM run) every case must be untrusted, which proves the probe
    /// is sensitive. `PAM_REQUIRE_WIN_ACL_FIXTURES=1` makes a missing
    /// fixture a failure instead of a skip.
    #[test]
    fn the_acl_fixture_matrix() {
        let require = std::env::var_os("PAM_REQUIRE_WIN_ACL_FIXTURES").is_some_and(|v| v == "1");
        let elevated = std::env::var_os("PAM_TRUST_FIXTURES_ELEVATED").is_some_and(|v| v == "1");
        let Some(root) = std::env::var_os("PAM_TRUST_FIXTURES") else {
            assert!(!require, "PAM_TRUST_FIXTURES is not set");
            eprintln!("skipping: PAM_TRUST_FIXTURES is not set");
            return;
        };
        let root = PathBuf::from(root);
        let cases: [(&str, Option<UntrustedReason>); 10] = [
            ("locked", None),
            ("users_modify", Some(UntrustedReason::WritableByUser)),
            ("folder_write", Some(UntrustedReason::ParentWritable)),
            ("inherited", Some(UntrustedReason::ParentWritable)),
            ("owner_user", Some(UntrustedReason::WritableByUser)),
            ("delete_only", Some(UntrustedReason::WritableByUser)),
            ("delete_child", Some(UntrustedReason::ParentWritable)),
            ("junction", Some(UntrustedReason::Symlink)),
            ("symlink", Some(UntrustedReason::Symlink)),
            ("busy", Some(UntrustedReason::Busy)),
        ];
        for (name, expected) in cases {
            let path = root.join(name).join("PAM").join("policy.json");
            if std::fs::symlink_metadata(root.join(name)).is_err() {
                assert!(
                    !require,
                    "fixture {name} is missing under {}",
                    root.display()
                );
                eprintln!("skipping fixture {name}: not present");
                continue;
            }
            let result = verify_and_read(&path, &TrustRules::production());
            if elevated {
                assert!(
                    result.is_err(),
                    "{name}: an elevated token must read untrusted"
                );
                continue;
            }
            match (expected, result) {
                (None, Ok(_)) => {}
                (None, Err(error)) => panic!("{name}: expected trusted, got {error}"),
                (Some(reason), Ok(_)) => panic!("{name}: expected {reason}, got trusted"),
                (Some(reason), Err(error)) => {
                    assert_eq!(error.reason, reason, "{name}: {error}");
                }
            }
        }
    }
}
