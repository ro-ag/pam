//! The bare-launch rule: a double-clicked `.app` opens the GUI, a bare
//! terminal launch stays a CLI.

use std::path::Path;

use crate::launched_from_app_bundle;

#[test]
fn a_binary_inside_an_app_bundle_wants_the_gui() {
    assert!(launched_from_app_bundle(Path::new(
        "/Applications/pam.app/Contents/MacOS/pam"
    )));
}

#[test]
fn a_plain_binary_stays_a_cli() {
    assert!(!launched_from_app_bundle(Path::new("/usr/local/bin/pam")));
    assert!(!launched_from_app_bundle(Path::new(
        "/tmp/pam.app.backup/pam"
    )));
    assert!(!launched_from_app_bundle(Path::new(
        "/tmp/pam.application/pam"
    )));
}

#[test]
fn the_playbook_carries_the_whole_agent_loop() {
    for marker in [
        "pam doctor --json",
        "`established`",
        "`not_established`",
        "pam status --json",
        "pam flow list --json",
        "pam flow inspect <id> key=value --json",
        "pam flow run <id> key=value --no-wait --json",
        "pam wait <ticket> --json",
        "pam flow result <ticket> --json",
        "pam evidence read",
        "PAM_SOCKET_DIR",
        "input_unknown",
        "AGENTS.md",
    ] {
        assert!(
            crate::PLAYBOOK.contains(marker),
            "the playbook must teach `{marker}`"
        );
    }
    assert!(
        !crate::PLAYBOOK.contains("admin."),
        "the playbook never points an agent at the admin surface"
    );
}

// --- pam policy check: reading the administrator's file -----------------

mod policy_file {
    use std::path::Path;

    use pam_daemon::managed_policy::{MAX_POLICY_BYTES, TargetPlatform, Verdict};

    use crate::{PolicyBytes, PolicyContent, check_policy_file, read_policy_bytes};

    const MAX: u64 = MAX_POLICY_BYTES as u64;

    #[test]
    fn a_file_over_the_bound_is_refused_on_its_size_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        // Sparse: a gigabyte the reader must never try to read.
        std::fs::File::create(&path)
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        assert_eq!(
            read_policy_bytes(&path).unwrap(),
            PolicyBytes::TooLarge { size: 1 << 30 }
        );
        let check = check_policy_file(&path, TargetPlatform::Macos, false).unwrap();
        assert!(matches!(
            check.content,
            PolicyContent::TooLarge { size } if size == 1 << 30
        ));
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX + 1)
            .unwrap();
        assert_eq!(
            read_policy_bytes(&path).unwrap(),
            PolicyBytes::TooLarge { size: MAX + 1 }
        );
    }

    #[test]
    fn a_file_at_the_bound_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge.json");
        std::fs::write(&path, vec![b' '; usize::try_from(MAX).unwrap()]).unwrap();
        let PolicyBytes::Read(bytes) = read_policy_bytes(&path).unwrap() else {
            panic!("a file of exactly the bound is read");
        };
        assert_eq!(bytes.len() as u64, MAX);
    }

    #[test]
    fn only_a_regular_file_is_opened() {
        let dir = tempfile::tempdir().unwrap();
        let error = read_policy_bytes(dir.path()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let missing = read_policy_bytes(&dir.path().join("missing.json")).unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    }

    /// A fifo would block the open until a writer came; it is refused on
    /// its type before any open.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("policy.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let error = read_policy_bytes(&fifo).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// The fixed path is judged as named, so a link in it reaches the daemon's
    /// own check; any other path has its parent resolved.
    #[test]
    fn only_the_fixed_path_is_judged_unresolved() {
        use std::path::Component;

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("PAM")).unwrap();
        let named = dir
            .path()
            .join("PAM")
            .join("..")
            .join("PAM")
            .join("policy.json");
        let absolute = std::path::absolute(&named).unwrap();
        assert_eq!(crate::trust_check_path(&named, &absolute), absolute);
        let other = dir.path().join("other.json");
        let resolved = crate::trust_check_path(&named, &other);
        assert!(
            resolved
                .components()
                .all(|part| part != Component::ParentDir),
            "{}",
            resolved.display()
        );
    }

    #[test]
    fn a_byte_order_mark_is_read_as_the_daemon_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bom.json");
        std::fs::write(
            &path,
            b"\xEF\xBB\xBF{\"version\":1,\"organization\":\"Example Corp\"}",
        )
        .unwrap();
        let check = check_policy_file(&path, TargetPlatform::Macos, false).unwrap();
        let PolicyContent::Inspected {
            inspection,
            document,
        } = &check.content
        else {
            panic!("a small file is inspected");
        };
        assert_eq!(inspection.verdict(), Verdict::Valid);
        assert_eq!(document.as_ref().unwrap()["organization"], "Example Corp");
        assert!(check.trust.is_none(), "no trust check unless asked");
    }

    #[test]
    fn the_trust_check_judges_the_named_file_in_its_resolved_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, br#"{"version":1}"#).unwrap();
        let check = check_policy_file(&path, TargetPlatform::host(), true).unwrap();
        let trust = check.trust.expect("asked for");
        let expected = dir.path().canonicalize().unwrap().join("policy.json");
        let expected =
            pam_daemon::managed_policy::without_verbatim_prefix(&expected.to_string_lossy())
                .into_owned();
        assert_eq!(trust.checked_path, Path::new(&expected));
        assert!(!trust.at_fixed_path());
        assert!(
            trust.outcome.is_err(),
            "a file this test owns is never trusted"
        );
    }

    /// The file name is never resolved: a link is judged as a link.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_policy_is_judged_as_a_symlink() {
        use pam_daemon::managed_policy_trust::UntrustedReason;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.json");
        std::fs::write(&target, br#"{"version":1}"#).unwrap();
        let link = dir.path().join("policy.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let check = check_policy_file(&link, TargetPlatform::host(), true).unwrap();
        let trust = check.trust.unwrap();
        assert!(trust.checked_path.ends_with("policy.json"));
        assert_eq!(trust.outcome.unwrap_err().reason, UntrustedReason::Symlink);
    }
}
