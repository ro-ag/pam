use super::*;
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::fs;

/// A direct profile: no proxy, the platform's trust.
fn direct() -> Arc<NetSettings> {
    Arc::new(NetSettings::direct())
}

/// The fake release, fetched over the plain-http origin: the test allowance.
#[cfg(unix)]
async fn install_fake(
    base: &Path,
    release: &EngineRelease,
    cancel: watch::Receiver<bool>,
    mirror: Option<&MirrorBase>,
) -> Result<EngineStatus, EngineError> {
    install_release_over_plain_http_for_tests(base, release, cancel, direct(), mirror).await
}

#[test]
fn every_ci_runner_maps_to_exactly_one_pinned_asset() {
    let mut names: Vec<&str> = ENGINE_ASSETS.iter().map(|a| a.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), ENGINE_ASSETS.len());
    for asset in &ENGINE_ASSETS {
        assert!(asset.name.contains(ENGINE_TAG), "{}", asset.name);
        assert_eq!(asset.sha256.len(), 64);
        assert!(
            asset
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert!(asset.bytes > 1_000_000);
        assert_eq!(asset.target.asset(), asset);
    }
    for (os, arch, target) in [
        ("macos", "aarch64", Target::MacosArm64),
        ("windows", "x86_64", Target::WinCpuX64),
        ("windows", "aarch64", Target::WinCpuArm64),
    ] {
        assert_eq!(Target::for_platform(os, arch), Some(target));
    }
    // Linux and Intel macOS are not supported: no asset, so the engine
    // reports `unsupported_target`.
    for (os, arch) in [
        ("freebsd", "x86_64"),
        ("linux", "x86_64"),
        ("linux", "aarch64"),
        ("macos", "x86_64"),
    ] {
        assert_eq!(Target::for_platform(os, arch), None, "{os} {arch}");
    }
    assert!(
        Target::current().is_some(),
        "this host is a supported target"
    );
    assert!(ENGINE_RELEASE_BASE.ends_with(&format!("{ENGINE_TAG}/")));
}

#[test]
fn the_layout_keeps_everything_under_the_private_engine_directory() {
    let layout = EngineLayout::new(std::path::Path::new("/base"));
    assert_eq!(layout.root(), std::path::Path::new("/base/engine"));
    assert_eq!(
        layout.archive_path("a.tar.gz"),
        std::path::Path::new("/base/engine/a.tar.gz")
    );
    assert_eq!(
        layout.install_dir("b1"),
        std::path::Path::new("/base/engine/llama-b1")
    );
    assert_eq!(
        layout.server_path("b1", Target::WinCpuX64),
        std::path::Path::new("/base/engine/llama-b1/llama-server.exe")
    );
    assert_eq!(
        layout.server_path("b1", Target::MacosArm64),
        std::path::Path::new("/base/engine/llama-b1/llama-server")
    );
}

#[test]
fn status_reports_why_the_engine_is_not_usable() {
    let base = tempfile::tempdir().unwrap();
    let missing = status(base.path());
    assert!(!missing.installed);
    assert_eq!(missing.cause.as_deref(), Some("not_installed"));
    assert_eq!(missing.expected_tag, ENGINE_TAG);

    let layout = EngineLayout::new(base.path());
    fs::create_dir_all(layout.root()).unwrap();
    fs::write(layout.manifest_path(), b"{not json").unwrap();
    assert_eq!(
        status(base.path()).cause.as_deref(),
        Some("manifest_invalid")
    );

    let target = Target::current().unwrap();
    let manifest = |tag: &str, build: u64| EngineManifest {
        tag: tag.into(),
        build,
        target,
        asset: "x".into(),
        sha256: "0".repeat(64),
        bytes: 1,
        version_line: "version: test".into(),
        installed_at_ms: 0,
        source: None,
    };
    fs::write(
        layout.manifest_path(),
        serde_json::to_vec(&manifest("b1", 1)).unwrap(),
    )
    .unwrap();
    assert_eq!(status(base.path()).cause.as_deref(), Some("stale_release"));

    fs::write(
        layout.manifest_path(),
        serde_json::to_vec(&manifest(ENGINE_TAG, ENGINE_BUILD)).unwrap(),
    )
    .unwrap();
    assert_eq!(status(base.path()).cause.as_deref(), Some("server_missing"));

    fs::create_dir_all(layout.install_dir(ENGINE_TAG)).unwrap();
    fs::write(layout.server_path(ENGINE_TAG, target), b"").unwrap();
    let ready = status(base.path());
    assert!(ready.installed);
    assert_eq!(
        ready.server_path.as_deref(),
        Some(layout.server_path(ENGINE_TAG, target).as_path())
    );
    assert!(ready.cause.is_none());
}

/// A tar.gz holding `llama-<tag>/llama-server`, a script that prints the
/// given build line, built with the OS tar the installer itself uses.
#[cfg(unix)]
fn fake_archive(tag: &str, build_line: &str) -> (tempfile::TempDir, Vec<u8>) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join(format!("llama-{tag}"));
    fs::create_dir_all(&tree).unwrap();
    let server = tree.join("llama-server");
    fs::write(
        &server,
        format!("#!/bin/sh\necho '{build_line}'\necho 'built with test'\n"),
    )
    .unwrap();
    fs::set_permissions(&server, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(tree.join("libggml.dylib"), b"not a library").unwrap();
    let archive = dir.path().join("release.tar.gz");
    let status = std::process::Command::new(trusted_tar_path().unwrap())
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(dir.path())
        .arg(format!("llama-{tag}"))
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = fs::read(&archive).unwrap();
    (dir, bytes)
}

#[cfg(unix)]
fn release_for(server: &crate::testing::TestServer, bytes: &[u8], build: u64) -> EngineRelease {
    EngineRelease {
        tag: "btest".into(),
        build,
        url_base: server.url(""),
        target: Target::current().unwrap(),
        asset_name: "release.tar.gz".into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn install_downloads_unpacks_and_smoke_checks_the_server() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let origin = crate::testing::serve(bytes.clone(), "\"etag\"").await;
    let release = release_for(&origin, &bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let installed = install_fake(base.path(), &release, rx.clone(), None)
        .await
        .expect("the fake release installs");
    let layout = EngineLayout::new(base.path());
    let server = layout.server_path("btest", release.target);
    assert_eq!(installed.server_path.as_deref(), Some(server.as_path()));
    assert!(server.is_file());
    assert!(layout.install_dir("btest").join("libggml.dylib").is_file());
    let manifest = installed.manifest.expect("manifest recorded");
    assert_eq!(manifest.tag, "btest");
    assert_eq!(manifest.build, 42);
    assert_eq!(manifest.sha256, release.sha256);
    assert_eq!(
        manifest.version_line,
        "version: 0.0.0 (build 42, commit abc)"
    );
    assert_eq!(
        manifest.source,
        Some(EngineSource::Download {
            host: origin
                .url("")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_owned()
        }),
        "the manifest records the upstream host"
    );
    assert!(
        !layout.archive_path("release.tar.gz").exists(),
        "archive removed"
    );
    assert!(
        !crate::registry::verified_sidecar_path(&layout.archive_path("release.tar.gz")).exists(),
        "the downloader's verification sidecar goes with the archive"
    );
    assert!(
        fs::read_dir(layout.root()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")),
        "the manifest's temporary file is renamed away"
    );
    assert!(
        fs::read_dir(layout.root()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".unpack-")),
        "scratch directory removed"
    );
    // A second install of the same release is a no-op read: no transfer.
    let requests_after_install = origin.requests().len();
    let again = install_fake(base.path(), &release, rx, None).await.unwrap();
    assert_eq!(again.manifest, Some(manifest));
    assert_eq!(origin.requests().len(), requests_after_install);
}

#[cfg(unix)]
#[tokio::test]
async fn a_tampered_archive_never_reaches_tar() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let origin = crate::testing::serve(bytes.clone(), "\"etag\"").await;
    let mut release = release_for(&origin, &bytes, 42);
    release.sha256 = "f".repeat(64);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let error = install_fake(base.path(), &release, rx, None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineError::Download { ref cause, .. } if cause == "digest_mismatch"),
        "{error:?}"
    );
    let layout = EngineLayout::new(base.path());
    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
}

#[cfg(unix)]
#[tokio::test]
async fn a_server_that_reports_another_build_is_discarded() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 41, commit abc)");
    let origin = crate::testing::serve(bytes.clone(), "\"etag\"").await;
    let release = release_for(&origin, &bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let error = install_fake(base.path(), &release, rx, None)
        .await
        .unwrap_err();
    assert!(matches!(error, EngineError::Verify { .. }), "{error:?}");
    let layout = EngineLayout::new(base.path());
    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
    assert!(fs::read_dir(layout.root()).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".unpack-")
    }));
}

/// With a mirror the archive is asked for by its pinned name under the
/// mirror directory, and held to the same digest; the local origin plays
/// the mirror.
#[cfg(unix)]
#[tokio::test]
async fn install_fetches_the_pinned_asset_name_from_the_mirror() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let origin = crate::testing::serve(bytes.clone(), "\"etag\"").await;
    let mut release = release_for(&origin, &bytes, 42);
    // Upstream is unreachable on purpose: only the mirror can serve it.
    release.url_base = "https://releases.pam-test.invalid/llama/btest/".to_owned();
    let mirror = MirrorBase::for_tests(&origin.url("corp/llama.cpp/btest"));
    assert_eq!(
        release.url(Some(&mirror)).unwrap(),
        origin.url("corp/llama.cpp/btest/release.tar.gz")
    );
    assert_eq!(
        release.url(None).unwrap(),
        "https://releases.pam-test.invalid/llama/btest/release.tar.gz"
    );
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let installed = install_fake(base.path(), &release, rx, Some(&mirror))
        .await
        .expect("the fake release installs from the mirror");
    assert!(installed.installed);
    let manifest = installed.manifest.unwrap();
    assert_eq!(manifest.sha256, release.sha256);
    assert_eq!(
        manifest.source,
        Some(EngineSource::Mirror {
            host: "127.0.0.1".to_owned(),
            url: origin.url("corp/llama.cpp/btest/release.tar.gz"),
        }),
        "the manifest records the mirror"
    );
    assert!(
        origin
            .requests()
            .iter()
            .any(|line| line.starts_with("GET /corp/llama.cpp/btest/release.tar.gz ")),
        "the mirror is asked for the pinned asset name: {:?}",
        origin.requests()
    );
}

/// A mirror that serves other bytes is refused as a digest mismatch, and
/// nothing reaches tar; the pinned digest is not the mirror's to change.
#[cfg(unix)]
#[tokio::test]
async fn a_mirror_serving_other_bytes_is_a_digest_mismatch() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let (_other, other_bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit xyz)");
    let origin = crate::testing::serve(other_bytes, "\"etag\"").await;
    let mut release = release_for(&origin, &bytes, 42);
    release.bytes = 0;
    release.url_base = "https://releases.pam-test.invalid/llama/btest/".to_owned();
    let mirror = MirrorBase::for_tests(&origin.url(""));
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let error = install_fake(base.path(), &release, rx, Some(&mirror))
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineError::Download { ref cause, .. } if cause == "size_mismatch" || cause == "digest_mismatch"),
        "{error:?}"
    );
    let layout = EngineLayout::new(base.path());
    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
}

/// A plain-http release address is refused by the production path before
/// any transfer, with the launcher's cause carried through.
#[cfg(unix)]
#[tokio::test]
async fn production_install_refuses_a_plain_http_release() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let origin = crate::testing::serve(bytes.clone(), "\"etag\"").await;
    let release = release_for(&origin, &bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let error = install_release(base.path(), &release, rx, direct(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineError::Download { ref cause, ref detail }
            if cause == "start" && detail.contains("only https addresses are downloaded")),
        "{error:?}"
    );
    assert!(origin.requests().is_empty(), "curl never ran");
}

/// Opt-in: fetches the real pinned release from GitHub and proves the
/// pinned digest, the OS tar and the real `llama-server --version` agree.
/// `cargo test -p pam_model --lib -- engine --ignored --nocapture`.
#[tokio::test]
#[ignore = "downloads the pinned llama.cpp release from GitHub"]
async fn the_pinned_release_installs_on_this_host() {
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let installed = install(base.path(), rx, direct(), None)
        .await
        .expect("the pinned release installs");
    assert!(installed.installed, "{installed:?}");
    let manifest = installed.manifest.clone().expect("manifest");
    assert_eq!(manifest.tag, ENGINE_TAG);
    assert_eq!(manifest.build, ENGINE_BUILD);
    assert_eq!(manifest.sha256, Target::current().unwrap().asset().sha256);
    println!(
        "PAM_ENGINE_INSTALL {}",
        serde_json::to_string(&manifest).unwrap()
    );
    assert_eq!(status(base.path()), installed);
}

// ---- installing from a file on this machine ----

/// A release pinned to `bytes`, for an archive that is never fetched: its
/// URL base is an unreachable name, so only the file can supply it.
#[cfg(unix)]
fn offline_release(bytes: &[u8], build: u64) -> EngineRelease {
    EngineRelease {
        tag: "btest".into(),
        build,
        url_base: "https://releases.pam-test.invalid/llama/btest/".to_owned(),
        target: Target::current().unwrap(),
        asset_name: "llama-btest-bin-test.tar.gz".into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        bytes: bytes.len() as u64,
    }
}

/// The archive under its pinned name in a folder IT would hand over.
#[cfg(unix)]
fn provisioned(release: &EngineRelease, bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(&release.asset_name);
    fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[cfg(unix)]
fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// The pinned archive given by its file path: copied, hashed, unpacked,
/// smoke-checked and recorded as imported; the original is untouched and
/// the private copy is gone afterwards.
#[cfg(unix)]
#[tokio::test]
async fn import_installs_the_pinned_archive_from_a_file_and_leaves_the_original() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let (_share, path) = provisioned(&release, &bytes);
    let before = fs::metadata(&path).unwrap();
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let installed = import_release(base.path(), &release, &path, rx.clone())
        .await
        .expect("the archive imports");
    assert!(installed.installed);
    let layout = EngineLayout::new(base.path());
    assert!(layout.server_path("btest", release.target).is_file());
    let manifest = installed.manifest.clone().expect("manifest");
    assert_eq!(manifest.sha256, release.sha256);
    assert_eq!(manifest.bytes, release.bytes);
    assert_eq!(manifest.asset, release.asset_name);
    match &manifest.source {
        Some(EngineSource::Import {
            path: recorded,
            imported_at_ms,
        }) => {
            assert_eq!(recorded, &path.display().to_string());
            assert!(*imported_at_ms > 0);
        }
        other => panic!("import source expected, got {other:?}"),
    }
    assert!(
        !layout.archive_path(&release.asset_name).exists(),
        "private copy removed"
    );
    assert!(
        entries(layout.root())
            .iter()
            .all(|n| !n.starts_with(".unpack-"))
    );
    let after = fs::metadata(&path).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(fs::read(&path).unwrap(), bytes, "the original is untouched");
    // Already installed with this digest: a second import reads and copies nothing.
    let again = import_release(base.path(), &release, &path, rx)
        .await
        .unwrap();
    assert_eq!(again.manifest, Some(manifest));
}

/// A folder is accepted only as the folder holding the asset by its exact
/// name; the asset is found there, and nothing else in it is looked at.
#[cfg(unix)]
#[tokio::test]
async fn import_accepts_the_folder_that_holds_the_asset_by_name() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let (share, _path) = provisioned(&release, &bytes);
    fs::write(share.path().join("llama-other-bin-test.tar.gz"), b"decoy").unwrap();
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let installed = import_release(base.path(), &release, share.path(), rx)
        .await
        .expect("the folder's archive imports");
    assert!(installed.installed);
    assert!(matches!(
        installed.manifest.unwrap().source,
        Some(EngineSource::Import { path, .. }) if path == share.path().display().to_string()
    ));
}

/// What is refused by name, with nothing copied and nothing installed: a
/// missing path, a file not named like the asset, a folder without it, a
/// bare unpacked tree, a symbolic link at either level, and a source inside
/// the engine directory.
#[cfg(unix)]
#[tokio::test]
async fn import_refuses_anything_that_is_not_the_pinned_archive() {
    let (tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let layout = EngineLayout::new(base.path());
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let attempt = |path: PathBuf| {
        let rx = rx.clone();
        let release = release.clone();
        let base = base.path().to_path_buf();
        async move {
            import_release(&base, &release, &path, rx)
                .await
                .unwrap_err()
        }
    };
    let expected = release.asset_name.clone();

    let missing = attempt(tree.path().join("nowhere")).await;
    assert!(
        matches!(missing, EngineError::SourceMissing { .. }),
        "{missing:?}"
    );

    // The right bytes under the wrong name: the name is part of the pin.
    let renamed = tree.path().join("release.tar.gz");
    let wrong_name = attempt(renamed.clone()).await;
    assert!(
        matches!(&wrong_name, EngineError::NotTheAsset { found, expected: e, bytes: b, .. }
            if found.contains("release.tar.gz") && e == &expected && *b == release.bytes),
        "{wrong_name:?}"
    );
    assert!(wrong_name.to_string().contains(&expected), "{wrong_name}");

    // A bare unpacked tree has nothing to hash.
    let unpacked = attempt(tree.path().join("llama-btest")).await;
    assert!(
        matches!(&unpacked, EngineError::NotTheAsset { found, .. } if found.contains("holds no")),
        "{unpacked:?}"
    );

    // A folder with a symlink under the asset name, and a symlink to the folder.
    let (share, real) = provisioned(&release, &bytes);
    let linked_dir = tree.path().join("linked");
    fs::create_dir(&linked_dir).unwrap();
    std::os::unix::fs::symlink(&real, linked_dir.join(&release.asset_name)).unwrap();
    let inner_link = attempt(linked_dir).await;
    assert!(
        matches!(inner_link, EngineError::SourceSymlink { .. }),
        "{inner_link:?}"
    );
    let outer = tree.path().join("share-link");
    std::os::unix::fs::symlink(share.path(), &outer).unwrap();
    let outer_link = attempt(outer).await;
    assert!(
        matches!(outer_link, EngineError::SourceSymlink { .. }),
        "{outer_link:?}"
    );

    // A source inside the engine directory would be deleted by the install.
    fs::create_dir_all(layout.root()).unwrap();
    let inside = layout.root().join(&release.asset_name);
    fs::write(&inside, &bytes).unwrap();
    let in_engine = attempt(inside.clone()).await;
    assert!(
        matches!(in_engine, EngineError::SourceInsideEngineDir { .. }),
        "{in_engine:?}"
    );
    fs::remove_file(&inside).unwrap();

    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
    assert!(
        entries(layout.root()).is_empty(),
        "{:?}",
        entries(layout.root())
    );
}

/// A file of another size is refused before a byte is copied; a file of the
/// right size with other bytes is copied, found not to match, deleted, and
/// nothing is installed — the pinned digest is not the file's to change.
#[cfg(unix)]
#[tokio::test]
async fn import_holds_the_file_to_the_pinned_size_and_digest() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let (_other, other_bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit xyz)");
    let release = offline_release(&bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let layout = EngineLayout::new(base.path());
    let (_cancel, rx) = tokio::sync::watch::channel(false);

    let mut padded = bytes.clone();
    padded.push(0);
    let (_s1, wrong_size) = provisioned(&release, &padded);
    let error = import_release(base.path(), &release, &wrong_size, rx.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineError::SizeMismatch { expected, actual, .. }
            if expected == release.bytes && actual == release.bytes + 1),
        "{error:?}"
    );
    assert!(entries(layout.root()).is_empty(), "nothing was copied");

    // Same size, other bytes: the tar archives differ only in their payload
    // only when their lengths agree, so pad the pinned one to match.
    let mut same_size = other_bytes.clone();
    same_size.resize(bytes.len(), 0);
    let (_s2, wrong_digest) = provisioned(&release, &same_size);
    let error = import_release(base.path(), &release, &wrong_digest, rx)
        .await
        .unwrap_err();
    match &error {
        EngineError::DigestMismatch {
            expected,
            actual,
            tag,
        } => {
            assert_eq!(expected, &release.sha256);
            assert_eq!(actual, &format!("{:x}", Sha256::digest(&same_size)));
            assert_eq!(tag, "btest");
            assert!(error.to_string().contains("pins llama.cpp btest"));
        }
        other => panic!("digest mismatch expected, got {other:?}"),
    }
    assert!(
        !layout.archive_path(&release.asset_name).exists(),
        "the copy is deleted"
    );
    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
    assert!(wrong_digest.is_file(), "the original is untouched");
}

/// The digest can match and the server still lie about its build: that is
/// refused like a download of such an archive, and nothing stays installed.
#[cfg(unix)]
#[tokio::test]
async fn import_requires_the_unpacked_server_to_report_the_pinned_build() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 41, commit abc)");
    let release = offline_release(&bytes, 42);
    let (_share, path) = provisioned(&release, &bytes);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let error = import_release(base.path(), &release, &path, rx)
        .await
        .unwrap_err();
    assert!(matches!(error, EngineError::Verify { .. }), "{error:?}");
    let layout = EngineLayout::new(base.path());
    assert!(!layout.install_dir("btest").exists());
    assert!(!layout.manifest_path().exists());
    assert!(
        entries(layout.root()).is_empty(),
        "{:?}",
        entries(layout.root())
    );
}

/// Cancelling mid-copy deletes the private copy and installs nothing.
#[cfg(unix)]
#[tokio::test]
async fn a_cancelled_import_leaves_no_copy() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let (_share, path) = provisioned(&release, &bytes);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(true);
    let error = import_release(base.path(), &release, &path, rx)
        .await
        .unwrap_err();
    assert!(matches!(error, EngineError::Cancelled), "{error:?}");
    let layout = EngineLayout::new(base.path());
    assert!(
        entries(layout.root()).is_empty(),
        "{:?}",
        entries(layout.root())
    );
}

/// The production entry point builds the pinned release itself: a file
/// carrying the pinned asset's name but not its size is refused with the
/// compiled-in numbers, and nothing can be installed with other ones.
#[tokio::test]
async fn production_import_holds_a_file_to_the_compiled_in_pin() {
    let target = Target::current().unwrap();
    let asset = target.asset();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(asset.name);
    fs::write(&path, b"not the release").unwrap();
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let error = import(base.path(), &path, rx).await.unwrap_err();
    assert!(
        matches!(&error, EngineError::SizeMismatch { expected, actual: 15, expected_name }
            if *expected == asset.bytes && expected_name == asset.name),
        "{error:?}"
    );
    assert!(!status(base.path()).installed);
    assert_eq!(status(base.path()).cause.as_deref(), Some("not_installed"));
}

/// A manifest planted beside an unpacked tree cannot make the daemon run it:
/// `status` reports what the manifest claims only for the pinned tag and
/// build, and an install or import over it goes through the full check
/// again, since the planted digest is not the pinned one.
#[cfg(unix)]
#[tokio::test]
async fn a_planted_manifest_is_no_substitute_for_the_pinned_digest() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let base = tempfile::tempdir().unwrap();
    let layout = EngineLayout::new(base.path());
    // "Installed", says a manifest with the pinned tag and build but another digest.
    fs::create_dir_all(layout.install_dir("btest")).unwrap();
    fs::write(
        layout.server_path("btest", release.target),
        b"#!/bin/sh\nexit 1\n",
    )
    .unwrap();
    let planted = EngineManifest {
        tag: "btest".into(),
        build: 42,
        target: release.target,
        asset: release.asset_name.clone(),
        sha256: "0".repeat(64),
        bytes: release.bytes,
        version_line: "version: planted".into(),
        installed_at_ms: 0,
        source: None,
    };
    fs::write(
        layout.manifest_path(),
        serde_json::to_vec(&planted).unwrap(),
    )
    .unwrap();
    // The real archive, imported over it, replaces it: the planted server is gone.
    let (_share, path) = provisioned(&release, &bytes);
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let installed = import_release(base.path(), &release, &path, rx)
        .await
        .expect("the pinned archive replaces the planted tree");
    let manifest = installed.manifest.unwrap();
    assert_eq!(manifest.sha256, release.sha256);
    assert_eq!(
        manifest.version_line,
        "version: 0.0.0 (build 42, commit abc)"
    );
    assert!(matches!(manifest.source, Some(EngineSource::Import { .. })));
}

/// Removing deletes everything under the engine directory — archive,
/// release, manifest, private weight copies, scratch — and nothing else;
/// status then reads not installed.
#[cfg(unix)]
#[tokio::test]
async fn remove_clears_the_engine_directory_and_nothing_else() {
    let (_tree, bytes) = fake_archive("btest", "version: 0.0.0 (build 42, commit abc)");
    let release = offline_release(&bytes, 42);
    let (_share, path) = provisioned(&release, &bytes);
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    import_release(base.path(), &release, &path, rx)
        .await
        .unwrap();
    let layout = EngineLayout::new(base.path());
    fs::create_dir_all(layout.root().join("weights")).unwrap();
    fs::write(layout.root().join("weights").join("abc.gguf"), b"w").unwrap();
    fs::write(layout.root().join("api-key"), b"k").unwrap();
    fs::write(layout.archive_path(&release.asset_name), b"stale").unwrap();
    fs::create_dir_all(layout.root().join(".unpack-1-2")).unwrap();
    let neighbour = base.path().join("state.sqlite3");
    fs::write(&neighbour, b"db").unwrap();

    let report = remove(base.path()).unwrap();
    assert_eq!(report.engine_dir, layout.root());
    let mut removed = report.removed.clone();
    removed.sort();
    assert_eq!(
        removed,
        [
            ".pam-engine.json",
            ".unpack-1-2",
            "api-key",
            "llama-btest",
            release.asset_name.as_str(),
            "weights"
        ]
    );
    assert!(entries(layout.root()).is_empty());
    assert!(layout.root().is_dir(), "the private directory itself stays");
    assert!(
        neighbour.is_file(),
        "nothing outside the engine directory is touched"
    );
    assert!(!status(base.path()).installed);
    assert_eq!(status(base.path()).cause.as_deref(), Some("not_installed"));
    // Removing an engine that is not there is a no-op, not an error.
    assert!(remove(base.path()).unwrap().removed.is_empty());
    assert!(
        remove(&base.path().join("absent"))
            .unwrap()
            .removed
            .is_empty()
    );
}
