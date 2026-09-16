use super::*;
use sha2::{Digest, Sha256};
use std::fs;

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
        ("macos", "x86_64", Target::MacosX64),
        ("linux", "x86_64", Target::UbuntuX64),
        ("linux", "aarch64", Target::UbuntuArm64),
        ("windows", "x86_64", Target::WinCpuX64),
        ("windows", "aarch64", Target::WinCpuArm64),
    ] {
        assert_eq!(Target::for_platform(os, arch), Some(target));
    }
    assert_eq!(Target::for_platform("freebsd", "x86_64"), None);
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
        layout.server_path("b1", Target::UbuntuX64),
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

    let installed = install_release(base.path(), &release, rx.clone())
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
    let again = install_release(base.path(), &release, rx).await.unwrap();
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
    let error = install_release(base.path(), &release, rx)
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
    let error = install_release(base.path(), &release, rx)
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

/// Opt-in: fetches the real pinned release from GitHub and proves the
/// pinned digest, the OS tar and the real `llama-server --version` agree.
/// `cargo test -p pam_model --lib -- engine --ignored --nocapture`.
#[tokio::test]
#[ignore = "downloads the pinned llama.cpp release from GitHub"]
async fn the_pinned_release_installs_on_this_host() {
    let base = tempfile::tempdir().unwrap();
    let (_cancel, rx) = tokio::sync::watch::channel(false);
    let installed = install(base.path(), rx)
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
