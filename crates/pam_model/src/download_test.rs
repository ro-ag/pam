use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::download::{
    Checkpoint, DownloadError, DownloadHandle, DownloadProgress, DownloadRequest, DownloadState,
    curl_path, curl_recovery_line, sidecar_paths, start,
};
use crate::download_server_test as origin;
use crate::registry::verified_sidecar_path;

/// Every CI runner ships curl, so this never skips there; a machine without
/// it should still get a green suite and a legible reason.
macro_rules! require_curl {
    () => {
        if curl_path().is_err() {
            eprintln!("skipping: no curl on PATH ({})", curl_recovery_line());
            return;
        }
    };
}

/// A models dir with an empty `qwen/` waiting for `Qwen3.gguf`.
struct Fixture {
    _dir: tempfile::TempDir,
    dest: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vendor = dir.path().join("qwen");
    std::fs::create_dir_all(&vendor).unwrap();
    Fixture {
        dest: vendor.join("Qwen3.gguf"),
        _dir: dir,
    }
}

/// Deterministic bytes, so a digest can be asserted without a fixture file.
fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

fn sha256_of(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn size_of(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn request_for(url: String, dest: &Path, bytes: &[u8]) -> DownloadRequest {
    DownloadRequest {
        url,
        dest: dest.to_path_buf(),
        expected_size: Some(size_of(bytes)),
        expected_sha256: Some(sha256_of(bytes)),
        license_id: Some("apache-2.0".to_owned()),
    }
}

/// Waits for a terminal state, refusing to hang the suite.
async fn settled(handle: &DownloadHandle) -> DownloadState {
    tokio::time::timeout(Duration::from_secs(45), handle.wait())
        .await
        .expect("the transfer should reach a terminal state")
}

/// Polls until `path` shows up, or gives up.
async fn wait_for_path(path: &Path) -> bool {
    for _ in 0..200 {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn sidecar_names_match_pam_old() {
    let paths = sidecar_paths(Path::new("/models/qwen/Qwen3.gguf"));
    assert_eq!(
        paths.part,
        PathBuf::from("/models/qwen/.Qwen3.gguf.pam-model.part")
    );
    assert_eq!(
        paths.checkpoint,
        PathBuf::from("/models/qwen/.Qwen3.gguf.pam-model.json")
    );
    assert_eq!(
        paths.lock,
        PathBuf::from("/models/qwen/.Qwen3.gguf.pam-model.lock")
    );
}

#[test]
fn state_serializes_with_an_internal_tag() {
    let running = serde_json::to_value(DownloadState::Running(DownloadProgress {
        bytes: 12,
        total: Some(40),
    }))
    .unwrap();
    assert_eq!(running["state"], "running");
    assert_eq!(running["bytes"], 12);
    assert_eq!(running["total"], 40);

    let done = serde_json::to_value(DownloadState::Done {
        sha256: "abc".to_owned(),
        size_bytes: 40,
    })
    .unwrap();
    assert_eq!(done["state"], "done");
    assert_eq!(done["sha256"], "abc");

    let failed = serde_json::to_value(DownloadState::Failed {
        cause: "digest_mismatch".to_owned(),
        detail: "no".to_owned(),
    })
    .unwrap();
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["cause"], "digest_mismatch");

    let cancelled = serde_json::to_value(DownloadState::Cancelled).unwrap();
    assert_eq!(cancelled["state"], "cancelled");
}

#[tokio::test]
async fn a_whole_transfer_lands_and_clears_its_sidecars() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(96 * 1024);
    let server = origin::serve(bytes.clone(), "v1").await;

    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let handle = start(request).unwrap();

    assert_eq!(
        settled(&handle).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        }
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), bytes);

    let vendor = fixture.dest.parent().unwrap();
    assert_eq!(
        dir_entries(vendor),
        vec![
            ".Qwen3.gguf.pam-model.verified".to_owned(),
            "Qwen3.gguf".to_owned()
        ],
        "a finished download leaves the model and its verification, nothing else"
    );
    assert!(verified_sidecar_path(&fixture.dest).exists());
}

#[tokio::test]
async fn an_interrupted_transfer_resumes_from_its_part() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "v1", 64 * 1024).await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let paths = sidecar_paths(&fixture.dest);

    let broken = settled(&start(request.clone()).unwrap()).await;
    let DownloadState::Failed { cause, detail } = broken else {
        panic!("a dropped connection should fail the transfer, got {broken:?}");
    };
    assert_eq!(cause, "download_failed");
    assert!(!detail.is_empty(), "curl's complaint should survive");
    assert_eq!(
        std::fs::metadata(&paths.part).unwrap().len(),
        64 * 1024,
        "the received bytes are kept for the resume"
    );
    assert!(paths.checkpoint.exists());
    let checkpoint: Checkpoint =
        serde_json::from_slice(&std::fs::read(&paths.checkpoint).unwrap()).unwrap();
    assert_eq!(checkpoint.schema_version, 1);
    assert_eq!(checkpoint.canonical_source, request.url);
    assert_eq!(
        checkpoint.expected_digest,
        format!("sha256:{}", sha256_of(&bytes))
    );
    assert_eq!(checkpoint.expected_size_bytes, size_of(&bytes));
    assert_eq!(checkpoint.etag.as_deref(), Some("\"v1\""));

    assert_eq!(
        settled(&start(request).unwrap()).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        }
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), bytes);
    assert!(
        server
            .requests()
            .iter()
            .any(|line| line.trim() == "Range: bytes=65536-"),
        "the resume must ask for the bytes it is missing, saw {:?}",
        server.requests()
    );
}

#[tokio::test]
async fn a_wrong_digest_removes_the_part() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(32 * 1024);
    let server = origin::serve(bytes.clone(), "v1").await;

    let mut request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    request.expected_sha256 = Some(sha256_of(b"something else entirely"));

    let state = settled(&start(request).unwrap()).await;
    let DownloadState::Failed { cause, detail } = state else {
        panic!("a wrong digest must fail, got {state:?}");
    };
    assert_eq!(cause, "digest_mismatch");
    assert!(
        detail.contains(&sha256_of(&bytes)),
        "detail names both digests"
    );

    let paths = sidecar_paths(&fixture.dest);
    assert!(!paths.part.exists(), "known-wrong bytes are not kept");
    assert!(!fixture.dest.exists());
}

#[tokio::test]
async fn cancelling_keeps_the_part() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(512 * 1024);
    let server =
        origin::serve_slowly(bytes.clone(), "v1", 64 * 1024, Duration::from_millis(200)).await;

    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let handle = start(request).unwrap();
    let paths = sidecar_paths(&fixture.dest);
    assert!(
        wait_for_path(&paths.part).await,
        "the transfer should start writing before it is cancelled"
    );

    handle.cancel();
    assert_eq!(settled(&handle).await, DownloadState::Cancelled);
    assert!(paths.part.exists(), "a cancelled transfer stays resumable");
    assert!(paths.checkpoint.exists());
    assert!(!fixture.dest.exists());
}

#[tokio::test]
async fn a_second_download_of_the_same_file_is_locked() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(512 * 1024);
    let server =
        origin::serve_slowly(bytes.clone(), "v1", 64 * 1024, Duration::from_millis(200)).await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);

    let first = start(request.clone()).unwrap();
    let second = start(request);
    assert!(
        matches!(second, Err(DownloadError::Locked(_))),
        "a concurrent download of the same file is refused, got {second:?}"
    );

    first.cancel();
    settled(&first).await;
}

#[tokio::test]
async fn a_checkpoint_from_another_source_is_refused() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(1024);
    let paths = sidecar_paths(&fixture.dest);
    std::fs::write(
        &paths.checkpoint,
        serde_json::to_vec(&Checkpoint {
            schema_version: 1,
            canonical_source: "http://127.0.0.1:1/somewhere-else.gguf".to_owned(),
            expected_digest: format!("sha256:{}", sha256_of(&bytes)),
            expected_size_bytes: size_of(&bytes),
            license_digest: String::new(),
            etag: None,
        })
        .unwrap(),
    )
    .unwrap();

    let request = request_for(
        "http://127.0.0.1:1/Qwen3.gguf".to_owned(),
        &fixture.dest,
        &bytes,
    );
    let refused = start(request);
    assert!(
        matches!(refused, Err(DownloadError::CheckpointConflict(_))),
        "a part file of unknown provenance is never appended to, got {refused:?}"
    );
}

#[tokio::test]
async fn an_existing_destination_is_refused() {
    require_curl!();
    let fixture = fixture();
    std::fs::write(&fixture.dest, b"already here").unwrap();

    let request = request_for(
        "http://127.0.0.1:1/Qwen3.gguf".to_owned(),
        &fixture.dest,
        b"whatever",
    );
    let refused = start(request);
    assert!(
        matches!(refused, Err(DownloadError::AlreadyExists(_))),
        "pam never overwrites weights, got {refused:?}"
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), b"already here");
}
