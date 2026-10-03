use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_net::testing::{FakeProxy, ProxyMode, TEST_HOST, base64};
use pam_net::{MirrorBase, NetFailure, NetSettings, Proxy, ProxyAuth, ProxyPassword};
use sha2::{Digest, Sha256};

use crate::catalog::UPSTREAM_PREFIX;
use crate::download::{
    Checkpoint, DownloadError, DownloadHandle, DownloadProgress, DownloadRequest, DownloadState,
    ImportRequest, TransferLimits, curl_path, curl_recovery_line, discard_partial,
    failure_recovery, inspect_partial, sidecar_paths, start_import,
    start_over_plain_http_for_tests,
};
use crate::registry::verified_sidecar_path;
use crate::testing as origin;

/// A direct profile: no proxy, the platform's trust.
fn direct() -> Arc<NetSettings> {
    Arc::new(NetSettings::direct())
}

/// Every origin here is a plain-http loopback listener, so every transfer
/// goes through the test allowance; production `start` refuses `http://`
/// (`plain_http_is_refused_in_production`).
fn start(request: DownloadRequest) -> Result<DownloadHandle, DownloadError> {
    start_over_plain_http_for_tests(request, direct(), TransferLimits::default())
}

fn start_with_limits(
    request: DownloadRequest,
    limits: TransferLimits,
) -> Result<DownloadHandle, DownloadError> {
    start_over_plain_http_for_tests(request, direct(), limits)
}

/// A transfer under `net`: a proxied profile, in the tests that have one.
fn start_under(
    request: DownloadRequest,
    net: NetSettings,
) -> Result<DownloadHandle, DownloadError> {
    start_over_plain_http_for_tests(request, Arc::new(net), TransferLimits::default())
}

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
        vec!["Qwen3.gguf".to_owned()],
        "a finished download leaves the model, nothing else: the verification is the \
         caller's to record in its private store, never a file beside the weights"
    );
    assert!(!verified_sidecar_path(&fixture.dest).exists());
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
    assert_eq!(
        cause, "transfer_interrupted",
        "a dropped connection is named as one: {detail}"
    );
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
    assert!(
        server
            .requests()
            .iter()
            .any(|line| line.trim() == "If-Range: \"v1\""),
        "the resume must say which file its bytes belong to, saw {:?}",
        server.requests()
    );
}

#[tokio::test]
async fn a_changed_etag_restarts_the_transfer_from_zero() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "v1", 64 * 1024).await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let paths = sidecar_paths(&fixture.dest);

    let broken = settled(&start(request.clone()).unwrap()).await;
    assert!(matches!(broken, DownloadState::Failed { .. }), "{broken:?}");
    assert_eq!(std::fs::metadata(&paths.part).unwrap().len(), 64 * 1024);

    // The origin replaced the file. The same bytes under a new tag keep the
    // test honest: appending the old 64 KiB to the whole body would be a
    // size mismatch, and only a restart from zero can produce the digest.
    server.set_etag("v2");
    assert_eq!(
        settled(&start(request).unwrap()).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        },
        "the resume was refused and the transfer started over"
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), bytes);
    let requests = server.requests();
    let resumes = requests
        .iter()
        .filter(|line| line.trim() == "If-Range: \"v1\"")
        .count();
    assert_eq!(
        resumes, 1,
        "one resume was attempted with the old tag: {requests:?}"
    );
    let gets = requests
        .iter()
        .filter(|line| line.starts_with("GET "))
        .count();
    assert_eq!(
        gets, 3,
        "interrupted, refused resume, full restart: {requests:?}"
    );
    assert!(
        !requests
            .iter()
            .any(|line| line.trim() == "If-Range: \"v2\""),
        "the restart carries no range at all: {requests:?}"
    );
    assert!(!paths.part.exists());
    assert!(!paths.checkpoint.exists());
}

#[tokio::test]
async fn a_transfer_of_the_wrong_size_is_named_as_one() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(8 * 1024);
    let server = origin::serve(bytes.clone(), "v1").await;
    let mut request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    request.expected_size = Some(size_of(&bytes) + 1);

    let state = settled(&start(request).unwrap()).await;
    let DownloadState::Failed { cause, detail } = state else {
        panic!("a wrong size must fail, got {state:?}");
    };
    assert_eq!(cause, "size_mismatch");
    assert!(
        detail.contains("8192"),
        "the detail names the size: {detail}"
    );
    assert!(
        !fixture.dest.exists(),
        "nothing lands under the model's name"
    );
    assert!(
        sidecar_paths(&fixture.dest).part.exists(),
        "the bytes stay for a human to discard or inspect"
    );
}

#[tokio::test]
async fn a_file_that_appears_mid_transfer_is_never_overwritten() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(512 * 1024);
    let server =
        origin::serve_slowly(bytes.clone(), "v1", 64 * 1024, Duration::from_millis(100)).await;
    let handle = start(request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes)).unwrap();
    let paths = sidecar_paths(&fixture.dest);
    assert!(wait_for_path(&paths.part).await);

    // Someone drops weights under the same name while curl runs.
    std::fs::write(&fixture.dest, b"hand-copied weights").unwrap();

    let state = settled(&handle).await;
    let DownloadState::Failed { cause, detail } = state else {
        panic!("the finished transfer must not replace the file, got {state:?}");
    };
    assert_eq!(cause, "already_exists", "{detail}");
    assert_eq!(
        std::fs::read(&fixture.dest).unwrap(),
        b"hand-copied weights",
        "the file that was there first survives untouched"
    );
    assert!(
        paths.part.exists(),
        "the transferred bytes are kept, not lost"
    );
}

#[test]
fn a_url_that_is_not_https_is_refused_before_curl_runs() {
    let fixture = fixture();
    let request = |url: &str| DownloadRequest {
        url: url.to_owned(),
        dest: fixture.dest.clone(),
        expected_size: None,
        expected_sha256: None,
        license_id: None,
    };
    // Refused by the test allowance as well: never an option, a file, a
    // scheme curl would speak, user information, or a control character.
    for url in [
        "-K/tmp/x/a.gguf",
        "--config=/tmp/evil",
        "file:///etc/passwd",
        "ftp://example.invalid/x.gguf",
        "http://",
        "https:///nohost",
        "https://user:pw@example.com/x.gguf",
        "example.com/x.gguf",
        "http://example.com/x\n.gguf",
        "",
    ] {
        assert!(
            matches!(&start(request(url)), Err(DownloadError::InvalidUrl(bad)) if bad == url),
            "{url:?} must be refused as a URL"
        );
    }
    assert!(
        !sidecar_paths(&fixture.dest).lock.exists(),
        "nothing was set up"
    );
    for url in [
        "https://example.com/x.gguf",
        "HTTPS://127.0.0.1:1/x",
        "https://[::1]:1/x",
    ] {
        assert!(crate::download::check_url(url).is_ok(), "{url}");
    }
    for url in ["http://example.com/x.gguf", "HTTP://127.0.0.1:1/x"] {
        assert!(
            matches!(
                crate::download::check_url(url),
                Err(DownloadError::InvalidUrl(_))
            ),
            "{url} is plain http"
        );
    }
}

/// Production refuses a plain-`http` address outright, before curl, the
/// lock or a part file exist; the refusal names the address and says why.
#[tokio::test]
async fn plain_http_is_refused_in_production() {
    let fixture = fixture();
    let bytes = body(1024);
    let server = origin::serve(bytes.clone(), "v1").await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    assert!(request.url.starts_with("http://"));

    let refused = crate::download::start(request.clone(), direct());
    let Err(DownloadError::InvalidUrl(named)) = refused else {
        panic!("a plain-http address must be refused, got {refused:?}");
    };
    assert_eq!(named, request.url);
    let sentence = DownloadError::InvalidUrl(named).to_string();
    assert!(
        sentence.contains("only https addresses are downloaded"),
        "{sentence}"
    );
    assert!(server.requests().is_empty(), "curl never ran");
    assert!(!sidecar_paths(&fixture.dest).lock.exists());
    assert!(!sidecar_paths(&fixture.dest).part.exists());

    // The same request under the allowance is what the rest of this suite
    // runs on; the allowance admits only what the origin fixture needs.
    let refused = crate::download::start_with_limits(request, direct(), impatient());
    assert!(matches!(refused, Err(DownloadError::InvalidUrl(_))));
}

#[test]
fn the_curl_pam_runs_is_the_operating_systems_own() {
    let Ok(curl) = curl_path() else {
        eprintln!("skipping: no trusted curl ({})", curl_recovery_line());
        return;
    };
    assert!(curl.is_absolute(), "{curl:?}");
    assert!(curl.is_file(), "{curl:?}");
    #[cfg(target_os = "macos")]
    assert_eq!(curl, std::fs::canonicalize("/usr/bin/curl").unwrap());
    #[cfg(target_os = "windows")]
    assert!(
        curl.ends_with("System32\\curl.exe"),
        "{curl:?} is not the System32 binary"
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

/// Tight enough that a stalled transfer dies inside a test's patience:
/// anything under 1 MB/s for a second counts as stopped.
fn impatient() -> TransferLimits {
    TransferLimits {
        connect_timeout: Duration::from_secs(5),
        stall_window: Duration::from_secs(1),
        min_bytes_per_sec: 1_000_000,
    }
}

#[tokio::test]
async fn a_stalled_transfer_is_abandoned_and_stays_resumable() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(4 * 1024 * 1024);
    // ~13 KB/s: moving, but far under the floor the limits set.
    let server =
        origin::serve_slowly(bytes.clone(), "v1", 4 * 1024, Duration::from_millis(300)).await;

    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let handle = start_with_limits(request, impatient()).unwrap();

    let state = settled(&handle).await;
    let DownloadState::Failed { cause, detail } = state else {
        panic!("a transfer under the rate floor must be abandoned, got {state:?}");
    };
    assert_eq!(
        cause, "timeout",
        "a stall is named as one, not as a generic failure: {detail}"
    );
    assert_eq!(detail, NetFailure::Timeout.sentence());

    let paths = sidecar_paths(&fixture.dest);
    assert!(
        paths.part.exists(),
        "the bytes that did arrive are kept, so the retry resumes"
    );
    assert!(paths.checkpoint.exists());
    assert!(!fixture.dest.exists());
}

#[tokio::test]
async fn a_refused_connection_is_named_as_one() {
    require_curl!();
    let fixture = fixture();
    let request = request_for(
        "http://127.0.0.1:1/Qwen3.gguf".to_owned(),
        &fixture.dest,
        b"never sent",
    );

    let state = settled(&start_with_limits(request, impatient()).unwrap()).await;
    let DownloadState::Failed { cause, detail } = state else {
        panic!("a refused connection must fail the transfer, got {state:?}");
    };
    assert_eq!(cause, "connect_failed", "detail was {detail}");
    assert_eq!(
        detail,
        NetFailure::ConnectFailed {
            host: "127.0.0.1".to_owned()
        }
        .sentence()
    );
    assert_ne!(
        failure_recovery(&cause),
        failure_recovery("something new"),
        "the launcher's cause has a download recovery line"
    );
}

#[test]
fn every_cause_carries_its_own_recovery_sentence() {
    let fallback = failure_recovery("something new");
    // This module's own causes, then every cause the launcher can answer.
    let own = [
        "curl_missing",
        "io",
        "digest_mismatch",
        "size_mismatch",
        "checkpoint_conflict",
        "already_exists",
        "locked",
        "daemon_restart",
        "verify_failed",
        "lock_release_failed",
        "no_space",
        "model_changed",
    ];
    let host = || "h.example".to_owned();
    let proxy = || "proxy.example:3128".to_owned();
    let launcher = [
        NetFailure::CurlUnavailable,
        NetFailure::CurlTooOld {
            found: "7.0.0".to_owned(),
            needed: "7.63.0",
            feature: "a proxy",
        },
        NetFailure::SettingsInvalid("x".to_owned()),
        NetFailure::CaBundleTampered,
        NetFailure::RequestInvalid {
            field: "url",
            detail: "x".to_owned(),
        },
        NetFailure::Spawn("x".to_owned()),
        NetFailure::ProxyDnsFailed { proxy: proxy() },
        NetFailure::ProxyUnreachable { proxy: proxy() },
        NetFailure::ProxyAuthRequired {
            proxy: proxy(),
            offered: Vec::new(),
        },
        NetFailure::ProxyAuthRejected { proxy: proxy() },
        NetFailure::ProxyDenied {
            proxy: proxy(),
            target: host(),
            status: 403,
        },
        NetFailure::DnsFailed { host: host() },
        NetFailure::ConnectFailed { host: host() },
        NetFailure::ConnectTimeout { host: host() },
        NetFailure::TlsUntrustedIssuer {
            host: host(),
            issuer: None,
            backend: "LibreSSL".to_owned(),
        },
        NetFailure::TlsHostnameMismatch { host: host() },
        NetFailure::TlsExpired { host: host() },
        NetFailure::TlsRevocationUnavailable { host: host() },
        NetFailure::TlsFailed {
            host: host(),
            detail: "x".to_owned(),
        },
        NetFailure::CaBundleUnreadable,
        NetFailure::Timeout,
        NetFailure::Deadline,
        NetFailure::TooLarge { maximum: 1 },
        NetFailure::HttpStatus { status: Some(403) },
        NetFailure::WriteFailed,
        NetFailure::TransferInterrupted { exit: 18 },
        NetFailure::ResumeUnsupported,
        NetFailure::Other {
            exit: Some(1),
            detail: "x".to_owned(),
        },
    ];
    for cause in own
        .into_iter()
        .chain(launcher.iter().map(NetFailure::cause))
    {
        let line = failure_recovery(cause);
        assert_ne!(line, fallback, "{cause} deserves better than the fallback");
        assert!(!line.is_empty(), "{cause} has no recovery line");
    }
    assert_eq!(failure_recovery("curl_missing"), curl_recovery_line());
}

#[tokio::test]
async fn a_partial_can_be_inspected_and_thrown_away() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "v1", 64 * 1024).await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let paths = sidecar_paths(&fixture.dest);

    assert_eq!(
        inspect_partial(&fixture.dest),
        None,
        "nothing downloaded yet is not a partial"
    );

    settled(&start(request.clone()).unwrap()).await;
    let partial = inspect_partial(&fixture.dest).expect("the interrupted transfer left bytes");
    assert_eq!(partial.bytes, 64 * 1024);
    assert_eq!(partial.source.as_deref(), Some(request.url.as_str()));
    assert_eq!(
        partial.expected_digest.as_deref(),
        Some(format!("sha256:{}", sha256_of(&bytes)).as_str())
    );
    assert!(
        !partial.locked,
        "the transfer is over, nothing holds the lock"
    );

    assert_eq!(discard_partial(&fixture.dest).unwrap(), 64 * 1024);
    assert_eq!(inspect_partial(&fixture.dest), None);
    assert!(!paths.part.exists());
    assert!(!paths.checkpoint.exists());
    assert!(
        !paths.lock.exists(),
        "the lock is not state; discarding takes it with the rest"
    );
    assert_eq!(
        dir_entries(fixture.dest.parent().unwrap()),
        Vec::<String>::new(),
        "a discarded download leaves nothing behind"
    );
}

#[tokio::test]
async fn a_running_transfer_keeps_its_partial() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(512 * 1024);
    let server =
        origin::serve_slowly(bytes.clone(), "v1", 64 * 1024, Duration::from_millis(200)).await;
    let handle = start(request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes)).unwrap();
    let paths = sidecar_paths(&fixture.dest);
    assert!(wait_for_path(&paths.part).await);

    let refused = discard_partial(&fixture.dest);
    assert!(
        matches!(refused, Err(DownloadError::Locked(_))),
        "bytes are never deleted from under a running transfer, got {refused:?}"
    );
    assert!(
        inspect_partial(&fixture.dest).is_some_and(|partial| partial.locked),
        "a partial being written says so"
    );

    handle.cancel();
    settled(&handle).await;
    assert!(paths.part.exists(), "the refusal changed nothing");
    assert!(discard_partial(&fixture.dest).unwrap() > 0);
}

#[test]
fn releasing_the_lock_frees_it_even_while_a_duplicate_handle_is_alive() {
    let fixture = fixture();
    let paths = sidecar_paths(&fixture.dest);
    let owner = crate::download::acquire_lock(&paths.lock).unwrap();
    // The same open file description a forked child holds before its exec.
    let duplicate = owner.try_clone().unwrap();
    assert!(crate::download::is_locked(&paths.lock));

    crate::download::release_lock(owner);
    assert!(
        !crate::download::is_locked(&paths.lock),
        "an explicit unlock applies to the whole description, duplicate or not"
    );
    drop(duplicate);
    assert!(
        crate::download::acquire_lock(&paths.lock).is_ok(),
        "the next transfer takes the lock cleanly"
    );
}

#[tokio::test]
async fn a_checkpoint_conflict_leaves_the_lock_free() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(4 * 1024);
    let paths = sidecar_paths(&fixture.dest);
    std::fs::write(&paths.part, &bytes[..1024]).unwrap();
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
    let server = origin::serve(bytes.clone(), "v1").await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    assert!(matches!(
        start(request),
        Err(DownloadError::CheckpointConflict(_))
    ));
    assert!(
        !crate::download::is_locked(&paths.lock),
        "a refused start must not leave the transfer lock held"
    );
}

#[tokio::test]
async fn discarding_clears_a_checkpoint_conflict() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(4 * 1024);
    let paths = sidecar_paths(&fixture.dest);
    std::fs::write(&paths.part, &bytes[..1024]).unwrap();
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

    let server = origin::serve(bytes.clone(), "v1").await;
    let request = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    assert!(
        matches!(
            start(request.clone()),
            Err(DownloadError::CheckpointConflict(_))
        ),
        "the fixture must start from the conflict this test is about"
    );

    assert_eq!(discard_partial(&fixture.dest).unwrap(), 1024);
    assert_eq!(
        settled(&start(request).unwrap()).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        },
        "with the foreign bytes gone the download starts over cleanly"
    );
}

/// Checks the lock synchronously when the watch sender wakes a terminal waiter.
/// This catches publication-before-unlock without racing a second async task.
struct TerminalLockProbe {
    handle: DownloadHandle,
    lock: std::sync::Arc<std::fs::File>,
    observed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    locked: std::sync::Arc<std::sync::atomic::AtomicBool>,
    parent: std::task::Waker,
}

impl std::task::Wake for TerminalLockProbe {
    fn wake(self: std::sync::Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.handle.state().is_terminal() {
            self.observed.store(true, Ordering::SeqCst);
            match self.lock.try_lock() {
                Ok(()) => {
                    self.lock.unlock().unwrap();
                }
                Err(_) => {
                    self.locked.store(true, Ordering::SeqCst);
                }
            }
        }
        self.parent.wake_by_ref();
    }
}

#[tokio::test]
async fn terminal_notification_releases_the_transfer_lock_before_waking_observers() {
    use std::future::Future as _;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "terminal-lock", 64 * 1024).await;
    let handle = start(request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes)).unwrap();
    let lock = Arc::new(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(sidecar_paths(&fixture.dest).lock)
            .unwrap(),
    );
    let observed = Arc::new(AtomicBool::new(false));
    let locked = Arc::new(AtomicBool::new(false));
    let mut waiter = std::pin::pin!(handle.wait());
    let terminal = tokio::time::timeout(
        Duration::from_secs(10),
        std::future::poll_fn(|cx| {
            let probe = std::task::Waker::from(Arc::new(TerminalLockProbe {
                handle: handle.clone(),
                lock: lock.clone(),
                observed: observed.clone(),
                locked: locked.clone(),
                parent: cx.waker().clone(),
            }));
            waiter
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&probe))
        }),
    )
    .await
    .unwrap();
    assert!(matches!(terminal, DownloadState::Failed { .. }));
    assert!(
        observed.load(Ordering::SeqCst),
        "terminal publication woke the observer"
    );
    assert!(
        !locked.load(Ordering::SeqCst),
        "terminal publication must follow lock release"
    );
    drop(lock);
    assert_eq!(discard_partial(&fixture.dest).unwrap(), 64 * 1024);
}

#[test]
fn terminal_publication_unlocks_even_while_a_duplicate_handle_survives() {
    let fixture = fixture();
    let paths = sidecar_paths(&fixture.dest);
    let owner = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&paths.lock)
        .unwrap();
    owner.try_lock().unwrap();
    // File::try_clone shares the underlying file description, just as an
    // inherited descriptor does before exec. No unsafe fork/test hooks needed.
    let duplicate = owner.try_clone().unwrap();
    std::fs::write(&paths.part, b"partial").unwrap();
    let (sender, observer) =
        tokio::sync::watch::channel(DownloadState::Running(DownloadProgress {
            bytes: 7,
            total: None,
        }));
    crate::download::publish_terminal(&sender, owner, DownloadState::Cancelled);
    assert_eq!(*observer.borrow(), DownloadState::Cancelled);
    assert!(
        !inspect_partial(&fixture.dest).unwrap().locked,
        "terminal notification must relinquish ownership, even with duplicate handles"
    );
    drop(duplicate);
    assert_eq!(discard_partial(&fixture.dest).unwrap(), 7);
}

/// A profile with the fake proxy in it, with or without a credential.
fn through(proxy: &FakeProxy, auth: ProxyAuth, password: Option<&str>) -> NetSettings {
    let username = (auth != ProxyAuth::None).then_some("svc-pam");
    let proxy = Proxy::parse(&proxy.url(), auth, username).unwrap();
    let password = password.map(|value| ProxyPassword::new(value).unwrap());
    NetSettings::new(Some(proxy), password, Vec::new(), None).unwrap()
}

/// `http://origin.pam-test.invalid/<name>`: a name only the proxy reaches.
fn far(name: &str) -> String {
    format!("http://{TEST_HOST}/{name}")
}

#[tokio::test]
async fn a_proxied_transfer_resumes_through_the_proxy_and_lands() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "v1", 64 * 1024).await;
    let proxy = FakeProxy::start(ProxyMode::Allow, server_address(&server)).await;
    let request = request_for(far("Qwen3.gguf"), &fixture.dest, &bytes);
    let paths = sidecar_paths(&fixture.dest);

    let broken =
        settled(&start_under(request.clone(), through(&proxy, ProxyAuth::None, None)).unwrap())
            .await;
    assert!(
        matches!(&broken, DownloadState::Failed { cause, .. } if cause == "transfer_interrupted"),
        "{broken:?}"
    );
    assert_eq!(std::fs::metadata(&paths.part).unwrap().len(), 64 * 1024);

    assert_eq!(
        settled(&start_under(request, through(&proxy, ProxyAuth::None, None)).unwrap()).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        }
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), bytes);
    assert_eq!(
        proxy.request_lines(),
        vec![
            format!("CONNECT {TEST_HOST}:80 HTTP/1.1"),
            format!("CONNECT {TEST_HOST}:80 HTTP/1.1"),
        ],
        "both runs went through the proxy, as a CONNECT tunnel"
    );
    assert!(
        server
            .requests()
            .iter()
            .any(|line| line.trim() == "Range: bytes=65536-"),
        "the resume still asks for a range: {:?}",
        server.requests()
    );
    assert!(
        server
            .requests()
            .iter()
            .all(|line| !line.starts_with("Proxy-Authorization")),
        "nothing for the proxy reaches the origin"
    );
}

/// The proxy password the fake proxy is asked for, and must never echo.
const PROXY_PASSWORD: &str = "pr0xy \"secret\\ with:colon";

#[tokio::test]
async fn a_rejected_proxy_credential_fails_the_transfer_without_the_password() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(4 * 1024);
    let server = origin::serve(bytes.clone(), "v1").await;
    let proxy = FakeProxy::start(
        ProxyMode::RequireAuth {
            username: "svc-pam".to_owned(),
            password: "something else".to_owned(),
            offer: vec!["Basic realm=\"pam-test\"".to_owned()],
        },
        server_address(&server),
    )
    .await;
    let request = request_for(far("Qwen3.gguf"), &fixture.dest, &bytes);

    let state = settled(
        &start_under(
            request,
            through(&proxy, ProxyAuth::Basic, Some(PROXY_PASSWORD)),
        )
        .unwrap(),
    )
    .await;
    let DownloadState::Failed { cause, detail } = &state else {
        panic!("the proxy refused the credential, got {state:?}");
    };
    assert_eq!(cause, "proxy_auth_rejected");
    let encoded = base64(format!("svc-pam:{PROXY_PASSWORD}").as_bytes());
    for rendering in [
        detail.clone(),
        format!("{state:?}"),
        serde_json::to_string(&state).unwrap(),
        failure_recovery(cause).to_owned(),
    ] {
        assert!(!rendering.contains(PROXY_PASSWORD), "{rendering}");
        assert!(!rendering.contains(&encoded), "{rendering}");
        assert!(!rendering.contains("secret"), "{rendering}");
    }
    assert!(
        detail.contains(&proxy.address().to_string()),
        "the proxy is named: {detail}"
    );
    assert!(server.requests().is_empty(), "nothing reached the origin");
    assert!(
        !fixture.dest.exists(),
        "nothing lands under the model's name"
    );
}

/// A catalog address under the upstream prefix is fetched from the mirror,
/// same path, same digest; the local origin plays the mirror.
#[tokio::test]
async fn a_catalog_download_goes_to_the_mirror_under_the_same_path_and_digest() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(96 * 1024);
    let server = origin::serve(bytes.clone(), "v1").await;
    let mirror = MirrorBase::for_tests(&server.url("hf"));
    let upstream = format!("{UPSTREAM_PREFIX}org/model/resolve/main/Qwen3.gguf");

    let request = request_for(upstream.clone(), &fixture.dest, &bytes)
        .via_mirror(Some(&mirror), UPSTREAM_PREFIX);
    assert_eq!(
        request.url,
        server.url("hf/org/model/resolve/main/Qwen3.gguf"),
        "the prefix is replaced, the rest of the path is kept"
    );
    assert_eq!(request.expected_sha256, Some(sha256_of(&bytes)));

    assert_eq!(
        settled(&start(request).unwrap()).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes),
        }
    );
    assert!(
        server
            .requests()
            .iter()
            .any(|line| line.starts_with("GET /hf/org/model/resolve/main/Qwen3.gguf ")),
        "the mirror is asked for the catalog path: {:?}",
        server.requests()
    );

    // Not under the prefix: a pasted address is never rewritten.
    let pasted = request_for(
        "https://files.example/other.gguf".to_owned(),
        &fixture.dest,
        &bytes,
    )
    .via_mirror(Some(&mirror), UPSTREAM_PREFIX);
    assert_eq!(pasted.url, "https://files.example/other.gguf");
    let direct =
        request_for(upstream.clone(), &fixture.dest, &bytes).via_mirror(None, UPSTREAM_PREFIX);
    assert_eq!(direct.url, upstream);
}

/// The mirror serves the same bytes or nothing: a mirror that serves
/// something else is a digest mismatch, like a corrupted upstream transfer.
#[tokio::test]
async fn a_mirror_that_serves_other_bytes_is_a_digest_mismatch() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(8 * 1024);
    let server = origin::serve(body(8 * 1024 + 1), "v1").await;
    let mirror = MirrorBase::for_tests(&server.url(""));
    let request = request_for(
        format!("{UPSTREAM_PREFIX}org/model/resolve/main/Qwen3.gguf"),
        &fixture.dest,
        &bytes,
    )
    .via_mirror(Some(&mirror), UPSTREAM_PREFIX);
    let mut request = request;
    request.expected_size = None;

    let state = settled(&start(request).unwrap()).await;
    assert!(
        matches!(&state, DownloadState::Failed { cause, .. } if cause == "digest_mismatch"),
        "{state:?}"
    );
    assert!(!fixture.dest.exists());
    assert!(!sidecar_paths(&fixture.dest).part.exists());
}

/// The checkpoint records the effective address, so bytes fetched from
/// upstream are never glued onto a mirror transfer.
#[tokio::test]
async fn a_partial_from_upstream_conflicts_with_a_mirror_request() {
    require_curl!();
    let fixture = fixture();
    let bytes = body(256 * 1024);
    let server = origin::serve_interrupting(bytes.clone(), "v1", 64 * 1024).await;
    let upstream = request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes);
    let broken = settled(&start(upstream.clone()).unwrap()).await;
    assert!(matches!(broken, DownloadState::Failed { .. }), "{broken:?}");
    assert_eq!(
        inspect_partial(&fixture.dest).unwrap().source.as_deref(),
        Some(upstream.url.as_str())
    );

    let mirror = MirrorBase::for_tests(&server.url("mirror"));
    let mut via_mirror = upstream.clone();
    via_mirror.url = mirror.join("Qwen3.gguf").unwrap().into();
    let refused = start(via_mirror);
    assert!(
        matches!(refused, Err(DownloadError::CheckpointConflict(_))),
        "a mirror request over an upstream partial is a conflict, got {refused:?}"
    );
    assert_eq!(discard_partial(&fixture.dest).unwrap(), 64 * 1024);
}

/// The fixture's loopback address, as the fake proxy's upstream.
fn server_address(server: &origin::TestServer) -> std::net::SocketAddr {
    server
        .url("")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .parse()
        .unwrap()
}

// ---- importing weights from a file on this machine ----

/// A `.gguf` source outside the models directory, holding `bytes`.
fn import_source(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Qwen3.gguf");
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

fn import_request(source: &Path, dest: &Path, bytes: &[u8]) -> ImportRequest {
    ImportRequest {
        source: source.to_path_buf(),
        dest: dest.to_path_buf(),
        expected_size: Some(size_of(bytes)),
        expected_sha256: Some(sha256_of(bytes)),
    }
}

/// An import copies the file in through the same part file and link as a
/// download, reports the digest of the copy, leaves the source as it was
/// and no sidecar behind; a second import of the same file is refused.
#[tokio::test]
async fn an_import_copies_hashes_and_lands_without_touching_the_source() {
    let bytes = body(3 * 1024 * 1024 + 17);
    let (_src, source) = import_source(&bytes);
    let before = std::fs::metadata(&source).unwrap();
    let fixture = fixture();
    let handle = start_import(import_request(&source, &fixture.dest, &bytes)).unwrap();
    assert!(
        matches!(handle.state(), DownloadState::Running(DownloadProgress { bytes: 0, total: Some(t) }) if t == size_of(&bytes))
    );
    let state = settled(&handle).await;
    assert_eq!(
        state,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: size_of(&bytes)
        }
    );
    assert_eq!(std::fs::read(&fixture.dest).unwrap(), bytes);
    assert_eq!(dir_entries(fixture.dest.parent().unwrap()), ["Qwen3.gguf"]);
    let after = std::fs::metadata(&source).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(
        std::fs::read(&source).unwrap(),
        bytes,
        "the original is untouched"
    );
    let again = start_import(import_request(&source, &fixture.dest, &bytes));
    assert!(
        matches!(again, Err(DownloadError::AlreadyExists(_))),
        "{again:?}"
    );
}

/// The expected digest is the trust anchor: a file that hashes to anything
/// else is not imported, and no copy of it is left anywhere.
#[tokio::test]
async fn an_import_with_the_wrong_digest_removes_the_copy() {
    let bytes = body(70_000);
    let (_src, source) = import_source(&bytes);
    let fixture = fixture();
    let mut request = import_request(&source, &fixture.dest, &bytes);
    request.expected_sha256 = Some("f".repeat(64));
    let handle = start_import(request).unwrap();
    let state = settled(&handle).await;
    assert!(
        matches!(state, DownloadState::Failed { ref cause, .. } if cause == "digest_mismatch"),
        "{state:?}"
    );
    assert!(!fixture.dest.exists());
    assert!(
        dir_entries(fixture.dest.parent().unwrap()).is_empty(),
        "no part, no lock"
    );
    assert!(source.is_file(), "the original is untouched");
}

/// Without an expected digest the file is still copied and its digest
/// reported; the caller decides what that means (unverified).
#[tokio::test]
async fn an_import_without_a_digest_lands_and_reports_what_it_hashed_to() {
    let bytes = body(1000);
    let (_src, source) = import_source(&bytes);
    let fixture = fixture();
    let handle = start_import(ImportRequest {
        source: source.clone(),
        dest: fixture.dest.clone(),
        expected_size: None,
        expected_sha256: None,
    })
    .unwrap();
    assert_eq!(
        settled(&handle).await,
        DownloadState::Done {
            sha256: sha256_of(&bytes),
            size_bytes: 1000
        }
    );
    assert!(fixture.dest.is_file());
}

/// A wrong size is named before any digest is talked about.
#[tokio::test]
async fn an_import_of_the_wrong_size_is_named_as_one() {
    let bytes = body(500);
    let (_src, source) = import_source(&bytes);
    let fixture = fixture();
    let mut request = import_request(&source, &fixture.dest, &bytes);
    request.expected_size = Some(499);
    let state = settled(&start_import(request).unwrap()).await;
    assert!(
        matches!(state, DownloadState::Failed { ref cause, .. } if cause == "size_mismatch"),
        "{state:?}"
    );
    assert!(!fixture.dest.exists());
}

/// What is refused before a copy starts: a missing file, a symbolic link, a
/// directory, a file that is not a `.gguf`, a relative path, and a file
/// already inside the models directory.
#[cfg(unix)]
#[test]
fn an_import_source_that_breaks_a_rule_is_refused_by_name() {
    let bytes = body(10);
    let (src, source) = import_source(&bytes);
    let fixture = fixture();
    let request = |path: &Path| ImportRequest {
        source: path.to_path_buf(),
        dest: fixture.dest.clone(),
        expected_size: None,
        expected_sha256: None,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();

    let missing = start_import(request(&src.path().join("absent.gguf")));
    assert!(
        matches!(missing, Err(DownloadError::ImportSourceMissing(_))),
        "{missing:?}"
    );

    let link = src.path().join("link.gguf");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    let linked = start_import(request(&link));
    assert!(
        matches!(linked, Err(DownloadError::ImportSourceRefused { ref reason, .. }) if reason.contains("symbolic link")),
        "{linked:?}"
    );

    let dir = src.path().join("tree.gguf");
    std::fs::create_dir(&dir).unwrap();
    let directory = start_import(request(&dir));
    assert!(
        matches!(directory, Err(DownloadError::ImportSourceRefused { ref reason, .. }) if reason.contains("regular file")),
        "{directory:?}"
    );

    let text = src.path().join("notes.txt");
    std::fs::write(&text, b"x").unwrap();
    let not_gguf = start_import(request(&text));
    assert!(
        matches!(not_gguf, Err(DownloadError::ImportSourceRefused { ref reason, .. }) if reason.contains(".gguf")),
        "{not_gguf:?}"
    );

    let relative = start_import(request(Path::new("relative/Qwen3.gguf")));
    assert!(
        matches!(relative, Err(DownloadError::ImportSourceRefused { ref reason, .. }) if reason.contains("absolute")),
        "{relative:?}"
    );

    let inside = fixture.dest.parent().unwrap().join("Already.gguf");
    std::fs::write(&inside, b"x").unwrap();
    let in_models = start_import(request(&inside));
    assert!(
        matches!(in_models, Err(DownloadError::ImportSourceRefused { ref reason, .. }) if reason.contains("models directory")),
        "{in_models:?}"
    );
    assert!(!fixture.dest.exists());
    assert_eq!(
        dir_entries(fixture.dest.parent().unwrap()),
        ["Already.gguf"]
    );
}

/// A download holding the destination's lock, or a partial download beside
/// it, refuses the import: an import never writes under a transfer and
/// never glues onto downloaded bytes.
#[tokio::test]
async fn an_import_over_a_running_or_partial_download_is_refused() {
    require_curl!();
    let bytes = body(256 * 1024);
    let (_src, source) = import_source(&bytes);
    let fixture = fixture();
    let server = origin::serve_slowly(
        bytes.clone(),
        "\"etag\"",
        4 * 1024,
        Duration::from_millis(40),
    )
    .await;
    let download = start(request_for(server.url("Qwen3.gguf"), &fixture.dest, &bytes)).unwrap();
    let paths = sidecar_paths(&fixture.dest);
    assert!(wait_for_path(&paths.part).await);
    let locked = start_import(import_request(&source, &fixture.dest, &bytes));
    assert!(
        matches!(locked, Err(DownloadError::Locked(_))),
        "{locked:?}"
    );
    download.cancel();
    assert_eq!(settled(&download).await, DownloadState::Cancelled);
    assert!(paths.part.exists(), "the cancelled download keeps its part");
    let conflict = start_import(import_request(&source, &fixture.dest, &bytes));
    assert!(
        matches!(conflict, Err(DownloadError::CheckpointConflict(_))),
        "{conflict:?}"
    );
    assert!(paths.part.exists(), "the partial download is not touched");
    discard_partial(&fixture.dest).unwrap();
    let ok = start_import(import_request(&source, &fixture.dest, &bytes)).unwrap();
    assert!(matches!(settled(&ok).await, DownloadState::Done { .. }));
}

/// Cancelling an import deletes the partial copy: there is nothing to
/// resume, and a part file would read as a partial download.
#[tokio::test]
async fn cancelling_an_import_leaves_nothing_behind() {
    let bytes = body(64 * 1024 * 1024);
    let (_src, source) = import_source(&bytes);
    let fixture = fixture();
    let handle = start_import(import_request(&source, &fixture.dest, &bytes)).unwrap();
    handle.cancel();
    assert_eq!(settled(&handle).await, DownloadState::Cancelled);
    assert!(!fixture.dest.exists());
    assert!(
        dir_entries(fixture.dest.parent().unwrap()).is_empty(),
        "no part, no lock"
    );
    assert!(source.is_file());
}
