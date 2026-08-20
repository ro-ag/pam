use std::{
    collections::VecDeque,
    fs,
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use pam_core::ContentDigest;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;
use uuid::Uuid;

use super::{
    DownloadRequest, DownloadResponse, DownloadTransport, ImportRequest, LicenseConsent,
    LicenseSnapshot, ModelDescriptor, ModelError, ModelKey, ModelSource, TransferRequest,
    download_https, import_existing, revalidate_registered_model,
};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pam-model-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct Fixture {
    bytes: Vec<u8>,
    descriptor: ModelDescriptor,
    consent: LicenseConsent,
}

impl Fixture {
    fn new() -> Self {
        let bytes = one_tensor_gguf(0, 1, 4);
        Self::from_bytes(bytes)
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let digest = ContentDigest::from_sha256(Sha256::digest(&bytes).into());
        let license = LicenseSnapshot::new(
            "Apache-2.0",
            "https://example.test/license",
            ContentDigest::from_sha256([9; 32]),
        )
        .unwrap();
        let descriptor = ModelDescriptor::new(
            ModelKey::new("vendor", "model").unwrap(),
            "model.gguf",
            digest,
            u64::try_from(bytes.len()).unwrap(),
            license,
        )
        .unwrap();
        let consent = LicenseConsent::accept(&descriptor);
        Self {
            bytes,
            descriptor,
            consent,
        }
    }
}

fn one_tensor_gguf(tensor_type: u32, first_dimension: u64, payload_bytes: usize) -> Vec<u8> {
    let mut bytes = b"GGUF".to_vec();
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&6_u64.to_le_bytes());
    bytes.extend_from_slice(b"weight");
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&first_dimension.to_le_bytes());
    bytes.extend_from_slice(&tensor_type.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    while !bytes.len().is_multiple_of(32) {
        bytes.push(0);
    }
    bytes.resize(bytes.len() + payload_bytes, 0);
    bytes
}

#[test]
fn import_hashes_validates_and_registers_the_existing_file_in_place() {
    let directory = TestDirectory::new("import");
    let fixture = Fixture::new();
    let path = directory.0.join("model.gguf");
    fs::write(&path, &fixture.bytes).unwrap();
    let canonical = path.canonicalize().unwrap();

    let record = import_existing(ImportRequest {
        descriptor: fixture.descriptor.clone(),
        consent: fixture.consent,
        path: path.clone(),
        registered_at_ms: 42,
    })
    .unwrap();

    assert_eq!(record.path, canonical);
    assert_eq!(record.source, ModelSource::Local);
    assert_eq!(record.gguf.version, 3);
    assert_eq!(record.gguf.tensor_count, 1);
    assert_eq!(record.gguf.metadata_kv_count, 0);
    assert_eq!(record.registered_at_ms, 42);
    assert_eq!(fs::read(path).unwrap(), fixture.bytes);
}

#[test]
fn registered_model_revalidation_hashes_the_current_exact_gguf() {
    let directory = TestDirectory::new("revalidate");
    let fixture = Fixture::new();
    let path = directory.0.join("model.gguf");
    fs::write(&path, &fixture.bytes).unwrap();
    let record = import_existing(ImportRequest {
        descriptor: fixture.descriptor,
        consent: fixture.consent,
        path: path.clone(),
        registered_at_ms: 42,
    })
    .unwrap();

    revalidate_registered_model(&record).unwrap();
    let mut changed = fixture.bytes;
    *changed.last_mut().unwrap() = 1;
    fs::write(path, changed).unwrap();
    assert!(matches!(
        revalidate_registered_model(&record),
        Err(ModelError::DigestMismatch)
    ));
}

#[test]
fn import_checks_consent_before_touching_the_selected_path() {
    let directory = TestDirectory::new("consent-first");
    let fixture = Fixture::new();
    let other_license = LicenseSnapshot::new(
        "Other",
        "https://example.test/other",
        ContentDigest::from_sha256([1; 32]),
    )
    .unwrap();
    let other_descriptor = ModelDescriptor::new(
        fixture.descriptor.key.clone(),
        fixture.descriptor.filename.clone(),
        fixture.descriptor.expected_digest.clone(),
        fixture.descriptor.expected_size_bytes,
        other_license,
    )
    .unwrap();
    let error = import_existing(ImportRequest {
        descriptor: fixture.descriptor,
        consent: LicenseConsent::accept(&other_descriptor),
        path: directory.0.join("missing.gguf"),
        registered_at_ms: 1,
    })
    .unwrap_err();
    assert!(matches!(error, ModelError::LicenseNotAccepted));
}

#[test]
fn import_rejects_digest_mismatch() {
    let directory = TestDirectory::new("digest-mismatch");
    let mut fixture = Fixture::new();
    fixture.descriptor.expected_digest = ContentDigest::from_sha256([0; 32]);
    fixture.consent = LicenseConsent::accept(&fixture.descriptor);
    let path = directory.0.join("model.gguf");
    fs::write(&path, &fixture.bytes).unwrap();
    assert!(matches!(
        import_existing(ImportRequest {
            descriptor: fixture.descriptor,
            consent: fixture.consent,
            path,
            registered_at_ms: 1,
        }),
        Err(ModelError::DigestMismatch)
    ));
}

#[test]
#[ignore = "requires PAM_TEST_GGUF_PATH and PAM_TEST_GGUF_SHA256"]
fn external_gguf_passes_structural_and_integrity_validation() {
    let path = PathBuf::from(
        std::env::var_os("PAM_TEST_GGUF_PATH").expect("PAM_TEST_GGUF_PATH must be set"),
    );
    let digest = ContentDigest::parse(
        std::env::var("PAM_TEST_GGUF_SHA256").expect("PAM_TEST_GGUF_SHA256 must be set"),
    )
    .unwrap();
    let size_bytes = fs::metadata(&path).unwrap().len();
    let descriptor = ModelDescriptor::new(
        ModelKey::new("external", "validation").unwrap(),
        path.file_name().unwrap().to_string_lossy(),
        digest.clone(),
        size_bytes,
        LicenseSnapshot::new(
            "external-validation",
            "https://example.test/external-validation-license",
            ContentDigest::from_sha256([7; 32]),
        )
        .unwrap(),
    )
    .unwrap();

    let record = import_existing(ImportRequest {
        consent: LicenseConsent::accept(&descriptor),
        descriptor,
        path: path.clone(),
        registered_at_ms: 0,
    })
    .unwrap();

    assert_eq!(record.path, path.canonicalize().unwrap());
    assert_eq!(record.digest, digest);
    assert!(record.gguf.tensor_count > 0);
}

struct FakeTransport {
    responses: Mutex<VecDeque<FakeResponse>>,
    requests: Mutex<Vec<TransferRequest>>,
}

impl FakeTransport {
    fn new(responses: Vec<FakeResponse>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl DownloadTransport for FakeTransport {
    type Response = FakeResponse;

    fn send(
        &self,
        request: TransferRequest,
    ) -> impl Future<Output = Result<Self::Response, ModelError>> + Send {
        self.requests.lock().unwrap().push(request);
        let response = self.responses.lock().unwrap().pop_front().unwrap();
        std::future::ready(Ok(response))
    }
}

struct HoldingTransport {
    entered: Notify,
    release: Notify,
    response: Mutex<Option<FakeResponse>>,
}

impl HoldingTransport {
    fn new(response: FakeResponse) -> Self {
        Self {
            entered: Notify::new(),
            release: Notify::new(),
            response: Mutex::new(Some(response)),
        }
    }
}

impl DownloadTransport for HoldingTransport {
    type Response = FakeResponse;

    async fn send(&self, _request: TransferRequest) -> Result<Self::Response, ModelError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(self.response.lock().unwrap().take().unwrap())
    }
}

struct FakeResponse {
    status: u16,
    content_length: Option<String>,
    content_range: Option<String>,
    content_encoding: Option<String>,
    etag: Option<String>,
    location: Option<String>,
    chunks: VecDeque<Vec<u8>>,
    fail_after_chunks: bool,
    failure_returned: bool,
}

impl FakeResponse {
    fn full(bytes: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_length: Some(bytes.len().to_string()),
            content_range: None,
            content_encoding: None,
            etag: Some("\"stable\"".to_owned()),
            location: None,
            chunks: VecDeque::from([bytes]),
            fail_after_chunks: false,
            failure_returned: false,
        }
    }
}

impl DownloadResponse for FakeResponse {
    fn status(&self) -> u16 {
        self.status
    }

    fn content_length(&self) -> Option<&str> {
        self.content_length.as_deref()
    }

    fn content_range(&self) -> Option<&str> {
        self.content_range.as_deref()
    }

    fn content_encoding(&self) -> Option<&str> {
        self.content_encoding.as_deref()
    }

    fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    fn next_chunk(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, ModelError>> + Send {
        let result = if let Some(chunk) = self.chunks.pop_front() {
            Ok(Some(chunk))
        } else if self.fail_after_chunks && !self.failure_returned {
            self.failure_returned = true;
            Err(ModelError::Network)
        } else {
            Ok(None)
        };
        std::future::ready(result)
    }
}

fn download_request(directory: &Path, fixture: &Fixture) -> DownloadRequest {
    DownloadRequest {
        descriptor: fixture.descriptor.clone(),
        consent: fixture.consent.clone(),
        source: "https://models.example/model.gguf".to_owned(),
        allowed_redirect_hosts: vec!["cdn.example".to_owned()],
        destination: directory.join("model.gguf"),
        registered_at_ms: 77,
    }
}

#[tokio::test]
async fn download_publishes_only_the_verified_exact_file() {
    let directory = TestDirectory::new("download");
    let fixture = Fixture::new();
    let transport = FakeTransport::new(vec![FakeResponse::full(fixture.bytes.clone())]);
    let request = download_request(&directory.0, &fixture);
    let destination = request.destination.clone();

    let record = download_https(&transport, request).await.unwrap();

    assert_eq!(record.path, destination);
    assert_eq!(record.registered_at_ms, 77);
    assert_eq!(fs::read(&record.path).unwrap(), fixture.bytes);
    assert!(matches!(record.source, ModelSource::Https { .. }));
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
    assert_eq!(
        directory_entries(&directory.0),
        vec![".model.gguf.pam-model.lock", "model.gguf"]
    );
}

#[tokio::test]
async fn download_checks_exact_consent_before_creating_directories() {
    let directory = TestDirectory::new("download-consent-first");
    let fixture = Fixture::new();
    let transport = FakeTransport::new(Vec::new());
    let mut request = download_request(&directory.0.join("not-created"), &fixture);
    request.descriptor.expected_digest = ContentDigest::from_sha256([7; 32]);

    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::LicenseNotAccepted)
    ));
    assert!(!directory.0.join("not-created").exists());
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn interrupted_download_resumes_only_at_the_contiguous_offset() {
    let directory = TestDirectory::new("resume");
    let fixture = Fixture::new();
    let split = 12;
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..split].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let second_bytes = fixture.bytes[split..].to_vec();
    let second = FakeResponse {
        status: 206,
        content_length: Some(second_bytes.len().to_string()),
        content_range: Some(format!(
            "bytes {split}-{}/{}",
            fixture.bytes.len() - 1,
            fixture.bytes.len()
        )),
        chunks: VecDeque::from([second_bytes]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first, second]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));
    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[0].range_start(), 0);
    assert_eq!(requests[1].range_start(), u64::try_from(split).unwrap());
    assert_eq!(requests[1].if_range(), Some("\"stable\""));
}

#[tokio::test]
async fn exact_size_partial_is_verified_without_another_http_request() {
    let directory = TestDirectory::new("exact-partial");
    let fixture = Fixture::new();
    let interrupted = FakeResponse {
        fail_after_chunks: true,
        ..FakeResponse::full(fixture.bytes.clone())
    };
    let transport = FakeTransport::new(vec![interrupted]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::Network)
    ));
    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    assert_eq!(transport.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn checkpoint_with_a_missing_partial_restarts_from_zero() {
    let directory = TestDirectory::new("missing-partial");
    let fixture = Fixture::new();
    let split = 12;
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..split].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first, FakeResponse::full(fixture.bytes.clone())]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));
    fs::remove_file(directory.0.join(".model.gguf.pam-model.part")).unwrap();
    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[0].range_start(), 0);
    assert_eq!(requests[1].range_start(), 0);
    assert_eq!(requests[1].if_range(), None);
}

#[tokio::test]
async fn changed_resume_validator_discards_the_partial_and_restarts() {
    let directory = TestDirectory::new("validator-change");
    let fixture = Fixture::new();
    let split = 12;
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..split].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let remaining = fixture.bytes[split..].to_vec();
    let changed = FakeResponse {
        status: 206,
        content_length: Some(remaining.len().to_string()),
        content_range: Some(format!(
            "bytes {split}-{}/{}",
            fixture.bytes.len() - 1,
            fixture.bytes.len()
        )),
        etag: Some("\"changed\"".to_owned()),
        chunks: VecDeque::from([remaining]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![
        first,
        changed,
        FakeResponse::full(fixture.bytes.clone()),
    ]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));
    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[1].range_start(), u64::try_from(split).unwrap());
    assert_eq!(requests[1].if_range(), Some("\"stable\""));
    assert_eq!(requests[2].range_start(), 0);
    assert_eq!(requests[2].if_range(), None);
}

#[tokio::test]
async fn an_unquoted_etag_is_never_used_for_resume() {
    let directory = TestDirectory::new("weak-validator");
    let fixture = Fixture::new();
    let first = FakeResponse {
        content_length: None,
        etag: Some("unquoted".to_owned()),
        chunks: VecDeque::from([fixture.bytes[..12].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first, FakeResponse::full(fixture.bytes.clone())]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));
    download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[1].range_start(), 0);
    assert_eq!(requests[1].if_range(), None);
}

#[tokio::test]
async fn range_ignored_response_restarts_without_appending() {
    let directory = TestDirectory::new("range-restart");
    let fixture = Fixture::new();
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..10].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first, FakeResponse::full(fixture.bytes.clone())]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));
    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests[1].range_start(), 10);
}

#[tokio::test]
async fn forbidden_redirect_never_creates_a_final_model() {
    let directory = TestDirectory::new("redirect");
    let fixture = Fixture::new();
    let redirect = FakeResponse {
        status: 302,
        location: Some("https://untrusted.example/model.gguf?token=secret".to_owned()),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![redirect]);
    let request = download_request(&directory.0, &fixture);
    let destination = request.destination.clone();
    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::RedirectNotAllowed)
    ));
    assert!(!destination.exists());
}

#[tokio::test]
async fn oversized_durable_source_is_rejected_before_transport_or_path_effects() {
    let directory = TestDirectory::new("oversized-source");
    let fixture = Fixture::new();
    let mut request = download_request(&directory.0, &fixture);
    request.source = format!("https://models.example/{}", "a".repeat(4096));
    let destination = request.destination.clone();
    let transport = FakeTransport::new(Vec::new());

    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::InvalidSource)
    ));
    assert!(transport.requests.lock().unwrap().is_empty());
    assert!(!destination.exists());
    assert!(directory_entries(&directory.0).is_empty());
}

#[tokio::test]
async fn private_literal_ip_and_non_https_port_are_rejected_before_transport() {
    let directory = TestDirectory::new("unsafe-source");
    let fixture = Fixture::new();
    let transport = FakeTransport::new(Vec::new());
    for source in [
        "https://127.0.0.1/model.gguf",
        "https://169.254.169.254/model.gguf",
        "https://[::1]/model.gguf",
        "https://models.example:444/model.gguf",
    ] {
        let mut request = download_request(&directory.0, &fixture);
        request.source = source.to_owned();
        assert!(matches!(
            download_https(&transport, request).await,
            Err(ModelError::InsecureSource)
        ));
    }
    assert!(transport.requests.lock().unwrap().is_empty());
    assert!(directory_entries(&directory.0).is_empty());
}

#[tokio::test]
async fn a_public_literal_ip_on_port_443_is_permitted() {
    let directory = TestDirectory::new("public-literal");
    let fixture = Fixture::new();
    let transport = FakeTransport::new(vec![FakeResponse::full(fixture.bytes.clone())]);
    let mut request = download_request(&directory.0, &fixture);
    request.source = "https://8.8.8.8/model.gguf".to_owned();

    let record = download_https(&transport, request).await.unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
}

#[tokio::test]
async fn private_literal_redirect_is_rejected() {
    let directory = TestDirectory::new("private-redirect");
    let fixture = Fixture::new();
    let redirect = FakeResponse {
        status: 302,
        location: Some("https://127.0.0.1/model.gguf".to_owned()),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![redirect]);
    let mut request = download_request(&directory.0, &fixture);
    request.allowed_redirect_hosts.push("127.0.0.1".to_owned());

    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::RedirectNotAllowed)
    ));
    assert!(!directory.0.join("model.gguf").exists());
}

#[tokio::test]
async fn a_preexisting_lock_file_does_not_block_a_new_acquisition() {
    let directory = TestDirectory::new("stale-lock");
    let fixture = Fixture::new();
    fs::write(
        directory.0.join(".model.gguf.pam-model.lock"),
        b"stale owner",
    )
    .unwrap();
    let transport = FakeTransport::new(vec![FakeResponse::full(fixture.bytes.clone())]);

    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    assert!(directory.0.join(".model.gguf.pam-model.lock").exists());
}

#[tokio::test]
async fn a_hard_linked_lock_file_is_rejected_without_truncating_its_peer() {
    let directory = TestDirectory::new("hard-linked-lock");
    let fixture = Fixture::new();
    let peer = directory.0.join("lock-peer");
    let lock = directory.0.join(".model.gguf.pam-model.lock");
    fs::write(&peer, b"unrelated owner").unwrap();
    fs::hard_link(&peer, &lock).unwrap();
    let transport = FakeTransport::new(vec![FakeResponse::full(fixture.bytes.clone())]);

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::UnsafePath)
    ));
    assert_eq!(fs::read(peer).unwrap(), b"unrelated owner");
    assert!(!directory.0.join("model.gguf").exists());
}

#[tokio::test]
async fn advisory_lock_rejects_a_concurrent_acquisition_and_can_be_reused() {
    let directory = TestDirectory::new("concurrent-lock");
    let fixture = Fixture::new();
    let transport = Arc::new(HoldingTransport::new(FakeResponse::full(
        fixture.bytes.clone(),
    )));
    let first = tokio::spawn({
        let transport = Arc::clone(&transport);
        let request = download_request(&directory.0, &fixture);
        async move { download_https(transport.as_ref(), request).await }
    });
    transport.entered.notified().await;

    let contender = FakeTransport::new(Vec::new());
    assert!(matches!(
        download_https(&contender, download_request(&directory.0, &fixture)).await,
        Err(ModelError::ConcurrentAcquisition)
    ));

    transport.release.notify_one();
    first.await.unwrap().unwrap();
    download_https(&contender, download_request(&directory.0, &fixture))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_existing_verified_destination_is_reconciled_idempotently() {
    let directory = TestDirectory::new("reconcile");
    let fixture = Fixture::new();
    fs::write(directory.0.join("model.gguf"), &fixture.bytes).unwrap();
    let transport = FakeTransport::new(Vec::new());

    let record = download_https(&transport, download_request(&directory.0, &fixture))
        .await
        .unwrap();

    assert_eq!(fs::read(record.path).unwrap(), fixture.bytes);
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn existing_destination_is_never_replaced() {
    let directory = TestDirectory::new("no-replace");
    let fixture = Fixture::new();
    let request = download_request(&directory.0, &fixture);
    fs::write(&request.destination, b"existing").unwrap();
    let transport = FakeTransport::new(Vec::new());
    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::ExistingDestination)
    ));
    assert_eq!(
        fs::read(directory.0.join("model.gguf")).unwrap(),
        b"existing"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_destination_parent_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("symlink-parent");
    let outside = directory.0.join("outside");
    let redirected = directory.0.join("redirected");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, &redirected).unwrap();
    let fixture = Fixture::new();
    let mut request = download_request(&directory.0, &fixture);
    request.destination = redirected.join("new/model.gguf");
    let transport = FakeTransport::new(vec![FakeResponse::full(fixture.bytes)]);

    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::UnsafePath)
    ));
    assert!(!outside.join("new").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_partial_is_rejected_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("symlink-partial");
    let fixture = Fixture::new();
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..12].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first]);
    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::TransferInterrupted)
    ));

    let partial = directory.0.join(".model.gguf.pam-model.part");
    let outside = directory.0.join("outside.bin");
    fs::write(&outside, b"do not modify").unwrap();
    fs::remove_file(&partial).unwrap();
    symlink(&outside, &partial).unwrap();

    assert!(matches!(
        download_https(&transport, download_request(&directory.0, &fixture)).await,
        Err(ModelError::UnsafePath)
    ));
    assert_eq!(fs::read(outside).unwrap(), b"do not modify");
}

#[cfg(unix)]
#[tokio::test]
async fn acquisition_creates_private_directories_and_files() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TestDirectory::new("private-modes");
    let fixture = Fixture::new();
    let nested = directory.0.join("private/nested");
    let first = FakeResponse {
        content_length: None,
        chunks: VecDeque::from([fixture.bytes[..12].to_vec()]),
        ..FakeResponse::full(Vec::new())
    };
    let transport = FakeTransport::new(vec![first]);
    let request = download_request(&nested, &fixture);

    assert!(matches!(
        download_https(&transport, request).await,
        Err(ModelError::TransferInterrupted)
    ));
    for path in [directory.0.join("private"), nested.clone()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for name in [
        ".model.gguf.pam-model.lock",
        ".model.gguf.pam-model.json",
        ".model.gguf.pam-model.part",
    ] {
        assert_eq!(
            fs::metadata(nested.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn import_rejects_empty_or_truncated_tensor_data() {
    let directory = TestDirectory::new("invalid-spans");
    let mut empty = b"GGUF".to_vec();
    empty.extend_from_slice(&3_u32.to_le_bytes());
    empty.extend_from_slice(&0_u64.to_le_bytes());
    empty.extend_from_slice(&0_u64.to_le_bytes());
    for (name, bytes) in [
        ("empty.gguf", empty),
        ("truncated.gguf", one_tensor_gguf(0, 1, 3)),
        ("unsupported.gguf", one_tensor_gguf(4, 32, 18)),
        ("partial-block.gguf", one_tensor_gguf(2, 31, 18)),
    ] {
        let fixture = Fixture::from_bytes(bytes);
        let path = directory.0.join(name);
        fs::write(&path, &fixture.bytes).unwrap();
        assert!(matches!(
            import_existing(ImportRequest {
                descriptor: fixture.descriptor,
                consent: fixture.consent,
                path,
                registered_at_ms: 1,
            }),
            Err(ModelError::InvalidGguf)
        ));
    }
}

#[cfg(unix)]
#[test]
fn import_rejects_a_symlinked_parent_component() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("import-symlink-parent");
    let outside = directory.0.join("outside");
    let redirected = directory.0.join("redirected");
    fs::create_dir(&outside).unwrap();
    let fixture = Fixture::new();
    fs::write(outside.join("model.gguf"), &fixture.bytes).unwrap();
    symlink(&outside, &redirected).unwrap();

    assert!(matches!(
        import_existing(ImportRequest {
            descriptor: fixture.descriptor,
            consent: fixture.consent,
            path: redirected.join("model.gguf"),
            registered_at_ms: 1,
        }),
        Err(ModelError::UnsafePath)
    ));
}

fn directory_entries(path: &Path) -> Vec<String> {
    let mut entries = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    entries
}
