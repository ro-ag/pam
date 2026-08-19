use std::{
    collections::HashSet,
    fs::{File, TryLockError},
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use cap_fs_ext::{
    DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _, ambient_authority,
};
use cap_std::fs::{Dir, DirBuilder, File as CapFile, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use pam_core::ContentDigest;
use reqwest::{StatusCode, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;
use url::Url;
use uuid::Uuid;

use crate::{
    GgufMetadata, LicenseConsent, ModelDescriptor, ModelError, ModelSource, RegisteredModel,
    path::validate_absolute_unicode_path,
};

const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const GGUF_FIXED_HEADER_BYTES: u64 = 24;
const GGUF_DEFAULT_ALIGNMENT: u64 = 32;
const GGUF_MAX_ALIGNMENT: u64 = 4096;
const GGUF_MAX_ARRAY_ITEMS: u64 = 16_777_216;
const GGUF_MAX_HEADER_BYTES: u64 = 256 * 1024 * 1024;
const GGUF_MAX_METADATA_KEY_BYTES: u64 = 4096;
const GGUF_MAX_TENSOR_NAME_BYTES: u64 = 127;
const GGUF_MAX_STRING_BYTES: u64 = 256 * 1024 * 1024;
const GGUF_MAX_DIMENSIONS: u32 = 4;
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;

pub struct ImportRequest {
    pub descriptor: ModelDescriptor,
    pub consent: LicenseConsent,
    pub path: PathBuf,
    pub registered_at_ms: u64,
}

pub struct DownloadRequest {
    pub descriptor: ModelDescriptor,
    pub consent: LicenseConsent,
    pub source: String,
    pub allowed_redirect_hosts: Vec<String>,
    pub destination: PathBuf,
    pub registered_at_ms: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TransferRequest {
    url: Url,
    range_start: u64,
    if_range: Option<String>,
}

impl TransferRequest {
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[must_use]
    pub const fn range_start(&self) -> u64 {
        self.range_start
    }

    #[must_use]
    pub fn if_range(&self) -> Option<&str> {
        self.if_range.as_deref()
    }
}

pub trait DownloadResponse: Send {
    fn status(&self) -> u16;
    fn content_length(&self) -> Option<&str>;
    fn content_range(&self) -> Option<&str>;
    fn content_encoding(&self) -> Option<&str>;
    fn etag(&self) -> Option<&str>;
    fn location(&self) -> Option<&str>;
    fn next_chunk(&mut self) -> impl Future<Output = Result<Option<Vec<u8>>, ModelError>> + Send;
}

pub trait DownloadTransport: Send + Sync {
    type Response: DownloadResponse;

    fn send(
        &self,
        request: TransferRequest,
    ) -> impl Future<Output = Result<Self::Response, ModelError>> + Send;
}

#[derive(Clone)]
pub struct ReqwestDownloadTransport {
    client: reqwest::Client,
}

impl ReqwestDownloadTransport {
    /// Builds the production HTTPS transport with native trust, system proxy
    /// discovery, identity encoding, bounded reads, and manual redirects.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::Network`] when the secure client cannot initialize.
    pub fn secure() -> Result<Self, ModelError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|_| ModelError::Network)?;
        Ok(Self { client })
    }
}

pub struct ReqwestDownloadResponse {
    response: reqwest::Response,
    content_length: Option<String>,
    content_range: Option<String>,
    content_encoding: Option<String>,
    etag: Option<String>,
    location: Option<String>,
}

impl DownloadTransport for ReqwestDownloadTransport {
    type Response = ReqwestDownloadResponse;

    async fn send(&self, request: TransferRequest) -> Result<Self::Response, ModelError> {
        let mut builder = self
            .client
            .get(request.url)
            .header(header::ACCEPT_ENCODING, "identity");
        if request.range_start > 0 {
            builder = builder.header(header::RANGE, format!("bytes={}-", request.range_start));
            if let Some(if_range) = request.if_range {
                builder = builder.header(header::IF_RANGE, if_range);
            }
        }
        let response = builder.send().await.map_err(|_| ModelError::Network)?;
        Ok(ReqwestDownloadResponse {
            content_length: header_text(&response, header::CONTENT_LENGTH),
            content_range: header_text(&response, header::CONTENT_RANGE),
            content_encoding: header_text(&response, header::CONTENT_ENCODING),
            etag: header_text(&response, header::ETAG),
            location: header_text(&response, header::LOCATION),
            response,
        })
    }
}

impl DownloadResponse for ReqwestDownloadResponse {
    fn status(&self) -> u16 {
        self.response.status().as_u16()
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

    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ModelError> {
        self.response
            .chunk()
            .await
            .map(|chunk| chunk.map(|bytes| bytes.to_vec()))
            .map_err(|_| ModelError::Network)
    }
}

/// Verifies and registers a user-owned GGUF in place without copying it.
///
/// # Errors
///
/// Returns an error when consent, path safety, GGUF structure, size, or SHA-256
/// does not match the descriptor.
pub fn import_existing(request: ImportRequest) -> Result<RegisteredModel, ModelError> {
    request.consent.verify(&request.descriptor)?;
    validate_absolute_unicode_path(&request.path)?;
    let (parent, name) = open_parent(&request.path, false)?;
    let inspected = inspect_model(&parent, &name, request.descriptor.expected_size_bytes)?;
    let canonical = request.path.canonicalize()?;
    validate_absolute_unicode_path(&canonical)?;
    verify_descriptor(&request.descriptor, &inspected)?;
    ensure_entry_identity(&parent, &name, &inspected)?;
    ensure_parent_current(&request.path, &parent)?;
    let (canonical_parent, canonical_name) = open_parent(&canonical, false)?;
    ensure_entry_identity(&canonical_parent, &canonical_name, &inspected)?;
    ensure_parent_current(&canonical, &canonical_parent)?;
    Ok(record(
        request.descriptor,
        canonical,
        inspected,
        ModelSource::Local,
        request.registered_at_ms,
    ))
}

/// Resumes, verifies, and atomically publishes a user-owned HTTPS GGUF.
///
/// The final path is never overwritten and the returned record contains only
/// metadata. Partial bytes and checkpoints remain siblings of the destination.
///
/// # Errors
///
/// Returns an error for missing consent, unsafe paths or URLs, invalid redirect
/// or range behavior, interrupted I/O, and integrity failures.
pub async fn download_https<T: DownloadTransport>(
    transport: &T,
    request: DownloadRequest,
) -> Result<RegisteredModel, ModelError> {
    request.consent.verify(&request.descriptor)?;
    validate_absolute_unicode_path(&request.destination)?;
    let (source, allowed_hosts) = source_and_allowed_hosts(&request)?;
    let (paths, acquisition_lock, request, source, mut checkpoint, mut offset) =
        match prepare_download_async(request, source).await? {
            DownloadPreparation::Complete(record) => return Ok(*record),
            DownloadPreparation::Ready(prepared) => {
                let PreparedDownload {
                    paths,
                    acquisition_lock,
                    request,
                    source,
                    checkpoint,
                    offset,
                } = *prepared;
                (paths, acquisition_lock, request, source, checkpoint, offset)
            }
        };

    loop {
        let requested_validator = checkpoint.etag.clone();
        let mut response = send_with_redirects(
            transport,
            &source,
            &allowed_hosts,
            offset,
            requested_validator.clone(),
        )
        .await?;

        validate_content_encoding(response.content_encoding())?;
        let status = response.status();
        let response_validator = strong_etag(response.etag());
        if status == StatusCode::OK.as_u16() && offset > 0 {
            remove_partial_async(&paths).await?;
            offset = 0;
            checkpoint.etag = None;
        }
        let range_length = if status == StatusCode::PARTIAL_CONTENT.as_u16() {
            let length = validate_content_range(
                response.content_range(),
                offset,
                request.descriptor.expected_size_bytes,
            )?;
            if offset > 0 && response_validator != requested_validator {
                checkpoint =
                    reset_partial_async(&paths, expected_checkpoint(&request, &source)).await?;
                offset = 0;
                continue;
            }
            Some(length)
        } else if status != StatusCode::OK.as_u16() {
            return Err(ModelError::UnexpectedStatus(status));
        } else {
            None
        };
        validate_segment_length(
            response.content_length(),
            request.descriptor.expected_size_bytes - offset,
            range_length,
        )?;
        checkpoint.etag = response_validator;
        write_checkpoint_async(&paths, &checkpoint).await?;

        let received = append_response_chunks(
            &mut response,
            open_partial_async(&paths, offset).await?,
            offset,
            request.descriptor.expected_size_bytes,
            checkpoint.etag.is_none(),
            &paths,
        )
        .await?;
        if received != request.descriptor.expected_size_bytes {
            if checkpoint.etag.is_none() {
                discard_partial_async(&paths).await?;
            }
            return Err(ModelError::TransferInterrupted);
        }
        return finish_download_async(paths, acquisition_lock, request, source).await;
    }
}

enum DownloadPreparation {
    Complete(Box<RegisteredModel>),
    Ready(Box<PreparedDownload>),
}

struct PreparedDownload {
    paths: AcquisitionPaths,
    acquisition_lock: AcquisitionLock,
    request: DownloadRequest,
    source: Url,
    checkpoint: DownloadCheckpoint,
    offset: u64,
}

async fn prepare_download_async(
    request: DownloadRequest,
    source: Url,
) -> Result<DownloadPreparation, ModelError> {
    tokio::task::spawn_blocking(move || prepare_download(request, source))
        .await
        .map_err(|_| ModelError::Network)?
}

fn prepare_download(
    request: DownloadRequest,
    source: Url,
) -> Result<DownloadPreparation, ModelError> {
    let paths = AcquisitionPaths::new(&request.destination)?;
    let acquisition_lock = AcquisitionLock::create(&paths)?;
    if entry_exists(&paths.parent, &paths.destination)? {
        let _acquisition_lock = acquisition_lock;
        let record = reconcile_existing_destination(&paths, &request, &source)?
            .ok_or(ModelError::ExistingDestination)?;
        return Ok(DownloadPreparation::Complete(Box::new(record)));
    }
    let mut checkpoint = load_or_create_checkpoint(&paths, &request, &source)?;
    let mut offset = partial_size(&paths)?;
    if offset > request.descriptor.expected_size_bytes {
        discard_partial(&paths)?;
        return Err(ModelError::CheckpointConflict);
    }
    if offset == request.descriptor.expected_size_bytes {
        let _acquisition_lock = acquisition_lock;
        let record = finish_download(&paths, request, &source)?;
        return Ok(DownloadPreparation::Complete(Box::new(record)));
    }
    if offset > 0 && checkpoint.etag.is_none() {
        checkpoint = reset_partial(&paths, &request, &source)?;
        offset = 0;
    }
    Ok(DownloadPreparation::Ready(Box::new(PreparedDownload {
        paths,
        acquisition_lock,
        request,
        source,
        checkpoint,
        offset,
    })))
}

async fn append_response_chunks<R: DownloadResponse>(
    response: &mut R,
    file: File,
    offset: u64,
    expected_size_bytes: u64,
    discard_without_validator: bool,
    paths: &AcquisitionPaths,
) -> Result<u64, ModelError> {
    let mut file = tokio::fs::File::from_std(file);
    let mut received = offset;
    loop {
        let chunk = match response.next_chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                file.sync_all().await?;
                drop(file);
                if discard_without_validator {
                    discard_partial_async(paths).await?;
                }
                return Err(error);
            }
        };
        let chunk_bytes =
            u64::try_from(chunk.len()).map_err(|_| ModelError::InvalidContentLength)?;
        received = received
            .checked_add(chunk_bytes)
            .ok_or(ModelError::InvalidContentLength)?;
        if received > expected_size_bytes {
            drop(file);
            discard_partial_async(paths).await?;
            return Err(ModelError::SizeMismatch {
                expected: expected_size_bytes,
                actual: received,
            });
        }
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    Ok(received)
}

async fn open_partial_async(paths: &AcquisitionPaths, offset: u64) -> Result<File, ModelError> {
    with_paths_blocking(paths, move |paths| open_partial(&paths, offset)).await
}

async fn remove_partial_async(paths: &AcquisitionPaths) -> Result<(), ModelError> {
    with_paths_blocking(paths, |paths| {
        remove_file_if_present(&paths.parent, &paths.partial)
    })
    .await
}

async fn write_checkpoint_async(
    paths: &AcquisitionPaths,
    checkpoint: &DownloadCheckpoint,
) -> Result<(), ModelError> {
    let checkpoint = checkpoint.clone();
    with_paths_blocking(paths, move |paths| write_checkpoint(&paths, &checkpoint)).await
}

async fn reset_partial_async(
    paths: &AcquisitionPaths,
    checkpoint: DownloadCheckpoint,
) -> Result<DownloadCheckpoint, ModelError> {
    with_paths_blocking(paths, move |paths| {
        discard_partial(&paths)?;
        write_checkpoint(&paths, &checkpoint)?;
        Ok(checkpoint)
    })
    .await
}

async fn discard_partial_async(paths: &AcquisitionPaths) -> Result<(), ModelError> {
    with_paths_blocking(paths, |paths| discard_partial(&paths)).await
}

async fn with_paths_blocking<T, F>(paths: &AcquisitionPaths, operation: F) -> Result<T, ModelError>
where
    T: Send + 'static,
    F: FnOnce(AcquisitionPaths) -> Result<T, ModelError> + Send + 'static,
{
    let paths = paths.try_clone()?;
    tokio::task::spawn_blocking(move || operation(paths))
        .await
        .map_err(|_| ModelError::Network)?
}

async fn finish_download_async(
    paths: AcquisitionPaths,
    acquisition_lock: AcquisitionLock,
    request: DownloadRequest,
    source: Url,
) -> Result<RegisteredModel, ModelError> {
    tokio::task::spawn_blocking(move || {
        let _acquisition_lock = acquisition_lock;
        finish_download(&paths, request, &source)
    })
    .await
    .map_err(|_| ModelError::Network)?
}

fn finish_download(
    paths: &AcquisitionPaths,
    request: DownloadRequest,
    source: &Url,
) -> Result<RegisteredModel, ModelError> {
    let inspected = inspect_model(
        &paths.parent,
        &paths.partial,
        request.descriptor.expected_size_bytes,
    )?;
    if let Err(error) = verify_descriptor(&request.descriptor, &inspected) {
        discard_partial(paths)?;
        return Err(error);
    }
    match publish_no_replace(paths, &inspected) {
        Ok(()) => {}
        Err(ModelError::ExistingDestination) => {
            if let Some(record) = reconcile_existing_destination(paths, &request, source)? {
                return Ok(record);
            }
            return Err(ModelError::ExistingDestination);
        }
        Err(error) => return Err(error),
    }
    sync_parent(&paths.parent)?;
    remove_file_if_present(&paths.parent, &paths.partial)?;
    remove_file_if_present(&paths.parent, &paths.checkpoint)?;
    sync_parent(&paths.parent)?;
    ensure_parent_current(&request.destination, &paths.parent)?;
    Ok(record(
        request.descriptor,
        request.destination,
        inspected,
        ModelSource::https(canonical_source_identity(source))?,
        request.registered_at_ms,
    ))
}

fn reconcile_existing_destination(
    paths: &AcquisitionPaths,
    request: &DownloadRequest,
    source: &Url,
) -> Result<Option<RegisteredModel>, ModelError> {
    match paths.parent.symlink_metadata(&paths.destination) {
        Ok(metadata) if metadata.file_type().is_symlink() => return Err(ModelError::UnsafePath),
        Ok(metadata) if !metadata.is_file() => return Err(ModelError::ExistingDestination),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let inspected = inspect_model(
        &paths.parent,
        &paths.destination,
        request.descriptor.expected_size_bytes,
    )
    .map_err(|error| match error {
        ModelError::Io(_) | ModelError::UnsafePath => error,
        _ => ModelError::ExistingDestination,
    })?;
    if verify_descriptor(&request.descriptor, &inspected).is_err() {
        return Err(ModelError::ExistingDestination);
    }
    discard_partial(paths)?;
    sync_parent(&paths.parent)?;
    ensure_parent_current(&request.destination, &paths.parent)?;
    Ok(Some(record(
        request.descriptor.clone(),
        request.destination.clone(),
        inspected,
        ModelSource::https(canonical_source_identity(source))?,
        request.registered_at_ms,
    )))
}

async fn send_with_redirects<T: DownloadTransport>(
    transport: &T,
    source: &Url,
    allowed_hosts: &[String],
    range_start: u64,
    if_range: Option<String>,
) -> Result<T::Response, ModelError> {
    let mut current_url = source.clone();
    for redirects in 0..=MAX_REDIRECTS {
        let response = transport
            .send(TransferRequest {
                url: current_url.clone(),
                range_start,
                if_range: if_range.clone(),
            })
            .await?;
        if !is_redirect(response.status()) {
            return Ok(response);
        }
        if redirects == MAX_REDIRECTS {
            return Err(ModelError::TooManyRedirects);
        }
        current_url = validate_redirect(&current_url, response.location(), allowed_hosts)?;
    }
    unreachable!("bounded redirect loop always returns")
}

struct InspectedModel {
    digest: ContentDigest,
    size_bytes: u64,
    gguf: GgufMetadata,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn inspect_model(
    parent: &Dir,
    name: &Path,
    expected_size_bytes: u64,
) -> Result<InspectedModel, ModelError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(name, &options)
        .map_err(|error| classify_file_open_error(parent, name, error))?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(ModelError::NotRegularFile);
    }
    if before.len() != expected_size_bytes {
        return Err(ModelError::SizeMismatch {
            expected: expected_size_bytes,
            actual: before.len(),
        });
    }
    let gguf = inspect_gguf(&mut file, before.len())?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut size_bytes = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size_bytes = size_bytes
            .checked_add(u64::try_from(count).map_err(|_| ModelError::InvalidContentLength)?)
            .ok_or(ModelError::InvalidContentLength)?;
    }
    let after = file.metadata()?;
    if before.len() != after.len() || before.len() != size_bytes {
        return Err(ModelError::SizeMismatch {
            expected: before.len(),
            actual: size_bytes,
        });
    }
    Ok(InspectedModel {
        digest: ContentDigest::from_sha256(hasher.finalize().into()),
        size_bytes,
        gguf,
        #[cfg(unix)]
        device: before.dev(),
        #[cfg(unix)]
        inode: before.ino(),
    })
}

fn read_gguf_header(
    file: &mut CapFile,
    file_size: u64,
) -> Result<(u32, u64, u64, u64), ModelError> {
    if file_size < GGUF_FIXED_HEADER_BYTES {
        return Err(ModelError::InvalidGguf);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut cursor = 0;
    if &read_bytes::<4>(file, &mut cursor, file_size)? != b"GGUF" {
        return Err(ModelError::InvalidGguf);
    }
    let version = read_u32(file, &mut cursor, file_size)?;
    if !matches!(version, 2 | 3) {
        return Err(ModelError::UnsupportedGgufVersion(version));
    }
    let tensor_count = read_u64(file, &mut cursor, file_size)?;
    let metadata_kv_count = read_u64(file, &mut cursor, file_size)?;
    Ok((version, tensor_count, metadata_kv_count, cursor))
}

fn inspect_gguf(file: &mut CapFile, file_size: u64) -> Result<GgufMetadata, ModelError> {
    let (version, tensor_count, metadata_kv_count, mut cursor) = read_gguf_header(file, file_size)?;
    if !(GgufMetadata::MIN_TENSOR_COUNT..=GgufMetadata::MAX_TENSOR_COUNT).contains(&tensor_count)
        || metadata_kv_count > GgufMetadata::MAX_METADATA_KV_COUNT
    {
        return Err(ModelError::InvalidGguf);
    }

    let mut metadata_keys = HashSet::new();
    let mut alignment = GGUF_DEFAULT_ALIGNMENT;
    let mut array_items = 0;
    for _ in 0..metadata_kv_count {
        let key = read_gguf_string(file, &mut cursor, file_size, GGUF_MAX_METADATA_KEY_BYTES)?;
        if !valid_metadata_key(&key) || !metadata_keys.insert(key.clone()) {
            return Err(ModelError::InvalidGguf);
        }
        let value_type = read_u32(file, &mut cursor, file_size)?;
        if key == b"general.alignment" {
            if value_type != 4 {
                return Err(ModelError::InvalidGguf);
            }
            alignment = u64::from(read_u32(file, &mut cursor, file_size)?);
            if !(8..=GGUF_MAX_ALIGNMENT).contains(&alignment) || !alignment.is_power_of_two() {
                return Err(ModelError::InvalidGguf);
            }
        } else {
            skip_metadata_value(file, &mut cursor, file_size, value_type, &mut array_items)?;
        }
        ensure_header_budget(cursor)?;
    }

    let tensor_capacity = usize::try_from(tensor_count).map_err(|_| ModelError::InvalidGguf)?;
    let mut tensor_names = HashSet::with_capacity(tensor_capacity);
    let mut tensors = Vec::with_capacity(tensor_capacity);
    for _ in 0..tensor_count {
        let name = read_gguf_string(file, &mut cursor, file_size, GGUF_MAX_TENSOR_NAME_BYTES)?;
        if !valid_tensor_name(&name) || !tensor_names.insert(name) {
            return Err(ModelError::InvalidGguf);
        }
        let dimensions = read_u32(file, &mut cursor, file_size)?;
        if !(1..=GGUF_MAX_DIMENSIONS).contains(&dimensions) {
            return Err(ModelError::InvalidGguf);
        }
        let first_dimension = read_u64(file, &mut cursor, file_size)?;
        if first_dimension == 0 {
            return Err(ModelError::InvalidGguf);
        }
        let mut rows = 1_u64;
        for _ in 1..dimensions {
            let dimension = read_u64(file, &mut cursor, file_size)?;
            if dimension == 0 {
                return Err(ModelError::InvalidGguf);
            }
            rows = rows.checked_mul(dimension).ok_or(ModelError::InvalidGguf)?;
        }
        let tensor_type = read_u32(file, &mut cursor, file_size)?;
        let (block_elements, block_bytes) = ggml_type_layout(tensor_type)?;
        if first_dimension % block_elements != 0 {
            return Err(ModelError::InvalidGguf);
        }
        let length = first_dimension
            .checked_div(block_elements)
            .and_then(|blocks| blocks.checked_mul(block_bytes))
            .and_then(|row_bytes| row_bytes.checked_mul(rows))
            .filter(|length| *length > 0 && *length <= ModelDescriptor::MAX_SIZE_BYTES)
            .ok_or(ModelError::InvalidGguf)?;
        tensors.push(TensorSpan {
            offset: read_u64(file, &mut cursor, file_size)?,
            length,
        });
        ensure_header_budget(cursor)?;
    }

    if tensor_count > 0 {
        let data_start = align_up(cursor, alignment).ok_or(ModelError::InvalidGguf)?;
        if data_start >= file_size {
            return Err(ModelError::InvalidGguf);
        }
        let data_bytes = file_size - data_start;
        tensors.sort_unstable_by_key(|tensor| tensor.offset);
        let mut previous_end = 0;
        for tensor in tensors {
            let end = tensor
                .offset
                .checked_add(tensor.length)
                .filter(|end| *end <= data_bytes)
                .ok_or(ModelError::InvalidGguf)?;
            if tensor.offset % alignment != 0 || tensor.offset < previous_end {
                return Err(ModelError::InvalidGguf);
            }
            previous_end = end;
        }
    }

    Ok(GgufMetadata {
        version,
        tensor_count,
        metadata_kv_count,
    })
}

#[derive(Clone, Copy)]
struct TensorSpan {
    offset: u64,
    length: u64,
}

fn ggml_type_layout(tensor_type: u32) -> Result<(u64, u64), ModelError> {
    let layout = match tensor_type {
        0 | 26 => (1, 4),
        1 | 25 | 30 => (1, 2),
        2 | 20 => (32, 18),
        3 => (32, 20),
        6 => (32, 22),
        7 => (32, 24),
        8 => (32, 34),
        9 => (32, 36),
        10 => (256, 84),
        11 | 21 => (256, 110),
        12 => (256, 144),
        13 => (256, 176),
        14 => (256, 210),
        15 => (256, 292),
        16 | 35 => (256, 66),
        17 => (256, 74),
        18 => (256, 98),
        19 => (256, 50),
        22 => (256, 82),
        23 => (256, 136),
        24 => (1, 1),
        27 | 28 => (1, 8),
        29 => (256, 56),
        34 => (256, 54),
        39 => (32, 17),
        40 => (64, 36),
        41 => (128, 18),
        42 => (64, 18),
        _ => return Err(ModelError::InvalidGguf),
    };
    Ok(layout)
}

fn skip_metadata_value(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
    value_type: u32,
    array_items: &mut u64,
) -> Result<(), ModelError> {
    match value_type {
        0 | 1 => skip_bytes(file, cursor, file_size, 1),
        2 | 3 => skip_bytes(file, cursor, file_size, 2),
        4..=6 => skip_bytes(file, cursor, file_size, 4),
        7 => {
            if read_bytes::<1>(file, cursor, file_size)?[0] <= 1 {
                Ok(())
            } else {
                Err(ModelError::InvalidGguf)
            }
        }
        8 => skip_gguf_string(file, cursor, file_size),
        9 => {
            let element_type = read_u32(file, cursor, file_size)?;
            let count = read_u64(file, cursor, file_size)?;
            *array_items = array_items
                .checked_add(count)
                .filter(|items| *items <= GGUF_MAX_ARRAY_ITEMS)
                .ok_or(ModelError::InvalidGguf)?;
            skip_metadata_array(file, cursor, file_size, element_type, count)
        }
        10..=12 => skip_bytes(file, cursor, file_size, 8),
        _ => Err(ModelError::InvalidGguf),
    }
}

fn skip_metadata_array(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
    element_type: u32,
    count: u64,
) -> Result<(), ModelError> {
    let scalar_bytes = match element_type {
        0 | 1 => Some(1_u64),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    };
    if let Some(scalar_bytes) = scalar_bytes {
        return skip_bytes(
            file,
            cursor,
            file_size,
            scalar_bytes
                .checked_mul(count)
                .ok_or(ModelError::InvalidGguf)?,
        );
    }
    match element_type {
        7 => {
            for _ in 0..count {
                if read_bytes::<1>(file, cursor, file_size)?[0] > 1 {
                    return Err(ModelError::InvalidGguf);
                }
            }
            Ok(())
        }
        8 => {
            for _ in 0..count {
                skip_gguf_string(file, cursor, file_size)?;
            }
            Ok(())
        }
        _ => Err(ModelError::InvalidGguf),
    }
}

fn read_gguf_string(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ModelError> {
    let length = read_u64(file, cursor, file_size)?;
    if length == 0 || length > maximum_bytes {
        return Err(ModelError::InvalidGguf);
    }
    let length = usize::try_from(length).map_err(|_| ModelError::InvalidGguf)?;
    let mut bytes = vec![0; length];
    read_exact(file, cursor, file_size, &mut bytes)?;
    Ok(bytes)
}

fn skip_gguf_string(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
) -> Result<(), ModelError> {
    let length = read_u64(file, cursor, file_size)?;
    if length > GGUF_MAX_STRING_BYTES {
        return Err(ModelError::InvalidGguf);
    }
    skip_bytes(file, cursor, file_size, length)
}

fn valid_metadata_key(value: &[u8]) -> bool {
    value.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
    })
}

fn valid_tensor_name(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok_and(|value| !value.chars().any(char::is_control))
}

fn ensure_header_budget(cursor: u64) -> Result<(), ModelError> {
    if cursor <= GGUF_MAX_HEADER_BYTES {
        Ok(())
    } else {
        Err(ModelError::InvalidGguf)
    }
}

fn read_u32(file: &mut CapFile, cursor: &mut u64, file_size: u64) -> Result<u32, ModelError> {
    Ok(u32::from_le_bytes(read_bytes(file, cursor, file_size)?))
}

fn read_u64(file: &mut CapFile, cursor: &mut u64, file_size: u64) -> Result<u64, ModelError> {
    Ok(u64::from_le_bytes(read_bytes(file, cursor, file_size)?))
}

fn read_bytes<const N: usize>(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
) -> Result<[u8; N], ModelError> {
    let mut bytes = [0; N];
    read_exact(file, cursor, file_size, &mut bytes)?;
    Ok(bytes)
}

fn read_exact(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
    bytes: &mut [u8],
) -> Result<(), ModelError> {
    let length = u64::try_from(bytes.len()).map_err(|_| ModelError::InvalidGguf)?;
    *cursor = cursor
        .checked_add(length)
        .filter(|end| *end <= file_size)
        .ok_or(ModelError::InvalidGguf)?;
    file.read_exact(bytes).map_err(|_| ModelError::InvalidGguf)
}

fn skip_bytes(
    file: &mut CapFile,
    cursor: &mut u64,
    file_size: u64,
    length: u64,
) -> Result<(), ModelError> {
    *cursor = cursor
        .checked_add(length)
        .filter(|end| *end <= file_size)
        .ok_or(ModelError::InvalidGguf)?;
    let length = i64::try_from(length).map_err(|_| ModelError::InvalidGguf)?;
    file.seek(SeekFrom::Current(length))?;
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|value| value & !(alignment - 1))
}

fn verify_descriptor(
    descriptor: &ModelDescriptor,
    inspected: &InspectedModel,
) -> Result<(), ModelError> {
    if inspected.size_bytes != descriptor.expected_size_bytes {
        return Err(ModelError::SizeMismatch {
            expected: descriptor.expected_size_bytes,
            actual: inspected.size_bytes,
        });
    }
    if inspected.digest != descriptor.expected_digest {
        return Err(ModelError::DigestMismatch);
    }
    Ok(())
}

fn record(
    descriptor: ModelDescriptor,
    path: PathBuf,
    inspected: InspectedModel,
    source: ModelSource,
    registered_at_ms: u64,
) -> RegisteredModel {
    RegisteredModel {
        key: descriptor.key,
        path,
        digest: inspected.digest,
        size_bytes: inspected.size_bytes,
        gguf: inspected.gguf,
        license: descriptor.license,
        source,
        registered_at_ms,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DownloadCheckpoint {
    schema_version: u32,
    canonical_source: String,
    expected_digest: ContentDigest,
    expected_size_bytes: u64,
    license_digest: ContentDigest,
    etag: Option<String>,
}

struct AcquisitionPaths {
    parent: Dir,
    destination: PathBuf,
    partial: PathBuf,
    checkpoint: PathBuf,
    lock: PathBuf,
}

impl AcquisitionPaths {
    fn new(destination: &Path) -> Result<Self, ModelError> {
        let (parent, destination_name) = open_parent(destination, true)?;
        let filename = destination_name
            .to_str()
            .ok_or(ModelError::InvalidPath)?
            .to_owned();
        Ok(Self {
            parent,
            destination: destination_name,
            partial: format!(".{filename}.pam-model.part").into(),
            checkpoint: format!(".{filename}.pam-model.json").into(),
            lock: format!(".{filename}.pam-model.lock").into(),
        })
    }

    fn try_clone(&self) -> Result<Self, ModelError> {
        Ok(Self {
            parent: self.parent.try_clone()?,
            destination: self.destination.clone(),
            partial: self.partial.clone(),
            checkpoint: self.checkpoint.clone(),
            lock: self.lock.clone(),
        })
    }
}

struct AcquisitionLock {
    _file: File,
}

impl AcquisitionLock {
    fn create(paths: &AcquisitionPaths) -> Result<Self, ModelError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        set_private_file_mode(&mut options);
        let file = paths
            .parent
            .open_with(&paths.lock, &options)
            .map_err(|error| classify_file_open_error(&paths.parent, &paths.lock, error))?;
        if !file.metadata()?.is_file() {
            return Err(ModelError::UnsafePath);
        }
        let mut file = file.into_std();
        ensure_single_link(&file)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(ModelError::ConcurrentAcquisition),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        file.set_len(0)?;
        writeln!(file, "{}", Uuid::new_v4())?;
        file.sync_all()?;
        Ok(Self { _file: file })
    }
}

fn load_or_create_checkpoint(
    paths: &AcquisitionPaths,
    request: &DownloadRequest,
    source: &Url,
) -> Result<DownloadCheckpoint, ModelError> {
    let expected = expected_checkpoint(request, source);
    if let Some(bytes) = read_bounded_file(&paths.parent, &paths.checkpoint, MAX_CHECKPOINT_BYTES)?
    {
        let mut stored: DownloadCheckpoint =
            serde_json::from_slice(&bytes).map_err(|_| ModelError::CheckpointConflict)?;
        if stored.schema_version != expected.schema_version
            || stored.canonical_source != expected.canonical_source
            || stored.expected_digest != expected.expected_digest
            || stored.expected_size_bytes != expected.expected_size_bytes
            || stored.license_digest != expected.license_digest
        {
            return Err(ModelError::CheckpointConflict);
        }
        if !entry_is_file(&paths.parent, &paths.partial)? {
            stored.etag = None;
            write_checkpoint(paths, &stored)?;
        }
        Ok(stored)
    } else {
        if entry_exists(&paths.parent, &paths.partial)? {
            return Err(ModelError::CheckpointConflict);
        }
        write_checkpoint(paths, &expected)?;
        Ok(expected)
    }
}

fn expected_checkpoint(request: &DownloadRequest, source: &Url) -> DownloadCheckpoint {
    DownloadCheckpoint {
        schema_version: 1,
        canonical_source: canonical_source_identity(source),
        expected_digest: request.descriptor.expected_digest.clone(),
        expected_size_bytes: request.descriptor.expected_size_bytes,
        license_digest: request.descriptor.license.notice_digest().clone(),
        etag: None,
    }
}

fn reset_partial(
    paths: &AcquisitionPaths,
    request: &DownloadRequest,
    source: &Url,
) -> Result<DownloadCheckpoint, ModelError> {
    discard_partial(paths)?;
    let checkpoint = expected_checkpoint(request, source);
    write_checkpoint(paths, &checkpoint)?;
    Ok(checkpoint)
}

fn write_checkpoint(
    paths: &AcquisitionPaths,
    checkpoint: &DownloadCheckpoint,
) -> Result<(), ModelError> {
    let bytes = serde_json::to_vec(checkpoint).map_err(|_| ModelError::CheckpointConflict)?;
    let filename = paths.destination.to_str().ok_or(ModelError::InvalidPath)?;
    let temporary = format!(".{filename}.pam-model.tmp-{}", Uuid::new_v4());
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    set_private_file_mode(&mut options);
    let result = (|| {
        let mut file = paths.parent.open_with(&temporary, &options)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        paths
            .parent
            .rename(&temporary, &paths.parent, &paths.checkpoint)?;
        sync_parent(&paths.parent)
    })();
    if result.is_err() {
        let _ = paths.parent.remove_file(&temporary);
    }
    result
}

fn partial_size(paths: &AcquisitionPaths) -> Result<u64, ModelError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    match paths.parent.open_with(&paths.partial, &options) {
        Ok(file) => {
            let metadata = file.metadata()?;
            if metadata.is_file() {
                Ok(metadata.len())
            } else {
                Err(ModelError::NotRegularFile)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(classify_file_open_error(
            &paths.parent,
            &paths.partial,
            error,
        )),
    }
}

fn open_partial(paths: &AcquisitionPaths, offset: u64) -> Result<File, ModelError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .append(offset > 0)
        .create_new(offset == 0)
        .follow(FollowSymlinks::No);
    set_private_file_mode(&mut options);
    let file = paths
        .parent
        .open_with(&paths.partial, &options)
        .map_err(|error| classify_file_open_error(&paths.parent, &paths.partial, error))?;
    let file = file.into_std();
    ensure_single_link(&file)?;
    if file.metadata()?.len() != offset {
        return Err(ModelError::CheckpointConflict);
    }
    Ok(file)
}

#[cfg(unix)]
fn ensure_single_link(file: &File) -> Result<(), ModelError> {
    let metadata = file.metadata()?;
    if std::os::unix::fs::MetadataExt::nlink(&metadata) == 1 {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

#[cfg(windows)]
fn ensure_single_link(file: &File) -> Result<(), ModelError> {
    use std::os::windows::fs::MetadataExt as _;

    if file.metadata()?.number_of_links() == Some(1) {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

#[cfg(not(any(unix, windows)))]
fn ensure_single_link(_file: &File) -> Result<(), ModelError> {
    Ok(())
}

fn discard_partial(paths: &AcquisitionPaths) -> Result<(), ModelError> {
    remove_file_if_present(&paths.parent, &paths.partial)?;
    remove_file_if_present(&paths.parent, &paths.checkpoint)?;
    Ok(())
}

fn publish_no_replace(
    paths: &AcquisitionPaths,
    inspected: &InspectedModel,
) -> Result<(), ModelError> {
    ensure_entry_identity(&paths.parent, &paths.partial, inspected)?;
    match paths
        .parent
        .hard_link(&paths.partial, &paths.parent, &paths.destination)
    {
        Ok(()) => ensure_entry_identity(&paths.parent, &paths.destination, inspected),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ModelError::ExistingDestination)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn ensure_entry_identity(
    parent: &Dir,
    name: &Path,
    inspected: &InspectedModel,
) -> Result<(), ModelError> {
    let metadata = parent.symlink_metadata(name)?;
    if metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.dev() == inspected.device
        && metadata.ino() == inspected.inode
    {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

#[cfg(not(unix))]
fn ensure_entry_identity(
    parent: &Dir,
    name: &Path,
    inspected: &InspectedModel,
) -> Result<(), ModelError> {
    let current = inspect_model(parent, name, inspected.size_bytes)?;
    if current.size_bytes == inspected.size_bytes
        && current.digest == inspected.digest
        && current.gguf == inspected.gguf
    {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

fn open_parent(path: &Path, create: bool) -> Result<(Dir, PathBuf), ModelError> {
    let name = PathBuf::from(path.file_name().ok_or(ModelError::InvalidPath)?);
    let parent = path.parent().ok_or(ModelError::InvalidPath)?;
    Ok((open_absolute_directory(parent, create)?, name))
}

fn open_absolute_directory(path: &Path, create: bool) -> Result<Dir, ModelError> {
    let mut root = PathBuf::new();
    let mut names = Vec::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if root.as_os_str().is_empty() => {
                root.push(prefix.as_os_str());
            }
            Component::RootDir => {
                root.push(component.as_os_str());
                rooted = true;
            }
            Component::Normal(name) if rooted => names.push(PathBuf::from(name)),
            Component::CurDir if rooted => {}
            Component::Prefix(_)
            | Component::Normal(_)
            | Component::CurDir
            | Component::ParentDir => {
                return Err(ModelError::InvalidPath);
            }
        }
    }
    if !rooted || !root.is_absolute() {
        return Err(ModelError::InvalidPath);
    }
    let mut directory = Dir::open_ambient_dir(&root, ambient_authority())?;
    if !directory.dir_metadata()?.is_dir() {
        return Err(ModelError::UnsafePath);
    }
    for name in names {
        directory = open_child_directory(&directory, &name, create)?;
    }
    Ok(directory)
}

fn open_child_directory(parent: &Dir, name: &Path, create: bool) -> Result<Dir, ModelError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => verify_directory(directory),
        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
            match create_private_directory(parent, name) {
                Ok(()) => sync_parent(parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            parent
                .open_dir_nofollow(name)
                .map_err(|error| classify_directory_open_error(parent, name, error))
                .and_then(verify_directory)
        }
        Err(error) => Err(classify_directory_open_error(parent, name, error)),
    }
}

fn create_private_directory(parent: &Dir, name: &Path) -> std::io::Result<()> {
    let mut builder = DirBuilder::new();
    set_private_directory_mode(&mut builder);
    parent.create_dir_with(name, &builder)
}

#[cfg(unix)]
fn set_private_directory_mode(builder: &mut DirBuilder) {
    builder.mode(0o700);
}

#[cfg(not(unix))]
fn set_private_directory_mode(_builder: &mut DirBuilder) {}

#[cfg(unix)]
fn set_private_file_mode(options: &mut OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_file_mode(_options: &mut OpenOptions) {}

fn verify_directory(directory: Dir) -> Result<Dir, ModelError> {
    if directory.dir_metadata()?.is_dir() {
        Ok(directory)
    } else {
        Err(ModelError::UnsafePath)
    }
}

fn classify_directory_open_error(parent: &Dir, name: &Path, error: std::io::Error) -> ModelError {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            ModelError::UnsafePath
        }
        _ => error.into(),
    }
}

fn classify_file_open_error(parent: &Dir, name: &Path, error: std::io::Error) -> ModelError {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            ModelError::UnsafePath
        }
        _ => error.into(),
    }
}

#[cfg(unix)]
fn ensure_parent_current(path: &Path, expected: &Dir) -> Result<(), ModelError> {
    let (current, _) = open_parent(path, false)?;
    let current = current.dir_metadata()?;
    let expected = expected.dir_metadata()?;
    if current.dev() == expected.dev() && current.ino() == expected.ino() {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

#[cfg(not(unix))]
fn ensure_parent_current(path: &Path, expected: &Dir) -> Result<(), ModelError> {
    let (current, _) = open_parent(path, false)?;
    if current.dir_metadata()?.is_dir() && expected.dir_metadata()?.is_dir() {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

fn entry_exists(parent: &Dir, name: &Path) -> Result<bool, ModelError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ModelError::UnsafePath),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn entry_is_file(parent: &Dir, name: &Path) -> Result<bool, ModelError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ModelError::UnsafePath),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(ModelError::NotRegularFile),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_bounded_file(
    parent: &Dir,
    name: &Path,
    maximum_bytes: u64,
) -> Result<Option<Vec<u8>>, ModelError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match parent.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(classify_file_open_error(parent, name, error)),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(ModelError::CheckpointConflict);
    }
    let mut bytes = Vec::new();
    let mut limited = Read::take(file, maximum_bytes.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ModelError::CheckpointConflict)? > maximum_bytes {
        return Err(ModelError::CheckpointConflict);
    }
    Ok(Some(bytes))
}

fn remove_file_if_present(parent: &Dir, name: &Path) -> Result<(), ModelError> {
    match parent.remove_file(name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Dir) -> Result<(), ModelError> {
    parent.open(".")?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(parent: &Dir) -> Result<(), ModelError> {
    if parent.dir_metadata()?.is_dir() {
        Ok(())
    } else {
        Err(ModelError::UnsafePath)
    }
}

fn validate_source(value: &str) -> Result<Url, ModelError> {
    let url = Url::parse(value).map_err(|_| ModelError::InvalidSource)?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.host_str().is_none()
        || url.host().is_some_and(|host| match host {
            url::Host::Ipv4(address) => non_public_ip(IpAddr::V4(address)),
            url::Host::Ipv6(address) => non_public_ip(IpAddr::V6(address)),
            url::Host::Domain(_) => false,
        })
    {
        return Err(ModelError::InsecureSource);
    }
    Ok(url)
}

fn source_and_allowed_hosts(request: &DownloadRequest) -> Result<(Url, Vec<String>), ModelError> {
    let source = validate_source(&request.source)?;
    ModelSource::https(canonical_source_identity(&source))?;
    let initial_host = source
        .host_str()
        .ok_or(ModelError::InvalidSource)?
        .to_ascii_lowercase();
    let mut allowed_hosts = request
        .allowed_redirect_hosts
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect::<Vec<_>>();
    allowed_hosts.push(initial_host);
    Ok((source, allowed_hosts))
}

fn validate_redirect(
    current: &Url,
    location: Option<&str>,
    allowed_hosts: &[String],
) -> Result<Url, ModelError> {
    let location = location.ok_or(ModelError::InvalidSource)?;
    let target = current
        .join(location)
        .map_err(|_| ModelError::InvalidSource)?;
    let host = target
        .host_str()
        .ok_or(ModelError::InvalidSource)?
        .to_ascii_lowercase();
    if target.scheme() != "https"
        || target.port_or_known_default() != Some(443)
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
        || !allowed_hosts.iter().any(|allowed| allowed == &host)
    {
        return Err(ModelError::RedirectNotAllowed);
    }
    if target.host().is_some_and(|host| match host {
        url::Host::Ipv4(address) => non_public_ip(IpAddr::V4(address)),
        url::Host::Ipv6(address) => non_public_ip(IpAddr::V6(address)),
        url::Host::Domain(_) => false,
    }) {
        return Err(ModelError::RedirectNotAllowed);
    }
    Ok(target)
}

fn non_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => non_public_ipv4(address),
        IpAddr::V6(address) => non_public_ipv6(address),
    }
}

fn non_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

fn non_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return non_public_ipv4(mapped);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])
        || (segments[0] == 0x2001 && segments[1] < 0x0200)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || segments[0] == 0x3fff
        || segments[0] == 0x5f00
        || (segments[0] & 0xffc0) == 0xfec0
}

fn canonical_source_identity(source: &Url) -> String {
    let mut sanitized = source.clone();
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    sanitized.to_string()
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn validate_content_encoding(value: Option<&str>) -> Result<(), ModelError> {
    if value.is_none_or(|encoding| encoding.eq_ignore_ascii_case("identity")) {
        Ok(())
    } else {
        Err(ModelError::InvalidContentEncoding)
    }
}

fn validate_segment_length(
    value: Option<&str>,
    remaining: u64,
    exact: Option<u64>,
) -> Result<(), ModelError> {
    if let Some(value) = value {
        let declared = value
            .parse::<u64>()
            .map_err(|_| ModelError::InvalidContentLength)?;
        if declared > remaining || exact.is_some_and(|exact| declared != exact) {
            return Err(ModelError::InvalidContentLength);
        }
    }
    Ok(())
}

fn validate_content_range(
    value: Option<&str>,
    expected_start: u64,
    expected_total: u64,
) -> Result<u64, ModelError> {
    let value = value.ok_or(ModelError::InvalidContentRange)?;
    let range = value
        .strip_prefix("bytes ")
        .ok_or(ModelError::InvalidContentRange)?;
    let (span, total) = range
        .split_once('/')
        .ok_or(ModelError::InvalidContentRange)?;
    let (start, end) = span
        .split_once('-')
        .ok_or(ModelError::InvalidContentRange)?;
    let start = start
        .parse::<u64>()
        .map_err(|_| ModelError::InvalidContentRange)?;
    let end = end
        .parse::<u64>()
        .map_err(|_| ModelError::InvalidContentRange)?;
    let total = total
        .parse::<u64>()
        .map_err(|_| ModelError::InvalidContentRange)?;
    if start != expected_start || end < start || end >= total || total != expected_total {
        return Err(ModelError::InvalidContentRange);
    }
    end.checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or(ModelError::InvalidContentRange)
}

fn strong_etag(value: Option<&str>) -> Option<String> {
    let value = value?;
    let bytes = value.as_bytes();
    if bytes.len() < 2
        || bytes.first() != Some(&b'"')
        || bytes.last() != Some(&b'"')
        || !bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
    {
        return None;
    }
    Some(value.to_owned())
}

fn header_text(response: &reqwest::Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
