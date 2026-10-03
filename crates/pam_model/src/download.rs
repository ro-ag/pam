//! Fetching weights: system `curl` as a child process, integrity in Rust.
//!
//! No pure-Rust TLS stack is free of a C compiler, so PAM shells out to the operating
//! system's own `curl`, started by the one launcher pam has (`pam_net`): the fixed,
//! root-owned binary, never a PATH lookup, a constant argument vector, every value on
//! standard input, an empty environment. curl only moves bytes: size and SHA-256 are
//! checked here after the transfer, against the catalog (missing curl is a named refusal
//! via [`curl_recovery_line`]). The proxy, the no-proxy list and the CA bundle a transfer
//! runs under are the [`NetSettings`] the caller resolved from the Network settings; no
//! environment variable of the daemon's is read, by this crate or by curl. [`start`]
//! refuses a URL that is not `https://` ([`DownloadError::InvalidUrl`]) so a pasted
//! string can never become a curl option, a `file://` read, or a plain-text transfer; a
//! mirror ([`DownloadRequest::via_mirror`]) changes where the bytes come from and nothing
//! about what they must hash to. Sidecar file names ([`sidecar_paths`]) are frozen to
//! match pam-old, so multi-gigabyte partial downloads already on disk keep resuming
//! instead of re-fetching. A checkpoint is never silently reused across a different URL
//! or digest ([`DownloadError::CheckpointConflict`]). The `ETag` is saved and sent back
//! as `If-Range` on a resume: a server whose file changed then answers the whole body
//! (curl reports that as a refused resume), and the transfer starts over from zero rather
//! than gluing new bytes onto an old part file. It is never sent as `--etag-compare`: a
//! `304` would leave an empty transfer over a half-finished part file, so the digest stays
//! the only integrity signal. Stalls are caught by [`TransferLimits`]; only a successful
//! transfer or a digest mismatch deletes the part file — cancelling or failing keeps it so
//! the next attempt resumes. A failure's `cause` is the launcher's own vocabulary
//! ([`NetFailure::cause`]), the same words the Network settings' Test action uses.
//!
//! Weights can also arrive from a file on this machine ([`start_import`]): the file is
//! copied — never moved — into the models directory through the same part file, lock,
//! digest check and link-into-place as a download, hashed in the pass that copies it,
//! with the same handle, states and cancel. No curl runs for an import.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use pam_net::{CurlChild, CurlRequest, MirrorBase, NetFailure, NetSettings, TrustedCurl, Url};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::registry::sha256_file;
use crate::weights::{Control, FREE_SPACE_HEADROOM_BYTES, WeightsError, platform_free_bytes};

/// Checkpoint format version. pam-old wrote `1`; nothing has changed.
const CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// How often the part file is stat-ed for progress.
const PROGRESS_POLL: Duration = Duration::from_millis(500);

/// How many redirects curl may follow inside one transfer. A catalog host
/// hands a download to its storage in one or two hops; every hop stays on
/// `https` (the launcher's `proto-redir`).
const MAX_REDIRECTS: u32 = 10;

/// What the checkpoint records when the request carries no digest — a
/// pasted URL, where the file is whatever the server sends.
const UNKNOWN_DIGEST: &str = "sha256:unknown";

/// What to fetch, and what it should turn out to be.
///
/// `expected_size` and `expected_sha256` come from a catalog preset. A
/// pasted URL leaves them `None`: the transfer still happens, the digest is
/// still computed and reported, but there is nothing to check it against
/// and the result is an unverified model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRequest {
    /// Source URL, `https` only, followed through `https` redirects. With a
    /// mirror this is already the mirror's address ([`Self::via_mirror`]).
    pub url: String,
    /// Where the finished file lands. Must not already exist.
    pub dest: PathBuf,
    /// Exact size the finished file must have, when known.
    pub expected_size: Option<u64>,
    /// Lowercase hex SHA-256 the finished file must have, when known.
    pub expected_sha256: Option<String>,
    /// License identifier, hashed into the checkpoint for pam-old
    /// compatibility.
    pub license_id: Option<String>,
}

impl DownloadRequest {
    /// Points the request at `mirror` when its URL is under `upstream_prefix`
    /// (for a catalog preset, `https://huggingface.co/`): the prefix is
    /// replaced by the mirror and the rest of the path is kept, so the same
    /// file is asked for and the expected size and digest stay what the
    /// catalog says. A URL not under the prefix, or no mirror, leaves the
    /// request as it is. The checkpoint records the effective address, so a
    /// partial fetched from upstream is a conflict for a mirror request
    /// rather than a part to glue mirror bytes onto.
    #[must_use]
    pub fn via_mirror(mut self, mirror: Option<&MirrorBase>, upstream_prefix: &str) -> Self {
        if let Some(mirror) = mirror
            && let Ok(upstream) = Url::parse(&self.url)
            && let Some(rebased) = mirror.rebase(&upstream, upstream_prefix)
        {
            self.url = rebased.into();
        }
        self
    }
}

/// A `.gguf` to copy in from a file on this machine, and what it should
/// turn out to be.
///
/// `expected_size` and `expected_sha256` come from the catalog preset the
/// file was matched to, or from a digest the human supplied; `None` means
/// the copy is kept whatever it hashes to and the model is unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRequest {
    /// The file to copy: absolute, a regular file (not a symbolic link),
    /// named `*.gguf`. Never modified, moved or deleted.
    pub source: PathBuf,
    /// Where the copy lands. Must not already exist.
    pub dest: PathBuf,
    /// Exact size the file must have, when known.
    pub expected_size: Option<u64>,
    /// Lowercase hex SHA-256 the copy must have, when known.
    pub expected_sha256: Option<String>,
}

/// Deadlines handed to curl, so a dead transfer ends instead of hanging.
///
/// The defaults are deliberately loose: a model is gigabytes over a link
/// PAM does not control, and a transfer that crawls is still a transfer.
/// What they refuse is a transfer that has stopped — no connection inside
/// [`Self::connect_timeout`], or less than [`Self::min_bytes_per_sec`]
/// sustained across [`Self::stall_window`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferLimits {
    /// How long curl may spend getting a connection.
    pub connect_timeout: Duration,
    /// How long the rate may stay under [`Self::min_bytes_per_sec`]
    /// before the transfer is abandoned. Rounded down to whole seconds:
    /// curl's `--speed-time` takes no finer unit.
    pub stall_window: Duration,
    /// The rate below which a transfer counts as stopped.
    pub min_bytes_per_sec: u64,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            stall_window: Duration::from_mins(1),
            min_bytes_per_sec: 1024,
        }
    }
}

/// Bytes moved so far, and the target when it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct DownloadProgress {
    /// Size of the part file.
    pub bytes: u64,
    /// Expected final size, when the request carried one.
    pub total: Option<u64>,
}

/// Where a transfer is, or how it ended.
///
/// Serialized with an internal `state` tag so the daemon can hand it
/// straight to the GUI as the body of a job row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DownloadState {
    /// curl is running; the part file is this big.
    Running(DownloadProgress),
    /// The file is at its destination and hashes to this.
    Done {
        /// Lowercase hex SHA-256 of the finished file.
        sha256: String,
        /// Its size on disk.
        size_bytes: u64,
    },
    /// The transfer stopped and the file is not there.
    ///
    /// `cause` is one of `curl_missing`, `checkpoint_conflict`,
    /// `digest_mismatch`, `size_mismatch`, `already_exists`, `locked`,
    /// `io`, `lock_release_failed`, or one of the launcher's causes
    /// ([`NetFailure::cause`]: `dns_failed`, `connect_failed`, `timeout`,
    /// `proxy_auth_required`, `tls_untrusted_issuer`, …). Every one has a
    /// line in [`failure_recovery`].
    Failed {
        /// Machine-readable cause the daemon maps to a recovery sentence.
        cause: String,
        /// What actually happened: the launcher's sentence, or this
        /// module's own.
        detail: String,
    },
    /// The human stopped it. The part file is kept for a resume.
    Cancelled,
}

impl DownloadState {
    /// Whether this state is the last one this transfer will publish.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, DownloadState::Running(_))
    }

    /// A failure with the given cause and detail.
    fn failed(cause: &str, detail: impl Into<String>) -> Self {
        DownloadState::Failed {
            cause: cause.to_owned(),
            detail: detail.into(),
        }
    }
}

/// Everything [`start`] refuses before a transfer exists.
///
/// Once a transfer is running its failures arrive as
/// [`DownloadState::Failed`] instead — by then there is a job to attach
/// them to.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// No trusted operating-system `curl`. See [`curl_recovery_line`].
    #[error("the operating-system curl is not available")]
    CurlMissing,

    /// The URL is not `https://` with a host: anything else (`http://`,
    /// `file://`, `ftp://`, a string starting with `-`) is refused before
    /// curl sees it.
    #[error("{0:?} is not an https URL; only https addresses are downloaded")]
    InvalidUrl(String),

    /// The launcher refused before any transfer existed: the network
    /// settings cannot be used, the trusted curl is too old for them, or a
    /// path cannot be handed to curl. Never answered by a direct connection.
    #[error("{0}")]
    Network(NetFailure),

    /// The destination file is already there. PAM never overwrites weights.
    #[error("{0:?} already exists")]
    AlreadyExists(PathBuf),

    /// Another download of this file holds the lock.
    #[error("{0:?} is locked by another download")]
    Locked(PathBuf),

    /// The part file on disk was started for a different URL or digest.
    #[error("checkpoint conflict: {0}")]
    CheckpointConflict(String),

    /// A filesystem call failed while setting the transfer up.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The file an import names does not exist or cannot be read.
    #[error("{0:?} does not exist or cannot be read")]
    ImportSourceMissing(PathBuf),

    /// The file an import names is not one PAM copies: a symbolic link,
    /// not a regular file, not a `.gguf`, or already inside the models
    /// directory.
    #[error("{path:?} was not imported: {reason}")]
    ImportSourceRefused {
        /// The path as given.
        path: PathBuf,
        /// Which rule refused it.
        reason: String,
    },

    /// The volume holding the models directory cannot take the copy.
    #[error(
        "not enough disk space under {dir} for the copy: {needed} bytes needed, {} free",
        free.map_or_else(|| "an unknown amount".to_owned(), |bytes| format!("{bytes} bytes"))
    )]
    NoSpace {
        /// The directory the copy would land in.
        dir: PathBuf,
        /// Bytes the copy needs, headroom included.
        needed: u64,
        /// Bytes free there, when known.
        free: Option<u64>,
    },
}

/// The three sidecar paths for a destination file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarPaths {
    /// `.<file>.pam-model.part` — bytes received so far.
    pub part: PathBuf,
    /// `.<file>.pam-model.json` — the [`Checkpoint`].
    pub checkpoint: PathBuf,
    /// `.<file>.pam-model.lock` — held for the life of the transfer.
    pub lock: PathBuf,
}

/// What a part file is, written beside it.
///
/// Field names and types are pam-old's. `expected_size_bytes` is `0` rather
/// than absent when the size is unknown, and `expected_digest` is
/// `"sha256:unknown"` rather than null, because that is what the existing
/// files on the owner's disk contain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Always `1`.
    pub schema_version: u32,
    /// The URL these bytes came from.
    pub canonical_source: String,
    /// `"sha256:<hex>"`, or `"sha256:unknown"`.
    pub expected_digest: String,
    /// Expected final size, `0` when unknown.
    pub expected_size_bytes: u64,
    /// SHA-256 of the license identifier string. Compatibility only.
    pub license_digest: String,
    /// Last `ETag` the server sent, when it sent one.
    pub etag: Option<String>,
}

impl Checkpoint {
    /// The checkpoint a request wants to see on disk.
    fn for_request(request: &DownloadRequest) -> Self {
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            canonical_source: request.url.clone(),
            expected_digest: request.expected_sha256.as_ref().map_or_else(
                || UNKNOWN_DIGEST.to_owned(),
                |digest| format!("sha256:{digest}"),
            ),
            expected_size_bytes: request.expected_size.unwrap_or(0),
            license_digest: hex::encode(Sha256::digest(
                request.license_id.as_deref().unwrap_or_default().as_bytes(),
            )),
            etag: None,
        }
    }

    /// Refuses a part file that was started for something else.
    ///
    /// Only the source and the digest are compared: those are the two
    /// facts that decide what the accumulated bytes mean. A license id that
    /// changed between releases is not a reason to re-fetch 18 GB.
    fn check_against(&self, wanted: &Self) -> Result<(), DownloadError> {
        if self.canonical_source != wanted.canonical_source {
            return Err(DownloadError::CheckpointConflict(format!(
                "the partial download came from {} but this request is for {}",
                self.canonical_source, wanted.canonical_source
            )));
        }
        if self.expected_digest != wanted.expected_digest {
            return Err(DownloadError::CheckpointConflict(format!(
                "the partial download expects {} but this request expects {}",
                self.expected_digest, wanted.expected_digest
            )));
        }
        Ok(())
    }
}

/// A running transfer: progress out, cancellation in.
///
/// Cloning it is cheap and shares one transfer — the daemon keeps a handle
/// per job and hands clones to whoever asks about it. Dropping every handle
/// does not stop the download; only [`DownloadHandle::cancel`] does.
#[derive(Debug, Clone)]
pub struct DownloadHandle {
    state: watch::Receiver<DownloadState>,
    cancel: Arc<watch::Sender<bool>>,
}

impl DownloadHandle {
    /// The transfer's state right now, without waiting.
    #[must_use]
    pub fn state(&self) -> DownloadState {
        self.state.borrow().clone()
    }

    /// Kills curl. The part file stays, so the next [`start`] resumes.
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }

    /// Waits for the terminal state.
    ///
    /// Safe to call from several places at once and after the fact: it
    /// reads the last published state first, so a caller that arrives late
    /// gets the verdict rather than hanging.
    pub async fn wait(&self) -> DownloadState {
        let mut states = self.state.clone();
        loop {
            let current = states.borrow_and_update().clone();
            if current.is_terminal() {
                return current;
            }
            if states.changed().await.is_err() {
                return states.borrow().clone();
            }
        }
    }
}

/// The sidecar paths beside `dest`.
///
/// Hidden and prefixed with the model's own file name, so a vendor
/// directory holding several models never collides and a registry scan —
/// which skips dotfiles — never lists a half-downloaded file as a model.
#[must_use]
pub fn sidecar_paths(dest: &Path) -> SidecarPaths {
    let name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    SidecarPaths {
        part: parent.join(format!(".{name}.pam-model.part")),
        checkpoint: parent.join(format!(".{name}.pam-model.json")),
        lock: parent.join(format!(".{name}.pam-model.lock")),
    }
}

/// What is sitting on disk for a transfer that never finished.
///
/// A partial is invisible to the registry — the sidecars are dotfiles and
/// a scan skips them — so this is the only way anyone learns that 12 GB of
/// a model is already here, or that the bytes came from a URL the current
/// request disagrees with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PartialDownload {
    /// Bytes in the part file.
    pub bytes: u64,
    /// The URL those bytes came from, when a checkpoint is readable.
    pub source: Option<String>,
    /// The digest the checkpoint expects, `sha256:<hex>` or
    /// `sha256:unknown`.
    pub expected_digest: Option<String>,
    /// Whether a transfer is holding the lock right now.
    pub locked: bool,
}

/// What a partial for `dest` looks like, or `None` when there is none.
///
/// A lock file with no part file is not a partial: [`start`] creates the
/// lock before curl writes a byte, and a crash can leave it behind.
#[must_use]
pub fn inspect_partial(dest: &Path) -> Option<PartialDownload> {
    let paths = sidecar_paths(dest);
    if !paths.part.exists() {
        return None;
    }
    let checkpoint = read_checkpoint(&paths.checkpoint);
    Some(PartialDownload {
        bytes: file_size(&paths.part),
        source: checkpoint
            .as_ref()
            .map(|point| point.canonical_source.clone()),
        expected_digest: checkpoint.map(|point| point.expected_digest),
        locked: is_locked(&paths.lock),
    })
}

/// Deletes the partial download beside `dest` and returns the bytes it
/// threw away.
///
/// This is the way out of a [`DownloadError::CheckpointConflict`], and the
/// way to start a transfer over rather than resume it. A running transfer
/// holds the lock, and its bytes are not something to delete from under
/// it: that is [`DownloadError::Locked`], and the caller is told to cancel
/// first.
///
/// The lock file goes too. It carries no state — it exists to be locked —
/// and leaving it behind would litter the vendor directory with a dotfile
/// per abandoned download.
pub fn discard_partial(dest: &Path) -> Result<u64, DownloadError> {
    let paths = sidecar_paths(dest);
    // Taking the lock is how "is anyone downloading this" is asked
    // everywhere else; holding it across the deletes keeps a transfer from
    // starting between the check and the unlink.
    let lock = acquire_lock(&paths.lock)?;
    let bytes = file_size(&paths.part);
    remove_if_present(&paths.part)?;
    remove_if_present(&paths.checkpoint)?;
    remove_if_present(&etag_path(&paths.checkpoint))?;
    // The lock file is unlinked while the lock is still held: a transfer
    // that opens the path in this window either gets the old inode (and
    // blocks on our lock until we release, then finds no part file) or a
    // fresh one after the unlink. Releasing first would let a second
    // transfer lock the old inode just before it disappears, after which a
    // third could lock a new one — two writers on one part file.
    remove_if_present(&paths.lock)?;
    release_lock(lock);
    Ok(bytes)
}

/// Reconciles the on-disk checkpoint with `wanted`: a foreign checkpoint is a
/// conflict, a matching one lends its etag, and the result is written back.
fn admit_checkpoint(paths: &SidecarPaths, wanted: &mut Checkpoint) -> Result<(), DownloadError> {
    if let Some(existing) = read_checkpoint(&paths.checkpoint) {
        existing.check_against(wanted)?;
        wanted.etag = existing.etag;
    }
    write_checkpoint(&paths.checkpoint, wanted)?;
    Ok(())
}

/// Gives the transfer lock back explicitly before the handle closes.
///
/// Closing alone releases the lock only when this is the last reference to
/// the open file description; a child forked by another task between our
/// open and its exec holds a duplicate until then, and `flock` follows the
/// description, not the handle. An explicit unlock applies to the whole
/// description, so the next `acquire_lock` never sees a ghost holder.
pub(crate) fn release_lock(lock: File) {
    let _ = lock.unlock();
    drop(lock);
}

/// Whether another process or task holds the transfer lock.
pub(crate) fn is_locked(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new()
        .create(false)
        .write(true)
        .truncate(false)
        .open(path)
    else {
        return false;
    };
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(std::fs::TryLockError::WouldBlock) => true,
        // An unreadable lock is not evidence of a transfer.
        Err(std::fs::TryLockError::Error(_)) => false,
    }
}

/// Removes `path`, treating "it was not there" as success.
fn remove_if_present(path: &Path) -> Result<(), DownloadError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DownloadError::Io(error)),
    }
}

/// The operating system's own `curl`, as the launcher verifies it.
///
/// Never a `PATH` lookup: on macOS `/usr/bin/curl`, canonicalized,
/// executable, with every ancestor root-owned and not group- or
/// world-writable; on Windows `%SystemRoot%\System32\curl.exe`,
/// canonicalized inside `System32`. The check is `pam_net`'s, shared with
/// the connector transport; an absent or untrustworthy curl is
/// [`DownloadError::CurlMissing`]. The GUI asks every time it draws the
/// catalog; the path check is a few `stat`s and the version probe behind it
/// runs once per process.
pub fn curl_path() -> Result<PathBuf, DownloadError> {
    TrustedCurl::resolve()
        .map(|curl| curl.path().to_path_buf())
        .map_err(launcher_refusal)
}

/// Whether `url` is something curl may be pointed at: an `https://` URL with
/// a host, no user information and no control character. The scheme check is
/// what keeps a pasted `file:///etc/passwd`, `ftp://…`, `-K/tmp/x` or a plain
/// `http://` address out of curl's hands; the launcher refuses the same
/// things again when it writes the config, so this is the first of two
/// fences, not the only one.
pub fn check_url(url: &str) -> Result<Url, DownloadError> {
    check_url_with(url, false)
}

/// [`check_url`], with plain `http` admitted when `plain_http` is set.
fn check_url_with(url: &str, plain_http: bool) -> Result<Url, DownloadError> {
    let refuse = || DownloadError::InvalidUrl(url.to_owned());
    if url.chars().any(char::is_control) {
        return Err(refuse());
    }
    // The text must name its host right after the scheme: the URL parser
    // would quietly read `https:///host` as `https://host/`, and an address
    // that needs repairing is not one to fetch.
    let host_starts_plainly = url.split_once("://").is_some_and(|(_, rest)| {
        rest.chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric() || first == '[')
    });
    if !host_starts_plainly {
        return Err(refuse());
    }
    let parsed = Url::parse(url).map_err(|_| refuse())?;
    let scheme_ok = parsed.scheme() == "https" || (plain_http && parsed.scheme() == "http");
    if !scheme_ok
        || parsed.host_str().is_none_or(str::is_empty)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(refuse());
    }
    Ok(parsed)
}

/// How to get curl on this platform, in one sentence.
#[must_use]
pub fn curl_recovery_line() -> &'static str {
    pam_net::curl_install_line()
}

/// What a launcher failure before any transfer is, as this module's error.
fn launcher_refusal(failure: NetFailure) -> DownloadError {
    match failure {
        NetFailure::CurlUnavailable => DownloadError::CurlMissing,
        other => DownloadError::Network(other),
    }
}

/// The one sentence that tells a human what to do about `cause`.
///
/// Covers every cause a download can end with, transport or not, so the
/// daemon has a single lookup to attach to a failed job row — the same
/// shape as an admin refusal's `recovery`.
#[must_use]
pub fn failure_recovery(cause: &str) -> &'static str {
    match cause {
        "curl_missing" | "curl_unavailable" => curl_recovery_line(),
        "disk_error" | "io" => {
            "Writing to the models directory failed; check free space and permissions, then \
             download again."
        }
        "digest_mismatch" => {
            "The finished file did not match the catalog digest and was removed; download again, \
             and report it if it happens twice."
        }
        "size_mismatch" => {
            "The transfer ended at the wrong size; discard the partial download and start it over."
        }
        "checkpoint_conflict" => {
            "The partial file on disk came from a different source; discard it, then download again."
        }
        "already_exists" => {
            "Those weights are already in the models directory; delete them first to refetch."
        }
        "locked" => "Another transfer is writing that file; cancel it first.",
        "lock_release_failed" => {
            "Inspect the installed file and current transfer state before retrying; the transfer ended but releasing its lock failed."
        }
        "verify_failed" => {
            "The digest run could not finish; check the file is readable and still there, then \
             verify again."
        }
        "no_space" => {
            "Verifying keeps PAM's own copy of the weights under its base directory, and that \
             volume has no room for one. Free the bytes named in the detail there, or keep the \
             models directory on the same APFS volume as PAM's base so the copy shares its \
             blocks, then verify again."
        }
        "model_changed" => {
            "The file changed while it was being verified; wait for whatever is writing it, \
             then verify again."
        }
        "daemon_restart" => {
            "The daemon restarted while this transfer ran; the partial file is kept, so download \
             again to resume."
        }
        network => network_recovery(network),
    }
}

/// [`failure_recovery`] for the causes the launcher answers
/// ([`NetFailure::cause`]): the path to the host, the certificate, the
/// transfer itself.
fn network_recovery(cause: &str) -> &'static str {
    match cause {
        "curl_too_old" => {
            "Update the operating system so its curl is current, or remove the network setting \
             that needs the newer version, then download again."
        }
        "network_settings_invalid" => {
            "Open Settings › Network, correct the setting named in the detail and save, then \
             download again."
        }
        "network_ca_tampered" | "ca_bundle_unreadable" => {
            "Re-import the CA bundle in Settings › Network, then download again."
        }
        "request_invalid" => {
            "Correct the address or the models directory named in the detail; nothing was sent."
        }
        "curl_spawn_failed" => "Check that this computer can start programs, then download again.",
        "proxy_dns_failed" => {
            "The proxy's name did not resolve; check the proxy address in Settings › Network and \
             this computer's DNS or VPN, then download again."
        }
        "proxy_unreachable" => {
            "Nothing answered at the proxy; check its host and port in Settings › Network and that \
             this computer is on the network it serves, then download again."
        }
        "proxy_auth_required" => {
            "The proxy wants a sign-in; set the proxy sign-in mode, user name and password in \
             Settings › Network, then download again."
        }
        "proxy_auth_rejected" => {
            "The proxy refused the stored sign-in; re-enter the proxy user name and password in \
             Settings › Network, then download again."
        }
        "proxy_denied" => {
            "The proxy refused to connect to the download host; ask its administrator to allow it, \
             or set a mirror in Settings › Network."
        }
        "dns_failed" => {
            "The download host did not resolve; check DNS and any VPN, and if the name only \
             resolves through the proxy, take it off the no-proxy list; then download again."
        }
        "connect_failed" | "connect_timeout" => {
            "Nothing accepted the connection; if this network only reaches the download host \
             through a proxy, set one in Settings › Network, then download again."
        }
        "timeout" | "deadline" => {
            "The transfer stopped moving and was abandoned; the partial file is kept, so download \
             again to resume from where it stopped."
        }
        "http_error" => {
            "The server refused the request — the detail carries the status. A gated model needs \
             its licence accepted on the source site first; a mirror must serve the same path."
        }
        "tls_untrusted_issuer" => {
            "The download host's certificate is not trusted; if your organisation inspects TLS, \
             import its root CA in Settings › Network, then download again."
        }
        "tls_hostname_mismatch" => {
            "The certificate presented is for another name; check the address and any proxy \
             that inspects TLS, then download again."
        }
        "tls_expired" => {
            "The certificate has expired or is not yet valid; check this computer's clock, then \
             download again."
        }
        "tls_revocation_unavailable" => {
            "Windows could not check the certificate's revocation list; publish the CA's CRL \
             over http or install the CA in the operating system's certificate store, then \
             download again."
        }
        "tls_error" => {
            "The TLS handshake failed; check the system clock and any inspecting proxy, then \
             download again."
        }
        "too_large" => {
            "The server sent more than the transfer may hold; check the address and download again."
        }
        "curl_failed" => {
            "Read the detail; run Test network settings in Settings › Network to see where the \
             transfer stops. The partial file is kept, so downloading again resumes it."
        }
        "transfer_interrupted" => {
            "The connection dropped mid-transfer; the partial file is kept, so download again to \
             resume."
        }
        "resume_unsupported" => {
            "The server would not continue from the partial file; discard the partial download and \
             start it over."
        }
        "disk_error" => {
            "Writing to the models directory failed; check free space and permissions, then \
             download again."
        }
        _ => "Read the detail; the partial file is kept, so downloading again resumes it.",
    }
}

/// Starts a transfer under `net` and returns immediately.
///
/// `net` is the network profile the caller resolved for this transfer —
/// proxy, no-proxy list, CA bundle — the only place curl learns any of it.
/// Everything that can be refused up front is refused here, synchronously,
/// so the caller learns about a missing curl, a plain-http address or an
/// occupied destination before a job row exists. Needs a tokio runtime: the
/// transfer runs as a spawned task.
pub fn start(
    request: DownloadRequest,
    net: Arc<NetSettings>,
) -> Result<DownloadHandle, DownloadError> {
    start_with_limits(request, net, TransferLimits::default())
}

/// [`start`], with the stall and connect deadlines spelled out.
///
/// Production takes [`TransferLimits::default`] through [`start`]; this
/// exists so the suite can prove a stalled transfer dies without waiting
/// a minute for it.
pub fn start_with_limits(
    request: DownloadRequest,
    net: Arc<NetSettings>,
    limits: TransferLimits,
) -> Result<DownloadHandle, DownloadError> {
    start_inner(request, net, limits, false)
}

/// [`start_with_limits`] for a plain-`http` loopback origin.
///
/// The test allowance, and the only way an `http://` address reaches curl:
/// the download suite and the daemon's own tests drive real curl against a
/// range-serving `TcpListener` that speaks no TLS. It exists only in test
/// builds and behind the `testing` feature, which no shipped binary turns
/// on; production goes through [`start`] and refuses `http://`.
#[cfg(any(test, feature = "testing"))]
pub fn start_over_plain_http_for_tests(
    request: DownloadRequest,
    net: Arc<NetSettings>,
    limits: TransferLimits,
) -> Result<DownloadHandle, DownloadError> {
    start_inner(request, net, limits, true)
}

fn start_inner(
    mut request: DownloadRequest,
    net: Arc<NetSettings>,
    limits: TransferLimits,
    plain_http: bool,
) -> Result<DownloadHandle, DownloadError> {
    let url = check_url_with(&request.url, plain_http)?;
    let curl = TrustedCurl::resolve().map_err(launcher_refusal)?;
    if request.dest.exists() {
        return Err(DownloadError::AlreadyExists(request.dest.clone()));
    }
    // curl runs at the filesystem root and is handed absolute paths only;
    // a relative models directory is resolved here, once, against the
    // daemon's own working directory.
    request.dest = std::path::absolute(&request.dest)?;
    if let Some(parent) = request.dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let paths = sidecar_paths(&request.dest);
    let lock = acquire_lock(&paths.lock)?;

    let mut wanted = Checkpoint::for_request(&request);
    if let Err(error) = admit_checkpoint(&paths, &mut wanted) {
        // Refusing is not the same as finishing: unlock explicitly, as
        // `publish_terminal` does, so a descriptor a concurrent fork inherited
        // cannot keep the lock alive past this return.
        release_lock(lock);
        return Err(error);
    }

    let (state, states) = watch::channel(DownloadState::Running(DownloadProgress {
        bytes: file_size(&paths.part),
        total: request.expected_size,
    }));
    let (cancel, cancelled) = watch::channel(false);

    let job = Job {
        etag_file: etag_path(&paths.checkpoint),
        request,
        url,
        net,
        paths,
        curl,
        limits,
        plain_http,
        state,
        _lock: lock,
    };
    tokio::spawn(run(job, cancelled));

    Ok(DownloadHandle {
        state: states,
        cancel: Arc::new(cancel),
    })
}

/// Copies a `.gguf` in from a file on this machine and returns at once.
///
/// Everything that can be refused up front is refused here, synchronously:
/// a source that is missing, a symbolic link, not a regular file, not a
/// `.gguf`, or inside the models directory; an occupied destination; a
/// transfer holding the destination's lock; a partial download beside it
/// (an import never glues onto downloaded bytes: discard the partial
/// first); a volume without room for the copy. The copy then runs off the
/// async threads through the same part file and link-into-place as a
/// download, hashed as it is written, with the same [`DownloadHandle`].
/// A cancel or a failure deletes the partial copy: an import starts over,
/// it does not resume. Needs a tokio runtime.
pub fn start_import(request: ImportRequest) -> Result<DownloadHandle, DownloadError> {
    let request = ImportRequest {
        source: request.source,
        dest: std::path::absolute(&request.dest)?,
        expected_size: request.expected_size,
        expected_sha256: request.expected_sha256,
    };
    let size = check_import_source(&request.source, &request.dest)?;
    if request.dest.exists() {
        return Err(DownloadError::AlreadyExists(request.dest.clone()));
    }
    let parent = request
        .dest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    std::fs::create_dir_all(&parent)?;
    let paths = sidecar_paths(&request.dest);
    let lock = acquire_lock(&paths.lock)?;
    if paths.part.exists() || paths.checkpoint.exists() {
        release_lock(lock);
        return Err(DownloadError::CheckpointConflict(format!(
            "a partial download of {} is on disk; discard it before importing a file over it",
            request.dest.display()
        )));
    }
    let needed = size.saturating_add(FREE_SPACE_HEADROOM_BYTES);
    let free = platform_free_bytes(&parent);
    if free.is_some_and(|free| free < needed) {
        release_lock(lock);
        return Err(DownloadError::NoSpace {
            dir: parent,
            needed,
            free,
        });
    }
    let total = request.expected_size.or(Some(size));
    let (state, states) =
        watch::channel(DownloadState::Running(DownloadProgress { bytes: 0, total }));
    let (cancel, cancelled) = watch::channel(false);
    tokio::spawn(run_import(request, paths, lock, total, state, cancelled));
    Ok(DownloadHandle {
        state: states,
        cancel: Arc::new(cancel),
    })
}

/// The import source's rules, and its size when it passes them.
fn check_import_source(source: &Path, dest: &Path) -> Result<u64, DownloadError> {
    let refuse = |reason: String| DownloadError::ImportSourceRefused {
        path: source.to_path_buf(),
        reason,
    };
    if !source.is_absolute() {
        return Err(refuse("the path must be absolute".to_owned()));
    }
    let meta = std::fs::symlink_metadata(source)
        .map_err(|_| DownloadError::ImportSourceMissing(source.to_path_buf()))?;
    if meta.file_type().is_symlink() {
        return Err(refuse(
            "it is a symbolic link; give the path of the file itself".to_owned(),
        ));
    }
    if !meta.is_file() {
        return Err(refuse("it is not a regular file".to_owned()));
    }
    if !source
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("gguf"))
    {
        return Err(refuse("only .gguf files are imported".to_owned()));
    }
    // The models directory is where the copy lands; a file already there is
    // a model already, and copying it onto itself would be absurd.
    if let (Ok(real), Some(models_dir)) =
        (source.canonicalize(), dest.parent().and_then(Path::parent))
        && models_dir
            .canonicalize()
            .is_ok_and(|models_dir| real.starts_with(models_dir))
    {
        return Err(refuse(
            "it is already inside the models directory".to_owned(),
        ));
    }
    Ok(meta.len())
}

/// Runs an import to its terminal state and publishes it.
async fn run_import(
    request: ImportRequest,
    paths: SidecarPaths,
    lock: File,
    total: Option<u64>,
    state: watch::Sender<DownloadState>,
    mut cancelled: watch::Receiver<bool>,
) {
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let copy = {
        let source = request.source.clone();
        let part = paths.part.clone();
        let done = Arc::clone(&done);
        let stop = Arc::clone(&stop);
        tokio::task::spawn_blocking(move || {
            let control = Control {
                progress: &|bytes| done.store(bytes, Ordering::Relaxed),
                cancelled: &|| stop.load(Ordering::Acquire),
            };
            crate::weights::copy_hashing(&source, &part, &control)
        })
    };
    tokio::pin!(copy);
    let mut ticker = tokio::time::interval(PROGRESS_POLL);
    let mut watching = true;
    let copied = loop {
        tokio::select! {
            finished = &mut copy => break finished,
            changed = cancelled.changed(), if watching => match changed {
                Ok(()) if *cancelled.borrow() => stop.store(true, Ordering::Release),
                Ok(()) => {}
                // Every handle was dropped: nobody is left to cancel.
                Err(_) => watching = false,
            },
            _ = ticker.tick() => {
                let _ = state.send(DownloadState::Running(DownloadProgress {
                    bytes: done.load(Ordering::Relaxed),
                    total,
                }));
            }
        }
    };
    let terminal = match copied {
        Ok(Ok((sha256, size_bytes))) => finish_import(&request, &paths, sha256, size_bytes),
        Ok(Err(WeightsError::Cancelled)) => DownloadState::Cancelled,
        Ok(Err(WeightsError::NoSpace { needed, free, .. })) => DownloadState::failed(
            "no_space",
            format!(
                "the copy needs {needed} bytes and the volume has {}",
                free.map_or_else(|| "an unknown amount".to_owned(), |b| format!("{b} bytes"))
            ),
        ),
        // Windows has no free-space probe, so a full volume shows up here
        // rather than in the pre-check; it gets the same name either way.
        Ok(Err(WeightsError::Io(error)))
            if matches!(
                error.kind(),
                std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
            ) =>
        {
            DownloadState::failed(
                "no_space",
                format!("the volume holding the models directory filled up: {error}"),
            )
        }
        Ok(Err(WeightsError::Io(error))) => {
            DownloadState::failed("io", format!("copying the file failed: {error}"))
        }
        Err(error) => DownloadState::failed("io", format!("the copy task panicked: {error}")),
    };
    // Whatever the verdict, no partial copy is left: an import is never
    // resumed, and the sidecars would otherwise read as a partial download.
    let _ = std::fs::remove_file(&paths.part);
    let _ = std::fs::remove_file(&paths.lock);
    publish_terminal(&state, lock, terminal);
}

/// Checks the finished copy against the request and links it into place.
fn finish_import(
    request: &ImportRequest,
    paths: &SidecarPaths,
    sha256: String,
    size_bytes: u64,
) -> DownloadState {
    if let Some(expected) = request.expected_size
        && size_bytes != expected
    {
        return DownloadState::failed(
            "size_mismatch",
            format!("expected {expected} bytes, the file holds {size_bytes}"),
        );
    }
    if let Some(expected) = &request.expected_sha256
        && expected != &sha256
    {
        return DownloadState::failed(
            "digest_mismatch",
            format!("expected sha256:{expected}, the file hashes to sha256:{sha256}"),
        );
    }
    if let Err(state) = link_into_place(&paths.part, &request.dest) {
        return state;
    }
    DownloadState::Done { sha256, size_bytes }
}

/// One transfer's owned state, moved into the spawned task.
struct Job {
    request: DownloadRequest,
    /// `request.url`, parsed and admitted by [`check_url`].
    url: Url,
    /// The network profile every curl run of this transfer uses.
    net: Arc<NetSettings>,
    paths: SidecarPaths,
    curl: TrustedCurl,
    etag_file: PathBuf,
    limits: TransferLimits,
    /// Whether the test allowance admitted a plain-`http` address; always
    /// `false` for a transfer started through [`start`].
    plain_http: bool,
    state: watch::Sender<DownloadState>,
    /// Held, not read: dropping it releases the advisory lock.
    _lock: File,
}

/// How the curl process ended.
enum CurlOutcome {
    /// Exit 0. The part file is complete, as far as curl knows.
    Completed,
    /// The human cancelled; curl was killed.
    Cancelled,
    /// curl refused or the transfer broke.
    Failed { cause: String, detail: String },
}

/// Runs a transfer to its terminal state and publishes it.
async fn run(job: Job, cancelled: watch::Receiver<bool>) {
    let terminal = job.execute(cancelled).await;
    let Job {
        state, _lock: lock, ..
    } = job;
    publish_terminal(&state, lock, terminal);
}

/// A terminal observer may resume or discard immediately. Explicitly unlock:
/// closing alone can leave an inherited/duplicated file description holding the
/// lock until its last reference closes (including a concurrent fork before exec).
pub(crate) fn publish_terminal(
    state: &watch::Sender<DownloadState>,
    lock: File,
    terminal: DownloadState,
) {
    let terminal = match lock.unlock() {
        Ok(()) => terminal,
        Err(error) => DownloadState::failed(
            "lock_release_failed",
            format!("could not release the transfer lock: {error}"),
        ),
    };
    drop(lock);
    let _ = state.send(terminal);
}

impl Job {
    /// Spawns curl, drives it, and verifies whatever it left behind.
    ///
    /// A resume carries the checkpoint's `ETag` as `If-Range`. When the
    /// server's file has changed it ignores the range and answers `200`
    /// with the whole body, which curl refuses as an unresumable transfer
    /// (exit 33) after saving the new `ETag`. That exact shape — a resume
    /// refused, and a different `ETag` than the one sent — means the old
    /// bytes belong to another file: the part is discarded and curl runs
    /// once more from zero. Any other refusal is reported as it is.
    async fn execute(&self, cancelled: watch::Receiver<bool>) -> DownloadState {
        let mut resume_etag = self.resume_etag();
        loop {
            let child = match self.curl_request(resume_etag.as_deref()).spawn().await {
                Ok(child) => child,
                Err(failure) => {
                    return DownloadState::failed(failure.cause(), failure.sentence());
                }
            };

            let outcome = self.drive(child, cancelled.clone()).await;
            let server_etag = self.saved_etag();
            self.absorb_etag();
            return match outcome {
                CurlOutcome::Cancelled => DownloadState::Cancelled,
                CurlOutcome::Failed { cause, detail } => {
                    if cause == "resume_unsupported"
                        && let Some(sent) = resume_etag.take()
                        && server_etag.is_some_and(|fresh| fresh != sent)
                        && self.restart_from_zero()
                    {
                        continue;
                    }
                    DownloadState::Failed { cause, detail }
                }
                CurlOutcome::Completed => self.finish().await,
            };
        }
    }

    /// The `ETag` a resume should send: the checkpoint's, and only when
    /// there are bytes to resume from.
    fn resume_etag(&self) -> Option<String> {
        if file_size(&self.paths.part) == 0 {
            return None;
        }
        read_checkpoint(&self.paths.checkpoint)?.etag
    }

    /// The `ETag` curl saved from the last response, if it saved one.
    fn saved_etag(&self) -> Option<String> {
        let etag = std::fs::read_to_string(&self.etag_file).ok()?;
        let etag = etag.trim();
        (!etag.is_empty()).then(|| etag.to_owned())
    }

    /// Throws the part file away so the next curl run starts at byte zero,
    /// and forgets the checkpoint's `ETag` so nothing is sent as `If-Range`.
    /// Answers whether the disk agreed.
    fn restart_from_zero(&self) -> bool {
        if std::fs::remove_file(&self.paths.part).is_err() {
            return false;
        }
        let Some(mut checkpoint) = read_checkpoint(&self.paths.checkpoint) else {
            return false;
        };
        checkpoint.etag = None;
        write_checkpoint(&self.paths.checkpoint, &checkpoint).is_ok()
    }

    /// The one curl invocation PAM makes, as the launcher is asked for it.
    ///
    /// `fail` turns an HTTP error status into a nonzero exit instead of a
    /// saved error page; `location` with `proto-redir` keeps the request
    /// and every redirect on `https`; `continue-at -` resumes from whatever
    /// is in the part file, with `If-Range` when the checkpoint knows what
    /// those bytes belong to; `retry 0` keeps retry policy here rather than
    /// inside curl, where PAM cannot report it. The connect timeout and the
    /// speed floor come from [`TransferLimits`] and are the difference
    /// between a failed download and a hung one. The proxy, the no-proxy
    /// list and the CA bundle are the profile's; the argument vector, the
    /// environment and the escaping are the launcher's.
    fn curl_request(&self, if_range: Option<&str>) -> CurlRequest<'_> {
        let mut request = self
            .curl
            .request(&self.net, &self.url)
            .fail_on_http_error()
            .follow_https_redirects(MAX_REDIRECTS)
            .connect_timeout(self.limits.connect_timeout.as_secs())
            // `speed-time` counts whole seconds, and 0 would disable the
            // check entirely; a sub-second window becomes one second rather
            // than no window at all (the launcher's own floor).
            .stall_limit(
                self.limits.min_bytes_per_sec,
                self.limits.stall_window.as_secs(),
            )
            .output(&self.paths.part)
            .etag_save(&self.etag_file)
            .resume();
        if let Some(etag) = if_range {
            request = request.header("If-Range", etag);
        }
        #[cfg(any(test, feature = "testing"))]
        if self.plain_http {
            request = request.allow_http_for_tests();
        }
        #[cfg(not(any(test, feature = "testing")))]
        let _ = self.plain_http;
        request
    }

    /// Waits for curl while publishing progress and watching for a cancel.
    async fn drive(
        &self,
        mut child: CurlChild,
        mut cancelled: watch::Receiver<bool>,
    ) -> CurlOutcome {
        let mut ticker = tokio::time::interval(PROGRESS_POLL);
        let mut watching = true;
        loop {
            tokio::select! {
                // Cancel-safe: a lost arm loses nothing, and the next call
                // carries on draining the same pipes.
                finished = child.wait() => return match finished {
                    Ok(_) => CurlOutcome::Completed,
                    Err(failure) => CurlOutcome::Failed {
                        cause: failure.cause().to_owned(),
                        detail: failure.sentence(),
                    },
                },
                changed = cancelled.changed(), if watching => match changed {
                    Ok(()) if *cancelled.borrow() => {
                        child.kill().await;
                        return CurlOutcome::Cancelled;
                    }
                    Ok(()) => {}
                    // Every handle was dropped: nobody is left to cancel.
                    Err(_) => watching = false,
                },
                _ = ticker.tick() => self.publish_progress(),
            }
        }
    }

    /// Checks what curl produced, and installs it if it holds up.
    async fn finish(&self) -> DownloadState {
        let size_bytes = file_size(&self.paths.part);
        if let Some(expected) = self.request.expected_size
            && size_bytes != expected
        {
            return DownloadState::failed(
                "size_mismatch",
                format!("expected {expected} bytes, the transfer produced {size_bytes}"),
            );
        }

        let part = self.paths.part.clone();
        let hashed = tokio::task::spawn_blocking(move || sha256_file(&part)).await;
        let sha256 = match hashed {
            Ok(Ok((sha256, _))) => sha256,
            Ok(Err(error)) => {
                return DownloadState::failed("io", format!("hashing failed: {error}"));
            }
            Err(error) => return DownloadState::failed("io", format!("hashing panicked: {error}")),
        };

        if let Some(expected) = &self.request.expected_sha256
            && expected != &sha256
        {
            let _ = std::fs::remove_file(&self.paths.part);
            return DownloadState::failed(
                "digest_mismatch",
                format!("expected sha256:{expected}, the transfer produced sha256:{sha256}"),
            );
        }

        if let Err(state) = self.install() {
            return state;
        }
        DownloadState::Done { sha256, size_bytes }
    }

    /// Moves the part file into place and clears the sidecars.
    fn install(&self) -> Result<(), DownloadState> {
        link_into_place(&self.paths.part, &self.request.dest)?;
        // No verification is recorded here: the downloader runs where the models directory
        // is, and a record written there is forgeable by whoever can write that directory.
        // The caller records it in its private trust store (`Registry::record_verified`)
        // once it sees `DownloadState::Done` for a request that carried an expected digest.

        let _ = std::fs::remove_file(&self.paths.checkpoint);
        let _ = std::fs::remove_file(&self.etag_file);
        let _ = std::fs::remove_file(&self.paths.lock);
        Ok(())
    }

    /// Publishes the part file's current size.
    fn publish_progress(&self) {
        let _ = self.state.send(DownloadState::Running(DownloadProgress {
            bytes: file_size(&self.paths.part),
            total: self.request.expected_size,
        }));
    }

    /// Folds curl's saved `ETag` into the checkpoint, so a resume carries it.
    fn absorb_etag(&self) {
        let Ok(etag) = std::fs::read_to_string(&self.etag_file) else {
            return;
        };
        let etag = etag.trim();
        if etag.is_empty() {
            return;
        }
        let Some(mut checkpoint) = read_checkpoint(&self.paths.checkpoint) else {
            return;
        };
        if checkpoint.etag.as_deref() == Some(etag) {
            return;
        }
        checkpoint.etag = Some(etag.to_owned());
        let _ = write_checkpoint(&self.paths.checkpoint, &checkpoint);
    }
}

/// Moves a finished part file to its destination.
///
/// The move is a hard link followed by an unlink of the part, not a
/// rename: `rename` replaces whatever is at the destination, so a file
/// that appeared between an existence check and the rename — another
/// PAM, a human copying weights in by hand — would be silently
/// overwritten. `hard_link` refuses an existing destination inside the
/// filesystem, atomically, with no check-then-act window. Both names
/// are in one directory, so the link cannot cross a device.
fn link_into_place(part: &Path, dest: &Path) -> Result<(), DownloadState> {
    if let Err(error) = std::fs::hard_link(part, dest) {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(DownloadState::failed(
                "already_exists",
                format!("{} appeared while the transfer ran", dest.display()),
            ));
        }
        return Err(DownloadState::failed(
            "io",
            format!("could not move the finished file into place: {error}"),
        ));
    }
    // The weights are in place under their final name; a part file that
    // would not go away costs a resume check next time, and reporting a
    // failed transfer here would be a lie.
    let _ = std::fs::remove_file(part);
    Ok(())
}

/// Takes the advisory lock for a destination.
///
/// The file is opened rather than created exclusively: a lock file left
/// behind by a crashed daemon must not make a resumable download
/// unresumable forever. The lock itself is what refuses a concurrent
/// transfer, and the operating system releases it when the process dies,
/// whether or not the file survives.
pub(crate) fn acquire_lock(path: &Path) -> Result<File, DownloadError> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)?;

    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err(DownloadError::Locked(path.to_path_buf()));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(DownloadError::Io(error)),
    }

    // Whose lock it is, for a human reading the directory. Best effort:
    // the lock is held either way.
    let _ = file.set_len(0);
    let _ = (&file).write_all(format!("{}\n", std::process::id()).as_bytes());
    Ok(file)
}

/// Reads a checkpoint, treating anything unreadable as absent.
fn read_checkpoint(path: &Path) -> Option<Checkpoint> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// Writes a checkpoint through a temp file, so a crash mid-write leaves the
/// old one rather than a truncated one.
fn write_checkpoint(path: &Path, checkpoint: &Checkpoint) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(checkpoint).map_err(std::io::Error::other)?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, &json)?;
    std::fs::rename(&temp, path)
}

/// Where curl saves the response `ETag`: `.<file>.pam-model.etag`.
fn etag_path(checkpoint: &Path) -> PathBuf {
    checkpoint.with_extension("etag")
}

/// Size of a file that may not exist yet.
fn file_size(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}
