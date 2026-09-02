//! Fetching weights: system `curl` as a child process, integrity in Rust.
//!
//! # Why curl
//!
//! Hugging Face is HTTPS, and every pure-Rust TLS stack either compiles C
//! (`ring`, `aws-lc`) or is still alpha. macOS, Windows 10+, and mainstream
//! Linux all ship `curl`, so PAM borrows the one TLS implementation that is
//! already on the machine and keeps its own dependency tree free of a C
//! compiler. curl moves bytes; it does not get to decide whether they are
//! the right bytes. Size and SHA-256 are checked here, after the transfer,
//! against what the catalog said the file should be.
//!
//! A machine without curl gets a refusal that names the binary and the
//! install command for its platform ([`curl_recovery_line`]) rather than a
//! transfer that fails halfway with a confusing message.
//!
//! # Sidecars, and why their names are frozen
//!
//! Beside the destination file, three hidden files carry the state of a
//! transfer ([`sidecar_paths`]):
//!
//! - `.<file>.pam-model.part` — the bytes so far. curl resumes into it.
//! - `.<file>.pam-model.json` — the [`Checkpoint`]: which URL these bytes
//!   came from and what they are supposed to hash to.
//! - `.<file>.pam-model.lock` — held for the life of the transfer, so two
//!   downloads of the same file cannot interleave into one part file.
//!
//! The names and the JSON field set are pam-old's, unchanged. The owner has
//! multi-gigabyte partial downloads on disk from the previous PAM; a rename
//! here would mean re-fetching them. `license_digest` is written for that
//! compatibility alone — nothing reads it back.
//!
//! A checkpoint is never silently reused. If the URL or the expected digest
//! on disk disagrees with the request, that is
//! [`DownloadError::CheckpointConflict`]: the part file's provenance is
//! unknown, and appending to it would produce a file that hashes to
//! nothing anyone asked for.
//!
//! # Entity tags
//!
//! curl writes the response `ETag` to a temp file (`--etag-save`) and it is
//! kept in the checkpoint, again for field compatibility. It is
//! deliberately *not* fed back as `--etag-compare` on resume: that sends
//! `If-None-Match` alongside the resume `Range`, and a server answering
//! `304 Not Modified` leaves curl with an empty successful transfer over a
//! half-finished part file. Integrity here comes from the digest, which is
//! stronger than an `ETag` and does not need the server's cooperation.
//!
//! # Shape of a transfer
//!
//! [`start`] does everything that can fail fast — locate curl, refuse an
//! existing destination, take the lock, reconcile the checkpoint — and then
//! spawns a task. The task's progress and terminal verdict come back
//! through a [`watch`] channel on [`DownloadHandle`], so a caller can poll
//! ([`DownloadHandle::state`]) or wait ([`DownloadHandle::wait`]) without
//! owning the task. Progress is the part file's size, polled every 500 ms:
//! curl's own progress meter would have to be parsed out of a terminal
//! format, and the file size is the fact that actually matters.
//!
//! Cancelling kills curl and keeps the part file. So does a failed
//! transfer. The only outcomes that delete anything are success (the
//! sidecars are gone once the file is in place) and a digest mismatch,
//! where the part is removed because resuming known-wrong bytes would loop
//! forever.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::watch;

use crate::catalog::CATALOG;
use crate::registry::{Registry, VerifiedRecord, sha256_file};

/// Checkpoint format version. pam-old wrote `1`; nothing has changed.
const CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// How often the part file is stat-ed for progress.
const PROGRESS_POLL: Duration = Duration::from_millis(500);

/// How much of curl's stderr survives into a failure detail. Two lines is
/// the usual size of a curl complaint; 4 KiB is room for a pathological one
/// without letting a hostile server write a log file for us.
const STDERR_TAIL_BYTES: usize = 4 * 1024;

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
    /// Source URL, followed through redirects.
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
    /// `download_failed`, `digest_mismatch`, `size_mismatch`,
    /// `already_exists`, `locked`, `io`.
    Failed {
        /// Machine-readable cause the daemon maps to a recovery sentence.
        cause: String,
        /// What actually happened, including curl's stderr tail.
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
    /// No `curl` on `PATH`. See [`curl_recovery_line`].
    #[error("curl not found on PATH")]
    CurlMissing,

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

/// The `curl` executable on `PATH`, looked up once per process.
///
/// Cached because a download asks for it and so does the GUI, every time it
/// draws the catalog; the answer does not change while PAM runs.
pub fn curl_path() -> Result<PathBuf, DownloadError> {
    static CURL: OnceLock<Option<PathBuf>> = OnceLock::new();
    CURL.get_or_init(find_curl)
        .clone()
        .ok_or(DownloadError::CurlMissing)
}

/// How to get curl on this platform, in one sentence.
#[must_use]
pub fn curl_recovery_line() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "curl ships with macOS; reinstall Xcode command line tools"
    }
    #[cfg(target_os = "windows")]
    {
        "curl.exe ships with Windows 10 1803+; winget install cURL.cURL"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        "apt install curl / dnf install curl"
    }
}

/// Starts a transfer and returns immediately.
///
/// Everything that can be refused up front is refused here, synchronously,
/// so the caller learns about a missing curl or an occupied destination
/// before a job row exists. Needs a tokio runtime: the transfer runs as a
/// spawned task.
pub fn start(request: DownloadRequest) -> Result<DownloadHandle, DownloadError> {
    let curl = curl_path()?;
    if request.dest.exists() {
        return Err(DownloadError::AlreadyExists(request.dest.clone()));
    }
    if let Some(parent) = request.dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let paths = sidecar_paths(&request.dest);
    let lock = acquire_lock(&paths.lock)?;

    let mut wanted = Checkpoint::for_request(&request);
    if let Some(existing) = read_checkpoint(&paths.checkpoint) {
        existing.check_against(&wanted)?;
        wanted.etag = existing.etag;
    }
    write_checkpoint(&paths.checkpoint, &wanted)?;

    let (state, states) = watch::channel(DownloadState::Running(DownloadProgress {
        bytes: file_size(&paths.part),
        total: request.expected_size,
    }));
    let (cancel, cancelled) = watch::channel(false);

    let job = Job {
        etag_file: etag_path(&paths.checkpoint),
        request,
        paths,
        curl,
        state,
        _lock: lock,
    };
    tokio::spawn(run(job, cancelled));

    Ok(DownloadHandle {
        state: states,
        cancel: Arc::new(cancel),
    })
}

/// One transfer's owned state, moved into the spawned task.
struct Job {
    request: DownloadRequest,
    paths: SidecarPaths,
    curl: PathBuf,
    etag_file: PathBuf,
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
    let _ = job.state.send(terminal);
}

impl Job {
    /// Spawns curl, drives it, and verifies whatever it left behind.
    async fn execute(&self, cancelled: watch::Receiver<bool>) -> DownloadState {
        let child = match self.spawn_curl() {
            Ok(child) => child,
            Err(error) => {
                return DownloadState::failed(
                    "download_failed",
                    format!("could not run curl: {error}"),
                );
            }
        };

        let outcome = self.drive(child, cancelled).await;
        self.absorb_etag();
        match outcome {
            CurlOutcome::Cancelled => DownloadState::Cancelled,
            CurlOutcome::Failed { cause, detail } => DownloadState::Failed { cause, detail },
            CurlOutcome::Completed => self.finish().await,
        }
    }

    /// The one curl invocation PAM makes.
    ///
    /// `--fail` turns an HTTP error status into a nonzero exit instead of a
    /// saved error page; `--continue-at -` resumes from whatever is in the
    /// part file; `--retry 0` keeps retry policy here rather than inside
    /// curl, where PAM cannot report it.
    fn spawn_curl(&self) -> std::io::Result<Child> {
        Command::new(&self.curl)
            .arg("--fail")
            .arg("--location")
            .arg("--silent")
            .arg("--show-error")
            .arg("--continue-at")
            .arg("-")
            .arg("--output")
            .arg(&self.paths.part)
            .arg("--etag-save")
            .arg(&self.etag_file)
            .arg("--retry")
            .arg("0")
            .arg(&self.request.url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
    }

    /// Waits for curl while publishing progress and watching for a cancel.
    async fn drive(&self, mut child: Child, mut cancelled: watch::Receiver<bool>) -> CurlOutcome {
        let mut stderr = child.stderr.take();
        let mut ticker = tokio::time::interval(PROGRESS_POLL);
        let mut watching = true;

        let status = loop {
            tokio::select! {
                exited = child.wait() => match exited {
                    Ok(status) => break status,
                    Err(error) => return CurlOutcome::Failed {
                        cause: "download_failed".to_owned(),
                        detail: format!("curl could not be waited on: {error}"),
                    },
                },
                changed = cancelled.changed(), if watching => match changed {
                    Ok(()) if *cancelled.borrow() => {
                        let _ = child.kill().await;
                        return CurlOutcome::Cancelled;
                    }
                    Ok(()) => {}
                    // Every handle was dropped: nobody is left to cancel.
                    Err(_) => watching = false,
                },
                _ = ticker.tick() => self.publish_progress(),
            }
        };

        if status.success() {
            return CurlOutcome::Completed;
        }

        let code = status
            .code()
            .map_or_else(|| "signal".to_owned(), |code| code.to_string());
        let tail = read_stderr_tail(&mut stderr).await;
        CurlOutcome::Failed {
            cause: "download_failed".to_owned(),
            detail: format!("curl exited {code}: {tail}"),
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

        if let Err(state) = self.install(&sha256, size_bytes) {
            return state;
        }
        DownloadState::Done { sha256, size_bytes }
    }

    /// Moves the part file into place and clears the sidecars.
    fn install(&self, sha256: &str, size_bytes: u64) -> Result<(), DownloadState> {
        if self.request.dest.exists() {
            return Err(DownloadState::failed(
                "already_exists",
                format!(
                    "{} appeared while the download ran",
                    self.request.dest.display()
                ),
            ));
        }
        if let Err(error) = std::fs::rename(&self.paths.part, &self.request.dest) {
            return Err(DownloadState::failed(
                "io",
                format!("could not move the finished file into place: {error}"),
            ));
        }

        if self.request.expected_sha256.is_some() {
            self.record_verification(sha256, size_bytes);
        }

        let _ = std::fs::remove_file(&self.paths.checkpoint);
        let _ = std::fs::remove_file(&self.etag_file);
        let _ = std::fs::remove_file(&self.paths.lock);
        Ok(())
    }

    /// Writes the verification sidecar with the digest just computed.
    ///
    /// The download hashed the bytes on the way in; making the registry
    /// re-read gigabytes to learn what is already known would be absurd. A
    /// failure to write it is not a failure of the download — the file is
    /// good, and the worst it costs is one re-verification.
    fn record_verification(&self, sha256: &str, size_bytes: u64) {
        let Some(models_dir) = self
            .request
            .dest
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
        else {
            return;
        };
        let file_name = self
            .request
            .dest
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let matches_catalog = CATALOG
            .iter()
            .find(|preset| preset.file_name == file_name)
            .map(|preset| preset.sha256 == sha256 && preset.size_bytes == size_bytes);

        let record = VerifiedRecord {
            sha256: sha256.to_owned(),
            size_bytes,
            verified_ts: now_unix_seconds(),
            matches_catalog,
        };
        let _ = Registry::new(models_dir).record_verified(&self.request.dest, &record);
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

/// Takes the advisory lock for a destination.
///
/// The file is opened rather than created exclusively: a lock file left
/// behind by a crashed daemon must not make a resumable download
/// unresumable forever. The lock itself is what refuses a concurrent
/// transfer, and the operating system releases it when the process dies,
/// whether or not the file survives.
fn acquire_lock(path: &Path) -> Result<File, DownloadError> {
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

/// The last [`STDERR_TAIL_BYTES`] of curl's complaint, as one line.
async fn read_stderr_tail(stderr: &mut Option<tokio::process::ChildStderr>) -> String {
    let Some(stderr) = stderr.as_mut() else {
        return String::from("(no stderr captured)");
    };

    let mut tail: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    while let Ok(read) = stderr.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        tail.extend_from_slice(&buffer[..read]);
        if tail.len() > STDERR_TAIL_BYTES {
            tail.drain(..tail.len() - STDERR_TAIL_BYTES);
        }
    }

    let text = String::from_utf8_lossy(&tail);
    let text = text.trim();
    if text.is_empty() {
        String::from("(no output)")
    } else {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// First executable named `curl` on `PATH`.
fn find_curl() -> Option<PathBuf> {
    let name = if cfg!(windows) { "curl.exe" } else { "curl" };
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }

    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = true;

    executable
}
