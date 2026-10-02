//! PAM's private copy of verified weights: the only file the engine is pointed at.
//!
//! The models directory is not a trust boundary: anything running as the user may be
//! able to rename or rewrite a `.gguf` there, so a digest checked on that file says
//! nothing about what the engine opens a moment later. Verification therefore
//! *materialises* the weights inside the daemon's private base
//! (`<base>/engine/weights/<sha256>.gguf`) and hashes **the private copy**: the file
//! name is the digest of bytes nothing outside the base can change, and the engine is
//! started on that path only.
//!
//! How the bytes get there, in order of preference:
//!
//! 1. **Copy-on-write clone** where the platform offers one through the standard
//!    library. On macOS `std::fs::copy` asks for `fclonefileat` first, which on APFS
//!    within one volume shares the blocks: no extra disk, a metadata operation whatever
//!    the size. The clone is then hashed once (one read pass, what a verification cost
//!    before).
//! 2. **A full copy hashed in the same pass** everywhere else (another volume, another
//!    filesystem, Windows): every chunk written is the chunk hashed, with progress and
//!    cancellation, after a free-space check that names the bytes needed.
//!
//! A **hard link is never used**: it names the same inode as the file in the models
//! directory, so an in-place rewrite of that file rewrites the "private" one too. It
//! would defeat a rename swap and nothing else.
//!
//! The clone and the free-space probe are injectable ([`CopyHooks`]) so a test can stand
//! in for another volume or a full disk.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::private::create_private_dir;
use crate::registry::FileFingerprint;

/// Chunk size for hashing and copying: large enough that syscall overhead disappears,
/// small enough that a cancel is noticed within milliseconds.
const CHUNK_BYTES: usize = 1024 * 1024;

/// Free space asked for beyond the copy itself, so a private copy never takes the
/// volume holding the daemon's store and logs to zero.
pub const FREE_SPACE_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

/// Prefix of a copy still being made. A finished copy is renamed to `<sha256>.gguf`.
const INCOMING_PREFIX: &str = ".incoming-";

/// Tries a copy-on-write clone of the first path at the second. `Ok(true)`: the clone
/// exists. `Ok(false)`: these two locations cannot share blocks and nothing was written.
pub type CloneFn = dyn Fn(&Path, &Path) -> std::io::Result<bool> + Send + Sync;

/// Free bytes available to this user on the volume holding a directory, or `None` when
/// that cannot be learned.
pub type FreeBytesFn = dyn Fn(&Path) -> Option<u64> + Send + Sync;

/// The two platform facts a materialisation depends on, replaceable in tests.
#[derive(Clone)]
pub struct CopyHooks {
    /// See [`CloneFn`]; [`platform_clone`] in production.
    pub clone: Arc<CloneFn>,
    /// See [`FreeBytesFn`]; [`platform_free_bytes`] in production.
    pub free_bytes: Arc<FreeBytesFn>,
}

impl Default for CopyHooks {
    fn default() -> Self {
        Self {
            clone: Arc::new(platform_clone),
            free_bytes: Arc::new(platform_free_bytes),
        }
    }
}

impl std::fmt::Debug for CopyHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyHooks").finish_non_exhaustive()
    }
}

/// How a private copy got its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyMethod {
    /// Copy-on-write clone: no extra disk.
    Cloned,
    /// Full copy, hashed as it was written: the file's size in extra disk.
    Copied,
    /// A private copy with this digest was already there and vouched for.
    Reused,
}

/// The private copy of one verified file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateWeights {
    /// `<weights dir>/<sha256>.gguf`.
    pub path: PathBuf,
    /// The copy's identity when it was made; compared again right before a load.
    pub fingerprint: FileFingerprint,
}

/// Progress and cancellation for a materialisation, which reads (and may write)
/// gigabytes.
pub struct Control<'a> {
    /// Called with the bytes hashed so far.
    pub progress: &'a (dyn Fn(u64) + Sync),
    /// Polled between chunks; `true` stops the work and removes what it wrote.
    pub cancelled: &'a (dyn Fn() -> bool + Sync),
}

impl Control<'static> {
    /// No progress sink and no cancel: for callers that hash a few bytes.
    #[must_use]
    pub fn none() -> Self {
        Self {
            progress: &|_| {},
            cancelled: &|| false,
        }
    }
}

/// Why a private copy could not be made.
#[derive(Debug, thiserror::Error)]
pub enum WeightsError {
    /// A filesystem call failed.
    #[error("private weights store error: {0}")]
    Io(#[from] std::io::Error),
    /// The volume holding the private store has no room for a full copy.
    #[error(
        "not enough disk space under {dir} for PAM's private copy of the weights: {needed} bytes \
         needed, {} free; free that much there, or keep the models directory on the same APFS \
         volume as PAM's base so the copy shares its blocks",
        free.map_or_else(|| "an unknown amount".to_owned(), |bytes| format!("{bytes} bytes"))
    )]
    NoSpace {
        /// The private store.
        dir: PathBuf,
        /// Bytes a full copy needs (the file's size plus headroom).
        needed: u64,
        /// Bytes free there, when known.
        free: Option<u64>,
    },
    /// The caller cancelled; nothing was kept.
    #[error("cancelled before the private copy was complete")]
    Cancelled,
}

/// A copy made and hashed but not yet named by its digest. Dropping it removes the
/// file; [`WeightStore::commit`] keeps it.
#[derive(Debug)]
pub struct Staged {
    incoming: PathBuf,
    /// Lowercase hex SHA-256 of the private bytes.
    pub sha256: String,
    /// Bytes hashed.
    pub size_bytes: u64,
    /// Clone or full copy.
    pub method: CopyMethod,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.incoming);
    }
}

/// The private weights directory and how copies are made into it.
#[derive(Debug, Clone)]
pub struct WeightStore {
    dir: PathBuf,
    hooks: CopyHooks,
}

impl WeightStore {
    /// A store over `dir`, which must be private to the daemon's user.
    pub fn new(dir: impl Into<PathBuf>, hooks: CopyHooks) -> Self {
        Self {
            dir: dir.into(),
            hooks,
        }
    }

    /// The directory the copies live in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the private copy with digest `sha256` lives.
    #[must_use]
    pub fn path_for(&self, sha256: &str) -> PathBuf {
        self.dir.join(format!("{sha256}.gguf"))
    }

    /// Copies `source` into the store and hashes the private bytes.
    ///
    /// A clone is tried first; where the two locations cannot share blocks the file is
    /// copied in full, hashed as it is written, after checking that the volume has room
    /// ([`WeightsError::NoSpace`] names the bytes needed). Either way the digest returned
    /// is the digest of the private file, not of `source`.
    pub fn stage(&self, source: &Path, control: &Control<'_>) -> Result<Staged, WeightsError> {
        create_private_dir(&self.dir)?;
        let needed = std::fs::metadata(source)?
            .len()
            .saturating_add(FREE_SPACE_HEADROOM_BYTES);
        let incoming = self.dir.join(incoming_name());
        let mut staged = Staged {
            incoming: incoming.clone(),
            sha256: String::new(),
            size_bytes: 0,
            method: CopyMethod::Cloned,
        };
        let cloned =
            (self.hooks.clone)(source, &incoming).map_err(|error| self.full_or(error, needed))?;
        if cloned {
            // A clone carries the source's mode; the private copy is the owner's alone.
            set_mode(&incoming, 0o600)?;
            (staged.sha256, staged.size_bytes) = hash_file(&incoming, control)?;
            return Ok(staged);
        }
        let free = (self.hooks.free_bytes)(&self.dir);
        if free.is_some_and(|free| free < needed) {
            return Err(WeightsError::NoSpace {
                dir: self.dir.clone(),
                needed,
                free,
            });
        }
        staged.method = CopyMethod::Copied;
        (staged.sha256, staged.size_bytes) =
            copy_hashing(source, &incoming, control).map_err(|error| match error {
                WeightsError::Io(io) => self.full_or(io, needed),
                other => other,
            })?;
        Ok(staged)
    }

    /// `error` as [`WeightsError::NoSpace`] when the volume ran out of room under the
    /// copy (the pre-check cannot see a volume that fills while the copy runs, or one
    /// whose free space is unknown), and as itself otherwise.
    fn full_or(&self, error: std::io::Error, needed: u64) -> WeightsError {
        if matches!(
            error.kind(),
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
        ) {
            WeightsError::NoSpace {
                dir: self.dir.clone(),
                needed,
                free: (self.hooks.free_bytes)(&self.dir),
            }
        } else {
            WeightsError::Io(error)
        }
    }

    /// Names a staged copy by its digest and returns it with its fingerprint.
    ///
    /// `vouched` is the fingerprint a verification record already holds for a private
    /// copy with this digest: when the file under that name still has it, the file is
    /// kept and the staged copy dropped (so a second model with the same bytes, or a
    /// repeated verification, never invalidates the record that names the first copy).
    /// Otherwise the staged copy replaces whatever is there.
    pub fn commit(
        &self,
        mut staged: Staged,
        vouched: Option<FileFingerprint>,
    ) -> Result<(PrivateWeights, CopyMethod), WeightsError> {
        let path = self.path_for(&staged.sha256);
        if let Some(vouched) = vouched
            && FileFingerprint::read(&path).ok() == Some(vouched)
        {
            return Ok((
                PrivateWeights {
                    path,
                    fingerprint: vouched,
                },
                CopyMethod::Reused,
            ));
        }
        // Read-only before it gets its name: nothing PAM does writes to it again. The
        // fingerprint is taken after the rename, which moves the change time.
        set_mode(&staged.incoming, 0o400)?;
        std::fs::rename(&staged.incoming, &path)?;
        staged.incoming = PathBuf::new();
        let fingerprint = FileFingerprint::read(&path)?;
        Ok((PrivateWeights { path, fingerprint }, staged.method))
    }

    /// Every finished private copy in the store, as `(sha256, path)`.
    #[must_use]
    pub fn copies(&self) -> Vec<(String, PathBuf)> {
        self.files()
            .into_iter()
            .filter_map(|(name, path)| {
                let digest = name.strip_suffix(".gguf")?;
                is_sha256_hex(digest).then(|| (digest.to_owned(), path))
            })
            .collect()
    }

    /// Every unfinished copy in the store: what a verification leaves behind when the
    /// process dies under it.
    #[must_use]
    pub fn incoming(&self) -> Vec<PathBuf> {
        self.files()
            .into_iter()
            .filter(|(name, _)| name.starts_with(INCOMING_PREFIX))
            .map(|(_, path)| path)
            .collect()
    }

    fn files(&self) -> Vec<(String, PathBuf)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|entry| Some((entry.file_name().to_str()?.to_owned(), entry.path())))
            .collect()
    }
}

/// The production [`CloneFn`].
///
/// macOS: when `source` and the directory of `dest` are on one device, `std::fs::copy`,
/// which asks the kernel for `fclonefileat` first; on APFS that shares the blocks. (On a
/// same-device volume that cannot clone, which no arm64 Mac boots from, the standard
/// library falls back to a whole-file kernel copy: still correct and still hashed
/// afterwards, only without progress while it runs.) Another device answers `Ok(false)`.
///
/// Everywhere else `Ok(false)`: the standard library offers no clone that can be told
/// from a full copy, so the hashed copy with progress and a space check is used.
pub fn platform_clone(source: &Path, dest: &Path) -> std::io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt as _;
        let Some(parent) = dest.parent() else {
            return Ok(false);
        };
        if std::fs::metadata(source)?.dev() != std::fs::metadata(parent)?.dev() {
            return Ok(false);
        }
        std::fs::copy(source, dest)?;
        Ok(true)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (source, dest);
        Ok(false)
    }
}

/// The production [`FreeBytesFn`].
///
/// macOS: the "Available" column of `/bin/df -Pk <dir>`, run with an empty environment.
/// Elsewhere `None`: the standard library has no free-space query, and a copy that runs
/// out of room is still refused legibly when the write fails.
#[must_use]
pub fn platform_free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/bin/df")
            .arg("-Pk")
            .arg(dir)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        parse_df_available_kib(&String::from_utf8_lossy(&output.stdout))?.checked_mul(1024)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = dir;
        None
    }
}

/// The "Available" figure of POSIX `df -Pk` output, in KiB: on the data line, the number
/// right before the `NN%` capacity column (device and mount names may contain spaces, so
/// the columns are found from that anchor and not by position).
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_df_available_kib(output: &str) -> Option<u64> {
    let fields: Vec<&str> = output.lines().nth(1)?.split_whitespace().collect();
    let capacity = fields.iter().position(|field| {
        field
            .strip_suffix('%')
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
    })?;
    // blocks, used, available, capacity: all three numbers must be there.
    let numbers = fields.get(capacity.checked_sub(3)?..capacity)?;
    numbers
        .iter()
        .map(|field| field.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()?
        .last()
        .copied()
}

/// Streams SHA-256 over `path`, reporting progress and honouring a cancel.
pub(crate) fn hash_file(path: &Path, control: &Control<'_>) -> Result<(String, u64), WeightsError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        if (control.cancelled)() {
            return Err(WeightsError::Cancelled);
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
        (control.progress)(total);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Copies `source` to a new owner-only file at `dest`, hashing exactly the bytes it
/// writes. The digest therefore describes the private file whatever happens to `source`
/// while it is read. The weights import copies with it too.
pub(crate) fn copy_hashing(
    source: &Path,
    dest: &Path,
    control: &Control<'_>,
) -> Result<(String, u64), WeightsError> {
    let mut reader = std::fs::File::open(source)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut writer = options.open(dest)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut total: u64 = 0;
    loop {
        if (control.cancelled)() {
            return Err(WeightsError::Cancelled);
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
        (control.progress)(total);
    }
    writer.sync_all()?;
    Ok((hex::encode(hasher.finalize()), total))
}

/// Sets a Unix permission mode; a no-op where modes do not exist (the private
/// directory's access control is what applies there).
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// A name for a copy in progress that two verifications in one process, or two
/// processes, never share.
fn incoming_name() -> String {
    use std::hash::{BuildHasher as _, RandomState};
    let unique = RandomState::new().hash_one(std::process::id());
    format!("{INCOMING_PREFIX}{}-{unique:016x}.part", std::process::id())
}

/// Whether `text` is a lowercase hex SHA-256.
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
