//! What is actually on disk: scan, classify, verify, delete.
//!
//! Layout: `<models dir>/<vendor>/<file>.gguf`, two levels and no deeper — the filesystem
//! *is* the registry, with `<vendor>/<file stem>` as the stable id. Loose files, files
//! nested deeper, non-`.gguf` files, and dotfiles (a download's own sidecars) are ignored.
//! [`classify`] admits a model only once its SHA-256 is verified ([`ModelClass::Engine`]);
//! unverified is [`ModelClass::TestOnly`] — loadable/promptable to prove wiring, but never
//! a tier default, since a job must never run on unchecked bytes; size is no longer a
//! criterion. Verified is not yet qualified: [`ModelEntry::qualification`] is set only when
//! the verified digest matches a [`crate::qualification`] record measured on the pinned
//! engine and the current target, and only a qualified entry may serve a job.
//! [`Registry::verify`] streams SHA-256 and records the result in the registry's **private
//! trust directory** (under the daemon's `0700` base, never in the models directory, which
//! anything running as the user may be able to write); against a matching catalog preset it
//! records `Some(true)` (expected bytes), `Some(false)` (wrong bytes under that name), or
//! `None` (nothing to compare). A record binds the digest to the file's canonical path and
//! its [`FileFingerprint`] (size, mtime, ctime, device, inode): a rewritten file stops being
//! verified at the next scan and a load re-checks the fingerprint ([`Registry::recheck`]).
//! A `.<file>.pam-model.verified` sidecar beside the file — what older versions wrote — is
//! never trusted; it only produces a "verify again" hint on the entry
//! ([`ModelEntry::verification_issue`]). A registry without a trust directory trusts
//! nothing. All calls hit the filesystem synchronously; async callers wrap them in
//! `spawn_blocking`.
//! A model dropped into the directory by hand and one PAM downloaded are the same kind of entry.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::catalog::{CATALOG, find_preset};
use crate::engine::Target;
use crate::gguf::{self, GgufError, GgufInfo};
use crate::private::write_private_file;
use crate::qualification::{self, Qualification};

/// Chunk size for [`sha256_file`]. Big enough that the syscall overhead
/// disappears, small enough to stay off the stack and out of the way.
const HASH_CHUNK_BYTES: usize = 1024 * 1024;

/// Suffix of the legacy verification sidecar older versions wrote next to a model
/// file. It is only ever looked for, to hint "verify again"; never trusted.
const VERIFIED_SIDECAR_SUFFIX: &str = ".pam-model.verified";

/// Version of the private trust record's layout.
const TRUST_RECORD_VERSION: u32 = 1;

/// What a model on disk is allowed to be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelClass {
    /// Digest verified; may serve a job and be a tier default.
    Engine,
    /// Unverified: loadable and promptable for wiring checks only; refused
    /// as a tier default until a Verify job checks its digest.
    TestOnly,
}

/// One model file, as the scan found it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ModelEntry {
    /// `<vendor>/<file stem>` — the id every model op takes.
    pub id: String,
    /// Directory the file sits in, under the models dir.
    pub vendor: String,
    /// File name including the `.gguf` extension.
    pub file_name: String,
    /// Absolute or models-dir-relative path, as the registry was built.
    pub path: PathBuf,
    /// Size on disk, and therefore what [`classify`] ruled on.
    pub size_bytes: u64,
    /// Header facts, when the file parsed.
    pub info: Option<GgufInfo>,
    /// Why the header did not parse, when it did not. A file with a reason
    /// still appears in the listing: a human who can see the broken file
    /// can delete it, and one who cannot see it just wonders where the disk
    /// space went.
    pub info_error: Option<String>,
    /// Engine or test-only, from [`classify`].
    pub class: ModelClass,
    /// The last verification, read back from the private trust directory and only
    /// when the file still matches the fingerprint it was verified at.
    pub verified: Option<VerifiedRecord>,
    /// Why this file is not verified although something says it once was: a trust
    /// record whose fingerprint no longer matches (the file changed), or only a legacy
    /// sidecar beside it (not trusted). Carries its own recovery line; `None` for a
    /// file that was simply never verified.
    pub verification_issue: Option<String>,
    /// The file's identity at scan time; [`Registry::recheck`] compares it again right
    /// before a load.
    #[serde(skip)]
    pub fingerprint: FileFingerprint,
    /// The admission evidence for this exact digest on this target, when there is
    /// any. `None` for an unverified file, a verified file nobody has measured, or a
    /// measured file on a target it was not measured on.
    pub qualification: Option<Qualification>,
    /// Catalog preset whose file name this is, when there is one.
    pub catalog_id: Option<&'static str>,
}

/// What identifies one file's current bytes without reading them: a changed size,
/// modification time, change time (which a writer cannot set back), device or inode
/// means the verified digest no longer describes the file. `ctime`, `dev` and `ino` are
/// Unix-only and `0` elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct FileFingerprint {
    /// Size in bytes.
    pub size_bytes: u64,
    /// Modification time, nanoseconds since the epoch.
    pub mtime_ns: u64,
    /// Inode change time, nanoseconds since the epoch.
    pub ctime_ns: u64,
    /// Device the file lives on.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
}

impl FileFingerprint {
    /// The fingerprint of a file's metadata.
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        let mtime_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .unwrap_or(0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let ctime_ns = u64::try_from(metadata.ctime())
                .ok()
                .and_then(|secs| secs.checked_mul(1_000_000_000))
                .and_then(|nanos| nanos.checked_add(u64::try_from(metadata.ctime_nsec()).ok()?))
                .unwrap_or(0);
            Self {
                size_bytes: metadata.len(),
                mtime_ns,
                ctime_ns,
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                size_bytes: metadata.len(),
                mtime_ns,
                ctime_ns: 0,
                dev: 0,
                ino: 0,
            }
        }
    }

    /// The fingerprint of the file at `path`, following symlinks.
    pub fn read(path: &Path) -> std::io::Result<Self> {
        Ok(Self::of(&std::fs::metadata(path)?))
    }
}

/// A verification result, persisted in the private trust directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedRecord {
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Size at the moment it was hashed.
    pub size_bytes: u64,
    /// Unix seconds when the hash was taken.
    pub verified_ts: i64,
    /// `Some(true)` when the digest matched the catalog preset with this
    /// file name, `Some(false)` when it did not, `None` when the file name
    /// is not a catalog one.
    pub matches_catalog: Option<bool>,
}

/// What [`Registry::verify`] returns to its caller — the same facts as the
/// sidecar, minus the timestamp the caller just caused.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifyOutcome {
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Bytes hashed.
    pub size_bytes: u64,
    /// Catalog verdict, as on [`VerifiedRecord::matches_catalog`].
    pub matches_catalog: Option<bool>,
}

/// Everything the registry can refuse or fail at.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A filesystem call failed.
    #[error("models directory error: {0}")]
    Io(#[from] std::io::Error),

    /// The model id or path does not name a file that is there.
    #[error("no model {0} in the models directory")]
    NotFound(String),

    /// A destructive operation was aimed at a path outside the models
    /// directory, and refused.
    #[error("{0:?} is outside the models directory; pam only deletes what it manages")]
    OutsideModelsDir(PathBuf),

    /// The configured models directory exists but is not a directory.
    #[error("{0:?} is not a directory")]
    NotADirectory(PathBuf),

    /// A vendor or file name is not one plain path segment: empty, `.`,
    /// `..`, a hidden name, a separator, a drive or root, or a character
    /// outside `[A-Za-z0-9._-]`. Refused before a path is built from it.
    #[error("{0:?} is not a plain name; pam only writes under <models dir>/<vendor>/<file>")]
    InvalidName(String),

    /// The file is not the one that was verified: it changed on disk after the
    /// verification (or after the scan a load was based on).
    #[error(
        "model {id} changed on disk after it was verified ({what}); verify it again before loading"
    )]
    Changed {
        /// The model id.
        id: String,
        /// What differs, for the human.
        what: String,
    },

    /// A header could not be read at all. Per-file parse failures land on
    /// [`ModelEntry::info_error`] instead; this is for the callers that
    /// asked about one specific file.
    #[error(transparent)]
    Gguf(#[from] GgufError),
}

/// The models directory, and every operation over it.
#[derive(Debug, Clone)]
pub struct Registry {
    dir: PathBuf,
    /// The qualification table entries are matched against; the compiled-in
    /// one outside tests.
    qualifications: &'static [Qualification],
    /// Where verification records live: a directory under the daemon's private base,
    /// never inside the models directory. `None` trusts nothing.
    trust_dir: Option<PathBuf>,
}

impl Registry {
    /// Builds a registry over `dir`. The directory need not exist yet — a
    /// scan of a missing directory is simply empty, which is the honest
    /// answer on a machine with no models.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self::with_qualifications(dir, qualification::QUALIFIED)
    }

    /// [`Registry::new`] with an explicit qualification table, so a harness can
    /// qualify a fixture it just wrote. Production callers use the compiled-in table.
    pub fn with_qualifications(
        dir: impl Into<PathBuf>,
        qualifications: &'static [Qualification],
    ) -> Self {
        Self {
            dir: dir.into(),
            qualifications,
            trust_dir: None,
        }
    }

    /// Keeps this registry's verification records in `dir`, which must be private to
    /// the daemon's user and outside the models directory. Without it nothing is ever
    /// verified.
    #[must_use]
    pub fn with_trust_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.trust_dir = Some(dir.into());
        self
    }

    /// The private directory verification records live in, when one is set.
    #[must_use]
    pub fn trust_dir(&self) -> Option<&Path> {
        self.trust_dir.as_deref()
    }

    /// The models directory this registry covers.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where a download of `file_name` from `vendor` should land, for names
    /// this binary wrote itself (a catalog preset's `vendor` and `file_name`
    /// are compiled-in constants).
    ///
    /// This is a plain join and does not validate: a caller holding a
    /// vendor or file name that came from outside — an admin argument, a
    /// URL — must use [`Registry::checked_dest_for`], which refuses anything
    /// that is not one plain path segment.
    #[must_use]
    pub fn dest_for(&self, vendor: &str, file_name: &str) -> PathBuf {
        self.dir.join(vendor).join(file_name)
    }

    /// [`Registry::dest_for`] for names that came from a caller: both must
    /// pass [`is_plain_name`], so the result is always exactly two levels
    /// under the models directory. `../../etc`, `/tmp`, `C:\x`, `.hidden`
    /// and an empty string are [`RegistryError::InvalidName`].
    pub fn checked_dest_for(
        &self,
        vendor: &str,
        file_name: &str,
    ) -> Result<PathBuf, RegistryError> {
        for name in [vendor, file_name] {
            if !is_plain_name(name) {
                return Err(RegistryError::InvalidName(name.to_owned()));
            }
        }
        Ok(self.dest_for(vendor, file_name))
    }

    /// Every `.gguf` under `<dir>/<vendor>/`, sorted by id.
    ///
    /// A file whose header does not parse still comes back, carrying
    /// [`ModelEntry::info_error`]; only a failure to read the *directory*
    /// is an error, because that is the one the human can act on.
    pub fn scan(&self) -> Result<Vec<ModelEntry>, RegistryError> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        if !self.dir.is_dir() {
            return Err(RegistryError::NotADirectory(self.dir.clone()));
        }

        let mut entries = Vec::new();
        for vendor_entry in std::fs::read_dir(&self.dir)? {
            let vendor_entry = vendor_entry?;
            if !vendor_entry.file_type()?.is_dir() {
                continue;
            }
            let Some(vendor) = file_name_string(&vendor_entry.path()) else {
                continue;
            };
            if vendor.starts_with('.') {
                continue;
            }

            for model_entry in std::fs::read_dir(vendor_entry.path())? {
                let model_entry = model_entry?;
                if !model_entry.file_type()?.is_file() {
                    continue;
                }
                let path = model_entry.path();
                let Some(file_name) = file_name_string(&path) else {
                    continue;
                };
                if file_name.starts_with('.') || !is_gguf(&path) {
                    continue;
                }
                let metadata = model_entry.metadata()?;
                entries.push(describe(
                    &path,
                    &vendor,
                    &file_name,
                    &metadata,
                    self.qualifications,
                    self.trust_dir.as_deref(),
                ));
            }
        }

        entries.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(entries)
    }

    /// The entry with this id, or `None`.
    ///
    /// A scan of a models directory is a handful of `stat`s and a few
    /// kilobytes of header per file, so looking one up by scanning is
    /// cheap enough to be the only code path — and it means `find` can
    /// never disagree with `scan`.
    pub fn find(&self, id: &str) -> Result<Option<ModelEntry>, RegistryError> {
        Ok(self.scan()?.into_iter().find(|entry| entry.id == id))
    }

    /// Streams SHA-256 over the model, records the result in its sidecar,
    /// and reports it.
    ///
    /// Blocking, and slow in proportion to the file: gigabytes take
    /// seconds. The daemon runs it as a job for exactly that reason.
    pub fn verify(&self, entry: &ModelEntry) -> Result<VerifyOutcome, RegistryError> {
        if !entry.path.is_file() {
            return Err(RegistryError::NotFound(entry.id.clone()));
        }

        // The file must be the same file at both ends of the hash: a writer racing the
        // verification would otherwise get its new bytes recorded under the old digest.
        let before = FileFingerprint::read(&entry.path)?;
        let (sha256, size_bytes) = sha256_file(&entry.path)?;
        let after = FileFingerprint::read(&entry.path)?;
        if before != after {
            return Err(RegistryError::Changed {
                id: entry.id.clone(),
                what: "it was modified while being hashed".to_owned(),
            });
        }
        let matches_catalog = entry
            .catalog_id
            .and_then(find_preset)
            .map(|preset| preset.sha256 == sha256 && preset.size_bytes == size_bytes);

        let record = VerifiedRecord {
            sha256: sha256.clone(),
            size_bytes,
            verified_ts: now_unix_seconds(),
            matches_catalog,
        };
        self.record_with(&entry.path, &record, before)?;

        Ok(VerifyOutcome {
            sha256,
            size_bytes,
            matches_catalog,
        })
    }

    /// Records a verification of the file at `path` in the private trust directory.
    ///
    /// The record binds `record` to the file's canonical path and its fingerprint as of
    /// this call, so the caller must have hashed these exact bytes; [`Registry::verify`]
    /// checks that itself. A finished download calls this directly: it already hashed
    /// the bytes on the way in, and re-reading the whole file to learn what it just
    /// computed would be absurd.
    ///
    /// The write is atomic and owner-only. A registry with no trust directory refuses:
    /// writing the record beside the file would make it forgeable by whoever can write
    /// the models directory.
    pub fn record_verified(
        &self,
        path: &Path,
        record: &VerifiedRecord,
    ) -> Result<(), RegistryError> {
        let fingerprint = FileFingerprint::read(path)?;
        self.record_with(path, record, fingerprint)
    }

    /// Records the verification a finished download already knows: it hashed the bytes
    /// on the way in and, when the request carried an expected digest, checked them.
    /// Call it only for such a download, from the owner of the private trust store.
    pub fn record_download(
        &self,
        dest: &Path,
        sha256: &str,
        size_bytes: u64,
    ) -> Result<(), RegistryError> {
        let file_name = dest
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let matches_catalog = CATALOG
            .iter()
            .find(|preset| preset.file_name == file_name)
            .map(|preset| preset.sha256 == sha256 && preset.size_bytes == size_bytes);
        self.record_verified(
            dest,
            &VerifiedRecord {
                sha256: sha256.to_owned(),
                size_bytes,
                verified_ts: now_unix_seconds(),
                matches_catalog,
            },
        )
    }

    fn record_with(
        &self,
        path: &Path,
        record: &VerifiedRecord,
        fingerprint: FileFingerprint,
    ) -> Result<(), RegistryError> {
        let trust_dir = self.trust_dir.as_deref().ok_or_else(|| {
            std::io::Error::other("no private verification store is configured for this registry")
        })?;
        let canonical = path.canonicalize()?;
        let trust = TrustRecord {
            version: TRUST_RECORD_VERSION,
            path: canonical.to_string_lossy().into_owned(),
            record: record.clone(),
            fingerprint,
        };
        let json = serde_json::to_vec_pretty(&trust).map_err(std::io::Error::other)?;
        write_private_file(&trust_record_path(trust_dir, &canonical), &json)?;
        Ok(())
    }

    /// Refuses unless the file at `entry.path` is still the file the entry was built
    /// from. Called right before (and right after) a load: the registry's
    /// verification is a claim about those bytes, and a swap between the scan and the
    /// engine opening the file would otherwise run unverified weights under a verified
    /// name. Only entries that carry a verification are checked.
    pub fn recheck(&self, entry: &ModelEntry) -> Result<(), RegistryError> {
        if entry.verified.is_none() {
            return Ok(());
        }
        let now = FileFingerprint::read(&entry.path).map_err(|_| RegistryError::Changed {
            id: entry.id.clone(),
            what: "it is no longer readable".to_owned(),
        })?;
        match fingerprint_difference(&entry.fingerprint, &now) {
            None => Ok(()),
            Some(what) => Err(RegistryError::Changed {
                id: entry.id.clone(),
                what,
            }),
        }
    }

    /// Deletes a model file and its verification records.
    ///
    /// Refuses anything that does not resolve to a path inside the models
    /// directory. The check canonicalizes both sides, so a `..` in the
    /// entry's path cannot walk out; a caller that hands over a path
    /// outside gets [`RegistryError::OutsideModelsDir`] and nothing is
    /// touched.
    ///
    /// Refusing a *loaded* or *downloading* model is the daemon's job — it
    /// is the only layer that knows either fact.
    pub fn delete(&self, entry: &ModelEntry) -> Result<(), RegistryError> {
        let models_dir = self
            .dir
            .canonicalize()
            .map_err(|_| RegistryError::OutsideModelsDir(entry.path.clone()))?;
        let target = entry
            .path
            .canonicalize()
            .map_err(|_| RegistryError::NotFound(entry.id.clone()))?;

        if !target.starts_with(&models_dir) {
            return Err(RegistryError::OutsideModelsDir(entry.path.clone()));
        }
        if !target.is_file() {
            return Err(RegistryError::NotFound(entry.id.clone()));
        }

        let sidecar = verified_sidecar_path(&target);
        std::fs::remove_file(&target)?;
        if let Some(trust_dir) = &self.trust_dir {
            let _ = std::fs::remove_file(trust_record_path(trust_dir, &target));
        }
        if sidecar.exists() {
            std::fs::remove_file(&sidecar)?;
        }
        Ok(())
    }
}

/// Builds the entry for one file, reading its header and its trust record.
fn describe(
    path: &Path,
    vendor: &str,
    file_name: &str,
    metadata: &std::fs::Metadata,
    qualifications: &'static [Qualification],
    trust_dir: Option<&Path>,
) -> ModelEntry {
    let size_bytes = metadata.len();
    let stem = file_name.strip_suffix(".gguf").unwrap_or(file_name);
    let fingerprint = FileFingerprint::of(metadata);
    let (info, info_error) = read_header_cached(path, &fingerprint);
    let (verified, verification_issue) = read_verified(path, &fingerprint, trust_dir);
    let qualification = qualify(verified.as_ref(), qualifications);

    ModelEntry {
        id: format!("{vendor}/{stem}"),
        vendor: vendor.to_owned(),
        file_name: file_name.to_owned(),
        path: path.to_path_buf(),
        size_bytes,
        info,
        info_error,
        class: classify(verified.as_ref()),
        verified,
        verification_issue,
        fingerprint,
        qualification,
        catalog_id: CATALOG
            .iter()
            .find(|preset| preset.file_name == file_name)
            .map(|preset| preset.id),
    }
}

type HeaderCache = std::sync::Mutex<
    std::collections::HashMap<PathBuf, (FileFingerprint, Result<GgufInfo, String>)>,
>;

/// How many files' parsed headers are remembered.
const HEADER_CACHE_MAX: usize = 64;

#[cfg(test)]
thread_local! {
    /// Header parses this thread has done, so a test can tell a cache hit from a parse.
    pub(crate) static HEADER_PARSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The parsed header of `path`, from a cache keyed by path and [`FileFingerprint`].
///
/// Every `find` is a full scan (and every job summary resolves its model by `find`), so
/// without this each one re-parsed every header in the directory — megabytes for a real
/// model, up to the parser's cap for a planted file. A changed size, mtime, ctime or
/// inode misses the cache, so an edited file is parsed afresh.
fn read_header_cached(
    path: &Path,
    fingerprint: &FileFingerprint,
) -> (Option<GgufInfo>, Option<String>) {
    static CACHE: std::sync::OnceLock<HeaderCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(HeaderCache::default);
    if let Some((cached, outcome)) = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(path)
        && cached == fingerprint
    {
        return match outcome {
            Ok(info) => (Some(info.clone()), None),
            Err(error) => (None, Some(error.clone())),
        };
    }
    #[cfg(test)]
    HEADER_PARSES.with(|count| count.set(count.get() + 1));
    let outcome = gguf::read_info(path).map_err(|error| error.to_string());
    let mut guard = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.len() >= HEADER_CACHE_MAX {
        guard.clear();
    }
    guard.insert(path.to_path_buf(), (*fingerprint, outcome.clone()));
    match outcome {
        Ok(info) => (Some(info), None),
        Err(error) => (None, Some(error)),
    }
}

/// The private trust record for a verification, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TrustRecord {
    version: u32,
    /// Canonical path of the file the record is about; a record copied under another
    /// path's name does not verify that other file.
    path: String,
    record: VerifiedRecord,
    fingerprint: FileFingerprint,
}

/// Where the trust record for the file at canonical path `canonical` lives: a file
/// named by the SHA-256 of the path, so no model name ever becomes a path segment.
fn trust_record_path(trust_dir: &Path, canonical: &Path) -> PathBuf {
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    trust_dir.join(format!("{}.json", hex::encode(digest)))
}

/// What differs between the fingerprint a record vouched for and the file's
/// current one, in words; `None` when they match.
fn fingerprint_difference(recorded: &FileFingerprint, now: &FileFingerprint) -> Option<String> {
    if recorded == now {
        return None;
    }
    let mut changed = Vec::new();
    if recorded.size_bytes != now.size_bytes {
        changed.push("size");
    }
    if recorded.mtime_ns != now.mtime_ns {
        changed.push("modification time");
    }
    if recorded.ctime_ns != now.ctime_ns {
        changed.push("change time");
    }
    if recorded.dev != now.dev || recorded.ino != now.ino {
        changed.push("file identity");
    }
    Some(format!("its {} differs", changed.join(", ")))
}

/// The verification this file is entitled to, and why not when it is not.
///
/// Only the private trust record counts, and only while the file still has the
/// fingerprint it was verified at. Anything unreadable is "not verified" rather than a
/// broken listing — a record written by a newer pam, half-written by a crash, or
/// edited by a curious human should cost one re-verification. A legacy sidecar beside
/// the file is *never* trusted — anything that can write the models directory can write
/// one — but its presence explains to the human why a once-verified model needs a
/// second verification.
fn read_verified(
    path: &Path,
    fingerprint: &FileFingerprint,
    trust_dir: Option<&Path>,
) -> (Option<VerifiedRecord>, Option<String>) {
    let legacy = verified_sidecar_path(path).exists();
    let legacy_hint = || {
        legacy.then(|| {
            "an old verification sidecar sits beside this file but sidecars are no longer \
             trusted; verify again"
                .to_owned()
        })
    };
    let Some(trust_dir) = trust_dir else {
        return (None, legacy_hint());
    };
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let Ok(bytes) = std::fs::read(trust_record_path(trust_dir, &canonical)) else {
        return (None, legacy_hint());
    };
    let Ok(trust) = serde_json::from_slice::<TrustRecord>(&bytes) else {
        return (
            None,
            Some("the verification record could not be read; verify again".to_owned()),
        );
    };
    if trust.version != TRUST_RECORD_VERSION || trust.path != canonical.to_string_lossy() {
        return (
            None,
            Some("the verification record does not describe this file; verify again".to_owned()),
        );
    }
    match fingerprint_difference(&trust.fingerprint, fingerprint) {
        None => (Some(trust.record), None),
        Some(what) => (
            None,
            Some(format!(
                "the file changed after it was verified ({what}); verify again"
            )),
        ),
    }
}

/// Whether `name` is one plain path segment: non-empty, not hidden, not
/// `.` or `..`, and only `[A-Za-z0-9._-]` — so no separator, drive letter
/// or root on any platform.
#[must_use]
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Whether a path names a GGUF file. Extension-based rather than
/// suffix-based, so `.GGUF` from a case-insensitive filesystem counts.
fn is_gguf(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gguf"))
}

fn file_name_string(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Whether a file may be a tier default at all: only a verified digest admits it.
#[must_use]
pub fn classify(verified: Option<&VerifiedRecord>) -> ModelClass {
    if verified.is_some() {
        ModelClass::Engine
    } else {
        ModelClass::TestOnly
    }
}

/// The qualification a verified digest carries on the current target, from
/// `records`. Nothing is qualified without a verification, on an unsupported
/// target, or on a target the record does not cover.
#[must_use]
pub fn qualify(
    verified: Option<&VerifiedRecord>,
    records: &'static [Qualification],
) -> Option<Qualification> {
    let target = Target::current()?;
    qualification::find_in(records, &verified?.sha256, target).copied()
}

/// `$HOME/llm` — the owner's existing layout, and the default the daemon
/// starts from.
///
/// `None` when the environment has no home directory at all, which the
/// caller reports rather than guessing at `/`.
#[must_use]
pub fn default_models_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join("llm"))
}

/// The legacy verification sidecar for a model file: `.<file name>.pam-model.verified`
/// beside it. Nothing writes it any more and nothing trusts it; it is looked for to
/// hint "verify again" and removed with the model it sat beside.
///
/// Hidden, so it never shows up in a listing of the vendor directory, and
/// prefixed by the model's own name, so two models in one directory cannot
/// collide.
#[must_use]
pub fn verified_sidecar_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}{VERIFIED_SIDECAR_SUFFIX}"))
}

/// Streams SHA-256 over a file, returning the lowercase hex digest and the
/// bytes read.
///
/// Chunked rather than read-to-end: these files are tens of gigabytes and
/// the point is to check them without needing room for them.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK_BYTES];
    let mut total: u64 = 0;

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
    }

    Ok((hex::encode(hasher.finalize()), total))
}
