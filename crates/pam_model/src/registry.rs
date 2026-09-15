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
//! [`Registry::verify`] streams SHA-256 to a `.<file>.pam-model.verified`
//! sidecar; against a matching catalog preset it records `Some(true)` (expected bytes),
//! `Some(false)` (wrong bytes under that name), or `None` (nothing to compare); an
//! unreadable or stale sidecar counts as absent, not an error. All calls hit the
//! filesystem synchronously; async callers wrap them in `spawn_blocking`.
//! A model dropped into the directory by hand and one PAM downloaded are the same kind of entry.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::catalog::{CATALOG, find_preset};
use crate::engine::Target;
use crate::gguf::{self, GgufError, GgufInfo};
use crate::qualification::{self, Qualification};

/// Chunk size for [`sha256_file`]. Big enough that the syscall overhead
/// disappears, small enough to stay off the stack and out of the way.
const HASH_CHUNK_BYTES: usize = 1024 * 1024;

/// Suffix of the verification sidecar written next to a model file.
const VERIFIED_SIDECAR_SUFFIX: &str = ".pam-model.verified";

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
    /// The last verification, read back from the sidecar.
    pub verified: Option<VerifiedRecord>,
    /// The admission evidence for this exact digest on this target, when there is
    /// any. `None` for an unverified file, a verified file nobody has measured, or a
    /// measured file on a target it was not measured on.
    pub qualification: Option<Qualification>,
    /// Catalog preset whose file name this is, when there is one.
    pub catalog_id: Option<&'static str>,
}

/// A verification result, persisted next to the model.
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
        }
    }

    /// The models directory this registry covers.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where a download of `file_name` from `vendor` should land.
    #[must_use]
    pub fn dest_for(&self, vendor: &str, file_name: &str) -> PathBuf {
        self.dir.join(vendor).join(file_name)
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
                entries.push(describe(
                    &path,
                    &vendor,
                    &file_name,
                    model_entry.metadata()?.len(),
                    self.qualifications,
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

        let (sha256, size_bytes) = sha256_file(&entry.path)?;
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
        self.record_verified(&entry.path, &record)?;

        Ok(VerifyOutcome {
            sha256,
            size_bytes,
            matches_catalog,
        })
    }

    /// Writes a verification sidecar next to `path`.
    ///
    /// A finished download calls this directly: it already hashed the bytes
    /// on the way in, and re-reading the whole file to learn what it just
    /// computed would be absurd.
    ///
    /// The write goes to a temp file and is renamed into place, so a crash
    /// mid-write leaves the old sidecar rather than a truncated one.
    pub fn record_verified(
        &self,
        path: &Path,
        record: &VerifiedRecord,
    ) -> Result<(), RegistryError> {
        let sidecar = verified_sidecar_path(path);
        let json = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;

        let temp = sidecar.with_extension("verified.tmp");
        std::fs::write(&temp, &json)?;
        std::fs::rename(&temp, &sidecar)?;
        Ok(())
    }

    /// Deletes a model file and its verification sidecar.
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
        if sidecar.exists() {
            std::fs::remove_file(&sidecar)?;
        }
        Ok(())
    }
}

/// Builds the entry for one file, reading its header and its sidecar.
fn describe(
    path: &Path,
    vendor: &str,
    file_name: &str,
    size_bytes: u64,
    qualifications: &'static [Qualification],
) -> ModelEntry {
    let stem = file_name.strip_suffix(".gguf").unwrap_or(file_name);
    let (info, info_error) = match gguf::read_info(path) {
        Ok(info) => (Some(info), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let verified = read_verified(path);
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
        qualification,
        catalog_id: CATALOG
            .iter()
            .find(|preset| preset.file_name == file_name)
            .map(|preset| preset.id),
    }
}

/// Reads a verification sidecar, treating anything unreadable as absent.
///
/// A sidecar written by a newer pam, half-written by a crash, or edited by
/// a curious human should cost one re-verification, not a broken listing.
fn read_verified(path: &Path) -> Option<VerifiedRecord> {
    let bytes = std::fs::read(verified_sidecar_path(path)).ok()?;
    serde_json::from_slice(&bytes).ok()
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

/// The verification sidecar for a model file: `.<file name>.pam-model.verified`
/// beside it.
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
