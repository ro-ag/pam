//! The first hundred bytes of the state file, read as plain bytes.
//!
//! Whether a file needs a backup before it is upgraded has to be decided
//! before the engine opens it: opening is the first thing that could change
//! it. The database header answers that without the engine. It can lag the
//! write-ahead log (a version stamped by a commit that was never
//! checkpointed is only in the log), never run ahead of it, so a decision
//! made from the header errs toward one backup too many and never toward one
//! too few; the open path corrects the label once the engine has read the
//! real version (see `open`).

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{EngineError, StoreError};

/// Length of a database header.
const HEADER_BYTES: usize = 100;

/// What every database file starts with.
const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// The version number the engine that wrote the fixtures and every released
/// database up to 0.4.3 stamps at offsets 92 and 96 (it never updates them).
const PREVIOUS_ENGINE_STAMP: u32 = 3_047_000;

/// The engine's result code for a file that cannot be opened.
const CANNOT_OPEN: i32 = 14;

/// The fields of a database header the open path decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// `PRAGMA user_version` as the main file records it.
    pub(crate) user_version: i64,
    /// `PRAGMA application_id` as the main file records it.
    pub(crate) application_id: i64,
    /// True when the header carries the previous engine's fixed stamp: the
    /// file has not been written by this engine since.
    pub(crate) previous_engine: bool,
}

/// What is at the state file's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnDisk {
    /// Nothing: the database is created.
    Absent,
    /// A zero-length file with no log beside it, in a directory that shows
    /// no sign of an earlier pam (see [`inspect`]). It holds nothing and is
    /// treated as a database about to be created.
    Empty,
    /// A database file.
    Database(Header),
}

/// The file `suffix` names beside the state file (`-wal`, `-shm`, ...).
pub(crate) fn sibling(state: &Path, suffix: &str) -> PathBuf {
    let mut name = state.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Reads the header of the file at `state` without the engine.
///
/// Refuses, without touching anything, a file that cannot be a database:
/// shorter than a header, or not starting with the header's magic. Refuses
/// likewise a missing or empty main file with a non-empty write-ahead log
/// beside it: the log holds commits of a main file that is gone, and the
/// engine, opening that pair, would delete the log as stale.
///
/// An empty main file with no log is refused too when its directory has
/// been a pam base before (`previous_install`): a zero-length file where a
/// database is expected is not a database pam wrote, and opening it as a new
/// one would start the grants, the approvals and the audit history over
/// without a word. Only a file that does not exist, or an empty one in a
/// directory pam has never used, is a database about to be created.
pub(crate) fn inspect(state: &Path) -> Result<OnDisk, StoreError> {
    let mut file = match std::fs::File::open(state) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            orphan_log(state, "is missing")?;
            return Ok(OnDisk::Absent);
        }
        Err(error) => return Err(unreadable(state, &error)),
    };
    let length = file
        .metadata()
        .map_err(|error| unreadable(state, &error))?
        .len();
    if length == 0 {
        orphan_log(state, "is empty")?;
        if let Some(sign) = previous_install(state) {
            return Err(emptied(state, &sign));
        }
        return Ok(OnDisk::Empty);
    }
    if length < HEADER_BYTES as u64 {
        return Err(StoreError::Corrupt {
            detail: format!(
                "the state file is {length} bytes, shorter than a database header: it \
                 was truncated or is not a database. Nothing was changed"
            ),
        });
    }
    let mut bytes = [0u8; HEADER_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|error| unreadable(state, &error))?;
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(StoreError::Corrupt {
            detail: "the state file does not start with a database header: it is not \
                     a database. Nothing was changed"
                .to_owned(),
        });
    }
    Ok(OnDisk::Database(Header {
        user_version: i64::from(signed(&bytes, 60)),
        application_id: i64::from(signed(&bytes, 68)),
        previous_engine: unsigned(&bytes, 92) == PREVIOUS_ENGINE_STAMP
            && unsigned(&bytes, 96) == PREVIOUS_ENGINE_STAMP,
    }))
}

/// Refuses when a write-ahead log with content sits beside a main file that
/// `what` (is missing, is empty).
fn orphan_log(state: &Path, what: &str) -> Result<(), StoreError> {
    let log = sibling(state, "-wal");
    let log_bytes = std::fs::metadata(&log).map_or(0, |meta| meta.len());
    if log_bytes == 0 {
        return Ok(());
    }
    Err(StoreError::Corrupt {
        detail: format!(
            "the state file {what} but its write-ahead log {} holds {log_bytes} bytes: \
             the main file was removed, truncated or replaced without its log. \
             Nothing was changed. Put the state file back beside the log, or, to \
             start empty, move the log and the -shm file away as well",
            log.display()
        ),
    })
}

/// What a pam daemon leaves in its base directory besides the state file,
/// as `(path below the base, must hold something)`: the store's own backups,
/// the daemon's log directory, its instance lock, the flow library and the
/// record of verified models. The names are the daemon's; the store only
/// looks for them.
const INSTALL_SIGNS: [(&str, bool); 5] = [
    (crate::backup::DIR, false),
    ("log", true),
    ("run/daemon.lock", false),
    ("flows", false),
    ("model-trust", false),
];

/// The first thing beside `state` that says pam has run in this directory
/// before, or `None` in a directory that holds nothing of pam's.
///
/// The daemon takes its instance lock, and may start its log, before it
/// opens the store, so a daemon's base always shows a sign: there an empty
/// state file is never opened as a new database.
fn previous_install(state: &Path) -> Option<PathBuf> {
    let base = state.parent().unwrap_or_else(|| Path::new(""));
    INSTALL_SIGNS
        .iter()
        .find_map(|(name, must_hold_something)| {
            let path = base.join(name);
            let found = if *must_hold_something {
                std::fs::read_dir(&path).is_ok_and(|mut entries| entries.next().is_some())
            } else {
                path.exists()
            };
            found.then_some(path)
        })
}

/// The refusal for an empty state file in a directory pam has used.
fn emptied(state: &Path, sign: &Path) -> StoreError {
    let root = crate::backup::root_for(state);
    let way_back = match crate::backup::newest(&root) {
        Some(dir) => format!(
            "To recover, stop the daemon, then either restore the newest backup from \
             {} (copy its files over the state file and beside it; it is as old as \
             the upgrade it was made before), or move the empty file aside to start \
             fresh",
            dir.display()
        ),
        None => format!(
            "There is no backup under {}. To recover, stop the daemon, then either \
             put back a copy of the state file you kept, or move the empty file \
             aside to start fresh",
            root.display()
        ),
    };
    StoreError::Corrupt {
        detail: format!(
            "the state file {} is empty, and this directory has been used by pam \
             before ({} exists): an empty file is not a database pam wrote, and \
             opening it as a new one would silently start the grants, approvals and \
             audit history over. Nothing was changed. {way_back}",
            state.display(),
            sign.display()
        ),
    }
}

/// A big-endian 32-bit field of the header.
fn unsigned(bytes: &[u8; HEADER_BYTES], offset: usize) -> u32 {
    let mut field = [0u8; 4];
    field.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(field)
}

fn signed(bytes: &[u8; HEADER_BYTES], offset: usize) -> i32 {
    let mut field = [0u8; 4];
    field.copy_from_slice(&bytes[offset..offset + 4]);
    i32::from_be_bytes(field)
}

/// The state file exists and could not be read: nothing can be decided about
/// it, so nothing is done to it.
fn unreadable(state: &Path, error: &std::io::Error) -> StoreError {
    StoreError::Database(EngineError::new(
        CANNOT_OPEN,
        &format!(
            "the state file {} could not be read ({error}); it was not changed. \
             Check that the user running pam owns it and may read and write it",
            state.display()
        ),
    ))
}
