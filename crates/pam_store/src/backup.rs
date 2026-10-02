//! Copies of the database files, made before an upgrade touches them.
//!
//! A backup is a directory under `<state file's directory>/backup/` holding
//! plain copies of the state file and of whichever of its `-wal`, `-shm` and
//! `-journal` companions exist, byte for byte as they were found. Together
//! those files are the database; a copy of the main file alone would lose
//! every commit still in the log, silently.
//!
//! - `state-<UTC time>-pre-sqlite`: made once, before this engine opens a
//!   database last written by the previous one (or by a pam older than the
//!   schema version at which the engines changed). Never deleted by pam.
//! - `state-<UTC time>-pre-v<N>`: made before a batch of schema migrations
//!   takes the database to version `N`. Only the newest
//!   [`KEEP_MIGRATION_BACKUPS`] are kept.
//!
//! The copy is written into a `.partial-` directory, every file and the
//! directory are synced, and only then is it renamed to its final name, so a
//! directory with a final name is always a complete copy. An existing backup
//! is never overwritten. When a backup of the same kind already holds exactly
//! the files being backed up, it is reused instead of copied again: a daemon
//! that a service manager restarts against a database it refuses does not
//! fill the disk.
//!
//! To restore one: stop the daemon, copy the files in the backup directory
//! over the ones beside `backup/` (removing a `-wal` or `-shm` the backup does
//! not have), and start the pam version that wrote them.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::StoreError;
use crate::header::sibling;

/// Directory, beside the state file, that holds the backups.
pub(crate) const DIR: &str = "backup";

/// Migration backups kept. Each is a full copy of the database, so the
/// number is small: enough to step back over the last few schema changes,
/// not a history.
pub(crate) const KEEP_MIGRATION_BACKUPS: usize = 3;

/// The files that together are one database: the main file, its write-ahead
/// log, the log's index, and the rollback journal of a database that was not
/// in WAL mode.
const SUFFIXES: [&str; 4] = ["", "-wal", "-shm", "-journal"];

/// Of [`SUFFIXES`], the files whose bytes are the database's content. The
/// log index is rebuilt by whoever opens the database, so it does not count
/// when two copies are compared.
const CONTENT_SUFFIXES: [&str; 3] = ["", "-wal", "-journal"];

const PREFIX: &str = "state-";
const PARTIAL_PREFIX: &str = ".partial-";

/// Length of a [`utc_stamp`].
const STAMP_LEN: usize = 16;

/// Attempts at a name for a backup made in the same second as another.
const MAX_SAME_SECOND: u32 = 100;

/// Why a backup is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Before the first open by this engine.
    PreSqlite,
    /// Before migrating to this schema version.
    PreSchema(i64),
}

impl Kind {
    fn label(self) -> String {
        match self {
            Self::PreSqlite => "pre-sqlite".to_owned(),
            Self::PreSchema(version) => format!("pre-v{version}"),
        }
    }
}

/// A backup directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Backup {
    /// Where the copy is.
    pub(crate) dir: PathBuf,
    /// What it was made for.
    pub(crate) kind: Kind,
    /// True when this call wrote it; false when an identical one was found.
    pub(crate) created: bool,
}

/// The backup directory for the database at `state`.
pub(crate) fn root_for(state: &Path) -> PathBuf {
    match state.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(DIR),
        _ => PathBuf::from(DIR),
    }
}

/// Copies the database at `state` into a new backup of `kind`, or finds the
/// existing backup of that kind that already holds the same files.
///
/// On any failure nothing of the database has been touched, the partial copy
/// is removed, and the error names the directory and the space the copy
/// needs.
pub(crate) fn take(state: &Path, kind: Kind) -> Result<Backup, StoreError> {
    let root = root_for(state);
    let needed_bytes = SUFFIXES
        .iter()
        .filter_map(|suffix| fs::metadata(sibling(state, suffix)).ok())
        .map(|meta| meta.len())
        .sum();
    let refused = |source: io::Error| StoreError::UpgradeBackup {
        path: root.clone(),
        needed_bytes,
        source,
    };
    create_private_dir(&root, true).map_err(&refused)?;
    remove_partials(&root);
    if let Some(dir) = find_identical(&root, state, kind).map_err(&refused)? {
        tracing::info!(backup = %dir.display(), "the backup of these database files already exists");
        return Ok(Backup {
            dir,
            kind,
            created: false,
        });
    }
    let stamp = utc_stamp(SystemTime::now());
    let label = kind.label();
    let partial = root.join(format!("{PARTIAL_PREFIX}{PREFIX}{stamp}-{label}"));
    let copied = copy_into(state, &partial).and_then(|()| publish(&root, &partial, &stamp, &label));
    match copied {
        Ok(dir) => {
            tracing::info!(
                backup = %dir.display(),
                bytes = needed_bytes,
                "copied the database files before upgrading them"
            );
            Ok(Backup {
                dir,
                kind,
                created: true,
            })
        }
        Err(source) => {
            // Ours, and incomplete: never mistaken for a backup.
            let _ = fs::remove_dir_all(&partial);
            Err(refused(source))
        }
    }
}

/// Removes a backup this open made and then found it did not need: the
/// header said an upgrade was pending and the log said it had already
/// happened. A backup that was found rather than made is left alone.
pub(crate) fn discard(backup: &Backup) {
    if !backup.created {
        return;
    }
    match fs::remove_dir_all(&backup.dir) {
        Ok(()) => tracing::info!(
            backup = %backup.dir.display(),
            "removed a backup made a moment ago: the database was already upgraded"
        ),
        Err(error) => tracing::warn!(
            backup = %backup.dir.display(),
            %error,
            "a backup that turned out to be unneeded could not be removed"
        ),
    }
}

/// Gives a backup this open made the label of what it turned out to precede.
/// A backup that was found rather than made keeps its name.
pub(crate) fn relabel(backup: Backup, kind: Kind) -> Backup {
    if !backup.created || backup.kind == kind {
        return backup;
    }
    let Some(root) = backup.dir.parent() else {
        return backup;
    };
    let stamp = utc_stamp(SystemTime::now());
    let Some(target) = free_name(root, &stamp, &kind.label()) else {
        return backup;
    };
    match fs::rename(&backup.dir, &target) {
        Ok(()) => Backup {
            dir: target,
            kind,
            created: true,
        },
        Err(error) => {
            tracing::warn!(backup = %backup.dir.display(), %error, "a backup could not be renamed");
            backup
        }
    }
}

/// Removes migration backups beyond the newest [`KEEP_MIGRATION_BACKUPS`].
/// Pre-engine backups are never removed. Failures are logged: retention is
/// housekeeping and never fails an open.
pub(crate) fn prune_migration_backups(root: &Path) {
    let mut migration: Vec<(String, u32, PathBuf)> = list(root)
        .into_iter()
        .filter(|entry| matches!(entry.kind, Kind::PreSchema(_)))
        .map(|entry| (entry.stamp, entry.serial, entry.dir))
        .collect();
    migration.sort();
    let excess = migration.len().saturating_sub(KEEP_MIGRATION_BACKUPS);
    for (_, _, dir) in migration.into_iter().take(excess) {
        match fs::remove_dir_all(&dir) {
            Ok(()) => {
                tracing::info!(backup = %dir.display(), "removed a migration backup past the retention count");
            }
            Err(error) => {
                tracing::warn!(backup = %dir.display(), %error, "an old migration backup could not be removed");
            }
        }
    }
}

/// The newest complete backup under `root`, of any kind.
pub(crate) fn newest(root: &Path) -> Option<PathBuf> {
    list(root)
        .into_iter()
        .max_by(|a, b| (&a.stamp, a.serial).cmp(&(&b.stamp, b.serial)))
        .map(|entry| entry.dir)
}

/// One complete backup directory, by its name.
struct Entry {
    dir: PathBuf,
    stamp: String,
    kind: Kind,
    serial: u32,
}

/// Every directory under `root` whose name is a complete backup's.
fn list(root: &Path) -> Vec<Entry> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let name = entry.file_name();
            let (stamp, kind, serial) = parse_name(name.to_str()?)?;
            Some(Entry {
                dir: entry.path(),
                stamp,
                kind,
                serial,
            })
        })
        .collect()
}

/// Splits `state-<stamp>-<label>[-<serial>]`. Anything else is not a backup
/// of ours and is never listed, compared or removed.
fn parse_name(name: &str) -> Option<(String, Kind, u32)> {
    let rest = name.strip_prefix(PREFIX)?;
    let stamp = rest.get(..STAMP_LEN)?;
    if !is_stamp(stamp) {
        return None;
    }
    let rest = rest.get(STAMP_LEN..)?.strip_prefix('-')?;
    let (label, serial) = match rest.rsplit_once('-') {
        Some((label, serial)) if label.starts_with("pre-") && is_digits(serial) => {
            (label, serial.parse().ok()?)
        }
        _ => (rest, 1),
    };
    let kind = if label == "pre-sqlite" {
        Kind::PreSqlite
    } else {
        let version = label.strip_prefix("pre-v")?;
        if !is_digits(version) {
            return None;
        }
        Kind::PreSchema(version.parse().ok()?)
    };
    Some((stamp.to_owned(), kind, serial))
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// `YYYYMMDDTHHMMSSZ`.
fn is_stamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == STAMP_LEN
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..15].iter().all(u8::is_ascii_digit)
}

/// The existing backup of `kind` whose content files equal the ones at
/// `state`, if any.
fn find_identical(root: &Path, state: &Path, kind: Kind) -> io::Result<Option<PathBuf>> {
    for entry in list(root) {
        if entry.kind != kind {
            continue;
        }
        let mut same = true;
        for suffix in CONTENT_SUFFIXES {
            let name = file_name(state, suffix);
            if !same_bytes(&sibling(state, suffix), &entry.dir.join(name))? {
                same = false;
                break;
            }
        }
        if same {
            return Ok(Some(entry.dir));
        }
    }
    Ok(None)
}

/// The name of the state file's `suffix` companion, without its directory.
fn file_name(state: &Path, suffix: &str) -> PathBuf {
    let mut name = state
        .file_name()
        .map_or_else(|| "state.sqlite3".into(), std::ffi::OsStr::to_owned);
    name.push(suffix);
    PathBuf::from(name)
}

/// True when both files are absent, or both exist with the same bytes.
fn same_bytes(left: &Path, right: &Path) -> io::Result<bool> {
    let (mut left, mut right) = match (open_existing(left)?, open_existing(right)?) {
        (None, None) => return Ok(true),
        (Some(left), Some(right)) => (left, right),
        _ => return Ok(false),
    };
    if left.metadata()?.len() != right.metadata()?.len() {
        return Ok(false);
    }
    let mut a = vec![0u8; 64 * 1024];
    let mut b = vec![0u8; 64 * 1024];
    loop {
        let read = read_full(&mut left, &mut a)?;
        if read_full(&mut right, &mut b)? != read || a[..read] != b[..read] {
            return Ok(false);
        }
        if read == 0 {
            return Ok(true);
        }
    }
}

fn open_existing(path: &Path) -> io::Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Fills `buffer` as far as the file goes; a short count means end of file.
fn read_full(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Copies every file of the database at `state` into the new directory
/// `partial` and syncs the copies and the directory.
fn copy_into(state: &Path, partial: &Path) -> io::Result<()> {
    create_private_dir(partial, false)?;
    for suffix in SUFFIXES {
        let Some(mut source) = open_existing(&sibling(state, suffix))? else {
            continue;
        };
        let mut copy = create_private_file(&partial.join(file_name(state, suffix)))?;
        io::copy(&mut source, &mut copy)?;
        copy.sync_all()?;
    }
    sync_dir(partial)
}

/// Gives the finished copy its final name, which no existing backup has.
fn publish(root: &Path, partial: &Path, stamp: &str, label: &str) -> io::Result<PathBuf> {
    let target = free_name(root, stamp, label).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "every backup name for this second is taken",
        )
    })?;
    fs::rename(partial, &target)?;
    sync_dir(root)?;
    Ok(target)
}

/// A backup name under `root` that nothing has yet.
fn free_name(root: &Path, stamp: &str, label: &str) -> Option<PathBuf> {
    (1..=MAX_SAME_SECOND)
        .map(|serial| {
            if serial == 1 {
                root.join(format!("{PREFIX}{stamp}-{label}"))
            } else {
                root.join(format!("{PREFIX}{stamp}-{label}-{serial}"))
            }
        })
        .find(|candidate| fs::symlink_metadata(candidate).is_err())
}

/// Copies a killed process left unfinished. They carry the partial prefix,
/// which only this module writes.
fn remove_partials(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(PARTIAL_PREFIX))
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// A directory only the owner can enter. With `existing_ok` an existing
/// directory is accepted as it is (and its parents are created).
fn create_private_dir(path: &Path, existing_ok: bool) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(existing_ok);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    if fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the backup path exists and is not a directory",
        ))
    }
}

/// A new file only the owner can read; never an existing one.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Makes a directory's entries durable. Windows has no way to sync a
/// directory handle; there the rename is durable when the file system's
/// journal says so.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// `YYYYMMDDTHHMMSSZ` for `time`, in UTC.
pub(crate) fn utc_stamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let rest = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    // Shifted so the count starts on 0000-03-01: leap days fall at the end
    // of each 400-year era.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}
