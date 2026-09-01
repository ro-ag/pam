//! GUI-local log reading: the tail of the daemon's own log file.
//!
//! # Why this is not a daemon operation
//!
//! The daemon log (`<base>/log/daemon.log`, written by
//! `pam_daemon::lifecycle::init_daemon_logging`) is the daemon's own
//! diagnostics — and its most important audience is a human debugging a
//! daemon that will not start or will not answer. Reading it must
//! therefore work precisely when the daemon is down, so it can never be
//! an IPC capability. The GUI process runs as the same user; it reads
//! the file straight from disk instead.
//!
//! Rotation: `tracing_appender::rolling::daily` appends the date to the
//! prefix (`daemon.log.2026-09-01`), so "the newest file" is the
//! lexicographically greatest `daemon.log*` name — ISO dates sort
//! correctly as strings, no mtime reads needed.

use std::fs;
use std::path::{Path, PathBuf};

use pam_daemon::lifecycle::{LOG_DIR, LOG_FILE};
use serde::Serialize;

use crate::bridge::{BridgeError, resolve_base_dir};

/// Smallest tail a caller can ask for; anything lower clamps up.
pub const MIN_LINES: u32 = 50;

/// Largest tail a caller can ask for; anything higher clamps down so a
/// huge log never floods the webview.
pub const MAX_LINES: u32 = 1_000;

/// What [`read_daemon_log`] answers: which file was read, and its tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogTail {
    /// Full path of the log file the tail came from.
    pub file: String,
    /// The last lines of that file, oldest first.
    pub lines: Vec<String>,
}

/// The requested line count folded into the allowed window.
#[must_use]
pub fn clamp_lines(lines: u32) -> u32 {
    lines.clamp(MIN_LINES, MAX_LINES)
}

/// The refusal for "no daemon log exists yet" — a legible state, not a
/// crash: a fresh install has simply never started the daemon.
fn no_log_yet(dir: &Path) -> BridgeError {
    BridgeError::new(
        "no_daemon_log",
        format!("no daemon log exists under {}", dir.display()),
        "Start the daemon once (any status poll starts it lazily); it logs from its first breath.",
    )
}

/// The newest `daemon.log*` file in `dir`: greatest name wins, because
/// daily rotation suffixes ISO dates (see the module docs). `Ok(None)`
/// when the directory holds no log files.
fn newest_log_file(dir: &Path) -> std::io::Result<Option<PathBuf>> {
    let mut newest: Option<(std::ffi::OsString, PathBuf)> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(LOG_FILE) || !entry.file_type()?.is_file() {
            continue;
        }
        if newest.as_ref().is_none_or(|(best, _)| name > *best) {
            newest = Some((name, entry.path()));
        }
    }
    Ok(newest.map(|(_, path)| path))
}

/// Reads the last `lines` (clamped) lines of the newest daemon log under
/// `base`. Pure disk I/O — works with the daemon down, which is the
/// whole point (module docs).
pub fn tail_daemon_log(base: &Path, lines: u32) -> Result<LogTail, BridgeError> {
    let wanted = clamp_lines(lines) as usize;
    let dir = base.join(LOG_DIR);
    let newest = match newest_log_file(&dir) {
        Ok(Some(path)) => path,
        Ok(None) => return Err(no_log_yet(&dir)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err(no_log_yet(&dir)),
        Err(err) => {
            return Err(BridgeError::new(
                "log_unreadable",
                format!("cannot list {}: {err}", dir.display()),
                "Check permissions on the pam log directory.",
            ));
        }
    };
    // Lossy: a stray non-UTF-8 byte must never make the whole log
    // unviewable — this is a diagnostics viewer, not an archive.
    let bytes = fs::read(&newest).map_err(|err| {
        BridgeError::new(
            "log_unreadable",
            format!("cannot read {}: {err}", newest.display()),
            "Check permissions on the pam log directory.",
        )
    })?;
    let content = String::from_utf8_lossy(&bytes);
    let all: Vec<&str> = content.lines().collect();
    let tail = &all[all.len().saturating_sub(wanted)..];
    Ok(LogTail {
        file: newest.display().to_string(),
        lines: tail.iter().map(ToString::to_string).collect(),
    })
}

/// The tail of the newest daemon log file, read straight from disk (no
/// daemon involved — see the module docs for why). `lines` is clamped
/// to [`MIN_LINES`]..=[`MAX_LINES`].
#[tauri::command]
pub fn read_daemon_log(lines: u32) -> Result<LogTail, BridgeError> {
    let base = resolve_base_dir()?;
    tail_daemon_log(&base, lines)
}
