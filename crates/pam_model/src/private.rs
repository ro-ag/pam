//! Small owner-only file helpers shared by the registry's verification records and
//! the engine supervisor's runtime files (API key file, pid file).
//!
//! Everything written here is private to the daemon's user: directories are created
//! `0700` and files `0600` on Unix (no mode concept elsewhere, where the parent
//! directory's access control is what applies). Writes go to a sibling temp file and
//! are renamed into place, so a crash leaves the old content rather than a truncated file.

use std::io::Write as _;
use std::path::Path;

/// Creates `dir` (and parents) owner-only on Unix.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `bytes` to `path` atomically, owner-only on Unix. The parent directory
/// is created owner-only when missing.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    let temp = path.with_extension("tmp");
    // A leftover temp from a crash would make `create_new` fail forever.
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })
}
