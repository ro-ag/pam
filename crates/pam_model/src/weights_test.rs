use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::registry::{FileFingerprint, sha256_file};
use crate::weights::{
    Control, CopyHooks, CopyMethod, FREE_SPACE_HEADROOM_BYTES, WeightStore, WeightsError,
    parse_df_available_kib, platform_clone, platform_free_bytes,
};

/// Hooks that behave like another volume: nothing clones, and `free` bytes are free.
fn other_volume(free: Option<u64>) -> CopyHooks {
    CopyHooks {
        clone: Arc::new(|_, _| Ok(false)),
        free_bytes: Arc::new(move |_| free),
    }
}

/// A source file of `len` patterned bytes and an empty private store beside it.
fn fixture(len: usize, hooks: CopyHooks) -> (tempfile::TempDir, PathBuf, WeightStore) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("model.gguf");
    let bytes: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
    std::fs::write(&source, bytes).unwrap();
    let store = WeightStore::new(dir.path().join("private").join("weights"), hooks);
    (dir, source, store)
}

fn files_in(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        },
    )
}

#[test]
fn a_location_that_cannot_clone_gets_a_copy_hashed_in_the_same_pass() {
    // Three chunks and a remainder, so the copy loop and the progress run more than once.
    let (_dir, source, store) = fixture(3 * 1024 * 1024 + 17, other_volume(None));
    let seen = AtomicU64::new(0);
    let control = Control {
        progress: &|done| {
            assert!(
                done >= seen.swap(done, Ordering::SeqCst),
                "progress only grows"
            );
        },
        cancelled: &|| false,
    };

    let staged = store.stage(&source, &control).unwrap();
    assert_eq!(staged.method, CopyMethod::Copied);
    let (expected, size) = sha256_file(&source).unwrap();
    assert_eq!(
        (staged.sha256.as_str(), staged.size_bytes),
        (expected.as_str(), size)
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        size,
        "progress reached the whole file"
    );

    let (private, method) = store.commit(staged, None).unwrap();
    assert_eq!(method, CopyMethod::Copied);
    assert_eq!(private.path, store.path_for(&expected));
    assert_eq!(
        sha256_file(&private.path).unwrap().0,
        expected,
        "the private file has the digest it is named by"
    );
    assert_eq!(
        private.fingerprint,
        FileFingerprint::read(&private.path).unwrap()
    );
    assert_eq!(files_in(store.dir()), vec![format!("{expected}.gguf")]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&private.path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400, "owner read-only");
        let dir_mode = std::fs::metadata(store.dir()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "the store is the owner's alone");
    }
}

#[test]
fn a_short_disk_is_refused_with_the_bytes_needed_before_anything_is_written() {
    let (_dir, source, store) = fixture(4096, other_volume(Some(1000)));

    let refused = store.stage(&source, &Control::none()).unwrap_err();
    let WeightsError::NoSpace { needed, free, .. } = &refused else {
        panic!("expected a space refusal, got {refused:?}");
    };
    assert_eq!(*needed, 4096 + FREE_SPACE_HEADROOM_BYTES);
    assert_eq!(*free, Some(1000));
    let message = refused.to_string();
    assert!(
        message.contains(&needed.to_string()) && message.contains("1000 bytes free"),
        "the refusal names both figures: {message}"
    );
    assert!(
        files_in(store.dir()).is_empty(),
        "nothing was written: {:?}",
        files_in(store.dir())
    );
}

#[test]
fn a_volume_that_fills_under_the_copy_is_the_same_refusal() {
    // The pre-check saw room (or could not see): the write itself reports the full disk.
    let hooks = CopyHooks {
        clone: Arc::new(|_, _| Err(std::io::Error::from(std::io::ErrorKind::StorageFull))),
        free_bytes: Arc::new(|_| None),
    };
    let (_dir, source, store) = fixture(64, hooks);

    let refused = store.stage(&source, &Control::none()).unwrap_err();
    assert!(
        matches!(refused, WeightsError::NoSpace { free: None, needed, .. } if needed == 64 + FREE_SPACE_HEADROOM_BYTES),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("an unknown amount free"));
    assert!(files_in(store.dir()).is_empty());
}

#[test]
fn a_cancel_stops_the_copy_and_removes_what_it_wrote() {
    let (_dir, source, store) = fixture(4 * 1024 * 1024, other_volume(None));
    let cancel = AtomicBool::new(false);
    let control = Control {
        // Cancelled once the first chunk has landed: a copy really was in flight.
        progress: &|_| cancel.store(true, Ordering::SeqCst),
        cancelled: &|| cancel.load(Ordering::SeqCst),
    };

    assert!(matches!(
        store.stage(&source, &control),
        Err(WeightsError::Cancelled)
    ));
    assert!(
        files_in(store.dir()).is_empty(),
        "the partial copy is gone: {:?}",
        files_in(store.dir())
    );
}

#[test]
fn a_vouched_copy_is_reused_and_an_unvouched_one_is_replaced() {
    let (_dir, source, store) = fixture(1024, other_volume(None));
    let (first, _) = store
        .commit(store.stage(&source, &Control::none()).unwrap(), None)
        .unwrap();

    // A record vouches for the file as it is: the second staging is dropped.
    let again = store.stage(&source, &Control::none()).unwrap();
    let (kept, method) = store.commit(again, Some(first.fingerprint)).unwrap();
    assert_eq!(method, CopyMethod::Reused);
    assert_eq!(kept, first);
    assert_eq!(files_in(store.dir()).len(), 1, "no staging file is left");

    // Nothing vouches for it (or the fingerprint on record is another file's): replaced.
    let again = store.stage(&source, &Control::none()).unwrap();
    let (replaced, method) = store
        .commit(again, Some(FileFingerprint::default()))
        .unwrap();
    assert_eq!(method, CopyMethod::Copied);
    assert_eq!(replaced.path, first.path);
    assert_eq!(files_in(store.dir()).len(), 1);
    assert_eq!(store.copies().len(), 1);
    assert!(store.incoming().is_empty());
}

#[test]
fn a_dropped_staging_leaves_nothing_behind() {
    let (_dir, source, store) = fixture(1024, other_volume(None));
    let staged = store.stage(&source, &Control::none()).unwrap();
    assert_eq!(
        store.incoming().len(),
        1,
        "the copy in progress is listed as unfinished"
    );
    drop(staged);
    assert!(files_in(store.dir()).is_empty());
}

#[test]
fn df_output_is_read_from_the_capacity_column_backwards() {
    let plain = "Filesystem   1024-blocks       Used  Available Capacity  Mounted on\n\
                 /dev/disk3s5  1942700360 1100000000  793000000    59%    /System/Volumes/Data\n";
    assert_eq!(parse_df_available_kib(plain), Some(793_000_000));
    // A device name with a space must not shift the columns.
    let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                  map auto_home 0 0 12 100% /System/Volumes/Data/home\n";
    assert_eq!(parse_df_available_kib(spaced), Some(12));
    for broken in [
        "",
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n",
        "header\n/dev/x 1 2 59% /\n",
        "header\n/dev/x one two three 59% /\n",
    ] {
        assert_eq!(parse_df_available_kib(broken), None, "{broken:?}");
    }
}

/// The claim the design rests on, measured: on this platform the standard library's
/// copy is a block-sharing clone within one volume, so a private copy of multi-gigabyte
/// weights costs neither time nor disk. A 2 GiB sparse file that had to be written out
/// would take seconds; a clone is a metadata operation.
#[cfg(target_os = "macos")]
#[test]
fn a_clone_within_one_volume_is_a_metadata_operation_whatever_the_size() {
    const SIZE: u64 = 2 * 1024 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sparse.gguf");
    std::fs::File::create(&source)
        .unwrap()
        .set_len(SIZE)
        .unwrap();
    let dest = dir.path().join("clone.gguf");

    let started = std::time::Instant::now();
    let cloned = platform_clone(&source, &dest).unwrap();
    let elapsed = started.elapsed();

    assert!(cloned, "one APFS volume clones");
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), SIZE);
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "cloning 2 GiB took {elapsed:?}: the bytes were copied, not shared"
    );
    // A clone is its own file: writing to the source afterwards does not reach it.
    let source_identity = FileFingerprint::read(&source).unwrap();
    let clone_identity = FileFingerprint::read(&dest).unwrap();
    assert_ne!(
        (source_identity.dev, source_identity.ino),
        (clone_identity.dev, clone_identity.ino),
        "a clone is not a hard link"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn a_clone_is_isolated_from_later_writes_to_its_source() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("model.gguf");
    std::fs::write(&source, b"verified bytes").unwrap();
    let dest = dir.path().join("clone.gguf");
    assert!(platform_clone(&source, &dest).unwrap());

    // An in-place rewrite, the edit a hard link would have carried into the copy.
    std::fs::write(&source, b"swapped bytes!").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"verified bytes");
}

#[cfg(target_os = "macos")]
#[test]
fn free_space_is_known_for_a_local_directory() {
    let dir = tempfile::tempdir().unwrap();
    let free = platform_free_bytes(dir.path()).expect("df answers for a local directory");
    assert!(free > 0);
    assert_eq!(platform_free_bytes(&dir.path().join("not-there")), None);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn platforms_without_a_safe_clone_always_take_the_hashed_copy() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("model.gguf");
    std::fs::write(&source, b"bytes").unwrap();
    let dest = dir.path().join("clone.gguf");
    assert!(!platform_clone(&source, &dest).unwrap());
    assert!(!dest.exists(), "nothing is written by a refused clone");
    assert_eq!(platform_free_bytes(dir.path()), None);
}
