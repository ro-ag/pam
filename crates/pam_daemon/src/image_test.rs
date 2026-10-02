use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::image::{
    BootImage, FileFacts, FsProbe, ImageProbe, ImageWatch, RECHECK_INTERVAL, VersionVerdict,
};

/// A probe whose answers a test edits between checks, counting every read.
#[derive(Default)]
struct ScriptedProbe {
    files: Mutex<HashMap<PathBuf, FileFacts>>,
    reads: AtomicUsize,
}

impl ScriptedProbe {
    fn put(&self, path: &str, facts: FileFacts) {
        self.files
            .lock()
            .unwrap()
            .insert(PathBuf::from(path), facts);
    }

    fn remove(&self, path: &str) {
        self.files.lock().unwrap().remove(Path::new(path));
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl ImageProbe for ScriptedProbe {
    fn facts(&self, path: &Path) -> Option<FileFacts> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.files.lock().unwrap().get(path).cloned()
    }
}

fn facts(canonical: &str, len: u64, inode: u64) -> FileFacts {
    FileFacts {
        canonical: PathBuf::from(canonical),
        len,
        modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)),
        identity: Some((1, inode)),
    }
}

const EXE: &str = "/opt/pam/bin/pam";

fn watch_over(probe: &Arc<ScriptedProbe>) -> Arc<ImageWatch> {
    probe.put(EXE, facts(EXE, 100, 7));
    let boot = BootImage::from_paths(vec![PathBuf::from(EXE)], probe.as_ref());
    ImageWatch::with_boot(boot, Arc::clone(probe) as Arc<dyn ImageProbe>)
}

#[tokio::test]
async fn equal_versions_never_look_at_the_disk() {
    let probe = Arc::new(ScriptedProbe::default());
    let watch = watch_over(&probe);
    let reads_at_boot = probe.reads();
    assert_eq!(watch.verdict("1.2.3", "1.2.3").await, VersionVerdict::Match);
    assert_eq!(probe.reads(), reads_at_boot);
}

#[tokio::test]
async fn a_claimed_version_alone_never_restarts_the_daemon() {
    let probe = Arc::new(ScriptedProbe::default());
    let watch = watch_over(&probe);
    // Whatever the client says — older, newer, garbage — the file on disk
    // is the one that is running, so the verdict is a refusal, not a restart.
    for claimed in ["0.0.1", "999.0.0", "", "not a version"] {
        assert_eq!(
            watch.verdict(claimed, "1.2.3").await,
            VersionVerdict::Mismatch,
            "claimed {claimed:?}"
        );
    }
}

#[tokio::test]
async fn each_changed_attribute_of_a_present_file_counts_as_replaced() {
    let changes: [(&str, FileFacts); 4] = [
        ("length", facts(EXE, 101, 7)),
        ("inode", facts(EXE, 100, 8)),
        ("canonical path", facts("/opt/pam-2/bin/pam", 100, 7)),
        (
            "modification time",
            FileFacts {
                modified: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(2_000)),
                ..facts(EXE, 100, 7)
            },
        ),
    ];
    for (what, now) in changes {
        let probe = Arc::new(ScriptedProbe::default());
        let watch = watch_over(&probe);
        probe.put(EXE, now);
        assert_eq!(
            watch.verdict("9.9.9", "1.2.3").await,
            VersionVerdict::Restart,
            "a changed {what} must read as a replaced image"
        );
    }
}

#[tokio::test]
async fn a_missing_file_is_not_a_replacement() {
    let probe = Arc::new(ScriptedProbe::default());
    let watch = watch_over(&probe);
    probe.remove(EXE);
    assert_eq!(
        watch.verdict("9.9.9", "1.2.3").await,
        VersionVerdict::Mismatch
    );
}

#[tokio::test]
async fn a_path_unreadable_at_boot_can_never_prove_a_replacement() {
    let probe = Arc::new(ScriptedProbe::default());
    // Nothing at the path when the daemon booted.
    let boot = BootImage::from_paths(vec![PathBuf::from(EXE)], probe.as_ref());
    let watch = ImageWatch::with_boot(boot, Arc::clone(&probe) as Arc<dyn ImageProbe>);
    probe.put(EXE, facts(EXE, 100, 7));
    assert_eq!(
        watch.verdict("9.9.9", "1.2.3").await,
        VersionVerdict::Mismatch
    );
}

#[tokio::test]
async fn a_flood_of_mismatches_costs_one_check_per_interval() {
    let probe = Arc::new(ScriptedProbe::default());
    let watch = watch_over(&probe);
    let reads_at_boot = probe.reads();
    for _ in 0..50 {
        assert_eq!(
            watch.verdict("0.0.1", "1.2.3").await,
            VersionVerdict::Mismatch
        );
    }
    // One recorded path, one read: forty-nine answers came from the cache.
    assert_eq!(probe.reads() - reads_at_boot, 1);

    // After the interval the disk is read again, so a real replacement is
    // noticed within a second of the next mismatched request.
    tokio::time::sleep(RECHECK_INTERVAL + Duration::from_millis(50)).await;
    probe.put(EXE, facts(EXE, 222, 9));
    assert_eq!(
        watch.verdict("0.0.1", "1.2.3").await,
        VersionVerdict::Restart
    );
    // A seen replacement is latched: no further reads are needed.
    let reads_after_restart = probe.reads();
    assert_eq!(
        watch.verdict("0.0.1", "1.2.3").await,
        VersionVerdict::Restart
    );
    assert_eq!(probe.reads(), reads_after_restart);
}

#[tokio::test]
async fn the_respawn_path_is_the_one_recorded_at_boot() {
    let probe = Arc::new(ScriptedProbe::default());
    let watch = watch_over(&probe);
    // Even after the file moved on, the boot record still names where the
    // daemon was started from.
    probe.remove(EXE);
    assert_eq!(watch.boot_path(), Some(Path::new(EXE)));
}

#[test]
fn the_filesystem_probe_sees_a_rename_into_place_install() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("pam");
    std::fs::write(&exe, b"old build").unwrap();
    let boot = BootImage::from_paths(vec![exe.clone()], &FsProbe);
    assert!(
        !boot.replaced(&FsProbe),
        "an untouched file is not replaced"
    );

    // The usual installer move: write the new build beside it, rename over.
    let staged = dir.path().join("pam.new");
    std::fs::write(&staged, b"a newer and longer build").unwrap();
    std::fs::rename(&staged, &exe).unwrap();
    assert!(boot.replaced(&FsProbe), "a renamed-over file is replaced");

    // Gone altogether: nothing to hand over to.
    std::fs::remove_file(&exe).unwrap();
    assert!(
        !boot.replaced(&FsProbe),
        "a missing file is not a replacement"
    );
}

#[test]
fn a_directory_at_the_path_is_not_an_image() {
    let dir = tempfile::tempdir().unwrap();
    assert!(FsProbe.facts(dir.path()).is_none());
    assert!(FsProbe.facts(&dir.path().join("absent")).is_none());
}

#[test]
fn capture_records_the_running_test_binary() {
    let boot = BootImage::capture(&FsProbe);
    let path = boot.path().expect("the platform names the test binary");
    assert!(path.is_absolute());
    assert!(!boot.replaced(&FsProbe));
}
