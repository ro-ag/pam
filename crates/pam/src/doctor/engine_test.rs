//! The engine end to end: verdicts over a scripted OS, the report's
//! acceptance by the daemon's validator, the safety invariants against a
//! real temporary base, and the unsandboxed run against a real daemon.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_proto::doctor::{
    DoctorReport, Platform, ProbeClass, ProbeId, ProbeState, ReportError, Verdict,
};

use super::os::HelloAnswer;
use super::os_test::{Answer, FakeOs, HelperMood, Op};
use super::{Options, run_with};

const BASE: &str = "/tmp/pamdoc-base";

fn run_fake(os: FakeOs) -> DoctorReport {
    run_with(&Options::new(PathBuf::from(BASE)), Arc::new(os)).unwrap()
}

/// The must-deny probes the inventory attempts on this platform, in order,
/// without the two that never come back `allowed` here: `public.unlink`
/// (never probed) and `bundle.write` (absent outside a bundle).
fn must_deny_here() -> Vec<ProbeId> {
    let platform = Platform::current().unwrap();
    ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && id.applies_to(platform))
        .filter(|id| !matches!(id, ProbeId::PublicUnlink | ProbeId::BundleWrite))
        .collect()
}

/// What `judge` lists under `skipped` for an unsandboxed run on this
/// platform, in inventory order: the never-probed rows, the other
/// platform's rows, and the bundle outside a bundle.
fn skipped_here() -> Vec<(String, String)> {
    let platform = Platform::current().unwrap();
    ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny)
        .filter_map(|id| {
            let why = match id {
                ProbeId::PublicUnlink => "not_probed: side effect".to_owned(),
                ProbeId::BundleWrite if id.applies_to(platform) => {
                    "absent: not inside an application bundle".to_owned()
                }
                _ if !id.applies_to(platform) => format!("not_probed: not probed on {platform}"),
                _ => return None,
            };
            Some((id.to_string(), why))
        })
        .collect()
}

fn accepted_by_the_daemon(report: &DoctorReport) -> Result<DoctorReport, ReportError> {
    DoctorReport::from_args(&serde_json::to_value(report.as_args()).unwrap())
}

#[test]
fn an_unsandboxed_process_fails_every_must_deny_probe_and_the_report_is_accepted() {
    let report = run_fake(FakeOs::unsandboxed());
    assert_eq!(report.verdict, Verdict::NotEstablished);
    assert_eq!(report.failed, must_deny_here());
    assert!(report.unverified.is_empty());
    let skipped: Vec<(String, String)> = report
        .skipped
        .iter()
        .map(|row| (row.id.to_string(), row.why.clone()))
        .collect();
    assert_eq!(skipped, skipped_here());
    assert_eq!(report.daemon.as_ref().unwrap().version, "0.4.3");
    assert_eq!(report.platform, Platform::current().unwrap());
    assert!(report.ts > 1_700_000_000);
    assert!(report.report.is_none());
    for probe in &report.probes {
        if probe.result != ProbeState::NotProbed {
            assert!(
                probe.elapsed_ms.is_some(),
                "{} has no elapsed time",
                probe.id
            );
        }
    }
    let accepted = accepted_by_the_daemon(&report).unwrap();
    assert_eq!(accepted, report.as_args());
}

#[test]
fn a_sandboxed_process_establishes_the_boundary() {
    let report = run_fake(FakeOs::sandboxed());
    assert_eq!(report.verdict, Verdict::Established);
    assert!(report.failed.is_empty());
    assert!(report.unverified.is_empty());
    let reach = &report.probes[0];
    assert_eq!(
        (reach.id, reach.result),
        (ProbeId::PublicReach, ProbeState::Allowed)
    );
    for id in must_deny_here() {
        let probe = report.probes.iter().find(|probe| probe.id == id).unwrap();
        assert_eq!(probe.result, ProbeState::Denied, "{id}");
        assert!(probe.os_error.is_some(), "{id} carries no OS error");
    }
    accepted_by_the_daemon(&report).unwrap();
}

#[test]
fn absent_private_state_counts_neither_way() {
    let os = FakeOs::sandboxed()
        .with(Op::ListDir, format!("{BASE}/backup"), Answer::Absent)
        .with(
            Op::Connect,
            format!("{BASE}/engine/run/engine.sock"),
            Answer::Absent,
        );
    let report = run_fake(os);
    assert_eq!(report.verdict, Verdict::Established);
    let skipped: Vec<ProbeId> = report.skipped.iter().map(|row| row.id).collect();
    assert!(skipped.contains(&ProbeId::BackupRead));
    if ProbeId::EngineSocket.applies_to(report.platform) {
        assert!(skipped.contains(&ProbeId::EngineSocket));
    }
}

#[test]
fn a_refused_admin_connect_reached_the_socket_and_an_unexpected_error_is_unverified() {
    let os = FakeOs::sandboxed()
        .with(
            Op::Connect,
            format!("{BASE}/admin/control.sock"),
            Answer::Refused,
        )
        .with(
            Op::OpenRead,
            format!("{BASE}/state.sqlite3"),
            Answer::Code(std::io::ErrorKind::Other, 5),
        );
    let report = run_fake(os);
    assert_eq!(report.verdict, Verdict::NotEstablished);
    if ProbeId::AdminEndpoint.applies_to(report.platform) {
        assert_eq!(report.failed, [ProbeId::AdminEndpoint]);
        let admin = report
            .probes
            .iter()
            .find(|probe| probe.id == ProbeId::AdminEndpoint)
            .unwrap();
        assert_eq!(admin.result, ProbeState::Allowed);
        assert_eq!(admin.os_error.as_ref().unwrap().kind, "ConnectionRefused");
    }
    assert_eq!(report.unverified, [ProbeId::StoreRead]);
    let store = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::StoreRead)
        .unwrap();
    assert_eq!(store.note.as_deref(), Some("unexpected error: Other"));
}

#[test]
fn an_unacknowledged_hello_cannot_probe_and_is_not_recordable() {
    for hello in [
        HelloAnswer::Silent,
        HelloAnswer::Legacy,
        HelloAnswer::Unreachable(std::io::Error::from_raw_os_error(super::classify::ENOENT)),
    ] {
        let report = run_fake(FakeOs::sandboxed().with_hello(hello));
        assert_eq!(report.verdict, Verdict::CannotProbe);
        assert!(report.daemon.is_none());
        assert_eq!(report.probes[0].id, ProbeId::PublicReach);
        assert_ne!(report.probes[0].result, ProbeState::Allowed);
        // The other probes still ran: the rows are evidence for the human.
        let store = report
            .probes
            .iter()
            .find(|probe| probe.id == ProbeId::StoreRead)
            .unwrap();
        assert_eq!(store.result, ProbeState::Denied);
        assert!(matches!(
            accepted_by_the_daemon(&report),
            Err(ReportError::NotRecordable(Verdict::CannotProbe))
        ));
    }
}

#[test]
fn unrecognised_helper_output_is_unverified_and_fails_the_verdict() {
    let mut os = FakeOs::sandboxed();
    os.helper_mood = HelperMood::Gibberish;
    let report = run_fake(os);
    assert_eq!(report.verdict, Verdict::NotEstablished);
    assert!(report.failed.is_empty());
    // The executable's row is a helper's answer on unix (`/bin/test -w`),
    // an open's on Windows.
    let expected: Vec<ProbeId> = [
        ProbeId::KeychainSearch,
        ProbeId::DaemonSignal,
        ProbeId::BrokerLaunchServices,
        ProbeId::BrokerAppleEvents,
        ProbeId::ExeWrite,
    ]
    .into_iter()
    .filter(|id| id.applies_to(report.platform))
    .filter(|id| *id != ProbeId::ExeWrite || cfg!(unix))
    .collect();
    assert_eq!(report.unverified, expected);
    for id in expected {
        let probe = report.probes.iter().find(|probe| probe.id == id).unwrap();
        assert!(
            probe.note.as_deref().unwrap().starts_with("unrecognised "),
            "{id}"
        );
    }
    assert!(
        report.env.harness_chain.is_empty(),
        "gibberish ps yields no chain"
    );
}

#[test]
fn a_missing_helper_is_unknown_with_the_spawn_error() {
    let mut os = FakeOs::sandboxed();
    os.helper_mood = HelperMood::Missing;
    let report = run_fake(os);
    assert_eq!(report.verdict, Verdict::NotEstablished);
    let keychain = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::KeychainSearch)
        .unwrap();
    assert_eq!(keychain.result, ProbeState::Unknown);
    assert_eq!(keychain.note.as_deref(), Some("spawn: NotFound"));
}

/// The signal probe takes the daemon's pid from the hello acknowledgement:
/// with no daemon reached there is no process to ask about, so the row is
/// `not_probed` (counted neither way) rather than `unknown`, and the lock
/// file is never read for it — nothing under the base is read at all.
#[test]
fn without_a_reached_daemon_the_signal_probe_is_not_probed_and_the_lock_is_never_read() {
    let os = Arc::new(FakeOs::sandboxed().with_hello(HelloAnswer::Unreachable(
        std::io::Error::from_raw_os_error(super::classify::ECONNREFUSED),
    )));
    let dynamic: Arc<dyn super::os::Os> = os.clone();
    let report = run_with(&Options::new(PathBuf::from(BASE)), dynamic).unwrap();
    assert_eq!(report.verdict, Verdict::CannotProbe);
    let signal = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::DaemonSignal)
        .unwrap();
    if signal.id.applies_to(report.platform) {
        assert_eq!(signal.result, ProbeState::NotProbed);
        assert_eq!(
            signal.note.as_deref(),
            Some("no daemon reached: no pid to probe")
        );
        assert!(!report.unverified.contains(&ProbeId::DaemonSignal));
        assert!(
            report
                .skipped
                .iter()
                .any(|row| row.id == ProbeId::DaemonSignal
                    && row.why == "not_probed: no daemon reached: no pid to probe"),
            "{:?}",
            report.skipped
        );
    }
    let calls = os.calls();
    assert!(
        !calls.iter().any(|call| call.contains("/bin/kill")),
        "no signal helper runs without a pid: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|call| call.starts_with("ReadPid ")),
        "the lock file is never read: {calls:#?}"
    );
}

#[test]
fn the_exe_and_bundle_probes_follow_the_executable() {
    let mut fake = FakeOs::unsandboxed();
    fake.exe = Some(PathBuf::from("/Applications/PAM.app/Contents/MacOS/pam"));
    let os = Arc::new(fake);
    let dynamic: Arc<dyn super::os::Os> = os.clone();
    let report = run_with(&Options::new(PathBuf::from(BASE)), dynamic).unwrap();
    let bundle = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::BundleWrite)
        .unwrap();
    if bundle.id.applies_to(report.platform) {
        assert_eq!(bundle.result, ProbeState::Allowed);
        assert!(report.failed.contains(&ProbeId::BundleWrite));
        // Asked through `access(2)`, never opened: nothing in the bundle
        // (nor the executable) is a write-open away from a dropped
        // signature cache.
        let calls = os.calls();
        assert!(calls.iter().any(|call| call
            == "helper /bin/test -w /Applications/PAM.app/Contents/Info.plist"));
        assert!(
            calls
                .iter()
                .any(|call| call == "helper /bin/test -w /Applications/PAM.app/Contents/MacOS/pam")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.starts_with("OpenWrite /Applications")),
            "{calls:#?}"
        );
    }
    let mut os = FakeOs::unsandboxed();
    os.exe = None;
    let report = run_fake(os);
    let exe = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::ExeWrite)
        .unwrap();
    assert_eq!(exe.result, ProbeState::Unknown);
    assert!(exe.note.as_deref().unwrap().starts_with("current_exe:"));
    assert_eq!(report.env.exe, None);
}

#[cfg(unix)]
#[test]
fn the_probes_target_exactly_the_spec_paths_and_absent_names() {
    let os = Arc::new(FakeOs::unsandboxed());
    let options = Options::new(PathBuf::from(BASE));
    let dynamic: Arc<dyn super::os::Os> = os.clone();
    let report = run_with(&options, dynamic).unwrap();
    assert_eq!(report.verdict, Verdict::NotEstablished);
    let calls = os.calls();
    let has = |call: &str| calls.iter().any(|line| line == call);
    for expected in [
        "hello /tmp/pamdoc-base/run/pam.sock via Direct",
        "Lock /tmp/pamdoc-base/run/daemon.lock",
        "OpenWrite /tmp/pamdoc-base/run/daemon.lock",
        "Connect /tmp/pamdoc-base/admin/control.sock",
        "Connect /tmp/pamdoc-base/run/../admin/control.sock",
        "Connect /tmp/pamdoc-base/engine/run/engine.sock",
        "ListDir /tmp/pamdoc-base/admin",
        "OpenRead /tmp/pamdoc-base/state.sqlite3",
        "OpenWrite /tmp/pamdoc-base/state.sqlite3",
        "OpenRead /tmp/pamdoc-base/state.sqlite3-wal",
        "OpenWrite /tmp/pamdoc-base/state.sqlite3-wal",
        "OpenRead /tmp/pamdoc-base/state.sqlite3-shm",
        "OpenWrite /tmp/pamdoc-base/state.sqlite3-shm",
        "ListDir /tmp/pamdoc-base/backup",
        "ListDir /tmp/pamdoc-base/model-trust",
        "ListDir /tmp/pamdoc-base/engine",
        "ListDir /tmp/pamdoc-base/engine/run",
        "ListDir /tmp/pamdoc-base/flows",
        "ListDir /tmp/pamdoc-base/log",
        "helper /bin/test -w /usr/local/bin/pam",
        // The pid the hello acknowledged, never one read from the lock.
        "helper /bin/kill -0 4242",
    ] {
        assert!(has(expected), "missing call {expected:?} in {calls:#?}");
    }
    // The public socket is reached by the hello only, never by a connect.
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("Connect ") && call.ends_with("pam.sock"))
    );
    // The executable is asked through `access(2)`, never opened: an
    // open-for-write of a mapped Mach-O drops its signature cache and every
    // later exec is killed.
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("OpenWrite ") && call.ends_with("/pam")),
        "{calls:#?}"
    );
    // The keychain item and the bundle id cannot exist.
    let pid = std::process::id();
    let security = calls
        .iter()
        .find(|call| call.contains("/usr/bin/security"))
        .unwrap();
    assert!(security.contains(&format!(
        "find-generic-password -s dev.pam.connector -a pam.doctor.absent.{pid}."
    )));
    assert!(has(
        "helper /usr/bin/lsappinfo find bundleid=com.apple.loginwindow"
    ));
    assert!(has(
        "helper /usr/bin/osascript -e id of application \"Finder\""
    ));
    // No helper is ever handed a payload: nothing launches, nothing is told.
    assert!(
        !calls
            .iter()
            .any(|call| call.contains("/usr/bin/open") || call.contains("activate"))
    );
    // Every helper is named by absolute path.
    for call in calls.iter().filter(|call| call.starts_with("helper ")) {
        assert!(call.starts_with("helper /"), "{call}");
    }
    // Nothing is read from under the base: the lock is opened for the
    // lock probe and the write probe, never for its bytes.
    assert!(
        !calls.iter().any(|call| call.starts_with("ReadPid ")),
        "{calls:#?}"
    );
}

/// A base laid out like `RuntimeDir` and the daemon's services leave it,
/// with the modes they use, and listeners on the socket paths so the
/// connect probes meet real sockets.
#[cfg(unix)]
struct FixtureBase {
    tmp: tempfile::TempDir,
    base: PathBuf,
    _listeners: Vec<std::os::unix::net::UnixListener>,
}

#[cfg(unix)]
impl FixtureBase {
    fn new() -> Self {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        use std::os::unix::net::UnixListener;

        let tmp = tempfile::Builder::new()
            .prefix("pamdoc")
            .tempdir_in("/tmp")
            .unwrap();
        let base = tmp.path().join("pam");
        let private_dir = |path: &Path| {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .unwrap();
        };
        let private_file = |path: &Path, bytes: &[u8]| {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        private_dir(&base);
        for dir in [
            "run",
            "engine/run",
            "admin",
            "backup",
            "model-trust",
            "engine",
            "flows",
            "log",
        ] {
            private_dir(&base.join(dir));
        }
        private_file(
            &base.join("run/daemon.lock"),
            std::process::id().to_string().as_bytes(),
        );
        private_file(&base.join("engine/run/api.key"), b"engine-key");
        private_file(&base.join("state.sqlite3"), b"sqlite");
        private_file(&base.join("state.sqlite3-wal"), b"wal");
        private_file(&base.join("state.sqlite3-shm"), b"shm");
        private_file(&base.join("log/daemon.log"), b"log");
        let listeners = [
            "run/pam.sock",
            "engine/run/engine.sock",
            "admin/control.sock",
        ]
        .into_iter()
        .map(|socket| {
            let listener = UnixListener::bind(base.join(socket)).unwrap();
            std::fs::set_permissions(base.join(socket), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            listener
        })
        .collect();
        Self {
            tmp,
            base,
            _listeners: listeners,
        }
    }

    /// Every entry under the base with what a probe could change.
    fn listing(&self) -> Vec<(PathBuf, u64, std::time::SystemTime, u32, u64)> {
        use std::os::unix::fs::MetadataExt;

        fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64, std::time::SystemTime, u32, u64)>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                let meta = std::fs::symlink_metadata(&path).unwrap();
                out.push((
                    path.clone(),
                    meta.len(),
                    meta.modified().unwrap(),
                    meta.mode(),
                    meta.ino(),
                ));
                if meta.is_dir() {
                    walk(&path, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(self.tmp.path(), &mut out);
        out
    }

    fn options(&self) -> Options {
        // Nothing answers the hello: a short bound keeps the run quick.
        let mut options = Options::new(self.base.clone());
        options.hello_bound = Duration::from_millis(300);
        options
    }
}

#[cfg(unix)]
#[test]
fn two_runs_against_a_real_base_change_nothing_on_disk() {
    let fixture = FixtureBase::new();
    let before = fixture.listing();
    let lock_before = std::fs::read(fixture.base.join("run/daemon.lock")).unwrap();
    let first = super::run(&fixture.options()).unwrap();
    let second = super::run(&fixture.options()).unwrap();
    assert_eq!(fixture.listing(), before, "a probe changed the base");
    assert_eq!(
        std::fs::read(fixture.base.join("run/daemon.lock")).unwrap(),
        lock_before
    );
    assert_eq!(
        std::fs::read(fixture.base.join("engine/run/api.key")).unwrap(),
        b"engine-key"
    );
    for report in [&first, &second] {
        // Nothing answered the hello.
        assert_eq!(report.verdict, Verdict::CannotProbe);
        for id in [
            ProbeId::RunLockWrite,
            ProbeId::AdminDir,
            ProbeId::StoreRead,
            ProbeId::StoreWrite,
            ProbeId::StoreWalRead,
            ProbeId::StoreWalWrite,
            ProbeId::StoreShmRead,
            ProbeId::StoreShmWrite,
            ProbeId::BackupRead,
            ProbeId::ModelTrustRead,
            ProbeId::EngineRead,
            ProbeId::EngineRuntimeRead,
            ProbeId::FlowsRead,
            ProbeId::LogRead,
            ProbeId::ExeWrite,
        ] {
            let probe = report.probes.iter().find(|probe| probe.id == id).unwrap();
            assert_eq!(probe.result, ProbeState::Allowed, "{id}: {probe:?}");
        }
        #[cfg(target_os = "macos")]
        for id in [
            ProbeId::AdminEndpoint,
            ProbeId::AdminEndpointAlias,
            ProbeId::EngineSocket,
            ProbeId::KeychainSearch,
            ProbeId::BrokerLaunchServices,
            ProbeId::BrokerAppleEvents,
        ] {
            let probe = report.probes.iter().find(|probe| probe.id == id).unwrap();
            assert_eq!(probe.result, ProbeState::Allowed, "{id}: {probe:?}");
        }
        // No daemon answered: there is no pid to signal, and the lock's
        // bytes (this process's pid) are never read for one.
        #[cfg(target_os = "macos")]
        {
            let signal = report
                .probes
                .iter()
                .find(|probe| probe.id == ProbeId::DaemonSignal)
                .unwrap();
            assert_eq!(signal.result, ProbeState::NotProbed, "{signal:?}");
        }
        let lock = report
            .probes
            .iter()
            .find(|probe| probe.id == ProbeId::RunLockProbe)
            .unwrap();
        assert_eq!(lock.result, ProbeState::Allowed);
        assert_eq!(lock.note.as_deref(), Some("free: no daemon holds the lock"));
    }
}

/// Restores the fixture's modes so the temp dir can be removed. The modes
/// are closed children first (the list order) and reopened parents first
/// (its reverse): a closed parent would hide its child from both steps.
#[cfg(unix)]
struct ModeGuard(Vec<(PathBuf, u32)>);

#[cfg(unix)]
impl Drop for ModeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        for (path, mode) in self.0.iter().rev() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode));
        }
    }
}

#[cfg(unix)]
#[test]
fn private_state_the_user_cannot_open_classifies_denied() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let fixture = FixtureBase::new();
    if std::fs::metadata(&fixture.base).unwrap().uid() == 0 {
        eprintln!("skipped: root opens everything");
        return;
    }
    let closed: Vec<(PathBuf, u32)> = [
        ("run/daemon.lock", 0o600),
        ("state.sqlite3", 0o600),
        ("state.sqlite3-wal", 0o600),
        ("state.sqlite3-shm", 0o600),
        ("admin", 0o700),
        ("backup", 0o700),
        ("model-trust", 0o700),
        ("engine/run", 0o700),
        ("engine", 0o700),
        ("flows", 0o700),
        ("log", 0o700),
    ]
    .into_iter()
    .map(|(path, mode)| (fixture.base.join(path), mode))
    .collect();
    let _guard = ModeGuard(closed.clone());
    for (path, _) in &closed {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let report = super::run(&fixture.options()).unwrap();
    for id in [
        ProbeId::RunLockWrite,
        ProbeId::AdminDir,
        ProbeId::StoreRead,
        ProbeId::StoreWrite,
        ProbeId::StoreWalRead,
        ProbeId::StoreWalWrite,
        ProbeId::StoreShmRead,
        ProbeId::StoreShmWrite,
        ProbeId::BackupRead,
        ProbeId::ModelTrustRead,
        ProbeId::EngineRead,
        ProbeId::EngineRuntimeRead,
        ProbeId::FlowsRead,
        ProbeId::LogRead,
    ] {
        let probe = report.probes.iter().find(|probe| probe.id == id).unwrap();
        assert_eq!(probe.result, ProbeState::Denied, "{id}: {probe:?}");
        assert_eq!(
            probe.os_error.as_ref().unwrap().kind,
            "PermissionDenied",
            "{id}"
        );
    }
    let lock = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::RunLockProbe)
        .unwrap();
    assert_eq!(lock.result, ProbeState::Denied);
    assert_eq!(lock.note.as_deref(), Some("lazy start unavailable here"));
    #[cfg(target_os = "macos")]
    {
        // Nothing answered the hello: no pid to signal, whatever the lock
        // file's mode.
        let signal = report
            .probes
            .iter()
            .find(|probe| probe.id == ProbeId::DaemonSignal)
            .unwrap();
        assert_eq!(signal.result, ProbeState::NotProbed);
        assert_eq!(
            signal.note.as_deref(),
            Some("no daemon reached: no pid to probe")
        );
        // The admin directory is closed: the socket inside it cannot be reached.
        let admin = report
            .probes
            .iter()
            .find(|probe| probe.id == ProbeId::AdminEndpoint)
            .unwrap();
        assert_eq!(admin.result, ProbeState::Denied);
    }
}

/// The spec's unsandboxed scenario against a real daemon on a temporary
/// base: `not_established` with the exact list of must-deny probes that
/// came back `allowed`, and a report the daemon's validator accepts.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsandboxed_run_against_a_real_daemon_is_not_established() {
    let daemon = pam_testkit::TestDaemon::spawn().await;
    let base = daemon.base_dir();
    let options = Options::new(base.clone());
    let report = tokio::task::spawn_blocking(move || super::run(&options))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        report.verdict,
        Verdict::NotEstablished,
        "{}",
        super::render_human(&report)
    );
    let reach = &report.probes[0];
    assert_eq!(
        (reach.id, reach.result),
        (ProbeId::PublicReach, ProbeState::Allowed)
    );
    let facts = report.daemon.as_ref().unwrap();
    assert_eq!(facts.version, pam_daemon::daemon::DAEMON_VERSION);
    assert_eq!(facts.via, pam_proto::wire::Via::Direct);
    assert!(report.unverified.is_empty(), "{:?}", report.unverified);
    // What exists on the fixture base is reachable; what does not is absent.
    let present = |relative: &str| base.join(relative).exists();
    let expected_failed: Vec<ProbeId> = must_deny_here()
        .into_iter()
        .filter(|id| match id {
            ProbeId::AdminEndpoint | ProbeId::AdminEndpointAlias => present("admin/control.sock"),
            ProbeId::AdminDir => present("admin"),
            ProbeId::StoreRead | ProbeId::StoreWrite => present("state.sqlite3"),
            ProbeId::StoreWalRead | ProbeId::StoreWalWrite => present("state.sqlite3-wal"),
            ProbeId::StoreShmRead | ProbeId::StoreShmWrite => present("state.sqlite3-shm"),
            ProbeId::BackupRead => present("backup"),
            ProbeId::ModelTrustRead => present("model-trust"),
            ProbeId::EngineRead => present("engine"),
            ProbeId::EngineRuntimeRead => present("engine/run"),
            ProbeId::EngineSocket => present("engine/run/engine.sock"),
            ProbeId::FlowsRead => present("flows"),
            ProbeId::LogRead => present("log"),
            _ => true,
        })
        .collect();
    assert_eq!(
        report.failed,
        expected_failed,
        "{}",
        super::render_human(&report)
    );
    for id in [
        ProbeId::AdminEndpoint,
        ProbeId::AdminDir,
        ProbeId::RunLockWrite,
        ProbeId::StoreRead,
        ProbeId::StoreWrite,
        ProbeId::KeychainSearch,
        ProbeId::DaemonSignal,
        ProbeId::BrokerLaunchServices,
        ProbeId::ExeWrite,
    ] {
        assert!(
            report.failed.contains(&id),
            "{id} must be allowed unsandboxed"
        );
    }
    let lock = report
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::RunLockProbe)
        .unwrap();
    assert_eq!(lock.note.as_deref(), Some("held: a daemon is running"));
    assert_eq!(report.env.resolved_base, base.display().to_string());
    assert_eq!(
        report.env.resolved_endpoint,
        base.join("run/pam.sock").display().to_string()
    );
    assert!(
        !report.env.harness_chain.is_empty(),
        "the ps walk found no ancestor"
    );
    let accepted = accepted_by_the_daemon(&report).unwrap();
    assert_eq!(accepted.verdict, Verdict::NotEstablished);
    let json = super::render_json(&report);
    assert!(json.len() < pam_proto::doctor::MAX_REPORT_BYTES);
    daemon.stop().await;
}
