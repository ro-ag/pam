//! The upgrade from a pre-migration daemon, through the real `pam` binary on the real socket
//! path.
//!
//! A daemon of an earlier build listens on `<base>/run/pam.sock`, greets every connection in
//! ZMTP, and holds `<base>/run/daemon.lock` with its pid in it. A client of this build dials the
//! same path and must tell that daemon from one it can talk to:
//!
//! - unsandboxed, it stops that daemon through the pid in the lock (the mechanism
//!   `pam daemon stop` uses), lazily starts its own build and completes the command;
//! - behind `PAM_SOCKET_DIR` it signals nothing and says who must act;
//! - when it cannot signal, it prints the instruction and exits non-zero, and the old daemon
//!   keeps running.
//!
//! The pre-migration daemon is a separate process (this test binary re-executed), so the pid in
//! the lock is the process that holds the lock and the listener: a signal that reaches it
//! releases both, the way the real one's exit does. It speaks no ZMTP beyond the 64-byte
//! greeting; a current client never reads further. Unix only: Windows has no signal to send and
//! reports such a daemon instead (`pam_client`'s `never_ready`).

#![cfg(unix)]

use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use pam::client::{self, DaemonStatus};
use pam_daemon::lifecycle::{LOCK_FILE, acquire_instance_lock};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_store::{RequestIngress, RequestState, Store};

/// Set for the re-executed child: the base the fake daemon serves.
const FAKE_BASE: &str = "PAM_FAKE_LEGACY_BASE";
/// Set for the re-executed child: leave the lock file without a pid.
const FAKE_NO_PID: &str = "PAM_FAKE_LEGACY_NO_PID";

/// Bound on each wait for a process to come up or go away.
const WAIT: Duration = Duration::from_secs(30);

/// The 64-byte greeting a ZMTP peer sends as soon as a connection opens: the signature
/// (`FF`, eight length bytes, `7F`), version 3.0, the `NULL` mechanism, zero padding.
fn zmtp_greeting() -> Vec<u8> {
    let mut greeting = vec![0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0x7F, 3, 0];
    greeting.extend_from_slice(b"NULL");
    greeting.resize(64, 0);
    greeting
}

/// The fake pre-migration daemon. Runs only when a test below re-executes this binary with
/// [`FAKE_BASE`] set; as an ordinary test it returns at once.
///
/// It does what the old daemon did as far as a client can tell: takes the instance lock
/// (writing its own pid), binds `pam.sock` and `events.sock`, and greets every connection in
/// ZMTP before reading. It installs no signal handler: `SIGTERM` ends the process, which
/// releases the lock and leaves both socket files behind, as a daemon that did not unlink them
/// would.
#[test]
fn fake_pre_migration_daemon_child() {
    let Ok(base) = std::env::var(FAKE_BASE) else {
        return;
    };
    let dirs = RuntimeDir::at_base(Path::new(&base)).expect("the run directory");
    let lock = acquire_instance_lock(dirs.run_dir()).expect("the instance lock is free");
    if std::env::var_os(FAKE_NO_PID).is_some() {
        std::fs::write(lock.path(), b"").expect("the lock file is emptied");
    }
    let _events = UnixListener::bind(dirs.run_dir().join("events.sock")).expect("events.sock");
    let listener = UnixListener::bind(dirs.public_socket()).expect("pam.sock");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { return };
        let _ = stream.write_all(&zmtp_greeting());
        // Keep the connection until the client lets go of it.
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stream, &mut std::io::sink());
        });
    }
}

/// The running fake daemon. Killed and reaped on the way out, panic included.
struct Fake(Child);

impl Fake {
    /// Starts the fake on `base` and returns once it holds the lock and greets in ZMTP on the
    /// socket a client dials.
    fn start(base: &Path, without_pid: bool) -> Self {
        let mut command = Command::new(std::env::current_exe().expect("this test binary"));
        command
            .args(["--exact", "fake_pre_migration_daemon_child", "--nocapture"])
            .env(FAKE_BASE, base)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if without_pid {
            command.env(FAKE_NO_PID, "1");
        }
        let fake = Self(command.spawn().expect("the fake daemon starts"));
        let socket = base.join("run").join("pam.sock");
        let deadline = Instant::now() + WAIT;
        loop {
            if let Ok(mut stream) = UnixStream::connect(&socket) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("a read timeout");
                let mut first = [0u8; 1];
                if stream.read_exact(&mut first).is_ok() {
                    assert_eq!(first[0], 0xFF, "the fake greets in ZMTP");
                    return fake;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the fake daemon never listened on {}",
                socket.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    /// Whether the process is still running.
    fn alive(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }

    /// Waits (bounded) for the process to end and returns how it ended.
    fn ended(&mut self) -> ExitStatus {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.0.try_wait().expect("the fake is waitable") {
                return status;
            }
            assert!(Instant::now() < deadline, "the fake daemon never ended");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Stops whatever daemon this build lazily started on `base`, panic included.
struct Cleanup {
    base: PathBuf,
    cwd: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if !matches!(
            client::probe_daemon(&self.base),
            Ok(DaemonStatus::Running { .. })
        ) {
            return;
        }
        let _ = pam(&self.base, &self.cwd, &["daemon", "stop"]).output();
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if matches!(
                client::probe_daemon(&self.base),
                Ok(DaemonStatus::NotRunning)
            ) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Short absolute temp path: macOS caps unix socket paths at 104 bytes. Canonical, because
/// the daemon records the caller's repository by its canonical path.
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix("pam")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp");
    let root = tmp.path().canonicalize().expect("the tempdir exists");
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).expect("a repository directory");
    // macOS assesses a fresh binary on first exec; pay that outside the assertions.
    let _ = Command::new(env!("CARGO_BIN_EXE_pam"))
        .arg("--version")
        .output();
    (tmp, root.join("base"), repo)
}

/// The compiled CLI against `base`, run from `cwd`, with no session override inherited.
fn pam(base: &Path, cwd: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pam"));
    command
        .args(args)
        .env("PAM_BASE_DIR", base)
        .env_remove("PAM_SOCKET_DIR")
        .current_dir(cwd)
        .stdin(Stdio::null());
    command
}

fn run(mut command: Command) -> (Option<i32>, String, String) {
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("the pam binary runs");
    (
        status.code(),
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
    )
}

/// The pid the instance lock names, when a process holds it.
fn lock_holder(base: &Path) -> Option<u32> {
    match client::probe_daemon(base).expect("the lock is probeable") {
        DaemonStatus::Running { pid } => pid,
        DaemonStatus::NotRunning => None,
    }
}

/// Seeds the relaxed profile, so the daemon this build starts runs a work request without an
/// approval; opened and closed before any daemon holds the store.
fn seed_relaxed(base: &Path) {
    tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async {
            let store = Store::open(&base.join("state.sqlite3"))
                .await
                .expect("the store opens");
            store
                .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
                .await
                .expect("the profile is seeded");
        });
}

/// What the new daemon's store recorded for `id`.
fn recorded(base: &Path, id: &str) -> Option<(RequestState, RequestIngress, Option<u32>)> {
    tokio::runtime::Runtime::new()
        .expect("a runtime")
        .block_on(async {
            let store = Store::open(&base.join("state.sqlite3"))
                .await
                .expect("the store opens");
            store
                .get_request(id)
                .await
                .expect("the request reads")
                .map(|row| (row.state, row.origin.ingress, row.origin.peer_pid))
        })
}

/// The whole takeover, with nothing injected: the compiled client meets a ZMTP greeting on
/// `pam.sock`, reads the pid from the lock, sends it `SIGTERM`, waits for the lock, lazily
/// starts its own build and is answered by it. Then a work request runs on the new daemon,
/// which also cleared the socket files the old one left.
#[test]
fn an_unsandboxed_client_stops_a_pre_migration_daemon_and_completes_on_this_build() {
    let (_tmp, base, repo) = fixture();
    seed_relaxed(&base);
    let _cleanup = Cleanup {
        base: base.clone(),
        cwd: repo.clone(),
    };
    let mut fake = Fake::start(&base, false);
    let old = fake.pid();
    assert_eq!(
        lock_holder(&base),
        Some(old),
        "the lock names the old daemon"
    );
    let run_dir = base.join("run");
    assert!(run_dir.join("events.sock").exists());

    let (code, stdout, stderr) = run(pam(&base, &repo, &["status", "--json"]));
    assert_eq!(code, Some(0), "stdout={stdout} stderr={stderr}");
    let status: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON result");
    assert_eq!(
        status["body"]["daemon_version"],
        env!("CARGO_PKG_VERSION"),
        "{status}"
    );

    // The old daemon was stopped by the signal the lock's pid was sent, not by this test.
    let ended = fake.ended();
    assert_eq!(ended.signal(), Some(15), "ended by SIGTERM: {ended:?}");
    // The lock is held again, by another process: the daemon this client started.
    let new = lock_holder(&base).expect("a daemon of this build holds the lock");
    assert_ne!(new, old);
    // It serves this protocol on the same path, and cleared what the old one left behind.
    let dirs = RuntimeDir::paths_at_base(&base).expect("paths resolve");
    let hello = pam_daemon::framed::client_hello(pam_proto::wire::Via::Direct);
    assert!(
        matches!(
            pam_client::transport::probe(&dirs, &hello, Duration::from_secs(5)),
            pam_client::transport::Probe::Ready(_)
        ),
        "the new daemon acknowledges a hello on pam.sock"
    );
    assert!(
        !run_dir.join("events.sock").exists(),
        "the stale events.sock is removed at bind"
    );

    // The next command is served without another takeover, and a work request completes.
    let (code, stdout, stderr) = run(pam(&base, &repo, &["echo", r#"{"msg":"hi"}"#, "--json"]));
    assert_eq!(code, Some(0), "stdout={stdout} stderr={stderr}");
    let echoed: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON result");
    assert_eq!(echoed["body"]["echo"]["msg"], "hi", "{echoed}");
    assert_eq!(lock_holder(&base), Some(new), "the same daemon answered");

    let (code, _, stderr) = run(pam(&base, &repo, &["daemon", "stop"]));
    assert_eq!(code, Some(0), "{stderr}");
    let id = echoed["id"].as_str().expect("the request id");
    let (state, ingress, peer) = recorded(&base, id).expect("the request was recorded");
    assert_eq!(state, RequestState::Done);
    assert_eq!(ingress, RequestIngress::Public);
    assert!(
        peer.is_some(),
        "the kernel's peer pid is on the request row"
    );
}

/// Through a session directory nothing is ever signalled: the client says the daemon behind
/// the relay predates its protocol and who must stop it, and the old daemon keeps running.
#[test]
fn behind_a_session_directory_a_pre_migration_daemon_is_reported_and_never_signalled() {
    let (_tmp, base, repo) = fixture();
    let mut fake = Fake::start(&base, false);
    let old = fake.pid();
    // What a relay of the old build hands a client: the old daemon's bytes, greeting first.
    let session = base.join("run");

    for args in [
        &["status", "--json"][..],
        &["wait", "req_anything", "--json"][..],
    ] {
        let mut command = pam(&base, &repo, args);
        command.env("PAM_SOCKET_DIR", &session);
        let (code, stdout, stderr) = run(command);
        assert_eq!(code, Some(1), "{args:?}: stdout={stdout} stderr={stderr}");
        assert!(
            stdout.is_empty(),
            "--json prints nothing it cannot stand behind: {stdout}"
        );
        assert!(
            stderr.contains("behind the session relay") && stderr.contains("$PAM_SOCKET_DIR"),
            "{stderr}"
        );
        assert!(
            stderr.contains("predates this pam's wire protocol"),
            "{stderr}"
        );
        assert!(
            stderr.contains("run `pam daemon stop` outside the sandbox and try again"),
            "{stderr}"
        );
    }

    assert!(fake.alive(), "the old daemon was not signalled");
    assert_eq!(lock_holder(&base), Some(old), "and still holds the lock");
    assert!(
        !base.join("state.sqlite3").exists(),
        "no daemon of this build was started"
    );
}

/// A lock that names no pid leaves nothing to signal: the client prints the instruction,
/// exits non-zero, starts nothing, and the old daemon keeps running.
#[test]
fn a_client_with_no_pid_to_signal_prints_the_instruction_and_exits_non_zero() {
    let (_tmp, base, repo) = fixture();
    let mut fake = Fake::start(&base, true);

    let (code, stdout, stderr) = run(pam(&base, &repo, &["status", "--json"]));
    assert_eq!(code, Some(1), "stdout={stdout} stderr={stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.starts_with("pam status: "), "{stderr}");
    assert!(
        stderr.contains("a pre-migration pam daemon (pid unknown) is running"),
        "{stderr}"
    );
    assert!(stderr.contains("this process may not stop it"), "{stderr}");
    assert!(
        stderr.contains("run `pam daemon stop` outside the sandbox, then retry"),
        "{stderr}"
    );

    assert!(fake.alive(), "the old daemon keeps running");
    assert!(
        !base.join("state.sqlite3").exists(),
        "no daemon of this build was started"
    );
    assert!(
        std::fs::read_to_string(base.join("run").join(LOCK_FILE))
            .expect("the lock file")
            .is_empty(),
        "the lock file was not rewritten"
    );
}

/// The same when the pid is known and the signal is refused: a sandbox that denies signals
/// and nothing else. The instruction names the pid, and the process it names is still alive.
#[cfg(target_os = "macos")]
#[test]
fn a_client_whose_signal_is_refused_names_the_pid_and_leaves_the_daemon_running() {
    let (_tmp, base, repo) = fixture();
    let mut fake = Fake::start(&base, false);
    let old = fake.pid();

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", "(version 1)(allow default)(deny signal)"])
        .arg(env!("CARGO_BIN_EXE_pam"))
        .args(["status", "--json"])
        .env("PAM_BASE_DIR", &base)
        .env_remove("PAM_SOCKET_DIR")
        .current_dir(&repo)
        .stdin(Stdio::null());
    let (code, stdout, stderr) = run(command);
    assert_eq!(code, Some(1), "stdout={stdout} stderr={stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains(&format!(
            "a pre-migration pam daemon (pid {old}) is running and this process may not stop it"
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("run `pam daemon stop` outside the sandbox, then retry"),
        "{stderr}"
    );

    assert!(fake.alive(), "the old daemon was not stopped");
    assert_eq!(lock_holder(&base), Some(old));
    assert!(
        !base.join("state.sqlite3").exists(),
        "no daemon of this build was started"
    );
}
