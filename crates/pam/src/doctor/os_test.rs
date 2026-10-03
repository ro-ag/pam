//! The OS seam: a fake every engine test shares, and the real seam's
//! side-effect rules proved against real files and a real socket.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::Via;

use super::classify::{EACCES, ECONNREFUSED, ENOENT};
use super::helpers::{Helper, HelperOutcome, HelperRun};
use super::os::{HelloAnswer, KeyringAnswer, LockState, Os, RealOs};

/// What a fake file or socket operation answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    Ok,
    Denied,
    Absent,
    Refused,
    Code(io::ErrorKind, i32),
}

impl Answer {
    fn to_io(self) -> io::Result<()> {
        match self {
            Self::Ok => Ok(()),
            Self::Denied => Err(io::Error::from_raw_os_error(EACCES)),
            Self::Absent => Err(io::Error::from_raw_os_error(ENOENT)),
            Self::Refused => Err(io::Error::from_raw_os_error(ECONNREFUSED)),
            Self::Code(kind, code) => Err(io::Error::new(kind, format!("fake os error {code}"))),
        }
    }
}

/// The operation a fake answer is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    OpenRead,
    OpenWrite,
    ListDir,
    Connect,
}

/// How the fake's helpers answer: as the real macOS tools do when the
/// sandbox lets them through, or as they do when it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperMood {
    Allowed,
    Denied,
    Gibberish,
    Missing,
}

/// A scripted OS: a default answer, per-path overrides, a hello, helper
/// moods, and a log of every call for the safety assertions.
pub(crate) struct FakeOs {
    pub(crate) default: Answer,
    pub(crate) overrides: HashMap<(Op, PathBuf), Answer>,
    pub(crate) lock: Result<LockState, Answer>,
    pub(crate) pid_file: Result<String, Answer>,
    pub(crate) hello: Mutex<Option<HelloAnswer>>,
    pub(crate) helper_mood: HelperMood,
    pub(crate) chain: Vec<String>,
    pub(crate) keyring: KeyringAnswer,
    pub(crate) exe: Option<PathBuf>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) env: HashMap<String, OsString>,
    pub(crate) calls: Mutex<Vec<String>>,
}

impl FakeOs {
    /// A same-user process with no sandbox: everything answers.
    pub(crate) fn unsandboxed() -> Self {
        Self {
            default: Answer::Ok,
            overrides: HashMap::new(),
            lock: Ok(LockState::Held),
            pid_file: Ok("4242\n".to_owned()),
            hello: Mutex::new(Some(HelloAnswer::Ready {
                version: "0.4.3".to_owned(),
                proto: 2,
                epoch: "01JBEPOCH".to_owned(),
            })),
            helper_mood: HelperMood::Allowed,
            chain: vec!["zsh".to_owned(), "claude".to_owned()],
            keyring: KeyringAnswer::Absent,
            exe: Some(PathBuf::from("/usr/local/bin/pam")),
            cwd: None,
            env: HashMap::new(),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A process held to the public socket: everything private is denied.
    pub(crate) fn sandboxed() -> Self {
        Self {
            default: Answer::Denied,
            lock: Ok(LockState::Held),
            helper_mood: HelperMood::Denied,
            keyring: KeyringAnswer::Denied,
            ..Self::unsandboxed()
        }
    }

    pub(crate) fn with(mut self, op: Op, path: impl Into<PathBuf>, answer: Answer) -> Self {
        self.overrides.insert((op, path.into()), answer);
        self
    }

    pub(crate) fn with_env(mut self, name: &str, value: &str) -> Self {
        self.env.insert(name.to_owned(), OsString::from(value));
        self
    }

    pub(crate) fn with_hello(self, hello: HelloAnswer) -> Self {
        *self.hello.lock().unwrap() = Some(hello);
        self
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn answer(&self, op: Op, path: &Path) -> io::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{op:?} {}", path.display()));
        self.overrides
            .get(&(op, path.to_path_buf()))
            .copied()
            .unwrap_or(self.default)
            .to_io()
    }

    fn helper_answer(&self, helper: &Helper) -> HelperOutcome {
        // The last path segment, splitting on either separator: a Windows
        // helper path keeps its backslashes on this host.
        let program = helper.program.to_string_lossy().into_owned();
        let program = program
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_owned();
        let run = |code, stdout: &str, stderr: &str| {
            HelperOutcome::Ran(HelperRun::new(code, stdout, stderr))
        };
        match (self.helper_mood, program.as_str()) {
            (HelperMood::Missing, _) => {
                HelperOutcome::SpawnFailed(io::Error::from_raw_os_error(ENOENT))
            }
            (HelperMood::Gibberish, _) => run(Some(7), "", "something unexpected\n"),
            (_, "ps") => {
                // One ancestor per call: `<ppid> <name>`; the chain is
                // walked from this process's pid up.
                let pid: u32 = helper.args[3].to_string_lossy().parse().unwrap();
                let depth = if pid == std::process::id() {
                    0
                } else {
                    usize::try_from(pid).unwrap().saturating_sub(100)
                };
                if depth == 0 {
                    run(Some(0), "  101 /usr/local/bin/pam\n", "")
                } else {
                    match self.chain.get(depth - 1) {
                        Some(name) => run(Some(0), &format!("  {} /bin/{name}\n", pid + 1), ""),
                        None => run(Some(0), "    0 /sbin/launchd\n", ""),
                    }
                }
            }
            (HelperMood::Allowed, "security") => run(
                Some(44),
                "",
                "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
            ),
            // Captured 2026-10-02 under broker-macos.sb.
            (HelperMood::Denied, "security") => run(
                Some(44),
                "",
                "security: SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid.\nsecurity: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
            ),
            // Signal 0 delivered; and, further down, the LaunchServices
            // query silent under a denied lookup: the same empty success.
            (HelperMood::Allowed, "kill") | (HelperMood::Denied, "lsappinfo") => {
                run(Some(0), "", "")
            }
            (HelperMood::Denied, "kill") => {
                run(Some(1), "", "kill: 4242: Operation not permitted\n")
            }
            (HelperMood::Allowed, "lsappinfo") => {
                run(Some(0), "ASN:0x0-0x1001-\"loginwindow\":\n", "")
            }
            // Captured 2026-10-02 outside and under both macOS profiles.
            (HelperMood::Allowed, "osascript") => run(Some(0), "com.apple.finder\n", ""),
            (HelperMood::Denied, "osascript") => run(
                Some(1),
                "",
                "2026-10-02 18:18:23.907 osascript[26160:255111] Connection Invalid error for service com.apple.hiservices-xpcservice.\n0:2: execution error: Can’t get application \"Finder\". (-1728)\n",
            ),
            (_, "where.exe") => run(Some(2), "", ""),
            (_, "powershell.exe") => {
                let script = helper
                    .args
                    .last()
                    .map(|arg| arg.to_string_lossy())
                    .unwrap_or_default();
                if script.contains("Win32_Process") {
                    run(Some(0), "claude.exe\r\ncmd.exe\r\nexplorer.exe\r\n", "")
                } else {
                    run(Some(0), "PATH=C:\\pam\\pam.exe\r\n", "")
                }
            }
            _ => run(Some(127), "", "no such helper\n"),
        }
    }
}

impl Os for FakeOs {
    fn open_read(&self, path: &Path) -> io::Result<()> {
        self.answer(Op::OpenRead, path)
    }

    fn open_write(&self, path: &Path) -> io::Result<()> {
        self.answer(Op::OpenWrite, path)
    }

    fn list_dir(&self, path: &Path) -> io::Result<()> {
        self.answer(Op::ListDir, path)
    }

    fn lock_probe(&self, path: &Path) -> io::Result<LockState> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("Lock {}", path.display()));
        match self.lock {
            Ok(state) => Ok(state),
            Err(answer) => answer.to_io().map(|()| LockState::Free),
        }
    }

    fn read_pid_file(&self, path: &Path) -> io::Result<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("ReadPid {}", path.display()));
        match &self.pid_file {
            Ok(text) => Ok(text.clone()),
            Err(answer) => answer.to_io().map(|()| String::new()),
        }
    }

    fn connect_unix(&self, path: &Path, _hold: Duration) -> io::Result<()> {
        self.answer(Op::Connect, path)
    }

    fn run_helper(&self, helper: &Helper) -> HelperOutcome {
        self.calls.lock().unwrap().push(format!(
            "helper {} {}",
            helper.program.display(),
            helper
                .args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        ));
        self.helper_answer(helper)
    }

    fn hello(&self, dirs: &RuntimeDir, via: Via, _timeout: Duration) -> HelloAnswer {
        self.calls.lock().unwrap().push(format!(
            "hello {} via {via:?}",
            dirs.public_socket().display()
        ));
        self.hello
            .lock()
            .unwrap()
            .take()
            .unwrap_or(HelloAnswer::Silent)
    }

    fn keyring_get(&self, account: &str) -> KeyringAnswer {
        self.calls
            .lock()
            .unwrap()
            .push(format!("keyring {account}"));
        self.keyring.clone()
    }

    fn current_exe(&self) -> io::Result<PathBuf> {
        self.exe.clone().ok_or_else(|| io::Error::other("no exe"))
    }

    fn current_dir(&self) -> io::Result<PathBuf> {
        self.cwd.clone().ok_or_else(|| io::Error::other("no cwd"))
    }

    fn env_var(&self, name: &str) -> Option<OsString> {
        self.env.get(name).cloned()
    }
}

/// The source of the seam and the probe files: the side-effect rules are
/// enforced by what is not written there.
const SEAM_SOURCES: &[(&str, &str)] = &[
    ("os.rs", include_str!("os.rs")),
    ("inventory.rs", include_str!("inventory.rs")),
    ("probe_unix.rs", include_str!("probe_unix.rs")),
    ("probe_windows.rs", include_str!("probe_windows.rs")),
];

#[test]
fn no_probe_source_writes_creates_truncates_unlinks_or_renames() {
    for (file, source) in SEAM_SOURCES {
        for forbidden in [
            "remove_file",
            "remove_dir",
            "rename(",
            "create(true)",
            "create_new",
            "truncate(true)",
            "write_all",
            "fs::write",
            "set_len",
            "create_dir",
            "set_permissions",
            "hard_link",
            "symlink",
            "copy(",
        ] {
            assert!(
                !source.contains(forbidden),
                "{file} must not contain `{forbidden}`"
            );
        }
    }
}

#[test]
fn the_seam_reads_bytes_in_exactly_one_place_the_pid_file() {
    let source = include_str!("os.rs");
    assert_eq!(source.matches("read_to_string").count(), 1);
    assert!(!source.contains("read_to_end"));
    assert!(!source.contains("read_exact"));
    assert!(!source.contains("fs::read("));
    // The read is bounded.
    assert!(source.contains(".take(MAX_PID_FILE_BYTES as u64)"));
}

#[test]
fn the_windows_probes_never_dial_and_never_read_the_control_file() {
    let source = include_str!("probe_windows.rs");
    for forbidden in [
        "TcpStream",
        "connect",
        "read_pid_file",
        "read_to_string",
        "fs::read",
    ] {
        assert!(
            !source.contains(forbidden),
            "probe_windows.rs must not contain `{forbidden}`"
        );
    }
    // The control file is opened for read through the seam only.
    assert!(source.contains("ProbeId::AdminControlRead => open_read("));
}

#[test]
fn the_admin_connect_sends_nothing_and_stays_open_for_the_hold_on_unix() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    let tmp = tempfile::Builder::new()
        .prefix("pamdoc")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = tmp.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let hold = super::probe_unix::CONNECT_HOLD;
    let tripwire = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let accepted = Instant::now();
        // macOS refuses the option on a socket whose peer already hung up
        // (EINVAL); the read then returns end of file at once.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut byte = [0_u8; 1];
        // Either end of file (the probe dropped the stream) or a timeout: a
        // byte is the failure. The time to end of file is the hold the
        // daemon gets to read our credentials.
        let bytes = match stream.read(&mut byte) {
            Ok(0) | Err(_) => 0,
            Ok(read) => read,
        };
        (bytes, accepted.elapsed())
    });
    assert!(RealOs.connect_unix(&socket, hold).is_ok());
    let (bytes, open_for) = tripwire.join().unwrap();
    assert_eq!(bytes, 0, "the admin probe sent a byte");
    assert!(
        open_for >= hold.saturating_sub(Duration::from_millis(20)),
        "the socket was dropped after {open_for:?}, before the {hold:?} hold"
    );
}

#[test]
fn the_real_seam_opens_without_creating_and_lists_without_listing_more_than_one() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("absent.sqlite3");
    assert_eq!(
        RealOs.open_write(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        RealOs.open_read(&missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!missing.exists(), "open_write created the file");
    assert_eq!(
        RealOs
            .list_dir(&tmp.path().join("absent"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    let present = tmp.path().join("state.sqlite3");
    std::fs::write(&present, b"sqlite").unwrap();
    let before = std::fs::metadata(&present).unwrap();
    RealOs.open_write(&present).unwrap();
    RealOs.open_read(&present).unwrap();
    RealOs.list_dir(tmp.path()).unwrap();
    let after = std::fs::metadata(&present).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(std::fs::read(&present).unwrap(), b"sqlite");
}

#[test]
fn the_lock_probe_reports_a_holder_and_releases_what_it_took() {
    let tmp = tempfile::tempdir().unwrap();
    let lock = tmp.path().join("daemon.lock");
    std::fs::write(&lock, b"1234").unwrap();
    assert_eq!(RealOs.lock_probe(&lock).unwrap(), LockState::Free);
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    holder.try_lock().unwrap();
    assert_eq!(RealOs.lock_probe(&lock).unwrap(), LockState::Held);
    drop(holder);
    // The probe's shared lock was released: an exclusive lock succeeds.
    let next = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    next.try_lock().unwrap();
    assert_eq!(std::fs::read(&lock).unwrap(), b"1234");
    assert_eq!(
        RealOs
            .lock_probe(&tmp.path().join("absent.lock"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn the_pid_file_read_is_bounded() {
    let tmp = tempfile::tempdir().unwrap();
    let lock = tmp.path().join("daemon.lock");
    std::fs::write(&lock, "9".repeat(1000)).unwrap();
    assert_eq!(
        RealOs.read_pid_file(&lock).unwrap().len(),
        super::os::MAX_PID_FILE_BYTES
    );
}
