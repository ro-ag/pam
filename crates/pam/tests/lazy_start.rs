//! The lazy daemon start, through the real `pam` binary: a client with no daemon behind it
//! spawns one, and that daemon is isolated from the command that started it.
//!
//! The daemon outlives the command and serves every later caller, so it must not inherit the
//! first caller's process group (a harness that kills the group would kill everyone's daemon) or
//! its environment (an agent-exported variable would reach every flow). On unix the assertions
//! read the process table through `ps`. On Windows the one thing proved is that a caller
//! capturing the command's stdout through a pipe is not held up by the daemon the command
//! started.

#[cfg(unix)]
mod unix {

    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use pam::client::{self, DaemonStatus};

    /// A variable only the calling shell has; it must never reach the daemon.
    const MARKER_NAME: &str = "PAM_TEST_AGENT_SECRET_MARKER";
    const MARKER_VALUE: &str = "leak-me-if-you-inherit-everything";

    /// Bound on each wait for the daemon to come up or go away.
    const WAIT: Duration = Duration::from_secs(30);

    /// Short absolute temp path: macOS caps unix socket paths at 104 bytes.
    fn short_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }

    fn pam(base: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_pam"))
            .args(args)
            .env("PAM_BASE_DIR", base)
            .env(MARKER_NAME, MARKER_VALUE)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .expect("the pam binary runs")
    }

    /// Stops the lazily started daemon on the way out, panic included.
    struct Cleanup {
        base: PathBuf,
        cwd: PathBuf,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = pam(&self.base, &self.cwd, &["daemon", "stop"]);
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

    fn ps(args: &[&str]) -> String {
        let output = Command::new("ps").args(args).output().expect("ps runs");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn a_lazily_started_daemon_leads_its_own_group_and_never_inherits_the_callers_environment() {
        let tmp = short_tempdir();
        let base = tmp.path().join("base");
        let _cleanup = Cleanup {
            base: base.clone(),
            cwd: tmp.path().to_path_buf(),
        };
        // macOS assesses a fresh binary on first exec; pay that outside the assertions.
        let _ = Command::new(env!("CARGO_BIN_EXE_pam"))
            .arg("--version")
            .output();

        let output = pam(&base, tmp.path(), &["status", "--json"]);
        assert!(
            output.status.success(),
            "a client with no daemon starts one and is answered: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("daemon_version"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );

        let DaemonStatus::Running { pid: Some(pid) } =
            client::probe_daemon(&base).expect("the lock is probeable")
        else {
            panic!("the lazily started daemon holds the instance lock");
        };
        let pid = pid.to_string();

        let group = ps(&["-o", "pgid=", "-p", &pid]);
        assert_eq!(
            group.trim(),
            pid,
            "the daemon leads its own process group, not the caller's"
        );

        // `ps e` appends the process environment; only judge it when this host shows one.
        let environment = ps(&["eww", "-p", &pid]);
        if environment.contains("PAM_BASE_DIR=") {
            assert!(
                !environment.contains(MARKER_NAME) && !environment.contains(MARKER_VALUE),
                "the daemon must not inherit the caller's environment: {environment}"
            );
        } else {
            eprintln!("this host's `ps` shows no process environment; environment check skipped");
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Bound on the captured call: a start takes a second or two; the hang this guards
    /// against lasts as long as the daemon lives.
    const CALL_BOUND: Duration = Duration::from_secs(30);

    /// After a failed call: how much longer the command itself is watched before anything is
    /// ended. Longer than everything the client can wait for on its own (two broker runs and two
    /// readiness waits), so "the command never exits" is told apart from "it exits late".
    const LATE_EXIT_WATCH: Duration = Duration::from_secs(75);

    /// After each process the diagnosis ends: how long the pipes get to report end-of-file.
    const RELEASE_WAIT: Duration = Duration::from_secs(3);

    const POLL: Duration = Duration::from_millis(10);

    /// How many characters of a captured stream or a process's command line a report shows.
    const SHOWN: usize = 400;

    /// The pids of every running `pam.exe`: the integration binary is `lazy_start-<hash>.exe`,
    /// so only daemons and clients of the binary under test show up.
    fn pam_pids() -> BTreeSet<u32> {
        let output = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq pam.exe", "/FO", "CSV", "/NH"])
            .output()
            .expect("tasklist runs");
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split("\",\"").nth(1)?.parse().ok())
            .collect()
    }

    fn end(pid: u32, tree: bool) {
        let pid = pid.to_string();
        let mut args = vec!["/PID", pid.as_str(), "/F"];
        if tree {
            args.push("/T");
        }
        let _ = Command::new("taskkill")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Ends the daemon this test started (the pids `pam.exe` gained since `before`), panic
    /// included: Windows has no `pam daemon stop`.
    struct Cleanup {
        before: BTreeSet<u32>,
    }

    impl Cleanup {
        fn started(&self) -> BTreeSet<u32> {
            pam_pids().difference(&self.before).copied().collect()
        }
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for pid in self.started() {
                end(pid, true);
            }
        }
    }

    fn pam(base: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pam"));
        command
            .args(["status", "--json"])
            .env("PAM_BASE_DIR", base)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// What one captured pipe delivered and when it reported end-of-file.
    #[derive(Default)]
    struct Stream {
        bytes: Vec<u8>,
        closed_after: Option<Duration>,
    }

    /// Reads `pipe` to end-of-file on its own thread. The thread is never joined: a pipe some
    /// process still holds would keep the test from reporting what it saw.
    fn drain(mut pipe: impl Read + Send + 'static, started: Instant) -> Arc<Mutex<Stream>> {
        let stream = Arc::new(Mutex::new(Stream::default()));
        let shared = Arc::clone(&stream);
        std::thread::spawn(move || {
            let mut chunk = [0_u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => shared.lock().unwrap().bytes.extend_from_slice(&chunk[..n]),
                }
            }
            shared.lock().unwrap().closed_after = Some(started.elapsed());
        });
        stream
    }

    /// One `pam status --json` whose stdout and stderr the test captures through pipes, the way
    /// an agent harness does, with the process exit and each pipe's end-of-file seen apart.
    struct Call {
        pid: u32,
        child: Arc<Mutex<Child>>,
        started: Instant,
        exited: Arc<Mutex<Option<(ExitStatus, Duration)>>>,
        stdout: Arc<Mutex<Stream>>,
        stderr: Arc<Mutex<Stream>>,
    }

    impl Call {
        fn start(base: &Path) -> Self {
            let started = Instant::now();
            let mut child = pam(base).spawn().expect("the pam binary runs");
            let stdout = drain(child.stdout.take().expect("stdout is piped"), started);
            let stderr = drain(child.stderr.take().expect("stderr is piped"), started);
            let pid = child.id();
            let child = Arc::new(Mutex::new(child));
            let exited = Arc::new(Mutex::new(None));
            let (watched, seen) = (Arc::clone(&child), Arc::clone(&exited));
            // Its own thread, so the exit is timed when it happens, whatever the test is doing.
            std::thread::spawn(move || {
                loop {
                    if let Ok(Some(status)) = watched.lock().unwrap().try_wait() {
                        *seen.lock().unwrap() = Some((status, started.elapsed()));
                        return;
                    }
                    std::thread::sleep(POLL);
                }
            });
            Self {
                pid,
                child,
                started,
                exited,
                stdout,
                stderr,
            }
        }

        fn exit(&self) -> Option<(ExitStatus, Duration)> {
            *self.exited.lock().unwrap()
        }

        fn pipes_closed(&self) -> bool {
            self.stdout.lock().unwrap().closed_after.is_some()
                && self.stderr.lock().unwrap().closed_after.is_some()
        }

        /// What a harness waits for: the process gone and both pipes at end-of-file.
        fn returned(&self) -> bool {
            self.exit().is_some() && self.pipes_closed()
        }

        fn wait_until(&self, deadline: Instant, done: impl Fn(&Self) -> bool) -> bool {
            loop {
                if done(self) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(POLL);
            }
        }

        fn text(stream: &Arc<Mutex<Stream>>) -> String {
            String::from_utf8_lossy(&stream.lock().unwrap().bytes).into_owned()
        }

        fn facts(&self) -> String {
            let pipe = |name: &str, stream: &Arc<Mutex<Stream>>| {
                let stream = stream.lock().unwrap();
                let closed = stream.closed_after.map_or_else(
                    || "STILL OPEN (no end-of-file)".to_owned(),
                    |after| format!("end-of-file after {after:?}"),
                );
                let text = String::from_utf8_lossy(&stream.bytes);
                let shown: String = text.chars().take(SHOWN).collect();
                format!("{name}: {closed}, {} bytes: {shown:?}", stream.bytes.len())
            };
            let exit = self.exit().map_or_else(
                || "STILL RUNNING".to_owned(),
                |(status, after)| format!("exited with {status} after {after:?}"),
            );
            format!(
                "command (pid {}): {exit}\n{}\n{}",
                self.pid,
                pipe("stdout", &self.stdout),
                pipe("stderr", &self.stderr)
            )
        }
    }

    /// One row of the process table.
    #[derive(Clone)]
    struct Process {
        pid: u32,
        parent: u32,
        line: String,
    }

    fn powershell() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set"))
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
    }

    /// The whole process table: pid, parent pid, session, start time, name and command line.
    ///
    /// Read through WMI with no cmdlet in the script: a cmdlet makes PowerShell search its module
    /// path, which is slow where many modules are installed and fails where the environment
    /// carries another PowerShell's module path.
    fn processes() -> Vec<Process> {
        let script = "foreach ($p in ([wmisearcher]'SELECT ProcessId, ParentProcessId, SessionId, \
                      CreationDate, Name, CommandLine FROM Win32_Process').Get()) { \
                      '{0}|{1}|session {2}|{3}|{4}|{5}' -f $p.ProcessId, $p.ParentProcessId, \
                      $p.SessionId, ([string]$p.CreationDate).PadRight(18).Substring(8, 10), \
                      $p.Name, $p.CommandLine }";
        let Ok(output) = Command::new(powershell())
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::null())
            .output()
        else {
            return Vec::new();
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut fields = line.splitn(3, '|');
                Some(Process {
                    pid: fields.next()?.trim().parse().ok()?,
                    parent: fields.next()?.trim().parse().ok()?,
                    line: line.trim().to_owned(),
                })
            })
            .collect()
    }

    /// `root`'s descendants in `table`, nearest first.
    fn descendants(table: &[Process], root: u32) -> Vec<Process> {
        let mut found: Vec<Process> = Vec::new();
        let mut parents = vec![root];
        while let Some(parent) = parents.pop() {
            for process in table.iter().filter(|p| p.parent == parent && p.pid != root) {
                if found.iter().all(|seen| seen.pid != process.pid) {
                    parents.push(process.pid);
                    found.push(process.clone());
                }
            }
        }
        found
    }

    /// The last `lines` lines of the newest `daemon.log*` under `log` (the log rotates daily).
    fn daemon_log_tail(log: &Path, lines: usize) -> String {
        let newest = std::fs::read_dir(log).ok().and_then(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("daemon.log"))
                })
                .max()
        });
        let Some(path) = newest else {
            return format!("<no daemon.log in {}>", log.display());
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let all: Vec<&str> = text.lines().collect();
                all[all.len().saturating_sub(lines)..].join("\n")
            }
            Err(error) => format!("<{}: {error}>", path.display()),
        }
    }

    fn listing(dir: &Path) -> String {
        std::fs::read_dir(dir).map_or_else(
            |error| format!("<{}: {error}>", dir.display()),
            |entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        )
    }

    fn whoami() -> String {
        Command::new("whoami").output().map_or_else(
            |error| format!("<whoami: {error}>"),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )
    }

    /// How long this host's PowerShell takes to start and exit with nothing to do, under an
    /// environment as bare as the one the daemon's broker gets: the floor under every broker run.
    fn bare_powershell_start() -> String {
        let mut command = Command::new(powershell());
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear();
        for name in ["SystemRoot", "SystemDrive", "windir", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let started = Instant::now();
        match command.status() {
            Ok(status) => format!("{status} after {:?}", started.elapsed()),
            Err(error) => format!("<{error}>"),
        }
    }

    fn relevant(table: &[Process]) -> String {
        let names = ["pam.exe", "powershell", "conhost", "lazy_start", "wmiprvse"];
        let mut shown = String::new();
        for process in table {
            let lower = process.line.to_ascii_lowercase();
            if names.iter().any(|name| lower.contains(name)) {
                let line: String = process.line.chars().take(SHOWN).collect();
                let _ = writeln!(shown, "{line}");
            }
        }
        shown
    }

    /// Ends processes one at a time, the command's own descendants first, then the command, then
    /// each daemon, then each daemon's descendants, and names the first one whose end closed the
    /// pipes: that process held them.
    fn find_holder(call: &Call, table: &[Process], daemons: &BTreeSet<u32>) -> String {
        let mut steps: Vec<(String, u32)> = descendants(table, call.pid)
            .into_iter()
            .map(|p| (format!("the command's descendant [{}]", p.line), p.pid))
            .collect();
        steps.push(("the command itself".to_owned(), call.pid));
        for daemon in daemons.iter().filter(|pid| **pid != call.pid) {
            if steps.iter().all(|(_, pid)| pid != daemon) {
                steps.push((format!("the pam.exe with pid {daemon}"), *daemon));
            }
            steps.extend(descendants(table, *daemon).into_iter().map(|p| {
                (
                    format!("the descendant of pam.exe {daemon} [{}]", p.line),
                    p.pid,
                )
            }));
        }
        let mut ended = Vec::new();
        for (who, pid) in steps {
            if pid == call.pid {
                let _ = call.child.lock().unwrap().kill();
            } else {
                end(pid, false);
            }
            if call.wait_until(Instant::now() + RELEASE_WAIT, Call::returned) {
                return format!(
                    "the pipes closed when {who} was ended (ended before it, without effect: \
                     {ended:?})"
                );
            }
            ended.push(pid);
        }
        format!("the pipes are STILL OPEN after ending {ended:?}: none of them held it")
    }

    /// Everything observable about a captured call that did not return in time, so the failure
    /// states which of these it was: the command never exited, the command exited and something
    /// kept its pipes open (and what), the broker hung, or the daemon never started.
    fn diagnose(call: &Call, base: &Path, cleanup: &Cleanup, halfway: &[Process]) -> String {
        let mut report = format!(
            "as {} (test pid {}), base {}\n-- at {CALL_BOUND:?}:\n{}\n",
            whoami(),
            std::process::id(),
            base.display(),
            call.facts()
        );
        let table = processes();
        let daemons = cleanup.started();
        let columns = "pid|parent|session|start|name|command";
        let _ = writeln!(report, "-- pam.exe started by this test: {daemons:?}");
        let _ = writeln!(
            report,
            "-- process table halfway ({columns}):\n{}-- process table at the bound:\n{}\
             -- {}: {}\n-- run: {}\n-- daemon.log tail:\n{}",
            relevant(halfway),
            relevant(&table),
            base.display(),
            listing(base),
            listing(&base.join("run")),
            daemon_log_tail(&base.join("log"), 30)
        );
        if call.exit().is_none() {
            let late = call.wait_until(Instant::now() + LATE_EXIT_WATCH, |call| {
                call.exit().is_some()
            });
            let _ = writeln!(
                report,
                "-- watched the command for up to {LATE_EXIT_WATCH:?} more: {}",
                if late { "it exited" } else { "it NEVER exited" },
            );
        }
        if call.wait_until(Instant::now() + RELEASE_WAIT, Call::returned) {
            let _ = writeln!(report, "-- the pipes closed once the command exited");
        } else {
            let _ = writeln!(report, "-- holder: {}", find_holder(call, &table, &daemons));
        }
        let _ = writeln!(report, "-- in the end:\n{}", call.facts());
        let _ = writeln!(
            report,
            "-- a bare PowerShell start on this host: {}",
            bare_powershell_start()
        );
        report
    }

    /// An agent harness captures the command's stdout through a pipe. The first command lazily
    /// starts the daemon, which outlives it: if the daemon held the pipe's write end the harness
    /// would wait for end-of-file until the daemon died.
    #[test]
    fn a_caller_capturing_stdout_through_a_pipe_is_not_held_by_the_daemon_it_started() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base: PathBuf = tmp.path().join("base");
        let cleanup = Cleanup { before: pam_pids() };

        let call = Call::start(&base);
        let bound = call.started + CALL_BOUND;
        if !call.wait_until(call.started + CALL_BOUND / 2, Call::returned) {
            // Slow already: what is running now tells a broker that hangs from a daemon that
            // holds the pipe, even when the two end at the same moment later.
            let halfway = processes();
            if !call.wait_until(bound, Call::returned) {
                let report = diagnose(&call, &base, &cleanup, &halfway);
                drop(cleanup);
                panic!("the captured call did not return within {CALL_BOUND:?}\n{report}");
            }
        }
        let (status, exited) = call.exit().expect("the call finished");
        let closed = |stream: &Arc<Mutex<Stream>>| stream.lock().unwrap().closed_after;
        let elapsed = exited.max(
            closed(&call.stdout)
                .max(closed(&call.stderr))
                .unwrap_or(exited),
        );
        let stdout = Call::text(&call.stdout);
        assert!(status.success(), "{stdout} {}", Call::text(&call.stderr));
        assert!(stdout.contains("daemon_version"), "{stdout}");
        eprintln!("first captured call returned in {elapsed:?}");

        assert!(
            !cleanup.started().is_empty(),
            "the daemon keeps running after the command that started it returned"
        );
        let again = pam(&base).output().expect("the second call runs");
        assert!(
            again.status.success()
                && String::from_utf8_lossy(&again.stdout).contains("daemon_version"),
            "the daemon answers the next caller"
        );
    }
}
