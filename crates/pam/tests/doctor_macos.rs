//! `pam doctor` under a real `sandbox-exec` profile: both verdicts through
//! the compiled binary, against a daemon on a scratch base.
//!
//! The daemon runs in-process ([`pam_testkit::TestDaemon`], relaxed profile
//! seeded, like `doctor_cli.rs`); the binary under test is a fresh APFS clone
//! per fixture, warmed with `--version` before anything is timed (the first
//! exec of a freshly linked binary stalls once while macOS assesses it), and
//! every path a profile names is the resolved one (`/private/tmp/…`), because
//! Seatbelt matches resolved paths.
//!
//! What each test establishes is recorded in
//! `docs/macos-sandbox-acceptance.md` ("Boundary self-check acceptance") and
//! in the per-profile table of `docs/sandbox/README.md`. A result that is not
//! the one the spec hoped for is asserted exactly as observed, never papered
//! over: a test that documents a gap by pinning the failing probe list is the
//! honest record of it.
#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pam::doctor::inventory::{
    ADMIN_DIR, ADMIN_SOCKET, BACKUP_DIR, ENGINE_DIR, ENGINE_SOCKET, FLOWS_DIR, MODEL_TRUST_DIR,
    RUN_DIR, STORE_FILE, STORE_SHM, STORE_WAL, engine_runtime_dir,
};
use pam::doctor::profiles::{self, Format, Harness, Variant};
use pam_daemon::lifecycle::{LOCK_FILE, LOG_DIR};
use pam_proto::doctor::{Platform, ProbeClass, ProbeId};
use pam_testkit::TestDaemon;
use tokio::time::timeout;

/// One doctor run (helpers included) plus the report and a status poll,
/// well inside the engine's own 30 s bound.
const DEADLINE: Duration = Duration::from_secs(120);

/// How long a `pam listen` may take to print its last startup line.
const RELAY_START: Duration = Duration::from_secs(30);

/// The macOS inventory ids whose class is must-deny, in inventory order.
fn must_deny_on_macos() -> Vec<ProbeId> {
    ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && id.applies_to(Platform::Macos))
        .collect()
}

/// The filesystem target of a macOS must-deny probe under `base`, from the
/// same constants `doctor::inventory` plans it with; `None` for the probes
/// whose target is not a path under the base (the keychain, the signal, the
/// brokers, the executable and bundle) and for the never-probed unlink.
fn target_of(id: ProbeId, base: &Path) -> Option<PathBuf> {
    Some(match id {
        ProbeId::RunLockWrite => base.join(RUN_DIR).join(LOCK_FILE),
        ProbeId::AdminEndpoint | ProbeId::AdminEndpointAlias => {
            base.join(ADMIN_DIR).join(ADMIN_SOCKET)
        }
        ProbeId::AdminDir => base.join(ADMIN_DIR),
        ProbeId::StoreRead | ProbeId::StoreWrite => base.join(STORE_FILE),
        ProbeId::StoreWalRead | ProbeId::StoreWalWrite => base.join(STORE_WAL),
        ProbeId::StoreShmRead | ProbeId::StoreShmWrite => base.join(STORE_SHM),
        ProbeId::BackupRead => base.join(BACKUP_DIR),
        ProbeId::ModelTrustRead => base.join(MODEL_TRUST_DIR),
        ProbeId::EngineRead => base.join(ENGINE_DIR),
        ProbeId::EngineRuntimeRead => engine_runtime_dir(base),
        ProbeId::EngineSocket => engine_runtime_dir(base).join(ENGINE_SOCKET),
        ProbeId::FlowsRead => base.join(FLOWS_DIR),
        ProbeId::LogRead => base.join(LOG_DIR),
        _ => return None,
    })
}

/// The must-deny ids an unsandboxed same-user process is expected to find
/// `allowed` on `base`: every macOS must-deny probe except those that are
/// never probed (`public.unlink`), those whose target is absent on this
/// base ([`target_of`]) and the bundle probe outside a `.app`.
fn reachable_unsandboxed(base: &Path) -> Vec<ProbeId> {
    must_deny_on_macos()
        .into_iter()
        .filter(|id| match id {
            ProbeId::PublicUnlink | ProbeId::BundleWrite => false,
            _ => target_of(*id, base).is_none_or(|path| path.exists()),
        })
        .collect()
}

/// The must-deny probes that list a directory under `base`, with the
/// directory, in inventory order.
fn directory_probes(base: &Path) -> Vec<(ProbeId, PathBuf)> {
    must_deny_on_macos()
        .into_iter()
        .filter(|id| {
            matches!(
                id,
                ProbeId::AdminDir
                    | ProbeId::BackupRead
                    | ProbeId::ModelTrustRead
                    | ProbeId::EngineRead
                    | ProbeId::EngineRuntimeRead
                    | ProbeId::FlowsRead
                    | ProbeId::LogRead
            )
        })
        .filter_map(|id| target_of(id, base).map(|path| (id, path)))
        .collect()
}

/// The ids of `list` as the report spells them.
fn names(list: &[ProbeId]) -> Vec<String> {
    list.iter().map(ToString::to_string).collect()
}

/// A JSON array of probe ids as strings.
fn id_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("a list of probe ids: {value}"))
        .iter()
        .map(|id| {
            id.as_str()
                .or_else(|| id["id"].as_str())
                .unwrap_or_else(|| panic!("a probe id: {id}"))
                .to_owned()
        })
        .collect()
}

struct CliRun {
    /// The exit code, or `-1` when a signal ended the process (named in
    /// `stderr` then).
    code: i32,
    stdout: String,
    stderr: String,
}

impl CliRun {
    /// The one JSON document a `--json` run prints: anything else on stdout
    /// fails the parse.
    fn document(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|error| {
            panic!(
                "stdout is one JSON document ({error}): {}\nstderr: {}",
                self.stdout, self.stderr
            )
        })
    }
}

fn finish(output: &std::process::Output) -> CliRun {
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&output.status) {
        use std::fmt::Write as _;
        let _ = write!(stderr, "[the pam process was ended by signal {signal}]");
    }
    CliRun {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
    }
}

/// A `sandbox-exec` invocation: the profile text written to a file and the
/// `-D` parameters the profile's harness passes.
#[derive(Clone)]
struct Sandbox {
    profile: PathBuf,
    params: Vec<(String, String)>,
}

impl Sandbox {
    fn write(dir: &Path, name: &str, text: &str, params: &[(&str, &Path)]) -> Self {
        let profile = dir.join(format!("{name}.sb"));
        std::fs::write(&profile, text).expect("the profile is written");
        Self {
            profile,
            params: params
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.display().to_string()))
                .collect(),
        }
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        for (key, value) in &self.params {
            command.arg("-D").arg(format!("{key}={value}"));
        }
        command.arg("-f").arg(&self.profile).arg(program);
        command
    }
}

/// A daemon on a scratch base, a warmed clone of the binary, a workspace to
/// run from and the resolved paths a profile needs. Everything lives under
/// `/tmp` (short socket paths) and is removed on drop; the daemon is stopped
/// by [`Fixture::stop`].
struct Fixture {
    daemon: Option<TestDaemon>,
    /// Scratch root (`/private/tmp/pam-doctor-…`): the clone, the workspace,
    /// the profiles, the relay directory.
    root: tempfile::TempDir,
    /// The daemon's base, resolved.
    base: PathBuf,
    /// The clone of the binary, resolved.
    exe: PathBuf,
    /// The directory the doctor runs from (a repository root).
    workspace: PathBuf,
    /// The user's home, resolved.
    home: PathBuf,
}

impl Fixture {
    async fn start() -> Self {
        let daemon = TestDaemon::spawn().await;
        let base = daemon.base_dir().canonicalize().expect("the base resolves");
        // The daemon started from the binary (`pam daemon`) creates its log
        // directory at start; the in-process one does not. Lay it out as a
        // real base has it, so `log.read` is probed rather than absent.
        std::fs::create_dir_all(base.join("log")).expect("the log directory");
        let root = tempfile::Builder::new()
            .prefix("pam-doctor-")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp");
        let resolved = root.path().canonicalize().expect("the root resolves");
        let exe = resolved.join("pam");
        std::fs::copy(env!("CARGO_BIN_EXE_pam"), &exe).expect("the binary clones");
        let workspace = resolved.join("ws");
        std::fs::create_dir_all(workspace.join(".git")).expect("the workspace");
        let home = std::env::home_dir()
            .expect("a home")
            .canonicalize()
            .expect("the home resolves");
        let fixture = Self {
            daemon: Some(daemon),
            root,
            base,
            exe,
            workspace,
            home,
        };
        // Warm exec outside any timing: macOS assesses a new binary once.
        let warm = fixture.run(None, &[], &["--version"]).await;
        assert_eq!(warm.code, 0, "the clone runs: {}", warm.stderr);
        fixture
    }

    fn scratch(&self) -> PathBuf {
        self.root.path().canonicalize().expect("the root resolves")
    }

    /// Runs the clone (under `sandbox` when given) with `PAM_BASE_DIR` set
    /// to the base, from the workspace, off the runtime thread: the daemon
    /// serving the request runs in this process.
    async fn run(&self, sandbox: Option<&Sandbox>, env: &[(&str, &Path)], args: &[&str]) -> CliRun {
        let mut command = match sandbox {
            Some(sandbox) => sandbox.command(&self.exe),
            None => Command::new(&self.exe),
        };
        command
            .args(args)
            .env("PAM_BASE_DIR", &self.base)
            .env_remove("PAM_SOCKET_DIR")
            .current_dir(&self.workspace)
            .stdin(Stdio::null());
        for (key, value) in env {
            command.env(key, value);
        }
        tokio::task::spawn_blocking(move || finish(&command.output().expect("the pam binary runs")))
            .await
            .expect("the pam exec joins")
    }

    /// The daemon's `boundary` status block, through `pam status --json`
    /// (unsandboxed).
    async fn boundary_block(&self) -> serde_json::Value {
        let status = self.run(None, &[], &["status", "--json"]).await;
        assert_eq!(status.code, 0, "{}", status.stderr);
        let response = status.document();
        assert_eq!(response["kind"], "result", "{response}");
        let block = response["body"]["boundary"].clone();
        assert!(
            block.is_object(),
            "status carries the boundary block: {response}"
        );
        block
    }

    /// `pam-agent.sb` rendered for this base, with the parameters its
    /// preamble names.
    fn pam_agent(&self) -> Sandbox {
        let text = profiles::render(Harness::SandboxExec, &self.base).expect("renders");
        Sandbox::write(
            &self.scratch(),
            "pam-agent",
            &text,
            &[
                ("HOME", self.home.as_path()),
                ("WORKSPACE", self.workspace.as_path()),
                ("PAM_EXE", self.exe.as_path()),
            ],
        )
    }

    /// The Gemini CLI profile rendered for this base, with the `-D` names
    /// Gemini's launcher passes (`TMP_DIR` and `CACHE_DIR` are scratch
    /// directories that hold nothing the probes touch).
    fn gemini(&self) -> Sandbox {
        let text = profiles::render(Harness::GeminiCli, &self.base).expect("renders");
        let scratch = self.scratch();
        let tmp = scratch.join("gemini-tmp");
        let cache = scratch.join("gemini-cache");
        std::fs::create_dir_all(&tmp).expect("tmp");
        std::fs::create_dir_all(&cache).expect("cache");
        let dev_null = Path::new("/dev/null");
        Sandbox::write(
            &scratch,
            "gemini",
            &text,
            &[
                ("TARGET_DIR", self.workspace.as_path()),
                ("TMP_DIR", tmp.as_path()),
                ("HOME_DIR", self.home.as_path()),
                ("CACHE_DIR", cache.as_path()),
                ("INCLUDE_DIR_0", dev_null),
                ("INCLUDE_DIR_1", dev_null),
                ("INCLUDE_DIR_2", dev_null),
                ("INCLUDE_DIR_3", dev_null),
                ("INCLUDE_DIR_4", dev_null),
            ],
        )
    }

    /// The broker-isolation fixture profile of `sandbox_macos.rs`, with its
    /// placeholders substituted.
    fn broker_fixture(&self) -> Sandbox {
        let scratch = self.scratch();
        let asset = scratch.join("trusted-asset");
        std::fs::write(&asset, b"trusted fixture asset").expect("the asset");
        let text = include_str!("support/broker-macos.sb")
            .replace("@BASE@", &self.base.display().to_string())
            .replace("@ASSET@", &asset.display().to_string())
            .replace("@HOME@", &self.home.display().to_string());
        Sandbox::write(&scratch, "broker-macos", &text, &[])
    }

    async fn stop(mut self) {
        if let Some(daemon) = self.daemon.take() {
            daemon.stop().await;
        }
    }
}

/// Every must-deny row of `report` is `denied` or `absent`, the absent ones
/// are exactly those whose target does not exist on `base` (plus the bundle
/// probe, outside a `.app`) and the never-probed `public.unlink`, and the
/// public reach is `allowed`.
fn assert_established_rows(report: &serde_json::Value, base: &Path) {
    let rows: BTreeMap<String, &serde_json::Value> = report["probes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| (row["id"].as_str().expect("id").to_owned(), row))
        .collect();
    assert_eq!(rows["public.reach"]["result"], "allowed", "{report}");
    let reachable = names(&reachable_unsandboxed(base));
    for id in must_deny_on_macos() {
        let row = rows[&id.to_string()];
        let result = row["result"].as_str().expect("result");
        let expected = match id {
            ProbeId::PublicUnlink => "not_probed",
            _ if reachable.contains(&id.to_string()) => "denied",
            _ => "absent",
        };
        assert_eq!(result, expected, "{id}: {row}");
    }
}

/// The helper evidence the rows carry under a profile that denies the
/// keychain, signals and both brokers: the strings captured on this OS
/// (macOS 26, Darwin 27.0.0, 2026-10-02), as `doctor::classify` folds them.
fn assert_denied_helper_evidence(report: &serde_json::Value) {
    let rows: BTreeMap<String, &serde_json::Value> = report["probes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| (row["id"].as_str().expect("id").to_owned(), row))
        .collect();
    let keychain = rows["keychain.search"];
    assert_eq!(
        keychain["os_error"]["kind"], "KeychainSearchDenied",
        "{keychain}"
    );
    assert_eq!(
        keychain["os_error"]["detail"],
        "security: SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid.",
        "{keychain}"
    );
    let signal = rows["daemon.signal"];
    assert_eq!(signal["os_error"]["kind"], "PermissionDenied", "{signal}");
    assert!(
        signal["os_error"]["detail"]
            .as_str()
            .is_some_and(|detail| detail.starts_with("kill: ")
                && detail.ends_with(": Operation not permitted")),
        "{signal}"
    );
    let launchservices = rows["broker.launchservices"];
    assert_eq!(
        launchservices["os_error"]["kind"], "LaunchServicesUnreachable",
        "{launchservices}"
    );
    assert_eq!(
        launchservices["os_error"]["detail"],
        "lsappinfo answered nothing for com.apple.loginwindow",
        "{launchservices}"
    );
    let appleevents = rows["broker.appleevents"];
    assert_eq!(
        appleevents["os_error"]["kind"], "AppleEventsUnreachable",
        "{appleevents}"
    );
    assert_eq!(
        appleevents["os_error"]["detail"],
        "osascript: connection invalid for com.apple.hiservices-xpcservice",
        "{appleevents}"
    );
    let exe = rows["exe.write"];
    assert_eq!(exe["note"], "access(W_OK) refused", "{exe}");
    assert_eq!(exe["os_error"]["kind"], "PermissionDenied", "{exe}");
}

/// Item 1: under `pam-agent.sb` the verdict is `established`, exit `0`;
/// every must-deny probe is denied or absent, the reach allowed, the daemon
/// accepts the report, `pam status` shows it, and no admin contact was ever
/// observed (the sandbox refuses the connect before it reaches the socket).
/// The probed files are untouched: socket and lock inodes, lock bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_pam_agent_sb_the_boundary_is_established_and_recorded() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start().await;
        let base = fixture.base.clone();
        let socket = base.join("run/pam.sock");
        let lock = base.join(RUN_DIR).join(LOCK_FILE);
        let socket_inode = std::fs::symlink_metadata(&socket).unwrap().ino();
        let lock_inode = std::fs::symlink_metadata(&lock).unwrap().ino();
        let lock_bytes = std::fs::read(&lock).unwrap();
        let before = fixture.boundary_block().await;
        assert!(before["last_report"].is_null(), "{before}");

        let sandbox = fixture.pam_agent();
        let run = fixture
            .run(Some(&sandbox), &[], &["doctor", "--json"])
            .await;
        assert_eq!(
            run.code, 0,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
        let report = run.document();
        assert_eq!(report["verdict"], "established", "{report}");
        assert_eq!(report["failed"], serde_json::json!([]), "{report}");
        assert_eq!(report["unverified"], serde_json::json!([]), "{report}");
        assert_eq!(report["daemon"]["via"], "direct", "{report}");
        assert_eq!(report["env"]["resolved_base"], base.display().to_string());
        assert!(report["env"]["socket_dir"].is_null(), "{report}");
        assert_established_rows(&report, &base);
        assert_denied_helper_evidence(&report);
        // The lock stays readable (the readiness probe lazy start needs).
        let lock_row = report["probes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "run.lock_probe")
            .unwrap()
            .clone();
        assert_eq!(lock_row["result"], "allowed", "{lock_row}");
        assert_eq!(lock_row["note"], "held: a daemon is running", "{lock_row}");

        // Recorded by the daemon, which saw the sandboxed clone directly.
        assert_eq!(report["report"]["recorded"], true, "{report}");
        let request_id = report["report"]["request_id"]
            .as_str()
            .expect("the record names the request")
            .to_owned();
        assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");
        assert_eq!(report["daemon_reply"]["verdict"], "established", "{report}");
        assert_eq!(report["daemon_reply"]["request_id"], request_id, "{report}");
        assert_eq!(report["daemon_reply"]["peer"]["relayed"], false, "{report}");
        assert_eq!(
            report["daemon_reply"]["peer"]["exe"],
            fixture.exe.display().to_string(),
            "{report}"
        );
        assert_eq!(
            report["daemon_reply"]["attributed_admin_contacts"], 0,
            "{report}"
        );

        let block = fixture.boundary_block().await;
        assert_eq!(block["last_report"]["verdict"], "established", "{block}");
        assert_eq!(block["last_report"]["request_id"], request_id, "{block}");
        assert_eq!(block["last_report"]["relayed"], false, "{block}");
        assert_eq!(block["reports"]["established"], 1, "{block}");
        assert_eq!(block["admin_contacts"]["unattributed_24h"], 0, "{block}");
        assert_eq!(block["admin_contacts"]["unattributed"], 0, "{block}");
        // The connect never reached the socket: nothing to attribute.
        assert_eq!(block["admin_contacts"]["total"], 0, "{block}");
        assert!(
            block["summary"]
                .as_str()
                .is_some_and(|summary| summary.starts_with("established ")),
            "{block}"
        );

        assert_eq!(
            std::fs::symlink_metadata(&socket).unwrap().ino(),
            socket_inode
        );
        assert_eq!(std::fs::symlink_metadata(&lock).unwrap().ino(), lock_inode);
        assert_eq!(std::fs::read(&lock).unwrap(), lock_bytes);
        fixture.stop().await;
    })
    .await
    .expect("test within deadline");
}

/// Item 2: the same clone without `sandbox-exec` exits `6`,
/// `not_established`, and `failed` is exactly the set of must-deny probes an
/// unsandboxed same-user process can do on this base. Its admin connects
/// reach the daemon; the 150 ms hold lets the accept loop read the pid, so
/// the contact is attributed to this report and `pam status` counts nothing
/// as unexpected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsandboxed_is_not_established_and_its_admin_contact_is_attributed() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start().await;
        let base = fixture.base.clone();
        let run = fixture.run(None, &[], &["doctor", "--json"]).await;
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
        let report = run.document();
        assert_eq!(report["verdict"], "not_established", "{report}");
        assert_eq!(report["daemon"]["via"], "direct", "{report}");
        let expected = names(&reachable_unsandboxed(&base));
        assert_eq!(id_list(&report["failed"]), expected, "{report}");
        assert_eq!(report["unverified"], serde_json::json!([]), "{report}");
        for id in [
            "run.lock_write",
            "admin.endpoint",
            "admin.endpoint_alias",
            "admin.dir",
            "store.read",
            "store.write",
            "log.read",
            "keychain.search",
            "daemon.signal",
            "broker.launchservices",
            "broker.appleevents",
            "exe.write",
        ] {
            assert!(
                expected.iter().any(|name| name == id),
                "{id} is reachable unsandboxed"
            );
        }
        // The chain is walked outside a sandbox (`/bin/ps` runs here).
        assert!(
            report["env"]["harness_chain"]
                .as_array()
                .is_some_and(|chain| !chain.is_empty()),
            "{report}"
        );

        assert_eq!(report["report"]["recorded"], true, "{report}");
        let request_id = report["report"]["request_id"]
            .as_str()
            .expect("the record names the request")
            .to_owned();
        assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");
        assert_eq!(
            report["daemon_reply"]["verdict"], "not_established",
            "{report}"
        );
        let peer_pid = report["daemon_reply"]["peer"]["pid"]
            .as_u64()
            .expect("the daemon saw the pid");
        assert!(
            report["daemon_reply"]["attributed_admin_contacts"]
                .as_u64()
                .is_some_and(|count| count >= 1),
            "the admin connect was attributed to this report: {report}"
        );

        let block = fixture.boundary_block().await;
        assert_eq!(
            block["last_report"]["verdict"], "not_established",
            "{block}"
        );
        assert_eq!(block["last_report"]["request_id"], request_id, "{block}");
        assert_eq!(block["last_report"]["peer_pid"], peer_pid, "{block}");
        assert_eq!(
            id_list(&block["last_report"]["failed"]),
            expected,
            "{block}"
        );
        assert_eq!(block["admin_contacts"]["unattributed_24h"], 0, "{block}");
        assert_eq!(block["admin_contacts"]["unattributed"], 0, "{block}");
        assert!(
            block["admin_contacts"]["total"]
                .as_u64()
                .is_some_and(|total| total >= 1),
            "the connect was observed: {block}"
        );
        let last = &block["admin_contacts"]["last"];
        assert_eq!(last["kind"], "admin_contact", "{block}");
        assert_eq!(last["peer_pid"], peer_pid, "{block}");
        assert_eq!(last["attributed"], request_id, "{block}");
        assert_eq!(
            last["peer_exe"],
            fixture.exe.display().to_string(),
            "{block}"
        );
        fixture.stop().await;
    })
    .await
    .expect("test within deadline");
}

/// What one harness profile yielded under `sandbox-exec`, or why it was not
/// run.
#[derive(Debug, PartialEq, Eq)]
enum ProfileOutcome {
    /// The verdict and the `failed` list the doctor printed under the
    /// rendered profile.
    Ran {
        verdict: String,
        failed: Vec<String>,
    },
    /// The harness consumes the format itself (JSON settings, TOML, a
    /// dialog guide): the rendered text was checked for syntax only.
    SyntaxOnly,
}

/// Item 3: every profile `Harness` renders. The two Seatbelt files run the
/// doctor under `sandbox-exec` with their harness's `-D` names and are
/// `established`; the JSON, TOML and Markdown ones are consumed by their
/// harness and are checked for syntax here (the harness's enforcement is
/// what a `pam doctor` from inside it proves). The table of outcomes is
/// recorded in `docs/sandbox/README.md`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_harness_profile_yields_its_recorded_verdict() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start().await;
        let base = fixture.base.clone();
        let mut outcomes = Vec::new();
        for harness in Harness::ALL {
            let profile = harness.profile();
            let text = profiles::render(harness, &base).expect("renders");
            assert!(
                text.contains(&format!("{}/run/pam.sock", base.display())),
                "{harness} allows the public socket"
            );
            let outcome = match profile.format {
                Format::Sbpl => {
                    let sandbox = match harness {
                        Harness::GeminiCli => fixture.gemini(),
                        Harness::SandboxExec => fixture.pam_agent(),
                        other => panic!("no -D parameters known for {other}"),
                    };
                    let run = fixture
                        .run(Some(&sandbox), &[], &["doctor", "--json"])
                        .await;
                    assert!(run.stderr.is_empty(), "{harness}: {}", run.stderr);
                    let report = run.document();
                    assert_eq!(
                        report["daemon_reply"]["accepted"], true,
                        "{harness}: {report}"
                    );
                    if run.code == 0 {
                        assert_established_rows(&report, &base);
                        assert_denied_helper_evidence(&report);
                    }
                    ProfileOutcome::Ran {
                        verdict: report["verdict"].as_str().unwrap_or("?").to_owned(),
                        failed: id_list(&report["failed"]),
                    }
                }
                Format::Json => {
                    let fragment: serde_json::Value = serde_json::from_str(&text)
                        .unwrap_or_else(|error| panic!("{harness} renders JSON ({error}): {text}"));
                    assert!(
                        fragment["sandbox"]["enabled"].as_bool() == Some(true),
                        "{fragment}"
                    );
                    let managed = profiles::render_variant(harness, Variant::Managed, &base)
                        .expect("the managed variant renders");
                    let managed: serde_json::Value =
                        serde_json::from_str(&managed).expect("the managed variant is JSON");
                    assert!(managed.is_object(), "{managed}");
                    ProfileOutcome::SyntaxOnly
                }
                Format::Toml | Format::Markdown => {
                    assert!(
                        !text.contains(profiles::BASE_PLACEHOLDER),
                        "{harness} substitutes every placeholder"
                    );
                    ProfileOutcome::SyntaxOnly
                }
            };
            outcomes.push((harness, outcome));
        }
        let established = |verdict: &str| ProfileOutcome::Ran {
            verdict: verdict.to_owned(),
            failed: Vec::new(),
        };
        let expected = vec![
            (Harness::ClaudeCode, ProfileOutcome::SyntaxOnly),
            (Harness::Codex, ProfileOutcome::SyntaxOnly),
            (Harness::GeminiCli, established("established")),
            (Harness::CopilotCli, ProfileOutcome::SyntaxOnly),
            (Harness::SandboxExec, established("established")),
        ];
        assert_eq!(outcomes, expected, "the per-profile table changed");
        fixture.stop().await;
    })
    .await
    .expect("test within deadline");
}

/// The broker-isolation fixture of `sandbox_macos.rs` is not a boundary
/// profile: it allows `file-read*` broadly and denies only the admin
/// directory, the store files and the keychain by name, so the daemon's
/// `log` directory (which a real daemon creates) stays listable under it.
/// The doctor says so: `not_established` on exactly the list-dir probes
/// whose directories exist on the base and the fixture does not name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_fixture_profile_leaves_the_log_directory_listable() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start().await;
        let base = fixture.base.clone();
        let sandbox = fixture.broker_fixture();
        let run = fixture
            .run(Some(&sandbox), &[], &["doctor", "--json"])
            .await;
        let report = run.document();
        // The fixture names the admin directory; every other directory it
        // leaves to its broad read allowance.
        let expected: Vec<String> = directory_probes(&base)
            .into_iter()
            .filter(|(id, path)| *id != ProbeId::AdminDir && path.exists())
            .map(|(id, _)| id.to_string())
            .collect();
        assert!(
            expected.iter().any(|id| id == "log.read"),
            "the fixture base has a log directory"
        );
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert_eq!(report["verdict"], "not_established", "{report}");
        assert_eq!(id_list(&report["failed"]), expected, "{report}");
        assert_eq!(report["unverified"], serde_json::json!([]), "{report}");
        assert_denied_helper_evidence(&report);
        assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");
        fixture.stop().await;
    })
    .await
    .expect("test within deadline");
}

/// A running `pam listen <dir>` of the clone, outside any sandbox. Killed
/// and reaped on the way out, panic included.
struct Relay {
    child: Child,
    output: PathBuf,
}

impl Relay {
    /// Starts the relay and returns once it has printed its last startup
    /// line: by then it has bound its socket and is accepting.
    fn start(exe: &Path, base: &Path, session: &Path, output: PathBuf) -> Self {
        let log = std::fs::File::create(&output).expect("the relay's output file");
        let child = Command::new(exe)
            .arg("listen")
            .arg(session)
            .env("PAM_BASE_DIR", base)
            .env_remove("PAM_SOCKET_DIR")
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("a second handle"))
            .stderr(log)
            .spawn()
            .expect("pam listen starts");
        let mut relay = Self { child, output };
        let deadline = Instant::now() + RELAY_START;
        loop {
            let printed = relay.printed();
            if printed.contains("stop with ctrl-c") {
                return relay;
            }
            let ended = relay.child.try_wait().expect("the relay is waitable");
            assert!(
                ended.is_none(),
                "pam listen ended at startup ({ended:?}): {printed}"
            );
            assert!(
                Instant::now() < deadline,
                "pam listen never finished starting: {printed}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn printed(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_default()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Ctrl-c by pid, then a bounded wait; `Drop` kills what is left.
    fn interrupt(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-INT", &self.pid().to_string()])
            .status();
        let deadline = Instant::now() + RELAY_START;
        while Instant::now() < deadline {
            if self
                .child
                .try_wait()
                .expect("the relay is waitable")
                .is_some()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `pam-agent.sb` rewritten for the session relay the way its own comment
/// says: the two PAM-block lines that allow `<base>/run/pam.sock` and the
/// read of `<base>/run/daemon.lock` are replaced by one allow of
/// `<dir>/pam.sock`, every deny kept. With `keep_lock_read` the lock line
/// stays (the variant the finding below suggests).
fn relay_variant(profile: &str, session: &Path, keep_lock_read: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(profile.len() + 128);
    for line in profile.lines() {
        let allows_socket =
            line.starts_with("(allow network-outbound") && line.contains("/run/pam.sock");
        let allows_lock =
            line.starts_with("(allow file-read-data") && line.contains("/run/daemon.lock");
        if allows_socket || (allows_lock && !keep_lock_read) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    let _ = writeln!(
        out,
        "(allow network-outbound (remote unix-socket (literal \"{}/pam.sock\")))",
        session.display()
    );
    out
}

/// The report of a sandboxed run through the relay under the documented
/// relay variant: reached via the relay, every private path denied, the
/// lock unreadable and therefore `daemon.signal` unverifiable, recorded by
/// the daemon with the relay (`relay_pid`) as its peer.
fn assert_relayed_without_lock_read(
    report: &serde_json::Value,
    session: &Path,
    base: &Path,
    relay_pid: u32,
) {
    assert_eq!(report["verdict"], "not_established", "{report}");
    assert_eq!(report["daemon"]["via"], "relay", "{report}");
    assert_eq!(
        report["env"]["socket_dir"],
        session.display().to_string(),
        "{report}"
    );
    assert_eq!(
        report["env"]["resolved_endpoint"],
        session.join("pam.sock").display().to_string(),
        "{report}"
    );
    assert_eq!(
        report["env"]["resolved_base"],
        base.display().to_string(),
        "{report}"
    );
    assert_eq!(report["failed"], serde_json::json!([]), "{report}");
    assert_eq!(
        id_list(&report["unverified"]),
        ["daemon.signal"],
        "{report}"
    );
    let rows: BTreeMap<String, &serde_json::Value> = report["probes"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| (row["id"].as_str().expect("id").to_owned(), row))
        .collect();
    assert_eq!(rows["public.reach"]["result"], "allowed", "{report}");
    for id in [
        "admin.endpoint",
        "admin.endpoint_alias",
        "admin.dir",
        "store.read",
        "store.write",
        "log.read",
    ] {
        assert_eq!(rows[id]["result"], "denied", "{id}: {report}");
    }
    assert_eq!(rows["run.lock_probe"]["result"], "denied", "{report}");
    assert_eq!(
        rows["run.lock_probe"]["note"], "unreadable under the relay; lazy start is not needed here",
        "{report}"
    );
    assert_eq!(rows["daemon.signal"]["result"], "unknown", "{report}");
    assert_eq!(
        rows["daemon.signal"]["note"], "lock file unreadable: no pid to probe",
        "{report}"
    );
    assert_eq!(report["report"]["recorded"], true, "{report}");
    assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");
    assert_eq!(report["daemon_reply"]["peer"]["relayed"], true, "{report}");
    assert_eq!(
        report["daemon_reply"]["peer"]["harness"], "relay",
        "{report}"
    );
    assert_eq!(
        report["daemon_reply"]["peer"]["pid"],
        u64::from(relay_pid),
        "the daemon's peer is the relay: {report}"
    );
}

/// Item 4: through `pam listen` (outside the sandbox) with `PAM_SOCKET_DIR`
/// set, the sandboxed clone reaches the daemon (`via: relay`), the admin
/// probes stay denied and the daemon records the report with the relay as
/// its peer. With the profile's documented relay variant — nothing under
/// `<base>` readable at all — the daemon's pid in `run/daemon.lock` cannot
/// be read, so `daemon.signal` is `unknown`, and an unknown fails the
/// verdict: `not_established` with `failed` empty and `unverified` exactly
/// `[daemon.signal]` (observed 2026-10-02; recorded in `cross-T7.md`). The
/// same profile with the lock-read line kept is `established`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn through_the_relay_the_verdict_is_computed_and_the_lock_decides_daemon_signal() {
    timeout(DEADLINE, async {
        let fixture = Fixture::start().await;
        let base = fixture.base.clone();
        let scratch = fixture.scratch();
        let session = scratch.join("sess");
        let relay = {
            let (exe, base, session, output) = (
                fixture.exe.clone(),
                base.clone(),
                session.clone(),
                scratch.join("relay.log"),
            );
            tokio::task::spawn_blocking(move || Relay::start(&exe, &base, &session, output))
                .await
                .expect("joins")
        };
        let agent = profiles::render(Harness::SandboxExec, &base).expect("renders");
        let params: [(&str, &Path); 3] = [
            ("HOME", fixture.home.as_path()),
            ("WORKSPACE", fixture.workspace.as_path()),
            ("PAM_EXE", fixture.exe.as_path()),
        ];
        let documented = Sandbox::write(
            &scratch,
            "relay-documented",
            &relay_variant(&agent, &session, false),
            &params,
        );
        let with_lock = Sandbox::write(
            &scratch,
            "relay-with-lock-read",
            &relay_variant(&agent, &session, true),
            &params,
        );
        let env: [(&str, &Path); 1] = [("PAM_SOCKET_DIR", session.as_path())];

        let run = fixture
            .run(Some(&documented), &env, &["doctor", "--json"])
            .await;
        assert_eq!(
            run.code, 6,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert_relayed_without_lock_read(&run.document(), &session, &base, relay.pid());

        // The lock-read line kept: the pid is readable, the signal is
        // refused, and the boundary is established through the relay.
        let run = fixture
            .run(Some(&with_lock), &env, &["doctor", "--json"])
            .await;
        assert_eq!(
            run.code, 0,
            "stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        let report = run.document();
        assert_eq!(report["verdict"], "established", "{report}");
        assert_eq!(report["daemon"]["via"], "relay", "{report}");
        assert_established_rows(&report, &base);
        assert_denied_helper_evidence(&report);
        assert_eq!(report["daemon_reply"]["accepted"], true, "{report}");

        let block = fixture.boundary_block().await;
        assert_eq!(block["last_report"]["verdict"], "established", "{block}");
        assert_eq!(block["last_report"]["relayed"], true, "{block}");
        assert_eq!(block["reports"]["retained"], 2, "{block}");
        assert_eq!(block["admin_contacts"]["total"], 0, "{block}");
        assert_eq!(block["admin_contacts"]["unattributed_24h"], 0, "{block}");

        let mut relay = relay;
        tokio::task::spawn_blocking(move || {
            relay.interrupt();
            drop(relay);
        })
        .await
        .expect("joins");
        assert!(
            !session.join("pam.sock").exists(),
            "the relay removed its socket"
        );
        fixture.stop().await;
    })
    .await
    .expect("test within deadline");
}

/// `pam-agent.sb` rendered for a scratch base, with a scratch script as
/// `PAM_EXE`, to run the engine's helper commands under it the way the
/// engine does (absolute program, cleared environment plus `HOME`, null
/// stdin). No daemon: the helpers do not need one.
struct Helpers {
    _root: tempfile::TempDir,
    sandbox: Sandbox,
    exe: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

impl Helpers {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("pam-doctor-helpers-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        let scratch = root.path().canonicalize().unwrap();
        let base = scratch.join("pam");
        let exe = scratch.join("pam-exe");
        std::fs::write(&exe, b"#!/bin/sh\nexit 0\n").unwrap();
        let workspace = scratch.join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        let home = std::env::home_dir().unwrap().canonicalize().unwrap();
        let text = profiles::render(Harness::SandboxExec, &base).expect("renders");
        let sandbox = Sandbox::write(
            &scratch,
            "pam-agent",
            &text,
            &[
                ("HOME", home.as_path()),
                ("WORKSPACE", workspace.as_path()),
                ("PAM_EXE", exe.as_path()),
            ],
        );
        Self {
            _root: root,
            sandbox,
            exe,
            workspace,
            home,
        }
    }

    fn run(&self, sandboxed: bool, program: &str, args: &[&str]) -> CliRun {
        let mut command = if sandboxed {
            self.sandbox.command(Path::new(program))
        } else {
            Command::new(program)
        };
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .stdin(Stdio::null())
            .current_dir(&self.workspace);
        finish(&command.output().expect("the helper runs"))
    }
}

/// The helper lines the classifiers pin, captured again under
/// `sandbox-exec` with `pam-agent.sb` (macOS 26, Darwin 27.0.0, 2026-10-02):
/// the keychain search fails at initialisation, `kill -0` is refused,
/// `test -w` on the executable exits 1 and `/bin/ps` cannot even exec.
/// Outside the profile the keychain search is an ordinary not-found and the
/// signal is permitted.
#[test]
fn keychain_signal_access_and_ps_helpers_under_pam_agent_sb_match_the_pinned_strings() {
    let helpers = Helpers::new();
    let parent = std::process::id().to_string();

    let absent = format!("pam.doctor.absent.{parent}.t7");
    let security = [
        "find-generic-password",
        "-s",
        "dev.pam.connector",
        "-a",
        &absent,
    ];
    let outside = helpers.run(false, "/usr/bin/security", &security);
    assert_eq!(outside.code, 44, "{}", outside.stderr);
    assert!(
        outside.stderr.starts_with(
            "security: SecKeychainSearchCopyNext: The specified item could not be found"
        ),
        "{}",
        outside.stderr
    );
    let inside = helpers.run(true, "/usr/bin/security", &security);
    assert_eq!(inside.code, 44, "{}", inside.stderr);
    assert!(
        inside.stderr.starts_with(
            "security: SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid."
        ),
        "{}",
        inside.stderr
    );

    let outside = helpers.run(false, "/bin/kill", &["-0", &parent]);
    assert_eq!(outside.code, 0, "{}", outside.stderr);
    let inside = helpers.run(true, "/bin/kill", &["-0", &parent]);
    assert_eq!(inside.code, 1, "{}", inside.stderr);
    assert_eq!(
        inside.stderr.trim(),
        format!("kill: {parent}: Operation not permitted")
    );

    let exe = helpers.exe.display().to_string();
    let outside = helpers.run(false, "/bin/test", &["-w", &exe]);
    assert_eq!(outside.code, 0);
    let inside = helpers.run(true, "/bin/test", &["-w", &exe]);
    assert_eq!(inside.code, 1);
    let inside = helpers.run(true, "/bin/test", &["-e", &exe]);
    assert_eq!(
        inside.code, 0,
        "the executable exists, it is only unwritable"
    );

    let inside = helpers.run(true, "/bin/ps", &["-o", "ppid=,comm=", "-p", &parent]);
    assert_ne!(inside.code, 0, "{}", inside.stdout);
    assert!(
        inside
            .stderr
            .contains("execvp() of '/bin/ps' failed: Operation not permitted"),
        "{}",
        inside.stderr
    );
}

/// The two broker helpers under `pam-agent.sb` (same capture): `lsappinfo`
/// answers nothing and `osascript` cannot reach
/// `com.apple.hiservices-xpcservice`. Their readings outside a sandbox are
/// not asserted: they need a GUI login session, which a runner may lack.
#[test]
fn broker_helpers_under_pam_agent_sb_match_the_pinned_strings() {
    let helpers = Helpers::new();

    let inside = helpers.run(
        true,
        "/usr/bin/lsappinfo",
        &["find", "bundleid=com.apple.loginwindow"],
    );
    assert_eq!(inside.code, 0, "{}", inside.stderr);
    assert!(inside.stdout.trim().is_empty(), "{}", inside.stdout);
    assert!(inside.stderr.trim().is_empty(), "{}", inside.stderr);

    let inside = helpers.run(
        true,
        "/usr/bin/osascript",
        &["-e", "id of application \"Finder\""],
    );
    assert_eq!(inside.code, 1, "{}", inside.stderr);
    assert!(inside.stdout.is_empty(), "{}", inside.stdout);
    assert!(
        inside
            .stderr
            .contains("Connection Invalid error for service com.apple.hiservices-xpcservice."),
        "{}",
        inside.stderr
    );
    assert!(inside.stderr.contains("(-1728)"), "{}", inside.stderr);
}
