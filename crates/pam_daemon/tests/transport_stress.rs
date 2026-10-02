//! Churn on the framed public transport and the admin all-events stream.
//!
//! Two scenarios over the same workload, which mixes polling with every way a
//! client can walk away: unary requests abandoned after they were written,
//! followers dropped mid-follow, and all-events subscribers dropped or never
//! read.
//!
//! - `abandoned_followers_and_subscribers_return_every_resource_to_baseline`
//!   runs in the ordinary test run against an in-process daemon, where the hub
//!   and the listener's permits can be read: follower and subscriber counts,
//!   hub entries and free public connections come back to baseline, the
//!   process's descriptors do not grow, and the daemon keeps answering.
//! - `churn_cross_process` (opt-in, two minutes) is the isolated cross-process
//!   investigation for ptrack #102 / issue #4: a compiled `pam daemon`, the real
//!   CLI follow, and the daemon's descriptor count read from outside. This is
//!   workload evidence, not a proof that a historical 25-minute stall is fixed.
//!   Run the compiled test directly, with no concurrent Cargo build.

use std::path::Path;

use pam_daemon::admin_transport;
use pam_daemon::framed::{self, DialError, PublicStream};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{Frame, MAX_FRAME_BYTES, Via, cause};
use pam_proto::{Envelope, Response};
use serde_json::json;

/// The two scenarios read process-wide descriptor counts: they never overlap.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One unary exchange on the public socket, as the CLI makes it.
async fn call(base: &Path, envelope: &Envelope) -> Result<Response, String> {
    let dirs = RuntimeDir::paths_at_base(base).map_err(|error| format!("paths: {error}"))?;
    let mut stream = framed::connect_public(&dirs)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    framed::call(
        &mut stream,
        &framed::client_hello(Via::Direct),
        envelope,
        MAX_FRAME_BYTES,
    )
    .await
    .map(|(_, response)| response)
    .map_err(|error| format!("call: {error}"))
}

/// A unary request written to the daemon and then abandoned: the connection
/// is dropped before the reply is read.
async fn abandon_call(base: &Path, envelope: &Envelope) -> Result<(), String> {
    let dirs = RuntimeDir::paths_at_base(base).map_err(|error| format!("paths: {error}"))?;
    let mut stream = framed::connect_public(&dirs)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    framed::open(
        &mut stream,
        &framed::client_hello(Via::Direct),
        &Frame::Request {
            envelope: envelope.clone(),
        },
    )
    .await
    .map(|_| ())
    .map_err(|error| format!("open: {error}"))
}

/// A follow of `ticket`, read as far as `following` (the daemon holds a
/// follower slot for it) and handed back still open. `repo` is the approved
/// repository the ticket was admitted under.
async fn open_follow(
    base: &Path,
    repo: &str,
    id: &str,
    ticket: &str,
) -> Result<PublicStream, String> {
    let dirs = RuntimeDir::paths_at_base(base).map_err(|error| format!("paths: {error}"))?;
    let mut stream = framed::connect_public(&dirs)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    let mut query =
        pam_testkit::envelope_for_repo(repo, id, "query", json!({ "ticket": ticket }), true);
    query.deadline_ms = 15_000;
    framed::follow(
        &mut stream,
        &framed::client_hello(Via::Direct),
        &query,
        0,
        None,
    )
    .await
    .map_err(|error| format!("follow: {error}"))?;
    match framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES).await {
        Ok(Frame::Following(_)) => Ok(stream),
        other => Err(format!("expected following, got {other:?}")),
    }
}

/// Whether the daemon refused an all-events subscriber for want of a slot.
fn capacity_refusal(result: &Result<admin_transport::AdminEvents, DialError>) -> bool {
    matches!(result, Err(DialError::Refused(error))
        if error.cause == cause::SUBSCRIBER_CAPACITY_EXHAUSTED)
}

mod in_process {
    use std::path::Path;
    use std::time::Duration;

    use pam_daemon::admin_transport;
    use pam_daemon::event_hub::MAX_SUBSCRIBERS;
    use pam_daemon::framed::MAX_PUBLIC_CONNECTIONS;
    use pam_proto::Response;
    use pam_testkit::{
        TestClient, TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope,
        short_tempdir, with_deadline,
    };

    use super::{SERIAL, abandon_call, call, capacity_refusal, open_follow};

    const ROUNDS: usize = 20;
    const FOLLOWERS_PER_ROUND: usize = 4;
    /// The descriptors a daemon may hold beyond its baseline once the churn is
    /// over: a lazily opened file is not a leak. One descriptor leaked per
    /// round would be twenty.
    const DESCRIPTOR_SLACK: usize = 3;

    /// Descriptors this process holds, where the platform lists them.
    fn open_descriptors() -> Option<usize> {
        std::fs::read_dir("/dev/fd").ok().map(Iterator::count)
    }

    /// Polls `check` until it holds, panicking legibly when it never does.
    async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !check() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "never returned to baseline: {what}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// One round of the workload: a running ticket whose followers come and go,
    /// an all-events subscriber admitted and one refused, a unary request
    /// abandoned after it was written, and a poll the daemon must answer.
    /// Returns the request ids that must still finish.
    async fn churn_round(
        client: &mut TestClient,
        base: &Path,
        repo: &str,
        round: usize,
    ) -> Vec<String> {
        // A ticket that is still running while its followers come
        // and go.
        let start = envelope_for_repo(
            repo,
            &format!("stress_ticket_{round}"),
            "echo",
            serde_json::json!({ "delay_ms": 60, "tag": round }),
            false,
        );
        let Response::Ticket { ticket, .. } = client.request(&start).await else {
            panic!("an echo with wait=false answers a ticket");
        };

        // Followers dropped mid-follow: attached (the daemon has
        // answered `following`), never read to `end`.
        let mut followers = Vec::new();
        for follower in 0..FOLLOWERS_PER_ROUND {
            let id = format!("stress_follow_{round}_{follower}");
            match open_follow(base, repo, &id, &ticket).await {
                Ok(stream) => followers.push(stream),
                // The ticket finished before this follower attached:
                // there was nothing to abandon.
                Err(reason) if reason.contains("End(") => break,
                Err(reason) => panic!("{id}: {reason}"),
            }
        }

        // The all-events slot beside the held ones: one subscriber
        // is admitted, the next is refused for capacity, both go.
        let subscriber = admin_transport::events(base, true).await;
        assert!(subscriber.is_ok(), "{:?}", subscriber.err());
        assert!(
            capacity_refusal(&admin_transport::events(base, true).await),
            "a fifth all-events subscriber is refused for capacity"
        );
        drop(subscriber);

        // A unary request abandoned after it was written.
        let abandoned = envelope_for_repo(
            repo,
            &format!("stress_abandoned_{round}"),
            "echo",
            serde_json::json!({ "delay_ms": 60, "tag": format!("a{round}") }),
            true,
        );
        abandon_call(base, &abandoned)
            .await
            .expect("the abandoned request is written");

        // The daemon keeps answering throughout.
        let poll = envelope_for_repo(
            repo,
            &format!("stress_status_{round}"),
            "status",
            serde_json::json!({}),
            true,
        );
        let answer = call(base, &poll).await.expect("the daemon answers a poll");
        assert!(matches!(answer, Response::Result { .. }), "{answer:?}");

        drop(followers);
        vec![ticket, format!("stress_abandoned_{round}")]
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn abandoned_followers_and_subscribers_return_every_resource_to_baseline() {
        let _serial = SERIAL.lock().await;
        with_deadline(async {
            let tmp = short_tempdir();
            seed_relaxed(&tmp).await;
            let repo_dir = tempfile::tempdir().expect("a repository directory");
            seed_repository_scope(&tmp, repo_dir.path(), &[]).await;
            let repo = repo_dir
                .path()
                .canonicalize()
                .expect("the repository exists")
                .to_string_lossy()
                .into_owned();
            let daemon = TestDaemon::spawn_at(tmp).await;
            let base = daemon.base_dir();
            let handle = daemon.handle();
            let hub = handle.event_hub();
            let mut client = daemon.client().await;

            // Baseline: one answered request has warmed everything the daemon
            // opens lazily, and its connection is gone.
            let status =
                envelope_for_repo(&repo, "stress_warm", "status", serde_json::json!({}), true);
            assert!(matches!(
                client.request(&status).await,
                Response::Result { .. }
            ));
            eventually("the warm-up connection closes", || {
                handle.public_connections_available() == MAX_PUBLIC_CONNECTIONS
            })
            .await;
            let baseline_descriptors = open_descriptors();
            let baseline = hub.usage();
            assert_eq!((baseline.followers, baseline.subscribers), (0, 0));

            // Subscribers that are attached for the whole run and never read:
            // the churn below happens beside them, on the one free slot.
            let mut held = Vec::new();
            for _ in 0..MAX_SUBSCRIBERS - 1 {
                held.push(
                    admin_transport::events(&base, true)
                        .await
                        .expect("an all-events subscriber attaches"),
                );
            }

            let mut tickets = Vec::new();
            for round in 0..ROUNDS {
                tickets.extend(churn_round(&mut client, &base, &repo, round).await);
            }

            // Abandoning a request never cancels it: every one finishes.
            for ticket in &tickets {
                let row = daemon
                    .wait_for_row(ticket, |row| row.state.is_terminal())
                    .await;
                assert_eq!(
                    row.state,
                    pam_store::RequestState::Done,
                    "{ticket} must finish, not be cancelled by its caller leaving"
                );
            }

            drop(held);
            let store_hub = hub.clone();
            eventually("hub followers, subscribers and entries", move || {
                let usage = store_hub.usage();
                (usage.followers, usage.subscribers, usage.entries) == (0, 0, 0)
            })
            .await;
            eventually("the listener's connection permits", || {
                handle.public_connections_available() == MAX_PUBLIC_CONNECTIONS
            })
            .await;
            if let Some(baseline) = baseline_descriptors {
                eventually("descriptors", || {
                    open_descriptors().is_some_and(|now| now <= baseline + DESCRIPTOR_SLACK)
                })
                .await;
            }

            // After all of it the daemon still serves both planes.
            let final_poll =
                envelope_for_repo(&repo, "stress_final", "status", serde_json::json!({}), true);
            assert!(matches!(
                client.request(&final_poll).await,
                Response::Result { .. }
            ));
            assert!(admin_transport::events(&base, true).await.is_ok());

            daemon.assert_invariant_clean().await;
            daemon.stop().await;
        })
        .await;
    }
}

#[cfg(unix)]
mod cross_process {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
    use pam_daemon::admin_transport::{self, AdminEvents};
    use pam_daemon::framed::{DialError, PublicStream};
    use pam_daemon::policy::PROFILE_SETTING_KEY;
    use pam_proto::wire::cause;
    use pam_proto::{Envelope, Response};
    use pam_store::Store;
    use pam_testkit::{envelope_for_repo, short_tempdir};
    use serde_json::{Value, json};
    use tokio::time::timeout;

    use super::{SERIAL, abandon_call, call, open_follow};

    const LOAD_TIME: Duration = Duration::from_mins(2);
    const LIFECYCLE_WAIT: Duration = Duration::from_secs(15);
    /// All-events subscribers attached for the whole run and never read; the
    /// daemon admits four, so one slot stays free for the churn.
    const HELD_SUBSCRIBERS: usize = 3;
    /// Followers held open on long tickets, never reading (at most 16 per
    /// ticket, so two tickets). The tickets run under their own repository,
    /// so their lane never delays the load's own `echo` requests; an echo may
    /// delay at most a minute, so the first ticket ends, and with it its
    /// followers, about a minute in and the second about a minute later.
    const HELD_FOLLOWERS_PER_TICKET: usize = 12;
    const HELD_TICKETS: usize = 2;
    /// Descriptors the daemon may hold beyond its baseline once every client
    /// is gone.
    const DESCRIPTOR_SLACK: usize = 4;

    struct Harness {
        child: Child,
        held_subscribers: Vec<AdminEvents>,
        held_followers: Vec<PublicStream>,
        held_tickets: Vec<String>,
        base: PathBuf,
        repo: String,
        /// The repository the held tickets run under.
        held_repo: String,
        temp: Option<tempfile::TempDir>,
        sequence: u64,
        successes: u64,
        by_capability: BTreeMap<String, u64>,
        abandoned_requests: u64,
        abandoned_followers: u64,
        subscriber_churn: u64,
        max_exchange_ms: u128,
    }

    impl Harness {
        async fn spawn() -> Self {
            let binary = std::env::var_os("PAM_STRESS_BINARY")
                .expect("PAM_STRESS_BINARY must name the compiled pam binary");
            assert!(
                Path::new(&binary).is_absolute(),
                "binary path must be absolute"
            );
            // Pay macOS executable assessment before the readiness clock starts.
            assert!(
                Command::new(&binary)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            let temp = short_tempdir();
            let base = temp.path().join("pam");
            let store = Store::open(&base.join("state.sqlite3")).await.unwrap();
            store
                .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
                .await
                .unwrap();
            let root = base.canonicalize().unwrap();
            let repo = root.display().to_string();
            let held = temp.path().join("held");
            std::fs::create_dir_all(&held).unwrap();
            let held = held.canonicalize().unwrap();
            let held_repo = held.display().to_string();
            store
                .set_setting(
                    "flows.scope_policy",
                    &json!({
                        "version": 1, "repositories": [
                            {"root": root, "connectors": []},
                            {"root": held, "connectors": []}
                        ]
                    })
                    .to_string(),
                )
                .await
                .unwrap();
            drop(store);
            let child = Command::new(binary)
                .arg("daemon")
                .env("PAM_BASE_DIR", &base)
                .env("PAM_LOG", "warn,pam_daemon=debug")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut harness = Self {
                child,
                held_subscribers: Vec::new(),
                held_followers: Vec::new(),
                held_tickets: Vec::new(),
                base,
                repo,
                held_repo,
                temp: Some(temp),
                sequence: 0,
                successes: 0,
                by_capability: BTreeMap::new(),
                abandoned_requests: 0,
                abandoned_followers: 0,
                subscriber_churn: 0,
                max_exchange_ms: 0,
            };
            let socket = pam_daemon::runtime_dir::RuntimeDir::paths_at_base(&harness.base)
                .expect("runtime paths")
                .public_socket()
                .to_path_buf();
            timeout(LIFECYCLE_WAIT, async {
                while !socket.exists() {
                    assert!(
                        harness.child.try_wait().unwrap().is_none(),
                        "daemon exited before readiness"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("daemon readiness within unchanged15s budget");
            harness.request("status", json!({}), true).await;
            harness
        }

        fn envelope(&mut self, capability: &str, args: Value, wait: bool) -> Envelope {
            self.sequence += 1;
            let mut envelope = envelope_for_repo(
                &self.repo,
                &format!("stress_{}", self.sequence),
                capability,
                args,
                wait,
            );
            envelope.deadline_ms = if capability.starts_with("admin.") {
                30_000
            } else {
                5_000
            };
            if capability.starts_with("admin.") {
                ADMIN_CALLER_AGENT.clone_into(&mut envelope.caller.agent);
                ADMIN_REPO.clone_into(&mut envelope.caller.repo);
            }
            envelope
        }

        async fn request(&mut self, capability: &str, args: Value, wait: bool) -> Response {
            let envelope = self.envelope(capability, args, wait);
            self.exchange_envelope(capability, &envelope).await
        }

        /// One bounded exchange: the private admin channel for `admin.*`, the
        /// framed public socket for everything else. A failure is diagnosed
        /// before it panics.
        async fn exchange_envelope(&mut self, capability: &str, envelope: &Envelope) -> Response {
            let started = Instant::now();
            let limit = Duration::from_millis(envelope.deadline_ms);
            let outcome = if capability.starts_with("admin.") {
                timeout(limit, admin_transport::exchange(&self.base, envelope))
                    .await
                    .map_err(|_| format!("exceeded {}ms", envelope.deadline_ms))
                    .and_then(|result| result.map_err(|error| error.to_string()))
            } else {
                timeout(limit, call(&self.base, envelope))
                    .await
                    .map_err(|_| format!("exceeded {}ms", envelope.deadline_ms))
                    .and_then(|result| result)
            };
            match outcome {
                Ok(response) => {
                    self.successes += 1;
                    *self.by_capability.entry(capability.to_owned()).or_default() += 1;
                    self.max_exchange_ms = self.max_exchange_ms.max(started.elapsed().as_millis());
                    response
                }
                Err(reason) => {
                    let elapsed_ms = started.elapsed().as_millis();
                    self.diagnose_delivery().await;
                    panic!(
                        "{capability} exchange failed after {elapsed_ms}ms; counts={}: {reason}",
                        self.metrics()
                    );
                }
            }
        }

        async fn diagnose_delivery(&mut self) {
            eprintln!(
                "PAM_STRESS_TIMEOUT_RESOURCES {} held_subscribers={} held_followers={}",
                resources(self.child.id()),
                self.held_subscribers.len(),
                self.held_followers.len()
            );
            for capability in ["status", "admin.profile.get"] {
                self.probe(capability, "held").await;
            }
            let removed = self.held_subscribers.len() + self.held_followers.len();
            self.held_subscribers.clear();
            self.held_followers.clear();
            tokio::time::sleep(Duration::from_millis(250)).await;
            eprintln!("PAM_STRESS_AB_REMOVED {removed}");
            for capability in ["status", "admin.profile.get"] {
                self.probe(capability, "removed").await;
            }
        }

        async fn probe(&mut self, capability: &str, peers: &str) {
            let envelope = self.envelope(capability, json!({}), true);
            let started = Instant::now();
            let outcome = if capability.starts_with("admin.") {
                match admin_transport::exchange(&self.base, &envelope).await {
                    Ok(Response::Result { .. }) => "result".to_owned(),
                    Ok(_) => "unexpected response".to_owned(),
                    Err(reason) => reason.to_string(),
                }
            } else {
                match call(&self.base, &envelope).await {
                    Ok(Response::Result { .. }) => "result".to_owned(),
                    Ok(_) => "unexpected response".to_owned(),
                    Err(reason) => reason,
                }
            };
            eprintln!(
                "PAM_STRESS_PROBE {}",
                json!({"capability": capability, "peers": peers,
                "elapsed_ms": started.elapsed().as_millis(), "outcome": outcome})
            );
        }

        fn metrics(&self) -> Value {
            json!({"pid": self.child.id(), "successful_exchanges": self.successes, "by_capability": self.by_capability,
                "abandoned_requests": self.abandoned_requests, "abandoned_followers": self.abandoned_followers,
                "subscriber_churn": self.subscriber_churn, "max_exchange_ms": self.max_exchange_ms})
        }

        async fn stop(mut self) {
            let started = Instant::now();
            assert!(
                Command::new("kill")
                    .args(["-TERM", &self.child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
            let status = timeout(LIFECYCLE_WAIT, async {
                loop {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("SIGTERM must exit within unchanged15s lifecycle budget");
            let log = daemon_log(&self.base);
            println!(
                "PAM_STRESS_SHUTDOWN {}",
                json!({"elapsed_ms": started.elapsed().as_millis(),
                "exit_success": status.success(), "draining_logged": log.contains("daemon draining"), "drained_logged": log.contains("daemon drained")})
            );
            assert!(status.success(), "daemon exited with {status}");
            assert!(
                log.contains("daemon draining") && log.contains("daemon drained"),
                "graceful drain logs missing: {log}"
            );
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "PAM_STRESS_FAILURE {} resources={} log={}",
                    self.metrics(),
                    resources(self.child.id()),
                    log_tail(&self.base)
                );
                if let Some(temp) = self.temp.take() {
                    eprintln!("PAM_STRESS_PRESERVED {}", temp.keep().display());
                }
            }
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            let _ = Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status();
            let until = Instant::now() + Duration::from_secs(3);
            while Instant::now() < until {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn daemon_log(base: &Path) -> String {
        let mut text = String::new();
        if let Ok(entries) = std::fs::read_dir(base.join("log")) {
            for entry in entries.flatten() {
                if let Ok(part) = std::fs::read_to_string(entry.path()) {
                    text.push_str(&part);
                }
            }
        }
        text
    }

    fn log_tail(base: &Path) -> String {
        let log = daemon_log(base);
        let mut start = log.len().saturating_sub(16_384);
        while !log.is_char_boundary(start) {
            start += 1;
        }
        log[start..].to_owned()
    }

    fn command_text(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// The daemon's open numeric descriptors, as `lsof` reports them.
    fn descriptors(pid: u32) -> Option<usize> {
        let pid = pid.to_string();
        command_text("lsof", &["-n", "-P", "-a", "-p", &pid, "-F", "f"]).map(|text| {
            text.lines()
                .filter(|line| {
                    line.strip_prefix('f')
                        .is_some_and(|fd| fd.parse::<u32>().is_ok())
                })
                .count()
        })
    }

    fn resources(pid: u32) -> Value {
        let pid_text = pid.to_string();
        let rss_cpu = command_text("ps", &["-o", "rss=,pcpu=", "-p", &pid_text]);
        #[cfg(target_os = "macos")]
        let thread_count = command_text("ps", &["-M", "-p", &pid_text])
            .map(|text| text.lines().count().saturating_sub(1));
        #[cfg(not(target_os = "macos"))]
        let thread_count = std::fs::read_dir(format!("/proc/{pid_text}/task"))
            .ok()
            .map(Iterator::count);
        json!({"rss_kib_cpu_percent": rss_cpu, "numeric_fd_count": descriptors(pid), "thread_rows": thread_count})
    }

    async fn cancellation_probe(harness: &mut Harness) {
        let response = harness
            .request("echo", json!({"delay_ms": 4_000}), false)
            .await;
        let Response::Ticket { ticket, .. } = response else {
            panic!("echo should return ticket: {response:?}");
        };
        let started = Instant::now();
        let response = harness
            .request("cancel", json!({"ticket": ticket}), true)
            .await;
        assert!(
            matches!(response, Response::Result { .. }),
            "cancel failed: {response:?}"
        );
        let terminal = timeout(Duration::from_secs(5), async {
            loop {
                let response = harness
                    .request("query", json!({"ticket": ticket}), true)
                    .await;
                let Response::Result { body, .. } = response else {
                    panic!("cancel query must return a result");
                };
                if matches!(body["state"].as_str(), Some("done" | "failed" | "refused")) {
                    break body;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("cancel reaches terminal within5s");
        assert_eq!(terminal["outcome"], "cancelled", "{terminal}");
        println!(
            "PAM_STRESS_CANCEL {}",
            json!({"ticket": ticket,
            "elapsed_ms": started.elapsed().as_millis(), "terminal": terminal["state"]})
        );
    }

    /// Exercises the real CLI follow while the original unread peers are still
    /// attached: the follow stream must not depend on anyone else reading.
    async fn follow_probe(harness: &mut Harness) {
        let response = harness
            .request("echo", json!({"delay_ms": 1_500}), false)
            .await;
        let Response::Ticket { ticket, .. } = response else {
            panic!("echo must return ticket");
        };
        let started = Instant::now();
        let output = timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(std::env::var_os("PAM_STRESS_BINARY").unwrap())
                .args(["subscribe", &ticket, "--timeout-ms", "15000"])
                .current_dir(&harness.base)
                .env("PAM_BASE_DIR", &harness.base)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("CLI follow completes within15s")
        .expect("CLI follow starts");
        assert!(
            output.status.success(),
            "follow failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response = harness
            .request("query", json!({"ticket": ticket}), true)
            .await;
        let Response::Result { body, .. } = response else {
            panic!("terminal query must return result");
        };
        assert_eq!(body["state"], "done");
        println!(
            "PAM_STRESS_FOLLOW {}",
            json!({"ticket": ticket, "elapsed_ms": started.elapsed().as_millis(),
            "exit_success": output.status.success(), "terminal_state": body["state"], "output": String::from_utf8_lossy(&output.stdout)})
        );
    }

    /// Long tickets with followers attached and never read, and all-events
    /// subscribers attached and never read: the standing peers the churn runs
    /// beside.
    async fn attach_standing_peers(harness: &mut Harness) {
        for _ in 0..HELD_SUBSCRIBERS {
            let events = admin_transport::events(&harness.base, true)
                .await
                .expect("an all-events subscriber attaches");
            harness.held_subscribers.push(events);
        }
        for _ in 0..HELD_TICKETS {
            harness.sequence += 1;
            let mut start = envelope_for_repo(
                &harness.held_repo,
                &format!("held_{}", harness.sequence),
                "echo",
                json!({"delay_ms": 60_000, "tag": harness.sequence}),
                false,
            );
            start.deadline_ms = 150_000;
            let Response::Ticket { ticket, .. } = harness.exchange_envelope("echo", &start).await
            else {
                panic!("a held echo answers a ticket");
            };
            for follower in 0..HELD_FOLLOWERS_PER_TICKET {
                let id = format!("held_follow_{}_{follower}", harness.held_tickets.len());
                let stream = open_follow(&harness.base, &harness.held_repo, &id, &ticket)
                    .await
                    .unwrap_or_else(|reason| panic!("{id}: {reason}"));
                harness.held_followers.push(stream);
            }
            harness.held_tickets.push(ticket);
        }
    }

    /// Waits for the daemon's descriptors to come back to `baseline`.
    async fn wait_for_descriptors(pid: u32, baseline: usize) {
        timeout(Duration::from_secs(15), async {
            loop {
                let now = descriptors(pid).expect("lsof reports the daemon");
                if now <= baseline + DESCRIPTOR_SLACK {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "daemon descriptors did not return to baseline {baseline}: now {:?}",
                descriptors(pid)
            )
        });
    }

    /// Reports what the daemon did to the subscribers that never read.
    async fn report_held_subscribers(harness: &mut Harness) {
        // The daemon cuts each, with `subscriber_lagged` once its queue
        // overflows or by closing it when its writes stall (reported, not
        // asserted: a short run may not get that far).
        let (mut lagged, mut closed) = (0, 0);
        for subscriber in &mut harness.held_subscribers {
            while let Ok(next) = timeout(Duration::from_secs(2), subscriber.next()).await {
                match next {
                    Ok(_) => {}
                    Err(DialError::Refused(error)) if error.cause == cause::SUBSCRIBER_LAGGED => {
                        lagged += 1;
                        break;
                    }
                    Err(_) => {
                        closed += 1;
                        break;
                    }
                }
            }
        }
        println!("PAM_STRESS_HELD_SUBSCRIBERS lagged={lagged} closed={closed}");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "120s isolated transport churn; explicit PAM_STRESS_BINARY; run without concurrent Cargo"]
    async fn churn_cross_process() {
        let _serial = SERIAL.lock().await;
        let mut harness = Harness::spawn().await;
        let baseline = descriptors(harness.child.id());
        println!(
            "PAM_STRESS_START {} resources={}",
            harness.metrics(),
            resources(harness.child.id())
        );
        attach_standing_peers(&mut harness).await;
        let started = Instant::now();
        let mut checkpoint = Duration::ZERO;
        while started.elapsed() < LOAD_TIME {
            for capability in ["status", "admin.profile.get", "echo"] {
                let response = harness.request(capability, json!({}), true).await;
                assert!(
                    matches!(response, Response::Result { .. }),
                    "{capability}: {response:?}"
                );
            }
            // A unary request written and abandoned.
            let envelope = harness.envelope("status", json!({}), true);
            abandon_call(&harness.base, &envelope)
                .await
                .expect("an abandoned request is written");
            harness.abandoned_requests += 1;
            // A follower dropped mid-follow, on a ticket the held ones follow
            // too (their slots are taken up to 12 of 16 per ticket).
            let ticket = harness.held_tickets[0].clone();
            let id = format!("churn_follow_{}", harness.sequence);
            match open_follow(&harness.base, &harness.held_repo, &id, &ticket).await {
                Ok(stream) => drop(stream),
                // The held ticket has ended: there is nothing to follow.
                Err(reason) if reason.contains("End(") => {}
                Err(reason) => panic!("{id}: {reason}"),
            }
            harness.abandoned_followers += 1;
            // An all-events subscriber attached and dropped. The standing
            // ones never read, so the daemon cuts each with `subscriber_lagged`
            // once its queue overflows and the slot is free again: the churn
            // is admitted either way.
            let subscriber = admin_transport::events(&harness.base, true).await;
            assert!(subscriber.is_ok(), "{:?}", subscriber.err());
            drop(subscriber);
            harness.subscriber_churn += 1;
            if started.elapsed() >= checkpoint {
                println!(
                    "PAM_STRESS_PROGRESS {} elapsed_ms={} held_subscribers={} held_followers={} resources={}",
                    harness.metrics(),
                    started.elapsed().as_millis(),
                    harness.held_subscribers.len(),
                    harness.held_followers.len(),
                    resources(harness.child.id())
                );
                checkpoint += Duration::from_secs(20);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        cancellation_probe(&mut harness).await;
        follow_probe(&mut harness).await;
        println!(
            "PAM_STRESS_LOADED_END {} elapsed_ms={} resources={}",
            harness.metrics(),
            started.elapsed().as_millis(),
            resources(harness.child.id())
        );
        let response = harness.request("status", json!({}), true).await;
        assert!(matches!(response, Response::Result { .. }));

        report_held_subscribers(&mut harness).await;

        // Every standing peer goes away; the daemon's descriptors come back.
        println!(
            "PAM_STRESS_SHUTDOWN_ORIGINAL_PEERS {}",
            harness.held_subscribers.len() + harness.held_followers.len()
        );
        harness.held_subscribers.clear();
        harness.held_followers.clear();
        for ticket in harness.held_tickets.clone() {
            harness.sequence += 1;
            let cancel = envelope_for_repo(
                &harness.held_repo,
                &format!("held_cancel_{}", harness.sequence),
                "cancel",
                json!({"ticket": ticket}),
                true,
            );
            let response = harness.exchange_envelope("cancel", &cancel).await;
            assert!(
                matches!(response, Response::Result { .. }),
                "cancelling a held ticket: {response:?}"
            );
        }
        if let Some(baseline) = baseline {
            wait_for_descriptors(harness.child.id(), baseline).await;
        }
        let response = harness.request("status", json!({}), true).await;
        assert!(matches!(response, Response::Result { .. }));
        harness.stop().await;
    }
}
