//! Opt-in isolated cross-process investigation for ptrack #102 / issue #4.
//! This is workload evidence, not a proof that a historical 25-minute stall
//! is fixed. Run the compiled test directly, with no concurrent Cargo build.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pam_daemon::admin::{ADMIN_CALLER_AGENT, ADMIN_REPO};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_proto::{Envelope, Response};
use pam_store::Store;
use pam_testkit::{envelope_for_repo, short_tempdir};
use serde_json::{Value, json};
use tokio::time::timeout;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, SubSocket, ZmqMessage};

const LOAD_TIME: Duration = Duration::from_mins(2);
const LIFECYCLE_WAIT: Duration = Duration::from_secs(15);
const HELD_SUBSCRIBERS: usize = 32;

struct Harness {
    child: Child,
    held: Vec<SubSocket>,
    base: PathBuf,
    temp: Option<tempfile::TempDir>,
    sequence: u64,
    successes: u64,
    by_capability: BTreeMap<String, u64>,
    abandoned_dealers: u64,
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
            held: Vec::new(),
            base,
            temp: Some(temp),
            sequence: 0,
            successes: 0,
            by_capability: BTreeMap::new(),
            abandoned_dealers: 0,
            subscriber_churn: 0,
            max_exchange_ms: 0,
        };
        timeout(LIFECYCLE_WAIT, async {
            while !harness.base.join("run/pam.sock").exists() {
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
            &self.base.display().to_string(),
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
        let started = Instant::now();
        let response = match exchange(&self.base, &envelope, false).await {
            Ok(response) => response,
            Err(reason) => {
                let elapsed_ms = started.elapsed().as_millis();
                self.diagnose_delivery().await;
                panic!(
                    "{capability} exchange failed after {elapsed_ms}ms; counts={}: {reason}",
                    self.metrics()
                );
            }
        };
        self.successes += 1;
        *self.by_capability.entry(capability.to_owned()).or_default() += 1;
        self.max_exchange_ms = self.max_exchange_ms.max(started.elapsed().as_millis());
        response.expect("non-abandoned request returns a response")
    }

    async fn diagnose_delivery(&mut self) {
        eprintln!(
            "PAM_STRESS_TIMEOUT_RESOURCES {} held={}",
            resources(self.child.id()),
            self.held.len()
        );
        for capability in ["status", "admin.profile.get"] {
            self.probe(capability, "held").await;
        }
        let removed = self.held.len();
        self.held.clear();
        tokio::time::sleep(Duration::from_millis(250)).await;
        eprintln!("PAM_STRESS_AB_REMOVED {removed}");
        for capability in ["status", "admin.profile.get"] {
            self.probe(capability, "removed").await;
        }
    }

    async fn probe(&mut self, capability: &str, peers: &str) {
        let envelope = self.envelope(capability, json!({}), true);
        let started = Instant::now();
        let result = exchange(&self.base, &envelope, false).await;
        let outcome = match result {
            Ok(Some(Response::Result { .. })) => "result".to_owned(),
            Ok(_) => "unexpected response".to_owned(),
            Err(reason) => reason,
        };
        eprintln!(
            "PAM_STRESS_PROBE {}",
            json!({"capability": capability, "peers": peers,
            "elapsed_ms": started.elapsed().as_millis(), "outcome": outcome})
        );
    }

    fn metrics(&self) -> Value {
        json!({"pid": self.child.id(), "successful_exchanges": self.successes, "by_capability": self.by_capability,
            "abandoned_dealers": self.abandoned_dealers, "subscriber_churn": self.subscriber_churn,
            "max_exchange_ms": self.max_exchange_ms})
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

/// A fresh DEALER for every exchange; the deadline includes handshake/send,
/// unlike the client's recv-only timeout. It never enlarges GUI deadlines.
async fn exchange(
    base: &Path,
    envelope: &Envelope,
    abandon: bool,
) -> Result<Option<Response>, String> {
    let mut phase = "connect";
    timeout(Duration::from_millis(envelope.deadline_ms), async {
        let mut socket = DealerSocket::new();
        socket
            .connect(&format!("ipc://{}", base.join("run/pam.sock").display()))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        phase = "send";
        socket
            .send(ZmqMessage::from(serde_json::to_vec(envelope).unwrap()))
            .await
            .map_err(|e| format!("send: {e}"))?;
        if abandon {
            return Ok(None);
        }
        phase = "recv";
        let message = socket.recv().await.map_err(|e| format!("recv: {e}"))?;
        let frames = message.into_vec();
        let frame = frames.first().ok_or_else(|| "empty reply".to_owned())?;
        serde_json::from_slice(frame)
            .map(Some)
            .map_err(|e| format!("reply JSON: {e}"))
    })
    .await
    .map_err(|_| format!("{phase} exceeded {}ms", envelope.deadline_ms))?
}

async fn subscriber(base: &Path) -> SubSocket {
    timeout(Duration::from_secs(5), async {
        let mut socket = SubSocket::new();
        socket
            .connect(&format!("ipc://{}", base.join("run/events.sock").display()))
            .await
            .unwrap();
        socket.subscribe("").await.unwrap();
        socket
    })
    .await
    .expect("SUB connect/subscribe within5s")
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

fn resources(pid: u32) -> Value {
    let pid = pid.to_string();
    let rss_cpu = command_text("ps", &["-o", "rss=,pcpu=", "-p", &pid]);
    let fd_count = command_text("lsof", &["-n", "-P", "-a", "-p", &pid, "-F", "f"]).map(|text| {
        text.lines()
            .filter(|line| {
                line.strip_prefix('f')
                    .is_some_and(|fd| fd.parse::<u32>().is_ok())
            })
            .count()
    });
    #[cfg(target_os = "macos")]
    let thread_count =
        command_text("ps", &["-M", "-p", &pid]).map(|text| text.lines().count().saturating_sub(1));
    #[cfg(not(target_os = "macos"))]
    let thread_count = std::fs::read_dir(format!("/proc/{pid}/task"))
        .ok()
        .map(Iterator::count);
    json!({"rss_kib_cpu_percent": rss_cpu, "numeric_fd_count": fd_count, "thread_rows": thread_count})
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

/// Exercise the real CLI follow/reconciliation path while original unread
/// peers still block PUB delivery. This does not promise immediate events.
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

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "120s isolated transport churn; explicit PAM_STRESS_BINARY; run without concurrent Cargo"]
async fn gui_polling_and_abandoned_subscribers_cross_process() {
    let mut harness = Harness::spawn().await;
    println!(
        "PAM_STRESS_START {} resources={}",
        harness.metrics(),
        resources(harness.child.id())
    );
    for _ in 0..HELD_SUBSCRIBERS {
        let socket = subscriber(&harness.base).await;
        harness.held.push(socket);
    }
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
        let envelope = harness.envelope("status", json!({}), true);
        exchange(&harness.base, &envelope, true)
            .await
            .expect("abandoned DEALER sends request");
        harness.abandoned_dealers += 1;
        drop(subscriber(&harness.base).await);
        harness.subscriber_churn += 1;
        if started.elapsed() >= checkpoint {
            println!(
                "PAM_STRESS_PROGRESS {} elapsed_ms={} held_subscribers={} resources={}",
                harness.metrics(),
                started.elapsed().as_millis(),
                harness.held.len(),
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
    println!("PAM_STRESS_SHUTDOWN_ORIGINAL_PEERS {}", harness.held.len());
    harness.stop().await;
}
