//! CLI-flow integration tests: a real daemon ([`run_daemon`]) on a temp
//! base dir, driven through the library functions the `pam` binary
//! dispatches to — [`client::send_request`], [`client::follow_ticket`],
//! and the renderers. The binary itself stays a thin clap shell, so
//! driving the lib functions covers the surface.

use std::path::PathBuf;
use std::time::Duration;

use pam::client;
use pam::render;
use pam_daemon::daemon::{DaemonHandle, run_daemon};
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_proto::{Event, Outcome, Response};
use pam_store::{RequestRow, RequestState, Store};
use tokio::sync::watch;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(20);

/// Bound on the event-follow calls; well under [`DEADLINE`] so a hang
/// fails legibly.
const FOLLOW_TIMEOUT: Duration = Duration::from_secs(10);

/// Temp dir with a short absolute path: macOS caps unix socket paths at
/// 104 bytes and the default temp root can get close.
fn short_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new()
            .prefix("pam")
            .tempdir_in("/tmp")
            .expect("tempdir under /tmp")
    }
    #[cfg(not(unix))]
    {
        tempfile::tempdir().expect("tempdir")
    }
}

struct TestDaemon {
    tmp: tempfile::TempDir,
    handle: DaemonHandle,
    shutdown: watch::Sender<bool>,
}

impl TestDaemon {
    async fn start() -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let (shutdown, shutdown_rx) = watch::channel(false);
        let handle = run_daemon(Some(base_of(&tmp)), shutdown_rx)
            .await
            .expect("daemon starts");
        Self {
            tmp,
            handle,
            shutdown,
        }
    }

    fn base(&self) -> PathBuf {
        base_of(&self.tmp)
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.handle.shutdown().await;
    }
}

/// The daemon base directory inside a test's temp dir.
fn base_of(tmp: &tempfile::TempDir) -> PathBuf {
    tmp.path().join("pam")
}

/// Persists the relaxed profile before the daemon (and thus the gate)
/// opens the store.
///
/// [`pam_daemon::policy::Profile::platform_default`] is `Relaxed` only on
/// macOS and `Standard` everywhere else, and only the relaxed profile
/// auto-grants a non-destructive capability on first use. These tests
/// drive `echo` without granting it, so without the seed they pass on
/// macOS and refuse with `not_granted` on Linux and Windows.
async fn seed_relaxed(tmp: &tempfile::TempDir) {
    let store = Store::open(&base_of(tmp).join("state.sqlite3"))
        .await
        .expect("store opens");
    store
        .set_setting(PROFILE_SETTING_KEY, "\"relaxed\"")
        .await
        .expect("relaxed profile persists");
}

/// Polls the store until the request row satisfies `pred`.
async fn wait_for_row(store: &Store, id: &str, pred: impl Fn(&RequestRow) -> bool) -> RequestRow {
    loop {
        if let Some(row) = store.get_request(id).await.expect("get_request ok")
            && pred(&row)
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn status_round_trips_and_maps_to_exit_zero() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "status",
            serde_json::json!({}),
            true,
            10_000,
            None,
        )
        .await
        .expect("request flows");

        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Verified);
        assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(render::exit_code(&response), 0);

        // The humane summary shows what the daemon reported.
        let summary = render::render_status(body);
        assert!(summary.contains(env!("CARGO_PKG_VERSION")), "{summary}");
        assert!(summary.contains("active requests"), "{summary}");

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn echo_solves_with_the_args_mirrored_back() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let args = serde_json::json!({ "msg": "hello" });
        let response =
            client::send_request(&daemon.base(), "echo", args.clone(), true, 10_000, None)
                .await
                .expect("request flows");

        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Solved);
        assert_eq!(*body, serde_json::json!({ "echo": args }));
        assert_eq!(render::exit_code(&response), 0);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn no_wait_returns_a_ticket_and_the_event_stream_ends_in_done() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        // Enough delay for the follow subscription to register before
        // the terminal event fires (zmq PUB has no replay).
        let args = serde_json::json!({ "delay_ms": 2_000 });
        let response = client::send_request(&daemon.base(), "echo", args, false, 10_000, None)
            .await
            .expect("request flows");

        let Response::Ticket { ticket, .. } = &response else {
            panic!("expected a ticket, got {response:?}");
        };
        assert_eq!(render::exit_code(&response), 0);
        let hint = render::render_ticket(ticket, 0);
        assert!(hint.contains(&format!("pam wait {ticket}")), "{hint}");

        // `pam wait` / `pam subscribe` share this one code path.
        let mut seen = Vec::new();
        let terminal = client::follow_ticket(&daemon.base(), ticket, FOLLOW_TIMEOUT, |event| {
            seen.push(event.clone());
        })
        .await
        .expect("follow reaches a terminal event");

        assert_eq!(terminal, Event::Done);
        assert_eq!(seen.last(), Some(&Event::Done));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_follow_that_joins_after_the_terminal_event_still_terminates() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "echo",
            serde_json::json!({}),
            false,
            10_000,
            None,
        )
        .await
        .expect("request flows");
        let Response::Ticket { ticket, .. } = response else {
            panic!("expected a ticket, got a different response");
        };

        // Let the request finish before anybody subscribes: all its
        // events — the terminal one included — are published to nobody,
        // and zmq PUB has no replay (issue #1).
        let store = daemon.handle.store();
        wait_for_row(&store, &ticket, |row| row.state == RequestState::Done).await;

        // The follow still terminates, through the store reconcile.
        let terminal = client::follow_ticket(&daemon.base(), &ticket, FOLLOW_TIMEOUT, |_| {})
            .await
            .expect("follow reaches a terminal event");
        assert_eq!(terminal, Event::Done);

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancel_stops_a_delayed_echo() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let args = serde_json::json!({ "delay_ms": 8_000 });
        let response = client::send_request(&daemon.base(), "echo", args, false, 10_000, None)
            .await
            .expect("request flows");
        let Response::Ticket { ticket, .. } = response else {
            panic!("expected a ticket, got {response:?}");
        };

        // Let the executor lease it so the cancel signals a runner.
        let store = daemon.handle.store();
        wait_for_row(&store, &ticket, |row| row.state == RequestState::Running).await;

        let response = client::send_request(
            &daemon.base(),
            "cancel",
            serde_json::json!({ "ticket": ticket }),
            true,
            10_000,
            None,
        )
        .await
        .expect("cancel flows");
        let Response::Result { outcome, body, .. } = &response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(*outcome, Outcome::Solved);
        assert_eq!(body["result"], "signalled_running");

        // The victim reaches its terminal state through its executor.
        let row = wait_for_row(&store, &ticket, |row| row.state == RequestState::Failed).await;
        assert_eq!(row.outcome.as_deref(), Some("cancelled"));

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_refusal_renders_cause_detail_and_recovery_and_exits_three() {
    timeout(DEADLINE, async {
        let daemon = TestDaemon::start().await;

        let response = client::send_request(
            &daemon.base(),
            "frobnicate",
            serde_json::json!({}),
            true,
            10_000,
            None,
        )
        .await
        .expect("request flows");

        let Response::Refusal {
            cause,
            detail,
            recovery,
            ..
        } = &response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, "unknown_capability");
        assert_eq!(render::exit_code(&response), render::EXIT_REFUSED);

        let text = render::render_refusal(cause, detail, recovery);
        assert!(text.contains("refused (unknown_capability)"), "{text}");
        assert!(text.contains(detail.as_str()), "{text}");
        assert!(text.contains("GUI"), "{text}");

        daemon.stop().await;
    })
    .await
    .expect("test within deadline");
}
