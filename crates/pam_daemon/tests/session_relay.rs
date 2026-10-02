//! The session relay against a real daemon: a framed request and a follow dialled at the relay's
//! one session socket reach the daemon and their answers come back — the exact bytes a sandboxed
//! `pam` client sends with `$PAM_SOCKET_DIR` set (its hello says `via: relay`). Exercised in
//! process: no process environment is mutated and no binary is spawned, so the test runs wherever
//! unix domain sockets do.
//!
//! The session directory holds exactly one socket: there is no second socket for events, because
//! a follow is a long-lived connection through the same pipe.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use pam_client::relay;
use pam_daemon::framed::{self, DialError};
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::wire::{Frame, MAX_FRAME_BYTES, Via};
use pam_proto::{Envelope, Event, Response};
use pam_store::RequestIngress;
use pam_testkit::{
    TestDaemon, envelope_for_repo, seed_relaxed, seed_repository_scope, short_tempdir,
    with_deadline,
};

/// Every read through the relay is bounded by this.
const PATIENCE: Duration = Duration::from_secs(8);

/// A real daemon with the relaxed profile and one approved repository, and a relay in front of it.
struct Rig {
    daemon: TestDaemon,
    repo: tempfile::TempDir,
    session_dir: PathBuf,
    socket: PathBuf,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), relay::RelayError>>,
}

impl Rig {
    async fn start() -> Self {
        let tmp = short_tempdir();
        seed_relaxed(&tmp).await;
        let repo = tempfile::tempdir().expect("a repository directory");
        seed_repository_scope(&tmp, repo.path(), &[]).await;
        let daemon = TestDaemon::spawn_at(tmp).await;
        let session_dir = daemon.base_dir().join("session");

        let bindings = relay::prepare(&session_dir, &daemon.base_dir())
            .expect("the relay prepares against the daemon base");
        let socket = bindings.socket().to_path_buf();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(relay::serve(bindings, shutdown_rx));
        Self {
            daemon,
            repo,
            session_dir,
            socket,
            shutdown_tx,
            server,
        }
    }

    fn repo(&self) -> String {
        self.repo
            .path()
            .canonicalize()
            .expect("the repository exists")
            .to_string_lossy()
            .into_owned()
    }

    fn envelope(&self, id: &str, args: serde_json::Value, wait: bool) -> Envelope {
        envelope_for_repo(&self.repo(), id, "echo", args, wait)
    }

    /// What the session directory holds, by name.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.session_dir)
            .expect("the session directory reads")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    async fn dial(&self) -> tokio::net::UnixStream {
        tokio::net::UnixStream::connect(&self.socket)
            .await
            .expect("the relay's session socket accepts")
    }

    /// One unary request, dialled the way a sandboxed client dials.
    async fn call(&self, envelope: &Envelope) -> Response {
        let mut stream = self.dial().await;
        tokio::time::timeout(
            PATIENCE,
            framed::call(
                &mut stream,
                &framed::client_hello(Via::Relay),
                envelope,
                MAX_FRAME_BYTES,
            ),
        )
        .await
        .expect("the reply arrives through the relay in time")
        .expect("the daemon answers through the relay")
        .1
    }

    async fn stop(self) {
        let Self {
            daemon,
            shutdown_tx,
            server,
            socket,
            ..
        } = self;
        let _ = shutdown_tx.send(true);
        server.await.expect("serve joins").expect("serve ok");
        assert!(!socket.exists(), "the relay removes its socket on shutdown");
        daemon.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_and_a_follow_travel_through_the_one_session_socket() {
    with_deadline(async {
        let rig = Rig::start().await;

        // The directory holds exactly the one socket, named like the daemon's public socket.
        let public = RuntimeDir::paths_at_base(&rig.daemon.base_dir())
            .expect("daemon paths")
            .public_socket()
            .file_name()
            .expect("socket name")
            .to_string_lossy()
            .into_owned();
        assert_eq!(rig.entries(), vec![public], "one socket, no events socket");
        let mode = std::fs::metadata(&rig.socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the session socket is owner-only");

        // A request: hello, request, reply, as through the daemon's own socket.
        let args = serde_json::json!({ "msg": "over the relay" });
        let reply = rig
            .call(&rig.envelope("req_via_relay", args.clone(), true))
            .await;
        let Response::Result { body, .. } = reply else {
            panic!("a waiting echo answers a result through the relay, got {reply:?}");
        };
        assert_eq!(body, serde_json::json!({ "echo": args }));

        // The daemon recorded who it saw: the relay's process as the kernel peer (this process,
        // since the relay runs in the test), and the client's own word that it was relayed.
        let row = rig
            .daemon
            .store()
            .get_request("req_via_relay")
            .await
            .expect("store reads")
            .expect("the request has a row");
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        assert!(row.origin.relayed, "the hello said via: relay");
        assert_eq!(
            row.origin.peer_pid,
            Some(std::process::id()),
            "the kernel's peer is the relay process"
        );

        // A follow: a ticket that takes a moment, followed to its end on one long-lived
        // connection through the same socket.
        let ticket_request = rig.envelope(
            "req_ticket",
            serde_json::json!({ "delay_ms": 400, "tag": "follow" }),
            false,
        );
        let Response::Ticket { ticket, .. } = rig.call(&ticket_request).await else {
            panic!("a non-waiting echo answers a ticket");
        };
        let query = envelope_for_repo(
            &rig.repo(),
            "req_follow_query",
            "query",
            serde_json::json!({ "ticket": ticket }),
            true,
        );
        let mut stream = rig.dial().await;
        framed::follow(
            &mut stream,
            &framed::client_hello(Via::Relay),
            &query,
            0,
            None,
        )
        .await
        .expect("the hello is acknowledged through the relay");
        let mut saw_event = false;
        let end = loop {
            let frame = tokio::time::timeout(
                PATIENCE,
                framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES),
            )
            .await
            .expect("a frame within the test's patience");
            match frame {
                Ok(Frame::Following(_)) => {}
                Ok(Frame::Event(_)) => saw_event = true,
                Ok(Frame::End(end)) => break end,
                other => panic!("expected following, event or end, got {other:?}"),
            }
        };
        assert_eq!(end.event, Some(Event::Done), "the follow ends with `done`");
        let Response::Result { body, .. } = end.response else {
            panic!("the end carries the durable answer");
        };
        assert_eq!(body["state"], "done");
        assert!(
            saw_event || end.seq.is_some(),
            "the stream carried the ticket's events through the pipe"
        );

        assert_eq!(
            rig.entries().len(),
            1,
            "dialling the relay never adds a socket to the directory"
        );
        rig.stop().await;
    })
    .await;
}

/// The relay is a pipe, not a gate: what the daemon refuses it carries as the daemon said it, and
/// a client that speaks nonsense gets the daemon's `bad_frame`, not the relay's opinion.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_carries_the_daemons_refusals_unchanged() {
    with_deadline(async {
        let rig = Rig::start().await;

        // A hello that is not a hello: the daemon's error frame comes back through the pipe.
        let mut stream = rig.dial().await;
        let nonsense = Frame::Reply {
            response: Response::refusal("x", "x", "x", "x"),
        };
        let result = tokio::time::timeout(
            PATIENCE,
            framed::open(&mut stream, &framed::client_hello(Via::Relay), &nonsense),
        )
        .await
        .expect("the daemon answers in time");
        // The hello is fine and the daemon acknowledges it; the request frame it does not know
        // is then refused on the same connection, never forwarded or fixed up by the relay.
        assert!(result.is_ok(), "{result:?}");
        let refused = tokio::time::timeout(
            PATIENCE,
            framed::read_daemon_frame(&mut stream, MAX_FRAME_BYTES),
        )
        .await
        .expect("an answer in time");
        assert!(
            matches!(&refused, Err(DialError::Refused(error)) if error.cause == "bad_frame"),
            "the daemon's own refusal crosses the relay: {refused:?}"
        );

        // The relay still serves the next client.
        let reply = rig
            .call(&rig.envelope("req_after", serde_json::json!({}), true))
            .await;
        assert!(matches!(reply, Response::Result { .. }), "{reply:?}");
        rig.stop().await;
    })
    .await;
}

/// The startup probe against a real daemon: a hello alone is acknowledged, so the relay sees a
/// daemon of this protocol and leaves it alone; with nothing listening it sees no daemon.
#[tokio::test(flavor = "multi_thread")]
async fn the_startup_probe_sees_a_real_daemon_and_an_absent_one() {
    with_deadline(async {
        let rig = Rig::start().await;
        let public = RuntimeDir::paths_at_base(&rig.daemon.base_dir())
            .expect("daemon paths")
            .public_socket()
            .to_path_buf();
        assert_eq!(
            relay::probe(&public).await,
            relay::Probe::Framed,
            "a hello is answered by a daemon of this protocol"
        );
        // The probe left the daemon serving: its next client is answered as usual.
        let reply = rig
            .call(&rig.envelope("req_after_probe", serde_json::json!({}), true))
            .await;
        assert!(matches!(reply, Response::Result { .. }), "{reply:?}");

        let nowhere = rig.session_dir.join("nobody-listens.sock");
        assert_eq!(relay::probe(&nowhere).await, relay::Probe::Unreachable);
        rig.stop().await;
    })
    .await;
}
