//! The session relay against a real daemon: a ZMTP request dialed at the
//! relay's session socket reaches the daemon and its answer comes back —
//! the exact bytes a sandboxed `pam` client sends with `$PAM_SOCKET_DIR`
//! set. Exercised in process: no process environment is mutated and no
//! binary is spawned, so the test runs wherever unix domain sockets do.

use std::time::{Duration, Instant};

use pam_client::request::build_envelope;
use pam_daemon::runtime_dir::RuntimeDir;
use pam_proto::{Outcome, Response};
use pam_testkit::TestDaemon;
use zeromq::{DealerSocket, Socket, SocketRecv, SocketSend, ZmqMessage};

#[tokio::test(flavor = "multi_thread")]
async fn a_request_dialed_at_the_relay_reaches_the_daemon() {
    let daemon = TestDaemon::spawn().await;
    let session_dir = daemon.base_dir().join("session");

    let bindings = pam_client::relay::prepare(&session_dir, &daemon.base_dir())
        .expect("the relay prepares against the daemon base");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(pam_client::relay::serve(bindings, shutdown_rx));
    let dirs = RuntimeDir::paths_at_dir(&session_dir).expect("session endpoints");

    let mut dealer = DealerSocket::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match dealer.connect(&dirs.router_endpoint()).await {
            Ok(()) => break,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("the relay socket never answered: {error}"),
        }
    }

    let envelope = build_envelope(
        "flow.list",
        serde_json::json!({ "limit": 5 }),
        true,
        10_000,
        None,
    );
    let payload = serde_json::to_vec(&envelope).expect("the envelope serializes");
    dealer
        .send(ZmqMessage::from(payload))
        .await
        .expect("the request goes out");
    let reply = tokio::time::timeout(Duration::from_secs(10), dealer.recv())
        .await
        .expect("a reply arrives in time")
        .expect("the reply frame reads");
    let payload = reply
        .into_vec()
        .first()
        .map(|frame| frame.to_vec())
        .unwrap_or_default();
    let response: Response = serde_json::from_slice(&payload).expect("a daemon response");
    match response {
        Response::Result { body, outcome, .. } => {
            assert_eq!(outcome, Outcome::Verified);
            assert!(
                !body["flows"].as_array().expect("flows").is_empty(),
                "the daemon answered through the relay: {body}"
            );
        }
        other => panic!("expected a result, got {other:?}"),
    }

    let _ = shutdown_tx.send(true);
    server.await.expect("serve joins").expect("serve ok");
}
