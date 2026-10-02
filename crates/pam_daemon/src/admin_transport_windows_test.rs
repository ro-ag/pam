//! The Windows adapter: loopback TCP behind the owner nonce in
//! `<base>\admin\control.json`. The handshake itself is tested with
//! `framed_windows`; here it is the administration plane on top of it. All but
//! the last test run on every platform, because only minting the nonce needs
//! Windows.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pam_proto::wire::cause;
use pam_proto::{Envelope, Event, Outcome, Response};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use super::events_stream::subscribe_on;
use super::frame::{MAX_REQUEST_BYTES, encode_request, exchange_on};
use super::frame_test::{DEADLINE, admin_service, hello, lifecycle, profile_get};
use super::loopback::{Listener, connect, prepare_base};
use crate::event_hub::EventHub;
use crate::framed::DialError;
use crate::framed_windows::{
    ADMIN_LABEL, NONCE_BYTES, PUBLIC_LABEL, admit_server, read_control, same, server_proof,
};

const NONCE: [u8; NONCE_BYTES] = [0x5A; NONCE_BYTES];

/// A canonical private base in a fresh temporary directory.
fn private_base(tmp: &tempfile::TempDir) -> PathBuf {
    prepare_base(&tmp.path().canonicalize().unwrap().join("pam")).unwrap()
}

async fn listener_at(base: &Path, hub: &Arc<EventHub>) -> Listener {
    Listener::bind_with_nonce(
        base,
        admin_service().await,
        lifecycle(),
        Arc::clone(hub),
        NONCE,
    )
    .unwrap()
}

/// The client's whole exchange against this adapter, as
/// `admin_transport::exchange` runs it on Windows.
async fn exchange(base: &Path, envelope: &Envelope) -> io::Result<Response> {
    let request = encode_request(envelope)?;
    let mut stream = connect(base).await?;
    exchange_on(&mut stream, envelope, &request).await
}

/// Control file, server proof, nonce, hello, request, reply — and the same
/// door for the event stream. Shutdown removes the control file, so a client
/// then finds no daemon rather than a dead port.
#[tokio::test]
async fn the_nonce_holder_is_served_requests_and_events_until_shutdown() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = tempfile::tempdir().unwrap();
        let base = private_base(&tmp);
        let hub = EventHub::new();
        let listener = listener_at(&base, &hub).await;
        let control = base.join("admin").join("control.json");
        let (port, nonce) = read_control(&control).unwrap();
        assert_ne!(port, 0);
        assert_eq!(nonce, NONCE);

        let response = exchange(&base, &profile_get("req_loopback")).await.unwrap();
        assert!(
            matches!(&response, Response::Result { id, outcome: Outcome::Verified, .. } if id == "req_loopback"),
            "{response:?}"
        );

        let stream = connect(&base).await.unwrap();
        let mut events = subscribe_on(stream, &hello(env!("CARGO_PKG_VERSION")))
            .await
            .unwrap();
        hub.publish("req_ticket", Event::Queued).unwrap();
        let frame = events.next().await.unwrap();
        assert_eq!(
            (frame.ticket.as_deref(), &frame.event),
            (Some("req_ticket"), &Event::Queued)
        );

        listener.shutdown().await;
        let ended = events.next().await;
        assert!(
            matches!(&ended, Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN),
            "{ended:?}"
        );
        assert!(!control.exists(), "the control file is removed at shutdown");
        let gone = exchange(&base, &profile_get("req_gone")).await;
        assert_eq!(gone.unwrap_err().kind(), io::ErrorKind::NotFound);
    })
    .await
    .expect("test within deadline");
}

/// A hello the daemon refuses must reach the client even though the client
/// wrote a large request right behind it: over TCP, closing with that request
/// unread would reset the connection and could discard the refusal.
#[tokio::test]
async fn a_refused_hello_survives_the_unread_request_behind_it() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = tempfile::tempdir().unwrap();
        let base = private_base(&tmp);
        let listener = listener_at(&base, &EventHub::new()).await;
        for round in 0..8 {
            let request = Envelope {
                client_version: "different-build".to_owned(),
                args: serde_json::json!({ "pad": "x".repeat(MAX_REQUEST_BYTES / 2) }),
                ..profile_get(&format!("req_other_build_{round}"))
            };
            let response = exchange(&base, &request).await.unwrap();
            assert!(
                matches!(&response, Response::Refusal { id, cause: named, retryable: false, .. }
                    if id == &request.id && named == cause::CLIENT_VERSION_MISMATCH),
                "{response:?}"
            );
        }
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

/// Dials the admin port and reads whatever the daemon sends after the client
/// presented `presented` as its nonce.
async fn present(port: u16, presented: [u8; NONCE_BYTES]) -> Vec<u8> {
    use tokio::io::AsyncWriteExt;
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut proof = [0u8; NONCE_BYTES];
    stream.read_exact(&mut proof).await.unwrap();
    assert!(same(&proof, &server_proof(ADMIN_LABEL, &NONCE)));
    stream.write_all(&presented).await.unwrap();
    // A well-formed hello and request behind the wrong nonce.
    let request = encode_request(&profile_get("req_wrong_nonce")).unwrap();
    let _ =
        crate::framed::open_encoded(&mut stream, &hello(env!("CARGO_PKG_VERSION")), &request).await;
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    answer
}

/// The public plane's nonce and label confer nothing here: a client that
/// expects the public proof never sends its nonce, and a peer that presents
/// any other nonce is closed before a frame is read or answered.
#[tokio::test]
async fn the_public_nonce_and_a_wrong_nonce_are_refused_before_any_frame() {
    tokio::time::timeout(DEADLINE, async {
        let tmp = tempfile::tempdir().unwrap();
        let base = private_base(&tmp);
        let listener = listener_at(&base, &EventHub::new()).await;
        let (port, _) = read_control(&base.join("admin").join("control.json")).unwrap();

        // A public client holding the same bytes still fails the proof: the
        // label separates the planes, and the nonce is never sent.
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let verdict = admit_server(&mut stream, PUBLIC_LABEL, &NONCE).await;
        assert_eq!(verdict.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        drop(stream);

        // A different nonce (the public plane's is unrelated to this one).
        let public_nonce = [0xA5; NONCE_BYTES];
        assert!(
            present(port, public_nonce).await.is_empty(),
            "nothing is answered to a peer that did not present the admin nonce"
        );

        // The owner is still served.
        let response = exchange(&base, &profile_get("req_owner")).await.unwrap();
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

/// The base rules that are this adapter's own: an absolute path, a real
/// directory, and a private `admin` directory that is not a link.
#[tokio::test]
async fn the_private_base_must_be_an_absolute_real_directory() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        prepare_base(Path::new("relative/pam")).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let file = tmp.path().join("file");
    std::fs::write(&file, b"not a directory").unwrap();
    assert_eq!(
        prepare_base(&file).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    // `admin` exists but is a file: neither the daemon nor a client uses it.
    let base = private_base(&tmp);
    std::fs::write(base.join("admin"), b"not a directory").unwrap();
    let bound = Listener::bind_with_nonce(
        &base,
        admin_service().await,
        lifecycle(),
        EventHub::new(),
        NONCE,
    );
    assert_eq!(
        bound.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        connect(&base).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

/// On Windows the adapter is the supported one and every bind mints its own
/// nonce, which is what a restarted daemon's clients must re-read.
#[cfg(windows)]
#[tokio::test]
async fn the_windows_adapter_is_supported_and_mints_a_fresh_nonce_per_bind() {
    assert!(crate::admin_transport::supported());
    let tmp = tempfile::tempdir().unwrap();
    let base = private_base(&tmp);
    let control = base.join("admin").join("control.json");
    let first = Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
    let (_, first_nonce) = read_control(&control).unwrap();
    let response = crate::admin_transport::exchange(&base, &profile_get("req_windows"))
        .await
        .unwrap();
    assert!(matches!(response, Response::Result { .. }), "{response:?}");
    first.shutdown().await;
    assert!(!control.exists());
    let second =
        Listener::bind(&base, admin_service().await, lifecycle(), EventHub::new()).unwrap();
    let (_, second_nonce) = read_control(&control).unwrap();
    assert!(!same(&first_nonce, &second_nonce));
    let mut events = crate::admin_transport::events(&base).await.unwrap();
    second.shutdown().await;
    assert!(matches!(
        events.next().await,
        Err(DialError::Refused(error)) if error.cause == cause::DAEMON_SHUTTING_DOWN
    ));
}
