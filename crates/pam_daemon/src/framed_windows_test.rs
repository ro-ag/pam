//! The loopback-and-nonce endpoint. The handshake is plain TCP, so these run
//! on every platform; only minting the nonce is Windows-only, and so is its
//! test at the end.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use pam_proto::wire::{MAX_FRAME_BYTES, Via, cause};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::framed::{Limits, Listener, call, client_hello};
use crate::framed_test::{Answering, Holding, PATIENCE, envelope, error_cause, eventually, result};
use crate::framed_windows::{
    ADMIN_LABEL, LoopbackAcceptor, MAX_PUBLIC_PENDING, NONCE_BYTES, PUBLIC_LABEL, admit_client,
    connect, read_control, same, server_proof,
};
use crate::ingress::PeerIdentity;

const PUBLIC_NONCE: [u8; NONCE_BYTES] = [3; NONCE_BYTES];
const ADMIN_NONCE: [u8; NONCE_BYTES] = [9; NONCE_BYTES];

/// A control file as a daemon would publish it, written by hand so a test
/// can point a client at a port of its choosing.
fn publish(path: &Path, port: u16, nonce: &[u8; NONCE_BYTES]) {
    let control = serde_json::json!({
        "schema_version": 1, "port": port, "nonce": hex::encode(nonce),
    });
    std::fs::write(path, serde_json::to_vec(&control).unwrap()).unwrap();
}

/// The handshake's two pure pieces: the proof is a domain-separated hash of
/// the nonce (never the nonce itself), and each plane's label gives a
/// different proof for the same nonce.
#[test]
fn the_server_proof_hides_the_nonce_and_differs_per_nonce_and_per_plane() {
    let a = [7u8; NONCE_BYTES];
    let b = [8u8; NONCE_BYTES];
    assert_ne!(server_proof(PUBLIC_LABEL, &a), a);
    assert_ne!(
        server_proof(PUBLIC_LABEL, &a),
        server_proof(PUBLIC_LABEL, &b)
    );
    assert_ne!(
        server_proof(PUBLIC_LABEL, &a),
        server_proof(ADMIN_LABEL, &a)
    );
    assert!(same(
        &server_proof(ADMIN_LABEL, &a),
        &server_proof(ADMIN_LABEL, &a)
    ));
    assert!(!same(&a, &b));
    assert_eq!(
        (PUBLIC_LABEL, ADMIN_LABEL),
        ("pam-public-server", "pam-admin-server")
    );
}

/// A listener that took the daemon's port but never read the owner's control
/// file cannot produce the proof, so a client refuses before sending the
/// nonce: the stale-control-file case is a refusal, not a leak.
#[tokio::test]
async fn a_client_never_sends_the_nonce_to_a_port_that_cannot_prove_it() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = tempfile::tempdir().unwrap();
        let control = tmp.path().join("public.json");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        publish(
            &control,
            listener.local_addr().unwrap().port(),
            &PUBLIC_NONCE,
        );
        let impostor = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // A wrong proof: the impostor guesses.
            stream.write_all(&[0u8; NONCE_BYTES]).await.unwrap();
            let mut got = Vec::new();
            let _ = stream.read_to_end(&mut got).await;
            got
        });
        let error = connect(&control, PUBLIC_LABEL).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let received = impostor.await.unwrap();
        assert!(
            received.is_empty(),
            "nothing was sent to the impostor, got {received:?}"
        );
    })
    .await
    .expect("test within deadline");
}

/// Server side: a peer that read the proof but presents the wrong nonce is
/// refused before any frame byte is read.
#[tokio::test]
async fn the_server_refuses_a_wrong_nonce_before_reading_a_frame() {
    tokio::time::timeout(PATIENCE, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let verdict = admit_client(&mut stream, PUBLIC_LABEL, &PUBLIC_NONCE).await;
            // Whatever the peer sent after the nonce is never consumed.
            let mut unread = Vec::new();
            let _ = stream.read_to_end(&mut unread).await;
            (verdict, unread)
        });
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut proof = [0u8; NONCE_BYTES];
        stream.read_exact(&mut proof).await.unwrap();
        assert!(same(&proof, &server_proof(PUBLIC_LABEL, &PUBLIC_NONCE)));
        stream.write_all(&[6u8; NONCE_BYTES]).await.unwrap();
        stream.write_all(b"frame bytes").await.unwrap();
        drop(stream);
        let (verdict, unread) = server.await.unwrap();
        assert_eq!(verdict.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(unread, b"frame bytes", "no frame byte was parsed");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn the_public_endpoint_publishes_serves_and_unpublishes() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = tempfile::tempdir().unwrap();
        let control = tmp.path().join("public.json");
        // A control file from an earlier boot is replaced whole.
        publish(&control, 1, &ADMIN_NONCE);
        let acceptor = LoopbackAcceptor::bind_with_nonce(
            &control,
            PUBLIC_LABEL,
            MAX_PUBLIC_PENDING,
            PUBLIC_NONCE,
        )
        .unwrap();
        assert_eq!(acceptor.control(), control);
        let published: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&control).unwrap()).unwrap();
        assert_eq!(published["schema_version"], 1);
        assert_eq!(published["nonce"], hex::encode(PUBLIC_NONCE));
        assert_eq!(published["nonce"].as_str().unwrap().len(), 64);
        let (port, nonce) = read_control(&control).unwrap();
        assert_eq!(
            (u64::from(port), nonce),
            (published["port"].as_u64().unwrap(), PUBLIC_NONCE)
        );
        assert!(!control.with_extension("json.tmp").exists());

        let policy = Answering::new(Limits::PUBLIC);
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));
        for id in ["req_first", "req_second"] {
            let mut stream = connect(&control, PUBLIC_LABEL).await.unwrap();
            let (_, response) = call(
                &mut stream,
                &client_hello(Via::Direct),
                &envelope(id),
                MAX_FRAME_BYTES,
            )
            .await
            .unwrap();
            assert_eq!(response, result(id));
        }
        // No kernel identity on this adapter: the peer is the nonce holder.
        assert_eq!(
            *policy.peers.lock().unwrap(),
            vec![PeerIdentity::OwnerNonce, PeerIdentity::OwnerNonce]
        );

        listener.shutdown().await;
        assert!(!control.exists(), "the control file is removed at shutdown");
        assert_eq!(
            connect(&control, PUBLIC_LABEL).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    })
    .await
    .expect("test within deadline");
}

/// Each plane has its own port, nonce and label. The public nonce confers
/// nothing on the administration listener, from either side of the handshake.
#[tokio::test]
async fn the_public_nonce_is_refused_by_the_admin_listener() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = tempfile::tempdir().unwrap();
        let admin_control = tmp.path().join("control.json");
        let policy = Answering::new(Limits::ADMIN);
        let acceptor =
            LoopbackAcceptor::bind_with_nonce(&admin_control, ADMIN_LABEL, 8, ADMIN_NONCE).unwrap();
        let (admin_port, _) = read_control(&admin_control).unwrap();
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));

        // A public client pointed at the admin port: the proof does not
        // verify, so the public nonce is never even sent.
        let crossed = tmp.path().join("crossed.json");
        publish(&crossed, admin_port, &PUBLIC_NONCE);
        let error = connect(&crossed, PUBLIC_LABEL).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        // The right nonce under the other plane's label fails the same way.
        publish(&crossed, admin_port, &ADMIN_NONCE);
        let error = connect(&crossed, PUBLIC_LABEL).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        // A peer that ignores the proof and presents the public nonce
        // anyway is closed without a frame and never served.
        let mut raw = TcpStream::connect((Ipv4Addr::LOCALHOST, admin_port))
            .await
            .unwrap();
        let mut proof = [0u8; NONCE_BYTES];
        raw.read_exact(&mut proof).await.unwrap();
        raw.write_all(&PUBLIC_NONCE).await.unwrap();
        let mut answer = Vec::new();
        let _ = raw.read_to_end(&mut answer).await;
        assert!(answer.is_empty(), "refused before any frame");

        // The owner of the admin control file is served.
        let mut stream = connect(&admin_control, ADMIN_LABEL).await.unwrap();
        let (_, response) = call(
            &mut stream,
            &client_hello(Via::Direct),
            &envelope("req_admin"),
            Limits::ADMIN.reply_bytes,
        )
        .await
        .unwrap();
        assert_eq!(response, result("req_admin"));
        assert_eq!(
            policy.peers.lock().unwrap().len(),
            1,
            "only the owner was served"
        );
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

/// The handshake budget is separate from the served cap and a peer stalling
/// in it delays no one; a connection over the served cap is admitted first
/// and then told.
#[tokio::test]
async fn stalled_handshakes_are_bounded_and_an_admitted_connection_over_the_cap_is_told() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = tempfile::tempdir().unwrap();
        let control = tmp.path().join("public.json");
        let acceptor =
            LoopbackAcceptor::bind_with_nonce(&control, PUBLIC_LABEL, 1, PUBLIC_NONCE).unwrap();
        let (port, _) = read_control(&control).unwrap();
        let policy = Holding::new(1);
        let listener = Listener::spawn(acceptor, Arc::clone(&policy));

        // One peer takes the proof and then says nothing: it holds the only
        // handshake slot.
        let mut stalled = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut proof = [0u8; NONCE_BYTES];
        stalled.read_exact(&mut proof).await.unwrap();
        // The next connection is closed unanswered: no proof, no frame.
        let mut over = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut nothing = Vec::new();
        let _ = over.read_to_end(&mut nothing).await;
        assert!(nothing.is_empty());
        assert_eq!(policy.started.load(Ordering::SeqCst), 0);

        // The stalled peer goes away; its slot comes back and the listener
        // was never blocked by it.
        drop(stalled);
        let mut held = loop {
            match connect(&control, PUBLIC_LABEL).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        };
        held.write_u8(b'h').await.unwrap();
        eventually(|| policy.started.load(Ordering::SeqCst) == 1).await;

        // Over the served cap: admitted by nonce, then one capacity frame.
        let mut refused = loop {
            match connect(&control, PUBLIC_LABEL).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        };
        assert_eq!(
            error_cause(&mut refused).await,
            cause::CONNECTION_CAPACITY_EXHAUSTED
        );
        assert_eq!(policy.started.load(Ordering::SeqCst), 1);
        policy.gate.add_permits(1);
        eventually(|| listener.available_connections() == 1).await;
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}

#[test]
fn a_control_file_this_build_does_not_understand_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let control = tmp.path().join("public.json");
    // Nothing published: a daemon still booting, or none.
    assert_eq!(
        read_control(&control).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    for content in [
        serde_json::json!({ "schema_version": 2, "port": 4000, "nonce": hex::encode(PUBLIC_NONCE) }),
        serde_json::json!({ "schema_version": 1, "port": 0, "nonce": hex::encode(PUBLIC_NONCE) }),
        serde_json::json!({ "schema_version": 1, "port": 4000, "nonce": "abcd" }),
        serde_json::json!({ "schema_version": 1, "port": 4000, "nonce": "z".repeat(64) }),
        serde_json::json!({ "port": 4000 }),
    ] {
        std::fs::write(&control, serde_json::to_vec(&content).unwrap()).unwrap();
        assert_eq!(
            read_control(&control).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{content}"
        );
    }
    std::fs::write(&control, b"not json").unwrap();
    assert_eq!(
        read_control(&control).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    // Only a regular file is read.
    let directory = tmp.path().join("directory.json");
    std::fs::create_dir(&directory).unwrap();
    assert_eq!(
        read_control(&directory).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

/// A dropped acceptor (its task aborted) still leaves no control file.
#[tokio::test]
async fn a_dropped_acceptor_removes_its_control_file() {
    let tmp = tempfile::tempdir().unwrap();
    let control = tmp.path().join("public.json");
    let acceptor =
        LoopbackAcceptor::bind_with_nonce(&control, PUBLIC_LABEL, MAX_PUBLIC_PENDING, PUBLIC_NONCE)
            .unwrap();
    assert!(control.exists());
    drop(acceptor);
    assert!(!control.exists());
}

/// Windows only: the nonce is fresh per boot, from the operating system.
#[cfg(windows)]
#[tokio::test]
async fn every_bind_mints_a_fresh_nonce() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first.json");
    let second = tmp.path().join("second.json");
    let _a = LoopbackAcceptor::bind(&first, PUBLIC_LABEL, MAX_PUBLIC_PENDING).unwrap();
    let _b = LoopbackAcceptor::bind(&second, PUBLIC_LABEL, MAX_PUBLIC_PENDING).unwrap();
    let (first_port, first_nonce) = read_control(&first).unwrap();
    let (second_port, second_nonce) = read_control(&second).unwrap();
    assert_ne!(first_nonce, second_nonce);
    assert_ne!(first_nonce, [0u8; NONCE_BYTES]);
    assert_ne!(first_port, second_port);
}
