//! The unix endpoint against a real socket: file mode, stale handling, the
//! kernel's peer credentials, and the listener's lifecycle on a real path.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use pam_proto::wire::{MAX_FRAME_BYTES, Via, cause};
use tokio::io::AsyncWriteExt;

use crate::framed::{Accept, Limits, Listener, call, client_hello};
use crate::framed_test::{Answering, Holding, PATIENCE, envelope, error_cause, eventually, result};
use crate::framed_unix::{UnixAcceptor, connect, own_identity, peer_identity};
use crate::ingress::PeerIdentity;
use crate::runtime_dir::MAX_SOCKET_PATH_BYTES;

/// A directory short enough for a unix socket path.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("pam")
        .tempdir_in("/tmp")
        .expect("tempdir under /tmp")
}

/// The uid this test process creates files as.
fn own_uid(dir: &std::path::Path) -> u32 {
    let probe = dir.join("uid-probe");
    std::fs::write(&probe, b"").unwrap();
    std::fs::metadata(&probe).unwrap().uid()
}

#[tokio::test]
async fn bind_replaces_a_stale_file_and_leaves_an_owner_only_socket() {
    let tmp = short_dir();
    let path = tmp.path().join("pam.sock");
    // What a dead daemon left behind.
    std::fs::write(&path, b"stale").unwrap();
    let acceptor = UnixAcceptor::bind(&path).unwrap();
    assert_eq!(acceptor.path(), path);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // tokio's listener does not unlink on drop; the acceptor does.
    drop(acceptor);
    assert!(!path.exists());
}

#[tokio::test]
async fn an_over_long_path_is_refused_with_the_limit_before_anything_is_touched() {
    let tmp = short_dir();
    let long = tmp.path().join("x".repeat(MAX_SOCKET_PATH_BYTES));
    let error = UnixAcceptor::bind(&long).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("104"), "{error}");
    assert!(!long.exists());
}

#[tokio::test]
async fn an_accepted_connection_carries_the_kernels_view_of_this_process() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = short_dir();
        let path = tmp.path().join("pam.sock");
        let mut acceptor = UnixAcceptor::bind(&path).unwrap();
        let client = connect(&path).await.unwrap();
        let (server, peer) = acceptor.accept().await.unwrap();

        let PeerIdentity::Unix { uid, gid, pid } = peer else {
            panic!("a unix peer has kernel credentials, got {peer:?}");
        };
        assert_eq!(uid, own_uid(tmp.path()));
        assert_eq!(pid, Some(std::process::id()));
        // Both ends are this process, and a local pair says the same.
        assert_eq!(peer, own_identity().unwrap());
        assert_eq!(peer, peer_identity(&client).unwrap());
        assert_eq!(peer, peer_identity(&server).unwrap());
        assert_eq!((peer.uid(), peer.pid()), (Some(uid), pid));
        let PeerIdentity::Unix { gid: own_gid, .. } = own_identity().unwrap() else {
            panic!("own identity is a unix identity");
        };
        assert_eq!(gid, own_gid);

        // Closing unlinks the socket and ends accepting.
        acceptor.close();
        assert!(!path.exists());
        let error = acceptor.accept().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(
            connect(&path).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_listener_on_a_real_socket_serves_records_the_peer_and_unlinks_at_shutdown() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = short_dir();
        let path = tmp.path().join("pam.sock");
        let policy = Answering::new(Limits::PUBLIC);
        let listener = Listener::spawn(UnixAcceptor::bind(&path).unwrap(), Arc::clone(&policy));

        for id in ["req_first", "req_second"] {
            let mut stream = connect(&path).await.unwrap();
            let request = envelope(id);
            let (_, response) = call(
                &mut stream,
                &client_hello(Via::Direct),
                &request,
                MAX_FRAME_BYTES,
            )
            .await
            .unwrap();
            assert_eq!(response, result(id));
        }
        let expected = PeerIdentity::Unix {
            uid: own_uid(tmp.path()),
            gid: match own_identity().unwrap() {
                PeerIdentity::Unix { gid, .. } => gid,
                PeerIdentity::OwnerNonce => panic!("own identity is a unix identity"),
            },
            pid: Some(std::process::id()),
        };
        assert_eq!(*policy.peers.lock().unwrap(), vec![expected, expected]);

        listener.shutdown().await;
        assert!(!path.exists(), "the socket file is unlinked at shutdown");
        assert_eq!(
            connect(&path).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_real_connection_over_the_cap_reads_the_capacity_frame() {
    tokio::time::timeout(PATIENCE, async {
        let tmp = short_dir();
        let path = tmp.path().join("pam.sock");
        let policy = Holding::new(1);
        let listener = Listener::spawn(UnixAcceptor::bind(&path).unwrap(), Arc::clone(&policy));

        let mut held = connect(&path).await.unwrap();
        held.write_u8(b'h').await.unwrap();
        eventually(|| policy.started.load(Ordering::SeqCst) == 1).await;

        // The one non-blocking write goes out through the real descriptor.
        let mut refused = connect(&path).await.unwrap();
        assert_eq!(
            error_cause(&mut refused).await,
            cause::CONNECTION_CAPACITY_EXHAUSTED
        );
        assert_eq!(policy.started.load(Ordering::SeqCst), 1);

        // The slot comes back when the held connection ends.
        policy.gate.add_permits(1);
        eventually(|| listener.available_connections() == 1).await;
        let mut again = connect(&path).await.unwrap();
        again.write_u8(b'h').await.unwrap();
        eventually(|| policy.started.load(Ordering::SeqCst) == 2).await;
        policy.gate.add_permits(1);
        eventually(|| listener.available_connections() == 1).await;
        listener.shutdown().await;
    })
    .await
    .expect("test within deadline");
}
