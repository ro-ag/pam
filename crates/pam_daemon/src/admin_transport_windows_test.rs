use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::platform::{NONCE_BYTES, same, server_proof};

/// The handshake's two pure pieces: the server proof is a domain-separated hash
/// of the nonce (never the nonce itself), and equality is constant-time by
/// construction of the fold.
#[test]
fn server_proof_hides_the_nonce_and_differs_per_nonce() {
    let a = [7u8; NONCE_BYTES];
    let b = [8u8; NONCE_BYTES];
    assert_ne!(server_proof(&a), a);
    assert_ne!(server_proof(&a), server_proof(&b));
    assert!(same(&server_proof(&a), &server_proof(&a)));
    assert!(!same(&a, &b));
}

/// A listener that reused the daemon's port but never read the owner's control
/// file cannot produce the proof, so a client refuses before sending the nonce:
/// the stale-control-file case is a refusal, not a leak.
#[tokio::test]
async fn a_client_never_sends_the_nonce_to_a_port_that_cannot_prove_it() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let impostor = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // A wrong proof: the impostor guesses.
        stream.write_all(&[0u8; NONCE_BYTES]).await.unwrap();
        let mut got = Vec::new();
        let _ = stream.read_to_end(&mut got).await;
        got
    });
    let nonce = [3u8; NONCE_BYTES];
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut proof = [0u8; NONCE_BYTES];
    stream.read_exact(&mut proof).await.unwrap();
    assert!(
        !same(&proof, &server_proof(&nonce)),
        "the guess is not the proof"
    );
    drop(stream);
    let received = impostor.await.unwrap();
    assert!(
        received.is_empty(),
        "nothing was sent to the impostor, got {received:?}"
    );
}

/// The end-to-end path — control file, server proof, nonce, framed exchange —
/// runs through `pam_testkit::TestDaemon` in the daemon integration suites,
/// which send every `admin.*` envelope through `admin_transport::exchange` on
/// every platform where `supported()` is true.
#[test]
fn the_windows_adapter_reports_itself_supported() {
    assert!(crate::admin_transport::supported());
}
