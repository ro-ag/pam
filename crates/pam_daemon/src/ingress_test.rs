use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use tokio::sync::mpsc;

use crate::ingress::{Ingress, IngressError, Origin, PeerIdentity, PublicPeer};

fn envelope(id: &str) -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: id.to_owned(),
        capability: "echo".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            // A label is attribution only, whatever it claims.
            agent: "pam-gui".to_owned(),
            repo: "/repo".to_owned(),
            pid: 1,
        },
        args: serde_json::json!({}),
        idempotency_key: None,
        deadline_ms: 5_000,
        wait: true,
    }
}

fn answer(id: &str) -> Response {
    Response::Result {
        id: id.to_owned(),
        outcome: Outcome::Solved,
        body: serde_json::json!({}),
        evidence: Vec::new(),
    }
}

#[test]
fn a_peer_identity_reports_only_what_the_kernel_said() {
    let unix = PeerIdentity::Unix {
        uid: 501,
        gid: 20,
        pid: Some(4242),
    };
    assert_eq!((unix.uid(), unix.pid()), (Some(501), Some(4242)));
    // A platform that reports no pid records none, never a guess.
    let no_pid = PeerIdentity::Unix {
        uid: 501,
        gid: 20,
        pid: None,
    };
    assert_eq!((no_pid.uid(), no_pid.pid()), (Some(501), None));
    // Windows: the holder of the owner nonce has neither.
    assert_eq!(
        (
            PeerIdentity::OwnerNonce.uid(),
            PeerIdentity::OwnerNonce.pid()
        ),
        (None, None)
    );
}

#[tokio::test]
async fn the_seam_hands_the_core_one_request_with_its_origin_and_peer_and_returns_its_answer() {
    let (incoming, mut core) = mpsc::channel(4);
    let ingress = Ingress::new(incoming);
    let peer = PublicPeer {
        identity: PeerIdentity::Unix {
            uid: 501,
            gid: 20,
            pid: Some(4242),
        },
        relayed: true,
    };
    let serving = tokio::spawn(async move {
        let request = core.recv().await.expect("one request");
        let seen = (request.origin, request.peer, request.envelope.clone());
        request.reply.send(answer(&request.envelope.id)).unwrap();
        // The second request is accepted and never answered.
        let dropped = core.recv().await.expect("a second request");
        drop(dropped.reply);
        (seen, dropped.origin, dropped.peer)
    });

    let response = ingress
        .call(Origin::Public, Some(peer), envelope("req_seam"))
        .await
        .unwrap();
    assert_eq!(response, answer("req_seam"));
    // A handler that went away without answering is named, not a hang.
    let unanswered = ingress
        .call(Origin::Admin, None, envelope("req_lost"))
        .await;
    assert_eq!(unanswered.unwrap_err(), IngressError::Unanswered);

    let ((origin, seen_peer, seen_envelope), second_origin, second_peer) = serving.await.unwrap();
    assert_eq!(origin, Origin::Public);
    assert_eq!(seen_peer, Some(peer));
    assert_eq!(seen_envelope, envelope("req_seam"));
    // The label did not change the plane the request arrived on.
    assert_eq!((second_origin, second_peer), (Origin::Admin, None));

    // The core is gone: nothing can answer any more.
    let closed = ingress
        .submit(Origin::Public, Some(peer), envelope("req_late"))
        .await;
    assert_eq!(closed.unwrap_err(), IngressError::Closed);
}

/// What goes onto the request row: the plane, and the kernel's view of the
/// peer for a public request only.
#[test]
fn the_recorded_origin_is_the_plane_and_the_public_peer() {
    use pam_store::{RequestIngress, RequestOrigin};

    use crate::ingress::recorded;

    let unix = PublicPeer {
        identity: PeerIdentity::Unix {
            uid: 501,
            gid: 20,
            pid: Some(4242),
        },
        relayed: true,
    };
    assert_eq!(
        recorded(Origin::Public, Some(unix)),
        RequestOrigin {
            ingress: RequestIngress::Public,
            peer_uid: Some(501),
            peer_pid: Some(4242),
            relayed: true,
        }
    );
    // A platform that reports no pid records none, never a guess.
    let no_pid = PublicPeer {
        identity: PeerIdentity::Unix {
            uid: 501,
            gid: 20,
            pid: None,
        },
        relayed: false,
    };
    assert_eq!(recorded(Origin::Public, Some(no_pid)).peer_pid, None);
    // Windows proves ownership of the control file, not a process.
    let nonce = PublicPeer {
        identity: PeerIdentity::OwnerNonce,
        relayed: false,
    };
    assert_eq!(recorded(Origin::Public, Some(nonce)), RequestOrigin::PUBLIC);
    // The legacy listener cannot ask the kernel.
    assert_eq!(recorded(Origin::Public, None), RequestOrigin::PUBLIC);
    // An administration submission is in process: no peer is claimed for it.
    assert_eq!(recorded(Origin::Admin, Some(unix)), RequestOrigin::ADMIN);

    // And back: a leased execution reads its origin from the row.
    assert_eq!(Origin::of_row(&RequestOrigin::ADMIN), Origin::Admin);
    assert_eq!(
        Origin::of_row(&recorded(Origin::Public, Some(unix))),
        Origin::Public
    );
    assert_eq!(Origin::Admin.wire(), pam_proto::wire::Ingress::Admin);
    assert_eq!(Origin::Public.wire(), pam_proto::wire::Ingress::Public);
}
