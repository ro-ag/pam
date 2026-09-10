use super::*;

#[crate::async_rt::test]
async fn router_connection_churn_does_not_accumulate_round_robin_identities() {
    let backend = Arc::new(GenericSocketBackend::with_options(
        None,
        SocketType::ROUTER,
        SocketOptions::default(),
    ));
    for _ in 0..1_000 {
        let id = PeerIdentity::new();
        let io = FramedIo::new(
            Box::new(futures::io::empty()),
            Box::new(futures::io::sink()),
        );
        backend.clone().peer_connected(&id, io).await;
        backend.peer_disconnected(&id);
    }
    assert!(backend.round_robin.is_empty());
    assert!(backend.peers.is_empty());
}
