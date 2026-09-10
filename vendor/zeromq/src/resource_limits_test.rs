use crate::{
    codec::InboundPermit, DealerSocket, RouterSocket, Socket, SocketRecv, SocketSend, ZmqMessage,
};
use std::time::Duration;
use tokio::{io::AsyncReadExt, net::TcpStream, time::timeout};

#[tokio::test]
async fn inbound_cap_timeout_and_paused_receiver_backpressure() {
    let mut router = RouterSocket::new();
    let endpoint = router.bind("tcp://127.0.0.1:0").await.unwrap().to_string();
    let address = endpoint.strip_prefix("tcp://").unwrap();
    // Reserve all but one global permit: a real incomplete handshake must consume
    // the last slot before spawning, and must release it at its deadline.
    let reservations: Vec<_> = (0..255)
        .map(|_| InboundPermit::acquire().unwrap())
        .collect();
    let mut stalled = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(2), stalled.read_exact(&mut [0_u8; 64]))
        .await
        .unwrap()
        .unwrap();
    assert!(InboundPermit::acquire().is_none());
    let mut refused = TcpStream::connect(address).await.unwrap();
    let refused_result = timeout(Duration::from_secs(2), refused.read(&mut [0_u8; 1]))
        .await
        .unwrap();
    assert!(matches!(refused_result, Ok(0) | Err(_)));
    assert_eq!(
        timeout(Duration::from_secs(7), stalled.read(&mut [0_u8; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let released = InboundPermit::acquire().expect("timed-out handshake released its permit");
    drop(released);
    drop(reservations);

    let mut dealer = DealerSocket::new();
    dealer.connect(&endpoint).await.unwrap();
    let message = ZmqMessage::from(vec![b'x'; 1024 * 1024]);
    let sending = async {
        for _ in 0..64 {
            dealer.send(message.clone()).await.unwrap();
        }
    };
    tokio::pin!(sending);
    // A receiver which stops polling must not drain into a background message queue.
    assert!(timeout(Duration::from_millis(200), &mut sending)
        .await
        .is_err());
    timeout(Duration::from_secs(15), async {
        tokio::join!(&mut sending, async {
            for _ in 0..64 {
                let message = router.recv().await.unwrap();
                assert_eq!(message.get(1).unwrap().len(), 1024 * 1024);
            }
        });
    })
    .await
    .unwrap();
}
