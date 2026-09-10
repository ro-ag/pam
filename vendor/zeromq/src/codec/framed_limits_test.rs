use super::*;

#[test]
fn inbound_permits_cover_both_io_halves_and_refuse_at_capacity() {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let mut permits: Vec<_> = (0..MAX_INBOUND_PEERS)
        .map(|_| InboundPermit::acquire_from(&COUNT).unwrap())
        .collect();
    assert!(InboundPermit::acquire_from(&COUNT).is_none());
    let io = FramedIo::new(
        Box::new(futures::io::empty()),
        Box::new(futures::io::sink()),
    )
    .with_inbound_permit(permits.pop().unwrap());
    let (read, write) = io.into_parts();
    drop(read);
    assert!(InboundPermit::acquire_from(&COUNT).is_none());
    drop(write);
    let replacement = InboundPermit::acquire_from(&COUNT).unwrap();
    assert!(InboundPermit::acquire_from(&COUNT).is_none());
    drop(replacement);
    drop(permits);
    assert_eq!(COUNT.load(Ordering::Acquire), 0);
}
