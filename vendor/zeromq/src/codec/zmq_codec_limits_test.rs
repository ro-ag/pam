//! PAM-specific bounded decoder regression tests; no native libzmq required.
use super::zmq_codec::{MAX_FRAME_BYTES, MAX_MESSAGE_BYTES, MAX_MESSAGE_FRAMES};
use super::{Message, ZmqCodec, ZmqGreeting};
use asynchronous_codec::{Decoder, Encoder};
use bytes::{BufMut, BytesMut};

fn ready_codec() -> ZmqCodec {
    let mut codec = ZmqCodec::new();
    let mut greeting = BytesMut::new();
    codec
        .encode(Message::Greeting(ZmqGreeting::default()), &mut greeting)
        .unwrap();
    assert!(matches!(
        codec.decode(&mut greeting).unwrap(),
        Some(Message::Greeting(_))
    ));
    codec
}

fn header(length: u64, more: bool) -> BytesMut {
    let mut bytes = BytesMut::with_capacity(9);
    bytes.put_u8(2 | u8::from(more));
    bytes.put_u64(length);
    bytes
}

fn frame(length: usize, more: bool) -> BytesMut {
    let mut bytes = header(length as u64, more);
    bytes.resize(bytes.len() + length, b'x');
    bytes
}

#[test]
fn huge_declared_lengths_fail_on_header_without_reserving_payload_memory() {
    for length in [MAX_FRAME_BYTES as u64 + 1, u64::MAX] {
        let mut codec = ready_codec();
        let mut bytes = header(length, false);
        let capacity = bytes.capacity();
        assert!(codec.decode(&mut bytes).is_err());
        assert!(bytes.capacity() <= capacity);
    }
}

#[test]
fn command_frames_obey_the_same_preallocation_cap() {
    let mut codec = ready_codec();
    let mut bytes = header(u64::MAX, false);
    bytes[0] |= 4;
    let capacity = bytes.capacity();
    assert!(codec.decode(&mut bytes).is_err());
    assert!(bytes.capacity() <= capacity);
}

#[test]
fn excess_empty_more_frames_cannot_accumulate_or_recurse_without_bound() {
    let mut codec = ready_codec();
    for _ in 0..MAX_MESSAGE_FRAMES {
        assert!(codec
            .decode(&mut BytesMut::from(&[1, 0][..]))
            .unwrap()
            .is_none());
    }
    assert!(codec.decode(&mut BytesMut::from(&[1, 0][..])).is_err());
}

#[test]
fn multipart_aggregate_rejects_next_header_before_body_reservation() {
    let mut codec = ready_codec();
    assert_eq!(MAX_MESSAGE_BYTES, 2 * MAX_FRAME_BYTES);
    for length in [MAX_FRAME_BYTES, MAX_FRAME_BYTES - 18] {
        assert!(codec.decode(&mut frame(length, true)).unwrap().is_none());
    }
    let mut next = header(1, false);
    let capacity = next.capacity();
    assert!(codec.decode(&mut next).is_err());
    assert!(next.capacity() <= capacity);
}

#[test]
fn routing_identity_and_one_mib_payload_fit_and_counters_reset() {
    let mut codec = ready_codec();
    for _ in 0..2 {
        assert!(codec.decode(&mut frame(255, true)).unwrap().is_none());
        assert!(codec.decode(&mut frame(0, true)).unwrap().is_none());
        let message = codec
            .decode(&mut frame(MAX_FRAME_BYTES, false))
            .unwrap()
            .unwrap();
        let Message::Message(message) = message else {
            panic!("expected payload");
        };
        let frames = message.into_vec();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].len(), 255);
        assert_eq!(frames[2].len(), MAX_FRAME_BYTES);
    }
}

#[test]
fn exact_multipart_byte_and_frame_boundaries_are_accepted() {
    let mut codec = ready_codec();
    for _ in 0..3 {
        assert!(codec
            .decode(&mut frame(MAX_MESSAGE_BYTES / 4 - 9, true))
            .unwrap()
            .is_none());
    }
    let message = codec
        .decode(&mut frame(MAX_MESSAGE_BYTES / 4 - 9, false))
        .unwrap()
        .unwrap();
    assert!(matches!(message, Message::Message(_)));
}
