use super::{
    PackBounds, PackError, PackLimits, preflight_pack, strip_upload_pack_preamble,
    upload_pack_request,
};
use flate2::{Compression, write::ZlibEncoder};
use std::io::Write as _;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccc"; // deliberately 42 chars (bad length)

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib encode");
    encoder.finish().expect("zlib finish")
}
fn encode_size_header(obj_type: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = size >> 4;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "size & 0x0f always fits a u8, test fixture builder only"
    )]
    let mut first = (obj_type << 4) | ((size & 0x0f) as u8);
    if rest > 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest > 0 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "rest & 0x7f always fits a u8, test fixture builder only"
        )]
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}
fn encode_ofs_delta_offset(mut n: u64) -> Vec<u8> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "n & 0x7f always fits a u8, test fixture builder only"
    )]
    let mut bytes = vec![(n & 0x7f) as u8];
    n >>= 7;
    while n > 0 {
        n -= 1;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "n & 0x7f always fits a u8, test fixture builder only"
        )]
        let byte = 0x80 | ((n & 0x7f) as u8);
        bytes.push(byte);
        n >>= 7;
    }
    bytes.reverse();
    bytes
}
fn encode_delta_varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "n & 0x7f always fits a u8, test fixture builder only"
        )]
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
    out
}
fn delta_payload(base_size: u64, result_size: u64, filler_len: usize) -> Vec<u8> {
    let mut out = encode_delta_varint(base_size);
    out.extend(encode_delta_varint(result_size));
    out.extend(std::iter::repeat_n(0xAA_u8, filler_len));
    out
}
fn position(body: &[u8]) -> usize {
    12 + body.len()
}
fn push_entry(body: &mut Vec<u8>, obj_type: u8, payload: &[u8]) -> usize {
    let start = position(body);
    body.extend(encode_size_header(
        obj_type,
        u64::try_from(payload.len()).expect("test payload fits u64"),
    ));
    body.extend(zlib(payload));
    start
}
fn push_ofs_delta(body: &mut Vec<u8>, base_start: usize, payload: &[u8]) -> usize {
    let start = position(body);
    body.extend(encode_size_header(
        6,
        u64::try_from(payload.len()).expect("test payload fits u64"),
    ));
    body.extend(encode_ofs_delta_offset(
        u64::try_from(start - base_start).expect("test offset fits u64"),
    ));
    body.extend(zlib(payload));
    start
}
fn push_ref_delta(body: &mut Vec<u8>, base_id: [u8; 20], payload: &[u8]) -> usize {
    let start = position(body);
    body.extend(encode_size_header(
        7,
        u64::try_from(payload.len()).expect("test payload fits u64"),
    ));
    body.extend_from_slice(&base_id);
    body.extend(zlib(payload));
    start
}
fn finish_pack(body: &[u8], count: u32, trailer: &[u8]) -> Vec<u8> {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&count.to_be_bytes());
    pack.extend_from_slice(body);
    pack.extend_from_slice(trailer);
    pack
}
fn generous_limits() -> PackLimits {
    PackLimits {
        max_objects: 1_000,
        max_object_bytes: 1_000_000,
        max_expanded_bytes: 10_000_000,
    }
}
fn assert_refused<T: std::fmt::Debug>(result: Result<T, PackError>) -> PackError {
    match result {
        Ok(value) => panic!("expected a refusal, got {value:?}"),
        Err(err) => err,
    }
}

// -- upload_pack_request -----------------------------------------------

#[test]
fn request_body_zero_haves() {
    let body = upload_pack_request(SHA_A, &[]).expect("valid want");
    let expected = format!("0033want {SHA_A} \n0000") + "0009done\n";
    assert_eq!(body, expected.into_bytes());
}
#[test]
fn request_body_one_have() {
    let body = upload_pack_request(SHA_A, &[SHA_B]).expect("valid want/have");
    let expected =
        format!("0033want {SHA_A} \n0000") + &format!("0032have {SHA_B}\n") + "0009done\n";
    assert_eq!(body, expected.into_bytes());
}
#[test]
fn request_body_two_haves() {
    let body = upload_pack_request(SHA_A, &[SHA_B, SHA_A]).expect("valid want/haves");
    let expected = format!("0033want {SHA_A} \n0000")
        + &format!("0032have {SHA_B}\n")
        + &format!("0032have {SHA_A}\n")
        + "0009done\n";
    assert_eq!(body, expected.into_bytes());
}
#[test]
fn request_refuses_three_haves() {
    assert!(upload_pack_request(SHA_A, &[SHA_A, SHA_B, SHA_A]).is_err());
}
#[test]
fn request_refuses_bad_sha_shape() {
    assert!(upload_pack_request(SHA_C, &[]).is_err());
    assert!(upload_pack_request("not-hex", &[]).is_err());
    assert!(upload_pack_request(SHA_A, &[SHA_C]).is_err());
}
#[test]
fn request_refuses_zero_sha() {
    let zero = "0".repeat(40);
    assert!(upload_pack_request(&zero, &[]).is_err());
    assert!(upload_pack_request(SHA_A, &[&zero]).is_err());
}

// -- strip_upload_pack_preamble ------------------------------------------

fn pkt(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() + 4;
    let mut out = format!("{len:04x}").into_bytes();
    out.extend_from_slice(payload);
    out
}

#[test]
fn preamble_strips_nak() {
    let mut body = pkt(b"NAK\n");
    body.extend_from_slice(b"PACKrest-of-pack");
    let pack = strip_upload_pack_preamble(&body).expect("NAK preamble is valid");
    assert_eq!(pack, b"PACKrest-of-pack");
}
#[test]
fn preamble_strips_ack() {
    let mut body = pkt(format!("ACK {SHA_A}\n").as_bytes());
    body.extend_from_slice(b"PACKmore");
    let pack = strip_upload_pack_preamble(&body).expect("ACK preamble is valid");
    assert_eq!(pack, b"PACKmore");
}
#[test]
fn preamble_strips_ack_continue_common_ready() {
    for suffix in [" continue", " common", " ready"] {
        let mut body = pkt(format!("ACK {SHA_A}{suffix}\n").as_bytes());
        body.extend_from_slice(b"PACKtail");
        let pack = strip_upload_pack_preamble(&body).expect("ACK <state> preamble is valid");
        assert_eq!(pack, b"PACKtail");
    }
}
#[test]
fn preamble_strips_flush_then_pack() {
    let mut body = b"0000".to_vec();
    body.extend_from_slice(b"PACKdata");
    let pack = strip_upload_pack_preamble(&body).expect("flush preamble is valid");
    assert_eq!(pack, b"PACKdata");
}
#[test]
fn preamble_refuses_err_line() {
    let body = pkt(b"ERR access denied\n");
    let err = assert_refused(strip_upload_pack_preamble(&body));
    assert_eq!(err.cause, "landing_sync_remote_error");
    assert_eq!(err.detail, "access denied");
}
#[test]
fn preamble_refuses_garbage() {
    assert!(strip_upload_pack_preamble(b"junk-not-a-pktline").is_err());
    assert!(strip_upload_pack_preamble(b"").is_err());
    assert!(strip_upload_pack_preamble(b"0004").is_err());
}

// -- preflight_pack: a valid mixed pack -----------------------------------

#[test]
fn preflight_accepts_a_mixed_pack_and_reports_exact_bounds() {
    let blob_data = b"hello world".to_vec();
    let commit_data = b"tree deadbeef\nparent cafebabe\nauthor a <a@a> 0 +0000\n".to_vec();
    let ofs_result_size: u64 = 20;
    let ofs_payload = delta_payload(u64::try_from(blob_data.len()).unwrap(), ofs_result_size, 5);
    let ref_result_size: u64 = 50;
    let ref_payload = delta_payload(99, ref_result_size, 3);

    let mut body = Vec::new();
    let blob_start = push_entry(&mut body, 3, &blob_data);
    push_entry(&mut body, 1, &commit_data);
    push_ofs_delta(&mut body, blob_start, &ofs_payload);
    push_ref_delta(&mut body, [7_u8; 20], &ref_payload);
    let pack = finish_pack(&body, 4, &[0_u8; 20]);

    let bounds = preflight_pack(&pack, generous_limits()).expect("mixed pack is within bounds");

    let expected_decoded = u64::try_from(blob_data.len()).unwrap()
        + u64::try_from(commit_data.len()).unwrap()
        + u64::try_from(ofs_payload.len()).unwrap()
        + u64::try_from(ref_payload.len()).unwrap();
    let expected_expanded = u64::try_from(blob_data.len()).unwrap()
        + u64::try_from(commit_data.len()).unwrap()
        + ofs_result_size
        + ref_result_size;
    assert_eq!(
        bounds,
        PackBounds {
            objects: 4,
            deltas: 2,
            compressed_bytes: u64::try_from(pack.len()).unwrap(),
            decoded_bytes: expected_decoded,
            expanded_bytes: expected_expanded,
        }
    );
}

// -- preflight_pack: refusals ----------------------------------------------

#[test]
fn preflight_refuses_wrong_version() {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&3_u32.to_be_bytes());
    pack.extend_from_slice(&0_u32.to_be_bytes());
    pack.extend_from_slice(&[0_u8; 20]);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}
#[test]
fn preflight_refuses_count_over_limit() {
    let pack = finish_pack(&[], 2, &[0_u8; 20]);
    let limits = PackLimits {
        max_objects: 1,
        ..generous_limits()
    };
    let err = assert_refused(preflight_pack(&pack, limits));
    assert_eq!(err.cause, "landing_sync_pack_bounds");
}
#[test]
fn preflight_refuses_reserved_type() {
    for reserved in [0_u8, 5_u8] {
        let mut body = Vec::new();
        push_entry(&mut body, reserved, b"whatever");
        let pack = finish_pack(&body, 1, &[0_u8; 20]);
        let err = assert_refused(preflight_pack(&pack, generous_limits()));
        assert_eq!(err.cause, "landing_sync_pack_invalid");
    }
}
#[test]
fn preflight_refuses_declared_size_over_limit() {
    let mut body = Vec::new();
    push_entry(&mut body, 3, b"123456");
    let pack = finish_pack(&body, 1, &[0_u8; 20]);
    let limits = PackLimits {
        max_object_bytes: 5,
        ..generous_limits()
    };
    let err = assert_refused(preflight_pack(&pack, limits));
    assert_eq!(err.cause, "landing_sync_pack_bounds");
}
#[test]
fn preflight_refuses_delta_result_over_limit() {
    let payload = delta_payload(1, 1_000, 3);
    let mut body = Vec::new();
    push_ref_delta(&mut body, [1_u8; 20], &payload);
    let pack = finish_pack(&body, 1, &[0_u8; 20]);
    let limits = PackLimits {
        max_object_bytes: 500,
        ..generous_limits()
    };
    let err = assert_refused(preflight_pack(&pack, limits));
    assert_eq!(err.cause, "landing_sync_pack_bounds");
}
#[test]
fn preflight_refuses_expanded_total_over_limit() {
    let mut body = Vec::new();
    push_entry(&mut body, 3, &[0_u8; 10]);
    push_entry(&mut body, 3, &[1_u8; 10]);
    let pack = finish_pack(&body, 2, &[0_u8; 20]);
    let limits = PackLimits {
        max_expanded_bytes: 15,
        ..generous_limits()
    };
    let err = assert_refused(preflight_pack(&pack, limits));
    assert_eq!(err.cause, "landing_sync_pack_bounds");
}
#[test]
fn preflight_refuses_inflated_length_mismatch() {
    let mut body = Vec::new();
    body.extend(encode_size_header(3, 10)); // declares 10 bytes
    body.extend(zlib(&[9_u8; 8])); // actually inflates to 8 bytes
    let pack = finish_pack(&body, 1, &[0_u8; 20]);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}
#[test]
fn preflight_refuses_truncated_stream() {
    let data = vec![b'x'; 128];
    let compressed = zlib(&data);
    let mut body = Vec::new();
    body.extend(encode_size_header(3, u64::try_from(data.len()).unwrap()));
    body.extend_from_slice(&compressed[..compressed.len() / 2]);
    // No trailer: the pack ends exactly inside the zlib stream.
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2_u32.to_be_bytes());
    pack.extend_from_slice(&1_u32.to_be_bytes());
    pack.extend_from_slice(&body);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}
#[test]
fn preflight_refuses_corrupt_zlib() {
    let mut body = Vec::new();
    let data = b"some reasonably sized payload for corruption";
    let mut corrupted = zlib(data);
    corrupted[2] ^= 0xFF;
    body.extend(encode_size_header(3, u64::try_from(data.len()).unwrap()));
    body.extend_from_slice(&corrupted);
    let pack = finish_pack(&body, 1, &[0_u8; 20]);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}
#[test]
fn preflight_refuses_extra_trailing_bytes() {
    let mut body = Vec::new();
    push_entry(&mut body, 3, b"abc");
    let mut trailer = vec![0_u8; 20];
    trailer.push(0xFF);
    let pack = finish_pack(&body, 1, &trailer);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}
#[test]
fn preflight_refuses_ofs_delta_pointing_at_itself() {
    let mut body = Vec::new();
    let payload = delta_payload(1, 1, 2);
    body.extend(encode_size_header(6, u64::try_from(payload.len()).unwrap()));
    body.extend(encode_ofs_delta_offset(0)); // offset 0: points at itself
    body.extend(zlib(&payload));
    let pack = finish_pack(&body, 1, &[0_u8; 20]);
    let err = assert_refused(preflight_pack(&pack, generous_limits()));
    assert_eq!(err.cause, "landing_sync_pack_invalid");
}

// -- integration: a real git-produced pack --------------------------------

#[test]
fn preflight_accepts_a_real_git_pack() {
    let Ok(version) = std::process::Command::new("git").arg("--version").output() else {
        return;
    };
    if !version.status.success() {
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let repo = dir.path();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("git command runs")
    };
    assert!(git(&["init", "-q"]).status.success());
    std::fs::write(repo.join("a.txt"), b"one\n").expect("write file");
    assert!(git(&["add", "a.txt"]).status.success());
    assert!(
        git(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "first"])
            .status
            .success()
    );
    std::fs::write(repo.join("a.txt"), b"two\n").expect("write file");
    assert!(git(&["add", "a.txt"]).status.success());
    assert!(
        git(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "second"])
            .status
            .success()
    );

    let listed = git(&["rev-list", "--objects", "HEAD"]);
    assert!(listed.status.success());
    let expected_objects = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .count();

    let mut child = std::process::Command::new("git")
        .args(["pack-objects", "--revs", "--stdout"])
        .current_dir(repo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn git pack-objects");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"HEAD\n")
        .expect("feed pack-objects");
    let output = child
        .wait_with_output()
        .expect("git pack-objects completes");
    assert!(output.status.success());

    let bounds =
        preflight_pack(&output.stdout, generous_limits()).expect("real pack is within bounds");
    assert_eq!(bounds.objects, u32::try_from(expected_objects).unwrap());
}
