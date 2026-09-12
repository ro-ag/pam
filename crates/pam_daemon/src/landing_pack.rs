//! Bounds a Git smart-HTTP protocol v0 `git-upload-pack` exchange before any
//! byte reaches `git index-pack`. The transport already caps the response at
//! 64 MiB; this module proves the *decoded* and *expanded* shape of the pack
//! is small enough to index safely, using pure-Rust inflate (no C zlib, no
//! sha1 crate — Git verifies the trailer later) and no whole-object
//! buffering. Every violation refuses on first sight; nothing here retries.
#![allow(
    dead_code,
    reason = "preflight-only scaffolding: the guarded landing sync flow wires \
              this module into a live fetch in a follow-up change, but the \
              bounds proof must exist and pass its own tests now"
)]
use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};

/// Fixed scratch output buffer for one inflate call; never grown, never
/// reused to accumulate a whole decoded object.
const INFLATE_SCRATCH_LEN: usize = 8 * 1024;
/// Hard cap on continuation bytes for any of the three varint encodings
/// this module parses, so a hostile pack cannot force an unbounded shift.
const MAX_VARINT_BYTES: u32 = 10;
/// `PACK` magic + u32 version + u32 count, then (elsewhere) a 20-byte
/// trailer; a pack shorter than both is never valid.
const PACK_HEADER_LEN: usize = 12;
const PACK_TRAILER_LEN: usize = 20;

/// Bounds a pack must satisfy before indexing.
#[allow(
    clippy::struct_field_names,
    reason = "the shared `max_` prefix names what these three numbers all are: bounds"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackLimits {
    /// Pack entry count.
    pub max_objects: u32,
    /// Any single decoded object OR delta result size.
    pub max_object_bytes: u64,
    /// Sum over entries of (non-delta: declared size; delta: declared
    /// result size).
    pub max_expanded_bytes: u64,
}

/// What the preflight measured; every number is a hard fact about the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PackBounds {
    pub objects: u32,
    /// `OFS_DELTA` + `REF_DELTA` entries.
    pub deltas: u32,
    /// Total pack length including the 12-byte header and 20-byte trailer.
    pub compressed_bytes: u64,
    /// Sum of inflated entry payloads; delta payloads count as their delta
    /// (not result) size.
    pub decoded_bytes: u64,
    /// See [`PackLimits::max_expanded_bytes`].
    pub expanded_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{cause}: {detail}")]
pub(crate) struct PackError {
    pub cause: &'static str,
    pub detail: String,
}

fn structural(detail: &str) -> PackError {
    PackError {
        cause: "landing_sync_pack_invalid",
        detail: detail.to_owned(),
    }
}
fn bounds(detail: &str) -> PackError {
    PackError {
        cause: "landing_sync_pack_bounds",
        detail: detail.to_owned(),
    }
}
fn request_invalid(detail: &str) -> PackError {
    PackError {
        cause: "landing_sync_request_invalid",
        detail: detail.to_owned(),
    }
}
fn response_invalid() -> PackError {
    PackError {
        cause: "landing_sync_response_invalid",
        detail: "upload-pack response preamble is malformed or missing the pack".to_owned(),
    }
}
fn is_valid_sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}
fn is_lower_hex40(bytes: &[u8]) -> bool {
    bytes.len() == 40
        && bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn push_pkt_line(body: &mut Vec<u8>, payload: &str) {
    let len = payload.len() + 4;
    body.extend_from_slice(format!("{len:04x}").as_bytes());
    body.extend_from_slice(payload.as_bytes());
}

/// Builds the exact v0 upload-pack request body: a `want` pkt-line, a flush,
/// zero to two `have` pkt-lines, then `done`. Refuses unless every sha is 40
/// lowercase hex, non-zero, and `haves.len() <= 2`.
pub(crate) fn upload_pack_request(want: &str, haves: &[&str]) -> Result<Vec<u8>, PackError> {
    if !is_valid_sha40(want) || haves.len() > 2 || haves.iter().any(|have| !is_valid_sha40(have)) {
        return Err(request_invalid(
            "want or have identity is not a valid non-zero 40-hex sha, or too many haves were given",
        ));
    }
    let mut body = Vec::new();
    push_pkt_line(&mut body, &format!("want {want} \n"));
    body.extend_from_slice(b"0000");
    for have in haves {
        push_pkt_line(&mut body, &format!("have {have}\n"));
    }
    push_pkt_line(&mut body, "done\n");
    Ok(body)
}

fn parse_pkt_len(header: &[u8]) -> Result<usize, PackError> {
    let text = std::str::from_utf8(header).map_err(|_| response_invalid())?;
    usize::from_str_radix(text, 16).map_err(|_| response_invalid())
}
fn classify_pkt(payload: &[u8]) -> Result<(), PackError> {
    if payload == b"NAK\n" {
        return Ok(());
    }
    if let Some(rest) = payload.strip_prefix(b"ACK ")
        && rest.len() >= 40
    {
        let (sha, tail) = rest.split_at(40);
        if is_lower_hex40(sha)
            && matches!(tail, b"\n" | b" continue\n" | b" common\n" | b" ready\n")
        {
            return Ok(());
        }
    }
    if let Some(rest) = payload.strip_prefix(b"ERR ") {
        let text = rest.strip_suffix(b"\n").unwrap_or(rest);
        let text = if text.len() > 200 { &text[..200] } else { text };
        return Err(PackError {
            cause: "landing_sync_remote_error",
            detail: String::from_utf8_lossy(text).into_owned(),
        });
    }
    Err(response_invalid())
}

/// Strips the v0 upload-pack response preamble: zero or more pkt-lines that
/// are exactly `NAK\n`, an `ACK <40hex>` line (bare or with `continue` /
/// `common` / `ready`), or a flush; stops at the first raw `PACK` bytes and
/// returns the pack slice. An `ERR <text>` pkt-line refuses with the remote
/// text truncated to 200 bytes; anything else refuses as malformed.
pub(crate) fn strip_upload_pack_preamble(body: &[u8]) -> Result<&[u8], PackError> {
    let mut pos = 0usize;
    loop {
        if body[pos..].starts_with(b"PACK") {
            return Ok(&body[pos..]);
        }
        let header = body.get(pos..pos + 4).ok_or_else(response_invalid)?;
        let length = parse_pkt_len(header)?;
        if length == 0 {
            pos += 4;
            continue;
        }
        if length < 4 {
            return Err(response_invalid());
        }
        let end = pos.checked_add(length).ok_or_else(response_invalid)?;
        let payload = body.get(pos + 4..end).ok_or_else(response_invalid)?;
        classify_pkt(payload)?;
        pos = end;
    }
}

fn parse_size_header(pack: &[u8], pos: &mut usize) -> Result<(u8, u64), PackError> {
    let byte0 = *pack
        .get(*pos)
        .ok_or_else(|| structural("pack entry header is truncated"))?;
    *pos += 1;
    let obj_type = (byte0 >> 4) & 0x7;
    let mut size = u64::from(byte0 & 0x0f);
    let mut shift = 4u32;
    let mut more = byte0 & 0x80 != 0;
    let mut extra = 0u32;
    while more {
        extra += 1;
        if extra > MAX_VARINT_BYTES {
            return Err(structural("pack entry size varint is too long"));
        }
        let byte = *pack
            .get(*pos)
            .ok_or_else(|| structural("pack entry header is truncated"))?;
        *pos += 1;
        if shift >= 64 {
            return Err(structural("pack entry size overflows"));
        }
        size |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        more = byte & 0x80 != 0;
    }
    Ok((obj_type, size))
}
fn parse_ofs_delta_offset(pack: &[u8], pos: &mut usize) -> Result<u64, PackError> {
    let first = *pack
        .get(*pos)
        .ok_or_else(|| structural("ofs-delta offset is truncated"))?;
    *pos += 1;
    let mut n = u64::from(first & 0x7f);
    let mut more = first & 0x80 != 0;
    let mut extra = 0u32;
    while more {
        extra += 1;
        if extra > MAX_VARINT_BYTES {
            return Err(structural("ofs-delta offset varint is too long"));
        }
        let byte = *pack
            .get(*pos)
            .ok_or_else(|| structural("ofs-delta offset is truncated"))?;
        *pos += 1;
        n = n
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| structural("ofs-delta offset overflows"))?;
        n |= u64::from(byte & 0x7f);
        more = byte & 0x80 != 0;
    }
    Ok(n)
}
fn parse_delta_varint(data: &[u8], pos: &mut usize) -> Result<u64, PackError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut extra = 0u32;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| structural("delta payload is too short for its size header"))?;
        *pos += 1;
        extra += 1;
        if extra > MAX_VARINT_BYTES {
            return Err(structural("delta size varint is too long"));
        }
        if shift >= 64 {
            return Err(structural("delta size overflows"));
        }
        result |= u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(result)
}

struct InflatedEntry {
    /// Up to the first 32 inflated bytes, kept only to parse a delta
    /// payload's two size varints; never the whole decoded object.
    prefix: Vec<u8>,
    compressed_len: usize,
}
fn inflate_bounded(
    pack: &[u8],
    start: usize,
    declared_size: u64,
) -> Result<InflatedEntry, PackError> {
    let mut decompress = Decompress::new(true);
    let mut scratch = [0_u8; INFLATE_SCRATCH_LEN];
    let mut prefix = Vec::with_capacity(32);
    loop {
        let consumed = usize::try_from(decompress.total_in())
            .map_err(|_| structural("pack compressed length overflows"))?;
        let input = pack
            .get(start + consumed..)
            .filter(|slice| !slice.is_empty())
            .ok_or_else(|| structural("pack data is truncated inside a zlib stream"))?;
        let prev_in = decompress.total_in();
        let prev_out = decompress.total_out();
        let status = decompress
            .decompress(input, &mut scratch, FlushDecompress::None)
            .map_err(|_| structural("pack entry zlib stream is corrupt"))?;
        let produced = decompress.total_out() - prev_out;
        let advanced = decompress.total_in() - prev_in;
        if produced == 0 && advanced == 0 {
            return Err(structural("pack entry zlib stream made no progress"));
        }
        if prefix.len() < 32 {
            let take = (32 - prefix.len()).min(
                usize::try_from(produced)
                    .map_err(|_| structural("pack entry produced an invalid length"))?,
            );
            prefix.extend_from_slice(&scratch[..take]);
        }
        if decompress.total_out() > declared_size {
            return Err(structural(
                "pack entry inflated length exceeds its declared size",
            ));
        }
        if status == Status::StreamEnd {
            if decompress.total_out() != declared_size {
                return Err(structural(
                    "pack entry inflated length does not match its declared size",
                ));
            }
            let compressed_len = usize::try_from(decompress.total_in())
                .map_err(|_| structural("pack compressed length overflows"))?;
            return Ok(InflatedEntry {
                prefix,
                compressed_len,
            });
        }
    }
}

fn parse_pack_header(pack: &[u8], limits: PackLimits) -> Result<u32, PackError> {
    if pack.len() < PACK_HEADER_LEN + PACK_TRAILER_LEN {
        return Err(structural(
            "pack is smaller than its fixed header and trailer",
        ));
    }
    if pack[..4] != *b"PACK" {
        return Err(structural("pack magic is invalid"));
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != 2 {
        return Err(structural("pack version is not 2"));
    }
    let count = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]);
    if count > limits.max_objects {
        return Err(bounds("pack object count exceeds max_objects"));
    }
    Ok(count)
}
fn classify_entry_type(obj_type: u8) -> Result<bool, PackError> {
    match obj_type {
        1..=4 => Ok(false),
        6 | 7 => Ok(true),
        _ => Err(structural("pack entry has a reserved type")),
    }
}
fn advance_delta_header(
    pack: &[u8],
    obj_type: u8,
    entry_start: usize,
    pos: &mut usize,
) -> Result<(), PackError> {
    match obj_type {
        6 => {
            let offset = parse_ofs_delta_offset(pack, pos)?;
            let offset = usize::try_from(offset)
                .map_err(|_| structural("ofs-delta offset does not fit this pack"))?;
            let base_offset = entry_start
                .checked_sub(offset)
                .ok_or_else(|| structural("ofs-delta base offset is before the pack header"))?;
            if offset == 0 || base_offset < PACK_HEADER_LEN {
                return Err(structural(
                    "ofs-delta base offset does not point strictly before the entry",
                ));
            }
            Ok(())
        }
        7 => {
            *pos = pos
                .checked_add(PACK_TRAILER_LEN)
                .filter(|&end| end <= pack.len())
                .ok_or_else(|| structural("pack is truncated before a ref-delta base"))?;
            Ok(())
        }
        _ => Ok(()),
    }
}
fn expanded_contribution(
    is_delta: bool,
    declared_size: u64,
    prefix: &[u8],
    limits: PackLimits,
) -> Result<u64, PackError> {
    if !is_delta {
        return Ok(declared_size);
    }
    let mut vpos = 0usize;
    let _base_size = parse_delta_varint(prefix, &mut vpos)?;
    let result_size = parse_delta_varint(prefix, &mut vpos)?;
    if result_size > limits.max_object_bytes {
        return Err(bounds("delta result size exceeds max_object_bytes"));
    }
    Ok(result_size)
}

#[derive(Default)]
struct EntryScan {
    deltas: u32,
    decoded_bytes: u64,
    expanded_bytes: u64,
}
fn scan_entry(
    pack: &[u8],
    pos: usize,
    limits: PackLimits,
    scan: &mut EntryScan,
) -> Result<usize, PackError> {
    let entry_start = pos;
    let mut pos = pos;
    let (obj_type, declared_size) = parse_size_header(pack, &mut pos)?;
    let is_delta = classify_entry_type(obj_type)?;
    if declared_size > limits.max_object_bytes {
        return Err(bounds("pack entry declared size exceeds max_object_bytes"));
    }
    advance_delta_header(pack, obj_type, entry_start, &mut pos)?;
    let inflated = inflate_bounded(pack, pos, declared_size)?;
    let pos = pos
        .checked_add(inflated.compressed_len)
        .filter(|&end| end <= pack.len())
        .ok_or_else(|| structural("pack entry runs past the end of the pack"))?;
    scan.decoded_bytes = scan
        .decoded_bytes
        .checked_add(declared_size)
        .ok_or_else(|| structural("decoded byte total overflows"))?;
    let contribution = expanded_contribution(is_delta, declared_size, &inflated.prefix, limits)?;
    if is_delta {
        scan.deltas += 1;
    }
    scan.expanded_bytes = scan
        .expanded_bytes
        .checked_add(contribution)
        .ok_or_else(|| structural("expanded byte total overflows"))?;
    if scan.expanded_bytes > limits.max_expanded_bytes {
        return Err(bounds("running expanded total exceeds max_expanded_bytes"));
    }
    Ok(pos)
}

/// Walks every entry of a version-2 packfile, inflating each zlib stream
/// with a bounded scratch buffer (no whole-object buffering), and enforces
/// `limits`. Refuses on the first structural or bounds violation; see the
/// module doc for the threat model.
pub(crate) fn preflight_pack(pack: &[u8], limits: PackLimits) -> Result<PackBounds, PackError> {
    let count = parse_pack_header(pack, limits)?;
    let mut pos = PACK_HEADER_LEN;
    let mut scan = EntryScan::default();
    for _ in 0..count {
        pos = scan_entry(pack, pos, limits, &mut scan)?;
    }
    if pack.len().checked_sub(pos) != Some(PACK_TRAILER_LEN) {
        return Err(structural(
            "pack has trailing bytes other than its 20-byte trailer",
        ));
    }
    Ok(PackBounds {
        objects: count,
        deltas: scan.deltas,
        compressed_bytes: pack.len() as u64,
        decoded_bytes: scan.decoded_bytes,
        expanded_bytes: scan.expanded_bytes,
    })
}

#[cfg(test)]
#[path = "landing_pack_test.rs"]
mod tests;
