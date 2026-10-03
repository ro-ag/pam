//! An evidence view's bytes, stored as fixed-size chunks with one digest
//! each (schema 20).
//!
//! A view can reach 64 MiB and a page is at most 64 KiB. Kept as one blob,
//! every page read made the engine load the whole view to cut the page out
//! of it. Kept as [`CHUNK_BYTES`] chunks, a page read loads the one or two
//! chunks it covers, and checks each against the SHA-256 recorded when the
//! view was written before a byte of it is served: bytes that changed on
//! disk are refused as corrupt, never handed out under the view's digest.
//! The chunk size is recorded per view (`evidence_view.chunk_bytes`), so a
//! later binary can choose another without rewriting old views.

use std::ops::Range;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::StoreError;

/// The chunk size of every view this binary writes: the largest page a
/// read may ask for, so a page spans at most two chunks and a default
/// 16 KiB page loads and checks one.
pub(crate) const CHUNK_BYTES: usize = 64 * 1024;

/// One chunk of a view about to be written: where it sits and its digest.
pub(crate) struct PlannedChunk {
    pub(crate) seq: i64,
    pub(crate) sha256: String,
    pub(crate) range: Range<usize>,
}

/// Cuts `bytes` into [`CHUNK_BYTES`] chunks and hashes each one. CPU work,
/// done before the connection is taken.
pub(crate) fn plan(bytes: &[u8]) -> Vec<PlannedChunk> {
    bytes
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let start = index * CHUNK_BYTES;
            PlannedChunk {
                seq: i64::try_from(index).unwrap_or(i64::MAX),
                sha256: hex::encode(Sha256::digest(chunk)),
                range: start..start + chunk.len(),
            }
        })
        .collect()
}

/// Writes the planned chunks of `bytes` for the view `evidence_id`. Inside
/// the caller's transaction, after the view row.
pub(crate) fn insert(
    conn: Db<'_>,
    evidence_id: &str,
    bytes: &[u8],
    chunks: &[PlannedChunk],
) -> Result<(), StoreError> {
    for chunk in chunks {
        conn.execute(
            "INSERT INTO evidence_view_chunk (evidence_id, seq, sha256, bytes) VALUES (?1, ?2, ?3, ?4)",
            params![evidence_id, chunk.seq, chunk.sha256, &bytes[chunk.range.clone()]],
        )?;
    }
    Ok(())
}

/// What reading a page out of the chunks came to.
pub(crate) enum PageBytes {
    /// The page, every chunk it touched matching its digest.
    Sound(Vec<u8>),
    /// A chunk is missing, has the wrong length, or does not hash to its
    /// recorded digest. Nothing may be served.
    Corrupt,
}

/// Reads `offset .. offset + length` (clamped to `total`) of the view
/// `evidence_id`, whose chunks are `chunk_bytes` long. The caller has
/// checked `offset < total`.
pub(crate) fn read_page(
    conn: Db<'_>,
    evidence_id: &str,
    offset: u64,
    length: u32,
    total: u64,
    chunk_bytes: u64,
) -> Result<PageBytes, StoreError> {
    if chunk_bytes == 0 || offset >= total {
        return Ok(PageBytes::Corrupt);
    }
    let end = offset.saturating_add(u64::from(length)).min(total);
    let first = offset / chunk_bytes;
    let last = (end - 1) / chunk_bytes;
    let mut stmt = conn.prepare(
        "SELECT seq, sha256, bytes FROM evidence_view_chunk \
         WHERE evidence_id = ?1 AND seq BETWEEN ?2 AND ?3 ORDER BY seq",
    )?;
    let mut rows = stmt.query(params![
        evidence_id,
        i64::try_from(first).unwrap_or(i64::MAX),
        i64::try_from(last).unwrap_or(i64::MAX)
    ])?;
    let mut page = Vec::with_capacity(usize::try_from(end - offset).unwrap_or(0));
    let mut expected = first;
    while let Some(row) = rows.next()? {
        let seq = row.get::<i64>(0)?;
        if u64::try_from(seq).ok() != Some(expected) {
            return Ok(PageBytes::Corrupt);
        }
        let digest: String = row.get(1)?;
        let ValueRef::Blob(bytes) = row.value(2)? else {
            return Ok(PageBytes::Corrupt);
        };
        let start = expected * chunk_bytes;
        let want = chunk_bytes.min(total - start);
        if u64::try_from(bytes.len()).ok() != Some(want)
            || !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(&digest)
        {
            return Ok(PageBytes::Corrupt);
        }
        // The part of this chunk the page covers, in chunk coordinates.
        let from = usize::try_from(offset.max(start) - start).unwrap_or(usize::MAX);
        let to = usize::try_from(end.min(start + want) - start).unwrap_or(usize::MAX);
        page.extend_from_slice(bytes.get(from..to).unwrap_or_default());
        expected += 1;
    }
    if expected != last + 1 {
        return Ok(PageBytes::Corrupt);
    }
    Ok(PageBytes::Sound(page))
}

/// The Rust half of migration 20 (see `migrations::SCHEMA_V20`): every view
/// that is still live in the new table gets its chunks, cut from the old
/// table's blob, provided the blob is the view it claims to be. One that is
/// not (no bytes, the wrong length, or bytes that do not hash to the
/// recorded `view_sha256`) keeps its row and identity, gets no chunks, so
/// a read refuses it as corrupt, and is reported in an
/// `evidence.view_corrupt` audit row on its request. Then the tail of the
/// migration swaps the tables.
pub(crate) fn migrate_v20(conn: &Connection) -> Result<(), StoreError> {
    let db = Db::new(conn);
    let live: Vec<String> = {
        let mut stmt = db.prepare(
            "SELECT evidence_id FROM evidence_view_v20 WHERE expired_at IS NULL ORDER BY evidence_id",
        )?;
        let mut rows = stmt.query(())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(row.get(0)?);
        }
        out
    };
    for evidence_id in live {
        convert(db, &evidence_id)?;
    }
    conn.execute_batch(crate::migrations::SCHEMA_V20_TAIL)
        .map_err(crate::error::engine)
}

/// Moves one live view's blob into chunks, or reports why it cannot.
fn convert(db: Db<'_>, evidence_id: &str) -> Result<(), StoreError> {
    let mut stmt = db.prepare(
        "SELECT view_blob, view_sha256, view_bytes, request_id, view_id \
         FROM evidence_view WHERE evidence_id = ?1",
    )?;
    let mut rows = stmt.query(params![evidence_id])?;
    let Some(row) = rows.next()? else {
        return Ok(());
    };
    let recorded: String = row.get(1)?;
    let length: i64 = row.get(2)?;
    let request_id: String = row.get(3)?;
    let view_id: String = row.get(4)?;
    let bytes = match row.value(0)? {
        ValueRef::Blob(bytes) | ValueRef::Text(bytes) => Some(bytes.to_vec()),
        _ => None,
    };
    drop(rows);
    let problem = match &bytes {
        None => Some("view_bytes_missing"),
        Some(bytes) if i64::try_from(bytes.len()).ok() != Some(length) => {
            Some("view_length_mismatch")
        }
        Some(bytes) if !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(&recorded) => {
            Some("view_digest_mismatch")
        }
        Some(_) => None,
    };
    match (problem, bytes) {
        (None, Some(bytes)) => insert(db, evidence_id, &bytes, &plan(&bytes)),
        (problem, _) => {
            let detail = serde_json::json!({
                "cause": problem.unwrap_or("view_bytes_missing"),
                "evidence_id": evidence_id,
                "view_id": view_id,
                "view_sha256": recorded,
                "view_bytes": length,
                "migration": 20,
                "note": "The stored view did not match its recorded digest; it was kept without its bytes, and reads of it refuse as evidence_corrupt.",
            })
            .to_string();
            db.execute(
                "INSERT INTO audit (request_id, action, decision, actor, detail, ts) \
                 VALUES (?1, 'evidence.view_corrupt', 'refuse', 'system', ?2, CAST(strftime('%s', 'now') AS INTEGER))",
                params![request_id, detail],
            )?;
            Ok(())
        }
    }
}
