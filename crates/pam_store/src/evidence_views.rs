//! Immutable redacted evidence views and durable, non-renewable read allowances.
use super::{Store, StoreError, blob_column};
use crate::db::Db;
use rusqlite::params;
use sha2::{Digest, Sha256};

pub(crate) const META_LIMIT: usize = 16 * 1024;
/// Most segments a stored provenance map may hold. A producer with a finer
/// map coarsens it to this many segments before publishing, and says so in
/// the view's identity; the store never drops a view for being detailed.
pub const MAX_EVIDENCE_MAP_SEGMENTS: usize = 8192;
/// Byte ceiling of a stored `map_json`. One serialized segment is at most
/// 113 bytes (two 8-digit ranges and the longest relation name), so
/// [`MAX_EVIDENCE_MAP_SEGMENTS`] of them always fit with room to spare. The
/// map is parsed on every page read, which is why it is bounded well below
/// the 64 MiB a view itself may reach.
pub const MAX_EVIDENCE_MAP_BYTES: usize = 1024 * 1024;
const VIEW_LIMIT: usize = 64 * 1024 * 1024;
const RANGE_LIMIT: u32 = 64 * 1024;

/// An immutable, fully redacted view; origin metadata is private to the daemon.
#[derive(Debug)]
pub struct EvidenceViewInsert {
    /// Existing evidence identifier.
    pub evidence_id: String,
    /// Originating request identifier.
    pub request_id: String,
    /// Canonical authorized repository.
    pub repository: String,
    /// Private resolved connector origin, never part of public responses.
    pub origin_json: String,
    /// Safe versioned identity metadata.
    pub identity_json: String,
    /// Bounded source map metadata or references.
    pub map_json: String,
    /// Immutable view identifier.
    pub view_id: String,
    /// Complete redacted view, hashed by the store.
    pub view_bytes: Vec<u8>,
}

/// Metadata only; no blob is read by the authorization lookup.
#[derive(Debug)]
pub struct EvidenceViewMeta {
    /// Originating admission revision: the global revocation count the
    /// request captured. Prefer [`Self::authorization_current`].
    pub authorization_revision: Option<i64>,
    /// Whether the originating request's admission still stands, read in the
    /// same statement as the rest of this metadata: false once a grant that
    /// request depended on was revoked after it was admitted (see
    /// [`Store::request_authorization_current`]).
    pub authorization_current: bool,
    /// Safe identity packet.
    pub identity_json: String,
    /// Private origin used for current-scope authorization.
    pub origin_json: String,
    /// Source map metadata.
    pub map_json: String,
    /// Immutable view identifier.
    pub view_id: String,
    /// SHA256 of exact view bytes.
    pub view_sha256: String,
    /// Original view length, including after retention.
    pub view_bytes: u64,
    /// Unix timestamp of retention, if removed.
    pub expired_at: Option<i64>,
}

/// A bounded read bound to an originating request, repository, and view identity.
#[derive(Debug)]
pub struct EvidenceRangeRequest {
    /// Originating request, not the current retrieval request.
    pub request_id: String,
    /// Existing evidence identifier.
    pub evidence_id: String,
    /// Canonical authorized repository.
    pub repository: String,
    /// Expected immutable view identifier.
    pub expected_view_id: String,
    /// Expected SHA256 of the view.
    pub expected_sha256: String,
    /// Zero-based byte offset in the view.
    pub offset: u64,
    /// Requested decoded byte count, at most 64 KiB.
    pub length: u32,
    /// Trusted daemon clock in Unix seconds.
    pub now: i64,
}

/// Exact view bytes and the shared allowance remaining after this attempt.
#[derive(Debug)]
pub struct EvidenceRange {
    /// Immutable view identifier.
    pub view_id: String,
    /// SHA256 of the complete view.
    pub view_sha256: String,
    /// Returned starting offset.
    pub offset: u64,
    /// Exact bytes, possibly cutting through a UTF-8 code point.
    pub bytes: Vec<u8>,
    /// Complete view length.
    pub total_bytes: u64,
    /// Next byte offset, absent at end of view.
    pub next_offset: Option<u64>,
    /// Fixed first-read expiry in Unix seconds.
    pub allowance_expires_at: i64,
    /// Unspent requested-byte allowance.
    pub remaining_bytes: u64,
    /// Unspent page attempts.
    pub remaining_pages: u32,
}

/// Retrieval result; callers must authorize before exposing any distinction.
#[derive(Debug)]
pub enum EvidenceRangeOutcome {
    /// No view matching the complete ownership and identity tuple.
    Unavailable,
    /// Authorized view was removed by retention.
    Expired,
    /// Invalid offset or requested length.
    InvalidRange,
    /// The originating request's finite allowance is exhausted or expired.
    BudgetExhausted,
    /// A charged exact byte range.
    Range(EvidenceRange),
}

fn invalid() -> StoreError {
    StoreError::UnexpectedValue {
        column: "evidence_view",
        value: "invalid bounded view input".into(),
    }
}

impl Store {
    /// Inserts once, only for source evidence owned by the supplied request/repo.
    /// The daemon validates the canonical repository; request spelling may use a
    /// symlink. Returns false if source/request ownership does not exist. Duplicate views
    /// fail rather than replacing a view that existing references identify.
    pub async fn insert_evidence_view(
        &self,
        view: &EvidenceViewInsert,
    ) -> Result<bool, StoreError> {
        if view.view_bytes.len() > VIEW_LIMIT
            || view.view_id.is_empty()
            || view.view_id.len() > 256
            || [&view.origin_json, &view.identity_json].iter().any(|s| {
                s.len() > META_LIMIT || serde_json::from_str::<serde_json::Value>(s).is_err()
            })
            || view.map_json.len() > MAX_EVIDENCE_MAP_BYTES
            || !serde_json::from_str::<serde_json::Value>(&view.map_json).is_ok_and(|map| {
                map.as_array()
                    .is_some_and(|m| m.len() <= MAX_EVIDENCE_MAP_SEGMENTS)
            })
        {
            return Err(invalid());
        }
        // Hash before taking the connection: up to 64 MiB of CPU work that
        // no other store call should queue behind.
        let view_sha256 = hex::encode(Sha256::digest(&view.view_bytes));
        let mut identity: serde_json::Value =
            serde_json::from_str(&view.identity_json).map_err(|_| invalid())?;
        if !identity.is_object() {
            return Err(invalid());
        }
        // The job outlives this borrow: the view is copied once, here, and
        // its bytes are bound by reference.
        let view = EvidenceViewInsert {
            evidence_id: view.evidence_id.clone(),
            request_id: view.request_id.clone(),
            repository: view.repository.clone(),
            origin_json: view.origin_json.clone(),
            // Rebuilt below from `identity`; the original text is not stored.
            identity_json: String::new(),
            map_json: view.map_json.clone(),
            view_id: view.view_id.clone(),
            view_bytes: view.view_bytes.clone(),
        };
        self.run(move |conn| {
            let identity_fields = identity.as_object_mut().ok_or_else(invalid)?;
            // Only bounded metadata is loaded; the protected source may be a large
            // serialized compact rather than the logical text passed to redaction.
            let mut stmt = conn.prepare("SELECT substr(content_hash,1,65),LENGTH(content) FROM evidence WHERE id=?1 AND request_id=?2")?;
            let mut rows = stmt.query(params![view.evidence_id, view.request_id])?;
            let Some(row) = rows.next()? else {
                return Ok(false);
            };
            let digest: String = row.get(0)?;
            let bytes = u64::try_from(row.get::<i64>(1)?).map_err(|_| invalid())?;
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            drop(rows);
            identity_fields.insert("protected_evidence_sha256".into(), digest.into());
            identity_fields.insert("protected_evidence_bytes".into(), bytes.into());
            let identity_json = identity.to_string();
            if identity_json.len() > META_LIMIT {
                return Err(invalid());
            }
            let affected = conn.execute(
                "INSERT INTO evidence_view (evidence_id,request_id,repository,origin_json,identity_json,map_json,view_id,view_sha256,view_bytes,view_blob) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE EXISTS (SELECT 1 FROM evidence e JOIN request r ON r.id=e.request_id WHERE e.id=?1 AND e.request_id=?2)",
                params![view.evidence_id,view.request_id,view.repository,view.origin_json,identity_json,view.map_json,view.view_id,view_sha256, i64::try_from(view.view_bytes.len()).map_err(|_| invalid())?,view.view_bytes],
            )?;
            Ok(affected > 0)
        })
        .await
    }

    /// Looks up bounded metadata using the full ownership tuple. Private origin
    /// is returned only for the daemon to reauthorize before public exposure.
    pub async fn evidence_view_meta(
        &self,
        request_id: &str,
        evidence_id: &str,
        repository: &str,
    ) -> Result<Option<EvidenceViewMeta>, StoreError> {
        let request_id = request_id.to_owned();
        let evidence_id = evidence_id.to_owned();
        let repository = repository.to_owned();
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!("SELECT v.identity_json,v.origin_json,v.map_json,v.view_id,v.view_sha256,v.view_bytes,v.expired_at,request.authorization_revision,CASE WHEN {admission} THEN 1 ELSE 0 END FROM evidence_view v JOIN request ON request.id=v.request_id WHERE v.evidence_id=?1 AND v.request_id=?2 AND v.repository=?3", admission = super::ADMISSION_STANDS))?;
            let mut rows = stmt.query(params![evidence_id,request_id,repository])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            Ok(Some(EvidenceViewMeta {
                authorization_revision: row.get(7)?,
                authorization_current: row.get::<i64>(8)? == 1,
                identity_json: row.get(0)?,
                origin_json: row.get(1)?,
                map_json: row.get(2)?,
                view_id: row.get(3)?,
                view_sha256: row.get(4)?,
                view_bytes: u64::try_from(row.get::<i64>(5)?).map_err(|_| invalid())?,
                expired_at: row.get(6)?,
            }))
        })
        .await
    }

    /// Charges every valid range attempt against a persisted first-read one-hour,
    /// 64-MiB, 4096-page allowance. Continuations and retries never renew it.
    /// Cancellation after charging does not refund uncertain delivery.
    pub async fn read_evidence_view_range(
        &self,
        request: &EvidenceRangeRequest,
    ) -> Result<EvidenceRangeOutcome, StoreError> {
        let request = EvidenceRangeRequest {
            request_id: request.request_id.clone(),
            evidence_id: request.evidence_id.clone(),
            repository: request.repository.clone(),
            expected_view_id: request.expected_view_id.clone(),
            expected_sha256: request.expected_sha256.clone(),
            offset: request.offset,
            length: request.length,
            now: request.now,
        };
        self.run(move |conn| {
            // Each write autocommits, on purpose: the allowance charge must
            // survive a failure of the read that follows it. The job runs
            // whole, so nothing interleaves between the charge and the read.
            Self::evidence_range_locked(conn, &request)
        })
        .await
    }

    fn evidence_range_locked(
        conn: Db<'_>,
        r: &EvidenceRangeRequest,
    ) -> Result<EvidenceRangeOutcome, StoreError> {
        let mut stmt = conn.prepare("SELECT view_bytes,expired_at FROM evidence_view WHERE evidence_id=?1 AND request_id=?2 AND repository=?3 AND view_id=?4 AND view_sha256=?5")?;
        let mut rows = stmt.query(params![
            r.evidence_id.clone(),
            r.request_id.clone(),
            r.repository.clone(),
            r.expected_view_id.clone(),
            r.expected_sha256.clone()
        ])?;
        let Some(row) = rows.next()? else {
            return Ok(EvidenceRangeOutcome::Unavailable);
        };
        let total = u64::try_from(row.get::<i64>(0)?).map_err(|_| invalid())?;
        if row.get::<Option<i64>>(1)?.is_some() {
            return Ok(EvidenceRangeOutcome::Expired);
        }
        drop(rows);
        if r.length == 0 || r.length > RANGE_LIMIT || r.offset > total {
            return Ok(EvidenceRangeOutcome::InvalidRange);
        }
        if r.offset == total {
            // Exactly at the end, which for an empty view is also the start:
            // a legitimate read with nothing left to return. It answers an
            // empty end-of-view page instead of an error, and charges
            // nothing, since no bytes and no page were delivered.
            return Self::end_of_view(conn, r, total).map(EvidenceRangeOutcome::Range);
        }
        let Some(expires) = r.now.checked_add(3600) else {
            return Err(invalid());
        };
        conn.execute("INSERT OR IGNORE INTO evidence_read_allowance (request_id,repository,started_at,expires_at,remaining_bytes,remaining_pages) VALUES (?1,?2,?3,?4,67108864,4096)",params![r.request_id.clone(),r.repository.clone(),r.now,expires])?;
        let changed = conn.execute("UPDATE evidence_read_allowance SET remaining_bytes=remaining_bytes-?3,remaining_pages=remaining_pages-1 WHERE request_id=?1 AND repository=?2 AND expires_at>?4 AND remaining_bytes>=?3 AND remaining_pages>0",params![r.request_id.clone(),r.repository.clone(),i64::from(r.length),r.now])?;
        if changed == 0 {
            return Ok(EvidenceRangeOutcome::BudgetExhausted);
        }
        let mut stmt = conn.prepare("SELECT substr(v.view_blob,?3,?4),a.expires_at,a.remaining_bytes,a.remaining_pages FROM evidence_view v JOIN evidence_read_allowance a ON a.request_id=v.request_id AND a.repository=v.repository WHERE v.evidence_id=?1 AND v.request_id=?2")?;
        let mut rows = stmt.query(params![
            r.evidence_id.clone(),
            r.request_id.clone(),
            i64::try_from(r.offset).map_err(|_| invalid())? + 1,
            i64::from(r.length)
        ])?;
        let row = rows.next()?.ok_or_else(invalid)?;
        let bytes = blob_column(&row, 0)?;
        if bytes.is_empty() {
            // `offset < total` yet no bytes: the blob is gone without a
            // retention tombstone. Answering an empty page would hand the
            // reader the same `next_offset` forever, a page charged each
            // time; say the view is unavailable instead.
            return Ok(EvidenceRangeOutcome::Unavailable);
        }
        let next = r.offset + u64::try_from(bytes.len()).map_err(|_| invalid())?;
        Ok(EvidenceRangeOutcome::Range(EvidenceRange {
            view_id: r.expected_view_id.clone(),
            view_sha256: r.expected_sha256.clone(),
            offset: r.offset,
            bytes,
            total_bytes: total,
            next_offset: (next < total).then_some(next),
            allowance_expires_at: row.get(1)?,
            remaining_bytes: u64::try_from(row.get::<i64>(2)?).map_err(|_| invalid())?,
            remaining_pages: u32::try_from(row.get::<i64>(3)?).map_err(|_| invalid())?,
        }))
    }

    /// The uncharged empty page at `offset == total`. The allowance figures
    /// are the persisted ones when a read already started the allowance, and
    /// the untouched first-read figures when none has: reading the end of a
    /// view does not start the clock.
    fn end_of_view(
        conn: Db<'_>,
        r: &EvidenceRangeRequest,
        total: u64,
    ) -> Result<EvidenceRange, StoreError> {
        let mut stmt = conn.prepare("SELECT expires_at,remaining_bytes,remaining_pages FROM evidence_read_allowance WHERE request_id=?1 AND repository=?2")?;
        let mut rows = stmt.query(params![r.request_id.clone(), r.repository.clone()])?;
        let (allowance_expires_at, remaining_bytes, remaining_pages) = match rows.next()? {
            Some(row) => (
                row.get::<i64>(0)?,
                u64::try_from(row.get::<i64>(1)?.max(0)).map_err(|_| invalid())?,
                u32::try_from(row.get::<i64>(2)?.max(0)).map_err(|_| invalid())?,
            ),
            None => (
                r.now.checked_add(3600).ok_or_else(invalid)?,
                67_108_864,
                4096,
            ),
        };
        Ok(EvidenceRange {
            view_id: r.expected_view_id.clone(),
            view_sha256: r.expected_sha256.clone(),
            offset: r.offset,
            bytes: Vec::new(),
            total_bytes: total,
            next_offset: None,
            allowance_expires_at,
            remaining_bytes,
            remaining_pages,
        })
    }
}
