//! Immutable redacted evidence views and durable, non-renewable read allowances.
use super::{Store, StoreError, blob_column};
use sha2::{Digest, Sha256};
use turso::params;

pub(crate) const META_LIMIT: usize = 16 * 1024;
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
    /// Originating admission revision, for revocation checks.
    pub authorization_revision: Option<i64>,
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
            || [&view.origin_json, &view.identity_json, &view.map_json]
                .iter()
                .any(|s| {
                    s.len() > META_LIMIT || serde_json::from_str::<serde_json::Value>(s).is_err()
                })
        {
            return Err(invalid());
        }
        let mut identity: serde_json::Value =
            serde_json::from_str(&view.identity_json).map_err(|_| invalid())?;
        let identity_fields = identity.as_object_mut().ok_or_else(invalid)?;
        let _guard = self.conn_lock.lock().await;
        // Only bounded metadata is loaded; the protected source may be a large
        // serialized compact rather than the logical text passed to redaction.
        let mut rows = self.conn.query(
            "SELECT substr(content_hash,1,65),LENGTH(content) FROM evidence WHERE id=?1 AND request_id=?2",
            params![view.evidence_id.clone(), view.request_id.clone()],
        ).await?;
        let Some(row) = rows.next().await? else {
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
        let affected = self.conn.execute(
            "INSERT INTO evidence_view (evidence_id,request_id,repository,origin_json,identity_json,map_json,view_id,view_sha256,view_bytes,view_blob) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE EXISTS (SELECT 1 FROM evidence e JOIN request r ON r.id=e.request_id WHERE e.id=?1 AND e.request_id=?2)",
            params![view.evidence_id.clone(),view.request_id.clone(),view.repository.clone(),view.origin_json.clone(),identity_json,view.map_json.clone(),view.view_id.clone(),hex::encode(Sha256::digest(&view.view_bytes)), i64::try_from(view.view_bytes.len()).map_err(|_| invalid())?,view.view_bytes.clone()],
        ).await?;
        Ok(affected > 0)
    }

    /// Looks up bounded metadata using the full ownership tuple. Private origin
    /// is returned only for the daemon to reauthorize before public exposure.
    pub async fn evidence_view_meta(
        &self,
        request_id: &str,
        evidence_id: &str,
        repository: &str,
    ) -> Result<Option<EvidenceViewMeta>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT v.identity_json,v.origin_json,v.map_json,v.view_id,v.view_sha256,v.view_bytes,v.expired_at,r.authorization_revision FROM evidence_view v JOIN request r ON r.id=v.request_id WHERE v.evidence_id=?1 AND v.request_id=?2 AND v.repository=?3", params![evidence_id,request_id,repository]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        Ok(Some(EvidenceViewMeta {
            authorization_revision: row.get(7)?,
            identity_json: row.get(0)?,
            origin_json: row.get(1)?,
            map_json: row.get(2)?,
            view_id: row.get(3)?,
            view_sha256: row.get(4)?,
            view_bytes: u64::try_from(row.get::<i64>(5)?).map_err(|_| invalid())?,
            expired_at: row.get(6)?,
        }))
    }

    /// Charges every valid range attempt against a persisted first-read one-hour,
    /// 64-MiB, 4096-page allowance. Continuations and retries never renew it.
    /// Cancellation after charging does not refund uncertain delivery.
    pub async fn read_evidence_view_range(
        &self,
        request: &EvidenceRangeRequest,
    ) -> Result<EvidenceRangeOutcome, StoreError> {
        let _guard = self.conn_lock.lock().await;
        // Each write autocommits: dropping this future cannot leave a BEGIN open
        // or roll back a charged attempt. The lock prevents local interleaving.
        self.evidence_range_locked(request).await
    }

    async fn evidence_range_locked(
        &self,
        r: &EvidenceRangeRequest,
    ) -> Result<EvidenceRangeOutcome, StoreError> {
        let mut rows = self.conn.query("SELECT view_bytes,expired_at FROM evidence_view WHERE evidence_id=?1 AND request_id=?2 AND repository=?3 AND view_id=?4 AND view_sha256=?5",params![r.evidence_id.clone(),r.request_id.clone(),r.repository.clone(),r.expected_view_id.clone(),r.expected_sha256.clone()]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(EvidenceRangeOutcome::Unavailable);
        };
        let total = u64::try_from(row.get::<i64>(0)?).map_err(|_| invalid())?;
        if row.get::<Option<i64>>(1)?.is_some() {
            return Ok(EvidenceRangeOutcome::Expired);
        }
        drop(rows);
        // `offset == total` is past the last byte: nothing to return, so
        // it must not charge a page and a length against the allowance.
        if r.length == 0 || r.length > RANGE_LIMIT || r.offset >= total {
            return Ok(EvidenceRangeOutcome::InvalidRange);
        }
        let Some(expires) = r.now.checked_add(3600) else {
            return Err(invalid());
        };
        self.conn.execute("INSERT OR IGNORE INTO evidence_read_allowance (request_id,repository,started_at,expires_at,remaining_bytes,remaining_pages) VALUES (?1,?2,?3,?4,67108864,4096)",params![r.request_id.clone(),r.repository.clone(),r.now,expires]).await?;
        let changed = self.conn.execute("UPDATE evidence_read_allowance SET remaining_bytes=remaining_bytes-?3,remaining_pages=remaining_pages-1 WHERE request_id=?1 AND repository=?2 AND expires_at>?4 AND remaining_bytes>=?3 AND remaining_pages>0",params![r.request_id.clone(),r.repository.clone(),i64::from(r.length),r.now]).await?;
        if changed == 0 {
            return Ok(EvidenceRangeOutcome::BudgetExhausted);
        }
        let mut rows = self.conn.query("SELECT substr(v.view_blob,?3,?4),a.expires_at,a.remaining_bytes,a.remaining_pages FROM evidence_view v JOIN evidence_read_allowance a ON a.request_id=v.request_id AND a.repository=v.repository WHERE v.evidence_id=?1 AND v.request_id=?2",params![r.evidence_id.clone(),r.request_id.clone(),i64::try_from(r.offset).map_err(|_| invalid())? + 1,i64::from(r.length)]).await?;
        let row = rows.next().await?.ok_or_else(invalid)?;
        let bytes = blob_column(&row, 0)?;
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
}
