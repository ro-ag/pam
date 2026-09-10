//! Immutable redacted evidence views and durable, non-renewable read allowances.
use super::{Store, StoreError, blob_column};
use sha2::{Digest, Sha256};
use turso::params;

const META_LIMIT: usize = 16 * 1024;
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
        let _guard = self.conn_lock.lock().await;
        let affected = self.conn.execute(
            "INSERT INTO evidence_view (evidence_id,request_id,repository,origin_json,identity_json,map_json,view_id,view_sha256,view_bytes,view_blob) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE EXISTS (SELECT 1 FROM evidence e JOIN request r ON r.id=e.request_id WHERE e.id=?1 AND e.request_id=?2)",
            params![view.evidence_id.clone(),view.request_id.clone(),view.repository.clone(),view.origin_json.clone(),view.identity_json.clone(),view.map_json.clone(),view.view_id.clone(),hex::encode(Sha256::digest(&view.view_bytes)), i64::try_from(view.view_bytes.len()).map_err(|_| invalid())?,view.view_bytes.clone()],
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
        if r.length == 0 || r.length > RANGE_LIMIT || r.offset > total {
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> (tempfile::TempDir, Store, EvidenceRangeRequest) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("state.db")).await.unwrap();
        store
            .insert_request("r", "flow.run", "/repo-alias", "test", "{}", None)
            .await
            .unwrap();
        store
            .insert_evidence("e", "r", "log", b"private source", None)
            .await
            .unwrap();
        let view = EvidenceViewInsert {
            evidence_id: "e".into(),
            request_id: "r".into(),
            repository: "/canonical/repo".into(),
            origin_json: "{}".into(),
            identity_json: "{}".into(),
            map_json: "[]".into(),
            view_id: "v".into(),
            view_bytes: vec![0, 255, 195, 169, 10],
        };
        assert!(store.insert_evidence_view(&view).await.unwrap());
        let sha = hex::encode(Sha256::digest(&view.view_bytes));
        (
            dir,
            store,
            EvidenceRangeRequest {
                request_id: "r".into(),
                evidence_id: "e".into(),
                repository: "/canonical/repo".into(),
                expected_view_id: "v".into(),
                expected_sha256: sha,
                offset: 1,
                length: 2,
                now: 100,
            },
        )
    }

    #[tokio::test]
    async fn exact_binary_ranges_and_complete_identity_binding() {
        let (_dir, store, mut r) = fixture().await;
        let EvidenceRangeOutcome::Range(page) = store.read_evidence_view_range(&r).await.unwrap()
        else {
            panic!("range")
        };
        assert_eq!(page.bytes, vec![255, 195]);
        assert_eq!(page.next_offset, Some(3));
        assert_eq!(page.remaining_bytes, 67_108_862);
        assert_eq!(page.allowance_expires_at, 3700);
        r.repository = "/elsewhere".into();
        assert!(
            store
                .evidence_view_meta("r", "e", &r.repository)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::Unavailable
        ));
        r.repository = "/canonical/repo".into();
        r.expected_sha256 = "forged".into();
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::Unavailable
        ));
        r.expected_sha256 = page.view_sha256;
        r.offset = 6;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::InvalidRange
        ));
        r.offset = 0;
        r.length = 65_537;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::InvalidRange
        ));
    }

    #[tokio::test]
    async fn allowance_persists_on_reopen_and_never_renews() {
        let (dir, store, mut r) = fixture().await;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::Range(_)
        ));
        drop(store);
        let store = Store::open(&dir.path().join("state.db")).await.unwrap();
        let EvidenceRangeOutcome::Range(page) = store.read_evidence_view_range(&r).await.unwrap()
        else {
            panic!("range")
        };
        assert_eq!(page.remaining_pages, 4094);
        assert_eq!(page.remaining_bytes, 67_108_860);
        r.now = 3700;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::BudgetExhausted
        ));
        r.now = 10_000;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::BudgetExhausted
        ));
    }

    #[tokio::test]
    async fn byte_and_page_caps_are_shared_across_evidence() {
        let (_dir, store, mut r) = fixture().await;
        let _ = store.read_evidence_view_range(&r).await.unwrap();
        {
            let _guard = store.conn_lock.lock().await;
            store
                .conn
                .execute("UPDATE evidence_read_allowance SET remaining_bytes=1", ())
                .await
                .unwrap();
        }
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::BudgetExhausted
        ));
        store
            .insert_evidence("other", "r", "log", b"another source", None)
            .await
            .unwrap();
        let view = EvidenceViewInsert {
            evidence_id: "other".into(),
            request_id: "r".into(),
            repository: r.repository.clone(),
            origin_json: "{}".into(),
            identity_json: "{}".into(),
            map_json: "[]".into(),
            view_id: "other-view".into(),
            view_bytes: b"safe".to_vec(),
        };
        assert!(store.insert_evidence_view(&view).await.unwrap());
        r.evidence_id = "other".into();
        r.expected_view_id = "other-view".into();
        r.expected_sha256 = hex::encode(Sha256::digest(b"safe"));
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::BudgetExhausted
        ));
        r.length = 1;
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::Range(_)
        ));
        {
            let _guard = store.conn_lock.lock().await;
            store
                .conn
                .execute(
                    "UPDATE evidence_read_allowance SET remaining_bytes=100,remaining_pages=0",
                    (),
                )
                .await
                .unwrap();
        }
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::BudgetExhausted
        ));
    }

    #[tokio::test]
    async fn pruning_preserves_authorized_tombstone_until_request_retention() {
        let (_dir, store, r) = fixture().await;
        let _ = store.read_evidence_view_range(&r).await.unwrap();
        {
            let _guard = store.conn_lock.lock().await;
            store
                .conn
                .execute(
                    "UPDATE request SET state='done',updated_ts=1 WHERE id='r'",
                    (),
                )
                .await
                .unwrap();
        }
        store
            .prune_evidence_before(i64::MAX, "verdict")
            .await
            .unwrap();
        assert!(store.get_evidence("e").await.unwrap().is_none());
        let meta = store
            .evidence_view_meta("r", "e", "/canonical/repo")
            .await
            .unwrap()
            .unwrap();
        assert!(meta.expired_at.is_some());
        assert_eq!(meta.view_bytes, 5);
        assert!(matches!(
            store.read_evidence_view_range(&r).await.unwrap(),
            EvidenceRangeOutcome::Expired
        ));
        store.prune_requests_before(i64::MAX).await.unwrap();
        assert!(
            store
                .evidence_view_meta("r", "e", "/canonical/repo")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn view_insertion_is_immutable_owned_and_metadata_bounded() {
        let (_dir, store, _r) = fixture().await;
        let mut view = EvidenceViewInsert {
            evidence_id: "e".into(),
            request_id: "wrong".into(),
            repository: "/repo".into(),
            origin_json: "{}".into(),
            identity_json: "{}".into(),
            map_json: "[]".into(),
            view_id: "second".into(),
            view_bytes: vec![],
        };
        assert!(!store.insert_evidence_view(&view).await.unwrap());
        view.request_id = "r".into();
        assert!(store.insert_evidence_view(&view).await.is_err());
        view.origin_json = format!("\"{}\"", "x".repeat(META_LIMIT));
        assert!(store.insert_evidence_view(&view).await.is_err());
    }
}
