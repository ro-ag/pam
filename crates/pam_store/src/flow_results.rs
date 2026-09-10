//! Bounded metadata reads for scoped status and durable flow projections.
use super::{RequestState, Store, StoreError};
use turso::params;

/// Request metadata suitable for authorization, without arguments or audit text.
#[derive(Debug)]
pub struct RequestStatusMeta {
    /// Capability name.
    pub capability: String,
    /// Original caller repository spelling; the daemon canonicalizes it.
    pub repository: String,
    /// Lifecycle state.
    pub state: RequestState,
    /// Terminal outcome or cause, bounded to 128 bytes.
    pub outcome: Option<String>,
    /// Captured admission revision.
    pub authorization_revision: Option<i64>,
}

/// Bounded flow projection metadata with the private captured origin.
#[derive(Debug)]
pub struct FlowResultMeta {
    /// Private connector authorization metadata, never returned publicly.
    pub origin_json: String,
    /// Protected verdict metadata; only its typed `agent_result` may be exposed.
    pub metadata_json: String,
}

impl Store {
    /// Reads only bounded status metadata; oversized legacy values fail closed.
    pub async fn request_status_meta(
        &self,
        ticket: &str,
    ) -> Result<Option<RequestStatusMeta>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query(
            "SELECT capability,repo,state,outcome,authorization_revision FROM request WHERE id=?1 AND LENGTH(CAST(state AS BLOB))<=32 AND LENGTH(CAST(capability AS BLOB))<=128 AND LENGTH(CAST(repo AS BLOB))<=8192 AND (outcome IS NULL OR LENGTH(CAST(outcome AS BLOB))<=128)",params![ticket]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        Ok(Some(RequestStatusMeta {
            capability: row.get(0)?,
            repository: row.get(1)?,
            state: RequestState::parse(&row.get::<String>(2)?)?,
            outcome: row.get(3)?,
            authorization_revision: row.get(4)?,
        }))
    }

    /// All captured origins, including retained tombstones. Missing ownership,
    /// oversized metadata, or overflow refuses the complete set, never a prefix.
    /// Empty means no evidence has yet been captured for this request.
    pub async fn request_evidence_origins(
        &self,
        ticket: &str,
        repository: &str,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut missing=self.conn.query(
            "SELECT EXISTS(SELECT 1 FROM evidence e WHERE e.request_id=?1 AND NOT EXISTS(SELECT 1 FROM evidence_view v WHERE v.evidence_id=e.id AND v.request_id=e.request_id AND v.repository=?2)) OR EXISTS(SELECT 1 FROM evidence_view WHERE request_id=?1 AND repository!=?2)",params![ticket,repository]).await?;
        if let Some(row) = missing.next().await?
            && row.get::<i64>(0)? != 0
        {
            return Ok(None);
        }
        drop(missing);
        let mut rows=self.conn.query(
            "SELECT DISTINCT CASE WHEN LENGTH(CAST(origin_json AS BLOB))<=16384 THEN origin_json ELSE NULL END FROM evidence_view WHERE request_id=?1 AND repository=?2 LIMIT 257",params![ticket,repository]).await?;
        let mut origins = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next().await? {
            let Some(origin) = row.get::<Option<String>>(0)? else {
                return Ok(None);
            };
            bytes = bytes.saturating_add(origin.len());
            if origins.len() == 256 || bytes > 65536 {
                return Ok(None);
            }
            origins.push(origin);
        }
        Ok(Some(origins))
    }

    /// Reads no source/view blobs. The view ownership tuple authenticates the
    /// canonical repository; tombstones retain origin until request retention.
    pub async fn flow_result_meta(
        &self,
        ticket: &str,
        repository: &str,
    ) -> Result<Option<FlowResultMeta>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query(
            "SELECT v.origin_json,e.meta_json FROM evidence e JOIN evidence_view v ON v.evidence_id=e.id AND v.request_id=e.request_id WHERE e.request_id=?1 AND v.repository=?2 AND e.kind='flow.result' AND LENGTH(CAST(e.meta_json AS BLOB))<=16384 AND LENGTH(CAST(v.origin_json AS BLOB))<=16384 ORDER BY e.ts DESC,e.id DESC LIMIT 1",params![ticket,repository]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        Ok(Some(FlowResultMeta {
            origin_json: row.get(0)?,
            metadata_json: row.get(1)?,
        }))
    }
}
