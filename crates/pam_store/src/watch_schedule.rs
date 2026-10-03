//! Durable scheduling for an already admitted, checkpointed read-only watch.
use super::{Store, StoreError, now_ts};
use rusqlite::params;

impl Store {
    /// Park only a running, admitted flow whose checkpoint is ready. Neither
    /// its admission revision nor its absolute deadline is refreshed.
    pub async fn park_flow_request(
        &self,
        id: &str,
        resume_at_ms: i64,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        if now_ms < 0 || resume_at_ms <= now_ms {
            return Ok(false);
        }
        let id = id.to_owned();
        self.run(move |conn| {
            Ok(conn.execute(
                &format!(
                    "UPDATE request SET state='queued',resume_at_ms=?2,updated_ts=?4
                 WHERE id=?1 AND capability='flow.run' AND state='running'
                 AND queue_authorized=1 AND expires_at_ms>?3 AND expires_at_ms>=?2
                 AND {admission}
                 AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
                    admission = super::ADMISSION_STANDS
                ),
                params![id, resume_at_ms, now_ms, now_ts()],
            )? == 1)
        })
        .await
    }

    /// Check a recovered schedule using only scalar metadata, before indexing
    /// it in the queue. Malformed or non-ready legacy schedules fail closed.
    pub async fn validate_parked_flow_request(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let id = id.to_owned();
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT 1 FROM request WHERE id=?1 AND capability='flow.run' AND state='queued'
                 AND resume_at_ms>0 AND resume_at_ms<=expires_at_ms
                 AND queue_authorized=1 AND expires_at_ms>?2
                 AND {admission}
                 AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
                admission = super::ADMISSION_STANDS
            ))?;
            let mut rows = stmt.query(params![id, now_ms])?;
            Ok(rows.next()?.is_some())
        })
        .await
    }

    /// Distinguish expiry from authorization failure after a rejected wake,
    /// without loading the request's arguments or other retained payloads.
    pub async fn request_admission_expired(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let id = id.to_owned();
        self.run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT 1 FROM request WHERE id=?1 AND expires_at_ms<=?2")?;
            let mut rows = stmt.query(params![id, now_ms])?;
            Ok(rows.next()?.is_some())
        })
        .await
    }

    /// Release a due parked checkpoint without granting fresh authority. The
    /// executor rechecks current repository/connector policy before any I/O.
    pub async fn wake_parked_flow_request(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let id = id.to_owned();
        self.run(move |conn| {
            Ok(conn.execute(
                &format!(
                    "UPDATE request SET resume_at_ms=NULL,updated_ts=?3
                 WHERE id=?1 AND capability='flow.run' AND state='queued'
                 AND resume_at_ms IS NOT NULL AND resume_at_ms<=?2
                 AND queue_authorized=1 AND expires_at_ms>?2
                 AND {admission}
                 AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
                    admission = super::ADMISSION_STANDS
                ),
                params![id, now_ms, now_ts()],
            )? == 1)
        })
        .await
    }
}
