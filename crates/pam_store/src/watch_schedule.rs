//! Durable scheduling for an already admitted, checkpointed read-only watch.
use super::{Store, StoreError, now_ts};
use turso::params;

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
        let _guard = self.conn_lock.lock().await;
        Ok(self.conn.execute(
            "UPDATE request SET state='queued',resume_at_ms=?2,updated_ts=?4
             WHERE id=?1 AND capability='flow.run' AND state='running'
             AND queue_authorized=1 AND expires_at_ms>?3 AND expires_at_ms>=?2
             AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL)
             AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
            params![id, resume_at_ms, now_ms, now_ts()],
        ).await? == 1)
    }

    /// Check a recovered schedule using only scalar metadata, before indexing
    /// it in the queue. Malformed or non-ready legacy schedules fail closed.
    pub async fn validate_parked_flow_request(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query(
            "SELECT 1 FROM request WHERE id=?1 AND capability='flow.run' AND state='queued'
             AND resume_at_ms>0 AND resume_at_ms<=expires_at_ms
             AND queue_authorized=1 AND expires_at_ms>?2
             AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL)
             AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
            params![id, now_ms],
        ).await?;
        Ok(rows.next().await?.is_some())
    }

    /// Distinguish expiry from authorization failure after a rejected wake,
    /// without loading the request's arguments or other retained payloads.
    pub async fn request_admission_expired(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query(
                "SELECT 1 FROM request WHERE id=?1 AND expires_at_ms<=?2",
                params![id, now_ms],
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    /// Release a due parked checkpoint without granting fresh authority. The
    /// executor rechecks current repository/connector policy before any I/O.
    pub async fn wake_parked_flow_request(
        &self,
        id: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let _guard = self.conn_lock.lock().await;
        Ok(self.conn.execute(
            "UPDATE request SET resume_at_ms=NULL,updated_ts=?3
             WHERE id=?1 AND capability='flow.run' AND state='queued'
             AND resume_at_ms IS NOT NULL AND resume_at_ms<=?2
             AND queue_authorized=1 AND expires_at_ms>?2
             AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL)
             AND EXISTS(SELECT 1 FROM flow_journal WHERE request_id=?1 AND state='ready')",
            params![id, now_ms, now_ts()],
        ).await? == 1)
    }
}
