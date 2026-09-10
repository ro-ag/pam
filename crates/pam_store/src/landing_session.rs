//! Bounded private landing receipts, scoped to the original admitted flow ticket.
use super::{Store, StoreError};
use turso::params;

/// Private landing manifest and prepared effect state; never returned by public reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingSession {
    /// Compare-and-swap generation.
    pub revision: i64,
    /// Versioned daemon-owned document, at most 128 KiB.
    pub document: String,
}

fn invalid() -> StoreError {
    StoreError::UnexpectedValue {
        column: "landing_session",
        value: "invalid or oversized private landing document".to_owned(),
    }
}

fn validate(id: &str, document: &str) -> Result<(), StoreError> {
    if id.is_empty()
        || id.len() > 128
        || id.chars().any(char::is_control)
        || document.len() > 131_072
        || !serde_json::from_str::<serde_json::Value>(document).is_ok_and(|value| value.is_object())
    {
        return Err(invalid());
    }
    Ok(())
}

impl Store {
    /// Read without allocating an oversized persisted document.
    pub async fn read_landing_session(
        &self,
        request_id: &str,
    ) -> Result<Option<LandingSession>, StoreError> {
        validate(request_id, "{}")?;
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT revision, CASE WHEN length(CAST(document AS BLOB))<=131072 THEN document ELSE NULL END FROM landing_session WHERE request_id=?1", params![request_id]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let document: String = row.get::<Option<String>>(1)?.ok_or_else(invalid)?;
        validate(request_id, &document)?;
        Ok(Some(LandingSession {
            revision: row.get(0)?,
            document,
        }))
    }

    /// Insert once or replace one exact generation. Only an unexpired running
    /// original flow with unchanged grant revision may change private receipts.
    pub async fn save_landing_session(
        &self,
        request_id: &str,
        expected_revision: Option<i64>,
        document: &str,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        validate(request_id, document)?;
        if expected_revision.is_some_and(|revision| revision < 0 || revision == i64::MAX) {
            return Err(invalid());
        }
        let _guard = self.conn_lock.lock().await;
        let changed = match expected_revision {
            None => self.conn.execute("INSERT INTO landing_session(request_id,revision,document) SELECT id,0,?2 FROM request WHERE id=?1 AND state='running' AND capability='flow.run' AND expires_at_ms>?3 AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL) ON CONFLICT(request_id) DO NOTHING", params![request_id,document,now_ms]).await?,
            Some(revision) => self.conn.execute("UPDATE landing_session SET document=?3,revision=revision+1 WHERE request_id=?1 AND revision=?2 AND EXISTS(SELECT 1 FROM request WHERE id=?1 AND state='running' AND capability='flow.run' AND expires_at_ms>?4 AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL))",params![request_id,revision,document,now_ms]).await?,
        };
        Ok(changed == 1)
    }
}
