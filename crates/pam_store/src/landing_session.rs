//! Bounded private landing receipts, scoped to the original admitted flow ticket.
use super::{Store, StoreError};
use serde::Deserialize;
use turso::params;

/// Private landing manifest and prepared effect state; never returned by public reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingSession {
    /// Compare-and-swap generation.
    pub revision: i64,
    /// Versioned daemon-owned document, at most 128 KiB.
    pub document: String,
}

#[derive(Deserialize)]
struct RecoveryProof {
    version: u32,
    flow_digest: String,
    repository: String,
    intent: RecoveryIntent,
}

#[derive(Deserialize)]
struct RecoveryIntent {
    step_id: String,
    operation: String,
    state: String,
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
    /// Startup-only handoff to read-only reconciliation on the original ticket.
    /// This is not permission to repeat the effect: the private prepared intent
    /// remains unchanged and the runtime must reconcile it before any new I/O.
    /// Original admission, expiry, spent budget, and checkpoint are never reset.
    pub async fn recover_landing_reconciliation(
        &self,
        request_id: &str,
        expected_revision: i64,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        validate(request_id, "{}")?;
        if !(0..i64::MAX).contains(&expected_revision) {
            return Err(invalid());
        }
        let _guard = self.conn_lock.lock().await;
        if !self.landing_prepared_intent_locked(request_id).await? {
            return Ok(false);
        }
        Ok(self.conn.execute(
            "UPDATE flow_journal SET state='ready',revision=revision+1
             WHERE request_id=?1 AND revision=?2 AND state='prepared' AND effectful=1
             AND EXISTS(SELECT 1 FROM request WHERE id=?1 AND repo=flow_journal.repository
             AND capability='flow.run' AND state IN ('running','waiting_approval')
             AND queue_authorized=1 AND expires_at_ms>?3
             AND authorization_revision=(SELECT COUNT(*) FROM \"grant\" WHERE revoked_ts IS NOT NULL))",
            params![request_id,expected_revision,now_ms],
        ).await? == 1)
    }

    /// Caller owns `conn_lock`, including during terminal-write transactions.
    /// Recognizes the retained uncertain effect across the ready/requeue handoff;
    /// it does not authorize recovery and deliberately does not require live admission.
    pub(super) async fn landing_prepared_intent_locked(
        &self,
        request_id: &str,
    ) -> Result<bool, StoreError> {
        let mut rows = self.conn.query(
            "SELECT CASE WHEN length(CAST(s.document AS BLOB))<=131072 THEN s.document ELSE NULL END,
             j.flow_digest, j.repository, j.step_id FROM landing_session s
             JOIN flow_journal j ON j.request_id=s.request_id
             JOIN request r ON r.id=j.request_id
             WHERE r.id=?1 AND j.schema_version=1
             AND j.state IN ('ready','prepared') AND j.effectful=1
             AND length(CAST(j.flow_digest AS BLOB))=64
             AND length(CAST(j.repository AS BLOB)) BETWEEN 1 AND 4096
             AND length(CAST(j.step_id AS BLOB)) BETWEEN 1 AND 256
             AND r.repo=j.repository AND r.capability='flow.run'",
            params![request_id],
        ).await?;
        let Some(row) = rows.next().await? else {
            return Ok(false);
        };
        let document: String = row.get::<Option<String>>(0)?.ok_or_else(invalid)?;
        let Ok(proof) = serde_json::from_str::<RecoveryProof>(&document) else {
            return Ok(false);
        };
        Ok(proof.version == 1
            && proof.flow_digest == row.get::<String>(1)?
            && proof.repository == row.get::<String>(2)?
            && proof.intent.step_id == row.get::<String>(3)?
            && proof.intent.state == "prepared"
            && matches!(
                proof.intent.operation.as_str(),
                "push" | "ensure_pr" | "merge" | "sync"
            ))
    }

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
