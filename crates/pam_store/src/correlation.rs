//! Immutable private workflow correlation. Authorization belongs to the daemon.
use super::{Store, StoreError};
use turso::params;

/// Result of binding one immutable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationBind {
    /// This call first persisted the identity.
    Inserted,
    /// Identical bytes were already persisted.
    Existing,
    /// Different bytes were already persisted; nothing changed.
    Conflict,
}

/// One private, bounded step binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationStep {
    /// Stable flow step identifier.
    pub step_id: String,
    /// Opaque canonical JSON, validated by the owning daemon service.
    pub canonical_json: String,
}

fn invalid(reason: &str) -> StoreError {
    StoreError::UnexpectedValue {
        column: "correlation",
        value: reason.to_owned(),
    }
}

fn validate(json: &str, maximum: usize) -> Result<(), StoreError> {
    if json.len() > maximum {
        return Err(invalid("JSON exceeds byte limit"));
    }
    if !serde_json::from_str::<serde_json::Value>(json).is_ok_and(|value| value.is_object()) {
        return Err(invalid("JSON must be an object"));
    }
    Ok(())
}

impl Store {
    /// Bind a target exactly once. This private API does not authorize a reader.
    pub async fn bind_correlation_target(
        &self,
        request_id: &str,
        canonical_json: &str,
    ) -> Result<CorrelationBind, StoreError> {
        validate(canonical_json, 16384)?;
        let _guard = self.conn_lock.lock().await;
        let mut rows = self
            .conn
            .query("SELECT 1 FROM request WHERE id=?1", params![request_id])
            .await?;
        if rows.next().await?.is_none() {
            return Err(StoreError::NotFound {
                table: "request",
                id: request_id.to_owned(),
            });
        }
        drop(rows);
        let mut rows = self.conn.query("SELECT CASE WHEN LENGTH(CAST(canonical_json AS BLOB))<=16384 THEN canonical_json ELSE NULL END FROM correlation_target WHERE request_id=?1", params![request_id]).await?;
        if let Some(row) = rows.next().await? {
            return Ok(
                if row.get::<Option<String>>(0)?.as_deref() == Some(canonical_json) {
                    CorrelationBind::Existing
                } else {
                    CorrelationBind::Conflict
                },
            );
        }
        drop(rows);
        self.conn
            .execute(
                "INSERT INTO correlation_target(request_id,canonical_json) VALUES (?1,?2)",
                params![request_id, canonical_json],
            )
            .await?;
        Ok(CorrelationBind::Inserted)
    }

    /// Bind a step only after the target, with finite per-request capacity.
    /// The connection mutex covers comparison, accounting and insertion.
    pub async fn bind_correlation_step(
        &self,
        request_id: &str,
        step_id: &str,
        canonical_json: &str,
    ) -> Result<CorrelationBind, StoreError> {
        validate(canonical_json, 8192)?;
        if step_id.is_empty() || step_id.len() > 256 {
            return Err(invalid("step identifier must contain 1..256 bytes"));
        }
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT 1 FROM correlation_target t JOIN request r ON r.id=t.request_id WHERE t.request_id=?1", params![request_id]).await?;
        if rows.next().await?.is_none() {
            return Err(StoreError::NotFound {
                table: "correlation_target",
                id: request_id.to_owned(),
            });
        }
        drop(rows);
        let mut rows = self.conn.query("SELECT CASE WHEN LENGTH(CAST(canonical_json AS BLOB))<=8192 THEN canonical_json ELSE NULL END FROM correlation_step WHERE request_id=?1 AND step_id=?2", params![request_id,step_id]).await?;
        if let Some(row) = rows.next().await? {
            return Ok(
                if row.get::<Option<String>>(0)?.as_deref() == Some(canonical_json) {
                    CorrelationBind::Existing
                } else {
                    CorrelationBind::Conflict
                },
            );
        }
        drop(rows);
        let mut rows = self.conn.query("SELECT COUNT(*),COALESCE(SUM(LENGTH(CAST(canonical_json AS BLOB))),0) FROM correlation_step WHERE request_id=?1", params![request_id]).await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| invalid("missing capacity accounting"))?;
        let bytes =
            i64::try_from(canonical_json.len()).map_err(|_| invalid("JSON length overflow"))?;
        if row.get::<i64>(0)? >= 64 || row.get::<i64>(1)?.saturating_add(bytes) > 524288 {
            return Err(invalid("step capacity exhausted"));
        }
        drop(rows);
        self.conn
            .execute(
                "INSERT INTO correlation_step(request_id,step_id,canonical_json) VALUES (?1,?2,?3)",
                params![request_id, step_id, canonical_json],
            )
            .await?;
        Ok(CorrelationBind::Inserted)
    }

    /// Private target read: bounded before allocation, no public authorization implied.
    pub async fn read_correlation_target(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT CASE WHEN LENGTH(CAST(canonical_json AS BLOB))<=16384 THEN canonical_json ELSE NULL END FROM correlation_target t JOIN request r ON r.id=t.request_id WHERE t.request_id=?1", params![request_id]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let json = row
            .get::<Option<String>>(0)?
            .ok_or_else(|| invalid("stored target exceeds byte limit"))?;
        validate(&json, 16384)?;
        Ok(Some(json))
    }

    /// Private step read. Overflow refuses the complete set rather than a prefix.
    pub async fn read_correlation_steps(
        &self,
        request_id: &str,
    ) -> Result<Vec<CorrelationStep>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT CASE WHEN LENGTH(CAST(step_id AS BLOB))<=256 THEN step_id ELSE NULL END,CASE WHEN LENGTH(CAST(canonical_json AS BLOB))<=8192 THEN canonical_json ELSE NULL END FROM correlation_step s JOIN request r ON r.id=s.request_id WHERE s.request_id=?1 ORDER BY step_id LIMIT 65", params![request_id]).await?;
        let mut steps = Vec::new();
        let mut bytes = 0usize;
        while let Some(row) = rows.next().await? {
            if steps.len() == 64 {
                return Err(invalid("stored step capacity exceeded"));
            }
            let step_id = row
                .get::<Option<String>>(0)?
                .ok_or_else(|| invalid("stored step identifier oversized"))?;
            let canonical_json = row
                .get::<Option<String>>(1)?
                .ok_or_else(|| invalid("stored step JSON oversized"))?;
            validate(&canonical_json, 8192)?;
            bytes = bytes.saturating_add(canonical_json.len());
            if bytes > 524288 {
                return Err(invalid("stored step bytes exceeded"));
            }
            steps.push(CorrelationStep {
                step_id,
                canonical_json,
            });
        }
        Ok(steps)
    }
}
