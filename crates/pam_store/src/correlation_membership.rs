//! Bounded observed membership, separate from immutable product identity.
use std::collections::BTreeSet;

use super::{Store, StoreError};
use turso::params;

const MAX_MEMBERS: usize = 256;
const MAX_JSON_BYTES: usize = 16_384;

fn invalid(detail: &str) -> StoreError {
    StoreError::UnexpectedValue {
        column: "correlation_membership",
        value: detail.to_owned(),
    }
}

fn validate_binding(encoded: &str) -> Result<(), StoreError> {
    if encoded.len() > 8192 {
        return Err(invalid("binding exceeds byte limit"));
    }
    let binding: serde_json::Value =
        serde_json::from_str(encoded).map_err(|_| invalid("invalid binding JSON"))?;
    if binding["schema_version"] != 1
        || binding["decision"]["status"] != "matched"
        || binding["origin"]["connector"] != "github"
        || binding["origin"]["call"] != "run"
        || binding["identity"].get("job_ids").is_some()
        || ["run_id", "run_attempt"]
            .into_iter()
            .any(|key| binding["identity"][key].as_u64().is_none_or(|n| n == 0))
        || binding["identity"]["repository"]
            .as_str()
            .is_none_or(str::is_empty)
        || binding["origin"]["base_url"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "membership requires a matched immutable GitHub run attempt",
        ));
    }
    Ok(())
}

fn members(ids: &[u64]) -> Result<BTreeSet<u64>, StoreError> {
    if ids.len() > MAX_MEMBERS || ids.contains(&0) {
        return Err(invalid("membership requires at most 256 positive job IDs"));
    }
    Ok(ids.iter().copied().collect())
}

impl Store {
    /// Append observations only under the exact persisted immutable binding.
    /// `None` means the binding changed or is missing; overflow writes nothing.
    pub async fn append_correlation_membership(
        &self,
        request_id: &str,
        step_id: &str,
        expected_binding_json: &str,
        observed: &[u64],
    ) -> Result<Option<Vec<u64>>, StoreError> {
        validate_binding(expected_binding_json)?;
        let incoming = members(observed)?;
        let _guard = self.conn_lock.lock().await;
        let Some(current) = self
            .membership_locked(request_id, step_id, expected_binding_json)
            .await?
        else {
            return Ok(None);
        };
        let mut merged = members(&current)?;
        merged.extend(incoming);
        if merged.len() > MAX_MEMBERS {
            return Err(invalid("job membership capacity exhausted"));
        }
        let merged: Vec<u64> = merged.into_iter().collect();
        let encoded = serde_json::to_string(&merged)
            .map_err(|_| invalid("membership serialization failed"))?;
        if encoded.len() > MAX_JSON_BYTES {
            return Err(invalid("membership exceeds byte limit"));
        }
        self.conn.execute(
            "INSERT INTO correlation_membership(request_id,step_id,members_json) VALUES(?1,?2,?3)
             ON CONFLICT(request_id,step_id) DO UPDATE SET members_json=excluded.members_json",
            params![request_id, step_id, encoded],
        ).await?;
        Ok(Some(merged))
    }

    /// Restore membership only when its immutable parent still matches exactly.
    /// No membership row means no jobs have yet been observed for that binding.
    pub async fn read_correlation_membership(
        &self,
        request_id: &str,
        step_id: &str,
        expected_binding_json: &str,
    ) -> Result<Option<Vec<u64>>, StoreError> {
        validate_binding(expected_binding_json)?;
        let _guard = self.conn_lock.lock().await;
        self.membership_locked(request_id, step_id, expected_binding_json)
            .await
    }

    async fn membership_locked(
        &self,
        request_id: &str,
        step_id: &str,
        expected: &str,
    ) -> Result<Option<Vec<u64>>, StoreError> {
        let mut rows = self.conn.query(
            "SELECT CASE WHEN length(CAST(s.canonical_json AS BLOB))<=8192 THEN s.canonical_json ELSE NULL END,
             m.request_id,CASE WHEN length(CAST(m.members_json AS BLOB))<=16384 THEN m.members_json ELSE NULL END
             FROM correlation_step s LEFT JOIN correlation_membership m
             ON m.request_id=s.request_id AND m.step_id=s.step_id
             WHERE s.request_id=?1 AND s.step_id=?2",
            params![request_id, step_id],
        ).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        if row.get::<Option<String>>(0)?.as_deref() != Some(expected) {
            return Ok(None);
        }
        if row.get::<Option<String>>(1)?.is_none() {
            return Ok(Some(Vec::new()));
        }
        let encoded = row
            .get::<Option<String>>(2)?
            .ok_or_else(|| invalid("stored membership exceeds byte limit"))?;
        let ids: Vec<u64> =
            serde_json::from_str(&encoded).map_err(|_| invalid("invalid stored membership"))?;
        let canonical = members(&ids)?;
        if canonical.len() != ids.len() {
            return Err(invalid("stored membership contains duplicate IDs"));
        }
        Ok(Some(canonical.into_iter().collect()))
    }
}
