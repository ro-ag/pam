//! Public watch progress is a published metadata projection, never a checkpoint read.
use super::{Store, StoreError};
use serde_json::{Value, json};
use turso::params;

impl Store {
    /// Only the journal-committed published observation, never a newer uncommitted row.
    pub async fn flow_watch_progress(
        &self,
        ticket: &str,
        repository: &str,
    ) -> Result<Option<String>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut cursor_rows=self.conn.query("SELECT CASE WHEN LENGTH(CAST(checkpoint_json AS BLOB))<=131072 THEN checkpoint_json ELSE NULL END FROM flow_journal WHERE request_id=?1",params![ticket]).await?;
        let Some(cursor_row) = cursor_rows.next().await? else {
            return Ok(None);
        };
        let Some(cursor_json) = cursor_row.get::<Option<String>>(0)? else {
            return Ok(None);
        };
        let Some((id, schedule)) = committed_evidence(&cursor_json) else {
            return Ok(None);
        };
        drop(cursor_rows);
        let mut rows=self.conn.query("SELECT CASE WHEN LENGTH(CAST(e.meta_json AS BLOB))<=16384 THEN e.meta_json ELSE NULL END,e.id FROM evidence e JOIN evidence_view v ON v.evidence_id=e.id AND v.request_id=e.request_id JOIN request r ON r.id=e.request_id WHERE e.request_id=?1 AND v.repository=?2 AND r.repo=?2 AND e.kind='flow.watch' AND e.id=?3 AND v.expired_at IS NULL LIMIT 1",params![ticket,repository,id]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let Some(raw) = row.get::<Option<String>>(0)? else {
            return Ok(None);
        };
        let id: String = row.get(1)?;
        Ok(progress(&raw, &id, schedule))
    }
}

fn progress(raw: &str, id: &str, schedule: Option<(u64, i64)>) -> Option<String> {
    let meta: Value = serde_json::from_str(raw).ok()?;
    let value = meta.get("watch_progress")?;
    let mut out = json!({});
    for (key, max) in [
        ("step", 128),
        ("connector", 32),
        ("status", 64),
        ("watch_state", 16),
        ("evidence_id", 128),
    ] {
        let text = value[key]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control))?;
        out[key] = json!(text);
    }
    if out["evidence_id"] != id
        || !matches!(
            out["watch_state"].as_str()?,
            "pending" | "terminal" | "unavailable"
        )
    {
        return None;
    }
    out["polls"] = json!(value["polls"].as_u64().filter(|n| *n <= 100)?);
    out["omissions"] = json!(value["omissions"].as_u64()?);
    out["next_poll_at"] = if value["next_poll_at"].is_null() {
        Value::Null
    } else {
        json!(value["next_poll_at"].as_i64()?)
    };
    if let Some((polls, next)) = schedule {
        out["polls"] = json!(polls);
        out["next_poll_at"] = json!(next);
    }
    serde_json::to_string(&out).ok()
}

fn committed_evidence(raw: &str) -> Option<(String, Option<(u64, i64)>)> {
    let cursor: Value = serde_json::from_str(raw).ok()?;
    let (value, schedule) = if let Some(watch) = cursor.get("watch").filter(|v| !v.is_null()) {
        let polls = watch["polls"].as_u64().filter(|n| *n <= 100)?;
        let next = watch["next_poll_ms"].as_i64()?;
        (watch.get("last_evidence")?, Some((polls, next)))
    } else {
        (cursor.get("last_watch_evidence")?, None)
    };
    let id = value
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control))?;
    Some((id.to_owned(), schedule))
}
