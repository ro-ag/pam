//! Crash-safe reservations; exact completed captures may refund unused capacity.
use super::{Store, StoreError};
use turso::params;

/// Durable charged work, including incomplete or cancelled reservations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RequestBudgetUsage {
    /// Connector/command attempts.
    pub attempts: u64,
    /// Physical HTTP sends.
    pub http_calls: u64,
    /// Reserved HTTP response bytes.
    pub http_bytes: u64,
    /// Reserved command capture bytes.
    pub command_bytes: u64,
}

/// One operation charged before external work starts.
#[derive(Debug, Clone, Copy)]
pub enum RequestBudgetCharge {
    /// One attempt.
    Attempt,
    /// One HTTP send and its maximum capture.
    Http(u64),
    /// Maximum command capture.
    Command(u64),
}

impl Store {
    /// Read existing counters and evidence allowance without creating or renewing either.
    /// The caller must authorize the original request before exposing this metadata.
    pub async fn request_budget_report(
        &self,
        id: &str,
        repository: &str,
    ) -> Result<Option<serde_json::Value>, StoreError> {
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query(
            "SELECT r.expires_at_ms,a.expires_at,a.remaining_bytes,a.remaining_pages FROM request r LEFT JOIN evidence_read_allowance a ON a.request_id=r.id AND a.repository=r.repo WHERE r.id=?1 AND r.repo=?2",
            params![id,repository]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let expiry: Option<i64> = row.get(0)?;
        let evidence_expiry: Option<i64> = row.get(1)?;
        let evidence_bytes: Option<i64> = row.get(2)?;
        let evidence_pages: Option<i64> = row.get(3)?;
        drop(rows);
        let allowance_state = match evidence_expiry {
            None => "not_initialized",
            Some(expiry) if expiry <= super::now_ts() => "expired",
            Some(_) if evidence_bytes.unwrap_or(0) <= 0 || evidence_pages.unwrap_or(0) <= 0 => {
                "exhausted"
            }
            Some(_) => "existing_allowance",
        };
        let usage = self.budget_usage_locked(id).await?;
        let work = usage.map(|u| serde_json::json!({
            "attempt_slots_charged":u.attempts,"http_call_slots_charged":u.http_calls,
            "http_bytes_charged":u.http_bytes,"command_bytes_charged":u.command_bytes,
            "attempt_slots_remaining":256-u.attempts,"http_call_slots_remaining":128-u.http_calls,
            "http_bytes_remaining":134_217_728-u.http_bytes,"command_bytes_remaining":134_217_728-u.command_bytes,
            "accounting":"completed_captures_plus_unsettled_reservations_not_physical_network_traffic"
        }));
        Ok(Some(
            serde_json::json!({"execution_expires_at_ms":expiry,"work":work,
            "evidence_reads":{"state":allowance_state,
                "expires_at":evidence_expiry,"remaining_bytes":evidence_bytes,"remaining_pages":evidence_pages,
                "authorization_state":"rechecked_per_read","availability":"not_guaranteed"}}),
        ))
    }

    /// Initialize once for an existing request, or restore its spent allowance.
    pub async fn load_request_budget(&self, id: &str) -> Result<RequestBudgetUsage, StoreError> {
        let _guard = self.conn_lock.lock().await;
        self.conn.execute("INSERT INTO request_budget(request_id) SELECT id FROM request WHERE id=?1 ON CONFLICT(request_id) DO NOTHING", params![id]).await?;
        self.budget_usage_locked(id)
            .await?
            .ok_or_else(|| StoreError::NotFound {
                table: "request",
                id: id.to_owned(),
            })
    }

    /// Atomically reserve against compiled ceilings; `None` means no work is allowed.
    pub async fn reserve_request_budget(
        &self,
        id: &str,
        charge: RequestBudgetCharge,
    ) -> Result<Option<RequestBudgetUsage>, StoreError> {
        let (attempt, calls, http, command) = match charge {
            RequestBudgetCharge::Attempt => (1, 0, 0, 0),
            RequestBudgetCharge::Http(bytes) if (1..=134_217_728).contains(&bytes) => {
                (0, 1, bytes, 0)
            }
            RequestBudgetCharge::Command(bytes) if (1..=134_217_728).contains(&bytes) => {
                (0, 0, 0, bytes)
            }
            _ => return Ok(None),
        };
        let http = i64::try_from(http).expect("compiled bound fits i64");
        let command = i64::try_from(command).expect("compiled bound fits i64");
        let _guard = self.conn_lock.lock().await;
        let changed=self.conn.execute("UPDATE request_budget SET attempts=attempts+?2,http_calls=http_calls+?3,http_bytes=http_bytes+?4,command_bytes=command_bytes+?5 WHERE request_id=?1 AND attempts BETWEEN 0 AND 256-?2 AND http_calls BETWEEN 0 AND 128-?3 AND http_bytes BETWEEN 0 AND 134217728-?4 AND command_bytes BETWEEN 0 AND 134217728-?5 AND EXISTS(SELECT 1 FROM request WHERE id=?1)",params![id,attempt,calls,http,command]).await?;
        if changed == 0 {
            return Ok(None);
        }
        self.budget_usage_locked(id).await
    }

    /// Refund only the unused bytes of one completed, consuming reservation.
    /// A caller must never retry an ambiguous failure: retaining charge is safe.
    pub async fn refund_request_budget(
        &self,
        id: &str,
        charge: RequestBudgetCharge,
    ) -> Result<RequestBudgetUsage, StoreError> {
        let (http, command) = match charge {
            RequestBudgetCharge::Http(bytes) if bytes <= 134_217_728 => (bytes, 0),
            RequestBudgetCharge::Command(bytes) if bytes <= 134_217_728 => (0, bytes),
            _ => {
                return Err(StoreError::UnexpectedValue {
                    column: "request_budget_refund",
                    value: "invalid refund".to_owned(),
                });
            }
        };
        let http = i64::try_from(http).expect("compiled bound");
        let command = i64::try_from(command).expect("compiled bound");
        let _guard = self.conn_lock.lock().await;
        let changed=self.conn.execute("UPDATE request_budget SET http_bytes=http_bytes-?2,command_bytes=command_bytes-?3 WHERE request_id=?1 AND http_bytes>=?2 AND command_bytes>=?3",params![id,http,command]).await?;
        if changed != 1 {
            return Err(StoreError::UnexpectedValue {
                column: "request_budget_refund",
                value: "missing reservation or insufficient charge".to_owned(),
            });
        }
        self.budget_usage_locked(id)
            .await?
            .ok_or_else(|| StoreError::NotFound {
                table: "request_budget",
                id: id.to_owned(),
            })
    }

    /// Caller owns the connection mutex; no transaction can be stranded by cancellation.
    async fn budget_usage_locked(
        &self,
        id: &str,
    ) -> Result<Option<RequestBudgetUsage>, StoreError> {
        let mut rows=self.conn.query("SELECT attempts,http_calls,http_bytes,command_bytes FROM request_budget WHERE request_id=?1",params![id]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let mut values = [0_u64; 4];
        for (index, limit) in [256, 128, 134_217_728, 134_217_728].into_iter().enumerate() {
            let n = row.get::<i64>(index)?;
            if !(0..=limit).contains(&n) {
                return Err(StoreError::UnexpectedValue {
                    column: "request_budget",
                    value: "counter outside compiled bound".to_owned(),
                });
            }
            values[index] = u64::try_from(n).expect("nonnegative counter");
        }
        Ok(Some(RequestBudgetUsage {
            attempts: values[0],
            http_calls: values[1],
            http_bytes: values[2],
            command_bytes: values[3],
        }))
    }
}
