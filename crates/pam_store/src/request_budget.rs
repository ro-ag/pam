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
