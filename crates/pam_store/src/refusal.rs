//! Refusals decided before a request row exists.
//!
//! An audit row needs a request row (`audit.request_id` is NOT NULL and a
//! foreign key), so a refusal that happens before admission could never have
//! one. This module is where those live: bounded, coalesced and attribution
//! only (see migration 18). A refusal is recorded once per run of identical
//! attempts, with the count of the run, so a client that hammers the daemon
//! neither grows the table nor multiplies the writes.
//!
//! Nothing here authorizes anything and no gate reads it. The peer columns are
//! the daemon's view of the connection; `agent`, `repo`, `request_id` and
//! `capability` are what the client claimed, bounded by [`MAX_AGENT_BYTES`],
//! [`MAX_REPO_BYTES`] and friends. The writer truncates to those bounds
//! instead of refusing: a refusal that cannot be recorded because its text was
//! long is the flaw this table exists to close.
//!
//! Bounds: the newest [`MAX_REFUSALS`] rows are kept, each write that inserts
//! prunes; [`Store::prune_refusals_before`] is the audit window's half, driven
//! by retention.

use rusqlite::params;

use super::{RequestIngress, Store, StoreError};
use crate::db::{Db, Row};

/// How many refusal rows are kept (the newest).
pub const MAX_REFUSALS: u32 = 2_000;

/// Longest `cause` kept, in bytes.
pub const MAX_CAUSE_BYTES: usize = 128;

/// Longest `detail` kept, in bytes.
pub const MAX_DETAIL_BYTES: usize = 512;

/// Longest `peer_exe` kept, in bytes.
pub const MAX_PEER_EXE_BYTES: usize = 1024;

/// Longest claimed `agent` kept, in bytes.
pub const MAX_AGENT_BYTES: usize = 256;

/// Longest claimed `repo` kept, in bytes.
pub const MAX_REPO_BYTES: usize = 1024;

/// Longest claimed `request_id` kept, in bytes.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Longest claimed `capability` kept, in bytes.
pub const MAX_CAPABILITY_BYTES: usize = 128;

/// Largest page [`Store::list_refusals`] returns.
pub const MAX_REFUSAL_LIST_LIMIT: u64 = 500;

/// One refusal, as written by an insert: the run of attempts it stands for
/// and who the daemon and the client say they were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRecord {
    /// The first attempt of the run (unix seconds).
    pub ts: i64,
    /// The latest attempt of the run (unix seconds); `ts` for a single one.
    pub last_ts: i64,
    /// The plane the refusal happened on.
    pub ingress: RequestIngress,
    /// Stable machine cause, the same wording the client was refused with.
    pub cause: String,
    /// One short line of context.
    pub detail: String,
    /// How many attempts the row stands for (at least one).
    pub count: u64,
    /// The peer's user id as the kernel reported it; `None` where it has none.
    pub peer_uid: Option<u32>,
    /// The peer's process id as the kernel reported it; `None` where it has none.
    pub peer_pid: Option<u32>,
    /// The executable behind the pid, resolved by the daemon; `None` on a miss.
    pub peer_exe: Option<String>,
    /// The agent label the client claimed. Attribution only.
    pub agent: Option<String>,
    /// The repository the client claimed. Attribution only.
    pub repo: Option<String>,
    /// The request id the client supplied. There is no such request.
    pub request_id: Option<String>,
    /// The capability the client named, when its envelope parsed that far.
    pub capability: Option<String>,
}

/// One write of a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalWrite {
    /// A new row.
    Insert(RefusalRecord),
    /// More attempts of a run already written: adds `count` to row `id` and
    /// moves its `last_ts`. Answers `None` when the row is gone (pruned).
    Bump {
        /// The row, as an earlier insert answered it.
        id: i64,
        /// Attempts to add.
        count: u64,
        /// The latest attempt (unix seconds).
        last_ts: i64,
    },
}

/// One row of `refusal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRow {
    /// Row id.
    pub id: i64,
    /// The first attempt of the run (unix seconds).
    pub ts: i64,
    /// The latest attempt of the run (unix seconds).
    pub last_ts: i64,
    /// The plane the refusal happened on.
    pub ingress: RequestIngress,
    /// Stable machine cause.
    pub cause: String,
    /// One short line of context.
    pub detail: String,
    /// How many attempts the row stands for.
    pub count: u64,
    /// The peer's user id as the kernel reported it.
    pub peer_uid: Option<u32>,
    /// The peer's process id as the kernel reported it.
    pub peer_pid: Option<u32>,
    /// The executable behind the pid.
    pub peer_exe: Option<String>,
    /// The agent label the client claimed.
    pub agent: Option<String>,
    /// The repository the client claimed.
    pub repo: Option<String>,
    /// The request id the client supplied.
    pub request_id: Option<String>,
    /// The capability the client named.
    pub capability: Option<String>,
}

/// `text` cut to at most `max` bytes on a character boundary.
#[must_use]
pub fn bounded(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn clip(text: Option<String>, max: usize) -> Option<String> {
    text.map(|text| bounded(&text, max).to_owned())
}

fn narrow(value: Option<i64>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

fn count_value(count: u64) -> i64 {
    i64::try_from(count.max(1)).unwrap_or(i64::MAX)
}

const COLUMNS: &str = "id, ts, last_ts, ingress, cause, detail, count, peer_uid, peer_pid, \
     peer_exe, agent, repo, request_id, capability";

fn refusal_row(row: &Row<'_>) -> Result<RefusalRow, StoreError> {
    let ingress: String = row.get(3)?;
    let count: i64 = row.get(6)?;
    Ok(RefusalRow {
        id: row.get(0)?,
        ts: row.get(1)?,
        last_ts: row.get(2)?,
        ingress: RequestIngress::parse(&ingress)?,
        cause: row.get(4)?,
        detail: row.get(5)?,
        count: u64::try_from(count).unwrap_or(0),
        peer_uid: narrow(row.get(7)?),
        peer_pid: narrow(row.get(8)?),
        peer_exe: row.get(9)?,
        agent: row.get(10)?,
        repo: row.get(11)?,
        request_id: row.get(12)?,
        capability: row.get(13)?,
    })
}

fn insert(conn: Db<'_>, record: RefusalRecord) -> Result<i64, StoreError> {
    let RefusalRecord {
        ts,
        last_ts,
        ingress,
        cause,
        detail,
        count,
        peer_uid,
        peer_pid,
        peer_exe,
        agent,
        repo,
        request_id,
        capability,
    } = record;
    // A cause is never empty: the CHECK would refuse the whole batch.
    let cause = if cause.is_empty() {
        "unknown".to_owned()
    } else {
        bounded(&cause, MAX_CAUSE_BYTES).to_owned()
    };
    conn.execute(
        "INSERT INTO refusal (ts, last_ts, ingress, cause, detail, count, peer_uid, peer_pid, \
         peer_exe, agent, repo, request_id, capability)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            ts,
            last_ts.max(ts),
            ingress.as_str(),
            cause,
            bounded(&detail, MAX_DETAIL_BYTES),
            count_value(count),
            peer_uid,
            peer_pid,
            clip(peer_exe, MAX_PEER_EXE_BYTES),
            clip(agent, MAX_AGENT_BYTES),
            clip(repo, MAX_REPO_BYTES),
            clip(request_id, MAX_REQUEST_ID_BYTES),
            clip(capability, MAX_CAPABILITY_BYTES),
        ],
    )?;
    let mut stmt = conn.prepare("SELECT last_insert_rowid()")?;
    let mut rows = stmt.query(())?;
    rows.next()?.map_or(Ok(0), |row| row.get(0))
}

impl Store {
    /// Applies a batch of refusal writes in one transaction and answers, per
    /// write, the row it landed on: the new id of an insert, the bumped id of
    /// a bump (`None` when that row had been pruned). The table is then
    /// pruned to the newest [`MAX_REFUSALS`] rows, so the bound holds
    /// whatever the batch did.
    ///
    /// Text beyond its column's bound is truncated, never refused.
    pub async fn write_refusals(
        &self,
        writes: Vec<RefusalWrite>,
    ) -> Result<Vec<Option<i64>>, StoreError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        self.transact(move |conn| {
            let mut landed = Vec::with_capacity(writes.len());
            let mut inserted = false;
            for write in writes {
                match write {
                    RefusalWrite::Insert(record) => {
                        landed.push(Some(insert(conn, record)?));
                        inserted = true;
                    }
                    RefusalWrite::Bump { id, count, last_ts } => {
                        let changed = conn.execute(
                            "UPDATE refusal SET count = count + ?2, \
                             last_ts = MAX(last_ts, ?3) WHERE id = ?1",
                            params![id, count_value(count), last_ts],
                        )?;
                        landed.push((changed == 1).then_some(id));
                    }
                }
            }
            if inserted {
                conn.execute(
                    "DELETE FROM refusal WHERE id NOT IN (
                         SELECT id FROM refusal ORDER BY id DESC LIMIT ?1)",
                    params![MAX_REFUSALS],
                )?;
            }
            Ok(landed)
        })
        .await
    }

    /// Refusal rows, newest first by their first attempt, narrowed like the
    /// request list: a row whose claimed repository, agent or capability was
    /// never recorded matches no filter on it. `limit` is clamped to
    /// `1..=`[`MAX_REFUSAL_LIST_LIMIT`].
    pub async fn list_refusals(
        &self,
        limit: u64,
        repo: Option<&str>,
        agent: Option<&str>,
        capability: Option<&str>,
    ) -> Result<Vec<RefusalRow>, StoreError> {
        let repo = repo.map(str::to_owned);
        let agent = agent.map(str::to_owned);
        let capability = capability.map(str::to_owned);
        self.read(move |conn| {
            let limit = limit.clamp(1, MAX_REFUSAL_LIST_LIMIT);
            let mut clauses: Vec<String> = Vec::new();
            let mut args: Vec<String> = Vec::new();
            for (column, value) in [("repo", repo), ("agent", agent), ("capability", capability)] {
                if let Some(value) = value {
                    args.push(value);
                    clauses.push(format!("{column} = ?{}", args.len()));
                }
            }
            let where_sql = if clauses.is_empty() {
                String::new()
            } else {
                format!("WHERE {} ", clauses.join(" AND "))
            };
            let mut stmt = conn.prepare(&format!(
                "SELECT {COLUMNS} FROM refusal {where_sql}ORDER BY ts DESC, id DESC LIMIT {limit}"
            ))?;
            let mut rows = stmt.query(rusqlite::params_from_iter(args.iter()))?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(refusal_row(&row)?);
            }
            Ok(out)
        })
        .await
    }

    /// How many refusal rows are kept right now.
    pub async fn refusal_rows(&self) -> Result<u64, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM refusal")?;
            let mut rows = stmt.query(())?;
            let count: i64 = rows.next()?.map_or(Ok(0), |row| row.get(0))?;
            Ok(u64::try_from(count).unwrap_or(0))
        })
        .await
    }

    /// Deletes the refusal rows whose latest attempt is older than
    /// `cutoff_ts`, the audit window's half of retention. Answers how many
    /// rows went. Nothing depends on a refusal row, so there is nothing to
    /// remove with them.
    pub async fn prune_refusals_before(&self, cutoff_ts: i64) -> Result<u64, StoreError> {
        self.transact(move |conn| {
            conn.execute("DELETE FROM refusal WHERE last_ts < ?1", params![cutoff_ts])
        })
        .await
    }
}
