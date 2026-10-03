//! The boundary self-check record: accepted `doctor.report` documents and the
//! daemon's own observations (admin contacts, unknown public harnesses), both
//! bounded, plus the two peer-resolution columns on the request row.
//!
//! Everything here is attribution. The verdict in a report is the client's
//! claim, stored beside the kernel peer facts the daemon recorded itself; an
//! observation is what the daemon saw on its own side. Nothing is authorized
//! by any of it, and no gate reads these tables (see migration 16).
//!
//! Bounds: the newest [`MAX_BOUNDARY_REPORTS`] reports, the newest
//! [`MAX_BOUNDARY_OBSERVATIONS`] unexpected observations and the newest
//! [`MAX_EXPECTED_OBSERVATIONS`] expected ones (the GUI's own admin contacts)
//! are kept; each insert prunes. Lifetime counters in `setting`
//! ([`SETTING_ADMIN_CONTACTS_TOTAL`], [`SETTING_ADMIN_CONTACTS_EXPECTED_TOTAL`],
//! [`SETTING_PUBLIC_UNKNOWN_TOTAL`]) survive the pruning, so a flood neither
//! grows the store nor erases that the first contact happened.

use rusqlite::params;

use super::{AuditEntry, OwnedAudit, Store, StoreError, now_ts};
use crate::db::{Db, Row};

/// How many accepted reports are kept (the newest).
pub const MAX_BOUNDARY_REPORTS: u32 = 64;

/// How many unexpected observations are kept (the newest).
pub const MAX_BOUNDARY_OBSERVATIONS: u32 = 256;

/// How many expected observations (the trusted image's own admin contacts)
/// are kept (the newest).
pub const MAX_EXPECTED_OBSERVATIONS: u32 = 32;

/// Largest report document the store accepts, in serialized bytes; the
/// table's CHECK says the same.
pub const MAX_BOUNDARY_REPORT_BYTES: usize = 16 * 1024;

/// Observation kind: a connection the private admin listener accepted.
pub const OBSERVATION_ADMIN_CONTACT: &str = "admin_contact";

/// Observation kind: a loopback connection that failed the admin nonce
/// handshake (Windows).
pub const OBSERVATION_ADMIN_HANDSHAKE_FAILED: &str = "admin_handshake_failed";

/// Observation kind: a public request whose resolved ancestry is neither a
/// known agent nor the relay.
pub const OBSERVATION_PUBLIC_UNKNOWN_HARNESS: &str = "public_unknown_harness";

/// `setting` key: lifetime count of unexpected admin contacts (both admin
/// kinds), deduplicated ones included.
pub const SETTING_ADMIN_CONTACTS_TOTAL: &str = "boundary.admin_contacts_total";

/// `setting` key: lifetime count of expected admin contacts.
pub const SETTING_ADMIN_CONTACTS_EXPECTED_TOTAL: &str = "boundary.admin_contacts_expected_total";

/// `setting` key: lifetime count of public requests from an unknown harness.
pub const SETTING_PUBLIC_UNKNOWN_TOTAL: &str = "boundary.public_unknown_total";

/// Longest text accepted in any peer or detail column.
const MAX_TEXT_BYTES: usize = 1024;

/// The peer of a request or a connection, as the daemon saw it: the kernel's
/// uid and pid, and the daemon's own resolution of the executable behind the
/// pid and the classification of its ancestry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundaryPeer {
    /// Effective user id at accept, where the kernel reports one.
    pub uid: Option<u32>,
    /// Process id at accept, where the kernel reports one.
    pub pid: Option<u32>,
    /// Executable path resolved from the pid; `None` when it could not be.
    pub exe: Option<String>,
    /// Ancestry classification: a known agent, `relay`, or the nearest
    /// parent's name; `None` when it could not be resolved.
    pub harness: Option<String>,
}

/// What one accepted `doctor.report` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryReportInsert<'a> {
    /// The `doctor.report` request's id (the row must exist).
    pub request_id: &'a str,
    /// The client's clock, from the document.
    pub report_ts: i64,
    /// `established` or `not_established`; the CHECK refuses anything else.
    pub verdict: &'a str,
    /// Probe ids that were allowed where denial was required, as JSON.
    pub failed_json: &'a str,
    /// Probe ids whose result was unknown, as JSON.
    pub unverified_json: &'a str,
    /// Self-reported `caller.agent`.
    pub agent: &'a str,
    /// Self-reported `caller.repo`.
    pub repo: &'a str,
    /// The daemon's view of the peer at receipt.
    pub peer: &'a BoundaryPeer,
    /// The hello's relay marker (self-reported).
    pub relayed: bool,
    /// The client's version string.
    pub client_version: &'a str,
    /// The whole document, at most [`MAX_BOUNDARY_REPORT_BYTES`].
    pub report_json: &'a str,
}

/// One row of `boundary_report`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryReportRow {
    /// Row id; the `report_id` the capability answers with.
    pub id: i64,
    /// The request that carried it; `None` once retention pruned it.
    pub request_id: Option<String>,
    /// When the daemon received it (unix seconds).
    pub ts: i64,
    /// The client's clock.
    pub report_ts: i64,
    /// The client's verdict.
    pub verdict: String,
    /// Probe ids that failed, as sent.
    pub failed: Vec<String>,
    /// Probe ids that were unverified, as sent.
    pub unverified: Vec<String>,
    /// Self-reported agent.
    pub agent: String,
    /// Self-reported repository.
    pub repo: String,
    /// The daemon's view of the peer.
    pub peer: BoundaryPeer,
    /// The relay marker.
    pub relayed: bool,
    /// The client's version.
    pub client_version: String,
    /// The document.
    pub report_json: String,
}

/// What one observation writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryObservationInsert<'a> {
    /// One of the three `OBSERVATION_*` kinds.
    pub kind: &'a str,
    /// The contact is the trusted image's own (the GUI).
    pub expected: bool,
    /// The peer as the daemon saw it.
    pub peer: &'a BoundaryPeer,
    /// Free-form context, one line.
    pub detail: Option<&'a str>,
    /// Already explained by this `doctor.report` request.
    pub attributed: Option<&'a str>,
}

/// One row of `boundary_observation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryObservationRow {
    /// Row id.
    pub id: i64,
    /// When it was observed (unix seconds).
    pub ts: i64,
    /// One of the three `OBSERVATION_*` kinds.
    pub kind: String,
    /// The contact is the trusted image's own.
    pub expected: bool,
    /// The peer as the daemon saw it.
    pub peer: BoundaryPeer,
    /// Free-form context.
    pub detail: Option<String>,
    /// The `doctor.report` request that explains it, when one does.
    pub attributed: Option<String>,
}

/// The figures the `status.boundary` block is built from, read in one pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoundaryCensus {
    /// The newest accepted report.
    pub last_report: Option<BoundaryReportRow>,
    /// Reports currently kept.
    pub reports_retained: u32,
    /// Of those, `established`.
    pub reports_established: u32,
    /// Of those, `not_established`.
    pub reports_not_established: u32,
    /// Unexpected admin contacts (both admin kinds) nobody has explained.
    pub admin_unattributed: u32,
    /// Of those, observed in the last 24 hours.
    pub admin_unattributed_24h: u32,
    /// Lifetime unexpected admin contacts.
    pub admin_total: u64,
    /// Lifetime expected admin contacts.
    pub admin_expected_total: u64,
    /// The newest unexpected admin contact.
    pub last_admin_contact: Option<BoundaryObservationRow>,
    /// The newest expected admin contact.
    pub last_expected_admin_contact: Option<BoundaryObservationRow>,
    /// Lifetime public requests from an unknown harness.
    pub public_unknown_total: u64,
    /// The newest of those.
    pub last_public_unknown: Option<BoundaryObservationRow>,
}

fn invalid(what: &str) -> StoreError {
    StoreError::UnexpectedValue {
        column: "boundary",
        value: what.to_owned(),
    }
}

fn check_text(field: &str, text: &str) -> Result<(), StoreError> {
    if text.len() > MAX_TEXT_BYTES || text.chars().any(char::is_control) {
        return Err(invalid(&format!(
            "{field} exceeds {MAX_TEXT_BYTES} bytes or contains a control character"
        )));
    }
    Ok(())
}

fn check_peer(peer: &BoundaryPeer) -> Result<(), StoreError> {
    if let Some(exe) = &peer.exe {
        check_text("peer_exe", exe)?;
    }
    if let Some(harness) = &peer.harness {
        check_text("peer_harness", harness)?;
    }
    Ok(())
}

fn ids(json: &str) -> Vec<String> {
    serde_json::from_str(json).unwrap_or_default()
}

const REPORT_COLUMNS: &str = "id, request_id, ts, report_ts, verdict, failed_json, unverified_json, \
     agent, repo, peer_uid, peer_pid, peer_exe, peer_harness, relayed, client_version, report_json";

const OBSERVATION_COLUMNS: &str =
    "id, ts, kind, expected, peer_uid, peer_pid, peer_exe, peer_harness, detail, attributed";

fn narrow(value: Option<i64>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

fn report_row(row: &Row<'_>) -> Result<BoundaryReportRow, StoreError> {
    let failed: String = row.get(5)?;
    let unverified: String = row.get(6)?;
    Ok(BoundaryReportRow {
        id: row.get(0)?,
        request_id: row.get(1)?,
        ts: row.get(2)?,
        report_ts: row.get(3)?,
        verdict: row.get(4)?,
        failed: ids(&failed),
        unverified: ids(&unverified),
        agent: row.get(7)?,
        repo: row.get(8)?,
        peer: BoundaryPeer {
            uid: narrow(row.get(9)?),
            pid: narrow(row.get(10)?),
            exe: row.get(11)?,
            harness: row.get(12)?,
        },
        relayed: row.get::<i64>(13)? == 1,
        client_version: row.get(14)?,
        report_json: row.get(15)?,
    })
}

fn observation_row(row: &Row<'_>) -> Result<BoundaryObservationRow, StoreError> {
    Ok(BoundaryObservationRow {
        id: row.get(0)?,
        ts: row.get(1)?,
        kind: row.get(2)?,
        expected: row.get::<i64>(3)? == 1,
        peer: BoundaryPeer {
            uid: narrow(row.get(4)?),
            pid: narrow(row.get(5)?),
            exe: row.get(6)?,
            harness: row.get(7)?,
        },
        detail: row.get(8)?,
        attributed: row.get(9)?,
    })
}

/// Reads one counter from `setting`; unset or unparsable reads as zero.
fn counter(conn: Db<'_>, key: &str) -> Result<u64, StoreError> {
    let mut stmt = conn.prepare("SELECT value FROM setting WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    Ok(rows
        .next()?
        .map(|row| row.get::<String>(0))
        .transpose()?
        .and_then(|value| value.parse().ok())
        .unwrap_or(0))
}

/// Adds one to a counter in `setting`.
fn bump(conn: Db<'_>, key: &str) -> Result<(), StoreError> {
    let next = counter(conn, key)?.saturating_add(1);
    conn.execute(
        "INSERT INTO setting (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, next.to_string()],
    )?;
    Ok(())
}

fn first_observation(
    conn: Db<'_>,
    filter: &str,
) -> Result<Option<BoundaryObservationRow>, StoreError> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {OBSERVATION_COLUMNS} FROM boundary_observation WHERE {filter} \
         ORDER BY ts DESC, id DESC LIMIT 1"
    ))?;
    let mut rows = stmt.query(())?;
    rows.next()?.map(|row| observation_row(&row)).transpose()
}

fn scalar(conn: Db<'_>, sql: &str, params: impl rusqlite::Params) -> Result<i64, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    rows.next()?.map_or(Ok(0), |row| row.get(0))
}

fn count_u32(conn: Db<'_>, sql: &str, params: impl rusqlite::Params) -> Result<u32, StoreError> {
    Ok(u32::try_from(scalar(conn, sql, params)?).unwrap_or(u32::MAX))
}

impl Store {
    /// Records an accepted report and its `doctor.report` audit row in one
    /// transaction, pruning to the newest [`MAX_BOUNDARY_REPORTS`]. Answers
    /// the row id. A document over [`MAX_BOUNDARY_REPORT_BYTES`], a verdict
    /// outside the two recordable ones or an unknown request fail the whole
    /// write.
    pub async fn insert_boundary_report(
        &self,
        insert: BoundaryReportInsert<'_>,
        audit: AuditEntry<'_>,
    ) -> Result<i64, StoreError> {
        if insert.report_json.len() > MAX_BOUNDARY_REPORT_BYTES {
            return Err(invalid("report document exceeds 16 KiB"));
        }
        if !matches!(insert.verdict, "established" | "not_established") {
            return Err(invalid("report verdict is not recordable"));
        }
        check_text("request_id", insert.request_id)?;
        check_text("agent", insert.agent)?;
        check_text("repo", insert.repo)?;
        check_text("client_version", insert.client_version)?;
        check_peer(insert.peer)?;
        let request_id = insert.request_id.to_owned();
        let verdict = insert.verdict.to_owned();
        let failed_json = insert.failed_json.to_owned();
        let unverified_json = insert.unverified_json.to_owned();
        let agent = insert.agent.to_owned();
        let repo = insert.repo.to_owned();
        let peer = insert.peer.clone();
        let relayed = i64::from(insert.relayed);
        let client_version = insert.client_version.to_owned();
        let report_json = insert.report_json.to_owned();
        let report_ts = insert.report_ts;
        let audit = OwnedAudit::new(audit);
        self.transact(move |conn| {
            conn.execute(
                "INSERT INTO boundary_report (request_id, ts, report_ts, verdict, failed_json, \
                 unverified_json, agent, repo, peer_uid, peer_pid, peer_exe, peer_harness, \
                 relayed, client_version, report_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    request_id,
                    now_ts(),
                    report_ts,
                    verdict,
                    failed_json,
                    unverified_json,
                    agent,
                    repo,
                    peer.uid,
                    peer.pid,
                    peer.exe,
                    peer.harness,
                    relayed,
                    client_version,
                    report_json
                ],
            )?;
            let id = scalar(conn, "SELECT last_insert_rowid()", ())?;
            conn.execute(
                "DELETE FROM boundary_report WHERE id NOT IN (
                     SELECT id FROM boundary_report ORDER BY ts DESC, id DESC LIMIT ?1)",
                params![MAX_BOUNDARY_REPORTS],
            )?;
            Self::insert_audit_row(conn, &request_id, audit.entry())?;
            Ok(id)
        })
        .await
    }

    /// Records one observation, pruning its class (expected or not) to its
    /// bound and moving the lifetime counter, in one transaction. Answers
    /// the row id.
    pub async fn insert_boundary_observation(
        &self,
        insert: BoundaryObservationInsert<'_>,
    ) -> Result<i64, StoreError> {
        let counter_key = counter_key_for(insert.kind, insert.expected)?;
        check_peer(insert.peer)?;
        if let Some(detail) = insert.detail {
            check_text("detail", detail)?;
        }
        if let Some(attributed) = insert.attributed {
            check_text("attributed", attributed)?;
        }
        let kind = insert.kind.to_owned();
        let expected = i64::from(insert.expected);
        let peer = insert.peer.clone();
        let detail = insert.detail.map(str::to_owned);
        let attributed = insert.attributed.map(str::to_owned);
        let keep = if insert.expected {
            MAX_EXPECTED_OBSERVATIONS
        } else {
            MAX_BOUNDARY_OBSERVATIONS
        };
        self.transact(move |conn| {
            conn.execute(
                "INSERT INTO boundary_observation (ts, kind, expected, peer_uid, peer_pid, \
                 peer_exe, peer_harness, detail, attributed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    now_ts(),
                    kind,
                    expected,
                    peer.uid,
                    peer.pid,
                    peer.exe,
                    peer.harness,
                    detail,
                    attributed
                ],
            )?;
            let id = scalar(conn, "SELECT last_insert_rowid()", ())?;
            conn.execute(
                "DELETE FROM boundary_observation WHERE expected = ?1 AND id NOT IN (
                     SELECT id FROM boundary_observation WHERE expected = ?1
                     ORDER BY ts DESC, id DESC LIMIT ?2)",
                params![expected, keep],
            )?;
            bump(conn, counter_key)?;
            Ok(id)
        })
        .await
    }

    /// Moves the lifetime counter for an observation that was seen but not
    /// written (deduplicated against a recent row of the same peer).
    pub async fn count_boundary_observation(
        &self,
        kind: &str,
        expected: bool,
    ) -> Result<(), StoreError> {
        let counter_key = counter_key_for(kind, expected)?;
        self.run(move |conn| bump(conn, counter_key)).await
    }

    /// Attributes every unexplained unexpected admin contact of kernel pid
    /// `pid` observed at or after `since_ts` to `request_id`. Answers how
    /// many rows changed.
    pub async fn attribute_boundary_observations(
        &self,
        pid: u32,
        since_ts: i64,
        request_id: &str,
    ) -> Result<u64, StoreError> {
        check_text("request_id", request_id)?;
        let request_id = request_id.to_owned();
        self.run(move |conn| {
            conn.execute(
                "UPDATE boundary_observation SET attributed = ?1
                 WHERE peer_pid = ?2 AND ts >= ?3 AND attributed IS NULL AND expected = 0
                   AND kind IN ('admin_contact', 'admin_handshake_failed')",
                params![request_id, pid, since_ts],
            )
        })
        .await
    }

    /// The newest `limit` reports, newest first.
    pub async fn list_boundary_reports(
        &self,
        limit: u32,
    ) -> Result<Vec<BoundaryReportRow>, StoreError> {
        let limit = limit.min(MAX_BOUNDARY_REPORTS);
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {REPORT_COLUMNS} FROM boundary_report ORDER BY ts DESC, id DESC LIMIT ?1"
            ))?;
            let mut rows = stmt.query(params![limit])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(report_row(&row)?);
            }
            Ok(out)
        })
        .await
    }

    /// The newest `limit` observations of every kind, newest first.
    pub async fn list_boundary_observations(
        &self,
        limit: u32,
    ) -> Result<Vec<BoundaryObservationRow>, StoreError> {
        let limit = limit.min(MAX_BOUNDARY_OBSERVATIONS + MAX_EXPECTED_OBSERVATIONS);
        self.read(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {OBSERVATION_COLUMNS} FROM boundary_observation \
                 ORDER BY ts DESC, id DESC LIMIT ?1"
            ))?;
            let mut rows = stmt.query(params![limit])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(observation_row(&row)?);
            }
            Ok(out)
        })
        .await
    }

    /// Everything the `status.boundary` block is built from, in one read.
    pub async fn boundary_census(&self) -> Result<BoundaryCensus, StoreError> {
        self.read(move |conn| {
            let last_report = {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {REPORT_COLUMNS} FROM boundary_report ORDER BY ts DESC, id DESC LIMIT 1"
                ))?;
                let mut rows = stmt.query(())?;
                rows.next()?.map(|row| report_row(&row)).transpose()?
            };
            let reports_retained = count_u32(conn, "SELECT count(*) FROM boundary_report", ())?;
            let reports_established = count_u32(
                conn,
                "SELECT count(*) FROM boundary_report WHERE verdict = 'established'",
                (),
            )?;
            let unattributed = "expected = 0 AND attributed IS NULL \
                 AND kind IN ('admin_contact', 'admin_handshake_failed')";
            let admin_unattributed = count_u32(
                conn,
                &format!("SELECT count(*) FROM boundary_observation WHERE {unattributed}"),
                (),
            )?;
            let admin_unattributed_24h = count_u32(
                conn,
                &format!(
                    "SELECT count(*) FROM boundary_observation WHERE {unattributed} AND ts >= ?1"
                ),
                params![now_ts() - 86_400],
            )?;
            Ok(BoundaryCensus {
                last_report,
                reports_retained,
                reports_established,
                reports_not_established: reports_retained.saturating_sub(reports_established),
                admin_unattributed,
                admin_unattributed_24h,
                admin_total: counter(conn, SETTING_ADMIN_CONTACTS_TOTAL)?,
                admin_expected_total: counter(conn, SETTING_ADMIN_CONTACTS_EXPECTED_TOTAL)?,
                last_admin_contact: first_observation(
                    conn,
                    "expected = 0 AND kind IN ('admin_contact', 'admin_handshake_failed')",
                )?,
                last_expected_admin_contact: first_observation(
                    conn,
                    "expected = 1 AND kind IN ('admin_contact', 'admin_handshake_failed')",
                )?,
                public_unknown_total: counter(conn, SETTING_PUBLIC_UNKNOWN_TOTAL)?,
                last_public_unknown: first_observation(conn, "kind = 'public_unknown_harness'")?,
            })
        })
        .await
    }

    /// Writes the daemon's resolution of a public request's peer on its row.
    /// Answers whether the row exists.
    pub async fn set_request_peer_facts(
        &self,
        id: &str,
        exe: Option<&str>,
        harness: Option<&str>,
    ) -> Result<bool, StoreError> {
        if let Some(exe) = exe {
            check_text("peer_exe", exe)?;
        }
        if let Some(harness) = harness {
            check_text("peer_harness", harness)?;
        }
        let id = id.to_owned();
        let exe = exe.map(str::to_owned);
        let harness = harness.map(str::to_owned);
        self.run(move |conn| {
            let changed = conn.execute(
                "UPDATE request SET peer_exe = ?1, peer_harness = ?2 WHERE id = ?3",
                params![exe, harness, id],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    /// The daemon's resolution of a request's peer: `(peer_exe,
    /// peer_harness)`, or `None` when the request does not exist.
    pub async fn request_peer_facts(
        &self,
        id: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>, StoreError> {
        let id = id.to_owned();
        self.run(move |conn| {
            let mut stmt =
                conn.prepare("SELECT peer_exe, peer_harness FROM request WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            Ok(Some((row.get(0)?, row.get(1)?)))
        })
        .await
    }
}

/// Which lifetime counter an observation of `kind` moves.
fn counter_key_for(kind: &str, expected: bool) -> Result<&'static str, StoreError> {
    match (kind, expected) {
        (OBSERVATION_ADMIN_CONTACT | OBSERVATION_ADMIN_HANDSHAKE_FAILED, true) => {
            Ok(SETTING_ADMIN_CONTACTS_EXPECTED_TOTAL)
        }
        (OBSERVATION_ADMIN_CONTACT | OBSERVATION_ADMIN_HANDSHAKE_FAILED, false) => {
            Ok(SETTING_ADMIN_CONTACTS_TOTAL)
        }
        (OBSERVATION_PUBLIC_UNKNOWN_HARNESS, false) => Ok(SETTING_PUBLIC_UNKNOWN_TOTAL),
        _ => Err(invalid("unknown observation kind")),
    }
}
