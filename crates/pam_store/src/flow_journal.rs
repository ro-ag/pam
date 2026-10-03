//! Bounded private flow continuation journal. Each mutation is one atomic SQL
//! statement, or one transaction where a protected checkpoint is filed with
//! the journal write that names it; cancellation never leaves a transaction
//! open. Authorization and the checkpoint's contents remain the daemon's
//! responsibility.
use super::{Actor, AuditEntry, Decision, Store, StoreError};
use crate::db::Db;
use rusqlite::params;
use sha2::{Digest, Sha256};

/// Upper bound before JSON parsing or database persistence.
pub const MAX_FLOW_CHECKPOINT_BYTES: usize = 131_072;
/// Bound on references retained alongside the checkpoint.
pub const MAX_FLOW_JOURNAL_EVIDENCE: usize = 128;
/// Private runtime snapshots; never a public evidence retrieval shortcut.
pub const EVIDENCE_KIND_FLOW_CHECKPOINT: &str = "flow.checkpoint";

/// Immutable provenance of one original workflow request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowJournalIdentity {
    /// Original request/ticket, never a replacement execution identity.
    pub request_id: String,
    /// Canonical recipe SHA-256.
    pub flow_digest: String,
    /// Canonical admitted repository path.
    pub repository: String,
    /// SHA-256 of daemon-frozen inputs and repository variables.
    pub input_fingerprint: String,
}

/// Current execution disposition. Prepared effects cannot be retried as reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowJournalState {
    /// Prior checkpoint is settled; a subsequent operation may be prepared.
    Ready,
    /// Intent was committed before I/O. Completion is not yet durable.
    Prepared,
    /// Final checkpoint; immutable through this API.
    Completed,
    /// Effect may have occurred. No automatic replay or settlement is allowed.
    Uncertain,
}

impl FlowJournalState {
    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "ready" => Ok(Self::Ready),
            "prepared" => Ok(Self::Prepared),
            "completed" => Ok(Self::Completed),
            "uncertain" => Ok(Self::Uncertain),
            _ => Err(invalid("invalid journal phase")),
        }
    }
}

/// Bounded state; checkpoint JSON contains references/progress, never raw logs
/// or credentials. The daemon validates its own versioned checkpoint schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowJournal {
    /// Original immutable provenance.
    pub identity: FlowJournalIdentity,
    /// Compare-and-swap generation; every successful mutation advances it.
    pub revision: i64,
    /// Recovery disposition.
    pub state: FlowJournalState,
    /// Last prepared step, retained after completion for diagnosis.
    pub step_id: Option<String>,
    /// Original step attempt number, at most 256.
    pub attempt: u32,
    /// Whether the prepared operation might modify external or local state.
    pub effectful: bool,
    /// Last settled checkpoint; preparing or abandoning a read never replaces it.
    pub checkpoint_json: String,
    /// Bounded evidence identifiers; payloads stay in the protected evidence store.
    pub evidence_refs: Vec<String>,
}

/// Idempotent creation cannot replace a different recipe/repository/input binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowJournalBegin {
    /// Initial ready checkpoint was inserted.
    Inserted,
    /// The original identity already exists; read its current continuation state.
    Existing,
    /// The ticket already has different immutable provenance.
    Conflict,
}

/// A protected checkpoint (`flow.checkpoint` evidence) filed in the same
/// transaction as the journal write whose checkpoint JSON names it.
#[derive(Debug, Clone, Copy)]
pub struct FlowCheckpoint<'a> {
    /// The new evidence row's id, the one the journal's checkpoint names.
    pub evidence_id: &'a str,
    /// The snapshot, at most 1 MiB.
    pub bytes: &'a [u8],
}

/// `audit.action` of the row that closes a checkpoint left without a journal.
pub const ACTION_FLOW_CHECKPOINT_ORPHANED: &str = "flow.checkpoint_orphaned";

/// Largest protected checkpoint the store files (the daemon's own bound).
const MAX_CHECKPOINT_BLOB_BYTES: usize = 1024 * 1024;

/// Orphaned checkpoints one sweep transaction closes.
const ORPHAN_SWEEP_BATCH: i64 = 64;

/// A checkpoint to file, owned for the job and hashed before the connection
/// is taken.
struct OwnedCheckpoint {
    evidence_id: String,
    bytes: Vec<u8>,
    content_hash: String,
}

impl OwnedCheckpoint {
    fn new(checkpoint: FlowCheckpoint<'_>) -> Result<Self, StoreError> {
        identifier(checkpoint.evidence_id, 128)?;
        if checkpoint.bytes.len() > MAX_CHECKPOINT_BLOB_BYTES {
            return Err(invalid("protected checkpoint exceeds 1 MiB"));
        }
        Ok(Self {
            evidence_id: checkpoint.evidence_id.to_owned(),
            bytes: checkpoint.bytes.to_vec(),
            content_hash: hex::encode(Sha256::digest(checkpoint.bytes)),
        })
    }

    fn file(&self, conn: Db<'_>, request_id: &str) -> Result<(), StoreError> {
        Store::insert_evidence_row(
            conn,
            &self.evidence_id,
            request_id,
            EVIDENCE_KIND_FLOW_CHECKPOINT,
            &self.bytes,
            &self.content_hash,
            None,
        )
    }
}

/// Test-only fault injection: the request id whose next checkpointed journal
/// write fails between the journal statement and the checkpoint insert, as a
/// crash there would interrupt it. Keyed by request so parallel tests do not
/// trip each other.
#[cfg(test)]
pub(crate) static CRASH_BETWEEN_JOURNAL_AND_CHECKPOINT: std::sync::Mutex<Option<String>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn injected_crash(request_id: &str) -> Result<(), StoreError> {
    let mut armed = CRASH_BETWEEN_JOURNAL_AND_CHECKPOINT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if armed.as_deref() == Some(request_id) {
        *armed = None;
        return Err(StoreError::Unavailable {
            detail: "injected crash between the journal write and its checkpoint".to_owned(),
        });
    }
    Ok(())
}

#[cfg(not(test))]
#[allow(clippy::unnecessary_wraps)] // Same signature as the test build's fallible injector.
fn injected_crash(_request_id: &str) -> Result<(), StoreError> {
    Ok(())
}

impl Store {
    /// Read a private runtime snapshot only for its exact original request and
    /// kind. SQL withholds oversized blobs before any Rust payload allocation.
    pub async fn read_flow_checkpoint(
        &self,
        request_id: &str,
        evidence_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        identifier(request_id, 128)?;
        identifier(evidence_id, 128)?;
        let request_id = request_id.to_owned();
        let evidence_id = evidence_id.to_owned();
        self.run(move |conn| {
            let mut stmt = conn.prepare("SELECT CASE WHEN length(content)<=1048576 THEN content ELSE NULL END FROM evidence WHERE id=?1 AND request_id=?2 AND kind='flow.checkpoint'")?;
            let mut rows = stmt.query(params![evidence_id,request_id])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            row.get::<Option<Vec<u8>>>(0)?
                .map(Some)
                .ok_or_else(|| invalid("protected checkpoint exceeds 1 MiB"))
        })
        .await
    }

    /// Bind once. Existing progress is never reset to the supplied initial value.
    pub async fn begin_flow_journal(
        &self,
        identity: &FlowJournalIdentity,
        initial_checkpoint: &str,
    ) -> Result<FlowJournalBegin, StoreError> {
        validate_identity(identity)?;
        checkpoint(initial_checkpoint)?;
        let identity = identity.clone();
        let initial_checkpoint = initial_checkpoint.to_owned();
        self.run(move |conn| Self::begin_flow_journal_locked(conn, &identity, &initial_checkpoint))
            .await
    }

    /// [`Self::begin_flow_journal`] and the first protected checkpoint in one
    /// transaction: the journal row is written first, and the checkpoint its
    /// `initial_checkpoint` names is filed only when that row was inserted.
    /// A crash anywhere inside leaves neither, so there is never a journal
    /// whose checkpoint is missing, nor a checkpoint without its journal. An
    /// existing or conflicting journal files nothing.
    pub async fn begin_flow_journal_with_checkpoint(
        &self,
        identity: &FlowJournalIdentity,
        initial_checkpoint: &str,
        snapshot: FlowCheckpoint<'_>,
    ) -> Result<FlowJournalBegin, StoreError> {
        validate_identity(identity)?;
        checkpoint(initial_checkpoint)?;
        let snapshot = OwnedCheckpoint::new(snapshot)?;
        let identity = identity.clone();
        let initial_checkpoint = initial_checkpoint.to_owned();
        self.transact(move |conn| {
            let begun = Self::begin_flow_journal_locked(conn, &identity, &initial_checkpoint)?;
            if begun == FlowJournalBegin::Inserted {
                injected_crash(&identity.request_id)?;
                snapshot.file(conn, &identity.request_id)?;
            }
            Ok(begun)
        })
        .await
    }

    fn begin_flow_journal_locked(
        conn: Db<'_>,
        identity: &FlowJournalIdentity,
        initial_checkpoint: &str,
    ) -> Result<FlowJournalBegin, StoreError> {
        let changed = conn.execute(
            "INSERT INTO flow_journal(request_id,schema_version,flow_digest,repository,input_fingerprint,revision,state,step_id,attempt,effectful,checkpoint_json,evidence_refs_json) VALUES (?1,1,?2,?3,?4,0,'ready',NULL,0,0,?5,'[]') ON CONFLICT(request_id) DO NOTHING",
            params![identity.request_id,identity.flow_digest,identity.repository,identity.input_fingerprint,initial_checkpoint],
        )?;
        if changed == 1 {
            return Ok(FlowJournalBegin::Inserted);
        }
        let existing = Self::flow_journal_locked(conn, &identity.request_id)?
            .ok_or_else(|| invalid("conflicting journal disappeared"))?;
        Ok(if existing.identity == *identity {
            FlowJournalBegin::Existing
        } else {
            FlowJournalBegin::Conflict
        })
    }

    /// [`Self::settle_flow_attempt`] and the protected checkpoint its
    /// `checkpoint_json` names, in one transaction: the journal is settled
    /// first and the checkpoint filed only when the settlement applied. A
    /// stale revision, a non-prepared phase or a terminal request files
    /// nothing and answers false; a crash inside leaves the journal
    /// prepared and no checkpoint.
    pub async fn settle_flow_attempt_with_checkpoint(
        &self,
        request_id: &str,
        expected_revision: i64,
        checkpoint_json: &str,
        evidence_refs: &[String],
        completed: bool,
        snapshot: FlowCheckpoint<'_>,
    ) -> Result<bool, StoreError> {
        transition_args(request_id, expected_revision)?;
        checkpoint(checkpoint_json)?;
        let refs = references(evidence_refs)?;
        let snapshot = OwnedCheckpoint::new(snapshot)?;
        let state = if completed { "completed" } else { "ready" };
        let request_id = request_id.to_owned();
        let checkpoint_json = checkpoint_json.to_owned();
        self.transact(move |conn| {
            if !Self::settle_flow_attempt_locked(
                conn,
                &request_id,
                expected_revision,
                state,
                &checkpoint_json,
                &refs,
            )? {
                return Ok(false);
            }
            injected_crash(&request_id)?;
            snapshot.file(conn, &request_id)?;
            Ok(true)
        })
        .await
    }

    fn settle_flow_attempt_locked(
        conn: Db<'_>,
        request_id: &str,
        expected_revision: i64,
        state: &str,
        checkpoint_json: &str,
        refs: &str,
    ) -> Result<bool, StoreError> {
        Ok(conn.execute(
            "UPDATE flow_journal SET revision=revision+1,state=?3,checkpoint_json=?4,evidence_refs_json=?5 WHERE request_id=?1 AND revision=?2 AND state='prepared' AND EXISTS(SELECT 1 FROM request WHERE id=?1 AND state IN ('queued','running','waiting_approval'))",
            params![request_id,expected_revision,state,checkpoint_json,refs],
        )? == 1)
    }

    /// Boot recovery for checkpoints a crash left without their journal:
    /// `flow.checkpoint` evidence whose request has no `flow_journal` row.
    /// A daemon that filed the first checkpoint and the journal in two
    /// statements could stop between them; nothing can ever read such a
    /// checkpoint (every read goes through a journal or a landing session
    /// of a journaled run). Each one is closed with an
    /// [`ACTION_FLOW_CHECKPOINT_ORPHANED`] audit row on its request, naming
    /// the evidence id, its size and digest and when it was filed, and the
    /// row is deleted in the same transaction, so the record says what was
    /// removed. Bounded batches, oldest first; answers how many it closed.
    /// A second sweep finds nothing.
    pub async fn close_orphan_flow_checkpoints(&self) -> Result<u64, StoreError> {
        let mut closed = 0_u64;
        loop {
            let batch = self.transact(Self::close_orphan_checkpoint_batch).await?;
            closed = closed.saturating_add(batch);
            if batch < u64::try_from(ORPHAN_SWEEP_BATCH).unwrap_or(u64::MAX) {
                return Ok(closed);
            }
        }
    }

    fn close_orphan_checkpoint_batch(conn: Db<'_>) -> Result<u64, StoreError> {
        let orphans: Vec<(String, String, String, i64, i64)> = {
            let mut stmt = conn.prepare(
                "SELECT e.id, e.request_id, e.content_hash, COALESCE(LENGTH(e.content), 0), e.ts \
                 FROM evidence e \
                 WHERE e.kind = 'flow.checkpoint' \
                   AND NOT EXISTS (SELECT 1 FROM flow_journal j WHERE j.request_id = e.request_id) \
                 ORDER BY e.ts, e.id LIMIT ?1",
            )?;
            let mut rows = stmt.query(params![ORPHAN_SWEEP_BATCH])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ));
            }
            out
        };
        for (evidence_id, request_id, content_hash, bytes, filed_ts) in &orphans {
            let detail = serde_json::json!({
                "cause": "flow_checkpoint_without_journal",
                "evidence_id": evidence_id,
                "bytes": bytes,
                "content_hash": content_hash,
                "filed_ts": filed_ts,
                "note": "A protected flow checkpoint had no journal, so nothing could read it; it was removed by crash recovery.",
            })
            .to_string();
            Self::insert_audit_row(
                conn,
                request_id,
                AuditEntry {
                    action: ACTION_FLOW_CHECKPOINT_ORPHANED,
                    decision: Decision::Timeout,
                    actor: Actor::System,
                    detail: Some(&detail),
                },
            )?;
            // A view of a checkpoint is never published; should one exist,
            // it becomes a tombstone before its evidence goes.
            conn.execute(
                "UPDATE evidence_view SET expired_at = ?2 WHERE evidence_id = ?1 AND expired_at IS NULL",
                params![evidence_id, super::now_ts()],
            )?;
            conn.execute("DELETE FROM evidence WHERE id = ?1", params![evidence_id])?;
        }
        Ok(u64::try_from(orphans.len()).unwrap_or(u64::MAX))
    }

    /// Read limits are applied inside SQL before text is allocated in Rust.
    pub async fn read_flow_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<FlowJournal>, StoreError> {
        identifier(request_id, 128)?;
        let request_id = request_id.to_owned();
        self.run(move |conn| Self::flow_journal_locked(conn, &request_id))
            .await
    }

    /// Commit intent before I/O. False means stale ownership or a non-ready
    /// phase or a terminal request; the caller must not execute in that case.
    pub async fn prepare_flow_attempt(
        &self,
        request_id: &str,
        expected_revision: i64,
        step_id: &str,
        attempt: u32,
        effectful: bool,
    ) -> Result<bool, StoreError> {
        transition_args(request_id, expected_revision)?;
        identifier(step_id, 256)?;
        if !(1..=256).contains(&attempt) {
            return Err(invalid("attempt must be within 1..256"));
        }
        let request_id = request_id.to_owned();
        let step_id = step_id.to_owned();
        self.run(move |conn| {
            Ok(conn.execute(
                "UPDATE flow_journal SET revision=revision+1,state='prepared',step_id=?3,attempt=?4,effectful=?5 WHERE request_id=?1 AND revision=?2 AND state='ready' AND EXISTS(SELECT 1 FROM request WHERE id=?1 AND state IN ('queued','running','waiting_approval'))",
                params![request_id,expected_revision,step_id,i64::from(attempt),i64::from(effectful)],
            )? == 1)
        })
        .await
    }

    /// Atomically settle the owned prepared attempt and publish its checkpoint.
    /// Completed and uncertain journals, and terminal requests, reject settlement.
    pub async fn settle_flow_attempt(
        &self,
        request_id: &str,
        expected_revision: i64,
        checkpoint_json: &str,
        evidence_refs: &[String],
        completed: bool,
    ) -> Result<bool, StoreError> {
        transition_args(request_id, expected_revision)?;
        checkpoint(checkpoint_json)?;
        let refs = references(evidence_refs)?;
        let state = if completed { "completed" } else { "ready" };
        let request_id = request_id.to_owned();
        let checkpoint_json = checkpoint_json.to_owned();
        self.run(move |conn| {
            Self::settle_flow_attempt_locked(
                conn,
                &request_id,
                expected_revision,
                state,
                &checkpoint_json,
                &refs,
            )
        })
        .await
    }

    /// Persist uncertainty before completing the original request after a crash.
    /// Repeated calls are harmless CAS misses; they never convert effects to reads.
    pub async fn mark_flow_uncertain(
        &self,
        request_id: &str,
        expected_revision: i64,
    ) -> Result<bool, StoreError> {
        self.transition_flow_phase(request_id, expected_revision, true, "uncertain")
            .await
    }

    /// A crashed read can be retried after current authorization and the original
    /// persisted budget are checked. This operation does not refund its reservation.
    pub async fn abandon_read_attempt(
        &self,
        request_id: &str,
        expected_revision: i64,
    ) -> Result<bool, StoreError> {
        self.transition_flow_phase(request_id, expected_revision, false, "ready")
            .await
    }

    async fn transition_flow_phase(
        &self,
        request_id: &str,
        revision: i64,
        effectful: bool,
        state: &str,
    ) -> Result<bool, StoreError> {
        transition_args(request_id, revision)?;
        let request_id = request_id.to_owned();
        let state = state.to_owned();
        self.run(move |conn| {
            Ok(conn.execute("UPDATE flow_journal SET revision=revision+1,state=?4 WHERE request_id=?1 AND revision=?2 AND state='prepared' AND effectful=?3",
                params![request_id,revision,i64::from(effectful),state])? == 1)
        })
        .await
    }

    fn flow_journal_locked(
        conn: Db<'_>,
        request_id: &str,
    ) -> Result<Option<FlowJournal>, StoreError> {
        let mut stmt = conn.prepare("SELECT schema_version,revision,CASE WHEN length(CAST(state AS BLOB))<=16 THEN state ELSE NULL END,attempt,effectful,CASE WHEN length(CAST(flow_digest AS BLOB))=64 THEN flow_digest ELSE NULL END,CASE WHEN length(CAST(repository AS BLOB)) BETWEEN 1 AND 4096 THEN repository ELSE NULL END,CASE WHEN length(CAST(input_fingerprint AS BLOB))=64 THEN input_fingerprint ELSE NULL END,CASE WHEN length(CAST(checkpoint_json AS BLOB))<=131072 THEN checkpoint_json ELSE NULL END,CASE WHEN length(CAST(evidence_refs_json AS BLOB))<=16384 THEN evidence_refs_json ELSE NULL END,CASE WHEN length(CAST(step_id AS BLOB))<=256 THEN step_id ELSE NULL END,CASE WHEN step_id IS NULL OR length(CAST(step_id AS BLOB)) BETWEEN 1 AND 256 THEN 1 ELSE 0 END FROM flow_journal WHERE request_id=?1")?;
        let mut rows = stmt.query(params![request_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let required = |index| -> Result<String, StoreError> {
            row.get::<Option<String>>(index)?
                .ok_or_else(|| invalid("journal text exceeds bounds"))
        };
        if row.get::<i64>(0)? != 1 || row.get::<i64>(11)? != 1 {
            return Err(invalid("invalid journal version or step size"));
        }
        let identity = FlowJournalIdentity {
            request_id: request_id.to_owned(),
            flow_digest: required(5)?,
            repository: required(6)?,
            input_fingerprint: required(7)?,
        };
        validate_identity(&identity)?;
        let checkpoint_json = required(8)?;
        checkpoint(&checkpoint_json)?;
        let refs_json = required(9)?;
        let evidence_refs: Vec<String> =
            serde_json::from_str(&refs_json).map_err(|_| invalid("invalid journal references"))?;
        references(&evidence_refs)?;
        let revision = row.get::<i64>(1)?;
        let attempt =
            u32::try_from(row.get::<i64>(3)?).map_err(|_| invalid("invalid journal attempt"))?;
        let effectful = row.get::<i64>(4)?;
        if revision < 0 || attempt > 256 || !matches!(effectful, 0 | 1) {
            return Err(invalid("invalid journal counters"));
        }
        Ok(Some(FlowJournal {
            identity,
            revision,
            state: FlowJournalState::parse(&required(2)?)?,
            step_id: row.get(10)?,
            attempt,
            effectful: effectful == 1,
            checkpoint_json,
            evidence_refs,
        }))
    }
}

fn validate_identity(identity: &FlowJournalIdentity) -> Result<(), StoreError> {
    identifier(&identity.request_id, 128)?;
    identifier(&identity.repository, 4096)?;
    for hash in [&identity.flow_digest, &identity.input_fingerprint] {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("journal fingerprints must be SHA-256 hex"));
        }
    }
    Ok(())
}

fn identifier(value: &str, maximum: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid("invalid journal identifier size or characters"));
    }
    Ok(())
}

fn checkpoint(value: &str) -> Result<(), StoreError> {
    if value.len() > MAX_FLOW_CHECKPOINT_BYTES {
        return Err(invalid("checkpoint exceeds byte limit"));
    }
    if !serde_json::from_str::<serde_json::Value>(value).is_ok_and(|v| v.is_object()) {
        return Err(invalid("checkpoint must be a JSON object"));
    }
    Ok(())
}

fn references(values: &[String]) -> Result<String, StoreError> {
    if values.len() > MAX_FLOW_JOURNAL_EVIDENCE {
        return Err(invalid("too many journal references"));
    }
    for value in values {
        identifier(value, 128)?;
    }
    let json = serde_json::to_string(values).map_err(|_| invalid("invalid references"))?;
    if json.len() > 16_384 {
        return Err(invalid("journal references exceed byte limit"));
    }
    Ok(json)
}

fn transition_args(request_id: &str, revision: i64) -> Result<(), StoreError> {
    identifier(request_id, 128)?;
    if revision < 0 || revision == i64::MAX {
        return Err(invalid("invalid journal revision"));
    }
    Ok(())
}

fn invalid(reason: &str) -> StoreError {
    StoreError::UnexpectedValue {
        column: "flow_journal",
        value: reason.to_owned(),
    }
}
