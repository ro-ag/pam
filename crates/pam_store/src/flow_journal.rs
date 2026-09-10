//! Bounded private flow continuation journal. Each mutation is one atomic SQL
//! statement; cancellation never leaves a transaction open. Authorization and
//! protected checkpoint/evidence ownership remain the daemon's responsibility.
use super::{Store, StoreError};
use turso::params;

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
        let _guard = self.conn_lock.lock().await;
        let mut rows = self.conn.query("SELECT CASE WHEN length(content)<=1048576 THEN content ELSE NULL END FROM evidence WHERE id=?1 AND request_id=?2 AND kind='flow.checkpoint'",params![evidence_id,request_id]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        row.get::<Option<Vec<u8>>>(0)?
            .map(Some)
            .ok_or_else(|| invalid("protected checkpoint exceeds 1 MiB"))
    }

    /// Bind once. Existing progress is never reset to the supplied initial value.
    pub async fn begin_flow_journal(
        &self,
        identity: &FlowJournalIdentity,
        initial_checkpoint: &str,
    ) -> Result<FlowJournalBegin, StoreError> {
        validate_identity(identity)?;
        checkpoint(initial_checkpoint)?;
        let _guard = self.conn_lock.lock().await;
        let changed = self.conn.execute(
            "INSERT INTO flow_journal(request_id,schema_version,flow_digest,repository,input_fingerprint,revision,state,step_id,attempt,effectful,checkpoint_json,evidence_refs_json) VALUES (?1,1,?2,?3,?4,0,'ready',NULL,0,0,?5,'[]') ON CONFLICT(request_id) DO NOTHING",
            params![identity.request_id.clone(),identity.flow_digest.clone(),identity.repository.clone(),identity.input_fingerprint.clone(),initial_checkpoint],
        ).await?;
        if changed == 1 {
            return Ok(FlowJournalBegin::Inserted);
        }
        let existing = self
            .flow_journal_locked(&identity.request_id)
            .await?
            .ok_or_else(|| invalid("conflicting journal disappeared"))?;
        Ok(if existing.identity == *identity {
            FlowJournalBegin::Existing
        } else {
            FlowJournalBegin::Conflict
        })
    }

    /// Read limits are applied inside SQL before text is allocated in Rust.
    pub async fn read_flow_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<FlowJournal>, StoreError> {
        identifier(request_id, 128)?;
        let _guard = self.conn_lock.lock().await;
        self.flow_journal_locked(request_id).await
    }

    /// Commit intent before I/O. False means stale ownership or a non-ready
    /// phase; the caller must not execute the operation in that case.
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
        let _guard = self.conn_lock.lock().await;
        Ok(self.conn.execute(
            "UPDATE flow_journal SET revision=revision+1,state='prepared',step_id=?3,attempt=?4,effectful=?5 WHERE request_id=?1 AND revision=?2 AND state='ready'",
            params![request_id,expected_revision,step_id,i64::from(attempt),i64::from(effectful)],
        ).await? == 1)
    }

    /// Atomically settle the owned prepared attempt and publish its checkpoint.
    /// Completed and uncertain journals cannot be modified, even with a fresh CAS.
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
        let _guard = self.conn_lock.lock().await;
        Ok(self.conn.execute(
            "UPDATE flow_journal SET revision=revision+1,state=?3,checkpoint_json=?4,evidence_refs_json=?5 WHERE request_id=?1 AND revision=?2 AND state='prepared'",
            params![request_id,expected_revision,state,checkpoint_json,refs],
        ).await? == 1)
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
        let _guard = self.conn_lock.lock().await;
        Ok(self.conn.execute("UPDATE flow_journal SET revision=revision+1,state=?4 WHERE request_id=?1 AND revision=?2 AND state='prepared' AND effectful=?3",
            params![request_id,revision,i64::from(effectful),state]).await? == 1)
    }

    async fn flow_journal_locked(
        &self,
        request_id: &str,
    ) -> Result<Option<FlowJournal>, StoreError> {
        let mut rows = self.conn.query(
            "SELECT schema_version,revision,CASE WHEN length(CAST(state AS BLOB))<=16 THEN state ELSE NULL END,attempt,effectful,CASE WHEN length(CAST(flow_digest AS BLOB))=64 THEN flow_digest ELSE NULL END,CASE WHEN length(CAST(repository AS BLOB)) BETWEEN 1 AND 4096 THEN repository ELSE NULL END,CASE WHEN length(CAST(input_fingerprint AS BLOB))=64 THEN input_fingerprint ELSE NULL END,CASE WHEN length(CAST(checkpoint_json AS BLOB))<=131072 THEN checkpoint_json ELSE NULL END,CASE WHEN length(CAST(evidence_refs_json AS BLOB))<=16384 THEN evidence_refs_json ELSE NULL END,CASE WHEN length(CAST(step_id AS BLOB))<=256 THEN step_id ELSE NULL END,CASE WHEN step_id IS NULL OR length(CAST(step_id AS BLOB)) BETWEEN 1 AND 256 THEN 1 ELSE 0 END FROM flow_journal WHERE request_id=?1",
            params![request_id],
        ).await?;
        let Some(row) = rows.next().await? else {
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
