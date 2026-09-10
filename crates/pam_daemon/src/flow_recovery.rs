//! Protected bounded runtime snapshots. Public evidence readers never receive these blobs.
use crate::{
    evidence_service::{ConnectorTarget, EvidenceOrigin, authorize_origin},
    executor::CapabilityFailure,
    flow_exec::{StepError, StepReport, StepStatus},
    scope_policy::ScopePolicy,
};
use pam_flow::{Flow, Vars};
use pam_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, io::Write, path::Path};

pub(crate) const KIND: &str = "flow.checkpoint";
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub fingerprint: String,
    pub vars: Vars,
    pub observed: Vars,
    pub reports: Vec<Value>,
    pub evidence: Vec<String>,
    pub origins: BTreeMap<String, ConnectorTarget>,
    pub all_origins: Vec<ConnectorTarget>,
}

pub(crate) fn failure() -> CapabilityFailure {
    CapabilityFailure::Failed{detail:"flow checkpoint unavailable or inconsistent; inspect retained evidence and reconcile uncertain effects before starting a new request".to_owned()}
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_BYTES {
            return Err(std::io::Error::other("checkpoint exceeds byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>, CapabilityFailure> {
    let mut writer = Bounded(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| failure())?;
    Ok(writer.0)
}

pub(crate) fn fingerprint(
    flow: &Flow,
    repo: &Path,
    initial: &Vars,
) -> Result<String, CapabilityFailure> {
    let encoded = encode(&(pam_flow::digest(flow), repo, initial))?;
    Ok(pam_compact::sha256_hex(&encoded))
}

impl Snapshot {
    pub fn decode(bytes: &[u8], fingerprint: &str, flow: &Flow) -> Result<Self, CapabilityFailure> {
        if bytes.len() > MAX_BYTES {
            return Err(failure());
        }
        let snapshot: Self = serde_json::from_slice(bytes).map_err(|_| failure())?;
        if snapshot.fingerprint != fingerprint
            || snapshot.reports.len() > flow.steps.len()
            || snapshot.all_origins.len() > 256
            || snapshot.origins.len() > flow.steps.len()
            || snapshot.evidence.len() > pam_store::MAX_FLOW_JOURNAL_EVIDENCE
        {
            return Err(failure());
        }
        snapshot.restore_reports(flow)?;
        Ok(snapshot)
    }
    pub async fn authorize(
        &self,
        store: &Store,
        ticket: &str,
        repo: &Path,
    ) -> Result<(), CapabilityFailure> {
        let policy = ScopePolicy::load(store).await.map_err(|_| failure())?;
        let repo = policy.authorize_repo(repo).map_err(|_| failure())?;
        let mut targets = self.all_origins.clone();
        targets.extend(self.origins.values().cloned());
        authorize_origin(store, &policy, &repo, &EvidenceOrigin { targets }).await?;
        if self.evidence.len() > pam_store::MAX_FLOW_JOURNAL_EVIDENCE {
            return Err(failure());
        }
        for id in &self.evidence {
            if id.is_empty() || id.len() > 128 {
                return Err(failure());
            }
            let view = store
                .evidence_view_meta(ticket, id, &repo.to_string_lossy())
                .await
                .map_err(|_| failure())?
                .ok_or_else(failure)?;
            if view.expired_at.is_some() {
                return Err(failure());
            }
            let origin: EvidenceOrigin =
                serde_json::from_str(&view.origin_json).map_err(|_| failure())?;
            authorize_origin(store, &policy, &repo, &origin).await?;
        }
        Ok(())
    }
    pub fn restore_reports(&self, flow: &Flow) -> Result<Vec<StepReport>, CapabilityFailure> {
        self.reports
            .iter()
            .zip(&flow.steps)
            .map(|(value, step)| {
                let dto: Report = serde_json::from_value(value.clone()).map_err(|_| failure())?;
                if dto.id != step.id
                    || dto.kind != step.kind()
                    || dto.evidence.len() > pam_store::MAX_FLOW_JOURNAL_EVIDENCE
                    || dto.evidence.iter().any(|id| !self.evidence.contains(id))
                {
                    return Err(failure());
                }
                let mut report = StepReport::new(&dto.id, step.kind(), status(&dto.status)?);
                report.attempts = dto.attempts;
                report.duration_ms = dto.duration_ms;
                report.exit_status = dto.exit_status;
                report.evidence = dto.evidence;
                report.evidence_unavailable = dto.evidence_unavailable;
                report.summary = dto.summary;
                report.error = dto.error.map(|error| StepError {
                    cause: error.cause,
                    detail: error.detail,
                    recovery: error.recovery,
                });
                Ok(report)
            })
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    id: String,
    kind: String,
    status: String,
    attempts: u8,
    duration_ms: u64,
    exit_status: Option<i32>,
    evidence: Vec<String>,
    #[serde(default)]
    evidence_unavailable: Vec<String>,
    summary: Option<String>,
    error: Option<Error>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Error {
    cause: String,
    detail: String,
    recovery: String,
}
fn status(value: &str) -> Result<StepStatus, CapabilityFailure> {
    match value {
        "succeeded" => Ok(StepStatus::Succeeded),
        "failed" => Ok(StepStatus::Failed),
        "skipped" => Ok(StepStatus::Skipped),
        "blocked" => Ok(StepStatus::Blocked),
        "cancelled" => Ok(StepStatus::Cancelled),
        _ => Err(failure()),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WatchState {
    pub step: String,
    pub args_fingerprint: String,
    pub origin: ConnectorTarget,
    pub profile_stamp: String,
    pub authorization_revision: i64,
    pub polls: u32,
    pub errors: u32,
    pub next_poll_ms: i64,
    pub collecting: bool,
    pub observation: Value,
    pub pins: Value,
    pub last_digest: String,
    pub last_evidence: String,
}

pub(crate) struct Recovery {
    pub fingerprint: String,
    pub revision: i64,
    pub watch: Option<WatchState>,
    cursor: Cursor,
}
impl Recovery {
    pub async fn open(
        store: &Store,
        ticket: &str,
        flow: &Flow,
        repo: &Path,
        initial: &Vars,
    ) -> Result<(Self, Snapshot), CapabilityFailure> {
        let fingerprint = fingerprint(flow, repo, initial)?;
        let identity = pam_store::FlowJournalIdentity {
            request_id: ticket.to_owned(),
            flow_digest: pam_flow::digest(flow),
            repository: repo.to_string_lossy().into_owned(),
            input_fingerprint: fingerprint.clone(),
        };
        let prior = store
            .read_flow_journal(ticket)
            .await
            .map_err(|_| failure())?;
        let empty = Snapshot {
            fingerprint: fingerprint.clone(),
            vars: initial.clone(),
            observed: initial.clone(),
            reports: Vec::new(),
            evidence: Vec::new(),
            origins: BTreeMap::new(),
            all_origins: Vec::new(),
        };
        let cursor = if prior.is_none() {
            file(store, ticket, &empty).await?
        } else {
            "{}".to_owned()
        };
        if matches!(
            store
                .begin_flow_journal(&identity, &cursor)
                .await
                .map_err(|_| failure())?,
            pam_store::FlowJournalBegin::Conflict
        ) {
            return Err(failure());
        }
        let row = store
            .read_flow_journal(ticket)
            .await
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        if !matches!(
            row.state,
            pam_store::FlowJournalState::Ready | pam_store::FlowJournalState::Completed
        ) {
            return Err(failure());
        }
        let cursor: Cursor = serde_json::from_str(&row.checkpoint_json).map_err(|_| failure())?;
        let bytes = store
            .read_flow_checkpoint(ticket, &cursor.evidence_id)
            .await
            .map_err(|_| failure())?
            .ok_or_else(failure)?;
        let snapshot = Snapshot::decode(&bytes, &fingerprint, flow)?;
        if snapshot.reports.len() != cursor.next_step {
            return Err(failure());
        }
        snapshot.authorize(store, ticket, repo).await?;
        cursor.authorize_watch(store, ticket, repo, flow).await?;
        Ok((
            Self {
                fingerprint,
                revision: row.revision,
                watch: cursor.watch.clone(),
                cursor,
            },
            snapshot,
        ))
    }
    pub async fn prepare(
        &mut self,
        store: &Store,
        ticket: &str,
        step: &pam_flow::Step,
        will_run: bool,
    ) -> Result<(), CapabilityFailure> {
        if !store
            .prepare_flow_attempt(
                ticket,
                self.revision,
                &step.id,
                1,
                will_run && step.effect == pam_flow::Effect::Stateful,
            )
            .await
            .map_err(|_| failure())?
        {
            return Err(failure());
        }
        self.revision += 1;
        Ok(())
    }
    pub async fn settle_watch(
        &mut self,
        store: &Store,
        ticket: &str,
        watch: WatchState,
        evidence: &[String],
    ) -> Result<(), CapabilityFailure> {
        if encode(&watch)?.len() > 16 * 1024 {
            return Err(failure());
        }
        let cursor = Cursor {
            evidence_id: self.cursor.evidence_id.clone(),
            next_step: self.cursor.next_step,
            watch: Some(watch.clone()),
            last_watch_evidence: Some(watch.last_evidence.clone()),
        };
        let json = serde_json::to_string(&cursor).map_err(|_| failure())?;
        let mut refs = evidence.to_vec();
        if !refs.contains(&watch.last_evidence) {
            refs.push(watch.last_evidence.clone());
        }
        if !store
            .settle_flow_attempt(ticket, self.revision, &json, &refs, false)
            .await
            .map_err(|_| failure())?
        {
            return Err(failure());
        }
        self.revision += 1;
        self.watch = Some(watch);
        self.cursor = cursor;
        Ok(())
    }
    pub async fn settle(
        &mut self,
        store: &Store,
        ticket: &str,
        snapshot: &Snapshot,
        completed: bool,
    ) -> Result<(), CapabilityFailure> {
        let mut cursor: Cursor =
            serde_json::from_str(&file(store, ticket, snapshot).await?).map_err(|_| failure())?;
        cursor.last_watch_evidence = self
            .watch
            .as_ref()
            .map(|w| w.last_evidence.clone())
            .or_else(|| self.cursor.last_watch_evidence.clone());
        let cursor = serde_json::to_string(&cursor).map_err(|_| failure())?;
        if !store
            .settle_flow_attempt(
                ticket,
                self.revision,
                &cursor,
                &snapshot.evidence,
                completed,
            )
            .await
            .map_err(|_| failure())?
        {
            return Err(failure());
        }
        self.revision += 1;
        self.cursor = serde_json::from_str(&cursor).map_err(|_| failure())?;
        self.watch = None;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    evidence_id: String,
    next_step: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    watch: Option<WatchState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_watch_evidence: Option<String>,
}
impl Cursor {
    async fn authorize_watch(
        &self,
        store: &Store,
        ticket: &str,
        repo: &Path,
        flow: &Flow,
    ) -> Result<(), CapabilityFailure> {
        if let Some(watch) = &self.watch {
            if encode(watch)?.len() > 16 * 1024
                || flow
                    .steps
                    .get(self.next_step)
                    .is_none_or(|step| step.id != watch.step || step.watch.is_none())
                || watch.polls > 100
            {
                return Err(failure());
            }
            let policy = ScopePolicy::load(store).await.map_err(|_| failure())?;
            authorize_origin(
                store,
                &policy,
                repo,
                &EvidenceOrigin {
                    targets: vec![watch.origin.clone()],
                },
            )
            .await?;
            let view = store
                .evidence_view_meta(ticket, &watch.last_evidence, &repo.to_string_lossy())
                .await
                .map_err(|_| failure())?
                .ok_or_else(failure)?;
            if view.expired_at.is_some()
                || view.authorization_revision != Some(watch.authorization_revision)
            {
                return Err(failure());
            }
            let origin = serde_json::from_str(&view.origin_json).map_err(|_| failure())?;
            authorize_origin(store, &policy, repo, &origin).await?;
        }
        Ok(())
    }
}
async fn file(
    store: &Store,
    ticket: &str,
    snapshot: &Snapshot,
) -> Result<String, CapabilityFailure> {
    let bytes = encode(snapshot)?;
    let evidence_id = format!("ev_{}", ulid::Ulid::new());
    store
        .insert_evidence(&evidence_id, ticket, KIND, &bytes, None)
        .await
        .map_err(|_| failure())?;
    serde_json::to_string(&Cursor {
        evidence_id,
        next_step: snapshot.reports.len(),
        watch: None,
        last_watch_evidence: None,
    })
    .map_err(|_| failure())
}
