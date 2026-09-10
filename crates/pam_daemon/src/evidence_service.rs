//! Scoped access to immutable redacted evidence views. Handles convey no authority.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pam_connectors::{ArgValue, ConnectorId};
use pam_proto::Outcome;
use pam_store::{EvidenceRangeOutcome, EvidenceRangeRequest, EvidenceViewInsert, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::executor::{CapabilityFailure, CapabilityOutput, ExecContext};
use crate::scope_policy::ScopePolicy;

pub(crate) const CAP_EVIDENCE_READ: &str = "evidence.read";

/// Private, resolved authorities captured by the producer, never from log prose.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EvidenceOrigin {
    pub targets: Vec<ConnectorTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConnectorTarget {
    pub connector: ConnectorId,
    pub base_url: String,
    pub call: String,
    pub args: BTreeMap<String, ArgValue>,
}

#[derive(Clone, Debug)]
pub(crate) struct CaptureScope {
    pub repository: String,
    pub origin: EvidenceOrigin,
}

pub(crate) async fn prepare(bytes: Vec<u8>) -> Result<crate::evidence_view::RedactedView, String> {
    crate::blocking_jobs::run(crate::blocking_jobs::Kind::LogCompaction, move || {
        crate::evidence_view::redact(&bytes)
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

/// Called only by evidence producers with host-resolved scope. Public callers
/// cannot create views or choose their origin metadata.
pub(crate) async fn publish(
    store: &Store,
    scope: &CaptureScope,
    request_id: &str,
    evidence_id: &str,
    view: crate::evidence_view::RedactedView,
    parent: serde_json::Value,
) -> Result<(), String> {
    let identity = json!({
        "schema_version": 1, "evidence_id": evidence_id, "request_id": request_id,
        "captured_at": now(), "input_sha256": view.source_sha256,
        "input_bytes": view.source_bytes, "offset_basis": "view_bytes",
        "redaction": {"policy": view.policy_version, "replacements": view.redactions,
            "coverage": "bounded_detectors"},
        "completeness": "not_asserted", "parent": parent,
        "products": scope.origin.targets.iter().map(|target| target.connector.as_str()).collect::<Vec<_>>()
    });
    let insert = EvidenceViewInsert {
        evidence_id: evidence_id.to_owned(),
        request_id: request_id.to_owned(),
        repository: scope.repository.clone(),
        origin_json: serde_json::to_string(&scope.origin).map_err(|err| err.to_string())?,
        identity_json: identity.to_string(),
        view_id: format!("view_{}", ulid::Ulid::new()),
        view_bytes: view.bytes,
        map_json: serde_json::to_string(&view.segments).map_err(|err| err.to_string())?,
    };
    if !store
        .insert_evidence_view(&insert)
        .await
        .map_err(|err| err.to_string())?
    {
        return Err("the evidence owner does not match the captured view".to_owned());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    evidence_id: String,
    request_id: String,
    #[serde(default)]
    offset: u64,
    #[serde(default = "default_length")]
    length: u32,
    expected_view_id: Option<String>,
    expected_sha256: Option<String>,
}

fn default_length() -> u32 {
    16_384
}

fn refusal(cause: &str, detail: &str) -> CapabilityFailure {
    CapabilityFailure::Refused {
        cause: cause.to_owned(), detail: detail.to_owned(),
        recovery: "Use an evidence reference from an approved task; inspect access and retention in the PAM GUI.".to_owned(),
    }
}

fn unavailable() -> CapabilityFailure {
    refusal(
        "evidence_unavailable",
        "No readable evidence matches this request, repository and current authorization.",
    )
}

fn store_failure(_: pam_store::StoreError) -> CapabilityFailure {
    refusal(
        "evidence_store_unavailable",
        "The evidence store could not complete this read.",
    )
}

fn read_args(value: &serde_json::Value) -> Result<ReadArgs, CapabilityFailure> {
    let args: ReadArgs = serde_json::from_value(value.clone()).map_err(|_| {
        refusal(
            "invalid_evidence_range",
            "Expected a bounded evidence range request.",
        )
    })?;
    if args.evidence_id.len() > 128
        || args.request_id.len() > 128
        || !(1..=65_536).contains(&args.length)
        || args.expected_view_id.is_some() != args.expected_sha256.is_some()
        || args
            .expected_view_id
            .as_ref()
            .is_some_and(|value| value.len() > 128)
        || args
            .expected_sha256
            .as_ref()
            .is_some_and(|value| value.len() > 128)
        || (args.offset != 0 && args.expected_view_id.is_none())
    {
        return Err(refusal(
            "invalid_evidence_range",
            "Use 1–65536 bytes and pin the view identity for continuation reads.",
        ));
    }
    Ok(args)
}

pub(crate) async fn read(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let args = read_args(&ctx.args)?;
    ctx.budget
        .attempt()
        .map_err(|err| refusal(err.cause, "The evidence request exhausted its work budget."))?;
    let policy = ScopePolicy::load(&ctx.store)
        .await
        .map_err(|_| unavailable())?;
    let repo = policy
        .authorize_repo(Path::new(&ctx.caller.repo))
        .map_err(|_| unavailable())?;
    let repository = repo.to_string_lossy().into_owned();
    let meta = ctx
        .store
        .evidence_view_meta(&args.request_id, &args.evidence_id, &repository)
        .await
        .map_err(store_failure)?
        .ok_or_else(unavailable)?;
    let revision = ctx
        .store
        .grant_revocation_revision()
        .await
        .map_err(store_failure)?;
    if meta.authorization_revision != Some(revision) {
        return Err(unavailable());
    }
    let origin: EvidenceOrigin =
        serde_json::from_str(&meta.origin_json).map_err(|_| unavailable())?;
    authorize_origin(&ctx.store, &policy, &repo, &origin).await?;
    let request = EvidenceRangeRequest {
        request_id: args.request_id.clone(),
        evidence_id: args.evidence_id.clone(),
        repository,
        expected_view_id: args
            .expected_view_id
            .unwrap_or_else(|| meta.view_id.clone()),
        expected_sha256: args
            .expected_sha256
            .unwrap_or_else(|| meta.view_sha256.clone()),
        offset: args.offset,
        length: args.length,
        now: now(),
    };
    let outcome = ctx
        .store
        .read_evidence_view_range(&request)
        .await
        .map_err(store_failure)?;
    // Recheck every outcome, including tombstones, after storage awaits.
    let current = ScopePolicy::load(&ctx.store)
        .await
        .map_err(|_| unavailable())?;
    current.authorize_repo(&repo).map_err(|_| unavailable())?;
    authorize_origin(&ctx.store, &current, &repo, &origin).await?;
    if ctx
        .store
        .grant_revocation_revision()
        .await
        .map_err(store_failure)?
        != revision
    {
        return Err(unavailable());
    }
    let range = match outcome {
        EvidenceRangeOutcome::Range(range) => range,
        EvidenceRangeOutcome::Unavailable => return Err(unavailable()),
        EvidenceRangeOutcome::Expired => {
            return Err(refusal(
                "evidence_expired",
                "Retention removed the evidence view.",
            ));
        }
        EvidenceRangeOutcome::InvalidRange => {
            return Err(refusal(
                "invalid_evidence_range",
                "The range or pinned view identity does not match.",
            ));
        }
        EvidenceRangeOutcome::BudgetExhausted => {
            return Err(refusal(
                "evidence_budget_exhausted",
                "The original request's evidence read allowance has expired or been consumed.",
            ));
        }
    };
    read_output(&request, &meta, &range)
}

fn read_output(
    request: &EvidenceRangeRequest,
    meta: &pam_store::EvidenceViewMeta,
    range: &pam_store::EvidenceRange,
) -> Result<CapabilityOutput, CapabilityFailure> {
    let identity: serde_json::Value =
        serde_json::from_str(&meta.identity_json).map_err(|_| unavailable())?;
    let segments: Vec<crate::evidence_view::Segment> =
        serde_json::from_str(&meta.map_json).map_err(|_| unavailable())?;
    let provenance = if range.bytes.is_empty() {
        Vec::new()
    } else {
        crate::evidence_view::resolve_segments(
            &segments,
            crate::evidence_view::ByteRange {
                start: range.offset,
                end: range.offset + u64::try_from(range.bytes.len()).unwrap_or(u64::MAX),
            },
        )
        .map_err(|_| {
            refusal(
                "evidence_provenance_unavailable",
                "The stored view mapping could not resolve this range.",
            )
        })?
    };
    Ok(CapabilityOutput {
        outcome: Outcome::Verified,
        body: json!({
            "schema_version": 1, "request_id": request.request_id, "evidence_id": request.evidence_id,
            "view_id": range.view_id, "view_sha256": range.view_sha256,
            "offset_basis": "view_bytes", "offset": range.offset,
            "returned_bytes": range.bytes.len(), "total_bytes": range.total_bytes,
            "next_offset": range.next_offset, "eof": range.next_offset.is_none(),
            "encoding": "hex", "data": hex(&range.bytes), "identity": identity, "provenance": provenance,
            "allowance": { "expires_at": range.allowance_expires_at,
                "remaining_bytes": range.remaining_bytes, "remaining_pages": range.remaining_pages }
        }),
        evidence: vec![request.evidence_id.clone()],
    })
}

async fn authorize_origin(
    store: &Store,
    policy: &ScopePolicy,
    repo: &Path,
    origin: &EvidenceOrigin,
) -> Result<(), CapabilityFailure> {
    if origin.targets.len() > 256 {
        return Err(unavailable());
    }
    for target in &origin.targets {
        let configured = store
            .get_connector(target.connector.as_str())
            .await
            .map_err(store_failure)?
            .ok_or_else(unavailable)?;
        let current_url =
            crate::connector_service::configured_url(target.connector, Some(&configured))
                .map_err(|_| unavailable())?;
        if !configured.enabled || current_url != target.base_url {
            return Err(unavailable());
        }
        policy
            .authorize_connector(
                repo,
                target.connector,
                &target.base_url,
                &target.call,
                &target.args,
            )
            .map_err(|_| unavailable())?;
    }
    Ok(())
}

pub(crate) fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}
