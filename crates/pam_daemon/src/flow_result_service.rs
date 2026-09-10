//! Durable bounded flow results; tickets never confer repository authority.
use std::path::Path;

use pam_proto::{Outcome, Response};
use pam_store::{FlowResultMeta, RequestStatusMeta, Store};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::evidence_service::{EvidenceOrigin, authorize_origin};
use crate::executor::{CapabilityFailure, CapabilityOutput, ExecContext};
use crate::scope_policy::ScopePolicy;

pub(crate) const CAP_FLOW_RESULT: &str = "flow.result";
const MAX_RESPONSE: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    ticket: String,
}

fn unavailable() -> CapabilityFailure {
    CapabilityFailure::Refused {
        cause: "result_unavailable".into(),
        detail: "No readable result matches this ticket, repository and current authorization."
            .into(),
        recovery: "Use a ticket from an approved task; inspect access in the PAM GUI.".into(),
    }
}

async fn ticket(ctx: &ExecContext) -> Result<String, CapabilityFailure> {
    let args: Args = serde_json::from_value(ctx.args.clone()).map_err(|_| unavailable())?;
    if args.ticket.is_empty() || args.ticket.len() > 128 {
        return Err(unavailable());
    }
    ctx.budget
        .attempt_persisted()
        .await
        .map_err(|_| unavailable())?;
    Ok(args.ticket)
}

/// Return only selected durable metadata, never the protected verdict body.
pub(crate) async fn result(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let ticket = ticket(ctx).await?;
    let (status, result) = authorized_metadata(&ctx.store, &ctx.caller.repo, &ticket).await?;
    let mut output = result_output(&ctx.request_id, &ticket, &status, result.as_ref())?;
    if let Some(progress) = ctx
        .store
        .flow_watch_progress(&ticket, &status.repository)
        .await
        .map_err(|_| unavailable())?
    {
        output.body["watch"] = serde_json::from_str(&progress).map_err(|_| unavailable())?;
        // Progress may have been published after the first origin snapshot.
        authorized_metadata(&ctx.store, &ctx.caller.repo, &ticket).await?;
    }
    bounded_output(&ctx.request_id, output.outcome, output.body)
}

/// Preserve lifecycle state even when no final agent projection exists yet.
pub(crate) fn result_output(
    id: &str,
    ticket: &str,
    status: &RequestStatusMeta,
    result: Option<&FlowResultMeta>,
) -> Result<CapabilityOutput, CapabilityFailure> {
    if status.capability != "flow.run" {
        return Err(unavailable());
    }
    let projection = if status.state.is_terminal() {
        result
            .and_then(|result| serde_json::from_str::<Value>(&result.metadata_json).ok())
            .and_then(|metadata| metadata.get("agent_result").cloned())
            .and_then(|value| validated_projection(&value, ticket).ok())
            .filter(|value| value["workflow"]["outcome"].as_str() == status.outcome.as_deref())
    } else {
        None
    };
    let outcome = status
        .outcome
        .as_deref()
        .and_then(parse_outcome)
        .unwrap_or(Outcome::Blocked);
    let unavailable = projection.is_none().then(|| {
        json!({"cause":if status.state.is_terminal() {
        "projection_unavailable"
    } else {"not_ready"}})
    });
    bounded_output(
        id,
        outcome,
        json!({"schema_version":1,"ticket":ticket,
        "state":status.state.as_str(),"outcome":status.outcome,"agent_result":projection,
        "result_unavailable":unavailable}),
    )
}

/// Scoped replacement for the former unrestricted status lookup.
pub(crate) async fn scoped_query(ctx: &ExecContext) -> Result<CapabilityOutput, CapabilityFailure> {
    let ticket = ticket(ctx).await?;
    let (status, _) = authorized_metadata(&ctx.store, &ctx.caller.repo, &ticket).await?;
    let outcome = if status.state.is_terminal() {
        status
            .outcome
            .as_deref()
            .and_then(parse_outcome)
            .unwrap_or(Outcome::Blocked)
    } else {
        Outcome::Blocked
    };
    bounded_output(
        &ctx.request_id,
        outcome,
        json!({"ticket":ticket,
        "state":status.state.as_str(),"outcome":status.outcome,"capability":status.capability}),
    )
}

/// Authorization happens before exposing existence, including terminal status.
pub(crate) async fn authorized_metadata(
    store: &Store,
    caller_repo: &str,
    ticket: &str,
) -> Result<(RequestStatusMeta, Option<FlowResultMeta>), CapabilityFailure> {
    let policy = ScopePolicy::load(store).await.map_err(|_| unavailable())?;
    let repo = policy
        .authorize_repo(Path::new(caller_repo))
        .map_err(|_| unavailable())?;
    let status = store
        .request_status_meta(ticket)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    if crate::executor::BuiltinCapability::from_name(&status.capability).is_none() {
        return Err(unavailable());
    }
    // Stored admission identity is immutable; never reinterpret it through a
    // symlink that may have been retargeted since the request was accepted.
    if Path::new(&status.repository) != repo {
        return Err(unavailable());
    }
    let owner = std::fs::canonicalize(&status.repository).map_err(|_| unavailable())?;
    if owner != Path::new(&status.repository) {
        return Err(unavailable());
    }
    let revision = store
        .grant_revocation_revision()
        .await
        .map_err(|_| unavailable())?;
    if status.authorization_revision != Some(revision) {
        return Err(unavailable());
    }
    let result = store
        .flow_result_meta(ticket, &repo.to_string_lossy())
        .await
        .map_err(|_| unavailable())?;
    let origins = store
        .request_evidence_origins(ticket, &repo.to_string_lossy())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(unavailable)?;
    let origins: Vec<EvidenceOrigin> = origins
        .into_iter()
        .map(|origin| serde_json::from_str(&origin).map_err(|_| unavailable()))
        .collect::<Result<_, _>>()?;
    for origin in &origins {
        authorize_origin(store, &policy, &repo, origin)
            .await
            .map_err(|_| unavailable())?;
    }
    let current = ScopePolicy::load(store).await.map_err(|_| unavailable())?;
    current.authorize_repo(&repo).map_err(|_| unavailable())?;
    for origin in &origins {
        authorize_origin(store, &current, &repo, origin)
            .await
            .map_err(|_| unavailable())?;
    }
    if store
        .grant_revocation_revision()
        .await
        .map_err(|_| unavailable())?
        != revision
    {
        return Err(unavailable());
    }
    Ok((status, result))
}

fn parse_outcome(value: &str) -> Option<Outcome> {
    match value {
        "solved" => Some(Outcome::Solved),
        "changed" => Some(Outcome::Changed),
        "verified" => Some(Outcome::Verified),
        "unresolved" => Some(Outcome::Unresolved),
        "blocked" => Some(Outcome::Blocked),
        _ => None,
    }
}

pub(crate) fn validated_projection(
    value: &Value,
    ticket: &str,
) -> Result<Value, CapabilityFailure> {
    let projection: crate::flow_contract::AgentResult =
        serde_json::from_value(value.clone()).map_err(|_| unavailable())?;
    if projection.schema_version != 1
        || projection.ticket != ticket
        || parse_outcome(&projection.workflow.outcome).is_none()
        || projection
            .observations
            .iter()
            .map(|item| item.text.len())
            .sum::<usize>()
            > 6000
        || serde_json::to_vec(&projection)
            .map_err(|_| unavailable())?
            .len()
            > 14 * 1024
    {
        return Err(unavailable());
    }
    let value = serde_json::to_value(projection).map_err(|_| unavailable())?;
    crate::evidence_view::redact_json(&value).map_err(|_| unavailable())
}

pub(crate) fn bounded_output(
    id: &str,
    outcome: Outcome,
    body: Value,
) -> Result<CapabilityOutput, CapabilityFailure> {
    let evidence: Vec<String> = body
        .get("agent_result")
        .and_then(|projection| projection.get("evidence"))
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .filter(|id| id.len() <= 128)
        .map(str::to_owned)
        .into_iter()
        .collect();
    let response = Response::Result {
        id: id.to_owned(),
        outcome,
        body: body.clone(),
        evidence: evidence.clone(),
    };
    if serde_json::to_vec(&response)
        .map_err(|_| unavailable())?
        .len()
        > MAX_RESPONSE
    {
        return Err(unavailable());
    }
    Ok(CapabilityOutput {
        outcome,
        body,
        evidence,
    })
}
