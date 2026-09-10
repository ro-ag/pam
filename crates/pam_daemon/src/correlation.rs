//! Frozen request targets and immutable product associations, before publication.
use std::collections::{BTreeMap, BTreeSet};

use pam_flow::{ConnectorId, CorrelationTarget, Flow, Role, Step, Vars};
use pam_store::{CorrelationBind, Store};
use serde_json::{Value, json};

use crate::correlation_eval::{Decision, Status};
use crate::evidence_service::ConnectorTarget;

pub(crate) const INVALID: &str = "correlation_invalid";
pub(crate) const CONFLICT: &str = "correlation_conflicting";
pub(crate) const MISSING: &str = "correlation_missing";
pub(crate) const STORAGE: &str = "correlation_storage";
pub(crate) const RECOVERY: &str = "Supply the exact repository, full commit and product identifiers; inspect retained evidence. Start a new request when the intended target changes.";

pub(crate) struct Failure {
    pub cause: &'static str,
    pub detail: String,
}

pub(crate) struct Frozen {
    record: Value,
    target: Option<CorrelationTarget>,
    target_id: String,
    decisions: BTreeMap<String, Value>,
    jobs: BTreeSet<String>,
}

impl Frozen {
    pub fn refuse_unbound_verification(&mut self, step: &Step) -> bool {
        if self.target.is_none() || step.role != Role::Verify {
            return false;
        }
        self.decisions.insert(step.id.clone(), json!({"status":"missing","detail":"local command verification has no authenticated revision binding"}));
        true
    }

    pub async fn prepare(
        store: &Store,
        ticket: &str,
        repository: &str,
        flow: &Flow,
        vars: &Vars,
    ) -> Result<Self, Failure> {
        let target = flow
            .correlation
            .as_ref()
            .map(|value| value.resolve(vars))
            .transpose()
            .map_err(|error| Failure {
                cause: INVALID,
                detail: error.to_string(),
            })?;
        let record = json!({"schema_version":1,"local_repository":repository,"flow_digest":pam_flow::digest(flow),"target":target});
        let encoded = record.to_string();
        if store
            .bind_correlation_target(ticket, &encoded)
            .await
            .map_err(storage)?
            == CorrelationBind::Conflict
        {
            return Err(Failure {
                cause: CONFLICT,
                detail:
                    "request already carries a different repository, recipe, or revision target"
                        .to_owned(),
            });
        }
        let mut frozen = Self {
            target_id: pam_compact::sha256_hex(encoded.as_bytes()),
            record,
            target,
            decisions: BTreeMap::new(),
            jobs: BTreeSet::new(),
        };
        for row in store
            .read_correlation_steps(ticket)
            .await
            .map_err(storage)?
        {
            let binding: Value = serde_json::from_str(&row.canonical_json).map_err(storage)?;
            frozen.remember_jobs(&binding);
        }
        Ok(frozen)
    }

    /// Product outcomes are deliberately excluded from the identity binding.
    pub async fn associate(
        &mut self,
        store: &Store,
        ticket: &str,
        step: &Step,
        origin: &ConnectorTarget,
        result: Option<&Value>,
    ) -> Result<(), Failure> {
        let identity = crate::correlation_eval::product_identity(
            origin.connector,
            &origin.call,
            &origin.args,
            result,
        );
        let mut decision = if let Some(target) = &self.target {
            crate::correlation_eval::evaluate(target, origin.connector, &origin.call, result)
        } else {
            decide(Status::Unbound, "no revision target was declared")
        };
        if self.target.is_some()
            && origin.connector == ConnectorId::Github
            && origin.call == "job_log"
        {
            let key = job_key(
                &origin.base_url,
                identity.get("repository"),
                identity.get("job_id"),
            );
            decision = if key.is_some_and(|key| self.jobs.contains(&key)) {
                decide(
                    Status::Matched,
                    "job belongs to an already matched run attempt on this server and repository",
                )
            } else {
                decide(
                    Status::Missing,
                    "job has no matched run-attempt association in this request",
                )
            };
        }
        if self.target.is_some() && decision.is_unbound() && step.role == Role::Verify {
            decision = decide(
                Status::Missing,
                "this verification operation cannot establish the declared revision association",
            );
        }
        let binding = json!({"schema_version":1,"target_id":self.target_id,"origin":origin,"identity":identity,"decision":decision});
        match store
            .bind_correlation_step(ticket, &step.id, &binding.to_string())
            .await
            .map_err(storage)?
        {
            CorrelationBind::Conflict => {
                decision = decide(
                    Status::Conflicting,
                    "a retry returned a different product identity; the original association remains pinned",
                );
            }
            CorrelationBind::Inserted | CorrelationBind::Existing => {
                if decision.is_matched() {
                    self.remember_jobs(&binding);
                }
            }
        }
        let failure = decision.cause();
        let detail = decision.detail.clone();
        self.decisions.insert(
            step.id.clone(),
            serde_json::to_value(decision).map_err(storage)?,
        );
        failure.map_or(Ok(()), |cause| Err(Failure { cause, detail }))
    }

    fn remember_jobs(&mut self, binding: &Value) {
        if binding["target_id"] != self.target_id
            || binding["decision"]["status"] != "matched"
            || binding["origin"]["connector"] != "github"
            || binding["origin"]["call"] != "run"
        {
            return;
        }
        let Some(base) = binding["origin"]["base_url"].as_str() else {
            return;
        };
        let identity = &binding["identity"];
        if let Some(ids) = identity["job_ids"].as_array() {
            for id in ids.iter().take(100) {
                if let Some(key) = job_key(base, identity.get("repository"), Some(id)) {
                    self.jobs.insert(key);
                }
            }
        }
    }

    pub fn report(&self) -> Value {
        json!({"target_id":self.target_id,"binding":self.record,"steps":self.decisions,"status":self.status()})
    }

    pub fn summary(&self) -> crate::flow_contract::CorrelationSummary {
        crate::flow_contract::CorrelationSummary {
            status: self.status().to_owned(),
            target_id: self.target_id.clone(),
            commit: self.target.as_ref().map(|target| target.commit.clone()),
        }
    }

    fn status(&self) -> &'static str {
        if self
            .decisions
            .values()
            .any(|value| value["status"] == "conflicting")
        {
            return "conflicting";
        }
        if self.target.is_none() {
            return "unbound";
        }
        if self
            .decisions
            .values()
            .any(|value| value["status"] == "missing")
        {
            return "missing";
        }
        if self
            .decisions
            .values()
            .any(|value| value["status"] == "matched")
        {
            "matched"
        } else {
            "missing"
        }
    }

    pub fn outcome(&self, outcome: pam_proto::Outcome) -> pam_proto::Outcome {
        if self.target.is_some()
            && self.status() != "matched"
            && matches!(
                outcome,
                pam_proto::Outcome::Solved | pam_proto::Outcome::Verified
            )
        {
            pam_proto::Outcome::Unresolved
        } else {
            outcome
        }
    }
}

fn job_key(base: &str, repository: Option<&Value>, job: Option<&Value>) -> Option<String> {
    let repository = repository?.as_str()?;
    let job = job?.as_u64().filter(|id| *id > 0)?;
    Some(json!([base, repository, job]).to_string())
}

fn storage(error: impl std::fmt::Display) -> Failure {
    Failure {
        cause: STORAGE,
        detail: format!("immutable correlation could not be recorded: {error}"),
    }
}

fn decide(status: Status, detail: &str) -> Decision {
    Decision {
        status,
        detail: detail.to_owned(),
    }
}
