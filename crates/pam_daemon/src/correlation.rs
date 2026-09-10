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
    sonar_mapping: Option<crate::sonar_mapping::Snapshot>,
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
        let sonar_mapping = if flow.steps.iter().any(|step| matches!(&step.action,
            pam_flow::Action::Connector { connector: ConnectorId::Sonarqube, call, .. } if call == "analysis")) {
            Some(crate::sonar_mapping::Snapshot::load(store).await.map_err(storage)?)
        } else { None };
        let record = json!({"schema_version":1,"local_repository":repository,"flow_digest":pam_flow::digest(flow),"target":target,
            "sonar_mapping_revision":sonar_mapping.as_ref().map(crate::sonar_mapping::Snapshot::revision)});
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
            sonar_mapping,
        };
        for row in store
            .read_correlation_steps(ticket)
            .await
            .map_err(storage)?
        {
            let binding: Value = serde_json::from_str(&row.canonical_json).map_err(storage)?;
            let decision = &binding["decision"];
            if binding["schema_version"] != 1
                || binding["target_id"] != frozen.target_id
                || !flow.steps.iter().any(|step| step.id == row.step_id)
                || !matches!(
                    decision["status"].as_str(),
                    Some("matched" | "missing" | "conflicting" | "unbound")
                )
                || decision["detail"]
                    .as_str()
                    .is_none_or(|detail| detail.len() > 4096)
            {
                return Err(Failure {
                    cause: STORAGE,
                    detail: "invalid retained product association".to_owned(),
                });
            }
            frozen
                .restore_jobs(store, ticket, &row.step_id, &binding)
                .await?;
            frozen.decisions.insert(row.step_id, decision.clone());
        }
        Ok(frozen)
    }

    pub async fn check_mapping(&self, store: &Store) -> Result<(), Failure> {
        if let Some(mapping) = &self.sonar_mapping
            && crate::sonar_mapping::Snapshot::load(store)
                .await
                .map_err(storage)?
                .revision()
                != mapping.revision()
        {
            return Err(Failure {
                cause: CONFLICT,
                detail: "Sonar repository mapping changed during collection; start a new request"
                    .to_owned(),
            });
        }
        Ok(())
    }

    pub fn invalidate(&mut self, error: &Failure) {
        self.decisions.insert(
            "mapping_check".to_owned(),
            json!({"status":"conflicting","detail":error.detail}),
        );
    }

    /// Repository identity comes only from the GUI-owned mapping snapshot.
    pub async fn enrich(
        &self,
        store: &Store,
        origin: &ConnectorTarget,
        result: Option<&mut Value>,
    ) -> Result<(), Failure> {
        if origin.connector != ConnectorId::Sonarqube || origin.call != "analysis" {
            return Ok(());
        }
        let mapping = self.sonar_mapping.as_ref().ok_or_else(|| Failure {
            cause: MISSING,
            detail: "Sonar mapping snapshot unavailable".to_owned(),
        })?;
        self.check_mapping(store).await?;
        let Some(result) = result else {
            return Ok(());
        };
        let project = result.get("project").and_then(Value::as_str).unwrap_or("");
        let repository = mapping.repository(&origin.base_url, project);
        let revision = result
            .get("revision")
            .and_then(Value::as_str)
            .filter(|_| result["revision_basis"] == "analysis_history")
            .and_then(|value| pam_flow::validate_full_commit(value).ok());
        let matched = repository.is_some() && revision.is_some();
        result["source_identity"] = json!({"status":if matched {"unambiguous"} else {"missing"},
            "repository_urls":repository.into_iter().collect::<Vec<_>>(),"revisions":revision.into_iter().collect::<Vec<_>>(),
            "partial":!matched,"invalid_metadata":false,"repository_basis":"gui_mapping","mapping_revision":mapping.revision(),
            "revision_basis":"sonar_reported_analysis_history"});
        Ok(())
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
                if decision.is_matched() && github_run_binding(&binding) {
                    let observed = observed_jobs(result)?;
                    let jobs = store
                        .append_correlation_membership(
                            ticket,
                            &step.id,
                            &binding.to_string(),
                            &observed,
                        )
                        .await
                        .map_err(storage)?
                        .ok_or_else(|| Failure {
                            cause: CONFLICT,
                            detail: "run-attempt binding changed before membership capture"
                                .to_owned(),
                        })?;
                    self.remember_jobs(&binding, &jobs);
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

    async fn restore_jobs(
        &mut self,
        store: &Store,
        ticket: &str,
        step_id: &str,
        binding: &Value,
    ) -> Result<(), Failure> {
        if !github_run_binding(binding) {
            return Ok(());
        }
        if binding["identity"].get("job_ids").is_some() {
            return Err(Failure { cause: STORAGE, detail: "legacy job membership was part of immutable identity; start a new request after upgrading".to_owned() });
        }
        let jobs = store
            .read_correlation_membership(ticket, step_id, &binding.to_string())
            .await
            .map_err(storage)?
            .ok_or_else(|| Failure {
                cause: STORAGE,
                detail: "retained run-attempt binding changed".to_owned(),
            })?;
        self.remember_jobs(binding, &jobs);
        Ok(())
    }

    fn remember_jobs(&mut self, binding: &Value, ids: &[u64]) {
        if binding["target_id"] != self.target_id || !github_run_binding(binding) {
            return;
        }
        let Some(base) = binding["origin"]["base_url"].as_str() else {
            return;
        };
        for id in ids {
            if let Some(key) = job_key(
                base,
                binding["identity"].get("repository"),
                Some(&json!(id)),
            ) {
                self.jobs.insert(key);
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

fn github_run_binding(binding: &Value) -> bool {
    binding["decision"]["status"] == "matched"
        && binding["origin"]["connector"] == "github"
        && binding["origin"]["call"] == "run"
}

fn observed_jobs(result: Option<&Value>) -> Result<Vec<u64>, Failure> {
    let jobs = result
        .and_then(|value| value.get("jobs"))
        .and_then(Value::as_array)
        .filter(|jobs| jobs.len() <= 256)
        .ok_or_else(|| Failure {
            cause: STORAGE,
            detail: "run jobs missing or membership capacity exceeded".to_owned(),
        })?;
    jobs.iter()
        .map(|job| {
            job.get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)
                .ok_or_else(|| Failure {
                    cause: STORAGE,
                    detail: "run contains invalid job membership".to_owned(),
                })
        })
        .collect()
}
