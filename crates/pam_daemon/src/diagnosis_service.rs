//! The bounded structured diagnosis run: the host asks, the model proposes, the host disposes. Each
//! round is one stateless advisory call over authoritative statuses, tagged evidence, and pre-bound
//! observe-only reads; a validated response may only finish or request one offered read, else it
//! becomes [`DiagnosisOutcome::Unresolved`]. The response may only repeat a host-minted
//! `operation_id`/`target_ref`; dispatch uses the pre-bound [`ObserveDispatch`] (connector, call,
//! args), never the response's own data — no variant can merge, publish, rerun, or run a command,
//! so the type system is the boundary, not the prompt. A terminal `finish` is admitted only when
//! the recipe's [`AuthorityRule`] is satisfied by *cited* evidence's tags, the evidence set is
//! complete, and confidence is not low (unknown/low always escalate), checked from host data only.
//! The outcome stays advisory — `Diagnosed` is a quoted hypothesis, never a check result. Failure
//! is the normal path: no model, a malformed or fabricated answer, a forged read pair, an exhausted
//! budget — each is [`DiagnosisOutcome::Unresolved`] with a stable cause and zero retries.
//! The caller renders an `Unresolved` cause into its handoff unchanged, as `escalation_required`.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;

use pam_model::diagnosis::{
    self, AllowedRead, Citation, Confidence, DiagnosisData, DiagnosisTask, EvidenceItem,
    Hypothesis, NextStep, RESPONSE_INPUT_LIMIT, Verdict,
};
use pam_model::runtime::{GenerateRequest, GenerateResult};

use crate::model_service::{ModelService, ModelUnavailable, Tier};

/// Most follow-up reads one run may dispatch.
pub const MAX_RUN_READS: usize = 4;

/// Most advisory calls one run may spend: one per read plus the terminal
/// answer.
pub const MAX_RUN_CALLS: usize = MAX_RUN_READS + 1;

/// One authority bar: what a hypothesis must be able to cite.
///
/// `requires_all` tags must all appear across the cited evidence;
/// `requires_any` needs at least one. A rule is a policy the *host*
/// defined — the model cannot see, change, or satisfy it with prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRule {
    /// The non-`unknown` hypothesis this bar applies to.
    pub hypothesis: String,
    /// Every tag here must appear among the cited evidence's tags.
    pub requires_all: Vec<String>,
    /// At least one tag here must appear among the cited evidence's tags.
    pub requires_any: Vec<String>,
}

/// The trusted half of a diagnosis: recipe identity, question, closed
/// hypothesis set, and per-hypothesis authority bars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosisRecipe {
    /// Recipe identity, e.g. `jenkins-build-failure`.
    pub id: String,
    /// Recipe version; the prompt names `id/version`.
    pub version: u32,
    /// The one trusted bounded question.
    pub question: String,
    /// The closed hypothesis set, including `unknown`.
    pub hypotheses: Vec<Hypothesis>,
    /// One bar per non-`unknown` hypothesis.
    pub authority: Vec<AuthorityRule>,
}

impl DiagnosisRecipe {
    /// Validates the cross-references (every bar names a listed
    /// hypothesis, every non-`unknown` hypothesis has a bar) and stores
    /// the recipe. Field bounds are re-checked at task construction.
    pub fn new(
        id: impl Into<String>,
        version: u32,
        question: impl Into<String>,
        hypotheses: Vec<Hypothesis>,
        authority: Vec<AuthorityRule>,
    ) -> Result<Self, pam_model::diagnosis::ContractViolation> {
        let recipe = Self {
            id: id.into(),
            version,
            question: question.into(),
            hypotheses,
            authority,
        };
        let listed: HashSet<&str> = recipe
            .hypotheses
            .iter()
            .map(|hypothesis| hypothesis.name.as_str())
            .collect();
        for rule in &recipe.authority {
            if !listed.contains(rule.hypothesis.as_str()) {
                return Err(pam_model::diagnosis::ContractViolation {
                    cause: "authority_rule",
                    detail: format!(
                        "the authority bar names unlisted hypothesis {:?}",
                        rule.hypothesis
                    ),
                });
            }
        }
        for hypothesis in &recipe.hypotheses {
            if hypothesis.name != diagnosis::UNKNOWN_HYPOTHESIS
                && !recipe
                    .authority
                    .iter()
                    .any(|rule| rule.hypothesis == hypothesis.name)
            {
                return Err(pam_model::diagnosis::ContractViolation {
                    cause: "authority_rule",
                    detail: format!("hypothesis {:?} has no authority bar", hypothesis.name),
                });
            }
        }
        Ok(recipe)
    }

    /// The build-failure recipe from the prompt specification: infra,
    /// code, config and flake answers, with `unknown` protecting reality.
    #[must_use]
    pub fn jenkins_build_failure() -> Self {
        let hypothesis = |name: &str, definition: &str| Hypothesis {
            name: name.to_owned(),
            definition: definition.to_owned(),
        };
        Self::new(
            "jenkins-build-failure",
            1,
            "Which failure class does this evidence support for the failed build?",
            vec![
                hypothesis(
                    "infra",
                    "Infrastructure failure: runner or service evidence is required.",
                ),
                hypothesis(
                    "code",
                    "Code failure: compiler, assertion or program failure evidence is required.",
                ),
                hypothesis(
                    "config",
                    "Configuration failure: a concrete configuration mismatch is required.",
                ),
                hypothesis(
                    "flake",
                    "Flakiness: comparable passing and failing attempts on the same commit are \
                     required; a transient-looking message or one passing rerun does not prove it.",
                ),
                hypothesis(
                    diagnosis::UNKNOWN_HYPOTHESIS,
                    "Evidence is insufficient or supports competing explanations.",
                ),
            ],
            vec![
                AuthorityRule {
                    hypothesis: "infra".into(),
                    requires_all: vec![],
                    requires_any: vec!["runner".into(), "service".into()],
                },
                AuthorityRule {
                    hypothesis: "code".into(),
                    requires_all: vec![],
                    requires_any: vec![
                        "compile_error".into(),
                        "assertion_failure".into(),
                        "program_failure".into(),
                    ],
                },
                AuthorityRule {
                    hypothesis: "config".into(),
                    requires_all: vec![],
                    requires_any: vec!["config_mismatch".into()],
                },
                AuthorityRule {
                    hypothesis: "flake".into(),
                    requires_all: vec!["passing_attempt".into(), "failing_attempt".into()],
                    requires_any: vec![],
                },
            ],
        )
        .expect("the built-in recipe satisfies its own bars")
    }

    fn identity(&self) -> String {
        format!("{}/v{}", self.id, self.version)
    }
}

/// One pre-bound observe-only dispatch.
///
/// Every field is host-authored before the run starts; the model's
/// response selects a whole [`BoundRead`] by its minted pair or nothing.
/// The struct deliberately has no constructor that accepts model text and
/// no variant beyond a observe-role connector call — there is no way to
/// express a merge, publish, rerun, or command here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveDispatch {
    /// Connector id, e.g. `jenkins`.
    pub connector: String,
    /// Observe-role call on that connector, e.g. `node_evidence`.
    pub call: String,
    /// The exact arguments to dispatch, validated identifiers only.
    pub args: BTreeMap<String, String>,
}

/// A read the host offers the model: the minted pair plus what will
/// actually run when the pair is requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundRead {
    /// The operation name the response may repeat.
    pub operation_id: String,
    /// Bounded description of what the read observes.
    pub description: String,
    /// The dispatch that runs when this read is selected.
    pub dispatch: ObserveDispatch,
}

/// Everything one run needs besides the recipe and the budgets.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RunInputs {
    /// Authoritative statuses; the model may not contradict them into a
    /// pass, and the outcome never overrides them either.
    pub statuses: serde_json::Value,
    /// The citable evidence, with host-assigned tags.
    pub evidence: Vec<EvidenceItem>,
    /// Whether the evidence set is complete enough to assert anything.
    pub complete: bool,
    /// Explicit omissions the model is told about.
    pub completeness_notes: Vec<String>,
    /// The host-minted reads, in offer order (`target_0`, `target_1`, ...).
    pub reads: Vec<BoundRead>,
}

/// How many reads and calls one run may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// Most follow-up reads dispatched across the whole run.
    pub max_reads: usize,
    /// Most advisory calls across the whole run.
    pub max_calls: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_reads: MAX_RUN_READS,
            max_calls: MAX_RUN_CALLS,
        }
    }
}

/// What one follow-up read returned. The host assigns the tags and the
/// completeness verdict; the model sees the text as evidence, nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOutcome {
    /// Evidence item name for the appended text.
    pub name: String,
    /// The observed bytes, UTF-8.
    pub text: String,
    /// Host-assigned semantic tags.
    pub tags: Vec<String>,
    /// Whether this read closes the run's completeness gap.
    pub completes: bool,
}

/// The advisory verdict, quoted data downstream — never executed, never a
/// status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryDiagnosis {
    /// The selected hypothesis from the recipe's closed set.
    pub hypothesis: String,
    /// Claimed confidence.
    pub confidence: Confidence,
    /// The model's bounded summary.
    pub summary: String,
    /// Byte-honest citations into the run's evidence.
    pub citations: Vec<Citation>,
}

impl From<&Verdict> for AdvisoryDiagnosis {
    fn from(verdict: &Verdict) -> Self {
        Self {
            hypothesis: verdict.hypothesis.clone(),
            confidence: verdict.confidence,
            summary: verdict.summary.clone(),
            citations: verdict.citations.clone(),
        }
    }
}

/// What the run spent on the model, accumulated across its calls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnosisUse {
    /// Advisory calls made.
    pub calls: usize,
    /// Framed prompt tokens, summed.
    pub prompt_tokens: usize,
    /// Generated tokens, summed.
    pub completion_tokens: usize,
    /// Registry id of the model that answered, when one did.
    pub model_id: Option<String>,
    /// Citations whose byte span the host derived from the verbatim quote
    /// because the model's own offsets were wrong.
    pub citations_resolved: usize,
}

/// The run's outcome: an advisory diagnosis, or the unresolved handoff.
#[derive(Debug, Clone, PartialEq)]
pub enum DiagnosisOutcome {
    /// A terminal verdict that survived every contract and authority
    /// check. Still advisory: the caller's workflow status is untouched.
    Diagnosed {
        /// The recipe identity and version that ran.
        recipe: String,
        /// The validated verdict as quoted data.
        advisory: AdvisoryDiagnosis,
        /// Follow-up reads dispatched.
        reads_used: usize,
        /// What the run spent.
        use_: DiagnosisUse,
    },
    /// Every failure path — including a merely unsure model — lands here,
    /// with the stable cause and whatever advisory payload existed.
    Unresolved {
        /// Stable machine-readable cause.
        cause: &'static str,
        /// What specifically ended the run.
        detail: String,
        /// The last validated verdict, when one existed.
        advisory: Option<AdvisoryDiagnosis>,
        /// Follow-up reads dispatched before the run ended.
        reads_used: usize,
        /// What the run spent.
        use_: DiagnosisUse,
    },
}

/// The real generator: the daemon's model service on the strongest
/// configured tier (`heavy` falls back to `light`, so one configured model
/// serves). A refusal of any kind — no default, missing weights, busy
/// runtime — becomes [`DiagnosisOutcome::Unresolved`] with cause
/// `model_unavailable`.
pub struct TierModel<'a> {
    /// The daemon's model layer.
    pub service: &'a ModelService,
    /// The tier to spend.
    pub tier: Tier,
}

impl TierModel<'_> {
    /// One bounded generation at the diagnosis envelope.
    pub fn generate(
        &self,
        request: GenerateRequest,
    ) -> impl Future<Output = Result<GenerateResult, ModelUnavailable>> + Send + '_ {
        self.service
            .generate_bounded(self.tier, request, RESPONSE_INPUT_LIMIT)
    }
}

/// Runs one bounded diagnosis: advisory calls with validated reads until a
/// terminal verdict survives every check or anything at all goes wrong.
///
/// The generator and reader are callables so the daemon wires the real
/// model service and connector dispatch, and the acceptance suite scripts
/// hostile models without weights.
#[allow(
    clippy::too_many_lines,
    reason = "one explicit loop with one early return per refusal cause; splitting the \
              refusal ladder would scatter the authority checks this service exists to \
              centralize"
)]
pub async fn diagnose<G, F, R, RF>(
    recipe: &DiagnosisRecipe,
    inputs: RunInputs,
    budgets: Budgets,
    generate: G,
    read: R,
) -> DiagnosisOutcome
where
    G: Fn(GenerateRequest) -> F,
    F: Future<Output = Result<GenerateResult, ModelUnavailable>>,
    R: Fn(ObserveDispatch) -> RF,
    RF: Future<Output = Result<ReadOutcome, String>>,
{
    let mut use_ = DiagnosisUse::default();
    let mut evidence = inputs.evidence;
    let mut complete = inputs.complete;
    let mut notes = inputs.completeness_notes;
    // Minted once: every call offers the same pairs, and only the budget
    // bounds how many may actually dispatch.
    let offered: Vec<AllowedRead> = inputs
        .reads
        .iter()
        .enumerate()
        .map(|(index, bound)| AllowedRead {
            operation_id: bound.operation_id.clone(),
            target_ref: format!("target_{index}"),
            description: bound.description.clone(),
        })
        .collect();
    let mut dispatched: HashSet<(String, String)> = HashSet::new();
    let mut reads_used = 0usize;

    let unresolved = |cause: &'static str,
                      detail: String,
                      advisory: Option<AdvisoryDiagnosis>,
                      use_: &DiagnosisUse,
                      reads_used: usize| {
        DiagnosisOutcome::Unresolved {
            cause,
            detail,
            advisory,
            reads_used,
            use_: use_.clone(),
        }
    };

    loop {
        if use_.calls >= budgets.max_calls {
            return unresolved(
                "budget_exhausted",
                format!("the run reached its {}-call budget", budgets.max_calls),
                None,
                &use_,
                reads_used,
            );
        }
        let task = match DiagnosisTask::new(
            recipe.identity(),
            recipe.question.clone(),
            recipe.hypotheses.clone(),
            DiagnosisData {
                statuses: inputs.statuses.clone(),
                complete,
                completeness_notes: notes.clone(),
                evidence: evidence.clone(),
                reads: offered.clone(),
            },
        ) {
            Ok(task) => task,
            Err(violation) => {
                return unresolved(
                    "contract_violation",
                    violation.to_string(),
                    None,
                    &use_,
                    reads_used,
                );
            }
        };
        let result = match generate(task.request()).await {
            Ok(result) => result,
            Err(error) => {
                return unresolved(
                    "model_unavailable",
                    error.to_string(),
                    None,
                    &use_,
                    reads_used,
                );
            }
        };
        use_.calls += 1;
        use_.prompt_tokens = use_.prompt_tokens.saturating_add(result.prompt_tokens);
        use_.completion_tokens = use_
            .completion_tokens
            .saturating_add(result.completion_tokens);
        use_.model_id = Some(result.model.id.clone());

        // Models quote exactly but miscount bytes: derive each citation's
        // span from its verbatim quote, then hold the result to the same
        // byte-exact contract as before.
        let resolved = diagnosis::resolve_citation_offsets(&result.text, &task);
        use_.citations_resolved = use_.citations_resolved.saturating_add(resolved.resolved);
        let verdict = match diagnosis::validate(&resolved.text, &task) {
            Ok(verdict) => verdict,
            Err(rejection) => {
                return unresolved(
                    rejection.cause,
                    rejection.to_string(),
                    None,
                    &use_,
                    reads_used,
                );
            }
        };
        let advisory = AdvisoryDiagnosis::from(&verdict);

        // One read per response, budget permitting; an unsure verdict may
        // still gather evidence before its terminal report.
        if let NextStep::Read {
            operation_id,
            target_ref,
        } = &verdict.next
        {
            if reads_used >= budgets.max_reads {
                return unresolved(
                    "budget_exhausted",
                    format!("the run reached its {}-read budget", budgets.max_reads),
                    Some(advisory),
                    &use_,
                    reads_used,
                );
            }
            if !dispatched.insert((operation_id.clone(), target_ref.clone())) {
                return unresolved(
                    "repeated_read",
                    format!("the read {operation_id}/{target_ref} was already dispatched"),
                    Some(advisory),
                    &use_,
                    reads_used,
                );
            }
            // `validate` admitted the pair, so the bound exists; dispatch
            // carries the pre-bound operation only.
            let bound = inputs
                .reads
                .iter()
                .find(|bound| bound.operation_id == *operation_id)
                .expect("the offered pair names a bound read");
            let outcome = match read(bound.dispatch.clone()).await {
                Ok(outcome) => outcome,
                Err(detail) => {
                    return unresolved("read_failed", detail, Some(advisory), &use_, reads_used);
                }
            };
            if outcome.text.len() > diagnosis::MAX_EVIDENCE_ITEM_BYTES {
                return unresolved(
                    "read_failed",
                    format!(
                        "the follow-up read is {} bytes; the evidence bound is {}",
                        outcome.text.len(),
                        diagnosis::MAX_EVIDENCE_ITEM_BYTES
                    ),
                    Some(advisory),
                    &use_,
                    reads_used,
                );
            }
            reads_used += 1;
            evidence.push(EvidenceItem {
                id: format!("ev_followup_{reads_used}"),
                name: outcome.name,
                tags: outcome.tags,
                text: outcome.text,
            });
            if outcome.completes {
                complete = true;
            }
            if notes.len() < diagnosis::MAX_COMPLETENESS_NOTES {
                notes.push(format!(
                    "follow-up read {operation_id} returned new evidence"
                ));
            }
            continue;
        }

        // Terminal verdict: escalation is computed here, in code, from
        // host data — never from a model flag.
        if verdict.hypothesis == diagnosis::UNKNOWN_HYPOTHESIS {
            return unresolved(
                "model_unknown",
                "the model answered unknown".to_owned(),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        if verdict.confidence == Confidence::Low {
            return unresolved(
                "low_confidence",
                "the model answered low confidence".to_owned(),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        if !complete {
            return unresolved(
                "incomplete_evidence",
                "the evidence set is not complete enough to assert a cause".to_owned(),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        let cited_tags: HashSet<&str> = evidence
            .iter()
            .filter(|item| {
                verdict
                    .citations
                    .iter()
                    .any(|citation| citation.evidence == item.id)
            })
            .flat_map(|item| item.tags.iter().map(String::as_str))
            .collect();
        if verdict.citations.is_empty() {
            return unresolved(
                "unsupported_hypothesis",
                "the verdict cites no evidence".to_owned(),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        let Some(rule) = recipe
            .authority
            .iter()
            .find(|rule| rule.hypothesis == verdict.hypothesis)
        else {
            return unresolved(
                "unsupported_hypothesis",
                format!("no authority bar is defined for {:?}", verdict.hypothesis),
                Some(advisory),
                &use_,
                reads_used,
            );
        };
        let missing_all: Vec<&str> = rule
            .requires_all
            .iter()
            .map(String::as_str)
            .filter(|tag| !cited_tags.contains(tag))
            .collect();
        if !missing_all.is_empty() {
            return unresolved(
                "unsupported_hypothesis",
                format!("the cited evidence lacks required tags {missing_all:?}"),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        if !rule.requires_any.is_empty()
            && !rule
                .requires_any
                .iter()
                .any(|tag| cited_tags.contains(tag.as_str()))
        {
            return unresolved(
                "unsupported_hypothesis",
                format!(
                    "the cited evidence lacks every required tag {:?}",
                    rule.requires_any
                ),
                Some(advisory),
                &use_,
                reads_used,
            );
        }
        return DiagnosisOutcome::Diagnosed {
            recipe: recipe.identity(),
            advisory,
            reads_used,
            use_,
        };
    }
}
