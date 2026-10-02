//! Which artifacts have earned a job: the compiled-in qualification table.
//!
//! Verification (a matching SHA-256, [`crate::registry::classify`]) only proves the bytes
//! are the bytes. Serving a job needs evidence that *those* bytes, on *this* engine build,
//! on *this* device class, met the product's gates under a frozen contract — a bench
//! record under `docs/benchmarks`. Each [`Qualification`] binds that evidence to one
//! artifact digest; [`find`] answers whether a digest is qualified on a target. The table
//! is code, not configuration: adding or removing a record is a reviewed change, and a
//! unit test refuses any record whose engine tag is not the pinned one, so bumping the
//! engine forces requalification instead of silently carrying old numbers forward.
//! Memory is deliberately not a gate: it is host-dependent and measured at admission.
//!
//! A record is a claim about **the capability bench**, and it is bound to what the bench
//! measured: [`BenchContract`] is the bench's answer-contract version, the digest of its
//! frozen case set, its system turn, output cap and input limit, and
//! [`Qualification::engine`] is the set of engine options that change output, as the run
//! used them. Their fingerprint ([`BenchContract::fingerprint`]) is stored on the record
//! ([`Qualification::bench_contract`]). [`assess`] recomputes it with the engine options
//! *this build* starts the model with: when they differ, the figures describe another
//! configuration, the artifact is unqualified ([`Standing::ContractChanged`]) and it needs
//! re-measurement. Changing the seed, the context, the template source or any other
//! output-affecting option therefore drops the badge by itself.
//!
//! What a record does **not** claim: that any other prompt was measured. A job's own
//! prompt (the log summary) has its own fingerprint, [`PromptContract`], which the daemon
//! discloses beside the readiness of a tier. It is a disclosure and never a gate: the
//! summary of a bench-qualified model is advisory, labelled untrusted, and has not been
//! measured separately.

use sha2::{Digest, Sha256};

use crate::engine::{ENGINE_TAG, Target};
use crate::engine_server::EngineContract;
use crate::runtime::GenerateRequest;

/// Version of the prompt fingerprint's own layout.
const CONTRACT_FINGERPRINT_VERSION: &str = "pam-prompt-contract-v1";

/// Version of the bench fingerprint's own layout: bumping it invalidates every record.
const BENCH_FINGERPRINT_VERSION: &str = "pam-bench-contract-v1";

/// What the capability bench asked, as a record states it: the identity of the prompt
/// set and the generation envelope every case ran under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct BenchContract<'a> {
    /// Answer-contract version, e.g. `answer-contract-v2`.
    pub contract: &'a str,
    /// SHA-256 of the frozen case set (records, host facts, questions, expectations).
    pub case_set_sha256: &'a str,
    /// SHA-256 of the system turn every case was framed under (the case digest does not
    /// cover it).
    pub system_sha256: &'a str,
    /// Output cap per case, in tokens.
    pub output_cap: usize,
    /// Framed-prompt token limit per case.
    pub input_limit: usize,
}

impl BenchContract<'_> {
    /// Lowercase hex SHA-256 over this contract and the engine options that change
    /// output. Stable across runs and hosts: it is a digest of the serialised fields in
    /// declaration order.
    #[must_use]
    pub fn fingerprint(&self, engine: &EngineContract) -> String {
        let mut hasher = Sha256::new();
        hasher.update(BENCH_FINGERPRINT_VERSION.as_bytes());
        hasher.update([0]);
        // Serialising plain structs of strings and numbers cannot fail.
        hasher.update(serde_json::to_vec(&(self, engine)).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

/// Everything a job sends to the model apart from the evidence itself. Disclosed, never
/// gated on: no qualification record was measured under a job's prompt.
///
/// Built from the request the product would really send, with fixed placeholders where
/// the evidence, the per-call fence token and host-measured values go, so an edit to the
/// instructions or to the framing code changes the fingerprint without anyone bumping a
/// version by hand.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PromptContract {
    /// What the job is, e.g. `log.summary`.
    pub task: String,
    /// The system turn as sent, placeholders in place of per-call values.
    pub system: Option<String>,
    /// The user turn as sent, a placeholder in place of the evidence.
    pub prompt: String,
    /// Hard ceiling on generated tokens.
    pub max_tokens: usize,
    /// Sampling temperature.
    pub temperature: f64,
    /// Stop strings.
    pub stop: Vec<String>,
    /// The framed-prompt token limit the job is admitted under.
    pub input_limit: usize,
}

impl PromptContract {
    /// The contract of `request` (built over placeholder evidence) for `task`, admitted
    /// under `input_limit` prompt tokens.
    #[must_use]
    pub fn of(task: &str, request: &GenerateRequest, input_limit: usize) -> Self {
        Self {
            task: task.to_owned(),
            system: request.system.clone(),
            prompt: request.prompt.clone(),
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            stop: request.stop.clone(),
            input_limit,
        }
    }

    /// Lowercase hex SHA-256 over this contract and the engine options that change
    /// output. Stable across runs and hosts: it is a digest of the serialised fields in
    /// declaration order.
    #[must_use]
    pub fn fingerprint(&self, engine: &EngineContract) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CONTRACT_FINGERPRINT_VERSION.as_bytes());
        hasher.update([0]);
        // Serialising plain structs of strings and numbers cannot fail.
        hasher.update(serde_json::to_vec(&(self, engine)).unwrap_or_default());
        hex::encode(hasher.finalize())
    }
}

/// Accuracy on decidable cases a record must reach.
pub const ACCURACY_GATE: f64 = 0.95;

/// False passes a record must have exactly: a wrong "this passed" is the one
/// error the product cannot afford.
pub const FALSE_PASS_GATE: u32 = 0;

/// Warm p95 latency, in milliseconds, a record must stay under on short tasks.
pub const WARM_P95_GATE_MS: u64 = 10_000;

/// One artifact's admission evidence: exact digest, exact engine, measured targets,
/// the contract it was measured under, and the figures that met the gates.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Qualification {
    /// Human name of the artifact, as the record calls it.
    pub artifact: &'static str,
    /// Exact SHA-256 of the GGUF file, lowercase hex. The only key admission uses.
    pub sha256: &'static str,
    /// The llama.cpp release tag the figures were measured on. Must equal
    /// [`ENGINE_TAG`]; a mismatch is a stale record, and a test refuses it.
    pub engine_tag: &'static str,
    /// Device classes the record covers. A digest is qualified only on a target it
    /// was measured on; Metal numbers say nothing about a CPU build.
    pub targets: &'static [Target],
    /// Task contract version the cases were frozen under.
    pub contract: &'static str,
    /// SHA-256 of the frozen case set, so the record names exactly what was asked.
    pub case_set_sha256: &'static str,
    /// Repository path of the evidence record, relative to the repository root.
    pub record: &'static str,
    /// Host envelope the figures were taken on, verbatim from the record.
    pub host: &'static str,
    /// Accuracy on decidable cases.
    pub accuracy: f64,
    /// Materially wrong accepted "pass" verdicts.
    pub false_passes: u32,
    /// Warm p95 latency on short tasks, milliseconds.
    pub warm_p95_ms: u64,
    /// The date the decision was recorded, `YYYY-MM-DD`.
    pub decided: &'static str,
    /// SHA-256 of the bench's system turn for the run ([`BenchContract::system_sha256`]).
    pub system_sha256: &'static str,
    /// Output cap of the reference run, in tokens.
    pub output_cap: usize,
    /// Framed-prompt token limit of the run.
    pub input_limit: usize,
    /// The engine options that change output, as the run used them.
    pub engine: EngineContract,
    /// [`BenchContract::fingerprint`] of the above, as recorded at measurement time. The
    /// record qualifies only a model this build starts with options that reproduce it.
    pub bench_contract: &'static str,
}

impl Qualification {
    /// Whether the record's figures clear every gate.
    #[must_use]
    pub fn meets_gates(&self) -> bool {
        self.accuracy >= ACCURACY_GATE
            && self.false_passes == FALSE_PASS_GATE
            && self.warm_p95_ms < WARM_P95_GATE_MS
    }

    /// Whether the record was measured on `target`.
    #[must_use]
    pub fn covers(&self, target: Target) -> bool {
        self.targets.contains(&target)
    }

    /// What the bench asked for this record.
    #[must_use]
    pub fn bench(&self) -> BenchContract<'static> {
        BenchContract {
            contract: self.contract,
            case_set_sha256: self.case_set_sha256,
            system_sha256: self.system_sha256,
            output_cap: self.output_cap,
            input_limit: self.input_limit,
        }
    }
}

/// Every artifact that may serve a job, on the targets it was measured on.
pub const QUALIFIED: &[Qualification] = &[Qualification {
    artifact: "gpt-oss-20b-MXFP4",
    sha256: "27cd6c432c7672cb812a92f611cf3ba7bbc35928262bb1e1253ff4ee6ae35901",
    engine_tag: "b10938",
    targets: &[Target::MacosArm64],
    contract: "answer-contract-v2",
    case_set_sha256: "779638853b93eee0ff338ea00f4334cb86c625862577c73f27be8c853c1272f2",
    record: "docs/benchmarks/2026-09-15-answer-contract-v2",
    host: "Apple M4 Max, 64 GiB, ambient load (not a 32 GB measurement)",
    accuracy: 0.980,
    false_passes: 0,
    warm_p95_ms: 593,
    decided: "2026-09-15",
    // What run 3 of the record was measured with. `record.json` states the contract
    // version, the case-set digest, the 160-token cap and the supervisor settings
    // (reasoning budget 0, thinking off, no prompt cache, seed 7, 8,192-token context,
    // default Metal offload). The bench and the supervisor at the run's revision
    // (620aa8c) establish the rest: the system turn, the 640-token input limit,
    // `-np 1`, `--jinja` and the 16-token output floor. A unit test rebuilds the
    // fingerprint from `record.json`, and the bench has a test that its code today still
    // has it.
    system_sha256: "3d832edb81cec408a5f06d97a2c140d260fe378dbaf0f21a360ed42edaf7ecaf",
    output_cap: 160,
    input_limit: 640,
    engine: EngineContract {
        context_tokens: 8192,
        reasoning_budget: 0,
        enable_thinking: false,
        gpu_layers: None,
        parallel_slots: 1,
        chat_template: "gguf-jinja",
        cache_prompt: false,
        seed: 7,
        min_output_tokens: 16,
    },
    bench_contract: "70f872a3a84ba1ba8a82a7fb9c6a1f97435290a5ce0947e39d8e138020647a28",
}];

/// The qualification for `sha256` on `target`, from the compiled-in table.
#[must_use]
pub fn find(sha256: &str, target: Target) -> Option<&'static Qualification> {
    find_in(QUALIFIED, sha256, target)
}

/// [`find`] over an explicit table, so a registry built for a test can carry
/// its own records.
///
/// A record only counts when it names the digest, covers the target, was
/// measured on the pinned engine, and its figures clear the gates. The last
/// two are checked here, on the admission path, and not only by the unit
/// test over the compiled-in table: a record that stops clearing them stops
/// qualifying anything the moment the constants move.
#[must_use]
pub fn find_in(
    records: &'static [Qualification],
    sha256: &str,
    target: Target,
) -> Option<&'static Qualification> {
    records.iter().find(|record| {
        record.sha256 == sha256
            && record.covers(target)
            && record.engine_tag == ENGINE_TAG
            && record.meets_gates()
    })
}

/// Where a digest stands against the table and the engine options this build uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Standing {
    /// A record covers the digest on this target, and this build starts the model with
    /// the options the record was measured with.
    Qualified(&'static Qualification),
    /// A record covers the digest on this target, but this build's options do not
    /// reproduce its bench contract: needs re-measurement.
    ContractChanged {
        /// The record that would otherwise qualify.
        record: &'static Qualification,
        /// What differs, in words (see [`contract_issue`]).
        differences: String,
    },
    /// No record covers the digest on this target.
    Unqualified,
}

/// Where `sha256` stands on `target`: [`find_in`], then the bench-contract check.
///
/// `engine` is the set of output-affecting options this build starts that model with.
/// The record's bench contract is fingerprinted with them and compared with the
/// fingerprint recorded at measurement time.
#[must_use]
pub fn assess(
    records: &'static [Qualification],
    sha256: &str,
    target: Target,
    engine: &EngineContract,
) -> Standing {
    let Some(record) = find_in(records, sha256, target) else {
        return Standing::Unqualified;
    };
    let current = record.bench().fingerprint(engine);
    if current == record.bench_contract {
        return Standing::Qualified(record);
    }
    Standing::ContractChanged {
        record,
        differences: engine_differences(record, engine, &current),
    }
}

/// What differs between the options a record was measured with and `engine`, one
/// `name: measured X, now Y` per option. When no option differs the fingerprints
/// themselves are named: the record's bench contract is not the one its fields describe.
fn engine_differences(record: &Qualification, engine: &EngineContract, current: &str) -> String {
    let fields = |contract: &EngineContract| {
        serde_json::to_value(contract)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default()
    };
    let (measured, now) = (fields(&record.engine), fields(engine));
    let differing: Vec<String> = measured
        .iter()
        .filter_map(|(name, was)| {
            let is = now.get(name)?;
            (was != is).then(|| format!("{name}: measured {was}, now {is}"))
        })
        .collect();
    if differing.is_empty() {
        let short = |fingerprint: &str| fingerprint.chars().take(12).collect::<String>();
        format!(
            "bench contract: recorded {}, now {}",
            short(record.bench_contract),
            short(current)
        )
    } else {
        differing.join("; ")
    }
}

/// The sentence a [`Standing::ContractChanged`] entry carries: the record, what differs,
/// and what that means.
#[must_use]
pub fn contract_issue(record: &Qualification, differences: &str) -> String {
    format!(
        "its qualification record ({}, {}) was measured with other engine options than this \
         build starts the model with ({differences}). The capability-bench figures do not \
         describe this configuration, so it needs re-measurement before it serves a job",
        record.record, record.contract
    )
}

/// Whether the table's records are all measured on the engine this build pins.
/// [`find_in`] refuses a stale record one at a time; this is the whole-table
/// assertion the unit test makes so a stale record is a failed build, not a
/// silently unqualified artifact.
#[cfg(test)]
pub(crate) fn all_on_pinned_engine(records: &[Qualification]) -> bool {
    records.iter().all(|record| record.engine_tag == ENGINE_TAG)
}
