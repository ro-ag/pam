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

use crate::engine::{ENGINE_TAG, Target};

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
}];

/// The qualification for `sha256` on `target`, from the compiled-in table.
#[must_use]
pub fn find(sha256: &str, target: Target) -> Option<&'static Qualification> {
    find_in(QUALIFIED, sha256, target)
}

/// [`find`] over an explicit table, so a registry built for a test can carry
/// its own records.
#[must_use]
pub fn find_in(
    records: &'static [Qualification],
    sha256: &str,
    target: Target,
) -> Option<&'static Qualification> {
    records
        .iter()
        .find(|record| record.sha256 == sha256 && record.covers(target))
}

/// Whether the table's records are all measured on the engine this build pins.
#[must_use]
pub fn all_on_pinned_engine(records: &[Qualification]) -> bool {
    records.iter().all(|record| record.engine_tag == ENGINE_TAG)
}
