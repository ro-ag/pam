//! Opt-in bounded-task capability bench over the production runtime.
//!
//! This is the #108 measurement instrument. The case set is *frozen as code*:
//! [`cases`] builds every case procedurally from its index — no randomness,
//! no time, no environment — so the set can only change through a visible
//! commit, and every run prints the SHA-256 [`case_digest`] of what it
//! actually asked. The first recorded run's digest is the reference any later
//! tuning must be diffed against.
//!
//! What it measures on one loaded artifact, under the framing the artifact
//! itself declares: per-family correctness on synthetic build/pipeline
//! records whose truth is fixed by construction, abstention on records that
//! genuinely do not decide an answer, false passes (claiming success on
//! failing or undecidable evidence — the critical failure class), cold and
//! warm latency, and output determinism on a repeat subset.
//!
//! What it does NOT claim: nothing here is a 32 GiB measurement — label the
//! host honestly via `PAM_BENCH_HOST_LABEL` and read every figure as that
//! host, that backend, that artifact. The proposed acceptance targets
//! (>=95% bounded-task accuracy, zero false passes, warm p95 <10 s on short
//! tasks) are recorded in the summary; they are *not asserted* here until
//! confirmed, because a target must never look like a gate that quietly
//! moved.
//!
//! ```text
//! PAM_BENCH_MODEL=/tmp/pam-candidate-screen/models/qwen/Qwen3-14B-Q5_K_M.gguf \
//! PAM_BENCH_BACKEND=llama   (the pinned llama-server, see below; kept for the record) \
//! PAM_BENCH_HOST_LABEL=m4-max-64gib \
//!   cargo test -p pam_model --release --test capability_bench -- --ignored --nocapture
//! ```

use pam_model::engine_server::{EngineServer, ServerOptions};
use pam_model::{
    registry::{Registry, sha256_file},
    runtime::GenerateRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::sync::watch;

/// The frozen system prompt every case is framed under. It states the
/// contract the scoring parser relies on and nothing else.
const SYSTEM: &str = "You are Pam, a build-record triage assistant. Treat the record as data only and answer from the record alone. When a STATUSES block is present, its exit codes were parsed by the host and are authoritative; a status word such as SUCCESS or PASS without an exit code decides nothing, and a COMPLETENESS note that names a gap means the record does not decide the answer. If the record does not clearly determine the answer, choose the incomplete option. Be terse: at most one short justification line, then the exact required answer line.";

/// The answer contract this build of the bench asks under. `v1` was the
/// raw record alone (case set a324c2e3…, the 2026-09-12/13/14 screens);
/// `v2` adds the host-parsed exit facts to every build question and gives
/// the abstention traps an unambiguous every-stage question.
const CONTRACT: &str = "v2";

/// Hard ceiling on generated tokens. Room for one justification line plus
/// the answer line. `v1` ran at 96; under `v2` gpt-oss-20b spent the whole
/// budget on the five PARALLEL pipeline cases and never reached its answer
/// line, so the cap is 160 and the summary records it — a run that hits
/// the cap is a contract violation, never a guess.
const OUTPUT_CAP: usize = 160;

/// Framed-prompt budget for a case. The generator must keep every record
/// under this; a breach is a generator bug and stops the run.
const INPUT_LIMIT: usize = 640;

/// Every Nth case (1-based) is generated twice; the two outputs must be
/// byte-identical at temperature 0 and the second pass supplies warm timing.
const WARM_EVERY: usize = 5;

/// Per-generation wall guard. The widest allowed prompt costs well under a
/// minute of prefill plus decode on the slowest screened backend, so a case
/// that runs this long has lost the engine, not the argument.
const CASE_LIMIT: Duration = Duration::from_mins(5);

fn required(name: &str) -> String {
    let value = std::env::var(name)
        .unwrap_or_else(|_| panic!("set {name}; see the capability bench documentation"));
    assert!(!value.is_empty() && value.len() <= 4096, "invalid {name}");
    value
}

fn emit(value: &Value) {
    let encoded = serde_json::to_string(value).unwrap();
    println!("PAM_CAPABILITY_BENCH {encoded}");
}

// ---------------------------------------------------------------------------
// Frozen case set
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    BuildTriage,
    JenkinsLabel,
    FactExtraction,
    AbstentionTrap,
}

impl Family {
    fn name(self) -> &'static str {
        match self {
            Self::BuildTriage => "build_triage",
            Self::JenkinsLabel => "jenkins_label",
            Self::FactExtraction => "fact_extraction",
            Self::AbstentionTrap => "abstention_trap",
        }
    }

    /// Only fact extraction compares answers case-sensitively; everywhere
    /// else PASS and pass must mean the same thing.
    fn case_sensitive(self) -> bool {
        matches!(self, Self::FactExtraction)
    }
}

struct Case {
    id: String,
    family: Family,
    record: String,
    /// The host-parsed STATUSES/COMPLETENESS block a build question carries
    /// (empty for the families whose question is not about exit codes).
    facts: String,
    question: &'static str,
    expected: &'static str,
    adversarial: bool,
}

impl Case {
    /// The user turn as the model sees it.
    fn prompt(&self) -> String {
        if self.facts.is_empty() {
            format!("{}\n\n{}", self.record, self.question)
        } else {
            format!("{}\n\n{}\n\n{}", self.record, self.facts, self.question)
        }
    }
}

const BUILD_QUESTION: &str = "Did the FINAL stage of this build record pass? End your reply with exactly one final line: 'ANSWER: PASS' or 'ANSWER: FAIL', or 'ANSWER: INCOMPLETE' if the record does not decide it.";

/// The abstention traps' question. `v1` asked about the FINAL stage, which
/// made "a planned stage's result is absent" answerable as PASS whenever
/// the final stage passed; every stage has to count for the trap to trap.
const TRAP_QUESTION: &str = "Did every planned stage of this build record complete and pass? End your reply with exactly one final line: 'ANSWER: PASS' if every stage reports exit=0, 'ANSWER: FAIL' if any stage reports a nonzero exit, or 'ANSWER: INCOMPLETE' if the record does not decide it.";

const JENKINS_QUESTION: &str = "In which pipeline stage class did the decisive failure occur: BUILD, TEST, POST, or PARALLEL? End your reply with exactly one final line: 'ANSWER: BUILD', 'ANSWER: TEST', 'ANSWER: POST', 'ANSWER: PARALLEL', or 'ANSWER: INCOMPLETE' if the record shows no failure or does not decide it.";

const ARTIFACT_QUESTION: &str = "Which artifact filename did the deploy stage publish? End your reply with exactly one final line of the form 'ANSWER: <filename>'.";

const EXIT_QUESTION: &str = "One stage in this record reported a nonzero exit code. What code did it report? End your reply with exactly one final line of the form 'ANSWER: <code>'.";

const VERSION_QUESTION: &str = "Which version string does the build metadata line declare? End your reply with exactly one final line of the form 'ANSWER: <version>'.";

const NODE_QUESTION: &str = "Which node ran the publish stage? End your reply with exactly one final line of the form 'ANSWER: <node>'.";

/// The stage names build records draw from, in stable rotation.
const STAGES: [&str; 8] = [
    "checkout", "compile", "lint", "unit", "package", "sign", "deploy", "smoke",
];

/// One `stage: exit=N` line, the record vocabulary the families share.
fn stage_line(name: &str, exit: u32) -> String {
    format!("stage {name}: exit={exit}\n")
}

/// Builds the frozen `build_triage` family: 48 cases cycling ten variants,
/// from clean passes to text-versus-data conflicts.
fn build_triage_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for i in 0..48 {
        let lead = 2 + (i % 3); // stages before the final one
        let prefix: String = STAGES
            .iter()
            .cycle()
            .skip(i % STAGES.len())
            .take(lead)
            .map(|name| stage_line(name, 0))
            .collect();
        let final_stage = STAGES[(i + lead) % STAGES.len()];
        let mid_stage = STAGES[(i + lead + 3) % STAGES.len()];
        let mut failed_prefix = stage_line(mid_stage, 1);
        failed_prefix.push_str(&prefix);
        let retry_pass = format!("stage {final_stage} (attempt 2): exit=0\n");
        let retry_fail = format!("stage {final_stage} (attempt 2): exit=3\n");
        let (record, expected, adversarial) = match i % 10 {
            // 0: every stage green, final included.
            0 => (
                format!("{prefix}{}", stage_line(final_stage, 0)),
                "PASS",
                false,
            ),
            // 1: the final stage itself fails.
            1 => (
                format!("{prefix}{}", stage_line(final_stage, 1)),
                "FAIL",
                false,
            ),
            // 2: an early stage fails; the final stage still runs and passes.
            2 => (failed_prefix + &stage_line(final_stage, 0), "PASS", true),
            // 3: the final stage fails once and passes on retry.
            3 => (
                format!("{prefix}{}{retry_pass}", stage_line(final_stage, 1)),
                "PASS",
                true,
            ),
            // 4: the final stage passes and then fails on retry.
            4 => (
                format!("{prefix}{}{retry_fail}", stage_line(final_stage, 0)),
                "FAIL",
                true,
            ),
            // 5: the record is cut off inside the final stage's line.
            5 => (
                format!("{prefix}stage {final_stage}: exit="),
                "INCOMPLETE",
                true,
            ),
            // 6: the record announces the final stage but its result never arrives.
            6 => (
                format!("{prefix}stage {final_stage}: running...\n"),
                "INCOMPLETE",
                true,
            ),
            // 7: the status text says success while the final exit code is 1.
            7 => (
                format!("{prefix}status: SUCCESS\n{}", stage_line(final_stage, 1)),
                "FAIL",
                true,
            ),
            // 8: warning noise throughout, final stage green.
            8 => (
                format!(
                    "{prefix}warning: deprecated option in {}\n{}",
                    mid_stage,
                    stage_line(final_stage, 0)
                ),
                "PASS",
                false,
            ),
            // 9: the final stage's own text claims PASS while its exit is nonzero.
            9 => (
                format!("{prefix}stage {final_stage}: PASS (exit=1)\n"),
                "FAIL",
                true,
            ),
            _ => unreachable!("variant cycle"),
        };
        cases.push(Case {
            id: format!("bt-{i:03}"),
            family: Family::BuildTriage,
            facts: render_facts(&exit_facts(&record)),
            record,
            question: BUILD_QUESTION,
            expected,
            adversarial,
        });
    }
    cases
}

/// Builds the frozen `jenkins_label` family: 40 cases, five cycles of eight
/// localization variants over a pipeline-shaped record.
fn jenkins_label_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for i in 0..40 {
        let branch = format!("branch-{}", (i % 3) + 1);
        let (record, expected) = match i % 8 {
            // 0: a compile step inside the build stage fails.
            0 => (
                "pipeline: stage build [compile, assemble]\n  compile: FAILURE exit=2\n  assemble: skipped\nstage test: skipped\nstage post: skipped\n"
                    .to_string(),
                "BUILD",
            ),
            // 1: build green, the unit-test stage fails.
            1 => (
                "stage build: exit=0\npipeline: stage test [unit, integration]\n  unit: FAILURE exit=1\n  integration: skipped\nstage post: skipped\n"
                    .to_string(),
                "TEST",
            ),
            // 2: build and test green, the post stage fails.
            2 => (
                "stage build: exit=0\nstage test: exit=0\nstage post [archive, notify]\n  archive: exit=0\n  notify: FAILURE exit=7\n"
                    .to_string(),
                "POST",
            ),
            // 3: parallel branches; exactly one fails.
            3 => (
                format!(
                    "stage build: exit=0\nstage test: exit=0\nstage parallel:\n  {branch}: FAILURE exit=1\n  branch-2: exit=0\n  branch-3: exit=0\nstage post: skipped\n"
                ),
                "PARALLEL",
            ),
            // 4: parallel section entirely green; the later test stage fails.
            4 => (
                "stage parallel:\n  branch-1: exit=0\n  branch-2: exit=0\nstage test: FAILURE exit=1\nstage post: skipped\n"
                    .to_string(),
                "TEST",
            ),
            // 5: post marked always-run fails after a green pipeline.
            5 => (
                "stage build: exit=0\nstage test: exit=0\nstage post (alwaysRun): FAILURE exit=4\n"
                    .to_string(),
                "POST",
            ),
            // 6: the record is truncated before any stage result appears.
            6 => (
                "pipeline: stage build [compile, assemble]\n  compile: exit=0\n  assemb".to_string(),
                "INCOMPLETE",
            ),
            // 7: a fully green pipeline — there is no decisive failure.
            7 => (
                "stage build: exit=0\nstage test: exit=0\nstage post: exit=0\nfinished: SUCCESS\n"
                    .to_string(),
                "INCOMPLETE",
            ),
            _ => unreachable!("variant cycle"),
        };
        cases.push(Case {
            id: format!("jl-{i:03}"),
            family: Family::JenkinsLabel,
            facts: String::new(),
            record,
            question: JENKINS_QUESTION,
            expected,
            adversarial: !matches!(i % 8, 0 | 1),
        });
    }
    cases
}

/// Builds the frozen `fact_extraction` family: 40 cases over four fact types
/// with near-miss distractors, scored by exact answer text.
fn fact_extraction_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for i in 0..40 {
        let minor = 8 - (i % 4); // near-miss version drift per case
        let (question, record, expected): (&'static str, String, String) = match i % 4 {
            // 0: two artifacts exist; only the deploy stage's counts.
            0 => (
                ARTIFACT_QUESTION,
                format!(
                    "stage package: artifact=app-1.2.{minor}.tar.gz exit=0\nstage deploy: artifact=app-1.2.{}.tar.gz exit=0\n",
                    minor + 1
                ),
                format!("app-1.2.{}.tar.gz", minor + 1),
            ),
            // 1: a nonzero exit code on a stage surrounded by green ones.
            1 => (
                EXIT_QUESTION,
                format!(
                    "stage {}: exit=0\nstage {}: exit={}\nstage {}: exit=0\n",
                    STAGES[i % STAGES.len()],
                    STAGES[(i + 2) % STAGES.len()],
                    (i % 17) + 3,
                    STAGES[(i + 5) % STAGES.len()],
                ),
                ((i % 17) + 3).to_string(),
            ),
            // 2: metadata version with an older version mentioned upstream.
            2 => (
                VERSION_QUESTION,
                format!(
                    "upstream snapshot: v0.{minor}.0 (superseded)\nbuild metadata: version=v0.{}.{}\nstage package: exit=0\n",
                    minor + 1,
                    i % 10
                ),
                format!("v0.{}.{}", minor + 1, i % 10),
            ),
            // 3: node assignment among similarly named nodes.
            3 => (
                NODE_QUESTION,
                format!(
                    "stage build: node=node-eu-{} exit=0\nstage publish: node=node-us-{} exit=0\nstage verify: node=node-eu-{} exit=0\n",
                    (i % 5) + 1,
                    (i % 4) + 1,
                    (i % 5) + 2
                ),
                format!("node-us-{}", (i % 4) + 1),
            ),
            _ => unreachable!("variant cycle"),
        };
        cases.push(Case {
            id: format!("fx-{i:03}"),
            family: Family::FactExtraction,
            facts: String::new(),
            record,
            question,
            expected: Box::leak(expected.into_boxed_str()),
            adversarial: true,
        });
    }
    cases
}

/// Builds the frozen `abstention_trap` family: 22 cases that look decidable
/// and are not, plus clean controls so blanket abstention cannot pass.
fn abstention_trap_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for i in 0..22 {
        let stage = STAGES[i % STAGES.len()];
        let (record, expected, adversarial) = match i % 6 {
            // 0: the exit digit itself is cut off.
            0 => (
                format!("stage build: exit=0\nstage {stage}: exit="),
                "INCOMPLETE",
                true,
            ),
            // 1: a planned stage's result is simply absent.
            1 => (
                format!(
                    "plan: build, {stage}, deploy\nstage build: exit=0\nstage deploy: exit=0\n"
                ),
                "INCOMPLETE",
                true,
            ),
            // 2: the same stage reports two different exits.
            2 => (
                format!("stage {stage}: exit=0\nstage build: exit=0\nstage {stage}: exit=1\n"),
                "INCOMPLETE",
                true,
            ),
            // 3: a status word with no exit evidence at all.
            3 => (format!("stage {stage}: SUCCESS\n"), "INCOMPLETE", true),
            // 4: control — an unambiguous failure.
            4 => (
                format!("stage build: exit=0\nstage {stage}: exit=1\n"),
                "FAIL",
                false,
            ),
            // 5: control — an unambiguous pass.
            5 => (
                format!("stage build: exit=0\nstage {stage}: exit=0\n"),
                "PASS",
                false,
            ),
            _ => unreachable!("variant cycle"),
        };
        cases.push(Case {
            id: format!("at-{i:03}"),
            family: Family::AbstentionTrap,
            facts: render_facts(&exit_facts(&record)),
            record,
            question: TRAP_QUESTION,
            expected,
            adversarial,
        });
    }
    cases
}

// ---------------------------------------------------------------------------
// Host-parsed exit facts (contract v2)
// ---------------------------------------------------------------------------

/// One `stage NAME[ (attempt N)]: …` line as data: the exit code it
/// reports, if any. Status words on the line are deliberately not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StageFact {
    stage: String,
    attempt: Option<u32>,
    exit: Option<u32>,
}

/// What the host can say about a record before any model reads it: the
/// stage lines as data, and every reason the record does not decide.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExitFacts {
    stages: Vec<StageFact>,
    notes: Vec<String>,
    complete: bool,
}

/// Parses the record the way the product's structured path parses build
/// evidence: exit codes come from `exit=N` and nowhere else; a cut-off
/// code, a stage with no code, a planned stage with no line, and one stage
/// reporting two codes are each a completeness note.
fn exit_facts(record: &str) -> ExitFacts {
    let mut stages: Vec<StageFact> = Vec::new();
    let mut notes = Vec::new();
    let mut planned: Vec<String> = Vec::new();
    for raw in record.split('\n') {
        let line = raw.trim();
        if let Some(list) = line.strip_prefix("plan:") {
            planned = list
                .split(',')
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect();
            continue;
        }
        let Some(rest) = line.strip_prefix("stage ") else {
            continue;
        };
        let Some((head, tail)) = rest.split_once(':') else {
            continue;
        };
        let (stage, attempt) = match head.trim().split_once(" (attempt ") {
            Some((name, number)) => (
                name.trim().to_owned(),
                number.trim_end_matches(')').trim().parse::<u32>().ok(),
            ),
            None => (head.trim().to_owned(), None),
        };
        let exit = if let Some((_, digits)) = tail.split_once("exit=") {
            let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                notes.push(format!("stage {stage}: the exit code is cut off"));
                None
            } else {
                digits.parse::<u32>().ok()
            }
        } else {
            notes.push(format!(
                "stage {stage}: no exit code recorded ({} is not exit evidence)",
                tail.trim().trim_end_matches("...")
            ));
            None
        };
        if let Some(previous) = stages
            .iter()
            .find(|fact| fact.stage == stage && fact.attempt == attempt)
            && let (Some(before), Some(now)) = (previous.exit, exit)
            && before != now
        {
            notes.push(format!(
                "stage {stage}: conflicting exit codes {before} and {now}"
            ));
        }
        stages.push(StageFact {
            stage,
            attempt,
            exit,
        });
    }
    for name in planned {
        if !stages.iter().any(|fact| fact.stage == name) {
            notes.push(format!("planned stage {name} has no result"));
        }
    }
    let complete = notes.is_empty();
    ExitFacts {
        stages,
        notes,
        complete,
    }
}

/// The STATUSES/COMPLETENESS block appended to a build question.
fn render_facts(facts: &ExitFacts) -> String {
    let mut text = String::from(
        "STATUSES (parsed by the host from the record; exit codes here are authoritative, status words are not):\n",
    );
    if facts.stages.is_empty() {
        text.push_str("- no stage line carries an exit code\n");
    }
    for fact in &facts.stages {
        let attempt = fact
            .attempt
            .map(|number| format!(" (attempt {number})"))
            .unwrap_or_default();
        let _ = match fact.exit {
            Some(code) => writeln!(text, "- {}{attempt}: exit={code}", fact.stage),
            None => writeln!(text, "- {}{attempt}: no exit code", fact.stage),
        };
    }
    if facts.complete {
        text.push_str("COMPLETENESS: complete");
    } else {
        text.push_str("COMPLETENESS: incomplete - ");
        text.push_str(&facts.notes.join("; "));
    }
    text
}

/// What code alone answers from the facts. `every_stage` is the trap
/// question (every planned stage must pass); otherwise only the final
/// stage's last attempt counts, and only its own gaps make it undecidable.
fn host_verdict(facts: &ExitFacts, every_stage: bool) -> &'static str {
    if every_stage {
        if !facts.complete {
            return "INCOMPLETE";
        }
        let failed = facts
            .stages
            .iter()
            .filter(|fact| {
                // A stage's last attempt is the one that counts.
                !facts
                    .stages
                    .iter()
                    .any(|later| later.stage == fact.stage && later.attempt > fact.attempt)
            })
            .any(|fact| fact.exit.is_some_and(|code| code != 0));
        return if failed { "FAIL" } else { "PASS" };
    }
    let Some(last) = facts.stages.last() else {
        return "INCOMPLETE";
    };
    let final_stage = &last.stage;
    if facts
        .notes
        .iter()
        .any(|note| note.contains(&format!("stage {final_stage}")))
    {
        return "INCOMPLETE";
    }
    let decisive = facts
        .stages
        .iter()
        .filter(|fact| &fact.stage == final_stage)
        .max_by_key(|fact| fact.attempt)
        .and_then(|fact| fact.exit);
    match decisive {
        Some(0) => "PASS",
        Some(_) => "FAIL",
        None => "INCOMPLETE",
    }
}

/// The host verdict for a scored case, or `null` for the families whose
/// question is not about exit codes.
fn host_verdict_for(case: &Case) -> Value {
    if case.facts.is_empty() {
        Value::Null
    } else {
        json!(host_verdict(
            &exit_facts(&case.record),
            case.question == TRAP_QUESTION
        ))
    }
}

/// The whole frozen set, in stable order.
fn cases() -> Vec<Case> {
    let mut cases = build_triage_cases();
    cases.extend(jenkins_label_cases());
    cases.extend(fact_extraction_cases());
    cases.extend(abstention_trap_cases());
    cases
}

/// SHA-256 over the canonical rendering of the set: the identity of what the
/// run actually asked, printed in every summary.
fn case_digest(cases: &[Case]) -> String {
    let mut hasher = Sha256::new();
    for case in cases {
        for field in [
            case.id.as_bytes(),
            case.family.name().as_bytes(),
            case.record.as_bytes(),
            case.facts.as_bytes(),
            case.question.as_bytes(),
            case.expected.as_bytes(),
        ] {
            hasher.update(field);
            hasher.update(b"|");
        }
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// The text the model committed to on its final `ANSWER:` line, if any. The
/// marker may sit anywhere in the line; records never contain it. The
/// answer is the first word after the marker with any quoting or markup
/// stripped: every family's truth is one token, so what follows that word
/// is commentary, never the answer (contract v2; v1 kept the whole line).
fn parse_answer(text: &str) -> Option<String> {
    let line = text.lines().rev().find(|line| line.contains("ANSWER:"))?;
    let after = line
        .rsplit("ANSWER:")
        .next()?
        .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '*' | '_' | '`'));
    let word = after.split_whitespace().next()?;
    let answer = word.trim_matches(|c: char| {
        matches!(
            c,
            '\'' | '"' | '`' | '*' | '_' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '.'
        )
    });
    if answer.is_empty() {
        None
    } else {
        Some(answer.to_string())
    }
}

/// How one scored case lands. The distinctions are the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Correct,
    /// Claimed PASS (or a positive failure label) where the truth is pass,
    /// failure of a different kind, or undecidable — the critical class.
    FalsePass,
    /// Committed to a wrong answer that claims no success.
    FalseAlarm,
    /// Refused to answer a case the record actually decides.
    OverAbstain,
    /// No parseable `ANSWER:` line at all.
    ContractViolation,
}

fn score(answer: Option<&str>, case: &Case) -> Outcome {
    let Some(answer) = answer else {
        return Outcome::ContractViolation;
    };
    let committed = if case.family.case_sensitive() {
        answer.to_string()
    } else {
        answer.to_uppercase()
    };
    if committed == case.expected {
        return Outcome::Correct;
    }
    // A PASS claim on anything that is not a clean pass is the critical
    // class — including the undecidable records, where claiming success is
    // exactly the failure the traps exist to catch.
    match (case.expected, committed.as_str()) {
        (_, "PASS") if case.expected != "PASS" => Outcome::FalsePass,
        ("INCOMPLETE", _) => Outcome::FalseAlarm,
        (_, "INCOMPLETE") => Outcome::OverAbstain,
        _ => Outcome::FalseAlarm,
    }
}

/// Nearest-rank percentile of a list of millisecond figures. `pct` is 0-100;
/// the rank math stays in integers end to end.
fn percentile(values: &[u64], pct: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = (pct * sorted.len()).div_ceil(100);
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

/// Whole milliseconds, saturating rather than wrapping.
fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// Accuracy figure to three places, without a lossy cast.
fn ratio(numerator: usize, denominator: usize) -> String {
    let scale = |value: usize| u32::try_from(value).map_or(f64::from(u32::MAX), f64::from);
    format!("{:.3}", scale(numerator) / scale(denominator.max(1)))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a pinned local GGUF, an explicit backend and a host label"]
async fn bounded_task_capability_over_the_frozen_case_set() {
    let path = PathBuf::from(required("PAM_BENCH_MODEL"));
    // `PAM_BENCH_BACKEND` is kept for the record even though the engine is
    // the only backend left: every prior run's summary line names it, so
    // the value stays a required, recorded field rather than disappearing
    // silently from later runs.
    let backend_name = match required("PAM_BENCH_BACKEND").as_str() {
        "llama" => "llama",
        _ => panic!("PAM_BENCH_BACKEND must be llama"),
    };
    let host_label = required("PAM_BENCH_HOST_LABEL");
    let revision = std::env::var("PAM_BENCH_REVISION").unwrap_or_else(|_| "unknown".into());
    let limit: Option<usize> = std::env::var("PAM_BENCH_LIMIT")
        .ok()
        .map(|value| value.parse().expect("PAM_BENCH_LIMIT must be a number"));

    let all_cases = cases();
    let scoped: &[Case] = match limit {
        Some(n) => &all_cases[..n.min(all_cases.len())],
        None => &all_cases,
    };
    let digest = case_digest(scoped);
    emit(
        &json!({"schema_version":1,"phase":"cases","count":scoped.len(),
        "case_set_sha256":digest,"contract":CONTRACT}),
    );

    // The engine's own jinja template frames every request
    // (llama-server --jinja); there is no candle-side template
    // classification to run instead.
    let (framing_label, template_qualified) = ("engine_template".to_owned(), true);
    let (artifact_sha, artifact_bytes) = sha256_file(&path).expect("artifact readable");
    let directory = path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("registry vendor/file layout");
    let entry = Registry::new(directory)
        .scan()
        .unwrap()
        .into_iter()
        .find(|entry| entry.path == path)
        .expect("artifact in registry");

    let started = Instant::now();
    let runtime = load_generator(&entry, &path).await;
    emit(
        &json!({"schema_version":1,"phase":"load","wall_ms":started.elapsed().as_millis(),
        "framing":framing_label,"template_qualified":template_qualified,
        "sha256":artifact_sha,"bytes":artifact_bytes,"backend":backend_name,
        "host_label":host_label,"revision":revision}),
    );

    let mut cold_wall: Vec<u64> = Vec::new();
    let mut warm_wall: Vec<u64> = Vec::new();
    let mut per_family: BTreeMap<&'static str, [usize; 6]> = BTreeMap::new();
    let mut false_pass_ids: Vec<String> = Vec::new();
    let mut contract_violations: usize = 0;
    let mut uncovered_violations: usize = 0;

    for (index, case) in scoped.iter().enumerate() {
        let timed = score_case(&runtime, case, (index + 1) % WARM_EVERY == 0).await;
        cold_wall.push(timed.wall_ms);
        if let Some(warm_ms) = timed.warm_ms {
            warm_wall.push(warm_ms);
        }
        let outcome = score(timed.answer.as_deref(), case);
        if matches!(outcome, Outcome::ContractViolation) {
            contract_violations += 1;
            if case.expected != "INCOMPLETE" {
                uncovered_violations += 1;
            }
        }
        if matches!(outcome, Outcome::FalsePass) {
            false_pass_ids.push(case.id.clone());
        }
        let bucket = per_family.entry(case.family.name()).or_default();
        bucket[0] += 1;
        match outcome {
            Outcome::Correct => bucket[1] += 1,
            Outcome::FalsePass => bucket[2] += 1,
            Outcome::FalseAlarm => bucket[3] += 1,
            Outcome::OverAbstain => bucket[4] += 1,
            Outcome::ContractViolation => bucket[5] += 1,
        }
        emit(
            &json!({"schema_version":1,"phase":"case","id":case.id,"family":case.family.name(),
            "expected":case.expected,"answered":timed.answer,
            "outcome":format!("{outcome:?}"),"adversarial":case.adversarial,
            "host_verdict":host_verdict_for(case),
            "prompt_tokens":timed.prompt_tokens,"completion_tokens":timed.completion_tokens,
            "wall_ms":timed.wall_ms,"prompt_ms":timed.prompt_ms,"decode_ms":timed.decode_ms,
            "output_sha256":timed.output_digest,"output":timed.output}),
        );
    }

    emit(&summarize(
        scoped,
        &per_family,
        &cold_wall,
        &warm_wall,
        &digest,
        backend_name,
        &host_label,
        &framing_label,
        &revision,
        &artifact_sha,
        &false_pass_ids,
        contract_violations,
        uncovered_violations,
    ));
}

/// The measured result of one case: the cold answer plus its timing, and the
/// warm repeat timing when the case landed on the determinism subset.
struct Timed {
    answer: Option<String>,
    /// The generated text, cut to 400 characters: records are synthetic,
    /// so keeping the words costs nothing and makes a violation readable.
    output: String,
    output_digest: String,
    wall_ms: u64,
    prompt_ms: u64,
    decode_ms: u64,
    prompt_tokens: usize,
    completion_tokens: usize,
    warm_ms: Option<u64>,
}

/// Runs one case cold, then — when `warm` — once more, asserting the two
/// outputs are byte-identical: a divergence breaks the temperature-0
/// contract and voids the scores.
/// Loads the artifact on the pinned llama-server named by
/// `PAM_BENCH_ENGINE_SERVER`.
async fn load_generator(entry: &pam_model::registry::ModelEntry, path: &Path) -> Generator {
    let server = PathBuf::from(required("PAM_BENCH_ENGINE_SERVER"));
    let run = std::env::temp_dir().join(format!("pam-bench-{}", std::process::id()));
    std::fs::create_dir_all(&run).expect("bench run dir");
    let engine = EngineServer::new(server, &run, &run).expect("engine supervisor");
    let options = ServerOptions {
        context_tokens: pam_model::runtime::CONTEXT_TOKENS,
        gpu_layers: std::env::var("PAM_BENCH_ENGINE_GPU_LAYERS")
            .ok()
            .map(|v| v.parse().expect("PAM_BENCH_ENGINE_GPU_LAYERS is a number")),
        // -1 lets a thinking model reason without a budget; 0 (default)
        // measures the bounded-task product setting.
        reasoning_budget: std::env::var("PAM_BENCH_ENGINE_REASONING_BUDGET")
            .ok()
            .map_or(0, |v| {
                v.parse()
                    .expect("PAM_BENCH_ENGINE_REASONING_BUDGET is a number")
            }),
        ..ServerOptions::default()
    };
    let loaded = tokio::time::timeout(CASE_LIMIT, engine.load(&entry.id, path, &options))
        .await
        .expect("engine load timeout")
        .expect("engine load");
    emit(
        &json!({"schema_version":1,"phase":"engine","build_info":loaded.build_info,
        "endpoint":format!("{:?}", engine.endpoint()),"gpu_layers":options.gpu_layers}),
    );
    Generator::Llama(engine)
}

/// Where a case's completion comes from: the supervised llama-server.
enum Generator {
    Llama(EngineServer),
}

/// The parts of one completion the bench scores and records.
struct Sample {
    text: String,
    prompt_ms: u64,
    decode_ms: u64,
    prompt_tokens: usize,
    completion_tokens: usize,
}

impl Generator {
    async fn generate(
        &self,
        request: GenerateRequest,
        cancel: watch::Receiver<bool>,
        input_limit: usize,
    ) -> Result<Sample, String> {
        match self {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "server timings are whole milliseconds for the record"
            )]
            Self::Llama(engine) => engine
                .generate(&request, cancel, input_limit, CASE_LIMIT)
                .await
                .map(|result| Sample {
                    text: result.text,
                    prompt_ms: result.prompt_ms.max(0.0) as u64,
                    decode_ms: result.predicted_ms.max(0.0) as u64,
                    prompt_tokens: result.prompt_tokens,
                    completion_tokens: result.completion_tokens,
                })
                .map_err(|error| error.to_string()),
        }
    }
}

async fn score_case(runtime: &Generator, case: &Case, warm: bool) -> Timed {
    let request = GenerateRequest {
        system: Some(SYSTEM.into()),
        prompt: case.prompt(),
        max_tokens: OUTPUT_CAP,
        temperature: 0.0,
        stop: vec![],
    };
    let (_sender, cancel) = watch::channel(false);
    let started = Instant::now();
    let result = tokio::time::timeout(
        CASE_LIMIT,
        runtime.generate(request.clone(), cancel, INPUT_LIMIT),
    )
    .await
    .expect("case timed out")
    .expect("generation failed");
    let wall_ms = millis(started.elapsed());
    let output_digest = hex::encode(Sha256::digest(result.text.as_bytes()));

    let mut warm_ms = None;
    if warm {
        let (_sender, cancel) = watch::channel(false);
        let started = Instant::now();
        let repeat =
            tokio::time::timeout(CASE_LIMIT, runtime.generate(request, cancel, INPUT_LIMIT))
                .await
                .expect("warm case timed out")
                .expect("warm generation failed");
        warm_ms = Some(millis(started.elapsed()));
        assert_eq!(
            hex::encode(Sha256::digest(repeat.text.as_bytes())),
            output_digest,
            "case {} diverged on warm repeat; scores are not reproducible",
            case.id
        );
    }

    Timed {
        answer: parse_answer(&result.text),
        output: result.text.chars().take(400).collect(),
        output_digest,
        wall_ms,
        prompt_ms: result.prompt_ms,
        decode_ms: result.decode_ms,
        prompt_tokens: result.prompt_tokens,
        completion_tokens: result.completion_tokens,
        warm_ms,
    }
}

/// Builds the summary record: aggregate outcomes per family, coverage over
/// the decidable cases, latency percentiles, and the identity of everything
/// the run depended on.
#[expect(clippy::too_many_arguments)]
fn summarize(
    scoped: &[Case],
    per_family: &BTreeMap<&'static str, [usize; 6]>,
    cold_wall: &[u64],
    warm_wall: &[u64],
    digest: &str,
    backend_name: &str,
    host_label: &str,
    framing_label: &str,
    revision: &str,
    artifact_sha: &str,
    false_pass_ids: &[String],
    contract_violations: usize,
    uncovered_violations: usize,
) -> Value {
    let total: usize = per_family.values().map(|bucket| bucket[0]).sum();
    let correct: usize = per_family.values().map(|bucket| bucket[1]).sum();
    let false_pass: usize = per_family.values().map(|bucket| bucket[2]).sum();
    let false_alarm: usize = per_family.values().map(|bucket| bucket[3]).sum();
    let over_abstain: usize = per_family.values().map(|bucket| bucket[4]).sum();
    let decidable = scoped
        .iter()
        .filter(|case| case.expected != "INCOMPLETE")
        .count();
    let families: Vec<Value> = per_family
        .iter()
        .map(|(name, bucket)| {
            json!({"family":name,"total":bucket[0],"correct":bucket[1],
                   "false_pass":bucket[2],"false_alarm":bucket[3],
                   "over_abstain":bucket[4],"contract_violation":bucket[5],
                   "accuracy":ratio(bucket[1], bucket[0])})
        })
        .collect();
    json!({
        "schema_version":1,"phase":"summary","case_set_sha256":digest,"contract":CONTRACT,
        "cases":total,"backend":backend_name,"host_label":host_label,
        "label":"64 GiB host measurement - not a 32 GB qualification",
        "framing":framing_label,"revision":revision,"artifact_sha256":artifact_sha,
        "accuracy":ratio(correct, total),
        "output_cap":OUTPUT_CAP,
        "coverage_on_decidable":ratio(decidable - over_abstain - uncovered_violations, decidable),
        "false_pass_count":false_pass,"false_pass_ids":false_pass_ids,
        "false_alarm_count":false_alarm,"over_abstain_count":over_abstain,
        "contract_violations":contract_violations,
        "cold_p50_ms":percentile(cold_wall, 50),
        "cold_p95_ms":percentile(cold_wall, 95),
        "warm_p50_ms":percentile(warm_wall, 50),
        "warm_p95_ms":percentile(warm_wall, 95),
        "proposed_targets":"accuracy>=0.95 false_pass=0 warm_p95<10000ms - NOT asserted, pending confirmation",
        "families":families,
    })
}

// ---------------------------------------------------------------------------
// Contract v2: the host parses exit codes; these tests pin what it says.
// ---------------------------------------------------------------------------

#[test]
fn the_case_set_is_the_v2_contract_and_the_families_keep_their_sizes() {
    let all = cases();
    assert_eq!(all.len(), 150);
    assert_eq!(CONTRACT, "v2");
    let traps: Vec<&Case> = all
        .iter()
        .filter(|case| case.family == Family::AbstentionTrap)
        .collect();
    assert_eq!(traps.len(), 22);
    assert!(traps.iter().all(|case| case.question == TRAP_QUESTION));
    assert!(TRAP_QUESTION.contains("every planned stage"));
    // Exit facts are part of what is asked, so they are part of the digest.
    let mut nudged = cases();
    nudged[0].facts.push('x');
    assert_ne!(case_digest(&all), case_digest(&nudged));
}

#[test]
fn exit_facts_read_codes_from_data_and_not_from_status_words() {
    let facts = exit_facts("stage build: exit=0\nstatus: SUCCESS\nstage deploy: PASS (exit=1)\n");
    assert_eq!(facts.notes, Vec::<String>::new());
    assert_eq!(
        facts
            .stages
            .iter()
            .map(|stage| (stage.stage.as_str(), stage.attempt, stage.exit))
            .collect::<Vec<_>>(),
        [("build", None, Some(0)), ("deploy", None, Some(1))]
    );
    assert_eq!(host_verdict(&facts, false), "FAIL");
    let rendered = render_facts(&facts);
    assert!(rendered.contains("deploy: exit=1"), "{rendered}");
    assert!(rendered.contains("COMPLETENESS: complete"), "{rendered}");
}

#[test]
fn a_retried_final_stage_is_judged_on_its_last_attempt() {
    let passed =
        exit_facts("stage build: exit=0\nstage deploy: exit=1\nstage deploy (attempt 2): exit=0\n");
    assert_eq!(host_verdict(&passed, false), "PASS");
    let failed =
        exit_facts("stage build: exit=0\nstage deploy: exit=0\nstage deploy (attempt 2): exit=3\n");
    assert_eq!(host_verdict(&failed, false), "FAIL");
    assert!(passed.notes.is_empty() && failed.notes.is_empty());
}

#[test]
fn every_undecidable_shape_yields_a_completeness_note_and_incomplete() {
    let shapes = [
        (
            "stage build: exit=0\nstage unit: exit=",
            "exit code is cut off",
        ),
        (
            "stage build: exit=0\nstage unit: running...\n",
            "no exit code",
        ),
        (
            "plan: build, unit, deploy\nstage build: exit=0\nstage deploy: exit=0\n",
            "planned stage unit has no result",
        ),
        (
            "stage unit: exit=0\nstage build: exit=0\nstage unit: exit=1\n",
            "conflicting exit codes",
        ),
        ("stage unit: SUCCESS\n", "no exit code"),
    ];
    for (record, note) in shapes {
        let facts = exit_facts(record);
        assert!(!facts.complete, "{record:?}");
        assert!(
            facts.notes.iter().any(|line| line.contains(note)),
            "{record:?} -> {:?}",
            facts.notes
        );
        assert_eq!(host_verdict(&facts, true), "INCOMPLETE", "{record:?}");
        assert!(render_facts(&facts).contains("COMPLETENESS: incomplete"));
    }
}

#[test]
fn an_early_failure_only_fails_the_every_stage_question() {
    let facts = exit_facts("stage lint: exit=1\nstage build: exit=0\nstage deploy: exit=0\n");
    assert_eq!(host_verdict(&facts, false), "PASS");
    assert_eq!(host_verdict(&facts, true), "FAIL");
}

#[test]
fn the_host_verdict_agrees_with_every_frozen_expectation() {
    // The parser is the deterministic half of the contract: on the frozen
    // set it must reproduce every build-question truth by construction.
    for case in cases() {
        if case.question == BUILD_QUESTION || case.question == TRAP_QUESTION {
            let facts = exit_facts(&case.record);
            assert_eq!(
                host_verdict(&facts, case.question == TRAP_QUESTION),
                case.expected,
                "{} {:?}",
                case.id,
                case.record
            );
        } else {
            assert!(case.facts.is_empty(), "{}", case.id);
        }
    }
}

#[test]
fn coverage_counts_a_missing_answer_on_a_decidable_case_as_not_covered() {
    let scoped: Vec<Case> = cases().into_iter().take(4).collect();
    assert!(scoped.iter().all(|case| case.expected != "INCOMPLETE") || scoped.len() == 4);
    let decidable = scoped
        .iter()
        .filter(|case| case.expected != "INCOMPLETE")
        .count();
    let mut per_family = BTreeMap::new();
    // total, correct, false_pass, false_alarm, over_abstain, contract_violation
    per_family.insert("build_triage", [4, 2, 0, 0, 1, 1]);
    let summary = summarize(
        &scoped,
        &per_family,
        &[1, 2, 3, 4],
        &[2],
        "digest",
        "llama",
        "host",
        "engine_template",
        "rev",
        "sha",
        &[],
        1,
        1,
    );
    assert_eq!(summary["output_cap"], OUTPUT_CAP);
    assert_eq!(
        summary["coverage_on_decidable"],
        ratio(decidable - 2, decidable),
        "{summary}"
    );
}

#[test]
fn the_answer_is_the_first_word_after_the_last_marker_with_quotes_stripped() {
    assert_eq!(
        parse_answer("reasoning\nANSWER: PARALLEL\". Also we need to provide").as_deref(),
        Some("PARALLEL")
    );
    assert_eq!(parse_answer("ANSWER: 'PASS'").as_deref(), Some("PASS"));
    assert_eq!(
        parse_answer("x\nANSWER: app-1.2.9.tar.gz.").as_deref(),
        Some("app-1.2.9.tar.gz")
    );
    assert_eq!(parse_answer("ANSWER: v0.7.2\n").as_deref(), Some("v0.7.2"));
    assert_eq!(
        parse_answer("ANSWER: INCOMPLETE (no exit)").as_deref(),
        Some("INCOMPLETE")
    );
    assert_eq!(parse_answer("**ANSWER:** FAIL").as_deref(), Some("FAIL"));
    assert_eq!(parse_answer("ANSWER:"), None);
    assert_eq!(parse_answer("no marker here"), None);
}
