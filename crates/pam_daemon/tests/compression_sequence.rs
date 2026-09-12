//! The #140 full-sequence qualification: compressor, unload/reload
//! residency, and the structured investigator (#139) on the admitted
//! runtime (#138), against deterministic-only preparation.
//!
//! What it measures, in product order:
//!
//! 1. Compressor-only phase on held-out oversized evidence packets: wall
//!    time, token reduction, peak RSS, and memory recovery afterwards.
//! 2. A fresh admission snapshot: the investigator loads after the
//!    compressor is gone, cold.
//! 3. Arm C — the compression arm: `diagnose` over the *compressed*
//!    evidence, with the real model generating. A `Diagnosed` outcome with
//!    the gold hypothesis proves the decisive relationships survived the
//!    selection (citations are byte-checked by the diagnosis contract, so
//!    a diagnosed verdict cannot quote bytes that are not there).
//! 4. Arm D — the deterministic-only arm on the *same oversized* evidence:
//!    the framed prompt exceeds the 2,048-token diagnosis envelope, so the
//!    runtime refuses and the run escalates unresolved. PAM never
//!    substitutes head/tail truncation; that refusal is the honest
//!    deterministic outcome and the benefit compression buys.
//! 5. The within-envelope class: deterministic evidence goes straight to
//!    the investigator (the product bypasses the classifier there); this
//!    arm records that compression has no benefit class at this size.
//!
//! Held-out authored packets, disjoint from the #108 dev records and the
//! compression-qualification corpus. Numbers are the evidence; each phase
//! emits one `PAM_COMPRESSION_SEQUENCE` JSON line.
//!
//! Set these environment variables, then run the test binary:
//!
//! - `PAM_COMPRESSION_MODEL_DIR`: the pinned Microsoft asset directory.
//! - `PAM_SEQUENCE_MODEL`: the pinned investigator GGUF.
//! - `PAM_SEQUENCE_BACKEND`: `cpu` (default) or `metal`.
//! - `PAM_SEQUENCE_HOST_LABEL`: an honest host label for the record.
//! - `PAM_SEQUENCE_REVISION`: optional source revision for the record.
//!
//! Then run `cargo test -p pam_daemon --release --test
//! compression_sequence -- --ignored --nocapture` with those variables
//! exported in the usual shell way.

use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use pam_daemon::diagnosis_service::{
    self, Budgets, DiagnosisOutcome, DiagnosisRecipe, ObserveDispatch, ReadOutcome, RunInputs,
};
use pam_daemon::model_service::ModelUnavailable;
use pam_model::diagnosis::{EvidenceItem, RESPONSE_INPUT_LIMIT};
use pam_model::registry::{Registry, sha256_file};
use pam_model::runtime::{Backend, GenerateRequest, Runtime};

/// The daemon's summary selection budget (`log_service::PROMPT_BUDGET_BYTES`);
/// the compressor target used here leaves framing headroom inside the
/// 2,048-token diagnosis envelope.
const COMPRESSED_TARGET_BYTES: usize = 3_600;

/// Resident set of this process in bytes, sampled through sysinfo's own
/// process entry — the same dependency the daemon uses for its admission
/// memory checks.
fn rss_bytes() -> u64 {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let pid = sysinfo::get_current_pid().expect("own pid resolvable");
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    system
        .process(pid)
        .map(sysinfo::Process::memory)
        .unwrap_or_default()
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn emit(value: &serde_json::Value) {
    println!(
        "PAM_COMPRESSION_SEQUENCE {}",
        serde_json::to_string(value).unwrap()
    );
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

fn asset_dir() -> PathBuf {
    PathBuf::from(required("PAM_COMPRESSION_MODEL_DIR"))
}

/// Console filler without retention keywords, so the classifier genuinely
/// decides these lines and the compressed rendering mirrors product input.
fn filler_line(index: usize) -> String {
    const POOL: [&str; 8] = [
        "cache hit ratio 0.58: reused 761 of 1312 objects",
        "toolchain probe: rustc 1.98.1, cargo 1.98.1",
        "network probe to registry mirror: 14 ms round trip",
        "workspace du: 3.1 GiB across 11042 files",
        "async pool warmed: 8 connections idle",
        "maven resolver: 197 artifacts resolved from mirror",
        "journal compacted: 4902 lines reduced to 587",
        "docker layer pull: layer 5 of 19 complete",
    ];
    let segment = index % 12 + 1;
    let percent = (index * 11) % 100;
    if index.is_multiple_of(3) {
        format!("download progress {index}/110: {percent} percent of segment {segment}\n")
    } else {
        format!("{} [seq {index}]\n", POOL[index % POOL.len()])
    }
}

fn filler(count: usize) -> String {
    (0..count).map(filler_line).collect()
}

/// One held-out incident: the packet text, the tags the recipe's authority
/// bar reads, and the hypothesis a correct diagnosis must land on.
struct Packet {
    label: &'static str,
    text: String,
    tags: &'static [&'static str],
    gold: &'static str,
    build: &'static str,
    job: &'static str,
}

fn oversized_packets() -> Vec<Packet> {
    vec![
        // Infra: the registry service failed repeatedly; the runner was
        // nearly full but recovered. Gold: infra.
        Packet {
            label: "oversized-infra",
            build: "5177",
            job: "delivery/indexer",
            tags: &["service"],
            gold: "infra",
            text: format!(
                "Started by upstream project delivery/indexer build 5177\n\
                 [Pipeline] stage (Fetch)\n\
                 registry service index-uploads returned 503 (3 consecutive probes)\n\
                 runner-03: disk usage 96 percent before cleanup\n\
                 {}\n\
                 [Pipeline] stage (Assemble)\n\
                 + cargo build --locked\n\
                 {}\n\
                 registry service index-uploads returned 503 again during publish\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n",
                filler(110),
                filler(40),
                filler(40)
            ),
        },
        // Code: a type error in the parser crate, exit 101. Gold: code.
        Packet {
            label: "oversized-code",
            build: "6419",
            job: "delivery/parser",
            tags: &["compile_error"],
            gold: "code",
            text: format!(
                "Started by upstream project delivery/parser build 6419\n\
                 [Pipeline] stage (Compile)\n\
                 + cargo test --locked\n\
                 {}\n\
                 error[E0308]: mismatched types at src/parse/lexer.rs:412\n\
                 process exited with code 101\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n",
                filler(120),
                filler(30)
            ),
        },
    ]
}

fn fits_packet() -> Packet {
    // Config: the pipeline environment contradicts the chart pin. Gold:
    // config. Small enough for the envelope without compression.
    Packet {
        label: "fits-config",
        build: "7262",
        job: "delivery/gateway",
        tags: &["config_mismatch"],
        gold: "config",
        text: format!(
            "Started by upstream project delivery/gateway build 7262\n\
             [Pipeline] stage (Render)\n\
             pipeline invoked with environment=prod but chart pins environment=staging\n\
             {}\n\
             [Pipeline] stage (Report)\n\
             Finished: FAILURE\n",
            filler(30)
        ),
    }
}

fn run_inputs(packet: &Packet, text: String) -> RunInputs {
    RunInputs {
        statuses: serde_json::json!({
            "job": format!("{}/build {}", packet.job, packet.build),
            "build_result": "FAILURE",
        }),
        evidence: vec![EvidenceItem {
            id: "ev_packet".to_owned(),
            name: format!("console evidence for {}", packet.label),
            tags: packet.tags.iter().map(|tag| (*tag).to_string()).collect(),
            text,
        }],
        complete: true,
        completeness_notes: vec![],
        reads: vec![],
    }
}

/// The real generator at the diagnosis envelope, mirroring the daemon's
/// `TierModel` seam: one bounded generation, any refusal surfaced. The raw
/// output is echoed and captured so the qualification can measure what the
/// model actually said, separately from what the strict contract accepted.
fn generate<'a>(
    runtime: &'a Runtime,
    request: GenerateRequest,
    captured: &'a std::sync::Mutex<Vec<String>>,
) -> impl Future<Output = Result<pam_model::runtime::GenerateResult, ModelUnavailable>> + Send + 'a
{
    // The sender stays owned by the returned future: dropping it would
    // make the watch read as cancelled.
    let (sender, cancel) = tokio::sync::watch::channel(false);
    let future = runtime.generate_bounded(request, cancel, RESPONSE_INPUT_LIMIT);
    Box::pin(async move {
        let _keep_sender_alive = sender;
        let result = future.await.map_err(ModelUnavailable::from)?;
        eprintln!(
            "RAW MODEL OUTPUT ({} prompt / {} completion tokens): {}",
            result.prompt_tokens, result.completion_tokens, result.text
        );
        captured
            .lock()
            .expect("capture lock")
            .push(result.text.clone());
        Ok(result)
    })
}

/// The #140 advisory read of one raw verdict: the hypothesis the model
/// chose, and whether every citation quote appears verbatim in the
/// evidence text the model was actually given. This is the level at which
/// compression's fidelity is judged here — the strict contract's
/// byte-offset requirement is recorded separately.
struct AdvisoryVerdict {
    hypothesis: String,
    quotes_verbatim: bool,
    offsets_exact: bool,
    citation_count: usize,
}

fn advisory_read(raw: &str, evidence_text: &str) -> Option<AdvisoryVerdict> {
    let value: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let hypothesis = value["hypothesis"].as_str()?.to_owned();
    let citations = value["citations"].as_array()?;
    let mut quotes_verbatim = true;
    let mut offsets_exact = true;
    for citation in citations {
        let Some(quote) = citation["quote"].as_str() else {
            quotes_verbatim = false;
            continue;
        };
        if !evidence_text
            .as_bytes()
            .windows(quote.len())
            .any(|window| window == quote.as_bytes())
        {
            quotes_verbatim = false;
        }
        let (Some(start), Some(end)) = (citation["start"].as_u64(), citation["end"].as_u64())
        else {
            offsets_exact = false;
            continue;
        };
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            offsets_exact = false;
            continue;
        };
        if end > evidence_text.len()
            || evidence_text.as_bytes().get(start..end) != Some(quote.as_bytes())
        {
            offsets_exact = false;
        }
    }
    Some(AdvisoryVerdict {
        hypothesis,
        quotes_verbatim,
        offsets_exact,
        citation_count: citations.len(),
    })
}

#[tokio::test]
#[ignore = "requires the pinned GGUF (PAM_SEQUENCE_MODEL) and compressor assets"]
#[allow(
    clippy::too_many_lines,
    reason = "one explicit product-ordered sequence per phase; splitting it               would scatter the residency and arm measurements"
)]
async fn compression_sequence_qualifies_against_deterministic_preparation() {
    let backend = match std::env::var("PAM_SEQUENCE_BACKEND").as_deref() {
        Ok("metal") => (Backend::Metal, "metal"),
        _ => (Backend::Cpu, "cpu"),
    };
    let host_label = required("PAM_SEQUENCE_HOST_LABEL");
    let revision = std::env::var("PAM_SEQUENCE_REVISION").unwrap_or_else(|_| "unknown".into());
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    let model_path = PathBuf::from(required("PAM_SEQUENCE_MODEL"));
    let (artifact_sha, artifact_bytes) = sha256_file(&model_path).expect("artifact readable");
    let directory = model_path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("registry vendor/file layout");
    let entry = Registry::new(directory)
        .scan()
        .expect("the models dir scans")
        .into_iter()
        .find(|entry| entry.path == model_path)
        .expect("artifact in registry");
    emit(&serde_json::json!({
        "phase": "env",
        "artifact_sha256": artifact_sha,
        "artifact_bytes": artifact_bytes,
        "backend": backend.1,
        "host_label": host_label,
        "revision": revision,
        "started_unix_s": started_at,
    }));

    // Phase 1: compressor on the oversized packets, investigator absent.
    let idle_rss = rss_bytes();
    let packets = oversized_packets();
    let mut compressed: Vec<(String, String, usize, usize)> = Vec::new();
    for packet in &packets {
        let (_sender, cancelled) = tokio::sync::watch::channel(false);
        let started = Instant::now();
        let report = tokio::task::spawn_blocking({
            let directory = asset_dir();
            let text = packet.text.clone();
            move || {
                pam_model::compression::compress(
                    &directory,
                    &text,
                    COMPRESSED_TARGET_BYTES,
                    &cancelled,
                )
            }
        })
        .await
        .expect("compress task joins")
        .unwrap_or_else(|err| panic!("{}: compress failed: {err}", packet.label));
        let wall = started.elapsed();
        assert!(
            wall < Duration::from_secs(30),
            "{}: compressor took {}s, over the caller budget",
            packet.label,
            wall.as_secs_f32()
        );
        let after_rss = rss_bytes();
        emit(&serde_json::json!({
            "phase": "compress",
            "label": packet.label,
            "input_bytes": packet.text.len(),
            "output_bytes": report.text.len(),
            "input_tokens": report.input_tokens,
            "output_tokens": report.output_tokens,
            "wall_ms": millis(wall),
            "idle_rss_bytes": idle_rss,
            "after_rss_bytes": after_rss,
        }));
        compressed.push((
            packet.label.to_owned(),
            report.text,
            report.input_tokens,
            report.output_tokens,
        ));
    }
    // The compressor's transient working set must be gone before the
    // investigator is admitted (loose bound: most of it returned).
    let after_compression_rss = rss_bytes();
    emit(&serde_json::json!({
        "phase": "compressor_recovery",
        "idle_rss_bytes": idle_rss,
        "after_rss_bytes": after_compression_rss,
    }));

    // Phase 2: fresh admission — the investigator loads after the
    // compressor is gone, and this load is the cold one.
    let runtime = Runtime::new();
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(600),
        runtime.load_on_backend(&entry, backend.0),
    )
    .await
    .expect("investigator load timed out")
    .expect("investigator loads");
    let load_wall = started.elapsed();
    let loaded_rss = rss_bytes();
    emit(&serde_json::json!({
        "phase": "investigator_load",
        "wall_ms": millis(load_wall),
        "rss_bytes": loaded_rss,
        "idle_rss_bytes": idle_rss,
    }));

    let recipe = DiagnosisRecipe::jenkins_build_failure();

    // Phase 3: arm C — diagnosis over compressed evidence. Two levels are
    // measured: the shipped strict contract (which rejects verdicts whose
    // citation offsets are not byte-exact) and the advisory verdict the
    // model actually produced (hypothesis plus verbatim quotes), which is
    // the level at which compression's fidelity is judged here.
    for packet in &packets {
        let (_label, text, input_tokens, output_tokens) = compressed
            .iter()
            .find(|(label, _, _, _)| label == packet.label)
            .expect("compressed packet recorded")
            .clone();
        let inputs = run_inputs(packet, text.clone());
        let (strict_outcome, advisory, tokens, wall) = run_arm(
            "arm_c",
            packet.label,
            packet.gold,
            &runtime,
            &recipe,
            inputs,
            &text,
            &["quote_mismatch", "offset_out_of_range"],
        )
        .await;
        emit(&serde_json::json!({
            "phase": "arm_c",
            "label": packet.label,
            "strict_outcome": strict_outcome,
            "advisory_hypothesis": advisory.hypothesis,
            "citations": advisory.citation_count,
            "quotes_verbatim": advisory.quotes_verbatim,
            "offsets_exact": advisory.offsets_exact,
            "prompt_tokens": tokens.0,
            "completion_tokens": tokens.1,
            "calls_wall_ms": millis(wall),
            "compress_input_tokens": input_tokens,
            "compress_output_tokens": output_tokens,
        }));
    }

    // Phase 4: arm D — the same oversized evidence, deterministic-only.
    // The framed prompt exceeds the envelope; the honest outcome is the
    // refusal and an unresolved handoff, never truncation.
    for packet in &packets {
        let captured = std::sync::Mutex::default();
        let inputs = run_inputs(packet, packet.text.clone());
        let outcome = tokio::time::timeout(
            Duration::from_secs(120),
            diagnosis_service::diagnose(
                &recipe,
                inputs,
                Budgets::default(),
                |request| generate(&runtime, request, &captured),
                |_dispatch: ObserveDispatch| async {
                    Err::<ReadOutcome, _>(String::from(
                        "no reads are offered in this qualification",
                    ))
                },
            ),
        )
        .await
        .expect("arm D diagnosis timed out");
        let DiagnosisOutcome::Unresolved { cause, detail, .. } = outcome else {
            panic!(
                "{}: oversized deterministic evidence must not diagnose",
                packet.label
            );
        };
        assert_eq!(cause, "model_unavailable", "{}: {cause}", packet.label);
        assert!(
            detail.contains("tokens"),
            "{}: expected the prompt-length refusal, got: {detail}",
            packet.label
        );
        emit(&serde_json::json!({
            "phase": "arm_d_refused",
            "label": packet.label,
            "cause": cause,
            "detail": detail,
        }));
    }

    // Phase 5: the within-envelope class — deterministic evidence goes
    // straight to the investigator; compression has no benefit there.
    let packet = fits_packet();
    let inputs = run_inputs(&packet, packet.text.clone());
    let (strict_outcome, advisory, tokens, wall) = run_arm(
        "fits_arm",
        packet.label,
        packet.gold,
        &runtime,
        &recipe,
        inputs,
        &packet.text,
        &["quote_mismatch", "offset_out_of_range"],
    )
    .await;
    emit(&serde_json::json!({
        "phase": "fits_arm",
        "label": packet.label,
        "strict_outcome": strict_outcome,
        "advisory_hypothesis": advisory.hypothesis,
        "citations": advisory.citation_count,
        "quotes_verbatim": advisory.quotes_verbatim,
        "offsets_exact": advisory.offsets_exact,
        "prompt_tokens": tokens.0,
        "completion_tokens": tokens.1,
        "calls_wall_ms": millis(wall),
        "input_bytes": packet.text.len(),
    }));

    runtime.unload().await.expect("investigator unloads");
    emit(&serde_json::json!({
        "phase": "summary",
        "note": "arm_c adds compression wall time and token cost to the diagnosis; arm_d proves deterministic-only escalates at this size; fits proves no benefit class under the envelope",
    }));
}

/// Runs one diagnosis through the shipped path, then measures the raw
/// verdict at the advisory level: the hypothesis chosen and whether every
/// citation quote appears verbatim in the evidence text the model was
/// actually given. The strict outcome must be either a diagnosis of the
/// gold hypothesis or one of the tolerated refusals — the byte-offset
/// citation-refusal family (`quote_mismatch`, `offset_out_of_range`) the
/// real screened artifact hits even with verbatim quotes, which belongs to
/// the citation contract, not to compression.
#[allow(clippy::too_many_arguments)]
async fn run_arm(
    phase: &'static str,
    label: &str,
    gold: &str,
    runtime: &Runtime,
    recipe: &DiagnosisRecipe,
    inputs: RunInputs,
    evidence_text: &str,
    tolerated_refusals: &[&str],
) -> (String, AdvisoryVerdict, (usize, usize), Duration) {
    let captured = std::sync::Mutex::default();
    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_mins(15),
        diagnosis_service::diagnose(
            recipe,
            inputs,
            Budgets::default(),
            |request| generate(runtime, request, &captured),
            |_dispatch: ObserveDispatch| async {
                Err::<ReadOutcome, _>(String::from("no reads are offered in this qualification"))
            },
        ),
    )
    .await
    .expect("diagnosis timed out");
    let wall = started.elapsed();

    let (strict_outcome, tokens) = match &outcome {
        DiagnosisOutcome::Diagnosed { advisory, use_, .. } => (
            format!("diagnosed:{}", advisory.hypothesis),
            (use_.prompt_tokens, use_.completion_tokens),
        ),
        DiagnosisOutcome::Unresolved { cause, use_, .. } => {
            assert!(
                tolerated_refusals.contains(cause),
                "{phase}/{label}: unexpected strict outcome: {cause}"
            );
            (
                format!("unresolved:{cause}"),
                (use_.prompt_tokens, use_.completion_tokens),
            )
        }
    };

    let raw = {
        let mut buffer = captured.lock().expect("capture lock");
        assert_eq!(
            buffer.len(),
            1,
            "{phase}/{label}: one advisory call expected"
        );
        buffer.pop().expect("captured verdict")
    };
    let advisory = advisory_read(&raw, evidence_text)
        .unwrap_or_else(|| panic!("{phase}/{label}: raw verdict did not parse as the schema"));
    assert_eq!(
        advisory.hypothesis, gold,
        "{phase}/{label}: the model chose the wrong hypothesis"
    );
    assert!(
        advisory.quotes_verbatim,
        "{phase}/{label}: a citation quote is not verbatim in the evidence the model was given"
    );
    (strict_outcome, advisory, tokens, wall)
}
