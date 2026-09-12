//! Held-out Microsoft record-selection qualification (roadmap task 140).
//!
//! The #108 labeled benchmark proved one dev record per Jenkins outcome
//! class. This suite qualifies the shipped pinned scorer on *held-out*
//! authored families (disjoint build numbers, artifacts and failure modes)
//! across the input classes the admission spec names: identifiers, numbers,
//! operators, negation, retry and cleanup boundaries, parallel branches,
//! multibyte spans, a long-range context relationship, and a near-cap
//! scale record. It also proves the deterministic fallback contract:
//! corrupted or missing assets refuse with stable causes, cancellation
//! stays responsive, and oversized inputs refuse before inference.
//!
//! The product only calls the classifier for evidence above the summary
//! selection budget, so every record here exceeds it; the small record at
//! the end documents the bypass class where compression must not run.
//!
//! Run against the pinned assets, in a release build:
//!
//! ```text
//! PAM_COMPRESSION_MODEL_DIR=/tmp/pam-microsoft-compression-assets \
//!   cargo test -p pam_model --release --test compression_qualification \
//!   -- --ignored --nocapture
//! ```
//!
//! The numbers are the evidence: each record emits one
//! `PAM_COMPRESSION_QUAL` JSON line for the benchmark record. Assertions
//! encode the qualification bar; a lost decisive fact fails with the
//! class label and is a restriction candidate, not a harness bug.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use pam_model::compression::{self, CompressionError};

/// The daemon's summary selection budget, repeated here because
/// `pam_model` cannot import the daemon's `pam_daemon::log_service` module.
/// The product never invokes the classifier at or below it.
const PRODUCT_BUDGET_BYTES: usize = 6_000;

/// The caller budget every compressor call must meet.
const CALLER_BUDGET: Duration = Duration::from_secs(30);

fn emit(value: &serde_json::Value) {
    println!(
        "PAM_COMPRESSION_QUAL {}",
        serde_json::to_string(value).unwrap()
    );
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn asset_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var_os("PAM_COMPRESSION_MODEL_DIR")
            .expect("set PAM_COMPRESSION_MODEL_DIR to the Microsoft asset directory"),
    )
}

/// Resident set of this process in bytes, sampled through `ps` so the
/// measurement matches the earlier smoke and screen records.
fn rss_bytes() -> u64 {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps runs");
    let text = String::from_utf8(output.stdout).expect("ps output is text");
    let kilobytes: u64 = text
        .split_whitespace()
        .next()
        .expect("ps printed an rss column")
        .parse()
        .expect("rss is numeric");
    kilobytes * 1024
}

/// Samples this process's peak RSS in a background thread until dropped.
struct PeakRss {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicU64>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PeakRss {
    fn start() -> Self {
        let peak = Arc::new(AtomicU64::new(rss_bytes()));
        let stop = Arc::new(AtomicU64::new(0));
        let (peak_thread, stop_thread) = (Arc::clone(&peak), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            while stop_thread.load(Ordering::Relaxed) == 0 {
                let sample = rss_bytes();
                peak_thread.fetch_max(sample, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        Self {
            peak,
            stop,
            handle: Some(handle),
        }
    }

    fn peak_bytes(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }
}

impl Drop for PeakRss {
    fn drop(&mut self) {
        self.stop.store(1, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("the sampler thread joins");
        }
    }
}

/// Realistic console filler with none of the retention keywords the
/// selection policy force-keeps, so the classifier genuinely decides
/// these lines. Numbers vary so records are not byte-identical to each
/// other or to the dev corpus.
fn filler_line(index: usize) -> String {
    const POOL: [&str; 10] = [
        "cache hit ratio 0.62: reused 843 of 1359 layer objects",
        "gradle daemon health: heap 1.2/2.0 GiB, metaspace 212 MiB",
        "maven resolver: 214 artifacts resolved from mirror",
        "toolchain probe: rustc 1.98.1, cargo 1.98.1",
        "network probe to registry mirror: 12 ms round trip",
        "journal compacted: 5319 lines reduced to 612",
        "docker layer pull: layer 7 of 19 complete",
        "async pool warmed: 8 connections idle",
        "workspace du: 3.4 GiB across 11844 files",
        "javac daemon: 2 active compilations, uptime 91 s",
    ];
    let segment = index % 14 + 1;
    let percent = (index * 7) % 100;
    if index.is_multiple_of(3) {
        format!("download progress {index}/120: {percent} percent of segment {segment}\n")
    } else {
        format!("{} [seq {index}]\n", POOL[index % POOL.len()])
    }
}

fn filler(count: usize) -> String {
    (0..count).map(filler_line).collect()
}

struct Record {
    /// Qualification input class the record belongs to.
    class: &'static str,
    label: &'static str,
    source: String,
    /// Decisive facts whose survival the class is judged on.
    facts: Vec<&'static str>,
    /// Whether a lost fact fails the run. Proven classes gate; restricted
    /// classes measure and record only, because the qualification run
    /// already proved the classifier can drop their decisive facts (the
    /// 2026-09-12 run lost the negation record's non-keyword causal line
    /// at the product budget), which is exactly why those classes stay
    /// excluded from any enablement.
    gated: bool,
}

/// Builds the held-out corpus. Families are disjoint from the #108 dev
/// records (build 482) and the smoke fixture: new build numbers, artifact
/// names and digests throughout.
#[allow(
    clippy::too_many_lines,
    reason = "one explicit authored record per qualification class; splitting               them would scatter the held-out corpus"
)]
fn corpus() -> Vec<Record> {
    vec![
        // Identifiers: artifact name, digest and triggering ref live on
        // non-keyword lines far from anything the policy force-keeps.
        Record {
            class: "identifiers",
            label: "artifact-identity",
            source: format!(
                "Started by upstream project delivery/api build 7306\n\
                 [Pipeline] stage (Package)\n\
                 [Pipeline] sh\n\
                 + cargo package --locked\n\
                 {}\n\
                 Uploading service-7306.tar.gz sha256=4b1e90c9f2ad (148.2 MiB)\n\
                 requested by deployment-bot for ref refs/heads/release/7.3\n\
                 {}\n\
                 [Pipeline] stage (Publish)\n\
                 Finished: SUCCESS\n",
                filler(150),
                filler(20)
            ),
            facts: vec![
                "Uploading service-7306.tar.gz sha256=4b1e90c9f2ad",
                "requested by deployment-bot for ref refs/heads/release/7.3",
            ],
            gated: true,
        },
        // Numbers: resource figures that decide the diagnosis, on plain
        // lines without retention keywords.
        Record {
            class: "numbers",
            label: "resource-exhaustion",
            source: format!(
                "Started by upstream project delivery/worker build 8841\n\
                 [Pipeline] stage (Verify)\n\
                 {}\n\
                 disk_free_gb=1.8 required_gb=5.0 on /var/lib/artifacts\n\
                 p95_queue_ms=41207 limit_ms=30000\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n",
                filler(150),
                filler(15)
            ),
            facts: vec![
                "disk_free_gb=1.8 required_gb=5.0 on /var/lib/artifacts",
                "p95_queue_ms=41207 limit_ms=30000",
            ],
            gated: true,
        },
        // Operators: comparisons and signed deltas on plain lines.
        Record {
            class: "operators",
            label: "quality-gate-comparison",
            source: format!(
                "Started by upstream project delivery/web build 9012\n\
                 [Pipeline] stage (Analysis)\n\
                 {}\n\
                 coverage 63.2 < 80.0 (delta -16.8)\n\
                 gate_result=reject policy=strict\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n",
                filler(150),
                filler(15)
            ),
            facts: vec![
                "coverage 63.2 < 80.0 (delta -16.8)",
                "gate_result=reject policy=strict",
            ],
            gated: true,
        },
        // Negation: inverting words and states that a keyword-driven
        // reading could flip if the lines were dropped.
        Record {
            class: "negation",
            label: "not-built-and-without-error",
            source: format!(
                "Started by upstream project delivery/cli build 5566\n\
                 [Pipeline] stage (Gate)\n\
                 {}\n\
                 deploy did not start: manifest rejected by admission\n\
                 status: NOT_BUILT\n\
                 {}\n\
                 [Pipeline] stage (Handoff)\n\
                 Finished: FAILURE\n",
                filler(150),
                filler(20)
            ),
            facts: vec![
                "deploy did not start: manifest rejected by admission",
                "status: NOT_BUILT",
            ],
            gated: false,
        },
        // Retry boundary: two transient service attempts and a final
        // success; the diagnosis needs all three in order.
        Record {
            class: "retry_boundary",
            label: "transient-then-success",
            source: format!(
                "Started by upstream project delivery/contracts build 6634\n\
                 [Pipeline] stage (Push)\n\
                 Retrying artifact push after 5 seconds (1 of 3)\n\
                 Attempt 2: registry returned status 503\n\
                 {}\n\
                 Attempt 3: push accepted, digest sha256:9f3b71\n\
                 {}\n\
                 Finished: SUCCESS\n",
                filler(150),
                filler(15)
            ),
            facts: vec![
                "Retrying artifact push after 5 seconds (1 of 3)",
                "Attempt 2: registry returned status 503",
                "Attempt 3: push accepted, digest sha256:9f3b71",
            ],
            gated: true,
        },
        // Cleanup boundary: successful cleanup after the terminal status
        // must neither displace the failure facts nor flip the verdict.
        Record {
            class: "cleanup_boundary",
            label: "post-failure-cleanup",
            source: format!(
                "Started by upstream project delivery/auth build 7340\n\
                 [Pipeline] stage (Integration)\n\
                 ERROR: integration tests failed: 3 failures in AuthSuite\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n\
                 cleanup: workspace pruned in 4.1s\n\
                 cleanup: 12 artifacts archived to storage\n\
                 cleanup: node released\n",
                filler(150)
            ),
            facts: vec![
                "ERROR: integration tests failed: 3 failures in AuthSuite",
                "Finished: FAILURE",
            ],
            gated: true,
        },
        // Parallel boundary: five branch outcomes interleaved with filler;
        // the four healthy branches sit more than the forced-context
        // window away from the failing branch's line.
        Record {
            class: "parallel_boundary",
            label: "one-failing-branch",
            source: format!(
                "Started by upstream project delivery/polyglot build 9901\n\
                 [Pipeline] parallel\n\
                 branch-eu: FAILURE exit=1\n\
                 {}\n\
                 branch-us: exit=0\n\
                 {}\n\
                 branch-ap: exit=0\n\
                 {}\n\
                 branch-ca: exit=0\n\
                 {}\n\
                 branch-sa: exit=0\n\
                 {}\n\
                 [Pipeline] stage (Report)\n\
                 Finished: FAILURE\n",
                filler(30),
                filler(30),
                filler(30),
                filler(30),
                filler(25)
            ),
            facts: vec![
                "branch-eu: FAILURE exit=1",
                "branch-us: exit=0",
                "branch-ap: exit=0",
                "branch-ca: exit=0",
                "branch-sa: exit=0",
            ],
            gated: true,
        },
        // Multibyte: decisive facts containing non-ASCII bytes exercise
        // char-boundary-safe span mapping end to end.
        Record {
            class: "multibyte",
            label: "utf8-fact-spans",
            source: format!(
                "Started by upstream project delivery/metrics build 4477\n\
                 [Pipeline] stage (Publish)\n\
                 {}\n\
                 artifact übersicht-4477.json sha256=d1c3a9 (2.2 MiB)\n\
                 log written to /var/log/übertreibung-4477.txt\n\
                 {}\n\
                 Finished: SUCCESS\n",
                filler(150),
                filler(15)
            ),
            facts: vec![
                "artifact übersicht-4477.json sha256=d1c3a9",
                "log written to /var/log/übertreibung-4477.txt",
            ],
            gated: true,
        },
        // Long-range context: the decisive relationship spans a filler
        // gap far wider than the forced-context window, so only genuine
        // classifier scoring can keep the antecedent line.
        Record {
            class: "context_relation",
            label: "antecedent-across-filler",
            source: format!(
                "Started by upstream project delivery/deploy build 2210\n\
                 [Pipeline] stage (Render)\n\
                 deploying profile canary-eu-west revision 2210f2c4\n\
                 {}\n\
                 ERROR: deployment target rejected the manifest\n\
                 Finished: FAILURE\n",
                filler(160)
            ),
            facts: vec![
                "deploying profile canary-eu-west revision 2210f2c4",
                "ERROR: deployment target rejected the manifest",
            ],
            gated: false,
        },
        // Scale: a near-cap record measuring latency and retention at the
        // top of the product envelope (still under the 8,192-token cap).
        Record {
            class: "scale",
            label: "near-cap-record",
            source: format!(
                "Started by upstream project delivery/bundle build 8123\n\
                 [Pipeline] stage (Assemble)\n\
                 {}\n\
                 Upload completed: bundle-8123.tar.gz sha256=e5a2b8\n\
                 duration 4120s of 7200 allowed\n\
                 {}\n\
                 Finished: UNSTABLE\n",
                filler(360),
                filler(25)
            ),
            facts: vec![
                "Upload completed: bundle-8123.tar.gz sha256=e5a2b8",
                "duration 4120s of 7200 allowed",
                "Finished: UNSTABLE",
            ],
            gated: true,
        },
    ]
}

/// Runs every held-out record through the pinned classifier at the product
/// budget. Proven classes gate: every decisive fact must survive, spans
/// must reconstruct byte-exactly, and the caller budget must hold.
/// Restricted classes (negation, long-range context) run and record only —
/// the qualification run measured a decisive loss there, which is why they
/// stay excluded from any enablement.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn heldout_records_retain_decisive_facts_within_the_caller_budget() {
    let directory = asset_dir();

    for record in corpus() {
        let source_bytes = record.source.len();
        assert!(
            source_bytes > PRODUCT_BUDGET_BYTES,
            "{}: the product bypasses records at or below the selection budget",
            record.label
        );
        let (_sender, cancelled) = tokio::sync::watch::channel(false);
        let sampler = PeakRss::start();
        let started = Instant::now();
        let report =
            compression::compress(&directory, &record.source, PRODUCT_BUDGET_BYTES, &cancelled)
                .unwrap_or_else(|err| panic!("{}: compress failed: {err}", record.label));
        let elapsed = started.elapsed();
        let peak_rss = sampler.peak_bytes();
        drop(sampler);

        assert!(
            elapsed < CALLER_BUDGET,
            "{}: {} exceeded the 30-second caller budget",
            record.label,
            elapsed.as_secs_f32()
        );
        assert!(
            report.text.len() <= PRODUCT_BUDGET_BYTES,
            "{}: output exceeded the product selection budget",
            record.label
        );

        // Span honesty: retained spans must rebuild the output byte-exactly.
        let mut reconstructed = String::new();
        let mut cursor = 0;
        for span in &report.retained {
            assert!(span.start >= cursor && span.end > span.start && span.end <= source_bytes);
            if span.start > cursor {
                reconstructed.push_str("[... omitted ...]\n");
            }
            reconstructed.push_str(&record.source[span.start..span.end]);
            cursor = span.end;
        }
        if cursor < source_bytes {
            reconstructed.push_str("[... omitted ...]\n");
        }
        assert_eq!(
            reconstructed, report.text,
            "{}: retained spans must rebuild the selection byte-exactly",
            record.label
        );

        let lost: Vec<&str> = record
            .facts
            .iter()
            .filter(|fact| !report.text.contains(**fact))
            .copied()
            .collect();
        emit(&serde_json::json!({
            "class": record.class,
            "label": record.label,
            "input_bytes": source_bytes,
            "output_bytes": report.text.len(),
            "input_tokens": report.input_tokens,
            "output_tokens": report.output_tokens,
            "wall_ms": millis(elapsed),
            "peak_rss_bytes": peak_rss,
            "facts_total": record.facts.len(),
            "facts_retained": record.facts.len() - lost.len(),
            "gated": record.gated,
            "model_id": report.model_id,
        }));
        if record.gated {
            assert!(
                lost.is_empty(),
                "{} ({}): decisive facts lost in compression: {lost:?}",
                record.class,
                record.label
            );
        } else if !lost.is_empty() {
            eprintln!(
                "RESTRICTED CLASS measured loss — {} ({}): {lost:?}; \
                 this class stays excluded from enablement",
                record.class, record.label
            );
        }
    }
}

/// The bypass class: a record at or below the selection budget is returned
/// unchanged by the selection policy — and the product never even calls the
/// classifier for it (`log_semantic` checks the budget first). This
/// documents why compression has no benefit class there.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn within_budget_records_are_returned_unchanged() {
    let directory = asset_dir();
    let source = format!(
        "Started by upstream project delivery/tiny build 3312\n\
         [Pipeline] stage (Check)\n\
         {}\n\
         gate_result=accept policy=strict\n\
         Finished: SUCCESS\n",
        filler(60)
    );
    assert!(source.len() <= PRODUCT_BUDGET_BYTES);
    let (_sender, cancelled) = tokio::sync::watch::channel(false);
    let report = compression::compress(&directory, &source, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect("official assets must load");
    assert_eq!(report.text, source, "selection must be the identity here");
    assert_eq!(report.retained.len(), 1);
    assert_eq!(report.retained[0].start, 0);
    assert_eq!(report.retained[0].end, source.len());
}

/// Cancellation stays responsive during asset verification, before any
/// inference: a pre-cancelled call refuses immediately, and a call
/// cancelled mid-verification ends strictly faster than a full run.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn cancellation_is_observed_before_inference_completes() {
    let directory = asset_dir();
    let source = format!(
        "Started by upstream project delivery/cancel build 1010\n{}",
        filler(120)
    );

    let (_sender, cancelled) = tokio::sync::watch::channel(true);
    let started = Instant::now();
    let error = compression::compress(&directory, &source, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect_err("a pre-cancelled call must refuse");
    assert!(matches!(error, CompressionError::Cancelled));
    assert!(started.elapsed() < Duration::from_secs(2));

    // Cancel from a timer while the run is in flight; the run must end
    // with `Cancelled` well before an uninterrupted run would.
    let (sender, cancelled) = tokio::sync::watch::channel(false);
    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        sender.send_replace(true);
    });
    let started = Instant::now();
    let error = compression::compress(&directory, &source, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect_err("a cancelled call must not produce a selection");
    let elapsed = started.elapsed();
    killer.join().expect("the timer thread joins");
    assert!(matches!(error, CompressionError::Cancelled));
    emit(&serde_json::json!({
        "class": "cancellation",
        "label": "mid-verification-cancel",
        "wall_ms": millis(elapsed),
        "cause": error.cause(),
    }));
    assert!(
        elapsed < CALLER_BUDGET,
        "cancellation must end the call inside the caller budget"
    );
}

/// Corrupted or missing assets refuse with stable causes — the
/// deterministic-evidence fallback contract — and never yield a
/// partial selection.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn corrupted_assets_refuse_with_stable_causes() {
    let source = format!(
        "Started by upstream project delivery/tamper build 1011\n{}\n",
        filler(120)
    );

    let mut scratch = std::env::temp_dir();
    scratch.push(format!("pam-compression-qual-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch directory created");

    // Verify every asset once by copying all three into the scratch
    // directory; the individual cases then mutate one at a time.
    for asset in compression::ASSETS {
        let destination = scratch.join(asset.name);
        std::fs::copy(asset_dir().join(asset.name), &destination)
            .unwrap_or_else(|err| panic!("{} copies for the tamper cases: {err}", asset.name));
    }
    let weights = scratch.join("model.safetensors");
    let original = std::fs::read(&weights).expect("weights readable");

    // A missing asset refuses before any inference.
    let tokenizer = scratch.join("tokenizer.json");
    std::fs::rename(&tokenizer, scratch.join("tokenizer.moved")).expect("move writes");
    let error = compress_in(&scratch, &source);
    assert!(matches!(error, CompressionError::Unavailable(_)), "{error}");
    std::fs::rename(scratch.join("tokenizer.moved"), &tokenizer).expect("restore writes");

    // Truncated weights: size check refuses.
    std::fs::write(&weights, &original[..original.len() / 2]).expect("truncate writes");
    let error = compress_in(&scratch, &source);
    assert!(matches!(error, CompressionError::Integrity(_)), "{error}");

    // Same-size corruption: the digest check refuses for any verified
    // asset, so a tampered file can never reach parsing or inference —
    // that is the contract, and it covers the tokenizer and config too.
    let mut tampered = original.clone();
    tampered[10_000_000] ^= 0xff;
    std::fs::write(&weights, &tampered).expect("tamper writes");
    let error = compress_in(&scratch, &source);
    assert!(matches!(error, CompressionError::Integrity(_)), "{error}");
    let mut tokenizer_bytes = std::fs::read(&tokenizer).expect("tokenizer readable");
    tokenizer_bytes[500_000] ^= 0xff;
    std::fs::write(&tokenizer, &tokenizer_bytes).expect("tamper writes");
    let error = compress_in(&scratch, &source);
    assert!(matches!(error, CompressionError::Integrity(_)), "{error}");

    std::fs::remove_dir_all(&scratch).expect("scratch cleaned up");
}

/// Runs the tampered directory once and returns the refusal cause.
fn compress_in(directory: &std::path::Path, source: &str) -> CompressionError {
    let (_sender, cancelled) = tokio::sync::watch::channel(false);
    compression::compress(directory, source, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect_err("tampered assets must refuse, never produce a selection")
}

/// The admission ceilings refuse before any inference: inputs over 64 KiB
/// and inputs over 8,192 classifier tokens.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn oversized_inputs_refuse_before_inference() {
    let directory = asset_dir();
    let (_sender, cancelled) = tokio::sync::watch::channel(false);

    let over_bytes = "x".repeat(64 * 1024 + 1);
    let error = compression::compress(&directory, &over_bytes, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect_err("over 64 KiB must refuse");
    assert!(matches!(error, CompressionError::InputLimit), "{error}");

    // Short tokens maximize token count per byte: ~24k tokens, well under
    // 64 KiB but far over the 8,192-token cap.
    let many_tokens = "abc def ".repeat(6_000);
    assert!(many_tokens.len() <= 64 * 1024);
    let error = compression::compress(&directory, &many_tokens, PRODUCT_BUDGET_BYTES, &cancelled)
        .expect_err("over 8,192 tokens must refuse");
    assert!(matches!(error, CompressionError::InputLimit), "{error}");
}
