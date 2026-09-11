//! Opt-in classifier smoke test, not diagnostic-quality qualification.
//! Run with `PAM_COMPRESSION_MODEL_DIR` pointing to the verified asset directory.
use std::{fmt::Write as _, path::PathBuf, time::Duration, time::Instant};

use pam_model::compression;
use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn official_classifier_preserves_jenkins_failure_and_recovery_evidence() {
    let directory = PathBuf::from(
        std::env::var_os("PAM_COMPRESSION_MODEL_DIR")
            .expect("set PAM_COMPRESSION_MODEL_DIR to the Microsoft asset directory"),
    );
    let mut source = String::from(
        "Started by upstream project delivery/service build 482\n[Pipeline] stage (Compile)\n[Pipeline] sh\n+ cargo build --locked\n",
    );
    for index in 0..40 {
        writeln!(source,
            "dependency build progress {index}: checking cached crate metadata and incremental workspace objects"
        ).unwrap();
    }
    source.push_str(
        "[Pipeline] stage (Upload artifact)\n[Pipeline] retry\nAttempt 1 of 2\nERROR: upload returned HTTP 503 from artifact repository\nRetrying upload after 5 seconds\nAttempt 2 of 2\nUpload completed: service-482.tar.gz sha256=8a019c\n[Pipeline] stage (Quality gate)\nAnalysis task AZ-482 completed\nERROR: quality gate failed: new_coverage=63.2, required=80.0\n[Pipeline] catchError\nRetaining artifact; marking this workflow unsuccessful\nFinished: FAILURE\n",
    );
    let budget = 1_800;
    let (_sender, cancelled) = tokio::sync::watch::channel(false);
    let started = Instant::now();
    let report = compression::compress(&directory, &source, budget, &cancelled)
        .expect("official assets must load and execute the actual classifier");
    eprintln!(
        "LLMLingua smoke: model={} elapsed={:?} tokens={}→{} bytes={}→{}",
        report.model_id,
        started.elapsed(),
        report.input_tokens,
        report.output_tokens,
        source.len(),
        report.text.len()
    );
    assert!(report.input_tokens > 256);
    assert!(report.text.len() <= budget);
    assert!(report.text.len() < source.len());
    assert_eq!(report.source_bytes, source.len());
    assert_eq!(
        report.source_sha256,
        hex::encode(Sha256::digest(source.as_bytes()))
    );
    for fact in [
        "ERROR: upload returned HTTP 503",
        "Retrying upload after 5 seconds",
        "Upload completed: service-482.tar.gz sha256=8a019c",
        "new_coverage=63.2, required=80.0",
        "[Pipeline] catchError",
        "Finished: FAILURE",
    ] {
        assert!(report.text.contains(fact), "missing required fact: {fact}");
    }
    let mut reconstructed = String::new();
    let mut cursor = 0;
    for span in &report.retained {
        assert!(span.start >= cursor && span.end > span.start && span.end <= source.len());
        if span.start > cursor {
            reconstructed.push_str("[... omitted ...]\n");
        }
        reconstructed.push_str(&source[span.start..span.end]);
        cursor = span.end;
    }
    if cursor < source.len() {
        reconstructed.push_str("[... omitted ...]\n");
    }
    assert_eq!(
        reconstructed, report.text,
        "retained bytes must match the source exactly"
    );
}

/// The #108 latency-and-retention benchmark: one labeled record per Jenkins
/// outcome class, compressed against the caller budget in an optimized
/// build. The 70.88 s debug smoke was wiring proof; this is the evidence for
/// or against the 30-second caller budget, and the decisive facts are the
/// deterministic expectations the compression must retain.
#[test]
#[ignore = "requires the official Microsoft assets in PAM_COMPRESSION_MODEL_DIR"]
fn labeled_jenkins_classes_meet_the_caller_budget() {
    let directory = PathBuf::from(
        std::env::var_os("PAM_COMPRESSION_MODEL_DIR")
            .expect("set PAM_COMPRESSION_MODEL_DIR to the Microsoft asset directory"),
    );
    let filler = "dependency build progress: checking cached crate metadata and incremental workspace objects\n";

    let cases: Vec<(&str, String, usize, Vec<&str>)> = vec![
        (
            "failure",
            format!(
                "Started by upstream project delivery/service build 482\n[Pipeline] stage (Compile)\n[Pipeline] sh\n+ cargo build --locked\n{filler}\
                 ERROR: compile failed: exit=101\n[Pipeline] catchError\nFinished: FAILURE\n"
            ),
            40,
            vec!["ERROR: compile failed: exit=101", "Finished: FAILURE"],
        ),
        (
            "retry",
            format!(
                "Started by upstream project delivery/service build 482\n[Pipeline] stage (Upload artifact)\n[Pipeline] retry\nAttempt 1 of 2\nERROR: upload returned HTTP 503 from artifact repository\n{filler}\
                 Attempt 2 of 2\nUpload completed: service-482.tar.gz sha256=8a019c\nFinished: SUCCESS\n"
            ),
            40,
            vec![
                "ERROR: upload returned HTTP 503",
                "Attempt 2 of 2",
                "Upload completed: service-482.tar.gz sha256=8a019c",
                "Finished: SUCCESS",
            ],
        ),
        (
            "post",
            format!(
                "Started by upstream project delivery/service build 482\n[Pipeline] stage (Compile)\n[Pipeline] sh\n+ cargo build --locked\n{filler}\
                 [Pipeline] stage (Post)\npost-stage notify: FAILURE exit=7\n[Pipeline] catchError\nRetaining artifact; marking this workflow unsuccessful\nFinished: FAILURE\n"
            ),
            40,
            vec!["post-stage notify: FAILURE exit=7", "Finished: FAILURE"],
        ),
        (
            "parallel",
            format!(
                "Started by upstream project delivery/service build 482\n[Pipeline] stage (Compile)\n[Pipeline] sh\n+ cargo build --locked\n{filler}\
                 [Pipeline] parallel\nbranch-eu: FAILURE exit=1\nbranch-us: exit=0\nbranch-ap: exit=0\n[Pipeline] catchError\nFinished: FAILURE\n"
            ),
            40,
            vec![
                "branch-eu: FAILURE exit=1",
                "branch-us: exit=0",
                "Finished: FAILURE",
            ],
        ),
    ];

    let budget = 1_800;
    for (label, mut source, filler_lines, facts) in cases {
        // Grow every record to a realistic pipeline length.
        for _ in 0..filler_lines {
            source.insert_str(source.len() - 1, filler);
        }
        let (_sender, cancelled) = tokio::sync::watch::channel(false);
        let started = Instant::now();
        let report = compression::compress(&directory, &source, budget, &cancelled)
            .unwrap_or_else(|err| panic!("{label}: official assets must load and execute: {err}"));
        let elapsed = started.elapsed();
        eprintln!(
            "LLMLingua {label}: elapsed={elapsed:?} tokens={}→{} bytes={}→{}",
            report.input_tokens,
            report.output_tokens,
            source.len(),
            report.text.len()
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "{label}: {} exceeded the 30-second caller budget",
            elapsed.as_secs_f32()
        );
        assert!(
            report.text.len() <= budget,
            "{label}: output exceeded the byte budget"
        );
        for fact in facts {
            assert!(
                report.text.contains(fact),
                "{label}: decisive fact lost in compression: {fact}"
            );
        }
    }
}
