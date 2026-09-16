use std::path::Path;

use crate::engine::{ENGINE_TAG, Target};
use crate::qualification::{
    ACCURACY_GATE, FALSE_PASS_GATE, QUALIFIED, Qualification, WARM_P95_GATE_MS,
    all_on_pinned_engine, find, find_in,
};

/// The repository root, two levels above this crate's manifest.
fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
}

const fn record_like(sha256: &'static str, targets: &'static [Target]) -> Qualification {
    Qualification {
        artifact: "fixture",
        sha256,
        engine_tag: ENGINE_TAG,
        targets,
        contract: "test",
        case_set_sha256: "",
        record: "docs/benchmarks/none",
        host: "test",
        accuracy: 1.0,
        false_passes: 0,
        warm_p95_ms: 1,
        decided: "2026-01-01",
    }
}

#[test]
fn the_table_is_not_empty_and_every_record_clears_the_gates() {
    assert!(!QUALIFIED.is_empty(), "no artifact may serve a job");
    for record in QUALIFIED {
        assert!(
            record.meets_gates(),
            "{} is in the table with accuracy {} / {} false passes / {} ms, which does not \
             clear the gates ({ACCURACY_GATE} / {FALSE_PASS_GATE} / {WARM_P95_GATE_MS} ms)",
            record.artifact,
            record.accuracy,
            record.false_passes,
            record.warm_p95_ms
        );
        assert!(
            !record.targets.is_empty(),
            "{} covers no target",
            record.artifact
        );
        assert_eq!(
            record.sha256.len(),
            64,
            "{} digest is not SHA-256 hex",
            record.artifact
        );
        assert!(
            record
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{} digest is not lowercase hex",
            record.artifact
        );
    }
}

#[test]
fn every_record_is_measured_on_the_pinned_engine() {
    assert!(
        all_on_pinned_engine(QUALIFIED),
        "a qualification names an engine tag other than {ENGINE_TAG}: the engine moved, \
         so the artifact must be re-measured before it may serve a job"
    );
    let stale = [Qualification {
        engine_tag: "b0",
        ..record_like("a", &[Target::MacosArm64])
    }];
    assert!(!all_on_pinned_engine(&stale));
}

#[test]
fn every_record_points_at_evidence_that_names_the_same_digest() {
    for record in QUALIFIED {
        let path = repo_root().join(record.record).join("record.json");
        let bytes = std::fs::read(&path).unwrap_or_else(|err| {
            panic!("{} has no record.json at {path:?}: {err}", record.artifact)
        });
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["artifact"]["sha256"].as_str(),
            Some(record.sha256),
            "{}: the table and its evidence disagree on the digest",
            record.artifact
        );
        assert_eq!(
            json["engine"]["tag"].as_str(),
            Some(record.engine_tag),
            "{}: the table and its evidence disagree on the engine",
            record.artifact
        );
        assert_eq!(
            json["contract"]["case_set_sha256"].as_str(),
            Some(record.case_set_sha256),
            "{}: the table and its evidence disagree on the case set",
            record.artifact
        );
    }
}

#[test]
fn gates_are_checked_individually() {
    let good = record_like("a", &[Target::MacosArm64]);
    assert!(good.meets_gates());
    assert!(
        !Qualification {
            accuracy: 0.949,
            ..good
        }
        .meets_gates()
    );
    assert!(
        !Qualification {
            false_passes: 1,
            ..good
        }
        .meets_gates()
    );
    assert!(
        !Qualification {
            warm_p95_ms: WARM_P95_GATE_MS,
            ..good
        }
        .meets_gates()
    );
}

#[test]
fn find_matches_digest_and_target_only() {
    static RECORDS: &[Qualification] = &[Qualification {
        artifact: "fixture",
        sha256: "abc",
        engine_tag: ENGINE_TAG,
        targets: &[Target::MacosArm64],
        contract: "test",
        case_set_sha256: "",
        record: "docs/benchmarks/none",
        host: "test",
        accuracy: 1.0,
        false_passes: 0,
        warm_p95_ms: 1,
        decided: "2026-01-01",
    }];
    assert!(find_in(RECORDS, "abc", Target::MacosArm64).is_some());
    assert!(
        find_in(RECORDS, "abc", Target::UbuntuX64).is_none(),
        "Metal figures do not qualify a CPU build"
    );
    assert!(find_in(RECORDS, "abd", Target::MacosArm64).is_none());
    assert!(find("not-a-digest", Target::MacosArm64).is_none());
}

#[test]
fn find_in_refuses_a_record_that_fails_a_gate_or_names_another_engine() {
    static FAILING: &[Qualification] = &[
        Qualification {
            false_passes: 1,
            ..record_like("gate", &[Target::MacosArm64])
        },
        Qualification {
            engine_tag: "b0",
            ..record_like("stale", &[Target::MacosArm64])
        },
        record_like("good", &[Target::MacosArm64]),
    ];
    assert!(
        find_in(FAILING, "gate", Target::MacosArm64).is_none(),
        "a false pass disqualifies on the admission path, not only in the table test"
    );
    assert!(
        find_in(FAILING, "stale", Target::MacosArm64).is_none(),
        "figures from another engine build qualify nothing"
    );
    assert!(find_in(FAILING, "good", Target::MacosArm64).is_some());
}
