use std::path::Path;

use crate::engine::{ENGINE_TAG, Target};
use crate::engine_server::{EngineContract, ServerOptions};
use crate::qualification::{
    ACCURACY_GATE, FALSE_PASS_GATE, PromptContract, QUALIFIED, Qualification, Standing,
    WARM_P95_GATE_MS, all_on_pinned_engine, assess, contract_issue, find, find_in,
};

/// The engine options a fixture record is "measured" with: this build's defaults.
const MEASURED: EngineContract = EngineContract {
    context_tokens: 8192,
    reasoning_budget: 0,
    enable_thinking: false,
    gpu_layers: None,
    parallel_slots: 1,
    chat_template: "gguf-jinja",
    cache_prompt: false,
    seed: 7,
    min_output_tokens: 16,
};

/// `record` with the bench-contract fingerprint its own fields describe, leaked into a
/// one-record table the way the compiled-in one is.
fn bound(record: &Qualification) -> &'static [Qualification] {
    let fingerprint = record.bench().fingerprint(&record.engine);
    Box::leak(
        vec![Qualification {
            bench_contract: Box::leak(fingerprint.into_boxed_str()),
            ..*record
        }]
        .into_boxed_slice(),
    )
}

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
        system_sha256: "",
        output_cap: 160,
        input_limit: 640,
        engine: MEASURED,
        bench_contract: "",
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
        // The bench contract cannot be typed into the table: every part of it that the
        // evidence states must be what the table says, and the fingerprint must be the
        // one those parts have. (The system turn, the input limit, `-np 1`, `--jinja`
        // and the output floor are not fields of `record.json`; the bench and the
        // supervisor at the run's revision establish them, and the bench's own test
        // holds today's bench to the same fingerprint.)
        assert_eq!(
            format!(
                "answer-contract-{}",
                json["contract"]["version"].as_str().unwrap()
            ),
            record.contract,
            "{}: contract version",
            record.artifact
        );
        let reference = json["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|run| run["run"] == json["reference_run"])
            .expect("the reference run is recorded");
        assert_eq!(reference["output_cap"], record.output_cap);
        let settings = &json["engine"]["supervisor_settings"];
        assert_eq!(settings["context_tokens"], record.engine.context_tokens);
        assert_eq!(settings["reasoning_budget"], record.engine.reasoning_budget);
        assert_eq!(settings["enable_thinking"], record.engine.enable_thinking);
        assert_eq!(settings["cache_prompt"], record.engine.cache_prompt);
        assert_eq!(settings["seed"], record.engine.seed);
        assert_eq!(
            json["engine"]["backend"]
                .as_str()
                .unwrap()
                .contains("default offload"),
            record.engine.gpu_layers.is_none(),
            "{}: GPU offload",
            record.artifact
        );
        assert_eq!(
            record.bench().fingerprint(&record.engine),
            record.bench_contract,
            "{}: the recorded bench contract is not the fingerprint of the record's own fields",
            record.artifact
        );
    }
}

#[test]
fn a_record_qualifies_only_a_model_started_with_the_options_it_was_measured_with() {
    let records = bound(&record_like("bound", &[Target::MacosArm64]));
    assert!(matches!(
        assess(records, "bound", Target::MacosArm64, &MEASURED),
        Standing::Qualified(record) if record.sha256 == "bound"
    ));
    // Every output-affecting option, changed one at a time, drops the badge and is named.
    for (name, changed) in [
        (
            "context_tokens",
            EngineContract {
                context_tokens: 4096,
                ..MEASURED
            },
        ),
        (
            "reasoning_budget",
            EngineContract {
                reasoning_budget: 512,
                ..MEASURED
            },
        ),
        (
            "enable_thinking",
            EngineContract {
                enable_thinking: true,
                ..MEASURED
            },
        ),
        (
            "gpu_layers",
            EngineContract {
                gpu_layers: Some(0),
                ..MEASURED
            },
        ),
        (
            "parallel_slots",
            EngineContract {
                parallel_slots: 2,
                ..MEASURED
            },
        ),
        (
            "chat_template",
            EngineContract {
                chat_template: "builtin",
                ..MEASURED
            },
        ),
        (
            "cache_prompt",
            EngineContract {
                cache_prompt: true,
                ..MEASURED
            },
        ),
        (
            "seed",
            EngineContract {
                seed: 9,
                ..MEASURED
            },
        ),
        (
            "min_output_tokens",
            EngineContract {
                min_output_tokens: 1,
                ..MEASURED
            },
        ),
    ] {
        let Standing::ContractChanged { differences, .. } =
            assess(records, "bound", Target::MacosArm64, &changed)
        else {
            panic!("{name} changed and the record still qualifies");
        };
        assert!(
            differences.starts_with(&format!("{name}: measured ")),
            "{differences}"
        );
    }
    assert_eq!(
        assess(records, "absent", Target::MacosArm64, &MEASURED),
        Standing::Unqualified
    );
    assert_eq!(
        assess(records, "bound", Target::WinCpuX64, &MEASURED),
        Standing::Unqualified,
        "the target check comes first"
    );
}

/// The fingerprint also covers what the bench asked: a record whose stated contract,
/// case set, system turn or envelope is not the one its fingerprint was taken over does
/// not qualify, whatever the engine options.
#[test]
fn a_record_whose_bench_identity_does_not_match_its_fingerprint_does_not_qualify() {
    let honest = bound(&record_like("bound", &[Target::MacosArm64]))[0];
    for edited in [
        Qualification {
            contract: "answer-contract-v3",
            ..honest
        },
        Qualification {
            case_set_sha256: "another case set",
            ..honest
        },
        Qualification {
            system_sha256: "another system turn",
            ..honest
        },
        Qualification {
            output_cap: 96,
            ..honest
        },
        Qualification {
            input_limit: 2048,
            ..honest
        },
    ] {
        let table: &'static [Qualification] = Box::leak(vec![edited].into_boxed_slice());
        let Standing::ContractChanged { differences, .. } =
            assess(table, "bound", Target::MacosArm64, &MEASURED)
        else {
            panic!("{edited:?} still qualifies");
        };
        assert!(
            differences.starts_with("bench contract: recorded "),
            "no engine option differs, so the fingerprints are named: {differences}"
        );
    }
}

#[test]
fn the_contract_issue_names_the_record_what_differs_and_the_recovery() {
    let record = record_like("bound", &[Target::MacosArm64]);
    let issue = contract_issue(&record, "seed: measured 7, now 9");
    assert!(
        issue.contains("docs/benchmarks/none")
            && issue.contains("(seed: measured 7, now 9)")
            && issue.contains("needs re-measurement"),
        "{issue}"
    );
}

/// The shipped claim, checked against this build: gpt-oss-20b-MXFP4 was measured on the
/// capability bench (answer contract v2) with exactly the options this build starts it
/// with, so the record qualifies it. Change one of those options and it stops.
#[test]
fn the_shipped_record_qualifies_under_the_options_this_build_starts_the_model_with() {
    let record = &QUALIFIED[0];
    assert_eq!(record.artifact, "gpt-oss-20b-MXFP4");
    assert_eq!(record.engine, EngineContract::of(&ServerOptions::default()));
    // The artifact's header advertises far more context than the envelope; it is
    // started at the envelope, which is what the bench ran.
    let product = EngineContract::of(&ServerOptions::for_model(Some(131_072)));
    assert!(matches!(
        assess(QUALIFIED, record.sha256, Target::MacosArm64, &product),
        Standing::Qualified(found) if found.sha256 == record.sha256
    ));
    let reseeded = EngineContract { seed: 8, ..product };
    assert!(matches!(
        assess(QUALIFIED, record.sha256, Target::MacosArm64, &reseeded),
        Standing::ContractChanged { .. }
    ));
}

/// A job's prompt has a fingerprint of its own. It is a disclosure: it moves with the
/// prompt, and nothing in [`assess`] reads it.
#[test]
fn a_prompt_contract_fingerprint_moves_with_the_prompt_and_gates_nothing() {
    let contract = PromptContract {
        task: "log.summary".to_owned(),
        system: Some("Summarise the evidence.".to_owned()),
        prompt: "<evidence>".to_owned(),
        max_tokens: 400,
        temperature: 0.0,
        stop: Vec::new(),
        input_limit: 2048,
    };
    let fingerprint = contract.fingerprint(&MEASURED);
    assert_eq!(fingerprint.len(), 64);
    assert_eq!(fingerprint, contract.clone().fingerprint(&MEASURED));
    for edited in [
        PromptContract {
            system: Some("Summarize the evidence.".to_owned()),
            ..contract.clone()
        },
        PromptContract {
            prompt: "<evidence> ".to_owned(),
            ..contract.clone()
        },
        PromptContract {
            max_tokens: 401,
            ..contract.clone()
        },
        PromptContract {
            temperature: 0.2,
            ..contract.clone()
        },
        PromptContract {
            stop: vec!["\n".to_owned()],
            ..contract.clone()
        },
        PromptContract {
            input_limit: 4096,
            ..contract.clone()
        },
    ] {
        assert_ne!(fingerprint, edited.fingerprint(&MEASURED), "{edited:?}");
    }
    assert_ne!(
        fingerprint,
        contract.fingerprint(&EngineContract {
            seed: 9,
            ..MEASURED
        })
    );
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
    static RECORDS: &[Qualification] = &[record_like("abc", &[Target::MacosArm64])];
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
