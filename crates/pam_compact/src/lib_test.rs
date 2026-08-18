use pam_core::{ContentDigest, EvidenceHandle};
use sha2::{Digest as _, Sha256};

use super::*;

fn source(bytes: &[u8]) -> SourceEvidence {
    SourceEvidence {
        handle: EvidenceHandle::parse("evidence://ci/1842/failure").expect("valid handle"),
        digest: ContentDigest::from_sha256(Sha256::digest(bytes).into()),
    }
}

fn compact(bytes: &[u8], metadata: &LogMetadata, policy: &CompactionPolicy) -> CompactedLog {
    compact_log(&source(bytes), bytes, metadata, policy).expect("valid compaction input")
}

fn policy(boundary_records: usize, failure_context_records: usize) -> CompactionPolicy {
    CompactionPolicy {
        boundary_records,
        failure_context_records,
        ..CompactionPolicy::default()
    }
}

#[test]
fn empty_log_retains_exit_status_without_inventing_source() {
    let result = compact(
        b"",
        &LogMetadata {
            exit_status: Some(0),
            stage_boundaries: Vec::new(),
        },
        &CompactionPolicy::default(),
    );

    assert_eq!(result.source_byte_count, 0);
    assert_eq!(result.retained_byte_count, 0);
    assert_eq!(result.source_record_count, 0);
    assert_eq!(result.retained_record_count, 0);
    assert!(result.fragments.is_empty());
    assert_eq!(result.rendered_text, "[no log output]\n[exit status: 0]\n");
}

#[test]
fn boundaries_reduce_success_output_in_source_order() {
    let bytes = b"first\nsecond\nthird\nlast\n";
    let result = compact(
        bytes,
        &LogMetadata {
            exit_status: Some(0),
            stage_boundaries: Vec::new(),
        },
        &policy(1, 1),
    );

    assert_eq!(result.retained_record_count, 2);
    assert_eq!(
        result.rendered_text,
        "first\n[... 2 records outside retention windows ...]\nlast\n[exit status: 0]\n"
    );
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn invalid_utf8_nul_and_missing_final_newline_are_safe_and_exact() {
    let bytes = b"ok\xff\0tail";
    let result = compact(bytes, &LogMetadata::default(), &policy(1, 0));

    assert_eq!(
        result.rendered_text,
        "ok\u{fffd}\\x00tail\n[exit status: unknown]\n"
    );
    assert_eq!(result.fragments[0].source.length, bytes.len() as u64);
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn crlf_is_normalized_and_standalone_cr_frames_are_superseded() {
    let bytes = b"start\r\n10%\r20%\r30%\r\ndone\r\n";
    let result = compact(bytes, &LogMetadata::default(), &policy(8, 0));

    assert!(!result.rendered_text.contains('\r'));
    assert_eq!(
        result.rendered_text,
        "start\n[... 2 progress frames superseded ...]\n30%\ndone\n[exit status: unknown]\n"
    );
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn ansi_csi_osc_and_truncated_sequences_are_stripped_safely() {
    let bytes = b"\x1b[31mred\x1b[0m\nosc\x1b]0;title\x07ok\ntruncated\x1b[31";
    let result = compact(bytes, &LogMetadata::default(), &policy(8, 0));

    assert_eq!(
        result.rendered_text,
        "red\noscok\ntruncated\n[exit status: unknown]\n"
    );
    assert!(!result.rendered_text.contains('\x1b'));
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn utf8_continuation_bytes_that_resemble_c1_controls_are_preserved() {
    let bytes = "ěĝ\n".as_bytes();
    let result = compact(bytes, &LogMetadata::default(), &policy(1, 0));

    assert_eq!(result.rendered_text, "ěĝ\n[exit status: unknown]\n");
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn consecutive_repeats_and_only_explicit_boilerplate_are_removed() {
    let bytes = b"header\nknown noise\nsame\nsame\nsame\nunknown noise\ntail\n";
    let mut policy = policy(20, 0);
    policy.boilerplate_rules.push(BoilerplateRule {
        id: "test-noise-v1".to_owned(),
        exact_line: "known noise".to_owned(),
    });
    let result = compact(bytes, &LogMetadata::default(), &policy);

    assert_eq!(
        result.rendered_text,
        "header\n[... 1 boilerplate records removed by test-noise-v1 ...]\nsame\n[... 2 repeated records collapsed ...]\nunknown noise\ntail\n[exit status: unknown]\n"
    );
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn overlapping_failure_neighborhoods_are_merged_without_reordering() {
    let bytes = b"zero\none\nERROR first\nthree\nfatal second\nfive\nsix\n";
    let result = compact(bytes, &LogMetadata::default(), &policy(0, 2));

    assert_eq!(result.retained_record_count, 7);
    assert_eq!(
        result.rendered_text,
        "zero\none\nERROR first\nthree\nfatal second\nfive\nsix\n[exit status: unknown]\n"
    );
    assert_eq!(rehydrate(&result, bytes), bytes);
}

#[test]
fn failure_keywords_do_not_match_across_record_boundaries() {
    let bytes = b"err\nor\nplain\nerror here\n";
    let result = compact(bytes, &LogMetadata::default(), &policy(0, 0));

    assert_eq!(
        result.rendered_text,
        "[... 3 records outside retention windows ...]\nerror here\n[exit status: unknown]\n"
    );
}

#[test]
fn stage_boundaries_retain_the_nearest_available_record() {
    let bytes = b"setup\ncompile\ntest\nfinish\n";
    let result = compact(
        bytes,
        &LogMetadata {
            exit_status: Some(1),
            stage_boundaries: vec![StageBoundary {
                label: "tests".to_owned(),
                byte_offset: 14,
            }],
        },
        &policy(0, 0),
    );

    assert_eq!(
        result.rendered_text,
        "[... 2 records outside retention windows ...]\ntest\n[... 1 records outside retention windows ...]\n[exit status: 1]\n"
    );
    let FragmentKind::Retained { reasons } = &result.fragments[1].kind else {
        panic!("stage record should be retained");
    };
    assert_eq!(
        reasons,
        &[RetentionReason::StageBoundary {
            label: "tests".to_owned(),
            byte_offset: 14,
        }]
    );
}

#[test]
fn same_input_and_policy_are_byte_stable() {
    let bytes = b"a\nline\nline\npanic now\nz\n";
    let metadata = LogMetadata {
        exit_status: Some(101),
        stage_boundaries: vec![StageBoundary {
            label: "build".to_owned(),
            byte_offset: 2,
        }],
    };
    let policy = policy(1, 1);

    let first = compact(bytes, &metadata, &policy);
    for _ in 0..32 {
        assert_eq!(compact(bytes, &metadata, &policy), first);
    }
    assert_eq!(first.algorithm_version, ALGORITHM_VERSION);
    assert_eq!(first.policy_version, DEFAULT_POLICY_VERSION);
}

#[test]
fn digest_mismatch_is_a_typed_failure() {
    let bytes = b"truth\n";
    let expected = ContentDigest::from_sha256([0x5a; 32]);
    let error = compact_log(
        &SourceEvidence {
            handle: source(bytes).handle,
            digest: expected.clone(),
        },
        bytes,
        &LogMetadata::default(),
        &CompactionPolicy::default(),
    )
    .expect_err("wrong digest must be rejected");

    assert_eq!(
        error,
        CompactError::DigestMismatch {
            expected,
            actual: ContentDigest::from_sha256(Sha256::digest(bytes).into()),
        }
    );
}

#[test]
fn source_size_limit_accepts_boundary_and_rejects_one_byte_over() {
    assert_eq!(validate_source_size(MAX_SOURCE_BYTES), Ok(()));
    assert_eq!(
        validate_source_size(MAX_SOURCE_BYTES + 1),
        Err(CompactError::SourceTooLarge {
            actual_bytes: (MAX_SOURCE_BYTES + 1) as u64,
            maximum_bytes: MAX_SOURCE_BYTES as u64,
        })
    );
}

#[test]
fn record_limit_accepts_boundary_and_rejects_one_record_over() {
    let at_limit = vec![b'\n'; MAX_SOURCE_RECORDS];
    let result = compact(&at_limit, &LogMetadata::default(), &policy(0, 0));
    assert_eq!(result.source_record_count, MAX_SOURCE_RECORDS as u64);

    let over_limit = vec![b'\n'; MAX_SOURCE_RECORDS + 1];
    assert_eq!(
        compact_log(
            &source(&over_limit),
            &over_limit,
            &LogMetadata::default(),
            &policy(0, 0),
        ),
        Err(CompactError::TooManyRecords {
            maximum_records: MAX_SOURCE_RECORDS as u64,
        })
    );
}

#[test]
fn policy_fields_are_bounded_and_cannot_inject_rendered_markers() {
    let bytes = b"noise\n";
    let invalid = [
        (
            CompactionPolicy {
                version: "bad\nversion".to_owned(),
                ..CompactionPolicy::default()
            },
            PolicyValidationError::Version,
        ),
        (
            CompactionPolicy {
                boundary_records: MAX_BOUNDARY_RECORDS + 1,
                ..CompactionPolicy::default()
            },
            PolicyValidationError::BoundaryRecords,
        ),
        (
            CompactionPolicy {
                failure_context_records: MAX_FAILURE_CONTEXT_RECORDS + 1,
                ..CompactionPolicy::default()
            },
            PolicyValidationError::FailureContextRecords,
        ),
        (
            CompactionPolicy {
                boilerplate_rules: vec![BoilerplateRule {
                    id: "inject\nmarker".to_owned(),
                    exact_line: "noise".to_owned(),
                }],
                ..CompactionPolicy::default()
            },
            PolicyValidationError::BoilerplateRuleId { index: 0 },
        ),
        (
            CompactionPolicy {
                boilerplate_rules: vec![BoilerplateRule {
                    id: "noise-v1".to_owned(),
                    exact_line: "noise\x1b[31m".to_owned(),
                }],
                ..CompactionPolicy::default()
            },
            PolicyValidationError::BoilerplateRuleText { index: 0 },
        ),
    ];

    for (policy, expected) in invalid {
        assert_eq!(
            compact_log(&source(bytes), bytes, &LogMetadata::default(), &policy,),
            Err(CompactError::InvalidPolicy(expected))
        );
    }

    let too_many_rules = CompactionPolicy {
        boilerplate_rules: (0..=MAX_BOILERPLATE_RULES)
            .map(|index| BoilerplateRule {
                id: format!("rule-{index}"),
                exact_line: format!("line {index}"),
            })
            .collect(),
        ..CompactionPolicy::default()
    };
    assert_eq!(
        compact_log(
            &source(bytes),
            bytes,
            &LogMetadata::default(),
            &too_many_rules,
        ),
        Err(CompactError::InvalidPolicy(
            PolicyValidationError::TooManyBoilerplateRules
        ))
    );
}

#[test]
fn policy_and_stage_length_limits_accept_boundary_and_reject_one_over() {
    let mut rules = (0..MAX_BOILERPLATE_RULES)
        .map(|index| BoilerplateRule {
            id: format!("rule-{index}"),
            exact_line: format!("line {index}"),
        })
        .collect::<Vec<_>>();
    rules[0] = BoilerplateRule {
        id: "i".repeat(MAX_BOILERPLATE_ID_BYTES),
        exact_line: "x".repeat(MAX_BOILERPLATE_TEXT_BYTES),
    };
    let bounded_policy = CompactionPolicy {
        version: "v".repeat(MAX_POLICY_VERSION_BYTES),
        boundary_records: MAX_BOUNDARY_RECORDS,
        failure_context_records: MAX_FAILURE_CONTEXT_RECORDS,
        boilerplate_rules: rules,
    };
    assert_eq!(validate_policy(&bounded_policy), Ok(()));

    for expected in [
        validate_policy(&CompactionPolicy {
            version: "v".repeat(MAX_POLICY_VERSION_BYTES + 1),
            ..CompactionPolicy::default()
        }),
        validate_policy(&CompactionPolicy {
            boilerplate_rules: vec![BoilerplateRule {
                id: "i".repeat(MAX_BOILERPLATE_ID_BYTES + 1),
                exact_line: "line".to_owned(),
            }],
            ..CompactionPolicy::default()
        }),
        validate_policy(&CompactionPolicy {
            boilerplate_rules: vec![BoilerplateRule {
                id: "rule".to_owned(),
                exact_line: "x".repeat(MAX_BOILERPLATE_TEXT_BYTES + 1),
            }],
            ..CompactionPolicy::default()
        }),
    ] {
        assert!(expected.is_err());
    }

    let stages = (0..MAX_STAGE_BOUNDARIES)
        .map(|index| StageBoundary {
            label: if index == 0 {
                "s".repeat(MAX_STAGE_LABEL_BYTES)
            } else {
                format!("stage {index}")
            },
            byte_offset: 1,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        validate_metadata(
            &LogMetadata {
                exit_status: None,
                stage_boundaries: stages,
            },
            1,
        ),
        Ok(())
    );
    assert_eq!(
        validate_metadata(
            &LogMetadata {
                exit_status: None,
                stage_boundaries: vec![StageBoundary {
                    label: "s".repeat(MAX_STAGE_LABEL_BYTES + 1),
                    byte_offset: 0,
                }],
            },
            1,
        ),
        Err(CompactError::InvalidMetadata(
            MetadataValidationError::StageLabel { index: 0 }
        ))
    );
}

#[test]
fn duplicate_boilerplate_rules_are_rejected() {
    let bytes = b"noise\n";
    let duplicate_id = CompactionPolicy {
        boilerplate_rules: vec![
            BoilerplateRule {
                id: "same".to_owned(),
                exact_line: "one".to_owned(),
            },
            BoilerplateRule {
                id: "same".to_owned(),
                exact_line: "two".to_owned(),
            },
        ],
        ..CompactionPolicy::default()
    };
    assert_eq!(
        compact_log(
            &source(bytes),
            bytes,
            &LogMetadata::default(),
            &duplicate_id,
        ),
        Err(CompactError::InvalidPolicy(
            PolicyValidationError::DuplicateBoilerplateRuleId { index: 1 }
        ))
    );

    let duplicate_text = CompactionPolicy {
        boilerplate_rules: vec![
            BoilerplateRule {
                id: "one".to_owned(),
                exact_line: "same".to_owned(),
            },
            BoilerplateRule {
                id: "two".to_owned(),
                exact_line: "same".to_owned(),
            },
        ],
        ..CompactionPolicy::default()
    };
    assert_eq!(
        compact_log(
            &source(bytes),
            bytes,
            &LogMetadata::default(),
            &duplicate_text,
        ),
        Err(CompactError::InvalidPolicy(
            PolicyValidationError::DuplicateBoilerplateRuleText { index: 1 }
        ))
    );
}

#[test]
fn policy_digest_binds_effective_configuration_canonically() {
    let bytes = b"first\nnoise\nlast\n";
    let base = CompactionPolicy::default();
    let base_result = compact(bytes, &LogMetadata::default(), &base);
    let changed_boundary = compact(
        bytes,
        &LogMetadata::default(),
        &CompactionPolicy {
            boundary_records: base.boundary_records - 1,
            ..base.clone()
        },
    );
    let changed_context = compact(
        bytes,
        &LogMetadata::default(),
        &CompactionPolicy {
            failure_context_records: base.failure_context_records + 1,
            ..base.clone()
        },
    );
    let rules = vec![
        BoilerplateRule {
            id: "noise-v1".to_owned(),
            exact_line: "noise".to_owned(),
        },
        BoilerplateRule {
            id: "first-v1".to_owned(),
            exact_line: "first".to_owned(),
        },
    ];
    let with_rules = compact(
        bytes,
        &LogMetadata::default(),
        &CompactionPolicy {
            boilerplate_rules: rules.clone(),
            ..base.clone()
        },
    );
    let reordered_rules = compact(
        bytes,
        &LogMetadata::default(),
        &CompactionPolicy {
            boilerplate_rules: rules.into_iter().rev().collect(),
            ..base
        },
    );

    assert_ne!(base_result.policy_digest, changed_boundary.policy_digest);
    assert_ne!(base_result.policy_digest, changed_context.policy_digest);
    assert_ne!(base_result.policy_digest, with_rules.policy_digest);
    assert_eq!(with_rules.policy_digest, reordered_rules.policy_digest);
}

#[test]
fn stage_metadata_is_bounded_and_offset_past_eof_is_rejected() {
    let bytes = b"one\ntwo\n";
    let cases = [
        (
            LogMetadata {
                exit_status: None,
                stage_boundaries: vec![StageBoundary {
                    label: "bad\nlabel".to_owned(),
                    byte_offset: 0,
                }],
            },
            MetadataValidationError::StageLabel { index: 0 },
        ),
        (
            LogMetadata {
                exit_status: None,
                stage_boundaries: vec![StageBoundary {
                    label: "late".to_owned(),
                    byte_offset: bytes.len() as u64 + 1,
                }],
            },
            MetadataValidationError::StageOffsetOutOfBounds {
                index: 0,
                byte_offset: bytes.len() as u64 + 1,
                source_length: bytes.len() as u64,
            },
        ),
    ];
    for (metadata, expected) in cases {
        assert_eq!(
            compact_log(
                &source(bytes),
                bytes,
                &metadata,
                &CompactionPolicy::default(),
            ),
            Err(CompactError::InvalidMetadata(expected))
        );
    }

    let too_many_stages = LogMetadata {
        exit_status: None,
        stage_boundaries: (0..=MAX_STAGE_BOUNDARIES)
            .map(|index| StageBoundary {
                label: format!("stage-{index}"),
                byte_offset: 0,
            })
            .collect(),
    };
    assert_eq!(
        compact_log(
            &source(bytes),
            bytes,
            &too_many_stages,
            &CompactionPolicy::default(),
        ),
        Err(CompactError::InvalidMetadata(
            MetadataValidationError::TooManyStageBoundaries
        ))
    );
}

#[test]
fn stage_offset_at_eof_is_valid_and_retains_the_last_record() {
    let bytes = b"one\ntwo\n";
    let result = compact(
        bytes,
        &LogMetadata {
            exit_status: None,
            stage_boundaries: vec![StageBoundary {
                label: "complete".to_owned(),
                byte_offset: bytes.len() as u64,
            }],
        },
        &policy(0, 0),
    );

    assert_eq!(
        result.rendered_text,
        "[... 1 records outside retention windows ...]\ntwo\n[exit status: unknown]\n"
    );
    let FragmentKind::Retained { reasons } = &result.fragments[1].kind else {
        panic!("EOF stage should retain the last record");
    };
    assert_eq!(
        reasons,
        &[RetentionReason::StageBoundary {
            label: "complete".to_owned(),
            byte_offset: bytes.len() as u64,
        }]
    );
}

#[test]
fn stage_metadata_requires_nonempty_source() {
    let bytes = b"";
    let metadata = LogMetadata {
        exit_status: None,
        stage_boundaries: vec![StageBoundary {
            label: "start".to_owned(),
            byte_offset: 0,
        }],
    };

    assert_eq!(
        compact_log(
            &source(bytes),
            bytes,
            &metadata,
            &CompactionPolicy::default(),
        ),
        Err(CompactError::InvalidMetadata(
            MetadataValidationError::StageWithoutSource { index: 0 }
        ))
    );
}

#[test]
fn every_fragment_span_rehydrates_exact_original_bytes() {
    let bytes = b"\xffhead\r\nnoise\n1%\r2%\r\nrepeat\nrepeat\nERROR\0end";
    let mut policy = policy(1, 1);
    policy.boilerplate_rules.push(BoilerplateRule {
        id: "noise-v1".to_owned(),
        exact_line: "noise".to_owned(),
    });
    let result = compact(bytes, &LogMetadata::default(), &policy);

    assert_eq!(rehydrate(&result, bytes), bytes);
    assert_eq!(result.fragments[0].source.offset, 0);
    for pair in result.fragments.windows(2) {
        assert_eq!(
            pair[0].source.offset + pair[0].source.length,
            pair[1].source.offset
        );
        assert_eq!(pair[0].source.handle, pair[1].source.handle);
    }
    let final_fragment = result.fragments.last().expect("at least one fragment");
    assert_eq!(
        final_fragment.source.offset + final_fragment.source.length,
        bytes.len() as u64
    );
}

fn rehydrate(result: &CompactedLog, exact_bytes: &[u8]) -> Vec<u8> {
    let mut rehydrated = Vec::new();
    for fragment in &result.fragments {
        let start = usize::try_from(fragment.source.offset).expect("test offset fits usize");
        let length = usize::try_from(fragment.source.length).expect("test length fits usize");
        let end = start + length;
        rehydrated.extend_from_slice(&exact_bytes[start..end]);
    }
    rehydrated
}
