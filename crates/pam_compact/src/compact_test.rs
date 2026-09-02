use std::fmt::Write as _;

use super::{
    ALGORITHM_VERSION, CompactError, Compacted, FailureKeyword, Fragment, FragmentKind,
    MAX_SOURCE_BYTES, MAX_SOURCE_RECORDS, OmissionReason, Policy, RetentionReason, compact,
    estimate_tokens, sha256_hex,
};

/// `value` as a `u64`; every count in these fixtures is small.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

/// Compacts with the shipped defaults and a successful exit status.
fn run(input: &[u8]) -> Compacted {
    compact(input, Some(0), &Policy::default()).unwrap()
}

/// The retention reasons of a fragment that must be retained.
fn reasons(fragment: &Fragment) -> &[RetentionReason] {
    match &fragment.kind {
        FragmentKind::Retained { reasons } => reasons,
        FragmentKind::Omitted { .. } => panic!("fragment {fragment:?} is retained"),
    }
}

/// The reason and record count of a fragment that must be omitted.
fn omission(fragment: &Fragment) -> (&OmissionReason, u64) {
    match &fragment.kind {
        FragmentKind::Omitted {
            reason,
            record_count,
        } => (reason, *record_count),
        FragmentKind::Retained { .. } => panic!("fragment {fragment:?} is omitted"),
    }
}

/// The rendered text of every fragment, in order, without the footer.
fn rendered(report: &Compacted) -> Vec<&str> {
    report
        .fragments
        .iter()
        .map(|fragment| fragment.rendered.as_str())
        .collect()
}

/// `count` distinct lines, none of which carries a failure keyword.
fn distinct_lines(count: usize) -> String {
    let mut lines = String::new();
    for index in 0..count {
        writeln!(lines, "line {index}").unwrap();
    }
    lines
}

#[test]
fn lf_crlf_and_bare_cr_frame_records() {
    let report = run(b"a\nb\r\nc\rd\re\n");

    assert_eq!(report.source_records, 5);
    assert_eq!(report.retained_records, 3);
    assert_eq!(
        rendered(&report),
        [
            "a\n",
            "b\n",
            "[... 2 progress frames superseded ...]\n",
            "e\n",
        ]
    );
    assert_eq!(
        omission(&report.fragments[2]),
        (&OmissionReason::SupersededProgress, 2)
    );
}

#[test]
fn ansi_and_control_bytes_render_in_display_form() {
    let input = b"\x1b[31mred\x1b[0m\ttab\x01\n";

    let report = run(input);

    assert_eq!(report.fragments.len(), 1);
    assert_eq!(report.fragments[0].rendered, "red\\ttab\\x01\n");
    assert_eq!(report.fragments[0].offset, 0);
    assert_eq!(report.fragments[0].length, as_u64(input.len()));
    assert_eq!(report.source_bytes, as_u64(input.len()));
}

#[test]
fn adjacent_repeats_collapse_and_reset_after_an_omission() {
    let report = run(b"x\nx\nx\ny\n");

    assert_eq!(report.source_records, 4);
    assert_eq!(report.retained_records, 2);
    assert_eq!(
        rendered(&report),
        ["x\n", "[... 2 repeated records collapsed ...]\n", "y\n"]
    );
    assert_eq!(
        omission(&report.fragments[1]),
        (&OmissionReason::Repeated, 2)
    );
}

#[test]
fn progress_frames_are_superseded_by_what_overwrites_them() {
    let overwritten_by_a_line = run(b"10%\r20%\r30%\rdone\n");
    assert_eq!(overwritten_by_a_line.source_records, 4);
    assert_eq!(
        rendered(&overwritten_by_a_line),
        ["[... 3 progress frames superseded ...]\n", "done\n"]
    );
    assert_eq!(
        omission(&overwritten_by_a_line.fragments[0]),
        (&OmissionReason::SupersededProgress, 3)
    );

    let overwritten_by_a_crlf_line = run(b"10%\r20%\r\n");
    assert_eq!(overwritten_by_a_crlf_line.source_records, 2);
    assert_eq!(
        rendered(&overwritten_by_a_crlf_line),
        ["[... 1 progress frames superseded ...]\n", "20%\n"]
    );

    let run_at_the_end_of_the_input = run(b"10%\r20%\r");
    assert_eq!(run_at_the_end_of_the_input.source_records, 2);
    assert_eq!(
        rendered(&run_at_the_end_of_the_input),
        ["[... 1 progress frames superseded ...]\n", "20%\n"]
    );
}

#[test]
fn boundaries_keep_the_first_and_last_windows() {
    let input = distinct_lines(100);
    let policy = Policy {
        boundary_records: 3,
        failure_context_records: 0,
    };

    let report = compact(input.as_bytes(), Some(0), &policy).unwrap();

    assert_eq!(report.source_records, 100);
    assert_eq!(report.retained_records, 6);
    assert_eq!(report.fragments.len(), 7);
    for fragment in &report.fragments[..3] {
        assert_eq!(reasons(fragment), [RetentionReason::FirstBoundary]);
    }
    assert_eq!(
        omission(&report.fragments[3]),
        (&OmissionReason::OutsideRetentionWindow, 94)
    );
    assert_eq!(
        report.fragments[3].rendered,
        "[... 94 records outside retention windows ...]\n"
    );
    for fragment in &report.fragments[4..] {
        assert_eq!(reasons(fragment), [RetentionReason::LastBoundary]);
    }
}

#[test]
fn failure_lines_keep_their_neighbourhood_case_insensitively() {
    let mut lines = (0..30)
        .map(|index| format!("line {index}\n"))
        .collect::<Vec<_>>();
    lines[15] = "Build FAILED: link error\n".to_owned();
    let input = lines.concat();
    let policy = Policy {
        boundary_records: 0,
        failure_context_records: 2,
    };

    let report = compact(input.as_bytes(), Some(1), &policy).unwrap();

    assert_eq!(report.retained_records, 5);
    assert_eq!(report.fragments.len(), 7);
    assert_eq!(
        omission(&report.fragments[0]),
        (&OmissionReason::OutsideRetentionWindow, 13)
    );
    assert_eq!(
        rendered(&report)[1..6],
        [
            "line 13\n",
            "line 14\n",
            "Build FAILED: link error\n",
            "line 16\n",
            "line 17\n",
        ]
    );
    for fragment in &report.fragments[1..6] {
        assert_eq!(
            reasons(fragment),
            [
                RetentionReason::FailureNeighborhood {
                    keyword: FailureKeyword::Error
                },
                RetentionReason::FailureNeighborhood {
                    keyword: FailureKeyword::Failed
                },
            ]
        );
    }
    assert_eq!(
        omission(&report.fragments[6]),
        (&OmissionReason::OutsideRetentionWindow, 12)
    );
}

#[test]
fn failure_windows_clamp_at_both_ends() {
    let policy = Policy {
        boundary_records: 0,
        failure_context_records: 5,
    };

    let report = compact(b"error\nb\nc\n", Some(1), &policy).unwrap();

    assert_eq!(report.source_records, 3);
    assert_eq!(report.retained_records, 3);
    assert_eq!(rendered(&report), ["error\n", "b\n", "c\n"]);
}

#[test]
fn every_byte_belongs_to_exactly_one_ordered_fragment() {
    let mut input = String::new();
    input.push_str("\x1b[32mstarting\x1b[0m\n");
    input.push_str("10%\r20%\r30%\r\n");
    input.push_str("same\nsame\nsame\n");
    input.push_str(&distinct_lines(60));
    input.push_str("error: link failed\n");
    input.push_str("tail without a newline");

    let report = run(input.as_bytes());

    assert_eq!(report.source_bytes, as_u64(input.len()));
    let mut cursor = 0;
    for fragment in &report.fragments {
        assert_eq!(fragment.offset, cursor);
        cursor += fragment.length;
    }
    assert_eq!(cursor, report.source_bytes);

    let retained_bytes = report
        .fragments
        .iter()
        .filter(|fragment| matches!(fragment.kind, FragmentKind::Retained { .. }))
        .map(|fragment| fragment.length)
        .sum::<u64>();
    assert_eq!(report.retained_bytes, retained_bytes);
    let retained_fragments = report
        .fragments
        .iter()
        .filter(|fragment| matches!(fragment.kind, FragmentKind::Retained { .. }))
        .count();
    let retained_fragments = as_u64(retained_fragments);
    assert_eq!(report.retained_records, retained_fragments);
    assert!(report.retained_bytes < report.source_bytes);
}

#[test]
fn empty_input_renders_the_no_output_line_and_exit_status() {
    let report = run(b"");

    assert_eq!(report.rendered_text, "[no log output]\n[exit status: 0]\n");
    assert!(report.fragments.is_empty());
    assert_eq!(report.source_records, 0);
    assert_eq!(report.source_bytes, 0);
    assert_eq!(report.retained_bytes, 0);
}

#[test]
fn unknown_exit_status_renders_unknown() {
    let report = compact(b"ok\n", None, &Policy::default()).unwrap();

    assert_eq!(report.exit_status, None);
    assert!(report.rendered_text.ends_with("[exit status: unknown]\n"));
}

#[test]
fn same_input_same_output() {
    let input = b"build\nerror: boom\n10%\r20%\rdone\n";

    let first = run(input);
    let second = run(input);

    assert_eq!(first, second);
    assert_eq!(first.source_sha256, sha256_hex(input));
    assert_eq!(first.algorithm_version, ALGORITHM_VERSION);
}

#[test]
fn too_large_and_too_many_records_are_refused_before_work() {
    let too_many = vec![b'\n'; MAX_SOURCE_RECORDS + 1];
    let records_error = compact(&too_many, Some(0), &Policy::default()).unwrap_err();
    assert_eq!(
        records_error,
        CompactError::TooManyRecords {
            maximum_records: 100_000
        }
    );
    assert_eq!(records_error.cause(), "too_many_records");

    let too_large = vec![0u8; MAX_SOURCE_BYTES + 1];
    let size_error = compact(&too_large, Some(0), &Policy::default()).unwrap_err();
    assert_eq!(
        size_error,
        CompactError::SourceTooLarge {
            actual_bytes: as_u64(MAX_SOURCE_BYTES) + 1,
            maximum_bytes: as_u64(MAX_SOURCE_BYTES),
        }
    );
    assert_eq!(size_error.cause(), "source_too_large");
}

#[test]
fn policy_bounds_are_validated() {
    let context = Policy {
        boundary_records: 20,
        failure_context_records: 65,
    };
    let error = compact(b"ok\n", Some(0), &context).unwrap_err();
    assert_eq!(
        error,
        CompactError::InvalidPolicy {
            field: "failure_context_records"
        }
    );
    assert_eq!(error.cause(), "invalid_policy");

    let boundary = Policy {
        boundary_records: MAX_SOURCE_RECORDS + 1,
        failure_context_records: 3,
    };
    assert_eq!(
        compact(b"ok\n", Some(0), &boundary).unwrap_err(),
        CompactError::InvalidPolicy {
            field: "boundary_records"
        }
    );
}

#[test]
fn estimate_tokens_rounds_up() {
    assert_eq!(estimate_tokens(0), 0);
    assert_eq!(estimate_tokens(1), 1);
    assert_eq!(estimate_tokens(4), 1);
    assert_eq!(estimate_tokens(5), 2);
}

#[test]
fn report_serializes_to_json_and_back() {
    let report = run(b"start\n10%\r20%\rerror: boom\nsame\nsame\n");

    let json = serde_json::to_string(&report).unwrap();
    let parsed: Compacted = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed, report);
}
