use super::compression::{self, CompressionError, SourceSpan};

#[test]
fn selects_original_whole_records_with_exact_spans_and_budgeted_omissions() {
    let text = "start\nverbose padding that can be omitted\n重要 = 1.25 ms\nmore padding that can be omitted\nend\n";
    let (output, spans) = compression::select_lines(text, &[0.0, 0.1, 0.9, 0.1, 0.0], 70).unwrap();
    assert!(output.contains("重要 = 1.25 ms\n"));
    assert!(!output.contains("verbose"));
    assert!(output.len() <= 70);
    for span in &spans {
        assert!(output.contains(&text[span.start..span.end]));
    }
    assert_eq!(spans[0], SourceSpan { start: 0, end: 6 });
    assert!(spans.windows(2).all(|pair| pair[0].end < pair[1].start));
}

#[test]
fn pipeline_retry_and_terminal_records_override_low_model_scores() {
    let text = "begin\na\nb\nc\nd\n[Pipeline] retry\nf\ng\nh\ni\nj\nFinished: FAILURE\nend\n";
    let scores = vec![0.0; text.lines().count()];
    assert!(matches!(
        compression::select_lines(text, &scores, 30),
        Err(CompressionError::Budget)
    ));
    let (output, _) = compression::select_lines(text, &scores, text.len()).unwrap();
    assert_eq!(output, text);
}

#[test]
fn oversized_required_record_is_never_truncated() {
    let text = "error: artifact publish rejected, expected digest=12345\n";
    assert!(matches!(
        compression::select_lines(text, &[1.0], 12),
        Err(CompressionError::Budget)
    ));
}

#[test]
fn scores_words_instead_of_overweighting_wordpiece_count() {
    let text = "runner disconnected\ncomplete\n";
    let offsets = [(0, 6), (7, 10), (10, 15), (15, 19), (20, 28)];
    let tokens = ["runner", "dis", "##conne", "##cted", "complete"].map(str::to_string);
    let result =
        compression::score_lines(text, &offsets, &tokens, &[0.0, 1.0, 1.0, 1.0, 0.2]).unwrap();
    assert_eq!(result, vec![0.5, 0.2]);
}

#[test]
fn rejects_nonfinite_scores_and_untrusted_offsets() {
    let tokens = vec!["a".to_string()];
    assert!(compression::score_lines("a", &[(0, 1)], &tokens, &[f32::NAN]).is_err());
    for offsets in [
        vec![(0, 9)],
        vec![(1, 2)],
        vec![(0, 0)],
        vec![(0, 2), (0, 2)],
    ] {
        assert!(compression::validate_offsets("é", &offsets).is_err());
    }
    assert!(compression::score_lines("a\nb", &[(0, 3)], &tokens, &[0.5]).is_err());
    assert!(compression::select_lines("a", &[f32::INFINITY], 10).is_err());
}

#[test]
fn empty_and_complete_outputs_remain_exact() {
    assert_eq!(
        compression::select_lines("", &[], 0).unwrap(),
        (String::new(), vec![])
    );
    let text = "one\r\ntwo without final newline";
    assert_eq!(
        compression::select_lines(text, &[0.0, 0.0], text.len()).unwrap(),
        (
            text.into(),
            vec![SourceSpan {
                start: 0,
                end: text.len()
            }]
        )
    );
}

#[test]
fn cancellation_and_byte_limit_precede_asset_access() {
    let directory = tempfile::tempdir().unwrap();
    let (_sender, cancelled) = tokio::sync::watch::channel(true);
    assert!(matches!(
        compression::compress(directory.path(), "log", 10, &cancelled),
        Err(CompressionError::Cancelled)
    ));
    let (_sender, active) = tokio::sync::watch::channel(false);
    assert!(matches!(
        compression::compress(
            directory.path(),
            &"x".repeat(compression::MAX_INPUT_BYTES + 1),
            10,
            &active
        ),
        Err(CompressionError::InputLimit)
    ));
    assert!(!compression::installed(directory.path()));
    assert_eq!(
        compression::compress(directory.path(), "log", 10, &active)
            .unwrap_err()
            .cause(),
        "unavailable"
    );
}
