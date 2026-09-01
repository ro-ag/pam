use std::fs;
use std::path::Path;

use crate::logs::{LogTail, MAX_LINES, MIN_LINES, clamp_lines, tail_daemon_log};

/// Builds `<base>/log/<name>` with one line per entry in `lines`.
fn write_log(base: &Path, name: &str, lines: &[&str]) {
    let dir = base.join("log");
    fs::create_dir_all(&dir).expect("log dir builds");
    fs::write(dir.join(name), lines.join("\n") + "\n").expect("log file writes");
}

#[test]
fn line_counts_clamp_into_the_window() {
    assert_eq!(clamp_lines(0), MIN_LINES);
    assert_eq!(clamp_lines(49), MIN_LINES);
    assert_eq!(clamp_lines(50), 50);
    assert_eq!(clamp_lines(500), 500);
    assert_eq!(clamp_lines(1_000), MAX_LINES);
    assert_eq!(clamp_lines(u32::MAX), MAX_LINES);
}

#[test]
fn picks_the_newest_dated_file_by_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_log(tmp.path(), "daemon.log.2026-08-30", &["old line"]);
    write_log(tmp.path(), "daemon.log.2026-09-01", &["new line"]);
    write_log(tmp.path(), "daemon.log.2026-08-31", &["middle line"]);

    let tail = tail_daemon_log(tmp.path(), 100).expect("tail reads");
    assert!(
        tail.file.ends_with("daemon.log.2026-09-01"),
        "newest date must win, got {}",
        tail.file
    );
    assert_eq!(tail.lines, vec!["new line".to_owned()]);
}

#[test]
fn ignores_files_outside_the_daemon_log_prefix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_log(tmp.path(), "daemon.log.2026-09-01", &["real"]);
    // Lexicographically later than any daemon.log name, but not a log.
    write_log(tmp.path(), "zz-other.txt", &["decoy"]);

    let tail = tail_daemon_log(tmp.path(), 100).expect("tail reads");
    assert!(tail.file.ends_with("daemon.log.2026-09-01"));
    assert_eq!(tail.lines, vec!["real".to_owned()]);
}

#[test]
fn returns_the_last_n_lines_oldest_first() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lines: Vec<String> = (1..=120).map(|n| format!("line {n}")).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    write_log(tmp.path(), "daemon.log.2026-09-01", &refs);

    // Asking under the floor clamps up to MIN_LINES.
    let tail = tail_daemon_log(tmp.path(), 1).expect("tail reads");
    assert_eq!(tail.lines.len(), MIN_LINES as usize);
    assert_eq!(tail.lines.first().unwrap(), "line 71");
    assert_eq!(tail.lines.last().unwrap(), "line 120");
}

#[test]
fn oversized_requests_clamp_to_the_ceiling() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lines: Vec<String> = (1..=1_200).map(|n| format!("line {n}")).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    write_log(tmp.path(), "daemon.log.2026-09-01", &refs);

    let tail = tail_daemon_log(tmp.path(), u32::MAX).expect("tail reads");
    assert_eq!(tail.lines.len(), MAX_LINES as usize);
    assert_eq!(tail.lines.first().unwrap(), "line 201");
    assert_eq!(tail.lines.last().unwrap(), "line 1200");
}

#[test]
fn a_short_file_returns_everything_it_has() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_log(tmp.path(), "daemon.log.2026-09-01", &["only", "two"]);

    let tail = tail_daemon_log(tmp.path(), 500).expect("tail reads");
    assert_eq!(tail.lines, vec!["only".to_owned(), "two".to_owned()]);
}

#[test]
fn missing_log_dir_is_a_legible_refusal_not_a_crash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // No log/ directory at all — a fresh install.
    let err = tail_daemon_log(tmp.path(), 100).expect_err("must refuse");
    assert_eq!(err.cause, "no_daemon_log");
    assert!(err.detail.contains("no daemon log exists"));
    assert!(err.recovery.contains("Start the daemon"));
}

#[test]
fn empty_log_dir_refuses_the_same_way() {
    let tmp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(tmp.path().join("log")).expect("log dir builds");
    let err = tail_daemon_log(tmp.path(), 100).expect_err("must refuse");
    assert_eq!(err.cause, "no_daemon_log");
}

#[test]
fn the_tail_serializes_as_file_and_lines() {
    let tail = LogTail {
        file: "/tmp/x/log/daemon.log.2026-09-01".to_owned(),
        lines: vec!["INFO ready".to_owned()],
    };
    let value = serde_json::to_value(&tail).expect("serializes");
    assert_eq!(
        value,
        serde_json::json!({
            "file": "/tmp/x/log/daemon.log.2026-09-01",
            "lines": ["INFO ready"],
        })
    );
}
