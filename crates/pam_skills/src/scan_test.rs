use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use super::scan::{ScanDiagnosticKind, ScanLimits, ScanSession, merge_scan_reports};
use crate::{AgentArtifact, ArtifactKind, ArtifactScope, LoadSemantics, OriginAgent, ScanReport};
use pam_core::ContentDigest;

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(1);

pub(crate) struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub(crate) fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pam-skills-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn scanner_hashes_exact_raw_bytes_and_accepts_line_endings() {
    let directory = TestDirectory::new("raw-hash");
    directory.write("lf.md", b"one\ntwo\n");
    directory.write("crlf.md", b"one\r\ntwo\r\n");

    let mut scanner = ScanSession::new(ScanLimits::default());
    let root = scanner.open_root(directory.path(), "", "test").unwrap();
    let lf = scanner
        .read_optional_file(&root, Path::new("lf.md"))
        .unwrap();
    let crlf = scanner
        .read_optional_file(&root, Path::new("crlf.md"))
        .unwrap();

    assert_eq!(lf.bytes, b"one\ntwo\n");
    assert_eq!(crlf.bytes, b"one\r\ntwo\r\n");
    assert_ne!(lf.content_hash, crlf.content_hash);
    assert!(scanner.finish().complete());
}

#[test]
fn scanner_enforces_file_and_aggregate_byte_limits() {
    let directory = TestDirectory::new("byte-limits");
    directory.write("large.md", b"12345");
    directory.write("first.md", b"123");
    directory.write("second.md", b"456");

    let mut scanner = ScanSession::new(ScanLimits {
        max_file_bytes: 4,
        max_aggregate_bytes: 5,
        ..ScanLimits::default()
    });
    let root = scanner.open_root(directory.path(), "", "test").unwrap();
    assert!(
        scanner
            .read_optional_file(&root, Path::new("large.md"))
            .is_none()
    );
    assert!(
        scanner
            .read_optional_file(&root, Path::new("first.md"))
            .is_some()
    );
    assert!(
        scanner
            .read_optional_file(&root, Path::new("second.md"))
            .is_none()
    );

    let report = scanner.finish();
    let kinds = report
        .diagnostics()
        .iter()
        .map(super::ScanDiagnostic::kind)
        .collect::<Vec<_>>();
    assert!(kinds.contains(&ScanDiagnosticKind::FileTooLarge));
    assert!(kinds.contains(&ScanDiagnosticKind::AggregateBytesExceeded));
    assert!(!report.complete());
}

#[test]
fn recursive_walk_enforces_traversal_depth() {
    let directory = TestDirectory::new("depth-limit");
    directory.write("rules/a/b/deep.md", b"rule");

    let mut scanner = ScanSession::new(ScanLimits {
        max_traversal_depth: 1,
        ..ScanLimits::default()
    });
    let root = scanner.open_root(directory.path(), "", "test").unwrap();
    let files = scanner.walk_files(&root, Path::new("rules"), |_| true);
    assert!(files.is_empty());

    let report = scanner.finish();
    assert!(report.diagnostics().iter().any(|diagnostic| {
        diagnostic.kind() == ScanDiagnosticKind::TraversalDepthExceeded
            && diagnostic.logical_path() == "rules/a/b"
    }));
    assert!(!report.complete());
}

#[test]
fn directory_entry_limit_accepts_exact_top_level_and_recursive_boundaries() {
    let directory = TestDirectory::new("entry-limit-boundary");
    directory.write("top/c.md", b"c");
    directory.write("top/a.md", b"a");
    directory.write("top/b.md", b"b");
    directory.write("rules/a.md", b"a");
    directory.write("rules/nested/b.md", b"b");

    let limits = ScanLimits {
        max_directory_entries: 3,
        ..ScanLimits::default()
    };
    let mut top_level = ScanSession::new(limits);
    let root = top_level.open_root(directory.path(), "", "test").unwrap();
    assert_eq!(
        top_level.list_files(&root, Path::new("top"), |_| true),
        [
            PathBuf::from("top/a.md"),
            PathBuf::from("top/b.md"),
            PathBuf::from("top/c.md"),
        ]
    );
    assert!(top_level.finish().complete());

    let mut recursive = ScanSession::new(limits);
    let root = recursive.open_root(directory.path(), "", "test").unwrap();
    assert_eq!(
        recursive.walk_files(&root, Path::new("rules"), |_| true),
        [
            PathBuf::from("rules/a.md"),
            PathBuf::from("rules/nested/b.md"),
        ]
    );
    assert!(recursive.finish().complete());
}

#[test]
fn directory_entry_limit_rejects_one_over_without_unbounded_collection() {
    let directory = TestDirectory::new("entry-limit-one-over");
    for name in ["d.md", "a.md", "c.md", "b.md"] {
        directory.write(&format!("top/{name}"), name.as_bytes());
    }
    directory.write("rules/a.md", b"a");
    directory.write("rules/nested/b.md", b"b");
    directory.write("rules/nested/c.md", b"c");

    let limits = ScanLimits {
        max_directory_entries: 3,
        ..ScanLimits::default()
    };
    let mut top_level = ScanSession::new(limits);
    let root = top_level.open_root(directory.path(), "", "test").unwrap();
    assert!(
        top_level
            .list_files(&root, Path::new("top"), |_| true)
            .is_empty()
    );
    let report = top_level.finish();
    assert_eq!(report.diagnostics().len(), 1);
    assert_eq!(
        report.diagnostics()[0].kind(),
        ScanDiagnosticKind::DirectoryEntryLimitExceeded
    );
    assert_eq!(report.diagnostics()[0].logical_path(), "top");
    assert!(!report.complete());

    let mut recursive = ScanSession::new(limits);
    let root = recursive.open_root(directory.path(), "", "test").unwrap();
    assert_eq!(
        recursive.walk_files(&root, Path::new("rules"), |_| true),
        [PathBuf::from("rules/a.md")]
    );
    let report = recursive.finish();
    assert_eq!(report.diagnostics().len(), 1);
    assert_eq!(
        report.diagnostics()[0].kind(),
        ScanDiagnosticKind::DirectoryEntryLimitExceeded
    );
    assert_eq!(report.diagnostics()[0].logical_path(), "rules/nested");
    assert!(!report.complete());
}

fn normalized(path: &str, byte: u8) -> AgentArtifact {
    AgentArtifact::new(
        path,
        path,
        ArtifactKind::Rule,
        ArtifactScope::Project,
        OriginAgent::Cursor,
        LoadSemantics::Always,
        ContentDigest::from_sha256([byte; 32]),
    )
    .unwrap()
}

fn report_with_retained_source(path: &str, byte: u8, source: &[u8]) -> ScanReport {
    let artifact = normalized(path, byte);
    let mut session = ScanSession::new(ScanLimits::default());
    session.push_artifact_with_content(artifact, source.to_vec());
    session.finish()
}

#[test]
fn report_merge_accepts_exact_multi_report_retained_source_boundary() {
    let limits = ScanLimits {
        max_aggregate_bytes: 5,
        ..ScanLimits::default()
    };
    let merged = merge_scan_reports(
        [
            report_with_retained_source("a.mdc", 1, b"12"),
            report_with_retained_source("b.mdc", 2, b"345"),
        ],
        limits,
    );

    assert!(merged.complete(), "{:?}", merged.diagnostics());
    assert_eq!(merged.artifacts().len(), 2);
    for artifact in merged.artifacts() {
        assert!(merged.always_loaded_source(&artifact.id()).is_some());
    }
}

#[test]
fn report_merge_retains_non_always_sources_without_serializing_or_debugging_bytes() {
    let private_source = b"private model-selected source body";
    let artifact = AgentArtifact::new(
        "selected",
        "selected.mdc",
        ArtifactKind::Rule,
        ArtifactScope::Project,
        OriginAgent::Cursor,
        LoadSemantics::ModelSelected,
        ContentDigest::from_sha256([9; 32]),
    )
    .unwrap();
    let artifact_id = artifact.id();
    let mut session = ScanSession::new(ScanLimits::default());
    session.push_artifact_with_content(artifact, private_source.to_vec());

    let merged = merge_scan_reports([session.finish()], ScanLimits::default());

    assert_eq!(
        merged.artifact_source(&artifact_id),
        Some(private_source.as_slice())
    );
    for rendered in [
        serde_json::to_string(&merged).unwrap(),
        format!("{merged:?}"),
    ] {
        assert!(!rendered.contains("private model-selected source body"));
    }
    assert!(format!("{merged:?}").contains("<redacted:1 sources>"));
}

#[test]
fn report_merge_rejects_one_over_global_retained_source_budget_atomically() {
    let limits = ScanLimits {
        max_aggregate_bytes: 5,
        ..ScanLimits::default()
    };
    let merged = merge_scan_reports(
        [
            report_with_retained_source("a.mdc", 1, b"123"),
            report_with_retained_source("b.mdc", 2, b"456"),
        ],
        limits,
    );

    assert!(!merged.complete());
    assert_eq!(
        merged
            .artifacts()
            .iter()
            .map(AgentArtifact::logical_path)
            .collect::<Vec<_>>(),
        ["a.mdc", "b.mdc"]
    );
    assert_eq!(merged.diagnostics().len(), 1);
    assert_eq!(
        merged.diagnostics()[0].kind(),
        ScanDiagnosticKind::AggregateBytesExceeded
    );
    assert_eq!(merged.diagnostics()[0].logical_path(), "b.mdc");
    let first = merged
        .artifacts()
        .iter()
        .find(|artifact| artifact.logical_path() == "a.mdc")
        .unwrap();
    let second = merged
        .artifacts()
        .iter()
        .find(|artifact| artifact.logical_path() == "b.mdc")
        .unwrap();
    assert_eq!(
        merged.always_loaded_source(&first.id()),
        Some(b"123".as_slice())
    );
    assert_eq!(merged.always_loaded_source(&second.id()), None);
}

#[test]
fn report_merge_is_atomic_deterministic_and_rejects_conflicting_identity() {
    let left = ScanReport::from_artifacts([normalized("z.mdc", 1)]);
    let right = ScanReport::from_artifacts([normalized("a.mdc", 1)]);
    let merged = ScanReport::merge([left, right]);
    assert!(merged.complete());
    assert_eq!(
        merged
            .artifacts()
            .iter()
            .map(AgentArtifact::logical_path)
            .collect::<Vec<_>>(),
        ["a.mdc", "z.mdc"]
    );

    let conflict = ScanReport::merge([
        ScanReport::from_artifacts([normalized("same.mdc", 1)]),
        ScanReport::from_artifacts([normalized("same.mdc", 2)]),
    ]);
    assert!(!conflict.complete());
    assert_eq!(conflict.artifacts().len(), 1);
    assert!(
        conflict.diagnostics().iter().any(|diagnostic| {
            diagnostic.kind() == ScanDiagnosticKind::DuplicateArtifactIdentity
        })
    );
}
