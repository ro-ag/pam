use std::{ffi::OsString, fs, path::PathBuf};

use pam_core::ProjectId;
use pam_protocol::{OperationTruth, SourceAvailability};
use pam_store::{Store, StoreError};
use tokio::io::AsyncWriteExt as _;

use super::{
    BriefProvider,
    ptrack::{
        ContextDigest, PtrackBriefProvider, context_handle, read_bounded,
        validate_registered_project,
    },
};

fn context_json() -> Vec<u8> {
    br#"{
      "goal": "Ship durable continuity",
      "summary": "Queue recovery was verified.",
      "active_plan": {
        "id": 3,
        "title": "Durable project continuity",
        "open_tasks": [
          {"id": 14, "plan_id": 3, "title": "Finish commands", "status": "doing", "hold_reason": null},
          {"id": 15, "plan_id": 3, "title": "Integrate ptrack", "status": "todo", "hold_reason": null}
        ],
        "hold_reason": null
      },
      "blocked": null,
      "blocked_more": 0,
      "on_hold": null,
      "on_hold_more": 0,
      "open_issues": [{"id": 7, "title": "Retain proof", "severity": "high", "status": "open", "task_id": 15}],
      "open_issues_more": 0,
      "recent_notes": [{"id": 31, "target": "task", "target_id": 13, "kind": "decision", "body": "Keep exact evidence."}],
      "inventory": {"Tasks": 42}
    }"#
    .to_vec()
}

#[test]
fn supported_context_json_maps_to_truthful_bounded_sections() {
    let bytes = context_json();
    let handle = context_handle(&bytes);
    let brief = serde_json::from_slice::<ContextDigest>(&bytes)
        .unwrap()
        .into_brief(handle.clone());

    assert_eq!(brief.goal.unwrap().text, "Ship durable continuity");
    assert_eq!(brief.decisions[0].text, "task #13: Keep exact evidence.");
    assert_eq!(brief.decisions[0].truth, OperationTruth::Observed);
    assert_eq!(brief.verified[0].truth, OperationTruth::Observed);
    assert_eq!(brief.next[0].text, "#14 [doing] Finish commands");
    assert_eq!(brief.next[0].truth, OperationTruth::Unresolved);
    assert_eq!(brief.next[2].text, "issue #7 [severity=high] Retain proof");
    assert!(
        brief
            .next
            .iter()
            .all(|item| item.evidence == [handle.clone()])
    );
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Available
    );
    assert_eq!(brief.provenance[0].evidence, Some(handle));
}

#[test]
fn registered_project_validation_requires_the_exact_pam_root() {
    let root = PathBuf::from("/projects/pam");
    let projects = br#"[
      {"Name":"pam","Path":"/projects/pam","LastSeen":"now"},
      {"Name":"other","Path":"/projects/other","LastSeen":"now"}
    ]"#;

    validate_registered_project(projects, &root).unwrap();
    assert!(validate_registered_project(projects, &PathBuf::from("/projects/pam/nested")).is_err());
    assert!(validate_registered_project(b"{}", &root).is_err());
}

#[tokio::test]
async fn subprocess_output_reader_drains_but_retains_only_the_bound() {
    let (mut writer, reader) = tokio::io::duplex(32);
    let producer = tokio::spawn(async move {
        writer.write_all(&[b'x'; 129]).await.unwrap();
    });

    let output = read_bounded(reader, 64).await.unwrap();

    producer.await.unwrap();
    assert_eq!(output.bytes, [b'x'; 64]);
    assert!(output.exceeded);
}

#[test]
fn oversized_fields_and_sections_are_truncated_and_marked_partial() {
    let tasks = (0..20)
        .map(|id| {
            serde_json::json!({
                "id": id,
                "plan_id": 3,
                "title": "bounded task",
                "status": "todo",
                "hold_reason": null
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "goal": "é".repeat(3_000),
        "summary": "summary",
        "active_plan": {
            "id": 3,
            "title": "Durable project continuity",
            "open_tasks": tasks,
            "hold_reason": null
        },
        "blocked": null,
        "blocked_more": 0,
        "on_hold": null,
        "on_hold_more": 0,
        "open_issues": null,
        "open_issues_more": 2,
        "recent_notes": null,
        "inventory": {"Tasks": 42}
    }))
    .unwrap();
    let context = serde_json::from_slice::<ContextDigest>(&bytes).unwrap();
    let brief = context.into_brief(context_handle(b"bounded"));

    assert!(brief.goal.unwrap().text.len() <= 4 * 1024);
    assert_eq!(brief.next.len(), 16);
    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Partial
    );
    assert!(
        brief.provenance[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("truncated or omitted")
    );
}

#[tokio::test]
async fn provider_does_not_invoke_or_expose_a_source_for_another_project() {
    let directory = test_directory("ptrack-project-scope");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let store = Store::open(directory.join("state.sqlite3")).unwrap();
    let provider = PtrackBriefProvider::with_executable(
        directory.clone(),
        ProjectId::from("project-a"),
        OsString::from("missing-ptrack-that-must-not-run"),
    );

    let brief = provider.brief(&ProjectId::from("project-b"), &store).await;

    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Unavailable
    );
    assert!(brief.provenance[0].evidence.is_none());
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn provider_reports_a_missing_supported_cli_without_storing_evidence() {
    let directory = test_directory("ptrack-missing-cli");
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).unwrap();
    let store = Store::open(directory.join("state.sqlite3")).unwrap();
    let project_id = ProjectId::from("project-a");
    let provider = PtrackBriefProvider::with_executable(
        directory.clone(),
        project_id.clone(),
        OsString::from("missing-ptrack-provider-test"),
    );

    let brief = provider.brief(&project_id, &store).await;

    assert_eq!(
        brief.provenance[0].availability,
        SourceAvailability::Unavailable
    );
    assert!(brief.provenance[0].evidence.is_none());
    assert!(matches!(
        store
            .inspect_evidence(
                project_id,
                pam_core::EvidenceHandle::parse("evidence://ptrack/context/missing").unwrap(),
            )
            .await,
        Err(StoreError::EvidenceNotFound { .. })
    ));
    store.shutdown().await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

fn test_directory(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pam-{name}-{}", std::process::id()))
}
