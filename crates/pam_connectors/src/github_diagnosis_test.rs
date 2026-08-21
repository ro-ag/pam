use std::{
    env, fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use pam_core::{ContentDigest, EvidenceHandle, ProjectId};
use pam_store::{EvidenceRedaction, EvidenceRetention, Store};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::github::{
    CollectRunLogs, CollectRunLogsRequest, CollectRunLogsResponse, GitHubActions,
    MAX_LOG_BYTES_PER_JOB, Repository, ReqwestGitHubTransport, RunId,
};
use super::github_diagnosis::{
    DiagnosisError, DiagnosisPersistence, DiagnosisStatus, ExactJobLog, FindingCategory,
    MAX_DIAGNOSIS_FINDINGS, MAX_DIAGNOSIS_LOGS, MAX_DIAGNOSIS_PROJECT_ID_BYTES, RunDiagnosis,
    diagnose_run,
};
use super::{
    BoundedSummary, CancellationToken, Connector, ConnectorOutput, ExactArtifact,
    InvocationContext, Truth,
};

const RUN_ID: u64 = 42;
const TEST_PROJECT: &str = "github-diagnosis-test";
static NEXT_DIAGNOSIS_STORE: AtomicU64 = AtomicU64::new(1);

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn exact_log(job_id: u64, bytes: &[u8]) -> ExactJobLog {
    ExactJobLog::new(job_id, bytes.to_vec()).unwrap()
}

fn canonical_handle(bytes: &[u8]) -> String {
    format!(
        "evidence://github-actions/log/{}",
        digest(bytes).sha256_hex()
    )
}

fn diagnosis_store(name: &str) -> (PathBuf, PathBuf, Store) {
    let fixture_id = NEXT_DIAGNOSIS_STORE.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!(
        "pam-connectors-{name}-{}-{fixture_id}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("pam.sqlite3");
    let store = Store::open(&path).unwrap();
    (root, path, store)
}

fn persistence(store: &Store) -> DiagnosisPersistence {
    DiagnosisPersistence::new(
        store.clone(),
        ProjectId::from(TEST_PROJECT),
        EvidenceRetention::Project,
        EvidenceRedaction::Unredacted,
        42,
    )
    .unwrap()
}

async fn diagnose(
    collection: &ConnectorOutput<CollectRunLogsResponse>,
    exact_logs: Vec<ExactJobLog>,
) -> Result<RunDiagnosis, DiagnosisError> {
    let (root, _, store) = diagnosis_store("diagnosis");
    let persistence = persistence(&store);
    let result = diagnose_run(collection, exact_logs, &persistence).await;
    drop(persistence);
    store.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
    result
}

fn response(entries: &[(u64, usize)], total_jobs: u64) -> CollectRunLogsResponse {
    let jobs = entries
        .iter()
        .map(|(job_id, _)| {
            json!({
                "id": job_id,
                "name": format!("job-{job_id}"),
                "status": "completed",
                "conclusion": "failure",
                "html_url": format!("https://github.com/ro-ag/pam/actions/runs/{RUN_ID}/job/{job_id}"),
                "steps": []
            })
        })
        .collect::<Vec<_>>();
    let logs = entries
        .iter()
        .map(|(job_id, byte_len)| {
            json!({
                "job_id": job_id,
                "artifact_name": format!("github-run-{RUN_ID}-job-{job_id}.log"),
                "byte_len": byte_len
            })
        })
        .collect::<Vec<_>>();
    serde_json::from_value(json!({
        "run": {
            "id": RUN_ID,
            "run_attempt": 1,
            "name": "CI",
            "status": "completed",
            "conclusion": "failure",
            "html_url": format!("https://github.com/ro-ag/pam/actions/runs/{RUN_ID}"),
            "head_branch": "main",
            "head_sha": "0123456789abcdef",
            "created_at": "2026-08-20T00:00:00Z",
            "updated_at": "2026-08-20T00:01:00Z"
        },
        "total_jobs": total_jobs,
        "jobs": jobs,
        "logs": logs
    }))
    .unwrap()
}

fn collection(
    response: CollectRunLogsResponse,
    complete: bool,
    payloads: Vec<(u64, Vec<u8>)>,
) -> ConnectorOutput<CollectRunLogsResponse> {
    let artifacts = payloads
        .into_iter()
        .map(|(job_id, bytes)| {
            ExactArtifact::new(format!("github-run-{RUN_ID}-job-{job_id}.log"), bytes).unwrap()
        })
        .collect();
    let truth = if complete {
        Truth::Complete
    } else {
        Truth::Partial {
            reason: BoundedSummary::new("one or more failed job logs were unavailable").unwrap(),
        }
    };
    ConnectorOutput::new(
        response,
        BoundedSummary::new("collected test logs").unwrap(),
        truth,
        Vec::new(),
        artifacts,
    )
    .unwrap()
}

#[tokio::test]
async fn findings_are_lexical_inferences_with_exact_hash_and_span_provenance() {
    let bytes = b"setup ok\nerror[E0308]: mismatched types\ntest result: FAILED. 1 failed\ncodesign validation failed\ndeadline exceeded\npermission denied\nerror: upstream response\n";
    let collection = collection(
        response(&[(7, bytes.len())], 1),
        true,
        vec![(7, bytes.to_vec())],
    );
    let diagnosis = diagnose(&collection, vec![exact_log(7, bytes)])
        .await
        .unwrap();

    assert_eq!(diagnosis.status(), DiagnosisStatus::Diagnosed);
    assert_eq!(diagnosis.logs().len(), 1);
    assert_eq!(diagnosis.findings().len(), 6);
    assert_eq!(
        diagnosis
            .findings()
            .iter()
            .map(super::github_diagnosis::DiagnosisFinding::category)
            .collect::<Vec<_>>(),
        vec![
            FindingCategory::Compilation,
            FindingCategory::Tests,
            FindingCategory::SigningOrPackaging,
            FindingCategory::Timeout,
            FindingCategory::Authorization,
            FindingCategory::RemoteOrUnknown,
        ]
    );
    for finding in diagnosis.findings() {
        assert!(finding.is_inference());
        assert_eq!(finding.job_id(), 7);
        assert_eq!(finding.evidence().handle.as_str(), canonical_handle(bytes));
        let start = usize::try_from(finding.evidence().offset).unwrap();
        let end = start + usize::try_from(finding.evidence().length).unwrap();
        assert!(end <= bytes.len());
        assert!(!&bytes[start..end].is_empty());
    }

    let compacted = diagnosis.logs()[0].compacted();
    assert_eq!(compacted.source.digest, digest(bytes));
    assert_eq!(compacted.source.handle.as_str(), canonical_handle(bytes));
    assert_eq!(
        compacted
            .fragments
            .iter()
            .map(|fragment| fragment.source.length)
            .sum::<u64>(),
        bytes.len() as u64
    );
    assert_eq!(compacted.fragments[0].source.offset, 0);
}

#[tokio::test]
async fn referenced_evidence_survives_store_restart_and_exact_range_read() {
    let bytes = b"setup ok\nerror[E0308]: mismatched types\ncleanup\n";
    let collection = collection(
        response(&[(7, bytes.len())], 1),
        true,
        vec![(7, bytes.to_vec())],
    );
    let (root, path, store) = diagnosis_store("durable-evidence");
    let persistence = persistence(&store);
    let diagnosis = diagnose_run(&collection, vec![exact_log(7, bytes)], &persistence)
        .await
        .unwrap();
    let reference = diagnosis.findings()[0].evidence().clone();
    drop(persistence);
    store.shutdown().await.unwrap();

    let reopened = Store::open(&path).unwrap();
    let project_id = ProjectId::from(TEST_PROJECT);
    let metadata = reopened
        .inspect_evidence(project_id.clone(), reference.handle.clone())
        .await
        .unwrap();
    assert_eq!(metadata.handle, reference.handle);
    assert_eq!(metadata.digest, digest(bytes));
    assert_eq!(metadata.project_id, project_id);
    assert_eq!(metadata.retention, EvidenceRetention::Project);
    assert_eq!(metadata.redaction, EvidenceRedaction::Unredacted);
    assert_eq!(metadata.created_at_ms, 42);
    assert!(
        reopened
            .inspect_evidence(ProjectId::from("other-project"), reference.handle.clone(),)
            .await
            .is_err()
    );
    let cited = reopened
        .read_evidence_range(
            ProjectId::from(TEST_PROJECT),
            reference.handle,
            reference.offset,
            reference.length,
        )
        .await
        .unwrap();
    let start = usize::try_from(reference.offset).unwrap();
    let end = start + usize::try_from(reference.length).unwrap();
    assert_eq!(cited, bytes[start..end]);
    reopened.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn invalid_batch_is_rejected_before_any_evidence_is_persisted() {
    let first = b"error: first\n";
    let second = b"error: second\n";
    let replacement = b"fatal: alterd\n";
    assert_eq!(replacement.len(), second.len());
    let collection = collection(
        response(&[(1, first.len()), (2, second.len())], 2),
        true,
        vec![(1, first.to_vec()), (2, second.to_vec())],
    );
    let (root, _, store) = diagnosis_store("invalid-batch");
    let persistence = persistence(&store);
    assert!(matches!(
        diagnose_run(
            &collection,
            vec![exact_log(1, first), exact_log(2, replacement)],
            &persistence,
        )
        .await,
        Err(DiagnosisError::ArtifactPayloadMismatch { job_id: 2 })
    ));
    let first_handle = EvidenceHandle::parse(canonical_handle(first)).unwrap();
    assert!(
        store
            .inspect_evidence(ProjectId::from(TEST_PROJECT), first_handle)
            .await
            .is_err()
    );
    drop(persistence);
    store.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn persistence_context_rejects_unbounded_identity_and_timestamp() {
    let (root, _, store) = diagnosis_store("invalid-persistence-context");
    assert!(matches!(
        DiagnosisPersistence::new(
            store.clone(),
            ProjectId::from("x".repeat(MAX_DIAGNOSIS_PROJECT_ID_BYTES + 1)),
            EvidenceRetention::Project,
            EvidenceRedaction::Unredacted,
            42,
        ),
        Err(DiagnosisError::InvalidPersistenceProject)
    ));
    assert!(matches!(
        DiagnosisPersistence::new(
            store.clone(),
            ProjectId::from(TEST_PROJECT),
            EvidenceRetention::Project,
            EvidenceRedaction::Unredacted,
            u64::MAX,
        ),
        Err(DiagnosisError::InvalidPersistenceTimestamp)
    ));
    store.shutdown().await.unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn canonical_manifest_is_byte_stable_and_contains_exact_provenance() {
    let bytes = b"compile\nerror[E0425]: missing value\n";
    let collection = collection(
        response(&[(9, bytes.len())], 1),
        true,
        vec![(9, bytes.to_vec())],
    );
    let first = diagnose(&collection, vec![exact_log(9, bytes)])
        .await
        .unwrap();
    let second = diagnose(&collection, vec![exact_log(9, bytes)])
        .await
        .unwrap();
    assert_eq!(first.manifest().bytes(), second.manifest().bytes());
    assert_eq!(first.manifest().name(), "github-run-42-diagnosis.json");

    let manifest: Value = serde_json::from_slice(first.manifest().bytes()).unwrap();
    assert_eq!(manifest["schema_version"], "pam-github-diagnosis-v1");
    assert_eq!(manifest["run_id"], RUN_ID);
    assert_eq!(manifest["input_complete"], true);
    assert_eq!(manifest["status"], "diagnosed");
    assert_eq!(
        manifest["logs"][0]["source"]["handle"],
        canonical_handle(bytes)
    );
    assert_eq!(
        manifest["logs"][0]["source"]["digest"],
        digest(bytes).as_str()
    );
    assert_eq!(manifest["findings"][0]["inference"], true);
    assert_eq!(manifest["findings"][0]["evidence"]["offset"], 8);
}

#[tokio::test]
async fn partial_input_never_becomes_diagnosed_and_benign_complete_input_is_unresolved() {
    let failing = b"error[E0308]: mismatch\n";
    let partial_collection = collection(
        response(&[(1, failing.len())], 1),
        false,
        vec![(1, failing.to_vec())],
    );
    let partial = diagnose(&partial_collection, vec![exact_log(1, failing)])
        .await
        .unwrap();
    assert_eq!(partial.status(), DiagnosisStatus::Partial);
    assert_eq!(partial.findings().len(), 1);
    assert!(partial.summary().as_str().starts_with("partial"));

    let benign = b"checkout complete\nbuild cache restored\nall steps completed\n";
    let complete_collection = collection(
        response(&[(2, benign.len())], 1),
        true,
        vec![(2, benign.to_vec())],
    );
    let unresolved = diagnose(&complete_collection, vec![exact_log(2, benign)])
        .await
        .unwrap();
    assert_eq!(unresolved.status(), DiagnosisStatus::Unresolved);
    assert!(unresolved.findings().is_empty());
}

#[tokio::test]
async fn findings_are_deduplicated_and_truncated_to_the_global_bound() {
    let bytes = b"error[E0308]: first\nerror[E0308]: duplicate class\ntest result: FAILED\ncodesign failed\ntimeout reached\npermission denied\nerror: remote unknown\n";
    let entries = (1..=MAX_DIAGNOSIS_LOGS as u64)
        .map(|job_id| (job_id, bytes.len()))
        .collect::<Vec<_>>();
    let logs = (1..=MAX_DIAGNOSIS_LOGS as u64)
        .map(|job_id| exact_log(job_id, bytes))
        .collect();
    let payloads = entries
        .iter()
        .map(|(job_id, _)| (*job_id, bytes.to_vec()))
        .collect();
    let collection = collection(response(&entries, entries.len() as u64), true, payloads);
    let diagnosis = diagnose(&collection, logs).await.unwrap();

    assert_eq!(diagnosis.findings().len(), MAX_DIAGNOSIS_FINDINGS);
    assert_eq!(diagnosis.status(), DiagnosisStatus::Partial);
    assert_eq!(
        diagnosis
            .findings()
            .iter()
            .filter(|finding| {
                finding.job_id() == 1 && finding.category() == FindingCategory::Compilation
            })
            .count(),
        1
    );
    let manifest: Value = serde_json::from_slice(diagnosis.manifest().bytes()).unwrap();
    assert_eq!(manifest["findings_truncated"], true);
}

#[tokio::test]
async fn artifact_correspondence_is_rejected_and_caller_chosen_handles_cannot_be_cited() {
    let bytes = b"error: exact bytes\n";
    let collected_response = response(&[(4, bytes.len())], 1);
    let collected = collection(collected_response.clone(), true, vec![(4, bytes.to_vec())]);
    let diagnosis = diagnose(&collected, vec![exact_log(4, bytes)])
        .await
        .unwrap();
    let arbitrary = EvidenceHandle::parse("evidence://attacker/chosen-handle").unwrap();
    assert_ne!(diagnosis.findings()[0].evidence().handle, arbitrary);
    assert_eq!(
        diagnosis.findings()[0].evidence().handle.as_str(),
        canonical_handle(bytes)
    );
    assert_eq!(
        diagnosis.logs()[0].compacted().source.handle.as_str(),
        canonical_handle(bytes)
    );

    let wrong_length = response(&[(4, bytes.len() + 1)], 1);
    let mut longer_artifact = bytes.to_vec();
    longer_artifact.push(b'x');
    let wrong_length = collection(wrong_length, true, vec![(4, longer_artifact)]);
    assert!(matches!(
        diagnose(&wrong_length, vec![exact_log(4, bytes)]).await,
        Err(DiagnosisError::ByteLengthMismatch { job_id: 4 })
    ));

    let mut value = serde_json::to_value(collected_response).unwrap();
    value["logs"][0]["artifact_name"] = json!("not-canonical.log");
    let wrong_name: CollectRunLogsResponse = serde_json::from_value(value).unwrap();
    let wrong_name = collection(wrong_name, true, vec![(4, bytes.to_vec())]);
    assert!(matches!(
        diagnose(&wrong_name, vec![exact_log(4, bytes)]).await,
        Err(DiagnosisError::ArtifactNameMismatch { job_id: 4 })
    ));

    let replacement = b"fatal: altered dat\n";
    assert_eq!(replacement.len(), bytes.len());
    assert!(matches!(
        diagnose(&collected, vec![exact_log(4, replacement)]).await,
        Err(DiagnosisError::ArtifactPayloadMismatch { job_id: 4 })
    ));
}

#[tokio::test]
async fn complete_truth_requires_artifact_and_evidence_for_every_failed_job() {
    let first = b"error: first\n";
    let second = b"error: other\n";
    let complete_response = response(&[(1, first.len()), (2, second.len())], 2);
    let mut value = serde_json::to_value(complete_response).unwrap();
    value["logs"].as_array_mut().unwrap().pop();
    let missing_log: CollectRunLogsResponse = serde_json::from_value(value).unwrap();
    let collection = collection(missing_log, true, vec![(1, first.to_vec())]);

    assert!(matches!(
        diagnose(&collection, vec![exact_log(1, first)]).await,
        Err(DiagnosisError::ContradictoryCompleteness)
    ));
}

#[tokio::test]
async fn log_count_and_payload_bounds_reject_overflow() {
    let bytes = b"error: bounded\n";
    let entries = (1..=(MAX_DIAGNOSIS_LOGS + 1) as u64)
        .map(|job_id| (job_id, bytes.len()))
        .collect::<Vec<_>>();
    let collection = collection(response(&entries, entries.len() as u64), true, Vec::new());
    assert!(matches!(
        diagnose(&collection, Vec::new()).await,
        Err(DiagnosisError::TooManyLogs)
    ));

    let oversized = vec![0_u8; MAX_LOG_BYTES_PER_JOB + 1];
    assert!(matches!(
        ExactJobLog::new(1, oversized),
        Err(DiagnosisError::LogTooLarge { job_id: 1 })
    ));
}

#[tokio::test]
#[ignore = "requires PAM_GITHUB_TOKEN, PAM_GITHUB_REPOSITORY, and PAM_GITHUB_RUN_ID"]
async fn live_failed_run_is_diagnosed_with_compact_exact_evidence() {
    let token = env::var("PAM_GITHUB_TOKEN").expect("PAM_GITHUB_TOKEN must be set");
    let repository = Repository::parse(
        env::var("PAM_GITHUB_REPOSITORY").expect("PAM_GITHUB_REPOSITORY must be set"),
    )
    .unwrap();
    let run_id = RunId::new(
        env::var("PAM_GITHUB_RUN_ID")
            .expect("PAM_GITHUB_RUN_ID must be set")
            .parse()
            .expect("PAM_GITHUB_RUN_ID must be an integer"),
    )
    .unwrap();
    let connector = GitHubActions::new(
        Url::parse("https://api.github.com/").unwrap(),
        ReqwestGitHubTransport::new(Some(token)).unwrap(),
    )
    .unwrap();
    let context = InvocationContext::new(
        Instant::now() + Duration::from_mins(1),
        CancellationToken::new(),
        1,
        None,
    )
    .unwrap();
    let collection = Connector::<CollectRunLogs>::execute(
        &connector,
        CollectRunLogsRequest::new(
            repository,
            run_id,
            16,
            MAX_LOG_BYTES_PER_JOB,
            16 * 1024 * 1024,
        )
        .unwrap(),
        context,
    )
    .await
    .unwrap();
    let exact_logs = collection
        .value()
        .logs()
        .iter()
        .map(|log| {
            let artifact = collection
                .artifacts()
                .iter()
                .find(|artifact| artifact.name() == log.artifact_name())
                .expect("every collected log must have its exact artifact");
            ExactJobLog::new(log.job_id(), artifact.bytes().to_vec()).unwrap()
        })
        .collect();
    let diagnosis = diagnose(&collection, exact_logs).await.unwrap();
    assert_eq!(diagnosis.status(), DiagnosisStatus::Diagnosed);
    assert!(diagnosis.findings().iter().any(|finding| {
        finding.category() == FindingCategory::SigningOrPackaging
            && finding
                .evidence()
                .handle
                .as_str()
                .starts_with("evidence://github-actions/log/")
    }));
    assert!(!diagnosis.manifest().bytes().is_empty());
}
