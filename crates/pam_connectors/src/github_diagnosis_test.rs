use std::{
    env,
    time::{Duration, Instant},
};

use pam_compact::SourceEvidence;
use pam_core::{ContentDigest, EvidenceHandle};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::github::{
    CollectRunLogs, CollectRunLogsRequest, CollectRunLogsResponse, GitHubActions,
    MAX_LOG_BYTES_PER_JOB, Repository, ReqwestGitHubTransport, RunId,
};
use super::github_diagnosis::{
    DiagnosisError, DiagnosisStatus, ExactJobLog, FindingCategory, MAX_DIAGNOSIS_FINDINGS,
    MAX_DIAGNOSIS_LOGS, diagnose_run,
};
use super::{CancellationToken, Connector, InvocationContext};

const RUN_ID: u64 = 42;

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::from_sha256(Sha256::digest(bytes).into())
}

fn exact_log(job_id: u64, bytes: &[u8]) -> ExactJobLog {
    ExactJobLog::new(
        job_id,
        SourceEvidence {
            handle: EvidenceHandle::parse(format!("evidence://github/job-{job_id}")).unwrap(),
            digest: digest(bytes),
        },
        bytes.to_vec(),
    )
    .unwrap()
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

#[test]
fn findings_are_lexical_inferences_with_exact_hash_and_span_provenance() {
    let bytes = b"setup ok\nerror[E0308]: mismatched types\ntest result: FAILED. 1 failed\ncodesign validation failed\ndeadline exceeded\npermission denied\nerror: upstream response\n";
    let response = response(&[(7, bytes.len())], 1);
    let diagnosis = diagnose_run(&response, true, vec![exact_log(7, bytes)]).unwrap();

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
        assert_eq!(
            finding.evidence().handle.as_str(),
            "evidence://github/job-7"
        );
        let start = usize::try_from(finding.evidence().offset).unwrap();
        let end = start + usize::try_from(finding.evidence().length).unwrap();
        assert!(end <= bytes.len());
        assert!(!&bytes[start..end].is_empty());
    }

    let compacted = diagnosis.logs()[0].compacted();
    assert_eq!(compacted.source.digest, digest(bytes));
    assert_eq!(compacted.source.handle.as_str(), "evidence://github/job-7");
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

#[test]
fn canonical_manifest_is_byte_stable_and_contains_exact_provenance() {
    let bytes = b"compile\nerror[E0425]: missing value\n";
    let response = response(&[(9, bytes.len())], 1);
    let first = diagnose_run(&response, true, vec![exact_log(9, bytes)]).unwrap();
    let second = diagnose_run(&response, true, vec![exact_log(9, bytes)]).unwrap();
    assert_eq!(first.manifest().bytes(), second.manifest().bytes());
    assert_eq!(first.manifest().name(), "github-run-42-diagnosis.json");

    let manifest: Value = serde_json::from_slice(first.manifest().bytes()).unwrap();
    assert_eq!(manifest["schema_version"], "pam-github-diagnosis-v1");
    assert_eq!(manifest["run_id"], RUN_ID);
    assert_eq!(manifest["input_complete"], true);
    assert_eq!(manifest["status"], "diagnosed");
    assert_eq!(
        manifest["logs"][0]["source"]["handle"],
        "evidence://github/job-9"
    );
    assert_eq!(
        manifest["logs"][0]["source"]["digest"],
        digest(bytes).as_str()
    );
    assert_eq!(manifest["findings"][0]["inference"], true);
    assert_eq!(manifest["findings"][0]["evidence"]["offset"], 8);
}

#[test]
fn partial_input_never_becomes_diagnosed_and_benign_complete_input_is_unresolved() {
    let failing = b"error[E0308]: mismatch\n";
    let partial_response = response(&[(1, failing.len())], 3);
    let partial = diagnose_run(&partial_response, false, vec![exact_log(1, failing)]).unwrap();
    assert_eq!(partial.status(), DiagnosisStatus::Partial);
    assert_eq!(partial.findings().len(), 1);
    assert!(partial.summary().as_str().starts_with("partial"));

    let benign = b"checkout complete\nbuild cache restored\nall steps completed\n";
    let complete_response = response(&[(2, benign.len())], 1);
    let unresolved = diagnose_run(&complete_response, true, vec![exact_log(2, benign)]).unwrap();
    assert_eq!(unresolved.status(), DiagnosisStatus::Unresolved);
    assert!(unresolved.findings().is_empty());
}

#[test]
fn findings_are_deduplicated_and_truncated_to_the_global_bound() {
    let bytes = b"error[E0308]: first\nerror[E0308]: duplicate class\ntest result: FAILED\ncodesign failed\ntimeout reached\npermission denied\nerror: remote unknown\n";
    let entries = (1..=MAX_DIAGNOSIS_LOGS as u64)
        .map(|job_id| (job_id, bytes.len()))
        .collect::<Vec<_>>();
    let logs = (1..=MAX_DIAGNOSIS_LOGS as u64)
        .map(|job_id| exact_log(job_id, bytes))
        .collect();
    let diagnosis = diagnose_run(&response(&entries, entries.len() as u64), true, logs).unwrap();

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

#[test]
fn malformed_digest_and_artifact_correspondence_are_rejected() {
    let bytes = b"error: exact bytes\n";
    let collected_response = response(&[(4, bytes.len())], 1);
    let bad_digest = ExactJobLog::new(
        4,
        SourceEvidence {
            handle: EvidenceHandle::parse("evidence://github/job-4").unwrap(),
            digest: digest(b"different"),
        },
        bytes.to_vec(),
    )
    .unwrap();
    assert!(matches!(
        diagnose_run(&collected_response, true, vec![bad_digest]),
        Err(DiagnosisError::DigestMismatch { job_id: 4 })
    ));

    let wrong_length = response(&[(4, bytes.len() + 1)], 1);
    assert!(matches!(
        diagnose_run(&wrong_length, true, vec![exact_log(4, bytes)]),
        Err(DiagnosisError::ByteLengthMismatch { job_id: 4 })
    ));

    let mut value = serde_json::to_value(collected_response).unwrap();
    value["logs"][0]["artifact_name"] = json!("not-canonical.log");
    let wrong_name: CollectRunLogsResponse = serde_json::from_value(value).unwrap();
    assert!(matches!(
        diagnose_run(&wrong_name, true, vec![exact_log(4, bytes)]),
        Err(DiagnosisError::ArtifactNameMismatch { job_id: 4 })
    ));
}

#[test]
fn log_count_and_payload_bounds_reject_overflow() {
    let bytes = b"error: bounded\n";
    let entries = (1..=(MAX_DIAGNOSIS_LOGS + 1) as u64)
        .map(|job_id| (job_id, bytes.len()))
        .collect::<Vec<_>>();
    assert!(matches!(
        diagnose_run(&response(&entries, entries.len() as u64), true, Vec::new()),
        Err(DiagnosisError::TooManyLogs)
    ));

    let oversized = vec![0_u8; MAX_LOG_BYTES_PER_JOB + 1];
    assert!(matches!(
        ExactJobLog::new(
            1,
            SourceEvidence {
                handle: EvidenceHandle::parse("evidence://github/job-1").unwrap(),
                digest: digest(&oversized),
            },
            oversized,
        ),
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
            ExactJobLog::new(
                log.job_id(),
                SourceEvidence {
                    handle: EvidenceHandle::parse(format!(
                        "evidence://github/run-{}-job-{}",
                        run_id.get(),
                        log.job_id()
                    ))
                    .unwrap(),
                    digest: digest(artifact.bytes()),
                },
                artifact.bytes().to_vec(),
            )
            .unwrap()
        })
        .collect();
    let diagnosis = diagnose_run(
        collection.value(),
        collection.truth().is_complete(),
        exact_logs,
    )
    .unwrap();
    assert_eq!(diagnosis.status(), DiagnosisStatus::Diagnosed);
    assert!(diagnosis.findings().iter().any(|finding| {
        finding.category() == FindingCategory::SigningOrPackaging
            && finding
                .evidence()
                .handle
                .as_str()
                .starts_with("evidence://github/run-")
    }));
    assert!(!diagnosis.manifest().bytes().is_empty());
}
