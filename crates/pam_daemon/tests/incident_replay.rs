//! Offline screening measures evidence preparation, not frontier resolution.
mod incident_support;
use incident_support::{Incident, load, measurement_identity, retention, validate_map};
use pam_compact::{Compacted, sha256_hex};
use pam_daemon::{
    log_service::{CompressInput, LogService},
    model_service::{ModelService, SETTING_MODELS_DIR},
};
use pam_store::Store;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Instant};

async fn replay(
    store: &Store,
    logs: &LogService,
    case: &Incident,
    source: &[u8],
    run: usize,
) -> (Value, u128) {
    let ticket = format!("screen-{run}-{}", case.case_id);
    store
        .insert_request(
            &ticket,
            "admin.log.compress",
            "offline-fixture",
            "screening",
            "{}",
            None,
        )
        .await
        .unwrap();
    let start = Instant::now();
    let status = case.authoritative_observation["status"].as_str().unwrap();
    let report = logs
        .compress(
            &ticket,
            CompressInput {
                name: "incident.log".into(),
                bytes: source.to_vec(),
                exit_status: match status {
                    "failure" => Some(1),
                    "success" => Some(0),
                    _ => None,
                },
                use_model: false,
            },
        )
        .await
        .unwrap();
    let elapsed = start.elapsed().as_micros();
    assert!(report.model.is_none() && report.summary.is_none() && report.semantic.is_none());
    let stored = store
        .get_evidence(&report.source.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.content, source);
    let compact_row = store
        .get_evidence(&report.compact.id)
        .await
        .unwrap()
        .unwrap();
    let compacted: Compacted = serde_json::from_slice(&compact_row.content).unwrap();
    validate_map(&compacted);
    let facts = retention(case, source, &compacted, &report.compact_text);
    let packet = json!({"task":case.task,"target":case.target,"authoritative_status":status,
        "untrusted_evidence":report.compact_text});
    let packet_bytes = serde_json::to_vec(&packet).unwrap();
    let measured = json!({"case_id":case.case_id,"family_id":case.family_id,"stage":case.stage,"products":case.products,
        "authenticity":"synthetic","mode":"offline_evidence","label_review":case.review,
        "model_input":packet,"source_sha256":sha256_hex(source),"redacted_source_sha256":compacted.source_sha256,
        "compact_sha256":sha256_hex(&compact_row.content),"source_bytes":source.len(),
        "compact_view_bytes":report.compact_text.len(),"stored_compact_bytes":compact_row.content.len(),
        "model_input_bytes":packet_bytes.len(),"model_input_sha256":sha256_hex(&packet_bytes),
        "estimated_source_tokens":report.stats.tokens_source_est,"estimated_compact_tokens":report.stats.tokens_compact_est,
        "fragments":compacted.fragments,"offset_basis":"redacted_source_bytes","relation":"covering_record",
        "synthetic_exit_footer":compacted.exit_status,"decisive_fact_retention":facts,
        "connector_calls":0,"public_response_bytes":null,"frontier_tokens":null,"corrections":null,"avoided_attempts":null,
        "not_measured":"Offline preparation invokes no connector or frontier agent; byte/token estimates are not realized savings.",
        "diagnosis":null,"qualification_eligible":false});
    (measured, elapsed)
}

#[tokio::test]
async fn frozen_screening_replays_the_real_deterministic_pipeline_without_label_leakage() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/incidents/v1");
    let (manifest_sha256, cases) = load(&root).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .set_setting(SETTING_MODELS_DIR, temp.path().to_str().unwrap())
        .await
        .unwrap();
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), models);
    let mut results = Vec::new();
    for (case, source) in cases {
        let (first, first_us) = replay(&store, &logs, &case, &source, 0).await;
        let (second, second_us) = replay(&store, &logs, &case, &source, 1).await;
        assert_eq!(
            first, second,
            "content, provenance and retention must replay exactly: {}",
            case.case_id
        );
        results.push(json!({"result":first,"preparation_micros":[first_us,second_us]}));
    }
    let report = json!({"schema_version":1,"corpus_id":"pam-screening-v1","manifest_sha256":manifest_sha256,
        "measurement_identity":measurement_identity(),
        "algorithm":pam_compact::ALGORITHM_VERSION,"crate_version":env!("CARGO_PKG_VERSION"),
        "harness_sha256":sha256_hex(include_bytes!("incident_replay.rs")),
        "loader_sha256":sha256_hex(include_bytes!("incident_support/mod.rs")),
        "redaction_code_sha256":sha256_hex(include_bytes!("../src/evidence_view.rs")),
        "log_service_sha256":sha256_hex(include_bytes!("../src/log_service.rs")),
        "compact_code_sha256":sha256_hex(include_bytes!("../../pam_compact/src/compact.rs")),
        "policy":pam_compact::Policy::default(),"purpose":"synthetic_screening_not_qualification",
        "results":results,"frontier_resolution_benefit":"not_measured"});
    if let Some(path) = std::env::var_os("PAM_INCIDENT_REPORT") {
        let bytes = serde_json::to_vec_pretty(&report).unwrap();
        assert!(bytes.len() <= 4 * 1024 * 1024);
        std::fs::write(path, bytes).unwrap();
    }
}

#[test]
fn screening_refuses_unreviewed_labels_leaked_ids_and_oversized_files() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/incidents/v1");
    let (_, cases) = load(&root).unwrap();
    let (mut case, source) = cases.into_iter().next().unwrap();
    let review = case.review.clone();
    case.review["status"] = json!("pending");
    assert!(incident_support::validate(&case, &source).is_err());
    case.review = review;
    case.task.push_str(&case.case_id);
    assert!(incident_support::validate(&case, &source).is_err());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("oversized.log");
    std::fs::write(&path, vec![b'x'; 8193]).unwrap();
    assert!(incident_support::bounded_file(&path, 8192).is_err());
}

fn noise(output: &mut Vec<u8>, amount: usize) {
    let end = output.len() + amount;
    let mut index = 0;
    while output.len() < end {
        let mut line = format!("compiler progress unit={index:08} arguments=").into_bytes();
        line.resize(1023, b'x');
        line.push(b'\n');
        output.extend_from_slice(&line[..line.len().min(end - output.len())]);
        index += 1;
    }
    if amount > 0 {
        *output.last_mut().unwrap() = b'\n';
    }
}

#[tokio::test]
#[ignore = "derived 40 MB stress measurement; excluded from independent incident counts"]
async fn forty_megabyte_derived_log_measures_bounds_without_claiming_model_fit() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/incidents/v1");
    let (_, cases) = load(&root).unwrap();
    let (case, original) = cases
        .into_iter()
        .find(|(case, _)| case.case_id == "build-retried-fetch-then-compile")
        .unwrap();
    let mut source = Vec::with_capacity(40_000_000);
    let padding = 40_000_000 - original.len();
    noise(&mut source, padding / 2);
    source.extend_from_slice(&original);
    noise(&mut source, padding - padding / 2);
    assert_eq!(source.len(), 40_000_000);
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .set_setting(SETTING_MODELS_DIR, temp.path().to_str().unwrap())
        .await
        .unwrap();
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), models);
    let (result, micros) = replay(&store, &logs, &case, &source, 40).await;
    let report = json!({"schema_version":1,"purpose":"derived_stress_not_an_independent_incident",
        "measurement_identity":measurement_identity(),
        "generator":"unique_1024_byte_progress_records_v1","source_bytes":source.len(),
        "preparation_micros":micros,"result":result,"model_fit":"not_measured_or_asserted"});
    if let Some(path) = std::env::var_os("PAM_INCIDENT_STRESS_REPORT") {
        let bytes = serde_json::to_vec_pretty(&report).unwrap();
        assert!(bytes.len() <= 4 * 1024 * 1024);
        std::fs::write(path, bytes).unwrap();
    }
}
