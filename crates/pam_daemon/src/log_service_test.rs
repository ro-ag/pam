use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_compact::{Compacted, MAX_SOURCE_BYTES};
use pam_store::{EVIDENCE_KIND_LOG_COMPACT, Store};
use tokio::time::timeout;

use crate::log_service::{
    CAUSE_NO_DEFAULT, CompressInput, EVIDENCE_KIND_LOG_SOURCE, EVIDENCE_KIND_LOG_SUMMARY, LogError,
    LogService, PROMPT_BUDGET_BYTES, new_evidence_id,
};
use crate::model_service::{ModelService, SETTING_DEFAULT_HEAVY, SETTING_MODELS_DIR};

const DEADLINE: Duration = Duration::from_secs(20);

/// Environment variable naming the GGUF the opt-in summary test uses.
const BENCH_MODEL_ENV: &str = "PAM_BENCH_MODEL";

/// A log service over an in-memory store, with one request row the
/// evidence foreign key can point at.
async fn service(request_id: &str) -> (Arc<Store>, Arc<LogService>) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .insert_request(
            request_id,
            "admin.log.compress",
            "gui",
            "pam-gui",
            "{}",
            None,
        )
        .await
        .unwrap();
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), models);
    (store, logs)
}

/// A build log with one failure in the middle, long enough that the
/// boundary windows cannot cover all of it.
fn noisy_log(lines: usize) -> Vec<u8> {
    let mut text = String::new();
    for index in 0..lines {
        if index == lines / 2 {
            text.push_str("error: undefined reference to `foo`\n");
        } else {
            writeln!(text, "compiling unit {index}").unwrap();
        }
    }
    text.into_bytes()
}

#[tokio::test]
async fn compress_without_a_model_stores_source_and_compact_and_skips_the_summary() {
    timeout(DEADLINE, async {
        let (store, logs) = service("req_log_1").await;
        let bytes = noisy_log(400);

        let report = logs
            .compress(
                "req_log_1",
                CompressInput {
                    name: "build.log".to_owned(),
                    bytes: bytes.clone(),
                    exit_status: Some(1),
                    use_model: true,
                },
            )
            .await
            .unwrap();

        assert!(report.summary.is_none(), "no model, no summary row");
        assert!(report.summary_text.is_none());
        assert!(report.model.is_none());
        let skipped = report.model_skipped.as_ref().expect("a skip is recorded");
        assert_eq!(skipped.cause, CAUSE_NO_DEFAULT);
        assert!(!skipped.detail.is_empty(), "the skip says why");

        let rows = store.list_evidence("req_log_1").await.unwrap();
        assert_eq!(rows.len(), 2, "source and compact, nothing else");
        assert_eq!(rows[0].kind, EVIDENCE_KIND_LOG_SOURCE);
        assert_eq!(rows[1].kind, EVIDENCE_KIND_LOG_COMPACT);
        assert_eq!(rows[0].id, report.source.id);
        assert_eq!(rows[1].id, report.compact.id);

        let source = store
            .get_evidence(&report.source.id)
            .await
            .unwrap()
            .expect("the source row is there");
        assert_eq!(source.content, bytes, "the source is stored byte for byte");

        let compact_row = store
            .get_evidence(&report.compact.id)
            .await
            .unwrap()
            .expect("the compact row is there");
        let compacted: Compacted = serde_json::from_slice(&compact_row.content).unwrap();
        assert_eq!(compacted.rendered_text, report.compact_text);
        assert_eq!(compacted.exit_status, Some(1));

        let meta: serde_json::Value =
            serde_json::from_str(compact_row.meta_json.as_deref().expect("compact meta")).unwrap();
        assert_eq!(meta["name"], "build.log");
        assert_eq!(meta["source_evidence"], report.source.id);
        assert_eq!(meta["source_bytes"], report.stats.source_bytes);
        assert_eq!(meta["compact_bytes"], report.stats.compact_bytes);
        assert_eq!(meta["algorithm_version"], pam_compact::ALGORITHM_VERSION);
        assert_eq!(
            report.stats.tokens_avoided_est,
            report.stats.tokens_source_est - report.stats.tokens_compact_est,
        );
        assert!(
            report.stats.tokens_avoided_est > 0,
            "a noisy log really does save tokens"
        );
        assert!(report.stats.retained_records < report.stats.source_records);

        let stats = store.compression_stats(0).await.unwrap();
        assert_eq!(stats.compressions, 1);
        assert_eq!(stats.tokens_avoided_est, report.stats.tokens_avoided_est);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn use_model_false_never_touches_the_model_layer() {
    timeout(DEADLINE, async {
        let (store, logs) = service("req_log_2").await;

        let report = logs
            .compress(
                "req_log_2",
                CompressInput {
                    name: "test.log".to_owned(),
                    bytes: noisy_log(80),
                    exit_status: None,
                    use_model: false,
                },
            )
            .await
            .unwrap();

        assert!(report.model_skipped.is_none(), "nothing was skipped");
        assert!(report.summary.is_none());
        assert!(report.model.is_none());
        assert_eq!(store.list_evidence("req_log_2").await.unwrap().len(), 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn oversized_input_is_refused_before_any_row_exists() {
    timeout(DEADLINE, async {
        let (store, logs) = service("req_log_3").await;

        let err = logs
            .compress(
                "req_log_3",
                CompressInput {
                    name: "huge.log".to_owned(),
                    bytes: vec![0u8; MAX_SOURCE_BYTES + 1],
                    exit_status: None,
                    use_model: false,
                },
            )
            .await
            .expect_err("an oversized log is refused");

        match err {
            LogError::SourceTooLarge {
                actual_bytes,
                maximum_bytes,
            } => {
                assert_eq!(actual_bytes, maximum_bytes + 1);
            }
            other => panic!("expected SourceTooLarge, got {other:?}"),
        }
        assert!(
            store.list_evidence("req_log_3").await.unwrap().is_empty(),
            "a refused compress leaves no rows"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn oversized_evidence_is_not_truncated_or_sent_for_generation() {
    let (store, logs) = service("req_oversized").await;
    let mut text = String::new();
    for index in 0..2000 {
        writeln!(text, "error: diagnostic {index}").unwrap();
    }
    let report = logs
        .compress(
            "req_oversized",
            CompressInput {
                name: "long.log".to_owned(),
                bytes: text.as_bytes().to_vec(),
                exit_status: Some(1),
                use_model: true,
            },
        )
        .await
        .unwrap();
    assert!(report.compact_text.len() > PROMPT_BUDGET_BYTES);
    assert!(report.compact_text.contains("diagnostic 1000"));
    assert_eq!(
        report.model_skipped.unwrap().cause,
        "evidence_exceeds_budget"
    );
    assert!(report.summary.is_none());
    drop(store);
}

#[test]
fn new_evidence_id_has_the_ev_prefix_and_ulid_length() {
    let id = new_evidence_id();
    assert!(id.starts_with("ev_"), "{id}");
    assert_eq!(id.len(), 3 + 26, "{id}");
    assert_ne!(id, new_evidence_id(), "ids are unique");
    assert!(id < new_evidence_id(), "ids sort in minting order");
}

/// The models directory and registry id a GGUF in `<models dir>/<vendor>/`
/// layout implies — the same derivation [`crate::model_service`] does.
fn registry_coordinates(path: &Path) -> (PathBuf, String) {
    let path = path
        .canonicalize()
        .expect("PAM_BENCH_MODEL names an existing file");
    let vendor_dir = path
        .parent()
        .expect("PAM_BENCH_MODEL must sit under <models dir>/<vendor>/");
    let models_dir = vendor_dir
        .parent()
        .expect("PAM_BENCH_MODEL must sit under <models dir>/<vendor>/")
        .to_path_buf();
    let vendor = vendor_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the vendor directory name is UTF-8");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the model file name is UTF-8");
    let model_id = format!(
        "{vendor}/{}",
        file_name.strip_suffix(".gguf").unwrap_or(file_name)
    );
    (models_dir, model_id)
}

/// Opt-in proof that the summary half is really wired to the model layer.
///
/// ```text
/// PAM_BENCH_MODEL=~/llm/qwen/Qwen3-0.6B-Q8_0.gguf \
///     cargo test -p pam_daemon bench_model_writes_a_summary_row -- --nocapture
/// ```
///
/// The path must sit in the registry layout — `<models dir>/<vendor>/<file>.gguf`.
/// The tier default is seeded straight into the settings table, and the file is
/// hashed and qualified through the in-crate test hook, because a wiring model
/// has no qualification record and `resolve` refuses anything without one. With
/// the variable unset the test prints how to enable it and passes.
#[tokio::test]
async fn bench_model_writes_a_summary_row() {
    let Some(raw) = std::env::var_os(BENCH_MODEL_ENV) else {
        eprintln!("summary bench skipped: set {BENCH_MODEL_ENV}=<models dir>/<vendor>/<file>.gguf");
        return;
    };
    let (models_dir, model_id) = registry_coordinates(&PathBuf::from(&raw));

    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .insert_request(
            "req_log_bench",
            "admin.log.compress",
            "gui",
            "pam-gui",
            "{}",
            None,
        )
        .await
        .unwrap();
    // Seeded before the model service is built: it reads the models
    // directory once, at construction.
    store
        .set_setting(
            SETTING_MODELS_DIR,
            &serde_json::json!(models_dir.display().to_string()).to_string(),
        )
        .await
        .unwrap();
    store
        .set_setting(
            SETTING_DEFAULT_HEAVY,
            &serde_json::json!(model_id).to_string(),
        )
        .await
        .unwrap();
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    let (sha256, size_bytes) = pam_model::registry::sha256_file(Path::new(&raw)).unwrap();
    models
        .registry()
        .record_verified(
            Path::new(&raw),
            &pam_model::VerifiedRecord {
                sha256: sha256.clone(),
                size_bytes,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    models.qualify_for_tests(&sha256);
    let logs = LogService::new(Arc::clone(&store), models);

    let mut log = String::new();
    for index in 0..200 {
        if index == 150 {
            log.push_str("Build FAILED: undefined reference to foo\n");
        } else {
            writeln!(log, "[{index}/200] compiling widget_{index}.c").unwrap();
        }
    }

    let report = logs
        .compress(
            "req_log_bench",
            CompressInput {
                name: "build.log".to_owned(),
                bytes: log.into_bytes(),
                exit_status: Some(1),
                use_model: true,
            },
        )
        .await
        .unwrap();

    assert!(
        report.model_skipped.is_none(),
        "the model was skipped: {:?}",
        report.model_skipped
    );
    let summary = report.summary.as_ref().expect("a summary row");
    let text = report.summary_text.as_deref().expect("summary text");
    assert!(!text.trim().is_empty(), "the summary is not empty");
    let used = report.model.as_ref().expect("a model answered");
    assert_eq!(used.tier, "heavy");
    assert_eq!(used.id, model_id);
    assert!(used.completion_tokens > 0, "the model generated tokens");

    let row = store
        .get_evidence(&summary.id)
        .await
        .unwrap()
        .expect("the summary row is there");
    assert_eq!(row.kind, EVIDENCE_KIND_LOG_SUMMARY);
    assert_eq!(row.content, text.as_bytes());
    let meta: serde_json::Value =
        serde_json::from_str(row.meta_json.as_deref().expect("summary meta")).unwrap();
    assert_eq!(meta["model_id"], model_id);
    assert_eq!(meta["tier"], "heavy");
    assert_eq!(meta["compact_evidence"], report.compact.id);

    println!(
        "--- summary from {model_id} ({} tok/s) ---",
        used.tokens_per_sec
    );
    println!("{text}");
    println!("--- end summary ---");
}

#[test]
fn summary_input_identity_follows_the_compact_view_bytes() {
    use crate::log_service::summary_input;
    let (prompt, identity) = summary_input("compact text", "compact");
    assert_eq!(prompt, "compact text");
    assert_eq!(identity["evidence_id"], "compact");
    assert_eq!(
        identity["sha256"],
        pam_compact::sha256_hex(prompt.as_bytes())
    );
    assert_eq!(identity["offset_basis"], "view_bytes");
}
