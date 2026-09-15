use std::sync::Arc;

use pam_model::engine::EngineStatus;
use pam_store::Store;

use crate::log_service::{
    CAUSE_MODEL_MISSING, CAUSE_MODEL_UNQUALIFIED, CAUSE_MODEL_UNVERIFIED, CAUSE_NO_DEFAULT,
};
use crate::model_readiness::{CAUSE_ENGINE_NOT_INSTALLED, Stage};
use crate::model_service::{ModelService, Tier};

async fn service(dir: &std::path::Path) -> Arc<ModelService> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    service.set_models_dir(dir).await.unwrap();
    service
}

fn touch_model(dir: &std::path::Path, vendor: &str, file_name: &str) -> std::path::PathBuf {
    let vendor_dir = dir.join(vendor);
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let path = vendor_dir.join(file_name);
    std::fs::write(&path, b"not a real gguf").unwrap();
    path
}

/// Hashes the placeholder and writes its sidecar; returns the digest.
fn verify(service: &ModelService, path: &std::path::Path) -> String {
    let (sha256, size_bytes) = pam_model::registry::sha256_file(path).unwrap();
    service
        .registry()
        .record_verified(
            path,
            &pam_model::VerifiedRecord {
                sha256: sha256.clone(),
                size_bytes,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    sha256
}

fn engine(installed: bool) -> EngineStatus {
    EngineStatus {
        expected_tag: "b10938".into(),
        expected_build: 10938,
        target: None,
        installed,
        server_path: None,
        manifest: None,
        cause: (!installed).then(|| "not_installed".to_owned()),
    }
}

#[tokio::test]
async fn an_unconfigured_tier_says_so_and_heavy_reports_its_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;

    let light = service
        .readiness(Tier::Light, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(light.stage, Stage::Unconfigured);
    assert_eq!(light.model_id, None);
    assert_eq!(light.blocker.as_ref().unwrap().cause, CAUSE_NO_DEFAULT);

    let path = touch_model(dir.path(), "qwen", "small.gguf");
    let sha256 = verify(&service, &path);
    service.qualify_for_tests(&sha256);
    service
        .set_default(Tier::Light, Some("qwen/small"))
        .await
        .unwrap();
    let heavy = service
        .readiness(Tier::Heavy, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(heavy.tier, "heavy");
    assert_eq!(heavy.configured, None, "heavy itself is unset");
    assert_eq!(heavy.model_id.as_deref(), Some("qwen/small"));
    assert!(heavy.fallback, "borrowed from light");
    assert_eq!(heavy.stage, Stage::Ready);
    assert!(heavy.blocker.is_none());
}

#[tokio::test]
async fn the_chain_stops_at_the_first_rung_that_fails() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service
        .set_default(Tier::Heavy, Some("qwen/small"))
        .await
        .unwrap();

    let missing = service
        .readiness(Tier::Heavy, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(missing.stage, Stage::Missing);
    assert_eq!(missing.blocker.as_ref().unwrap().cause, CAUSE_MODEL_MISSING);
    assert!(
        missing
            .blocker
            .as_ref()
            .unwrap()
            .detail
            .contains("qwen/small")
    );

    let path = touch_model(dir.path(), "qwen", "small.gguf");
    let unverified = service
        .readiness(Tier::Heavy, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(unverified.stage, Stage::Unverified);
    assert_eq!(
        unverified.blocker.as_ref().unwrap().cause,
        CAUSE_MODEL_UNVERIFIED
    );
    assert_eq!(unverified.qualification, None);

    let sha256 = verify(&service, &path);
    let unqualified = service
        .readiness(Tier::Heavy, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(unqualified.stage, Stage::Unqualified);
    assert_eq!(
        unqualified.blocker.as_ref().unwrap().cause,
        CAUSE_MODEL_UNQUALIFIED
    );

    service.qualify_for_tests(&sha256);
    let no_engine = service
        .readiness(Tier::Heavy, &engine(false), None)
        .await
        .unwrap();
    assert_eq!(no_engine.stage, Stage::EngineMissing);
    let blocker = no_engine.blocker.as_ref().unwrap();
    assert_eq!(blocker.cause, CAUSE_ENGINE_NOT_INSTALLED);
    assert!(blocker.detail.contains("b10938"), "{}", blocker.detail);
    assert!(
        blocker.detail.contains("not_installed"),
        "{}",
        blocker.detail
    );
    assert_eq!(
        no_engine.qualification.map(|record| record.artifact),
        Some("fixture"),
        "the qualification is reported even while the engine blocks"
    );

    let ready = service
        .readiness(Tier::Heavy, &engine(true), None)
        .await
        .unwrap();
    assert_eq!(ready.stage, Stage::Ready);
    assert!(ready.blocker.is_none());
    assert!(
        !ready.resident,
        "ready is not resident: it loads on the first job"
    );
}

#[tokio::test]
async fn residency_is_reported_beside_the_stage_not_as_one() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    touch_model(dir.path(), "qwen", "small.gguf");
    service
        .set_default(Tier::Light, Some("qwen/small"))
        .await
        .unwrap();

    let loaded = service
        .readiness(Tier::Light, &engine(true), Some("qwen/small"))
        .await
        .unwrap();
    assert_eq!(
        loaded.stage,
        Stage::Unverified,
        "a Try can load an unverified model"
    );
    assert!(loaded.resident);

    let other = service
        .readiness(Tier::Light, &engine(true), Some("qwen/other"))
        .await
        .unwrap();
    assert!(!other.resident);
}

#[test]
fn stages_serialize_as_snake_case_causes_the_gui_can_switch_on() {
    assert_eq!(
        serde_json::to_value(Stage::EngineMissing).unwrap(),
        serde_json::json!("engine_missing")
    );
    assert_eq!(
        serde_json::to_value(Stage::Ready).unwrap(),
        serde_json::json!("ready")
    );
}
