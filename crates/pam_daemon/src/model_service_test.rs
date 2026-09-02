use std::sync::Arc;

use pam_model::download::DownloadRequest;
use pam_store::Store;
use serde_json::json;

use crate::model_service::{
    JOB_RUNNING, ModelService, ModelServiceError, ModelUnavailable, SETTING_DEFAULT_HEAVY,
    SETTING_DEFAULT_LIGHT, Tier, should_unload,
};

/// A service over a fresh in-memory store, pointed at `dir`.
async fn service(dir: &std::path::Path) -> Arc<ModelService> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    service.set_models_dir(dir).await.unwrap();
    service
}

/// Writes a byte-identical-enough placeholder so a *path* exists; the
/// header never parses, which is fine for the tests that only care about
/// resolution and download bookkeeping.
fn touch_model(dir: &std::path::Path, vendor: &str, file_name: &str) -> std::path::PathBuf {
    let vendor_dir = dir.join(vendor);
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let path = vendor_dir.join(file_name);
    std::fs::write(&path, b"not a real gguf").unwrap();
    path
}

#[tokio::test]
async fn a_tier_with_no_default_is_unavailable_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;

    let light = service.resolve(Tier::Light).await.unwrap_err();
    assert!(matches!(light, ModelUnavailable::NoDefault(Tier::Light)));
    let heavy = service.resolve(Tier::Heavy).await.unwrap_err();
    assert!(matches!(heavy, ModelUnavailable::NoDefault(Tier::Heavy)));
}

#[tokio::test]
async fn heavy_falls_back_to_light_but_light_never_borrows_heavy() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    touch_model(dir.path(), "qwen", "small.gguf");
    service
        .set_default(Tier::Light, Some("qwen/small"))
        .await
        .unwrap();

    // heavy is unset, so it takes light's model.
    let entry = service.resolve(Tier::Heavy).await.unwrap();
    assert_eq!(entry.id, "qwen/small");

    // The other way round is not a fallback: a light job never spends the
    // heavy model.
    service.set_default(Tier::Light, None).await.unwrap();
    service
        .set_default(Tier::Heavy, Some("qwen/small"))
        .await
        .unwrap();
    assert!(matches!(
        service.resolve(Tier::Light).await.unwrap_err(),
        ModelUnavailable::NoDefault(Tier::Light)
    ));
    assert_eq!(service.resolve(Tier::Heavy).await.unwrap().id, "qwen/small");
}

#[tokio::test]
async fn a_default_naming_absent_weights_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service
        .set_default(Tier::Heavy, Some("qwen/deleted"))
        .await
        .unwrap();

    match service.resolve(Tier::Heavy).await.unwrap_err() {
        ModelUnavailable::Missing(id) => assert_eq!(id, "qwen/deleted"),
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[tokio::test]
async fn defaults_round_trip_through_the_settings() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    service.set_models_dir(dir.path()).await.unwrap();

    assert_eq!(service.defaults().await.unwrap(), (None, None));
    service
        .set_default(Tier::Light, Some("qwen/a"))
        .await
        .unwrap();
    service
        .set_default(Tier::Heavy, Some("qwen/b"))
        .await
        .unwrap();
    assert_eq!(
        service.defaults().await.unwrap(),
        (Some("qwen/a".to_owned()), Some("qwen/b".to_owned()))
    );
    // Stored as JSON, so the GUI reads the same shape it writes.
    assert_eq!(
        store.get_setting(SETTING_DEFAULT_LIGHT).await.unwrap(),
        Some(json!("qwen/a").to_string())
    );
    service.set_default(Tier::Heavy, None).await.unwrap();
    assert_eq!(
        store.get_setting(SETTING_DEFAULT_HEAVY).await.unwrap(),
        Some("null".to_owned())
    );
    assert_eq!(service.defaults().await.unwrap().1, None);
}

#[tokio::test]
async fn a_second_download_of_the_same_file_is_refused() {
    if pam_model::download::curl_path().is_err() {
        // No curl on this machine: the refusal under test never gets a
        // chance to fire, and a missing curl is its own refusal.
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let dest = dir.path().join("qwen").join("held.gguf");
    let request = || DownloadRequest {
        // Port 0 never connects, so the transfer stays live long enough
        // for the second call to collide with it and then fails on its
        // own; no network is touched.
        url: "http://127.0.0.1:0/held.gguf".to_owned(),
        dest: dest.clone(),
        expected_size: None,
        expected_sha256: None,
        license_id: None,
    };

    let job = service
        .start_download(request(), "qwen/held")
        .await
        .unwrap();
    assert!(job.starts_with("job_"));

    match service.start_download(request(), "qwen/held").await {
        Err(ModelServiceError::AlreadyDownloading(id)) => assert_eq!(id, "qwen/held"),
        other => panic!("expected AlreadyDownloading, got {other:?}"),
    }

    // The job is on the record while it runs, and cancelling it is
    // acknowledged.
    let status = service.status().await.unwrap();
    let jobs = status["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["id"], job.as_str());
    assert_eq!(jobs[0]["state"], JOB_RUNNING);
    assert!(service.cancel_download(&job).await);
    assert!(!service.cancel_download("job_nonexistent").await);
}

#[tokio::test]
async fn a_download_onto_installed_weights_is_refused() {
    if pam_model::download::curl_path().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let dest = touch_model(dir.path(), "qwen", "there.gguf");

    let request = DownloadRequest {
        url: "http://127.0.0.1:0/there.gguf".to_owned(),
        dest,
        expected_size: None,
        expected_sha256: None,
        license_id: None,
    };
    match service.start_download(request, "qwen/there").await {
        Err(ModelServiceError::AlreadyInstalled(id)) => assert_eq!(id, "qwen/there"),
        other => panic!("expected AlreadyInstalled, got {other:?}"),
    }
}

#[tokio::test]
async fn status_reports_the_settings_it_reads() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;

    let status = service.status().await.unwrap();
    assert_eq!(status["runtime"]["state"]["state"], "idle");
    assert_eq!(status["runtime"]["busy"], false);
    assert_eq!(status["jobs"].as_array().unwrap().len(), 0);
    assert_eq!(status["defaults"]["light"], serde_json::Value::Null);
    assert_eq!(status["idle_unload_min"], 10);
    assert_eq!(status["models_dir"], dir.path().display().to_string());
    assert!(status["host_ram_bytes"].as_u64().is_some());

    service.set_idle_unload_min(0).await.unwrap();
    assert_eq!(service.status().await.unwrap()["idle_unload_min"], 0);
}

#[tokio::test]
async fn boot_fails_the_jobs_a_dead_daemon_left_running() {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    store
        .insert_model_job("job_orphan", "download", "qwen/x", None, None)
        .await
        .unwrap();

    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    let jobs = service.status().await.unwrap();
    let job = &jobs["jobs"][0];
    assert_eq!(job["id"], "job_orphan");
    assert_eq!(job["state"], "failed");
    assert_eq!(job["detail"], "daemon_restart");
}

#[test]
fn idle_unload_waits_out_the_window_and_zero_means_never() {
    let now = 1_700_000_000;
    // Zero is off, however long the model has sat there.
    assert!(!should_unload(now - 86_400, now, 0));
    // Ten minutes: not at nine, yes at ten, yes past it.
    assert!(!should_unload(now - 9 * 60, now, 10));
    assert!(should_unload(now - 10 * 60, now, 10));
    assert!(should_unload(now - 60 * 60, now, 10));
    // Just used.
    assert!(!should_unload(now, now, 10));
    // A clock that jumped backwards is not idleness.
    assert!(!should_unload(now + 3_600, now, 10));
}
