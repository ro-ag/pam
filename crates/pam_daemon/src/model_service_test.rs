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

/// Verifies the placeholder at `path` (digest of whatever bytes are there) and
/// qualifies that digest on this target, so the tier gate admits it.
fn verify_and_qualify(service: &ModelService, path: &std::path::Path) {
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
    service.qualify_for_tests(&sha256);
}

#[tokio::test]
async fn resolve_refuses_a_default_that_is_unverified_or_unqualified() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    service
        .set_default(Tier::Light, Some("qwen/small"))
        .await
        .unwrap();

    assert!(
        matches!(
            service.resolve(Tier::Light).await.unwrap_err(),
            ModelUnavailable::Unverified(ref id) if id == "qwen/small"
        ),
        "nothing vouches for the bytes"
    );

    let (sha256, size_bytes) = pam_model::registry::sha256_file(&path).unwrap();
    service
        .registry()
        .record_verified(
            &path,
            &pam_model::VerifiedRecord {
                sha256,
                size_bytes,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    assert!(
        matches!(
            service.resolve(Tier::Light).await.unwrap_err(),
            ModelUnavailable::Unqualified(ref id) if id == "qwen/small"
        ),
        "verified is not qualified"
    );
    assert_eq!(
        service.defaults().await.unwrap().0.as_deref(),
        Some("qwen/small"),
        "the refused default stays configured and visible"
    );

    verify_and_qualify(&service, &path);
    assert_eq!(service.resolve(Tier::Light).await.unwrap().id, "qwen/small");
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
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    verify_and_qualify(&service, &path);
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
    let detail: serde_json::Value = serde_json::from_str(job["detail"].as_str().unwrap()).unwrap();
    assert_eq!(detail["cause"], "daemon_restart");
    assert!(
        detail["recovery"]
            .as_str()
            .is_some_and(|line| !line.is_empty()),
        "an orphaned job tells the human what to do about it: {detail}"
    );
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

fn diagnostic_request() -> pam_model::runtime::GenerateRequest {
    pam_model::runtime::GenerateRequest {
        system: None,
        prompt: "Diagnostic only".into(),
        max_tokens: 1,
        temperature: 0.0,
        stop: Vec::new(),
    }
}

#[tokio::test]
async fn diagnostic_requires_installed_id_and_does_not_resolve_or_load_a_default() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    touch_model(dir.path(), "qwen", "requested.gguf");
    touch_model(dir.path(), "qwen", "other.gguf");
    service
        .set_default(Tier::Light, Some("qwen/other"))
        .await
        .unwrap();
    let error = service
        .generate_diagnostic("qwen/requested", diagnostic_request())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ModelUnavailable::Runtime(pam_model::RuntimeError::LoadFailed(ref detail)) if detail.contains("engine is not installed")),
        "{error:?}"
    );
    let missing = service
        .generate_diagnostic("qwen/missing", diagnostic_request())
        .await
        .unwrap_err();
    assert!(
        matches!(missing, ModelUnavailable::Service(ModelServiceError::UnknownModel(id)) if id == "qwen/missing")
    );
    assert_eq!(service.snapshot().state, pam_model::RuntimeState::Idle);
}

#[tokio::test]
async fn reserved_model_operation_refuses_diagnostic_without_waiting_or_loading() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let _reservation = service.operation.lock().await;
    let error = service
        .generate_diagnostic("qwen/requested", diagnostic_request())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ModelUnavailable::Runtime(pam_model::RuntimeError::Busy)
    ));
    assert_eq!(service.snapshot().state, pam_model::RuntimeState::Idle);
}

#[tokio::test(start_paused = true)]
async fn diagnostic_deadline_drop_signals_the_worker_receiver() {
    let (guard, receiver) = crate::model_service::DiagnosticCancellation::new();
    let waiting = async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(8), waiting).await;
    assert!(result.is_err());
    assert!(
        *receiver.borrow(),
        "closing an unchanged sender alone would leave false"
    );
}

#[tokio::test]
async fn a_registry_switch_rejects_an_entry_resolved_from_the_old_directory() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    touch_model(first.path(), "qwen", "same.gguf");
    touch_model(second.path(), "qwen", "same.gguf");
    let service = service(first.path()).await;
    let stale = service.find("qwen/same").await.unwrap().unwrap();
    service.set_models_dir(second.path()).await.unwrap();
    let error = service.ensure_loaded(&stale).await.unwrap_err();
    assert!(
        matches!(error, pam_model::RuntimeError::LoadFailed(detail) if detail.contains("entry changed"))
    );
    let current = service.find("qwen/same").await.unwrap().unwrap();
    assert_ne!(current.path, stale.path);
    let refused = service
        .generate_diagnostic("qwen/same", diagnostic_request())
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ModelUnavailable::Runtime(pam_model::RuntimeError::LoadFailed(ref detail)) if detail.contains("engine is not installed")),
        "{refused:?}"
    );
    assert_eq!(service.snapshot().state, pam_model::RuntimeState::Idle);
}

/// The fake llama-server `cargo test` builds for `pam_model`, found next to
/// this test binary's directory; `None` when it was not built.
#[cfg(unix)]
fn fake_engine_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("pam-fake-llama-server");
    path.is_file().then_some(path)
}

/// Installs the fake server as if it were the pinned release: manifest plus
/// binary under `<engine base>/engine`, exactly what `engine::status` reads.
#[cfg(unix)]
fn install_fake_engine(service: &ModelService, fake: &std::path::Path) {
    use pam_model::engine::{ENGINE_BUILD, ENGINE_TAG, EngineLayout, EngineManifest, Target};
    let layout = EngineLayout::new(&service.engine_base());
    let target = Target::current().unwrap();
    std::fs::create_dir_all(layout.install_dir(ENGINE_TAG)).unwrap();
    std::fs::copy(fake, layout.server_path(ENGINE_TAG, target)).unwrap();
    let manifest = EngineManifest {
        tag: ENGINE_TAG.into(),
        build: ENGINE_BUILD,
        target,
        asset: target.asset().name.into(),
        sha256: target.asset().sha256.into(),
        bytes: target.asset().bytes,
        version_line: "version: fake".into(),
        installed_at_ms: 0,
    };
    std::fs::write(
        layout.manifest_path(),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn an_installed_engine_takes_over_load_generate_status_and_unload() {
    let Some(fake) = fake_engine_binary() else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    // Unix socket paths are capped at 104 bytes: keep the base short.
    let dir = tempfile::Builder::new()
        .prefix("pam-ms-")
        .tempdir_in("/tmp")
        .unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "tiny.gguf");
    verify_and_qualify(&service, &path);
    service
        .set_default(Tier::Light, Some("qwen/tiny"))
        .await
        .unwrap();
    assert!(service.engine_server().is_none(), "nothing installed yet");
    install_fake_engine(&service, &fake);
    assert!(service.engine_server().is_some());

    let result = service
        .generate_bounded(
            Tier::Light,
            pam_model::runtime::GenerateRequest {
                system: Some("You echo.".into()),
                prompt: "one two three".into(),
                max_tokens: 16,
                temperature: 0.0,
                stop: Vec::new(),
            },
            4096,
        )
        .await
        .unwrap();
    assert_eq!(result.text, "echo: one two three");
    assert_eq!(result.model.id, "qwen/tiny");
    assert_eq!(result.model.device, "llama.cpp");
    assert_eq!(result.completion_tokens, 4);
    assert!(result.tokens_per_sec > 0.0);

    let status = service.status().await.unwrap();
    assert_eq!(status["engine"]["installed"], true);
    assert_eq!(status["engine"]["loaded"]["id"], "qwen/tiny");
    assert_eq!(
        status["runtime"]["state"]["state"], "loaded",
        "the runtime snapshot mirrors what the engine holds"
    );
    assert_eq!(status["runtime"]["state"]["id"], "qwen/tiny");
    assert_eq!(status["runtime"]["busy"], false);

    // The prompt limit is enforced by the engine's own tokenizer count.
    let too_long = service
        .generate_bounded(
            Tier::Light,
            pam_model::runtime::GenerateRequest {
                system: None,
                prompt: "a b c d e f g h i j".into(),
                max_tokens: 4,
                temperature: 0.0,
                stop: Vec::new(),
            },
            4,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            too_long,
            ModelUnavailable::Runtime(pam_model::runtime::RuntimeError::PromptTooLong { .. })
        ),
        "{too_long:?}"
    );

    service.unload_all().await.unwrap();
    let status = service.status().await.unwrap();
    assert!(status["engine"]["loaded"].is_null());
    assert_eq!(status["runtime"]["state"]["state"], "idle");
}
