use std::sync::Arc;

use pam_model::download::DownloadRequest;
use pam_store::Store;
use serde_json::json;

use crate::model_service::{
    CAUSE_DAEMON_RESTART, DOWNLOAD_POLL, JOB_FAILED, JOB_RUNNING, ModelService, ModelServiceError,
    ModelUnavailable, SETTING_DEFAULT_HEAVY, SETTING_DEFAULT_LIGHT, SHUTDOWN_WAIT, Tier,
    should_unload,
};
use crate::test_log::Captured;

/// A service over a fresh in-memory store, pointed at `dir`. Its
/// downloads may fetch from the plain-http loopback origin the fixtures
/// serve; production refuses `http://`.
async fn service(dir: &std::path::Path) -> Arc<ModelService> {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    service.set_models_dir(dir).await.unwrap();
    service.allow_plain_http_downloads_for_tests();
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

/// The server's context is the admission envelope, lowered to what the GGUF
/// header reports when that is smaller; absent, zero or oversized figures
/// keep the envelope.
#[test]
fn context_tokens_follow_the_header_only_downwards() {
    use pam_model::engine_server::context_tokens_for;
    let envelope = pam_model::runtime::CONTEXT_TOKENS;
    assert_eq!(context_tokens_for(None), envelope);
    assert_eq!(context_tokens_for(Some(0)), envelope);
    assert_eq!(context_tokens_for(Some(2048)), 2048);
    assert_eq!(context_tokens_for(Some(envelope as u64)), envelope);
    assert_eq!(context_tokens_for(Some(131_072)), envelope);
    assert_eq!(context_tokens_for(Some(u64::MAX)), envelope);
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
    let (guard, receiver) = crate::model_service::CancelOnDrop::new();
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

/// A caller's deadline drops the generation future mid-await (the
/// `admin.models.try` timeout, a bounded summary); `busy` must not stay
/// stuck, or the idle-unload ticker would never drop the weights.
#[tokio::test(start_paused = true)]
async fn busy_clears_when_a_generation_future_is_dropped() {
    let busy = std::sync::atomic::AtomicBool::new(false);
    let generation = async {
        let _busy = crate::model_service::BusyGuard::engage(&busy);
        assert!(busy.load(std::sync::atomic::Ordering::Acquire));
        std::future::pending::<()>().await;
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), generation).await;
    assert!(result.is_err(), "the deadline dropped the generation");
    assert!(
        !busy.load(std::sync::atomic::Ordering::Acquire),
        "a dropped generation leaves the runtime idle"
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
    assert_eq!(
        status["runtime"]["state"]["weight_bytes"],
        std::fs::metadata(&path).unwrap().len(),
        "the snapshot reports the size the registry recorded at load time"
    );

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

/// A diagnostic runs only on the model the engine holds: naming another
/// installed model is refused without loading or swapping, and an idle
/// engine refuses rather than loading the model named.
#[cfg(unix)]
#[tokio::test]
async fn a_diagnostic_on_a_model_the_engine_does_not_hold_is_refused() {
    let Some(fake) = fake_engine_binary() else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("pam-md-")
        .tempdir_in("/tmp")
        .unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let tiny = touch_model(dir.path(), "qwen", "tiny.gguf");
    touch_model(dir.path(), "qwen", "other.gguf");
    install_fake_engine(&service, &fake);

    // Installed but idle: refused, nothing loaded.
    let idle = service
        .generate_diagnostic("qwen/tiny", diagnostic_request())
        .await
        .unwrap_err();
    assert!(
        matches!(idle, ModelUnavailable::NotResident { resident: None, .. }),
        "{idle:?}"
    );
    assert_eq!(service.snapshot().state, pam_model::RuntimeState::Idle);

    let entry = service.find("qwen/tiny").await.unwrap().unwrap();
    service.ensure_loaded(&entry).await.unwrap();
    let refused = service
        .generate_diagnostic("qwen/other", diagnostic_request())
        .await
        .unwrap_err();
    match refused {
        ModelUnavailable::NotResident {
            requested,
            resident,
        } => {
            assert_eq!(requested, "qwen/other");
            assert_eq!(resident.as_deref(), Some("qwen/tiny"));
        }
        other => panic!("expected NotResident, got {other:?}"),
    }
    let status = service.status().await.unwrap();
    assert_eq!(
        status["engine"]["loaded"]["id"], "qwen/tiny",
        "the resident model is untouched"
    );
    assert_eq!(
        status["runtime"]["state"]["weight_bytes"],
        std::fs::metadata(&tiny).unwrap().len()
    );
    let ok = service
        .generate_diagnostic("qwen/tiny", diagnostic_request())
        .await
        .unwrap();
    assert_eq!(ok.model.id, "qwen/tiny");
    service.unload_all().await.unwrap();
}

// ---- the trust anchor for weights lives under the daemon's private base ----

/// The legacy sidecar an older pam (or anything that can write the models directory)
/// leaves beside a file, claiming `sha256`.
fn plant_sidecar(path: &std::path::Path, sha256: &str, size_bytes: u64) {
    let record = pam_model::VerifiedRecord {
        sha256: sha256.to_owned(),
        size_bytes,
        verified_ts: 1,
        matches_catalog: None,
    };
    std::fs::write(
        pam_model::registry::verified_sidecar_path(path),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
}

/// A planted sidecar naming the qualified digest (the shape of the attack: right
/// size, written after the file) must not admit the file to a tier. Only a record
/// in the private base does.
#[tokio::test]
async fn a_sidecar_planted_in_the_models_directory_does_not_admit_a_model() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "forged.gguf");
    let (sha256, size_bytes) = pam_model::registry::sha256_file(&path).unwrap();
    service.qualify_for_tests(&sha256);
    service
        .set_default(Tier::Light, Some("qwen/forged"))
        .await
        .unwrap();
    plant_sidecar(&path, &sha256, size_bytes);

    let refused = service.resolve(Tier::Light).await.unwrap_err();
    assert!(
        matches!(refused, ModelUnavailable::Unverified(ref id) if id == "qwen/forged"),
        "{refused:?}"
    );
    let entry = service.find("qwen/forged").await.unwrap().unwrap();
    let blocker = crate::model_readiness::admission_blocker(&entry)
        .expect("not admitted")
        .1;
    assert!(
        blocker.detail.contains("sidecar") && blocker.detail.contains("verify again"),
        "an install upgraded from sidecars says why it needs a Verify: {}",
        blocker.detail
    );

    // The recovery works: Verify records in the private base, and the file serves.
    service.registry().verify(&entry).unwrap();
    assert!(
        service.trust_dir().starts_with(dir.path().join("base")),
        "the record lives under the daemon's base, not the models directory"
    );
    assert_eq!(
        service.resolve(Tier::Light).await.unwrap().id,
        "qwen/forged"
    );
}

/// Weights rewritten under a verified name stop serving: the verification was a claim
/// about other bytes, whatever the sidecar-style evidence beside the file says.
#[tokio::test]
async fn a_model_rewritten_after_verification_is_refused_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "swapped.gguf");
    verify_and_qualify(&service, &path);
    service
        .set_default(Tier::Light, Some("qwen/swapped"))
        .await
        .unwrap();
    let before = service.resolve(Tier::Light).await.unwrap();

    // Same size, different bytes.
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(&path, b"NOT a real gguf").unwrap();

    let refused = service.resolve(Tier::Light).await.unwrap_err();
    assert!(
        matches!(refused, ModelUnavailable::Unverified(ref id) if id == "qwen/swapped"),
        "{refused:?}"
    );
    let entry = service.find("qwen/swapped").await.unwrap().unwrap();
    assert!(
        entry
            .verification_issue
            .as_deref()
            .is_some_and(|issue| issue.contains("changed")),
        "{entry:?}"
    );
    // An entry resolved before the rewrite cannot be loaded either.
    let error = service.ensure_loaded(&before).await.unwrap_err();
    assert!(
        matches!(&error, pam_model::RuntimeError::LoadFailed(detail) if detail.contains("changed")),
        "{error:?}"
    );
}

/// A finished download that carried an expected digest is recorded as verified in the
/// private base; nothing is written beside the weights.
#[tokio::test]
async fn a_checked_download_is_recorded_in_the_private_base_not_beside_the_file() {
    if pam_model::download::curl_path().is_err() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let body: Vec<u8> = (0..=255_u8).cycle().take(64 * 1024).collect();
    let origin = pam_model::testing::serve(body.clone(), "\"etag-1\"").await;
    let (sha256, size) = {
        use sha2::{Digest, Sha256};
        (hex::encode(Sha256::digest(&body)), body.len() as u64)
    };
    let dest = dir.path().join("qwen").join("pinned.gguf");

    let job = service
        .start_download(
            DownloadRequest {
                url: origin.url("pinned.gguf"),
                dest: dest.clone(),
                expected_size: Some(size),
                expected_sha256: Some(sha256.clone()),
                license_id: None,
            },
            "qwen/pinned",
        )
        .await
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        let status = service.status().await.unwrap();
        let row = status["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == job.as_str())
            .unwrap()
            .clone();
        if row["state"] != JOB_RUNNING {
            assert_eq!(row["state"], "done", "{row}");
            break;
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let status = service.status().await.unwrap();
    let row = status["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == job.as_str())
        .unwrap();
    let detail: serde_json::Value = serde_json::from_str(row["detail"].as_str().unwrap()).unwrap();
    assert_eq!(detail["verified"], true, "{detail}");
    assert!(detail.get("verify_error").is_none(), "{detail}");

    assert!(!pam_model::registry::verified_sidecar_path(&dest).exists());
    let entry = service.find("qwen/pinned").await.unwrap().unwrap();
    assert_eq!(
        entry.verified.as_ref().map(|record| record.sha256.as_str()),
        Some(sha256.as_str())
    );
    assert!(std::fs::read_dir(service.trust_dir()).unwrap().count() >= 1);
    // The record is not curl's word for it: PAM's own copy of the file was made and
    // hashed, and it is what the engine would be started on.
    let private = service.weights_dir().join(format!("{sha256}.gguf"));
    assert_eq!(entry.engine_path(), private);
    assert_eq!(std::fs::read(&private).unwrap(), body);
}

// ---- a verified model is loaded from PAM's private copy, never from the models directory ----

/// The window the fingerprint re-check could only narrow: the models directory's file
/// is replaced after the scan a load is based on and before the engine opens it. The
/// engine is started on the private copy, so it gets the verified bytes regardless.
#[cfg(unix)]
#[tokio::test]
async fn a_source_swapped_between_the_scan_and_the_load_does_not_reach_the_engine() {
    let Some(fake) = fake_engine_binary() else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("pam-sw-")
        .tempdir_in("/tmp")
        .unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "tiny.gguf");
    let verified_bytes = std::fs::read(&path).unwrap();
    verify_and_qualify(&service, &path);
    service
        .set_default(Tier::Light, Some("qwen/tiny"))
        .await
        .unwrap();
    install_fake_engine(&service, &fake);
    let entry = service.resolve(Tier::Light).await.unwrap();
    let digest = entry.verified.as_ref().unwrap().sha256.clone();

    // After the resolve: other bytes renamed over the verified name (same length).
    let staged = dir.path().join("qwen").join(".evil");
    std::fs::write(&staged, b"NOT a real gguf").unwrap();
    std::fs::rename(&staged, &path).unwrap();

    let operation = service.operation.lock().await;
    service.ensure_loaded_inner(&entry).await.unwrap();
    let loaded = service
        .engine_server()
        .unwrap()
        .model()
        .expect("the engine holds the model");
    assert_eq!(
        loaded.path,
        service.weights_dir().join(format!("{digest}.gguf")),
        "the engine was started on the private copy"
    );
    assert!(
        loaded.path.starts_with(dir.path().join("base")),
        "which lives under the daemon's base, not in the models directory"
    );
    assert_eq!(std::fs::read(&loaded.path).unwrap(), verified_bytes);
    assert_eq!(
        pam_model::registry::sha256_file(&loaded.path).unwrap().0,
        digest,
        "what the engine opened has the verified digest"
    );
    drop(operation);

    // The next resolve sees the swap and refuses the tier; nothing unverified serves.
    assert!(matches!(
        service.resolve(Tier::Light).await.unwrap_err(),
        ModelUnavailable::Unverified(_)
    ));
    service.unload_all().await.unwrap();
    assert!(
        std::fs::read_dir(service.weights_dir())
            .unwrap()
            .next()
            .is_none(),
        "once unloaded, the copy of a file that is no longer verified is swept"
    );
}

/// An unverified model is still loadable for Try, from the file itself: there is no
/// claim about its bytes to protect, and it never serves a job.
#[cfg(unix)]
#[tokio::test]
async fn an_unverified_model_loads_from_the_models_directory() {
    let Some(fake) = fake_engine_binary() else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("pam-un-")
        .tempdir_in("/tmp")
        .unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "tiny.gguf");
    install_fake_engine(&service, &fake);
    let entry = service.find("qwen/tiny").await.unwrap().unwrap();

    service.ensure_loaded(&entry).await.unwrap();
    let engine = service.engine_server().unwrap();
    assert_eq!(engine.model().unwrap().path, path);

    // Verified afterwards: the same id is now another file to the engine, so a job
    // does not reuse the unverified load.
    verify_and_qualify(&service, &path);
    let verified = service.find("qwen/tiny").await.unwrap().unwrap();
    service.ensure_loaded(&verified).await.unwrap();
    assert_eq!(
        engine.model().unwrap().path,
        verified.engine_path(),
        "reloaded from the private copy"
    );
    assert_ne!(verified.engine_path(), path);
    service.unload_all().await.unwrap();
}

/// A verification is a job: it reports what it did with the private copy, and a cancel
/// leaves no copy and no record.
#[tokio::test]
async fn a_verify_job_makes_the_private_copy_and_a_cancelled_one_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    let entry = service.find("qwen/small").await.unwrap().unwrap();

    let job = service.start_verify(entry).await.unwrap();
    let row = finished_job(&service, &job).await;
    assert_eq!(row["state"], "done", "{row}");
    let detail: serde_json::Value = serde_json::from_str(row["detail"].as_str().unwrap()).unwrap();
    let digest = detail["sha256"].as_str().unwrap().to_owned();
    assert!(
        ["cloned", "copied"].contains(&detail["private_copy"].as_str().unwrap()),
        "{detail}"
    );
    assert_eq!(
        row["bytes_done"],
        std::fs::metadata(&path).unwrap().len(),
        "progress reached the whole file"
    );
    assert!(
        service
            .weights_dir()
            .join(format!("{digest}.gguf"))
            .is_file()
    );
    assert!(
        !service.cancel_verify(&job),
        "a finished job has nothing to cancel"
    );

    // A file large enough that the hash is still running when the cancel lands (sparse:
    // it costs no disk, and its clone costs none either).
    let big = dir.path().join("qwen").join("big.gguf");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(768 * 1024 * 1024)
        .unwrap();
    let entry = service.find("qwen/big").await.unwrap().unwrap();
    let job = service.start_verify(entry).await.unwrap();
    assert!(service.cancel_verify(&job));
    let row = finished_job(&service, &job).await;
    assert_eq!(row["state"], "cancelled", "{row}");
    assert_eq!(
        std::fs::read_dir(service.weights_dir()).unwrap().count(),
        1,
        "only the first model's copy is there"
    );
    assert_eq!(
        service.find("qwen/big").await.unwrap().unwrap().verified,
        None
    );
}

/// The daemon closes its store as the last step of shutdown. A download or a
/// verification still running then used to be left to its detached follower,
/// which found the store closed, logged that, and left the job row `running`
/// for the next boot to fail. `shutdown` stops the transfers and waits for
/// their followers, so the verdicts are written while the store still takes
/// them and nothing meets a closed store.
#[tokio::test]
async fn shutdown_stops_running_transfers_and_their_followers_before_the_store_closes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let service = ModelService::new(Arc::clone(&store)).await.unwrap();
    service.set_models_dir(dir.path()).await.unwrap();
    service.allow_plain_http_downloads_for_tests();
    service.set_engine_base(dir.path().join("base"));

    // A verification that is still hashing when the shutdown comes (sparse:
    // it costs no disk, and its clone costs none either).
    let big = dir.path().join("qwen").join("big.gguf");
    std::fs::create_dir_all(big.parent().unwrap()).unwrap();
    std::fs::File::create(&big)
        .unwrap()
        .set_len(768 * 1024 * 1024)
        .unwrap();
    let entry = service.find("qwen/big").await.unwrap().unwrap();
    let mut jobs = vec![service.start_verify(entry).await.unwrap()];

    // And, where there is a curl to run, a download an origin trickles out
    // for minutes.
    let origin = pam_model::testing::serve_slowly(
        vec![7_u8; 1024 * 1024],
        "\"etag-slow\"",
        512,
        std::time::Duration::from_millis(200),
    )
    .await;
    let downloading = pam_model::download::curl_path().is_ok();
    if downloading {
        jobs.push(
            service
                .start_download(
                    DownloadRequest {
                        url: origin.url("slow.gguf"),
                        dest: dir.path().join("qwen").join("slow.gguf"),
                        expected_size: None,
                        expected_sha256: None,
                        license_id: None,
                    },
                    "qwen/slow",
                )
                .await
                .unwrap(),
        );
    }
    let rows = store.list_model_jobs(10).await.unwrap();
    assert_eq!(rows.len(), jobs.len());
    assert!(rows.iter().all(|row| row.state == JOB_RUNNING), "{rows:?}");

    let (log, logging) = Captured::start();
    let started = std::time::Instant::now();
    service.shutdown().await;
    assert!(
        started.elapsed() < SHUTDOWN_WAIT,
        "the followers were waited out, not joined: {:?}",
        started.elapsed()
    );

    // The followers have ended: their verdicts are on the rows, read here
    // through the store before it closes, and their transfers are forgotten.
    let rows = store.list_model_jobs(10).await.unwrap();
    assert_eq!(rows.len(), jobs.len());
    for row in &rows {
        assert_eq!(row.state, JOB_FAILED, "{row:?}");
        let detail: serde_json::Value =
            serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["cause"], CAUSE_DAEMON_RESTART, "{row:?}");
        assert_eq!(
            detail["detail"], "the daemon stopped while this job was running",
            "{row:?}"
        );
    }
    assert!(!service.cancel_verify(&jobs[0]));
    if downloading {
        assert!(!service.cancel_download(&jobs[1]).await);
    }
    // Nothing of the cancelled verification is left in the private store.
    assert!(
        std::fs::read_dir(service.weights_dir()).map_or(0, Iterator::count) == 0,
        "the cancelled verification left a private copy"
    );

    store.close().await.unwrap();
    // Long enough for a follower that was still alive to poll once more and
    // meet the closed store.
    tokio::time::sleep(DOWNLOAD_POLL * 3).await;
    drop(logging);
    let text = log.text();
    assert!(!text.contains("the store is closed"), "{text}");
    assert!(!text.contains("not recorded"), "{text}");
    assert!(!text.contains("did not stop in time"), "{text}");

    // A second shutdown has nothing to do and returns at once.
    service.shutdown().await;
}

/// The wait for the followers is bounded: one that has not ended in time is
/// reported and left running, and the shutdown returns.
#[tokio::test]
async fn shutdown_leaves_a_follower_that_does_not_stop_in_time_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let big = dir.path().join("qwen").join("big.gguf");
    std::fs::create_dir_all(big.parent().unwrap()).unwrap();
    std::fs::File::create(&big)
        .unwrap()
        .set_len(768 * 1024 * 1024)
        .unwrap();
    let entry = service.find("qwen/big").await.unwrap().unwrap();
    let job = service.start_verify(entry).await.unwrap();

    // No time at all: the follower cannot have recorded its verdict yet.
    let (log, logging) = Captured::start();
    let started = std::time::Instant::now();
    service.shutdown_within(std::time::Duration::ZERO).await;
    drop(logging);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let text = log.text();
    assert!(text.contains("WARN"), "{text}");
    assert!(text.contains("did not stop in time"), "{text}");
    assert!(text.contains("left=1") || text.contains("left=2"), "{text}");

    // Left, not aborted: it still records why its job ended.
    let row = finished_job(&service, &job).await;
    assert_eq!(row["state"], JOB_FAILED, "{row}");
}

/// Polls `admin.models.status` until job `id` leaves `running`, and returns its row.
async fn finished_job(service: &ModelService, id: &str) -> serde_json::Value {
    let started = std::time::Instant::now();
    loop {
        let status = service.status().await.unwrap();
        let row = status["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .expect("the job has a row")
            .clone();
        if row["state"] != JOB_RUNNING {
            return row;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{row}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[test]
fn a_verification_that_cannot_keep_its_copy_fails_with_its_own_cause_and_recovery() {
    use pam_model::RegistryError;
    use pam_model::weights::WeightsError;
    let no_space = RegistryError::Weights(WeightsError::NoSpace {
        dir: "/base/engine/weights".into(),
        needed: 12_109_566_624,
        free: Some(1_000_000),
    });
    let cause = crate::model_service::verify_cause(&no_space);
    assert_eq!(cause, crate::model_service::CAUSE_NO_SPACE);
    let body = crate::model_service::job_failure_value(cause, &no_space.to_string());
    let detail = body["detail"].as_str().unwrap();
    assert!(
        detail.contains("12109566624 bytes needed") && detail.contains("1000000 bytes free"),
        "{detail}"
    );
    assert!(
        body["recovery"].as_str().unwrap().contains("verify again"),
        "{body}"
    );
    let changed = RegistryError::Changed {
        id: "qwen/tiny".into(),
        what: "it was modified while being verified".into(),
    };
    assert_eq!(
        crate::model_service::verify_cause(&changed),
        "model_changed"
    );
    assert_eq!(
        crate::model_service::verify_cause(&RegistryError::NotFound("x".into())),
        crate::model_service::CAUSE_VERIFY_FAILED
    );
}

/// What a killed daemon left half-made in the private weights store is removed by the
/// first status of the next one; finished copies of live verifications stay.
#[tokio::test]
async fn the_first_status_sweeps_what_a_dead_daemon_left_in_the_weights_store() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    service.set_engine_base(dir.path().join("base"));
    verify_and_qualify(&service, &path);
    let leftover = service
        .weights_dir()
        .join(".incoming-1-00000000deadbeef.part");
    std::fs::write(&leftover, b"half a model").unwrap();
    // A fresh base flag, as at daemon start.
    service.set_engine_base(dir.path().join("base"));

    let status = service.status().await.unwrap();
    assert_eq!(
        status["weights_dir"],
        service.weights_dir().display().to_string()
    );
    assert_eq!(status["summary_contract"]["task"], "log.summary");
    assert!(!leftover.exists());
    assert_eq!(
        std::fs::read_dir(service.weights_dir()).unwrap().count(),
        1,
        "the verified model keeps its copy"
    );
}

// ---- qualification is a capability-bench claim; the summary's contract is disclosed ----

/// The disclosed fingerprint is of the request the summary really sends, and the
/// disclosure says in plain words that nothing was measured under it.
#[tokio::test]
async fn the_summary_contract_is_disclosed_as_the_request_the_summary_sends() {
    use pam_model::engine_server::{EngineContract, ServerOptions};
    let contract = crate::model_service::summary_contract().expect("the request builds");
    assert_eq!(contract.task, "log.summary");
    let system = contract.system.as_deref().unwrap();
    assert!(
        system.starts_with(crate::log_service::SUMMARY_SYSTEM),
        "{system}"
    );
    assert!(
        system.contains("- exit status: unknown") && system.contains("<<<EVIDENCE <fence>>>>"),
        "host facts and the fence are part of what is fingerprinted: {system}"
    );
    assert!(
        contract.prompt.contains("<evidence>"),
        "{}",
        contract.prompt
    );
    assert_eq!(contract.max_tokens, crate::log_service::SUMMARY_MAX_TOKENS);
    assert!((contract.temperature - crate::log_service::SUMMARY_TEMPERATURE).abs() < f64::EPSILON);
    assert_eq!(
        contract.input_limit,
        crate::model_service::SUMMARY_INPUT_LIMIT_TOKENS
    );
    // The limit lives as a literal in `log_service` until that call names the constant.
    let log_service = include_str!("log_service.rs");
    assert!(
        log_service.contains("SUMMARY_INPUT_LIMIT_TOKENS")
            || log_service.contains("(Tier::Heavy, request, 2048, cancel)"),
        "the summary's input limit moved; SUMMARY_INPUT_LIMIT_TOKENS must move with it"
    );

    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let status = service.status().await.unwrap();
    let disclosed = &status["summary_contract"];
    assert_eq!(
        disclosed["fingerprint"],
        contract.fingerprint(&EngineContract::of(&ServerOptions::default()))
    );
    assert_eq!(
        disclosed["measured"], false,
        "nothing was measured under it"
    );
    let note = disclosed["note"].as_str().unwrap();
    assert!(
        note.contains("advisory")
            && note.contains("untrusted")
            && note.contains("not been measured"),
        "{note}"
    );
}

/// The summary request framed another way: what an edit to `frame_evidence` or to the
/// summary instructions would produce.
fn reworded(
    instructions: &str,
    host_facts: &[(&str, &str)],
    evidence: &str,
) -> Option<pam_model::runtime::FramedEvidence> {
    let mut framed =
        pam_model::runtime::frame_evidence_with(instructions, host_facts, evidence, "<fence>")?;
    framed.system.push_str(" Answer in one line.");
    Some(framed)
}

/// The summary's framing is not what a record was measured under, so editing it must
/// not drop the badge: it changes the disclosed fingerprint and nothing else.
#[tokio::test]
async fn a_summary_framing_change_moves_the_disclosure_and_not_the_qualification() {
    use pam_model::PromptContract;
    use pam_model::engine_server::{EngineContract, ServerOptions};
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    verify_and_qualify(&service, &path);
    service
        .set_default(Tier::Heavy, Some("qwen/small"))
        .await
        .unwrap();
    let engine = EngineContract::of(&ServerOptions::default());
    let shipped = crate::model_service::summary_disclosure(&engine)
        .fingerprint
        .expect("a fingerprint");

    let request = crate::log_service::summary_request_with("<evidence>", None, reworded).unwrap();
    let edited = PromptContract::of(
        "log.summary",
        &request,
        crate::model_service::SUMMARY_INPUT_LIMIT_TOKENS,
    )
    .fingerprint(&engine);
    assert_ne!(
        edited, shipped,
        "the disclosed fingerprint follows the prompt"
    );

    // Nothing about the gate reads that fingerprint: the record still qualifies the model.
    let entry = service.resolve(Tier::Heavy).await.unwrap();
    assert!(entry.qualification.is_some());
    let readiness = service.readiness_now(Tier::Heavy).await.unwrap();
    assert_eq!(
        readiness.qualification.map(|record| record.artifact),
        Some("fixture")
    );
    assert_eq!(
        readiness.summary_contract.fingerprint.as_deref(),
        Some(shipped.as_str())
    );
    assert!(!readiness.summary_contract.measured);
}

#[tokio::test]
async fn a_record_measured_with_other_engine_options_refuses_the_tier_and_says_re_measure() {
    use pam_model::engine_server::EngineContract;
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    service.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    verify_and_qualify(&service, &path);
    service
        .set_default(Tier::Light, Some("qwen/small"))
        .await
        .unwrap();
    assert_eq!(service.resolve(Tier::Light).await.unwrap().id, "qwen/small");

    // The same record, measured when the supervisor sent another seed: a bench-affecting
    // option this build no longer uses.
    let sha256 = pam_model::registry::sha256_file(&path).unwrap().0;
    let reseeded = EngineContract {
        seed: 9,
        ..service.engine_contract_for_tests(&sha256)
    };
    service.qualify_measured_with_for_tests(&sha256, reseeded);
    let refused = service.resolve(Tier::Light).await.unwrap_err();
    let ModelUnavailable::Unqualified(detail) = &refused else {
        panic!("expected an unqualified refusal, got {refused:?}");
    };
    assert!(
        detail.starts_with("qwen/small (")
            && detail.contains("seed: measured 9, now 7")
            && detail.contains("needs re-measurement"),
        "{detail}"
    );
    let entry = service.find("qwen/small").await.unwrap().unwrap();
    assert_eq!(entry.qualification, None, "the badge is not carried");
    assert_eq!(
        entry.class,
        pam_model::ModelClass::Engine,
        "it is still verified, and still answers Try"
    );
    let listed = serde_json::to_value(&entry).unwrap();
    assert!(
        listed["qualification_issue"]
            .as_str()
            .unwrap()
            .contains("re-measurement"),
        "the listing carries the reason: {listed}"
    );
}

/// The gate a summary passes is unchanged: a model that is not verified, or verified but
/// not bench-qualified (no record, or a record that no longer describes how it is run),
/// writes no summary; the compact evidence stands and the skip says why.
#[tokio::test]
async fn a_summary_is_skipped_for_a_model_that_is_unverified_or_unqualified() {
    use crate::log_service::{CompressInput, LogService};
    use pam_model::engine_server::EngineContract;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    models.set_models_dir(dir.path()).await.unwrap();
    models.set_engine_base(dir.path().join("base"));
    let path = touch_model(dir.path(), "qwen", "small.gguf");
    models
        .set_default(Tier::Heavy, Some("qwen/small"))
        .await
        .unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let skipped = |request: &'static str| {
        let logs = &logs;
        let store = &store;
        async move {
            store
                .insert_request(request, "admin.log.compress", "gui", "pam-gui", "{}", None)
                .await
                .unwrap();
            let report = logs
                .compress(
                    request,
                    CompressInput {
                        name: "build.log".to_owned(),
                        bytes: b"step one\nerror: link failed\n".to_vec(),
                        exit_status: Some(1),
                        use_model: true,
                    },
                )
                .await
                .unwrap();
            assert!(report.summary.is_none() && report.model.is_none());
            report.model_skipped.expect("the skip is explained")
        }
    };

    let unverified = skipped("req_unverified").await;
    assert_eq!(unverified.cause, crate::log_service::CAUSE_MODEL_UNVERIFIED);

    let (sha256, size_bytes) = pam_model::registry::sha256_file(&path).unwrap();
    models
        .registry()
        .record_verified(
            &path,
            &pam_model::VerifiedRecord {
                sha256: sha256.clone(),
                size_bytes,
                verified_ts: 0,
                matches_catalog: None,
            },
        )
        .unwrap();
    let unqualified = skipped("req_unqualified").await;
    assert_eq!(
        unqualified.cause,
        crate::log_service::CAUSE_MODEL_UNQUALIFIED
    );

    let reseeded = EngineContract {
        seed: 9,
        ..models.engine_contract_for_tests(&sha256)
    };
    models.qualify_measured_with_for_tests(&sha256, reseeded);
    let changed = skipped("req_changed").await;
    assert_eq!(changed.cause, crate::log_service::CAUSE_MODEL_UNQUALIFIED);
    assert!(
        changed.detail.contains("needs re-measurement"),
        "{}",
        changed.detail
    );

    // Qualified with the options this build uses: the gate opens, and the only thing
    // between the log and a summary is the engine, which this fixture does not install.
    models.qualify_for_tests(&sha256);
    let admitted = skipped("req_admitted").await;
    assert_eq!(admitted.cause, "load_failed", "{}", admitted.detail);
}

// ---- a dead engine is noticed, a failing one is not "in use", a wedged one is bounded ----

#[cfg(unix)]
async fn loaded_fake_service(prefix: &str) -> Option<(Arc<ModelService>, tempfile::TempDir)> {
    let fake = fake_engine_binary()?;
    let dir = tempfile::Builder::new()
        .prefix(prefix)
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
    install_fake_engine(&service, &fake);
    Some((service, dir))
}

#[cfg(unix)]
fn echo_request(prompt: &str) -> pam_model::runtime::GenerateRequest {
    pam_model::runtime::GenerateRequest {
        system: None,
        prompt: prompt.into(),
        max_tokens: 16,
        temperature: 0.0,
        stop: Vec::new(),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn an_engine_killed_from_outside_is_reported_and_the_next_request_reloads() {
    let Some((service, _dir)) = loaded_fake_service("pam-mx-").await else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    service
        .generate_bounded(Tier::Light, echo_request("one"), 4096)
        .await
        .unwrap();
    let pid = service.engine_server().unwrap().model().unwrap().pid;
    assert!(
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let started = std::time::Instant::now();
    while service.snapshot().state != pam_model::RuntimeState::Idle {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "still 'loaded'"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let status = service.status().await.unwrap();
    assert!(status["engine"]["loaded"].is_null());
    assert_eq!(
        status["engine"]["exited"]["model_id"], "qwen/tiny",
        "the human sees that the engine died, and which model it held: {status}"
    );

    // No manual Unload needed: the next request starts a fresh engine.
    let again = service
        .generate_bounded(Tier::Light, echo_request("two"), 4096)
        .await
        .unwrap();
    assert_eq!(again.text, "echo: two");
    let status = service.status().await.unwrap();
    assert!(
        status["engine"]["exited"].is_null(),
        "a fresh load clears it"
    );
    service.unload_all().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_generation_does_not_count_as_use() {
    let Some((service, _dir)) = loaded_fake_service("pam-mu-").await else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    service
        .generate_bounded(Tier::Light, echo_request("one"), 4096)
        .await
        .unwrap();
    service.last_used_for_tests(Some(1_000));

    // A prompt over the limit fails on the engine's own count.
    let refused = service
        .generate_bounded(Tier::Light, echo_request("a b c d e f g h"), 2)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ModelUnavailable::Runtime(_)),
        "{refused:?}"
    );
    assert_eq!(
        service.last_used_for_tests(None),
        1_000,
        "a refusal must not keep the weights resident past the idle window"
    );

    service
        .generate_bounded(Tier::Light, echo_request("two"), 4096)
        .await
        .unwrap();
    assert!(service.last_used_for_tests(None) > 1_000);
    service.unload_all().await.unwrap();
}

/// A daemon killed with SIGKILL leaves its engine running. The next daemon finds it
/// through the pid file and stops it — and only it: a pid file naming some other
/// process is cleared and that process is left alone.
#[cfg(unix)]
#[tokio::test]
async fn an_engine_a_dead_daemon_left_behind_is_stopped_but_a_stranger_is_not() {
    use crate::model_service::OrphanReap;
    let Some((first, dir)) = loaded_fake_service("pam-mo-").await else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    first
        .generate_bounded(Tier::Light, echo_request("one"), 4096)
        .await
        .unwrap();
    let orphan = first.engine_server().unwrap().model().unwrap().pid;
    let alive = |pid: u32| {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(alive(orphan));

    // "The daemon restarted": a second service over the same base, which never loaded
    // anything itself. (The first one is leaked, as a SIGKILLed process would be.)
    let second = service(dir.path()).await;
    second.set_engine_base(dir.path().join("base"));
    let leaked = Arc::clone(&first);
    std::mem::forget(leaked);
    let reaped = second.reap_orphan_engine().await;
    assert_eq!(reaped, OrphanReap::Killed { pid: orphan });
    let started = std::time::Instant::now();
    while alive(orphan) && started.elapsed() < std::time::Duration::from_secs(10) {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!alive(orphan), "the leftover engine is gone");
    assert!(second.engine_server().unwrap().pid_record().is_none());

    // A pid file that names an unrelated live process (pid reuse): nothing is killed.
    let mut stranger = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let server = second.engine_server().unwrap();
    std::fs::write(
        server.pid_file(),
        serde_json::to_vec(&pam_model::engine_server::EnginePidRecord {
            pid: stranger.id(),
            exe: server.binary().to_path_buf(),
            model_path: dir.path().join("qwen").join("tiny.gguf"),
            spawned_ms: 0,
        })
        .unwrap(),
    )
    .unwrap();
    let third = service(dir.path()).await;
    third.set_engine_base(dir.path().join("base"));
    let outcome = third.reap_orphan_engine().await;
    assert_eq!(outcome, OrphanReap::NotOurs { pid: stranger.id() });
    assert!(alive(stranger.id()), "an unrelated process must survive");
    assert!(server.pid_record().is_none(), "the stale record is cleared");
    let _ = stranger.kill();
    let _ = stranger.wait();
}

/// The cancel receiver and the total deadline stop a generation that is stuck behind
/// the service-wide lock, instead of queueing for a quarter hour.
#[tokio::test]
async fn a_generation_waiting_behind_a_stuck_one_is_cancelled_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path()).await;
    let request = || pam_model::runtime::GenerateRequest {
        system: None,
        prompt: "x".into(),
        max_tokens: 1,
        temperature: 0.0,
        stop: Vec::new(),
    };
    // Something else holds the operation lock for the whole test.
    let _stuck = service.operation.lock().await;

    // Cancel: returns promptly with `Cancelled`.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let waiting = service.generate_bounded_cancellable(Tier::Light, request(), 16, cancel_rx);
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::pin!(waiting);
        tokio::select! {
            result = &mut waiting => result,
            () = async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                cancel_tx.send(true).unwrap();
                std::future::pending::<()>().await;
            } => unreachable!(),
        }
    })
    .await
    .expect("the cancel took effect");
    assert!(
        matches!(
            cancelled,
            Err(ModelUnavailable::Runtime(
                pam_model::RuntimeError::Cancelled
            ))
        ),
        "{cancelled:?}"
    );

    // Deadline: with nobody cancelling, the total deadline ends the wait.
    service.set_generate_deadlines_for_tests(
        std::time::Duration::from_millis(300),
        std::time::Duration::from_millis(300),
    );
    let (_keep, never) = tokio::sync::watch::channel(false);
    let started = std::time::Instant::now();
    let error = service
        .generate_bounded_cancellable(Tier::Light, request(), 16, never)
        .await
        .unwrap_err();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(
        matches!(&error, ModelUnavailable::Runtime(pam_model::RuntimeError::GenerationFailed(detail)) if detail.contains("no result within")),
        "{error:?}"
    );
}
