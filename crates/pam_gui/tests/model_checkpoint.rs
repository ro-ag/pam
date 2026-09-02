//! The model-layer checkpoint, driven exactly the way the GUI drives it:
//! every step is a `pam_client::client::send_admin` call — the call the
//! bridge's `admin_call` command is one line over — against a real
//! daemon, with real weights.
//!
//! Opt-in, because it needs a GGUF on disk: set `PAM_BENCH_MODEL` to a
//! small test-only model (the wiring model is Qwen3-0.6B `Q8_0`, 639 MB)
//! and the test fetches it through the daemon's own download path (a
//! `file://` URL through system curl — the same code that fetches from
//! Hugging Face), lists it, refuses it as a tier default (`below_floor`),
//! loads it, prompts it, and unloads it. Unset, the test prints how to
//! run it and passes.
//!
//! Two knobs make it a production-binary check rather than a harness
//! one: `PAM_CHECKPOINT_BASE` points it at an already-running daemon's
//! base dir (for example the one `pam gui` started) instead of spawning
//! a `pam_testkit` daemon, and `PAM_CHECKPOINT_MODELS_DIR` names the
//! models directory it installs into (a fresh temp dir by default).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pam_client::client;
use pam_gui::bridge::expect_result;
use pam_proto::Response;
use pam_testkit::TestDaemon;
use serde_json::{Value, json};

/// The bridge's ordinary admin deadline.
const ADMIN_DEADLINE_MS: u64 = 30_000;

/// The bridge's `admin.models.try` deadline.
const TRY_DEADLINE_MS: u64 = 120_000;

/// How long the local download plus its verification may take.
const DOWNLOAD_WAIT: Duration = Duration::from_mins(3);

/// The wiring prompt; the answer only has to be non-empty.
const PROMPT: &str = "Say hello in five words.";

/// One admin op, unwrapped to its result body (a refusal is a failure).
async fn admin(base: &Path, op: &str, args: Value, deadline_ms: u64) -> Value {
    let response = client::send_admin(base, op, args, deadline_ms)
        .await
        .unwrap_or_else(|err| panic!("{op}: transport failed: {err}"));
    expect_result(response).unwrap_or_else(|err| panic!("{op}: refused: {err:?}"))
}

/// One admin op that must be refused; returns the refusal cause.
async fn admin_refused(base: &Path, op: &str, args: Value) -> String {
    let response = client::send_admin(base, op, args, ADMIN_DEADLINE_MS)
        .await
        .unwrap_or_else(|err| panic!("{op}: transport failed: {err}"));
    match response {
        Response::Refusal { cause, .. } => cause,
        other => panic!("{op}: expected a refusal, got {other:?}"),
    }
}

fn field<'a>(body: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(body, |value, key| &value[*key])
}

/// Steps 2 and 3: the paste-a-URL download through the daemon (curl
/// reads `file://` like any other scheme, resume flag included), polled
/// through `admin.models.status` the way the screen polls it.
async fn download_through_the_daemon(base: &Path, model: &Path) {
    // 2. Download through the daemon (Models > paste a URL). curl reads
    //    file:// like any other scheme, resume flag included.
    let url = format!("file://{}", model.display());
    let started = admin(
        base,
        "admin.models.download",
        json!({ "url": url, "vendor": "qwen" }),
        ADMIN_DEADLINE_MS,
    )
    .await;
    let job_id = started["job_id"]
        .as_str()
        .expect("download answers a job id")
        .to_owned();

    // 3. Poll status until the job settles (the screen polls the same op).
    let deadline = Instant::now() + DOWNLOAD_WAIT;
    let final_state = loop {
        let status = admin(base, "admin.models.status", json!({}), ADMIN_DEADLINE_MS).await;
        let job = status["jobs"]
            .as_array()
            .and_then(|jobs| jobs.iter().find(|job| job["id"] == job_id))
            .cloned();
        if let Some(job) = job
            && let Some(state) = job["state"].as_str()
            && state != "running"
        {
            break format!("{state} {}", job["detail"]);
        }
        assert!(Instant::now() < deadline, "download did not settle in time");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        final_state.starts_with("done"),
        "download job ended {final_state}"
    );
}

/// Step 6: load, prompt, read the `status` model block, unload.
async fn load_prompt_unload(base: &Path, model_id: &str) {
    // 6. Load, prompt, read status, unload.
    let loaded = admin(
        base,
        "admin.models.load",
        json!({ "model_id": model_id }),
        TRY_DEADLINE_MS,
    )
    .await;
    assert_eq!(field(&loaded, &["state", "state"]), "loaded");

    let answer = admin(
        base,
        "admin.models.try",
        json!({ "prompt": PROMPT, "max_tokens": 32 }),
        TRY_DEADLINE_MS,
    )
    .await;
    let text = answer["text"].as_str().unwrap_or_default();
    let tps = answer["tokens_per_sec"].as_f64().unwrap_or_default();
    assert!(
        !text.trim().is_empty(),
        "the model answered nothing: {answer}"
    );
    assert!(tps > 0.0, "no throughput reported: {answer}");
    eprintln!("checkpoint: {model_id} answered at {tps:.2} tok/s: {text:?}");

    let status = client::send_request(base, "status", json!({}), true, ADMIN_DEADLINE_MS, None)
        .await
        .expect("status answers");
    let status = expect_result(status).expect("status is a result");
    assert_eq!(field(&status, &["model", "state"]), "loaded");
    assert_eq!(field(&status, &["model", "id"]), model_id);

    let unloaded = admin(base, "admin.models.unload", json!({}), ADMIN_DEADLINE_MS).await;
    assert_eq!(field(&unloaded, &["state", "state"]), "idle");
}

#[tokio::test]
async fn the_model_layer_round_trips_through_the_admin_path() {
    let Some(model) = std::env::var_os("PAM_BENCH_MODEL") else {
        eprintln!(
            "model checkpoint skipped: set PAM_BENCH_MODEL=<path to a small .gguf> \
             (and optionally PAM_CHECKPOINT_BASE=<running daemon base dir>, \
             PAM_CHECKPOINT_MODELS_DIR=<models dir>)"
        );
        return;
    };
    let model = PathBuf::from(model)
        .canonicalize()
        .expect("PAM_BENCH_MODEL names an existing file");
    let file_name = model
        .file_name()
        .and_then(|name| name.to_str())
        .expect("model file name is UTF-8")
        .to_owned();
    let model_id = format!(
        "qwen/{}",
        file_name.strip_suffix(".gguf").unwrap_or(&file_name)
    );

    // Either the daemon a human started (`pam gui`), or a harness one.
    let harness = match std::env::var_os("PAM_CHECKPOINT_BASE") {
        Some(_) => None,
        None => Some(TestDaemon::spawn().await),
    };
    let base = std::env::var_os("PAM_CHECKPOINT_BASE").map_or_else(
        || harness.as_ref().expect("harness daemon").base_dir(),
        PathBuf::from,
    );
    let models_tmp = tempfile::tempdir().expect("tempdir");
    let models_dir = std::env::var_os("PAM_CHECKPOINT_MODELS_DIR")
        .map_or_else(|| models_tmp.path().to_path_buf(), PathBuf::from);
    std::fs::create_dir_all(&models_dir).expect("models dir exists");

    // 1. Point the daemon at the models dir (Settings > Models).
    let settings = admin(
        &base,
        "admin.models.settings.set",
        json!({ "models_dir": models_dir.display().to_string() }),
        ADMIN_DEADLINE_MS,
    )
    .await;
    assert_eq!(
        settings["models_dir"].as_str(),
        Some(models_dir.display().to_string().as_str())
    );

    download_through_the_daemon(&base, &model).await;

    // 4. The library lists it as test-only with its header parsed.
    let listed = admin(&base, "admin.models.list", json!({}), ADMIN_DEADLINE_MS).await;
    let entry = listed["models"]
        .as_array()
        .and_then(|models| models.iter().find(|m| m["id"] == model_id))
        .cloned()
        .unwrap_or_else(|| panic!("{model_id} missing from the library: {listed}"));
    assert_eq!(
        entry["class"], "test_only",
        "a 639 MB model is under the floor"
    );
    assert_eq!(entry["info"]["architecture"], "qwen3");

    // 5. The floor holds: never a tier default.
    let cause = admin_refused(
        &base,
        "admin.models.defaults.set",
        json!({ "tier": "light", "model_id": model_id }),
    )
    .await;
    assert_eq!(cause, "below_floor");

    load_prompt_unload(&base, &model_id).await;

    // 7. Every op above is an audited admin request; the harness can
    //    check the invariant directly, the external daemon shows its rows.
    if let Some(daemon) = harness {
        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    } else {
        let activity = admin(
            &base,
            "admin.activity.list",
            json!({ "limit": 50, "repo": "gui" }),
            ADMIN_DEADLINE_MS,
        )
        .await;
        let model_rows = activity["requests"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter(|row| {
                        row["capability"]
                            .as_str()
                            .is_some_and(|c| c.starts_with("admin.models."))
                    })
                    .count()
            })
            .unwrap_or_default();
        assert!(
            model_rows >= 8,
            "expected the model ops on the activity trail, saw {model_rows}"
        );
        eprintln!("checkpoint: {model_rows} admin.models.* rows on the live daemon's trail");
    }
}

/// Resume proof against a partial download already on disk (the owner's
/// `~/llm/qwen` holds pam-old partials of the catalog files): starting the
/// preset's download must continue from the existing part, not from zero,
/// and cancelling must keep the part for the next resume.
///
/// Opt-in: `PAM_CHECKPOINT_RESUME_PRESET=<catalog preset id>` with
/// `PAM_CHECKPOINT_MODELS_DIR` naming the directory that holds the
/// `.<file>.pam-model.part`, and `PAM_CHECKPOINT_BASE` for the daemon.
#[tokio::test]
async fn a_catalog_download_resumes_an_existing_part_and_cancel_keeps_it() {
    let (Some(preset_id), Some(models_dir), Some(base)) = (
        std::env::var_os("PAM_CHECKPOINT_RESUME_PRESET"),
        std::env::var_os("PAM_CHECKPOINT_MODELS_DIR"),
        std::env::var_os("PAM_CHECKPOINT_BASE"),
    ) else {
        eprintln!(
            "resume checkpoint skipped: set PAM_CHECKPOINT_RESUME_PRESET, \
             PAM_CHECKPOINT_MODELS_DIR and PAM_CHECKPOINT_BASE"
        );
        return;
    };
    let preset_id = preset_id.to_string_lossy().into_owned();
    let models_dir = PathBuf::from(models_dir);
    let base = PathBuf::from(base);
    // The catalog comes from the daemon, as the screen reads it.
    let catalog = admin(&base, "admin.models.catalog", json!({}), ADMIN_DEADLINE_MS).await;
    let preset = catalog["presets"]
        .as_array()
        .and_then(|presets| presets.iter().find(|p| p["id"] == preset_id))
        .cloned()
        .unwrap_or_else(|| panic!("{preset_id} is not a catalog preset: {catalog}"));
    let vendor = preset["vendor"].as_str().expect("preset vendor");
    let file_name = preset["file_name"].as_str().expect("preset file name");
    let part = models_dir
        .join(vendor)
        .join(format!(".{file_name}.pam-model.part"));
    let before = std::fs::metadata(&part).map_or(0, |meta| meta.len());
    assert!(before > 0, "no partial download at {}", part.display());

    admin(
        &base,
        "admin.models.settings.set",
        json!({ "models_dir": models_dir.display().to_string() }),
        ADMIN_DEADLINE_MS,
    )
    .await;
    let started = admin(
        &base,
        "admin.models.download",
        json!({ "preset_id": preset_id }),
        ADMIN_DEADLINE_MS,
    )
    .await;
    let job_id = started["job_id"].as_str().expect("job id").to_owned();

    // Progress must start above the existing part, never at zero.
    let deadline = Instant::now() + Duration::from_mins(2);
    let observed = loop {
        let status = admin(&base, "admin.models.status", json!({}), ADMIN_DEADLINE_MS).await;
        let job = status["jobs"]
            .as_array()
            .and_then(|jobs| jobs.iter().find(|job| job["id"] == job_id))
            .cloned()
            .expect("the job is listed");
        let done = job["bytes_done"].as_u64().unwrap_or_default();
        if done > before {
            break done;
        }
        assert_eq!(job["state"], "running", "job left running early: {job}");
        assert!(
            Instant::now() < deadline,
            "no progress past the part in time"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    eprintln!("resume: part was {before} bytes, transfer continued to {observed}");

    let cancelled = admin(
        &base,
        "admin.models.download.cancel",
        json!({ "job_id": job_id }),
        ADMIN_DEADLINE_MS,
    )
    .await;
    assert_eq!(cancelled["cancelled"], true);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = admin(&base, "admin.models.status", json!({}), ADMIN_DEADLINE_MS).await;
        let state = status["jobs"]
            .as_array()
            .and_then(|jobs| jobs.iter().find(|job| job["id"] == job_id))
            .and_then(|job| job["state"].as_str().map(ToOwned::to_owned))
            .expect("the job is listed");
        if state == "cancelled" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cancel did not settle; state {state}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let after = std::fs::metadata(&part).map_or(0, |meta| meta.len());
    assert!(after >= before, "the part shrank from {before} to {after}");
    eprintln!("resume: cancelled with the part kept at {after} bytes");
}
