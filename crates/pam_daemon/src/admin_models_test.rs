use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_model::catalog::CATALOG;
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::{RequestState, Store};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::admin::{
    ADMIN_CALLER_AGENT, ADMIN_REPO, AdminService, CAUSE_INVALID_ADMIN_ARGS, CAUSE_UNKNOWN_ADMIN_OP,
};
use crate::admin_models::{
    CAUSE_ALREADY_INSTALLED, CAUSE_BELOW_FLOOR, CAUSE_NO_CURATOR, CAUSE_NOT_DETECTED,
    CAUSE_UNKNOWN_MODEL, MODEL_ADMIN_OPS, OP_CURATOR_LIST, OP_CURATOR_SET, OP_CURATOR_TEST,
    OP_MODELS_CATALOG, OP_MODELS_DEFAULTS_SET, OP_MODELS_DELETE, OP_MODELS_DOWNLOAD,
    OP_MODELS_DOWNLOAD_CANCEL, OP_MODELS_LIST, OP_MODELS_LOAD, OP_MODELS_SETTINGS_SET,
    OP_MODELS_STATUS, OP_MODELS_TRY, OP_MODELS_UNLOAD, OP_MODELS_VERIFY,
};
use crate::approval::ApprovalService;
use crate::daemon::TERMINAL_ACTIONS;
use crate::log_service::LogService;
use crate::model_service::{ModelService, SETTING_CURATOR, Tier};
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(20);

/// Approval timeout long enough never to fire here.
const LONG_TIMEOUT: Duration = Duration::from_mins(10);

// ---------------------------------------------------------------- fixture

/// An admin service over an in-memory store, pointed at a temp models
/// directory that lives as long as the fixture.
struct Fixture {
    store: Arc<Store>,
    models: Arc<ModelService>,
    admin: AdminService,
    dir: tempfile::TempDir,
    next: std::sync::atomic::AtomicU32,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
    ));
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    models.set_models_dir(dir.path()).await.unwrap();
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let admin = AdminService::new(Arc::clone(&store), approvals, Arc::clone(&models), logs);
    Fixture {
        store,
        models,
        admin,
        dir,
        next: std::sync::atomic::AtomicU32::new(0),
    }
}

impl Fixture {
    fn models_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Runs one admin op through the whole service (row, tripwire,
    /// deadline, audit) and asserts the invariant every admin op owes:
    /// exactly one terminal audit row.
    async fn run(&self, op: &str, args: Value) -> Response {
        let index = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = format!("req_model_{index:03}");
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: id.clone(),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: "/repo/anywhere".to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 15_000,
            wait: true,
        };
        let response = self.admin.handle(&envelope).await;
        self.assert_single_terminal_audit(&id, &response).await;
        response
    }

    /// The op's request row is terminal, belongs to the gui repo, and
    /// carries exactly one terminal audit row.
    async fn assert_single_terminal_audit(&self, id: &str, response: &Response) {
        let row = self
            .store
            .get_request(id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("admin request {id} has a row"));
        assert_eq!(row.repo, ADMIN_REPO, "admin rows belong to the gui repo");
        let expected = match response {
            Response::Result { .. } => RequestState::Done,
            _ => RequestState::Refused,
        };
        assert_eq!(row.state, expected, "terminal state of {id}");

        let terminal: Vec<String> = self
            .store
            .audit_for_request(id)
            .await
            .unwrap()
            .into_iter()
            .filter(|audit| TERMINAL_ACTIONS.contains(&audit.action.as_str()))
            .map(|audit| audit.action)
            .collect();
        assert_eq!(
            terminal.len(),
            1,
            "request {id} should have exactly one terminal audit row, got {terminal:?}"
        );
    }

    /// Writes a synthetic GGUF under `<models dir>/<vendor>/<file_name>`.
    fn install_gguf(&self, vendor: &str, file_name: &str) -> PathBuf {
        let vendor_dir = self.models_dir().join(vendor);
        std::fs::create_dir_all(&vendor_dir).unwrap();
        let path = vendor_dir.join(file_name);
        std::fs::write(&path, tiny_gguf()).unwrap();
        path
    }
}

/// Unwraps a result body, asserting the outcome.
fn expect_result(response: Response, outcome: Outcome) -> Value {
    match response {
        Response::Result {
            outcome: got, body, ..
        } => {
            assert_eq!(got, outcome, "result outcome");
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

/// Unwraps a refusal, asserting the cause and that a recovery came with
/// it — a cause with no way forward is not a legible refusal.
fn expect_refusal(response: Response, cause: &str) -> String {
    match response {
        Response::Refusal {
            cause: got,
            detail,
            recovery,
            ..
        } => {
            assert_eq!(got, cause, "refusal cause");
            assert!(!recovery.is_empty(), "refusal carries a recovery line");
            detail
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ------------------------------------------------------- gguf byte fixture

/// ggml dtype ids the fixture uses.
const GGML_F32: u32 = 0;
const GGML_Q8_0: u32 = 8;

/// A little-endian GGUF writer, the same shape `pam_model`'s own parser
/// tests use: enough header for `read_info` to succeed, no tensor data.
#[derive(Default)]
struct GgufWriter {
    buf: Vec<u8>,
}

impl GgufWriter {
    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u64(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    fn kv_string(&mut self, key: &str, value: &str) {
        self.string(key);
        self.u32(8);
        self.string(value);
    }

    fn kv_u32(&mut self, key: &str, value: u32) {
        self.string(key);
        self.u32(4);
        self.u32(value);
    }

    fn tensor(&mut self, name: &str, dims: &[u64], dtype: u32, offset: u64) {
        self.string(name);
        self.u32(u32::try_from(dims.len()).unwrap());
        for dim in dims {
            self.u64(*dim);
        }
        self.u32(dtype);
        self.u64(offset);
    }
}

/// A minimal valid `qwen3` GGUF header — far under the engine floor, so
/// the registry classes it `test_only`, which is exactly what the floor
/// refusal needs to be provable without 18 GB of weights.
fn tiny_gguf() -> Vec<u8> {
    let mut w = GgufWriter::default();
    w.buf.extend_from_slice(b"GGUF");
    w.u32(3);
    w.u64(2); // tensors
    w.u64(4); // metadata kv
    w.kv_string("general.architecture", "qwen3");
    w.kv_u32("general.file_type", 7); // Q8_0
    w.kv_string("general.name", "Tiny test model");
    w.kv_u32("qwen3.context_length", 4096);
    // 512 x 256 Q8_0 blocks of 32 elements at 34 bytes, rounded to the
    // 32-byte default alignment.
    w.tensor("token_embd.weight", &[512, 256], GGML_Q8_0, 0);
    w.tensor("output_norm.weight", &[512], GGML_F32, 139_264);
    w.buf
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn every_model_op_is_dispatched_and_none_is_unknown() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        assert_eq!(MODEL_ADMIN_OPS.len(), 15, "the spec's fifteen ops");
        for op in MODEL_ADMIN_OPS {
            assert!(op.starts_with("admin."), "{op} is under the admin prefix");
            // Called with no arguments: whatever comes back, it must not
            // be "no such op" — the dispatcher owns every one of them.
            let response = fx.run(op, json!({})).await;
            if let Response::Refusal { cause, .. } = &response {
                assert_ne!(cause, CAUSE_UNKNOWN_ADMIN_OP, "{op} is not dispatched");
            }
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn list_on_an_empty_models_dir_is_empty_not_an_error() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let body = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
        assert_eq!(body["models"].as_array().unwrap().len(), 0);
        assert_eq!(
            body["models_dir"],
            fx.models_dir().display().to_string().as_str()
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn list_reports_a_synthesized_model_as_test_only() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        fx.install_gguf("qwen", "tiny.gguf");

        let body = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
        let models = body["models"].as_array().unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["id"], "qwen/tiny");
        assert_eq!(models[0]["vendor"], "qwen");
        assert_eq!(models[0]["class"], "test_only");
        assert_eq!(models[0]["info"]["architecture"], "qwen3");
        assert_eq!(models[0]["verified"], Value::Null);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn catalog_flags_every_preset_for_this_host() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let first = CATALOG.first().expect("a catalog entry");
        fx.install_gguf(first.vendor, first.file_name);

        let body = expect_result(
            fx.run(OP_MODELS_CATALOG, json!({})).await,
            Outcome::Verified,
        );
        let presets = body["presets"].as_array().unwrap();
        assert_eq!(presets.len(), CATALOG.len());
        assert_eq!(body["floor_bytes"], pam_model::MODEL_FLOOR_BYTES);
        let host_ram = body["host_ram_bytes"].as_u64().expect("host ram");

        for (value, preset) in presets.iter().zip(CATALOG) {
            assert_eq!(value["id"], preset.id);
            assert_eq!(value["quant"], preset.quant);
            assert_eq!(value["fits_host"], preset.fits_host(host_ram));
            assert_eq!(value["installed"], preset.id == first.id);
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_test_only_model_is_refused_as_a_tier_default() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        fx.install_gguf("qwen", "tiny.gguf");

        let detail = expect_refusal(
            fx.run(
                OP_MODELS_DEFAULTS_SET,
                json!({ "tier": "heavy", "model_id": "qwen/tiny" }),
            )
            .await,
            CAUSE_BELOW_FLOOR,
        );
        assert!(detail.contains("qwen/tiny"), "detail: {detail}");
        assert_eq!(fx.models.defaults().await.unwrap(), (None, None));

        // Clearing a tier is always allowed — that is how a human goes
        // back to the deterministic path.
        let body = expect_result(
            fx.run(OP_MODELS_DEFAULTS_SET, json!({ "tier": "light" }))
                .await,
            Outcome::Changed,
        );
        assert_eq!(body["model_id"], Value::Null);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn defaults_set_refuses_an_unknown_model_and_an_unknown_tier() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        expect_refusal(
            fx.run(
                OP_MODELS_DEFAULTS_SET,
                json!({ "tier": "light", "model_id": "qwen/nothing" }),
            )
            .await,
            CAUSE_UNKNOWN_MODEL,
        );
        expect_refusal(
            fx.run(
                OP_MODELS_DEFAULTS_SET,
                json!({ "tier": "medium", "model_id": "qwen/nothing" }),
            )
            .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn download_of_an_unknown_preset_is_an_argument_refusal() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let detail = expect_refusal(
            fx.run(OP_MODELS_DOWNLOAD, json!({ "preset_id": "not-a-preset" }))
                .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
        assert!(detail.contains("not-a-preset"), "detail: {detail}");

        // A pasted URL that names no .gguf is the same kind of mistake.
        expect_refusal(
            fx.run(
                OP_MODELS_DOWNLOAD,
                json!({ "url": "https://example.invalid/", "vendor": "qwen" }),
            )
            .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn a_pasted_url_downloads_end_to_end_and_lands_verified() {
    if pam_model::download::curl_path().is_err() {
        // Every supported platform ships curl; a machine without one
        // refuses `curl_missing` and has nothing else to prove here.
        return;
    }
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let body = tiny_gguf();
        let origin = pam_model::testing::serve(body.clone(), "\"etag-1\"").await;

        let started = expect_result(
            fx.run(
                OP_MODELS_DOWNLOAD,
                json!({ "url": origin.url("tiny.gguf"), "vendor": "qwen" }),
            )
            .await,
            Outcome::Changed,
        );
        let job_id = started["job_id"].as_str().expect("a job id").to_owned();
        assert!(job_id.starts_with("job_"));

        // The follower writes the verdict onto the row; poll for it
        // rather than assuming a duration.
        let job = loop {
            let jobs = fx.store.list_model_jobs(10).await.unwrap();
            let job = jobs.into_iter().find(|job| job.id == job_id).expect("row");
            if job.state != "running" {
                break job;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(job.state, "done", "job detail: {:?}", job.detail);
        assert_eq!(job.kind, "download");
        assert_eq!(job.model_id, "qwen/tiny");
        assert_eq!(job.bytes_done, i64::try_from(body.len()).unwrap());
        let detail: Value = serde_json::from_str(&job.detail.unwrap()).unwrap();
        let digest = detail["sha256"].as_str().expect("a digest").to_owned();
        assert_eq!(digest.len(), 64, "a hex sha-256");
        assert_eq!(detail["size_bytes"], body.len());

        // The file is where the registry expects it — and honestly
        // unverified: a pasted URL carries no digest to check against, so
        // nothing claims the bytes are what anyone intended.
        let listed = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
        let entry = &listed["models"][0];
        assert_eq!(entry["id"], "qwen/tiny");
        assert_eq!(entry["class"], "test_only");
        assert_eq!(entry["verified"], Value::Null);

        // Verifying it records the digest, and it is the one the transfer
        // computed on the way in.
        let verify = expect_result(
            fx.run(OP_MODELS_VERIFY, json!({ "model_id": "qwen/tiny" }))
                .await,
            Outcome::Changed,
        );
        let verify_job = verify["job_id"].as_str().unwrap().to_owned();
        loop {
            let jobs = fx.store.list_model_jobs(10).await.unwrap();
            let job = jobs.into_iter().find(|job| job.id == verify_job).unwrap();
            if job.state != "running" {
                assert_eq!(job.state, "done", "verify detail: {:?}", job.detail);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let listed = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
        assert_eq!(listed["models"][0]["verified"]["sha256"], digest.as_str());

        // Downloading it again is refused: PAM never overwrites weights.
        expect_refusal(
            fx.run(
                OP_MODELS_DOWNLOAD,
                json!({ "url": origin.url("tiny.gguf"), "vendor": "qwen" }),
            )
            .await,
            CAUSE_ALREADY_INSTALLED,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn cancelling_a_job_that_is_not_in_flight_is_refused() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        expect_refusal(
            fx.run(OP_MODELS_DOWNLOAD_CANCEL, json!({ "job_id": "job_gone" }))
                .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn verify_starts_a_job_and_delete_clears_the_default_it_held() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let path = fx.install_gguf("qwen", "tiny.gguf");

        let started = expect_result(
            fx.run(OP_MODELS_VERIFY, json!({ "model_id": "qwen/tiny" }))
                .await,
            Outcome::Changed,
        );
        let job_id = started["job_id"].as_str().unwrap().to_owned();
        let job = loop {
            let jobs = fx.store.list_model_jobs(10).await.unwrap();
            let job = jobs.into_iter().find(|job| job.id == job_id).expect("row");
            if job.state != "running" {
                break job;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(job.state, "done");
        assert_eq!(job.kind, "verify");

        // A test-only model cannot be a default through the op, so seed
        // one directly: deleting it must still clear the setting.
        fx.models
            .set_default(Tier::Light, Some("qwen/tiny"))
            .await
            .unwrap();
        let body = expect_result(
            fx.run(OP_MODELS_DELETE, json!({ "model_id": "qwen/tiny" }))
                .await,
            Outcome::Changed,
        );
        assert_eq!(body["deleted"], true);
        assert_eq!(body["cleared_defaults"], json!(["light"]));
        assert!(!path.exists(), "the weights are gone");
        assert_eq!(fx.models.defaults().await.unwrap(), (None, None));

        // And the second delete has nothing to remove.
        expect_refusal(
            fx.run(OP_MODELS_DELETE, json!({ "model_id": "qwen/tiny" }))
                .await,
            CAUSE_UNKNOWN_MODEL,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn load_and_verify_refuse_a_model_that_is_not_there() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        for op in [OP_MODELS_LOAD, OP_MODELS_VERIFY, OP_MODELS_DELETE] {
            expect_refusal(
                fx.run(op, json!({ "model_id": "qwen/absent" })).await,
                CAUSE_UNKNOWN_MODEL,
            );
        }
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn try_with_nothing_loaded_says_so() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let detail = expect_refusal(
            fx.run(OP_MODELS_TRY, json!({ "prompt": "hello" })).await,
            "no_model_loaded",
        );
        assert!(!detail.is_empty());

        // And an empty prompt never reaches the runtime at all.
        expect_refusal(
            fx.run(OP_MODELS_TRY, json!({ "prompt": "" })).await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn unload_on_an_idle_runtime_is_a_success() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let body = expect_result(fx.run(OP_MODELS_UNLOAD, json!({})).await, Outcome::Changed);
        assert_eq!(body["state"]["state"], "idle");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn status_carries_the_runtime_jobs_defaults_and_settings() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let body = expect_result(fx.run(OP_MODELS_STATUS, json!({})).await, Outcome::Verified);
        assert_eq!(body["runtime"]["state"]["state"], "idle");
        assert_eq!(body["runtime"]["busy"], false);
        assert_eq!(body["jobs"].as_array().unwrap().len(), 0);
        assert_eq!(body["defaults"]["light"], Value::Null);
        assert_eq!(body["defaults"]["heavy"], Value::Null);
        assert_eq!(body["idle_unload_min"], 10);
        assert_eq!(
            body["models_dir"],
            fx.models_dir().display().to_string().as_str()
        );
        assert!(body["host_ram_bytes"].as_u64().is_some());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn settings_set_moves_the_models_dir_and_the_idle_window() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let elsewhere = tempfile::tempdir().unwrap();

        let body = expect_result(
            fx.run(
                OP_MODELS_SETTINGS_SET,
                json!({
                    "models_dir": elsewhere.path().display().to_string(),
                    "idle_unload_min": 0,
                }),
            )
            .await,
            Outcome::Changed,
        );
        assert_eq!(
            body["models_dir"],
            elsewhere.path().display().to_string().as_str()
        );
        assert_eq!(body["idle_unload_min"], 0);
        assert_eq!(fx.models.models_dir(), elsewhere.path());

        // A directory that is not there is refused, and nothing moves.
        expect_refusal(
            fx.run(
                OP_MODELS_SETTINGS_SET,
                json!({ "models_dir": "/nowhere/pam/does/not/exist" }),
            )
            .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
        assert_eq!(fx.models.models_dir(), elsewhere.path());
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn curator_list_answers_with_whatever_is_on_path() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        let body = expect_result(fx.run(OP_CURATOR_LIST, json!({})).await, Outcome::Verified);
        // The machine decides how many CLIs exist; the shape does not.
        assert!(body["detected"].is_array());
        assert_eq!(body["selected"], Value::Null);
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn curator_set_refuses_an_agent_that_is_not_installed() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        // Detection reads the daemon's own PATH; pick whichever of the
        // four is not on this machine so the test is honest anywhere.
        let listed = expect_result(fx.run(OP_CURATOR_LIST, json!({})).await, Outcome::Verified);
        let detected: Vec<String> = listed["detected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cli| cli["id"].as_str().unwrap().to_owned())
            .collect();
        let Some(absent) = ["gemini", "copilot", "codex", "claude"]
            .into_iter()
            .find(|name| !detected.iter().any(|found| found == name))
        else {
            // All four installed: nothing to prove a refusal with.
            return;
        };

        let detail = expect_refusal(
            fx.run(OP_CURATOR_SET, json!({ "agent": absent })).await,
            CAUSE_NOT_DETECTED,
        );
        assert!(detail.contains(absent), "detail: {detail}");
        assert_eq!(fx.store.get_setting(SETTING_CURATOR).await.unwrap(), None);

        // A name from no known vendor is an argument mistake instead.
        expect_refusal(
            fx.run(OP_CURATOR_SET, json!({ "agent": "not-an-agent" }))
                .await,
            CAUSE_INVALID_ADMIN_ARGS,
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn curator_test_without_a_pick_says_there_is_no_curator() {
    timeout(DEADLINE, async {
        let fx = fixture().await;
        expect_refusal(fx.run(OP_CURATOR_TEST, json!({})).await, CAUSE_NO_CURATOR);

        // Clearing the pick is always allowed and always answers null.
        let body = expect_result(fx.run(OP_CURATOR_SET, json!({})).await, Outcome::Changed);
        assert_eq!(body["selected"], Value::Null);
        expect_refusal(fx.run(OP_CURATOR_TEST, json!({})).await, CAUSE_NO_CURATOR);
    })
    .await
    .expect("test within deadline");
}
