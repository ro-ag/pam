use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(unix)]
use pam_model::engine::EngineSource;
use pam_model::engine::{self, ENGINE_BUILD, ENGINE_TAG, EngineRelease, Target};
use pam_net::{NetFailure, NetSettings, NetworkSource};
use pam_proto::{Caller, Envelope, Outcome, PROTOCOL_VERSION, Response};
use pam_store::Store;
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::admin::{ADMIN_CALLER_AGENT, AdminService, CAUSE_INVALID_ADMIN_ARGS};
use crate::admin_engine::{
    CAUSE_ENGINE_BUSY, OP_ENGINE_IMPORT, OP_ENGINE_INSTALL, OP_ENGINE_REMOVE, OP_ENGINE_STATUS,
    install_cancellation,
};
use crate::admin_models::{
    OP_MODELS_CATALOG, OP_MODELS_IMPORT, OP_MODELS_LIST, OP_MODELS_LOAD, OP_MODELS_TRY,
    OP_MODELS_UNLOAD, OP_MODELS_VERIFY,
};
use crate::admin_models_test::{expect_refusal, expect_result, tiny_gguf};
use crate::approval::ApprovalService;
use crate::connector_service::ConnectorService;
use crate::log_service::LogService;
use crate::model_service::ModelService;
use crate::network_service::{
    FixedManagedNetwork, ManagedNetwork, NetworkDocument, NetworkService,
};
use crate::transport::EventPublisher;

const DEADLINE: Duration = Duration::from_secs(60);
const LONG_TIMEOUT: Duration = Duration::from_mins(10);
const MIRROR: &str = "https://artifacts.corp.example/llama.cpp/b10938/";

/// The install future lives under the admin deadline; when the deadline
/// drops it, the cancel receiver the transfer polls must observe `true` —
/// a dropped sender alone leaves `false` behind and `changed()` would then
/// pend forever on the closed channel, with curl running detached.
#[tokio::test(start_paused = true)]
async fn dropping_the_install_future_signals_its_cancel_receiver() {
    let (guard, mut cancel) = install_cancellation();
    let install = async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(120), install)
            .await
            .is_err(),
        "the deadline dropped the install"
    );
    assert!(*cancel.borrow(), "cancellation was requested on drop");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), cancel.changed())
            .await
            .is_ok(),
        "a waiter on changed() wakes rather than pending forever"
    );
}

// ---------------------------------------------------------------- fixture

/// A network source that refuses every request and counts them: the
/// air-gapped machine. An engine or weights import must never ask it.
#[derive(Default)]
struct RefusingSource {
    asked: AtomicUsize,
}

impl NetworkSource for RefusingSource {
    fn settings(
        &self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Arc<NetSettings>, NetFailure>> + Send + '_>>
    {
        self.asked.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err(NetFailure::SettingsInvalid(
                "this machine has no network; the test forbids every request".to_owned(),
            ))
        })
    }
}

struct Fixture {
    store: Arc<Store>,
    policy: Arc<crate::managed_policy_service::PolicyHandle>,
    models: Arc<ModelService>,
    admin: AdminService,
    network: Option<Arc<NetworkService>>,
    /// Short, so the engine's Unix socket path fits in 104 bytes.
    base: tempfile::TempDir,
    models_dir: tempfile::TempDir,
    next: AtomicU32,
}

/// An admin service over a temp base: with the daemon's network service
/// (mirror tests) or with `source` as the only network source (air gap).
async fn fixture(
    managed: Option<ManagedNetwork>,
    source: Option<Arc<dyn NetworkSource>>,
) -> Fixture {
    fixture_with(None, managed, source).await
}

/// [`fixture`] under the managed policy file `policy` (a trusted, scripted
/// one) that the daemon's services read.
async fn fixture_with(
    policy: Option<&str>,
    managed: Option<ManagedNetwork>,
    source: Option<Arc<dyn NetworkSource>>,
) -> Fixture {
    let mut base = tempfile::Builder::new();
    base.prefix("pam-eng-");
    // Windows has no such socket path to fit, and no `/tmp`.
    #[cfg(unix)]
    let base = base.tempdir_in("/tmp").expect("tempdir");
    #[cfg(not(unix))]
    let base = base.tempdir().expect("tempdir");
    let models_dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let policy = crate::admin_models_test::policy_handle(&store, policy).await;
    let (events, _rx) = EventPublisher::for_tests();
    let approvals = Arc::new(ApprovalService::new(
        Arc::clone(&store),
        events,
        LONG_TIMEOUT,
        Arc::clone(&policy),
    ));
    let models = ModelService::new(Arc::clone(&store), Arc::clone(&policy))
        .await
        .unwrap();
    models.set_models_dir(models_dir.path()).await.unwrap();
    models.set_engine_base(base.path().to_path_buf());
    let network = if let Some(source) = source {
        models.set_network_source(source);
        None
    } else {
        let network = Arc::new(
            NetworkService::new(Arc::clone(&store), None, base.path().to_path_buf())
                .with_managed(Arc::new(FixedManagedNetwork::new(managed))),
        );
        models.set_network_service(Arc::clone(&network));
        Some(network)
    };
    let logs = LogService::new(Arc::clone(&store), Arc::clone(&models));
    let connectors = Arc::new(ConnectorService::from_parts(
        Arc::clone(&store),
        None,
        None,
        Arc::clone(&policy),
    ));
    let flows = crate::flow_service_test::flows_for_tests(
        Path::new("pam-tests-have-no-flow-library"),
        &store,
        &approvals,
        &connectors,
        &logs,
    )
    .await;
    let mut admin = AdminService::new(
        Arc::clone(&store),
        approvals,
        Arc::clone(&models),
        logs,
        connectors,
        flows,
        crate::flow_service_test::closed_submit(),
        Arc::clone(&policy),
    );
    if let Some(network) = &network {
        admin = admin.with_network(Arc::clone(network));
    }
    Fixture {
        store,
        policy,
        models,
        admin,
        network,
        base,
        models_dir,
        next: AtomicU32::new(0),
    }
}

impl Fixture {
    /// The id of the request the last [`Self::run`] used.
    fn last_request_id(&self) -> String {
        let index = self.next.load(Ordering::Relaxed) - 1;
        format!("req_engine_{index:03}")
    }

    /// The last op's request carries the terminal `admin`/`refuse` row and
    /// the policy's `policy.locked_write` row, naming the op, the key, the
    /// cause and the full digest.
    async fn assert_refused_by_policy(&self, op: &str, cause: &str, key: &str) {
        let rows = self
            .store
            .audit_for_request(&self.last_request_id())
            .await
            .unwrap();
        assert!(
            rows.iter()
                .any(|row| row.action == crate::admin::ACTION_ADMIN
                    && row.decision == pam_store::Decision::Refuse),
            "{rows:?}"
        );
        let row = rows
            .iter()
            .find(|row| row.action == "policy.locked_write")
            .unwrap_or_else(|| panic!("no policy.locked_write row in {rows:?}"));
        let detail: Value = serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["op"], op);
        assert_eq!(detail["cause"], cause);
        assert_eq!(detail["keys"], json!([key]));
        assert_eq!(detail["digest"].as_str(), self.policy.view().digest());
    }

    async fn run(&self, op: &str, args: Value) -> Response {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            id: format!("req_engine_{index:03}"),
            capability: op.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            caller: Caller {
                agent: ADMIN_CALLER_AGENT.to_owned(),
                repo: "/repo/anywhere".to_owned(),
                pid: 4242,
            },
            args,
            idempotency_key: None,
            deadline_ms: 50_000,
            wait: true,
        };
        self.admin.handle(&envelope).await
    }

    async fn status(&self) -> Value {
        expect_result(
            self.run(OP_ENGINE_STATUS, json!({})).await,
            Outcome::Verified,
        )
    }

    /// Saves an engine mirror the way `admin.network.set` would store it.
    async fn save_engine_mirror(&self, mirror: &str) {
        let network = self.network.as_ref().expect("a network service");
        let document = NetworkDocument {
            engine_mirror: Some(mirror.to_owned()),
            ..NetworkDocument::default()
        };
        assert!(network.save(None, &document).await.unwrap());
    }

    /// Polls a job row to its verdict.
    async fn settled_job(&self, job_id: &str) -> pam_store::ModelJobRow {
        loop {
            let jobs = self.store.list_model_jobs(20).await.unwrap();
            let job = jobs.into_iter().find(|job| job.id == job_id).expect("row");
            if job.state != "running" {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
}

/// The pinned asset for this host.
fn pinned() -> &'static engine::EngineAsset {
    Target::current().expect("a supported host").asset()
}

/// What the release archive holds the server as on this host.
const SERVER_FILE: &str = if cfg!(windows) {
    "llama-server.exe"
} else {
    "llama-server"
};

// ------------------------------------------------------------------ tests

/// None of the engine ops takes a digest, a tag, a build, an address or a
/// size: every unknown key is refused before anything is read, and the
/// three that change files need `confirm: true`.
#[tokio::test]
async fn engine_ops_refuse_unknown_arguments_and_need_confirmation() {
    timeout(DEADLINE, async {
        let fx = fixture(None, None).await;
        for (op, base) in [
            (OP_ENGINE_INSTALL, json!({ "confirm": true })),
            (
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": "/nowhere" }),
            ),
            (OP_ENGINE_REMOVE, json!({ "confirm": true })),
            (OP_ENGINE_STATUS, json!({})),
        ] {
            for stray in ["sha256", "tag", "build", "url", "bytes", "digest", "asset"] {
                let mut args = base.clone();
                args[stray] = json!("x");
                let detail = expect_refusal(fx.run(op, args).await, CAUSE_INVALID_ADMIN_ARGS);
                assert!(detail.contains(stray), "{op} {stray}: {detail}");
            }
        }
        for (op, args) in [
            (OP_ENGINE_INSTALL, json!({})),
            (OP_ENGINE_INSTALL, json!({ "confirm": false })),
            (OP_ENGINE_IMPORT, json!({ "path": "/nowhere" })),
            (OP_ENGINE_REMOVE, json!({})),
            (OP_ENGINE_REMOVE, json!({ "confirm": "yes" })),
        ] {
            let detail = expect_refusal(fx.run(op, args).await, CAUSE_INVALID_ADMIN_ARGS);
            assert!(detail.contains("confirm"), "{op}: {detail}");
        }
        // A relative path, or no path, is an argument refusal too.
        for args in [
            json!({ "confirm": true }),
            json!({ "confirm": true, "path": "" }),
            json!({ "confirm": true, "path": "relative/llama.tar.gz" }),
        ] {
            expect_refusal(
                fx.run(OP_ENGINE_IMPORT, args).await,
                CAUSE_INVALID_ADMIN_ARGS,
            );
        }
        assert!(!engine::status(&fx.models.engine_base()).installed);
        assert!(
            !fx.base.path().join("engine").exists(),
            "no refused op created the engine directory"
        );
    })
    .await
    .expect("test within deadline");
}

/// Before any click the status says exactly what Install would fetch and
/// check: the pinned asset, size and digest, the upstream URL and host;
/// with a mirror saved, the mirror's URL and host and `mirror_in_use`; the
/// catalog's `fetch` likewise shows the models host. A mirror the policy
/// does not allow is reported, not used.
#[tokio::test]
async fn status_discloses_what_install_would_fetch_and_from_where() {
    timeout(DEADLINE, async {
        let fx = fixture(None, None).await;
        let asset = pinned();
        let body = fx.status().await;
        assert_eq!(body["installed"], false);
        assert_eq!(body["cause"], "not_installed");
        assert_eq!(body["expected_tag"], ENGINE_TAG);
        assert_eq!(body["expected_build"], ENGINE_BUILD);
        assert_eq!(body["expected_asset"], asset.name);
        assert_eq!(body["expected_size"], asset.bytes);
        assert_eq!(body["expected_sha256"], asset.sha256);
        assert_eq!(
            body["download_url"],
            format!("{}{}", engine::ENGINE_RELEASE_BASE, asset.name)
        );
        assert_eq!(body["download_host"], "github.com");
        assert_eq!(body["upstream_host"], "github.com");
        assert_eq!(body["mirror_in_use"], false);
        assert_eq!(body["mirror_host"], Value::Null);
        assert_eq!(
            body["engine_dir"],
            fx.base.path().join("engine").display().to_string()
        );
        assert_eq!(
            body["install_dir"],
            fx.base
                .path()
                .join("engine")
                .join(format!("llama-{ENGINE_TAG}"))
                .display()
                .to_string()
        );
        assert_eq!(body["source"], Value::Null);
        assert_eq!(body["loaded"], false);
        assert_eq!(body["removable"], false);
        assert!(body.get("network_issue").is_none());

        // The catalog shows the upstream host for every preset.
        let catalog = expect_result(
            fx.run(OP_MODELS_CATALOG, json!({})).await,
            Outcome::Verified,
        );
        let first = &catalog["presets"][0];
        assert_eq!(first["fetch"]["source"], "upstream");
        assert_eq!(first["fetch"]["host"], "huggingface.co");
        assert_eq!(first["fetch"]["url"], pam_model::CATALOG[0].url);
        assert_eq!(catalog["models_mirror"], Value::Null);

        // With a mirror saved, the URL is the mirror's plus the pinned name.
        fx.save_engine_mirror(MIRROR).await;
        let body = fx.status().await;
        assert_eq!(body["mirror_in_use"], true);
        assert_eq!(body["mirror_host"], "artifacts.corp.example");
        assert_eq!(body["download_host"], "artifacts.corp.example");
        assert_eq!(body["download_url"], format!("{MIRROR}{}", asset.name));
        assert_eq!(
            body["expected_sha256"], asset.sha256,
            "the digest is not the mirror's"
        );
        assert_eq!(body["upstream_host"], "github.com");
    })
    .await
    .expect("test within deadline");
}

/// A managed policy that names allowed mirror hosts makes any other mirror
/// an unusable setting: the status says so and the install refuses by
/// name, never falling back to upstream.
#[tokio::test]
async fn a_mirror_outside_the_policy_allowlist_refuses_the_install_by_name() {
    timeout(DEADLINE, async {
        let managed = ManagedNetwork {
            mirror_allowed_hosts: vec!["mirrors.corp.example".to_owned()],
            ..ManagedNetwork::default()
        };
        let fx = fixture(Some(managed), None).await;
        fx.save_engine_mirror(MIRROR).await;
        let body = fx.status().await;
        assert_eq!(body["network_issue"]["cause"], "network_settings_invalid");
        assert!(
            body["network_issue"]["detail"]
                .as_str()
                .unwrap()
                .contains("artifacts.corp.example"),
            "{body}"
        );
        assert_eq!(body["mirror_in_use"], false);
        assert_eq!(
            body["download_url"],
            format!("{}{}", engine::ENGINE_RELEASE_BASE, pinned().name),
            "the disclosure shows upstream, which is what a repaired setting would fetch"
        );
        let detail = expect_refusal(
            fx.run(OP_ENGINE_INSTALL, json!({ "confirm": true })).await,
            "network_settings_invalid",
        );
        assert!(detail.contains("artifacts.corp.example"), "{detail}");
        assert!(
            !fx.base.path().join("engine").exists(),
            "nothing was fetched"
        );
    })
    .await
    .expect("test within deadline");
}

/// The production import path, with the compiled-in pin: a file carrying
/// another name is refused naming the asset this build needs; a file with
/// the right name and the wrong size is refused with both sizes; a symlink
/// and a missing path are refused by name. Nothing is copied or installed.
#[tokio::test]
async fn import_refuses_what_is_not_the_pinned_archive_with_the_pinned_numbers() {
    timeout(DEADLINE, async {
        let fx = fixture(None, Some(Arc::new(RefusingSource::default()))).await;
        let asset = pinned();
        let share = tempfile::tempdir().unwrap();

        let other = share.path().join("llama-b1-bin-other.tar.gz");
        std::fs::write(&other, b"x").unwrap();
        let detail = expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": other.display().to_string() }),
            )
            .await,
            "engine_import_not_the_asset",
        );
        assert!(detail.contains(asset.name), "{detail}");
        assert!(detail.contains(&asset.bytes.to_string()), "{detail}");
        assert!(detail.contains(asset.sha256), "{detail}");

        let unpacked = share.path().join(format!("llama-{ENGINE_TAG}"));
        std::fs::create_dir(&unpacked).unwrap();
        std::fs::write(unpacked.join(SERVER_FILE), b"x").unwrap();
        let detail = expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": unpacked.display().to_string() }),
            )
            .await,
            "engine_import_not_the_asset",
        );
        assert!(detail.contains("holds no"), "{detail}");

        let wrong_size = share.path().join(asset.name);
        std::fs::write(&wrong_size, b"not the release").unwrap();
        let detail = expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": wrong_size.display().to_string() }),
            )
            .await,
            "engine_size_mismatch",
        );
        assert!(detail.contains(&asset.bytes.to_string()), "{detail}");
        assert!(detail.contains("15 bytes"), "{detail}");

        #[cfg(unix)]
        {
            let link = share.path().join("link");
            std::os::unix::fs::symlink(&wrong_size, &link).unwrap();
            expect_refusal(
                fx.run(
                    OP_ENGINE_IMPORT,
                    json!({ "confirm": true, "path": link.display().to_string() }),
                )
                .await,
                "engine_import_symlink",
            );
        }
        expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": share.path().join("absent").display().to_string() }),
            )
            .await,
            "engine_import_source_missing",
        );
        let engine_dir = fx.base.path().join("engine");
        assert!(
            !engine_dir.exists() || std::fs::read_dir(&engine_dir).unwrap().next().is_none(),
            "nothing was copied"
        );
        assert_eq!(fx.status().await["installed"], false);
    })
    .await
    .expect("test within deadline");
}

/// The fake server packed as the pinned release would be: a `.tar.gz` (a
/// `.zip` on Windows) holding `llama-<tag>/llama-server`, built with the OS
/// tar the installer uses, and the release pinned to its bytes (tag and
/// build stay the real pin, which is what `engine::status` reads).
fn fake_release_archive(fake: &Path) -> (tempfile::TempDir, PathBuf, EngineRelease) {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join(format!("llama-{ENGINE_TAG}"));
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::copy(fake, tree.join(SERVER_FILE)).unwrap();
    let extension = if cfg!(windows) { "zip" } else { "tar.gz" };
    let asset_name = format!("llama-{ENGINE_TAG}-bin-test.{extension}");
    let archive = dir.path().join(&asset_name);
    let mut tar = std::process::Command::new(engine::trusted_tar_path().unwrap());
    // `-a` picks the format from the suffix (the Windows tar writes zip).
    tar.arg(if cfg!(windows) { "-acf" } else { "-czf" })
        .arg(&archive)
        .arg("-C")
        .arg(dir.path())
        .arg(format!("llama-{ENGINE_TAG}"));
    assert!(tar.status().unwrap().success());
    let bytes = std::fs::read(&archive).unwrap();
    let release = EngineRelease {
        tag: ENGINE_TAG.to_owned(),
        build: ENGINE_BUILD,
        url_base: "https://releases.pam-test.invalid/llama/".to_owned(),
        target: Target::current().unwrap(),
        asset_name,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
    };
    (dir, archive, release)
}

/// The air-gapped first run, end to end, with a network source that
/// refuses every request: import the engine from a file → status says
/// installed from that file → import weights from a file → verify → load
/// → one generation; then Remove is refused while the model is loaded,
/// and clears the engine directory once it is unloaded. The network
/// source is never asked, so curl never ran.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one first run, step by step, in the order a human performs it"
)]
async fn an_air_gapped_first_run_imports_the_engine_and_weights_and_generates() {
    let Some(fake) = crate::model_service_test::fake_engine_binary() else {
        eprintln!("pam-fake-llama-server not built; skipping");
        return;
    };
    timeout(
        DEADLINE,
        Box::pin(async move {
            let source = Arc::new(RefusingSource::default());
            let fx = fixture(None, Some(Arc::clone(&source) as Arc<dyn NetworkSource>)).await;
            let (_share, archive, release) = fake_release_archive(&fake);
            fx.models.pin_engine_release_for_tests(release.clone());
            let before = std::fs::metadata(&archive).unwrap();

            // 1. The engine, from the folder IT dropped it in.
            let body = expect_result(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": archive.parent().unwrap().display().to_string() }),
            )
            .await,
            Outcome::Changed,
        );
            assert_eq!(body["installed"], true, "{body}");
            assert_eq!(body["cause"], Value::Null);
            assert_eq!(body["source"]["kind"], "import");
            assert_eq!(
                body["source"]["path"],
                archive.parent().unwrap().display().to_string()
            );
            assert_eq!(body["manifest"]["sha256"], release.sha256);
            assert_eq!(body["manifest"]["asset"], release.asset_name);
            assert_eq!(body["removable"], true);
            assert_eq!(body["loaded"], false);
            let status = fx.status().await;
            assert_eq!(status["installed"], true);
            assert_eq!(status["source"]["kind"], "import");
            assert!(
                status["manifest"]["version_line"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("build {ENGINE_BUILD}")),
                "{status}"
            );
            let after = std::fs::metadata(&archive).unwrap();
            assert_eq!(after.len(), before.len());
            assert_eq!(after.modified().unwrap(), before.modified().unwrap());
            assert!(
                !fx.base
                    .path()
                    .join("engine")
                    .join(&release.asset_name)
                    .exists(),
                "the private copy of the archive is gone after the install"
            );
            // A second import of the same archive copies nothing: already installed.
            let again = expect_result(
                fx.run(
                    OP_ENGINE_IMPORT,
                    json!({ "confirm": true, "path": archive.display().to_string() }),
                )
                .await,
                Outcome::Changed,
            );
            assert_eq!(again["manifest"], body["manifest"]);

            // 2. The weights, from a file: no digest known, so unverified.
            let weights_dir = tempfile::tempdir().unwrap();
            let weights = weights_dir.path().join("tiny.gguf");
            std::fs::write(&weights, tiny_gguf()).unwrap();
            let started = expect_result(
            fx.run(
                OP_MODELS_IMPORT,
                json!({ "confirm": true, "path": weights.display().to_string(), "vendor": "qwen" }),
            )
            .await,
            Outcome::Changed,
        );
            assert_eq!(started["model_id"], "qwen/tiny");
            assert_eq!(started["catalog"], Value::Null);
            assert_eq!(started["verified_on_completion"], false);
            assert!(
                started["note"].as_str().unwrap().contains("unverified"),
                "{started}"
            );
            let job = fx.settled_job(started["job_id"].as_str().unwrap()).await;
            assert_eq!(job.state, "done", "{:?}", job.detail);
            // The store's `kind` vocabulary has no `import` yet (cross-T4 item 1): the
            // row is told from a download by its source, a file path.
            assert_eq!(job.kind, crate::model_service::KIND_IMPORT);
            assert_eq!(
                job.source.as_deref(),
                Some(weights.display().to_string().as_str())
            );
            assert!(!job.source.as_deref().unwrap().starts_with("https://"));
            assert!(weights.is_file(), "the original weights file is untouched");
            let listed = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
            assert_eq!(listed["models"][0]["id"], "qwen/tiny");
            assert_eq!(listed["models"][0]["class"], "test_only");

            // 3. Verify, like any hand-placed file.
            let verify = expect_result(
                fx.run(OP_MODELS_VERIFY, json!({ "model_id": "qwen/tiny" }))
                    .await,
                Outcome::Changed,
            );
            let job = fx.settled_job(verify["job_id"].as_str().unwrap()).await;
            assert_eq!(job.state, "done", "{:?}", job.detail);
            let listed = expect_result(fx.run(OP_MODELS_LIST, json!({})).await, Outcome::Verified);
            assert_eq!(listed["models"][0]["class"], "engine");

            // 4. Load on the imported engine and generate once.
            expect_result(
                fx.run(OP_MODELS_LOAD, json!({ "model_id": "qwen/tiny" }))
                    .await,
                Outcome::Changed,
            );
            let answer = expect_result(
                fx.run(
                    OP_MODELS_TRY,
                    json!({ "model_id": "qwen/tiny", "prompt": "one two three", "max_tokens": 16 }),
                )
                .await,
                Outcome::Verified,
            );
            assert_eq!(answer["text"], "echo: one two three", "{answer}");
            assert_eq!(answer["model"]["device"], "llama.cpp");

            // 5. Remove is refused while a model is loaded, and nothing is deleted.
            assert_eq!(fx.status().await["loaded"], true);
            assert_eq!(fx.status().await["removable"], false);
            let detail = expect_refusal(
                fx.run(OP_ENGINE_REMOVE, json!({ "confirm": true })).await,
                CAUSE_ENGINE_BUSY,
            );
            assert!(detail.contains("loaded"), "{detail}");
            assert_eq!(fx.status().await["installed"], true);

            // 6. Unloaded, Remove clears the engine directory: release, manifest,
            //    the private weights copy; the models directory is untouched.
            expect_result(fx.run(OP_MODELS_UNLOAD, json!({})).await, Outcome::Changed);
            let engine_dir = fx.base.path().join("engine");
            assert!(
                engine_dir.join("weights").is_dir(),
                "the verified copy lived there"
            );
            let removed = expect_result(
                fx.run(OP_ENGINE_REMOVE, json!({ "confirm": true })).await,
                Outcome::Changed,
            );
            assert_eq!(removed["removed"], true);
            assert_eq!(removed["engine_dir"], engine_dir.display().to_string());
            assert!(
                removed["entries_removed"].as_u64().unwrap() >= 3,
                "{removed}"
            );
            assert_eq!(removed["status"]["installed"], false);
            assert_eq!(removed["status"]["removable"], false);
            assert!(std::fs::read_dir(&engine_dir).unwrap().next().is_none());
            assert!(
                fx.models_dir
                    .path()
                    .join("qwen")
                    .join("tiny.gguf")
                    .is_file()
            );
            let status = fx.status().await;
            assert_eq!(status["installed"], false);
            assert_eq!(status["cause"], "not_installed");
            assert_eq!(status["source"], Value::Null);
            assert!(
                fx.models.engine_server().is_none(),
                "the supervisor was forgotten"
            );

            // Nothing above touched the network.
            assert_eq!(
                source.asked.load(Ordering::SeqCst),
                0,
                "no network request was made"
            );
        }),
    )
    .await
    .expect("test within deadline");
}

/// A tampered archive cannot be imported, whatever manifest sits beside it:
/// the daemon runs only a server whose archive hashed to the pin and whose
/// `--version` reports the pinned build. Here the digest is right and the
/// build is not (a server that lies), and a planted manifest claiming the
/// pinned digest over a foreign tree does not survive an import either.
#[cfg(unix)]
#[tokio::test]
async fn no_import_or_manifest_runs_a_server_that_is_not_the_pinned_build() {
    timeout(DEADLINE, async {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture(None, Some(Arc::new(RefusingSource::default()))).await;
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join(format!("llama-{ENGINE_TAG}"));
        std::fs::create_dir_all(&tree).unwrap();
        let server = tree.join("llama-server");
        std::fs::write(
            &server,
            format!(
                "#!/bin/sh\necho 'version: 0.0.0 (build {}, commit evil)'\n",
                ENGINE_BUILD + 1
            ),
        )
        .unwrap();
        std::fs::set_permissions(&server, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asset_name = format!("llama-{ENGINE_TAG}-bin-test.tar.gz");
        let archive = dir.path().join(&asset_name);
        assert!(
            std::process::Command::new(engine::trusted_tar_path().unwrap())
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(dir.path())
                .arg(format!("llama-{ENGINE_TAG}"))
                .status()
                .unwrap()
                .success()
        );
        let bytes = std::fs::read(&archive).unwrap();
        fx.models.pin_engine_release_for_tests(EngineRelease {
            tag: ENGINE_TAG.to_owned(),
            build: ENGINE_BUILD,
            url_base: "https://releases.pam-test.invalid/llama/".to_owned(),
            target: Target::current().unwrap(),
            asset_name,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes: bytes.len() as u64,
        });
        let detail = expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": archive.display().to_string() }),
            )
            .await,
            "engine_verify_failed",
        );
        assert!(
            detail.contains(&format!("build {ENGINE_BUILD}")),
            "{detail}"
        );
        assert_eq!(fx.status().await["installed"], false);
        assert!(fx.models.engine_server().is_none());

        // A planted manifest: the pinned tag, build and digest, over the
        // lying server. `status` believes files; the supervisor would start
        // it. The import of the real pin replaces it, and nothing else
        // accepts it: the digest it claims is not the archive's.
        let layout = engine::EngineLayout::new(&fx.models.engine_base());
        std::fs::create_dir_all(layout.install_dir(ENGINE_TAG)).unwrap();
        std::fs::copy(
            &server,
            layout.server_path(ENGINE_TAG, Target::current().unwrap()),
        )
        .unwrap();
        let planted = engine::EngineManifest {
            tag: ENGINE_TAG.to_owned(),
            build: ENGINE_BUILD,
            target: Target::current().unwrap(),
            asset: pinned().name.to_owned(),
            sha256: pinned().sha256.to_owned(),
            bytes: pinned().bytes,
            version_line: "version: planted".to_owned(),
            installed_at_ms: 0,
            source: Some(EngineSource::Download {
                host: "github.com".to_owned(),
            }),
        };
        std::fs::write(
            layout.manifest_path(),
            serde_json::to_vec(&planted).unwrap(),
        )
        .unwrap();
        // Importing the (lying) archive over it is still refused, and the
        // refusal leaves the planted install in place rather than half gone.
        expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": archive.display().to_string() }),
            )
            .await,
            "engine_verify_failed",
        );
        // Remove clears the planted tree; status is honest afterwards.
        expect_result(
            fx.run(OP_ENGINE_REMOVE, json!({ "confirm": true })).await,
            Outcome::Changed,
        );
        assert_eq!(fx.status().await["installed"], false);
    })
    .await
    .expect("test within deadline");
}

// ---------------------------------------------------------------- managed policy

/// A release pinned for the test whose archive lives on `origin`, a plain
/// loopback server that records every request it gets.
fn release_on(origin: &pam_model::testing::TestServer) -> EngineRelease {
    EngineRelease {
        tag: ENGINE_TAG.to_owned(),
        build: ENGINE_BUILD,
        url_base: origin.url(""),
        target: Target::current().expect("a supported host"),
        asset_name: "llama-policy-test.tar.gz".to_owned(),
        sha256: "0".repeat(64),
        bytes: 16,
    }
}

#[tokio::test]
async fn mirror_only_without_a_mirror_refuses_the_install_and_the_origin_sees_nothing() {
    timeout(DEADLINE, async {
        let origin = pam_model::testing::serve(vec![0; 16], "\"etag-e\"").await;
        let source = Arc::new(RefusingSource::default());
        let fx = fixture_with(
            Some(
                r#"{ "version": 1, "revision": "rev-e", "contact": "it@example.test",
                     "models": { "engine_source": "mirror_only" } }"#,
            ),
            None,
            Some(Arc::clone(&source) as Arc<dyn NetworkSource>),
        )
        .await;
        fx.models.pin_engine_release_for_tests(release_on(&origin));

        let detail = expect_refusal(
            fx.run(OP_ENGINE_INSTALL, json!({ "confirm": true })).await,
            "policy_not_allowed",
        );
        assert!(detail.contains("models.engine_source"), "{detail}");
        assert!(detail.contains("it@example.test"), "{detail}");
        assert!(detail.contains("rev rev-e"), "{detail}");
        fx.assert_refused_by_policy(
            OP_ENGINE_INSTALL,
            "policy_not_allowed",
            "models.engine_source",
        )
        .await;
        // Not a request, not a profile resolution, not a file.
        assert!(origin.requests().is_empty(), "{:?}", origin.requests());
        assert_eq!(
            source.asked.load(Ordering::SeqCst),
            0,
            "no network profile was asked for"
        );
        assert!(!fx.base.path().join("engine").exists());

        // The status says why, before the click.
        let body = fx.status().await;
        assert_eq!(body["source_policy"]["engine_source"], "mirror_only");
        assert_eq!(body["source_policy"]["install_allowed"], false);
        assert_eq!(body["source_policy"]["install_blocked"], "mirror_missing");
        assert_eq!(body["source_policy"]["effective"]["source"], "policy");
        assert_eq!(body["source_policy"]["effective"]["state"], "applied");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn mirror_only_with_a_mirror_in_force_lets_the_install_through_to_that_mirror() {
    timeout(DEADLINE, async {
        let fx = fixture_with(
            Some(r#"{ "version": 1, "models": { "engine_source": "mirror_only" } }"#),
            None,
            None,
        )
        .await;
        fx.save_engine_mirror(MIRROR).await;
        let body = fx.status().await;
        assert_eq!(body["source_policy"]["install_allowed"], true);
        assert_eq!(body["source_policy"]["install_blocked"], Value::Null);
        assert_eq!(body["mirror_in_use"], true);
        assert_eq!(
            body["download_url"],
            format!("{MIRROR}{}", pinned().name),
            "the disclosure shows the mirror, never upstream"
        );
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn import_only_refuses_install_and_leaves_import_open() {
    timeout(DEADLINE, async {
        let origin = pam_model::testing::serve(vec![0; 16], "\"etag-i\"").await;
        let fx = fixture_with(
            Some(r#"{ "version": 1, "models": { "engine_source": "import_only" } }"#),
            None,
            None,
        )
        .await;
        fx.models.pin_engine_release_for_tests(release_on(&origin));
        expect_refusal(
            fx.run(OP_ENGINE_INSTALL, json!({ "confirm": true })).await,
            "policy_not_allowed",
        );
        fx.assert_refused_by_policy(
            OP_ENGINE_INSTALL,
            "policy_not_allowed",
            "models.engine_source",
        )
        .await;
        assert!(origin.requests().is_empty());
        let body = fx.status().await;
        assert_eq!(body["source_policy"]["install_allowed"], false);
        assert_eq!(body["source_policy"]["install_blocked"], "import_only");
        assert_eq!(body["source_policy"]["import_allowed"], true);

        // Import is past the policy: it fails on the path, not on the policy.
        let missing = fx.base.path().join("no-such-archive.tar.gz");
        expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": missing.display().to_string() }),
            )
            .await,
            "engine_import_source_missing",
        );
    })
    .await
    .expect("test within deadline");
}

/// The control for the two tests above: with the policy absent the same
/// install does reach the origin, so "zero requests" proves the refusal.
#[tokio::test]
async fn without_a_source_policy_the_same_install_does_reach_the_origin() {
    if pam_model::download::curl_path().is_err() {
        return;
    }
    timeout(DEADLINE, async {
        let origin = pam_model::testing::serve(vec![0; 16], "\"etag-c\"").await;
        let fx = fixture(None, None).await;
        fx.models.pin_engine_release_for_tests(release_on(&origin));
        let body = fx.status().await;
        assert_eq!(
            body["source_policy"]["effective"],
            json!({ "source": "default", "locked": false })
        );
        assert_eq!(body["source_policy"]["install_allowed"], true);
        // The archive is not the pinned bytes, so the install fails, but only
        // after it asked the origin for them.
        let _ = fx.run(OP_ENGINE_INSTALL, json!({ "confirm": true })).await;
        assert!(!origin.requests().is_empty(), "the origin was contacted");
    })
    .await
    .expect("test within deadline");
}

#[tokio::test]
async fn an_engine_import_needs_import_among_the_allowed_sources() {
    timeout(DEADLINE, async {
        let fx = fixture_with(
            Some(r#"{ "version": 1, "models": { "allowed_sources": ["catalog"] } }"#),
            None,
            None,
        )
        .await;
        let archive = fx.base.path().join("archive.tar.gz");
        std::fs::write(&archive, b"x").unwrap();
        let detail = expect_refusal(
            fx.run(
                OP_ENGINE_IMPORT,
                json!({ "confirm": true, "path": archive.display().to_string() }),
            )
            .await,
            "policy_not_allowed",
        );
        assert!(detail.contains("models.allowed_sources"), "{detail}");
        fx.assert_refused_by_policy(
            OP_ENGINE_IMPORT,
            "policy_not_allowed",
            "models.allowed_sources",
        )
        .await;
        assert!(
            !fx.base.path().join("engine").exists(),
            "nothing was copied"
        );
        let body = fx.status().await;
        assert_eq!(body["source_policy"]["import_allowed"], false);
    })
    .await
    .expect("test within deadline");
}
