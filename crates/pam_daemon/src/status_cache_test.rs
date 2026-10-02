use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_store::Store;

use crate::blocking_jobs::{self, Kind};
use crate::model_service::ModelService;
use crate::secrets::{FakeSecretBackend, SecretStore};
use crate::status_cache::{FIRST_SNAPSHOT_WAIT, STALE_AFTER, StatusCache};

/// How long the lanes are held in the issue-35 regression.
const HELD: Duration = Duration::from_millis(900);

struct Fixture {
    store: Arc<Store>,
    cache: Arc<StatusCache>,
    _models_dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let models = ModelService::new(Arc::clone(&store)).await.unwrap();
    // Never the real models directory.
    let models_dir = tempfile::tempdir().unwrap();
    models.set_models_dir(models_dir.path()).await.unwrap();
    let secrets = Arc::new(SecretStore::new(Arc::new(FakeSecretBackend::default())));
    Fixture {
        cache: StatusCache::new(models, secrets),
        store,
        _models_dir: models_dir,
    }
}

#[tokio::test]
async fn a_refreshed_snapshot_answers_with_every_block_and_is_not_stale() {
    let fx = fixture().await;
    fx.cache.refresh().await;
    let body = fx.cache.body(&fx.store, Instant::now()).await;

    assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["active_requests"], 0);
    assert_eq!(body["snapshot"]["stale"], false);
    assert!(body["snapshot"]["model_age_ms"].is_u64());
    assert!(body["snapshot"]["keyring_age_ms"].is_u64());
    assert_eq!(body["model"]["state"], "idle");
    assert_eq!(body["model"]["readiness"]["light"]["stage"], "unconfigured");
    assert_eq!(body["model"]["readiness"]["heavy"]["cause"], "no_default");
    assert_eq!(body["model"]["engine"]["installed"], false);
    assert_eq!(body["keyring"]["state"], "reachable");
}

/// The regression for ptrack issue 35: with the model filesystem lane and
/// the keychain lane both held by slow work, `status` used to wait behind
/// them on every poll. It now reads the snapshot and returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_does_not_wait_behind_a_held_model_lane_or_keychain() {
    let fx = fixture().await;
    fx.cache.refresh().await;

    let model_lane = tokio::spawn(blocking_jobs::run(Kind::ModelFilesystem, || {
        std::thread::sleep(HELD);
    }));
    let keychain = tokio::spawn(blocking_jobs::run(Kind::Keychain, || {
        std::thread::sleep(HELD);
    }));
    // Let both closures take their lanes.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let asked = Instant::now();
    let body = fx.cache.body(&fx.store, Instant::now()).await;
    let took = asked.elapsed();

    assert!(
        took < Duration::from_millis(400),
        "status waited {took:?} while the lanes were held for {HELD:?}"
    );
    // Answered from the snapshot: complete, and not flagged stale.
    assert_eq!(body["keyring"]["state"], "reachable");
    assert_eq!(body["model"]["readiness"]["light"]["stage"], "unconfigured");
    assert_eq!(body["snapshot"]["stale"], false);

    model_lane.await.unwrap().unwrap();
    keychain.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn before_the_first_snapshot_status_waits_a_bounded_moment_then_says_stale() {
    let fx = fixture().await;
    let asked = tokio::time::Instant::now();
    // Nothing ever refreshes this cache.
    let body = fx.cache.body(&fx.store, Instant::now()).await;

    assert_eq!(asked.elapsed(), FIRST_SNAPSHOT_WAIT);
    assert_eq!(body["snapshot"]["stale"], true);
    assert!(body["snapshot"]["model_age_ms"].is_null());
    assert!(body["keyring"].is_null());
    // The in-memory half is still real, and the shape is still the one
    // clients parse.
    assert_eq!(body["model"]["state"], "idle");
    assert!(body["model"]["readiness"]["light"].is_null());
    assert!(body["model"]["defaults"]["heavy"].is_null());
    assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn a_snapshot_nobody_refreshes_ages_into_stale() {
    let fx = fixture().await;
    fx.cache.refresh().await;
    assert_eq!(
        fx.cache.body(&fx.store, Instant::now()).await["snapshot"]["stale"],
        false
    );

    tokio::time::pause();
    tokio::time::advance(STALE_AFTER + Duration::from_secs(1)).await;
    let body = fx.cache.body(&fx.store, Instant::now()).await;
    assert_eq!(body["snapshot"]["stale"], true);
    assert!(body["snapshot"]["model_age_ms"].as_u64().unwrap() >= 10_000);
    // Stale is a flag, not a refusal: the last known answer is still given.
    assert_eq!(body["keyring"]["state"], "reachable");
}

#[tokio::test]
async fn the_background_task_fills_the_snapshot_and_stops_on_shutdown() {
    let fx = fixture().await;
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = Arc::clone(&fx.cache).spawn(shutdown_rx);

    // No explicit refresh: the first `status` is answered by the task's
    // first pass, inside the bounded first-snapshot wait.
    let body = fx.cache.body(&fx.store, Instant::now()).await;
    assert_eq!(body["snapshot"]["stale"], false);
    assert_eq!(body["keyring"]["state"], "reachable");

    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the refresher stops on shutdown")
        .unwrap();
}

/// A daemon nobody polls touches neither the keychain nor the models
/// directory: the refresher sleeps until a `status` asks.
#[tokio::test]
async fn the_background_task_does_nothing_until_status_is_asked_for() {
    let fx = fixture().await;
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = Arc::clone(&fx.cache).spawn(shutdown_rx);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let observations = serde_json::to_value(blocking_jobs::snapshot()).unwrap();
    // Nothing has been refreshed: asking for the body now is what wakes it.
    let asked = Instant::now();
    let body = fx.cache.body(&fx.store, Instant::now()).await;
    assert_eq!(body["snapshot"]["stale"], false);
    assert!(
        body["snapshot"]["keyring_age_ms"].as_u64().unwrap()
            <= u64::try_from(asked.elapsed().as_millis()).unwrap() + 50,
        "the snapshot was taken because of this poll, not before it: {body} / {observations}"
    );

    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the refresher stops on shutdown")
        .unwrap();
}

/// When the task is running and the snapshot is stale anyway, something
/// behind it is hung: `status` answers at once instead of waiting too.
#[tokio::test(start_paused = true)]
async fn a_stale_snapshot_with_a_running_refresher_is_answered_without_waiting() {
    let fx = fixture().await;
    // Under a paused clock the blocking work behind a refresh cannot beat
    // its timeout, which is exactly the state under test: a refresh was
    // attempted just now and produced nothing fresh.
    fx.cache.refresh().await;
    let asked = tokio::time::Instant::now();
    let body = fx.cache.body(&fx.store, Instant::now()).await;
    assert!(
        asked.elapsed() < Duration::from_millis(500),
        "status waited {:?} behind a refresher that is already running",
        asked.elapsed()
    );
    assert_eq!(body["daemon_version"], env!("CARGO_PKG_VERSION"));
}
