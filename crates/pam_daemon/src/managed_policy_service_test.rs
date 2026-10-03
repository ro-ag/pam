//! The policy service against scripted sources: the state machine, the
//! fallback chain, the last good copy, absence, the poll, audit rows,
//! change hooks and the network overlay.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pam_store::{
    Actor, AuditRow, Decision, RequestIngress, RequestOrigin, RequestState,
    SETTING_POLICY_LAST_GOOD, Store,
};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::managed_policy::{
    CAUSE_POLICY_FROZEN, Key, LeafStatus, PolicyView, TargetPlatform, inspect_bytes,
};
use crate::managed_policy_service::{
    ABSENCE_CONFIRM_AFTER, ACTION_POLICY_CLEAR, ACTION_POLICY_LOAD, ACTION_POLICY_LOCKED_WRITE,
    ACTION_POLICY_REJECT, CAPABILITY_POLICY_LOAD, DAEMON_CALLER_AGENT, Fingerprint, PolicyHandle,
    PolicySource, PolicyState, REASON_ABSENT_UNCONFIRMED, REVERIFY_INTERVAL, STAT_INTERVAL,
    SourceRead, Trigger, audit_locked_write,
};
use crate::network_service::{ManagedNetworkLayer, ProxyEntry, sha256_hex};
use crate::policy::Profile;

// --- Documents -------------------------------------------------------------

/// Profile locked strict, a locked proxy and a valid Tier B mirror.
const STRICT: &str = r#"{
  "version": 1,
  "revision": "r1",
  "organization": "Example Corp",
  "contact": "it@example.com",
  "security": { "profile": { "locked": "strict", "reason": "SEC-1" } },
  "network": {
    "proxy": { "locked": { "url": "http://proxy.example.com:8080", "auth": "none" } },
    "engine_mirror": { "locked": "https://artifacts.example.com/llama.cpp" },
    "mirror_allowed_hosts": ["artifacts.example.com"]
  }
}"#;

/// The same policy with another revision: a new digest, same rules.
const STRICT_R2: &str = r#"{
  "version": 1,
  "revision": "r2",
  "security": { "profile": { "locked": "strict" } },
  "network": {
    "proxy": { "locked": { "url": "http://proxy.example.com:8080", "auth": "none" } },
    "engine_mirror": { "locked": "https://artifacts.example.com/llama.cpp" },
    "mirror_allowed_hosts": ["artifacts.example.com"]
  }
}"#;

/// A truncated file: a file-level failure.
const TRUNCATED: &str = r#"{"version":"#;

/// A version this binary does not read.
const VERSION_2: &str = r#"{"version":2,"security":{"profile":{"locked":"strict"}}}"#;

/// A mirror host typo (Tier B) in an otherwise good file.
const MIRROR_TYPO: &str = r#"{
  "version": 1,
  "revision": "typo",
  "security": { "profile": { "locked": "strict" } },
  "network": {
    "proxy": { "locked": { "url": "http://proxy.example.com:8080", "auth": "none" } },
    "engine_mirror": { "locked": "https://artifactz.example.com/llama.cpp" },
    "mirror_allowed_hosts": ["artifacts.example.com"]
  }
}"#;

/// A proxy with no port (rejected, Tier A) and a `never` of the wrong type
/// (rejected, Tier A); the profile lock applies.
const BAD_TIER_A: &str = r#"{
  "version": 1,
  "revision": "bad-a",
  "security": {
    "profile": { "locked": "strict" },
    "grants": { "never": "flow.step:*/merge" }
  },
  "network": { "proxy": { "locked": { "url": "http://p.example.com", "auth": "none" } } }
}"#;

/// A loosening policy: the profile locked relaxed.
const RELAXED: &str =
    r#"{"version":1,"revision":"loose","security":{"profile":{"locked":"relaxed"}}}"#;

/// One certificate block `normalize_pem` accepts.
#[cfg_attr(windows, allow(dead_code))]
const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

/// Where the CA bundle documents pin their file.
const CA_PATH: &str = "/Library/Application Support/PAM/ca/corp-root.pem";

#[cfg_attr(windows, allow(dead_code))]
fn pem_digest() -> String {
    let normalized = pam_net::normalize_pem(PEM.as_bytes()).expect("the fixture is a bundle");
    sha256_hex(normalized.pem.as_bytes())
}

#[cfg_attr(windows, allow(dead_code))]
fn ca_document(sha256: &str, revision: &str) -> String {
    json!({
        "version": 1,
        "revision": revision,
        "network": { "ca_bundle": { "locked": { "path": CA_PATH, "sha256": sha256 } } }
    })
    .to_string()
}

fn digest(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

// --- The scripted source ------------------------------------------------------

/// A source whose answers the test sets. Every change of the file bumps
/// its fingerprint, the way a real replace changes the stat.
#[derive(Default)]
struct Fake {
    read: Mutex<Option<SourceRead>>,
    fingerprint: Mutex<Option<Fingerprint>>,
    referenced: Mutex<Option<SourceRead>>,
    generation: AtomicU64,
    reads: AtomicUsize,
}

impl Fake {
    fn new(read: SourceRead) -> Arc<Self> {
        let fake = Arc::new(Self::default());
        fake.set(read);
        fake
    }

    /// Replaces the file: a new answer and a new stat.
    fn set(&self, read: SourceRead) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.fingerprint.lock().unwrap() = match &read {
            SourceRead::Absent => None,
            _ => Some(Fingerprint {
                len: generation,
                modified: None,
                identity: None,
            }),
        };
        *self.read.lock().unwrap() = Some(read);
    }

    /// Changes the answer without changing the stat (a trust fact changed,
    /// or the next read of a file that was busy).
    fn set_quietly(&self, read: SourceRead) {
        *self.read.lock().unwrap() = Some(read);
    }

    fn set_text(&self, text: &str) {
        self.set(SourceRead::Trusted(text.as_bytes().to_vec()));
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn set_referenced(&self, read: SourceRead) {
        *self.referenced.lock().unwrap() = Some(read);
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl PolicySource for Fake {
    fn origin(&self) -> String {
        "/fake/policy.json".to_owned()
    }

    fn read(&self) -> SourceRead {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.read
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(SourceRead::Absent)
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        self.fingerprint.lock().unwrap().clone()
    }

    fn read_referenced(&self, path: &Path, _max_bytes: u64) -> SourceRead {
        assert_eq!(path, Path::new(CA_PATH), "only the pinned bundle is read");
        self.referenced
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(SourceRead::Absent)
    }
}

fn trusted(text: &str) -> SourceRead {
    SourceRead::Trusted(text.as_bytes().to_vec())
}

fn untrusted() -> SourceRead {
    SourceRead::Untrusted {
        code: "writable_by_user",
        detail: "/fake/policy.json (writable_by_user): the daemon's user can modify it".to_owned(),
    }
}

struct Fixture {
    store: Arc<Store>,
    fake: Arc<Fake>,
    base: tempfile::TempDir,
}

impl Fixture {
    async fn new(read: SourceRead) -> Self {
        Self {
            store: Arc::new(Store::open_in_memory().await.unwrap()),
            fake: Fake::new(read),
            base: tempfile::tempdir().unwrap(),
        }
    }

    async fn boot(&self) -> Arc<PolicyHandle> {
        let source: Arc<dyn PolicySource> = self.fake.clone();
        PolicyHandle::load(Arc::clone(&self.store), source, self.base.path()).await
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn net_dir(&self) -> PathBuf {
        self.base.path().join(crate::network_service::NET_DIR)
    }

    /// Every policy audit row on daemon-owned requests, oldest first.
    async fn daemon_rows(&self) -> Vec<AuditRow> {
        let requests = self
            .store
            .list_requests_filtered(None, None, None, None, Some(CAPABILITY_POLICY_LOAD), false)
            .await
            .unwrap();
        let mut rows = Vec::new();
        for request in requests {
            assert_eq!(request.caller_agent, DAEMON_CALLER_AGENT);
            assert_eq!(request.origin.ingress, RequestIngress::Admin);
            assert_eq!(request.state, RequestState::Done);
            rows.extend(self.store.audit_for_request(&request.id).await.unwrap());
        }
        rows.sort_by_key(|row| row.id);
        rows
    }

    async fn rows_named(&self, action: &str) -> Vec<Value> {
        self.daemon_rows()
            .await
            .into_iter()
            .filter(|row| row.action == action)
            .map(|row| {
                assert_eq!(row.actor, Actor::Policy);
                serde_json::from_str(row.detail.as_deref().unwrap()).unwrap()
            })
            .collect()
    }

    async fn last_good_row(&self) -> Option<String> {
        self.store
            .get_setting(SETTING_POLICY_LAST_GOOD)
            .await
            .unwrap()
    }
}

fn profile(view: &PolicyView, user: Profile) -> Profile {
    view.effective_profile(Some(user)).0
}

fn counter(handle: &PolicyHandle) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    handle.on_change(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    count
}

fn reload() -> Trigger {
    Trigger::Reload { request_id: None }
}

// --- Boot and the states ------------------------------------------------------

#[tokio::test]
async fn a_boot_with_no_file_is_unmanaged_and_writes_nothing() {
    let fx = Fixture::new(SourceRead::Absent).await;
    let handle = fx.boot().await;

    let status = handle.status();
    assert_eq!(status.state, PolicyState::None);
    assert!(!handle.view().is_managed());
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Relaxed);
    assert!(handle.network_closed().is_none());
    assert!(handle.managed_network().is_none());
    assert!(fx.daemon_rows().await.is_empty());
    assert_eq!(fx.last_good_row().await, None);
    assert_eq!(
        status.public_json(),
        json!({
            "state": "none", "revision": null, "digest": null, "loaded_ts": null,
            "managed": false, "rejected_leaves": 0,
        })
    );
}

#[tokio::test]
async fn a_trusted_valid_file_is_active_with_its_values_audited_and_kept() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;

    let status = handle.status();
    assert_eq!(status.state, PolicyState::Active);
    assert_eq!(status.digest.as_deref(), Some(digest(STRICT).as_str()));
    assert_eq!(status.revision.as_deref(), Some("r1"));
    assert_eq!(status.organization.as_deref(), Some("Example Corp"));
    assert_eq!(status.rejected_leaves, 0);
    assert!(status.loaded_ts.is_some());
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);

    let public = status.public_json();
    assert_eq!(public["state"], "active");
    assert_eq!(public["managed"], true);
    assert_eq!(public["digest"], digest(STRICT)[..12]);
    assert_eq!(public["revision"], "r1");
    assert!(
        !public.to_string().contains("strict") && !public.to_string().contains("proxy"),
        "the public block carries no rule text: {public}"
    );

    let loads = fx.rows_named(ACTION_POLICY_LOAD).await;
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0]["trigger"], "boot");
    assert_eq!(loads[0]["state"], "active");
    assert_eq!(loads[0]["digest"], digest(STRICT));
    assert_eq!(loads[0]["revision"], "r1");
    assert_eq!(loads[0]["prior_digest"], Value::Null);
    assert!(
        !loads[0].to_string().contains("proxy.example.com"),
        "an audit row never carries a leaf value"
    );
    assert!(fx.rows_named(ACTION_POLICY_REJECT).await.is_empty());

    let row = fx
        .last_good_row()
        .await
        .expect("the last good copy is kept");
    assert!(row.ends_with(STRICT), "the exact bytes are kept");
    assert!(row.contains(&digest(STRICT)));
}

#[tokio::test]
async fn the_network_overlay_is_the_locked_fields() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let layer: &dyn ManagedNetworkLayer = handle.as_ref();
    let managed = layer.current().expect("the proxy is locked");
    assert_eq!(
        managed.proxy,
        Some(Some(ProxyEntry {
            url: "http://proxy.example.com:8080".to_owned(),
            auth: "none".to_owned(),
            username: None,
        }))
    );
    assert_eq!(
        managed.engine_mirror,
        Some(Some("https://artifacts.example.com/llama.cpp/".to_owned()))
    );
    assert_eq!(managed.ca_bundle, None);
    assert!(handle.network_closed().is_none());
}

#[tokio::test]
async fn a_trusted_file_that_turns_malformed_keeps_the_last_good_for_every_key() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let good = handle.view();
    let hooks = counter(&handle);

    fx.fake.set_text(TRUNCATED);
    let status = handle.reload(reload()).await;

    assert_eq!(status.state, PolicyState::LastGood);
    assert_eq!(status.reason_code, Some("policy_not_json"));
    assert_eq!(
        status.file_digest.as_deref(),
        Some(digest(TRUNCATED).as_str())
    );
    assert_eq!(status.digest.as_deref(), Some(digest(STRICT).as_str()));
    assert_eq!(
        status.last_good.as_ref().map(|good| good.digest.as_str()),
        Some(digest(STRICT).as_str())
    );
    assert_eq!(*handle.view(), *good, "every key reads the last good value");
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);
    assert_eq!(handle.status().admin_json()["state"], "last_good");
    assert_eq!(
        hooks.load(Ordering::SeqCst),
        0,
        "the effective policy did not change"
    );

    let rejects = fx.rows_named(ACTION_POLICY_REJECT).await;
    assert_eq!(rejects.len(), 1);
    assert_eq!(rejects[0]["trigger"], "reload");
    assert_eq!(rejects[0]["state"], "last_good");
    assert_eq!(rejects[0]["code"], "policy_not_json");
    assert_eq!(rejects[0]["digest"], digest(TRUNCATED));
    assert_eq!(rejects[0]["last_good_digest"], digest(STRICT));

    // A stuck file is not a row per check.
    handle.reload(reload()).await;
    handle.poll_once().await;
    assert_eq!(fx.rows_named(ACTION_POLICY_REJECT).await.len(), 1);
    assert_eq!(
        fx.last_good_row().await.map(|row| row.ends_with(STRICT)),
        Some(true)
    );
}

#[tokio::test]
async fn a_version_this_binary_does_not_read_falls_back_to_the_last_good() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    fx.fake.set_text(VERSION_2);
    let status = handle.reload(reload()).await;
    assert_eq!(status.state, PolicyState::LastGood);
    assert_eq!(status.reason_code, Some("policy_version_unsupported"));
    let detail = status.reason_detail.unwrap();
    assert!(detail.contains('2') && detail.contains('1'), "{detail}");
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);
}

#[tokio::test]
async fn an_untrusted_file_with_no_last_good_is_frozen() {
    let fx = Fixture::new(untrusted()).await;
    let handle = fx.boot().await;
    let status = handle.status();
    let view = handle.view();

    assert_eq!(status.state, PolicyState::Frozen);
    assert_eq!(status.reason_code, Some("writable_by_user"));
    assert_eq!(status.digest, None);
    // Tier A: writes freeze, reads show the user's value.
    assert!(view.is_held(Key::SecurityProfile));
    assert!(view.is_held(Key::NetworkProxy));
    assert_eq!(profile(&view, Profile::Relaxed), Profile::Relaxed);
    assert_eq!(
        view.check_profile(Profile::Relaxed).unwrap_err().cause,
        CAUSE_POLICY_FROZEN
    );
    // Tier B: unmanaged.
    assert_eq!(view.status(Key::ModelsDir), None);
    assert_eq!(view.status(Key::NetworkEngineMirror), None);
    // The intent is unknown: nothing is closed.
    assert!(handle.network_closed().is_none());
    assert!(handle.managed_network().is_none());

    let rejects = fx.rows_named(ACTION_POLICY_REJECT).await;
    assert_eq!(rejects.len(), 1);
    assert_eq!(rejects[0]["state"], "frozen");
    assert_eq!(rejects[0]["code"], "writable_by_user");
    assert_eq!(rejects[0]["digest"], Value::Null);
    assert_eq!(
        fx.last_good_row().await,
        None,
        "an untrusted file is never kept"
    );
}

#[tokio::test]
async fn rejected_tier_a_leaves_with_no_last_good_hold_and_close_the_network() {
    let fx = Fixture::new(trusted(BAD_TIER_A)).await;
    let handle = fx.boot().await;
    let status = handle.status();
    let view = handle.view();

    assert_eq!(status.state, PolicyState::Degraded);
    assert_eq!(
        profile(&view, Profile::Relaxed),
        Profile::Strict,
        "a good leaf applies"
    );
    assert!(matches!(
        view.status(Key::GrantsNever),
        Some(LeafStatus::Held {
            intent_known: true,
            ..
        })
    ));
    assert_eq!(
        view.check_grant_add("flow.step:x/merge", None)
            .unwrap_err()
            .cause,
        CAUSE_POLICY_FROZEN
    );
    let closed = handle
        .network_closed()
        .expect("a rejected proxy closes consumers");
    assert_eq!(closed.key, Key::NetworkProxy);
    assert_eq!(status.network_closed.as_ref(), Some(&closed));
    assert!(status.rejected_leaves >= 2);
    let keys: Vec<&str> = status.diagnostics.iter().map(|d| d.key.as_str()).collect();
    assert!(keys.contains(&"network.proxy") && keys.contains(&"security.grants.never"));

    let loads = fx.rows_named(ACTION_POLICY_LOAD).await;
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0]["state"], "degraded");
    let rejected = loads[0]["rejected"].as_array().unwrap();
    assert!(rejected.contains(&json!({ "key": "network.proxy", "code": "policy_value_invalid" })));
    assert_eq!(fx.rows_named(ACTION_POLICY_REJECT).await.len(), 1);
}

#[tokio::test]
async fn a_tier_b_typo_degrades_only_that_key_and_the_user_value_stands() {
    let fx = Fixture::new(trusted(MIRROR_TYPO)).await;
    let handle = fx.boot().await;
    let status = handle.status();
    let view = handle.view();

    assert_eq!(status.state, PolicyState::Degraded);
    assert!(matches!(
        view.status(Key::NetworkEngineMirror),
        Some(LeafStatus::Rejected { .. })
    ));
    assert_eq!(profile(&view, Profile::Relaxed), Profile::Strict);
    let managed = handle.managed_network().unwrap();
    assert_eq!(managed.engine_mirror, None, "the user's mirror stands");
    assert!(managed.proxy.is_some(), "every other leaf applies");
    assert!(handle.network_closed().is_none());
    assert!(
        status
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.key == "network.engine_mirror")
    );
}

#[tokio::test]
async fn a_degraded_file_takes_the_last_good_value_and_does_not_replace_the_copy() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;

    fx.fake.set_text(MIRROR_TYPO);
    let status = handle.reload(reload()).await;
    assert_eq!(status.state, PolicyState::Degraded);
    let view = handle.view();
    assert!(matches!(
        view.status(Key::NetworkEngineMirror),
        Some(LeafStatus::LastGood { .. })
    ));
    assert_eq!(
        handle.managed_network().unwrap().engine_mirror,
        Some(Some("https://artifacts.example.com/llama.cpp/".to_owned()))
    );
    // The copy holds the mirror, so it stays; a re-read gives the same view.
    assert_eq!(
        status.last_good.map(|good| good.digest),
        Some(digest(STRICT))
    );
    handle.reload(reload()).await;
    assert_eq!(*handle.view(), *view);
}

#[tokio::test]
async fn a_loosening_file_is_honoured_only_when_trusted() {
    let fx = Fixture::new(trusted(RELAXED)).await;
    let handle = fx.boot().await;
    assert_eq!(handle.status().state, PolicyState::Active);
    assert_eq!(profile(&handle.view(), Profile::Strict), Profile::Relaxed);

    let fx = Fixture::new(untrusted()).await;
    let handle = fx.boot().await;
    assert_eq!(handle.status().state, PolicyState::Frozen);
    assert_eq!(profile(&handle.view(), Profile::Strict), Profile::Strict);
    assert_eq!(fx.rows_named(ACTION_POLICY_REJECT).await.len(), 1);
}

// --- Busy, the last good copy across restarts -----------------------------------

#[tokio::test]
async fn a_busy_file_keeps_the_previous_view_and_is_read_again_next_poll() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let good = handle.view();
    let hooks = counter(&handle);

    fx.fake.set(SourceRead::Busy {
        detail: "replaced while it was checked".to_owned(),
    });
    handle.poll_once().await;
    let status = handle.status();
    assert_eq!(status.state, PolicyState::Active);
    assert_eq!(status.reason_code, Some("busy"));
    assert_eq!(*handle.view(), *good);
    assert_eq!(hooks.load(Ordering::SeqCst), 0);
    assert!(fx.rows_named(ACTION_POLICY_REJECT).await.is_empty());

    // The stat does not change again, yet the next poll reads in full.
    fx.fake.set_quietly(trusted(STRICT_R2));
    let reads = fx.fake.reads();
    handle.poll_once().await;
    assert_eq!(fx.fake.reads(), reads + 1);
    assert_eq!(handle.status().revision.as_deref(), Some("r2"));
    assert_eq!(handle.status().reason_code, None);
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_busy_file_at_boot_uses_the_last_good_copy() {
    let fx = Fixture::new(trusted(STRICT)).await;
    drop(fx.boot().await);
    fx.fake.set(SourceRead::Busy {
        detail: "a writer holds it".to_owned(),
    });
    let handle = fx.boot().await;
    assert_eq!(handle.status().state, PolicyState::LastGood);
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);
}

#[tokio::test]
async fn the_last_good_copy_survives_a_restart_and_keeps_the_profile_strict() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.sqlite3");
    let fake = Fake::new(trusted(STRICT));
    let base = tempfile::tempdir().unwrap();
    {
        let store = Arc::new(Store::open(&path).await.unwrap());
        let source: Arc<dyn PolicySource> = fake.clone();
        let handle = PolicyHandle::load(Arc::clone(&store), source, base.path()).await;
        assert_eq!(handle.status().state, PolicyState::Active);
        drop(handle);
        store.close().await.unwrap();
    }
    fake.set_text(TRUNCATED);
    let store = Arc::new(Store::open(&path).await.unwrap());
    let source: Arc<dyn PolicySource> = fake.clone();
    let handle = PolicyHandle::load(Arc::clone(&store), source, base.path()).await;
    let status = handle.status();
    assert_eq!(status.state, PolicyState::LastGood);
    assert_eq!(status.digest.as_deref(), Some(digest(STRICT).as_str()));
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);
    store.close().await.unwrap();
}

#[tokio::test]
async fn a_last_good_row_that_does_not_hash_to_its_digest_is_ignored() {
    let fx = Fixture::new(trusted(STRICT)).await;
    drop(fx.boot().await);
    let row = fx.last_good_row().await.unwrap();
    let tampered = row.replace("\"strict\"", "\"relaxed\"");
    assert_ne!(row, tampered);
    fx.store
        .set_setting(SETTING_POLICY_LAST_GOOD, &tampered)
        .await
        .unwrap();
    fx.fake.set_text(TRUNCATED);
    let handle = fx.boot().await;
    assert_eq!(handle.status().state, PolicyState::Frozen);
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Relaxed);
    assert!(handle.view().is_held(Key::SecurityProfile));
}

// --- Absence ------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn absence_after_a_managed_state_is_confirmed_by_a_second_poll() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let hooks = counter(&handle);

    fx.fake.set(SourceRead::Absent);
    handle.poll_once().await;
    let status = handle.status();
    assert_eq!(
        status.state,
        PolicyState::Active,
        "one absence is not enough"
    );
    assert!(status.absence_pending);
    assert_eq!(status.reason_code, Some(REASON_ABSENT_UNCONFIRMED));
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);

    // Too soon: still pending.
    tokio::time::advance(Duration::from_secs(1)).await;
    handle.poll_once().await;
    assert_eq!(handle.status().state, PolicyState::Active);

    tokio::time::advance(ABSENCE_CONFIRM_AFTER).await;
    handle.poll_once().await;
    let status = handle.status();
    assert_eq!(status.state, PolicyState::None);
    assert!(!status.absence_pending);
    assert!(!handle.view().is_managed());
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Relaxed);
    assert_eq!(
        fx.last_good_row().await,
        None,
        "the last good copy is deleted"
    );
    assert_eq!(hooks.load(Ordering::SeqCst), 1);

    let clears = fx.rows_named(ACTION_POLICY_CLEAR).await;
    assert_eq!(clears.len(), 1);
    assert_eq!(clears[0]["prior_digest"], digest(STRICT));
    assert_eq!(clears[0]["trigger"], "poll");
}

#[tokio::test(start_paused = true)]
async fn an_explicit_reload_observes_an_absence_but_never_confirms_it() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;

    fx.fake.set(SourceRead::Absent);
    assert!(handle.reload(reload()).await.absence_pending);
    tokio::time::advance(ABSENCE_CONFIRM_AFTER * 2).await;
    let status = handle.reload(reload()).await;
    assert_eq!(status.state, PolicyState::Active);
    assert!(status.absence_pending);

    // The poll is the confirming observation, the reload the first.
    handle.poll_once().await;
    assert_eq!(handle.status().state, PolicyState::None);
}

#[tokio::test(start_paused = true)]
async fn a_file_that_comes_back_cancels_the_pending_absence() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    fx.fake.set(SourceRead::Absent);
    handle.poll_once().await;
    fx.fake.set_text(STRICT);
    tokio::time::advance(ABSENCE_CONFIRM_AFTER * 2).await;
    handle.poll_once().await;
    let status = handle.status();
    assert_eq!(status.state, PolicyState::Active);
    assert!(!status.absence_pending);
    fx.fake.set(SourceRead::Absent);
    handle.poll_once().await;
    assert_eq!(
        handle.status().state,
        PolicyState::Active,
        "a fresh first observation"
    );
    assert!(fx.rows_named(ACTION_POLICY_CLEAR).await.is_empty());
}

#[tokio::test]
async fn a_boot_with_no_file_deletes_a_stale_last_good_copy() {
    let fx = Fixture::new(trusted(STRICT)).await;
    drop(fx.boot().await);
    assert!(fx.last_good_row().await.is_some());
    fx.fake.set(SourceRead::Absent);
    let handle = fx.boot().await;
    assert_eq!(handle.status().state, PolicyState::None);
    assert_eq!(fx.last_good_row().await, None);
    let clears = fx.rows_named(ACTION_POLICY_CLEAR).await;
    assert_eq!(clears.len(), 1);
    assert_eq!(clears[0]["trigger"], "boot");
}

// --- Audit and hooks ----------------------------------------------------------

#[tokio::test]
async fn a_reload_from_an_admin_op_audits_on_the_ops_own_request() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    fx.store
        .insert_running_request_from(
            "req_admin",
            "admin.policy.reload",
            crate::admin::ADMIN_REPO,
            crate::admin::ADMIN_CALLER_AGENT,
            "{}",
            None,
            &RequestOrigin::ADMIN,
        )
        .await
        .unwrap();

    fx.fake.set_text(STRICT_R2);
    handle
        .reload(Trigger::Reload {
            request_id: Some("req_admin".to_owned()),
        })
        .await;

    let rows = fx.store.audit_for_request("req_admin").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, ACTION_POLICY_LOAD);
    assert_eq!(rows[0].decision, Decision::Allow);
    assert_eq!(rows[0].actor, Actor::Policy);
    let detail: Value = serde_json::from_str(rows[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["trigger"], "reload");
    assert_eq!(detail["digest"], digest(STRICT_R2));
    assert_eq!(detail["prior_digest"], digest(STRICT));
    assert_eq!(detail["revision"], "r2");
    // The op's row is the op's to finish.
    assert_eq!(
        fx.store
            .get_request("req_admin")
            .await
            .unwrap()
            .unwrap()
            .state,
        RequestState::Running
    );
    // Only the boot load is on a daemon-owned row.
    assert_eq!(fx.rows_named(ACTION_POLICY_LOAD).await.len(), 1);
}

#[tokio::test]
async fn an_unchanged_digest_writes_no_load_row() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    handle.reload(reload()).await;
    handle.reload(reload()).await;
    assert_eq!(fx.rows_named(ACTION_POLICY_LOAD).await.len(), 1);
    fx.fake.set_text(STRICT_R2);
    handle.reload(reload()).await;
    let loads = fx.rows_named(ACTION_POLICY_LOAD).await;
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[1]["trigger"], "reload");
}

#[tokio::test]
async fn change_hooks_fire_exactly_once_per_effective_change() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let hooks = counter(&handle);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let revisions = Arc::clone(&seen);
    handle.on_change(move |view| {
        revisions.lock().unwrap().push(view.meta().revision.clone());
    });

    handle.reload(reload()).await;
    handle.poll_once().await;
    assert_eq!(hooks.load(Ordering::SeqCst), 0, "no change, no hook");

    fx.fake.set_text(STRICT_R2);
    handle.reload(reload()).await;
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    handle.reload(reload()).await;
    assert_eq!(hooks.load(Ordering::SeqCst), 1);

    fx.fake.set_text(RELAXED);
    handle.poll_once().await;
    assert_eq!(hooks.load(Ordering::SeqCst), 2);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![Some("r2".to_owned()), Some("loose".to_owned())]
    );
}

#[tokio::test]
async fn the_locked_write_row_names_the_op_the_key_and_the_digest() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    fx.store
        .insert_running_request_from(
            "req_set",
            "admin.profile.set",
            crate::admin::ADMIN_REPO,
            crate::admin::ADMIN_CALLER_AGENT,
            "{}",
            None,
            &RequestOrigin::ADMIN,
        )
        .await
        .unwrap();
    let view = handle.view();
    let refusal = view.check_profile(Profile::Relaxed).unwrap_err();
    audit_locked_write(&fx.store, "req_set", "admin.profile.set", &refusal, &view)
        .await
        .unwrap();
    let rows = fx.store.audit_for_request("req_set").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, ACTION_POLICY_LOCKED_WRITE);
    assert_eq!(rows[0].decision, Decision::Refuse);
    let detail: Value = serde_json::from_str(rows[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(
        detail,
        json!({
            "op": "admin.profile.set",
            "keys": ["security.profile"],
            "cause": "setting_locked",
            "digest": digest(STRICT),
            "revision": "r1",
        })
    );
}

// --- The poll task ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_poll_reads_on_a_changed_stat_and_reverifies_on_schedule() {
    let fx = Fixture::new(trusted(STRICT)).await;
    let handle = fx.boot().await;
    let (stop, shutdown) = watch::channel(false);
    let task = handle.spawn_poller(shutdown);
    let after_boot = fx.fake.reads();

    // Unchanged stat: no full read.
    tokio::time::sleep(STAT_INTERVAL * 3 + Duration::from_secs(1)).await;
    assert_eq!(fx.fake.reads(), after_boot);

    // A changed stat: one full read at the next tick.
    fx.fake.set_text(STRICT_R2);
    tokio::time::sleep(STAT_INTERVAL).await;
    assert_eq!(fx.fake.reads(), after_boot + 1);
    assert_eq!(handle.status().revision.as_deref(), Some("r2"));

    // A trust fact changes with no new stat: the re-verify notices.
    fx.fake.set_quietly(untrusted());
    tokio::time::sleep(STAT_INTERVAL * 5).await;
    assert_eq!(handle.status().state, PolicyState::Active);
    tokio::time::sleep(REVERIFY_INTERVAL).await;
    assert_eq!(handle.status().state, PolicyState::LastGood);
    assert_eq!(handle.status().reason_code, Some("writable_by_user"));

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("the poll stops on the shutdown watch")
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_poll_stops_when_the_shutdown_sender_drops() {
    let fx = Fixture::new(SourceRead::Absent).await;
    let handle = fx.boot().await;
    let (stop, shutdown) = watch::channel(false);
    let task = handle.spawn_poller(shutdown);
    drop(stop);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("a dropped sender is shutdown")
        .unwrap();
}

// --- The managed CA bundle ------------------------------------------------------
//
// The tests below import a pinned bundle, which Windows does not do (it trusts a
// private CA through its certificate store), so they run off Windows only; the
// Windows rule has its own test after them.

/// A bundle a Windows policy pins is a rejected leaf with no effect: it is not
/// held, takes nothing from a last-good copy and never closes the network.
#[cfg(windows)]
#[tokio::test]
async fn a_pinned_ca_bundle_on_windows_is_rejected_and_never_closes_the_network() {
    let document = json!({
        "version": 1,
        "revision": "ca-win",
        "network": { "ca_bundle": { "locked": {
            "path": r"C:\ProgramData\PAM\ca\corp-root.pem",
            "sha256": "a".repeat(64),
        } } }
    })
    .to_string();
    let fx = Fixture::new(trusted(&document)).await;
    let handle = fx.boot().await;

    assert!(handle.network_closed().is_none());
    assert!(
        handle
            .managed_network()
            .is_none_or(|managed| managed.ca_bundle.is_none())
    );
    let status = handle.status();
    assert_eq!(status.rejected_leaves, 1);
    let row = status
        .keys
        .iter()
        .find(|row| row.key == "network.ca_bundle")
        .expect("the key is reported");
    assert_eq!(row.state, "rejected");
    assert_eq!(row.code, Some("network_ca_unsupported_on_windows"));
}

#[cfg(not(windows))]
#[tokio::test]
async fn a_pinned_ca_bundle_is_imported_through_the_trust_check_and_the_digest() {
    let sha = pem_digest();
    let fx = Fixture::new(trusted(&ca_document(&sha, "ca1"))).await;
    fx.fake.set_referenced(trusted(PEM));
    let handle = fx.boot().await;

    assert_eq!(handle.status().state, PolicyState::Active);
    let entry = handle
        .managed_network()
        .and_then(|managed| managed.ca_bundle)
        .flatten()
        .expect("the managed CA record");
    assert_eq!(entry.sha256, sha);
    assert_eq!(entry.certificates, 1);
    assert_eq!(entry.source_path.as_deref(), Some(CA_PATH));
    let copy = fx.net_dir().join(format!("ca-{}.pem", &sha[..12]));
    assert_eq!(sha256_hex(&std::fs::read(&copy).unwrap()), sha);
    assert!(handle.network_closed().is_none());

    // A re-verify of the same pin is no change.
    let hooks = counter(&handle);
    handle.reload(reload()).await;
    assert_eq!(hooks.load(Ordering::SeqCst), 0);
}

#[cfg(not(windows))]
#[tokio::test]
async fn a_ca_digest_mismatch_with_no_last_good_closes_the_network() {
    let fx = Fixture::new(trusted(&ca_document(&"a".repeat(64), "ca-bad"))).await;
    fx.fake.set_referenced(trusted(PEM));
    let handle = fx.boot().await;

    let status = handle.status();
    assert_eq!(status.state, PolicyState::Degraded);
    let closed = handle.network_closed().expect("consumers close");
    assert_eq!(closed.key, Key::NetworkCaBundle);
    assert_eq!(closed.code, "policy_value_invalid");
    assert!(closed.detail.contains(&pem_digest()), "{}", closed.detail);
    let row = status
        .keys
        .iter()
        .find(|row| row.key == "network.ca_bundle")
        .unwrap();
    assert_eq!(row.state, "held");
    assert_eq!(status.rejected_leaves, 1);
    assert!(
        handle
            .managed_network()
            .is_none_or(|managed| managed.ca_bundle.is_none())
    );
    let loads = fx.rows_named(ACTION_POLICY_LOAD).await;
    assert_eq!(
        loads[0]["rejected"],
        json!([{ "key": "network.ca_bundle", "code": "policy_value_invalid" }])
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn an_untrusted_ca_bundle_closes_the_network() {
    let fx = Fixture::new(trusted(&ca_document(&pem_digest(), "ca1"))).await;
    fx.fake.set_referenced(untrusted());
    let handle = fx.boot().await;
    let closed = handle.network_closed().expect("consumers close");
    assert_eq!(closed.code, "writable_by_user");
}

#[cfg(not(windows))]
#[tokio::test]
async fn a_failing_new_ca_pin_falls_back_to_the_last_good_pin() {
    let sha = pem_digest();
    let fx = Fixture::new(trusted(&ca_document(&sha, "ca1"))).await;
    fx.fake.set_referenced(trusted(PEM));
    let handle = fx.boot().await;
    let good = handle.managed_network().unwrap().ca_bundle;

    // A new pin the file does not match; the old copy still proves the old one.
    fx.fake.set_text(&ca_document(&"b".repeat(64), "ca2"));
    let status = handle.reload(reload()).await;
    assert_eq!(status.state, PolicyState::Degraded);
    assert!(handle.network_closed().is_none());
    assert_eq!(handle.managed_network().unwrap().ca_bundle, good);
    assert_eq!(
        status.last_good.map(|good| good.digest),
        Some(digest(&ca_document(&sha, "ca1"))),
        "the copy that holds the CA stays"
    );
}

#[cfg(not(windows))]
#[tokio::test]
async fn a_busy_ca_bundle_uses_the_private_copy_that_matches_the_pin() {
    let sha = pem_digest();
    let fx = Fixture::new(trusted(&ca_document(&sha, "ca1"))).await;
    fx.fake.set_referenced(trusted(PEM));
    let handle = fx.boot().await;
    fx.fake.set_referenced(SourceRead::Busy {
        detail: "being replaced".to_owned(),
    });
    handle.reload(reload()).await;
    assert!(handle.network_closed().is_none());
    assert_eq!(handle.status().state, PolicyState::Active);
}

// --- The file source ------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn the_file_source_reads_a_trusted_file_and_reports_a_missing_one_absent() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use crate::managed_policy_service::FileSource;
    use crate::managed_policy_trust::TrustRules;

    let tmp = tempfile::tempdir().unwrap();
    let dir = std::fs::canonicalize(tmp.path()).unwrap();
    let uid = std::fs::metadata(&dir).unwrap().uid();
    let path = dir.join("policy.json");
    let missing = FileSource::at(&path, TrustRules::owned_by(uid));
    assert_eq!(missing.read(), SourceRead::Absent);
    assert_eq!(missing.fingerprint(), None);

    std::fs::write(&path, STRICT).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let source = FileSource::at(&path, TrustRules::owned_by(uid));
    assert_eq!(source.origin(), path.display().to_string());
    assert_eq!(source.read(), trusted(STRICT));
    assert!(source.fingerprint().is_some());

    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let base = tempfile::tempdir().unwrap();
    let handle = PolicyHandle::load(store, Arc::new(source), base.path()).await;
    assert_eq!(handle.status().state, PolicyState::Active);
    assert_eq!(profile(&handle.view(), Profile::Relaxed), Profile::Strict);

    // A file the daemon's user can write is not trusted.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let writable = FileSource::at(&path, TrustRules::owned_by(uid));
    assert!(matches!(
        writable.read(),
        SourceRead::Untrusted {
            code: "writable_by_user",
            ..
        }
    ));
}

#[test]
fn the_platform_source_reads_the_fixed_path() {
    let source = crate::managed_policy_service::FileSource::platform();
    assert_eq!(
        source.origin(),
        crate::managed_policy_trust::policy_path()
            .display()
            .to_string()
    );
}

#[tokio::test]
async fn the_none_handle_never_manages_anything() {
    let handle = PolicyHandle::none();
    assert_eq!(handle.status().state, PolicyState::None);
    assert_eq!(handle.reload(reload()).await.state, PolicyState::None);
    handle.poll_once().await;
    assert!(!handle.view().is_managed());
    assert!(handle.managed_network().is_none());
}

#[test]
fn a_view_inspected_twice_is_equal() {
    // The hooks compare views; parsing is deterministic.
    let first = inspect_bytes(STRICT.as_bytes(), TargetPlatform::host())
        .result
        .unwrap();
    let second = inspect_bytes(STRICT.as_bytes(), TargetPlatform::host())
        .result
        .unwrap();
    assert_eq!(first, second);
}
