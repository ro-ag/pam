//! `admin.policy.get` and `admin.policy.reload` through the real admin
//! dispatch, over a scripted policy source (never the machine's own file).

use std::sync::Arc;

use pam_proto::{Outcome, Response};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::admin::{ACTION_ADMIN, CAUSE_INVALID_ADMIN_ARGS};
use crate::admin_policy::{
    LOGIN_UNIT_LABEL, OP_POLICY_GET, OP_POLICY_RELOAD, POLICY_ADMIN_OPS, login_unit_present,
    trust_json,
};
use crate::admin_test::managed;
use crate::managed_policy::TargetPlatform;
use crate::managed_policy_service::{
    ACTION_POLICY_LOAD, ACTION_POLICY_REJECT, Fingerprint, PolicyHandle, PolicySource, SourceRead,
};
use crate::policy::Profile;

fn body_of(response: Response) -> Value {
    match response {
        Response::Result { outcome, body, .. } => {
            assert_eq!(outcome, Outcome::Verified);
            body
        }
        other => panic!("expected a result, got {other:?}"),
    }
}

fn sha256(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// A policy that applies, names the organization, requires the login unit
/// and carries one Tier B typo (a mirror on a host the allowlist omits).
fn policy_text() -> String {
    json!({
        "version": 1,
        "revision": "pol-1",
        "organization": "Example Corp",
        "contact": "it@example.test",
        "security": { "profile": { "locked": "strict", "reason": "SEC-1" } },
        "network": {
            "mirror_allowed_hosts": ["artifacts.example.com"],
            "models_mirror": { "default": "https://elsewhere.example.org/hf" },
        },
        "service": { "require_login_unit": true },
    })
    .to_string()
}

async fn actions(managed: &crate::admin_test::Managed, id: &str) -> Vec<(String, Value)> {
    managed
        .store
        .audit_for_request(id)
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            let detail = row
                .detail
                .as_deref()
                .map_or(Value::Null, |text| serde_json::from_str(text).unwrap());
            (row.action, detail)
        })
        .collect()
}

#[test]
fn the_two_ops_are_the_whole_surface() {
    assert_eq!(POLICY_ADMIN_OPS, [OP_POLICY_GET, OP_POLICY_RELOAD]);
    for op in POLICY_ADMIN_OPS {
        assert!(op.starts_with("admin.policy."), "{op} is misnamed");
    }
}

#[tokio::test]
async fn get_with_no_policy_says_unmanaged_and_reads_no_file() {
    let managed = managed(None, Profile::Relaxed).await;
    let body = body_of(managed.op("req_get", OP_POLICY_GET, json!({})).await);
    assert_eq!(body["state"], "none");
    assert_eq!(body["digest"], Value::Null);
    assert_eq!(body["last_good"], Value::Null);
    assert_eq!(body["keys"], json!([]));
    assert_eq!(body["diagnostics"], json!([]));
    assert_eq!(body["origin"]["trust"]["verdict"], "absent");
    assert_eq!(body["origin"]["trust"]["owner"], "unknown");
    assert_eq!(body["compliance"]["login_unit"]["required"], false);
    let rows = actions(&managed, "req_get").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, ACTION_ADMIN);
    assert_eq!(rows[0].1["op"], OP_POLICY_GET);
}

#[tokio::test]
async fn get_answers_the_merged_view_the_policy_screen_draws() {
    let text = policy_text();
    let managed = managed(Some(&text), Profile::Relaxed).await;
    let body = body_of(managed.op("req_get", OP_POLICY_GET, json!({})).await);

    assert_eq!(body["state"], "degraded", "{body}");
    assert_eq!(body["digest"], sha256(&text), "the full digest");
    assert_eq!(body["revision"], "pol-1");
    assert_eq!(body["organization"], "Example Corp");
    assert_eq!(body["contact"], "it@example.test");
    assert!(body["loaded_ts"].is_i64(), "{body}");
    assert!(body["checked_ts"].is_i64(), "{body}");
    assert_eq!(body["origin"]["path"], "switchable");
    assert_eq!(
        body["origin"]["platform"],
        TargetPlatform::host().as_str(),
        "{body}"
    );
    let trust = &body["origin"]["trust"];
    assert_eq!(trust["verdict"], "trusted");
    for fact in ["owner", "writable_by_user", "symlink", "parents"] {
        assert_eq!(trust[fact], "ok", "{fact}: {trust}");
    }
    assert_eq!(trust["code"], Value::Null);

    // The per-key table: resolved state, tier and modes; the rejected leaf
    // with its code; every diagnostic names its key.
    let keys = body["keys"].as_array().expect("keys");
    let row = |key: &str| {
        keys.iter()
            .find(|row| row["key"] == key)
            .unwrap_or_else(|| panic!("no {key} row in {keys:?}"))
            .clone()
    };
    let profile = row("security.profile");
    assert_eq!(profile["state"], "applied");
    assert_eq!(profile["tier"], "A");
    assert_eq!(profile["mode"], json!(["locked"]));
    let mirror = row("network.models_mirror");
    assert_eq!(mirror["state"], "rejected");
    assert_eq!(mirror["tier"], "B");
    assert!(mirror["code"].is_string(), "{mirror}");
    assert!(
        body["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["key"] == "network.models_mirror"),
        "{body}"
    );
    assert_eq!(body["rejected_leaves"], 1);

    let login_unit = &body["compliance"]["login_unit"];
    assert_eq!(login_unit["required"], true);
    assert!(
        login_unit["present"].is_boolean() || login_unit["present"].is_null(),
        "{login_unit}"
    );
    // A read: no policy.* row on the request, only the terminal one.
    let rows = actions(&managed, "req_get").await;
    assert_eq!(
        rows.iter()
            .map(|(action, _)| action.as_str())
            .collect::<Vec<_>>(),
        [ACTION_ADMIN]
    );
}

#[tokio::test]
async fn reload_reads_the_file_now_and_audits_on_its_own_request() {
    let first = policy_text();
    let managed = managed(Some(&first), Profile::Relaxed).await;
    let second = json!({ "version": 1, "revision": "pol-2" }).to_string();
    managed.source.set(Some(&second));
    // `get` answers from memory: the new file is not read yet.
    let body = body_of(managed.op("req_get", OP_POLICY_GET, json!({})).await);
    assert_eq!(body["revision"], "pol-1");

    let body = body_of(managed.op("req_reload", OP_POLICY_RELOAD, json!({})).await);
    assert_eq!(body["state"], "active");
    assert_eq!(body["revision"], "pol-2");
    assert_eq!(body["digest"], sha256(&second));
    assert_eq!(body["compliance"]["login_unit"]["required"], false);
    let rows = actions(&managed, "req_reload").await;
    assert_eq!(
        rows.iter()
            .map(|(action, _)| action.as_str())
            .collect::<Vec<_>>(),
        [ACTION_POLICY_LOAD, ACTION_ADMIN],
        "{rows:?}"
    );
    assert_eq!(rows[0].1["trigger"], "reload");
    assert_eq!(rows[0].1["digest"], sha256(&second));
    assert_eq!(rows[0].1["prior_digest"], sha256(&first));
    assert_eq!(
        rows[1].1,
        json!({
            "op": OP_POLICY_RELOAD,
            "trigger": "admin",
            "prior_state": "degraded",
            "prior_digest": sha256(&first),
            "state": "active",
            "digest": sha256(&second),
        })
    );

    // The same file again changes nothing: only the terminal row.
    body_of(managed.op("req_again", OP_POLICY_RELOAD, json!({})).await);
    let rows = actions(&managed, "req_again").await;
    assert_eq!(
        rows.iter()
            .map(|(action, _)| action.as_str())
            .collect::<Vec<_>>(),
        [ACTION_ADMIN]
    );

    // A damaged file keeps the last good policy and says why, once.
    managed.source.set(Some("{\"version\":"));
    let body = body_of(managed.op("req_bad", OP_POLICY_RELOAD, json!({})).await);
    assert_eq!(body["state"], "last_good");
    assert_eq!(body["reason_code"], "policy_not_json");
    assert_eq!(body["revision"], "pol-2", "the last good policy stays");
    assert_eq!(body["last_good"]["digest"], sha256(&second));
    assert_eq!(
        body["origin"]["trust"]["verdict"], "trusted",
        "the bytes passed the trust check; they did not parse"
    );
    let rows = actions(&managed, "req_bad").await;
    assert_eq!(
        rows.iter()
            .map(|(action, _)| action.as_str())
            .collect::<Vec<_>>(),
        [ACTION_POLICY_REJECT, ACTION_ADMIN],
        "{rows:?}"
    );
}

#[tokio::test]
async fn both_ops_take_no_arguments() {
    let managed = managed(None, Profile::Relaxed).await;
    for (index, op) in POLICY_ADMIN_OPS.iter().enumerate() {
        for (case, args) in [
            json!({ "path": "/tmp/other.json" }),
            json!({ "digest": "ab" }),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("req_args_{index}_{case}");
            match managed.op(&id, op, args.clone()).await {
                Response::Refusal { cause, .. } => {
                    assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS, "{op} {args}");
                }
                other => panic!("{op} {args}: expected a refusal, got {other:?}"),
            }
        }
    }
}

/// A source whose file fails the trust check with `code`.
struct Refused(&'static str);

impl PolicySource for Refused {
    fn origin(&self) -> String {
        "refused".to_owned()
    }

    fn read(&self) -> SourceRead {
        if self.0 == "busy" {
            return SourceRead::Busy {
                detail: "a writer holds the file".to_owned(),
            };
        }
        SourceRead::Untrusted {
            code: self.0,
            detail: format!("the file fails the trust check: {}", self.0),
        }
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        None
    }

    fn read_referenced(&self, _path: &std::path::Path, _max_bytes: u64) -> SourceRead {
        SourceRead::Absent
    }
}

/// The trust breakdown names the fact that failed, leaves the facts the
/// check never reached `unknown`, and carries the administrator's
/// recovery.
#[tokio::test]
async fn the_trust_breakdown_names_the_fact_that_failed() {
    for (code, failed) in [
        ("writable_by_user", Some("writable_by_user")),
        ("not_owned_by_root", Some("owner")),
        ("symlink", Some("symlink")),
        ("parent_writable", Some("parents")),
        ("not_regular", None),
    ] {
        let store = Arc::new(pam_store::Store::open_in_memory().await.unwrap());
        let handle = PolicyHandle::load(
            store,
            Arc::new(Refused(code)),
            std::path::Path::new("pam-tests-write-no-ca-copy"),
        )
        .await;
        let status = handle.status();
        assert_eq!(status.state.as_str(), "frozen", "{code}");
        let trust = trust_json(&status);
        assert_eq!(trust["verdict"], "untrusted", "{code}");
        assert_eq!(trust["code"], code);
        assert!(trust["recovery"].is_string(), "{trust}");
        for fact in ["owner", "writable_by_user", "symlink", "parents"] {
            let want = if Some(fact) == failed {
                "failed"
            } else {
                "unknown"
            };
            assert_eq!(trust[fact], want, "{code}: {fact}");
        }
    }
    let store = Arc::new(pam_store::Store::open_in_memory().await.unwrap());
    let handle = PolicyHandle::load(
        store,
        Arc::new(Refused("busy")),
        std::path::Path::new("pam-tests-write-no-ca-copy"),
    )
    .await;
    let trust = trust_json(&handle.status());
    assert_eq!(trust["verdict"], "busy");
    assert_eq!(trust["owner"], "unknown");
}

#[test]
fn the_login_unit_is_looked_for_where_install_and_an_mdm_put_it() {
    let home = tempfile::tempdir().unwrap();
    let machine = tempfile::tempdir().unwrap();
    let plist = format!("{LOGIN_UNIT_LABEL}.plist");
    assert_eq!(
        login_unit_present(TargetPlatform::Macos, Some(home.path()), machine.path()),
        Some(false)
    );
    let user_dir = home.path().join("Library/LaunchAgents");
    std::fs::create_dir_all(&user_dir).unwrap();
    std::fs::write(user_dir.join(&plist), "<plist/>").unwrap();
    assert_eq!(
        login_unit_present(TargetPlatform::Macos, Some(home.path()), machine.path()),
        Some(true)
    );
    let other_home = tempfile::tempdir().unwrap();
    let machine_dir = machine.path().join("Library/LaunchAgents");
    std::fs::create_dir_all(&machine_dir).unwrap();
    std::fs::write(machine_dir.join(&plist), "<plist/>").unwrap();
    assert_eq!(
        login_unit_present(
            TargetPlatform::Macos,
            Some(other_home.path()),
            machine.path()
        ),
        Some(true),
        "the machine-wide unit an MDM pushes counts"
    );
    assert_eq!(
        login_unit_present(TargetPlatform::Macos, None, machine.path()),
        None
    );
    assert_eq!(
        login_unit_present(TargetPlatform::Windows, Some(home.path()), machine.path()),
        None,
        "only schtasks can say on Windows"
    );
}
