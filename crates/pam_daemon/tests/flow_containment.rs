//! Actual flow child and grandchild containment; no direct sandbox-exec shortcut.
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(target_os = "macos")]
use pam_proto::Outcome;
use pam_proto::Response;
use pam_testkit::{
    TestDaemon, base_of, envelope_for_repo, seed_allowed_programs, seed_extra_path, seed_flow,
    seed_relaxed, seed_repository_scope, short_tempdir,
};
use serde_json::json;

fn probe_root() -> Option<PathBuf> {
    std::env::var_os("PAM_CONTAINMENT_BASE").map(PathBuf::from)
}

#[test]
fn containment_child() {
    let Some(base) = probe_root() else {
        return;
    };
    std::fs::write("child-started", b"started").unwrap();
    #[cfg(target_os = "macos")]
    {
        assert_private_denied(&base);
        let grandchild = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "containment_grandchild", "--nocapture"])
            .output()
            .unwrap();
        assert!(
            grandchild.status.success(),
            "{} {}",
            String::from_utf8_lossy(&grandchild.stdout),
            String::from_utf8_lossy(&grandchild.stderr)
        );
        std::fs::write("child-verified", b"denied").unwrap();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = base;
}

#[test]
fn containment_grandchild() {
    let Some(base) = probe_root() else {
        return;
    };
    #[cfg(target_os = "macos")]
    {
        assert_private_denied(&base);
        std::fs::write("grandchild-verified", b"denied").unwrap();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = base;
}

#[cfg(target_os = "macos")]
fn assert_private_denied(base: &Path) {
    let denied = |result: std::io::Result<()>| {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    };
    denied(std::os::unix::net::UnixStream::connect(base.join("admin/control.sock")).map(drop));
    denied(
        std::os::unix::net::UnixStream::connect(base.join("run/../admin/control.sock")).map(drop),
    );
    denied(std::fs::read(base.join("state.sqlite3")).map(drop));
    for file in [
        base.join("state.sqlite3"),
        base.join("trusted-fixture-asset"),
        std::env::current_exe().unwrap(),
    ] {
        denied(std::fs::OpenOptions::new().write(true).open(file).map(drop));
    }
    let signal = std::process::Command::new("/bin/kill")
        .args(["-0", &std::env::var("PAM_CONTAINMENT_PARENT").unwrap()])
        .output()
        .unwrap();
    assert!(!signal.status.success());
    assert!(String::from_utf8_lossy(&signal.stderr).contains("Operation not permitted"));
    let keychain = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            &format!("pam-containment-missing-{}", std::process::id()),
            "-a",
            "pam-containment-nonexistent",
        ])
        .output()
        .unwrap();
    assert!(!keychain.status.success());
    assert!(
        String::from_utf8_lossy(&keychain.stderr)
            .contains("SecKeychainSearchCreateFromAttributes:"),
        "ordinary item-not-found does not prove denial: {}",
        String::from_utf8_lossy(&keychain.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn real_flow_contains_children_and_descendants_or_refuses_before_spawn() {
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let tmp = short_tempdir();
    let repo = short_tempdir();
    let base = base_of(&tmp);
    seed_relaxed(&tmp).await;
    seed_repository_scope(&tmp, repo.path(), &[]).await;
    let name = executable.file_name().unwrap().to_str().unwrap();
    seed_allowed_programs(&tmp, &[name]).await;
    seed_extra_path(&tmp, &[executable.parent().unwrap().to_str().unwrap()]).await;
    let flow = json!({"schema":1,"id":"containment","name":"Containment fixture","steps":[{
        "id":"untrusted-child", "effect":"stateful", "run":[name,"--exact","containment_child","--nocapture"],
        "env":{"PAM_CONTAINMENT_BASE":base.canonicalize().unwrap(),"PAM_CONTAINMENT_PARENT":std::process::id().to_string()}
    }]});
    drop(seed_flow(&tmp, "containment", &flow.to_string()));
    std::fs::write(base.join("trusted-fixture-asset"), b"unchanged").unwrap();
    let daemon = TestDaemon::spawn_at(tmp).await;
    daemon.store().insert_grant("flow.run").await.unwrap();
    daemon
        .store()
        .insert_grant(&pam_daemon::flow_service::step_capability(
            "containment",
            "untrusted-child",
        ))
        .await
        .unwrap();
    daemon
        .store()
        .set_setting("containment.sentinel", "unchanged")
        .await
        .unwrap();
    let mut client = daemon.client().await;
    let mut request = envelope_for_repo(
        repo.path().canonicalize().unwrap().to_str().unwrap(),
        "containment-run",
        "flow.run",
        json!({"id":"containment","inputs":{}}),
        true,
    );
    request.deadline_ms = 90_000;
    let response = tokio::time::timeout(Duration::from_secs(100), client.request(&request))
        .await
        .unwrap();
    let mut retained_debug = String::new();
    for meta in daemon
        .store()
        .list_evidence("containment-run")
        .await
        .unwrap()
    {
        if let Some(row) = daemon.store().get_evidence(&meta.id).await.unwrap() {
            retained_debug.push_str(&String::from_utf8_lossy(&row.content));
        }
    }
    #[cfg(target_os = "macos")]
    {
        assert!(
            matches!(
                &response,
                Response::Result {
                    outcome: Outcome::Changed,
                    ..
                }
            ),
            "{response:?} retained: {retained_debug}"
        );
        assert_eq!(
            std::fs::read(repo.path().join("child-verified")).unwrap(),
            b"denied"
        );
        assert_eq!(
            std::fs::read(repo.path().join("grandchild-verified")).unwrap(),
            b"denied"
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert!(
            !repo.path().join("child-started").exists(),
            "unsupported platform executed helper"
        );
        let mut retained = String::new();
        if let Response::Result { evidence, .. } = &response {
            for id in evidence {
                if let Some(row) = daemon.store().get_evidence(id).await.unwrap() {
                    retained.push_str(&String::from_utf8_lossy(&row.content));
                }
            }
        }
        assert!(
            retained.contains("command_containment_unavailable"),
            "{response:?} {retained}"
        );
    }
    assert_host_unchanged(&daemon, &base).await;
    daemon.assert_single_terminal_audit("containment-run").await;
    drop(daemon.stop().await);
}

async fn assert_host_unchanged(daemon: &TestDaemon, base: &std::path::Path) {
    assert_eq!(
        std::fs::read(base.join("trusted-fixture-asset")).unwrap(),
        b"unchanged"
    );
    assert!(
        daemon
            .store()
            .get_request("containment-run")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        daemon
            .store()
            .get_setting("containment.sentinel")
            .await
            .unwrap()
            .as_deref(),
        Some("unchanged")
    );
}
