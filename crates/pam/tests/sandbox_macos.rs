//! Fixture proof of an explicit macOS sandbox profile, not an installed enterprise policy.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use pam_daemon::daemon::run_daemon;
use pam_daemon::policy::PROFILE_SETTING_KEY;
use pam_store::Store;
use serde_json::json;
use tokio::sync::watch;

/// Runs only when re-executed under the fixture sandbox by the parent test.
#[test]
fn sandbox_probe_child() {
    let Ok(root) = std::env::var("PAM_SANDBOX_PROBE") else {
        return;
    };
    let root = PathBuf::from(root);
    let denied = |result: std::io::Result<()>| {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    };
    denied(std::os::unix::net::UnixStream::connect(root.join("pam/admin/control.sock")).map(drop));
    denied(std::fs::read(root.join("pam/state.sqlite3")).map(drop));
    denied(
        std::fs::OpenOptions::new()
            .write(true)
            .open(root.join("pam/state.sqlite3"))
            .map(drop),
    );
    denied(
        std::fs::OpenOptions::new()
            .write(true)
            .open(root.join("trusted-asset"))
            .map(drop),
    );
    denied(
        std::fs::OpenOptions::new()
            .write(true)
            .open(env!("CARGO_BIN_EXE_pam"))
            .map(drop),
    );
    let signal = Command::new("/bin/kill")
        .args(["-0", &std::env::var("PAM_SANDBOX_PARENT_PID").unwrap()])
        .output()
        .unwrap();
    assert!(!signal.status.success());
    assert!(String::from_utf8_lossy(&signal.stderr).contains("Operation not permitted"));
    // No item is created or read: a unique nonexistent service/account is queried.
    // Exit 44 alone is NOT evidence of denial (it also means ordinary not-found).
    let keychain = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            &format!("pam-sandbox-missing-{}", std::process::id()),
            "-a",
            "pam-sandbox-fixture-nonexistent",
        ])
        .output()
        .unwrap();
    assert!(!keychain.status.success());
    let stderr = String::from_utf8_lossy(&keychain.stderr);
    assert!(
        stderr.contains("SecKeychainSearchCreateFromAttributes:"),
        "keychain initialization was not denied: {stderr}"
    );
}

async fn execute(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

fn sandbox(profile: &Path, program: &Path, root: &Path, repo: &Path) -> Command {
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-f")
        .arg(profile)
        .arg(program)
        .current_dir(repo)
        .env("PAM_BASE_DIR", root.join("pam"));
    command
}

async fn pam(profile: &Path, root: &Path, repo: &Path, args: &[&str]) -> Output {
    let mut command = sandbox(profile, Path::new(env!("CARGO_BIN_EXE_pam")), root, repo);
    command.args(args);
    execute(command).await
}

fn body(output: &Output, code: i32) -> serde_json::Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_allows_brokered_evidence_but_denies_private_authority() {
    // Warm exec outside deadlines: macOS assesses newly linked binaries once.
    let mut warm = Command::new(env!("CARGO_BIN_EXE_pam"));
    warm.arg("--version");
    assert!(execute(warm).await.status.success());
    tokio::time::timeout(Duration::from_secs(90), async {
        let temp = tempfile::Builder::new().prefix("pamsb").tempdir_in("/tmp").unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(root.join("trusted-asset"), b"trusted fixture asset").unwrap();
        let base = root.join("pam");
        let store = Store::open(&base.join("state.sqlite3")).await.unwrap();
        store.set_setting(PROFILE_SETTING_KEY, "\"relaxed\"").await.unwrap();
        store.set_setting("flows.scope_policy", &json!({"version":1,"repositories":[{"root":repo,"connectors":[]}]}).to_string()).await.unwrap();
        drop(store);
        let (shutdown, receiver) = watch::channel(false);
        let daemon = run_daemon(Some(base.clone()), receiver).await.unwrap();
        let profile = root.join("agent.sb");
        let text = include_str!("support/broker-macos.sb")
            .replace("@BASE@", base.to_str().unwrap())
            .replace("@ASSET@", root.join("trusted-asset").to_str().unwrap())
            .replace("@HOME@", std::env::var("HOME").unwrap().as_str());
        std::fs::write(&profile, text).unwrap();
        let original = body(&pam(&profile, &root, &repo, &["echo", "{}", "--json"]).await, 0);
        let ticket = original["id"].as_str().unwrap();
        let store = daemon.store();
        store.insert_evidence("sandbox-evidence", ticket, "log_source", b"safe\n", None).await.unwrap();
        assert!(store.insert_evidence_view(&pam_store::EvidenceViewInsert {
            evidence_id:"sandbox-evidence".into(),request_id:ticket.into(),repository:repo.to_string_lossy().into_owned(),
            origin_json:json!({"targets":[]}).to_string(),identity_json:json!({"schema_version":1}).to_string(),
            map_json:json!([{"view":{"start":0,"end":5},"parent":{"start":0,"end":5},"relation":"identity"}]).to_string(),
            view_id:"sandbox-view".into(),view_bytes:b"safe\n".to_vec(),
        }).await.unwrap());
        let args = ["evidence","read","sandbox-evidence","--request",ticket,"--length","2","--json"];
        let read = body(&pam(&profile,&root,&repo,&args).await,0);
        assert_eq!(read["body"]["data"],"7361");
        assert_eq!(read["body"]["next_offset"],2);
        let mut probe = sandbox(&profile,&std::env::current_exe().unwrap(),&root,&repo);
        probe.args(["--exact","sandbox_probe_child","--nocapture"])
            .env("PAM_SANDBOX_PROBE",&root)
            .env("PAM_SANDBOX_PARENT_PID",std::process::id().to_string());
        let denied = execute(probe).await;
        assert!(denied.status.success(),"{} {}",String::from_utf8_lossy(&denied.stdout),String::from_utf8_lossy(&denied.stderr));
        assert_eq!(std::fs::read(root.join("trusted-asset")).unwrap(),b"trusted fixture asset");
        store.set_setting("flows.scope_policy",&json!({"version":1,"repositories":[]}).to_string()).await.unwrap();
        let refused = body(&pam(&profile,&root,&repo,&args).await,3);
        assert_eq!(refused["cause"],"evidence_unavailable");
        assert!(store.get_evidence("sandbox-evidence").await.unwrap().is_some());
        let _ = shutdown.send(true);
        daemon.shutdown().await;
    }).await.expect("sandbox acceptance fixture completes within deadline");
}
