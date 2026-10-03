//! `doctor.report` end to end: a real daemon on a temp base, the doctor's
//! admin probe on the real private socket, the report over the public plane,
//! the request and audit rows, the attribution, and the `boundary` block of
//! `status`.

use std::time::Duration;

use pam_daemon::boundary::{ACTION_DOCTOR_REPORT, CAP_DOCTOR_REPORT, CAUSE_INVALID_REPORT};
use pam_daemon::daemon::{ACTION_EXECUTE, ACTION_EXECUTION_REFUSAL};
use pam_proto::doctor::{
    DaemonFacts, DoctorReport, EnvFacts, Frontend, OsError, Platform, Probe, ProbeId, ProbeResult,
};
use pam_proto::wire::Via;
use pam_proto::{Outcome, Response};
use pam_store::{Actor, Decision, RequestIngress, RequestState};
use pam_testkit::{TestDaemon, envelope, with_deadline};
use serde_json::{Value, json};

/// A full document for this platform: every must-deny probe denied except
/// `admin.endpoint`, which the probe below really reaches.
fn document() -> Value {
    let platform = Platform::current().expect("a supported platform");
    let probes = ProbeId::all()
        .map(|id| {
            if !id.applies_to(platform) {
                return Probe::not_applicable(id, platform);
            }
            match id {
                ProbeId::PublicUnlink => Probe::not_probed(id, "side effect"),
                ProbeId::PublicReach | ProbeId::RunLockProbe | ProbeId::AdminEndpoint => {
                    Probe::new(id, ProbeResult::allowed())
                }
                _ => Probe::new(
                    id,
                    ProbeResult::denied(OsError::of_kind("PermissionDenied")),
                ),
            }
        })
        .collect();
    let env = EnvFacts {
        socket_dir: None,
        base_dir_override: None,
        resolved_base: "/Users/me/.pam".to_owned(),
        resolved_endpoint: "/Users/me/.pam/run/pam.sock".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        exe: std::env::current_exe()
            .ok()
            .map(|exe| exe.to_string_lossy().into_owned()),
        cwd_repo: None,
        frontend: Frontend::Embedded,
        harness_chain: vec!["cargo".to_owned()],
    };
    let daemon = Some(DaemonFacts {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        proto: 2,
        epoch: "01JB".to_owned(),
        via: Via::Direct,
    });
    let report = DoctorReport::new(platform, 1_759_400_000, daemon, probes, env);
    serde_json::to_value(report.as_args()).unwrap()
}

fn same_file(a: &str, b: &std::path::Path) -> bool {
    std::path::Path::new(a).canonicalize().ok() == b.canonicalize().ok()
}

async fn status(client: &mut pam_testkit::TestClient, id: &str) -> Value {
    match client
        .request(&envelope(id, "status", json!({}), true))
        .await
    {
        Response::Result { body, .. } => body,
        other => panic!("expected a status result, got {other:?}"),
    }
}

/// Waits for the admin probe from this process to be observed and
/// attributed to `request_id`.
#[cfg(unix)]
async fn assert_probe_attributed(store: &pam_store::Store, request_id: &str) {
    let rows = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let rows = store.list_boundary_observations(16).await.unwrap();
            if rows
                .iter()
                .any(|row| row.peer.pid == Some(std::process::id()) && row.attributed.is_some())
            {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the probe was observed and attributed");
    let probe = rows
        .iter()
        .find(|row| row.kind == pam_store::OBSERVATION_ADMIN_CONTACT)
        .unwrap();
    assert_eq!(probe.attributed.as_deref(), Some(request_id));
    assert!(!probe.expected);
    assert_eq!(
        probe.detail.as_deref(),
        Some("accepted; the peer sent nothing")
    );
}

/// The `boundary` block after one `not_established` run whose admin probe
/// was explained.
fn assert_block_after_run(boundary: &Value) {
    assert_eq!(boundary["last_report"]["verdict"], "not_established");
    assert_eq!(boundary["last_report"]["request_id"], "req_doc");
    assert_eq!(boundary["last_report"]["agent"], "claude");
    assert_eq!(boundary["last_report"]["failed"], json!(["admin.endpoint"]));
    assert!(boundary["last_report"]["age_s"].is_u64());
    assert_eq!(boundary["reports"]["retained"], 1);
    assert_eq!(boundary["admin_contacts"]["unattributed"], 0);
    assert_eq!(
        boundary["peer_identity"],
        if cfg!(unix) { "kernel_pid" } else { "none" }
    );
    let summary = boundary["summary"].as_str().unwrap();
    assert!(summary.starts_with("not_established "), "{summary}");
    assert!(
        summary.ends_with("admin contacts unattributed: 0"),
        "{summary}"
    );
}

#[tokio::test]
async fn a_doctor_run_is_recorded_with_the_daemon_view_of_its_peer_and_explains_its_admin_probe() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        let store = daemon.store();

        // Before any run: the block says so.
        let body = status(&mut client, "req_status_before").await;
        assert_eq!(body["boundary"]["last_report"], Value::Null);
        assert_eq!(
            body["boundary"]["summary"],
            "never checked — run pam doctor from the agent"
        );

        // An ordinary public request carries the daemon's resolution of
        // its peer on its row: this process's executable and ancestry.
        let response = client
            .request(&envelope("req_echo", "echo", json!({ "msg": "hi" }), true))
            .await;
        assert!(matches!(response, Response::Result { .. }), "{response:?}");
        let (exe, harness) = store
            .request_peer_facts("req_echo")
            .await
            .unwrap()
            .expect("the echo row");
        if cfg!(unix) {
            let own = std::env::current_exe().unwrap();
            assert!(
                exe.as_deref().is_some_and(|got| same_file(got, &own)),
                "{exe:?}"
            );
            assert!(harness.is_some(), "an ancestry was classified");
        } else {
            assert_eq!((exe, harness), (None, None));
        }

        // The doctor's `admin.endpoint` probe: connect, send nothing, hold
        // the socket a moment (so the kernel can still name the peer when
        // the daemon accepts), drop.
        #[cfg(unix)]
        {
            let socket = daemon.base_dir().join("admin").join("control.sock");
            let probe = tokio::net::UnixStream::connect(&socket).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(probe);
        }

        // The report.
        let response = client
            .request(&envelope("req_doc", CAP_DOCTOR_REPORT, document(), true))
            .await;
        let Response::Result { outcome, body, .. } = response else {
            panic!("expected a result, got {response:?}");
        };
        assert_eq!(outcome, Outcome::Verified);
        assert_eq!(body["accepted"], true);
        assert_eq!(body["request_id"], "req_doc");
        assert_eq!(body["verdict"], "not_established");
        assert_eq!(body["claimed_harness"], "cargo");
        if cfg!(unix) {
            assert_eq!(body["peer"]["pid"], std::process::id());
            assert!(body["peer"]["exe"].is_string());
        } else {
            assert_eq!(body["peer"]["pid"], Value::Null);
            assert_eq!(body["harness_agrees"], Value::Null);
        }

        // One request row on the public plane, terminal, with its two
        // audit rows: the report's own and the pipeline's terminal one.
        let row = store.get_request("req_doc").await.unwrap().unwrap();
        assert_eq!(row.state, RequestState::Done);
        assert_eq!(row.origin.ingress, RequestIngress::Public);
        let audit = store.audit_for_request("req_doc").await.unwrap();
        let actions: Vec<&str> = audit.iter().map(|row| row.action.as_str()).collect();
        assert_eq!(actions, [ACTION_DOCTOR_REPORT, ACTION_EXECUTE]);
        assert_eq!(audit[0].decision, Decision::Allow);
        assert_eq!(audit[0].actor, Actor::System);
        let detail: Value = serde_json::from_str(audit[0].detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["failed"], json!(["admin.endpoint"]));

        let reports = store.list_boundary_reports(10).await.unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].request_id.as_deref(), Some("req_doc"));
        assert_eq!(reports[0].failed, ["admin.endpoint"]);
        assert_eq!(reports[0].client_version, env!("CARGO_PKG_VERSION"));

        // The admin probe was seen, from this pid, and the report from the
        // same pid explains it (whichever of the two the store saw first).
        #[cfg(unix)]
        assert_probe_attributed(&store, "req_doc").await;

        // The block after the run.
        let body = status(&mut client, "req_status_after").await;
        assert_block_after_run(&body["boundary"]);

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}

/// A forged verdict is refused `invalid_args`, audited as an execution
/// refusal, and stores nothing: no report row, and the block stays empty.
#[tokio::test]
async fn a_forged_report_is_refused_and_leaves_no_record() {
    with_deadline(async {
        let daemon = TestDaemon::spawn().await;
        let mut client = daemon.client().await;
        let store = daemon.store();
        let mut forged = document();
        forged["verdict"] = json!("established");
        forged["failed"] = json!([]);
        let response = client
            .request(&envelope("req_forged", CAP_DOCTOR_REPORT, forged, true))
            .await;
        let Response::Refusal {
            cause,
            detail,
            retryable,
            ..
        } = response
        else {
            panic!("expected a refusal, got {response:?}");
        };
        assert_eq!(cause, CAUSE_INVALID_REPORT);
        assert!(!retryable);
        assert!(
            detail.starts_with("doctor.report was refused: "),
            "{detail}"
        );
        daemon
            .assert_row_state("req_forged", RequestState::Refused)
            .await;
        assert_eq!(
            daemon.terminal_audit_actions("req_forged").await,
            [ACTION_EXECUTION_REFUSAL]
        );
        assert!(store.list_boundary_reports(10).await.unwrap().is_empty());
        let body = status(&mut client, "req_status_forged").await;
        assert_eq!(body["boundary"]["last_report"], Value::Null);

        daemon.assert_invariant_clean().await;
        daemon.stop().await;
    })
    .await;
}
