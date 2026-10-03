//! The Windows plan, driven through the fake on any host: which seam call
//! each probe makes, with which path, account or helper, and what the
//! classifiers make of the fake's answers.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use pam_proto::doctor::{Platform, ProbeId, ProbeState};

use super::Options;
use super::inventory::{Context, Outcome};
use super::os_test::FakeOs;
use super::probe_windows::{DEFAULT_SYSTEM_ROOT, harness_chain, plan};

const BASE: &str = "/tmp/pamdoc-base";

fn context(os: FakeOs) -> (Context, Arc<FakeOs>) {
    let os = Arc::new(os);
    let dynamic: Arc<dyn super::os::Os> = os.clone();
    let context = Context::new(
        Platform::Windows,
        &Options::new(PathBuf::from(BASE)),
        dynamic,
    )
    .unwrap();
    (context, os)
}

fn run(context: &Context, id: ProbeId) -> Outcome {
    let planned = plan(id, context).unwrap_or_else(|| panic!("{id} has no Windows plan"));
    assert_eq!(planned.id, id);
    (planned.op)()
}

#[test]
fn only_the_windows_specific_probes_are_planned_here() {
    let (context, _) = context(FakeOs::unsandboxed());
    for id in ProbeId::all() {
        let windows_specific = matches!(
            id,
            ProbeId::AdminControlRead
                | ProbeId::KeychainSearch
                | ProbeId::DaemonProcessQuery
                | ProbeId::BrokerShellExecute
        );
        assert_eq!(plan(id, &context).is_some(), windows_specific, "{id}");
    }
}

#[test]
fn the_control_file_is_opened_for_read_through_the_seam_only() {
    let (context, os) = context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::AdminControlRead);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    let expected = format!(
        "OpenRead {}",
        Path::new(BASE).join("admin").join("control.json").display()
    );
    assert_eq!(os.calls(), [expected]);
}

#[test]
fn the_credential_store_is_asked_for_the_absent_account() {
    let (context, os) = context(FakeOs::sandboxed());
    let outcome = run(&context, ProbeId::KeychainSearch);
    assert_eq!(outcome.result.state, ProbeState::Denied);
    assert_eq!(
        os.calls(),
        [format!("keyring {}", context.absent_account())]
    );
    assert!(
        context
            .absent_account()
            .starts_with(&format!("pam.doctor.absent.{}.", context.pid))
    );
}

#[test]
fn the_process_query_asks_powershell_for_the_lock_pids_path() {
    let (context, os) = context(FakeOs::unsandboxed().with_env("SystemRoot", r"C:\Windows"));
    let outcome = run(&context, ProbeId::DaemonProcessQuery);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    assert_eq!(outcome.result.note.as_deref(), Some("query only"));
    let calls = os.calls();
    assert_eq!(
        calls[0],
        format!("ReadPid {}", context.lock_path().display())
    );
    let powershell = Path::new(r"C:\Windows")
        .join("System32")
        .join(r"WindowsPowerShell\v1.0\powershell.exe");
    assert!(calls[1].starts_with(&format!(
        "helper {} -NoProfile -NonInteractive -NoLogo -Command ",
        powershell.display()
    )));
    assert!(calls[1].contains("Get-Process -Id 4242 -ErrorAction Stop"));
    assert!(calls[1].contains("'PATH=' + [string]$p.Path"));
}

#[test]
fn an_unreadable_lock_leaves_the_process_query_unknown() {
    let mut os = FakeOs::unsandboxed();
    os.pid_file = Err(super::os_test::Answer::Denied);
    let (context, os) = context(os);
    let outcome = run(&context, ProbeId::DaemonProcessQuery);
    assert_eq!(outcome.result.state, ProbeState::Unknown);
    assert_eq!(
        outcome.result.note.as_deref(),
        Some("lock file unreadable: no pid to probe")
    );
    assert_eq!(os.calls().len(), 1, "no helper runs without a pid");
}

#[test]
fn process_creation_is_the_shell_execute_broker() {
    let (context, os) = context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::BrokerShellExecute);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    let where_exe = Path::new(DEFAULT_SYSTEM_ROOT)
        .join("System32")
        .join("where.exe");
    assert_eq!(os.calls(), [format!("helper {} /?", where_exe.display())]);
}

#[test]
fn the_harness_chain_is_one_powershell_walk() {
    let (_, os) = context(FakeOs::unsandboxed());
    let chain = harness_chain(os.as_ref(), 4242, std::time::Duration::from_secs(5));
    assert_eq!(chain, ["claude.exe", "cmd.exe", "explorer.exe"]);
    let calls = os.calls();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].contains("$id = 4242;"));
    assert!(calls[0].contains("Win32_Process"));
    assert!(calls[0].contains("$seen.ContainsKey($id)"), "cycle-safe");
    let mut missing = FakeOs::unsandboxed();
    missing.helper_mood = super::os_test::HelperMood::Missing;
    assert!(harness_chain(&missing, 4242, std::time::Duration::from_secs(5)).is_empty());
}
