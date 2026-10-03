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
    let (context, _) = self::context(FakeOs::unsandboxed());
    for id in ProbeId::all() {
        let windows_specific = matches!(
            id,
            ProbeId::AdminControlRead
                | ProbeId::KeychainSearch
                | ProbeId::DaemonProcessQuery
                | ProbeId::BrokerShellExecute
                | ProbeId::ExeWrite
        );
        assert_eq!(plan(id, &context).is_some(), windows_specific, "{id}");
    }
}

#[test]
fn the_control_file_is_opened_for_read_through_the_seam_only() {
    let (context, os) = self::context(FakeOs::unsandboxed());
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
    let (context, os) = self::context(FakeOs::sandboxed());
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
fn the_process_query_asks_powershell_for_the_path_of_the_pid_the_hello_named() {
    let (context, os) = self::context(FakeOs::unsandboxed().with_env("SystemRoot", r"C:\Windows"));
    // What the reach probe records from the acknowledged hello.
    context.daemon_pid.set(Some(4242));
    let outcome = run(&context, ProbeId::DaemonProcessQuery);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    assert_eq!(outcome.result.note.as_deref(), Some("query only"));
    let calls = os.calls();
    assert_eq!(calls.len(), 1, "one helper, nothing read: {calls:#?}");
    let powershell = Path::new(r"C:\Windows")
        .join("System32")
        .join(r"WindowsPowerShell\v1.0\powershell.exe");
    assert!(calls[0].starts_with(&format!(
        "helper {} -NoProfile -NonInteractive -NoLogo -Command ",
        powershell.display()
    )));
    assert!(calls[0].contains("Get-Process -Id 4242 -ErrorAction Stop"));
    assert!(calls[0].contains("'PATH=' + [string]$p.Path"));
}

#[test]
fn without_a_reached_daemon_the_process_query_is_not_probed() {
    let (context, os) = self::context(FakeOs::unsandboxed());
    // The reach probe answered: nothing acknowledged the hello.
    context.daemon_pid.set(None);
    let outcome = run(&context, ProbeId::DaemonProcessQuery);
    assert_eq!(outcome.result.state, ProbeState::NotProbed);
    assert_eq!(
        outcome.result.note.as_deref(),
        Some("no daemon reached: no pid to probe")
    );
    assert!(os.calls().is_empty(), "no helper runs without a pid");
}

#[test]
fn process_creation_is_the_shell_execute_broker() {
    let (context, os) = self::context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::BrokerShellExecute);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    let where_exe = Path::new(DEFAULT_SYSTEM_ROOT)
        .join("System32")
        .join("where.exe");
    assert_eq!(os.calls(), [format!("helper {} /?", where_exe.display())]);
}

#[test]
fn the_executable_is_opened_for_write_through_the_seam_only() {
    // Windows keeps the open: the share check refuses a mapped image after
    // the ACL's access check and before any handle exists, and there is no
    // signature cache to invalidate (macOS asks through `access(2)`).
    let (context, os) = self::context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Allowed);
    assert_eq!(os.calls(), ["OpenWrite /usr/local/bin/pam"]);
    let (context, os) = self::context(FakeOs::sandboxed());
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Denied);
    assert_eq!(os.calls(), ["OpenWrite /usr/local/bin/pam"]);
    let mut fake = FakeOs::unsandboxed();
    fake.exe = None;
    let (context, os) = self::context(fake);
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Unknown);
    assert!(outcome.result.note.unwrap().starts_with("current_exe:"));
    assert!(
        os.calls().is_empty(),
        "nothing is opened without an executable"
    );
}

#[test]
fn the_harness_chain_is_one_powershell_walk() {
    let (_, os) = self::context(FakeOs::unsandboxed());
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
