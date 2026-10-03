//! The walk and the runner: bounds, deadlines, the context's derived names
//! and paths, and one row per inventory entry.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pam_proto::doctor::{INVENTORY, Platform, ProbeId, ProbeResult, ProbeState};
use pam_proto::wire::Via;

use super::Options;
use super::inventory::{Context, Planned, UNLINK_NOT_PROBED, bounded, plan, run_planned, walk};
use super::os_test::FakeOs;

fn context(os: FakeOs, base: &Path) -> Context {
    let platform = Platform::current().expect("a supported platform");
    Context::new(platform, &Options::new(base.to_path_buf()), Arc::new(os)).unwrap()
}

fn planned(
    id: ProbeId,
    bound: Duration,
    op: impl FnOnce() -> ProbeResult + Send + 'static,
) -> Planned {
    Planned {
        id,
        bound,
        op: Box::new(move || op().into()),
    }
}

#[test]
fn the_runner_collects_every_result_with_its_elapsed_time() {
    let results = run_planned(
        vec![
            planned(
                ProbeId::StoreRead,
                Duration::from_secs(2),
                ProbeResult::allowed,
            ),
            planned(
                ProbeId::StoreWrite,
                Duration::from_secs(2),
                ProbeResult::absent,
            ),
        ],
        Duration::from_secs(10),
    );
    assert_eq!(results.len(), 2);
    for (id, outcome) in results {
        assert!(
            outcome.result.elapsed_ms.is_some(),
            "{id} has no elapsed time"
        );
        match id {
            ProbeId::StoreRead => assert_eq!(outcome.result.state, ProbeState::Allowed),
            ProbeId::StoreWrite => assert_eq!(outcome.result.state, ProbeState::Absent),
            other => panic!("unexpected {other}"),
        }
    }
}

#[test]
fn a_probe_that_overruns_its_bound_is_unknown_and_does_not_hold_the_run() {
    let started = Instant::now();
    let results = run_planned(
        vec![
            planned(ProbeId::StoreRead, Duration::from_millis(50), || {
                std::thread::sleep(Duration::from_millis(400));
                ProbeResult::allowed()
            }),
            planned(
                ProbeId::AdminDir,
                Duration::from_secs(2),
                ProbeResult::allowed,
            ),
        ],
        Duration::from_secs(10),
    );
    assert!(
        started.elapsed() < Duration::from_millis(350),
        "the run waited for the slow probe"
    );
    let slow = results
        .iter()
        .find(|(id, _)| *id == ProbeId::StoreRead)
        .unwrap();
    assert_eq!(slow.1.result.state, ProbeState::Unknown);
    assert_eq!(slow.1.result.note.as_deref(), Some("timed out after 50 ms"));
    let fast = results
        .iter()
        .find(|(id, _)| *id == ProbeId::AdminDir)
        .unwrap();
    assert_eq!(fast.1.result.state, ProbeState::Allowed);
}

#[test]
fn the_run_deadline_caps_every_bound() {
    let results = run_planned(
        vec![planned(ProbeId::StoreRead, Duration::from_secs(5), || {
            std::thread::sleep(Duration::from_millis(400));
            ProbeResult::allowed()
        })],
        Duration::from_millis(50),
    );
    assert_eq!(results[0].1.result.state, ProbeState::Unknown);
    assert_eq!(
        results[0].1.result.note.as_deref(),
        Some("the run deadline passed before the probe answered")
    );
}

#[test]
fn a_probe_whose_thread_panics_is_unknown() {
    let results = run_planned(
        vec![planned(ProbeId::StoreRead, Duration::from_secs(2), || {
            panic!("probe bug")
        })],
        Duration::from_secs(5),
    );
    assert_eq!(results[0].1.result.state, ProbeState::Unknown);
    assert_eq!(
        results[0].1.result.note.as_deref(),
        Some("the probe thread ended without a result")
    );
}

#[test]
fn a_bounded_computation_answers_or_is_dropped() {
    assert_eq!(bounded(|| 7).wait(Duration::from_secs(2)), Some(7));
    let slow = bounded(|| {
        std::thread::sleep(Duration::from_millis(400));
        7
    });
    assert_eq!(slow.wait(Duration::from_millis(20)), None);
}

#[test]
fn the_context_derives_its_paths_and_absent_names_from_the_base() {
    let base = PathBuf::from("/tmp/pamdoc-base");
    let context = context(FakeOs::unsandboxed(), &base);
    assert_eq!(context.via(), Via::Direct);
    assert_eq!(context.lock_path(), base.join("run").join("daemon.lock"));
    assert_eq!(
        context.dirs.public_socket(),
        base.join("run").join("pam.sock")
    );
    assert!(context.session_dir.is_none());
    assert!(context.base_override.is_none());
    assert_eq!(context.pid, std::process::id());
    assert!(!context.nonce.is_empty());
    assert!(context.nonce.chars().all(|ch| ch.is_ascii_alphanumeric()));
    assert_eq!(
        context.absent_account(),
        format!("pam.doctor.absent.{}.{}", context.pid, context.nonce)
    );
    // Two contexts never share a nonce.
    let other = self::context(FakeOs::unsandboxed(), &base);
    assert_ne!(context.nonce, other.nonce);
}

#[test]
fn the_session_override_dials_the_relay_and_keeps_the_base_lock() {
    let base = PathBuf::from("/tmp/pamdoc-base");
    let os = FakeOs::unsandboxed()
        .with_env("PAM_SOCKET_DIR", "/tmp/pamdoc-session")
        .with_env("PAM_BASE_DIR", "/tmp/pamdoc-base");
    let context = context(os, &base);
    assert_eq!(context.via(), Via::Relay);
    assert_eq!(
        context.dirs.public_socket(),
        Path::new("/tmp/pamdoc-session/pam.sock")
    );
    assert_eq!(context.lock_path(), base.join("run").join("daemon.lock"));
    assert_eq!(
        context
            .base_override
            .as_deref()
            .map(|value| value.to_string_lossy().into_owned()),
        Some("/tmp/pamdoc-base".to_owned())
    );
    // An empty override is unset.
    let os = FakeOs::unsandboxed().with_env("PAM_SOCKET_DIR", "");
    assert!(self::context(os, &base).session_dir.is_none());
}

#[test]
fn a_socket_path_that_does_not_fit_is_a_run_error() {
    let base = PathBuf::from(format!("/tmp/{}", "p".repeat(120)));
    let result = Context::new(
        Platform::Macos,
        &Options::new(base),
        Arc::new(FakeOs::unsandboxed()),
    );
    assert!(matches!(result, Err(super::RunError::Base(_))));
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("cannot resolve the public endpoint")
    );
}

#[test]
fn every_applicable_probe_has_a_plan_and_the_walk_emits_one_row_per_inventory_entry() {
    let base = PathBuf::from("/tmp/pamdoc-base");
    let context = context(FakeOs::unsandboxed(), &base);
    for id in ProbeId::all() {
        let applicable = id.applies_to(context.platform) && id != ProbeId::PublicUnlink;
        assert_eq!(
            plan(id, &context).is_some(),
            applicable,
            "{id}: plan presence must match applicability"
        );
    }
    let walk = walk(&context);
    assert_eq!(walk.probes.len(), INVENTORY.len());
    let ids: Vec<ProbeId> = walk.probes.iter().map(|probe| probe.id).collect();
    assert_eq!(
        ids,
        ProbeId::all().collect::<Vec<_>>(),
        "rows in inventory order"
    );
    for probe in &walk.probes {
        if !probe.id.applies_to(context.platform) && probe.id != ProbeId::PublicUnlink {
            assert_eq!(probe.result, ProbeState::NotProbed);
            assert_eq!(
                probe.note.as_deref(),
                Some(format!("not probed on {}", context.platform).as_str())
            );
        }
    }
    let unlink = walk
        .probes
        .iter()
        .find(|probe| probe.id == ProbeId::PublicUnlink)
        .unwrap();
    assert_eq!(unlink.result, ProbeState::NotProbed);
    assert_eq!(unlink.note.as_deref(), Some(UNLINK_NOT_PROBED));
    let daemon = walk.daemon.unwrap();
    assert_eq!(
        (daemon.version.as_str(), daemon.proto, daemon.via),
        ("0.4.3", 2, Via::Direct)
    );
    if cfg!(windows) {
        // One `PowerShell` walk of `Win32_Process`, as the fake prints it.
        assert_eq!(
            walk.harness_chain,
            ["claude.exe", "cmd.exe", "explorer.exe"]
        );
    } else {
        assert_eq!(walk.harness_chain, ["zsh", "claude", "launchd"]);
    }
}
