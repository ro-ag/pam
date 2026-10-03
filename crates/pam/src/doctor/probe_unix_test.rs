//! The unix executable and bundle rows: asked through `/bin/test`
//! (`access(2)`), never through an open — the calls made, against the
//! fake; the classification, against the real OS and real files.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pam_proto::doctor::{Platform, ProbeId, ProbeResult, ProbeState};

use super::Options;
use super::classify::ACCESS_REFUSED_NOTE;
use super::inventory::{Context, Outcome};
use super::os::RealOs;
use super::os_test::{FakeOs, HelperMood};
use super::probe_unix::{TEST, access_write, plan};

const BASE: &str = "/tmp/pamdoc-base";

fn context(os: FakeOs) -> (Context, Arc<FakeOs>) {
    let os = Arc::new(os);
    let dynamic: Arc<dyn super::os::Os> = os.clone();
    let context = Context::new(
        Platform::current().unwrap(),
        &Options::new(PathBuf::from(BASE)),
        dynamic,
    )
    .unwrap();
    (context, os)
}

fn run(context: &Context, id: ProbeId) -> Outcome {
    let planned = plan(id, context).unwrap_or_else(|| panic!("{id} has no unix plan"));
    assert_eq!(planned.id, id);
    (planned.op)()
}

#[test]
fn the_executable_is_asked_through_access_and_never_opened() {
    let (context, os) = self::context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result, ProbeResult::allowed());
    assert_eq!(os.calls(), [format!("helper {TEST} -w /usr/local/bin/pam")]);

    // Refused: a second question tells the refusal from a missing path.
    let (context, os) = self::context(FakeOs::sandboxed());
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Denied);
    assert_eq!(outcome.result.note.as_deref(), Some(ACCESS_REFUSED_NOTE));
    assert_eq!(outcome.result.os_error.unwrap().kind, "PermissionDenied");
    assert_eq!(
        os.calls(),
        [
            format!("helper {TEST} -w /usr/local/bin/pam"),
            format!("helper {TEST} -e /usr/local/bin/pam"),
        ]
    );
}

#[test]
fn the_bundle_is_asked_the_same_way_and_is_absent_outside_one() {
    let mut fake = FakeOs::sandboxed();
    fake.exe = Some(PathBuf::from("/Applications/PAM.app/Contents/MacOS/pam"));
    let (context, os) = self::context(fake);
    let outcome = run(&context, ProbeId::BundleWrite);
    assert_eq!(outcome.result.state, ProbeState::Denied);
    assert_eq!(
        os.calls(),
        [
            format!("helper {TEST} -w /Applications/PAM.app/Contents/Info.plist"),
            format!("helper {TEST} -e /Applications/PAM.app/Contents/Info.plist"),
        ]
    );
    let (context, os) = self::context(FakeOs::unsandboxed());
    let outcome = run(&context, ProbeId::BundleWrite);
    assert_eq!(outcome.result.state, ProbeState::Absent);
    assert_eq!(
        outcome.result.note.as_deref(),
        Some("not inside an application bundle")
    );
    assert!(os.calls().is_empty(), "no helper runs outside a bundle");
}

#[test]
fn a_helper_that_cannot_answer_leaves_the_row_unknown() {
    let mut fake = FakeOs::unsandboxed();
    fake.helper_mood = HelperMood::Missing;
    let (context, _) = self::context(fake);
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Unknown);
    assert_eq!(outcome.result.note.as_deref(), Some("spawn: NotFound"));

    let mut fake = FakeOs::unsandboxed();
    fake.helper_mood = HelperMood::Gibberish;
    let (context, _) = self::context(fake);
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Unknown);
    assert!(
        outcome
            .result
            .note
            .as_deref()
            .unwrap()
            .starts_with("unrecognised test output (exit 7)")
    );

    let mut fake = FakeOs::unsandboxed();
    fake.exe = None;
    let (context, os) = self::context(fake);
    let outcome = run(&context, ProbeId::ExeWrite);
    assert_eq!(outcome.result.state, ProbeState::Unknown);
    assert!(outcome.result.note.unwrap().starts_with("current_exe:"));
    assert!(
        os.calls().is_empty(),
        "no helper runs without an executable"
    );
}

#[test]
fn the_real_helper_answers_for_a_writable_a_read_only_and_a_missing_file() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let plist = tmp.path().join("Info.plist");
    std::fs::write(&plist, b"<plist/>").unwrap();
    let bound = Duration::from_secs(5);
    let before = std::fs::metadata(&plist).unwrap();
    assert_eq!(access_write(&RealOs, &plist, bound), ProbeResult::allowed());
    std::fs::set_permissions(&plist, PermissionsExt::from_mode(0o444)).unwrap();
    let denied = access_write(&RealOs, &plist, bound);
    assert_eq!(denied.state, ProbeState::Denied);
    assert_eq!(denied.note.as_deref(), Some(ACCESS_REFUSED_NOTE));
    assert_eq!(
        access_write(&RealOs, &tmp.path().join("absent.plist"), bound),
        ProbeResult::absent()
    );
    // Asked, never touched.
    let after = std::fs::metadata(&plist).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(std::fs::read(&plist).unwrap(), b"<plist/>");
}
