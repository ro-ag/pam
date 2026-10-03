use std::collections::HashSet;

use serde_json::json;

use crate::doctor::{
    DaemonFacts, DoctorReport, EnvFacts, Frontend, INVENTORY, Judgement, MAX_CHAIN_NAMES,
    MAX_PROBES, MAX_REPORT_BYTES, MAX_TEXT_BYTES, MAX_WHY_BYTES, OsError, Platform, Probe,
    ProbeClass, ProbeId, ProbeResult, ProbeState, ReportError, ReportRecord, SCHEMA_VERSION,
    Skipped, TextFault, Verdict, judge,
};
use crate::wire::Via;

fn env() -> EnvFacts {
    EnvFacts {
        socket_dir: None,
        base_dir_override: None,
        resolved_base: "/Users/me/.pam".to_owned(),
        resolved_endpoint: "/Users/me/.pam/run/pam.sock".to_owned(),
        client_version: "0.5.0".to_owned(),
        exe: Some("/Applications/PAM.app/Contents/MacOS/pam".to_owned()),
        cwd_repo: Some("/work/app".to_owned()),
        frontend: Frontend::Embedded,
        harness_chain: vec!["zsh".to_owned(), "claude".to_owned()],
    }
}

fn daemon() -> DaemonFacts {
    DaemonFacts {
        version: "0.5.0".to_owned(),
        proto: 2,
        epoch: "01JB0000000000000000000000".to_owned(),
        via: Via::Direct,
    }
}

fn denied() -> ProbeResult {
    ProbeResult::denied(OsError {
        kind: "PermissionDenied".to_owned(),
        code: Some(1),
        detail: None,
    })
}

fn reach() -> Probe {
    Probe::new(ProbeId::PublicReach, ProbeResult::allowed())
}

/// Every inventory row for `platform`: `public.reach` allowed, each
/// applicable must-deny probe with `must_deny`, info probes allowed, and
/// the rest not probed.
fn rows(platform: Platform, must_deny: &ProbeResult) -> Vec<Probe> {
    ProbeId::all()
        .map(|id| {
            if id.applies_to(platform) {
                match id.class() {
                    ProbeClass::MustAllow | ProbeClass::Info => {
                        Probe::new(id, ProbeResult::allowed())
                    }
                    ProbeClass::MustDeny => Probe::new(id, must_deny.clone()),
                }
            } else {
                Probe::not_applicable(id, platform)
            }
        })
        .collect()
}

fn report(platform: Platform, probes: Vec<Probe>) -> DoctorReport {
    DoctorReport::new(platform, 1_759_400_000, Some(daemon()), probes, env())
}

fn args(report: &DoctorReport) -> serde_json::Value {
    serde_json::to_value(report.as_args()).unwrap()
}

// --- inventory ---------------------------------------------------------

#[test]
fn inventory_rows_are_indexed_by_discriminant_and_unique() {
    let mut names = HashSet::new();
    for (index, row) in INVENTORY.iter().enumerate() {
        assert_eq!(row.id as usize, index, "{}", row.name);
        assert_eq!(row.id.spec(), row);
        assert_eq!(row.id.as_str(), row.name);
        assert_eq!(row.id.class(), row.class);
        assert_eq!(row.id.platforms(), row.platforms);
        assert_eq!(row.id.checks(), row.checks);
        assert!(!row.checks.is_empty(), "{}", row.name);
        assert!(names.insert(row.name), "duplicate name {}", row.name);
        assert!(
            row.name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'.' || byte == b'_'),
            "{} is not a stable id",
            row.name
        );
    }
    assert_eq!(ProbeId::all().count(), INVENTORY.len());
}

#[test]
fn every_id_parses_from_its_name_and_round_trips_serde() {
    for id in ProbeId::all() {
        assert_eq!(id.as_str().parse::<ProbeId>().unwrap(), id);
        assert_eq!(id.to_string(), id.as_str());
        let wire = serde_json::to_value(id).unwrap();
        assert_eq!(wire, json!(id.as_str()));
        assert_eq!(serde_json::from_value::<ProbeId>(wire).unwrap(), id);
    }
    let error = "public.unlink.twice".parse::<ProbeId>().unwrap_err();
    assert_eq!(
        error.to_string(),
        "unknown probe id \"public.unlink.twice\""
    );
    assert!(serde_json::from_value::<ProbeId>(json!("store.delete")).is_err());
    assert!(serde_json::from_value::<ProbeId>(json!(7)).is_err());
}

#[test]
fn public_reach_is_the_only_must_allow_probe() {
    let must_allow: Vec<ProbeId> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustAllow)
        .collect();
    assert_eq!(must_allow, vec![ProbeId::PublicReach]);
    assert_eq!(INVENTORY[0].id, ProbeId::PublicReach);
    assert!(ProbeId::PublicReach.applies_to(Platform::Macos));
    assert!(ProbeId::PublicReach.applies_to(Platform::Windows));
}

#[test]
fn public_unlink_is_never_probed() {
    assert_eq!(ProbeId::PublicUnlink.class(), ProbeClass::MustDeny);
    assert!(ProbeId::PublicUnlink.platforms().is_empty());
    assert!(!ProbeId::PublicUnlink.applies_to(Platform::Macos));
    assert!(!ProbeId::PublicUnlink.applies_to(Platform::Windows));
}

#[test]
fn macos_must_deny_set_is_the_spec_list() {
    let macos: Vec<&str> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && id.applies_to(Platform::Macos))
        .map(ProbeId::as_str)
        .collect();
    assert_eq!(
        macos,
        [
            "run.lock_write",
            "admin.endpoint",
            "admin.endpoint_alias",
            "admin.dir",
            "store.read",
            "store.write",
            "store.wal_read",
            "store.wal_write",
            "store.shm_read",
            "store.shm_write",
            "backup.read",
            "model_trust.read",
            "engine.read",
            "engine.runtime_read",
            "engine.socket",
            "flows.read",
            "log.read",
            "keychain.search",
            "daemon.signal",
            "broker.launchservices",
            "broker.appleevents",
            "exe.write",
            "bundle.write",
        ]
    );
}

#[test]
fn windows_must_deny_set_is_the_spec_list() {
    let windows: Vec<&str> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && id.applies_to(Platform::Windows))
        .map(ProbeId::as_str)
        .collect();
    assert_eq!(
        windows,
        [
            "run.lock_write",
            "admin.control_read",
            "admin.dir",
            "store.read",
            "store.write",
            "store.wal_read",
            "store.wal_write",
            "store.shm_read",
            "store.shm_write",
            "backup.read",
            "model_trust.read",
            "engine.read",
            "engine.runtime_read",
            "flows.read",
            "log.read",
            "keychain.search",
            "daemon.process_query",
            "broker.shellexecute",
            "exe.write",
        ]
    );
    // The macOS-only mechanisms are reported `not_probed` there.
    for id in [
        ProbeId::EngineSocket,
        ProbeId::BundleWrite,
        ProbeId::BrokerLaunchServices,
        ProbeId::BrokerAppleEvents,
        ProbeId::DaemonSignal,
        ProbeId::AdminEndpoint,
        ProbeId::AdminEndpointAlias,
    ] {
        assert!(!id.applies_to(Platform::Windows), "{id}");
    }
}

#[test]
fn the_info_probe_is_the_lock_probe() {
    let info: Vec<ProbeId> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::Info)
        .collect();
    assert_eq!(info, vec![ProbeId::RunLockProbe]);
}

#[test]
fn current_platform_is_supported_here() {
    assert!(Platform::current().is_some());
    assert_eq!(Platform::Macos.to_string(), "macos");
    assert_eq!(Platform::Windows.to_string(), "windows");
}

// --- results -----------------------------------------------------------

#[test]
fn os_error_from_io_keeps_kind_and_code() {
    // EACCES on unix, ERROR_ACCESS_DENIED on Windows.
    let access_denied = if cfg!(windows) { 5 } else { 13 };
    let error = std::io::Error::from_raw_os_error(access_denied);
    let os_error = OsError::from_io(&error);
    assert_eq!(os_error.kind, "PermissionDenied");
    assert_eq!(os_error.code, Some(access_denied));
    assert_eq!(os_error.detail, None);
    let timeout = OsError::of_kind("timeout").with_detail("2 s elapsed");
    assert_eq!(timeout.code, None);
    assert_eq!(timeout.detail.as_deref(), Some("2 s elapsed"));
}

#[test]
fn probe_rows_take_their_class_from_the_inventory() {
    let probe = Probe::new(
        ProbeId::StoreRead,
        denied().with_elapsed_ms(3).with_note("read-only open"),
    );
    assert_eq!(probe.class, ProbeClass::MustDeny);
    assert_eq!(probe.result, ProbeState::Denied);
    assert_eq!(probe.elapsed_ms, Some(3));
    assert_eq!(probe.note.as_deref(), Some("read-only open"));
    assert_eq!(ProbeResult::default().state, ProbeState::Unknown);
    assert_eq!(ProbeResult::allowed().state, ProbeState::Allowed);
    assert_eq!(ProbeResult::absent().state, ProbeState::Absent);
    assert_eq!(
        ProbeResult::unknown("timeout").note.as_deref(),
        Some("timeout")
    );
    let skipped = Probe::not_applicable(ProbeId::EngineSocket, Platform::Windows);
    assert_eq!(skipped.result, ProbeState::NotProbed);
    assert_eq!(skipped.note.as_deref(), Some("not probed on windows"));
    let with_error = ProbeResult::unknown("odd").with_os_error(OsError::of_kind("Other"));
    assert_eq!(with_error.os_error.unwrap().kind, "Other");
}

// --- verdict -----------------------------------------------------------

fn verdict_of(must_deny: ProbeResult) -> Judgement {
    judge(&[reach(), Probe::new(ProbeId::StoreRead, must_deny)])
}

#[test]
fn must_deny_allowed_fails_the_verdict() {
    let judgement = verdict_of(ProbeResult::allowed());
    assert_eq!(judgement.verdict, Verdict::NotEstablished);
    assert_eq!(judgement.failed, vec![ProbeId::StoreRead]);
    assert!(judgement.unverified.is_empty());
    assert!(judgement.skipped.is_empty());
}

#[test]
fn must_deny_denied_establishes() {
    let judgement = verdict_of(denied());
    assert_eq!(judgement.verdict, Verdict::Established);
    assert!(judgement.failed.is_empty());
    assert!(judgement.unverified.is_empty());
    assert!(judgement.skipped.is_empty());
}

#[test]
fn must_deny_absent_is_skipped_not_judged() {
    let judgement = verdict_of(ProbeResult::absent());
    assert_eq!(judgement.verdict, Verdict::Established);
    assert_eq!(
        judgement.skipped,
        vec![Skipped {
            id: ProbeId::StoreRead,
            why: "absent".to_owned()
        }]
    );
}

#[test]
fn must_deny_unknown_is_unverified_and_fails_the_verdict() {
    let judgement = verdict_of(ProbeResult::unknown("timeout"));
    assert_eq!(judgement.verdict, Verdict::NotEstablished);
    assert!(judgement.failed.is_empty());
    assert_eq!(judgement.unverified, vec![ProbeId::StoreRead]);
}

#[test]
fn must_deny_not_probed_is_skipped_with_its_reason() {
    let judgement = verdict_of(ProbeResult::not_probed("side effect"));
    assert_eq!(judgement.verdict, Verdict::Established);
    assert_eq!(
        judgement.skipped,
        vec![Skipped {
            id: ProbeId::StoreRead,
            why: "not_probed: side effect".to_owned()
        }]
    );
    // A note is optional; the state alone is the reason then.
    let bare = judge(&[
        reach(),
        Probe::new(
            ProbeId::StoreRead,
            ProbeResult {
                state: ProbeState::NotProbed,
                ..ProbeResult::default()
            },
        ),
    ]);
    assert_eq!(bare.skipped[0].why, "not_probed");
}

#[test]
fn info_probes_are_never_judged() {
    for state in [
        ProbeState::Allowed,
        ProbeState::Denied,
        ProbeState::Absent,
        ProbeState::Unknown,
        ProbeState::NotProbed,
    ] {
        let judgement = judge(&[
            reach(),
            Probe::new(
                ProbeId::RunLockProbe,
                ProbeResult {
                    state,
                    ..ProbeResult::default()
                },
            ),
        ]);
        assert_eq!(judgement.verdict, Verdict::Established, "{state}");
        assert!(judgement.failed.is_empty(), "{state}");
        assert!(judgement.unverified.is_empty(), "{state}");
        assert!(judgement.skipped.is_empty(), "{state}");
    }
}

#[test]
fn public_reach_not_allowed_cannot_probe() {
    for state in [
        ProbeState::Denied,
        ProbeState::Absent,
        ProbeState::Unknown,
        ProbeState::NotProbed,
    ] {
        let judgement = judge(&[
            Probe::new(
                ProbeId::PublicReach,
                ProbeResult {
                    state,
                    ..ProbeResult::default()
                },
            ),
            Probe::new(ProbeId::StoreRead, denied()),
        ]);
        assert_eq!(judgement.verdict, Verdict::CannotProbe, "{state}");
    }
}

#[test]
fn missing_public_reach_cannot_probe_even_with_every_denial() {
    let judgement = judge(&[Probe::new(ProbeId::StoreRead, denied())]);
    assert_eq!(judgement.verdict, Verdict::CannotProbe);
    assert_eq!(judge(&[]).verdict, Verdict::CannotProbe);
}

#[test]
fn failed_and_unverified_are_separate_and_in_row_order() {
    let judgement = judge(&[
        reach(),
        Probe::new(ProbeId::AdminEndpoint, ProbeResult::allowed()),
        Probe::new(ProbeId::StoreRead, denied()),
        Probe::new(ProbeId::DaemonSignal, ProbeResult::unknown("no pid")),
        Probe::new(ProbeId::BackupRead, ProbeResult::absent()),
        Probe::new(ProbeId::ExeWrite, ProbeResult::allowed()),
    ]);
    assert_eq!(judgement.verdict, Verdict::NotEstablished);
    assert_eq!(
        judgement.failed,
        vec![ProbeId::AdminEndpoint, ProbeId::ExeWrite]
    );
    assert_eq!(judgement.unverified, vec![ProbeId::DaemonSignal]);
    assert_eq!(judgement.skipped.len(), 1);
    assert_eq!(judgement.skipped[0].id, ProbeId::BackupRead);
}

#[test]
fn an_unsandboxed_machine_lists_every_applicable_must_deny_probe() {
    let report = report(
        Platform::Macos,
        rows(Platform::Macos, &ProbeResult::allowed()),
    );
    assert_eq!(report.verdict, Verdict::NotEstablished);
    let expected: Vec<ProbeId> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && id.applies_to(Platform::Macos))
        .collect();
    assert_eq!(report.failed, expected);
    assert!(report.unverified.is_empty());
    // The never-probed and the Windows-only must-deny probes are skipped
    // with the reason; nothing else is.
    let skipped: Vec<Skipped> = ProbeId::all()
        .filter(|id| id.class() == ProbeClass::MustDeny && !id.applies_to(Platform::Macos))
        .map(|id| Skipped {
            id,
            why: "not_probed: not probed on macos".to_owned(),
        })
        .collect();
    assert_eq!(
        skipped.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![
            ProbeId::PublicUnlink,
            ProbeId::AdminControlRead,
            ProbeId::DaemonProcessQuery,
            ProbeId::BrokerShellExecute
        ]
    );
    assert_eq!(report.skipped, skipped);
}

#[test]
fn a_sandboxed_machine_is_established() {
    let report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    assert_eq!(report.verdict, Verdict::Established);
    assert!(report.failed.is_empty());
    assert!(report.unverified.is_empty());
    report.validate().unwrap();
}

// --- document ----------------------------------------------------------

#[test]
fn new_is_consistent_and_as_args_drops_the_record() {
    let mut report = report(
        Platform::Windows,
        rows(Platform::Windows, &ProbeResult::allowed()),
    );
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    report.validate().unwrap();
    report.report = Some(ReportRecord {
        recorded: true,
        request_id: Some("req_01".to_owned()),
        reason: None,
    });
    report.validate().unwrap();
    assert_eq!(report.as_args().report, None);
    assert_eq!(report.as_args().probes, report.probes);
}

#[test]
fn report_round_trips_and_is_accepted_as_args() {
    let report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    let wire = serde_json::to_string(&report).unwrap();
    let back: DoctorReport = serde_json::from_str(&wire).unwrap();
    assert_eq!(back, report);
    assert_eq!(DoctorReport::from_args(&args(&report)).unwrap(), report);
}

#[test]
fn wire_format_is_pinned() {
    let probe = Probe::new(ProbeId::StoreRead, denied().with_elapsed_ms(2));
    assert_eq!(
        serde_json::to_value(&probe).unwrap(),
        json!({
            "id": "store.read",
            "class": "must_deny",
            "result": "denied",
            "os_error": { "kind": "PermissionDenied", "code": 1 },
            "elapsed_ms": 2
        })
    );
    assert_eq!(
        serde_json::to_value(reach()).unwrap(),
        json!({ "id": "public.reach", "class": "must_allow", "result": "allowed" })
    );
    let report = report(
        Platform::Macos,
        vec![
            reach(),
            Probe::new(
                ProbeId::DaemonSignal,
                ProbeResult::unknown("lock file unreadable"),
            ),
            Probe::not_probed(ProbeId::PublicUnlink, "side effect"),
        ],
    );
    let wire = serde_json::to_value(&report).unwrap();
    assert_eq!(wire["schema_version"], json!(1));
    assert_eq!(wire["verdict"], json!("not_established"));
    assert_eq!(wire["platform"], json!("macos"));
    assert_eq!(wire["ts"], json!(1_759_400_000));
    assert_eq!(
        wire["daemon"],
        json!({ "version": "0.5.0", "proto": 2, "epoch": "01JB0000000000000000000000", "via": "direct" })
    );
    assert_eq!(
        wire["probes"][1],
        json!({ "id": "daemon.signal", "class": "must_deny", "result": "unknown", "note": "lock file unreadable" })
    );
    assert_eq!(wire["failed"], json!([]));
    assert_eq!(wire["unverified"], json!(["daemon.signal"]));
    assert_eq!(
        wire["skipped"],
        json!([{ "id": "public.unlink", "why": "not_probed: side effect" }])
    );
    assert_eq!(
        wire["env"],
        json!({
            "socket_dir": null,
            "base_dir_override": null,
            "resolved_base": "/Users/me/.pam",
            "resolved_endpoint": "/Users/me/.pam/run/pam.sock",
            "client_version": "0.5.0",
            "exe": "/Applications/PAM.app/Contents/MacOS/pam",
            "cwd_repo": "/work/app",
            "frontend": "embedded",
            "harness_chain": ["zsh", "claude"]
        })
    );
    assert_eq!(wire["report"], json!(null));
    assert_eq!(
        serde_json::to_value(Verdict::CannotProbe).unwrap(),
        json!("cannot_probe")
    );
    assert_eq!(
        serde_json::to_value(Frontend::DevelopmentServer).unwrap(),
        json!("development_server")
    );
    assert_eq!(
        serde_json::to_value(ProbeState::NotProbed).unwrap(),
        json!("not_probed")
    );
}

#[test]
fn a_full_report_with_errors_on_every_row_fits_the_bound() {
    let long_path = format!("/Users/{}/.pam", "n".repeat(120));
    let mut env = env();
    env.resolved_base.clone_from(&long_path);
    env.resolved_endpoint = format!("{long_path}/run/pam.sock");
    env.exe = Some(format!(
        "{long_path}/../Applications/PAM.app/Contents/MacOS/pam"
    ));
    env.harness_chain = (0..10).map(|i| format!("harness-process-{i}")).collect();
    let probes = rows(
        Platform::Macos,
        &denied()
            .with_elapsed_ms(1_999)
            .with_note("Operation not permitted; the sandbox refused the open"),
    );
    let mut report = DoctorReport::new(Platform::Macos, u64::MAX, Some(daemon()), probes, env);
    report.report = Some(ReportRecord {
        recorded: false,
        request_id: None,
        reason: Some("the daemon refused the report: request_capacity_exhausted".to_owned()),
    });
    let bytes = serde_json::to_vec(&report).unwrap();
    assert!(
        bytes.len() <= MAX_REPORT_BYTES / 2,
        "{} bytes leaves too little headroom under {MAX_REPORT_BYTES}",
        bytes.len()
    );
    report.validate().unwrap();
}

// --- refusals ----------------------------------------------------------

#[test]
fn refuses_an_oversized_document_before_parsing() {
    let note = "n".repeat(MAX_TEXT_BYTES);
    let probes: Vec<Probe> = (0..MAX_PROBES)
        .map(|_| Probe::new(ProbeId::StoreRead, denied().with_note(note.clone())))
        .collect();
    let report = report(Platform::Macos, probes);
    let error = DoctorReport::from_args(&args(&report)).unwrap_err();
    assert!(
        matches!(error, ReportError::TooLarge { bytes } if bytes > MAX_REPORT_BYTES),
        "{error}"
    );
}

#[test]
fn refuses_unknown_members_anywhere() {
    let report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    let mut top = args(&report);
    top["from_the_future"] = json!(true);
    assert!(matches!(
        DoctorReport::from_args(&top).unwrap_err(),
        ReportError::Json(_)
    ));
    let mut row = args(&report);
    row["probes"][0]["payload"] = json!("x");
    assert!(matches!(
        DoctorReport::from_args(&row).unwrap_err(),
        ReportError::Json(_)
    ));
    let mut env = args(&report);
    env["env"]["home"] = json!("/Users/me");
    assert!(matches!(
        DoctorReport::from_args(&env).unwrap_err(),
        ReportError::Json(_)
    ));
    let mut id = args(&report);
    id["probes"][0]["id"] = json!("public.anything");
    let error = DoctorReport::from_args(&id).unwrap_err();
    assert!(
        matches!(&error, ReportError::Json(detail) if detail.contains("unknown probe id")),
        "{error}"
    );
}

#[test]
fn refuses_control_characters_and_overlong_strings() {
    let mut report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    report.probes[1].note = Some("line\nbreak".to_owned());
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "probes[].note",
            fault: TextFault::ControlCharacter
        }
    );
    report.probes[1].note = Some("x".repeat(MAX_TEXT_BYTES + 1));
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "probes[].note",
            fault: TextFault::TooLong {
                bytes: MAX_TEXT_BYTES + 1,
                max: MAX_TEXT_BYTES
            }
        }
    );
    report.probes[1].note = None;
    report.env.exe = Some("/tmp/\u{7f}pam".to_owned());
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "env.exe",
            fault: TextFault::ControlCharacter
        }
    ));
    report.env.exe = None;
    report.env.harness_chain = vec!["tab\there".to_owned()];
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "env.harness_chain[]",
            ..
        }
    ));
    report.env.harness_chain = (0..=MAX_CHAIN_NAMES).map(|i| i.to_string()).collect();
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::TooManyChainNames(MAX_CHAIN_NAMES + 1)
    );
    report.env.harness_chain.clear();
    report.daemon.as_mut().unwrap().epoch = "01JB\u{1b}[0m".to_owned();
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "daemon.epoch",
            ..
        }
    ));
    report.daemon = None;
    report.report = Some(ReportRecord {
        recorded: false,
        request_id: None,
        reason: Some("\u{0}".to_owned()),
    });
    assert!(matches!(
        report.validate().unwrap_err(),
        ReportError::Text {
            field: "report.reason",
            ..
        }
    ));
}

#[test]
fn a_skipped_reason_at_the_note_bound_still_validates() {
    let reason = "r".repeat(MAX_TEXT_BYTES);
    let report = report(
        Platform::Macos,
        vec![reach(), Probe::not_probed(ProbeId::StoreRead, reason)],
    );
    assert!(report.skipped[0].why.len() <= MAX_WHY_BYTES);
    report.validate().unwrap();
}

#[test]
fn refuses_the_wrong_schema_version() {
    let mut report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    report.schema_version = 2;
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::SchemaVersion(2)
    );
}

#[test]
fn refuses_too_many_rows_and_duplicates() {
    let probes: Vec<Probe> = (0..=MAX_PROBES)
        .map(|_| Probe::new(ProbeId::StoreRead, denied()))
        .collect();
    let report = report(Platform::Macos, probes);
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::TooManyProbes(MAX_PROBES + 1)
    );
    let twice = self::report(
        Platform::Macos,
        vec![
            reach(),
            Probe::new(ProbeId::StoreRead, denied()),
            Probe::new(ProbeId::StoreRead, ProbeResult::allowed()),
        ],
    );
    assert_eq!(
        twice.validate().unwrap_err(),
        ReportError::DuplicateProbe(ProbeId::StoreRead)
    );
}

#[test]
fn refuses_a_row_whose_class_or_platform_disagrees_with_the_inventory() {
    let mut report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    let lock_write = report
        .probes
        .iter()
        .position(|probe| probe.id == ProbeId::RunLockWrite)
        .unwrap();
    report.probes[lock_write].class = ProbeClass::Info;
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::ClassMismatch {
            id: ProbeId::RunLockWrite,
            class: ProbeClass::Info
        }
    );
    // A Windows-only probe cannot carry a result in a macOS report.
    let foreign = self::report(
        Platform::Macos,
        vec![reach(), Probe::new(ProbeId::AdminControlRead, denied())],
    );
    assert_eq!(
        foreign.validate().unwrap_err(),
        ReportError::NotApplicable {
            id: ProbeId::AdminControlRead,
            platform: Platform::Macos
        }
    );
    // Nor can the never-probed one, anywhere.
    let unlink = self::report(
        Platform::Windows,
        vec![reach(), Probe::new(ProbeId::PublicUnlink, denied())],
    );
    assert!(matches!(
        unlink.validate().unwrap_err(),
        ReportError::NotApplicable {
            id: ProbeId::PublicUnlink,
            ..
        }
    ));
}

#[test]
fn refuses_a_verdict_or_list_the_rows_do_not_compute() {
    let honest = report(
        Platform::Macos,
        rows(Platform::Macos, &ProbeResult::allowed()),
    );
    let mut claimed = honest.clone();
    claimed.verdict = Verdict::Established;
    assert_eq!(
        claimed.validate().unwrap_err(),
        ReportError::Inconsistent { field: "verdict" }
    );
    let mut trimmed = honest.clone();
    trimmed.failed.pop();
    assert_eq!(
        trimmed.validate().unwrap_err(),
        ReportError::Inconsistent { field: "failed" }
    );
    let mut padded = honest.clone();
    padded.unverified.push(ProbeId::StoreRead);
    assert_eq!(
        padded.validate().unwrap_err(),
        ReportError::Inconsistent {
            field: "unverified"
        }
    );
    let mut reworded = honest;
    reworded.skipped[0].why = "absent".to_owned();
    assert_eq!(
        reworded.validate().unwrap_err(),
        ReportError::Inconsistent { field: "skipped" }
    );
}

#[test]
fn refuses_overlong_lists_before_comparing_them() {
    let mut report = report(Platform::Macos, rows(Platform::Macos, &denied()));
    report.failed = vec![ProbeId::StoreRead; MAX_PROBES + 1];
    assert_eq!(
        report.validate().unwrap_err(),
        ReportError::TooManyListed {
            field: "failed",
            count: MAX_PROBES + 1
        }
    );
}

#[test]
fn the_daemon_does_not_record_a_cannot_probe_report() {
    let report = DoctorReport::new(
        Platform::Macos,
        1,
        None,
        vec![Probe::new(
            ProbeId::PublicReach,
            ProbeResult::unknown("timeout"),
        )],
        env(),
    );
    assert_eq!(report.verdict, Verdict::CannotProbe);
    report.validate().unwrap();
    assert_eq!(
        DoctorReport::from_args(&args(&report)).unwrap_err(),
        ReportError::NotRecordable(Verdict::CannotProbe)
    );
}

#[test]
fn refusals_name_their_cause() {
    for error in [
        ReportError::TooLarge { bytes: 20_000 },
        ReportError::Json("bad".to_owned()),
        ReportError::SchemaVersion(9),
        ReportError::TooManyProbes(65),
        ReportError::DuplicateProbe(ProbeId::StoreRead),
        ReportError::ClassMismatch {
            id: ProbeId::StoreRead,
            class: ProbeClass::Info,
        },
        ReportError::NotApplicable {
            id: ProbeId::EngineSocket,
            platform: Platform::Windows,
        },
        ReportError::Text {
            field: "env.exe",
            fault: TextFault::TooLong {
                bytes: 2000,
                max: 1024,
            },
        },
        ReportError::Text {
            field: "env.exe",
            fault: TextFault::ControlCharacter,
        },
        ReportError::TooManyListed {
            field: "failed",
            count: 65,
        },
        ReportError::TooManyChainNames(17),
        ReportError::Inconsistent { field: "verdict" },
        ReportError::NotRecordable(Verdict::CannotProbe),
    ] {
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(!message.contains('\n'), "{message}");
    }
    assert_eq!(
        ReportError::ClassMismatch {
            id: ProbeId::StoreRead,
            class: ProbeClass::Info
        }
        .to_string(),
        "probe store.read claims class info; the inventory says must_deny"
    );
}
