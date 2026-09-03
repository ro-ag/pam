use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pam_flow::{ArgValue, ConnectorId};
use url::Url;

use crate::aws::{
    ALLOWED, FORBIDDEN_FLAGS, MAX_ARG_BYTES, MAX_EXTRA_ARGS, argv, aws_binary,
    clear_binary_for_tests, set_binary_for_tests,
};
use crate::testing::FakeTransport;
use crate::transport::{AWS_BASE_URL, Connection};
use crate::{CallResult, ConnectorError, call, verify};

// ---------------------------------------------------------------- allowlist

#[test]
fn the_allowlist_is_the_reviewed_pair_list() {
    // The spec's prose says "25"; the table it lists holds 26 pairs, and the
    // table is the reviewed artefact. Every entry is exact — no prefix
    // heuristic, which would admit `ecr get-login-password` and `s3 presign`.
    assert_eq!(ALLOWED.len(), 26);
    for (service, command) in ALLOWED {
        assert!(!service.is_empty() && !command.is_empty());
    }
    let mut seen: Vec<(&str, &str)> = ALLOWED.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), ALLOWED.len(), "the allowlist repeats a pair");

    for expected in [
        ("sts", "get-caller-identity"),
        ("ec2", "describe-instances"),
        ("s3api", "list-objects-v2"),
        ("iam", "list-attached-role-policies"),
        ("cloudformation", "describe-stack-events"),
        ("lambda", "get-function-configuration"),
        ("logs", "filter-log-events"),
        ("ecs", "describe-services"),
        ("rds", "describe-db-instances"),
        ("cloudwatch", "get-metric-data"),
    ] {
        assert!(ALLOWED.contains(&expected), "{expected:?} is missing");
    }
}

#[test]
fn commands_outside_the_allowlist_are_refused() {
    for (service, command) in [
        ("ecr", "get-login-password"),
        ("s3", "presign"),
        ("ec2", "terminate-instances"),
        ("sts", "assume-role"),
        ("iam", "list-users-x"),
    ] {
        let error = argv(service, command, &[], None).unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{service} {command}");
        assert!(error.detail().contains("allowlist"), "{error:?}");
    }
}

#[test]
fn the_argument_vector_puts_pams_own_flags_last() {
    let line = argv(
        "logs",
        "filter-log-events",
        &["--log-group-name".to_owned(), "/pam/daemon".to_owned()],
        Some("build"),
    )
    .unwrap();
    assert_eq!(
        line,
        vec![
            "logs",
            "filter-log-events",
            "--log-group-name",
            "/pam/daemon",
            "--profile",
            "build",
            "--output",
            "json",
            "--no-cli-pager",
        ]
    );
}

#[test]
fn without_a_profile_no_profile_flag_appears() {
    let line = argv("sts", "get-caller-identity", &[], None).unwrap();
    assert_eq!(
        line,
        vec![
            "sts",
            "get-caller-identity",
            "--output",
            "json",
            "--no-cli-pager"
        ]
    );
}

#[test]
fn the_flags_pam_owns_may_not_come_from_a_step() {
    for flag in FORBIDDEN_FLAGS {
        for spelling in [(*flag).to_owned(), format!("{flag}=x"), flag.to_uppercase()] {
            let error = argv(
                "sts",
                "get-caller-identity",
                std::slice::from_ref(&spelling),
                None,
            )
            .unwrap_err();
            assert_eq!(error.cause(), "connector_bad_args", "{spelling}");
        }
    }
}

#[test]
fn file_urls_are_refused_anywhere_in_an_argument() {
    for arg in [
        "file:///etc/passwd",
        "fileb:///etc/passwd",
        "--cli-body=FILE://x",
        "prefixfile://y",
    ] {
        let error = argv("sts", "get-caller-identity", &[arg.to_owned()], None).unwrap_err();
        assert_eq!(error.cause(), "connector_bad_args", "{arg}");
    }
}

#[test]
fn arguments_are_bounded_and_printable() {
    let too_many: Vec<String> = (0..=MAX_EXTRA_ARGS).map(|n| n.to_string()).collect();
    assert!(argv("sts", "get-caller-identity", &too_many, None).is_err());

    let too_long = vec!["x".repeat(MAX_ARG_BYTES + 1)];
    assert!(argv("sts", "get-caller-identity", &too_long, None).is_err());

    for bad in ["", "new\nline", "nul\0byte", "back\\slash", "semi;colon"] {
        assert!(
            argv("sts", "get-caller-identity", &[bad.to_owned()], None).is_err(),
            "{bad:?} was accepted"
        );
    }

    let fine = vec![
        "--query".to_owned(),
        "Reservations[*].Instances[?State.Name=='running'].InstanceId".to_owned(),
    ];
    assert!(argv("ec2", "describe-instances", &fine, None).is_ok());
}

#[test]
fn a_profile_must_look_like_a_profile_name() {
    for profile in ["", "-evil", "has space", "a/b", &"x".repeat(65)] {
        assert!(
            argv("sts", "get-caller-identity", &[], Some(profile)).is_err(),
            "{profile:?} was accepted"
        );
    }
    for profile in ["default", "build-ro", "team.read_only", "a"] {
        assert!(
            argv("sts", "get-caller-identity", &[], Some(profile)).is_ok(),
            "{profile} was refused"
        );
    }
}

#[tokio::test]
async fn commands_answers_with_the_allowlist_and_spawns_nothing() {
    let result = call(
        ConnectorId::Aws,
        &connection(None),
        "commands",
        &BTreeMap::new(),
        &FakeTransport::new(),
        deadline(),
    )
    .await
    .unwrap();
    let CallResult::Json(value) = result else {
        panic!("commands answers with JSON");
    };
    let listed = value["commands"].as_array().unwrap();
    assert_eq!(listed.len(), ALLOWED.len());
    assert_eq!(listed[0]["service"], "sts");
    assert_eq!(listed[0]["command"], "get-caller-identity");
}

#[tokio::test]
async fn an_unknown_call_names_what_aws_offers() {
    let error = cli(&connection(None), &BTreeMap::new(), "invoke")
        .await
        .unwrap_err();
    assert!(error.detail().contains("commands"), "{error:?}");
}

#[tokio::test]
async fn a_missing_binary_is_a_cli_missing_refusal() {
    set_binary_for_tests(PathBuf::from("/nonexistent/pam-test/aws"));
    let error = cli(
        &connection(None),
        &cli_args("sts", "get-caller-identity", None),
        "cli",
    )
    .await
    .unwrap_err();
    clear_binary_for_tests();
    assert_eq!(error, ConnectorError::CliMissing);
}

#[test]
fn the_binary_lookup_can_be_pointed_somewhere_else() {
    let before = aws_binary();
    set_binary_for_tests(PathBuf::from("/tmp/pam-fake-aws"));
    assert_eq!(aws_binary(), Some(PathBuf::from("/tmp/pam-fake-aws")));
    clear_binary_for_tests();
    assert_eq!(aws_binary(), before);
}

// ------------------------------------------------------------------- spawns

#[tokio::test]
async fn cli_runs_the_binary_and_parses_its_json() {
    let Some(dir) = fake_aws(r#"printf '%s' '{"Buckets":[{"Name":"pam-evidence"}]}'"#) else {
        return;
    };
    let result = cli(
        &connection(Some("build")),
        &cli_args("s3api", "list-buckets", Some("--max-items 1")),
        "cli",
    )
    .await
    .unwrap();
    let recorded = std::fs::read_to_string(dir.path().join("argv.txt")).unwrap();
    clear_binary_for_tests();

    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        vec![
            "s3api",
            "list-buckets",
            "--max-items",
            "1",
            "--profile",
            "build",
            "--output",
            "json",
            "--no-cli-pager",
        ]
    );
    let CallResult::Json(value) = result else {
        panic!("cli answers with JSON");
    };
    assert_eq!(value["service"], "s3api");
    assert_eq!(value["partial"], false);
    assert_eq!(value["exit_status"], 0);
    assert_eq!(value["output"]["Buckets"][0]["Name"], "pam-evidence");
    assert!(value["text"].is_null());
}

#[tokio::test]
async fn a_non_zero_exit_becomes_a_cli_refusal_carrying_the_stderr() {
    let Some(_dir) = fake_aws(r"printf '%s' 'An error occurred (AccessDenied)' >&2; exit 254")
    else {
        return;
    };
    let error = cli(
        &connection(None),
        &cli_args("iam", "list-users", None),
        "cli",
    )
    .await
    .unwrap_err();
    clear_binary_for_tests();
    assert_eq!(error.cause(), "connector_cli");
    assert!(error.detail().contains("AccessDenied"), "{error:?}");
    assert!(error.detail().contains("254"), "{error:?}");
}

#[tokio::test]
async fn output_over_the_cap_comes_back_as_partial_text() {
    let Some(_dir) = fake_aws(r#"awk 'BEGIN{for(i=0;i<30000;i++) printf "0123456789"}'"#) else {
        return;
    };
    let result = cli(
        &connection(None),
        &cli_args("ec2", "describe-instances", None),
        "cli",
    )
    .await
    .unwrap();
    clear_binary_for_tests();
    let CallResult::Json(value) = result else {
        panic!("cli answers with JSON");
    };
    assert_eq!(value["partial"], true);
    assert!(value["output"].is_null());
    assert!(value["text"].as_str().unwrap().len() >= 256 * 1024);
}

#[tokio::test]
async fn verify_reports_the_account_and_the_arn() {
    let Some(_dir) = fake_aws(
        r#"printf '%s' '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ada","UserId":"A"}'"#,
    ) else {
        return;
    };
    let report = verify(
        ConnectorId::Aws,
        &connection(None),
        &FakeTransport::new(),
        deadline(),
    )
    .await
    .unwrap();
    clear_binary_for_tests();
    assert_eq!(
        report.detail,
        "account 123456789012 arn arn:aws:iam::123456789012:user/ada"
    );
}

#[tokio::test]
async fn verify_treats_a_non_zero_exit_as_a_credential_problem() {
    let Some(_dir) = fake_aws(r"printf '%s' 'Unable to locate credentials' >&2; exit 255") else {
        return;
    };
    let error = verify(
        ConnectorId::Aws,
        &connection(None),
        &FakeTransport::new(),
        deadline(),
    )
    .await
    .unwrap_err();
    clear_binary_for_tests();
    assert_eq!(error, ConnectorError::Auth);
}

#[tokio::test]
async fn verify_refuses_an_identity_without_an_account_or_an_arn() {
    let Some(_dir) = fake_aws(r#"printf '%s' '{"UserId":"A"}'"#) else {
        return;
    };
    let error = verify(
        ConnectorId::Aws,
        &connection(None),
        &FakeTransport::new(),
        deadline(),
    )
    .await
    .unwrap_err();
    clear_binary_for_tests();
    assert_eq!(error.cause(), "connector_bad_response");
}

// ------------------------------------------------------------------ helpers

/// Writes a stand-in `aws` and points the module at it.
///
/// Answers `None` on Windows, where a `#!/bin/sh` script is not executable;
/// the argument-vector and allowlist tests above cover the same ground
/// without spawning anything.
fn fake_aws(body: &str) -> Option<tempfile::TempDir> {
    if cfg!(windows) {
        eprintln!("fake `aws` scripts need a POSIX shell; skipping the spawn test on Windows");
        return None;
    }
    let dir = tempfile::tempdir().expect("a temporary directory");
    let script = dir.path().join("aws");
    let argv_path = dir.path().join("argv.txt");
    let source = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n{body}\n",
        argv_path.display()
    );
    std::fs::write(&script, source).expect("the fake aws is written");
    make_executable(&script);
    set_binary_for_tests(script);
    Some(dir)
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the fake aws is executable");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

async fn cli(
    conn: &Connection,
    args: &BTreeMap<String, ArgValue>,
    name: &str,
) -> Result<CallResult, ConnectorError> {
    call(
        ConnectorId::Aws,
        conn,
        name,
        args,
        &FakeTransport::new(),
        deadline(),
    )
    .await
}

fn cli_args(service: &str, command: &str, extra: Option<&str>) -> BTreeMap<String, ArgValue> {
    let mut args = BTreeMap::new();
    args.insert("service".to_owned(), ArgValue::Text(service.to_owned()));
    args.insert("command".to_owned(), ArgValue::Text(command.to_owned()));
    if let Some(extra) = extra {
        args.insert("args".to_owned(), ArgValue::Text(extra.to_owned()));
    }
    args
}

fn connection(profile: Option<&str>) -> Connection {
    Connection {
        base_url: Url::parse(AWS_BASE_URL).expect("the placeholder URL parses"),
        username: profile.map(str::to_owned),
        secret: None,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
