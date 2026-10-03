use std::fmt::Write as _;
use std::time::Duration;

use super::duration::format_duration;
use super::input_type::InputType;
use super::schema::{Action, Approval, ConnectorId, Effect, Flow, OutputPolicy, Role, When};
use super::validate::{
    FlowError, MAX_FILE_BYTES, connector_calls, is_sensitive_arg, is_shell, looks_secret_like,
    parse, parse_value,
};

/// Wraps step YAML in the smallest valid flow around it.
fn wrap(steps: &str) -> String {
    format!("schema: 1\nid: demo\nname: Demo\nsteps:\n{steps}")
}

fn good(yaml: &str) -> Flow {
    parse(yaml).expect("flow should be valid")
}

fn bad(yaml: &str) -> (String, String) {
    match parse(yaml).expect_err("flow should be invalid") {
        FlowError::Invalid { path, message } => (path, message),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

fn bad_step(steps: &str) -> (String, String) {
    bad(&wrap(steps))
}

#[test]
fn a_minimal_flow_resolves_every_default() {
    let flow = good(&wrap("  - id: status\n    run: [git, status]\n"));
    assert_eq!(flow.id, "demo");
    assert_eq!(flow.name, "Demo");
    assert!(flow.description.is_empty());
    assert!(flow.inputs.is_empty());
    let step = &flow.steps[0];
    assert_eq!(
        step.action,
        Action::Command {
            argv: vec!["git".to_string(), "status".to_string()]
        }
    );
    assert_eq!(step.timeout, Duration::from_mins(5));
    assert_eq!(step.effect, Effect::ReadOnly);
    assert_eq!(step.role, Role::Observe);
    assert_eq!(step.output, OutputPolicy::Compact);
    assert_eq!(step.when, When::NeedsSucceeded);
    assert_eq!(step.approval, Approval::None);
    assert_eq!(step.retry.attempts, 1);
    assert!(step.needs.is_empty());
    assert!(step.env.is_empty());
}

#[test]
fn the_schema_version_must_be_one() {
    let (path, message) =
        bad("schema: 2\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [git]\n");
    assert_eq!(path, "schema");
    assert!(message.contains('1'), "{message}");
}

#[test]
fn the_flow_id_follows_the_id_rules() {
    for id in ["Demo", "de mo", "de_mo", "", "déjà"] {
        let (path, message) = bad(&format!(
            "schema: 1\nid: {id}\nname: Demo\nsteps:\n  - id: a\n    run: [git]\n"
        ));
        assert_eq!(path, "id", "{id}: {message}");
    }
    let long = "a".repeat(65);
    let (path, _) = bad(&format!(
        "schema: 1\nid: {long}\nname: Demo\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "id");
}

#[test]
fn the_name_is_required_and_bounded() {
    let (path, _) = bad("schema: 1\nid: demo\nname: ''\nsteps:\n  - id: a\n    run: [git]\n");
    assert_eq!(path, "name");
    let long = "n".repeat(121);
    let (path, message) = bad(&format!(
        "schema: 1\nid: demo\nname: {long}\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "name");
    assert!(message.contains("120"), "{message}");
}

#[test]
fn the_description_is_bounded() {
    let long = "d".repeat(2049);
    let (path, message) = bad(&format!(
        "schema: 1\nid: demo\nname: Demo\ndescription: {long}\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "description");
    assert!(message.contains("2048"), "{message}");
}

#[test]
fn a_step_note_is_optional_trimmed_and_bounded() {
    let flow = good(&wrap("  - id: a\n    run: [git]\n"));
    assert!(flow.steps[0].note.is_empty(), "no key means no note");

    let flow = good(&wrap(
        "  - id: a\n    run: [git]\n    note: \"  \\n\\t \"\n",
    ));
    assert!(flow.steps[0].note.is_empty(), "whitespace alone is no note");

    let flow = good(&wrap(
        "  - id: a\n    run: [git]\n    note: |\n      Why this runs first.\n      Keep it short.\n",
    ));
    assert_eq!(flow.steps[0].note, "Why this runs first.\nKeep it short.");

    let flow = good(&wrap(
        "  - id: a\n    connector: jenkins\n    call: jobs\n    note: connector steps carry notes too\n",
    ));
    assert_eq!(flow.steps[0].note, "connector steps carry notes too");

    let long = "n".repeat(2049);
    let (path, message) = bad_step(&format!("  - id: a\n    run: [git]\n    note: {long}\n"));
    assert_eq!(path, "steps[0].note");
    assert!(message.contains("2048"), "{message}");
}

#[test]
fn a_flow_needs_at_least_one_step_and_at_most_sixty_four() {
    let (path, _) = bad("schema: 1\nid: demo\nname: Demo\nsteps: []\n");
    assert_eq!(path, "steps");

    let mut steps = String::new();
    for n in 0..65 {
        write!(steps, "  - id: s{n}\n    run: [git]\n").expect("write to a String");
    }
    let (path, message) = bad(&wrap(&steps));
    assert_eq!(path, "steps");
    assert!(message.contains("64"), "{message}");
}

#[test]
fn inputs_are_named_bounded_and_may_only_reference_the_repo() {
    let mut inputs = String::new();
    for n in 0..17 {
        write!(inputs, "  in{n}:\n    description: x\n").expect("write to a String");
    }
    let (path, message) = bad(&format!(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n{inputs}steps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "inputs");
    assert!(message.contains("16"), "{message}");

    let (path, _) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  Repo:\n    description: x\nsteps:\n  - id: a\n    run: [git]\n",
    );
    assert_eq!(path, "inputs.Repo");

    let (path, message) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  repo:\n    description: x\n    default: '${steps.a.exit_status}'\nsteps:\n  - id: a\n    run: [git]\n",
    );
    assert_eq!(path, "inputs.repo.default");
    assert!(message.contains("steps.a.exit_status"), "{message}");

    let flow = good(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  repo:\n    description: owner/name\n    default: '${repo.origin}'\nsteps:\n  - id: a\n    run: [git, log, '${inputs.repo}']\n",
    );
    assert_eq!(
        flow.inputs["repo"].default.as_deref(),
        Some("${repo.origin}")
    );
}

#[test]
fn step_ids_follow_the_id_rules_and_are_unique() {
    let (path, _) = bad_step("  - id: Status\n    run: [git]\n");
    assert_eq!(path, "steps[0].id");

    let (path, message) = bad_step("  - id: a\n    run: [git]\n  - id: a\n    run: [git]\n");
    assert_eq!(path, "steps[1].id");
    assert!(
        message.contains("duplicate") || message.contains("already"),
        "{message}"
    );
}

#[test]
fn a_step_is_a_command_or_a_connector_call_but_never_both_or_neither() {
    let (path, message) = bad_step(
        "  - id: a\n    run: [git]\n    connector: github\n    call: runs\n    with: { repo: x/y }\n",
    );
    assert_eq!(path, "steps[0]");
    assert!(message.contains("run"), "{message}");

    let (path, _) = bad_step("  - id: a\n    timeout: 10s\n");
    assert_eq!(path, "steps[0]");

    let (path, _) = bad_step("  - id: a\n    run: [git]\n    call: runs\n");
    assert_eq!(path, "steps[0].call");

    let (path, _) = bad_step("  - id: a\n    run: [git]\n    with: { repo: x }\n");
    assert_eq!(path, "steps[0].with");

    let (path, _) = bad_step(
        "  - id: a\n    connector: github\n    call: runs\n    with: { repo: x/y }\n    env: { A: b }\n",
    );
    assert_eq!(path, "steps[0].env");
}

#[test]
fn an_empty_argv_is_rejected() {
    let (path, _) = bad_step("  - id: a\n    run: []\n");
    assert_eq!(path, "steps[0].run");
}

#[test]
fn the_program_is_a_bare_name() {
    for program in ["/usr/bin/git", "./git", "..", "-git", "sub/git"] {
        let (path, _) = bad_step(&format!("  - id: a\n    run: ['{program}']\n"));
        assert_eq!(path, "steps[0].run[0]", "{program}");
    }
    let (path, _) = bad_step("  - id: a\n    run: ['C:\\tools\\git.exe']\n");
    assert_eq!(path, "steps[0].run[0]");
}

#[test]
fn shells_are_refused_at_validation() {
    for program in [
        "sh", "bash", "CMD.EXE", "cmd", "pwsh", "sudo", "env", "xargs", "Doas",
    ] {
        let (path, message) = bad_step(&format!("  - id: a\n    run: ['{program}', '-c', 'x']\n"));
        assert_eq!(path, "steps[0].run[0]", "{program}");
        assert!(
            message.contains("shell") || message.contains("refused"),
            "{message}"
        );
    }
    assert!(is_shell("bash"));
    assert!(is_shell("CMD.EXE"));
    assert!(is_shell("powershell.exe"));
    assert!(!is_shell("git"));
    assert!(!is_shell("bashful"));
}

#[test]
fn argument_bounds_are_enforced() {
    let mut many = String::new();
    for n in 0..65 {
        write!(many, ", 'a{n}'").expect("write to a String");
    }
    let (path, message) = bad_step(&format!("  - id: a\n    run: [git{many}]\n"));
    assert_eq!(path, "steps[0].run");
    assert!(message.contains("64"), "{message}");

    let long = "a".repeat(4097);
    let (path, _) = bad_step(&format!("  - id: a\n    run: [git, '{long}']\n"));
    assert_eq!(path, "steps[0].run[1]");

    let chunk = "b".repeat(4000);
    let mut big = String::new();
    for _ in 0..9 {
        write!(big, ", '{chunk}'").expect("write to a String");
    }
    let (path, message) = bad_step(&format!("  - id: a\n    run: [git{big}]\n"));
    assert_eq!(path, "steps[0].run");
    assert!(message.contains("32768"), "{message}");
}

#[test]
fn connector_connector_call_and_arguments_are_checked() {
    let (path, message) = bad_step("  - id: a\n    connector: gitlab\n    call: runs\n");
    assert_eq!(path, "steps[0].connector");
    assert!(message.contains("github"), "{message}");

    let (path, _) = bad_step("  - id: a\n    connector: github\n");
    assert_eq!(path, "steps[0].call");

    let (path, message) = bad_step("  - id: a\n    connector: github\n    call: rerun\n");
    assert_eq!(path, "steps[0].call");
    assert!(message.contains("job_log"), "{message}");

    let (path, message) = bad_step(
        "  - id: a\n    connector: github\n    call: runs\n    with: { repo: x/y, branch: main }\n",
    );
    assert_eq!(path, "steps[0].with.branch");
    assert!(message.contains("status"), "{message}");

    let (path, message) =
        bad_step("  - id: a\n    connector: github\n    call: runs\n    with: {}\n");
    assert_eq!(path, "steps[0].with");
    assert!(message.contains("repo"), "{message}");

    let (path, _) = bad_step("  - id: a\n    connector: github\n    call: runs\n");
    assert_eq!(path, "steps[0].with");

    let flow = good(&wrap(
        "  - id: a\n    connector: github\n    call: runs\n    with: { repo: 'ro-ag/pam', limit: 1 }\n",
    ));
    let Action::Connector {
        connector,
        call,
        with,
    } = &flow.steps[0].action
    else {
        panic!("connector step");
    };
    assert_eq!(*connector, ConnectorId::Github);
    assert_eq!(call, "runs");
    assert_eq!(with.len(), 2);
}

#[test]
fn needs_and_when_name_earlier_steps_only() {
    let (path, message) =
        bad_step("  - id: a\n    run: [git]\n    needs: [b]\n  - id: b\n    run: [git]\n");
    assert_eq!(path, "steps[0].needs[0]");
    assert!(message.contains('b'), "{message}");

    let (path, _) = bad_step("  - id: a\n    run: [git]\n    needs: [a]\n");
    assert_eq!(path, "steps[0].needs[0]");

    let (path, _) = bad_step(
        "  - id: a\n    run: [git]\n    when: { succeeded: b }\n  - id: b\n    run: [git]\n",
    );
    assert_eq!(path, "steps[0].when");

    let (path, _) = bad_step(
        "  - id: a\n    run: [git]\n  - id: b\n    run: [git]\n    when: { failed: nope }\n",
    );
    assert_eq!(path, "steps[1].when");

    let flow = good(&wrap(
        "  - id: a\n    run: [git]\n  - id: b\n    run: [git]\n    needs: [a]\n    when: { failed: a }\n",
    ));
    assert_eq!(flow.steps[1].needs, ["a"]);
    assert_eq!(flow.steps[1].when, When::Failed("a".to_string()));
}

#[test]
fn stateful_steps_force_approval_and_default_to_change() {
    let flow = good(&wrap(
        "  - id: a\n    run: [git, push]\n    effect: stateful\n",
    ));
    assert_eq!(flow.steps[0].effect, Effect::Stateful);
    assert_eq!(flow.steps[0].role, Role::Change);
    assert_eq!(flow.steps[0].approval, Approval::Required);
    assert!(flow.steps[0].gated());

    let flow = good(&wrap(
        "  - id: a\n    run: [git, push]\n    effect: stateful\n    approval: none\n",
    ));
    assert_eq!(flow.steps[0].approval, Approval::Required);

    let (path, message) =
        bad_step("  - id: a\n    run: [git, push]\n    effect: stateful\n    role: verify\n");
    assert_eq!(path, "steps[0].role");
    assert!(
        message.contains("read-only") || message.contains("read only"),
        "{message}"
    );

    let flow = good(&wrap(
        "  - id: a\n    run: [cargo, test]\n    role: verify\n",
    ));
    assert_eq!(flow.steps[0].role, Role::Verify);
    assert!(!flow.steps[0].gated());
}

#[test]
fn the_timeout_is_bounded() {
    let (path, message) = bad_step("  - id: a\n    run: [git]\n    timeout: 60\n");
    assert_eq!(path, "steps[0].timeout");
    assert!(message.contains("60s"), "{message}");

    let (path, _) = bad_step("  - id: a\n    run: [git]\n    timeout: 0s\n");
    assert_eq!(path, "steps[0].timeout");

    let (path, message) = bad_step("  - id: a\n    run: [git]\n    timeout: 3601s\n");
    assert_eq!(path, "steps[0].timeout");
    assert!(message.contains("1h"), "{message}");

    let flow = good(&wrap("  - id: a\n    run: [git]\n    timeout: 90s\n"));
    assert_eq!(flow.steps[0].timeout, Duration::from_secs(90));
}

#[test]
fn retry_attempts_and_backoff_are_bounded() {
    let (path, _) = bad_step("  - id: a\n    run: [git]\n    retry: { attempts: 0 }\n");
    assert_eq!(path, "steps[0].retry.attempts");

    let (path, message) = bad_step("  - id: a\n    run: [git]\n    retry: { attempts: 6 }\n");
    assert_eq!(path, "steps[0].retry.attempts");
    assert!(message.contains('5'), "{message}");

    let (path, message) =
        bad_step("  - id: a\n    run: [git]\n    retry: { attempts: 2, backoff: 61s }\n");
    assert_eq!(path, "steps[0].retry.backoff");
    assert!(message.contains("60s"), "{message}");

    let flow = good(&wrap(
        "  - id: a\n    run: [git]\n    retry: { attempts: 2, backoff: 500ms }\n",
    ));
    assert_eq!(flow.steps[0].retry.attempts, 2);
    assert_eq!(flow.steps[0].retry.backoff, Duration::from_millis(500));
}

#[test]
fn environment_names_follow_the_shell_convention() {
    for name in ["cargo_term_color", "1ABC", "A-B"] {
        let (path, _) = bad_step(&format!(
            "  - id: a\n    run: [git]\n    env: {{ {name}: x }}\n"
        ));
        assert_eq!(path, format!("steps[0].env.{name}"), "{name}");
    }
    let flow = good(&wrap(
        "  - id: a\n    run: [cargo, test]\n    env: { CARGO_TERM_COLOR: never, _X2: y }\n",
    ));
    assert_eq!(flow.steps[0].env["CARGO_TERM_COLOR"], "never");
}

#[test]
fn secret_like_strings_are_refused_everywhere() {
    let secrets = [
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "github_pat_11ABCDEFG0abcdefghij",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
        "Bearer abc123",
        "https://user:pw@example.com/x",
    ];
    for secret in secrets {
        assert!(looks_secret_like(secret), "{secret}");
        let (path, message) = bad_step(&format!("  - id: a\n    run: [curl, '{secret}']\n"));
        assert_eq!(path, "steps[0].run[1]", "{secret}");
        assert!(message.contains("secret"), "{message}");

        let (path, _) = bad_step(&format!(
            "  - id: a\n    run: [git]\n    env: {{ A: '{secret}' }}\n"
        ));
        assert_eq!(path, "steps[0].env.A", "{secret}");

        let (path, _) = bad(&format!(
            "schema: 1\nid: demo\nname: Demo\ninputs:\n  k:\n    description: x\n    default: '{secret}'\nsteps:\n  - id: a\n    run: [git]\n"
        ));
        assert_eq!(path, "inputs.k.default", "{secret}");

        let (path, _) = bad_step(&format!(
            "  - id: a\n    connector: github\n    call: runs\n    with: {{ repo: '{secret}' }}\n"
        ));
        assert_eq!(path, "steps[0].with.repo", "{secret}");

        let (path, message) = bad_step(&format!(
            "  - id: a\n    run: [git]\n    note: '{secret}'\n"
        ));
        assert_eq!(path, "steps[0].note", "{secret}");
        assert!(message.contains("secret"), "{message}");
    }

    for innocent in [
        "ro-ag/pam",
        "--all-targets",
        "https://example.com/x",
        "origin/main..HEAD",
    ] {
        assert!(!looks_secret_like(innocent), "{innocent}");
    }
}

#[test]
fn sensitive_argument_names_are_refused() {
    for arg in [
        "--token=abc",
        "--token",
        "--password",
        "--secret",
        "--api-key=x",
        "--API-KEY",
    ] {
        assert!(is_sensitive_arg(arg), "{arg}");
        let (path, message) = bad_step(&format!("  - id: a\n    run: [gh, '{arg}']\n"));
        assert_eq!(path, "steps[0].run[1]", "{arg}");
        assert!(
            message.contains("credential") || message.contains("secret"),
            "{message}"
        );
    }
    assert!(!is_sensitive_arg("--tokens"));
    assert!(!is_sensitive_arg("--all-targets"));
}

#[test]
fn unknown_variables_are_rejected_wherever_they_appear() {
    let (path, message) = bad_step("  - id: a\n    run: [git, '${inputs.nope}']\n");
    assert_eq!(path, "steps[0].run[1]");
    assert!(message.contains("inputs.nope"), "{message}");

    let (path, _) = bad_step("  - id: a\n    run: [git, '${repo.branch}']\n");
    assert_eq!(path, "steps[0].run[1]");

    let (path, _) =
        bad_step("  - id: a\n    run: [git]\n  - id: b\n    run: [git, '${steps.a.stdout}']\n");
    assert_eq!(path, "steps[1].run[1]");

    let (path, _) =
        bad_step("  - id: a\n    run: [git, '${steps.b.result.id}']\n  - id: b\n    run: [git]\n");
    assert_eq!(path, "steps[0].run[1]");

    let (path, _) = bad_step("  - id: a\n    run: [git]\n    env: { A: '${nope}' }\n");
    assert_eq!(path, "steps[0].env.A");

    let (path, _) = bad_step(
        "  - id: a\n    run: [git]\n  - id: b\n    connector: github\n    call: runs\n    with: { repo: '${steps.a.result.repo}', status: '${inputs.x}' }\n",
    );
    assert_eq!(path, "steps[1].with.status");

    let flow = good(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  repo:\n    description: x\nsteps:\n  - id: a\n    run: [git, log, '${inputs.repo}', '${repo.path}', '${repo.name}']\n  - id: b\n    run: [git, show, '${steps.a.exit_status}', '${steps.a.result.head[0].sha}']\n",
    );
    assert_eq!(flow.steps.len(), 2);
}

#[test]
fn a_file_over_the_limit_is_too_large() {
    let padding = "#".repeat(MAX_FILE_BYTES);
    match parse(&format!(
        "{padding}\nschema: 1\nid: demo\nname: Demo\nsteps: []\n"
    )) {
        Err(FlowError::TooLarge { actual, maximum }) => {
            assert!(actual > maximum);
            assert_eq!(maximum, MAX_FILE_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn malformed_yaml_becomes_an_invalid_error() {
    let (path, message) = bad("schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: [\n");
    assert!(!path.is_empty());
    assert!(!message.is_empty());

    let (_, message) = bad("schema: 1\nid: demo\nname: Demo\nsteps: []\nschedule: daily\n");
    assert!(message.contains("schedule"), "{message}");
}

#[test]
fn the_connector_call_table_matches_the_spec() {
    let names = |id| {
        connector_calls(id)
            .iter()
            .map(|spec| spec.name)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(ConnectorId::Github),
        ["run_status", "runs", "run", "job_log"]
    );
    assert_eq!(
        names(ConnectorId::Jenkins),
        [
            "build_status",
            "jobs",
            "builds",
            "console",
            "investigate",
            "node_evidence"
        ]
    );
    assert_eq!(
        names(ConnectorId::Sonarqube),
        ["ce_status", "analysis", "quality_gate", "issues"]
    );
    assert_eq!(names(ConnectorId::Jira), ["search", "issue"]);
    assert_eq!(names(ConnectorId::Confluence), ["search", "page"]);
    assert_eq!(
        names(ConnectorId::Sharepoint),
        ["document", "documents", "lists"]
    );

    let spec = |id, call: &str| {
        connector_calls(id)
            .iter()
            .find(|spec| spec.name == call)
            .copied()
            .expect("call exists")
    };
    assert_eq!(
        spec(ConnectorId::Github, "runs").args,
        [
            ("repo", true),
            ("status", false),
            ("limit", false),
            ("page", false)
        ]
    );
    assert_eq!(
        spec(ConnectorId::Github, "run").args,
        [
            ("repo", true),
            ("run_id", true),
            ("page", false),
            ("run_attempt", false)
        ]
    );
    assert_eq!(
        spec(ConnectorId::Jenkins, "console").args,
        [("job", true), ("build", true)]
    );
    assert_eq!(
        spec(ConnectorId::Sharepoint, "documents").args,
        [("site", true), ("query", true), ("limit", false)]
    );

    // Only two calls stream a log rather than JSON.
    let logs: Vec<_> = ConnectorId::ALL
        .into_iter()
        .flat_map(|id| {
            connector_calls(id)
                .iter()
                .filter(|spec| spec.yields_log)
                .map(move |spec| (id.as_str(), spec.name))
        })
        .collect();
    assert_eq!(logs, [("github", "job_log"), ("jenkins", "console")]);
}

#[test]
fn parse_value_accepts_the_raw_json_shape() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [
            { "id": "status", "run": ["git", "status", "--short"], "role": "verify" },
            { "id": "log", "run": ["git", "log", "--oneline"], "needs": ["status"],
              "when": { "succeeded": "status" }, "timeout": "10m",
              "retry": { "attempts": 2, "backoff": "1s" } }
        ]
    });
    let flow = parse_value(&raw).expect("parses");
    assert_eq!(flow.steps.len(), 2);
    assert_eq!(flow.steps[1].needs, vec!["status"]);
    assert_eq!(flow.steps[1].when, When::Succeeded("status".into()));
    assert_eq!(format_duration(flow.steps[1].timeout), "10m");
    assert_eq!(flow.steps[1].retry.attempts, 2);
}

#[test]
fn parse_value_carries_a_step_note_through_yaml() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [ { "id": "status", "run": ["git", "status"], "note": "First line.\nSecond line." } ]
    });
    let flow = parse_value(&raw).expect("parses");
    assert_eq!(flow.steps[0].note, "First line.\nSecond line.");
}

#[test]
fn parse_value_reports_the_same_paths_as_parse() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [ { "id": "later", "run": ["git", "status"], "needs": ["missing"] } ]
    });
    let err = parse_value(&raw).unwrap_err();
    let yaml_err = parse(
        "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: later\n    run: [git, status]\n    needs: [missing]\n",
    )
    .unwrap_err();
    assert_eq!(err.to_string(), yaml_err.to_string());
    assert!(err.to_string().starts_with("steps[0].needs[0]"), "{err}");
}

#[test]
fn parse_value_refuses_an_unknown_key_by_path() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [ { "id": "s", "run": ["git", "status"], "ui": { "x": 1 } } ]
    });
    let err = parse_value(&raw).unwrap_err();
    match err {
        FlowError::Invalid { path, message } => {
            assert_eq!(path, "steps[0]", "{path}: {message}");
            assert!(message.contains("unknown field `ui`"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn empty_output_assertion_is_command_only() {
    let flow = good(&wrap(
        "  - id: clean\n    run: [git, status]\n    expect_empty_output: true\n",
    ));
    assert!(flow.steps[0].expect_empty_output);
    let (path, _) = bad_step(
        "  - id: runs\n    connector: github\n    call: runs\n    expect_empty_output: true\n",
    );
    assert_eq!(path, "steps[0].expect_empty_output");
}

#[test]
fn status_assertions_are_bounded_connector_literals() {
    let yaml = "  - id: gate\n    connector: sonarqube\n    call: quality_gate\n    with: { project: pam }\n    expect_status: OK\n";
    assert_eq!(
        good(&wrap(yaml)).steps[0].expect_status.as_deref(),
        Some("OK")
    );
    for expected in ["''".to_owned(), "' OK '".to_owned(), "X".repeat(65)] {
        assert_eq!(
            bad_step(&yaml.replace("expect_status: OK", &format!("expect_status: {expected}"))).0,
            "steps[0].expect_status"
        );
    }
    assert_eq!(
        bad_step("  - id: command\n    run: [git, status]\n    expect_status: OK\n").0,
        "steps[0].expect_status"
    );
}

#[test]
fn a_flow_naming_the_removed_aws_connector_is_refused_legibly() {
    // A flow saved before the AWS adapter was removed still names it: the
    // validator refuses the step with the removal named, never a panic.
    for step in [
        "  - id: a\n    connector: aws\n    call: commands\n",
        "  - id: a\n    connector: aws\n    call: cli\n    with: { service: sts, command: get-caller-identity }\n",
        "  - id: a\n    connector: aws\n    call: nonsense\n",
    ] {
        let (path, message) = bad_step(step);
        assert_eq!(path, "steps[0].connector");
        assert!(message.contains("`aws` connector was removed"), "{message}");
        assert!(message.contains("Delete this step"), "{message}");
        assert!(!message.contains("unknown connector"), "{message}");
    }
    assert_eq!(ConnectorId::parse("aws"), None);
    assert!(ConnectorId::ALL.iter().all(|id| id.as_str() != "aws"));
    // Any other unknown name keeps the plain refusal.
    let (path, message) = bad_step("  - id: a\n    connector: gitlab\n    call: runs\n");
    assert_eq!(path, "steps[0].connector");
    assert!(message.contains("unknown connector `gitlab`"), "{message}");
}

#[test]
fn a_result_pointer_the_run_could_never_walk_is_refused() {
    for tail in [
        "result.",
        "result.jobs[a]",
        "result.jobs[0",
        "result..id",
        "result.jobs[]",
    ] {
        let (path, message) = bad_step(&format!(
            "  - id: a\n    run: [git]\n  - id: b\n    run: [git, '${{steps.a.{tail}}}']\n"
        ));
        assert_eq!(path, "steps[1].run[1]", "{tail}");
        assert!(message.contains("unknown variable"), "{tail}: {message}");
    }
    for tail in [
        "result",
        "exit_status",
        "result.id",
        "result.jobs[0].id",
        "result.a[1][2].b",
    ] {
        good(&wrap(&format!(
            "  - id: a\n    run: [git]\n  - id: b\n    run: [git, '${{steps.a.{tail}}}']\n"
        )));
    }
}

#[test]
fn secret_like_strings_are_refused_in_prose_fields_too() {
    let secret = "ghp_0123456789abcdef";
    let (path, message) = bad(&format!(
        "schema: 1\nid: demo\nname: 'Demo {secret}'\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "name");
    assert!(message.contains("secret"), "{message}");

    let (path, _) = bad(&format!(
        "schema: 1\nid: demo\nname: Demo\ndescription: 'token {secret}'\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "description");

    let (path, _) = bad(&format!(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  k:\n    description: 'use {secret}'\nsteps:\n  - id: a\n    run: [git]\n"
    ));
    assert_eq!(path, "inputs.k.description");
}

#[test]
fn a_declared_input_nobody_reads_is_refused() {
    let (path, message) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  extra:\n    description: unused\nsteps:\n  - id: status\n    run: [git, status]\n",
    );
    assert_eq!(path, "inputs.extra");
    assert!(
        message.contains("no step argument"),
        "the message names what would have to read it: {message}"
    );
}

#[test]
fn a_default_alone_does_not_make_an_input_used() {
    let (path, _) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  repo:\n    description: owner/name\n    default: '${repo.origin}'\nsteps:\n  - id: status\n    run: [git, status]\n",
    );
    assert_eq!(path, "inputs.repo");
}

#[test]
fn environment_connector_and_correlation_reads_all_count() {
    let flow = good(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  who:\n    description: greeter\n  repo:\n    description: owner/name\nsteps:\n  - id: status\n    run: [git, status]\n    env: { WHO: '${inputs.who}' }\n  - id: runs\n    connector: github\n    call: runs\n    with: { repo: '${inputs.repo}' }\n",
    );
    assert_eq!(flow.inputs.len(), 2, "env and connector reads count");
    let correlated = good(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  repository:\n    description: clone url\n  commit:\n    description: full sha\ncorrelation:\n  repository: '${inputs.repository}'\n  commit: '${inputs.commit}'\nsteps:\n  - id: status\n    run: [git, status]\n",
    );
    assert!(correlated.correlation.is_some(), "correlation reads count");
}

#[test]
fn an_input_name_may_not_start_with_a_dash() {
    let (path, message) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  -bad:\n    description: x\nsteps:\n  - id: status\n    run: [git, status]\n",
    );
    assert_eq!(path, "inputs.-bad");
    assert!(message.contains("does not start with"), "{message}");
}

/// A one-input flow whose step reads the input as an argument.
fn typed(input_yaml: &str) -> String {
    format!(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  subject:\n    description: x\n{input_yaml}\
         steps:\n  - id: look\n    run: [git, log, '${{inputs.subject}}']\n"
    )
}

#[test]
fn an_input_without_a_type_is_a_string_and_renders_as_before() {
    let flow = good(&typed(""));
    let input = &flow.inputs["subject"];
    assert_eq!(input.kind, InputType::String);
    assert!(input.values.is_empty());
    assert!(input.check("subject", "--anything goes").is_ok());
    let yaml = crate::to_normalized_yaml(&flow);
    assert!(!yaml.contains("type:"), "{yaml}");
    assert!(!yaml.contains("values:"), "{yaml}");
}

#[test]
fn every_input_type_declares_and_round_trips() {
    for (declaration, kind) in [
        ("    type: string\n", InputType::String),
        ("    type: int\n", InputType::Int),
        ("    type: sha\n", InputType::Sha),
        ("    type: ref\n", InputType::Ref),
        ("    type: path\n", InputType::Path),
        (
            "    type: enum\n    values: [debug, release]\n",
            InputType::Enum,
        ),
    ] {
        let flow = good(&typed(declaration));
        assert_eq!(flow.inputs["subject"].kind, kind, "{declaration}");
        let again = good(&crate::to_normalized_yaml(&flow));
        assert_eq!(again, flow, "{declaration}");
        assert_eq!(crate::digest(&again), crate::digest(&flow));
    }
}

#[test]
fn a_typed_input_changes_the_digest() {
    let plain = good(&typed(""));
    let typed_int = good(&typed("    type: int\n"));
    assert_ne!(crate::digest(&plain), crate::digest(&typed_int));
}

#[test]
fn an_unknown_input_type_is_refused_with_the_choices() {
    let (path, message) = bad(&typed("    type: url\n"));
    assert_eq!(path, "inputs.subject.type");
    assert!(message.contains("unknown variant `url`"), "{message}");
    for name in ["string", "int", "sha", "ref", "path", "enum"] {
        assert!(message.contains(name), "{message}");
    }
}

#[test]
fn enum_declarations_are_checked() {
    for (declaration, message) in [
        ("    type: enum\n", "non-empty"),
        ("    type: enum\n    values: []\n", "non-empty"),
        ("    type: enum\n    values: [a, a]\n", "repeats"),
        ("    type: int\n    values: [a]\n", "belongs to"),
        ("    values: [a]\n", "belongs to"),
    ] {
        let (path, text) = bad(&typed(declaration));
        assert_eq!(path, "inputs.subject.values", "{declaration}");
        assert!(text.contains(message), "{declaration}: {text}");
    }
}

#[test]
fn a_literal_default_must_satisfy_its_type() {
    for (declaration, accepted) in [
        ("    type: int\n    default: '1'\n", true),
        ("    type: int\n    default: 'one'\n", false),
        ("    type: ref\n    default: main\n", true),
        ("    type: ref\n    default: 'HEAD@{1}'\n", false),
        ("    type: path\n    default: docs/a.md\n", true),
        ("    type: path\n    default: ../../etc\n", false),
        ("    type: enum\n    values: [a, b]\n    default: b\n", true),
        (
            "    type: enum\n    values: [a, b]\n    default: c\n",
            false,
        ),
        ("    type: string\n    default: '--anything'\n", true),
    ] {
        let yaml = typed(declaration);
        if accepted {
            good(&yaml);
        } else {
            let (path, message) = bad(&yaml);
            assert_eq!(path, "inputs.subject.default", "{declaration}");
            assert!(message.starts_with("input `subject` must be "), "{message}");
        }
    }
}

#[test]
fn a_default_that_reads_the_repository_is_checked_at_run_time_not_here() {
    // `${repo.path}` is absolute, which a `path` input refuses once filled in.
    let flow = good(&typed("    type: path\n    default: '${repo.path}'\n"));
    let input = &flow.inputs["subject"];
    assert!(input.check("subject", "/Users/me/repo").is_err());
    assert!(input.check("subject", "crates").is_ok());
}

#[test]
fn a_typed_input_refuses_a_mismatched_value_naming_input_type_and_rule() {
    let flow = good(&typed("    type: sha\n"));
    let error = flow.inputs["subject"]
        .check("subject", &format!("--upload-pack={}", "a".repeat(26)))
        .expect_err("not a sha");
    assert_eq!(
        error.to_string(),
        "input `subject` must be a full lowercase hexadecimal object id: only lowercase \
         hexadecimal digits (0-9, a-f) are allowed"
    );
    assert_eq!(error.input, "subject");
}

#[test]
fn reserved_environment_names_are_refused_with_the_reason_and_the_list() {
    for name in [
        "PATH",
        "HOME",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "TMPDIR",
        "PAM_ARTIFACTS",
        "NODE_OPTIONS",
    ] {
        let (path, message) = bad_step(&format!(
            "  - id: build\n    run: [make]\n    env: {{ {name}: x }}\n"
        ));
        assert_eq!(path, format!("steps[0].env.{name}"));
        assert!(
            message.contains(&format!("`{name}` is reserved: ")),
            "{message}"
        );
        assert!(
            message.contains("GIT_*") && message.contains("LD_*"),
            "{message}"
        );
        assert!(message.contains("drop it from `env`"), "{message}");
    }
}

#[test]
fn a_reserved_name_is_refused_even_with_a_substituted_value() {
    let (path, _) = bad(
        "schema: 1\nid: demo\nname: Demo\ninputs:\n  dir:\n    description: x\nsteps:\n  - id: a\n    run: [make]\n    env: { PATH: '${inputs.dir}' }\n",
    );
    assert_eq!(path, "steps[0].env.PATH");
}

#[test]
fn ordinary_environment_names_are_accepted() {
    let flow = good(&wrap(
        "  - id: build\n    run: [make]\n    env: { RUSTFLAGS: '-D warnings', CI: '1', GIT_AUTHOR_NAME: pam, WHO: me }\n",
    ));
    assert_eq!(flow.steps[0].env.len(), 4);
}

#[test]
fn a_later_stateful_step_must_say_what_it_depends_on() {
    let (path, message) = bad_step(
        "  - id: check\n    run: [git, status]\n  - id: push\n    run: [git, push]\n    effect: stateful\n",
    );
    assert_eq!(path, "steps[1]");
    assert!(message.contains("step `push` is stateful"), "{message}");
    assert!(
        message.contains("add `needs: [...]`") && message.contains("`when: always`"),
        "{message}"
    );
}

#[test]
fn an_explicit_default_when_does_not_say_what_it_depends_on() {
    let (path, _) = bad_step(
        "  - id: check\n    run: [git, status]\n  - id: push\n    run: [git, push]\n    effect: stateful\n    when: needs_succeeded\n",
    );
    assert_eq!(path, "steps[1]");
}

#[test]
fn stateful_ordering_is_accepted_when_the_flow_says_it() {
    for tail in [
        "    needs: [check]\n",
        "    when: always\n",
        "    when: { succeeded: check }\n",
        "    when: { failed: check }\n",
    ] {
        good(&wrap(&format!(
            "  - id: check\n    run: [git, status]\n  - id: push\n    run: [git, push]\n    effect: stateful\n{tail}"
        )));
    }
}

#[test]
fn the_first_step_may_be_stateful_without_needs_and_read_only_steps_stay_independent() {
    good(&wrap(
        "  - id: push\n    run: [git, push]\n    effect: stateful\n  - id: look\n    run: [git, status]\n  - id: other\n    run: [git, log]\n",
    ));
}
