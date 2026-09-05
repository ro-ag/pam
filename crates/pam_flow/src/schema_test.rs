use std::collections::BTreeMap;
use std::time::Duration;

use super::schema::{
    Action, Approval, ArgValue, ConnectorId, Effect, Flow, OutputPolicy, RawFlow, Retry, Role,
    Step, When,
};

const FULL: &str = r"
schema: 1
id: full
name: Full featured
description: Every field the schema knows.
inputs:
  repo:
    description: owner/name on GitHub
    default: ${repo.origin}
steps:
  - id: latest
    connector: github
    call: runs
    with: { repo: '${inputs.repo}', status: failure, limit: 1 }
  - id: worktree
    run: [git, status, --short]
    timeout: 60s
    effect: read_only
    role: observe
    output: summarize
    needs: [latest]
    when: needs_succeeded
    retry: { attempts: 2, backoff: 500ms }
    approval: none
    env: { CARGO_TERM_COLOR: never }
    note: |-
      Check the tree first.
      Stale files hide real failures.
";

fn raw(yaml: &str) -> Result<RawFlow, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(yaml)
}

#[test]
fn a_full_featured_flow_deserializes() {
    let flow = raw(FULL).expect("full flow deserializes");
    assert_eq!(flow.schema, 1);
    assert_eq!(flow.id, "full");
    assert_eq!(flow.name, "Full featured");
    assert_eq!(
        flow.inputs["repo"].default.as_deref(),
        Some("${repo.origin}")
    );
    assert_eq!(flow.steps.len(), 2);

    let first = &flow.steps[0];
    assert_eq!(first.connector.as_deref(), Some("github"));
    assert_eq!(first.call.as_deref(), Some("runs"));
    let with = first.with.as_ref().expect("with map");
    assert_eq!(with["status"], ArgValue::Text("failure".to_string()));
    assert_eq!(with["limit"], ArgValue::Int(1));

    let second = &flow.steps[1];
    assert_eq!(
        second.run.as_ref().expect("run argv").as_slice(),
        ["git", "status", "--short"]
    );
    assert_eq!(second.timeout.as_deref(), Some("60s"));
    assert_eq!(second.effect, Some(Effect::ReadOnly));
    assert_eq!(second.role, Some(Role::Observe));
    assert_eq!(second.output, Some(OutputPolicy::Summarize));
    assert_eq!(second.when, Some(When::NeedsSucceeded));
    assert_eq!(second.approval, Some(Approval::None));
    let retry = second.retry.as_ref().expect("retry");
    assert_eq!(retry.attempts, 2);
    assert_eq!(retry.backoff.as_deref(), Some("500ms"));
    assert_eq!(
        second.env.as_ref().expect("env")["CARGO_TERM_COLOR"],
        "never"
    );
    assert_eq!(
        second.note.as_deref(),
        Some("Check the tree first.\nStale files hide real failures.")
    );
    assert_eq!(flow.steps[0].note, None);
}

#[test]
fn an_unknown_flow_key_names_the_key() {
    let err = raw("schema: 1\nid: x\nname: X\nsteps: []\nschedule: daily\n")
        .expect_err("unknown key rejected");
    assert!(err.to_string().contains("schedule"), "{err}");
}

#[test]
fn an_unknown_step_key_names_the_key() {
    let err =
        raw("schema: 1\nid: x\nname: X\nsteps:\n  - id: a\n    run: [git]\n    shell: true\n")
            .expect_err("unknown key rejected");
    assert!(err.to_string().contains("shell"), "{err}");
}

#[test]
fn when_reads_both_shapes() {
    let flow = raw(
        "schema: 1\nid: x\nname: X\nsteps:\n  - id: a\n    run: [git]\n    when: always\n  - id: b\n    run: [git]\n    when: { succeeded: a }\n  - id: c\n    run: [git]\n    when: { failed: a }\n",
    )
    .expect("when shapes");
    assert_eq!(flow.steps[0].when, Some(When::Always));
    assert_eq!(flow.steps[1].when, Some(When::Succeeded("a".to_string())));
    assert_eq!(flow.steps[2].when, Some(When::Failed("a".to_string())));
}

#[test]
fn a_missing_step_id_is_an_error() {
    let err = raw("schema: 1\nid: x\nname: X\nsteps:\n  - run: [git]\n").expect_err("id required");
    assert!(err.to_string().contains("id"), "{err}");
}

#[test]
fn connector_ids_round_trip_through_their_names() {
    for id in ConnectorId::ALL {
        assert_eq!(ConnectorId::parse(id.as_str()), Some(id));
        assert_eq!(id.to_string(), id.as_str());
    }
    assert_eq!(ConnectorId::ALL.len(), 7);
    assert_eq!(ConnectorId::parse("gitlab"), None);
    assert_eq!(ConnectorId::parse("GitHub"), None);
    assert_eq!(ConnectorId::Sonarqube.as_str(), "sonarqube");
}

#[test]
fn arg_values_render_as_plain_text() {
    assert_eq!(ArgValue::Text("failure".to_string()).to_string(), "failure");
    assert_eq!(ArgValue::Int(-3).to_string(), "-3");
}

#[test]
fn step_kind_and_gating_follow_the_action_and_effect() {
    let command = Step {
        id: "a".to_string(),
        action: Action::Command {
            argv: vec!["git".to_string()],
        },
        ..step_defaults()
    };
    assert_eq!(command.kind(), "command");
    assert!(!command.gated());

    let stateful = Step {
        effect: Effect::Stateful,
        role: Role::Change,
        approval: Approval::Required,
        ..command.clone()
    };
    assert_eq!(stateful.kind(), "command");
    assert!(stateful.gated());

    let approved = Step {
        approval: Approval::Required,
        ..command.clone()
    };
    assert!(approved.gated());

    let connector = Step {
        action: Action::Connector {
            connector: ConnectorId::Github,
            call: "runs".to_string(),
            with: BTreeMap::new(),
        },
        ..command
    };
    assert_eq!(connector.kind(), "connector");
    assert!(connector.gated());
}

#[test]
fn a_flow_serializes_durations_as_strings() {
    let flow = Flow {
        id: "x".to_string(),
        name: "X".to_string(),
        description: String::new(),
        inputs: BTreeMap::new(),
        steps: vec![Step {
            id: "a".to_string(),
            action: Action::Command {
                argv: vec!["git".to_string()],
            },
            timeout: Duration::from_secs(90),
            retry: Retry {
                attempts: 2,
                backoff: Duration::from_millis(500),
            },
            ..step_defaults()
        }],
    };
    let json = serde_json::to_value(&flow).expect("flow serializes");
    assert_eq!(json["steps"][0]["timeout"], "90s");
    assert_eq!(json["steps"][0]["retry"]["backoff"], "500ms");
    assert_eq!(json["steps"][0]["action"]["kind"], "command");
    assert_eq!(json["steps"][0]["action"]["argv"][0], "git");
    assert!(
        json["steps"][0].get("note").is_none(),
        "an empty note is left out of the resolved JSON"
    );
}

#[test]
fn a_step_note_serializes_only_when_set() {
    let step = Step {
        id: "a".to_string(),
        action: Action::Command {
            argv: vec!["git".to_string()],
        },
        note: "Why this step exists.".to_string(),
        ..step_defaults()
    };
    let json = serde_json::to_value(&step).expect("step serializes");
    assert_eq!(json["note"], "Why this step exists.");
}

fn step_defaults() -> Step {
    Step {
        id: String::new(),
        action: Action::Command { argv: Vec::new() },
        timeout: Duration::from_mins(5),
        effect: Effect::ReadOnly,
        role: Role::Observe,
        output: OutputPolicy::Compact,
        expect_empty_output: false,
        needs: Vec::new(),
        when: When::NeedsSucceeded,
        retry: Retry::default(),
        approval: Approval::None,
        env: BTreeMap::new(),
        note: String::new(),
    }
}

#[test]
fn default_output_assertion_is_absent_from_resolved_json() {
    let json = serde_json::to_value(step_defaults()).unwrap();
    assert!(json.get("expect_empty_output").is_none());
}
