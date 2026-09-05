use std::collections::BTreeSet;

use super::builtin::{builtin, builtin_yaml};
use super::normalize::to_normalized_yaml;
use super::schema::{Action, ConnectorId, OutputPolicy, Role};
use super::validate::parse;

#[test]
fn pam_ships_the_seven_starter_flows() {
    let ids: Vec<_> = builtin().iter().map(|flow| flow.id).collect();
    assert_eq!(
        ids,
        [
            "after-merge-checks",
            "ci-failure-triage",
            "dependency-audit",
            "pr-readiness",
            "release-readiness",
            "sonar-gate-check",
            "summarize-build-log",
        ]
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "builtins are listed in id order");
}

#[test]
fn every_builtin_parses_and_owns_its_id() {
    for entry in builtin() {
        let flow = parse(entry.yaml)
            .unwrap_or_else(|err| panic!("builtin `{}` does not parse: {err}", entry.id));
        assert_eq!(flow.id, entry.id, "id must equal the file stem");
        assert!(!flow.name.is_empty(), "{} has no name", entry.id);
        assert!(
            !flow.description.is_empty(),
            "{} has no description",
            entry.id
        );
        assert_eq!(builtin_yaml(entry.id), Some(entry.yaml));
    }
    assert_eq!(builtin_yaml("nothing-like-this"), None);
}

#[test]
fn every_builtin_survives_normalization() {
    for entry in builtin() {
        let flow = parse(entry.yaml).expect("builtin parses");
        let normalized = to_normalized_yaml(&flow);
        let again = parse(&normalized).expect("normalized builtin parses");
        assert_eq!(flow, again, "{} does not round-trip", entry.id);
    }
}

#[test]
fn every_builtin_step_id_is_unique_and_every_input_is_used() {
    for entry in builtin() {
        let flow = parse(entry.yaml).expect("builtin parses");
        let ids: BTreeSet<_> = flow.steps.iter().map(|step| step.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            flow.steps.len(),
            "{} repeats a step id",
            entry.id
        );

        let body = to_normalized_yaml(&flow);
        for name in flow.inputs.keys() {
            assert!(
                body.contains(&format!("${{inputs.{name}}}")),
                "{} declares input `{name}` and never uses it",
                entry.id
            );
        }
    }
}

#[test]
fn the_command_starters_match_the_spec_table() {
    let argv = |id: &str| -> Vec<Vec<String>> {
        parse(builtin_yaml(id).expect("builtin"))
            .expect("parses")
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Command { argv } => Some(argv.clone()),
                Action::Connector { .. } => None,
            })
            .collect()
    };

    assert_eq!(
        argv("after-merge-checks"),
        [
            vec!["git", "fetch", "--prune"],
            vec![
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none"
            ],
            vec!["git", "log", "--oneline", "-20"],
        ]
    );
    assert_eq!(
        argv("pr-readiness"),
        [
            vec![
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none"
            ],
            vec!["git", "fetch", "--prune"],
            vec!["git", "log", "--oneline", "origin/main..HEAD"],
            vec!["cargo", "fmt", "--all", "--check"],
            vec![
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ],
            vec!["cargo", "test", "--workspace"],
        ]
    );
    assert_eq!(
        argv("release-readiness"),
        [
            vec![
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none"
            ],
            vec!["git", "describe", "--tags", "--abbrev=0"],
            vec!["cargo", "test", "--workspace"],
            vec!["cargo", "package", "--list", "--allow-dirty"],
        ]
    );
    assert_eq!(
        argv("summarize-build-log"),
        [vec!["cargo", "build", "--all-targets"]]
    );
    assert_eq!(
        argv("dependency-audit"),
        [
            vec!["cargo", "audit"],
            vec!["cargo", "tree", "--duplicates"]
        ]
    );
}

#[test]
fn the_starters_carry_the_roles_and_output_policies_the_spec_asks_for() {
    let flow = parse(builtin_yaml("after-merge-checks").expect("builtin")).expect("parses");
    assert_eq!(flow.steps[1].role, Role::Verify);
    assert_eq!(flow.steps[2].output, OutputPolicy::Summarize);

    let flow = parse(builtin_yaml("pr-readiness").expect("builtin")).expect("parses");
    let verify: Vec<_> = flow
        .steps
        .iter()
        .filter(|step| step.role == Role::Verify)
        .map(|step| step.id.as_str())
        .collect();
    assert_eq!(verify, ["clean-tree", "fmt", "clippy", "tests"]);
    let summarized: Vec<_> = flow
        .steps
        .iter()
        .filter(|step| step.output == OutputPolicy::Summarize)
        .map(|step| step.id.as_str())
        .collect();
    assert_eq!(summarized, ["clippy", "tests"]);

    let flow = parse(builtin_yaml("dependency-audit").expect("builtin")).expect("parses");
    assert_eq!(flow.steps[0].role, Role::Verify);
    assert_eq!(flow.steps[0].output, OutputPolicy::Summarize);
    assert!(
        flow.description.contains("cargo-audit"),
        "the description must say the flow needs cargo-audit"
    );
}

#[test]
fn the_connector_starters_call_the_spec_table() {
    let calls = |id: &str| -> Vec<(ConnectorId, String)> {
        parse(builtin_yaml(id).expect("builtin"))
            .expect("parses")
            .steps
            .iter()
            .filter_map(|step| match &step.action {
                Action::Connector {
                    connector, call, ..
                } => Some((*connector, call.clone())),
                Action::Command { .. } => None,
            })
            .collect()
    };

    assert_eq!(
        calls("ci-failure-triage"),
        [
            (ConnectorId::Github, "runs".to_string()),
            (ConnectorId::Github, "run".to_string()),
            (ConnectorId::Github, "job_log".to_string()),
        ]
    );
    assert_eq!(
        calls("sonar-gate-check"),
        [
            (ConnectorId::Sonarqube, "quality_gate".to_string()),
            (ConnectorId::Sonarqube, "issues".to_string()),
        ]
    );

    let flow = parse(builtin_yaml("ci-failure-triage").expect("builtin")).expect("parses");
    assert_eq!(
        flow.inputs["repo"].default.as_deref(),
        Some("${repo.origin}")
    );
    assert_eq!(flow.steps[2].output, OutputPolicy::Summarize);
    assert!(flow.steps.iter().all(super::schema::Step::gated));
}

#[test]
fn readiness_clean_tree_steps_assert_all_porcelain_output_is_empty() {
    for id in ["after-merge-checks", "pr-readiness", "release-readiness"] {
        let flow = parse(builtin_yaml(id).unwrap()).unwrap();
        let step = flow
            .steps
            .iter()
            .find(|step| step.id == "clean-tree")
            .unwrap();
        assert!(step.expect_empty_output, "{id}");
        assert_eq!(step.role, Role::Verify);
        assert_eq!(
            step.action,
            Action::Command {
                argv: [
                    "git",
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    "--ignore-submodules=none"
                ]
                .map(str::to_owned)
                .to_vec()
            }
        );
    }
}
