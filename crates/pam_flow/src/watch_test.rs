use crate::{Watch, digest, parse, to_normalized_yaml};
use std::time::Duration;
fn recipe(watch: &str) -> String {
    format!(
        "schema: 1\nid: watch\nname: Watch\nsteps:\n - id: poll\n   connector: github\n   call: run\n   with: {{repo: team/repo, run_id: 9, run_attempt: 1}}\n   watch: {watch}\n"
    )
}
#[test]
fn defaults_and_policy_changes_roundtrip_and_change_digest() {
    let first = parse(&recipe("{}")).unwrap();
    assert_eq!(first.steps[0].watch, Some(Watch::default()));
    let explicit = parse(&recipe("{max_polls: 60, interval: 5s, max_interval: 30s}")).unwrap();
    assert_eq!(digest(&first), digest(&explicit));
    let changed = parse(&recipe(
        "{max_polls: 100, interval: 10s, max_interval: 300s}",
    ))
    .unwrap();
    assert_ne!(digest(&first), digest(&changed));
    assert_eq!(
        changed.steps[0].watch.unwrap().interval,
        Duration::from_secs(10)
    );
    assert_eq!(parse(&to_normalized_yaml(&changed)).unwrap(), changed);
}
#[test]
fn out_of_bounds_and_user_terminal_predicates_refuse() {
    for watch in [
        "{max_polls: 0}",
        "{max_polls: 101}",
        "{interval: 4s}",
        "{interval: 40s,max_interval: 30s}",
        "{max_interval: 301s}",
        "{until: success}",
        "{terminal: true}",
    ] {
        assert!(parse(&recipe(watch)).is_err(), "{watch}");
    }
}
#[test]
fn effects_commands_retry_and_unpinned_attempts_refuse() {
    let valid = recipe("{}");
    for invalid in [
        valid.replace("   watch:", "   effect: stateful\n   watch:"),
        valid.replace("   watch:", "   retry: {attempts: 2}\n   watch:"),
        valid.replace(", run_attempt: 1", ""),
        valid.replace("run_attempt: 1", "run_attempt: 0"),
        valid.replace("run_attempt: 1", "run_attempt: latest"),
        valid.replace("   call: run", "   call: runs"),
        valid.replace("   watch:", "   role: verify\n   watch:"),
    ] {
        assert!(parse(&invalid).is_err(), "{invalid}");
    }
    assert!(parse("schema: 1\nid: command\nname: Command\nsteps:\n - id: run\n   run: [git, status]\n   watch: {}\n").is_err());
}
#[test]
fn declared_input_ids_are_fixed_but_step_results_are_not() {
    let valid = recipe("{}")
        .replace("steps:", "inputs:\n  attempt: {}\nsteps:")
        .replace("run_attempt: 1", "run_attempt: '${inputs.attempt}'");
    assert!(parse(&valid).is_ok());
    let previous=recipe("{}").replace("steps:","steps:\n - id: previous\n   connector: github\n   call: runs\n   with: {repo: team/repo}\n").replace("run_attempt: 1","run_attempt: '${steps.previous.result.runs[0].run_attempt}'");
    assert!(parse(&previous).is_err());
}
