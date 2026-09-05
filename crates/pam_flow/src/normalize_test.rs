use super::normalize::{digest, to_normalized_yaml};
use super::validate::parse;

/// Spelled out the long way: defaults written explicitly, inputs out of
/// order, and a second step that differs from every default.
const SOURCE: &str = r"
schema: 1
id: demo
name: Demo flow
description: A demo.
inputs:
  zebra:
    description: last
  repo:
    description: first
    default: '${repo.origin}'
steps:
  - id: b
    run: [git, status, --short]
    timeout: 300s
    effect: read_only
    role: observe
    output: compact
    when: needs_succeeded
    retry: { attempts: 1, backoff: 500ms }
    approval: none
  - id: a
    connector: github
    call: runs
    with: { repo: '${inputs.repo}', limit: 5 }
    timeout: 90s
    output: summarize
    needs: [b]
    when: { failed: b }
    retry: { attempts: 3, backoff: 2s }
";

fn normalized(yaml: &str) -> String {
    to_normalized_yaml(&parse(yaml).expect("valid flow"))
}

#[test]
fn renders_canonical_yaml_with_defaults_omitted() {
    assert_eq!(
        normalized(SOURCE),
        "schema: 1\n\
         id: demo\n\
         name: Demo flow\n\
         description: A demo.\n\
         inputs:\n  \
           repo:\n    \
             description: first\n    \
             default: ${repo.origin}\n  \
           zebra:\n    \
             description: last\n\
         steps:\n\
         - id: b\n  \
           run:\n  \
           - git\n  \
           - status\n  \
           - --short\n\
         - id: a\n  \
           connector: github\n  \
           call: runs\n  \
           with:\n    \
             limit: 5\n    \
             repo: ${inputs.repo}\n  \
           timeout: 90s\n  \
           output: summarize\n  \
           needs:\n  \
           - b\n  \
           when:\n    \
             failed: b\n  \
           retry:\n    \
             attempts: 3\n    \
             backoff: 2s\n"
    );
}

#[test]
fn the_rendering_is_stable_and_idempotent() {
    let once = normalized(SOURCE);
    assert_eq!(once, normalized(SOURCE), "two parses render alike");
    assert_eq!(once, normalized(&once), "re-parsing changes nothing");
}

#[test]
fn re_parsing_the_rendering_gives_an_equal_flow() {
    let flow = parse(SOURCE).expect("valid flow");
    let again = parse(&to_normalized_yaml(&flow)).expect("normalized form is valid");
    assert_eq!(flow, again);
}

#[test]
fn formatting_alone_does_not_change_the_digest() {
    let spaced = SOURCE.replace("  - id: b", "\n\n  - id: b");
    let flow = parse(SOURCE).expect("valid flow");
    let respaced = parse(&spaced).expect("valid flow");
    assert_eq!(digest(&flow), digest(&respaced));
    assert_eq!(digest(&flow).len(), 64);
    assert!(digest(&flow).chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn content_changes_the_digest() {
    let flow = parse(SOURCE).expect("valid flow");
    let renamed = parse(&SOURCE.replace("name: Demo flow", "name: Demo")).expect("valid flow");
    let retimed = parse(&SOURCE.replace("timeout: 90s", "timeout: 91s")).expect("valid flow");
    assert_ne!(digest(&flow), digest(&renamed));
    assert_ne!(digest(&flow), digest(&retimed));
}

#[test]
fn a_stateful_step_keeps_its_forced_approval_visible() {
    let yaml = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: push\n    run: [git, push]\n    effect: stateful\n";
    assert_eq!(
        normalized(yaml),
        "schema: 1\nid: demo\nname: Demo\nsteps:\n- id: push\n  run:\n  - git\n  - push\n  effect: stateful\n  approval: required\n"
    );
}

#[test]
fn an_empty_description_and_empty_maps_disappear() {
    let yaml = "schema: 1\nid: demo\nname: Demo\ndescription: ''\nsteps:\n  - id: a\n    connector: aws\n    call: commands\n";
    assert_eq!(
        normalized(yaml),
        "schema: 1\nid: demo\nname: Demo\nsteps:\n- id: a\n  connector: aws\n  call: commands\n"
    );
}

#[test]
fn a_note_is_the_last_step_key_and_round_trips_a_block_scalar() {
    let yaml = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    note: |\n      Check the tree first.\n      Stale files hide real failures.\n    run: [git, status]\n    env: { CARGO_TERM_COLOR: never }\n";
    let once = normalized(yaml);
    assert_eq!(
        once,
        "schema: 1\nid: demo\nname: Demo\nsteps:\n- id: a\n  run:\n  - git\n  - status\n  env:\n    CARGO_TERM_COLOR: never\n  note: |-\n    Check the tree first.\n    Stale files hide real failures.\n"
    );
    assert_eq!(once, normalized(&once), "a two-line note is idempotent");
    assert_eq!(
        parse(&once).expect("normalized form is valid").steps[0].note,
        "Check the tree first.\nStale files hide real failures."
    );
}

#[test]
fn an_empty_note_disappears_and_only_a_real_note_moves_the_digest() {
    let plain = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [git, status]\n";
    let blank = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [git, status]\n    note: '   '\n";
    let noted = "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: a\n    run: [git, status]\n    note: Read this first.\n";
    assert_eq!(normalized(plain), normalized(blank));
    assert!(
        !normalized(blank).contains("note"),
        "a blank note is left out"
    );
    assert!(normalized(noted).ends_with("  note: Read this first.\n"));

    let plain = parse(plain).expect("valid flow");
    let blank = parse(blank).expect("valid flow");
    let noted = parse(noted).expect("valid flow");
    assert_eq!(digest(&plain), digest(&blank));
    assert_ne!(digest(&plain), digest(&noted));
}

#[test]
fn empty_output_assertion_survives_normalization_and_changes_digest() {
    let plain =
        parse("schema: 1\nid: clean\nname: Clean\nsteps:\n  - id: clean\n    run: [git, status]\n")
            .unwrap();
    let mut asserted = plain.clone();
    asserted.steps[0].expect_empty_output = true;
    let yaml = to_normalized_yaml(&asserted);
    assert!(yaml.contains("expect_empty_output: true"));
    assert_eq!(parse(&yaml).unwrap(), asserted);
    assert_ne!(digest(&plain), digest(&asserted));
    assert!(!to_normalized_yaml(&plain).contains("expect_empty_output"));
}

#[test]
fn connector_status_assertion_survives_normalization_and_changes_digest() {
    let plain = parse("schema: 1\nid: gate\nname: Gate\nsteps:\n  - id: gate\n    connector: sonarqube\n    call: quality_gate\n    with: { project: pam }\n").unwrap();
    let mut asserted = plain.clone();
    asserted.steps[0].expect_status = Some("OK".to_owned());
    let yaml = to_normalized_yaml(&asserted);
    assert!(yaml.contains("expect_status: OK"));
    assert_eq!(parse(&yaml).unwrap(), asserted);
    assert_ne!(digest(&plain), digest(&asserted));
    assert!(!to_normalized_yaml(&plain).contains("expect_status"));
}
