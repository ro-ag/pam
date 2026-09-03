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
