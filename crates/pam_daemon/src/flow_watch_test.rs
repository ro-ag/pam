use super::flow_watch::{State, admit_next, next_delay, normalize, validate_pins};
use pam_flow::ConnectorId;
use serde_json::json;
use std::time::Duration;

fn github() -> serde_json::Value {
    json!({"watch_state":"terminal","status":"completed","conclusion":"success","run_id":7,"run_attempt":2,"source_identity":{"status":"unambiguous","repository_urls":["https://github.com/team/repo.git"],"revisions":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"partial":false,"invalid_metadata":false}})
}

#[test]
fn stable_digest_excludes_poll_time_and_diagnostic_noise_but_tracks_real_change() {
    let first = github();
    let mut later = first.clone();
    later["polls"] = json!(90);
    later["timestamp"] = json!(123);
    later["raw_log"] = json!("ignored");
    let a = normalize(ConnectorId::Github, &first).unwrap();
    let b = normalize(ConnectorId::Github, &later).unwrap();
    assert_eq!(a.digest, b.digest);
    assert_eq!(a.state, State::Terminal);
    assert!(b.payload.get("raw_log").is_none());
    later["conclusion"] = json!("failure");
    assert_ne!(
        a.digest,
        normalize(ConnectorId::Github, &later).unwrap().digest
    );
}

#[test]
fn terminal_collection_cannot_swap_attempt_commit_or_analysis() {
    let previous = normalize(ConnectorId::Github, &github()).unwrap().payload;
    let current = github();
    assert!(validate_pins(ConnectorId::Github, &previous, &current).is_ok());
    let mut changed = current.clone();
    changed["run_attempt"] = json!(3);
    assert!(validate_pins(ConnectorId::Github, &previous, &changed).is_err());
    changed = current;
    changed["source_identity"]["revisions"] = json!(["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]);
    assert!(validate_pins(ConnectorId::Github, &previous, &changed).is_err());
    let ce = json!({"project":"p","ce_task":"t","identity":{"component_key":"p","branch":"main","pull_request":null},"analysis_id":"a"});
    let mut changed = ce.clone();
    changed["analysis_id"] = json!("other");
    assert!(validate_pins(ConnectorId::Sonarqube, &ce, &changed).is_err());
}

#[test]
fn malformed_and_oversized_identity_cannot_be_normalized() {
    let mut value = github();
    value["watch_state"] = json!("pending");
    assert!(normalize(ConnectorId::Github, &value).is_err());
    value = github();
    value["source_identity"]["repository_urls"] = json!(["x".repeat(2049)]);
    assert!(normalize(ConnectorId::Github, &value).is_err());
    value = github();
    value["run_id"] = json!(-1);
    assert!(normalize(ConnectorId::Github, &value).is_err());
}

#[test]
fn backoff_respects_policy_caps_and_never_shortens_retry_after() {
    let s = Duration::from_secs;
    assert_eq!(next_delay(s(5), s(300), 1, None), s(5));
    assert_eq!(next_delay(s(5), s(300), 3, None), s(20));
    assert_eq!(next_delay(s(10), s(30), u32::MAX, None), s(30));
    assert_eq!(next_delay(s(5), s(300), u32::MAX, Some(s(900))), s(900));
}

#[test]
fn polling_preserves_collection_headroom_and_original_deadline() {
    let check = |polls, max, outages, http, remaining, delay| {
        admit_next(
            ConnectorId::Jenkins,
            polls,
            max,
            outages,
            http,
            Duration::from_secs(remaining),
            Duration::from_secs(delay),
        )
    };
    assert!(check(0, 100, 0, 41, 100, 5).is_ok());
    assert!(check(0, 100, 0, 40, 100, 5).is_err());
    assert!(check(100, 200, 0, 100, 100, 5).is_err());
    assert!(check(3, 3, 0, 100, 100, 5).is_err());
    assert!(check(0, 100, 3, 100, 100, 5).is_err());
    assert!(check(0, 100, 0, 100, 5, 5).is_err());
}
