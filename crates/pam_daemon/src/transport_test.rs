//! What the transport does before and around the framed listener: the field
//! limits every envelope is held to on both planes, and the cleanup of what an
//! older daemon left in the run directory. The listener itself is covered in
//! `framed_test`, `public_transport_test` and the integration suites.

use pam_proto::{Caller, Envelope, PROTOCOL_VERSION, Response};

use crate::runtime_dir::RuntimeDir;
use crate::transport::{bad_request, envelope_within_limits, remove_superseded};

fn envelope() -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        id: "req_limits".to_owned(),
        capability: "echo".to_owned(),
        client_version: env!("CARGO_PKG_VERSION").to_owned(),
        caller: Caller {
            agent: "claude".to_owned(),
            repo: "/work/app".to_owned(),
            pid: 4242,
        },
        args: serde_json::json!({}),
        idempotency_key: Some("key".to_owned()),
        deadline_ms: 60_000,
        wait: true,
    }
}

/// Each identity and scope field is carried at its ceiling and refused one
/// byte over it; an empty id names no request and is refused too.
#[test]
fn every_envelope_field_is_bounded_at_its_own_ceiling() {
    type Set = fn(&mut Envelope, String);
    assert!(envelope_within_limits(&envelope()));

    let fields: [(&str, usize, Set); 6] = [
        ("id", 128, |envelope, text| envelope.id = text),
        ("capability", 128, |envelope, text| {
            envelope.capability = text;
        }),
        ("client_version", 128, |envelope, text| {
            envelope.client_version = text;
        }),
        ("caller.agent", 128, |envelope, text| {
            envelope.caller.agent = text;
        }),
        ("caller.repo", 4096, |envelope, text| {
            envelope.caller.repo = text;
        }),
        ("idempotency_key", 128, |envelope, text| {
            envelope.idempotency_key = Some(text);
        }),
    ];
    for (field, ceiling, set) in fields {
        let mut at = envelope();
        set(&mut at, "x".repeat(ceiling));
        assert!(envelope_within_limits(&at), "{field} at {ceiling} bytes");
        let mut over = envelope();
        set(&mut over, "x".repeat(ceiling + 1));
        assert!(
            !envelope_within_limits(&over),
            "{field} at {} bytes",
            ceiling + 1
        );
    }

    let mut unnamed = envelope();
    unnamed.id.clear();
    assert!(!envelope_within_limits(&unnamed));
    let mut keyless = envelope();
    keyless.idempotency_key = None;
    assert!(envelope_within_limits(&keyless));
}

#[test]
fn a_bad_request_refusal_names_the_request_and_is_final() {
    let Response::Refusal {
        id,
        cause,
        detail,
        recovery,
        retryable,
    } = bad_request("req_named".to_owned(), "cannot parse request envelope")
    else {
        panic!("expected a refusal");
    };
    assert_eq!(
        (id.as_str(), cause.as_str(), retryable),
        ("req_named", "bad_request", false)
    );
    assert_eq!(detail, "cannot parse request envelope");
    assert!(recovery.contains("GUI"), "recovery: {recovery}");
}

/// The names an older daemon bound and this one does not serve are cleared
/// from the run directory; everything else there is left alone, and a
/// directory that never held them is fine.
#[test]
fn files_an_older_daemon_left_are_removed_and_nothing_else_is() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dirs = RuntimeDir::at_base(tmp.path()).expect("runtime dir");
    let run = dirs.run_dir();
    // Nothing to remove: not an error, nothing created.
    remove_superseded(&dirs);
    assert_eq!(std::fs::read_dir(run).unwrap().count(), 0);

    for name in ["events.sock", "pam.next.sock", "daemon.lock", "public.json"] {
        std::fs::write(run.join(name), b"left behind").expect("write");
    }
    std::fs::write(dirs.public_socket(), b"left behind").expect("write");
    remove_superseded(&dirs);
    assert!(!run.join("events.sock").exists());
    assert!(!run.join("pam.next.sock").exists());
    assert!(run.join("daemon.lock").exists());
    assert!(run.join("public.json").exists());
    // On unix the listener's own bind replaces a stale `pam.sock`; on
    // Windows nothing binds there, so the leftover goes here: a client takes
    // one beside a held lock for a pre-migration daemon.
    assert_eq!(dirs.public_socket().exists(), cfg!(unix));
}
