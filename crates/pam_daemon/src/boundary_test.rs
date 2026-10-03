//! The boundary observer with an injected process table: classification,
//! bounded resolution, the request-row facts, unknown harnesses, admin
//! contacts (expected and not, deduplicated), the sink registry, the
//! observed stream, and the `status` block.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pam_store::{
    BoundaryCensus, BoundaryObservationInsert, BoundaryPeer, OBSERVATION_ADMIN_CONTACT,
    OBSERVATION_ADMIN_HANDSHAKE_FAILED, OBSERVATION_PUBLIC_UNKNOWN_HARNESS, RequestIngress,
    RequestOrigin, Store,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

use crate::boundary::{
    AdminContact, Boundary, Observed, PeerFacts, PeerResolver, ResolvedPeer, admin_sink_for,
    harness_agreement, never_checked_block, register_admin_sink, summary,
};
use crate::framed::Accept;
use crate::ingress::PeerIdentity;

const IMAGE: &str = "/Applications/PAM.app/Contents/MacOS/pam";
const OTHER_EXE: &str = "/usr/local/bin/pam";

/// A process table: pid → (exe, ancestors nearest first). `slow` pids take
/// longer than the resolution budget.
#[derive(Default)]
struct FakeResolver {
    table: HashMap<u32, ResolvedPeer>,
    slow: Vec<u32>,
}

impl FakeResolver {
    fn with(mut self, pid: u32, exe: &str, chain: &[&str]) -> Self {
        self.table.insert(
            pid,
            ResolvedPeer {
                exe: Some(PathBuf::from(exe)),
                chain: chain.iter().map(|name| (*name).to_owned()).collect(),
            },
        );
        self
    }
}

impl PeerResolver for FakeResolver {
    fn resolve(&self, pid: u32) -> ResolvedPeer {
        if self.slow.contains(&pid) {
            std::thread::sleep(crate::boundary::RESOLVE_BUDGET * 3);
        }
        self.table.get(&pid).cloned().unwrap_or_default()
    }
}

fn resolver() -> FakeResolver {
    FakeResolver::default()
        .with(100, OTHER_EXE, &["zsh", "claude", "launchd"])
        .with(200, OTHER_EXE, &["python3", "zsh"])
        .with(300, IMAGE, &["launchd"])
        .with(400, OTHER_EXE, &["zsh"])
}

async fn boundary(resolver: FakeResolver) -> (Arc<Store>, Arc<Boundary>) {
    let store = Arc::new(Store::open_in_memory().await.unwrap());
    let boundary = Boundary::new(
        Arc::clone(&store),
        Some(PathBuf::from(IMAGE)),
        Arc::new(resolver),
    );
    boundary.load().await;
    (store, boundary)
}

fn public(pid: u32) -> RequestOrigin {
    RequestOrigin {
        ingress: RequestIngress::Public,
        peer_uid: Some(501),
        peer_pid: Some(pid),
        relayed: false,
    }
}

async fn request(store: &Store, id: &str, origin: &RequestOrigin) {
    store
        .insert_admitted_request_from(
            id,
            "echo",
            "/repo",
            "claude",
            "{}",
            None,
            9_000_000_000_000,
            origin,
        )
        .await
        .unwrap();
}

fn unix(pid: u32) -> PeerIdentity {
    PeerIdentity::Unix {
        uid: 501,
        gid: 20,
        pid: Some(pid),
    }
}

#[test]
fn classification_follows_the_shared_table_and_the_relay_marker() {
    let resolved = ResolvedPeer {
        exe: Some(PathBuf::from(OTHER_EXE)),
        chain: vec!["zsh".to_owned(), "claude".to_owned()],
    };
    let facts = PeerFacts::classify(&resolved, false);
    assert_eq!(facts.exe.as_deref(), Some(OTHER_EXE));
    assert_eq!(facts.harness.as_deref(), Some("claude"));

    let relayed = PeerFacts::classify(&resolved, true);
    assert_eq!(relayed.harness.as_deref(), Some("relay"));

    let verbatim = PeerFacts::classify(
        &ResolvedPeer {
            exe: None,
            chain: vec!["python3".to_owned()],
        },
        false,
    );
    assert_eq!(verbatim.harness.as_deref(), Some("python3"));
    assert!(verbatim.exe.is_none());

    let empty = PeerFacts::classify(&ResolvedPeer::default(), false);
    assert!(empty.is_empty());
    assert!(empty.harness.is_none());
}

/// `harness_agrees` is three-valued: `false` only when both sides know
/// and differ. A sandboxed client whose `/bin/ps` cannot exec claims
/// `unknown`, a relayed peer is seen as `relay`, and a daemon with no
/// resolution sees nothing — each is undetermined, never a disagreement.
#[test]
fn harness_agreement_is_undetermined_unless_both_sides_know() {
    assert_eq!(harness_agreement(Some("claude"), "claude"), Some(true));
    assert_eq!(harness_agreement(Some("claude"), "codex"), Some(false));
    assert_eq!(harness_agreement(Some("zsh"), "zsh"), Some(true));
    // The client's walk produced nothing: `classify_chain(&[])`.
    assert_eq!(
        harness_agreement(Some("claude"), &pam_proto::caller::classify_chain(&[])),
        None
    );
    assert_eq!(harness_agreement(Some("claude"), "unknown"), None);
    // The daemon sees the relay process, not the client.
    assert_eq!(harness_agreement(Some("relay"), "claude"), None);
    assert_eq!(harness_agreement(Some("relay"), "relay"), None);
    // The daemon resolved nothing (Windows, a missed budget).
    assert_eq!(harness_agreement(None, "claude"), None);
    assert_eq!(harness_agreement(None, "unknown"), None);
}

#[tokio::test]
async fn resolution_is_bounded_and_a_miss_is_null() {
    let (_store, boundary) = boundary(FakeResolver {
        slow: vec![999],
        ..resolver()
    })
    .await;
    assert_eq!(
        boundary.resolve(Some(100), false).await,
        PeerFacts {
            exe: Some(OTHER_EXE.to_owned()),
            harness: Some("claude".to_owned()),
        }
    );
    assert!(boundary.resolve(None, false).await.is_empty());
    assert!(boundary.resolve(Some(12345), false).await.is_empty());
    let started = std::time::Instant::now();
    let slow = boundary.resolve(Some(999), false).await;
    assert!(slow.is_empty());
    assert!(started.elapsed() < crate::boundary::RESOLVE_BUDGET * 2);
    // The relay marker survives a miss: it is the hello's own statement.
    assert_eq!(
        boundary.resolve(Some(12345), true).await.harness.as_deref(),
        Some("relay")
    );
}

#[tokio::test]
async fn an_unknown_harness_is_neither_a_known_agent_nor_the_relay_nor_the_image() {
    let (_store, boundary) = boundary(resolver()).await;
    let facts = |exe: Option<&str>, harness: Option<&str>| PeerFacts {
        exe: exe.map(str::to_owned),
        harness: harness.map(str::to_owned),
    };
    assert!(!boundary.is_unknown_harness(&facts(Some(OTHER_EXE), Some("claude"))));
    assert!(!boundary.is_unknown_harness(&facts(Some(OTHER_EXE), Some("relay"))));
    assert!(!boundary.is_unknown_harness(&facts(Some(IMAGE), Some("launchd"))));
    assert!(!boundary.is_unknown_harness(&facts(Some(OTHER_EXE), None)));
    assert!(boundary.is_unknown_harness(&facts(Some(OTHER_EXE), Some("python3"))));
    assert!(boundary.is_unknown_harness(&facts(None, Some("zsh"))));
}

#[tokio::test]
async fn a_public_request_gets_its_facts_on_the_row_and_an_unknown_harness_is_counted_once_per_window()
 {
    let (store, boundary) = boundary(resolver()).await;
    for (id, pid) in [
        ("req_claude", 100),
        ("req_py", 200),
        ("req_py_again", 200),
        ("req_gui", 300),
    ] {
        let origin = public(pid);
        request(&store, id, &origin).await;
        let facts = boundary.resolve(Some(pid), false).await;
        boundary.note_public_request(id, &origin, &facts).await;
    }
    assert_eq!(
        store.request_peer_facts("req_claude").await.unwrap(),
        Some((Some(OTHER_EXE.to_owned()), Some("claude".to_owned())))
    );
    assert_eq!(
        store.request_peer_facts("req_py").await.unwrap(),
        Some((Some(OTHER_EXE.to_owned()), Some("python3".to_owned())))
    );
    assert_eq!(
        store.request_peer_facts("req_gui").await.unwrap(),
        Some((Some(IMAGE.to_owned()), Some("launchd".to_owned())))
    );
    // One row for the two python requests (same pid, inside the window);
    // the counter saw both.
    let rows = store.list_boundary_observations(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, OBSERVATION_PUBLIC_UNKNOWN_HARNESS);
    assert_eq!(rows[0].peer.pid, Some(200));
    assert_eq!(rows[0].peer.harness.as_deref(), Some("python3"));
    assert_eq!(rows[0].detail.as_deref(), Some("req_py"));
    let block = boundary.status_block();
    assert_eq!(block["public_unknown_harness"]["total"], 2);
    assert_eq!(block["public_unknown_harness"]["last"]["peer_pid"], 200);
    assert_eq!(block["last_report"], serde_json::Value::Null);

    // Nothing resolved: nothing written, no error.
    request(&store, "req_bare", &RequestOrigin::PUBLIC).await;
    boundary
        .note_public_request("req_bare", &RequestOrigin::PUBLIC, &PeerFacts::default())
        .await;
    assert_eq!(
        store.request_peer_facts("req_bare").await.unwrap(),
        Some((None, None))
    );
}

#[tokio::test]
async fn admin_contacts_are_recorded_with_the_resolved_peer_and_the_image_marks_them_expected() {
    let (store, boundary) = boundary(resolver()).await;
    // The doctor's probe: accepted, nothing sent, from a foreign executable.
    boundary
        .observe_admin_contact(AdminContact::Accepted {
            peer: unix(400),
            spoke: false,
        })
        .await;
    // The GUI: a hello from the daemon's own image.
    boundary
        .observe_admin_contact(AdminContact::Accepted {
            peer: unix(300),
            spoke: true,
        })
        .await;
    // Something else speaking on the private socket.
    boundary
        .observe_admin_contact(AdminContact::Accepted {
            peer: unix(200),
            spoke: true,
        })
        .await;
    // The daemon's own image that connected and said nothing is still a
    // contact to explain (a doctor run from the installed binary).
    boundary
        .observe_admin_contact(AdminContact::Accepted {
            peer: unix(300),
            spoke: false,
        })
        .await;
    boundary
        .observe_admin_contact(AdminContact::HandshakeFailed)
        .await;

    let rows = store.list_boundary_observations(10).await.unwrap();
    assert_eq!(rows.len(), 5);
    let find = |pid: Option<u32>, spoke_detail: &str| {
        rows.iter()
            .find(|row| row.peer.pid == pid && row.detail.as_deref() == Some(spoke_detail))
            .unwrap_or_else(|| panic!("{pid:?} {spoke_detail}: {rows:?}"))
    };
    let probe = find(Some(400), "accepted; the peer sent nothing");
    assert_eq!(probe.kind, OBSERVATION_ADMIN_CONTACT);
    assert!(!probe.expected);
    assert_eq!(probe.peer.exe.as_deref(), Some(OTHER_EXE));
    assert_eq!(probe.peer.harness.as_deref(), Some("zsh"));
    assert_eq!(probe.peer.uid, Some(501));
    let gui = find(Some(300), "hello from the daemon's own image");
    assert!(gui.expected);
    assert_eq!(gui.peer.exe.as_deref(), Some(IMAGE));
    let foreign = find(Some(200), "hello from another executable");
    assert!(!foreign.expected);
    let silent_image = find(Some(300), "accepted; the peer sent nothing");
    assert!(!silent_image.expected);
    let failed = find(None, "failed the owner-nonce handshake");
    assert_eq!(failed.kind, OBSERVATION_ADMIN_HANDSHAKE_FAILED);
    assert!(!failed.expected);

    let block = boundary.status_block();
    assert_eq!(block["admin_contacts"]["unattributed"], 4);
    assert_eq!(block["admin_contacts"]["unattributed_24h"], 4);
    assert_eq!(block["admin_contacts"]["total"], 4);
    assert_eq!(block["admin_contacts"]["expected_total"], 1);
    assert_eq!(block["admin_contacts"]["last_expected"]["peer_pid"], 300);
    assert_eq!(
        block["admin_contacts"]["last"]["kind"],
        OBSERVATION_ADMIN_HANDSHAKE_FAILED
    );
    assert_eq!(
        block["summary"],
        "never checked — run pam doctor from the agent"
    );
}

#[tokio::test]
async fn repeated_contacts_from_one_pid_write_one_row_and_move_the_counter() {
    let (store, boundary) = boundary(resolver()).await;
    for _ in 0..3 {
        boundary
            .observe_admin_contact(AdminContact::Accepted {
                peer: unix(400),
                spoke: false,
            })
            .await;
    }
    for _ in 0..3 {
        boundary
            .observe_admin_contact(AdminContact::Accepted {
                peer: unix(300),
                spoke: true,
            })
            .await;
    }
    let rows = store.list_boundary_observations(10).await.unwrap();
    assert_eq!(rows.len(), 2);
    let block = boundary.status_block();
    assert_eq!(block["admin_contacts"]["unattributed"], 1);
    assert_eq!(block["admin_contacts"]["total"], 3);
    assert_eq!(block["admin_contacts"]["expected_total"], 3);
}

#[tokio::test]
async fn a_contact_after_a_report_from_the_same_pid_is_born_attributed() {
    let (store, boundary) = boundary(resolver()).await;
    // Seed a report the way the capability does, then a contact.
    let origin = public(400);
    request(&store, "req_doc", &origin).await;
    store
        .insert_boundary_report(
            pam_store::BoundaryReportInsert {
                request_id: "req_doc",
                report_ts: 1,
                verdict: "established",
                failed_json: "[]",
                unverified_json: "[]",
                agent: "claude",
                repo: "/repo",
                peer: &BoundaryPeer::default(),
                relayed: false,
                client_version: "0",
                report_json: "{}",
            },
            pam_store::AuditEntry {
                action: "doctor.report",
                decision: pam_store::Decision::Allow,
                actor: pam_store::Actor::System,
                detail: None,
            },
        )
        .await
        .unwrap();
    // The in-memory memory of recent reports is what attributes a later
    // contact; it is filled by `record_report`, exercised in the executor
    // tests. Here the store-side attribution of an earlier contact:
    store
        .insert_boundary_observation(BoundaryObservationInsert {
            kind: OBSERVATION_ADMIN_CONTACT,
            expected: false,
            peer: &BoundaryPeer {
                pid: Some(400),
                ..BoundaryPeer::default()
            },
            detail: None,
            attributed: None,
        })
        .await
        .unwrap();
    boundary.load().await;
    let block = boundary.status_block();
    assert_eq!(block["admin_contacts"]["unattributed"], 1);
    assert_eq!(block["last_report"]["verdict"], "established");
    assert_eq!(block["last_report"]["request_id"], "req_doc");
    assert_eq!(block["reports"]["retained"], 1);
    assert_eq!(block["reports"]["established"], 1);
    assert!(block["last_report"]["age_s"].is_u64());
    assert_eq!(block["peer_identity"], crate::boundary::PEER_IDENTITY);
}

#[test]
fn the_summary_line_names_the_verdict_its_age_the_sender_and_the_unexplained_contacts() {
    let mut census = BoundaryCensus::default();
    assert_eq!(
        summary(&census, 1_000),
        "never checked — run pam doctor from the agent"
    );
    census.last_report = Some(pam_store::BoundaryReportRow {
        id: 1,
        request_id: Some("req_1".to_owned()),
        ts: 1_000,
        report_ts: 999,
        verdict: "established".to_owned(),
        failed: Vec::new(),
        unverified: Vec::new(),
        agent: "claude".to_owned(),
        repo: "/repo".to_owned(),
        peer: BoundaryPeer {
            pid: Some(48_122),
            ..BoundaryPeer::default()
        },
        relayed: false,
        client_version: "0".to_owned(),
        report_json: "{}".to_owned(),
    });
    assert_eq!(
        summary(&census, 1_420),
        "established 7 min ago by claude (pid 48122, direct); admin contacts unattributed: 0"
    );
    census.admin_unattributed = 2;
    let report = census.last_report.as_mut().unwrap();
    report.verdict = "not_established".to_owned();
    report.relayed = true;
    report.peer.pid = None;
    assert_eq!(
        summary(&census, 1_000 + 7_200),
        "not_established 2 h ago by claude (no pid, relay); admin contacts unattributed: 2"
    );
    assert!(summary(&census, 1_012).contains(" 12 s ago "));
    assert!(summary(&census, 1_000 + 3 * 86_400).contains(" 3 d ago "));
    // A clock that went backwards is not a negative age.
    assert!(summary(&census, 10).contains(" 0 s ago "));
}

#[test]
fn the_never_checked_block_has_every_member_and_no_report() {
    let block = never_checked_block();
    assert_eq!(block["last_report"], serde_json::Value::Null);
    assert_eq!(block["reports"]["retained"], 0);
    assert_eq!(block["admin_contacts"]["unattributed"], 0);
    assert_eq!(block["admin_contacts"]["last"], serde_json::Value::Null);
    assert_eq!(block["public_unknown_harness"]["total"], 0);
    assert_eq!(
        block["peer_identity"],
        if cfg!(unix) { "kernel_pid" } else { "none" }
    );
    assert_eq!(
        block["summary"],
        "never checked — run pam doctor from the agent"
    );
}

#[tokio::test]
async fn the_sink_registry_is_keyed_by_base_and_the_latest_registration_wins() {
    let (store, boundary) = boundary(resolver()).await;
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let (first, task_a) = boundary.spawn_admin_observer(shutdown.clone());
    let (second, task_b) = boundary.spawn_admin_observer(shutdown);
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("pam");
    std::fs::create_dir_all(&base).unwrap();
    assert!(admin_sink_for(&base).is_none());
    register_admin_sink(&base, first);
    assert!(admin_sink_for(&base).is_some());
    register_admin_sink(&base, second);
    // A different base is not confused with it.
    assert!(admin_sink_for(dir.path()).is_none());
    // The registered sink reaches the observer.
    std::fs::create_dir_all(base.join("admin")).unwrap();
    admin_sink_for(&base.join("admin").join(".."))
        .unwrap()
        .record(AdminContact::Accepted {
            peer: unix(400),
            spoke: false,
        });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !store
                .list_boundary_observations(1)
                .await
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the observer recorded the contact");
    task_a.abort();
    task_b.abort();
}

/// Hands out scripted duplex streams as accepted connections.
struct Scripted {
    streams: VecDeque<(DuplexStream, PeerIdentity)>,
    closed: bool,
}

impl Accept for Scripted {
    type Stream = DuplexStream;

    fn accept(&mut self) -> impl Future<Output = io::Result<(DuplexStream, PeerIdentity)>> + Send {
        std::future::ready(
            self.streams
                .pop_front()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected)),
        )
    }

    fn reject(stream: DuplexStream, _frame: &[u8]) -> impl Future<Output = ()> + Send {
        drop(stream);
        std::future::ready(())
    }

    fn close(&mut self) {
        self.closed = true;
    }
}

#[tokio::test]
async fn an_observed_connection_reports_its_peer_and_whether_it_spoke_when_it_ends() {
    let (store, boundary) = boundary(resolver()).await;
    let (_shutdown_tx, shutdown) = watch::channel(false);
    let (sink, task) = boundary.spawn_admin_observer(shutdown);
    let (silent_server, silent_client) = tokio::io::duplex(64);
    let (talking_server, mut talking_client) = tokio::io::duplex(64);
    let (rejected_server, _rejected_client) = tokio::io::duplex(64);
    let mut acceptor = Observed::new(
        Scripted {
            streams: [
                (silent_server, unix(400)),
                (talking_server, unix(200)),
                (rejected_server, unix(100)),
            ]
            .into(),
            closed: false,
        },
        Some(sink),
    );

    let (silent, peer) = acceptor.accept().await.unwrap();
    assert_eq!(peer, unix(400));
    drop(silent_client);
    drop(silent);

    let (mut talking, _) = acceptor.accept().await.unwrap();
    talking_client.write_all(b"hello").await.unwrap();
    let mut buffer = [0u8; 5];
    talking.read_exact(&mut buffer).await.unwrap();
    talking.write_all(b"ack").await.unwrap();
    talking.flush().await.unwrap();
    let mut ack = [0u8; 3];
    talking_client.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"ack");
    drop(talking);

    // A rejected connection (over the cap) is not a contact.
    let (rejected, _) = acceptor.accept().await.unwrap();
    <Observed<Scripted> as Accept>::reject(rejected, b"full").await;
    acceptor.close();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if store.list_boundary_observations(10).await.unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("two contacts recorded");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rows = store.list_boundary_observations(10).await.unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let silent = rows.iter().find(|row| row.peer.pid == Some(400)).unwrap();
    assert_eq!(
        silent.detail.as_deref(),
        Some("accepted; the peer sent nothing")
    );
    let talking = rows.iter().find(|row| row.peer.pid == Some(200)).unwrap();
    assert_eq!(
        talking.detail.as_deref(),
        Some("hello from another executable")
    );
    task.abort();
}

#[test]
fn the_production_resolver_sees_this_process() {
    let resolved = crate::boundary::SystemResolver.resolve(std::process::id());
    let exe = std::env::current_exe().unwrap();
    assert_eq!(
        resolved
            .exe
            .as_deref()
            .and_then(|path| Path::canonicalize(path).ok()),
        exe.canonicalize().ok()
    );
    // Our ancestors exist (cargo, a shell, ...) and the walk is bounded.
    assert!(!resolved.chain.is_empty());
    assert!(resolved.chain.len() <= pam_proto::caller::MAX_CHAIN_DEPTH);
    assert!(
        crate::boundary::SystemResolver
            .resolve(u32::MAX - 1)
            .exe
            .is_none()
    );
}
