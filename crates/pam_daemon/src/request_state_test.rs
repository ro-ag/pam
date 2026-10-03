use pam_store::{Actor, AuditEntry, Decision, RequestOrigin, RequestState, Store, StoreError};

use crate::request_state::{
    IN_FLIGHT, RequestEvent, TransitionRefusal, sources, target, transition,
};

use RequestState::{Done, Failed, Queued, Refused, Running, WaitingApproval};

const STATES: [RequestState; 6] = [Queued, Running, WaitingApproval, Done, Refused, Failed];

/// Every event, `Finish` with each of the six states.
fn events() -> Vec<RequestEvent> {
    let mut events = vec![
        RequestEvent::Admit,
        RequestEvent::Place,
        RequestEvent::Lease,
        RequestEvent::Park,
        RequestEvent::Wake,
        RequestEvent::AwaitApproval,
        RequestEvent::Resume,
        RequestEvent::Requeue,
    ];
    events.extend(STATES.map(RequestEvent::Finish));
    events
}

/// The table, written out a second time by hand: for each event other than
/// admission, where it takes a `queued`, a `running` and a `waiting_approval`
/// request (`None`: illegal from there).
fn expected_in_flight(event: RequestEvent) -> [Option<RequestState>; 3] {
    match event {
        RequestEvent::Admit => unreachable!("admission starts from no row"),
        RequestEvent::Place | RequestEvent::Requeue => [None, Some(Queued), Some(Queued)],
        RequestEvent::Lease => [Some(Running), None, None],
        RequestEvent::Park => [None, Some(Queued), None],
        RequestEvent::Wake => [Some(Queued), None, None],
        RequestEvent::AwaitApproval => [Some(WaitingApproval); 3],
        RequestEvent::Resume => [Some(Running); 3],
        RequestEvent::Finish(state) => [Some(state); 3],
    }
}

/// Every (from, event) pair: seven starting points (no row and the six
/// states) by fourteen events.
#[test]
fn the_table_answers_every_state_and_event_pair() {
    let mut checked = 0;
    for from in std::iter::once(None).chain(STATES.map(Some)) {
        for event in events() {
            let got = transition(from, event);
            let want = match (from, event) {
                (_, RequestEvent::Finish(state)) if !state.is_terminal() => {
                    Err(TransitionRefusal::NotTerminal { state })
                }
                (None, RequestEvent::Admit) => Ok(Running),
                (None, _) => Err(TransitionRefusal::NotAdmitted),
                (Some(_), RequestEvent::Admit) => Err(TransitionRefusal::AlreadyAdmitted),
                (Some(state @ (Done | Refused | Failed)), _) => {
                    Err(TransitionRefusal::AlreadyTerminal { state })
                }
                (Some(state), _) => {
                    let column = IN_FLIGHT.iter().position(|s| *s == state).unwrap();
                    expected_in_flight(event)[column]
                        .ok_or(TransitionRefusal::Illegal { from: state, event })
                }
            };
            assert_eq!(got, want, "{from:?} --{event:?}-->");
            checked += 1;
        }
    }
    assert_eq!(checked, 7 * 14);
}

/// `sources` and `target` are the table read by columns: an event is legal
/// from exactly its sources (when it has a target at all: a `Finish` with a
/// non-terminal state has none), and always lands on its target.
#[test]
fn sources_and_target_agree_with_the_table() {
    for event in events() {
        for state in STATES {
            let legal = transition(Some(state), event).is_ok();
            assert_eq!(
                legal,
                sources(event).contains(&state) && target(event).is_ok(),
                "{state:?} {event:?}"
            );
            if legal {
                assert_eq!(transition(Some(state), event), target(event));
            }
        }
    }
    assert!(sources(RequestEvent::Admit).is_empty());
    assert!(IN_FLIGHT.iter().all(|state| !state.is_terminal()));
}

// --- the table against the store's own guards -------------------------------

const REPO: &str = "/repo/state";

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn audit() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

/// A fresh row driven to `state` through the store's own transitions.
async fn row_in(store: &Store, id: &str, state: RequestState) {
    store
        .insert_admitted_request_from(
            id,
            "echo",
            REPO,
            "agent",
            "{}",
            None,
            now_ms() + 60_000,
            &RequestOrigin::PUBLIC,
        )
        .await
        .unwrap();
    match state {
        Running => {}
        Queued => assert!(
            store
                .authorize_queued_request(id, REPO, now_ms())
                .await
                .unwrap()
        ),
        WaitingApproval => store.insert_approval_waiting(id, "echo").await.unwrap(),
        terminal => assert!(
            store
                .finish_request(id, terminal, Some("seeded"), audit())
                .await
                .unwrap()
        ),
    }
    assert_eq!(state_of(store, id).await, state);
}

async fn state_of(store: &Store, id: &str) -> RequestState {
    store.get_request(id).await.unwrap().unwrap().state
}

/// Applies `event` through the store call that implements it; `true` when
/// the store took the write.
async fn apply(store: &Store, id: &str, event: RequestEvent) -> bool {
    match event {
        RequestEvent::Place => store
            .authorize_queued_request(id, REPO, now_ms())
            .await
            .unwrap(),
        RequestEvent::Lease => store.start_queued_request(id, now_ms()).await.unwrap(),
        RequestEvent::Resume => match store.update_request_state(id, Running, None).await {
            Ok(()) => true,
            Err(StoreError::AlreadyTerminal { .. }) => false,
            Err(error) => panic!("{error}"),
        },
        RequestEvent::Finish(state) => store
            .finish_request(id, state, Some("checked"), audit())
            .await
            .unwrap(),
        other => unreachable!("{other:?} is not driven here"),
    }
}

/// For the events whose store call needs no flow journal or checkpoint, the
/// store's guard accepts a write from exactly the states the table allows,
/// and leaves the row where the table says. (The guard may refuse more for
/// reasons the table does not model; for these rows it does not.)
#[tokio::test]
async fn the_store_guards_accept_what_the_table_allows() {
    let store = Store::open_in_memory().await.unwrap();
    let driven = [
        RequestEvent::Place,
        RequestEvent::Lease,
        RequestEvent::Resume,
        RequestEvent::Finish(Done),
        RequestEvent::Finish(Refused),
        RequestEvent::Finish(Failed),
    ];
    let mut checked = 0;
    for (e, event) in driven.into_iter().enumerate() {
        for (s, from) in STATES.into_iter().enumerate() {
            let id = format!("row_{e}_{s}");
            row_in(&store, &id, from).await;
            let table = transition(Some(from), event);
            let took = apply(&store, &id, event).await;
            assert_eq!(
                took,
                table.is_ok(),
                "{from:?} --{event:?}--> store took={took}"
            );
            let now = state_of(&store, &id).await;
            assert_eq!(now, table.unwrap_or(from), "{from:?} --{event:?}-->");
            checked += 1;
        }
    }
    assert_eq!(checked, 6 * 6);
}
