//! The request state machine: one table of which event may move a request
//! from which state, and to which.
//!
//! A request's state is the store's `request.state` column. Every change to
//! it is one store call whose SQL guard accepts only some current states, and
//! four daemon modules decide when to make those calls: the queue (admission,
//! placement, leases, parked checkpoints, cancellation, expiry, the
//! stranded-row reconciler), the terminal writer, boot recovery
//! ([`crate::lifecycle`]) and the approval wait (the flow run's step approval).
//! This module is where the legal transitions are written down once. Each
//! writer names its event and takes the state the event leads to from
//! [`target`] or, where it knows the current state, asks [`transition`]. The
//! store's guard stays the last line of defence: a write the table allows but
//! the row no longer qualifies for (it finished meanwhile) matches nothing,
//! and the store refuses it or makes it the first-wins no-op.
//!
//! | Event | From | To | Store call |
//! | --- | --- | --- | --- |
//! | [`RequestEvent::Admit`] | no row | `running` | `Store::insert_admitted_request_from` |
//! | [`RequestEvent::Place`] | `running`, `waiting_approval` | `queued` | `Store::authorize_queued_request` |
//! | [`RequestEvent::Lease`] | `queued` | `running` | `Store::start_queued_request` |
//! | [`RequestEvent::Park`] | `running` | `queued` | `Store::park_flow_request` |
//! | [`RequestEvent::Wake`] | `queued` | `queued` | `Store::wake_parked_flow_request` |
//! | [`RequestEvent::AwaitApproval`] | any in flight | `waiting_approval` | `Store::insert_approval_waiting` |
//! | [`RequestEvent::Resume`] | any in flight | `running` | `Store::update_request_state` |
//! | [`RequestEvent::Requeue`] | `running`, `waiting_approval` | `queued` | `Store::requeue_journaled_flow` |
//! | [`RequestEvent::Finish`] | any in flight | the terminal state | `Store::finish_request`, `Store::fail_expired_requests` |
//!
//! "In flight" is `queued`, `running` and `waiting_approval`. A terminal
//! request (`done`, `refused`, `failed`) never leaves its state: every event
//! on it is refused ([`TransitionRefusal::AlreadyTerminal`]). The store
//! guards add conditions the table does not model (the admission still
//! stands, the expiry is ahead, the capability is `flow.run`, the journal is
//! at a safe checkpoint); they can only narrow what the table allows.

use pam_store::RequestState;

/// What happens to a request. See the module docs for the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestEvent {
    /// Admission inserts the row, born `running` with its absolute expiry.
    Admit,
    /// The gate allowed it: it joins its repository's lane.
    Place,
    /// Leased off its lane to run.
    Lease,
    /// A `flow.run` watch keeps its admission until its next poll.
    Park,
    /// A parked checkpoint is due and rejoins its lane.
    Wake,
    /// A human must approve before it carries on.
    AwaitApproval,
    /// The approval was granted and the run carries on.
    Resume,
    /// Boot recovery requeues a journaled flow at a safe checkpoint.
    Requeue,
    /// A terminal verdict, carrying the terminal state.
    Finish(RequestState),
}

/// Why the table refuses an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionRefusal {
    /// [`RequestEvent::Finish`] was handed a state that is not terminal.
    NotTerminal {
        /// The offending state.
        state: RequestState,
    },
    /// The request is terminal and never changes again.
    AlreadyTerminal {
        /// Its terminal state.
        state: RequestState,
    },
    /// There is no request row for an event other than admission.
    NotAdmitted,
    /// Admission of a request that already has a row.
    AlreadyAdmitted,
    /// The event is not legal from this in-flight state.
    Illegal {
        /// The current state.
        from: RequestState,
        /// The refused event.
        event: RequestEvent,
    },
}

/// The in-flight states: every state a request can still leave.
pub const IN_FLIGHT: [RequestState; 3] = [
    RequestState::Queued,
    RequestState::Running,
    RequestState::WaitingApproval,
];

/// The states `event` may start from (empty for [`RequestEvent::Admit`],
/// which starts from no row).
#[must_use]
pub fn sources(event: RequestEvent) -> &'static [RequestState] {
    match event {
        RequestEvent::Admit => &[],
        RequestEvent::Place | RequestEvent::Requeue => {
            &[RequestState::Running, RequestState::WaitingApproval]
        }
        RequestEvent::Lease | RequestEvent::Wake => &[RequestState::Queued],
        RequestEvent::Park => &[RequestState::Running],
        RequestEvent::AwaitApproval | RequestEvent::Resume | RequestEvent::Finish(_) => &IN_FLIGHT,
    }
}

/// The state `event` leads to, whatever it starts from; refused only for a
/// [`RequestEvent::Finish`] that carries a non-terminal state. A writer that
/// leaves the from-state check to the store's guard takes its target here.
pub fn target(event: RequestEvent) -> Result<RequestState, TransitionRefusal> {
    Ok(match event {
        RequestEvent::Admit | RequestEvent::Lease | RequestEvent::Resume => RequestState::Running,
        RequestEvent::Place | RequestEvent::Park | RequestEvent::Wake | RequestEvent::Requeue => {
            RequestState::Queued
        }
        RequestEvent::AwaitApproval => RequestState::WaitingApproval,
        RequestEvent::Finish(state) if state.is_terminal() => state,
        RequestEvent::Finish(state) => return Err(TransitionRefusal::NotTerminal { state }),
    })
}

/// The transition table: where `event` takes a request that is in `from`
/// (`None`: no row yet), or why it may not.
pub fn transition(
    from: Option<RequestState>,
    event: RequestEvent,
) -> Result<RequestState, TransitionRefusal> {
    let to = target(event)?;
    match (from, event) {
        (None, RequestEvent::Admit) => Ok(to),
        (None, _) => Err(TransitionRefusal::NotAdmitted),
        (Some(_), RequestEvent::Admit) => Err(TransitionRefusal::AlreadyAdmitted),
        (Some(state), _) if state.is_terminal() => {
            Err(TransitionRefusal::AlreadyTerminal { state })
        }
        (Some(state), _) if sources(event).contains(&state) => Ok(to),
        (Some(from), _) => Err(TransitionRefusal::Illegal { from, event }),
    }
}
