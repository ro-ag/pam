//! The in-memory event hub behind [`EventPublisher`].
//!
//! Every lifecycle event a daemon service publishes lands here, under one
//! `std::sync::Mutex` that is never held across an await: [`EventPublisher::publish`]
//! appends and returns, and nothing in it waits on a peer. The hub then fans the
//! event out two ways:
//!
//! - **Followers** of that one ticket ([`EventHub::attach`]): each has its own
//!   bounded queue ([`FOLLOWER_QUEUE`]) and a wake-up, and receives the
//!   *sanitised* event — progress prose replaced by [`PUBLIC_PROGRESS_NOTE`].
//!   Task, product, repository and evidence details stay behind scoped result
//!   reads.
//! - **All-events subscribers** ([`EventHub::subscribe_all`]), for the private
//!   administration plane only: the unsanitised event plus the ticket's
//!   admission metadata ([`TicketMeta`]) and a daemon-wide counter.
//!
//! There is no broadcast: a public client sees the events of a ticket it was
//! authorised to follow and nothing else.
//!
//! Per live ticket the hub keeps a sequence counter (starting at 1), a replay
//! ring of the last [`REPLAY_RING`] sanitised events, the optional metadata and
//! the attached followers. An entry is created at first publish, first attach
//! or [`EventHub::register`], and removed when its terminal event (`done` or
//! `refused`) has been published, or by [`EventHub::unregister`] for a ticket
//! that ended without one. The table holds at most [`MAX_ENTRIES`]
//! tickets; beyond that the oldest entry with no followers is dropped, which
//! only loses replay.
//!
//! **Nothing here is the record.** Events are notifications: a slow follower
//! loses its oldest queued `progress` event first, and a lifecycle event only
//! when nothing else can go. The terminal condition is a flag, not a queue
//! entry, so it cannot be dropped; the durable result is in the store.
//!
//! Sequence numbers are per ticket and per [`EventHub::epoch`], a ULID minted
//! when the hub is built (once per daemon boot). A resuming follower that saw a
//! different epoch starts over.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pam_proto::Event;
use pam_proto::wire::{EventFrame, Frame, Ingress};
use thiserror::Error;
use tokio::sync::Notify;

/// Public progress carries no task-specific prose; details require scoped reads.
pub const PUBLIC_PROGRESS_NOTE: &str = "Task progress updated";

/// Public followers attached at once, across all tickets.
pub const MAX_FOLLOWERS: usize = 96;

/// Public followers attached to one ticket at once.
pub const MAX_FOLLOWERS_PER_TICKET: usize = 16;

/// Events one follower may have queued before the drop policy applies.
pub const FOLLOWER_QUEUE: usize = 64;

/// Sanitised events kept per live ticket for resume and late attach.
pub const REPLAY_RING: usize = 32;

/// Tickets the hub tracks at once.
pub const MAX_ENTRIES: usize = 512;

/// All-events subscribers attached at once.
pub const MAX_SUBSCRIBERS: usize = 4;

/// Events one all-events subscriber may have queued before it lags.
pub const SUBSCRIBER_QUEUE: usize = 1024;

/// Capacity of the channel [`EventPublisher::for_tests`] taps the hub with.
#[cfg(test)]
pub(crate) const TEST_TAP_CAPACITY: usize = 256;

/// The event hub was closed by shutdown; the event was dropped.
#[derive(Debug, Error)]
#[error("transport is shut down; event dropped")]
pub struct PublishError;

/// Why a follower could not attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AttachError {
    /// Every follower slot is taken.
    #[error("all 96 public follower slots are taken")]
    TotalCapacity,
    /// The ticket already has its share of followers.
    #[error("the ticket already has 16 followers")]
    TicketCapacity,
    /// The hub was closed by shutdown.
    #[error("the event hub is closed")]
    Closed,
}

/// Why an all-events subscriber could not attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SubscribeError {
    /// Every subscriber slot is taken.
    #[error("all 4 event subscriber slots are taken")]
    Capacity,
    /// The hub was closed by shutdown.
    #[error("the event hub is closed")]
    Closed,
}

/// What admission knows about a ticket, attached to the events the
/// administration plane sees. Registered with [`EventHub::register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketMeta {
    /// The capability the ticket runs.
    pub capability: String,
    /// The caller's repository as admitted.
    pub repo: String,
    /// The caller's self-reported agent label.
    pub agent: String,
    /// The plane the ticket was admitted on.
    pub ingress: Ingress,
}

/// One event as an all-events subscriber receives it: unsanitised, with the
/// ticket and its metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminEvent {
    /// Daemon-wide counter of published events; a gap means the subscriber
    /// missed events.
    pub n: u64,
    /// The ticket the event belongs to.
    pub ticket: String,
    /// The ticket's admission metadata, when it was registered.
    pub meta: Option<Arc<TicketMeta>>,
    /// The event, with its real progress note.
    pub event: Event,
}

impl AdminEvent {
    /// The `event` frame the administration plane writes for this event.
    #[must_use]
    pub fn into_frame(self) -> Frame {
        let meta = self.meta.as_deref();
        Frame::Event(EventFrame {
            seq: None,
            n: Some(self.n),
            ticket: Some(self.ticket),
            capability: meta.map(|meta| meta.capability.clone()),
            repo: meta.map(|meta| meta.repo.clone()),
            agent: meta.map(|meta| meta.agent.clone()),
            ingress: meta.map(|meta| meta.ingress),
            event: self.event,
        })
    }
}

/// How much the hub currently holds (for tests and inspection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubUsage {
    /// Tickets with an entry.
    pub entries: usize,
    /// Live [`Follower`] handles.
    pub followers: usize,
    /// Live [`Subscriber`] handles that have not lagged.
    pub subscribers: usize,
}

#[derive(Debug, Default)]
struct FollowerQueue {
    events: VecDeque<(u64, Event)>,
    /// The terminal event and its sequence number: a flag beside the queue,
    /// so the drop policy can never lose it.
    terminal: Option<(u64, Event)>,
    closed: bool,
}

#[derive(Debug, Default)]
struct FollowerShared {
    queue: Mutex<FollowerQueue>,
    wake: Notify,
}

#[derive(Debug, Default)]
struct SubscriberQueue {
    events: VecDeque<AdminEvent>,
    lagged: bool,
    closed: bool,
}

#[derive(Debug, Default)]
struct SubscriberShared {
    queue: Mutex<SubscriberQueue>,
    wake: Notify,
}

#[derive(Debug)]
struct SubscriberSlot {
    id: u64,
    shared: Arc<SubscriberShared>,
}

#[derive(Debug)]
struct Entry {
    /// Creation order, for evicting the oldest idle entry.
    born: u64,
    /// The latest sequence number published for the ticket.
    seq: u64,
    ring: VecDeque<(u64, Event)>,
    meta: Option<Arc<TicketMeta>>,
    followers: Vec<(u64, Arc<FollowerShared>)>,
    /// The ticket reached a terminal state without a terminal event
    /// ([`EventHub::unregister`]): the entry goes with its last follower.
    ended: bool,
}

#[derive(Debug, Default)]
struct State {
    closed: bool,
    entries: HashMap<String, Entry>,
    next_born: u64,
    next_id: u64,
    /// Live follower handles, including those whose entry has ended.
    followers: usize,
    subscribers: Vec<SubscriberSlot>,
    /// Events published since boot: the all-events stream's counter.
    published: u64,
    /// What [`EventPublisher::for_tests`] observes: the sanitised
    /// `(ticket, event)` pairs, as a public follower would see them.
    #[cfg(test)]
    tap: Option<tokio::sync::mpsc::Sender<(String, Event)>>,
}

/// The daemon's one event fan-out. See the module docs.
#[derive(Debug)]
pub struct EventHub {
    epoch: String,
    state: Mutex<State>,
}

/// A poisoned lock means a panic elsewhere while holding it; the hub's state
/// is counters and queues that stay usable, and events are best effort.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a follower may see of `event`: lifecycle as it is, progress without
/// its prose. The variants are enumerated so a future payload-bearing event
/// needs review before it reaches a public client.
fn sanitized(event: Event) -> Event {
    match event {
        Event::Progress { pct, note: _ } => Event::Progress {
            pct,
            note: PUBLIC_PROGRESS_NOTE.to_owned(),
        },
        Event::Queued | Event::Started | Event::ApprovalPending | Event::Done | Event::Refused => {
            event
        }
    }
}

const fn is_terminal(event: &Event) -> bool {
    matches!(event, Event::Done | Event::Refused)
}

const fn is_progress(event: &Event) -> bool {
    matches!(event, Event::Progress { .. })
}

/// What became of an item offered to a bounded queue.
enum Offer<T> {
    /// It is queued, possibly in place of the oldest queued progress event.
    Queued,
    /// The queue holds only lifecycle events and the item was progress: it
    /// was dropped instead.
    DroppedProgress,
    /// The queue holds only lifecycle events and so is the item.
    Full(T),
}

/// The drop policy shared by both queue kinds: when full, the oldest queued
/// progress event makes room; progress never displaces a lifecycle event.
fn offer<T>(
    queue: &mut VecDeque<T>,
    item: T,
    capacity: usize,
    progress: impl Fn(&T) -> bool,
) -> Offer<T> {
    if queue.len() < capacity {
        queue.push_back(item);
        return Offer::Queued;
    }
    if let Some(index) = queue.iter().position(&progress) {
        queue.remove(index);
        queue.push_back(item);
        return Offer::Queued;
    }
    if progress(&item) {
        return Offer::DroppedProgress;
    }
    Offer::Full(item)
}

impl Entry {
    fn new(born: u64) -> Self {
        Self {
            born,
            seq: 0,
            ring: VecDeque::with_capacity(REPLAY_RING),
            meta: None,
            followers: Vec::new(),
            ended: false,
        }
    }
}

/// The entry for `ticket`, created (after evicting the oldest idle entry when
/// the table is full) if it is not there.
fn entry_mut<'a>(
    entries: &'a mut HashMap<String, Entry>,
    next_born: &mut u64,
    ticket: &str,
) -> &'a mut Entry {
    if !entries.contains_key(ticket) && entries.len() >= MAX_ENTRIES {
        // At most `MAX_FOLLOWERS` entries can have a follower, so an idle
        // one always exists at the cap.
        let oldest = entries
            .iter()
            .filter(|(_, entry)| entry.followers.is_empty())
            .min_by_key(|(_, entry)| entry.born)
            .map(|(ticket, _)| ticket.clone());
        if let Some(oldest) = oldest {
            entries.remove(&oldest);
        }
    }
    entries.entry(ticket.to_owned()).or_insert_with(|| {
        *next_born += 1;
        Entry::new(*next_born)
    })
}

fn deliver_to_follower(shared: &FollowerShared, seq: u64, event: &Event) {
    let mut queue = lock(&shared.queue);
    if is_terminal(event) {
        queue.terminal = Some((seq, event.clone()));
    } else if let Offer::Full(item) = offer(
        &mut queue.events,
        (seq, event.clone()),
        FOLLOWER_QUEUE,
        |(_, queued)| is_progress(queued),
    ) {
        // Only lifecycle events on both sides: the oldest one goes.
        queue.events.pop_front();
        queue.events.push_back(item);
    }
    drop(queue);
    shared.wake.notify_one();
}

/// Queues `event` for one subscriber. Returns `false` when the subscriber
/// lagged and must be detached.
fn deliver_to_subscriber(shared: &SubscriberShared, event: AdminEvent) -> bool {
    let mut queue = lock(&shared.queue);
    let kept = !matches!(
        offer(&mut queue.events, event, SUBSCRIBER_QUEUE, |queued| {
            is_progress(&queued.event)
        }),
        Offer::Full(_)
    );
    if !kept {
        queue.lagged = true;
        queue.events.clear();
    }
    drop(queue);
    shared.wake.notify_one();
    kept
}

impl EventHub {
    /// A hub with a freshly minted epoch.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_epoch(ulid::Ulid::new().to_string())
    }

    /// A hub with an explicit epoch (tests).
    #[must_use]
    pub fn with_epoch(epoch: String) -> Arc<Self> {
        Arc::new(Self {
            epoch,
            state: Mutex::new(State::default()),
        })
    }

    /// The ULID minted when this hub was built: what `hello_ack` and
    /// `following` carry so a follower can tell a restarted daemon.
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// A publishing handle onto this hub.
    #[must_use]
    pub fn publisher(self: &Arc<Self>) -> EventPublisher {
        EventPublisher {
            hub: Arc::clone(self),
        }
    }

    /// Feeds every sanitised event to `tap` as well, so a unit test can
    /// observe what was published without attaching to each ticket.
    #[cfg(test)]
    pub(crate) fn set_test_tap(&self, tap: tokio::sync::mpsc::Sender<(String, Event)>) {
        lock(&self.state).tap = Some(tap);
    }

    /// Records what admission knows about `ticket`, so the all-events stream
    /// can name its capability, repository, agent label and ingress. Call it
    /// before the ticket's first event.
    pub fn register(&self, ticket: &str, meta: TicketMeta) {
        let mut state = lock(&self.state);
        if state.closed {
            return;
        }
        let State {
            entries, next_born, ..
        } = &mut *state;
        entry_mut(entries, next_born, ticket).meta = Some(Arc::new(meta));
    }

    /// Forgets a ticket that reached a terminal state: its metadata and,
    /// once nothing follows it, its entry. A ticket whose terminal event was
    /// published is already gone and this is a no-op; it exists for the
    /// endings that publish none (a verdict parked for retry, a refusal
    /// nobody is told about), which would otherwise hold a table slot until
    /// the table is full. Followers still attached keep their queue and end
    /// on their own re-check of the store.
    pub fn unregister(&self, ticket: &str) {
        let mut state = lock(&self.state);
        let Some(entry) = state.entries.get_mut(ticket) else {
            return;
        };
        entry.meta = None;
        entry.ended = true;
        if entry.followers.is_empty() {
            state.entries.remove(ticket);
        }
    }

    /// Publishes one event for `ticket`. Never waits: full queues drop by the
    /// policy in the module docs.
    ///
    /// # Errors
    ///
    /// [`PublishError`] once the hub is closed.
    pub fn publish(&self, ticket: &str, event: Event) -> Result<(), PublishError> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(PublishError);
        }
        state.published += 1;
        let n = state.published;
        let State {
            entries,
            next_born,
            subscribers,
            ..
        } = &mut *state;
        let terminal = is_terminal(&event);
        let entry = entry_mut(entries, next_born, ticket);
        entry.seq += 1;
        let seq = entry.seq;
        let meta = entry.meta.clone();

        // The administration view first: it takes the event as published.
        subscribers.retain(|slot| {
            deliver_to_subscriber(
                &slot.shared,
                AdminEvent {
                    n,
                    ticket: ticket.to_owned(),
                    meta: meta.clone(),
                    event: event.clone(),
                },
            )
        });

        // Everything public from here on sees only the sanitised event.
        let public = sanitized(event);
        if entry.ring.len() == REPLAY_RING {
            entry.ring.pop_front();
        }
        entry.ring.push_back((seq, public.clone()));
        for (_, follower) in &entry.followers {
            deliver_to_follower(follower, seq, &public);
        }
        if terminal {
            // Attached followers keep their own queue and the terminal flag.
            entries.remove(ticket);
        }

        #[cfg(test)]
        if let Some(tap) = &state.tap {
            use tokio::sync::mpsc::error::TrySendError;
            return match tap.try_send((ticket.to_owned(), public)) {
                // A full tap drops the notification, as any slow reader does.
                Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
                // The test dropped its receiver: its stand-in for shutdown.
                Err(TrySendError::Closed(_)) => Err(PublishError),
            };
        }
        Ok(())
    }

    /// Attaches a follower to `ticket`: registers its queue and returns the
    /// ring entries after `after_seq` in one critical section, so no event
    /// published from here on can be missed. An `after_seq` beyond the
    /// ticket's latest sequence number belongs to another counter (an evicted
    /// entry) and replays the whole ring.
    ///
    /// # Errors
    ///
    /// [`AttachError`] at either follower cap, or once the hub is closed.
    pub fn attach(self: &Arc<Self>, ticket: &str, after_seq: u64) -> Result<Attached, AttachError> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(AttachError::Closed);
        }
        if state.followers >= MAX_FOLLOWERS {
            return Err(AttachError::TotalCapacity);
        }
        if state
            .entries
            .get(ticket)
            .is_some_and(|entry| entry.followers.len() >= MAX_FOLLOWERS_PER_TICKET)
        {
            return Err(AttachError::TicketCapacity);
        }
        state.next_id += 1;
        state.followers += 1;
        let id = state.next_id;
        let shared = Arc::new(FollowerShared::default());
        let State {
            entries, next_born, ..
        } = &mut *state;
        let entry = entry_mut(entries, next_born, ticket);
        let after = if after_seq > entry.seq { 0 } else { after_seq };
        let replay = entry
            .ring
            .iter()
            .filter(|(seq, _)| *seq > after)
            .cloned()
            .collect();
        let seq = entry.seq;
        entry.followers.push((id, Arc::clone(&shared)));
        Ok(Attached {
            follower: Follower {
                hub: Arc::clone(self),
                ticket: ticket.to_owned(),
                id,
                shared,
            },
            replay,
            seq,
        })
    }

    /// Subscribes to every event, unsanitised (administration plane only).
    /// The daemon core publishes nothing for a control request (`status`,
    /// `query`, `cancel`), so a subscriber's own polls never come back to it.
    ///
    /// # Errors
    ///
    /// [`SubscribeError`] at the subscriber cap, or once the hub is closed.
    pub fn subscribe_all(self: &Arc<Self>) -> Result<Subscriber, SubscribeError> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(SubscribeError::Closed);
        }
        if state.subscribers.len() >= MAX_SUBSCRIBERS {
            return Err(SubscribeError::Capacity);
        }
        state.next_id += 1;
        let id = state.next_id;
        let shared = Arc::new(SubscriberShared::default());
        state.subscribers.push(SubscriberSlot {
            id,
            shared: Arc::clone(&shared),
        });
        Ok(Subscriber {
            hub: Arc::clone(self),
            id,
            shared,
        })
    }

    /// Closes the hub: every follower and subscriber is told, and every later
    /// publish, attach and subscribe errors. Shutdown calls it last.
    pub fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        #[cfg(test)]
        {
            state.tap = None;
        }
        for entry in state.entries.values() {
            for (_, follower) in &entry.followers {
                lock(&follower.queue).closed = true;
                follower.wake.notify_one();
            }
        }
        for slot in &state.subscribers {
            lock(&slot.shared.queue).closed = true;
            slot.shared.wake.notify_one();
        }
        state.entries.clear();
        state.subscribers.clear();
    }

    /// What the hub holds right now.
    #[must_use]
    pub fn usage(&self) -> HubUsage {
        let state = lock(&self.state);
        HubUsage {
            entries: state.entries.len(),
            followers: state.followers,
            subscribers: state.subscribers.len(),
        }
    }

    fn detach_follower(&self, ticket: &str, id: u64) {
        let mut state = lock(&self.state);
        state.followers = state.followers.saturating_sub(1);
        let Some(entry) = state.entries.get_mut(ticket) else {
            return;
        };
        entry.followers.retain(|(follower, _)| *follower != id);
        // An entry that only ever existed for this follower has nothing to
        // replay and no terminal publish coming to remove it.
        if entry.followers.is_empty() && (entry.ended || (entry.seq == 0 && entry.meta.is_none())) {
            state.entries.remove(ticket);
        }
    }

    fn detach_subscriber(&self, id: u64) {
        lock(&self.state).subscribers.retain(|slot| slot.id != id);
    }
}

/// What [`EventHub::attach`] hands back.
#[derive(Debug)]
pub struct Attached {
    /// The live follower; dropping it detaches and frees its slot.
    pub follower: Follower,
    /// Ring entries after the requested position, oldest first.
    pub replay: Vec<(u64, Event)>,
    /// The ticket's latest sequence number at attach.
    pub seq: u64,
}

/// What a follower sees next.
#[derive(Debug, Clone, PartialEq)]
pub enum Followed {
    /// One (sanitised) event.
    Event {
        /// Its per-ticket sequence number.
        seq: u64,
        /// The event.
        event: Event,
    },
    /// The ticket's terminal event was published and everything queued
    /// before it has been delivered. Returned again on every later call.
    Terminal {
        /// The terminal event's sequence number.
        seq: u64,
        /// `done` or `refused`.
        event: Event,
    },
    /// The hub was closed by shutdown.
    Closed,
}

/// One attached follower of one ticket. Dropping it detaches the queue and
/// releases the follower slot; it never cancels work.
#[derive(Debug)]
pub struct Follower {
    hub: Arc<EventHub>,
    ticket: String,
    id: u64,
    shared: Arc<FollowerShared>,
}

impl Follower {
    /// The followed ticket.
    #[must_use]
    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    /// Waits for the next event, the terminal flag or the hub's close.
    /// Cancel-safe: an event is only taken when it is returned.
    pub async fn next(&mut self) -> Followed {
        loop {
            {
                let mut queue = lock(&self.shared.queue);
                if let Some((seq, event)) = queue.events.pop_front() {
                    return Followed::Event { seq, event };
                }
                if let Some((seq, event)) = queue.terminal.clone() {
                    return Followed::Terminal { seq, event };
                }
                if queue.closed {
                    return Followed::Closed;
                }
            }
            self.shared.wake.notified().await;
        }
    }

    /// Events queued and not yet taken (tests and inspection).
    #[must_use]
    pub fn queued(&self) -> usize {
        lock(&self.shared.queue).events.len()
    }
}

impl Drop for Follower {
    fn drop(&mut self) {
        self.hub.detach_follower(&self.ticket, self.id);
    }
}

/// What an all-events subscriber sees next.
#[derive(Debug, Clone, PartialEq)]
pub enum Subscribed {
    /// One event.
    Event(AdminEvent),
    /// The subscriber's queue overflowed with lifecycle events; it was
    /// detached. The connection is closed with `subscriber_lagged`.
    Lagged,
    /// The hub was closed by shutdown.
    Closed,
}

/// One all-events subscriber. Dropping it frees its slot.
#[derive(Debug)]
pub struct Subscriber {
    hub: Arc<EventHub>,
    id: u64,
    shared: Arc<SubscriberShared>,
}

impl Subscriber {
    /// Waits for the next event, the lag verdict or the hub's close.
    /// Cancel-safe: an event is only taken when it is returned.
    pub async fn next(&mut self) -> Subscribed {
        loop {
            {
                let mut queue = lock(&self.shared.queue);
                if queue.lagged {
                    return Subscribed::Lagged;
                }
                if let Some(event) = queue.events.pop_front() {
                    return Subscribed::Event(event);
                }
                if queue.closed {
                    return Subscribed::Closed;
                }
            }
            self.shared.wake.notified().await;
        }
    }

    /// Events queued and not yet taken (tests and inspection).
    #[must_use]
    pub fn queued(&self) -> usize {
        lock(&self.shared.queue).events.len()
    }
}

impl Drop for Subscriber {
    fn drop(&mut self) {
        self.hub.detach_subscriber(self.id);
    }
}

/// Clone-able handle daemon services use to publish lifecycle events.
#[derive(Debug, Clone)]
pub struct EventPublisher {
    hub: Arc<EventHub>,
}

impl EventPublisher {
    /// A publisher over a hub tapped by a bare channel, for in-crate unit
    /// tests that need to observe published events without binding real
    /// sockets. The channel carries what a public client sees.
    #[cfg(test)]
    pub(crate) fn for_tests() -> (Self, tokio::sync::mpsc::Receiver<(String, Event)>) {
        let hub = EventHub::new();
        let (tx, rx) = tokio::sync::mpsc::channel(TEST_TAP_CAPACITY);
        hub.set_test_tap(tx);
        (hub.publisher(), rx)
    }

    /// The hub this handle publishes into.
    #[must_use]
    pub fn hub(&self) -> &Arc<EventHub> {
        &self.hub
    }

    /// Best-effort notification: hand the event to the hub, which queues it
    /// for whoever follows or drops it when slow peers have filled their
    /// bounded queues. Authoritative results remain in Store.
    ///
    /// The ready future preserves callers' awaitable API without letting a
    /// notification delay request completion, cancellation or administration.
    pub fn publish(
        &self,
        request_id: &str,
        event: Event,
    ) -> std::future::Ready<Result<(), PublishError>> {
        std::future::ready(self.hub.publish(request_id, event))
    }
}
