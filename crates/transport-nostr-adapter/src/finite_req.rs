//! Finite requests whose replies never reach nostr-sdk's reader (#2885).
//!
//! nostr-sdk reads each connection's frames one at a time and verifies every
//! EVENT before it reads the next, so a history reply delays every live
//! message queued behind it. A finite request (one filter, read until its
//! EOSE) goes out instead through `Relay::send_msg` under an id in a reserved
//! namespace ([`ID_PREFIX`]), which the SDK never registers or resends.
//! [`DivertTransport`], installed under the SDK's transport, takes that id's
//! EVENT, EOSE and CLOSED frames off the connection before the SDK sees them
//! and queues them for the request. The caller's task parses, verifies and
//! counts them ([`FiniteRequests::fetch`]). Every other frame passes through
//! unchanged.
//!
//! A request binds to the connection its REQ goes out on. A reply on any
//! other connection, or after the request ended, is dropped unread. When that
//! connection ends, the request ends `Disconnected`. A REQ the request retired
//! before it went out never goes out.
//!
//! Each request's queue holds at most its byte budget plus one frame. The
//! queue counts whole frames as they came, envelope and padding included,
//! while the budget counts the serialized JSON of the valid events kept; one
//! frame of room covers the envelopes of an ordinary page, however slow the
//! caller. Only what the collector does not count against the budget can fill
//! it: rejected events, or more than a frame of padding or escaping. A full
//! queue ends the request as a byte-budget cut, never a short page. Frames past the item
//! budget are dropped unparsed. A frame the wrapper cannot attribute to any
//! request (a binary frame, or one whose verb or EVENT id it cannot read) ends
//! every request on its connection `InvalidMessage`, as it might have been one
//! of theirs.
//!
//! The collector applies the checks the SDK applies to subscription input: the
//! client's relay limits on frame size, event size and tags (a frame never
//! past nostr-sdk's default 5 MiB, the queue's ceiling), expiry, the event id and signature of the
//! bytes supplied, the database's id-level deletion check and the client's
//! admission policy. It also drops an event outside the request's filter. A
//! pair of id and signature it already verified skips only the signature
//! check; the id is recomputed from the supplied bytes every time. None of
//! these checks saves, notifies or gossips anything.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::Message;
use futures::{SinkExt, Stream, StreamExt, stream};
use nostr::filter::MatchEventOptions;
use nostr::message::relay::RelayMessage;
use nostr_sdk::NotificationUpdate;
use nostr_sdk::prelude::{
    AdmitPolicy, AdmitStatus, ClientBuilder, ClientMessage, DatabaseEventStatus, Event, EventId,
    Filter, NostrDatabase, Relay, RelayUrl, Signature, SubscriptionId, Url,
};
use nostr_sdk::relay::{RelayEventLimits, RelayNotification};
use nostr_sdk::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use serde_json::Value;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::sweep::hint_tap::{head_verb, second_string};

/// Starts every finite request's subscription id. No id the SDK or the
/// adapter makes starts with `~`.
pub(crate) const ID_PREFIX: &str = "~f";

/// The largest frame any request takes, whatever the client's message limit:
/// nostr-sdk's default message ceiling. Each request's queue holds this much
/// past its byte budget, however low the client's own message limit.
const MAX_FRAME_BYTES: usize = 5 * 1024 * 1024;

/// Id and signature pairs the client remembers as verified. A duplicate
/// copy, from another relay or an overlapping request, then costs one hash
/// instead of a signature check. About 1 MiB at capacity.
const VERIFIED_CAPACITY: usize = 8_192;

/// The SDK's filter matching, which leaves NIP-50 search to the relay.
const MATCH: MatchEventOptions = MatchEventOptions::new().nip50(false);

/// What one request may take from its relay.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FiniteLimits {
    /// EVENT frames, valid or not, before the request is cut.
    pub(crate) max_items: usize,
    /// Serialized JSON of valid events, duplicates included, before it is cut.
    pub(crate) max_event_bytes: usize,
    pub(crate) timeout: Duration,
}

/// How a request ended. Only `Eose` is a complete reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FiniteEnd {
    Eose,
    /// The relay sent more EVENT frames than `max_items`.
    ItemLimit,
    /// The relay sent more valid event JSON than `max_event_bytes`, or more
    /// than the request's queue holds.
    ByteLimit,
    /// The relay refused or ended the request with `CLOSED` and this reason.
    Closed(String),
    TimedOut,
    Cancelled,
    /// The connection the REQ went out on ended first.
    Disconnected,
    /// A frame that may have belonged to the request could not be read.
    InvalidMessage,
    /// The REQ could not be queued.
    SetupFailed,
}

/// What one request read.
#[derive(Debug)]
pub(crate) struct FiniteReply {
    /// Distinct valid events within the budgets, in the order they came.
    pub(crate) events: Vec<Event>,
    /// EVENT frames read for the request, valid or not, duplicates and the
    /// first one over the item budget included.
    pub(crate) raw_items: usize,
    /// Valid copies read, duplicates and the first one over a budget
    /// included.
    pub(crate) received_items: usize,
    /// Valid copies of an event already kept.
    pub(crate) duplicates: usize,
    /// Serialized JSON of every valid copy read, duplicates and the first one
    /// over a budget included: what the byte budget counts.
    pub(crate) event_bytes: usize,
    /// Serialized JSON of the events kept.
    pub(crate) kept_event_bytes: usize,
    /// Event bytes the relay sent for the request: the serialized JSON of
    /// each valid copy, and the whole frame of every other EVENT taken off
    /// the wire for it, read or not. A cut or cancelled reply reports them too.
    pub(crate) fetched_bytes: u64,
    /// Its EOSE carried NIP-67 `more`.
    pub(crate) more: bool,
    pub(crate) end: FiniteEnd,
}

impl FiniteReply {
    /// This refused attempt's reply, continued by the retry after it: one
    /// reply, with the first attempt's events kept and its counts carried.
    fn then(mut self, retry: Self) -> Self {
        let kept = self
            .events
            .iter()
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        for event in retry.events {
            if kept.contains(&event.id) {
                self.duplicates += 1;
            } else {
                self.kept_event_bytes += event.as_json().len();
                self.events.push(event);
            }
        }
        Self {
            raw_items: self.raw_items + retry.raw_items,
            received_items: self.received_items + retry.received_items,
            duplicates: self.duplicates + retry.duplicates,
            event_bytes: self.event_bytes + retry.event_bytes,
            fetched_bytes: self.fetched_bytes + retry.fetched_bytes,
            more: retry.more,
            end: retry.end,
            ..self
        }
    }

    pub(crate) fn ended(end: FiniteEnd) -> Self {
        Self {
            events: Vec::new(),
            raw_items: 0,
            received_items: 0,
            duplicates: 0,
            event_bytes: 0,
            kept_event_bytes: 0,
            fetched_bytes: 0,
            more: false,
            end,
        }
    }
}

/// The finite requests of one client, shared by its clones and its
/// transport. Build it with the client, and install [`Self::transport`]
/// under the SDK's transport.
#[derive(Clone)]
pub(crate) struct FiniteRequests(Arc<Registry>);

impl fmt::Debug for FiniteRequests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FiniteRequests").finish_non_exhaustive()
    }
}

struct Registry {
    /// Whether the client has a NIP-42 authenticator. Without one, an
    /// `auth-required` refusal is final.
    can_authenticate: bool,
    /// The client's admission policy and database, consulted as the SDK
    /// consults them for subscription input.
    policy: Option<Arc<dyn AdmitPolicy>>,
    database: Arc<dyn NostrDatabase>,
    /// The client's relay limits on a frame and on an event, which the SDK
    /// applies to subscription input before admitting it. Limits set on one
    /// relay (`add_relay(..).limits(..)`) are not applied: nostr-sdk offers no
    /// way to read them back, and nothing in MDK sets them.
    max_frame: usize,
    event_limits: RelayEventLimits,
    next_id: AtomicU64,
    next_connection: AtomicU64,
    requests: Mutex<HashMap<String, Arc<Slot>>>,
    verified: Mutex<Verified>,
}

#[derive(Default)]
struct Verified {
    pairs: HashSet<(EventId, Signature)>,
    order: VecDeque<(EventId, Signature)>,
}

impl Verified {
    fn contains(&self, pair: &(EventId, Signature)) -> bool {
        self.pairs.contains(pair)
    }

    fn insert(&mut self, pair: (EventId, Signature)) {
        if self.pairs.insert(pair) {
            self.order.push_back(pair);
            while self.order.len() > VERIFIED_CAPACITY {
                if let Some(oldest) = self.order.pop_front() {
                    self.pairs.remove(&oldest);
                }
            }
        }
    }
}

/// One request, as its connection's reader sees it.
struct Slot {
    /// The relay URL as the transport connects to it.
    relay: String,
    max_items: usize,
    max_frame: usize,
    queue_bytes: usize,
    state: Mutex<SlotState>,
    ready: Notify,
}

#[derive(Default)]
struct SlotState {
    binding: Binding,
    frames: VecDeque<String>,
    queued_bytes: usize,
    /// EVENT frames queued, at most one past the item budget.
    event_frames: usize,
    /// EVENT frames dropped at the wrapper, unread.
    dropped_event_bytes: u64,
    /// An end the wrapper decided, after every frame already queued.
    end: Option<FiniteEnd>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Binding {
    /// Its REQ has not gone out yet.
    #[default]
    Unsent,
    /// Its REQ went out on this connection.
    Sent(u64),
    /// The request ended. A REQ still queued is suppressed.
    Retired,
}

impl Slot {
    fn lock(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A frame for this request, read on `connection`; `event` for an EVENT.
    fn receive(&self, connection: u64, event: bool, text: String) {
        let mut state = self.lock();
        if state.binding != Binding::Sent(connection) {
            return;
        }
        let bytes = text.len();
        if state.end.is_some() {
            if event {
                state.dropped_event_bytes += bytes as u64;
            }
            return;
        }
        // The SDK checks its message limit on the trimmed frame; the queue
        // takes no frame past its own ceiling, whatever that limit is.
        if bytes > MAX_FRAME_BYTES || text.trim().len() > self.max_frame {
            state.end = Some(FiniteEnd::InvalidMessage);
        } else if event && state.event_frames > self.max_items {
            // The collector stops at the first frame over the budget.
            state.dropped_event_bytes += bytes as u64;
            return;
        } else if state.queued_bytes + bytes > self.queue_bytes {
            state.end = Some(FiniteEnd::ByteLimit);
        } else {
            state.event_frames += usize::from(event);
            state.queued_bytes += bytes;
            state.frames.push_back(text);
        }
        if state.end.is_some() && event {
            state.dropped_event_bytes += bytes as u64;
        }
        drop(state);
        self.ready.notify_one();
    }

    fn end_from_wire(&self, connection: u64, end: FiniteEnd) {
        let mut state = self.lock();
        if state.binding == Binding::Sent(connection) && state.end.is_none() {
            state.end = Some(end);
            drop(state);
            self.ready.notify_one();
        }
    }

    /// The frames queued so far, or the wrapper's end once none are left.
    fn take(&self) -> Result<VecDeque<String>, Option<FiniteEnd>> {
        let mut state = self.lock();
        if state.frames.is_empty() {
            return Err(state.end.clone());
        }
        state.queued_bytes = 0;
        Ok(std::mem::take(&mut state.frames))
    }
}

impl FiniteRequests {
    /// The finite requests of the client `builder` builds, under its
    /// authenticator, admission policy and database.
    pub(crate) fn for_builder(builder: &ClientBuilder) -> Self {
        Self(Arc::new(Registry {
            can_authenticate: builder.authenticator.is_some(),
            policy: builder.admit_policy.clone(),
            database: builder.database.clone(),
            max_frame: builder
                .relay_limits
                .messages
                .max_size
                .map_or(MAX_FRAME_BYTES, |max| (max as usize).min(MAX_FRAME_BYTES)),
            event_limits: builder.relay_limits.events.clone(),
            next_id: AtomicU64::new(0),
            next_connection: AtomicU64::new(0),
            requests: Mutex::default(),
            verified: Mutex::default(),
        }))
    }

    /// `transport`, with this client's finite requests' replies taken off it.
    pub(crate) fn transport(&self, transport: Arc<dyn WebSocketTransport>) -> DivertTransport {
        DivertTransport {
            transport,
            registry: self.0.clone(),
        }
    }

    /// Ask `relay` for `filter`'s events until its EOSE, within `limits`. A
    /// relay that requires NIP-42 authentication is asked once more under a
    /// new id after the client authenticates, within what the refused attempt
    /// left of `limits`; the reply carries both attempts' events and counts.
    pub(crate) async fn fetch(
        &self,
        relay: &Relay,
        filter: Filter,
        limits: FiniteLimits,
        cancel: &CancellationToken,
    ) -> FiniteReply {
        let deadline = Instant::now() + limits.timeout;
        // Subscribed before the REQ, so an authentication the SDK finishes
        // while the relay answers is still in the stream.
        let mut notifications = self
            .0
            .can_authenticate
            .then(|| relay.notifications_with_gaps());
        let first = self.request(relay, &filter, limits, deadline, cancel).await;
        let auth_required =
            matches!(&first.end, FiniteEnd::Closed(reason) if is_auth_required(reason));
        let Some(notifications) = notifications.as_mut().filter(|_| auth_required) else {
            return first;
        };
        if !authenticated(notifications, deadline, cancel).await {
            return first;
        }
        // The retry spends what the refused attempt left of the budget.
        let left = FiniteLimits {
            max_items: limits.max_items.saturating_sub(first.raw_items),
            max_event_bytes: limits.max_event_bytes.saturating_sub(first.event_bytes),
            ..limits
        };
        let retry = self.request(relay, &filter, left, deadline, cancel).await;
        first.then(retry)
    }

    async fn request(
        &self,
        relay: &Relay,
        filter: &Filter,
        limits: FiniteLimits,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> FiniteReply {
        if cancel.is_cancelled() {
            return FiniteReply::ended(FiniteEnd::Cancelled);
        }
        let id = format!(
            "{ID_PREFIX}{:x}",
            self.0.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let slot = self
            .0
            .new_slot(<&Url>::from(relay.url()).as_str().to_owned(), limits);
        let registered = Registered::new(&self.0, id.clone(), slot.clone(), relay.clone());
        let subscription_id = SubscriptionId::new(&id);
        let req = ClientMessage::req(subscription_id.clone(), vec![filter.clone()]);
        let mut collector = Collector::new(filter, limits, &self.0, relay.url(), &subscription_id);
        let mut deadline = std::pin::pin!(tokio::time::sleep_until(deadline));
        let queued = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(FiniteEnd::Cancelled),
            () = &mut deadline => Err(FiniteEnd::TimedOut),
            queued = relay.send_msg(req).into_future() => queued.map_err(|_| FiniteEnd::SetupFailed),
        };
        // Whether the collector read the frame that ended the request. What
        // the relay sent past that frame is not read and not charged, as the
        // SDK's own requests discard it. A request something else ended (a
        // cancellation, its deadline, its connection) is charged for every
        // EVENT frame it was sent and did not finish reading, the frame it was
        // reading and the rest of its batch included. Each frame races the
        // cancellation and the deadline, so neither waits on a slow admission
        // check or a long page.
        let (end, read_to_end, rest) = match queued {
            Err(end) => (end, false, VecDeque::new()),
            Ok(()) => 'collect: loop {
                match slot.take() {
                    Ok(mut frames) => {
                        while let Some(frame) = frames.pop_front() {
                            let read = tokio::select! {
                                biased;
                                () = cancel.cancelled() => Err(FiniteEnd::Cancelled),
                                () = &mut deadline => Err(FiniteEnd::TimedOut),
                                end = collector.frame(&frame) => Ok(end),
                            };
                            match read {
                                Ok(Some(end)) => break 'collect (end, true, frames),
                                Ok(None) => tokio::task::coop::consume_budget().await,
                                Err(end) => {
                                    frames.push_front(frame);
                                    break 'collect (end, false, frames);
                                }
                            }
                        }
                    }
                    Err(Some(end)) => break (end, false, VecDeque::new()),
                    Err(None) => {
                        tokio::select! {
                            biased;
                            () = cancel.cancelled() => break (FiniteEnd::Cancelled, false, VecDeque::new()),
                            () = &mut deadline => break (FiniteEnd::TimedOut, false, VecDeque::new()),
                            () = slot.ready.notified() => {}
                        }
                    }
                }
            },
        };
        let unread = registered.retire().await;
        if !read_to_end {
            collector.charge_unread(rest);
            collector.charge_unread(unread.frames);
            collector.fetched_bytes += unread.dropped_event_bytes;
        }
        collector.reply(end)
    }
}

/// Whether a `CLOSED` reason asks for NIP-42 authentication. Some relays put
/// the prefix behind one `error:` wrapper (mdk#3439).
pub(crate) fn is_auth_required(reason: &str) -> bool {
    let reason = reason
        .get(..6)
        .filter(|wrapper| wrapper.eq_ignore_ascii_case("error:"))
        .map_or(reason, |_| reason[6..].trim_start());
    reason.starts_with("auth-required:")
}

/// Wait until `deadline` for the SDK to authenticate to the relay whose
/// notifications these are. True when it did, or when lost notifications may
/// have hidden it.
async fn authenticated(
    notifications: &mut (impl Stream<Item = NotificationUpdate<RelayNotification>> + Unpin),
    deadline: Instant,
    cancel: &CancellationToken,
) -> bool {
    let wait = async {
        while let Some(update) = notifications.next().await {
            match update {
                NotificationUpdate::Notification(RelayNotification::Authenticated)
                | NotificationUpdate::Lagged { .. } => return true,
                NotificationUpdate::Notification(RelayNotification::AuthenticationFailed) => {
                    return false;
                }
                NotificationUpdate::Notification(_) => {}
            }
        }
        false
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        () = tokio::time::sleep_until(deadline) => false,
        authenticated = wait => authenticated,
    }
}

/// A registered request. Dropping it retires the request, as [`Self::retire`]
/// does, without waiting for its CLOSE to be queued.
struct Registered {
    registry: Arc<Registry>,
    id: String,
    slot: Arc<Slot>,
    relay: Relay,
    retired: bool,
}

/// What a request left unread when it retired.
struct Unread {
    frames: VecDeque<String>,
    dropped_event_bytes: u64,
}

impl Registered {
    fn new(registry: &Arc<Registry>, id: String, slot: Arc<Slot>, relay: Relay) -> Self {
        registry
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), slot.clone());
        Self {
            registry: registry.clone(),
            id,
            slot,
            relay,
            retired: false,
        }
    }

    /// Stop taking frames for the request, and close it on the relay if its
    /// REQ went out. Whatever it had not read yet is returned.
    async fn retire(mut self) -> Unread {
        let (sent, unread) = self.unregister();
        if sent {
            let close = ClientMessage::close(SubscriptionId::new(&self.id));
            let _ = self.relay.send_msg(close).await;
        }
        unread
    }

    fn unregister(&mut self) -> (bool, Unread) {
        self.retired = true;
        self.registry
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        let mut state = self.slot.lock();
        let sent = matches!(state.binding, Binding::Sent(_));
        state.binding = Binding::Retired;
        let unread = Unread {
            frames: std::mem::take(&mut state.frames),
            dropped_event_bytes: state.dropped_event_bytes,
        };
        (sent, unread)
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        if self.retired {
            return;
        }
        let (sent, _) = self.unregister();
        if sent && let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let close = ClientMessage::close(SubscriptionId::new(&self.id));
            let relay = self.relay.clone();
            runtime.spawn(async move {
                let _ = relay.send_msg(close).await;
            });
        }
    }
}

/// Reads one request's frames in order.
struct Collector<'a> {
    filter: &'a Filter,
    limits: FiniteLimits,
    registry: &'a Registry,
    relay: &'a RelayUrl,
    subscription_id: &'a SubscriptionId,
    seen: HashSet<EventId>,
    events: Vec<Event>,
    raw_items: usize,
    received_items: usize,
    duplicates: usize,
    event_bytes: usize,
    kept_event_bytes: usize,
    fetched_bytes: u64,
    more: bool,
}

impl<'a> Collector<'a> {
    fn new(
        filter: &'a Filter,
        limits: FiniteLimits,
        registry: &'a Registry,
        relay: &'a RelayUrl,
        subscription_id: &'a SubscriptionId,
    ) -> Self {
        Self {
            filter,
            limits,
            registry,
            relay,
            subscription_id,
            seen: HashSet::new(),
            events: Vec::new(),
            raw_items: 0,
            received_items: 0,
            duplicates: 0,
            event_bytes: 0,
            kept_event_bytes: 0,
            fetched_bytes: 0,
            more: false,
        }
    }

    /// Read one frame; the request's end, when this frame ends it.
    async fn frame(&mut self, text: &str) -> Option<FiniteEnd> {
        // The SDK parses the trimmed frame; the counts keep its whole length.
        let json = text.trim();
        let Ok(message) = RelayMessage::from_json(json) else {
            if head_verb(text).as_deref() == Some("EVENT") {
                self.raw_items += 1;
                self.fetched_bytes += text.len() as u64;
            }
            return Some(FiniteEnd::InvalidMessage);
        };
        match message {
            RelayMessage::Event { event, .. } => self.event(event.into_owned(), text.len()).await,
            RelayMessage::EndOfStoredEvents(_) => {
                // An EOSE the SDK takes but serde_json cannot read whole (a
                // trailing number out of range) may say `more`: it does.
                self.more = serde_json::from_str::<Value>(json)
                    .map_or(true, |frame| says_more(frame.get(2)));
                Some(FiniteEnd::Eose)
            }
            RelayMessage::Closed { message, .. } => Some(FiniteEnd::Closed(message.into_owned())),
            // The wrapper diverts nothing else.
            _ => Some(FiniteEnd::InvalidMessage),
        }
    }

    async fn event(&mut self, event: Event, frame_bytes: usize) -> Option<FiniteEnd> {
        self.raw_items += 1;
        let bytes = event.as_json().len();
        if !(self.checked(&event, bytes) && self.admitted(&event).await) {
            self.fetched_bytes += frame_bytes as u64;
            return (self.raw_items > self.limits.max_items).then_some(FiniteEnd::ItemLimit);
        }
        self.received_items += 1;
        self.fetched_bytes += bytes as u64;
        self.event_bytes = self.event_bytes.saturating_add(bytes);
        if self.raw_items > self.limits.max_items {
            return Some(FiniteEnd::ItemLimit);
        }
        if self.event_bytes > self.limits.max_event_bytes {
            return Some(FiniteEnd::ByteLimit);
        }
        if self.seen.insert(event.id) {
            self.kept_event_bytes += bytes;
            self.events.push(event);
        } else {
            self.duplicates += 1;
        }
        None
    }

    /// The SDK's own checks of an event's size, shape and authenticity.
    fn checked(&self, event: &Event, bytes: usize) -> bool {
        let limits = &self.registry.event_limits;
        if limits
            .get_max_size(&event.kind)
            .is_some_and(|max| bytes > max as usize)
            || limits
                .get_max_num_tags(&event.kind)
                .is_some_and(|max| event.tags.len() > usize::from(max))
            || event.is_expired()
            || !self.filter.match_event(event, MATCH)
            || !event.verify_id()
        {
            return false;
        }
        let pair = (event.id, event.sig);
        let lock = || {
            self.registry
                .verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        };
        if lock().contains(&pair) {
            return true;
        }
        if !event.verify_signature() {
            return false;
        }
        lock().insert(pair);
        true
    }

    /// The client's database has not deleted it, and its admission policy
    /// takes it. A failed lookup admits nothing.
    async fn admitted(&self, event: &Event) -> bool {
        if !matches!(
            self.registry.database.check_id(&event.id).await,
            Ok(DatabaseEventStatus::Saved | DatabaseEventStatus::NotExistent)
        ) {
            return false;
        }
        let Some(policy) = &self.registry.policy else {
            return true;
        };
        matches!(
            policy
                .admit_event(self.relay, self.subscription_id, event)
                .await,
            Ok(AdmitStatus::Success)
        )
    }

    /// Charge EVENT frames taken off the wire for the request and never read.
    fn charge_unread(&mut self, frames: impl IntoIterator<Item = String>) {
        for frame in frames {
            if head_verb(&frame).as_deref() == Some("EVENT") {
                self.fetched_bytes += frame.len() as u64;
            }
        }
    }

    fn reply(self, end: FiniteEnd) -> FiniteReply {
        FiniteReply {
            events: self.events,
            raw_items: self.raw_items,
            received_items: self.received_items,
            duplicates: self.duplicates,
            event_bytes: self.event_bytes,
            kept_event_bytes: self.kept_event_bytes,
            fetched_bytes: self.fetched_bytes,
            more: self.more,
            end,
        }
    }
}

/// Whether NIP-67's third EOSE element names `more`. No other name, `finish`
/// included, changes what a caller does.
fn says_more(hints: Option<&Value>) -> bool {
    hints
        .and_then(Value::as_array)
        .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("more")))
}

/// How the wrapper reads a frame the relay sent.
#[derive(Debug, PartialEq, Eq)]
enum Inbound {
    /// An EVENT, EOSE or CLOSED under a finite request's id.
    Owned { event: bool, id: String },
    /// Anyone else's frame, or one under a verb that carries no EVENT.
    Other,
    /// A frame whose verb, or EVENT id, cannot be read as JSON reads it: it
    /// may have been any request's EVENT.
    Unattributed,
}

/// Read a frame's verb and subscription id the way the SDK's parser reads
/// them, without parsing the rest. Wherever the SDK could take a frame as an
/// EVENT, this reads the same verb and id, so no finite request's EVENT
/// reaches the SDK unseen.
fn classify(text: &str) -> Inbound {
    let Some(verb) = head_verb(text) else {
        return Inbound::Unattributed;
    };
    let event = verb == "EVENT";
    if !event && verb != "EOSE" && verb != "CLOSED" {
        return Inbound::Other;
    }
    match second_string(text) {
        Some(id) if id.starts_with(ID_PREFIX) => Inbound::Owned { event, id },
        Some(_) => Inbound::Other,
        None if event => Inbound::Unattributed,
        // An unreadable EOSE or CLOSED ends nothing: its request waits out its
        // deadline rather than completing.
        None => Inbound::Other,
    }
}

impl Registry {
    /// A new request's slot for `relay`, within `limits`.
    fn new_slot(&self, relay: String, limits: FiniteLimits) -> Arc<Slot> {
        Arc::new(Slot {
            relay,
            max_items: limits.max_items,
            max_frame: self.max_frame,
            queue_bytes: limits.max_event_bytes.saturating_add(MAX_FRAME_BYTES),
            state: Mutex::default(),
            ready: Notify::new(),
        })
    }

    fn slot(&self, id: &str) -> Option<Arc<Slot>> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }

    fn slots(&self) -> Vec<Arc<Slot>> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// A text frame `relay` sent on `connection`: `None` when it was a
    /// finite request's, ended or not, and must not reach the SDK. A relay
    /// keeps answering a REQ until it reads the CLOSE, and nothing in the SDK
    /// expects those frames.
    fn received(&self, connection: u64, text: String) -> Option<String> {
        match classify(&text) {
            Inbound::Other => Some(text),
            Inbound::Unattributed => {
                self.unattributed(connection);
                Some(text)
            }
            Inbound::Owned { event, id } => {
                // Unknown: a request that already ended. Dropped unread.
                if let Some(slot) = self.slot(&id) {
                    slot.receive(connection, event, text);
                }
                None
            }
        }
    }

    /// A frame on `connection` that may have been any request's.
    fn unattributed(&self, connection: u64) {
        for slot in self.slots() {
            slot.end_from_wire(connection, FiniteEnd::InvalidMessage);
        }
    }

    /// A text frame the client sends `relay` on `connection`: false for a
    /// finite request's REQ that must not go out, because the request ended
    /// before it did.
    fn sending(&self, relay: &str, connection: u64, text: &str) -> bool {
        if head_verb(text).as_deref() != Some("REQ") {
            return true;
        }
        let Some(id) = second_string(text).filter(|id| id.starts_with(ID_PREFIX)) else {
            return true;
        };
        let Some(slot) = self.slot(&id).filter(|slot| slot.relay == relay) else {
            return false;
        };
        let mut state = slot.lock();
        if state.binding != Binding::Unsent {
            return false;
        }
        state.binding = Binding::Sent(connection);
        true
    }

    /// `connection` ended: so did every request whose REQ went out on it.
    fn disconnected(&self, connection: u64) {
        for slot in self.slots() {
            slot.end_from_wire(connection, FiniteEnd::Disconnected);
        }
    }
}

type ConnectFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<(WebSocketSink, WebSocketStream), nostr_sdk::error::Error>>
            + Send
            + 'a,
    >,
>;

/// A client's transport, with its finite requests' replies taken off every
/// connection. See the module docs.
#[derive(Clone)]
pub(crate) struct DivertTransport {
    transport: Arc<dyn WebSocketTransport>,
    registry: Arc<Registry>,
}

impl fmt::Debug for DivertTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DivertTransport")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl WebSocketTransport for DivertTransport {
    fn support_ping(&self) -> bool {
        self.transport.support_ping()
    }

    fn connect<'a>(&'a self, url: &'a Url, proxy: Option<SocketAddr>) -> ConnectFuture<'a> {
        Box::pin(async move {
            let (sink, stream) = self.transport.connect(url, proxy).await?;
            let connection = self
                .registry
                .next_connection
                .fetch_add(1, Ordering::Relaxed);
            let relay: Arc<str> = Arc::from(url.as_str());
            let registry = self.registry.clone();
            let sink: WebSocketSink = Box::pin(sink.with_flat_map(move |message: Message| {
                let send = match &message {
                    Message::Text(text) => registry.sending(&relay, connection, text),
                    _ => true,
                };
                stream::iter(send.then_some(Ok(message)))
            }));
            let stream: WebSocketStream = Box::pin(Diverted {
                stream,
                registry: self.registry.clone(),
                connection,
                ended: false,
            });
            Ok((sink, stream))
        })
    }
}

/// One connection's incoming frames, less its finite requests' replies. When
/// it ends, errs or is dropped, so does every request bound to it.
struct Diverted {
    stream: WebSocketStream,
    registry: Arc<Registry>,
    connection: u64,
    ended: bool,
}

impl Diverted {
    fn end(&mut self) {
        if !self.ended {
            self.ended = true;
            self.registry.disconnected(self.connection);
        }
    }
}

impl Stream for Diverted {
    type Item = Result<Message, nostr_sdk::error::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(Message::Text(text)))) => {
                    if let Some(text) = self.registry.received(self.connection, text) {
                        return Poll::Ready(Some(Ok(Message::Text(text))));
                    }
                }
                // The SDK drops a binary frame unread, and it may have been
                // any request's EVENT: it ends the connection's requests.
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    self.registry.unattributed(self.connection);
                    return Poll::Ready(Some(Ok(Message::Binary(data))));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.end();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.end();
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }
}

impl Drop for Diverted {
    fn drop(&mut self) {
        self.end();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    use nostr_sdk::authenticator::SignerAuthenticator;
    use nostr_sdk::local_relay::{LocalRelay, LocalRelayBuilderNip42};
    use nostr_sdk::prelude::{Client, ClientNotification, RelayUrl};

    use super::*;
    use crate::sweep::hint_tap::escaped;

    const RELAY: &str = "wss://relay.example.com/";

    fn limits(max_items: usize, max_event_bytes: usize) -> FiniteLimits {
        FiniteLimits {
            max_items,
            max_event_bytes,
            timeout: Duration::from_secs(10),
        }
    }

    fn note(keys: &Keys, content: &str) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .finalize(keys)
            .unwrap()
    }

    fn event_frame(event: &Event) -> String {
        RelayMessage::event(SubscriptionId::new("~f0"), event.clone()).as_json()
    }

    fn eose(hints: &str) -> String {
        format!(r#"["EOSE","~f0"{hints}]"#)
    }

    /// The finite requests of a client built the way production builds one.
    fn requests() -> FiniteRequests {
        FiniteRequests::for_builder(&crate::network_proxy::nostr_builder(Ok(None)))
    }

    fn relay_url() -> RelayUrl {
        RelayUrl::parse(RELAY).unwrap()
    }

    /// Read `frames` in order as one request of `filter` from `finite` would.
    async fn collect_with(
        finite: &FiniteRequests,
        filter: &Filter,
        limits: FiniteLimits,
        frames: &[String],
    ) -> FiniteReply {
        let (relay, id) = (relay_url(), SubscriptionId::new("~f0"));
        let mut collector = Collector::new(filter, limits, &finite.0, &relay, &id);
        for frame in frames {
            if let Some(end) = collector.frame(frame).await {
                return collector.reply(end);
            }
        }
        collector.reply(FiniteEnd::TimedOut)
    }

    async fn collect(filter: &Filter, limits: FiniteLimits, frames: &[String]) -> FiniteReply {
        collect_with(&requests(), filter, limits, frames).await
    }

    /// An event the SDK would drop never reaches the result, but its frame
    /// still counts toward the relay's reply, so a page of them is not a
    /// short page.
    #[tokio::test]
    async fn only_valid_matching_events_are_kept_and_every_frame_counts() {
        let keys = Keys::generate();
        let good = note(&keys, "good");
        let expired = EventBuilder::new(Kind::TextNote, "expired")
            .tag(Tag::expiration(Timestamp::from_secs(1)))
            .finalize(&keys)
            .unwrap();
        let off_filter = EventBuilder::new(Kind::Metadata, "{}")
            .finalize(&keys)
            .unwrap();
        // One tag past the SDK's default ceiling.
        let crowded = EventBuilder::new(Kind::TextNote, "crowded")
            .tags((0..=2_000).map(|n| Tag::parse(["x", &n.to_string()]).unwrap()))
            .finalize(&keys)
            .unwrap();
        // Another event's valid signature on this one's id and content.
        let mut forged = serde_json::to_value(note(&keys, "forged")).unwrap();
        forged["sig"] = serde_json::to_value(good.sig).unwrap();
        let forged = format!(r#"["EVENT","~f0",{forged}]"#);
        // This one's id and signature on other content.
        let mut tampered = serde_json::to_value(&good).unwrap();
        tampered["content"] = "tampered".into();
        let tampered = format!(r#"["EVENT","~f0",{tampered}]"#);

        let filter = Filter::new().kind(Kind::TextNote);
        let reply = collect(
            &filter,
            limits(10, 1 << 20),
            &[
                event_frame(&expired),
                event_frame(&off_filter),
                event_frame(&crowded),
                forged,
                tampered,
                event_frame(&good),
                eose(""),
            ],
        )
        .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.raw_items, 6);
        assert_eq!(reply.events, vec![good]);

        // A frame that names the request but cannot be read ends it: a later
        // EOSE cannot turn the lost event into a short page.
        let reply = collect(
            &filter,
            limits(10, 1 << 20),
            &[r#"["EVENT","~f0",{"id":7}]"#.to_owned(), eose("")],
        )
        .await;
        assert_eq!(reply.end, FiniteEnd::InvalidMessage);
        assert_eq!(reply.raw_items, 1);
    }

    /// Budgets count duplicates and the first event over them, which is not
    /// kept. A reply exactly at its budget still completes at its EOSE.
    #[tokio::test]
    async fn budgets_count_the_first_overflow_and_keep_it_out() {
        let keys = Keys::generate();
        let events: Vec<Event> = (0..3).map(|n| note(&keys, &n.to_string())).collect();
        let filter = Filter::new().kind(Kind::TextNote);
        let one = events[0].as_json().len();

        let frames: Vec<String> = events.iter().map(event_frame).chain([eose("")]).collect();
        let at_limit = collect(&filter, limits(3, 3 * one + 3), &frames).await;
        assert_eq!(at_limit.end, FiniteEnd::Eose);
        assert_eq!(at_limit.events.len(), 3);

        let over_items = collect(&filter, limits(2, 1 << 20), &frames).await;
        assert_eq!(over_items.end, FiniteEnd::ItemLimit);
        assert_eq!(over_items.raw_items, 3);
        assert_eq!(over_items.events, events[..2]);

        // A duplicate is charged like any copy; the third event crosses the
        // byte budget and is left out.
        let with_duplicate = [
            event_frame(&events[0]),
            event_frame(&events[0]),
            event_frame(&events[1]),
            eose(""),
        ];
        let over_bytes = collect(&filter, limits(10, 2 * one + one / 2), &with_duplicate).await;
        assert_eq!(over_bytes.end, FiniteEnd::ByteLimit);
        assert_eq!(over_bytes.events, events[..1]);
        assert_eq!(
            over_bytes.fetched_bytes,
            (2 * one + events[1].as_json().len()) as u64
        );
    }

    /// A copy whose id and signature the client verified before skips only
    /// the signature check. Its id is recomputed from the bytes supplied, so
    /// a copy with other content fails.
    #[test]
    fn a_verified_copy_skips_only_the_signature_check() {
        let keys = Keys::generate();
        let good = note(&keys, "good");
        let finite = requests();
        let filter = Filter::new().kind(Kind::TextNote);
        let (relay, id) = (relay_url(), SubscriptionId::new("~f0"));
        let collector = Collector::new(&filter, limits(10, 1 << 20), &finite.0, &relay, &id);
        assert!(collector.checked(&good, good.as_json().len()));
        assert!(
            finite
                .0
                .verified
                .lock()
                .unwrap()
                .contains(&(good.id, good.sig))
        );
        let mut tampered = good.clone();
        tampered.content = "tampered".to_owned();
        assert!(!collector.checked(&tampered, tampered.as_json().len()));
        let mut resigned = good.clone();
        resigned.sig = note(&keys, "other").sig;
        assert!(
            !collector.checked(&resigned, resigned.as_json().len()),
            "an unverified pair is checked"
        );
    }

    #[derive(Debug)]
    struct RejectContent(&'static str);

    impl AdmitPolicy for RejectContent {
        fn admit_event<'a>(
            &'a self,
            _: &'a RelayUrl,
            _: &'a SubscriptionId,
            event: &'a Event,
        ) -> Pin<Box<dyn Future<Output = Result<AdmitStatus, nostr_sdk::error::Error>> + Send + 'a>>
        {
            let rejected = event.content == self.0;
            Box::pin(async move {
                Ok(if rejected {
                    AdmitStatus::Rejected { reason: None }
                } else {
                    AdmitStatus::Success
                })
            })
        }
    }

    /// The client's admission policy and its database's deletions keep an
    /// event out of a finite reply as they keep it out of a subscription. It
    /// still counts as a frame the relay sent.
    #[tokio::test]
    async fn the_clients_policy_and_deletions_apply() {
        let keys = Keys::generate();
        let kept = note(&keys, "kept");
        let rejected = note(&keys, "rejected");
        let deleted = note(&keys, "deleted");
        let database = nostr_memory::MemoryDatabase::unbounded();
        database.save_event(&deleted).await.unwrap();
        let deletion = EventBuilder::new(Kind::EventDeletion, "")
            .tag(Tag::event(deleted.id))
            .finalize(&keys)
            .unwrap();
        database.save_event(&deletion).await.unwrap();
        let builder = crate::network_proxy::nostr_builder(Ok(None))
            .admit_policy(RejectContent("rejected"))
            .database(database);
        let finite = FiniteRequests::for_builder(&builder);
        let filter = Filter::new().kind(Kind::TextNote);
        let reply = collect_with(
            &finite,
            &filter,
            limits(10, 1 << 20),
            &[
                event_frame(&rejected),
                event_frame(&deleted),
                event_frame(&kept),
                eose(""),
            ],
        )
        .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.raw_items, 3);
        assert_eq!(reply.events, vec![kept]);
    }

    #[tokio::test]
    async fn eose_hints_and_closed_reasons_are_kept() {
        let filter = Filter::new().kind(Kind::TextNote);
        let reply = collect(&filter, limits(1, 1), &[eose(r#",["auth","more"]"#)]).await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert!(reply.more);
        let reply = collect(&filter, limits(1, 1), &[eose(r#",["finish"]"#)]).await;
        assert!(!reply.more);
        // The SDK takes this EOSE, skipping what follows the hints; its hints
        // are unread, so they may say `more`.
        let unread = eose(r#",["finish"],1e400"#);
        assert!(RelayMessage::from_json(unread.as_str()).is_ok());
        let reply = collect(&filter, limits(1, 1), &[unread]).await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert!(reply.more);
        let closed =
            RelayMessage::closed(SubscriptionId::new("~f0"), "rate-limited: slow").as_json();
        let reply = collect(&filter, limits(1, 1), &[closed]).await;
        assert_eq!(
            reply.end,
            FiniteEnd::Closed("rate-limited: slow".to_owned())
        );
        // The SDK trims Unicode whitespace before it parses a frame.
        let keys = Keys::generate();
        let kept = note(&keys, "padded");
        let pad = |frame: String| format!("\u{2003}\n{frame}\u{2003}");
        let reply = collect(
            &filter,
            limits(2, 1 << 20),
            &[pad(event_frame(&kept)), pad(eose(r#",["more"]"#))],
        )
        .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert!(reply.more);
        assert_eq!(reply.events, vec![kept]);
        assert!(is_auth_required("auth-required: sign in"));
        assert!(is_auth_required("ERROR: auth-required: sign in"));
        assert!(!is_auth_required("restricted: auth-required: no"));
    }

    /// A request registered under `id` for [`RELAY`], as `fetch` registers
    /// one before queuing its REQ.
    fn register(registry: &Registry, id: &str, limits: FiniteLimits) -> Arc<Slot> {
        let slot = registry.new_slot(RELAY.to_owned(), limits);
        registry
            .requests
            .lock()
            .unwrap()
            .insert(id.to_owned(), slot.clone());
        slot
    }

    fn req(id: &str) -> String {
        ClientMessage::req(SubscriptionId::new(id), vec![Filter::new()]).as_json()
    }

    fn frame(verb: &str, id: &str) -> String {
        format!(r#"["{verb}","{id}",{{}}]"#)
    }

    fn queued(slot: &Slot) -> usize {
        slot.lock().frames.len()
    }

    /// A request takes frames only from the connection its REQ went out on,
    /// ends when that connection does, and frames under a finite id never
    /// reach the SDK, whether or not their request is still registered.
    #[test]
    fn frames_reach_only_the_request_on_the_connection_its_req_went_out_on() {
        let registry = requests().0;
        let slot = register(&registry, "~f1", limits(10, 1 << 20));
        assert!(registry.sending(RELAY, 2, &req("~f1")));
        assert!(!registry.sending(RELAY, 3, &req("~f1")), "sent once only");
        assert!(registry.sending(RELAY, 2, &req("live")));

        assert_eq!(registry.received(1, frame("EVENT", "~f1")), None);
        assert_eq!(queued(&slot), 0, "another connection's reply is dropped");
        assert_eq!(registry.received(2, frame("EVENT", "~f1")), None);
        assert_eq!(queued(&slot), 1);
        assert_eq!(
            registry.received(2, frame("EVENT", "~f9")),
            None,
            "an ended request's reply"
        );
        let live = frame("EVENT", "live");
        assert_eq!(registry.received(2, live.clone()), Some(live));
        let notice = r#"["NOTICE","~f1"]"#.to_owned();
        assert_eq!(registry.received(2, notice.clone()), Some(notice));

        registry.disconnected(1);
        assert_eq!(slot.lock().end, None);
        registry.disconnected(2);
        assert_eq!(slot.lock().end, Some(FiniteEnd::Disconnected));
        // The frame read before the connection ended is still read first.
        assert_eq!(slot.take().unwrap().len(), 1);
        assert_eq!(slot.take().unwrap_err(), Some(FiniteEnd::Disconnected));
    }

    /// The wrapper reads every frame's verb and id as the SDK's parser does.
    /// A frame the SDK takes as a finite request's EVENT, EOSE or CLOSED is
    /// that request's, under the same id; one it takes as anything else
    /// passes on. A frame whose verb or EVENT id is not JSON, which the SDK
    /// drops unread, may have been any request's EVENT: it ends the
    /// connection's requests rather than passing on unseen.
    #[test]
    fn frames_are_classified_as_the_sdk_parses_them() {
        let event = serde_json::to_string(&note(&Keys::generate(), "x")).unwrap();
        let owned = |event: bool| Inbound::Owned {
            event,
            id: "~f1".to_owned(),
        };
        let cases = [
            (format!(r#"["EVENT","~f1",{event}]"#), owned(true)),
            (
                format!(" \n [ \"EVENT\" ,\t\"~f1\" , {event} ] "),
                owned(true),
            ),
            (format!(r#"["\u0045VENT","~f1",{event}]"#), owned(true)),
            (format!(r#"["EVENT","\u007ef1",{event}]"#), owned(true)),
            (format!(r#"["EVENT","live",{event}]"#), Inbound::Other),
            (r#"["EOSE","~f1"]"#.to_owned(), owned(false)),
            (r#"["EOSE","~f1",["more"]]"#.to_owned(), owned(false)),
            (
                r#"["CLOSED","~f1","error: refused"]"#.to_owned(),
                owned(false),
            ),
            (r#"["NOTICE","~f1"]"#.to_owned(), Inbound::Other),
            (r#"["OK","~f1",true,""]"#.to_owned(), Inbound::Other),
            (r#"["AUTH","~f1"]"#.to_owned(), Inbound::Other),
            // Every verb read whole however it is escaped.
            (
                format!(r#"["{}","~f1","error: refused"]"#, escaped("CLOSED")),
                owned(false),
            ),
            (
                format!(r#"["{}","~f1"]"#, escaped("NOTICE")),
                Inbound::Other,
            ),
            (
                format!(r#"["{}","~f1","00"]"#, escaped("NEG-MSG")),
                Inbound::Other,
            ),
            (
                format!(r#"["{}","~f1","blocked"]"#, escaped("NEG-ERR")),
                Inbound::Other,
            ),
            // A readable EVENT id with a body that is not: its own request
            // reads it and ends `InvalidMessage`.
            (r#"["EVENT","~f1",{"id":7}]"#.to_owned(), owned(true)),
            // Not JSON where the verb or EVENT id is.
            (
                format!("[\"EV\nENT\",\"~f1\",{event}]"),
                Inbound::Unattributed,
            ),
            (
                format!("[\"EVENT\",\"~f1\t\",{event}]"),
                Inbound::Unattributed,
            ),
            (
                format!("[\"EVENT\",\"~\u{1}f1\",{event}]"),
                Inbound::Unattributed,
            ),
            (r#"["EVENT",7,{}]"#.to_owned(), Inbound::Unattributed),
            (r#"[1,"~f1"]"#.to_owned(), Inbound::Unattributed),
            ("not json".to_owned(), Inbound::Unattributed),
        ];
        for (frame, expected) in cases {
            let class = classify(&frame);
            assert_eq!(class, expected, "{frame:?}");
            let agrees = |event: bool, id: &str| {
                if id.starts_with(ID_PREFIX) {
                    class
                        == Inbound::Owned {
                            event,
                            id: id.to_owned(),
                        }
                } else {
                    class == Inbound::Other
                }
            };
            match RelayMessage::from_json(frame.as_str()) {
                Ok(RelayMessage::Event {
                    subscription_id, ..
                }) => assert!(agrees(true, subscription_id.as_str()), "{frame:?}"),
                Ok(RelayMessage::EndOfStoredEvents(id)) => {
                    assert!(agrees(false, id.as_str()), "{frame:?}");
                }
                Ok(RelayMessage::Closed {
                    subscription_id, ..
                }) => assert!(agrees(false, subscription_id.as_str()), "{frame:?}"),
                Ok(_) => assert_eq!(class, Inbound::Other, "{frame:?}"),
                Err(_) => assert!(
                    class != Inbound::Other || !frame.contains("EVENT"),
                    "a frame the SDK drops passed as someone else's: {frame:?}"
                ),
            }
            if class == Inbound::Unattributed {
                assert!(
                    RelayMessage::from_json(frame.as_str()).is_err(),
                    "the SDK reads {frame:?}"
                );
            }
        }
    }

    /// A REQ still queued when its request ended, or one for no registered
    /// request, never goes out.
    #[test]
    fn a_retired_request_sends_no_req() {
        let registry = requests().0;
        let slot = register(&registry, "~f1", limits(10, 1 << 20));
        slot.lock().binding = Binding::Retired;
        assert!(!registry.sending(RELAY, 1, &req("~f1")));
        assert!(!registry.sending(RELAY, 1, &req("~f2")));
        register(&registry, "~f3", limits(10, 1 << 20));
        assert!(!registry.sending("wss://other.example.com/", 1, &req("~f3")));
    }

    /// A frame the wrapper cannot attribute may have been any request's: it
    /// ends those on its connection, and still reaches the SDK.
    #[test]
    fn an_unattributed_frame_ends_only_its_connections_requests() {
        let registry = requests().0;
        let here = register(&registry, "~f1", limits(10, 1 << 20));
        let there = register(&registry, "~f2", limits(10, 1 << 20));
        assert!(registry.sending(RELAY, 1, &req("~f1")));
        assert!(registry.sending(RELAY, 2, &req("~f2")));
        for garbage in [r#"["EVENT",7,{}]"#, "not json", r#"[1,"~f1"]"#] {
            assert_eq!(
                registry.received(1, garbage.to_owned()).as_deref(),
                Some(garbage)
            );
        }
        assert_eq!(here.lock().end, Some(FiniteEnd::InvalidMessage));
        assert_eq!(there.lock().end, None);
    }

    /// A binary frame may have been any request's EVENT, and the SDK drops
    /// it unread: it ends the requests on its connection, and still reaches
    /// the SDK. The text EOSE after it cannot then read as a short page.
    #[tokio::test]
    async fn a_binary_frame_ends_its_connections_requests() {
        let finite = requests();
        let slot = register(&finite.0, "~f1", limits(10, 1 << 20));
        let binary = frame("EVENT", "~f1").into_bytes();
        let transport = finite.transport(Arc::new(Scripted(Mutex::new(vec![
            Message::Binary(binary.clone()),
            Message::Text(eose_for("~f1")),
        ]))));
        let url = Url::parse(RELAY).unwrap();
        let (mut sink, mut stream) = transport.connect(&url, None).await.unwrap();
        sink.send(Message::Text(req("~f1"))).await.unwrap();
        assert!(
            matches!(stream.next().await, Some(Ok(Message::Binary(data))) if data == binary),
            "the binary frame reaches the SDK"
        );
        assert!(
            futures::FutureExt::now_or_never(stream.next()).is_none(),
            "the request's EOSE does not"
        );
        assert_eq!(slot.lock().end, Some(FiniteEnd::InvalidMessage));
    }

    fn eose_for(id: &str) -> String {
        format!(r#"["EOSE","{id}"]"#)
    }

    /// A transport whose one connection sends `.0`, then waits.
    #[derive(Debug)]
    struct Scripted(Mutex<Vec<Message>>);

    impl WebSocketTransport for Scripted {
        fn support_ping(&self) -> bool {
            false
        }

        fn connect<'a>(&'a self, _: &'a Url, _: Option<SocketAddr>) -> ConnectFuture<'a> {
            let frames = std::mem::take(&mut *self.0.lock().unwrap());
            Box::pin(async move {
                let sink: WebSocketSink =
                    Box::pin(futures::sink::drain().sink_map_err(|never| match never {}));
                let stream: WebSocketStream =
                    Box::pin(stream::iter(frames.into_iter().map(Ok)).chain(stream::pending()));
                Ok((sink, stream))
            })
        }
    }

    /// The reader never waits on a request: frames past its item budget are
    /// dropped unread, and a queue past its byte budget cuts it.
    #[test]
    fn wire_bounds_cut_a_request_without_holding_the_reader() {
        let registry = requests().0;
        let slot = register(&registry, "~f1", limits(1, 0));
        assert!(registry.sending(RELAY, 1, &req("~f1")));
        for _ in 0..3 {
            registry.received(1, frame("EVENT", "~f1"));
        }
        assert_eq!(queued(&slot), 2, "the first frame over the budget is read");
        assert_eq!(
            slot.lock().dropped_event_bytes,
            frame("EVENT", "~f1").len() as u64
        );

        let slot = register(&registry, "~f2", limits(100, 0));
        assert!(registry.sending(RELAY, 1, &req("~f2")));
        // Two fit in the one frame of room a zero budget leaves; a third does not.
        let big = format!(r#"["EVENT","~f2","{}"]"#, "x".repeat(MAX_FRAME_BYTES / 3));
        registry.received(1, big.clone());
        registry.received(1, big.clone());
        registry.received(1, big);
        assert_eq!(queued(&slot), 2);
        assert_eq!(slot.lock().end, Some(FiniteEnd::ByteLimit));

        // A page within its event budget fits however much envelope its
        // frames carry: the queue's one frame of room is far more than any
        // page's envelopes.
        let keys = Keys::generate();
        let page: Vec<Event> = (0..200).map(|n| note(&keys, &n.to_string())).collect();
        let budget = page.iter().map(|event| event.as_json().len()).sum();
        let slot = register(&registry, "~f3", limits(page.len(), budget));
        assert!(registry.sending(RELAY, 1, &req("~f3")));
        for event in &page {
            let frame = RelayMessage::event(SubscriptionId::new("~f3"), event.clone()).as_json();
            registry.received(1, format!("  {frame}  "));
        }
        assert_eq!(queued(&slot), page.len());
        assert_eq!(slot.lock().end, None);
    }

    /// A low message limit refuses a frame over it, and leaves a page within
    /// its event budget the queue's whole room for envelopes.
    #[test]
    fn a_low_message_limit_bounds_frames_not_the_queue() {
        let mut relay_limits = nostr_sdk::relay::RelayLimits::default();
        relay_limits.messages.max_size = Some(500);
        let registry = FiniteRequests::for_builder(
            &crate::network_proxy::nostr_builder(Ok(None)).relay_limits(relay_limits),
        )
        .0;
        let keys = Keys::generate();
        let page: Vec<Event> = (0..100).map(|n| note(&keys, &n.to_string())).collect();
        let budget = page.iter().map(|event| event.as_json().len()).sum();
        let slot = register(&registry, "~f1", limits(page.len(), budget));
        assert!(registry.sending(RELAY, 1, &req("~f1")));
        for event in &page {
            let frame = RelayMessage::event(SubscriptionId::new("~f1"), event.clone()).as_json();
            registry.received(1, format!("{frame}  "));
        }
        assert_eq!(queued(&slot), page.len());
        assert_eq!(slot.lock().end, None);
        // At the limit once trimmed, as the SDK measures it.
        let at_limit = format!(r#"["EOSE","~f1","{}"]"#, "x".repeat(500 - 17));
        assert_eq!(at_limit.len(), 500);
        registry.received(1, format!("\n{at_limit}\n"));
        assert_eq!(slot.lock().end, None);
        registry.received(1, format!(r#"["EVENT","~f1","{}"]"#, "x".repeat(500)));
        assert_eq!(slot.lock().end, Some(FiniteEnd::InvalidMessage));
    }

    /// A client connected to `url` with finite requests installed, as
    /// `NostrSdkRelayClient::from_builder` installs them.
    async fn client_on(keys: Option<Keys>, url: &RelayUrl) -> (FiniteRequests, Client) {
        let builder = crate::network_proxy::nostr_builder(Ok(None));
        let builder = match keys {
            Some(keys) => builder.authenticator(SignerAuthenticator::new(keys)),
            None => builder,
        };
        let finite = FiniteRequests::for_builder(&builder);
        let transport = finite.transport(builder.websocket_transport.clone());
        let client = builder.websocket_transport(transport).build();
        client.add_relay(url).await.unwrap();
        client
            .try_connect_relay(url, Duration::from_secs(5))
            .await
            .unwrap();
        (finite, client)
    }

    /// History replies never reach the SDK: no notification, before or after
    /// the request ends. While the caller is not reading them, they wait in
    /// the request's queue, and a live event on the same connection is
    /// delivered at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn history_never_reaches_the_sdk_or_holds_up_live_events() {
        let relay = LocalRelay::builder().build();
        relay.run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let history: HashSet<EventId> = {
            let mut ids = HashSet::new();
            for n in 0..400 {
                let event = note(&keys, &format!("history {n}"));
                ids.insert(event.id);
                relay.add_event(event).await.unwrap();
            }
            ids
        };
        let (finite, client) = client_on(None, &url).await;
        let mut notifications = client.notifications();
        client
            .subscribe(Filter::new().kind(Kind::Metadata).since(Timestamp::now()))
            .await
            .unwrap();
        let sdk_relay = client.relay(&url).await.unwrap().unwrap();

        let cancel = CancellationToken::new();
        let filter = Filter::new().kind(Kind::TextNote);
        let mut fetch =
            std::pin::pin!(finite.fetch(&sdk_relay, filter, limits(1_000, 1 << 24), &cancel));
        // One poll queues the REQ; the caller then stops reading.
        assert!(futures::poll!(fetch.as_mut()).is_pending());

        let live = EventBuilder::new(Kind::Metadata, "{}")
            .finalize(&keys)
            .unwrap();
        relay.add_event(live.clone()).await.unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match notifications.next().await {
                    Some(ClientNotification::Event { event, .. }) if event.id == live.id => break,
                    Some(ClientNotification::Event { event, .. }) => {
                        assert!(!history.contains(&event.id), "history reached the SDK");
                    }
                    Some(ClientNotification::Message { message, .. }) => {
                        assert!(!message.as_json().contains(ID_PREFIX), "{message:?}");
                    }
                    Some(_) => {}
                    None => panic!("notifications ended"),
                }
            }
        })
        .await;
        assert!(delivered.is_ok(), "the live event waited for history");

        let reply = fetch.await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(
            reply
                .events
                .iter()
                .map(|event| event.id)
                .collect::<HashSet<_>>(),
            history
        );

        // Nothing of the request reaches the SDK afterwards either. The relay
        // answers one connection's frames in order, so every frame it sent
        // for the request, up to its CLOSE, comes before a later REQ's EOSE.
        let barrier = client
            .subscribe(Filter::new().kind(Kind::Metadata).limit(0))
            .await
            .unwrap()
            .value;
        let barrier_reached = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match notifications.next().await.expect("notifications ended") {
                ClientNotification::Message { message, .. } => {
                    assert!(!message.as_json().contains(ID_PREFIX), "{message:?}");
                    if matches!(message.as_ref(), RelayMessage::EndOfStoredEvents(id) if **id == barrier)
                    {
                        break;
                    }
                }
                ClientNotification::Event { event, .. } => {
                    assert!(!history.contains(&event.id), "history reached the SDK");
                }
                _ => {}
            }
            }
        })
        .await;
        assert!(barrier_reached.is_ok(), "the later REQ's EOSE never came");
        client.shutdown().await;
    }

    /// Signals `0` when asked to admit an event, and never answers: an
    /// admission check that stalls part-way through a page.
    #[derive(Debug)]
    struct Stalled(Arc<Notify>);

    impl AdmitPolicy for Stalled {
        fn admit_event<'a>(
            &'a self,
            _: &'a RelayUrl,
            _: &'a SubscriptionId,
            _: &'a Event,
        ) -> Pin<Box<dyn Future<Output = Result<AdmitStatus, nostr_sdk::error::Error>> + Send + 'a>>
        {
            self.0.notify_one();
            Box::pin(futures::future::pending())
        }
    }

    /// A cancellation stops a request at once, even part-way through a page
    /// and while an admission check is still pending, and charges every EVENT
    /// frame it was sent and did not finish reading, so a sweep cut mid-page
    /// still meters the page.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancellation_mid_page_charges_the_unread_frames() {
        let relay = LocalRelay::builder().build();
        relay.run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        // The request is the registry's first, so its id is `~f0`.
        let mut page_bytes = 0;
        for n in 0..300 {
            let event = note(&keys, &format!("history {n}"));
            page_bytes += event_frame(&event).len() as u64;
            relay.add_event(event).await.unwrap();
        }
        let started = Arc::new(Notify::new());
        let builder =
            crate::network_proxy::nostr_builder(Ok(None)).admit_policy(Stalled(started.clone()));
        let finite = FiniteRequests::for_builder(&builder);
        let transport = finite.transport(builder.websocket_transport.clone());
        let client = builder.websocket_transport(transport).build();
        client.add_relay(&url).await.unwrap();
        client
            .try_connect_relay(&url, Duration::from_secs(5))
            .await
            .unwrap();
        let sdk_relay = client.relay(&url).await.unwrap().unwrap();
        let cancel = CancellationToken::new();
        let filter = Filter::new().kind(Kind::TextNote);
        let mut fetch =
            std::pin::pin!(finite.fetch(&sdk_relay, filter, limits(1_000, 1 << 24), &cancel));
        tokio::select! {
            reply = &mut fetch => panic!("ended before its first admission: {reply:?}"),
            () = started.notified() => {}
        }
        // The collector is stuck on the first event; wait for the rest of the
        // page to reach the request behind it.
        let slot = finite.0.slots().pop().expect("the request is registered");
        tokio::time::timeout(Duration::from_secs(10), async {
            while slot.lock().event_frames < 300 {
                slot.ready.notified().await;
            }
        })
        .await
        .expect("the page is queued");
        cancel.cancel();
        let reply = fetch.await;
        assert_eq!(reply.end, FiniteEnd::Cancelled);
        // Every frame is charged once, whole, the one held in admission
        // included.
        assert_eq!(reply.fetched_bytes, page_bytes);
        client.shutdown().await;
    }

    /// A refusal partway through a page keeps that page: the retry's reply
    /// continues the refused attempt's, within what it left of the budget.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retry_after_authentication_continues_the_refused_page() {
        let keys = Keys::generate();
        let [a, b] = ["a", "b"].map(|content| note(&keys, content));
        for (max_items, end, kept) in [
            (10, FiniteEnd::Eose, vec![a.clone(), b.clone()]),
            (1, FiniteEnd::ItemLimit, vec![a.clone()]),
        ] {
            let (url, server) = refusing_relay(a.clone(), b.clone()).await;
            let (finite, client) = client_on(Some(Keys::generate()), &url).await;
            let relay = client.relay(&url).await.unwrap().unwrap();
            let reply = finite
                .fetch(
                    &relay,
                    Filter::new().kind(Kind::TextNote),
                    limits(max_items, 1 << 20),
                    &CancellationToken::new(),
                )
                .await;
            assert_eq!(reply.end, end, "budget {max_items}");
            assert_eq!(reply.events, kept, "budget {max_items}");
            assert_eq!(reply.raw_items, 2, "budget {max_items}");
            client.shutdown().await;
            server.abort();
        }
    }

    /// A relay that answers its first REQ with `first` and an
    /// `auth-required` refusal, authenticates the client, and answers the
    /// next REQ with `second` and EOSE.
    async fn refusing_relay(
        first: Event,
        second: Event,
    ) -> (RelayUrl, tokio::task::JoinHandle<()>) {
        use tokio_tungstenite::tungstenite::Message as Ws;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = RelayUrl::parse(&format!("ws://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut reqs = 0;
            while let Some(Ok(message)) = socket.next().await {
                let Ws::Text(text) = message else {
                    continue;
                };
                let frame: Value = serde_json::from_str(&text).unwrap();
                let replies = match (frame[0].as_str(), frame[1].as_str()) {
                    (Some("REQ"), Some(id)) => {
                        reqs += 1;
                        if reqs == 1 {
                            vec![
                                serde_json::json!(["EVENT", id, first]),
                                serde_json::json!(["CLOSED", id, "auth-required: sign in"]),
                                serde_json::json!(["AUTH", "challenge"]),
                            ]
                        } else {
                            vec![
                                serde_json::json!(["EVENT", id, second]),
                                serde_json::json!(["EOSE", id]),
                            ]
                        }
                    }
                    (Some("AUTH"), _) => {
                        vec![serde_json::json!(["OK", frame[1]["id"], true, ""])]
                    }
                    _ => Vec::new(),
                };
                for reply in replies {
                    socket
                        .send(Ws::Text(reply.to_string().into()))
                        .await
                        .unwrap();
                }
            }
        });
        (url, server)
    }

    /// The client's own relay limits apply, as the SDK applies them to its
    /// subscriptions.
    #[tokio::test]
    async fn the_clients_relay_limits_apply() {
        let keys = Keys::generate();
        let small = note(&keys, "small");
        let large = note(&keys, &"x".repeat(1_000));
        let mut relay_limits = nostr_sdk::relay::RelayLimits::default();
        relay_limits.events.max_size = Some(500);
        let finite = FiniteRequests::for_builder(
            &crate::network_proxy::nostr_builder(Ok(None)).relay_limits(relay_limits),
        );
        let reply = collect_with(
            &finite,
            &Filter::new().kind(Kind::TextNote),
            limits(10, 1 << 20),
            &[event_frame(&small), event_frame(&large), eose("")],
        )
        .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.events, vec![small]);
        assert_eq!(reply.raw_items, 2);
    }

    /// A relay that requires NIP-42 for reads is asked again, under a new id,
    /// once the client authenticates. A client that cannot authenticate gets
    /// the refusal at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_auth_required_refusal_is_retried_after_authentication() {
        let relay = LocalRelay::builder()
            .nip42(LocalRelayBuilderNip42::read())
            .build();
        relay.run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let stored = note(&keys, "stored");
        relay.add_event(stored.clone()).await.unwrap();
        let filter = Filter::new().kind(Kind::TextNote);
        let cancel = CancellationToken::new();

        let (finite, client) = client_on(Some(keys.clone()), &url).await;
        let sdk_relay = client.relay(&url).await.unwrap().unwrap();
        let reply = finite
            .fetch(&sdk_relay, filter.clone(), limits(10, 1 << 20), &cancel)
            .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.events, vec![stored]);
        client.shutdown().await;

        let (finite, client) = client_on(None, &url).await;
        let sdk_relay = client.relay(&url).await.unwrap().unwrap();
        let started = Instant::now();
        let reply = finite
            .fetch(&sdk_relay, filter, limits(10, 1 << 20), &cancel)
            .await;
        assert!(matches!(&reply.end, FiniteEnd::Closed(reason) if is_auth_required(reason)));
        assert!(started.elapsed() < Duration::from_secs(5));
        client.shutdown().await;
    }
}
