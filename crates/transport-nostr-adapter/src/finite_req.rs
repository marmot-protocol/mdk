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
//! Each request's queue holds at most its byte budget plus one frame: a
//! relay that keeps to the request never fills it, however slow the caller.
//! A full queue ends the request as a byte-budget cut. Frames past the item
//! budget are dropped unparsed. A frame the wrapper cannot attribute to any
//! request (one whose verb or EVENT id it cannot read) ends every request on
//! its connection `InvalidMessage`, as it might have been one of theirs.
//!
//! The collector applies the checks the SDK applies to subscription input: the
//! SDK's message and tag ceilings, expiry, and the event id and signature of
//! the bytes supplied. It also drops an event outside the request's filter. A
//! pair of id and signature it already verified skips only the signature
//! check; the id is recomputed from the supplied bytes every time.

use std::borrow::Cow;
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
use nostr_sdk::prelude::{
    ClientMessage, Event, EventId, Filter, Kind, Relay, Signature, SubscriptionId, Url,
};
use nostr_sdk::relay::RelayNotification;
use nostr_sdk::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use serde_json::Value;
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::sweep::hint_tap::{head_verb, second_string};

/// Starts every finite request's subscription id. No id the SDK or the
/// adapter makes starts with `~`.
pub(crate) const ID_PREFIX: &str = "~f";

/// The largest frame a request takes: nostr-sdk's default message ceiling,
/// which the SDK applies to subscription input before parsing it.
const MAX_FRAME_BYTES: usize = 5 * 1024 * 1024;

/// nostr-sdk's default tag ceilings for subscription input.
const MAX_TAGS: usize = 2_000;
const MAX_CONTACT_LIST_TAGS: usize = 10_000;

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
    /// Event bytes the relay sent for the request: the serialized JSON of
    /// each valid copy, and the whole frame of every other EVENT taken off
    /// the wire for it, read or not. A cut or cancelled reply reports them too.
    pub(crate) fetched_bytes: u64,
    /// Its EOSE carried NIP-67 `more`.
    pub(crate) more: bool,
    pub(crate) end: FiniteEnd,
}

impl FiniteReply {
    fn ended(end: FiniteEnd) -> Self {
        Self {
            events: Vec::new(),
            raw_items: 0,
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

    /// A frame for this request, read on `connection`.
    fn receive(&self, connection: u64, verb: &str, text: String) {
        let mut state = self.lock();
        if state.binding != Binding::Sent(connection) {
            return;
        }
        let event = verb == "EVENT";
        let bytes = text.len();
        if state.end.is_some() {
            if event {
                state.dropped_event_bytes += bytes as u64;
            }
            return;
        }
        if bytes > MAX_FRAME_BYTES {
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
    pub(crate) fn new(can_authenticate: bool) -> Self {
        Self(Arc::new(Registry {
            can_authenticate,
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
    /// new id after the client authenticates; the reply is the retry's, with
    /// the refused attempt's bytes still charged.
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
        let mut notifications = self.0.can_authenticate.then(|| relay.notifications());
        let first = self.request(relay, &filter, limits, deadline, cancel).await;
        let auth_required =
            matches!(&first.end, FiniteEnd::Closed(reason) if is_auth_required(reason));
        let Some(notifications) = notifications.as_mut().filter(|_| auth_required) else {
            return first;
        };
        if !authenticated(notifications, deadline, cancel).await {
            return first;
        }
        let mut retry = self.request(relay, &filter, limits, deadline, cancel).await;
        retry.fetched_bytes += first.fetched_bytes;
        retry
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
        let slot = Arc::new(Slot {
            relay: <&Url>::from(relay.url()).as_str().to_owned(),
            max_items: limits.max_items,
            queue_bytes: limits.max_event_bytes.saturating_add(MAX_FRAME_BYTES),
            state: Mutex::default(),
            ready: Notify::new(),
        });
        let registered = Registered::new(&self.0, id.clone(), slot.clone(), relay.clone());
        let req = ClientMessage::req(SubscriptionId::new(&id), vec![filter.clone()]);
        let queued = tokio::select! {
            biased;
            () = cancel.cancelled() => return FiniteReply::ended(FiniteEnd::Cancelled),
            () = tokio::time::sleep_until(deadline) => return FiniteReply::ended(FiniteEnd::TimedOut),
            queued = relay.send_msg(req).into_future() => queued,
        };
        if queued.is_err() {
            return FiniteReply::ended(FiniteEnd::SetupFailed);
        }
        let verified = &self.0.verified;
        let mut collector = Collector::new(filter, limits, verified);
        // Whether the collector read the frame that ended the request. What
        // the relay sent past that frame is not read and not charged, as the
        // SDK's own requests discard it. A request something else ended (a
        // cancellation, its deadline, its connection) is charged for every
        // frame it was sent and did not read.
        let (end, read_to_end) = loop {
            match slot.take() {
                Ok(frames) => {
                    let mut ended = None;
                    for frame in frames {
                        if let Some(end) = collector.frame(&frame) {
                            ended = Some(end);
                            break;
                        }
                        tokio::task::coop::consume_budget().await;
                    }
                    if let Some(end) = ended {
                        break (end, true);
                    }
                }
                Err(Some(end)) => break (end, false),
                Err(None) => {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => break (FiniteEnd::Cancelled, false),
                        () = tokio::time::sleep_until(deadline) => break (FiniteEnd::TimedOut, false),
                        () = slot.ready.notified() => {}
                    }
                }
            }
        };
        let unread = registered.retire().await;
        if !read_to_end {
            collector.charge_unread(unread.frames);
            collector.fetched_bytes += unread.dropped_event_bytes;
        }
        collector.reply(end)
    }
}

/// Whether a `CLOSED` reason asks for NIP-42 authentication. Some relays put
/// the prefix behind one `error:` wrapper (mdk#3439).
fn is_auth_required(reason: &str) -> bool {
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
    notifications: &mut (impl Stream<Item = RelayNotification> + Unpin),
    deadline: Instant,
    cancel: &CancellationToken,
) -> bool {
    let wait = async {
        while let Some(notification) = notifications.next().await {
            match notification {
                RelayNotification::Authenticated => return true,
                RelayNotification::AuthenticationFailed => return false,
                _ => {}
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
    verified: &'a Mutex<Verified>,
    seen: HashSet<EventId>,
    events: Vec<Event>,
    raw_items: usize,
    event_bytes: usize,
    fetched_bytes: u64,
    more: bool,
}

impl<'a> Collector<'a> {
    fn new(filter: &'a Filter, limits: FiniteLimits, verified: &'a Mutex<Verified>) -> Self {
        Self {
            filter,
            limits,
            verified,
            seen: HashSet::new(),
            events: Vec::new(),
            raw_items: 0,
            event_bytes: 0,
            fetched_bytes: 0,
            more: false,
        }
    }

    /// Read one frame; the request's end, when this frame ends it.
    fn frame(&mut self, text: &str) -> Option<FiniteEnd> {
        let Ok(message) = RelayMessage::from_json(text) else {
            if head_verb(text).as_deref() == Some("EVENT") {
                self.raw_items += 1;
                self.fetched_bytes += text.len() as u64;
            }
            return Some(FiniteEnd::InvalidMessage);
        };
        match message {
            RelayMessage::Event { event, .. } => self.event(event.into_owned(), text.len()),
            RelayMessage::EndOfStoredEvents(_) => {
                self.more =
                    serde_json::from_str::<Value>(text).is_ok_and(|frame| says_more(frame.get(2)));
                Some(FiniteEnd::Eose)
            }
            RelayMessage::Closed { message, .. } => Some(FiniteEnd::Closed(message.into_owned())),
            // The wrapper diverts nothing else.
            _ => Some(FiniteEnd::InvalidMessage),
        }
    }

    fn event(&mut self, event: Event, frame_bytes: usize) -> Option<FiniteEnd> {
        self.raw_items += 1;
        if !self.valid(&event) {
            self.fetched_bytes += frame_bytes as u64;
            return (self.raw_items > self.limits.max_items).then_some(FiniteEnd::ItemLimit);
        }
        let bytes = event.as_json().len();
        self.fetched_bytes += bytes as u64;
        self.event_bytes = self.event_bytes.saturating_add(bytes);
        if self.raw_items > self.limits.max_items {
            return Some(FiniteEnd::ItemLimit);
        }
        if self.event_bytes > self.limits.max_event_bytes {
            return Some(FiniteEnd::ByteLimit);
        }
        if self.seen.insert(event.id) {
            self.events.push(event);
        }
        None
    }

    fn valid(&self, event: &Event) -> bool {
        let max_tags = if event.kind == Kind::ContactList {
            MAX_CONTACT_LIST_TAGS
        } else {
            MAX_TAGS
        };
        if event.tags.len() > max_tags
            || event.is_expired()
            || !self.filter.match_event(event, MATCH)
            || !event.verify_id()
        {
            return false;
        }
        let pair = (event.id, event.sig);
        let lock = || self.verified.lock().unwrap_or_else(|e| e.into_inner());
        if lock().contains(&pair) {
            return true;
        }
        if !event.verify_signature() {
            return false;
        }
        lock().insert(pair);
        true
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

impl Registry {
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
        let Some(verb) = head_verb(&text).map(Cow::into_owned) else {
            self.unattributed(connection);
            return Some(text);
        };
        if !matches!(verb.as_str(), "EVENT" | "EOSE" | "CLOSED") {
            return Some(text);
        }
        match second_string(&text) {
            Some(id) if id.starts_with(ID_PREFIX) => {
                // Unknown: a request that already ended. Dropped unread.
                if let Some(slot) = self.slot(&id) {
                    slot.receive(connection, &verb, text);
                }
                None
            }
            // An EVENT whose id cannot be read may have been anyone's.
            None if verb == "EVENT" => {
                self.unattributed(connection);
                Some(text)
            }
            _ => Some(text),
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

    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp};
    use nostr_sdk::authenticator::SignerAuthenticator;
    use nostr_sdk::local_relay::{LocalRelay, LocalRelayBuilderNip42};
    use nostr_sdk::prelude::{Client, ClientNotification, RelayUrl};

    use super::*;

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

    /// Read `frames` in order as one request of `filter` would.
    fn collect(filter: &Filter, limits: FiniteLimits, frames: &[String]) -> FiniteReply {
        let verified = Mutex::default();
        let mut collector = Collector::new(filter, limits, &verified);
        for frame in frames {
            if let Some(end) = collector.frame(frame) {
                return collector.reply(end);
            }
        }
        collector.reply(FiniteEnd::TimedOut)
    }

    /// An event the SDK would drop never reaches the result, but its frame
    /// still counts toward the relay's reply, so a page of them is not a
    /// short page.
    #[test]
    fn only_valid_matching_events_are_kept_and_every_frame_counts() {
        let keys = Keys::generate();
        let good = note(&keys, "good");
        let expired = EventBuilder::new(Kind::TextNote, "expired")
            .tag(Tag::expiration(Timestamp::from_secs(1)))
            .finalize(&keys)
            .unwrap();
        let off_filter = EventBuilder::new(Kind::Metadata, "{}")
            .finalize(&keys)
            .unwrap();
        let crowded = EventBuilder::new(Kind::TextNote, "crowded")
            .tags((0..=MAX_TAGS).map(|n| Tag::parse(["x", &n.to_string()]).unwrap()))
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
        );
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.raw_items, 6);
        assert_eq!(reply.events, vec![good]);

        // A frame that names the request but cannot be read ends it: a later
        // EOSE cannot turn the lost event into a short page.
        let reply = collect(
            &filter,
            limits(10, 1 << 20),
            &[r#"["EVENT","~f0",{"id":7}]"#.to_owned(), eose("")],
        );
        assert_eq!(reply.end, FiniteEnd::InvalidMessage);
        assert_eq!(reply.raw_items, 1);
    }

    /// Budgets count duplicates and the first event over them, which is not
    /// kept. A reply exactly at its budget still completes at its EOSE.
    #[test]
    fn budgets_count_the_first_overflow_and_keep_it_out() {
        let keys = Keys::generate();
        let events: Vec<Event> = (0..3).map(|n| note(&keys, &n.to_string())).collect();
        let filter = Filter::new().kind(Kind::TextNote);
        let one = events[0].as_json().len();

        let frames: Vec<String> = events.iter().map(event_frame).chain([eose("")]).collect();
        let at_limit = collect(&filter, limits(3, 3 * one + 3), &frames);
        assert_eq!(at_limit.end, FiniteEnd::Eose);
        assert_eq!(at_limit.events.len(), 3);

        let over_items = collect(&filter, limits(2, 1 << 20), &frames);
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
        let over_bytes = collect(&filter, limits(10, 2 * one + one / 2), &with_duplicate);
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
        let verified = Mutex::default();
        let filter = Filter::new().kind(Kind::TextNote);
        let collector = Collector::new(&filter, limits(10, 1 << 20), &verified);
        assert!(collector.valid(&good));
        assert!(verified.lock().unwrap().contains(&(good.id, good.sig)));
        let mut tampered = good.clone();
        tampered.content = "tampered".to_owned();
        assert!(!collector.valid(&tampered));
        let mut resigned = good.clone();
        resigned.sig = note(&keys, "other").sig;
        assert!(!collector.valid(&resigned), "an unverified pair is checked");
    }

    #[test]
    fn eose_hints_and_closed_reasons_are_kept() {
        let filter = Filter::new().kind(Kind::TextNote);
        let reply = collect(&filter, limits(1, 1), &[eose(r#",["auth","more"]"#)]);
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert!(reply.more);
        let reply = collect(&filter, limits(1, 1), &[eose(r#",["finish"]"#)]);
        assert!(!reply.more);
        let closed =
            RelayMessage::closed(SubscriptionId::new("~f0"), "rate-limited: slow").as_json();
        let reply = collect(&filter, limits(1, 1), &[closed]);
        assert_eq!(
            reply.end,
            FiniteEnd::Closed("rate-limited: slow".to_owned())
        );
        assert!(is_auth_required("auth-required: sign in"));
        assert!(is_auth_required("ERROR: auth-required: sign in"));
        assert!(!is_auth_required("restricted: auth-required: no"));
    }

    /// A request registered under `id` for [`RELAY`], as `fetch` registers
    /// one before queuing its REQ.
    fn register(registry: &Registry, id: &str, limits: FiniteLimits) -> Arc<Slot> {
        let slot = Arc::new(Slot {
            relay: RELAY.to_owned(),
            max_items: limits.max_items,
            queue_bytes: limits.max_event_bytes.saturating_add(MAX_FRAME_BYTES),
            state: Mutex::default(),
            ready: Notify::new(),
        });
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
        let registry = FiniteRequests::new(false).0;
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

    /// A REQ still queued when its request ended, or one for no registered
    /// request, never goes out.
    #[test]
    fn a_retired_request_sends_no_req() {
        let registry = FiniteRequests::new(false).0;
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
        let registry = FiniteRequests::new(false).0;
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

    /// The reader never waits on a request: frames past its item budget are
    /// dropped unread, and a queue past its byte budget cuts it.
    #[test]
    fn wire_bounds_cut_a_request_without_holding_the_reader() {
        let registry = FiniteRequests::new(false).0;
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
    }

    async fn client_on(finite: &FiniteRequests, keys: Option<Keys>, url: &RelayUrl) -> Client {
        let builder = crate::network_proxy::nostr_builder(Ok(None));
        let builder = match keys {
            Some(keys) => builder.authenticator(SignerAuthenticator::new(keys)),
            None => builder,
        };
        let transport = finite.transport(builder.websocket_transport.clone());
        let client = builder.websocket_transport(transport).build();
        client.add_relay(url).await.unwrap();
        client
            .try_connect_relay(url, Duration::from_secs(5))
            .await
            .unwrap();
        client
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
        let finite = FiniteRequests::new(false);
        let client = client_on(&finite, None, &url).await;
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

        // Nothing of the request reaches the SDK afterwards either.
        while let Ok(Some(notification)) =
            tokio::time::timeout(Duration::from_millis(200), notifications.next()).await
        {
            if let ClientNotification::Message { message, .. } = notification {
                assert!(!message.as_json().contains(ID_PREFIX), "{message:?}");
            }
        }
        client.shutdown().await;
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

        let finite = FiniteRequests::new(true);
        let client = client_on(&finite, Some(keys.clone()), &url).await;
        let sdk_relay = client.relay(&url).await.unwrap().unwrap();
        let reply = finite
            .fetch(&sdk_relay, filter.clone(), limits(10, 1 << 20), &cancel)
            .await;
        assert_eq!(reply.end, FiniteEnd::Eose);
        assert_eq!(reply.events, vec![stored]);
        client.shutdown().await;

        let finite = FiniteRequests::new(false);
        let client = client_on(&finite, None, &url).await;
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
