//! Request-owned WebSocket transport for public-event preview queries.
//!
//! The default SDK transport resolves and dials relay hostnames itself, so the
//! relay plane could only classify literal hosts. Preview queries accept
//! untrusted `nevent`/`naddr` relay hints, so this transport applies the full
//! dial discipline from `docs/marmot-architecture/overview/dial-safety.md`:
//! the URL passes [`RelaySafetyPolicy`] again (retired hosts, plaintext, onion
//! and literal-address rules), the hostname is resolved once, every resolved
//! address passes `reject_non_public_ip`, and the TCP connection is pinned to a
//! validated `SocketAddr`. TLS then runs over that socket with the original URL
//! hostname for SNI and certificate verification (WebPKI roots, the SDK
//! default); no proxy, no redirect and no IP rewriting. Loopback is reachable
//! only for a literal loopback host under the explicit
//! `allow_loopback_relay_endpoints` dev flag, and then every resolved address
//! must be loopback.
//!
//! Received traffic is charged in two places, never twice. Raw bytes are
//! charged by [`PinnedSocketIo`], which wraps the pinned TCP socket *below*
//! TLS and WebSocket parsing: TLS records, the HTTP upgrade response, frame
//! headers, fragmented and empty continuation frames all consume the shared
//! [`PublicEventTrafficMeter`] byte budget before any parser sees them, and a
//! read that crosses the budget is discarded and closes the socket. The byte
//! budget is therefore a conservative wire budget that includes TLS and HTTP
//! handshakes. Each decoded relay message is then charged as one item or one
//! message (no bytes) before the SDK verifies or deduplicates it: `EVENT`
//! envelopes are classified by actually decoding the JSON command (escaped
//! spellings included) and undecodable text counts as an event. Outbound
//! traffic is locally generated (bounded filters) and not charged.
//!
//! Every socket of a request phase belongs to a request-owned
//! [`PublicEventSocketRegistry`]. The same absolute deadline is enforced by the
//! socket adapter for reads and writes (readiness, flush and shutdown
//! included), by the outbound sink and by the inbound stream; whichever sees it
//! first forcibly drops the TCP stream, closing the descriptor even while SDK
//! cleanup still runs its own longer close timeout. When the phase ends, or its
//! future is dropped, the registry closes every remaining socket and refuses new
//! ones. There is no background task: cleanup is bounded by the request's own
//! lifetime.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::task::{Context, Poll, Waker, ready};

use async_wsocket::Message;
use cgka_traits::TransportEndpoint;
use cgka_traits::app_components::{is_loopback_host, is_loopback_ip, reject_non_public_ip};
use futures::{Sink, Stream, StreamExt};
use nostr_sdk::error::Error as SdkError;
use nostr_sdk::transport::websocket::WebSocketTransport;
use pinned_tokio_tungstenite::tungstenite::Error as TungsteniteError;
use pinned_tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
use pinned_tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep, timeout_at};
use url::{Host, Url};

use super::{DIRECTORY_RELAY_CONNECT_WAIT, RelaySafetyPolicy};

/// Largest WebSocket frame or message accepted from a preview relay: one
/// 256 KiB signed event plus its relay envelope.
pub(crate) const PUBLIC_EVENT_MAX_FRAME_BYTES: usize = 320 * 1024;
/// Resolved addresses tried per relay; the rest are ignored.
const MAX_PINNED_ADDRESSES: usize = 8;
/// Sockets one request phase may open, reconnect attempts included: two per
/// relay for the four-relay maximum.
const MAX_SOCKETS_PER_PHASE: usize = 8;

type TransportSink = Pin<Box<dyn Sink<Message, Error = SdkError> + Send>>;
type TransportStream = Pin<Box<dyn Stream<Item = Result<Message, SdkError>> + Send>>;
type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(TransportSink, TransportStream), SdkError>> + Send + 'a>>;

/// Context-free dial refusal. Display and Debug never carry the URL, DNS
/// answers or addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicEventDialRefused;

impl fmt::Display for PublicEventDialRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("public event relay dial refused")
    }
}

impl std::error::Error for PublicEventDialRefused {}

fn refused() -> SdkError {
    SdkError::transport(PublicEventDialRefused)
}

/// The socket was closed by its deadline, the traffic budget or request
/// cleanup. Carries no URL, address or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicEventSocketClosed;

impl fmt::Display for PublicEventSocketClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("public event relay socket closed")
    }
}

impl std::error::Error for PublicEventSocketClosed {}

fn socket_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, PublicEventSocketClosed)
}

/// Limits for one meter. A child meter charges its parent too, so a phase
/// meter and the whole request share one set of request-wide counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicEventTrafficLimits {
    /// Decoded `EVENT` envelopes, duplicates and invalid events included.
    pub(crate) max_items: usize,
    /// Raw received wire bytes: TLS records, the HTTP upgrade response and
    /// every WebSocket frame header and payload, fragments included.
    pub(crate) max_bytes: usize,
    /// Decoded non-`EVENT` relay messages and control frames.
    pub(crate) max_messages: usize,
}

/// Add `amount` without wrapping and return the new value.
fn saturating_add(counter: &AtomicUsize, amount: usize) -> usize {
    let previous = counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            Some(value.saturating_add(amount))
        })
        .unwrap_or_else(|value| value);
    previous.saturating_add(amount)
}

/// Shared received-traffic counters. Cloned only as an `Arc`; no task or
/// daemon owns it, and it dies with the request.
#[derive(Debug)]
pub(crate) struct PublicEventTrafficMeter {
    parent: Option<Arc<PublicEventTrafficMeter>>,
    limits: PublicEventTrafficLimits,
    items: AtomicUsize,
    bytes: AtomicUsize,
    messages: AtomicUsize,
    exhausted: AtomicBool,
}

impl PublicEventTrafficMeter {
    pub(crate) fn new(limits: PublicEventTrafficLimits) -> Arc<Self> {
        Arc::new(Self {
            parent: None,
            limits,
            items: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            messages: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
        })
    }

    pub(crate) fn child(parent: &Arc<Self>, limits: PublicEventTrafficLimits) -> Arc<Self> {
        Arc::new(Self {
            parent: Some(parent.clone()),
            limits,
            items: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            messages: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
        })
    }

    pub(crate) fn items(&self) -> usize {
        self.items.load(Ordering::SeqCst)
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn messages(&self) -> usize {
        self.messages.load(Ordering::SeqCst)
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_exhausted())
    }

    /// Charge bytes and one item or message here and in every ancestor.
    /// Returns whether delivery may continue; the charge is kept either way.
    #[cfg(test)]
    pub(crate) fn charge(&self, bytes: usize, event: bool) -> bool {
        self.charge_counts(bytes, usize::from(event), usize::from(!event))
    }

    /// Charge raw received wire bytes before any parser sees them.
    pub(crate) fn charge_wire(&self, bytes: usize) -> bool {
        self.charge_counts(bytes, 0, 0)
    }

    /// Charge one decoded relay message. Its bytes were already charged on
    /// the wire, so they are not counted again.
    pub(crate) fn charge_message(&self, event: bool) -> bool {
        self.charge_counts(0, usize::from(event), usize::from(!event))
    }

    fn charge_counts(&self, bytes: usize, items: usize, messages: usize) -> bool {
        let parent_ok = self
            .parent
            .as_ref()
            .is_none_or(|parent| parent.charge_counts(bytes, items, messages));
        let bytes = saturating_add(&self.bytes, bytes);
        let items = saturating_add(&self.items, items);
        let messages = saturating_add(&self.messages, messages);
        let within = items <= self.limits.max_items
            && bytes <= self.limits.max_bytes
            && messages <= self.limits.max_messages;
        if !(parent_ok && within) {
            self.exhausted.store(true, Ordering::SeqCst);
        }
        !self.is_exhausted()
    }
}

/// One pinned TCP stream shared by its I/O adapter and its request registry,
/// so request cleanup can drop the descriptor even when nobody polls it.
#[derive(Debug, Default)]
struct SocketSlot {
    state: StdMutex<SocketState>,
}

#[derive(Debug, Default)]
struct SocketState {
    stream: Option<TcpStream>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl SocketSlot {
    fn lock(&self) -> MutexGuard<'_, SocketState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Drop the TCP stream (closing its descriptor) and wake both directions.
    fn close(&self) {
        let (stream, read, write) = {
            let mut state = self.lock();
            (
                state.stream.take(),
                state.read_waker.take(),
                state.write_waker.take(),
            )
        };
        drop(stream);
        for waker in [read, write].into_iter().flatten() {
            waker.wake();
        }
    }

    fn is_open(&self) -> bool {
        self.lock().stream.is_some()
    }
}

/// Every socket one request phase opened. Bounded, request-owned and closed as
/// a whole when the phase ends or its future is dropped.
#[derive(Debug, Default)]
pub(crate) struct PublicEventSocketRegistry {
    state: StdMutex<RegistryState>,
}

#[derive(Debug, Default)]
struct RegistryState {
    closed: bool,
    sockets: Vec<Arc<SocketSlot>>,
}

impl PublicEventSocketRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock(&self) -> MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Adopt a connected socket, or drop it when the registry is closed or full.
    fn register(&self, stream: TcpStream) -> Option<Arc<SocketSlot>> {
        let mut state = self.lock();
        if state.closed || state.sockets.len() >= MAX_SOCKETS_PER_PHASE {
            return None;
        }
        let slot = Arc::new(SocketSlot {
            state: StdMutex::new(SocketState {
                stream: Some(stream),
                ..SocketState::default()
            }),
        });
        state.sockets.push(slot.clone());
        Some(slot)
    }

    /// Forcibly close every socket and refuse new ones. Idempotent.
    pub(crate) fn close_all(&self) {
        let sockets = {
            let mut state = self.lock();
            state.closed = true;
            state.sockets.clone()
        };
        for slot in sockets {
            slot.close();
        }
    }

    #[cfg(test)]
    fn open_sockets(&self) -> usize {
        self.lock()
            .sockets
            .iter()
            .filter(|slot| slot.is_open())
            .count()
    }
}

/// Closes a phase's sockets when dropped, including on caller cancellation.
pub(crate) struct CloseSocketsOnDrop(pub(crate) Arc<PublicEventSocketRegistry>);

impl Drop for CloseSocketsOnDrop {
    fn drop(&mut self) {
        self.0.close_all();
    }
}

/// The pinned TCP socket as seen by TLS/WebSocket: charges every received byte
/// before any parser sees it and enforces the request deadline on both
/// directions with separate timers, so read and write wakers both fire.
pub(crate) struct PinnedSocketIo {
    slot: Arc<SocketSlot>,
    meter: Arc<PublicEventTrafficMeter>,
    read_deadline: Pin<Box<Sleep>>,
    write_deadline: Pin<Box<Sleep>>,
}

impl PinnedSocketIo {
    fn new(slot: Arc<SocketSlot>, meter: Arc<PublicEventTrafficMeter>, deadline: Instant) -> Self {
        Self {
            slot,
            meter,
            read_deadline: Box::pin(tokio::time::sleep_until(deadline)),
            write_deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    /// Whether the deadline passed or the shared budget is exhausted. Either
    /// forcibly closes the socket.
    fn must_stop(&mut self, cx: &mut Context<'_>, write: bool) -> bool {
        let deadline = if write {
            &mut self.write_deadline
        } else {
            &mut self.read_deadline
        };
        if deadline.as_mut().poll(cx).is_ready() || self.meter.is_exhausted() {
            self.slot.close();
            return true;
        }
        false
    }

    fn poll_socket<T>(
        &self,
        cx: &mut Context<'_>,
        write: bool,
        op: impl FnOnce(Pin<&mut TcpStream>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let mut state = self.slot.lock();
        let Some(stream) = state.stream.as_mut() else {
            return Poll::Ready(Err(socket_closed()));
        };
        let poll = op(Pin::new(stream), cx);
        if poll.is_pending() {
            let waker = Some(cx.waker().clone());
            if write {
                state.write_waker = waker;
            } else {
                state.read_waker = waker;
            }
        }
        poll
    }
}

impl Drop for PinnedSocketIo {
    fn drop(&mut self) {
        self.slot.close();
    }
}

impl AsyncRead for PinnedSocketIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.must_stop(cx, false) {
            return Poll::Ready(Err(socket_closed()));
        }
        let before = buf.filled().len();
        ready!(this.poll_socket(cx, false, |stream, cx| stream.poll_read(cx, buf)))?;
        let received = buf.filled().len().saturating_sub(before);
        if !this.meter.charge_wire(received) {
            // Over budget: the bytes never reach TLS or WebSocket parsing.
            buf.set_filled(before);
            this.slot.close();
            return Poll::Ready(Err(socket_closed()));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PinnedSocketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.must_stop(cx, true) {
            return Poll::Ready(Err(socket_closed()));
        }
        this.poll_socket(cx, true, |stream, cx| stream.poll_write(cx, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.must_stop(cx, true) {
            return Poll::Ready(Err(socket_closed()));
        }
        this.poll_socket(cx, true, |stream, cx| stream.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Past the deadline the descriptor is dropped instead of waiting for
        // an orderly shutdown; an already closed socket is shut down.
        if this.must_stop(cx, true) || !this.slot.is_open() {
            return Poll::Ready(Ok(()));
        }
        this.poll_socket(cx, true, |stream, cx| stream.poll_shutdown(cx))
    }
}

/// Whether a relay text message is, or may be, an `EVENT` envelope. The
/// command is decoded with a real JSON parser, so spellings that use JSON
/// unicode escapes count too. Anything that cannot be decoded is charged as an
/// event rather than trusted as cheap.
pub(crate) fn relay_text_is_event(text: &str) -> bool {
    use serde::Deserializer as _;
    use serde::de::{IgnoredAny, SeqAccess, Visitor};

    struct Command;

    impl<'de> Visitor<'de> for Command {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a relay message array")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let command = seq.next_element::<String>()?;
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(command)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(text);
    let command = (&mut deserializer)
        .deserialize_seq(Command)
        .and_then(|command| deserializer.end().map(|()| command));
    match command {
        Ok(Some(command)) => command == "EVENT",
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Charge one decoded message as an item or message (its bytes were charged
/// on the wire) and convert it to the SDK message type. `None` means the
/// message must not be delivered and the stream ends.
fn admit_frame(meter: &PublicEventTrafficMeter, message: TungsteniteMessage) -> Option<Message> {
    let event = match &message {
        TungsteniteMessage::Text(text) => relay_text_is_event(text.as_str()),
        TungsteniteMessage::Binary(data) => match std::str::from_utf8(data) {
            Ok(text) => relay_text_is_event(text),
            Err(_) => true,
        },
        _ => false,
    };
    if !meter.charge_message(event) {
        return None;
    }
    Some(match message {
        TungsteniteMessage::Text(text) => Message::Text(text.as_str().to_owned()),
        TungsteniteMessage::Binary(data) => Message::Binary(data.to_vec()),
        TungsteniteMessage::Ping(data) => Message::Ping(data.to_vec()),
        TungsteniteMessage::Pong(data) => Message::Pong(data.to_vec()),
        TungsteniteMessage::Close(frame) => Message::Close(frame.map(Into::into)),
        // Raw frames are never produced while reading.
        TungsteniteMessage::Frame(_) => return None,
    })
}

/// Charges every decoded message before the SDK sees it and ends at the
/// request deadline or when the shared meter is exhausted; either also
/// forcibly closes the underlying socket.
pub(crate) struct MeteredStream<S> {
    inner: S,
    meter: Arc<PublicEventTrafficMeter>,
    deadline: Pin<Box<Sleep>>,
    socket: Option<Arc<SocketSlot>>,
    done: bool,
}

impl<S> MeteredStream<S> {
    pub(crate) fn new(inner: S, meter: Arc<PublicEventTrafficMeter>, deadline: Instant) -> Self {
        Self {
            inner,
            meter,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
            socket: None,
            done: false,
        }
    }

    fn with_socket(mut self, socket: Arc<SocketSlot>) -> Self {
        self.socket = Some(socket);
        self
    }

    fn finish(&mut self) {
        self.done = true;
        if let Some(socket) = &self.socket {
            socket.close();
        }
    }
}

impl<S> Stream for MeteredStream<S>
where
    S: Stream<Item = Result<TungsteniteMessage, TungsteniteError>> + Unpin,
{
    type Item = Result<Message, SdkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        if this.meter.is_exhausted() || this.deadline.as_mut().poll(cx).is_ready() {
            this.finish();
            return Poll::Ready(None);
        }
        match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
            None => {
                this.finish();
                Poll::Ready(None)
            }
            Some(Err(error)) => {
                this.finish();
                Poll::Ready(Some(Err(SdkError::transport(error))))
            }
            Some(Ok(message)) => match admit_frame(&this.meter, message) {
                Some(message) => Poll::Ready(Some(Ok(message))),
                None => {
                    this.finish();
                    Poll::Ready(None)
                }
            },
        }
    }
}

/// Outbound half: converts SDK messages to native frames. Readiness, flush
/// and close all stop at the request deadline, which forcibly closes the
/// socket instead of waiting on a backpressured peer.
struct PinnedSink<S> {
    inner: S,
    socket: Arc<SocketSlot>,
    deadline: Pin<Box<Sleep>>,
}

impl<S> PinnedSink<S> {
    fn new(inner: S, socket: Arc<SocketSlot>, deadline: Instant) -> Self {
        Self {
            inner,
            socket,
            deadline: Box::pin(tokio::time::sleep_until(deadline)),
        }
    }

    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        if self.deadline.as_mut().poll(cx).is_ready() {
            self.socket.close();
            return true;
        }
        false
    }
}

impl<S> Sink<Message> for PinnedSink<S>
where
    S: Sink<TungsteniteMessage, Error = TungsteniteError> + Unpin,
{
    type Error = SdkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.expired(cx) {
            return Poll::Ready(Err(SdkError::transport(PublicEventSocketClosed)));
        }
        Pin::new(&mut this.inner)
            .poll_ready(cx)
            .map_err(SdkError::transport)
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if this.deadline.is_elapsed() {
            this.socket.close();
            return Err(SdkError::transport(PublicEventSocketClosed));
        }
        Pin::new(&mut this.inner)
            .start_send(TungsteniteMessage::from(item))
            .map_err(SdkError::transport)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if this.expired(cx) {
            return Poll::Ready(Err(SdkError::transport(PublicEventSocketClosed)));
        }
        Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(SdkError::transport)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        // Past the deadline the descriptor is already dropped: closed.
        if this.expired(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner)
            .poll_close(cx)
            .map_err(SdkError::transport)
    }
}

/// Resolve once and validate every answer. A literal loopback host is usable
/// only with the dev flag and then only over loopback addresses; any other
/// host must resolve exclusively to public addresses.
pub(crate) async fn resolve_relay_addrs_with<F, Fut>(
    url: &Url,
    allow_loopback: bool,
    resolver: F,
) -> Result<Vec<SocketAddr>, PublicEventDialRefused>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = io::Result<Vec<IpAddr>>>,
{
    let port = url.port_or_known_default().ok_or(PublicEventDialRefused)?;
    let host = url.host().ok_or(PublicEventDialRefused)?;
    let local = allow_loopback && is_loopback_host(host.clone());
    if url.scheme() == "ws" && !local {
        return Err(PublicEventDialRefused);
    }
    let ips = match host {
        Host::Domain(domain) => resolver(domain.to_owned(), port)
            .await
            .map_err(|_| PublicEventDialRefused)?,
        Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
    };
    if ips.is_empty() {
        return Err(PublicEventDialRefused);
    }
    let mut addrs = Vec::new();
    for ip in ips {
        if local {
            if !is_loopback_ip(ip) {
                return Err(PublicEventDialRefused);
            }
        } else {
            reject_non_public_ip(ip, false).map_err(|_| PublicEventDialRefused)?;
        }
        let addr = SocketAddr::new(ip, port);
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    addrs.truncate(MAX_PINNED_ADDRESSES);
    Ok(addrs)
}

async fn connect_pinned(
    addrs: &[SocketAddr],
    deadline: Instant,
) -> Result<TcpStream, PublicEventDialRefused> {
    for addr in addrs {
        if let Ok(Ok(stream)) = timeout_at(deadline, TcpStream::connect(*addr)).await {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    Err(PublicEventDialRefused)
}

/// One request phase's transport. It holds no background task; its sockets
/// belong to the phase's [`PublicEventSocketRegistry`].
#[derive(Clone)]
pub(crate) struct PinnedPublicEventTransport {
    policy: RelaySafetyPolicy,
    meter: Arc<PublicEventTrafficMeter>,
    sockets: Arc<PublicEventSocketRegistry>,
    deadline: Instant,
}

impl fmt::Debug for PinnedPublicEventTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedPublicEventTransport")
            .finish_non_exhaustive()
    }
}

impl PinnedPublicEventTransport {
    pub(crate) fn new(
        policy: RelaySafetyPolicy,
        meter: Arc<PublicEventTrafficMeter>,
        sockets: Arc<PublicEventSocketRegistry>,
        deadline: Instant,
    ) -> Self {
        Self {
            policy,
            meter,
            sockets,
            deadline,
        }
    }

    async fn dial(&self, raw_url: &str) -> Result<(TransportSink, TransportStream), SdkError> {
        if self.meter.is_exhausted() || Instant::now() >= self.deadline {
            return Err(refused());
        }
        let url = Url::parse(raw_url).map_err(|_| refused())?;
        if self
            .policy
            .retain_safe_endpoints(
                vec![TransportEndpoint(url.as_str().to_owned())],
                "public event dial",
            )
            .is_empty()
        {
            return Err(refused());
        }
        let connect_deadline = self
            .deadline
            .min(Instant::now() + DIRECTORY_RELAY_CONNECT_WAIT);
        let addrs = timeout_at(
            connect_deadline,
            resolve_relay_addrs_with(
                &url,
                self.policy.allows_loopback(),
                crate::collector_host_safety::system_resolve,
            ),
        )
        .await
        .map_err(|_| refused())?
        .map_err(SdkError::transport)?;
        let socket = connect_pinned(&addrs, connect_deadline)
            .await
            .map_err(SdkError::transport)?;
        // A closed (finished or cancelled) or full registry drops the socket.
        let slot = self.sockets.register(socket).ok_or_else(refused)?;
        // Raw bytes are metered and the deadline enforced below TLS.
        let io = PinnedSocketIo::new(slot.clone(), self.meter.clone(), self.deadline);
        let config = public_event_websocket_config();
        // The request keeps the original URL, so the Host header, SNI and
        // certificate verification use the configured hostname, never the
        // pinned address.
        let (websocket, _response) = timeout_at(
            connect_deadline,
            pinned_tokio_tungstenite::client_async_tls_with_config(
                url.as_str(),
                io,
                Some(config),
                None,
            ),
        )
        .await
        .map_err(|_| refused())?
        .map_err(SdkError::transport)?;
        let (sink, stream) = websocket.split();
        let sink: TransportSink = Box::pin(PinnedSink::new(sink, slot.clone(), self.deadline));
        let stream: TransportStream = Box::pin(
            MeteredStream::new(stream, self.meter.clone(), self.deadline).with_socket(slot),
        );
        Ok((sink, stream))
    }
}

fn public_event_websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(PUBLIC_EVENT_MAX_FRAME_BYTES))
        .max_frame_size(Some(PUBLIC_EVENT_MAX_FRAME_BYTES))
}

impl WebSocketTransport for PinnedPublicEventTransport {
    fn support_ping(&self) -> bool {
        false
    }

    fn connect<'a>(
        &'a self,
        url: &'a nostr::types::Url,
        proxy: Option<SocketAddr>,
    ) -> TransportFuture<'a> {
        Box::pin(async move {
            // A proxy would resolve the hostname itself, bypassing the pin.
            if proxy.is_some() {
                return Err(refused());
            }
            self.dial(url.as_str()).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limits(max_items: usize, max_bytes: usize, max_messages: usize) -> PublicEventTrafficLimits {
        PublicEventTrafficLimits {
            max_items,
            max_bytes,
            max_messages,
        }
    }

    async fn resolve(
        url: &str,
        allow_loopback: bool,
        answer: Vec<IpAddr>,
    ) -> Result<Vec<SocketAddr>, PublicEventDialRefused> {
        let url = Url::parse(url).unwrap();
        resolve_relay_addrs_with(&url, allow_loopback, move |_, _| async move { Ok(answer) }).await
    }

    #[tokio::test]
    async fn hostnames_resolving_to_non_public_addresses_are_never_dialed() {
        let public: IpAddr = "93.184.216.34".parse().unwrap();
        for private in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fc00::1",
        ] {
            let private: IpAddr = private.parse().unwrap();
            assert!(
                resolve("wss://hint.example", false, vec![private])
                    .await
                    .is_err()
            );
            assert!(
                resolve("wss://hint.example", false, vec![public, private])
                    .await
                    .is_err(),
                "one unsafe answer rejects the whole name"
            );
            assert!(
                resolve("wss://hint.example", true, vec![private])
                    .await
                    .is_err(),
                "the loopback flag never trusts a name that happens to resolve locally"
            );
        }
        assert!(
            resolve("wss://hint.example", false, Vec::new())
                .await
                .is_err()
        );
        assert_eq!(
            resolve("wss://hint.example", false, vec![public, public])
                .await
                .unwrap(),
            vec![SocketAddr::new(public, 443)],
            "the validated address is the pinned dial target"
        );
    }

    #[tokio::test]
    async fn literal_loopback_requires_the_dev_flag_and_loopback_answers() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(
            resolve("ws://127.0.0.1:7777", false, Vec::new())
                .await
                .is_err()
        );
        assert_eq!(
            resolve("ws://127.0.0.1:7777", true, Vec::new())
                .await
                .unwrap(),
            vec![SocketAddr::new(loopback, 7777)]
        );
        assert!(
            resolve("ws://localhost:7777", true, vec![loopback])
                .await
                .is_ok()
        );
        assert!(
            resolve(
                "ws://localhost:7777",
                true,
                vec!["93.184.216.34".parse().unwrap()]
            )
            .await
            .is_err(),
            "localhost resolving off-device is refused"
        );
        assert!(
            resolve(
                "ws://hint.example",
                true,
                vec!["93.184.216.34".parse().unwrap()]
            )
            .await
            .is_err(),
            "public plaintext stays refused"
        );
    }

    #[test]
    fn event_envelopes_are_decoded_not_prefix_matched() {
        assert!(relay_text_is_event(r#"["EVENT","sub",{}]"#));
        assert!(relay_text_is_event(r#" [ "EVENT" , "sub", {"id":"x"} ] "#));
        // A JSON unicode escape for the leading `E` (backslash, `u0045`).
        let escaped = ["[\"", "\\", "u0045VENT\",\"sub\",{}]"].concat();
        assert!(escaped.starts_with("[\"\\u0045"));
        assert!(
            relay_text_is_event(&escaped),
            "an escaped command is still an event"
        );
        let escaped_eose = ["[\"", "\\", "u0045OSE\",\"sub\"]"].concat();
        assert!(!relay_text_is_event(&escaped_eose));
        assert!(!relay_text_is_event(r#"["EOSE","sub"]"#));
        assert!(!relay_text_is_event(r#"["NOTICE","EVENT"]"#));
        assert!(!relay_text_is_event(r#"["EVENTS","sub"]"#));
        assert!(
            relay_text_is_event("not json"),
            "undecodable text is charged as an event"
        );
        assert!(relay_text_is_event(r#"["EVENT","sub",{}] trailing"#));
        assert!(relay_text_is_event(r#"[5,"sub"]"#));
    }

    #[test]
    fn child_meters_charge_the_request_across_phases() {
        let request = PublicEventTrafficMeter::new(limits(3, 1000, 2));
        let first = PublicEventTrafficMeter::child(&request, limits(8, 1000, usize::MAX));
        let second = PublicEventTrafficMeter::child(&request, limits(8, 1000, usize::MAX));
        assert!(first.charge(10, true));
        assert!(first.charge(10, true));
        assert!(second.charge(10, false));
        assert!(second.charge(10, true));
        assert!(
            !second.charge(10, true),
            "the fourth event exceeds the request"
        );
        assert!(first.is_exhausted() && second.is_exhausted());
        assert_eq!(request.items(), 4, "the rejected frame was still charged");
        assert_eq!(request.bytes(), 50);
        assert_eq!(second.items(), 2);
        assert_eq!(request.messages(), 1);
    }

    #[tokio::test]
    async fn metered_streams_charge_invalid_and_duplicate_events_before_the_sdk() {
        let request = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 64));
        let phase = PublicEventTrafficMeter::child(&request, limits(2, 1024 * 1024, usize::MAX));
        let invalid = r#"["EVENT","s",{"id":"00","sig":"bad"}]"#;
        let frames: Vec<Result<TungsteniteMessage, TungsteniteError>> = vec![
            Ok(TungsteniteMessage::Ping(vec![1u8, 2, 3].into())),
            Ok(TungsteniteMessage::text(invalid.to_owned())),
            Ok(TungsteniteMessage::text(invalid.to_owned())),
            Ok(TungsteniteMessage::text(r#"["EVENT","s",{}]"#.to_owned())),
            Ok(TungsteniteMessage::text(r#"["EOSE","s"]"#.to_owned())),
        ];
        let stream = MeteredStream::new(
            futures::stream::iter(frames),
            phase.clone(),
            Instant::now() + Duration::from_secs(5),
        );
        let delivered: Vec<_> = stream.collect().await;
        assert_eq!(
            delivered.len(),
            3,
            "ping and both invalid duplicates, then the budget ends"
        );
        assert_eq!(phase.items(), 3);
        assert_eq!(request.items(), 3);
        assert_eq!(request.messages(), 1);
        assert_eq!(
            request.bytes(),
            0,
            "decoded messages are not charged twice; their bytes are charged on the wire"
        );
        assert!(phase.is_exhausted());
        assert!(
            !request.is_exhausted(),
            "the request keeps capacity for its next phase"
        );
    }

    #[tokio::test]
    async fn metered_streams_bound_control_frames() {
        let request = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 2));
        assert!(request.messages() == 0 && request.bytes() == 0);
        let frames: Vec<Result<TungsteniteMessage, TungsteniteError>> = (0..5)
            .map(|_| Ok(TungsteniteMessage::Pong(Vec::<u8>::new().into())))
            .collect();
        let delivered: Vec<_> = MeteredStream::new(
            futures::stream::iter(frames),
            request.clone(),
            Instant::now() + Duration::from_secs(5),
        )
        .collect()
        .await;
        assert_eq!(delivered.len(), 2);
        assert!(request.is_exhausted());
    }

    async fn loopback_listener() -> (tokio::net::TcpListener, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    /// A pinned socket adapter over a real loopback connection.
    async fn pinned_io(
        addr: SocketAddr,
        meter: &Arc<PublicEventTrafficMeter>,
        sockets: &Arc<PublicEventSocketRegistry>,
        deadline: Instant,
    ) -> (PinnedSocketIo, Arc<SocketSlot>) {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let slot = sockets.register(tcp).unwrap();
        (
            PinnedSocketIo::new(slot.clone(), meter.clone(), deadline),
            slot,
        )
    }

    /// Wait until the peer observes the connection closed: EOF or an error,
    /// after draining anything still buffered.
    async fn peer_observes_close(stream: &mut TcpStream) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buffer = vec![0u8; 64 * 1024];
        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        drained.is_ok()
    }

    #[tokio::test]
    async fn fragmented_wire_traffic_is_charged_below_websocket_reassembly() {
        use tokio::io::AsyncWriteExt;
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut websocket = pinned_tokio_tungstenite::accept_async(tcp).await.unwrap();
            let raw = websocket.get_mut();
            // An unfinished text frame (FIN clear), then empty continuation
            // frames that never finish the message: the WebSocket parser
            // consumes them without ever yielding a message.
            if raw.write_all(&[0x01, 0x01, b'[']).await.is_err() {
                return (0usize, true);
            }
            let continuations = [0x00u8, 0x00].repeat(512);
            let mut sent = 3usize;
            while sent < 64 * 1024 * 1024 {
                match tokio::time::timeout(Duration::from_secs(5), raw.write_all(&continuations))
                    .await
                {
                    Ok(Ok(())) => sent += continuations.len(),
                    // The client dropped the socket.
                    Ok(Err(_)) => return (sent, true),
                    // Stalled: the client neither read nor closed.
                    Err(_) => return (sent, false),
                }
            }
            (sent, false)
        });

        let meter = PublicEventTrafficMeter::new(limits(16, 16 * 1024, 64));
        let sockets = PublicEventSocketRegistry::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (io, _slot) = pinned_io(addr, &meter, &sockets, deadline).await;
        let (websocket, _response) = pinned_tokio_tungstenite::client_async_with_config(
            format!("ws://{addr}"),
            io,
            Some(public_event_websocket_config()),
        )
        .await
        .unwrap();
        let (_sink, stream) = websocket.split();
        let delivered: Vec<_> = tokio::time::timeout(
            Duration::from_secs(4),
            MeteredStream::new(stream, meter.clone(), deadline).collect::<Vec<_>>(),
        )
        .await
        .expect("fragment floods end on the byte budget, not the deadline");
        assert!(
            delivered.iter().all(Result::is_err),
            "no message was ever assembled or delivered"
        );
        assert_eq!(meter.items(), 0);
        assert_eq!(meter.messages(), 0);
        assert!(meter.is_exhausted());
        assert!(
            meter.bytes() > 16 * 1024,
            "frame headers and empty continuations were charged on the wire"
        );
        assert_eq!(sockets.open_sockets(), 0, "the descriptor was dropped");
        let (sent, closed) = server.await.unwrap();
        assert!(closed, "the relay saw the connection close");
        assert!(sent < 64 * 1024 * 1024);
    }

    #[tokio::test]
    async fn fragmented_receive_stalls_end_and_free_the_socket_at_the_deadline() {
        use tokio::io::AsyncWriteExt;
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut websocket = pinned_tokio_tungstenite::accept_async(tcp).await.unwrap();
            let raw = websocket.get_mut();
            raw.write_all(&[0x01, 0x01, b'[']).await.unwrap();
            // Stall mid-message and wait for the client to drop the socket.
            peer_observes_close(raw).await
        });

        let meter = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 64));
        let sockets = PublicEventSocketRegistry::new();
        let deadline = Instant::now() + Duration::from_millis(500);
        let (io, slot) = pinned_io(addr, &meter, &sockets, deadline).await;
        let (websocket, _response) = pinned_tokio_tungstenite::client_async_with_config(
            format!("ws://{addr}"),
            io,
            Some(public_event_websocket_config()),
        )
        .await
        .unwrap();
        let (sink, stream) = websocket.split();
        let started = std::time::Instant::now();
        let delivered: Vec<_> = MeteredStream::new(stream, meter.clone(), deadline)
            .with_socket(slot)
            .collect()
            .await;
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(delivered.iter().all(Result::is_err));
        assert_eq!(sockets.open_sockets(), 0);
        // The sink half is still alive: the close did not wait for it.
        assert!(
            server.await.unwrap(),
            "no connection lingers past the deadline"
        );
        drop(sink);
    }

    #[tokio::test]
    async fn backpressured_socket_writes_flush_and_close_end_at_the_deadline() {
        use tokio::io::AsyncWriteExt;
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            // Never read before the client's deadline: its writes backpressure.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            peer_observes_close(&mut tcp).await
        });

        let meter = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 64));
        let sockets = PublicEventSocketRegistry::new();
        let deadline = Instant::now() + Duration::from_millis(500);
        let (mut io, _slot) = pinned_io(addr, &meter, &sockets, deadline).await;
        let chunk = vec![0u8; 256 * 1024];
        let started = std::time::Instant::now();
        loop {
            if io.write_all(&chunk).await.is_err() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "writes must stop"
            );
        }
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(
            sockets.open_sockets(),
            0,
            "the deadline dropped the descriptor"
        );
        assert!(io.flush().await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), io.shutdown())
                .await
                .expect("shutdown never waits past the deadline")
                .is_ok()
        );
        assert!(server.await.unwrap(), "the peer saw the forced close");
    }

    #[tokio::test]
    async fn backpressured_websocket_sinks_stop_and_close_at_the_deadline() {
        use futures::SinkExt;
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut websocket = pinned_tokio_tungstenite::accept_async(tcp).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            peer_observes_close(websocket.get_mut()).await
        });

        let meter = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 64));
        let sockets = PublicEventSocketRegistry::new();
        let deadline = Instant::now() + Duration::from_millis(500);
        let (io, slot) = pinned_io(addr, &meter, &sockets, deadline).await;
        let (websocket, _response) = pinned_tokio_tungstenite::client_async_with_config(
            format!("ws://{addr}"),
            io,
            Some(public_event_websocket_config()),
        )
        .await
        .unwrap();
        let (sink, _stream) = websocket.split();
        let mut sink = PinnedSink::new(sink, slot, deadline);
        let message = Message::Binary(vec![0u8; 256 * 1024]);
        let started = std::time::Instant::now();
        loop {
            if sink.send(message.clone()).await.is_err() {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "sends must stop"
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), sink.close())
                .await
                .expect("close never waits on a backpressured peer")
                .is_ok()
        );
        assert_eq!(sockets.open_sockets(), 0);
        assert!(
            server.await.unwrap(),
            "no connection lingers past the deadline"
        );
    }

    #[tokio::test]
    async fn request_cleanup_closes_unpolled_sockets_and_refuses_new_ones() {
        let (listener, addr) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            peer_observes_close(&mut tcp).await
        });
        let meter = PublicEventTrafficMeter::new(limits(16, 4 * 1024 * 1024, 64));
        let sockets = PublicEventSocketRegistry::new();
        let (io, _slot) = pinned_io(
            addr,
            &meter,
            &sockets,
            Instant::now() + Duration::from_secs(60),
        )
        .await;
        assert_eq!(sockets.open_sockets(), 1);
        // Dropping the request's guard (end or cancellation) closes the socket
        // although nothing polls it and its own deadline is far away.
        drop(CloseSocketsOnDrop(sockets.clone()));
        assert_eq!(sockets.open_sockets(), 0);
        assert!(server.await.unwrap());
        let (late_listener, late_addr) = loopback_listener().await;
        let late = TcpStream::connect(late_addr).await.unwrap();
        assert!(
            sockets.register(late).is_none(),
            "a closed request adopts nothing"
        );
        drop(late_listener);
        drop(io);
    }
}
