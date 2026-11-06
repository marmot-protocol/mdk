//! Real socket interruption in front of the harness-owned loopback relay.
//! All advertised relay URLs use this gate, so reconnect/discovery cannot bypass it.
//! Each proxy also taps the forwarded WebSocket frames into aggregate traffic counts,
//! logs the history requests clients send, and can withhold them (a relay that
//! never answers history while live traffic flows). It answers NIP-11 requests
//! itself, since the harness relay serves no information document.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

// Larger frames stop the tap; loopback relay messages stay far below this.
const MAX_TAPPED_FRAME: u64 = 8 * 1024 * 1024;
// A client's HTTP request head; an upgrade is far smaller.
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// The NIP-11 document every endpoint serves until a scenario replaces it:
/// the White Noise relays' shape (strfry with NIP-77 and a 500-result filter
/// cap). The harness relay returns at most 500 events for a filter with no
/// `limit`, like strfry, but honors a larger requested `limit`, which strfry
/// clamps.
pub const PRODUCTION_RELAY_INFORMATION: &str = r#"{"name":"cgka-conformance relay","supported_nips":[1,9,11,40,77],"limitation":{"max_limit":500}}"#;

/// Wire traffic through one proxied relay endpoint, summed over a range of
/// its connections. Byte counts are raw TCP payload per direction; message
/// verbs and event deliveries come from uncompressed text frames.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTrafficV1 {
    /// Index the next accepted connection will receive.
    pub next_session: u64,
    pub connections: u64,
    pub upstream_bytes: u64,
    pub downstream_bytes: u64,
    pub upstream_messages: BTreeMap<String, u64>,
    pub downstream_messages: BTreeMap<String, u64>,
    /// Connections by the side whose stream ended first ("client" or "relay").
    pub closed_first_by: BTreeMap<String, u64>,
    /// Compressed, malformed or oversized frames forwarded without parsing.
    pub undecoded_frames: u64,
    /// Relay-to-client `EVENT` deliveries by event id, when requested.
    pub events: BTreeMap<String, RelayEventDeliveryV1>,
    /// Client history requests by proxy clock, when events are requested.
    #[serde(default)]
    pub history_requests: Vec<HistoryRequestV1>,
    /// Completed live group REQs, before client validation, when events are requested.
    #[serde(default)]
    pub live_group_replies: Vec<LiveGroupReplyV1>,

    /// Each connection's `#p` values across every `REQ` it sent, live ones
    /// included, when events are requested. An account's connections name
    /// its inbox, so this tells whose connection a history request came over.
    #[serde(default)]
    pub connection_inboxes: BTreeMap<u64, BTreeSet<String>>,
    /// Each connection's own wire totals, by connection index, when events
    /// are requested, so a caller can count one account's cost alone.
    #[serde(default)]
    pub connection_traffic: BTreeMap<u64, ConnectionTrafficV1>,
    /// The proxy's clock when this snapshot was taken, on the scale of
    /// [`HistoryRequestV1::at_ms`].
    #[serde(default)]
    pub now_ms: u64,
}

/// One connection's wire cost: raw bytes each way, and the relay-to-client
/// `EVENT` frames and their bytes by the [`RelayDeliveryPath`] of the `REQ`
/// that carried them (`unknown` when the subscription was never seen).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionTrafficV1 {
    pub upstream_bytes: u64,
    pub downstream_bytes: u64,
    pub event_frames: BTreeMap<String, u64>,
    pub event_bytes: BTreeMap<String, u64>,
}

/// One packed live group's raw reply through its EOSE, from wire frames.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveGroupReplyV1 {
    pub at_ms: u64,
    pub connection: u64,
    pub routes: Vec<String>,
    pub raw_events: u64,
}

#[derive(Clone, Debug, Default)]
struct PendingLiveGroupReply {
    routes: Vec<String>,
    raw_events: u64,
}

/// One history filter a client sent: a `REQ` filter with an `until`, or a
/// `NEG-OPEN` filter. Live subscriptions carry no `until` and are not logged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRequestV1 {
    /// Milliseconds since the proxy started.
    pub at_ms: u64,
    /// `REQ` or `NEG-OPEN`.
    pub verb: String,
    /// The filter's first `#h` value (a group route), else its first `#p`
    /// value (an inbox).
    pub route: Option<String>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<u64>,
    /// Event ids the filter names; zero for a window.
    pub ids: usize,
    /// The proxy withheld it from the relay.
    pub withheld: bool,
    /// The connection it came over, keyed as in
    /// [`RelayTrafficV1::connection_inboxes`].
    #[serde(default)]
    pub connection: u64,
}

/// One client connection's counters.
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayTrafficSessionV1 {
    upstream_bytes: u64,
    downstream_bytes: u64,
    upstream_messages: BTreeMap<String, u64>,
    downstream_messages: BTreeMap<String, u64>,
    events: BTreeMap<String, RelayEventDeliveryV1>,
    /// `EVENT` frames and bytes by delivery path label.
    event_frames_by_path: BTreeMap<String, u64>,
    event_bytes_by_path: BTreeMap<String, u64>,
    /// Each open subscription's `REQ`, by subscription id.
    subscriptions: BTreeMap<String, RelayDeliveryPath>,
    history_requests: Vec<HistoryRequestV1>,
    live_group_pending: BTreeMap<String, PendingLiveGroupReply>,
    live_group_replies: Vec<LiveGroupReplyV1>,

    inboxes: BTreeSet<String>,
    undecoded_frames: u64,
    first_eof: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEventDeliveryV1 {
    pub kind: u16,
    pub count: u64,
    pub bytes: u64,
    /// The event's own `created_at`, in seconds.
    #[serde(default)]
    pub created_at: u64,
    /// Deliveries by the [`RelayDeliveryPath`] of the subscription that
    /// carried them.
    #[serde(default)]
    pub via_ids: u64,
    #[serde(default)]
    pub via_window: u64,
    #[serde(default)]
    pub via_paged_window: u64,
    #[serde(default)]
    pub via_maintenance: u64,
    #[serde(default)]
    pub via_live: u64,
    /// The path of its first delivery on this connection, and when, on the
    /// scale of [`HistoryRequestV1::at_ms`].
    #[serde(default)]
    pub first: Option<(RelayDeliveryPath, u64)>,
}

/// What a subscription's `REQ` asked for. Both recovery owners fetch over the
/// account's one connection, with ids and unlimited windows alike, so a path
/// names a request shape, not an owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDeliveryPath {
    /// Event ids.
    Ids,
    /// A window (a filter with an `until`) without a `limit`: owner capture
    /// pages and the runner's sweeps.
    Window,
    /// A window with a `limit`: epoch-gap pages and the reconciliation set.
    PagedWindow,
    /// A group's maintenance subscription, which returns the group's stored
    /// events from its floor and then live ones.
    Maintenance,
    /// Any other subscription, which also returns stored events first.
    Live,
}

impl RelayDeliveryPath {
    /// The path's report label, as it serializes.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ids => "ids",
            Self::Window => "window",
            Self::PagedWindow => "paged_window",
            Self::Maintenance => "maintenance",
            Self::Live => "live",
        }
    }

    fn of(items: &[serde_json::Value]) -> Self {
        let has = |field: &str| {
            items
                .iter()
                .skip(2)
                .any(|filter| filter.get(field).is_some())
        };
        let subscription = items.get(1).and_then(serde_json::Value::as_str);
        if has("ids") {
            Self::Ids
        } else if has("until") && has("limit") {
            Self::PagedWindow
        } else if has("until") {
            Self::Window
        } else if subscription.is_some_and(|id| id.starts_with("marmot:group-maintenance:")) {
            Self::Maintenance
        } else {
            Self::Live
        }
    }
}

type Traffic = Arc<Mutex<Vec<RelayTrafficSessionV1>>>;

enum Command {
    SetAvailable(bool, oneshot::Sender<u64>),
}

pub(crate) struct RelayFaultProxy {
    address: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
    task: JoinHandle<()>,
    rejected: Arc<AtomicU64>,
    active: Arc<AtomicU64>,
    traffic: Traffic,
    gate: Arc<Gate>,
}

/// What every connection of one proxy reads as it forwards.
struct Gate {
    started: Instant,
    /// Withhold history requests from the relay.
    stall_history: AtomicBool,
    /// The NIP-11 document, or `None` to pass information requests through.
    information: Mutex<Option<String>>,
}

impl Gate {
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Incremental WebSocket reader for one direction of a proxied connection.
#[derive(Default)]
struct FrameTap {
    opened: bool,
    broken: bool,
    pending: Vec<u8>,
    message: Vec<u8>,
}

impl FrameTap {
    /// Consume forwarded bytes. Returns completed text messages and the number
    /// of frames that could not be decoded.
    fn feed(&mut self, bytes: &[u8]) -> (Vec<Vec<u8>>, u64) {
        let mut complete = Vec::new();
        if self.broken {
            return (complete, 0);
        }
        self.pending.extend_from_slice(bytes);
        if !self.opened {
            // The HTTP upgrade precedes frames in both directions.
            let Some(end) = self.pending.windows(4).position(|w| w == b"\r\n\r\n") else {
                return (complete, 0);
            };
            self.pending.drain(..end + 4);
            self.opened = true;
        }
        let (mut offset, mut undecoded) = (0, 0);
        while let Some(frame) = next_frame(&self.pending[offset..]) {
            let Some((length, first, payload)) = frame else {
                // An implausible length cannot be skipped reliably.
                self.broken = true;
                self.pending = Vec::new();
                return (complete, undecoded + 1);
            };
            offset += length;
            match first & 0x0f {
                // Keep close status codes as synthetic verbs; skip other control frames.
                0x8 => {
                    let code = payload
                        .get(..2)
                        .map_or(0, |c| u16::from_be_bytes([c[0], c[1]]));
                    complete.push(format!(r#"["ws-close:{code}"]"#).into_bytes());
                    continue;
                }
                0x9..=0xf => continue,
                0x0 => {}
                _ => self.message.clear(),
            }
            if first & 0x40 != 0 {
                undecoded += 1;
                continue;
            }
            self.message.extend_from_slice(&payload);
            if first & 0x80 != 0 {
                complete.push(std::mem::take(&mut self.message));
            }
        }
        self.pending.drain(..offset);
        (complete, undecoded)
    }
}

/// The frame at the start of `bytes`, or `None` until it is complete:
/// (frame length, first header byte, unmasked payload).
fn next_frame(bytes: &[u8]) -> Option<Option<(usize, u8, Vec<u8>)>> {
    let (&first, &second) = (bytes.first()?, bytes.get(1)?);
    let (mut start, length) = match second & 0x7f {
        126 => (
            4,
            u64::from(u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?)),
        ),
        127 => (10, u64::from_be_bytes(bytes.get(2..10)?.try_into().ok()?)),
        length => (2, u64::from(length)),
    };
    if length > MAX_TAPPED_FRAME {
        return Some(None);
    }
    let mask: Option<[u8; 4]> = if second & 0x80 == 0 {
        None
    } else {
        start += 4;
        Some(bytes.get(start - 4..start)?.try_into().ok()?)
    };
    let end = start + length as usize;
    let mut payload = bytes.get(start..end)?.to_vec();
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Some(Some((end, first, payload)))
}

/// Count one completed message and return its items, or `None` when it is no
/// JSON array.
fn record_message(
    session: &mut RelayTrafficSessionV1,
    message: &[u8],
    upstream: bool,
    at_ms: u64,
) -> Option<Vec<serde_json::Value>> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_slice(message) else {
        session.undecoded_frames += 1;
        return None;
    };
    let verb = items.first().and_then(|verb| verb.as_str()).unwrap_or("?");
    let verbs = if upstream {
        &mut session.upstream_messages
    } else {
        &mut session.downstream_messages
    };
    // Relay refusals (for example rate limiting) are counted apart from accepts.
    let refused = verb == "OK" && items.get(2) == Some(&serde_json::Value::Bool(false));
    let key = if refused { "OK-refused" } else { verb };
    *verbs.entry(key.to_owned()).or_default() += 1;
    let subscription = items.get(1).and_then(serde_json::Value::as_str);
    if upstream
        && verb == "REQ"
        && let Some(subscription) = subscription
    {
        let asked = RelayDeliveryPath::of(&items);
        session.subscriptions.insert(subscription.to_owned(), asked);
        session.live_group_pending.remove(subscription);
        if asked == RelayDeliveryPath::Live {
            let routes = items
                .iter()
                .skip(2)
                .filter_map(|filter| filter["#h"].as_array())
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if !routes.is_empty() {
                session.live_group_pending.insert(
                    subscription.to_owned(),
                    PendingLiveGroupReply {
                        routes,
                        raw_events: 0,
                    },
                );
            }
        }
    }
    if let Some(subscription) = subscription {
        if upstream && verb == "CLOSE" {
            session.live_group_pending.remove(subscription);
        } else if !upstream && verb == "EVENT" {
            if let Some(reply) = session.live_group_pending.get_mut(subscription) {
                reply.raw_events += 1;
            }
        } else if !upstream
            && verb == "EOSE"
            && let Some(reply) = session.live_group_pending.remove(subscription)
        {
            session.live_group_replies.push(LiveGroupReplyV1 {
                at_ms,
                connection: 0,
                routes: reply.routes,
                raw_events: reply.raw_events,
            });
        }
    }
    if !upstream
        && verb == "EVENT"
        && let Some(event) = items.get(2)
        && let Some(id) = event["id"].as_str()
    {
        let asked = subscription.and_then(|subscription| session.subscriptions.get(subscription));
        let asked = asked.copied();
        let delivery = session.events.entry(id.to_owned()).or_default();
        delivery.kind = u16::try_from(event["kind"].as_u64().unwrap_or_default()).unwrap_or(0);
        delivery.created_at = event["created_at"].as_u64().unwrap_or_default();
        delivery.count += 1;
        delivery.bytes += message.len() as u64;
        let label = asked.map_or("unknown", RelayDeliveryPath::label);
        *session
            .event_frames_by_path
            .entry(label.to_owned())
            .or_default() += 1;
        *session
            .event_bytes_by_path
            .entry(label.to_owned())
            .or_default() += message.len() as u64;
        if let Some(asked) = asked {
            *match asked {
                RelayDeliveryPath::Ids => &mut delivery.via_ids,
                RelayDeliveryPath::Window => &mut delivery.via_window,
                RelayDeliveryPath::PagedWindow => &mut delivery.via_paged_window,
                RelayDeliveryPath::Maintenance => &mut delivery.via_maintenance,
                RelayDeliveryPath::Live => &mut delivery.via_live,
            } += 1;
            delivery.first.get_or_insert((asked, at_ms));
        }
    }
    Some(items)
}

/// The history filters of one client message, or none for any other message.
fn history_filters(items: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    match items.first().and_then(serde_json::Value::as_str) {
        Some("REQ") => items
            .iter()
            .skip(2)
            .filter(|filter| filter.get("until").is_some())
            .collect(),
        Some("NEG-OPEN") => items.get(2).into_iter().collect(),
        _ => Vec::new(),
    }
}

fn history_request(
    verb: &str,
    filter: &serde_json::Value,
    at_ms: u64,
    withheld: bool,
    connection: u64,
) -> HistoryRequestV1 {
    let tag = |name: &str| {
        filter[name]
            .as_array()?
            .first()?
            .as_str()
            .map(str::to_owned)
    };
    HistoryRequestV1 {
        at_ms,
        verb: verb.to_owned(),
        route: tag("#h").or_else(|| tag("#p")),
        since: filter["since"].as_u64(),
        until: filter["until"].as_u64(),
        limit: filter["limit"].as_u64(),
        ids: filter["ids"].as_array().map_or(0, Vec::len),
        withheld,
        connection,
    }
}

/// The `#p` values of a client `REQ`'s filters.
fn named_inboxes(items: &[serde_json::Value]) -> impl Iterator<Item = &str> {
    let filters = match items.first().and_then(serde_json::Value::as_str) {
        Some("REQ") => items.get(2..).unwrap_or_default(),
        _ => &[],
    };
    filters
        .iter()
        .filter_map(|filter| filter["#p"].as_array())
        .flatten()
        .filter_map(serde_json::Value::as_str)
}

/// Client-to-relay forwarding after the HTTP upgrade. Each frame is
/// forwarded unchanged once it is complete. While the stall is on, a data
/// message that starts is held until its last frame; a history `REQ` or
/// `NEG-OPEN` is then withheld if the stall is still on, as are later
/// `CLOSE`, `NEG-MSG` and `NEG-CLOSE` messages for its subscription. Control
/// frames always pass at once. A frame the gate cannot parse ends withholding
/// for the connection.
#[derive(Default)]
struct RequestGate {
    passthrough: bool,
    pending: Vec<u8>,
    /// The message in progress: `None` between messages, `Some(None)` when
    /// it is forwarded as it arrives, `Some(Some(..))` with its raw frames
    /// and payload when it is held.
    current: Option<Option<(Vec<u8>, Vec<u8>)>>,
    /// Subscriptions whose opening request was withheld.
    withheld: BTreeSet<String>,
}

impl RequestGate {
    /// Bytes to forward now, and the payloads of messages completed by
    /// `bytes` that the gate withheld.
    fn feed(&mut self, bytes: &[u8], stall: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut withheld = Vec::new();
        if self.passthrough {
            return (bytes.to_vec(), withheld);
        }
        self.pending.extend_from_slice(bytes);
        let mut forward = Vec::new();
        let mut offset = 0;
        while let Some(frame) = next_frame(&self.pending[offset..]) {
            let Some((length, first, payload)) = frame else {
                self.passthrough = true;
                break;
            };
            let raw = &self.pending[offset..offset + length];
            offset += length;
            let opcode = first & 0x0f;
            if opcode >= 0x8 {
                forward.extend_from_slice(raw);
                continue;
            }
            if opcode != 0x0 || self.current.is_none() {
                // A compressed message cannot be read, so it is never held.
                let hold = stall && first & 0x40 == 0;
                if let Some(Some((frames, _))) = self.current.take() {
                    forward.extend(frames);
                }
                self.current = Some(hold.then(|| (Vec::new(), Vec::new())));
            }
            match self.current.as_mut().expect("message in progress") {
                Some((frames, message)) => {
                    frames.extend_from_slice(raw);
                    message.extend_from_slice(&payload);
                }
                None => forward.extend_from_slice(raw),
            }
            if first & 0x80 != 0
                && let Some(Some((frames, message))) = self.current.take()
            {
                // A message held while the stall was on goes through if it
                // was lifted before the message ended.
                if stall && self.withholds(&message) {
                    withheld.push(message);
                } else {
                    forward.extend(frames);
                }
            }
        }
        if self.passthrough {
            if let Some(Some((frames, _))) = self.current.take() {
                forward.extend(frames);
            }
            forward.extend_from_slice(&self.pending[offset..]);
            self.pending = Vec::new();
        } else {
            self.pending.drain(..offset);
        }
        (forward, withheld)
    }

    fn withholds(&mut self, payload: &[u8]) -> bool {
        let Ok(serde_json::Value::Array(items)) = serde_json::from_slice(payload) else {
            return false;
        };
        let (Some(verb), Some(id)) = (
            items.first().and_then(serde_json::Value::as_str),
            items.get(1).and_then(serde_json::Value::as_str),
        ) else {
            return false;
        };
        match verb {
            "REQ" | "NEG-OPEN" if !history_filters(&items).is_empty() => {
                self.withheld.insert(id.to_owned());
                true
            }
            // A live REQ that reuses a withheld id replaces it.
            "REQ" => {
                self.withheld.remove(id);
                false
            }
            "CLOSE" | "NEG-CLOSE" => self.withheld.remove(id),
            "NEG-MSG" => self.withheld.contains(id),
            _ => false,
        }
    }
}

/// The client-to-relay side of a connection.
#[derive(Clone, Copy)]
struct Upstream<'a> {
    gate: &'a Gate,
    /// Whether the client's request head was already read and forwarded.
    opened: bool,
}

/// Forward one direction, recording its bytes and completed messages on
/// `clock`'s time. The client side passes its requests through its gate.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    traffic: &Traffic,
    index: usize,
    client: Option<Upstream<'_>>,
    clock: &Gate,
) -> io::Result<()> {
    let opened = client.is_some_and(|client| client.opened);
    let mut tap = FrameTap {
        opened,
        ..FrameTap::default()
    };
    // Bytes that opened no WebSocket are never parsed as frames.
    let mut requests = RequestGate {
        passthrough: !opened,
        ..RequestGate::default()
    };
    let upstream = client.is_some();
    let gate = client.map(|client| client.gate);
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            let side = if upstream { "client" } else { "relay" };
            traffic.lock().expect("relay traffic lock poisoned")[index]
                .first_eof
                .get_or_insert(side);
            return to.shutdown().await;
        }
        let bytes = &buffer[..read];
        let (forward, withheld) = match gate {
            Some(gate) => requests.feed(bytes, gate.stall_history.load(Ordering::SeqCst)),
            None => (bytes.to_vec(), Vec::new()),
        };
        to.write_all(&forward).await?;
        let (messages, undecoded) = tap.feed(bytes);
        let at_ms = clock.elapsed_ms();
        let mut sessions = traffic.lock().expect("relay traffic lock poisoned");
        let session = &mut sessions[index];
        if upstream {
            session.upstream_bytes += read as u64;
        } else {
            session.downstream_bytes += read as u64;
        }
        session.undecoded_frames += undecoded;
        for message in &messages {
            let Some(items) = record_message(session, message, upstream, at_ms) else {
                continue;
            };
            if upstream {
                let verb = items.first().and_then(|verb| verb.as_str()).unwrap_or("?");
                let held = withheld.contains(message);
                for filter in history_filters(&items) {
                    let request = history_request(verb, filter, at_ms, held, index as u64);
                    session.history_requests.push(request);
                }
                let inboxes = named_inboxes(&items).map(str::to_owned);
                session.inboxes.extend(inboxes);
            }
        }
    }
}

/// How a client connection opened.
enum Opening {
    /// An HTTP request head through its blank line, and the bytes after it.
    Head(Vec<u8>, Vec<u8>),
    /// Bytes that are no HTTP `GET`, passed on unread.
    Other(Vec<u8>),
}

/// Read a client's opening bytes until they hold a complete HTTP request head
/// or can no longer start one. `None` when the client closes first or sends
/// an oversized head.
async fn read_opening(stream: &mut TcpStream) -> Option<Opening> {
    let mut head = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = head.split_off(end + 4);
            return Some(Opening::Head(head, rest));
        }
        let prefix = head.len().min(4);
        if head[..prefix] != b"GET "[..prefix] {
            return Some(Opening::Other(head));
        }
        if head.len() > MAX_REQUEST_HEAD {
            return None;
        }
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(&buffer[..read]);
    }
}

/// Whether a request head asks for the relay's NIP-11 document: an HTTP
/// request that is no WebSocket upgrade and accepts `application/nostr+json`.
fn asks_for_information(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    let header = |name: &str| {
        text.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_ascii_lowercase())
        })
    };
    let upgrade = header("upgrade").is_some_and(|value| value.contains("websocket"));
    let accept = header("accept").is_some_and(|value| value.contains("application/nostr+json"));
    !upgrade && accept
}

async fn serve_information(stream: &mut TcpStream, document: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{document}",
        document.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

struct ActiveConnection(Arc<AtomicU64>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// Restores the listener even when an interrupted scenario future is cancelled.
struct RestoreAvailability(mpsc::UnboundedSender<Command>);

impl Drop for RestoreAvailability {
    fn drop(&mut self) {
        let (reply, _) = oneshot::channel();
        let _ = self.0.send(Command::SetAvailable(true, reply));
    }
}

impl RelayFaultProxy {
    pub(crate) async fn start(upstream: SocketAddr) -> io::Result<Self> {
        if !upstream.ip().is_loopback() {
            return Err(io::Error::other(
                "relay fault proxy requires a loopback upstream",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (commands, mut receiver) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicU64::new(0));
        let active_task = active.clone();
        let rejected = Arc::new(AtomicU64::new(0));
        let rejected_task = rejected.clone();
        let traffic = Traffic::default();
        let traffic_task = traffic.clone();
        let gate = Arc::new(Gate {
            started: Instant::now(),
            stall_history: AtomicBool::new(false),
            information: Mutex::new(Some(PRODUCTION_RELAY_INFORMATION.to_owned())),
        });
        let gate_task = gate.clone();
        let task = tokio::spawn(async move {
            let mut available = true;
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    command = receiver.recv() => {
                        let Some(Command::SetAvailable(next, reply)) = command else { break };
                        available = next;
                        let closed = if available { 0 } else { active_task.load(Ordering::SeqCst) };
                        if !available {
                            sessions.abort_all();
                            while sessions.join_next().await.is_some() {}
                        }
                        let _ = reply.send(closed);
                    }
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                    accepted = listener.accept() => {
                        let Ok((mut downstream, _)) = accepted else { break };
                        if !available {
                            rejected_task.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        let active = active_task.clone();
                        let traffic = traffic_task.clone();
                        let gate = gate_task.clone();
                        sessions.spawn(async move {
                            // The exact harness-owned address is pinned above; no DNS or external dial.
                            let Ok(Ok(mut upstream)) = tokio::time::timeout(
                                Duration::from_secs(5), TcpStream::connect(upstream),
                            ).await else { return };
                            active.fetch_add(1, Ordering::SeqCst);
                            let _active = ActiveConnection(active);
                            let Some(opening) = read_opening(&mut downstream).await else { return };
                            let (head, rest) = match opening {
                                Opening::Head(head, rest) => (Some(head), rest),
                                Opening::Other(bytes) => (None, bytes),
                            };
                            let information = gate.information.lock().expect("relay information lock").clone();
                            // A NIP-11 fetch is answered here and opens no relay session.
                            if let (Some(head), Some(document)) = (&head, information)
                                && asks_for_information(head)
                            {
                                serve_information(&mut downstream, &document).await;
                                return;
                            }
                            let index = {
                                let mut sessions = traffic.lock().expect("relay traffic lock poisoned");
                                sessions.push(RelayTrafficSessionV1::default());
                                sessions.len() - 1
                            };
                            if let Some(head) = &head {
                                if upstream.write_all(head).await.is_err() {
                                    return;
                                }
                                traffic.lock().expect("relay traffic lock poisoned")[index]
                                    .upstream_bytes += head.len() as u64;
                            }
                            let (client_read, client_write) = downstream.split();
                            let (relay_read, relay_write) = upstream.split();
                            // Bytes the client sent after its head pass the gate first.
                            let client_read = std::io::Cursor::new(rest).chain(client_read);
                            let client = Upstream { gate: &gate, opened: head.is_some() };
                            let _ = tokio::try_join!(
                                pump(client_read, relay_write, &traffic, index, Some(client), &gate),
                                pump(relay_read, client_write, &traffic, index, None, &gate),
                            );
                        });
                    }
                }
            }
            sessions.abort_all();
            while sessions.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            commands,
            task,
            rejected,
            active,
            traffic,
            gate,
        })
    }

    /// Withhold history requests from the relay, or forward them again. Live
    /// subscriptions and publications keep flowing either way.
    pub(crate) fn stall_history(&self, stalled: bool) {
        self.gate.stall_history.store(stalled, Ordering::SeqCst);
    }

    /// Serve `document` to NIP-11 requests, or pass them to the relay.
    pub(crate) fn set_information(&self, document: Option<String>) {
        *self
            .gate
            .information
            .lock()
            .expect("relay information lock") = document;
    }

    pub(crate) fn url(&self) -> String {
        format!("ws://{}/", self.address)
    }

    /// Traffic summed over connections from index `first_session` onward.
    /// Per-event deliveries are merged only when `events`, which keeps the
    /// snapshot bounded by distinct events rather than by reconnects.
    pub(crate) fn traffic_since(&self, first_session: u64, events: bool) -> RelayTrafficV1 {
        let sessions = self.traffic.lock().expect("relay traffic lock poisoned");
        let first = usize::try_from(first_session).unwrap_or(usize::MAX);
        let mut total = RelayTrafficV1 {
            next_session: sessions.len() as u64,
            now_ms: self.gate.elapsed_ms(),
            ..RelayTrafficV1::default()
        };
        let add = |into: &mut BTreeMap<String, u64>, from: &BTreeMap<String, u64>| {
            for (verb, count) in from {
                *into.entry(verb.clone()).or_default() += count;
            }
        };
        for (offset, session) in sessions.iter().skip(first).enumerate() {
            total.connections += 1;
            total.upstream_bytes += session.upstream_bytes;
            total.downstream_bytes += session.downstream_bytes;
            total.undecoded_frames += session.undecoded_frames;
            add(&mut total.upstream_messages, &session.upstream_messages);
            add(&mut total.downstream_messages, &session.downstream_messages);
            if let Some(side) = session.first_eof {
                *total.closed_first_by.entry(side.to_owned()).or_default() += 1;
            }
            if events {
                total
                    .history_requests
                    .extend(session.history_requests.iter().cloned());
                let connection = (first + offset) as u64;
                total
                    .live_group_replies
                    .extend(session.live_group_replies.iter().cloned().map(|mut reply| {
                        reply.connection = connection;
                        reply
                    }));
                total
                    .connection_inboxes
                    .insert(connection, session.inboxes.clone());
                total.connection_traffic.insert(
                    connection,
                    ConnectionTrafficV1 {
                        upstream_bytes: session.upstream_bytes,
                        downstream_bytes: session.downstream_bytes,
                        event_frames: session.event_frames_by_path.clone(),
                        event_bytes: session.event_bytes_by_path.clone(),
                    },
                );
            }
            for (id, delivery) in session.events.iter().filter(|_| events) {
                let merged = total.events.entry(id.clone()).or_default();
                merged.kind = delivery.kind;
                merged.created_at = delivery.created_at;
                merged.count += delivery.count;
                merged.bytes += delivery.bytes;
                merged.via_ids += delivery.via_ids;
                merged.via_window += delivery.via_window;
                merged.via_paged_window += delivery.via_paged_window;
                merged.via_maintenance += delivery.via_maintenance;
                merged.via_live += delivery.via_live;
                // Sessions merge in order, so the earliest one's first stays.
                if merged.first.is_none() {
                    merged.first = delivery.first;
                }
            }
        }
        total.history_requests.sort_by_key(|request| request.at_ms);
        total
    }

    async fn set_available(&self, available: bool) -> io::Result<u64> {
        let (reply, received) = oneshot::channel();
        self.commands
            .send(Command::SetAvailable(available, reply))
            .map_err(|_| io::Error::other("relay fault proxy stopped"))?;
        received
            .await
            .map_err(|_| io::Error::other("relay fault proxy stopped"))
    }

    /// Returns the number of established connections actually cut and new
    /// connections rejected during the outage. Participants remain running.
    pub(crate) async fn interrupt(&self, duration: Duration) -> io::Result<(u64, u64)> {
        self.interrupt_when_connected(duration, Duration::from_secs(15))
            .await
    }

    async fn interrupt_when_connected(
        &self,
        duration: Duration,
        readiness_timeout: Duration,
    ) -> io::Result<(u64, u64)> {
        // Consecutive scripted faults can arrive before the SDK's reconnect retry.
        // Wait for an actual upstream-connected socket, without driving participant
        // state or shortening production retry timers. No connection means the
        // caller still receives zero cuts and refuses the unexercised stimulus.
        if tokio::time::timeout(readiness_timeout, async {
            while self.active.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_err()
        {
            return Ok((0, 0));
        }
        let restore = RestoreAvailability(self.commands.clone());
        let before = self.rejected.load(Ordering::SeqCst);
        let closed = self.set_available(false).await?;
        tokio::time::sleep(duration).await;
        self.set_available(true).await?;
        drop(restore);
        Ok((
            closed,
            self.rejected.load(Ordering::SeqCst).saturating_sub(before),
        ))
    }
}

impl Drop for RelayFaultProxy {
    fn drop(&mut self) {
        self.task.abort(); // Dropping the listener task also aborts its JoinSet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn interruption_waits_for_a_reconnecting_socket_before_cutting_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = RelayFaultProxy::start(listener.local_addr().unwrap())
            .await
            .unwrap();
        let interruption = proxy.interrupt(Duration::from_millis(20));
        tokio::pin!(interruption);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut interruption)
                .await
                .is_err()
        );
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (_upstream, _) = listener.accept().await.unwrap();
        let (closed, rejected) = tokio::time::timeout(Duration::from_secs(1), interruption)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((closed, rejected), (1, 0));
        assert!(client.read_u8().await.is_err());
    }

    #[tokio::test]
    async fn missing_connection_refuses_within_deadline_without_starting_an_outage() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = RelayFaultProxy::start(listener.local_addr().unwrap())
            .await
            .unwrap();
        let cuts = tokio::time::timeout(
            Duration::from_secs(1),
            proxy.interrupt_when_connected(Duration::from_secs(30), Duration::from_millis(50)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(cuts, (0, 0));
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        client.write_all(b"a").await.unwrap();
        assert_eq!(upstream.read_u8().await.unwrap(), b'a');
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_a_connection_leaves_relay_available() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = RelayFaultProxy::start(listener.local_addr().unwrap())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                proxy.interrupt(Duration::from_secs(30)),
            )
            .await
            .is_err()
        );
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (mut upstream, _) = listener.accept().await.unwrap();
        client.write_all(b"a").await.unwrap();
        assert_eq!(upstream.read_u8().await.unwrap(), b'a');
    }

    #[tokio::test]
    async fn interruption_closes_live_sockets_and_restores_new_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    Ok((mut stream, _)) = listener.accept() => {
                        tasks.spawn(async move {
                            let (mut reader, mut writer) = stream.split();
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        });
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        let proxy = RelayFaultProxy::start(upstream).await.unwrap();
        let mut first = TcpStream::connect(proxy.address).await.unwrap();
        first.write_all(b"a").await.unwrap();
        assert_eq!(first.read_u8().await.unwrap(), b'a');
        let (closed, _) = proxy.interrupt(Duration::from_millis(20)).await.unwrap();
        assert_eq!(closed, 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), first.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        let mut second = TcpStream::connect(proxy.address).await.unwrap();
        second.write_all(b"b").await.unwrap();
        assert_eq!(second.read_u8().await.unwrap(), b'b');

        // A cancellation must not strand subsequent scenarios behind an outage.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                proxy.interrupt(Duration::from_secs(30)),
            )
            .await
            .is_err()
        );
        let mut third = TcpStream::connect(proxy.address).await.unwrap();
        third.write_all(b"c").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), third.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'c'
        );

        proxy.set_available(false).await.unwrap();
        let mut rejected = TcpStream::connect(proxy.address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), rejected.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(proxy.rejected.load(Ordering::SeqCst), 1);
        proxy.set_available(true).await.unwrap();
        echo.abort();
    }

    fn frame(first: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let masked = u8::from(mask.is_some()) << 7;
        let mut bytes = vec![first];
        match u8::try_from(payload.len()) {
            Ok(length) if length < 126 => bytes.push(masked | length),
            _ => {
                bytes.push(masked | 126);
                bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            }
        }
        match mask {
            Some(mask) => {
                bytes.extend_from_slice(&mask);
                bytes.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
            }
            None => bytes.extend_from_slice(payload),
        }
        bytes
    }

    #[test]
    fn tap_counts_split_masked_and_fragmented_nostr_messages() {
        let event =
            br#"["EVENT","sub",{"id":"ab","kind":445,"created_at":1700000000,"content":"x"}]"#;
        let mut downstream = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        downstream.extend(frame(0x01, &event[..10], None));
        downstream.extend(frame(0x89, b"ping", None));
        downstream.extend(frame(0x80, &event[10..], None));
        downstream.extend(frame(0x81, br#"["EOSE","sub"]"#, None));
        downstream.extend(frame(0x81, br#"["OK","ab",false,"rate-limited"]"#, None));
        downstream.extend(frame(0x88, &1002_u16.to_be_bytes(), None));
        downstream.extend(frame(0xc1, b"compressed", None));
        let (mut tap, mut session) = (FrameTap::default(), RelayTrafficSessionV1::default());
        for chunk in downstream.chunks(7) {
            let (messages, undecoded) = tap.feed(chunk);
            session.undecoded_frames += undecoded;
            for message in messages {
                record_message(&mut session, &message, false, 0);
            }
        }
        assert_eq!(
            session.downstream_messages,
            BTreeMap::from([
                ("EOSE".into(), 1),
                ("EVENT".into(), 1),
                ("OK-refused".into(), 1),
                ("ws-close:1002".into(), 1),
            ])
        );
        let expected = RelayEventDeliveryV1 {
            kind: 445,
            count: 1,
            bytes: event.len() as u64,
            created_at: 1_700_000_000,
            ..RelayEventDeliveryV1::default()
        };
        assert_eq!(session.events["ab"], expected);
        assert_eq!(session.undecoded_frames, 1);

        let request = format!(r##"["REQ","s",{{"#h":["{}"]}}]"##, "a".repeat(200));
        let mut upstream = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        upstream.extend(frame(0x81, request.as_bytes(), Some([1, 2, 3, 4])));
        let decoded = FrameTap::default().feed(&upstream);
        assert_eq!(decoded, (vec![request.into_bytes()], 0));
        let mut broken = FrameTap {
            opened: true,
            ..FrameTap::default()
        };
        assert_eq!(broken.feed(&[0x81, 127, 0xff, 0, 0, 0, 0, 0, 0, 0]).1, 1);
        assert!(broken.feed(&frame(0x81, b"[]", None)).0.is_empty());
    }

    #[tokio::test]
    async fn deliveries_are_counted_by_the_request_shape_that_carried_them() {
        let requests = [
            r#"["REQ","fetch",{"kinds":[445]},{"ids":["ab"]}]"#,
            r##"["REQ","page",{"#h":["g"],"until":5}]"##,
            r##"["REQ","gap",{"#h":["g"],"until":5,"limit":500}]"##,
            r##"["REQ","marmot:group-maintenance:1",{"#h":["g"],"since":1}]"##,
            r##"["REQ","live",{"#h":["g"],"since":10}]"##,
        ];
        let event = |subscription: &str, id: &str| {
            format!(r#"["EVENT","{subscription}",{{"id":"{id}","kind":445,"created_at":7}}]"#)
        };
        let record = |deliveries: &[(&str, &str, u64)]| {
            let mut session = RelayTrafficSessionV1::default();
            for request in requests {
                record_message(&mut session, request.as_bytes(), true, 0);
            }
            for (subscription, id, at_ms) in deliveries {
                let message = event(subscription, id);
                record_message(&mut session, message.as_bytes(), false, *at_ms);
            }
            session
        };
        let first = record(&[
            ("live", "ab", 30),
            ("fetch", "ab", 40),
            ("page", "ab", 50),
            ("gap", "cd", 10),
            ("marmot:group-maintenance:1", "cd", 20),
            // A subscription this connection never asked for names no path.
            ("closed", "cd", 5),
        ]);
        let ab = &first.events["ab"];
        let cd = &first.events["cd"];
        assert_eq!(
            (ab.via_ids, ab.via_window, ab.via_live, ab.count),
            (1, 1, 1, 3)
        );
        assert_eq!(ab.first, Some((RelayDeliveryPath::Live, 30)));
        assert_eq!(
            (cd.via_paged_window, cd.via_maintenance, cd.count),
            (1, 1, 3)
        );
        assert_eq!(cd.first, Some((RelayDeliveryPath::PagedWindow, 10)));

        // Connections merge in order: counts add, and the earliest
        // connection's first delivery stays.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = RelayFaultProxy::start(listener.local_addr().unwrap())
            .await
            .unwrap();
        let second = record(&[("fetch", "ab", 1)]);
        proxy.traffic.lock().unwrap().extend([first, second]);
        let merged = proxy.traffic_since(0, true).events;
        assert_eq!((merged["ab"].via_ids, merged["ab"].count), (2, 4));
        assert_eq!(merged["ab"].first, Some((RelayDeliveryPath::Live, 30)));
        let later = proxy.traffic_since(1, true).events;
        assert_eq!(later["ab"].first, Some((RelayDeliveryPath::Ids, 1)));

        // Each connection keeps its own frames and bytes by path, so one
        // account's cost can be read without the other connections'.
        let connections = proxy.traffic_since(0, true).connection_traffic;
        let frames = |connection: u64| connections[&connection].event_frames.clone();
        let paths = |pairs: &[(&str, u64)]| {
            pairs
                .iter()
                .map(|(path, count)| ((*path).to_owned(), *count))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            frames(0),
            paths(&[
                ("ids", 1),
                ("live", 1),
                ("maintenance", 1),
                ("paged_window", 1),
                ("unknown", 1),
                ("window", 1),
            ])
        );
        assert_eq!(frames(1), paths(&[("ids", 1)]));
        let fetch = event("fetch", "ab").len() as u64;
        assert_eq!(connections[&1].event_bytes, paths(&[("ids", fetch)]));
    }

    #[test]
    fn live_group_eose_counts_packed_raw_replies_and_resets_on_replacement() {
        let mut session = RelayTrafficSessionV1::default();
        let req = br##"["REQ","packed",{"#h":["counted","quiet"],"since":10}]"##;
        record_message(&mut session, req, true, 1);
        for id in ["aa", "bb"] {
            record_message(
                &mut session,
                format!(r#"["EVENT","packed",{{"id":"{id}"}}]"#).as_bytes(),
                false,
                2,
            );
        }
        record_message(&mut session, br#"["EOSE","packed"]"#, false, 3);
        record_message(&mut session, br#"["EVENT","packed",{"id":"cc"}]"#, false, 4);
        record_message(&mut session, req, true, 5);
        record_message(&mut session, br#"["EOSE","packed"]"#, false, 6);
        record_message(
            &mut session,
            br##"["REQ","history",{"#h":["counted"],"until":10}]"##,
            true,
            7,
        );
        record_message(&mut session, br#"["EOSE","history"]"#, false, 8);
        record_message(&mut session, req, true, 9);
        record_message(&mut session, br#"["CLOSE","packed"]"#, true, 10);
        record_message(&mut session, br#"["EOSE","packed"]"#, false, 11);
        assert_eq!(
            session.live_group_replies,
            vec![
                LiveGroupReplyV1 {
                    at_ms: 3,
                    connection: 0,
                    routes: vec!["counted".into(), "quiet".into()],
                    raw_events: 2
                },
                LiveGroupReplyV1 {
                    at_ms: 6,
                    connection: 0,
                    routes: vec!["counted".into(), "quiet".into()],
                    raw_events: 0
                },
            ]
        );
        assert!(session.live_group_pending.is_empty());
    }

    fn masked(payload: &str) -> Vec<u8> {
        frame(0x81, payload.as_bytes(), Some([7, 1, 9, 3]))
    }

    #[test]
    fn request_gate_withholds_only_stalled_history_and_its_follow_ups() {
        let live = r##"["REQ","live",{"#h":["g"],"since":10}]"##;
        let history = r##"["REQ","old",{"#h":["g"],"since":1,"until":5,"limit":501}]"##;
        let negentropy = r##"["NEG-OPEN","neg",{"#h":["g"],"until":5},"61"]"##;
        let follow_ups = [
            r#"["NEG-MSG","neg","62"]"#,
            r#"["CLOSE","old"]"#,
            r#"["NEG-CLOSE","neg"]"#,
        ];
        let ping = frame(0x89, b"ping", Some([1, 2, 3, 4]));
        let compressed = frame(0xc1, b"compressed", Some([1, 2, 3, 4]));
        let mut stream = masked(live);
        // A fragmented history request with a ping between its frames.
        stream.extend(frame(0x01, &history.as_bytes()[..9], Some([1, 2, 3, 4])));
        stream.extend(&ping);
        stream.extend(frame(0x80, &history.as_bytes()[9..], Some([5, 6, 7, 8])));
        stream.extend(masked(negentropy));
        for follow_up in follow_ups {
            stream.extend(masked(follow_up));
        }
        stream.extend(masked(r#"["CLOSE","live"]"#));
        stream.extend(&compressed);
        let run = |stall: bool| {
            let (mut gate, mut forwarded, mut withheld) =
                (RequestGate::default(), Vec::new(), Vec::new());
            for chunk in stream.chunks(5) {
                let (forward, held) = gate.feed(chunk, stall);
                forwarded.extend(forward);
                withheld.extend(held.into_iter().map(|m| String::from_utf8(m).unwrap()));
            }
            (forwarded, withheld)
        };

        assert_eq!(run(false), (stream.clone(), Vec::new()));

        let mut expected = masked(live);
        expected.extend(&ping);
        expected.extend(masked(r#"["CLOSE","live"]"#));
        expected.extend(&compressed);
        let mut withheld = vec![history, negentropy];
        withheld.extend(follow_ups);
        let withheld = withheld.into_iter().map(str::to_owned).collect();
        assert_eq!(run(true), (expected, withheld));

        // A history request held when the stall is lifted mid-message goes
        // through once it ends.
        let mut gate = RequestGate::default();
        let start = frame(0x01, &history.as_bytes()[..9], Some([1, 2, 3, 4]));
        let end = frame(0x80, &history.as_bytes()[9..], Some([5, 6, 7, 8]));
        assert_eq!(gate.feed(&start, true), (Vec::new(), Vec::new()));
        let mut both = start.clone();
        both.extend(&end);
        assert_eq!(gate.feed(&end, false), (both, Vec::new()));
    }

    #[test]
    fn request_gate_passes_everything_after_a_frame_it_cannot_parse() {
        let mut gate = RequestGate::default();
        let broken = [0x81, 127, 0xff, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(gate.feed(&broken, true), (broken.to_vec(), Vec::new()));
        let history = masked(r#"["REQ","old",{"until":5}]"#);
        assert_eq!(gate.feed(&history, true), (history, Vec::new()));
    }

    #[tokio::test]
    async fn information_fetches_are_answered_and_upgrades_reach_the_relay() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = RelayFaultProxy::start(listener.local_addr().unwrap())
            .await
            .unwrap();
        let fetch = b"GET / HTTP/1.1\r\nHost: relay\r\nAccept: application/nostr+json\r\n\r\n";
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (_dialled, _) = listener.accept().await.unwrap();
        client.write_all(fetch).await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(PRODUCTION_RELAY_INFORMATION));
        assert_eq!(proxy.traffic_since(0, true).connections, 0);

        // An upgrade reaches the relay with its head intact, and a stalled
        // history request is logged and withheld while a live one passes.
        let upgrade =
            b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nAccept: application/nostr+json\r\n\r\n";
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (mut relay, _) = listener.accept().await.unwrap();
        client.write_all(upgrade).await.unwrap();
        let mut received = vec![0; upgrade.len()];
        relay.read_exact(&mut received).await.unwrap();
        assert_eq!(received, upgrade);
        proxy.stall_history(true);
        let live = masked(r##"["REQ","live",{"#h":["g"],"since":10}]"##);
        client
            .write_all(&masked(
                r##"["REQ","old",{"#h":["g"],"since":1,"until":5,"limit":501}]"##,
            ))
            .await
            .unwrap();
        client.write_all(&live).await.unwrap();
        let mut received = vec![0; live.len()];
        relay.read_exact(&mut received).await.unwrap();
        assert_eq!(received, live);
        // A live inbox subscription names whose connection it is.
        let inbox = masked(r##"["REQ","inbox",{"kinds":[1059],"#p":["bob"]}]"##);
        client.write_all(&inbox).await.unwrap();
        let mut received = vec![0; inbox.len()];
        relay.read_exact(&mut received).await.unwrap();
        let traffic = proxy.traffic_since(0, true);
        let connection = traffic.history_requests[0].connection;
        assert_eq!(
            traffic.connection_inboxes[&connection],
            BTreeSet::from(["bob".to_owned()])
        );
        let requests = traffic.history_requests;
        let logged: Vec<_> = requests
            .iter()
            .map(|r| {
                (
                    r.verb.as_str(),
                    r.route.as_deref(),
                    r.since,
                    r.until,
                    r.limit,
                    r.withheld,
                )
            })
            .collect();
        assert_eq!(
            logged,
            [("REQ", Some("g"), Some(1), Some(5), Some(501), true)]
        );
        assert!(proxy.traffic_since(0, false).history_requests.is_empty());

        // With no document set, a fetch reaches the relay too.
        proxy.set_information(None);
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        let (mut relay, _) = listener.accept().await.unwrap();
        client.write_all(fetch).await.unwrap();
        let mut received = vec![0; fetch.len()];
        relay.read_exact(&mut received).await.unwrap();
        assert_eq!(received, fetch);
        assert_eq!(proxy.traffic_since(0, true).connections, 2);
    }
}
