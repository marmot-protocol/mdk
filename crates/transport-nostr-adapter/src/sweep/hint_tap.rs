//! NIP-67 `more` hints for the sweep's own REQs, read off the wire.
//!
//! nostr-sdk keeps EOSE's first two elements and drops NIP-67's third, and an
//! acquisition's REQ id never reaches its caller. [`HintTransport`] wraps the
//! client's WebSocket transport instead:
//!
//! - A sweep registers its one filter for one relay before its REQ goes out
//!   ([`EoseHints::watch`]).
//! - The first REQ the client then sends that relay with exactly that filter,
//!   and nothing else, binds the watch to its subscription id.
//! - That id's EOSE says whether it was `more` before the SDK reads the
//!   frame, so the answer is there once the acquisition completes.
//!
//! Frames pass unchanged, and only that answer is kept. The sweep acts on
//! nothing else a hint says: `more` splits a slice, and `finish` is ignored,
//! so a misread hint can cost requests but never skips history.
//!
//! The tap reads the relay's frames as the SDK does, so a hint lands on the
//! REQ the SDK ends: text frames only, the verb decoded as JSON decodes it,
//! and an EOSE identified by nostr's own `RelayMessage` parser. A watch reads
//! no hint, and the slice is left to counting, when any of these happens
//! while it is live:
//!
//! - another watch on the relay has the same filter;
//! - a second one-filter REQ carries the filter, since a stale or unrelated
//!   REQ can't be told from the sweep's;
//! - a REQ re-uses the bound id before its EOSE;
//! - the relay sends an EOSE longer than any real one ([`MAX_EOSE_FRAME`]),
//!   which the tap never parses: it reads frames before the SDK's size check.
//!
//! With no watch live, frames skip the tap's lock.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_wsocket::Message;
use futures::{SinkExt, StreamExt, future};
use nostr::message::relay::{RelayMessage, RelayMessageContext};
use nostr_sdk::prelude::{ClientMessage, Filter, RelayUrl, Url};
use nostr_sdk::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use serde_json::Value;

/// Hints for live watches, shared by every connection of one client.
#[derive(Default)]
pub(crate) struct EoseHints {
    /// Watches registered and not yet dropped.
    live: AtomicUsize,
    /// By relay URL, as the transport is asked to connect to it.
    relays: Mutex<HashMap<String, RelayWatches>>,
}

#[derive(Default)]
struct RelayWatches {
    /// Every live watch on this relay, whatever it has seen so far.
    watches: Vec<Arc<WatchState>>,
    /// Watches by the id of the REQ that carried their filter, until that
    /// id's EOSE.
    bound: HashMap<String, Arc<WatchState>>,
}

struct WatchState {
    filter: Filter,
    seen: Mutex<Seen>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Waiting,
    Bound,
    /// The hint could belong to another watch or another REQ.
    Ambiguous,
    Eose {
        more: bool,
    },
}

impl WatchState {
    fn set(&self, seen: Seen) {
        let mut current = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if *current != Seen::Ambiguous {
            *current = seen;
        }
    }

    fn get(&self) -> Seen {
        *self.seen.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for EoseHints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EoseHints")
            .field("live", &self.live.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl EoseHints {
    /// Watch for the hint on the next REQ to `endpoint` carrying exactly
    /// `filter`. Register before the REQ goes out; drop once its reply is read.
    pub(crate) fn watch(self: &Arc<Self>, endpoint: &RelayUrl, filter: &Filter) -> HintWatch {
        let key = <&Url>::from(endpoint).as_str().to_owned();
        let mut relays = self.lock();
        let relay = relays.entry(key.clone()).or_default();
        let mut seen = Seen::Waiting;
        for twin in relay.watches.iter().filter(|other| other.filter == *filter) {
            twin.set(Seen::Ambiguous);
            seen = Seen::Ambiguous;
        }
        let state = Arc::new(WatchState {
            filter: filter.clone(),
            seen: Mutex::new(seen),
        });
        relay.watches.push(state.clone());
        self.live.fetch_add(1, Ordering::AcqRel);
        HintWatch {
            hints: self.clone(),
            key,
            state,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, RelayWatches>> {
        self.relays.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A frame the client sends `relay`: the first one-filter REQ carrying a
    /// waiting watch's filter binds it. Any later one, or a REQ re-using a
    /// bound id, leaves the hint without a sure owner.
    fn sent(&self, relay: &str, text: &str) {
        if self.live.load(Ordering::Acquire) == 0 || head_verb(text).as_deref() != Some("REQ") {
            return;
        }
        let Ok(ClientMessage::Req {
            subscription_id,
            filters,
        }) = ClientMessage::from_json(text)
        else {
            return;
        };
        let mut relays = self.lock();
        let Some(RelayWatches { watches, bound }) = relays.get_mut(relay) else {
            return;
        };
        // A REQ re-using an id replaces that subscription, and the old one's
        // EOSE may still be on its way: neither REQ owns the next EOSE.
        let reused = bound
            .remove(subscription_id.as_str())
            .inspect(|displaced| displaced.set(Seen::Ambiguous))
            .is_some();
        let [filter] = filters.as_slice() else {
            return;
        };
        // The sweep's REQ is one of these, but a stale or unrelated REQ with
        // the same filter can't be told from it.
        for watch in watches.iter().filter(|watch| watch.filter == **filter) {
            if !reused && watch.get() == Seen::Waiting {
                watch.set(Seen::Bound);
                bound.insert(subscription_id.as_str().to_owned(), watch.clone());
            } else {
                watch.set(Seen::Ambiguous);
            }
        }
    }

    /// A frame `relay` sends the client: an EOSE settles the watch bound to
    /// its id.
    fn received(&self, relay: &str, text: &str) {
        if self.live.load(Ordering::Acquire) == 0 || head_verb(text).as_deref() != Some("EOSE") {
            return;
        }
        // The tap reads frames before the SDK's size check, so it parses only
        // what a real EOSE could be, and outside the lock.
        let eose = (text.len() <= MAX_EOSE_FRAME).then(|| read_eose(text));
        let mut relays = self.lock();
        let Some(watches) = relays.get_mut(relay) else {
            return;
        };
        match eose {
            Some(Some((id, more))) => {
                if let Some(watch) = watches.bound.remove(&id) {
                    watch.set(Seen::Eose { more });
                }
            }
            Some(None) => {}
            // Unread, it may end any bound REQ, so none keeps a hint.
            None => {
                for watch in watches.bound.values() {
                    watch.set(Seen::Ambiguous);
                }
            }
        }
    }

    fn forget(&self, key: &str, state: &Arc<WatchState>) {
        let mut relays = self.lock();
        if let Some(relay) = relays.get_mut(key) {
            relay.watches.retain(|watch| !Arc::ptr_eq(watch, state));
            relay.bound.retain(|_, watch| !Arc::ptr_eq(watch, state));
            if relay.watches.is_empty() {
                relays.remove(key);
            }
        }
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The longest EOSE frame the tap parses. A real one is a subscription id of
/// at most 64 characters and a few hint names.
const MAX_EOSE_FRAME: usize = 1024;

/// An EOSE frame's subscription id, read with the parser and trimming the SDK
/// uses, and whether it says NIP-67 `more`, which that parser drops. None when
/// the SDK would not take the frame as an EOSE, so it ends no REQ. The parser
/// alone decides that: a hint the tap can't read is no hint, and the frame
/// still ends its REQ.
fn read_eose(text: &str) -> Option<(String, bool)> {
    let text = text.trim();
    let Ok(RelayMessage::EndOfStoredEvents(id)) =
        RelayMessage::from_json_with_context(text, &mut RelayMessageContext::Unknown)
    else {
        return None;
    };
    let more = serde_json::from_str::<Value>(text).is_ok_and(|frame| says_more(frame.get(2)));
    Some((id.as_str().to_owned(), more))
}

/// Whether NIP-67's third EOSE element names `more`. No other name, `finish`
/// included, changes what the sweep does.
fn says_more(hints: Option<&Value>) -> bool {
    hints
        .and_then(Value::as_array)
        .is_some_and(|names| names.iter().any(|name| name.as_str() == Some("more")))
}

/// The longest a verb the tap reads can be on the wire: "EOSE" with every
/// character escaped as `\uXXXX` is 24 bytes.
const MAX_VERB_TOKEN: usize = 32;

/// A frame's verb, its first element decoded as JSON decodes it (escapes
/// included), when that is a string short enough to be one the tap reads.
/// Reads only the frame's head, so it is cheap enough for every frame.
fn head_verb(text: &str) -> Option<Cow<'_, str>> {
    let token = text.trim_start().strip_prefix('[')?.trim_start();
    let body = token.strip_prefix('"')?;
    let mut escaped = false;
    for (index, byte) in body.bytes().enumerate().take(MAX_VERB_TOKEN) {
        match byte {
            b'"' if !escaped => {
                let raw = &body[..index];
                if !raw.contains('\\') {
                    return Some(Cow::Borrowed(raw));
                }
                return serde_json::from_str::<String>(&token[..index + 2])
                    .ok()
                    .map(Cow::Owned);
            }
            b'\\' if !escaped => escaped = true,
            _ => escaped = false,
        }
    }
    None
}

/// One sweep REQ's watch. Dropping it forgets the registration.
pub(crate) struct HintWatch {
    hints: Arc<EoseHints>,
    key: String,
    state: Arc<WatchState>,
}

impl HintWatch {
    /// Whether the watched REQ's EOSE said `more`, when it was seen and no
    /// other watch or REQ could own it.
    pub(crate) fn more(&self) -> bool {
        matches!(self.state.get(), Seen::Eose { more: true })
    }
}

impl Drop for HintWatch {
    fn drop(&mut self) {
        self.hints.forget(&self.key, &self.state);
    }
}

type ConnectFuture<'a> = std::pin::Pin<
    Box<
        dyn Future<Output = Result<(WebSocketSink, WebSocketStream), nostr_sdk::error::Error>>
            + Send
            + 'a,
    >,
>;

/// The client's transport, with [`EoseHints`] reading every frame.
#[derive(Clone)]
pub(crate) struct HintTransport {
    transport: Arc<dyn WebSocketTransport>,
    hints: Arc<EoseHints>,
}

impl HintTransport {
    pub(crate) fn new(transport: Arc<dyn WebSocketTransport>, hints: Arc<EoseHints>) -> Self {
        Self { transport, hints }
    }
}

impl fmt::Debug for HintTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HintTransport")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl WebSocketTransport for HintTransport {
    fn support_ping(&self) -> bool {
        self.transport.support_ping()
    }

    fn connect<'a>(&'a self, url: &'a Url, proxy: Option<SocketAddr>) -> ConnectFuture<'a> {
        Box::pin(async move {
            let (sink, stream) = self.transport.connect(url, proxy).await?;
            let relay: Arc<str> = Arc::from(url.as_str());
            let (sent_hints, sent_relay) = (self.hints.clone(), relay.clone());
            // Text frames only: the SDK ignores the rest, and `as_text` would
            // read a binary frame as one.
            let sink: WebSocketSink = Box::pin(sink.with(move |message: Message| {
                if let Message::Text(text) = &message {
                    sent_hints.sent(&sent_relay, text);
                }
                future::ready(Ok::<_, nostr_sdk::error::Error>(message))
            }));
            let hints = self.hints.clone();
            let stream: WebSocketStream = Box::pin(stream.inspect(move |item| {
                if let Ok(Message::Text(text)) = item {
                    hints.received(&relay, text);
                }
            }));
            Ok((sink, stream))
        })
    }
}

#[cfg(test)]
mod tests {
    use nostr_sdk::prelude::{Kind, SubscriptionId, Timestamp};

    use super::*;

    const RELAY: &str = "wss://relay.example.com";

    fn relay() -> RelayUrl {
        RelayUrl::parse(RELAY).unwrap()
    }

    fn filter(since: u64) -> Filter {
        Filter::new()
            .kind(Kind::from(445))
            .since(Timestamp::from_secs(since))
            .until(Timestamp::from_secs(since + 59))
            .limit(500)
    }

    fn key() -> String {
        <&Url>::from(&relay()).as_str().to_owned()
    }

    fn req(id: &str, filters: Vec<Filter>) -> String {
        ClientMessage::req(SubscriptionId::new(id), filters).as_json()
    }

    /// Every character of `text` as a JSON `\uXXXX` escape. Built at run time
    /// so the escapes reach the frame as written.
    fn escaped(text: &str) -> String {
        text.chars()
            .map(|c| format!("{}u{:04X}", '\\', u32::from(c)))
            .collect()
    }

    /// "EOSE" with only its first character escaped.
    fn escaped_eose() -> String {
        format!("{}OSE", escaped("E"))
    }

    /// Whether a watch bound to REQ "sweep" reads `more` after `frames`.
    fn more_after(frames: &[&str]) -> bool {
        let hints = Arc::new(EoseHints::default());
        let watch = hints.watch(&relay(), &filter(0));
        hints.sent(&key(), &req("sweep", vec![filter(0)]));
        for frame in frames {
            hints.received(&key(), frame);
        }
        watch.more()
    }

    #[test]
    fn only_more_is_read_from_a_hint() {
        for (third, more) in [
            (r#"["more"]"#, true),
            (r#"["finish","more"]"#, true),
            (r#"["auth","more"]"#, true),
            (r#"["later",7,"more"]"#, true),
            (r#"["finish"]"#, false),
            (r#"["auth","finish"]"#, false),
            (r#"["auth"]"#, false),
            (r#"[]"#, false),
            (r#""more""#, false),
        ] {
            let frame: Value = serde_json::from_str(&format!(r#"["EOSE","s",{third}]"#)).unwrap();
            assert_eq!(says_more(frame.get(2)), more, "{third}");
        }
        assert!(!says_more(None));
        assert!(!more_after(&[r#"["EOSE","sweep",["finish"]]"#]));
    }

    #[test]
    fn verbs_are_read_from_the_frame_head_as_json_reads_them() {
        assert!(escaped_eose().starts_with('\\'));
        assert_eq!(escaped("EOSE").len(), 24);
        for (frame, verb) in [
            (r#"["EOSE","s"]"#.to_owned(), Some("EOSE")),
            (r#" [ "EOSE" ,"s"]"#.to_owned(), Some("EOSE")),
            (format!(r#"["{}","s"]"#, escaped_eose()), Some("EOSE")),
            (format!(r#"["{}","s"]"#, escaped("EOSE")), Some("EOSE")),
            (format!(r#"["{}","s"]"#, escaped("REQ")), Some("REQ")),
            (r#"["EOSEX","s"]"#.to_owned(), Some("EOSEX")),
            (r#"["E\"OSE","s"]"#.to_owned(), Some("E\"OSE")),
            (r#"["EVENT","EOSE"]"#.to_owned(), Some("EVENT")),
            (r#"{"EOSE":1}"#.to_owned(), None),
            (r#"[1,"EOSE"]"#.to_owned(), None),
            (r#"["EOSE"#.to_owned(), None),
        ] {
            assert_eq!(head_verb(&frame).as_deref(), verb, "{frame}");
        }
        let long = format!(r#"["{}","s"]"#, "E".repeat(MAX_VERB_TOKEN));
        assert_eq!(head_verb(&long), None);
        assert_eq!(
            head_verb(&req("s", vec![filter(0)])).as_deref(),
            Some("REQ")
        );
    }

    #[test]
    fn eose_frames_are_read_as_the_sdk_reads_them() {
        // An escaped verb or id is still the REQ's EOSE to the SDK.
        for frame in [
            format!(r#"["{}","sweep",["more"]]"#, escaped_eose()),
            format!(r#"["{}","sweep",["more"]]"#, escaped("EOSE")),
            format!(r#"["EOSE","{}",["more"]]"#, escaped("sweep")),
            " \n[ \"EOSE\" , \"sweep\" , [\"more\"] ] ".to_owned(),
        ] {
            assert!(more_after(&[&frame]), "{frame}");
        }
        // The SDK ends the REQ on its first EOSE, however it was spelled and
        // whether or not the tap can read its hint, so a second one is not
        // that REQ's reply. `1e400` is past what a JSON value can hold, but
        // the SDK skips trailing elements without reading them.
        let late = r#"["EOSE","sweep",["more"]]"#;
        for first in [
            r#"["EOSE","sweep"]"#.to_owned(),
            format!(r#"["{}","sweep"]"#, escaped_eose()),
            r#"["EOSE","sweep",["more"],1e400]"#.to_owned(),
        ] {
            assert!(
                RelayMessage::from_json(first.as_str()).is_ok(),
                "the SDK takes {first}"
            );
            assert!(!more_after(&[&first, late]), "{first}");
        }
        // A frame the SDK would not take as an EOSE ends nothing.
        for rejected in [
            r#"["EOSE",7,["more"]]"#,
            r#"["EOSE"]"#,
            r#"["EOSE","sweep",["more"]"#,
            r#"["EOSEX","sweep",["more"]]"#,
        ] {
            assert!(RelayMessage::from_json(rejected).is_err(), "{rejected}");
            assert!(!more_after(&[rejected]), "{rejected}");
            assert!(more_after(&[rejected, late]), "{rejected}");
        }
    }

    #[test]
    fn the_watched_reqs_eose_leaves_its_hint() {
        let hints = Arc::new(EoseHints::default());
        let watch = hints.watch(&relay(), &filter(0));
        let other = hints.watch(&relay(), &filter(60));

        // Another relay's REQ and a two-filter REQ bind nothing.
        hints.sent("wss://elsewhere.example.com/", &req("a", vec![filter(0)]));
        hints.sent(&key(), &req("b", vec![filter(0), filter(60)]));
        hints.sent(&key(), &req("c", vec![filter(0)]));
        hints.sent(&key(), &req("d", vec![filter(60)]));
        assert!(!watch.more());

        // Only the bound id's EOSE counts, and only its first.
        hints.received(&key(), r#"["EOSE","b",["more"]]"#);
        hints.received(&key(), r#"["EVENT","c",{}]"#);
        assert!(!watch.more());
        hints.received(&key(), r#"["EOSE","c",["more"]]"#);
        hints.received(&key(), r#"["EOSE","c"]"#);
        hints.received(&key(), r#"["EOSE","d"]"#);
        hints.received(&key(), r#"["EOSE","d",["more"]]"#);
        assert!(watch.more());
        assert!(!other.more());

        drop((watch, other));
        assert_eq!(hints.live.load(Ordering::Acquire), 0);
        assert!(hints.lock().is_empty());
    }

    #[test]
    fn two_watches_with_one_filter_read_no_hint() {
        let hints = Arc::new(EoseHints::default());
        let first = hints.watch(&relay(), &filter(0));
        hints.sent(&key(), &req("a", vec![filter(0)]));
        let second = hints.watch(&relay(), &filter(0));
        hints.sent(&key(), &req("b", vec![filter(0)]));
        hints.received(&key(), r#"["EOSE","a",["more"]]"#);
        hints.received(&key(), r#"["EOSE","b",["more"]]"#);

        assert!(!first.more());
        assert!(!second.more());

        // Once both are gone, the next watch reads its hint again.
        drop((first, second));
        let third = hints.watch(&relay(), &filter(0));
        hints.sent(&key(), &req("c", vec![filter(0)]));
        hints.received(&key(), r#"["EOSE","c",["more"]]"#);
        assert!(third.more());
    }

    #[test]
    fn a_reused_id_reads_no_hint_for_either_req() {
        let hints = Arc::new(EoseHints::default());
        let first = hints.watch(&relay(), &filter(0));
        let second = hints.watch(&relay(), &filter(60));
        hints.sent(&key(), &req("a", vec![filter(0)]));
        hints.sent(&key(), &req("a", vec![filter(60)]));
        // The first REQ's EOSE, still on its way, or the second's.
        hints.received(&key(), r#"["EOSE","a",["more"]]"#);

        assert!(!first.more());
        assert!(!second.more());

        // An unwatched or two-filter REQ re-using the id spoils it too.
        for replacement in [
            req("b", vec![filter(120)]),
            req("b", vec![filter(120), filter(180)]),
        ] {
            let watch = hints.watch(&relay(), &filter(240));
            hints.sent(&key(), &req("b", vec![filter(240)]));
            hints.sent(&key(), &replacement);
            hints.received(&key(), r#"["EOSE","b",["more"]]"#);
            assert!(!watch.more(), "{replacement}");
        }
    }

    #[test]
    fn a_second_req_with_the_watched_filter_reads_no_hint() {
        let hints = Arc::new(EoseHints::default());

        // A stale REQ with the filter binds first and answers first; the
        // sweep's own REQ follows, before or after that EOSE.
        for stale_eose_first in [true, false] {
            let watch = hints.watch(&relay(), &filter(0));
            hints.sent(&key(), &req("stale", vec![filter(0)]));
            if stale_eose_first {
                hints.received(&key(), r#"["EOSE","stale",["more"]]"#);
            }
            hints.sent(&key(), &req("sweep", vec![filter(0)]));
            if !stale_eose_first {
                hints.received(&key(), r#"["EOSE","stale",["more"]]"#);
            }
            hints.received(&key(), r#"["EOSE","sweep",["more"]]"#);
            assert!(!watch.more(), "stale EOSE first: {stale_eose_first}");
        }
        assert!(hints.lock().is_empty());
    }

    #[test]
    fn an_eose_too_long_to_read_spoils_every_bound_watch() {
        let padding = serde_json::to_string(&vec!["x"; MAX_EOSE_FRAME]).unwrap();
        let long = |verb: &str| format!(r#"["{verb}","other",["more",{padding}]]"#);
        let more = r#"["EOSE","sweep",["more"]]"#;

        // Whatever id it names, and however its verb is spelled, it is never
        // parsed, and it may be the bound REQ's EOSE.
        for verb in ["EOSE".to_owned(), escaped_eose(), escaped("EOSE")] {
            let oversized = long(&verb);
            assert!(oversized.len() > MAX_EOSE_FRAME);
            assert!(!more_after(&[&oversized, more]), "{verb}");
        }
        // A long frame that is not an EOSE spoils nothing.
        assert!(more_after(&[&long("NOTICE"), more]));

        // A watch whose REQ goes out afterwards still reads its hint.
        let hints = Arc::new(EoseHints::default());
        let bound = hints.watch(&relay(), &filter(0));
        let later = hints.watch(&relay(), &filter(60));
        hints.sent(&key(), &req("sweep", vec![filter(0)]));
        hints.received(&key(), &long("EOSE"));
        hints.sent(&key(), &req("later", vec![filter(60)]));
        hints.received(&key(), r#"["EOSE","later",["more"]]"#);
        assert!(!bound.more());
        assert!(later.more());
    }

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
                    Box::pin(futures::stream::iter(frames.into_iter().map(Ok)));
                Ok((sink, stream))
            })
        }
    }

    #[tokio::test]
    async fn only_text_frames_reach_the_tap() {
        let hints = Arc::new(EoseHints::default());
        let watch = hints.watch(&relay(), &filter(0));
        let transport = HintTransport::new(
            Arc::new(Scripted(Mutex::new(vec![
                // Read, this would end the REQ before its real EOSE.
                Message::Binary(br#"["EOSE","sweep"]"#.to_vec()),
                Message::Text(r#"["EOSE","sweep",["more"]]"#.to_owned()),
            ]))),
            hints.clone(),
        );
        let (mut sink, mut stream) = transport
            .connect(<&Url>::from(&relay()), None)
            .await
            .unwrap();

        // A binary REQ with the filter would spoil the binding if it were read.
        sink.send(Message::Binary(req("binary", vec![filter(0)]).into_bytes()))
            .await
            .unwrap();
        sink.send(Message::Text(req("sweep", vec![filter(0)])))
            .await
            .unwrap();
        stream.next().await.unwrap().unwrap();
        assert!(!watch.more());
        stream.next().await.unwrap().unwrap();
        assert!(watch.more());
    }
}
