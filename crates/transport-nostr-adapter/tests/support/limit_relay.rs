//! Test-only WebSocket proxy that enforces production relay subscription
//! limits in front of an in-process upstream relay.
//!
//! Each client connection gets its own upstream connection, so the per-socket
//! accounting below mirrors what a real relay keeps per WebSocket. Frames that
//! pass the limits are forwarded unchanged; a refused `REQ` is answered here
//! and never reaches the upstream. Statistics are aggregate counts only: the
//! proxy never prints subscription ids, filters, or payloads.
//!
//! Modelled on the deployed strfry 1.1.3 limits as reported by the relay
//! operators: ordinary REQs and NEG sessions have separate per-connection caps
//! (same value); the NEG cap and NEG parse errors answer with a NOTICE (no
//! session id), never CLOSED; a NEG session is freed only by NEG-CLOSE, a
//! same-id NEG-OPEN or disconnect, not by reconciliation completion; ordinary
//! REQ filters have `limit` silently clamped to 500.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

/// Kinds a production relay accepts in an explicit `kinds` list.
pub const PRODUCTION_ALLOWED_KINDS: [u64; 11] =
    [0, 3, 5, 303, 445, 1059, 10000, 10002, 10050, 24133, 30443];

/// strfry-like refusal reasons. The machine-readable prefix decides what
/// nostr-sdk does with the REQ (`error:`/`invalid:` drop it from the registry).
pub mod reason {
    pub const TOO_MANY_SUBSCRIPTIONS: &str = "error: too many concurrent REQs";
    pub const TOO_MANY_FILTERS: &str = "invalid: too many filters";
    pub const TOO_MANY_KINDS: &str = "invalid: too many kinds in filter";
    pub const KIND_NOT_ALLOWED: &str = "invalid: kind not allowed";
    pub const MALFORMED: &str = "invalid: malformed REQ";
    pub const TOO_MANY_TAGS: &str = "invalid: too many tags in filter";
    /// strfry sends this as a NOTICE with no session id.
    pub const TOO_MANY_NEG: &str = "ERROR: too many concurrent NEG requests";
}

/// Strfry's per-filter result cap for ordinary REQs.
pub const REQ_LIMIT_CLAMP: u64 = 500;
/// Largest `limit` strfry accepts on a NEG-OPEN filter.
pub const NEG_MAX_LIMIT: u64 = 5_000_000;

/// Negentropy v1 message: version 0x61, one range up to infinity (timestamp
/// 0, empty id prefix) in Fingerprint mode (1) with a fingerprint no set has.
const STALLING_NEG_MSG: &str = "61000001ffeeddccbbaa99887766554433221100";

/// Injected misbehaviour for NEG sessions, switchable at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegFault {
    /// Forward NEG traffic unchanged.
    None,
    /// Answer every NEG-OPEN with NEG-ERR (session not created).
    ErrOnOpen,
    /// Swallow every NEG-OPEN: the session is open on the relay, but nothing
    /// answers it (exercises the client's first-reply timeout).
    SilentOpen,
    /// Answer NEG-OPEN at once with a crafted NEG-MSG holding one mismatched
    /// fingerprint over the whole range, which obliges the client to send
    /// another round, then swallow the client's NEG-MSGs. The first-reply
    /// timeout is satisfied, so only the caller's overall deadline ends the
    /// sync.
    FingerprintThenStall,
}

/// How a refused REQ is answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectStyle {
    /// `["CLOSED", id, reason]` (NIP-01).
    Closed,
    /// `["NOTICE", reason]` with no id, as older relays do.
    Notice,
}

#[derive(Clone, Debug)]
pub struct LimitConfig {
    /// Simultaneous live REQs per connection.
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_kinds_per_filter: usize,
    /// Kinds allowed in an explicit `kinds` list; `None` allows any.
    pub allowed_kinds: Option<BTreeSet<u64>>,
    /// Distinct tag-filter keys (`#h`, `#p`, ...) allowed per filter.
    pub max_tag_keys_per_filter: usize,
    /// Clamp each ordinary REQ filter's `limit` (absent or larger) to this.
    pub req_limit_clamp: Option<u64>,
    /// Live NEG sessions per connection (a separate counter from REQs).
    pub max_neg_sessions: usize,
    /// Phantom NEG sessions every connection starts with, to pre-fill the cap.
    pub neg_prefilled_sessions: usize,
    /// Alternative model: live NEG sessions also count toward
    /// `max_subscriptions` (strfry 1.1.3 does not do this).
    pub neg_counts_toward_limit: bool,
    pub reject_style: RejectStyle,
}

impl Default for LimitConfig {
    /// The production relay limits.
    fn default() -> Self {
        Self {
            max_subscriptions: 200,
            max_filters: 3,
            max_kinds_per_filter: 16,
            allowed_kinds: Some(PRODUCTION_ALLOWED_KINDS.into_iter().collect()),
            max_tag_keys_per_filter: 3,
            req_limit_clamp: Some(REQ_LIMIT_CLAMP),
            max_neg_sessions: 200,
            neg_prefilled_sessions: 0,
            neg_counts_toward_limit: false,
            reject_style: RejectStyle::Closed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReqOutcome {
    Accepted,
    /// Accepted as a same-id replacement of a REQ already live on the socket.
    Replaced,
    Rejected(&'static str),
}

/// One client `REQ` as the proxy saw it. The id is kept only so tests can
/// correlate repeats; never print it.
#[derive(Clone, Debug)]
pub struct ReqRecord {
    pub at: Instant,
    pub connection: usize,
    pub subscription_id: String,
    pub filters: usize,
    pub outcome: ReqOutcome,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionStats {
    pub open: bool,
    pub active: usize,
    pub peak_active: usize,
    pub reqs: usize,
    pub rejected: usize,
    pub closes: usize,
    pub neg_active: usize,
    pub neg_peak: usize,
    pub neg_opens: usize,
}

#[derive(Clone, Debug, Default)]
pub struct LimitStats {
    pub connections: Vec<ConnectionStats>,
    pub total_reqs: usize,
    pub accepted_reqs: usize,
    pub rejections: BTreeMap<&'static str, usize>,
    pub max_filters_seen: usize,
    pub max_kinds_seen: usize,
    pub max_tag_keys_seen: usize,
    /// Most values one tag key (`#h`, `#p`, ...) carried in a REQ filter.
    pub max_tag_values_seen: usize,
    pub disallowed_kinds_seen: BTreeSet<u64>,
    /// REQ filters whose `limit` was clamped (absent or above the clamp).
    pub clamped_filters: usize,
    /// Largest `limit` a REQ filter asked for (absent counts as 0).
    pub max_req_limit_seen: u64,
    /// REQs re-sent with an id already live on the same connection.
    pub reqs_with_active_id: usize,
    pub closes: usize,
    /// CLOSEs naming an id that was not live on the connection.
    pub closes_unknown: usize,
    /// Live REQs the upstream itself ended with CLOSED.
    pub upstream_closed: usize,
    pub neg_opens: usize,
    pub neg_rejections: BTreeMap<&'static str, usize>,
    pub neg_closes: usize,
    /// NEG-CLOSEs naming a session that was not open.
    pub neg_closes_unknown: usize,
    /// NEG cap NOTICEs sent.
    pub neg_cap_notices: usize,
    /// NEG-ERR frames the upstream sent.
    pub upstream_neg_errs: usize,
    /// NEG-MSG frames dropped by `NegFault::FingerprintThenStall`.
    pub neg_msgs_dropped: usize,
    pub neg_max_limit_seen: u64,
    pub neg_max_kinds_seen: usize,
    pub neg_disallowed_kinds_seen: BTreeSet<u64>,
    pub forced_drops: usize,
    pub req_log: Vec<ReqRecord>,
}

impl LimitStats {
    /// Live REQs across currently open connections.
    pub fn active_now(&self) -> usize {
        self.connections
            .iter()
            .filter(|c| c.open)
            .map(|c| c.active)
            .sum()
    }

    /// Live (non-phantom) NEG sessions across open connections.
    pub fn neg_active_now(&self) -> usize {
        self.connections
            .iter()
            .filter(|c| c.open)
            .map(|c| c.neg_active)
            .sum()
    }

    pub fn open_connections(&self) -> usize {
        self.connections.iter().filter(|c| c.open).count()
    }

    pub fn peak_active(&self) -> usize {
        self.connections
            .iter()
            .map(|c| c.peak_active)
            .max()
            .unwrap_or(0)
    }

    pub fn rejections_total(&self) -> usize {
        self.rejections.values().sum()
    }

    pub fn reqs_since(&self, since: Instant) -> usize {
        self.req_log.iter().filter(|r| r.at >= since).count()
    }

    pub fn reqs_on_connection(&self, connection: usize) -> usize {
        self.req_log
            .iter()
            .filter(|r| r.connection == connection)
            .count()
    }

    /// Distinct subscription ids ever sent in a REQ.
    pub fn distinct_req_ids(&self) -> usize {
        self.req_log
            .iter()
            .map(|r| r.subscription_id.as_str())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Short privacy-safe summary for `--nocapture` output.
    pub fn summary(&self) -> String {
        format!(
            "reqs={} accepted={} rejections={:?} active_now={} peak_active={} open_conns={} \
             conns={} max_filters={} max_kinds={} max_tag_keys={} max_tag_values={} disallowed_kinds={:?} \
             clamped_filters={} max_req_limit={} reqs_with_active_id={} closes={} \
             closes_unknown={} upstream_closed={} neg_opens={} neg_active_now={} neg_closes={} \
             neg_closes_unknown={} neg_cap_notices={} neg_rejections={:?} upstream_neg_errs={} \
             neg_msgs_dropped={} neg_max_limit={} neg_max_kinds={} neg_disallowed_kinds={:?} \
             forced_drops={}",
            self.total_reqs,
            self.accepted_reqs,
            self.rejections,
            self.active_now(),
            self.peak_active(),
            self.open_connections(),
            self.connections.len(),
            self.max_filters_seen,
            self.max_kinds_seen,
            self.max_tag_keys_seen,
            self.max_tag_values_seen,
            self.disallowed_kinds_seen,
            self.clamped_filters,
            self.max_req_limit_seen,
            self.reqs_with_active_id,
            self.closes,
            self.closes_unknown,
            self.upstream_closed,
            self.neg_opens,
            self.neg_active_now(),
            self.neg_closes,
            self.neg_closes_unknown,
            self.neg_cap_notices,
            self.neg_rejections,
            self.upstream_neg_errs,
            self.neg_msgs_dropped,
            self.neg_max_limit_seen,
            self.neg_max_kinds_seen,
            self.neg_disallowed_kinds_seen,
            self.forced_drops,
        )
    }
}

#[derive(Default)]
struct ConnectionState {
    active: HashSet<String>,
    neg: HashSet<String>,
}

#[derive(Default)]
struct Shared {
    stats: LimitStats,
    states: Vec<ConnectionState>,
    neg_fault: Option<NegFault>,
    /// Delay before each client frame is handled, so a refusal or an upstream
    /// answer costs about one simulated round trip.
    client_delay: Duration,
}

impl Shared {
    fn counted(&self, connection: usize, config: &LimitConfig) -> usize {
        let state = &self.states[connection];
        state.active.len()
            + if config.neg_counts_toward_limit {
                state.neg.len()
            } else {
                0
            }
    }

    fn neg_counted(&self, connection: usize, config: &LimitConfig) -> usize {
        self.states[connection].neg.len() + config.neg_prefilled_sessions
    }

    fn refresh(&mut self, connection: usize) {
        let state = &self.states[connection];
        let (active, neg) = (state.active.len(), state.neg.len());
        let conn = &mut self.stats.connections[connection];
        conn.active = active;
        conn.peak_active = conn.peak_active.max(active);
        conn.neg_active = neg;
        conn.neg_peak = conn.neg_peak.max(neg);
    }
}

pub struct LimitRelay {
    url: String,
    shared: Arc<Mutex<Shared>>,
    drop_tx: watch::Sender<u64>,
}

/// What the proxy does with one client frame.
enum Verdict {
    Forward,
    /// Forward this rewritten frame instead (a clamped `limit`).
    ForwardRewritten(String),
    /// Drop the frame without any reply.
    Swallow,
    /// Reply to the client and optionally tell the upstream to drop a live id.
    Refuse {
        reply: String,
        upstream: Option<String>,
    },
}

impl LimitRelay {
    pub async fn start(upstream: String, config: LimitConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let shared = Arc::new(Mutex::new(Shared::default()));
        let (drop_tx, _) = watch::channel(0_u64);
        let accept_shared = shared.clone();
        let accept_drop = drop_tx.clone();
        let config = Arc::new(config);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = accept_shared.clone();
                let config = config.clone();
                let upstream = upstream.clone();
                let mut drop_rx = accept_drop.subscribe();
                drop_rx.mark_unchanged();
                tokio::spawn(async move {
                    let Ok(client) = accept_async(stream).await else {
                        return;
                    };
                    let Ok((relay, _)) = connect_async(&upstream).await else {
                        return;
                    };
                    let connection = {
                        let mut shared = shared.lock().unwrap();
                        shared.states.push(ConnectionState::default());
                        shared.stats.connections.push(ConnectionStats {
                            open: true,
                            ..ConnectionStats::default()
                        });
                        shared.states.len() - 1
                    };
                    let (mut client_write, mut client_read) = client.split();
                    let (mut relay_write, mut relay_read) = relay.split();
                    loop {
                        tokio::select! {
                            _ = drop_rx.changed() => break,
                            frame = client_read.next() => {
                                let Some(Ok(message)) = frame else { break };
                                let delay = shared.lock().unwrap().client_delay;
                                if !delay.is_zero() {
                                    tokio::time::sleep(delay).await;
                                }
                                let Message::Text(text) = &message else {
                                    if matches!(message, Message::Close(_)) {
                                        break;
                                    }
                                    continue;
                                };
                                let verdict = inspect_client_frame(
                                    &shared,
                                    &config,
                                    connection,
                                    text.as_str(),
                                );
                                match verdict {
                                    Verdict::Forward => {
                                        if relay_write.send(message).await.is_err() {
                                            break;
                                        }
                                    }
                                    Verdict::ForwardRewritten(text) => {
                                        if relay_write.send(Message::Text(text.into())).await.is_err() {
                                            break;
                                        }
                                    }
                                    Verdict::Swallow => {}
                                    Verdict::Refuse { reply, upstream } => {
                                        if let Some(upstream) = upstream
                                            && relay_write
                                                .send(Message::Text(upstream.into()))
                                                .await
                                                .is_err()
                                        {
                                            break;
                                        }
                                        if client_write
                                            .send(Message::Text(reply.into()))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }
                                }
                            }
                            frame = relay_read.next() => {
                                let Some(Ok(message)) = frame else { break };
                                if let Message::Text(text) = &message
                                    && !inspect_relay_frame(&shared, connection, text.as_str())
                                {
                                    continue;
                                }
                                if matches!(message, Message::Close(_)) {
                                    break;
                                }
                                if client_write.send(message).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let mut shared = shared.lock().unwrap();
                    shared.states[connection] = ConnectionState::default();
                    let conn = &mut shared.stats.connections[connection];
                    conn.open = false;
                    conn.active = 0;
                    conn.neg_active = 0;
                    // Dropping both halves here abruptly ends the client and
                    // upstream sockets, as a relay restart or network drop would.
                });
            }
        });
        Self {
            url,
            shared,
            drop_tx,
        }
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn stats(&self) -> LimitStats {
        self.shared.lock().unwrap().stats.clone()
    }

    /// Simulate a round trip of about `delay` on every connection.
    pub fn set_client_delay(&self, delay: Duration) {
        self.shared.lock().unwrap().client_delay = delay;
    }

    /// Switch the injected NEG behaviour for every connection.
    pub fn set_neg_fault(&self, fault: NegFault) {
        self.shared.lock().unwrap().neg_fault = Some(fault);
    }

    /// Abruptly end every open client connection (and its upstream socket).
    pub fn drop_all_connections(&self) {
        self.shared.lock().unwrap().stats.forced_drops += 1;
        self.drop_tx.send_modify(|generation| *generation += 1);
    }

    /// Poll the stats until `condition` holds or `timeout` passes. Returns
    /// whether it held.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        mut condition: impl FnMut(&LimitStats) -> bool,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if condition(&self.stats()) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait until the REQ count has not changed for `quiet`, or `timeout`.
    pub async fn wait_quiet(&self, quiet: Duration, timeout: Duration) -> LimitStats {
        let deadline = Instant::now() + timeout;
        let mut last = self.stats();
        let mut last_change = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let now = self.stats();
            if now.total_reqs != last.total_reqs
                || now.closes != last.closes
                || now.active_now() != last.active_now()
                || now.open_connections() != last.open_connections()
            {
                last_change = Instant::now();
            }
            last = now;
            if last_change.elapsed() >= quiet || Instant::now() >= deadline {
                return last;
            }
        }
    }
}

fn filter_kinds(filter: &Value) -> Vec<u64> {
    filter
        .get("kinds")
        .and_then(Value::as_array)
        .map(|kinds| kinds.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

/// Most values any one tag key carries across `filters`.
fn max_tag_values(filters: &[Value]) -> usize {
    filters
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|object| {
            object
                .iter()
                .filter(|(key, _)| key.starts_with('#'))
                .filter_map(|(_, values)| values.as_array().map(Vec::len))
        })
        .max()
        .unwrap_or(0)
}

/// The first limit a set of filters breaks, recording what it saw.
fn filter_violation(
    filters: &[Value],
    config: &LimitConfig,
    max_kinds_seen: &mut usize,
    max_tag_keys_seen: &mut usize,
    disallowed_seen: &mut BTreeSet<u64>,
) -> Option<&'static str> {
    let mut violation = None;
    if filters.is_empty() || filters.iter().any(|f| !f.is_object()) {
        violation = Some(reason::MALFORMED);
    }
    if filters.len() > config.max_filters {
        violation.get_or_insert(reason::TOO_MANY_FILTERS);
    }
    for filter in filters {
        let tag_keys = filter
            .as_object()
            .map(|object| object.keys().filter(|key| key.starts_with('#')).count())
            .unwrap_or(0);
        *max_tag_keys_seen = (*max_tag_keys_seen).max(tag_keys);
        if tag_keys > config.max_tag_keys_per_filter {
            violation.get_or_insert(reason::TOO_MANY_TAGS);
        }
        let kinds = filter_kinds(filter);
        *max_kinds_seen = (*max_kinds_seen).max(kinds.len());
        if kinds.len() > config.max_kinds_per_filter {
            violation.get_or_insert(reason::TOO_MANY_KINDS);
        }
        if let Some(allowed) = &config.allowed_kinds {
            for kind in kinds {
                if !allowed.contains(&kind) {
                    disallowed_seen.insert(kind);
                    violation.get_or_insert(reason::KIND_NOT_ALLOWED);
                }
            }
        }
    }
    violation
}

fn inspect_client_frame(
    shared: &Mutex<Shared>,
    config: &LimitConfig,
    connection: usize,
    text: &str,
) -> Verdict {
    let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(text) else {
        return Verdict::Forward;
    };
    let Some(verb) = frame.first().and_then(Value::as_str) else {
        return Verdict::Forward;
    };
    let id = frame
        .get(1)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut shared = shared.lock().unwrap();
    let shared = &mut *shared;
    match verb {
        "REQ" => {
            let filters = frame.get(2..).unwrap_or_default();
            shared.stats.total_reqs += 1;
            shared.stats.connections[connection].reqs += 1;
            shared.stats.max_filters_seen = shared.stats.max_filters_seen.max(filters.len());
            let already_active = shared.states[connection].active.contains(&id);
            if already_active {
                shared.stats.reqs_with_active_id += 1;
            }
            let mut violation = filter_violation(
                filters,
                config,
                &mut shared.stats.max_kinds_seen,
                &mut shared.stats.max_tag_keys_seen,
                &mut shared.stats.disallowed_kinds_seen,
            );
            shared.stats.max_tag_values_seen = shared
                .stats
                .max_tag_values_seen
                .max(max_tag_values(filters));
            if violation.is_none()
                && !already_active
                && shared.counted(connection, config) >= config.max_subscriptions
            {
                violation = Some(reason::TOO_MANY_SUBSCRIPTIONS);
            }
            let outcome = match violation {
                None if already_active => ReqOutcome::Replaced,
                None => ReqOutcome::Accepted,
                Some(reason) => ReqOutcome::Rejected(reason),
            };
            shared.stats.req_log.push(ReqRecord {
                at: Instant::now(),
                connection,
                subscription_id: id.clone(),
                filters: filters.len(),
                outcome: outcome.clone(),
            });
            match violation {
                None => {
                    shared.stats.accepted_reqs += 1;
                    shared.states[connection].active.insert(id);
                    shared.refresh(connection);
                    let mut frame = frame;
                    let mut clamped = false;
                    for filter in frame.iter_mut().skip(2) {
                        let limit = filter.get("limit").and_then(Value::as_u64);
                        shared.stats.max_req_limit_seen =
                            shared.stats.max_req_limit_seen.max(limit.unwrap_or(0));
                        if let Some(clamp) = config.req_limit_clamp
                            && limit.is_none_or(|limit| limit > clamp)
                        {
                            filter["limit"] = Value::from(clamp);
                            shared.stats.clamped_filters += 1;
                            clamped = true;
                        }
                    }
                    if clamped {
                        Verdict::ForwardRewritten(Value::Array(frame).to_string())
                    } else {
                        Verdict::Forward
                    }
                }
                Some(reason) => {
                    *shared.stats.rejections.entry(reason).or_default() += 1;
                    shared.stats.connections[connection].rejected += 1;
                    // A refused replacement ends the subscription it replaced.
                    let upstream = shared.states[connection]
                        .active
                        .remove(&id)
                        .then(|| serde_json::json!(["CLOSE", id]).to_string());
                    shared.refresh(connection);
                    let reply = match config.reject_style {
                        RejectStyle::Closed => serde_json::json!(["CLOSED", id, reason]),
                        RejectStyle::Notice => serde_json::json!(["NOTICE", reason]),
                    };
                    Verdict::Refuse {
                        reply: reply.to_string(),
                        upstream,
                    }
                }
            }
        }
        "CLOSE" => {
            shared.stats.closes += 1;
            shared.stats.connections[connection].closes += 1;
            if !shared.states[connection].active.remove(&id) {
                shared.stats.closes_unknown += 1;
            }
            shared.refresh(connection);
            Verdict::Forward
        }
        "NEG-OPEN" => {
            shared.stats.neg_opens += 1;
            shared.stats.connections[connection].neg_opens += 1;
            let filters = frame.get(2..3).unwrap_or_default();
            let neg_limit = filters
                .first()
                .and_then(|f| f.get("limit"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            shared.stats.neg_max_limit_seen = shared.stats.neg_max_limit_seen.max(neg_limit);
            // A same-id NEG-OPEN replaces (frees) the earlier session.
            let replaced = shared.states[connection].neg.remove(&id);
            let mut violation = filter_violation(
                filters,
                config,
                &mut shared.stats.neg_max_kinds_seen,
                &mut shared.stats.max_tag_keys_seen,
                &mut shared.stats.neg_disallowed_kinds_seen,
            );
            if violation.is_none() && neg_limit > NEG_MAX_LIMIT {
                violation = Some(reason::MALFORMED);
            }
            let over_cap = shared.neg_counted(connection, config) >= config.max_neg_sessions
                || (config.neg_counts_toward_limit
                    && shared.counted(connection, config) >= config.max_subscriptions);
            if violation.is_none() && over_cap {
                violation = Some(reason::TOO_MANY_NEG);
            }
            let fault = shared.neg_fault.unwrap_or(NegFault::None);
            match violation {
                // Parse errors and the cap answer with a NOTICE, no session id.
                Some(reason) => {
                    *shared.stats.neg_rejections.entry(reason).or_default() += 1;
                    if reason == reason::TOO_MANY_NEG {
                        shared.stats.neg_cap_notices += 1;
                    }
                    shared.refresh(connection);
                    let notice = if reason == reason::TOO_MANY_NEG {
                        reason.to_owned()
                    } else {
                        format!("ERROR: bad msg: {reason}")
                    };
                    Verdict::Refuse {
                        reply: serde_json::json!(["NOTICE", notice]).to_string(),
                        upstream: replaced
                            .then(|| serde_json::json!(["NEG-CLOSE", id]).to_string()),
                    }
                }
                None if fault == NegFault::ErrOnOpen => {
                    *shared
                        .stats
                        .neg_rejections
                        .entry("injected NEG-ERR")
                        .or_default() += 1;
                    shared.refresh(connection);
                    Verdict::Refuse {
                        reply: serde_json::json!(["NEG-ERR", id, "blocked: injected refusal"])
                            .to_string(),
                        upstream: replaced
                            .then(|| serde_json::json!(["NEG-CLOSE", id]).to_string()),
                    }
                }
                None => {
                    shared.states[connection].neg.insert(id.clone());
                    shared.refresh(connection);
                    match fault {
                        NegFault::SilentOpen => Verdict::Swallow,
                        NegFault::FingerprintThenStall => Verdict::Refuse {
                            reply: serde_json::json!(["NEG-MSG", id, STALLING_NEG_MSG]).to_string(),
                            upstream: None,
                        },
                        _ => Verdict::Forward,
                    }
                }
            }
        }
        "NEG-MSG"
            if shared.neg_fault == Some(NegFault::FingerprintThenStall)
                && shared.states[connection].neg.contains(&id) =>
        {
            shared.stats.neg_msgs_dropped += 1;
            Verdict::Swallow
        }
        "NEG-CLOSE" => {
            shared.stats.neg_closes += 1;
            if !shared.states[connection].neg.remove(&id) {
                shared.stats.neg_closes_unknown += 1;
            }
            shared.refresh(connection);
            Verdict::Forward
        }
        _ => Verdict::Forward,
    }
}

/// Account for one upstream frame; `false` drops it.
fn inspect_relay_frame(shared: &Mutex<Shared>, connection: usize, text: &str) -> bool {
    let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(text) else {
        return true;
    };
    let verb = frame.first().and_then(Value::as_str).unwrap_or_default();
    let Some(id) = frame.get(1).and_then(Value::as_str) else {
        return true;
    };
    let mut shared = shared.lock().unwrap();
    let fault = shared.neg_fault.unwrap_or(NegFault::None);
    match verb {
        // EOSE does not end a live subscription; only CLOSED does.
        "CLOSED" => {
            if shared.states[connection].active.remove(id) {
                shared.stats.upstream_closed += 1;
            }
            shared.refresh(connection);
        }
        // Assumption: a relay-sent NEG-ERR ends that session on the relay.
        "NEG-ERR" => {
            shared.stats.upstream_neg_errs += 1;
            shared.states[connection].neg.remove(id);
            shared.refresh(connection);
        }
        // Completion does not free the session; only NEG-CLOSE does.
        "NEG-MSG" if fault == NegFault::FingerprintThenStall => {
            shared.stats.neg_msgs_dropped += 1;
            return false;
        }
        _ => {}
    }
    true
}
