//! Relays that fail the way production relays do, over real sockets.
//!
//! Each [`FaultRelay`] is a `nostr_relay_builder::LocalRelay` (storage, filter
//! matching, NIP-42) behind a WebSocket proxy that applies [`Faults`]: an HTTP
//! status instead of the upgrade, a stalled handshake, a socket dropped on the
//! first REQ, a CLOSED for listed kinds with the exact wire reason, an OK
//! false or no OK at all for writes, a refused AUTH, held EOSEs, and NIP-67
//! EOSE hints. The proxy writes reasons verbatim. `LocalRelay`'s own policies prefix theirs
//! with `error:` or `blocked:`. Faults can change while a test runs, so a relay
//! can fail one check and answer the next.
//!
//! [`FaultRelay::seed`] stores events directly in the relay behind the proxy,
//! so every relay can hold its own records whatever faults it applies.

use futures::{SinkExt, StreamExt};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{WebSocketStream, connect_async};

/// What a relay does with a WebSocket upgrade request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Upgrade {
    #[default]
    Accept,
    /// Answer with this HTTP status (503 for an overloaded relay) and close.
    Status(u16),
    /// Fail the next WebSocket upgrade, then accept subsequent upgrades.
    StatusOnce(u16),
    /// Accept the TCP connection and never answer.
    Stall,
}

/// What a relay answers to a client's EVENT.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Write {
    #[default]
    Accept,
    /// `["OK", id, false, reason]`, with `reason` sent verbatim.
    Reject(String),
    /// Store the event but never send its OK.
    NeverOk,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Faults {
    pub upgrade: Upgrade,
    /// A REQ with a filter naming any of these kinds is answered with
    /// `["CLOSED", sub, closed_reason]` and never reaches the relay.
    pub closed_kinds: Vec<u64>,
    pub closed_reason: String,
    /// Close the TCP connection when a REQ arrives, without CLOSED or EOSE.
    pub drop_on_req: bool,
    /// Never forward the relay's EOSE.
    pub hold_eose: bool,
    /// Append a NIP-67 hint (`more`, `auth`) to every EOSE.
    pub eose_hint: Option<String>,
    pub write: Write,
    /// Answer every client AUTH with `["OK", id, false, reason]` instead of
    /// passing it to the relay, which then stays unauthenticated.
    pub reject_auth: Option<String>,
}

impl Faults {
    /// White Noise's strfry relays refuse group-message and KeyPackage-relay
    /// reads with this exact reason.
    pub(crate) fn white_noise_strfry() -> Self {
        Self::closing(
            &[443, 10051],
            "bad req: filter validation failed: kind not allowed: 10051",
        )
    }

    pub(crate) fn closing(kinds: &[u64], reason: &str) -> Self {
        Self {
            closed_kinds: kinds.to_vec(),
            closed_reason: reason.to_owned(),
            ..Self::default()
        }
    }

    pub(crate) fn rejecting_writes(reason: &str) -> Self {
        Self {
            write: Write::Reject(reason.to_owned()),
            ..Self::default()
        }
    }
}

/// What reached the relay through its proxy.
#[derive(Clone, Debug, Default)]
pub(crate) struct Traffic {
    /// TCP connections the proxy accepted.
    pub connections: usize,
    /// WebSocket upgrades rejected with an HTTP error.
    pub rejected_upgrades: usize,
    /// The kinds each REQ asked for, in arrival order.
    pub reqs: Vec<Vec<u64>>,
    /// The kind of each EVENT a client sent, whatever the reply.
    pub writes: Vec<u64>,
    /// The kind of each EVENT the upstream acknowledged to the client.
    pub accepted_writes: Vec<u64>,
    /// AUTH challenges the relay sent and AUTH events clients answered with.
    pub challenges: usize,
    pub auths: usize,
}

pub(crate) struct FaultRelay {
    pub url: String,
    upstream: Option<String>,
    faults: Arc<Mutex<Faults>>,
    traffic: Arc<Mutex<Traffic>>,
    _relay: Option<LocalRelay>,
    _refusing_socket: Option<TcpSocket>,
    proxy: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for FaultRelay {
    fn drop(&mut self) {
        if let Some(proxy) = &self.proxy {
            proxy.abort();
        }
    }
}

impl FaultRelay {
    /// A relay built from `builder` (NIP-42 or `auth_dm`, say) behind the
    /// fault proxy.
    pub(crate) async fn spawn(builder: RelayBuilder, faults: Faults) -> Self {
        let relay = LocalRelay::new(builder.max_filter_limit(500));
        relay.run().await.unwrap();
        let upstream = relay.url().await.to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let faults = Arc::new(Mutex::new(faults));
        let traffic = Arc::new(Mutex::new(Traffic::default()));
        let proxy = tokio::spawn(serve(
            listener,
            upstream.clone(),
            faults.clone(),
            traffic.clone(),
        ));
        Self {
            url,
            upstream: Some(upstream),
            faults,
            traffic,
            _relay: Some(relay),
            _refusing_socket: None,
            proxy: Some(proxy),
        }
    }

    pub(crate) async fn with_faults(faults: Faults) -> Self {
        Self::spawn(RelayBuilder::default(), faults).await
    }

    /// Reserve a port without listening, so every dial is refused and no
    /// concurrent test can claim it.
    pub(crate) fn refusing() -> Self {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("ws://{}", socket.local_addr().unwrap());
        Self {
            url,
            upstream: None,
            faults: Arc::default(),
            traffic: Arc::default(),
            _relay: None,
            _refusing_socket: Some(socket),
            proxy: None,
        }
    }

    pub(crate) fn set_faults(&self, faults: Faults) {
        *self.faults.lock().unwrap() = faults;
    }

    pub(crate) fn traffic(&self) -> Traffic {
        self.traffic.lock().unwrap().clone()
    }

    /// Store a signed event (JSON) behind the proxy, bypassing every fault.
    pub(crate) async fn seed(&self, event: &str) {
        let upstream = self
            .upstream
            .as_ref()
            .expect("a refusing relay stores nothing");
        let (mut ws, _) = connect_async(upstream.as_str()).await.unwrap();
        let event: Value = serde_json::from_str(event).unwrap();
        let id = event["id"].clone();
        ws.send(Message::text(json!(["EVENT", event]).to_string()))
            .await
            .unwrap();
        let reply = timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = ws.next().await {
                if let Ok(text) = message.to_text()
                    && let Ok(Value::Array(reply)) = serde_json::from_str::<Value>(text)
                    && reply.first() == Some(&json!("OK"))
                    && reply.get(1) == Some(&id)
                {
                    return reply;
                }
            }
            panic!("seed relay closed before OK");
        })
        .await
        .unwrap();
        assert_eq!(reply.get(2), Some(&json!(true)), "seed rejected: {reply:?}");
        let _ = ws.close(None).await;
    }
}

async fn serve(
    listener: TcpListener,
    upstream: String,
    faults: Arc<Mutex<Faults>>,
    traffic: Arc<Mutex<Traffic>>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((client, _)) = accepted else { continue };
                traffic.lock().unwrap().connections += 1;
                connections.spawn(connection(client, upstream.clone(), faults.clone(), traffic.clone()));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn connection(
    mut client: TcpStream,
    upstream: String,
    faults: Arc<Mutex<Faults>>,
    traffic: Arc<Mutex<Traffic>>,
) {
    if faults.lock().unwrap().upgrade == Upgrade::Stall {
        let _held = client;
        std::future::pending::<()>().await;
        return;
    }
    let mut header = Vec::new();
    let read_header = async {
        while !header.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut bytes = [0; 1024];
            let n = client.read(&mut bytes).await.ok()?;
            if n == 0 || header.len() + n > 8192 {
                return None;
            }
            header.extend_from_slice(&bytes[..n]);
        }
        Some(())
    };
    if timeout(Duration::from_secs(5), read_header).await != Ok(Some(())) {
        return;
    }
    let header = String::from_utf8_lossy(&header).into_owned();
    let field = |name: &str| {
        header.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(field, _)| field.trim().eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().to_owned())
        })
    };
    let Some(key) = field("sec-websocket-key") else {
        // A NIP-11 read: the page advertises the cap the relay enforces.
        let body = r#"{"supported_nips":[1,11,42],"limitation":{"max_limit":500}}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = client.write_all(reply.as_bytes()).await;
        return;
    };
    let rejected_status = {
        let mut faults = faults.lock().unwrap();
        match faults.upgrade {
            Upgrade::Status(status) => Some(status),
            Upgrade::StatusOnce(status) => {
                faults.upgrade = Upgrade::Accept;
                Some(status)
            }
            _ => None,
        }
    };
    if let Some(status) = rejected_status {
        traffic.lock().unwrap().rejected_upgrades += 1;
        let reply = format!(
            "HTTP/1.1 {status} Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = client.write_all(reply.as_bytes()).await;
        return;
    }
    let accept = derive_accept_key(key.as_bytes());
    let reply = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if client.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    let mut client = WebSocketStream::from_raw_socket(client, Role::Server, None).await;
    let Ok((mut relay, _)) = connect_async(upstream.as_str()).await else {
        return;
    };
    let mut pending_writes = HashMap::new();
    loop {
        tokio::select! {
            message = client.next() => {
                let Some(Ok(message)) = message else { return };
                let Message::Text(text) = message else {
                    if message.is_close() { return }
                    continue;
                };
                let frame: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                let faults = faults.lock().unwrap().clone();
                match frame.get(0).and_then(Value::as_str) {
                    Some("REQ") => {
                        let kinds: Vec<u64> = frame.as_array().into_iter().flatten().skip(2)
                            .flat_map(|filter| filter["kinds"].as_array().cloned().unwrap_or_default())
                            .filter_map(|kind| kind.as_u64())
                            .collect();
                        traffic.lock().unwrap().reqs.push(kinds.clone());
                        if faults.drop_on_req {
                            return;
                        }
                        if kinds.iter().any(|kind| faults.closed_kinds.contains(kind)) {
                            let closed = json!(["CLOSED", frame[1], faults.closed_reason]);
                            if client.send(Message::text(closed.to_string())).await.is_err() { return }
                            continue;
                        }
                    }
                    Some("EVENT") => {
                        let kind = frame[1]["kind"].as_u64().expect("client EVENT kind");
                        traffic.lock().unwrap().writes.push(kind);
                        match faults.write {
                            Write::Accept => {
                                pending_writes.insert(frame[1]["id"].clone(), Some(kind));
                            }
                            Write::Reject(reason) => {
                                let ok = json!(["OK", frame[1]["id"], false, reason]);
                                if client.send(Message::text(ok.to_string())).await.is_err() { return }
                                continue;
                            }
                            Write::NeverOk => {
                                pending_writes.insert(frame[1]["id"].clone(), None);
                            }
                        }
                    }
                    Some("AUTH") => {
                        traffic.lock().unwrap().auths += 1;
                        if let Some(reason) = faults.reject_auth {
                            let ok = json!(["OK", frame[1]["id"], false, reason]);
                            if client.send(Message::text(ok.to_string())).await.is_err() { return }
                            continue;
                        }
                    }
                    _ => {}
                }
                if relay.send(Message::Text(text)).await.is_err() { return }
            }
            message = relay.next() => {
                let Some(Ok(message)) = message else { return };
                let Message::Text(text) = message else {
                    if message.is_close() { return }
                    continue;
                };
                let frame: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
                let faults = faults.lock().unwrap().clone();
                let forward = match frame.get(0).and_then(Value::as_str) {
                    Some("EOSE") if faults.hold_eose => None,
                    Some("EOSE") => match faults.eose_hint {
                        Some(hint) => Some(json!(["EOSE", frame[1], [hint]]).to_string()),
                        None => Some(text.to_string()),
                    },
                    Some("OK") => match pending_writes.remove(&frame[1]) {
                        Some(None) => None,
                        Some(Some(kind)) => {
                            if frame[2] == true {
                                traffic.lock().unwrap().accepted_writes.push(kind);
                            }
                            Some(text.to_string())
                        }
                        None => Some(text.to_string()),
                    },
                    Some("AUTH") => {
                        traffic.lock().unwrap().challenges += 1;
                        Some(text.to_string())
                    }
                    _ => Some(text.to_string()),
                };
                if let Some(forward) = forward
                    && client.send(Message::text(forward)).await.is_err()
                {
                    return;
                }
            }
        }
    }
}
