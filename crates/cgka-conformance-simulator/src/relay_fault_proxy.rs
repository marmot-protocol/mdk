//! Real socket interruption in front of the harness-owned loopback relay.
//! All advertised relay URLs use this gate, so reconnect/discovery cannot bypass it.
//! Each proxy also taps the forwarded WebSocket frames into aggregate traffic counts.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

// Larger frames stop the tap; loopback relay messages stay far below this.
const MAX_TAPPED_FRAME: u64 = 8 * 1024 * 1024;

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
}

/// One client connection's counters.
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayTrafficSessionV1 {
    upstream_bytes: u64,
    downstream_bytes: u64,
    upstream_messages: BTreeMap<String, u64>,
    downstream_messages: BTreeMap<String, u64>,
    events: BTreeMap<String, RelayEventDeliveryV1>,
    undecoded_frames: u64,
    first_eof: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEventDeliveryV1 {
    pub kind: u16,
    pub count: u64,
    pub bytes: u64,
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

fn record_message(session: &mut RelayTrafficSessionV1, message: &[u8], upstream: bool) {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_slice(message) else {
        session.undecoded_frames += 1;
        return;
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
    if !upstream
        && verb == "EVENT"
        && let Some(event) = items.get(2)
        && let Some(id) = event["id"].as_str()
    {
        let delivery = session.events.entry(id.to_owned()).or_default();
        delivery.kind = u16::try_from(event["kind"].as_u64().unwrap_or_default()).unwrap_or(0);
        delivery.count += 1;
        delivery.bytes += message.len() as u64;
    }
}

/// Forward one direction, recording its bytes and completed messages.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    traffic: &Traffic,
    index: usize,
    upstream: bool,
) -> io::Result<()> {
    let mut tap = FrameTap::default();
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
        to.write_all(&buffer[..read]).await?;
        let (messages, undecoded) = tap.feed(&buffer[..read]);
        let mut sessions = traffic.lock().expect("relay traffic lock poisoned");
        let session = &mut sessions[index];
        if upstream {
            session.upstream_bytes += read as u64;
        } else {
            session.downstream_bytes += read as u64;
        }
        session.undecoded_frames += undecoded;
        for message in &messages {
            record_message(session, message, upstream);
        }
    }
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
                        sessions.spawn(async move {
                            // The exact harness-owned address is pinned above; no DNS or external dial.
                            let Ok(Ok(mut upstream)) = tokio::time::timeout(
                                Duration::from_secs(5), TcpStream::connect(upstream),
                            ).await else { return };
                            active.fetch_add(1, Ordering::SeqCst);
                            let _active = ActiveConnection(active);
                            let index = {
                                let mut sessions = traffic.lock().expect("relay traffic lock poisoned");
                                sessions.push(RelayTrafficSessionV1::default());
                                sessions.len() - 1
                            };
                            let (client_read, client_write) = downstream.split();
                            let (relay_read, relay_write) = upstream.split();
                            let _ = tokio::try_join!(
                                pump(client_read, relay_write, &traffic, index, true),
                                pump(relay_read, client_write, &traffic, index, false),
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
        })
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
            ..RelayTrafficV1::default()
        };
        let add = |into: &mut BTreeMap<String, u64>, from: &BTreeMap<String, u64>| {
            for (verb, count) in from {
                *into.entry(verb.clone()).or_default() += count;
            }
        };
        for session in sessions.iter().skip(first) {
            total.connections += 1;
            total.upstream_bytes += session.upstream_bytes;
            total.downstream_bytes += session.downstream_bytes;
            total.undecoded_frames += session.undecoded_frames;
            add(&mut total.upstream_messages, &session.upstream_messages);
            add(&mut total.downstream_messages, &session.downstream_messages);
            if let Some(side) = session.first_eof {
                *total.closed_first_by.entry(side.to_owned()).or_default() += 1;
            }
            for (id, delivery) in session.events.iter().filter(|_| events) {
                let merged = total.events.entry(id.clone()).or_default();
                merged.kind = delivery.kind;
                merged.count += delivery.count;
                merged.bytes += delivery.bytes;
            }
        }
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
        let event = br#"["EVENT","sub",{"id":"ab","kind":445,"content":"x"}]"#;
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
                record_message(&mut session, &message, false);
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
}
