use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN,
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamRecordError, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, Semaphore, mpsc};
use tokio::time::{sleep, timeout};
use transport_quic_stream::{
    AgentTextStreamCrypto, AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimitError,
    AgentTextStreamReceiveLimits, ReceivedTextChunk, ReceivedTextStream, SentTextStream,
    decrypt_record, encrypt_record,
};

pub const QUIC_BROKER_PROTOCOL_V1: &str = "marmot.quic_broker.v1";
pub const DEFAULT_SUBSCRIBER_QUEUE_DEPTH: usize = 32;
pub const DEFAULT_BROKER_BACKLOG_DEPTH: usize = 1024;
pub const DEFAULT_BROKER_MAX_ROOMS: usize = 512;
pub const DEFAULT_BROKER_MAX_BACKLOG_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_BROKER_MAX_CONNECTIONS: usize = 256;
pub const DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION: usize = 64;
pub const DEFAULT_BROKER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_BROKER_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_BROKER_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

const FRAME_LEN_BYTES: usize = 4;
#[cfg(test)]
const LOCAL_SERVER_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const MAX_FRAME_SIZE: usize = AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + 1024;
const PUBLISH_SUBSCRIBER_GRACE: Duration = Duration::from_secs(5);
const FINISHED_ROOM_TTL: Duration = Duration::from_secs(60);
// Stale unfinished rooms are a defense-in-depth cleanup path for task
// cancellation, so keep the same retention window as finished backlog rooms.
const UNFINISHED_ROOM_TTL: Duration = FINISHED_ROOM_TTL;
const SEND_STOP_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct QuicBrokerConfig {
    pub bind_addr: SocketAddr,
    pub per_subscriber_queue: usize,
    pub max_backlog: usize,
    pub max_rooms: usize,
    pub max_backlog_bytes: usize,
    pub max_connections: usize,
    pub max_streams_per_connection: usize,
    pub read_timeout: Duration,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub tls: QuicBrokerTlsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuicBrokerTlsConfig {
    GenerateSelfSigned {
        subject_alt_names: Vec<String>,
    },
    PemFiles {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl Default for QuicBrokerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4450),
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            max_rooms: DEFAULT_BROKER_MAX_ROOMS,
            max_backlog_bytes: DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            max_connections: DEFAULT_BROKER_MAX_CONNECTIONS,
            max_streams_per_connection: DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION,
            read_timeout: DEFAULT_BROKER_READ_TIMEOUT,
            max_idle_timeout: DEFAULT_BROKER_MAX_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
            tls: QuicBrokerTlsConfig::GenerateSelfSigned {
                subject_alt_names: vec!["localhost".to_owned()],
            },
        }
    }
}

pub struct QuicBrokerServer {
    endpoint: Endpoint,
    server_cert_der: Vec<u8>,
    state: Arc<BrokerState>,
    connection_limiter: Arc<Semaphore>,
    max_streams_per_connection: usize,
    read_timeout: Duration,
}

impl QuicBrokerServer {
    pub fn bind(config: QuicBrokerConfig) -> Result<Self, QuicBrokerError> {
        if config.per_subscriber_queue == 0 {
            return Err(QuicBrokerError::EmptySubscriberQueue);
        }
        if config.max_backlog == 0 {
            return Err(QuicBrokerError::EmptyBacklog);
        }
        if config.max_rooms == 0 {
            return Err(QuicBrokerError::EmptyRoomLimit);
        }
        if config.max_backlog_bytes == 0 {
            return Err(QuicBrokerError::EmptyBacklogByteLimit);
        }
        if config.max_connections == 0 {
            return Err(QuicBrokerError::EmptyConnectionLimit);
        }
        if config.max_streams_per_connection == 0 {
            return Err(QuicBrokerError::EmptyStreamLimit);
        }
        if config.read_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyReadTimeout);
        }
        if config.max_idle_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyIdleTimeout);
        }
        if config.keep_alive_interval.is_zero() {
            return Err(QuicBrokerError::EmptyKeepAliveInterval);
        }
        let (mut server_config, server_cert_der) = configure_server(&config.tls)?;
        server_config.transport_config(Arc::new(broker_transport_config(&config)?));
        let endpoint = Endpoint::server(server_config, config.bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
            state: Arc::new(BrokerState::new(
                config.per_subscriber_queue,
                config.max_backlog,
                config.max_rooms,
                config.max_backlog_bytes,
            )),
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            max_streams_per_connection: config.max_streams_per_connection,
            read_timeout: config.read_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicBrokerError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn server_cert_der(&self) -> &[u8] {
        &self.server_cert_der
    }

    pub fn server_cert_sha256_fingerprint(&self) -> String {
        certificate_sha256_fingerprint_hex(&self.server_cert_der)
    }

    pub async fn run_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), QuicBrokerError> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    self.endpoint.close(0_u32.into(), b"shutdown");
                    self.endpoint.wait_idle().await;
                    return Ok(());
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };
                    let Ok(permit) = Arc::clone(&self.connection_limiter).try_acquire_owned() else {
                        incoming.refuse();
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let max_streams_per_connection = self.max_streams_per_connection;
                    let read_timeout = self.read_timeout;
                    tokio::spawn(async move {
                        let _permit = permit;
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        let _ = handle_connection(
                            state,
                            connection,
                            max_streams_per_connection,
                            read_timeout,
                        ).await;
                    });
                }
            }
        }
    }
}

fn certificate_sha256_fingerprint_hex(certificate_der: &[u8]) -> String {
    hex::encode(Sha256::digest(certificate_der))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BrokerStreamKey {
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
}

impl BrokerStreamKey {
    pub fn new(stream_id: impl Into<Vec<u8>>, start_event_id: MessageId) -> Self {
        Self {
            stream_id: stream_id.into(),
            start_event_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuicBrokerControlEnvelopeV1 {
    pub marmot_broker: String,
    #[serde(flatten)]
    pub control: QuicBrokerControlV1,
}

impl QuicBrokerControlEnvelopeV1 {
    pub fn publish(stream_id: impl AsRef<[u8]>, start_event_id: &MessageId) -> Self {
        Self {
            marmot_broker: QUIC_BROKER_PROTOCOL_V1.to_owned(),
            control: QuicBrokerControlV1::Publish {
                stream_id: hex::encode(stream_id.as_ref()),
                start_event_id: hex::encode(start_event_id.as_slice()),
            },
        }
    }

    pub fn subscribe(stream_id: impl AsRef<[u8]>, start_event_id: &MessageId) -> Self {
        Self {
            marmot_broker: QUIC_BROKER_PROTOCOL_V1.to_owned(),
            control: QuicBrokerControlV1::Subscribe {
                stream_id: hex::encode(stream_id.as_ref()),
                start_event_id: hex::encode(start_event_id.as_slice()),
            },
        }
    }

    pub fn key(&self) -> Result<BrokerStreamKey, QuicBrokerError> {
        if self.marmot_broker != QUIC_BROKER_PROTOCOL_V1 {
            return Err(QuicBrokerError::WrongControlProtocol(
                self.marmot_broker.clone(),
            ));
        }
        let (stream_id, start_event_id) = match &self.control {
            QuicBrokerControlV1::Publish {
                stream_id,
                start_event_id,
            }
            | QuicBrokerControlV1::Subscribe {
                stream_id,
                start_event_id,
            } => (stream_id, start_event_id),
        };
        let stream_id = decode_stream_id(stream_id)?;
        let start_event_id = decode_start_event_id(start_event_id)?;
        Ok(BrokerStreamKey::new(
            stream_id,
            MessageId::new(start_event_id),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum QuicBrokerControlV1 {
    Publish {
        stream_id: String,
        start_event_id: String,
    },
    Subscribe {
        stream_id: String,
        start_event_id: String,
    },
}

#[derive(Clone, Debug)]
pub enum BrokerServerTrust {
    Platform,
    CertificateDer(Vec<u8>),
    InsecureLocal,
}

#[derive(Clone, Debug)]
pub struct PublishTextToBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub text: String,
    pub max_chunk_bytes: usize,
    pub chunk_delay: Duration,
    pub crypto: Option<AgentTextStreamCrypto>,
}

#[derive(Clone, Debug)]
pub struct OpenBrokerTextPublisher {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
}

#[derive(Clone, Debug)]
pub struct SubscribeTextFromBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
}

pub struct BrokerTextPublisher {
    endpoint: Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
    crypto: Option<AgentTextStreamCrypto>,
}

impl BrokerTextPublisher {
    pub async fn connect(config: OpenBrokerTextPublisher) -> Result<Self, QuicBrokerError> {
        let endpoint = client_endpoint(config.trust, config.broker_addr)?;
        let connection = endpoint
            .connect(config.broker_addr, &config.server_name)?
            .await?;
        let mut send = connection.open_uni().await?;
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::publish(&config.stream_id, &config.start_event_id),
        )
        .await?;

        Ok(Self {
            endpoint,
            connection,
            send,
            transcript: AgentTextStreamTranscriptV1::new(config.stream_id, config.start_event_id),
            next_seq: 1,
            crypto: config.crypto,
        })
    }

    pub async fn append_text(
        &mut self,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        self.append_record_text(
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            text,
            max_chunk_bytes,
            chunk_delay,
        )
        .await
    }

    pub async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        if max_chunk_bytes == 0 {
            return Err(QuicBrokerError::EmptyChunkSize);
        }
        if max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
            return Err(QuicBrokerError::ChunkSizeTooLarge(max_chunk_bytes));
        }

        let mut appended = 0_u64;
        for chunk in transport_quic_stream::split_text_deltas(text, max_chunk_bytes) {
            let record = AgentTextStreamRecordV1::new(
                self.transcript.stream_id().to_vec(),
                self.next_seq,
                record_type,
                chunk,
            );
            record.validate()?;
            self.next_seq += 1;
            let wire_record = if let Some(crypto) = &self.crypto {
                encrypt_record(crypto, &record)?
            } else {
                record.clone()
            };
            write_record_frame(&mut self.send, &wire_record).await?;
            self.transcript
                .append(record.seq, record.record_type, &record.plaintext_frame);
            appended += 1;
            if !chunk_delay.is_zero() {
                sleep(chunk_delay).await;
            }
        }
        Ok(appended)
    }

    pub async fn finish(mut self) -> Result<SentTextStream, QuicBrokerError> {
        self.send.finish()?;
        let stopped = timeout(SEND_STOP_WAIT, self.send.stopped()).await;
        self.connection.close(0_u32.into(), b"done");
        self.endpoint.wait_idle().await;
        match stopped {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {}
        }
        Ok(SentTextStream {
            stream_id: self.transcript.stream_id().to_vec(),
            transcript_hash: self.transcript.hash(),
            chunk_count: self.transcript.chunk_count(),
        })
    }
}

pub async fn publish_text_to_broker(
    config: PublishTextToBroker,
) -> Result<SentTextStream, QuicBrokerError> {
    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr: config.broker_addr,
        server_name: config.server_name,
        trust: config.trust,
        stream_id: config.stream_id,
        start_event_id: config.start_event_id,
        crypto: config.crypto,
    })
    .await?;
    publisher
        .append_text(&config.text, config.max_chunk_bytes, config.chunk_delay)
        .await?;
    publisher.finish().await
}

pub async fn subscribe_text_from_broker(
    config: SubscribeTextFromBroker,
) -> Result<ReceivedTextStream, QuicBrokerError> {
    subscribe_text_from_broker_with_updates(config, |_| {}).await
}

pub async fn subscribe_text_from_broker_with_updates<F>(
    config: SubscribeTextFromBroker,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    subscribe_text_from_broker_with_limits(
        config,
        AgentTextStreamReceiveLimits::default(),
        &mut on_chunk,
    )
    .await
}

pub async fn subscribe_text_from_broker_with_limits<F>(
    config: SubscribeTextFromBroker,
    limits: AgentTextStreamReceiveLimits,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    let endpoint = client_endpoint(config.trust, config.broker_addr)?;
    let connection = endpoint
        .connect(config.broker_addr, &config.server_name)?
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::subscribe(&config.stream_id, &config.start_event_id),
    )
    .await?;
    send.finish()?;

    let mut expected_seq = 1_u64;
    let mut chunks = Vec::new();
    let mut text = String::new();
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id);
    let mut limit_state = AgentTextStreamReceiveAccumulator::new(limits);

    while let Some(record) = read_record_frame(&mut recv, None).await? {
        let record = if let Some(crypto) = &config.crypto {
            decrypt_record(crypto, &record)?
        } else {
            record
        };
        limit_state.observe(&record)?;
        if record.stream_id != config.stream_id {
            return Err(QuicBrokerError::MixedStreamIds);
        }
        if record.seq != expected_seq {
            return Err(QuicBrokerError::UnexpectedSequence {
                expected: expected_seq,
                actual: record.seq,
            });
        }
        expected_seq += 1;

        let frame_text = stream_record_text(&record)?;
        if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
            text.push_str(&frame_text);
        }
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        let chunk = ReceivedTextChunk {
            seq: record.seq,
            record_type: record.record_type,
            flags: record.flags,
            text: frame_text,
        };
        on_chunk(&chunk);
        chunks.push(chunk);
    }

    connection.close(0_u32.into(), b"done");
    if chunks.is_empty() {
        return Err(QuicBrokerError::EmptyStream);
    }
    Ok(ReceivedTextStream {
        stream_id: transcript.stream_id().to_vec(),
        chunks,
        text,
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    })
}

/// Decode the per-record text a subscriber can surface for a single stream record.
///
/// `TextDelta`, `Status`, `ProgressDelta`, and `Checkpoint` carry UTF-8 the
/// consumer renders: deltas build the provisional preview, status/progress feed
/// non-chat agent chrome, and a `Checkpoint` is a full preview snapshot the
/// consumer swaps in for its live preview. `Abort` and `FinalNotice` are
/// advisory (the consumer acts on the record type, not its bytes), as is any
/// unknown future type, so they decode to an empty string. Note this only
/// decodes one record's frame; accumulation into the provisional answer text is
/// the caller's job and stays `TextDelta`-only.
fn stream_record_text(record: &AgentTextStreamRecordV1) -> Result<String, QuicBrokerError> {
    match record.record_type {
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        | AGENT_TEXT_STREAM_RECORD_STATUS
        | AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        | AGENT_TEXT_STREAM_RECORD_CHECKPOINT => {
            Ok(str::from_utf8(&record.plaintext_frame)?.to_owned())
        }
        _ => Ok(String::new()),
    }
}

#[derive(Debug)]
struct BrokerState {
    per_subscriber_queue: usize,
    max_backlog: usize,
    max_rooms: usize,
    max_backlog_bytes: usize,
    inner: Mutex<BrokerStateInner>,
}

#[derive(Debug, Default)]
struct BrokerStateInner {
    rooms: HashMap<BrokerStreamKey, BrokerRoom>,
    next_subscriber_id: u64,
    total_backlog_bytes: usize,
}

#[derive(Debug)]
struct BrokerRoom {
    subscribers: Vec<Subscriber>,
    backlog: VecDeque<BacklogRecord>,
    backlog_bytes: usize,
    subscriber_notify: Arc<Notify>,
    finished_at: Option<Instant>,
    last_activity_at: Instant,
}

impl Default for BrokerRoom {
    fn default() -> Self {
        Self {
            subscribers: Vec::new(),
            backlog: VecDeque::new(),
            backlog_bytes: 0,
            subscriber_notify: Arc::new(Notify::new()),
            finished_at: None,
            last_activity_at: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct BacklogRecord {
    record: AgentTextStreamRecordV1,
    bytes: usize,
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<AgentTextStreamRecordV1>,
}

impl BrokerState {
    fn new(
        per_subscriber_queue: usize,
        max_backlog: usize,
        max_rooms: usize,
        max_backlog_bytes: usize,
    ) -> Self {
        Self {
            per_subscriber_queue,
            max_backlog,
            max_rooms,
            max_backlog_bytes,
            inner: Mutex::new(BrokerStateInner::default()),
        }
    }

    async fn subscribe(
        &self,
        key: BrokerStreamKey,
    ) -> Result<
        (
            u64,
            Vec<AgentTextStreamRecordV1>,
            mpsc::Receiver<AgentTextStreamRecordV1>,
        ),
        QuicBrokerError,
    > {
        let (tx, rx) = mpsc::channel(self.per_subscriber_queue);
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        if !inner.rooms.contains_key(&key) && inner.rooms.len() >= self.max_rooms {
            return Err(QuicBrokerError::RoomLimitExceeded {
                limit: self.max_rooms,
            });
        }
        let id = inner.next_subscriber_id;
        inner.next_subscriber_id += 1;
        let room = inner.rooms.entry(key).or_default();
        if room.finished_at.is_none() {
            room.last_activity_at = Instant::now();
        }
        let backlog = room
            .backlog
            .iter()
            .map(|entry| entry.record.clone())
            .collect();
        if room.finished_at.is_some() {
            return Ok((id, backlog, rx));
        }
        room.subscribers.push(Subscriber { id, tx });
        room.subscriber_notify.notify_waiters();
        room.subscriber_notify.notify_one();
        Ok((id, backlog, rx))
    }

    async fn unsubscribe(&self, key: &BrokerStreamKey, id: u64) {
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        let mut should_remove = false;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.retain(|subscriber| subscriber.id != id);
            if room.finished_at.is_none() {
                room.last_activity_at = Instant::now();
            }
            should_remove = room.subscribers.is_empty()
                && room.backlog.is_empty()
                && room.finished_at.is_none();
        }
        if should_remove {
            remove_room(&mut inner, key);
        }
    }

    async fn publish(
        &self,
        key: &BrokerStreamKey,
        record: AgentTextStreamRecordV1,
    ) -> Result<usize, QuicBrokerError> {
        let record_bytes = record.encode()?.len();
        if record_bytes > self.max_backlog_bytes {
            return Err(QuicBrokerError::BacklogRecordTooLarge {
                record_bytes,
                limit: self.max_backlog_bytes,
            });
        }
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        if inner
            .rooms
            .get(key)
            .is_some_and(|room| room.finished_at.is_some())
        {
            remove_room(&mut inner, key);
        }
        if !inner.rooms.contains_key(key) && inner.rooms.len() >= self.max_rooms {
            return Err(QuicBrokerError::RoomLimitExceeded {
                limit: self.max_rooms,
            });
        }
        let mut delivered = 0;
        let mut total_backlog_bytes = inner.total_backlog_bytes;
        let room = inner.rooms.entry(key.clone()).or_default();
        room.last_activity_at = Instant::now();
        room.backlog.push_back(BacklogRecord {
            record: record.clone(),
            bytes: record_bytes,
        });
        room.backlog_bytes += record_bytes;
        total_backlog_bytes += record_bytes;
        while room.backlog.len() > self.max_backlog || total_backlog_bytes > self.max_backlog_bytes
        {
            let Some(dropped) = room.backlog.pop_front() else {
                break;
            };
            room.backlog_bytes = room.backlog_bytes.saturating_sub(dropped.bytes);
            total_backlog_bytes = total_backlog_bytes.saturating_sub(dropped.bytes);
        }
        room.subscribers.retain(|subscriber| {
            if subscriber.tx.try_send(record.clone()).is_ok() {
                delivered += 1;
                true
            } else {
                false
            }
        });
        let should_remove =
            room.subscribers.is_empty() && room.backlog.is_empty() && room.finished_at.is_none();
        inner.total_backlog_bytes = total_backlog_bytes;
        if should_remove {
            remove_room(&mut inner, key);
        }
        Ok(delivered)
    }

    async fn wait_for_subscriber(&self, key: &BrokerStreamKey) -> Result<(), QuicBrokerError> {
        let result = timeout(PUBLISH_SUBSCRIBER_GRACE, async {
            loop {
                let notify = {
                    let mut inner = self.inner.lock().await;
                    self.purge_expired_rooms(&mut inner);
                    if !inner.rooms.contains_key(key) && inner.rooms.len() >= self.max_rooms {
                        return Err(QuicBrokerError::RoomLimitExceeded {
                            limit: self.max_rooms,
                        });
                    }
                    let room = inner.rooms.entry(key.clone()).or_default();
                    if room.finished_at.is_some() {
                        *room = BrokerRoom::default();
                    }
                    if !room.subscribers.is_empty() {
                        return Ok(());
                    }
                    room.subscriber_notify.clone()
                };
                notify.notified().await;
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.drop_empty_unfinished_room(key).await;
                Ok(())
            }
        }
    }

    async fn drop_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        remove_room(&mut inner, key);
    }

    async fn drop_empty_unfinished_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        let should_remove = inner.rooms.get(key).is_some_and(|room| {
            room.subscribers.is_empty() && room.backlog.is_empty() && room.finished_at.is_none()
        });
        if should_remove {
            remove_room(&mut inner, key);
        }
    }

    async fn finish_room(self: &Arc<Self>, key: &BrokerStreamKey) {
        if !self.mark_room_finished(key).await {
            return;
        }
        let state = Arc::clone(self);
        let key = key.clone();
        tokio::spawn(async move {
            sleep(FINISHED_ROOM_TTL).await;
            state.drop_expired_finished_room(&key).await;
        });
    }

    async fn mark_room_finished(&self, key: &BrokerStreamKey) -> bool {
        let mut inner = self.inner.lock().await;
        self.purge_expired_rooms(&mut inner);
        let mut should_remove = false;
        let mut should_retain = false;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.clear();
            should_remove = room.backlog.is_empty();
            if !should_remove {
                let now = Instant::now();
                room.finished_at = Some(now);
                room.last_activity_at = now;
                should_retain = true;
            }
        }
        if should_remove {
            remove_room(&mut inner, key);
        }
        should_retain
    }

    async fn drop_expired_finished_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        let Some(room) = inner.rooms.get(key) else {
            return;
        };
        if room
            .finished_at
            .is_some_and(|finished_at| finished_at.elapsed() >= FINISHED_ROOM_TTL)
        {
            remove_room(&mut inner, key);
        }
    }

    fn purge_expired_rooms(&self, inner: &mut BrokerStateInner) {
        // Finished rooms get a one-shot timer in `finish_room`; unfinished-room
        // cleanup is activity-driven and runs when the broker state is touched.
        let mut total_backlog_bytes = 0;
        inner.rooms.retain(|_, room| {
            let retain = if let Some(finished_at) = room.finished_at {
                finished_at.elapsed() < FINISHED_ROOM_TTL
            } else {
                !room.subscribers.is_empty()
                    || room.last_activity_at.elapsed() < UNFINISHED_ROOM_TTL
            };
            if retain {
                total_backlog_bytes += room.backlog_bytes;
            }
            retain
        });
        inner.total_backlog_bytes = total_backlog_bytes;
    }

    #[cfg(test)]
    async fn room_count(&self) -> usize {
        self.inner.lock().await.rooms.len()
    }

    #[cfg(test)]
    async fn backlog_bytes_for_test(&self) -> usize {
        self.inner.lock().await.total_backlog_bytes
    }

    #[cfg(test)]
    async fn age_finished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.finished_at = Some(Instant::now().checked_sub(age).unwrap());
        }
    }

    #[cfg(test)]
    async fn age_unfinished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key)
            && room.finished_at.is_none()
        {
            room.last_activity_at = Instant::now().checked_sub(age).unwrap();
        }
    }
}

fn remove_room(inner: &mut BrokerStateInner, key: &BrokerStreamKey) {
    if let Some(room) = inner.rooms.remove(key) {
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(room.backlog_bytes);
    }
}

async fn handle_connection(
    state: Arc<BrokerState>,
    connection: quinn::Connection,
    max_streams_per_connection: usize,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let stream_limiter = Arc::new(Semaphore::new(max_streams_per_connection));
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                let Ok(mut recv) = uni else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_publish_stream(state, recv, read_timeout).await;
                });
            }
            bi = connection.accept_bi() => {
                let Ok((mut send, mut recv)) = bi else {
                    return Ok(());
                };
                let Ok(permit) = Arc::clone(&stream_limiter).try_acquire_owned() else {
                    let _ = send.reset(0_u32.into());
                    let _ = recv.stop(0_u32.into());
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_subscribe_stream(state, send, recv, read_timeout).await;
                });
            }
        }
    }
}

async fn handle_publish_stream(
    state: Arc<BrokerState>,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv, read_timeout).await?;
    let QuicBrokerControlV1::Publish { .. } = control.control else {
        return Err(QuicBrokerError::SubscribeRequiresBidirectionalStream);
    };
    let key = control.key()?;
    state.wait_for_subscriber(&key).await?;
    let mut limit_state = AgentTextStreamReceiveAccumulator::default();

    // The `read_timeout` is a handshake deadline only: it bounds how long an
    // unauthenticated peer may stall before sending its publish control frame.
    // Once a publisher has authenticated a room we must NOT apply a per-record
    // deadline. Agents legitimately go quiet between records (e.g. a long tool
    // call with no progress events); a per-frame deadline would error the
    // publish stream on that silence, which latches the composer's `live_error`
    // and kills the live preview for the rest of the response with no recovery.
    // QUIC liveness (max_idle_timeout + keep_alive_interval) still reaps a
    // genuinely dead publisher, and the resource caps (max_connections /
    // max_rooms / backlog budgets) still bound an idle-but-alive one, so reads
    // here are intentionally unbounded by the application-level deadline.
    let result = async {
        while let Some(record) = read_record_frame(&mut recv, None).await? {
            if record.stream_id != key.stream_id {
                return Err(QuicBrokerError::MixedStreamIds);
            }
            limit_state.observe(&record)?;
            state.publish(&key, record).await?;
        }
        Ok::<_, QuicBrokerError>(())
    }
    .await;

    if matches!(&result, Err(QuicBrokerError::MixedStreamIds)) {
        state.drop_room(&key).await;
    } else {
        state.finish_room(&key).await;
    }
    result
}

async fn handle_subscribe_stream(
    state: Arc<BrokerState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    read_timeout: Duration,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv, read_timeout).await?;
    let QuicBrokerControlV1::Subscribe { .. } = control.control else {
        return Err(QuicBrokerError::PublishRequiresUnidirectionalStream);
    };
    let key = control.key()?;
    let (subscriber_id, backlog, mut rx) = state.subscribe(key.clone()).await?;
    let result = async {
        for record in backlog {
            write_record_frame(&mut send, &record).await?;
        }
        while let Some(record) = rx.recv().await {
            write_record_frame(&mut send, &record).await?;
        }
        send.finish()?;
        Ok::<_, QuicBrokerError>(())
    }
    .await;
    state.unsubscribe(&key, subscriber_id).await;
    result
}

async fn write_control_frame(
    send: &mut quinn::SendStream,
    control: &QuicBrokerControlEnvelopeV1,
) -> Result<(), QuicBrokerError> {
    let bytes = serde_json::to_vec(control)?;
    write_bytes_frame(send, &bytes).await
}

async fn read_control_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
) -> Result<QuicBrokerControlEnvelopeV1, QuicBrokerError> {
    let bytes = read_bytes_frame(recv, Some(read_timeout))
        .await?
        .ok_or(QuicBrokerError::MissingControlFrame)?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn write_record_frame(
    send: &mut quinn::SendStream,
    record: &AgentTextStreamRecordV1,
) -> Result<(), QuicBrokerError> {
    let bytes = record.encode()?;
    write_bytes_frame(send, &bytes).await
}

async fn read_record_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
) -> Result<Option<AgentTextStreamRecordV1>, QuicBrokerError> {
    let Some(bytes) = read_bytes_frame(recv, read_timeout).await? else {
        return Ok(None);
    };
    Ok(Some(AgentTextStreamRecordV1::decode(&bytes)?))
}

async fn write_bytes_frame(
    send: &mut quinn::SendStream,
    bytes: &[u8],
) -> Result<(), QuicBrokerError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| QuicBrokerError::FrameTooLarge(bytes.len()))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

async fn read_bytes_frame(
    recv: &mut quinn::RecvStream,
    read_timeout: Option<Duration>,
) -> Result<Option<Vec<u8>>, QuicBrokerError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        let chunk = match read_timeout {
            Some(read_timeout) => {
                broker_read_deadline(read_timeout, recv.read(&mut len_bytes[read..])).await?
            }
            None => recv.read(&mut len_bytes[read..]).await?,
        };
        match chunk {
            Some(0) => return Err(QuicBrokerError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicBrokerError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len)?;
    let mut bytes = vec![0_u8; len];
    match read_timeout {
        Some(read_timeout) => {
            broker_read_deadline(read_timeout, recv.read_exact(&mut bytes)).await?;
        }
        None => recv.read_exact(&mut bytes).await?,
    }
    Ok(Some(bytes))
}

async fn broker_read_deadline<T, E>(
    read_timeout: Duration,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, QuicBrokerError>
where
    QuicBrokerError: From<E>,
{
    timeout(read_timeout, read)
        .await
        .map_err(|_| QuicBrokerError::ReadTimeout)?
        .map_err(Into::into)
}

fn validate_frame_len(len: usize) -> Result<(), QuicBrokerError> {
    if len == 0 {
        return Err(QuicBrokerError::EmptyFrame);
    }
    if len > MAX_FRAME_SIZE {
        return Err(QuicBrokerError::FrameTooLarge(len));
    }
    Ok(())
}

fn decode_stream_id(value: &str) -> Result<Vec<u8>, QuicBrokerError> {
    let bytes = hex::decode(value)?;
    if bytes.is_empty() {
        return Err(QuicBrokerError::EmptyStreamId);
    }
    if bytes.len() > AGENT_TEXT_STREAM_MAX_STREAM_ID_LEN {
        return Err(QuicBrokerError::StreamIdTooLong(bytes.len()));
    }
    Ok(bytes)
}

fn decode_start_event_id(value: &str) -> Result<Vec<u8>, QuicBrokerError> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(QuicBrokerError::InvalidStartEventIdLength(bytes.len()));
    }
    Ok(bytes)
}

fn broker_transport_config(config: &QuicBrokerConfig) -> Result<TransportConfig, QuicBrokerError> {
    let mut transport = TransportConfig::default();
    let streams = VarInt::try_from(config.max_streams_per_connection as u64)?;
    transport
        .max_concurrent_bidi_streams(streams)
        .max_concurrent_uni_streams(streams)
        .max_idle_timeout(Some(config.max_idle_timeout.try_into()?))
        .keep_alive_interval(Some(config.keep_alive_interval));
    Ok(transport)
}

fn configure_server(tls: &QuicBrokerTlsConfig) -> Result<(ServerConfig, Vec<u8>), QuicBrokerError> {
    match tls {
        QuicBrokerTlsConfig::GenerateSelfSigned { subject_alt_names } => {
            let subject_alt_names = if subject_alt_names.is_empty() {
                vec!["localhost".to_owned()]
            } else {
                subject_alt_names.clone()
            };
            let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
                .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
            let cert_der = CertificateDer::from(certified_key.cert);
            let key_der = PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
            let server_config =
                ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())
                    .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
            Ok((server_config, cert_der.as_ref().to_vec()))
        }
        QuicBrokerTlsConfig::PemFiles {
            cert_path,
            key_path,
        } => {
            let certs = load_certificate_chain(cert_path)?;
            let leaf_cert_der = certs
                .first()
                .ok_or(QuicBrokerError::EmptyCertificateChain)?
                .as_ref()
                .to_vec();
            let key = load_private_key(key_path)?;
            let server_config = ServerConfig::with_single_cert(certs, key)
                .map_err(|err| QuicBrokerError::Certificate(err.to_string()))?;
            Ok((server_config, leaf_cert_der))
        }
    }
}

fn load_certificate_chain(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(QuicBrokerError::Io)?;
    if certs.is_empty() {
        return Err(QuicBrokerError::EmptyCertificateChain);
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, QuicBrokerError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(QuicBrokerError::Io)?
        .ok_or(QuicBrokerError::MissingPrivateKey)
}

fn client_endpoint(
    trust: BrokerServerTrust,
    broker_addr: SocketAddr,
) -> Result<Endpoint, QuicBrokerError> {
    let client_config = match trust {
        BrokerServerTrust::Platform => ClientConfig::try_with_platform_verifier()?,
        BrokerServerTrust::CertificateDer(cert_der) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(cert_der))?;
            ClientConfig::with_root_certificates(Arc::new(roots))
                .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?
        }
        BrokerServerTrust::InsecureLocal => {
            if !broker_addr.ip().is_loopback() {
                return Err(QuicBrokerError::InsecureLocalRequiresLoopback(broker_addr));
            }
            ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(insecure_client_crypto()?)
                    .map_err(|err| QuicBrokerError::ClientConfig(err.to_string()))?,
            ))
        }
    };
    let mut endpoint = Endpoint::client(client_bind_addr_for_broker(broker_addr))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn client_bind_addr_for_broker(broker_addr: SocketAddr) -> SocketAddr {
    match broker_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn insecure_client_crypto() -> Result<rustls::ClientConfig, QuicBrokerError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new(provider))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicBrokerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    QuinnConfig(#[from] quinn::ConfigError),
    #[error("broker QUIC transport value exceeds varint bounds")]
    TransportValueTooLarge(#[from] quinn::VarIntBoundsExceeded),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    #[error(transparent)]
    ReadExact(#[from] quinn::ReadExactError),
    #[error(transparent)]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error(transparent)]
    Stopped(#[from] quinn::StoppedError),
    #[error(transparent)]
    Record(#[from] AgentTextStreamRecordError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),
    #[error(transparent)]
    StreamCrypto(#[from] transport_quic_stream::QuicTextStreamError),
    #[error(transparent)]
    ReceiveLimit(#[from] AgentTextStreamReceiveLimitError),
    #[error("certificate setup failed: {0}")]
    Certificate(String),
    #[error("certificate PEM file did not contain any certificates")]
    EmptyCertificateChain,
    #[error("private key PEM file did not contain a usable private key")]
    MissingPrivateKey,
    #[error("QUIC client config failed: {0}")]
    ClientConfig(String),
    #[error("--insecure-local is only allowed for loopback QUIC broker endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("broker subscriber queue depth cannot be zero")]
    EmptySubscriberQueue,
    #[error("broker backlog depth cannot be zero")]
    EmptyBacklog,
    #[error("broker room limit cannot be zero")]
    EmptyRoomLimit,
    #[error("broker backlog byte limit cannot be zero")]
    EmptyBacklogByteLimit,
    #[error("broker connection limit cannot be zero")]
    EmptyConnectionLimit,
    #[error("broker per-connection stream limit cannot be zero")]
    EmptyStreamLimit,
    #[error("broker read timeout cannot be zero")]
    EmptyReadTimeout,
    #[error("broker idle timeout cannot be zero")]
    EmptyIdleTimeout,
    #[error("broker keep-alive interval cannot be zero")]
    EmptyKeepAliveInterval,
    #[error("broker room limit exceeded: {limit}")]
    RoomLimitExceeded { limit: usize },
    #[error("broker backlog record is larger than the byte budget: {record_bytes} > {limit}")]
    BacklogRecordTooLarge { record_bytes: usize, limit: usize },
    #[error("broker frame read timed out")]
    ReadTimeout,
    #[error("broker control frame is missing")]
    MissingControlFrame,
    #[error("wrong broker control protocol: {0}")]
    WrongControlProtocol(String),
    #[error("publish streams must be unidirectional")]
    PublishRequiresUnidirectionalStream,
    #[error("subscribe streams must be bidirectional")]
    SubscribeRequiresBidirectionalStream,
    #[error("agent text stream id cannot be empty")]
    EmptyStreamId,
    #[error("agent text stream id is too long: {0}")]
    StreamIdTooLong(usize),
    #[error("agent text stream start event id must be 32 bytes, got {0}")]
    InvalidStartEventIdLength(usize),
    #[error("agent text stream did not contain any records")]
    EmptyStream,
    #[error("agent text stream frame length was truncated")]
    TruncatedFrameLength,
    #[error("agent text stream frame cannot be empty")]
    EmptyFrame,
    #[error("agent text stream frame is too large: {0}")]
    FrameTooLarge(usize),
    #[error("agent text stream chunk size cannot be zero")]
    EmptyChunkSize,
    #[error("agent text stream chunk size exceeds app profile max: {0}")]
    ChunkSizeTooLarge(usize),
    #[error("agent text stream mixed stream ids")]
    MixedStreamIds,
    #[error("agent text stream sequence mismatch: expected {expected}, got {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_RECORD_STATUS;
    use tokio::sync::oneshot;

    fn test_state(max_backlog: usize) -> BrokerState {
        BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog,
            DEFAULT_BROKER_MAX_ROOMS,
            DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        )
    }

    #[tokio::test]
    async fn broker_forwards_live_records_to_subscriber_with_same_transcript() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xaa; 32];
        let start_event_id = MessageId::new(vec![0x11; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            text: "hello broker stream".to_owned(),
            max_chunk_bytes: 6,
            chunk_delay: Duration::ZERO,
            crypto: None,
        })
        .await
        .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "hello broker stream");
        assert_eq!(received.chunk_count, 4);
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_does_not_apply_per_record_deadline_to_authenticated_publisher() {
        // Regression for the live-preview latch: an agent that goes quiet between
        // records (e.g. a long tool call with no progress events) must not have
        // its publish stream errored by a per-record read deadline. Before the
        // fix, `read_timeout` was enforced on every record-frame read after the
        // handshake, so an idle gap longer than the deadline killed the stream;
        // the composer then latched `live_error` and the preview was dead for the
        // rest of the response. Here we use a tiny read_timeout and idle well past
        // it between two records, and assert both records still arrive. The QUIC
        // idle timeout (kept long here) is what reaps a genuinely dead publisher.
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            read_timeout: Duration::from_millis(100),
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xa9; 32];
        let start_event_id = MessageId::new(vec![0x19; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("before", 32, Duration::ZERO)
            .await
            .unwrap();
        // Idle far longer than the per-record read_timeout (100ms).
        sleep(Duration::from_millis(500)).await;
        // This write would have failed before the fix, because the broker would
        // have already errored the publish stream on the idle gap.
        publisher
            .append_text("after", 32, Duration::ZERO)
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "beforeafter");
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_closes_subscribers_when_publish_stream_errors_after_backlog() {
        let stream_id = vec![0xac; 32];
        let start_event_id = MessageId::new(vec![0x21; 32]);
        let small_record =
            AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"ok".to_vec());
        let large_record = AgentTextStreamRecordV1::text_delta(
            stream_id.clone(),
            2,
            b"this record is too large".to_vec(),
        );
        let max_backlog_bytes = small_record.encode().unwrap().len();
        assert!(large_record.encode().unwrap().len() > max_backlog_bytes);

        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog_bytes,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("ok", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_text("this record is too large", 32, Duration::ZERO)
            .await
            .unwrap();
        let _ = publisher.finish().await;

        let received = tokio::time::timeout(Duration::from_secs(2), subscriber)
            .await
            .expect("subscriber should not park forever after publish loop error")
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "ok");
        assert_eq!(received.chunk_count, 1);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_forwards_status_records_without_adding_to_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0x33; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        })
        .await
        .unwrap();
        publisher
            .append_text("hello", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_STATUS,
                "thinking",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(received.stream_id, stream_id);
        assert_eq!(received.text, "hello");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[0].record_type,
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        );
        assert_eq!(received.chunks[0].text, "hello");
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_STATUS
        );
        assert_eq!(received.chunks[1].text, "thinking");
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_forwards_checkpoint_snapshot_without_merging_into_final_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xc4; 32];
        let start_event_id = MessageId::new(vec![0x44; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        })
        .await
        .unwrap();
        // A delta builds the provisional answer; the checkpoint is a full preview
        // snapshot the receiver forwards for the consumer to swap in.
        publisher
            .append_text("hello", 32, Duration::ZERO)
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
                "hello world",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // Checkpoint plaintext reaches the subscriber as the record's text...
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_CHECKPOINT
        );
        assert_eq!(received.chunks[1].text, "hello world");
        // ...but it is not merged into the provisional final text, which stays the
        // concatenation of TextDelta frames only.
        assert_eq!(received.text, "hello");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(sent.chunk_count, received.chunk_count);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_progress_and_status_only_stream_yields_empty_final_text() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0x9c; 32];
        let start_event_id = MessageId::new(vec![0x55; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        })
        .await
        .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_STATUS,
                "thinking",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        publisher
            .append_record_text(
                AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
                "searching",
                32,
                Duration::ZERO,
            )
            .await
            .unwrap();
        let sent = publisher.finish().await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // A stream that never sends a TextDelta has no chat answer: the final text
        // is legitimately empty, so consumers can tell "no answer" apart from a
        // real preview instead of rendering a blank chat bubble.
        assert_eq!(received.text, "");
        // The status/progress content is still delivered per-record for live
        // non-chat chrome.
        assert_eq!(received.chunks.len(), 2);
        assert_eq!(
            received.chunks[0].record_type,
            AGENT_TEXT_STREAM_RECORD_STATUS
        );
        assert_eq!(received.chunks[0].text, "thinking");
        assert_eq!(
            received.chunks[1].record_type,
            AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        );
        assert_eq!(received.chunks[1].text, "searching");
        assert_eq!(received.chunk_count, 2);
        assert_eq!(sent.transcript_hash, received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_subscriber_rejects_streams_past_receive_limits() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xdd; 32];
        let start_event_id = MessageId::new(vec![0x44; 32]);
        let subscriber = tokio::spawn(subscribe_text_from_broker_with_limits(
            SubscribeTextFromBroker {
                broker_addr,
                server_name: "localhost".to_owned(),
                trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
                stream_id: stream_id.clone(),
                start_event_id: start_event_id.clone(),
                crypto: None,
            },
            AgentTextStreamReceiveLimits {
                max_records: 1,
                max_plaintext_bytes: 1024,
            },
            |_| {},
        ));
        sleep(Duration::from_millis(100)).await;

        let _ = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id,
            start_event_id,
            text: "two records".to_owned(),
            max_chunk_bytes: 3,
            chunk_delay: Duration::ZERO,
            crypto: None,
        })
        .await;

        let err = timeout(Duration::from_secs(5), subscriber)
            .await
            .expect("subscriber should hit receive limit")
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            err,
            QuicBrokerError::ReceiveLimit(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                attempted: 2,
                limit: 1
            })
        ));

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_replays_full_backlog_to_late_subscriber() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: 2,
            max_backlog: 16,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xbb; 32];
        let start_event_id = MessageId::new(vec![0x22; 32]);
        let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        })
        .await
        .unwrap();

        publisher
            .append_text("abcdefghij", 1, Duration::ZERO)
            .await
            .unwrap();
        let late_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id: stream_id.clone(),
            start_event_id,
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publisher.finish().await.unwrap();
        let _ = early_subscriber.await;
        let late_received = late_subscriber.await.unwrap().unwrap();

        assert_eq!(late_received.text, "abcdefghij");
        assert_eq!(late_received.chunk_count, 10);
        assert_eq!(sent.transcript_hash, late_received.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_replays_finished_backlog_to_late_subscriber() {
        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            ..QuicBrokerConfig::default()
        })
        .unwrap();
        let broker_addr = server.local_addr().unwrap();
        let server_cert = server.server_cert_der().to_vec();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let broker_task = tokio::spawn(server.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0x33; 32]);
        let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        }));
        sleep(Duration::from_millis(100)).await;

        let sent = publish_text_to_broker(PublishTextToBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            text: "finished transcript".to_owned(),
            max_chunk_bytes: 4,
            crypto: None,
            chunk_delay: Duration::ZERO,
        })
        .await
        .unwrap();
        let early_received = early_subscriber.await.unwrap().unwrap();
        assert_eq!(early_received.transcript_hash, sent.transcript_hash);

        let late_received = timeout(
            Duration::from_secs(5),
            subscribe_text_from_broker(SubscribeTextFromBroker {
                broker_addr,
                server_name: "localhost".to_owned(),
                trust: BrokerServerTrust::CertificateDer(server_cert),
                stream_id,
                start_event_id,
                crypto: None,
            }),
        )
        .await
        .expect("late subscriber should receive retained finished backlog")
        .unwrap();

        assert_eq!(late_received.text, "finished transcript");
        assert_eq!(late_received.transcript_hash, sent.transcript_hash);

        let _ = shutdown_tx.send(());
        broker_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn broker_retains_finished_rooms_and_closes_live_subscribers() {
        let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
        let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await.unwrap();
        assert_eq!(state.room_count().await, 1);

        state.publish(&key, record.clone()).await.unwrap();
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        assert_eq!(rx.recv().await.expect("queued live record").seq, record.seq);
        assert!(rx.recv().await.is_none());

        let (_late_id, backlog, mut finished_rx) = state.subscribe(key).await.unwrap();
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].seq, record.seq);
        assert!(finished_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn broker_drops_finished_rooms_after_ttl() {
        let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        state.publish(&key, record).await.unwrap();
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        state
            .age_finished_room_for_test(&key, FINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;
        state.drop_expired_finished_room(&key).await;
        assert_eq!(state.room_count().await, 0);
    }

    #[tokio::test]
    async fn broker_purges_stale_unfinished_rooms_without_live_subscribers() {
        let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
        let stale_key = BrokerStreamKey::new(vec![0xab; 32], MessageId::new(vec![0x12; 32]));
        let live_key = BrokerStreamKey::new(vec![0xcd; 32], MessageId::new(vec![0x34; 32]));

        state
            .publish(
                &stale_key,
                AgentTextStreamRecordV1::text_delta(vec![0xab; 32], 1, b"stale".to_vec()),
            )
            .await
            .unwrap();
        state
            .publish(
                &live_key,
                AgentTextStreamRecordV1::text_delta(vec![0xcd; 32], 1, b"live".to_vec()),
            )
            .await
            .unwrap();
        let (_subscriber_id, _backlog, _rx) = state.subscribe(live_key.clone()).await.unwrap();
        state
            .age_unfinished_room_for_test(&stale_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;
        state
            .age_unfinished_room_for_test(&live_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;

        state
            .publish(
                &BrokerStreamKey::new(vec![0xef; 32], MessageId::new(vec![0x56; 32])),
                AgentTextStreamRecordV1::text_delta(vec![0xef; 32], 1, b"trigger".to_vec()),
            )
            .await
            .unwrap();

        assert_eq!(state.room_count().await, 2);
        let (_late_id, stale_backlog, _stale_rx) = state.subscribe(stale_key).await.unwrap();
        assert!(stale_backlog.is_empty());
        let (_live_id, live_backlog, _live_rx) = state.subscribe(live_key).await.unwrap();
        assert_eq!(live_backlog.len(), 1);
    }

    #[tokio::test]
    async fn broker_buffers_records_until_subscriber_arrives() {
        let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        assert_eq!(state.publish(&key, record.clone()).await.unwrap(), 0);
        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
        let received = backlog.first().expect("subscriber should receive backlog");

        assert_eq!(received.seq, record.seq);
        assert_eq!(received.plaintext_frame, record.plaintext_frame);
    }

    #[tokio::test]
    async fn broker_backlog_drops_oldest_records_when_bound_reached() {
        let state = test_state(2);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        for seq in 1..=3 {
            let record = AgentTextStreamRecordV1::text_delta(
                vec![0xaa; 32],
                seq,
                format!("chunk-{seq}").into_bytes(),
            );
            assert_eq!(state.publish(&key, record).await.unwrap(), 0);
        }

        let (_subscriber_id, backlog, mut rx) = state.subscribe(key).await.unwrap();
        let first = backlog.first().expect("subscriber should receive backlog");
        let second = backlog.get(1).expect("subscriber should receive backlog");
        assert_eq!(first.seq, 2);
        assert_eq!(second.seq, 3);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn broker_state_rejects_new_rooms_past_limit() {
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            1,
            usize::MAX,
        );
        let first_key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let second_key = BrokerStreamKey::new(vec![0xbb; 32], MessageId::new(vec![0x22; 32]));

        state
            .publish(
                &first_key,
                AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"first".to_vec()),
            )
            .await
            .unwrap();
        let err = state
            .publish(
                &second_key,
                AgentTextStreamRecordV1::text_delta(vec![0xbb; 32], 1, b"second".to_vec()),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            QuicBrokerError::RoomLimitExceeded { limit: 1 }
        ));
        assert_eq!(state.room_count().await, 1);
    }

    #[tokio::test]
    async fn broker_state_enforces_global_backlog_byte_budget() {
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let sample = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
        let state = BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            4,
            sample.encode().unwrap().len() * 2,
        );

        for seq in 1..=3 {
            state
                .publish(
                    &key,
                    AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], seq, b"hello".to_vec()),
                )
                .await
                .unwrap();
        }

        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
        assert_eq!(
            backlog.iter().map(|record| record.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(state.backlog_bytes_for_test().await <= sample.encode().unwrap().len() * 2);
    }

    #[tokio::test]
    async fn broker_read_deadline_times_out_stalled_reads() {
        let err = broker_read_deadline(Duration::from_millis(5), async {
            sleep(Duration::from_millis(50)).await;
            Ok::<_, std::io::Error>(())
        })
        .await
        .unwrap_err();

        assert!(matches!(err, QuicBrokerError::ReadTimeout));
    }

    #[test]
    fn broker_config_rejects_zero_resource_limits() {
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_rooms: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyRoomLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_connections: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyConnectionLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                max_streams_per_connection: 0,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyStreamLimit)
        ));
        assert!(matches!(
            QuicBrokerServer::bind(QuicBrokerConfig {
                bind_addr: LOCAL_SERVER_BIND,
                read_timeout: Duration::ZERO,
                ..QuicBrokerConfig::default()
            }),
            Err(QuicBrokerError::EmptyReadTimeout)
        ));
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        assert!(matches!(
            validate_frame_len(MAX_FRAME_SIZE + 1),
            Err(QuicBrokerError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn stream_record_text_decodes_renderable_frames_and_leaves_advisory_records_empty() {
        use cgka_traits::agent_text_stream::{
            AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        };

        let stream_id = vec![0x11; 32];
        let record = |record_type, plaintext: &str| {
            AgentTextStreamRecordV1::new(stream_id.clone(), 1, record_type, plaintext.as_bytes())
        };

        // Renderable frames decode to their UTF-8 plaintext. Checkpoint is a full
        // preview snapshot the consumer swaps in, so it must not stay blank.
        for (record_type, plaintext) in [
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
            (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
            (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
            (AGENT_TEXT_STREAM_RECORD_CHECKPOINT, "hello world"),
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, plaintext)).unwrap(),
                plaintext
            );
        }

        // Abort and FinalNotice are advisory: the consumer reacts to the record
        // type, so they decode to "" even when the sender attached bytes.
        for record_type in [
            AGENT_TEXT_STREAM_RECORD_ABORT,
            AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        ] {
            assert_eq!(
                stream_record_text(&record(record_type, "ignored")).unwrap(),
                ""
            );
        }
    }

    #[test]
    fn client_bind_addr_matches_broker_address_family() {
        assert_eq!(
            client_bind_addr_for_broker(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450)),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            client_bind_addr_for_broker(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4450)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        );
    }

    #[tokio::test]
    async fn insecure_local_rejects_remote_broker_addr() {
        let err = publish_text_to_broker(PublishTextToBroker {
            broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4450),
            server_name: "example.com".to_owned(),
            trust: BrokerServerTrust::InsecureLocal,
            stream_id: vec![0xaa; 32],
            start_event_id: MessageId::new(vec![0x11; 32]),
            text: "hello".to_owned(),
            max_chunk_bytes: 5,
            chunk_delay: Duration::ZERO,
            crypto: None,
        })
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            QuicBrokerError::InsecureLocalRequiresLoopback(_)
        ));
    }

    #[tokio::test]
    async fn broker_can_bind_with_pem_certificate_files() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        std::fs::write(&cert_path, certified_key.cert.pem()).unwrap();
        std::fs::write(&key_path, certified_key.signing_key.serialize_pem()).unwrap();

        let server = QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            tls: QuicBrokerTlsConfig::PemFiles {
                cert_path,
                key_path,
            },
            ..QuicBrokerConfig::default()
        })
        .unwrap();

        assert_eq!(server.server_cert_der(), certified_key.cert.der().as_ref());
    }

    #[test]
    fn certificate_fingerprint_is_sha256_hex() {
        assert_eq!(
            certificate_sha256_fingerprint_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
