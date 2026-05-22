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
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamRecordError, AgentTextStreamRecordV1,
    AgentTextStreamTranscriptV1,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::time::{sleep, timeout};
use transport_quic_stream::{ReceivedTextChunk, ReceivedTextStream, SentTextStream};

pub const QUIC_BROKER_PROTOCOL_V1: &str = "marmot.quic_broker.v1";
pub const DEFAULT_SUBSCRIBER_QUEUE_DEPTH: usize = 32;
pub const DEFAULT_BROKER_BACKLOG_DEPTH: usize = 1024;

const FRAME_LEN_BYTES: usize = 4;
#[cfg(test)]
const LOCAL_SERVER_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const MAX_FRAME_SIZE: usize = AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + 1024;
const PUBLISH_SUBSCRIBER_GRACE: Duration = Duration::from_secs(5);
const FINISHED_ROOM_TTL: Duration = Duration::from_secs(60);
const SEND_STOP_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct QuicBrokerConfig {
    pub bind_addr: SocketAddr,
    pub per_subscriber_queue: usize,
    pub max_backlog: usize,
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
}

impl QuicBrokerServer {
    pub fn bind(config: QuicBrokerConfig) -> Result<Self, QuicBrokerError> {
        if config.per_subscriber_queue == 0 {
            return Err(QuicBrokerError::EmptySubscriberQueue);
        }
        if config.max_backlog == 0 {
            return Err(QuicBrokerError::EmptyBacklog);
        }
        let (server_config, server_cert_der) = configure_server(&config.tls)?;
        let endpoint = Endpoint::server(server_config, config.bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
            state: Arc::new(BrokerState::new(
                config.per_subscriber_queue,
                config.max_backlog,
            )),
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
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        let _ = handle_connection(state, connection).await;
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
}

#[derive(Clone, Debug)]
pub struct OpenBrokerTextPublisher {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
}

#[derive(Clone, Debug)]
pub struct SubscribeTextFromBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
}

pub struct BrokerTextPublisher {
    endpoint: Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
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
        })
    }

    pub async fn append_text(
        &mut self,
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
            let record = AgentTextStreamRecordV1::text_delta(
                self.transcript.stream_id().to_vec(),
                self.next_seq,
                chunk,
            );
            self.next_seq += 1;
            write_record_frame(&mut self.send, &record).await?;
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

    while let Some(record) = read_record_frame(&mut recv).await? {
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

        let delta = if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
            let delta = str::from_utf8(&record.plaintext_frame)?.to_owned();
            text.push_str(&delta);
            delta
        } else {
            String::new()
        };
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        let chunk = ReceivedTextChunk {
            seq: record.seq,
            record_type: record.record_type,
            flags: record.flags,
            text: delta,
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

#[derive(Debug)]
struct BrokerState {
    per_subscriber_queue: usize,
    max_backlog: usize,
    inner: Mutex<BrokerStateInner>,
}

#[derive(Debug, Default)]
struct BrokerStateInner {
    rooms: HashMap<BrokerStreamKey, BrokerRoom>,
    next_subscriber_id: u64,
}

#[derive(Debug)]
struct BrokerRoom {
    subscribers: Vec<Subscriber>,
    backlog: VecDeque<AgentTextStreamRecordV1>,
    subscriber_notify: Arc<Notify>,
    finished_at: Option<Instant>,
}

impl Default for BrokerRoom {
    fn default() -> Self {
        Self {
            subscribers: Vec::new(),
            backlog: VecDeque::new(),
            subscriber_notify: Arc::new(Notify::new()),
            finished_at: None,
        }
    }
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<AgentTextStreamRecordV1>,
}

impl BrokerState {
    fn new(per_subscriber_queue: usize, max_backlog: usize) -> Self {
        Self {
            per_subscriber_queue,
            max_backlog,
            inner: Mutex::new(BrokerStateInner::default()),
        }
    }

    async fn subscribe(
        &self,
        key: BrokerStreamKey,
    ) -> (
        u64,
        Vec<AgentTextStreamRecordV1>,
        mpsc::Receiver<AgentTextStreamRecordV1>,
    ) {
        let (tx, rx) = mpsc::channel(self.per_subscriber_queue);
        let mut inner = self.inner.lock().await;
        self.purge_expired_finished_rooms(&mut inner);
        let id = inner.next_subscriber_id;
        inner.next_subscriber_id += 1;
        let room = inner.rooms.entry(key).or_default();
        let backlog = room.backlog.iter().cloned().collect();
        if room.finished_at.is_some() {
            return (id, backlog, rx);
        }
        room.subscribers.push(Subscriber { id, tx });
        room.subscriber_notify.notify_waiters();
        room.subscriber_notify.notify_one();
        (id, backlog, rx)
    }

    async fn unsubscribe(&self, key: &BrokerStreamKey, id: u64) {
        let mut inner = self.inner.lock().await;
        self.purge_expired_finished_rooms(&mut inner);
        let mut should_remove = false;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.retain(|subscriber| subscriber.id != id);
            should_remove = room.subscribers.is_empty()
                && room.backlog.is_empty()
                && room.finished_at.is_none();
        }
        if should_remove {
            inner.rooms.remove(key);
        }
    }

    async fn publish(&self, key: &BrokerStreamKey, record: AgentTextStreamRecordV1) -> usize {
        let mut inner = self.inner.lock().await;
        self.purge_expired_finished_rooms(&mut inner);
        if inner
            .rooms
            .get(key)
            .is_some_and(|room| room.finished_at.is_some())
        {
            inner.rooms.remove(key);
        }
        let mut delivered = 0;
        let room = inner.rooms.entry(key.clone()).or_default();
        room.backlog.push_back(record.clone());
        while room.backlog.len() > self.max_backlog {
            room.backlog.pop_front();
        }
        room.subscribers.retain(|subscriber| {
            if subscriber.tx.try_send(record.clone()).is_ok() {
                delivered += 1;
                true
            } else {
                false
            }
        });
        delivered
    }

    async fn wait_for_subscriber(&self, key: &BrokerStreamKey) {
        let _ = timeout(PUBLISH_SUBSCRIBER_GRACE, async {
            loop {
                let notify = {
                    let mut inner = self.inner.lock().await;
                    self.purge_expired_finished_rooms(&mut inner);
                    let room = inner.rooms.entry(key.clone()).or_default();
                    if room.finished_at.is_some() {
                        *room = BrokerRoom::default();
                    }
                    if !room.subscribers.is_empty() {
                        return;
                    }
                    room.subscriber_notify.clone()
                };
                notify.notified().await;
            }
        })
        .await;
    }

    async fn drop_room(&self, key: &BrokerStreamKey) {
        let mut inner = self.inner.lock().await;
        inner.rooms.remove(key);
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
        self.purge_expired_finished_rooms(&mut inner);
        let mut should_remove = false;
        let mut should_retain = false;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.clear();
            should_remove = room.backlog.is_empty();
            if !should_remove {
                room.finished_at = Some(Instant::now());
                should_retain = true;
            }
        }
        if should_remove {
            inner.rooms.remove(key);
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
            inner.rooms.remove(key);
        }
    }

    fn purge_expired_finished_rooms(&self, inner: &mut BrokerStateInner) {
        inner.rooms.retain(|_, room| {
            room.finished_at
                .is_none_or(|finished_at| finished_at.elapsed() < FINISHED_ROOM_TTL)
        });
    }

    #[cfg(test)]
    async fn room_count(&self) -> usize {
        self.inner.lock().await.rooms.len()
    }

    #[cfg(test)]
    async fn age_finished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.finished_at = Some(Instant::now().checked_sub(age).unwrap());
        }
    }
}

async fn handle_connection(
    state: Arc<BrokerState>,
    connection: quinn::Connection,
) -> Result<(), QuicBrokerError> {
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                let Ok(recv) = uni else {
                    return Ok(());
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _ = handle_publish_stream(state, recv).await;
                });
            }
            bi = connection.accept_bi() => {
                let Ok((send, recv)) = bi else {
                    return Ok(());
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _ = handle_subscribe_stream(state, send, recv).await;
                });
            }
        }
    }
}

async fn handle_publish_stream(
    state: Arc<BrokerState>,
    mut recv: quinn::RecvStream,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv).await?;
    let QuicBrokerControlV1::Publish { .. } = control.control else {
        return Err(QuicBrokerError::SubscribeRequiresBidirectionalStream);
    };
    let key = control.key()?;
    state.wait_for_subscriber(&key).await;

    while let Some(record) = read_record_frame(&mut recv).await? {
        if record.stream_id != key.stream_id {
            state.drop_room(&key).await;
            return Err(QuicBrokerError::MixedStreamIds);
        }
        state.publish(&key, record).await;
    }
    state.finish_room(&key).await;
    Ok(())
}

async fn handle_subscribe_stream(
    state: Arc<BrokerState>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), QuicBrokerError> {
    let control = read_control_frame(&mut recv).await?;
    let QuicBrokerControlV1::Subscribe { .. } = control.control else {
        return Err(QuicBrokerError::PublishRequiresUnidirectionalStream);
    };
    let key = control.key()?;
    let (subscriber_id, backlog, mut rx) = state.subscribe(key.clone()).await;
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
) -> Result<QuicBrokerControlEnvelopeV1, QuicBrokerError> {
    let bytes = read_bytes_frame(recv)
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
) -> Result<Option<AgentTextStreamRecordV1>, QuicBrokerError> {
    let Some(bytes) = read_bytes_frame(recv).await? else {
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
) -> Result<Option<Vec<u8>>, QuicBrokerError> {
    let mut len_bytes = [0_u8; FRAME_LEN_BYTES];
    let mut read = 0;
    while read < FRAME_LEN_BYTES {
        match recv.read(&mut len_bytes[read..]).await? {
            Some(0) => return Err(QuicBrokerError::TruncatedFrameLength),
            Some(n) => read += n,
            None if read == 0 => return Ok(None),
            None => return Err(QuicBrokerError::TruncatedFrameLength),
        }
    }

    let len = u32::from_be_bytes(len_bytes) as usize;
    validate_frame_len(len)?;
    let mut bytes = vec![0_u8; len];
    recv.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
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
    use tokio::sync::oneshot;

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
        }));
        sleep(Duration::from_millis(100)).await;

        let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
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
        let state = Arc::new(BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
        ));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
        let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await;
        assert_eq!(state.room_count().await, 1);

        state.publish(&key, record.clone()).await;
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        assert_eq!(rx.recv().await.expect("queued live record").seq, record.seq);
        assert!(rx.recv().await.is_none());

        let (_late_id, backlog, mut finished_rx) = state.subscribe(key).await;
        assert_eq!(backlog.len(), 1);
        assert_eq!(backlog[0].seq, record.seq);
        assert!(finished_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn broker_drops_finished_rooms_after_ttl() {
        let state = Arc::new(BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
        ));
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        state.publish(&key, record).await;
        state.finish_room(&key).await;

        assert_eq!(state.room_count().await, 1);
        state
            .age_finished_room_for_test(&key, FINISHED_ROOM_TTL + Duration::from_secs(1))
            .await;
        state.drop_expired_finished_room(&key).await;
        assert_eq!(state.room_count().await, 0);
    }

    #[tokio::test]
    async fn broker_buffers_records_until_subscriber_arrives() {
        let state = BrokerState::new(DEFAULT_SUBSCRIBER_QUEUE_DEPTH, DEFAULT_BROKER_BACKLOG_DEPTH);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

        assert_eq!(state.publish(&key, record.clone()).await, 0);
        let (_subscriber_id, backlog, _rx) = state.subscribe(key).await;
        let received = backlog.first().expect("subscriber should receive backlog");

        assert_eq!(received.seq, record.seq);
        assert_eq!(received.plaintext_frame, record.plaintext_frame);
    }

    #[tokio::test]
    async fn broker_backlog_drops_oldest_records_when_bound_reached() {
        let state = BrokerState::new(DEFAULT_SUBSCRIBER_QUEUE_DEPTH, 2);
        let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
        for seq in 1..=3 {
            let record = AgentTextStreamRecordV1::text_delta(
                vec![0xaa; 32],
                seq,
                format!("chunk-{seq}").into_bytes(),
            );
            assert_eq!(state.publish(&key, record).await, 0);
        }

        let (_subscriber_id, backlog, mut rx) = state.subscribe(key).await;
        let first = backlog.first().expect("subscriber should receive backlog");
        let second = backlog.get(1).expect("subscriber should receive backlog");
        assert_eq!(first.seq, 2);
        assert_eq!(second.seq, 3);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        assert!(matches!(
            validate_frame_len(MAX_FRAME_SIZE + 1),
            Err(QuicBrokerError::FrameTooLarge(_))
        ));
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
