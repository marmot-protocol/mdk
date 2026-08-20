use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fips::native::client::FipsStream;
use fips_message::{HandshakeClient, Limits, Reassembler, SessionId, chunk_message};
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::{sleep, timeout};
use transport_nostr_adapter::{
    FipsRelayApi, FipsRelayApiDiagnostics, FipsRelayApiError, FipsRelayEndpoint,
    FipsRelayNotification, FipsRelaySubscription,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::NativeFipsRelayConfig;
use crate::wire::{
    InboundRelayMessage, parse_relay_message, publish_message, subscription_message,
    unsubscribe_message,
};

const ACTOR_QUEUE: usize = 128;
const NOTIFICATION_BUFFER: usize = 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const SUBSCRIPTION_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const SUBSCRIPTION_EOSE_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLISH_OVERALL_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLISH_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);
const HELLO_RETRY: Duration = Duration::from_millis(250);
const RECONNECT_INITIAL: Duration = Duration::from_millis(250);
const RECONNECT_MAX: Duration = Duration::from_secs(5);
const SESSION_TICK: Duration = Duration::from_millis(250);

/// Native FIPS implementation of MDK's semantic Nostr-relay boundary.
///
/// One supervised WFP1 flow is kept per `fips://<npub>` endpoint. Active
/// subscriptions are replayed after a flow reset. Publications succeed only
/// after the relay returns a matching Nostr `OK true` response.
#[derive(Clone)]
pub struct NativeFipsRelayApi {
    inner: Arc<Inner>,
}

struct Inner {
    config: NativeFipsRelayConfig,
    actors: Mutex<HashMap<FipsRelayEndpoint, mpsc::Sender<ActorCommand>>>,
    diagnostics: Arc<NativeFipsDiagnostics>,
    notifications: broadcast::Sender<FipsRelayNotification>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointConnectionState {
    Connecting,
    Connected,
    Reconnecting,
}

#[derive(Default)]
struct NativeFipsDiagnostics {
    endpoints: Mutex<HashMap<FipsRelayEndpoint, EndpointConnectionState>>,
}

impl NativeFipsDiagnostics {
    fn set(&self, endpoint: &FipsRelayEndpoint, state: EndpointConnectionState) {
        self.endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(endpoint.clone(), state);
    }

    fn remove(&self, endpoint: &FipsRelayEndpoint) {
        self.endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(endpoint);
    }

    fn snapshot(&self) -> FipsRelayApiDiagnostics {
        let endpoints = self
            .endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let connected_endpoints = endpoints
            .values()
            .filter(|state| **state == EndpointConnectionState::Connected)
            .count() as u64;
        let active_endpoints = endpoints.len() as u64;
        FipsRelayApiDiagnostics {
            enabled: true,
            active_endpoints,
            connected_endpoints,
            reconnecting_endpoints: active_endpoints.saturating_sub(connected_endpoints),
        }
    }
}

struct EndpointDiagnosticsGuard {
    endpoint: FipsRelayEndpoint,
    diagnostics: Arc<NativeFipsDiagnostics>,
}

impl Drop for EndpointDiagnosticsGuard {
    fn drop(&mut self) {
        self.diagnostics.remove(&self.endpoint);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.notifications.send(FipsRelayNotification::Shutdown);
    }
}

impl NativeFipsRelayApi {
    pub fn new(config: NativeFipsRelayConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                actors: Mutex::new(HashMap::new()),
                diagnostics: Arc::new(NativeFipsDiagnostics::default()),
                notifications: broadcast::channel(NOTIFICATION_BUFFER).0,
            }),
        }
    }

    fn actor_sender(&self, endpoint: &FipsRelayEndpoint) -> mpsc::Sender<ActorCommand> {
        let mut actors = self
            .inner
            .actors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sender) = actors.get(endpoint)
            && !sender.is_closed()
        {
            return sender.clone();
        }
        let (sender, receiver) = mpsc::channel(ACTOR_QUEUE);
        self.inner
            .diagnostics
            .set(endpoint, EndpointConnectionState::Connecting);
        tokio::spawn(run_endpoint_actor(
            endpoint.clone(),
            self.inner.config.clone(),
            self.inner.diagnostics.clone(),
            self.inner.notifications.clone(),
            receiver,
        ));
        actors.insert(endpoint.clone(), sender.clone());
        sender
    }

    fn forget_closed_actor(&self, endpoint: &FipsRelayEndpoint) {
        let mut actors = self
            .inner
            .actors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if actors.get(endpoint).is_some_and(mpsc::Sender::is_closed) {
            actors.remove(endpoint);
        }
    }

    async fn request(
        &self,
        endpoint: &FipsRelayEndpoint,
        request: ActorRequest,
    ) -> Result<(), FipsRelayApiError> {
        for _ in 0..2 {
            let sender = self.actor_sender(endpoint);
            let (response_tx, response_rx) = oneshot::channel();
            if sender
                .send(ActorCommand {
                    request: request.clone(),
                    response: response_tx,
                })
                .await
                .is_ok()
            {
                return response_rx.await.unwrap_or(Err(FipsRelayApiError::Closed));
            }
            self.forget_closed_actor(endpoint);
        }
        Err(FipsRelayApiError::Unavailable)
    }

    async fn publish_with_retry(
        &self,
        endpoint: &FipsRelayEndpoint,
        event_id: String,
        message: String,
    ) -> Result<(), FipsRelayApiError> {
        let mut retry = RECONNECT_INITIAL;
        let mut last_error = FipsRelayApiError::Unavailable;
        for attempt in 0..3 {
            match self
                .request(
                    endpoint,
                    ActorRequest::Publish {
                        event_id: event_id.clone(),
                        message: message.clone(),
                    },
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(error @ FipsRelayApiError::Rejected)
                | Err(error @ FipsRelayApiError::InvalidResponse) => return Err(error),
                Err(error) => last_error = error,
            }
            if attempt < 2 {
                sleep(retry).await;
                retry = retry.saturating_mul(2).min(RECONNECT_MAX);
            }
        }
        Err(last_error)
    }
}

#[async_trait]
impl FipsRelayApi for NativeFipsRelayApi {
    async fn subscribe(
        &self,
        endpoint: &FipsRelayEndpoint,
        subscription: &FipsRelaySubscription,
    ) -> Result<(), FipsRelayApiError> {
        let request = ActorRequest::Subscribe {
            subscription_id: subscription.subscription_id.clone(),
            message: subscription_message(subscription),
        };
        timeout(
            SUBSCRIPTION_COMMAND_TIMEOUT,
            self.request(endpoint, request),
        )
        .await
        .unwrap_or(Err(FipsRelayApiError::Unavailable))
    }

    async fn unsubscribe(
        &self,
        endpoint: &FipsRelayEndpoint,
        subscription_id: &str,
    ) -> Result<(), FipsRelayApiError> {
        let request = ActorRequest::Unsubscribe {
            subscription_id: subscription_id.to_owned(),
            message: unsubscribe_message(subscription_id),
        };
        timeout(
            SUBSCRIPTION_COMMAND_TIMEOUT,
            self.request(endpoint, request),
        )
        .await
        .unwrap_or(Err(FipsRelayApiError::Unavailable))
    }

    async fn publish_event(
        &self,
        endpoint: &FipsRelayEndpoint,
        event: &NostrTransportEvent,
    ) -> Result<(), FipsRelayApiError> {
        let outbound = publish_message(event).ok_or(FipsRelayApiError::InvalidResponse)?;
        timeout(
            PUBLISH_OVERALL_TIMEOUT,
            self.publish_with_retry(endpoint, outbound.event_id, outbound.message),
        )
        .await
        .unwrap_or(Err(FipsRelayApiError::Unavailable))
    }

    fn notifications(&self) -> broadcast::Receiver<FipsRelayNotification> {
        self.inner.notifications.subscribe()
    }

    fn diagnostics(&self) -> FipsRelayApiDiagnostics {
        self.inner.diagnostics.snapshot()
    }
}

#[derive(Clone)]
enum ActorRequest {
    Subscribe {
        subscription_id: String,
        message: String,
    },
    Unsubscribe {
        subscription_id: String,
        message: String,
    },
    Publish {
        event_id: String,
        message: String,
    },
}

struct ActorCommand {
    request: ActorRequest,
    response: oneshot::Sender<Result<(), FipsRelayApiError>>,
}

impl ActorCommand {
    fn is_abandoned(&self) -> bool {
        self.response.is_closed()
    }
}

struct PendingPublish {
    deadline: Instant,
    response: oneshot::Sender<Result<(), FipsRelayApiError>>,
}

async fn run_endpoint_actor(
    endpoint: FipsRelayEndpoint,
    config: NativeFipsRelayConfig,
    diagnostics: Arc<NativeFipsDiagnostics>,
    notifications: broadcast::Sender<FipsRelayNotification>,
    mut commands: mpsc::Receiver<ActorCommand>,
) {
    let _diagnostics_guard = EndpointDiagnosticsGuard {
        endpoint: endpoint.clone(),
        diagnostics: diagnostics.clone(),
    };
    let mut desired_subscriptions = BTreeMap::<String, String>::new();
    let mut queued = VecDeque::<ActorCommand>::new();
    let mut reconnect_delay = RECONNECT_INITIAL;

    loop {
        queued.retain(|command| !command.is_abandoned());
        if desired_subscriptions.is_empty() && queued.is_empty() {
            let Some(command) = commands.recv().await else {
                return;
            };
            queued.push_back(command);
        }

        let session = match connect_session(&config, &endpoint).await {
            Ok(session) => {
                diagnostics.set(&endpoint, EndpointConnectionState::Connected);
                reconnect_delay = RECONNECT_INITIAL;
                session
            }
            Err(()) => {
                diagnostics.set(&endpoint, EndpointConnectionState::Reconnecting);
                tracing::debug!(
                    target: "transport_fips_native::native",
                    method = "run_endpoint_actor",
                    "native FIPS relay session setup failed; retrying"
                );
                tokio::select! {
                    command = commands.recv() => {
                        let Some(command) = command else { return; };
                        queued.push_back(command);
                    }
                    _ = sleep(reconnect_delay) => {}
                }
                reconnect_delay = reconnect_delay.saturating_mul(2).min(RECONNECT_MAX);
                continue;
            }
        };

        match run_connected(
            session,
            &endpoint,
            &notifications,
            &mut commands,
            &mut queued,
            &mut desired_subscriptions,
        )
        .await
        {
            ConnectedExit::Shutdown => return,
            ConnectedExit::Reconnect => {
                diagnostics.set(&endpoint, EndpointConnectionState::Reconnecting);
                tracing::debug!(
                    target: "transport_fips_native::native",
                    method = "run_endpoint_actor",
                    "native FIPS relay session ended; reconnecting"
                );
            }
        }
    }
}

enum ConnectedExit {
    Shutdown,
    Reconnect,
}

async fn run_connected(
    mut session: ConnectedSession,
    endpoint: &FipsRelayEndpoint,
    notifications: &broadcast::Sender<FipsRelayNotification>,
    commands: &mut mpsc::Receiver<ActorCommand>,
    queued: &mut VecDeque<ActorCommand>,
    desired_subscriptions: &mut BTreeMap<String, String>,
) -> ConnectedExit {
    let mut pending_eose = HashMap::<String, Instant>::new();
    let mut pending_publishes = HashMap::<String, Vec<PendingPublish>>::new();

    for (subscription_id, message) in desired_subscriptions.iter() {
        if session.send_logical(message.as_bytes()).await.is_err() {
            return ConnectedExit::Reconnect;
        }
        pending_eose.insert(
            subscription_id.clone(),
            Instant::now() + SUBSCRIPTION_EOSE_TIMEOUT,
        );
    }

    while let Some(command) = queued.pop_front() {
        if command.is_abandoned() {
            continue;
        }
        if handle_command(
            &mut session,
            command,
            desired_subscriptions,
            &mut pending_eose,
            &mut pending_publishes,
        )
        .await
        .is_err()
        {
            fail_pending_publishes(&mut pending_publishes, FipsRelayApiError::Closed);
            return ConnectedExit::Reconnect;
        }
    }

    let mut tick = tokio::time::interval(SESSION_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    fail_pending_publishes(&mut pending_publishes, FipsRelayApiError::Closed);
                    return ConnectedExit::Shutdown;
                };
                if command.is_abandoned() {
                    continue;
                }
                if handle_command(
                    &mut session,
                    command,
                    desired_subscriptions,
                    &mut pending_eose,
                    &mut pending_publishes,
                ).await.is_err() {
                    fail_pending_publishes(&mut pending_publishes, FipsRelayApiError::Closed);
                    return ConnectedExit::Reconnect;
                }
            }
            received = session.receive_messages() => {
                let messages = match received {
                    Ok(messages) => messages,
                    Err(_) => {
                        fail_pending_publishes(&mut pending_publishes, FipsRelayApiError::Closed);
                        return ConnectedExit::Reconnect;
                    }
                };
                for message in messages {
                    let Some(message) = parse_relay_message(&message) else {
                        fail_pending_publishes(
                            &mut pending_publishes,
                            FipsRelayApiError::InvalidResponse,
                        );
                        return ConnectedExit::Reconnect;
                    };
                    match message {
                        InboundRelayMessage::Event { subscription_id, event } => {
                            if desired_subscriptions.contains_key(&subscription_id) {
                                let _ = notifications.send(FipsRelayNotification::Event {
                                    endpoint: endpoint.clone(),
                                    subscription_id,
                                    event,
                                });
                            }
                        }
                        InboundRelayMessage::EndOfStoredEvents { subscription_id } => {
                            if desired_subscriptions.contains_key(&subscription_id) {
                                pending_eose.remove(&subscription_id);
                                let _ = notifications.send(
                                    FipsRelayNotification::EndOfStoredEvents {
                                        endpoint: endpoint.clone(),
                                        subscription_id,
                                    },
                                );
                            }
                        }
                        InboundRelayMessage::Ok { event_id, accepted } => {
                            if let Some(pending) = pending_publishes.remove(&event_id) {
                                let result = if accepted {
                                    Ok(())
                                } else {
                                    Err(FipsRelayApiError::Rejected)
                                };
                                for publish in pending {
                                    let _ = publish.response.send(result);
                                }
                            }
                        }
                        InboundRelayMessage::Closed { subscription_id } => {
                            if desired_subscriptions.contains_key(&subscription_id) {
                                fail_pending_publishes(
                                    &mut pending_publishes,
                                    FipsRelayApiError::Closed,
                                );
                                return ConnectedExit::Reconnect;
                            }
                        }
                        InboundRelayMessage::Unsupported => {
                            fail_pending_publishes(
                                &mut pending_publishes,
                                FipsRelayApiError::InvalidResponse,
                            );
                            return ConnectedExit::Reconnect;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                if session.expire(now).is_err()
                    || pending_eose.values().any(|deadline| *deadline <= now)
                {
                    fail_pending_publishes(&mut pending_publishes, FipsRelayApiError::Closed);
                    return ConnectedExit::Reconnect;
                }
                let receipt_expired = pending_publishes
                    .values()
                    .flatten()
                    .any(|publish| publish.deadline <= now);
                if receipt_expired {
                    fail_pending_publishes(
                        &mut pending_publishes,
                        FipsRelayApiError::Unavailable,
                    );
                    return ConnectedExit::Reconnect;
                }
            }
        }
    }
}

async fn handle_command(
    session: &mut ConnectedSession,
    command: ActorCommand,
    desired_subscriptions: &mut BTreeMap<String, String>,
    pending_eose: &mut HashMap<String, Instant>,
    pending_publishes: &mut HashMap<String, Vec<PendingPublish>>,
) -> Result<(), ()> {
    match command.request {
        ActorRequest::Subscribe {
            subscription_id,
            message,
        } => {
            if session.send_logical(message.as_bytes()).await.is_err() {
                let _ = command.response.send(Err(FipsRelayApiError::Closed));
                return Err(());
            }
            desired_subscriptions.insert(subscription_id.clone(), message);
            pending_eose.insert(subscription_id, Instant::now() + SUBSCRIPTION_EOSE_TIMEOUT);
            let _ = command.response.send(Ok(()));
        }
        ActorRequest::Unsubscribe {
            subscription_id,
            message,
        } => {
            desired_subscriptions.remove(&subscription_id);
            pending_eose.remove(&subscription_id);
            if session.send_logical(message.as_bytes()).await.is_err() {
                let _ = command.response.send(Err(FipsRelayApiError::Closed));
                return Err(());
            }
            let _ = command.response.send(Ok(()));
        }
        ActorRequest::Publish { event_id, message } => {
            if session.send_logical(message.as_bytes()).await.is_err() {
                let _ = command.response.send(Err(FipsRelayApiError::Closed));
                return Err(());
            }
            pending_publishes
                .entry(event_id)
                .or_default()
                .push(PendingPublish {
                    deadline: Instant::now() + PUBLISH_RECEIPT_TIMEOUT,
                    response: command.response,
                });
        }
    }
    Ok(())
}

fn fail_pending_publishes(
    pending_publishes: &mut HashMap<String, Vec<PendingPublish>>,
    error: FipsRelayApiError,
) {
    for pending in pending_publishes.drain().flat_map(|(_, pending)| pending) {
        let _ = pending.response.send(Err(error));
    }
}

struct ConnectedSession {
    stream: AsyncFd<FipsStream>,
    session_id: SessionId,
    next_message_id: u64,
    reassembler: Reassembler,
    recv_buf: Vec<u8>,
    limits: Limits,
}

impl ConnectedSession {
    async fn send_logical(&mut self, message: &[u8]) -> Result<(), ()> {
        let datagrams = chunk_message(
            self.session_id,
            self.next_message_id,
            message,
            self.recv_buf.len(),
            self.limits,
        )
        .map_err(|_| ())?;
        for datagram in datagrams {
            send_datagram(&self.stream, &datagram)
                .await
                .map_err(|_| ())?;
        }
        self.next_message_id = self.next_message_id.checked_add(1).ok_or(())?;
        Ok(())
    }

    async fn receive_messages(&mut self) -> Result<Vec<Vec<u8>>, ()> {
        let len = recv_datagram(&self.stream, &mut self.recv_buf)
            .await
            .map_err(|_| ())?;
        self.reassembler
            .ingest(&self.recv_buf[..len], Instant::now())
            .map(|messages| {
                messages
                    .into_iter()
                    .map(|message| message.payload)
                    .collect()
            })
            .map_err(|_| ())
    }

    fn expire(&mut self, now: Instant) -> Result<(), ()> {
        self.reassembler.expire(now).map_err(|_| ())
    }
}

async fn connect_session(
    config: &NativeFipsRelayConfig,
    endpoint: &FipsRelayEndpoint,
) -> Result<ConnectedSession, ()> {
    let socket_path = PathBuf::from(config.socket_path());
    let node_key = endpoint.node_pubkey().to_bytes();
    let service_port = config.service_port();
    let stream = tokio::task::spawn_blocking(move || {
        let stream = FipsStream::connect_at(&socket_path, 0, (node_key, service_port))?;
        stream.set_nonblocking(true)?;
        Ok::<_, io::Error>(stream)
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let max_datagram = stream.max_payload();
    let stream = AsyncFd::new(stream).map_err(|_| ())?;
    let session_id = SessionId::from_u128(rand::random());
    let limits = message_limits();
    let mut handshake =
        HandshakeClient::new(session_id, Instant::now(), HELLO_RETRY, SETUP_TIMEOUT)
            .map_err(|_| ())?;
    let mut recv_buf = vec![0u8; max_datagram];

    timeout(SETUP_TIMEOUT + Duration::from_secs(1), async {
        while !handshake.is_ready() {
            if let Some(hello) = handshake.poll(Instant::now()).map_err(|_| ())? {
                send_datagram(&stream, &hello).await.map_err(|_| ())?;
            }
            tokio::select! {
                received = recv_datagram(&stream, &mut recv_buf) => {
                    let len = received.map_err(|_| ())?;
                    handshake.receive(&recv_buf[..len]).map_err(|_| ())?;
                }
                _ = sleep(Duration::from_millis(25)) => {}
            }
        }
        Ok::<(), ()>(())
    })
    .await
    .map_err(|_| ())??;

    Ok(ConnectedSession {
        stream,
        session_id,
        next_message_id: 0,
        reassembler: Reassembler::new(session_id, limits).map_err(|_| ())?,
        recv_buf,
        limits,
    })
}

fn message_limits() -> Limits {
    Limits {
        max_message_size: 128 * 1024,
        max_chunks: 4096,
        max_incomplete_messages: 16,
        max_reassembly_bytes: 8 * 1024 * 1024,
        max_completed_messages: 16,
        incomplete_timeout: Duration::from_secs(30),
    }
}

async fn recv_datagram(stream: &AsyncFd<FipsStream>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut ready = stream.readable().await?;
        match ready.try_io(|inner| inner.get_ref().recv(buf)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

async fn send_datagram(stream: &AsyncFd<FipsStream>, datagram: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = stream.writable().await?;
        match ready.try_io(|inner| inner.get_ref().send(datagram)) {
            Ok(result) => return result,
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(seed: &str) -> FipsRelayEndpoint {
        FipsRelayEndpoint::parse(&format!("fips://{seed}")).expect("valid FIPS endpoint")
    }

    #[test]
    fn diagnostics_report_only_aggregate_connection_state() {
        let diagnostics = NativeFipsDiagnostics::default();
        let connected = endpoint("npub1pq5w2qtanuqfu6xctrqvz6jz5adwa0qyr3wvkfw2xy6yv7fneytq49daxg");
        let reconnecting =
            endpoint("npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266");

        diagnostics.set(&connected, EndpointConnectionState::Connected);
        diagnostics.set(&reconnecting, EndpointConnectionState::Reconnecting);
        assert_eq!(
            diagnostics.snapshot(),
            FipsRelayApiDiagnostics {
                enabled: true,
                active_endpoints: 2,
                connected_endpoints: 1,
                reconnecting_endpoints: 1,
            }
        );

        diagnostics.remove(&reconnecting);
        assert_eq!(diagnostics.snapshot().active_endpoints, 1);
    }
}
