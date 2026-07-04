//! Local Marmot agent connector daemon.

mod account;
mod allowlist;
mod bootstrap;
mod connection;
mod error;
mod event_projection;
mod inbound;
mod invite_policy;
mod media_temp;
mod messaging;
mod quic;
mod socket;
mod stream;
mod stream_session;
mod validation;

#[cfg(test)]
mod tests;

pub use bootstrap::{
    BootstrapError, BootstrapOptions, BootstrapResult, DEFAULT_BOOTSTRAP_LABEL,
    DEFAULT_QUIC_CANDIDATE, DEFAULT_RELAYS, default_bootstrap_home, read_bootstrap_auth_token,
    resolve_bootstrap_home, resolve_bootstrap_quic_candidates, resolve_bootstrap_relays,
    resolve_bootstrap_socket, run_bootstrap,
};
pub use error::ConnectorError;
pub use socket::{bind_connector_socket, bind_connector_socket_with_mode, default_socket_path};

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use agent_control::AgentControlEvent;
use marmot_account::AccountHome;
use marmot_app::{MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, broadcast};

// Re-exported at the crate root so `crate::AppMessageQuery` resolves for the white-box tests in
// `src/tests.rs`; the crate's own modules import it from `marmot_app` directly.
#[cfg(test)]
pub(crate) use marmot_app::AppMessageQuery;

use crate::allowlist::AllowlistStore;
use crate::event_projection::InboundCatchUpDriver;
use crate::stream_session::{DebugFinalSendStore, SendIdempotencyStore, StreamSessionStore};
use crate::validation::{endpoint, validate_control_plane_config};

pub(crate) const AGENT_SOCKET_DIR_MODE: u32 = 0o700;
pub(crate) const AGENT_SOCKET_MODE: u32 = 0o600;
pub(crate) const ALLOWLIST_DIR: &str = "agent-allowlist";
pub(crate) const STREAM_COMPOSE_CHANNEL_DEPTH: usize = 32;
pub(crate) const STREAM_COMPOSE_CHUNK_BYTES: usize = 1024;
pub(crate) const INBOUND_CATCH_UP_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const INVITE_POLICY_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const INVITE_POLICY_RETRY_BASE: Duration = Duration::from_secs(5);
pub(crate) const INVITE_POLICY_RETRY_MAX: Duration = Duration::from_secs(300);
/// Maximum time a stream compose session may sit without an append/status/progress
/// command before the sweeper aborts it. Bounds the lifetime of sessions abandoned by
/// a crashed or restarted gateway (fresh ids on restart leave no cleanup path).
pub(crate) const STREAM_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// How often the background sweeper scans for idle stream compose sessions.
pub(crate) const STREAM_SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Maximum age of a decrypted inbound media temp directory before the sweeper
/// removes the whole per-blob dir under `$TMPDIR/marmot-media/`.
pub(crate) const MEDIA_TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
/// How often the background sweeper scans for stale inbound media temp dirs.
pub(crate) const MEDIA_TEMP_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Capacity of the per-subscription delivered-inbound-id cursor used to dedup storage-backed
/// replay after broadcast lag. Comfortably larger than the runtime broadcast channel depth
/// (1024) so every message that could be re-queried after a single overflow is still tracked.
pub(crate) const DELIVERED_INBOUND_CURSOR_CAPACITY: usize = 4096;
pub(crate) const MAX_PROFILE_NAME_CHARS: usize = 80;
/// Default maximum concurrently served control-socket connections. The
/// control plane is local and authenticated, but the threat model includes a
/// prompt-injected/compromised gateway; each connection holds a spawned task
/// plus, for `SubscribeInbound`, runtime/debug subscriptions and a delivered
/// cursor, so beyond the cap new connections are closed instead of accepted.
pub const MAX_CONTROL_CONNECTIONS: usize = 64;

#[derive(Clone, Debug)]
pub struct AgentConnectorConfig {
    pub home: PathBuf,
    pub socket: PathBuf,
    pub socket_dir_mode: u32,
    pub socket_mode: u32,
    pub relays: Vec<String>,
    pub allow_any: bool,
    pub debug_controls: bool,
    pub auth_token: Option<String>,
    /// Cap on concurrently served control connections; connections beyond it
    /// are closed at accept time. Must be nonzero.
    pub max_connections: usize,
    /// Dev/test gate for insecure loopback brokers. When set, a stream-begin
    /// `quic://` candidate whose host is a LITERAL loopback (`localhost` or a
    /// loopback IP literal) may resolve to loopback and connect with
    /// certificate verification disabled (`BrokerServerTrust::InsecureLocal`).
    /// Off by default: agent-supplied candidates must resolve to public
    /// addresses and always verify certificates, so a prompt-injected gateway
    /// cannot steer the connector at local services (SSRF) or downgrade TLS
    /// trust through DNS. See `docs/marmot-architecture/overview/dial-safety.md`.
    pub allow_insecure_local_broker: bool,
    /// Dev/test gate for loopback relay endpoints (e.g. an in-process
    /// `MockRelay` or a local `nostr-rs-relay`). Admits loopback only;
    /// private/link-local/CGNAT relay hosts stay rejected. Off by default:
    /// production rejects non-public relay hosts at the relay-safety chokepoint.
    /// Threaded into the connector's
    /// `MarmotAppConfig::allow_loopback_relay_endpoints`.
    pub allow_loopback_relays: bool,
}

impl AgentConnectorConfig {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let socket = default_socket_path(&home);
        Self {
            home,
            socket,
            socket_dir_mode: AGENT_SOCKET_DIR_MODE,
            socket_mode: AGENT_SOCKET_MODE,
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
            auth_token: None,
            max_connections: MAX_CONTROL_CONNECTIONS,
            allow_insecure_local_broker: false,
            allow_loopback_relays: false,
        }
    }
}

#[derive(Clone)]
pub struct AgentConnector {
    pub(crate) account_home: AccountHome,
    pub(crate) allowlists: AllowlistStore,
    pub(crate) allow_any: bool,
    pub(crate) debug_controls: bool,
    pub(crate) auth_token: Option<String>,
    pub(crate) allow_insecure_local_broker: bool,
    pub(crate) debug_events: broadcast::Sender<AgentControlEvent>,
    pub(crate) debug_final_sends: DebugFinalSendStore,
    pub(crate) idempotency: SendIdempotencyStore,
    pub(crate) streams: StreamSessionStore,
    pub(crate) app: MarmotApp,
    pub(crate) runtime: MarmotAppRuntime,
    pub(crate) inbound_catch_up: InboundCatchUpDriver,
    relays: Vec<String>,
    connection_errors: Arc<AtomicU64>,
    /// Connections closed at accept time because the concurrency cap was hit.
    /// Kept separate from `connection_errors` so expected backpressure does
    /// not muddy fault-rate diagnostics.
    connections_refused: Arc<AtomicU64>,
}

impl AgentConnector {
    pub fn open(config: AgentConnectorConfig) -> Result<Self, ConnectorError> {
        let account_home = AccountHome::open(&config.home);
        let relays = config.relays;
        let app = MarmotApp::with_relays_and_account_home_and_config(
            &config.home,
            relays.clone(),
            account_home.clone(),
            MarmotAppConfig::default()
                .with_allow_loopback_relay_endpoints(config.allow_loopback_relays),
        );
        let runtime = MarmotAppRuntime::new(app.clone());
        let inbound_catch_up = InboundCatchUpDriver::new(runtime.clone());
        let allowlists = AllowlistStore::new(&config.home);
        let (debug_events, _) = broadcast::channel(1024);
        Ok(Self {
            account_home,
            allowlists,
            allow_any: config.allow_any,
            debug_controls: config.debug_controls,
            auth_token: config.auth_token,
            allow_insecure_local_broker: config.allow_insecure_local_broker,
            debug_events,
            debug_final_sends: DebugFinalSendStore::default(),
            idempotency: SendIdempotencyStore::new(&config.home),
            streams: StreamSessionStore::default(),
            app,
            runtime,
            inbound_catch_up,
            relays,
            connection_errors: Arc::new(AtomicU64::new(0)),
            connections_refused: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn serve_once(&self, listener: &UnixListener) -> Result<(), ConnectorError> {
        let (stream, _peer_addr) = listener.accept().await?;
        self.handle_connection(stream).await
    }

    pub async fn start(&self) -> Result<(), ConnectorError> {
        self.runtime.start().await?;
        self.spawn_invite_policy_worker();
        self.spawn_stream_session_sweeper();
        self.spawn_media_temp_sweeper();
        self.ensure_agent_accounts_ready().await?;
        Ok(())
    }

    async fn ensure_agent_accounts_ready(&self) -> Result<(), ConnectorError> {
        let accounts = self.account_home.accounts()?;
        for account in accounts.into_iter().filter(|account| account.local_signing) {
            self.ensure_agent_account_relay_lists(&account.label)
                .await?;
            let has_key_package = !self
                .runtime
                .account_key_packages(&account.label, Vec::new())
                .await?
                .is_empty();
            if !has_key_package {
                self.runtime.publish_key_package(&account.label).await?;
            }
        }
        Ok(())
    }

    async fn ensure_agent_account_relay_lists(
        &self,
        account_ref: &str,
    ) -> Result<(), ConnectorError> {
        let missing_nip65 = self.runtime.account_nip65_relays(account_ref)?.is_empty();
        let missing_inbox = self.runtime.account_inbox_relays(account_ref)?.is_empty();
        if self.relays.is_empty() || (!missing_nip65 && !missing_inbox) {
            return Ok(());
        }

        let relays = self.configured_relay_endpoints();
        if missing_nip65 {
            self.runtime
                .set_account_nip65_relays(account_ref, relays.clone(), relays.clone())
                .await?;
        }
        if missing_inbox {
            self.runtime
                .set_account_inbox_relays(account_ref, relays.clone(), relays)
                .await?;
        }
        Ok(())
    }

    pub(crate) fn configured_relay_endpoints(&self) -> Vec<cgka_traits::TransportEndpoint> {
        self.relays.iter().map(|relay| endpoint(relay)).collect()
    }
}

pub async fn serve_socket(config: AgentConnectorConfig) -> Result<(), ConnectorError> {
    validate_control_plane_config(&config)?;
    let listener = bind_connector_socket_with_mode(
        &config.socket,
        config.socket_dir_mode,
        config.socket_mode,
    )?;
    let max_connections = config.max_connections;
    let connector = AgentConnector::open(config)?;
    connector.start().await?;
    let connection_limiter = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                let connection_error =
                    connector.connection_errors.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "agent_connector",
                    method = "serve_socket",
                    connection_error,
                    error_code = "accept_error",
                    error_kind = ?err.kind(),
                    "accept failed"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        // Bound concurrent per-connection tasks (and the subscriptions and
        // cursors they hold), mirroring the broker's connection limiter:
        // beyond the cap the connection is closed instead of served.
        let Ok(permit) = Arc::clone(&connection_limiter).try_acquire_owned() else {
            let connections_refused = connector
                .connections_refused
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            tracing::warn!(
                target: "agent_connector",
                method = "serve_socket",
                connections_refused,
                error_code = "connection_limit_exceeded",
                "refusing control connection beyond the concurrency cap"
            );
            drop(stream);
            continue;
        };
        let connector = connector.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = connector.handle_connection(stream).await {
                let connection_error =
                    connector.connection_errors.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "agent_connector",
                    method = "serve_socket",
                    connection_error,
                    error_code = err.privacy_safe_code(),
                    "connection failed"
                );
            }
        });
    }
}
