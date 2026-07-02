//! Active agent text-stream compose sessions, the debug final-send recorder, and idle sweeping.

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_control::AgentControlDebugFinalSend;
use agent_stream_compose::StreamComposeCommand;
use cgka_traits::GroupId;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::error::ConnectorError;
use crate::validation::normalize_hex;

#[derive(Clone, Default)]
pub(crate) struct DebugFinalSendStore {
    sends: Arc<Mutex<Vec<AgentControlDebugFinalSend>>>,
}

impl DebugFinalSendStore {
    pub(crate) fn record(
        &self,
        mut send: AgentControlDebugFinalSend,
    ) -> AgentControlDebugFinalSend {
        let mut sends = self.sends.lock().expect("debug final send lock poisoned");
        let next_id = sends.len() + 1;
        send.message_ids_hex = vec![format!("{next_id:064x}")];
        sends.push(send.clone());
        send
    }

    pub(crate) fn list(&self) -> Vec<AgentControlDebugFinalSend> {
        self.sends
            .lock()
            .expect("debug final send lock poisoned")
            .clone()
    }
}

/// Maximum number of recent idempotency keys retained for durable-send dedup.
/// Oldest keys are evicted FIFO once the cap is reached; this bounds memory while
/// comfortably covering any plausible in-flight retry window.
const SEND_IDEMPOTENCY_CAPACITY: usize = 1024;

/// Relative path under the connector home for persisted `send_final` idempotency
/// records (`$MARMOT_HOME/dev/send-idempotency.json`).
pub(crate) const SEND_IDEMPOTENCY_FILE: &str = "dev/send-idempotency.json";

/// On-disk schema version for [`SEND_IDEMPOTENCY_FILE`].
const SEND_IDEMPOTENCY_FILE_VERSION: u8 = 1;

/// Bounded FIFO map from a client-supplied idempotency key to a server-derived
/// request fingerprint plus the durable message ids produced by the first
/// successful `send_final` for that key.
///
/// A retry that reuses the same key AND matches the recorded fingerprint returns
/// the cached ids without re-sending, so a retry after a post-write timeout cannot
/// double-post an unrecallable encrypted message. A reused key whose fingerprint
/// differs (a different request body under the same key) is treated as a cache
/// miss, so it can never return ids belonging to an unrelated send. Keys are
/// evicted oldest-first once the capacity is reached and the eviction is mirrored
/// to disk.
///
/// Records are persisted under [`SEND_IDEMPOTENCY_FILE`] with crash-safe atomic
/// renames so a connector restart can still dedup a bounded retry window. The
/// store is connector-local (single-host) by design.
#[derive(Clone)]
pub(crate) struct SendIdempotencyStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
    inner: Arc<Mutex<SendIdempotencyInner>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedSendIdempotencyEntry {
    key: String,
    fingerprint: String,
    message_ids_hex: Vec<String>,
    recorded_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedSendIdempotencyFile {
    version: u8,
    entries: Vec<PersistedSendIdempotencyEntry>,
}

#[derive(Default)]
struct SendIdempotencyInner {
    order: std::collections::VecDeque<String>,
    seen: HashMap<String, (String, Vec<String>)>,
    recorded_at: HashMap<String, u64>,
}

impl SendIdempotencyStore {
    pub(crate) fn new(home: &Path) -> Self {
        let store = Self {
            path: home.join(SEND_IDEMPOTENCY_FILE),
            lock: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(SendIdempotencyInner::default())),
        };
        store.load_from_disk();
        store
    }

    /// The message ids recorded for `key` by an earlier successful send, but only
    /// when the recorded request `fingerprint` matches. A key hit with a different
    /// fingerprint returns `None` (treated as a cache miss).
    pub(crate) fn get(&self, key: &str, fingerprint: &str) -> Option<Vec<String>> {
        self.inner
            .lock()
            .expect("send idempotency lock poisoned")
            .seen
            .get(key)
            .filter(|(recorded, _)| recorded == fingerprint)
            .map(|(_, ids)| ids.clone())
    }

    /// Record the request `fingerprint` and durable message ids produced for
    /// `key`. A repeat record for an existing key keeps the original entry (the
    /// first successful send wins); otherwise the key is appended and the oldest
    /// is evicted once at capacity.
    pub(crate) fn record(&self, key: String, fingerprint: String, message_ids: Vec<String>) {
        let should_persist = {
            let mut inner = self.inner.lock().expect("send idempotency lock poisoned");
            if inner.seen.contains_key(&key) {
                return;
            }
            if inner.order.len() >= SEND_IDEMPOTENCY_CAPACITY
                && let Some(evicted) = inner.order.pop_front()
            {
                inner.seen.remove(&evicted);
                inner.recorded_at.remove(&evicted);
            }
            inner.seen.insert(key.clone(), (fingerprint, message_ids));
            inner.recorded_at.insert(key.clone(), unix_timestamp_secs());
            inner.order.push_back(key);
            true
        };
        if !should_persist {
            return;
        }
        // #691: persist OFF the async send hot path. The in-memory entry recorded
        // above already enforces first-write-wins for the lifetime of this process,
        // so the (fs + double-fsync) disk write does not need to block the caller.
        // Durability is therefore at-least-once: a crash after the send returns but
        // before the spawned write lands can lose the on-disk record, so a retry
        // after restart may re-send — acceptable because the in-process dedup covers
        // the common retry window and the record only persists after a successful
        // send. When called outside a tokio runtime (unit tests) we persist inline.
        match tokio::runtime::Handle::try_current() {
            Ok(_) => {
                let store = self.clone();
                tokio::task::spawn_blocking(move || store.persist_to_disk_logged());
            }
            Err(_) => self.persist_to_disk_logged(),
        }
    }

    /// Persist the current records to disk, logging (not propagating) any error.
    /// Used by both the off-hot-path `spawn_blocking` write and the inline fallback.
    fn persist_to_disk_logged(&self) {
        if let Err(err) = self.persist_to_disk() {
            tracing::warn!(
                target: "agent_connector",
                method = "send_idempotency_persist",
                error_code = "persist_failed",
                error = %err,
                "failed to persist send idempotency record"
            );
        }
    }

    fn load_from_disk(&self) {
        let _guard = self.lock.lock().expect("send idempotency lock poisoned");
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "send_idempotency_load",
                    error_code = "read_failed",
                    error = %err,
                    "failed to read send idempotency file; starting empty"
                );
                return;
            }
        };
        match serde_json::from_slice::<PersistedSendIdempotencyFile>(&bytes) {
            Ok(file) if file.version == SEND_IDEMPOTENCY_FILE_VERSION => {
                *self.inner.lock().expect("send idempotency lock poisoned") =
                    inner_from_persisted(file.entries);
            }
            Ok(_unsupported) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "send_idempotency_load",
                    error_code = "unsupported_version",
                    "ignoring send idempotency file with unsupported version; starting empty"
                );
            }
            Err(_err) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "send_idempotency_load",
                    error_code = "corrupt_record",
                    "ignoring corrupt send idempotency file; starting empty"
                );
            }
        }
    }

    fn persist_to_disk(&self) -> Result<(), ConnectorError> {
        let _guard = self.lock.lock().expect("send idempotency lock poisoned");
        let inner = self.inner.lock().expect("send idempotency lock poisoned");
        let entries = inner
            .order
            .iter()
            .filter_map(|key| {
                let (fingerprint, message_ids_hex) = inner.seen.get(key)?;
                Some(PersistedSendIdempotencyEntry {
                    key: key.clone(),
                    fingerprint: fingerprint.clone(),
                    message_ids_hex: message_ids_hex.clone(),
                    recorded_at: *inner.recorded_at.get(key).unwrap_or(&0),
                })
            })
            .collect::<Vec<_>>();
        drop(inner);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        let temp_path = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&PersistedSendIdempotencyFile {
            version: SEND_IDEMPOTENCY_FILE_VERSION,
            entries,
        })?;
        {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        if let Err(err) = std::fs::rename(&temp_path, &self.path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(err.into());
        }
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        if let Some(parent) = self.path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn file_path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn temp_path(&self) -> PathBuf {
        self.path.with_extension("json.tmp")
    }
}

fn inner_from_persisted(entries: Vec<PersistedSendIdempotencyEntry>) -> SendIdempotencyInner {
    let mut inner = SendIdempotencyInner::default();
    for entry in entries {
        if inner.seen.contains_key(&entry.key) {
            continue;
        }
        if inner.order.len() >= SEND_IDEMPOTENCY_CAPACITY
            && let Some(evicted) = inner.order.pop_front()
        {
            inner.seen.remove(&evicted);
            inner.recorded_at.remove(&evicted);
        }
        inner.seen.insert(
            entry.key.clone(),
            (entry.fingerprint, entry.message_ids_hex),
        );
        inner
            .recorded_at
            .insert(entry.key.clone(), entry.recorded_at);
        inner.order.push_back(entry.key);
    }
    inner
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Default)]
pub(crate) struct StreamSessionStore {
    sessions: Arc<Mutex<HashMap<String, ActiveStreamSession>>>,
}

#[derive(Clone)]
pub(crate) struct ActiveStreamSession {
    pub(crate) account_label: String,
    pub(crate) group_id: GroupId,
    pub(crate) stream_id: Vec<u8>,
    pub(crate) start_message_id_hex: String,
    pub(crate) tx: mpsc::Sender<StreamComposeCommand>,
    pub(crate) cancel_tx: mpsc::Sender<()>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) last_activity: Instant,
}

impl StreamSessionStore {
    pub(crate) fn insert(&self, stream_id_hex: String, session: ActiveStreamSession) {
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        if let Some(previous) = sessions.insert(stream_id_hex, session) {
            // Graceful cancel over the dedicated signal: let the replaced
            // session emit its live Abort and self-terminate. The cancel signal
            // can't be starved by a full command queue, so only force-abort if
            // the cancel channel itself is gone.
            match previous.cancel_tx.try_send(()) {
                // Delivered, or a cancel is already queued (`Full`): the session
                // will still observe a cancel and emit its `Abort`, so leave it
                // to self-terminate gracefully.
                Ok(()) | Err(TrySendError::Full(())) => {}
                // The receiver is gone: the session can no longer publish an
                // `Abort`, so force-abort the task to reclaim its resources.
                Err(TrySendError::Closed(())) => previous.abort.abort(),
            }
        }
    }

    pub(crate) fn get(&self, stream_id_hex: &str) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        let session = sessions.get_mut(&stream_id_hex).ok_or_else(|| {
            ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
        })?;
        // Touching the session on any command keeps it alive against the idle sweep.
        session.last_activity = Instant::now();
        Ok(session.clone())
    }

    pub(crate) fn remove(
        &self,
        stream_id_hex: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        self.sessions
            .lock()
            .expect("stream session lock poisoned")
            .remove(&stream_id_hex)
            .ok_or_else(|| {
                ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
            })
    }

    /// Abort and drop every session whose last activity is older than `max_idle`.
    ///
    /// Returns the number of sessions swept. This is what bounds the lifetime of
    /// sessions abandoned when the gateway crashes or restarts mid-stream: each such
    /// session otherwise keeps the compose task, its `mpsc::Sender`, the accumulated
    /// transcript, and (when broker connect succeeded) a dedicated quinn `Endpoint`
    /// UDP socket plus a live keep-alive'd QUIC connection alive forever.
    pub(crate) fn sweep_idle(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_activity) >= max_idle)
            .map(|(stream_id_hex, _)| stream_id_hex.clone())
            .collect();
        for stream_id_hex in &stale {
            if let Some(session) = sessions.remove(stream_id_hex) {
                // Graceful cancel over the dedicated signal so an abandoned
                // session still emits a live `Abort`; only force-abort if the
                // cancel channel is gone. The forced abort is intentionally NOT
                // unconditional here: a successful cancel lets the session flush
                // its Abort and shut itself down.
                match session.cancel_tx.try_send(()) {
                    // Delivered, or a cancel is already queued (`Full`): the
                    // session will still drain a cancel and emit its `Abort`.
                    Ok(()) | Err(TrySendError::Full(())) => {}
                    // The receiver is gone, so no `Abort` can be published:
                    // force-abort to release the held resources.
                    Err(TrySendError::Closed(())) => session.abort.abort(),
                }
            }
        }
        stale.len()
    }
}
