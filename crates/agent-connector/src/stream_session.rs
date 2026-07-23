//! Active agent text-stream compose sessions, the debug final-send recorder, and idle sweeping.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agent_control::AgentControlDebugFinalSend;
use agent_stream_compose::StreamComposeCommand;
use cgka_traits::GroupId;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::watch;

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
        let mut sends = crate::lock_recover(&self.sends);
        let next_id = sends.len() + 1;
        send.message_ids_hex = vec![format!("{next_id:064x}")];
        sends.push(send.clone());
        send
    }

    pub(crate) fn list(&self) -> Vec<AgentControlDebugFinalSend> {
        crate::lock_recover(&self.sends).clone()
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
        crate::lock_recover(&self.inner)
            .seen
            .get(key)
            .filter(|(recorded, _)| constant_time_eq(recorded.as_bytes(), fingerprint.as_bytes()))
            .map(|(_, ids)| ids.clone())
    }

    /// Record the request `fingerprint` and durable message ids produced for
    /// `key`. A repeat record for an existing key keeps the original entry (the
    /// first successful send wins); otherwise the key is appended and the oldest
    /// is evicted once at capacity.
    pub(crate) fn record(&self, key: String, fingerprint: String, message_ids: Vec<String>) {
        let should_persist = {
            let mut inner = crate::lock_recover(&self.inner);
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
                error_kind = err.code(),
                "failed to persist send idempotency record"
            );
        }
    }

    fn load_from_disk(&self) {
        let _guard = crate::lock_recover(&self.lock);
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return,
            Err(err) => {
                tracing::warn!(
                    target: "agent_connector",
                    method = "send_idempotency_load",
                    error_code = "read_failed",
                    error_kind = %err.kind(),
                    "failed to read send idempotency file; starting empty"
                );
                return;
            }
        };
        match serde_json::from_slice::<PersistedSendIdempotencyFile>(&bytes) {
            Ok(file) if file.version == SEND_IDEMPOTENCY_FILE_VERSION => {
                *crate::lock_recover(&self.inner) = inner_from_persisted(file.entries);
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
        let _guard = crate::lock_recover(&self.lock);
        let inner = crate::lock_recover(&self.inner);
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
            // Create missing directories privately, but preserve an existing
            // operator-selected mode: this is also the control-socket parent
            // and may intentionally be group-traversable with token auth.
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(parent)?;
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

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = u8::from(left.len() != right.len());
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

const STREAM_BEGIN_RECEIPT_CAPACITY: usize = 1024;

#[derive(Clone, Default)]
pub(crate) struct StreamSessionStore {
    sessions: Arc<Mutex<HashMap<String, ActiveStreamSession>>>,
    begin_receipts: Arc<Mutex<StreamBeginReceiptStore>>,
}

#[derive(Default)]
struct StreamBeginReceiptStore {
    order: VecDeque<String>,
    by_request_id: HashMap<String, StreamBeginReceipt>,
    in_flight_by_request_id: HashMap<String, InFlightStreamBegin>,
    reserved_stream_ids: HashSet<String>,
}

struct InFlightStreamBegin {
    fingerprint: String,
    stream_id_hex: String,
    completion: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) struct StreamBeginReceipt {
    pub(crate) fingerprint: String,
    pub(crate) stream_id_hex: String,
    pub(crate) stream_capability: String,
    pub(crate) start_message_id_hex: String,
    pub(crate) quic_candidates: Vec<String>,
    pub(crate) policy_max_plaintext_frame_len: Option<u32>,
}

pub(crate) enum StreamBeginReservation {
    Completed(StreamBeginReceipt),
    Wait(watch::Receiver<bool>),
    Leader {
        stream_id: Vec<u8>,
        stream_id_hex: String,
        guard: StreamBeginReservationGuard,
    },
}

pub(crate) struct StreamBeginReservationGuard {
    store: StreamSessionStore,
    request_id: String,
    stream_id_hex: String,
    active: bool,
}

impl StreamBeginReservationGuard {
    pub(crate) fn complete(mut self, receipt: StreamBeginReceipt) {
        let completed =
            self.store
                .complete_stream_begin(&self.request_id, &self.stream_id_hex, receipt);
        debug_assert!(completed, "active StreamBegin reservation must still exist");
        self.active = !completed;
    }
}

impl Drop for StreamBeginReservationGuard {
    fn drop(&mut self) {
        if self.active {
            self.store
                .release_stream_begin(&self.request_id, &self.stream_id_hex);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ActiveStreamSession {
    pub(crate) account_label: String,
    pub(crate) group_id: GroupId,
    pub(crate) stream_id: Vec<u8>,
    pub(crate) stream_capability: [u8; 32],
    pub(crate) start_message_id_hex: String,
    pub(crate) tx: mpsc::Sender<StreamComposeCommand>,
    pub(crate) cancel_tx: mpsc::Sender<()>,
    pub(crate) abort: tokio::task::AbortHandle,
    pub(crate) last_activity: Instant,
    /// Set once the compose task has validated the finalize expectation and
    /// exited. The compose task is then gone, but the durable
    /// `finish_agent_text_stream` publish that follows can still fail; the
    /// retained transcript lets a re-issued `StreamFinalize` retry that publish
    /// without the (dead) compose task, so a transient error never strands the
    /// stream with a live preview and no durable final (#366).
    pub(crate) finalized: Option<FinalizedStream>,
}

/// Frozen finalize inputs retained after the compose task exits, so the durable
/// finish step is retryable and a retry that disagrees with the frozen
/// transcript is rejected.
#[derive(Clone)]
pub(crate) struct FinalizedStream {
    pub(crate) final_text: String,
    pub(crate) transcript_hash: [u8; 32],
    pub(crate) chunk_count: u64,
}

impl StreamSessionStore {
    pub(crate) fn insert_new(
        &self,
        stream_id_hex: String,
        session: ActiveStreamSession,
    ) -> Result<(), ConnectorError> {
        let mut sessions = crate::lock_recover(&self.sessions);
        if sessions.contains_key(&stream_id_hex) {
            return Err(ConnectorError::StreamIdInUse);
        }
        sessions.insert(stream_id_hex, session);
        Ok(())
    }

    pub(crate) fn get_authorized(
        &self,
        stream_id_hex: &str,
        stream_capability: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let mut sessions = crate::lock_recover(&self.sessions);
        let session = sessions
            .get_mut(&stream_id_hex)
            .ok_or(ConnectorError::StreamCapabilityDenied)?;
        if !stream_capability_matches(&session.stream_capability, stream_capability) {
            return Err(ConnectorError::StreamCapabilityDenied);
        }
        // Touching the session on any command keeps it alive against the idle sweep.
        session.last_activity = Instant::now();
        Ok(session.clone())
    }

    pub(crate) fn reserve_stream_begin(
        &self,
        request_id: String,
        fingerprint: String,
        requested_stream_id_hex: Option<String>,
    ) -> Result<StreamBeginReservation, ConnectorError> {
        // Keep the lock order stable: active sessions first, then begin state.
        // No DNS, runtime, or broker work runs while either mutex is held.
        let sessions = crate::lock_recover(&self.sessions);
        let mut receipts = crate::lock_recover(&self.begin_receipts);

        if let Some(receipt) = receipts.by_request_id.get(&request_id) {
            if !constant_time_eq(receipt.fingerprint.as_bytes(), fingerprint.as_bytes()) {
                return Err(ConnectorError::StreamBeginRequestConflict);
            }
            return Ok(StreamBeginReservation::Completed(receipt.clone()));
        }
        if let Some(in_flight) = receipts.in_flight_by_request_id.get(&request_id) {
            if !constant_time_eq(in_flight.fingerprint.as_bytes(), fingerprint.as_bytes()) {
                return Err(ConnectorError::StreamBeginRequestConflict);
            }
            return Ok(StreamBeginReservation::Wait(
                in_flight.completion.subscribe(),
            ));
        }

        let (stream_id, stream_id_hex) = if let Some(stream_id_hex) = requested_stream_id_hex {
            if sessions.contains_key(&stream_id_hex)
                || receipts.reserved_stream_ids.contains(&stream_id_hex)
                || receipts
                    .by_request_id
                    .values()
                    .any(|receipt| receipt.stream_id_hex == stream_id_hex)
            {
                return Err(ConnectorError::StreamIdInUse);
            }
            (hex::decode(&stream_id_hex)?, stream_id_hex)
        } else {
            loop {
                let stream_id = transport_quic_stream::random_stream_id();
                let stream_id_hex = hex::encode(&stream_id);
                if !sessions.contains_key(&stream_id_hex)
                    && !receipts.reserved_stream_ids.contains(&stream_id_hex)
                    && !receipts
                        .by_request_id
                        .values()
                        .any(|receipt| receipt.stream_id_hex == stream_id_hex)
                {
                    break (stream_id, stream_id_hex);
                }
            }
        };
        let (completion, _receiver) = watch::channel(false);
        receipts.reserved_stream_ids.insert(stream_id_hex.clone());
        receipts.in_flight_by_request_id.insert(
            request_id.clone(),
            InFlightStreamBegin {
                fingerprint,
                stream_id_hex: stream_id_hex.clone(),
                completion,
            },
        );
        drop(receipts);
        drop(sessions);

        Ok(StreamBeginReservation::Leader {
            stream_id,
            stream_id_hex: stream_id_hex.clone(),
            guard: StreamBeginReservationGuard {
                store: self.clone(),
                request_id,
                stream_id_hex,
                active: true,
            },
        })
    }

    fn complete_stream_begin(
        &self,
        request_id: &str,
        stream_id_hex: &str,
        receipt: StreamBeginReceipt,
    ) -> bool {
        let mut receipts = crate::lock_recover(&self.begin_receipts);
        let matches = receipts
            .in_flight_by_request_id
            .get(request_id)
            .is_some_and(|in_flight| in_flight.stream_id_hex == stream_id_hex);
        if !matches {
            return false;
        }
        let completion = receipts
            .in_flight_by_request_id
            .remove(request_id)
            .expect("checked in-flight reservation")
            .completion;
        receipts.reserved_stream_ids.remove(stream_id_hex);
        if !receipts.by_request_id.contains_key(request_id) {
            if receipts.order.len() >= STREAM_BEGIN_RECEIPT_CAPACITY
                && let Some(evicted) = receipts.order.pop_front()
            {
                receipts.by_request_id.remove(&evicted);
            }
            receipts.order.push_back(request_id.to_owned());
            receipts
                .by_request_id
                .insert(request_id.to_owned(), receipt);
        }
        drop(receipts);
        let _ = completion.send(true);
        true
    }

    fn release_stream_begin(&self, request_id: &str, stream_id_hex: &str) {
        let mut receipts = crate::lock_recover(&self.begin_receipts);
        let matches = receipts
            .in_flight_by_request_id
            .get(request_id)
            .is_some_and(|in_flight| in_flight.stream_id_hex == stream_id_hex);
        if !matches {
            return;
        }
        let in_flight = receipts
            .in_flight_by_request_id
            .remove(request_id)
            .expect("checked in-flight reservation");
        receipts.reserved_stream_ids.remove(stream_id_hex);
        drop(receipts);
        let _ = in_flight.completion.send(true);
    }

    /// Remove the entry for `stream_id_hex` only when it is still the same
    /// session as `session` (identified by command-channel identity).
    ///
    /// With a get-first finalize flow, an unconditional removal could tear
    /// down a same-stream-id replacement session inserted concurrently
    /// between the `get` and the removal; the channel-identity check makes
    /// the removal a no-op in that case.
    pub(crate) fn remove_if_same(
        &self,
        stream_id_hex: &str,
        session: &ActiveStreamSession,
    ) -> Option<ActiveStreamSession> {
        let mut sessions = crate::lock_recover(&self.sessions);
        match sessions.get(stream_id_hex) {
            Some(entry) if entry.tx.same_channel(&session.tx) => sessions.remove(stream_id_hex),
            _ => None,
        }
    }

    /// Freeze the finalize inputs on the stored entry so a durable-finish failure
    /// can be retried without the compose task, which has exited by this point.
    ///
    /// Returns `true` only when the freeze landed on the still-current session
    /// (matched by command-channel identity). It returns `false` when the entry
    /// was removed or replaced by a same-stream-id session between the caller's
    /// `get` and this call: in that case the caller's session is stale and must
    /// NOT proceed to the durable publish, or a failure there would leave no
    /// retry handle (`finalized` unset) and strand the stream (#366).
    #[must_use]
    pub(crate) fn mark_finalized(
        &self,
        stream_id_hex: &str,
        session: &ActiveStreamSession,
        finalized: FinalizedStream,
    ) -> bool {
        let mut sessions = crate::lock_recover(&self.sessions);
        match sessions.get_mut(stream_id_hex) {
            Some(entry) if entry.tx.same_channel(&session.tx) => {
                entry.finalized = Some(finalized);
                entry.last_activity = Instant::now();
                true
            }
            _ => false,
        }
    }

    pub(crate) fn remove_authorized(
        &self,
        stream_id_hex: &str,
        stream_capability: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let mut sessions = crate::lock_recover(&self.sessions);
        let session = sessions
            .get(&stream_id_hex)
            .ok_or(ConnectorError::StreamCapabilityDenied)?;
        if !stream_capability_matches(&session.stream_capability, stream_capability) {
            return Err(ConnectorError::StreamCapabilityDenied);
        }
        sessions
            .remove(&stream_id_hex)
            .ok_or(ConnectorError::StreamCapabilityDenied)
    }

    #[cfg(test)]
    pub(crate) fn get_for_test(
        &self,
        stream_id_hex: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        crate::lock_recover(&self.sessions)
            .get(&stream_id_hex)
            .cloned()
            .ok_or(ConnectorError::StreamCapabilityDenied)
    }

    #[cfg(test)]
    pub(crate) fn insert(&self, stream_id_hex: String, session: ActiveStreamSession) {
        self.insert_new(stream_id_hex, session)
            .expect("test stream id must be unused");
    }

    #[cfg(test)]
    pub(crate) fn get(&self, stream_id_hex: &str) -> Result<ActiveStreamSession, ConnectorError> {
        self.get_for_test(stream_id_hex)
    }

    #[cfg(test)]
    pub(crate) fn remove(
        &self,
        stream_id_hex: &str,
    ) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        crate::lock_recover(&self.sessions)
            .remove(&stream_id_hex)
            .ok_or(ConnectorError::StreamCapabilityDenied)
    }

    /// Abort and drop every session whose last activity is older than `max_idle`.
    ///
    /// Returns the number of sessions swept. This is what bounds the lifetime of
    /// sessions abandoned when the gateway crashes or restarts mid-stream: each such
    /// session otherwise keeps the compose task, its `mpsc::Sender`, the accumulated
    /// transcript, and (when broker connect succeeded) a dedicated quinn `Endpoint`
    /// UDP socket plus a live keep-alive'd QUIC connection alive forever.
    ///
    /// A session whose transcript has been finalized is NEVER swept: its compose
    /// task has already exited and the frozen transcript is the only handle for
    /// retrying a durable finish that failed. Sweeping it would recreate the
    /// exact #366 failure mode (a published live preview with no durable final
    /// and no way to retry), so a finalized session lives until its durable
    /// finish succeeds or the connector restarts.
    pub(crate) fn sweep_idle(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut sessions = crate::lock_recover(&self.sessions);
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| {
                session.finalized.is_none() && now.duration_since(session.last_activity) >= max_idle
            })
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

fn stream_capability_matches(expected: &[u8; 32], provided_hex: &str) -> bool {
    let decoded = hex::decode(provided_hex).unwrap_or_default();
    let mut provided = [0u8; 32];
    if decoded.len() == provided.len() {
        provided.copy_from_slice(&decoded);
    }
    let mut difference = u8::from(decoded.len() != provided.len());
    for (expected_byte, provided_byte) in expected.iter().zip(provided) {
        difference |= expected_byte ^ provided_byte;
    }
    difference == 0
}

pub(crate) fn normalize_stream_capability(provided_hex: &str) -> Result<String, ConnectorError> {
    let decoded = hex::decode(provided_hex).map_err(|_| ConnectorError::StreamCapabilityDenied)?;
    if decoded.len() != 32 {
        return Err(ConnectorError::StreamCapabilityDenied);
    }
    Ok(hex::encode(decoded))
}
