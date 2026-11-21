//! Persisted, bounded idempotency receipts for durable sends.

use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_control::AgentControlSendMaintenanceDisposition;
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedMutexGuard;

use crate::error::ConnectorError;

/// Maximum number of recent idempotency keys retained for durable-send dedup.
/// Oldest keys are evicted FIFO once the cap is reached; this bounds memory while
/// comfortably covering any plausible in-flight retry window.
pub(crate) const SEND_IDEMPOTENCY_CAPACITY: usize = 1024;

/// Relative path under the connector home for persisted `send_final` idempotency
/// records (`$MARMOT_HOME/dev/send-idempotency.json`).
pub(crate) const SEND_IDEMPOTENCY_FILE: &str = "dev/send-idempotency.json";

/// On-disk schema version for [`SEND_IDEMPOTENCY_FILE`].
const SEND_IDEMPOTENCY_FILE_VERSION: u8 = 1;

type SendIdempotencyGateKey = (String, String);
type SendIdempotencyGates = Arc<Mutex<HashMap<SendIdempotencyGateKey, Weak<SendIdempotencyGate>>>>;
type SendIdempotencyResult = (Vec<String>, AgentControlSendMaintenanceDisposition);

struct SendIdempotencyGate {
    lock: Arc<tokio::sync::Mutex<()>>,
    completed: Mutex<Option<SendIdempotencyResult>>,
}

/// Bounded FIFO map from a client-supplied idempotency key to a server-derived
/// request fingerprint plus the durable message ids produced by the first
/// successful `send_final` for that key.
///
/// A retry that reuses the same key AND matches the recorded fingerprint returns
/// the cached ids without re-sending, so a retry after a post-write timeout cannot
/// double-post an unrecallable encrypted message. A reused key whose fingerprint
/// differs is a cache miss through `acquire`, or a conflict through
/// `acquire_strict` (media sends). Neither returns ids for an unrelated send. Keys are
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
    in_flight: SendIdempotencyGates,
}

pub(crate) enum SendIdempotencyAcquisition {
    Completed(SendIdempotencyResult),
    Leader(SendIdempotencyLeader),
}

pub(crate) enum StrictIdempotencyAcquisition {
    Completed(SendIdempotencyResult),
    Leader(SendIdempotencyLeader),
    Conflict,
}

pub(crate) struct SendIdempotencyLeader {
    _guard: OwnedMutexGuard<()>,
    gate: Arc<SendIdempotencyGate>,
}

impl SendIdempotencyLeader {
    /// Publish the leader's successful result to callers that were already
    /// waiting on this in-process gate. This remains transient so a sequential
    /// reuse of a key with a different fingerprint keeps its legacy cache-miss
    /// behavior.
    pub(crate) fn complete(
        &self,
        message_ids: Vec<String>,
        maintenance_disposition: AgentControlSendMaintenanceDisposition,
    ) {
        *crate::lock_recover(&self.gate.completed) = Some((message_ids, maintenance_disposition));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedSendIdempotencyEntry {
    key: String,
    fingerprint: String,
    message_ids_hex: Vec<String>,
    #[serde(default)]
    maintenance_disposition: AgentControlSendMaintenanceDisposition,
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
    seen: HashMap<String, (String, Vec<String>, AgentControlSendMaintenanceDisposition)>,
    recorded_at: HashMap<String, u64>,
}

impl SendIdempotencyStore {
    pub(crate) fn new(home: &Path) -> Self {
        let store = Self {
            path: home.join(SEND_IDEMPOTENCY_FILE),
            lock: Arc::new(Mutex::new(())),
            inner: Arc::new(Mutex::new(SendIdempotencyInner::default())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        };
        store.load_from_disk();
        store
    }

    /// The message ids and maintenance disposition recorded for `key` by an
    /// earlier successful send, but only when the recorded request `fingerprint`
    /// matches. A key hit with a different fingerprint returns `None` (treated as
    /// a cache miss).
    pub(crate) fn get_with_disposition(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Option<(Vec<String>, AgentControlSendMaintenanceDisposition)> {
        crate::lock_recover(&self.inner)
            .seen
            .get(key)
            .filter(|(recorded, _, _)| {
                constant_time_eq(recorded.as_bytes(), fingerprint.as_bytes())
            })
            .map(|(_, ids, disposition)| (ids.clone(), *disposition))
    }

    #[cfg(test)]
    pub(crate) fn in_flight_participant_count(&self, key: &str, fingerprint: &str) -> usize {
        crate::lock_recover(&self.in_flight)
            .get(&(key.to_owned(), fingerprint.to_owned()))
            .map_or(0, Weak::strong_count)
    }

    /// Serialize matching in-flight sends before their first external side
    /// effect. A follower rechecks the committed cache and the transient gate
    /// result after the leader exits; if the leader failed, the follower becomes
    /// the next leader and may retry.
    ///
    /// The gate includes the fingerprint so the existing behavior for a reused
    /// key with a different request body remains a cache miss rather than
    /// blocking behind or reusing an unrelated send. A leader intentionally
    /// holds its gate across the external send and result recording. Those
    /// operations are not cancelled here because cancellation cannot prove that
    /// an unrecallable send did not land; a follower instead receives
    /// [`ConnectorError::SendInProgress`] after the bounded gate wait.
    pub(crate) async fn acquire(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<SendIdempotencyAcquisition, ConnectorError> {
        if let Some(result) = self.get_with_disposition(key, fingerprint) {
            return Ok(SendIdempotencyAcquisition::Completed(result));
        }

        let gate_key = (key.to_owned(), fingerprint.to_owned());
        let gate = {
            let mut in_flight = crate::lock_recover(&self.in_flight);
            in_flight.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = in_flight.get(&gate_key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(SendIdempotencyGate {
                    lock: Arc::new(tokio::sync::Mutex::new(())),
                    completed: Mutex::new(None),
                });
                in_flight.insert(gate_key, Arc::downgrade(&gate));
                gate
            }
        };
        let guard = crate::with_control_operation_timeout(
            "send_idempotency_wait",
            Arc::clone(&gate.lock).lock_owned(),
        )
        .await
        .map_err(|_| ConnectorError::SendInProgress)?;

        if let Some(result) = self.get_with_disposition(key, fingerprint) {
            return Ok(SendIdempotencyAcquisition::Completed(result));
        }
        if let Some(result) = crate::lock_recover(&gate.completed).clone() {
            return Ok(SendIdempotencyAcquisition::Completed(result));
        }
        Ok(SendIdempotencyAcquisition::Leader(SendIdempotencyLeader {
            _guard: guard,
            gate,
        }))
    }

    /// Acquire an idempotency reservation whose key is permanently bound to
    /// its first fingerprint. Used by media sends; plain `send_final` callers
    /// retain the historical cache-miss semantics of [`Self::acquire`].
    pub(crate) async fn acquire_strict(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<StrictIdempotencyAcquisition, ConnectorError> {
        {
            let inner = crate::lock_recover(&self.inner);
            if let Some((recorded, ids, disposition)) = inner.seen.get(key) {
                return if constant_time_eq(recorded.as_bytes(), fingerprint.as_bytes()) {
                    Ok(StrictIdempotencyAcquisition::Completed((
                        ids.clone(),
                        *disposition,
                    )))
                } else {
                    Ok(StrictIdempotencyAcquisition::Conflict)
                };
            }
        }

        let gate_key = (key.to_owned(), fingerprint.to_owned());
        let gate = {
            let mut in_flight = crate::lock_recover(&self.in_flight);
            in_flight.retain(|_, gate| gate.strong_count() > 0);
            if in_flight
                .iter()
                .any(|((reserved_key, reserved_fingerprint), gate)| {
                    reserved_key == key
                        && reserved_fingerprint != fingerprint
                        && gate.strong_count() > 0
                })
            {
                return Ok(StrictIdempotencyAcquisition::Conflict);
            }
            if let Some(gate) = in_flight.get(&gate_key).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(SendIdempotencyGate {
                    lock: Arc::new(tokio::sync::Mutex::new(())),
                    completed: Mutex::new(None),
                });
                in_flight.insert(gate_key, Arc::downgrade(&gate));
                gate
            }
        };
        let guard = crate::with_control_operation_timeout(
            "strict_send_idempotency_wait",
            Arc::clone(&gate.lock).lock_owned(),
        )
        .await
        .map_err(|_| ConnectorError::SendInProgress)?;

        {
            let inner = crate::lock_recover(&self.inner);
            if let Some((recorded, ids, disposition)) = inner.seen.get(key) {
                return if constant_time_eq(recorded.as_bytes(), fingerprint.as_bytes()) {
                    Ok(StrictIdempotencyAcquisition::Completed((
                        ids.clone(),
                        *disposition,
                    )))
                } else {
                    Ok(StrictIdempotencyAcquisition::Conflict)
                };
            }
        }
        if let Some(result) = crate::lock_recover(&gate.completed).clone() {
            return Ok(StrictIdempotencyAcquisition::Completed(result));
        }
        Ok(StrictIdempotencyAcquisition::Leader(
            SendIdempotencyLeader {
                _guard: guard,
                gate,
            },
        ))
    }

    /// Record the request `fingerprint`, durable message ids, and maintenance
    /// disposition produced for `key`. A repeat record for an existing key keeps
    /// the original entry (the first successful send wins); otherwise the key is
    /// appended and the oldest is evicted once at capacity.
    pub(crate) fn record_with_disposition(
        &self,
        key: String,
        fingerprint: String,
        message_ids: Vec<String>,
        maintenance_disposition: AgentControlSendMaintenanceDisposition,
    ) {
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
            inner.seen.insert(
                key.clone(),
                (fingerprint, message_ids, maintenance_disposition),
            );
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
                let (fingerprint, message_ids_hex, maintenance_disposition) =
                    inner.seen.get(key)?;
                Some(PersistedSendIdempotencyEntry {
                    key: key.clone(),
                    fingerprint: fingerprint.clone(),
                    message_ids_hex: message_ids_hex.clone(),
                    maintenance_disposition: *maintenance_disposition,
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
            (
                entry.fingerprint,
                entry.message_ids_hex,
                entry.maintenance_disposition,
            ),
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
