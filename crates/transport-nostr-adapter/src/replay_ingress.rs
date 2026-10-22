//! Ordered native input owned independently of an app receive future.

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as StdMutex, Weak};

/// Single account consumer of complete, chronologically ordered group ranges.
/// Unacknowledged frames remain owned when a receive future is cancelled.
pub struct ReplayIngress {
    shared: Arc<ReplayIngressState>,
    state: Weak<RwLock<AdapterState>>,
    account: MemberId,
    consumer: Arc<ReplayConsumer>,
}

/// Whether a complete native range can be admitted at this boundary.
pub enum ReplayBatchTake {
    /// A complete group range, retained until acknowledgement or lease return.
    Ready(ReplayBatch),
    /// The issued group range still owes an ordering boundary.
    Pending,
    /// No native range precedes other recovered input.
    Empty,
}

/// One complete group range. Borrow its current frame through ordinary ingest,
/// then acknowledge it. Dropping the lease returns the unacknowledged suffix.
pub struct ReplayBatch {
    data: Option<ReplayBatchData>,
    shared: Arc<ReplayIngressState>,
    state: Weak<RwLock<AdapterState>>,
    account: MemberId,
    _consumer: Arc<ReplayConsumer>,
}

struct ReplayConsumer {
    shared: Weak<ReplayIngressState>,
    serial: u64,
}

struct ReplayBatchData {
    id: u64,
    group: GroupId,
    deliveries: VecDeque<ReplayFrame>,
    bytes: usize,
    scope: Arc<AtomicBool>,
    gate: Arc<AtomicBool>,
}

struct ReplayFrame {
    delivery: TransportDelivery,
    origin: ReplayFrameOrigin,
}

impl ReplayFrame {
    fn key(&self) -> (Timestamp, &[u8]) {
        (
            self.delivery.message.timestamp,
            self.delivery.message.id.as_slice(),
        )
    }
}

impl ReplayBatchData {
    fn merge(&mut self, frames: Vec<ReplayFrame>, bytes: usize) {
        self.bytes += bytes;
        if frames.is_empty() {
            return;
        }
        if self.deliveries.is_empty() {
            self.deliveries = frames.into();
            return;
        }
        if self
            .deliveries
            .back()
            .is_none_or(|last| last.key() < frames[0].key())
        {
            self.deliveries.extend(frames);
            return;
        }
        if self
            .deliveries
            .front()
            .is_some_and(|first| frames.last().expect("incoming frame").key() < first.key())
        {
            self.deliveries.reserve(frames.len());
            for frame in frames.into_iter().rev() {
                self.deliveries.push_front(frame);
            }
            return;
        }
        let mut merged = VecDeque::with_capacity(self.deliveries.len() + frames.len());
        let mut old = std::mem::take(&mut self.deliveries).into_iter().peekable();
        let mut new = frames.into_iter().peekable();
        while let (Some(a), Some(b)) = (old.peek(), new.peek()) {
            match a.key().cmp(&b.key()) {
                std::cmp::Ordering::Less => merged.push_back(old.next().expect("old native frame")),
                std::cmp::Ordering::Greater => {
                    merged.push_back(new.next().expect("new native frame"))
                }
                std::cmp::Ordering::Equal => {
                    let mut kept = old.next().expect("old native frame");
                    let duplicate = new.next().expect("duplicate native frame");
                    if duplicate.origin == ReplayFrameOrigin::Retained {
                        kept.origin = ReplayFrameOrigin::Retained;
                    }
                    self.bytes -= duplicate.delivery.message.payload.len();
                    merged.push_back(kept);
                }
            }
        }
        merged.extend(old);
        merged.extend(new);
        self.deliveries = merged;
    }
}

struct ReplayGroupSlot {
    batch: u64,
    ready: Option<u64>,
    gate: Arc<AtomicBool>,
}

#[derive(Default)]
struct ReplayIngressQueue {
    consumer: Option<u64>,
    next_consumer: u64,
    next_batch: u64,
    next_ready: u64,
    scope: Option<Arc<AtomicBool>>,
    ready: BTreeMap<u64, ReplayBatchData>,
    retained: Vec<TransportDelivery>,
    groups: HashMap<GroupId, ReplayGroupSlot>,
    items: usize,
    bytes: usize,
}

impl ReplayIngressQueue {
    fn push_ready(&mut self, mut data: ReplayBatchData) {
        if data.id == 0 {
            self.next_batch = self.next_batch.checked_add(1).expect("native batch serial");
            data.id = self.next_batch;
        }
        self.next_ready = self.next_ready.checked_add(1).expect("native ready serial");
        if let Some(slot) = self.groups.get_mut(&data.group) {
            slot.batch = data.id;
            slot.ready = Some(self.next_ready);
        } else {
            self.groups.insert(
                data.group.clone(),
                ReplayGroupSlot {
                    batch: data.id,
                    ready: Some(self.next_ready),
                    gate: data.gate.clone(),
                },
            );
        }
        self.ready.insert(self.next_ready, data);
    }

    fn take_serial(&mut self, serial: u64) -> Option<ReplayBatchData> {
        let data = self.ready.remove(&serial)?;
        self.groups
            .get_mut(&data.group)
            .expect("queued native group")
            .ready = None;
        data.gate.store(true, Ordering::Release);
        Some(data)
    }

    fn release_group(&mut self, data: &ReplayBatchData) {
        if self
            .groups
            .get(&data.group)
            .is_some_and(|slot| slot.batch == data.id)
        {
            self.groups.remove(&data.group);
        }
    }

    fn retain_closed_batch(&mut self, mut data: ReplayBatchData) {
        self.release_group(&data);
        for frame in data.deliveries.drain(..) {
            if frame.origin == ReplayFrameOrigin::Retained {
                self.retained.push(frame.delivery);
            } else {
                self.items -= 1;
                self.bytes -= frame.delivery.message.payload.len();
            }
        }
    }

    fn release_detached(&mut self) {
        if self.consumer.is_some()
            || self
                .scope
                .as_ref()
                .is_some_and(|scope| scope.load(Ordering::Acquire))
        {
            return;
        }
        // These frames have durable spill/receipt copies. Closing the last
        // consumer releases the cache; another activation reloads those rows.
        let retained = std::mem::take(&mut self.retained);
        self.items -= retained.len();
        self.bytes -= retained
            .iter()
            .map(|delivery| delivery.message.payload.len())
            .sum::<usize>();
    }
}

#[derive(Default)]
pub(super) struct ReplayIngressState {
    queue: StdMutex<ReplayIngressQueue>,
    wake: Arc<Notify>,
    changed: AtomicBool,
}

impl ReplayIngressState {
    pub(super) fn held(&self) -> (usize, usize) {
        let queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        (queue.items, queue.bytes)
    }

    fn group_pending(&self, group: &GroupId) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .groups
            .contains_key(group)
    }

    pub(super) fn queued(&self, group: &GroupId) -> bool {
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .groups
            .get(group)
            .is_some_and(|slot| slot.ready.is_some())
    }

    pub(super) fn invalidate_group(&self, group: &GroupId) {
        if let Some(slot) = self
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .groups
            .get(group)
        {
            slot.gate.store(false, Ordering::Release);
        }
    }

    fn take_queued(&self, group: &GroupId) -> Option<ReplayBatchData> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let serial = queue.groups.get(group)?.ready?;
        let data = queue.take_serial(serial)?;
        queue.items -= data.deliveries.len();
        queue.bytes -= data.bytes;
        Some(data)
    }

    fn retain(&self, delivery: TransportDelivery) {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        queue.items += 1;
        queue.bytes += delivery.message.payload.len();
        queue.retained.push(delivery);
    }

    fn take_retained(&self) -> Vec<TransportDelivery> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let retained = std::mem::take(&mut queue.retained);
        queue.items -= retained.len();
        queue.bytes -= retained
            .iter()
            .map(|delivery| delivery.message.payload.len())
            .sum::<usize>();
        retained
    }

    fn return_batch(&self, data: ReplayBatchData) {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if data.deliveries.is_empty() {
            queue.release_group(&data);
        } else if data.scope.load(Ordering::Acquire) {
            // No second batch of this group can queue until this one drains.
            // Returning at the tail therefore preserves group order and lets
            // independent ready groups take their next bounded admission turn.
            queue.push_ready(data);
        } else {
            queue.retain_closed_batch(data);
        }
        queue.release_detached();
        drop(queue);
        self.changed.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    fn retain_closed(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        // Replacement retires old queued batches before new input can queue.
        while queue
            .ready
            .first_key_value()
            .is_some_and(|(_, data)| !data.scope.load(Ordering::Acquire))
        {
            let (_, data) = queue.ready.pop_first().expect("queued native batch");
            queue.retain_closed_batch(data);
        }
        queue.release_detached();
    }

    fn enqueue(&self, data: ReplayBatchData) {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        queue.items += data.deliveries.len();
        queue.bytes += data.bytes;
        queue.push_ready(data);
    }
}

impl ReplayIngress {
    /// Whether the source scope closed after this ingress was activated.
    /// Before first activation there is no closed scope.
    pub fn is_closed(&self) -> bool {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .scope
            .as_ref()
            .is_some_and(|scope| !scope.load(Ordering::Acquire))
    }

    /// Take one group's ready range, or the next fair range when no group is
    /// selected. Pending is an ordering fence, not end of input. The account's
    /// replay-change watch announces later range and admission progress.
    pub async fn take_batch(&mut self, group: Option<&GroupId>) -> ReplayBatchTake {
        let Some(state) = self.state.upgrade() else {
            return ReplayBatchTake::Empty;
        };
        let mut guard = state.write().await;
        let Some(coverage) = guard.account_replay_coverage.get_mut(&self.account) else {
            return ReplayBatchTake::Empty;
        };
        coverage.admit_retained();
        if coverage.buffered_items > coverage.outbox.len() {
            coverage.queue_owner_batches();
        }
        let data = {
            let mut queue = self.shared.queue.lock().unwrap_or_else(|p| p.into_inner());
            if queue.consumer != Some(self.consumer.serial) {
                return ReplayBatchTake::Empty;
            }
            let allowed = |data: &ReplayBatchData| {
                coverage
                    .groups
                    .get(&data.group)
                    .is_none_or(|group| coverage.group_ready(group))
            };
            let serial = match group {
                Some(group) => queue
                    .groups
                    .get(group)
                    .and_then(|slot| slot.ready)
                    .filter(|serial| queue.ready.get(serial).is_some_and(allowed)),
                None => queue
                    .ready
                    .iter()
                    .find(|(_, data)| allowed(data))
                    .map(|(serial, _)| *serial),
            };
            let Some(data) = serial.and_then(|serial| queue.take_serial(serial)) else {
                return if group.is_some_and(|group| {
                    queue.groups.contains_key(group)
                        || coverage
                            .groups
                            .get(group)
                            .is_some_and(|group| !coverage.group_ready(group))
                }) {
                    ReplayBatchTake::Pending
                } else {
                    ReplayBatchTake::Empty
                };
            };
            data
        };
        ReplayBatchTake::Ready(ReplayBatch {
            data: Some(data),
            shared: self.shared.clone(),
            state: self.state.clone(),
            account: self.account.clone(),
            _consumer: self.consumer.clone(),
        })
    }
}

impl Drop for ReplayConsumer {
    fn drop(&mut self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let mut queue = shared.queue.lock().unwrap_or_else(|p| p.into_inner());
        if queue.consumer == Some(self.serial) {
            queue.consumer = None;
            queue.release_detached();
        }
    }
}

impl ReplayBatch {
    /// Current oldest frame. The batch owns it throughout asynchronous ingest.
    /// A closed scope or newly recovered historical range returns no frame.
    /// Drop a revoked loan to merge its suffix at the next complete boundary.
    /// Durable supplements survive closure; discarded remote input retains loss.
    pub fn delivery(&self) -> Option<&TransportDelivery> {
        let data = self.data.as_ref()?;
        if !data.scope.load(Ordering::Acquire) || !data.gate.load(Ordering::Acquire) {
            return None;
        }
        data.deliveries.front().map(|frame| &frame.delivery)
    }

    /// Release only the current successfully ingested (or already-held) frame.
    /// No mutation precedes the async state lock, so cancelled acknowledgement
    /// leaves the same frame available for receipt-based duplicate admission.
    pub async fn acknowledge(&mut self) {
        let state = self.state.upgrade();
        let mut guard = match &state {
            Some(state) => Some(state.write().await),
            None => None,
        };
        let Some(data) = self.data.as_mut() else {
            return;
        };
        let Some(frame) = data.deliveries.pop_front() else {
            return;
        };
        let delivery = frame.delivery;
        data.bytes -= delivery.message.payload.len();
        {
            let mut queue = self.shared.queue.lock().unwrap_or_else(|p| p.into_inner());
            queue.items -= 1;
            queue.bytes -= delivery.message.payload.len();
            if data.deliveries.is_empty() {
                queue.release_group(data);
            }
        }
        if data.scope.load(Ordering::Acquire)
            && let Some(coverage) = guard
                .as_mut()
                .and_then(|state| state.account_replay_coverage.get_mut(&self.account))
        {
            coverage.ack_placement(&delivery.message.id);
        }
        self.shared.changed.store(true, Ordering::Release);
        self.shared.wake.notify_waiters();
    }
}

impl Drop for ReplayBatch {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            self.shared.return_batch(data);
        }
    }
}

impl NostrTransportAdapter {
    /// Register an account's ordered historical-input consumer before activation.
    /// Retained group spill frames supplement source input; they never prove a
    /// remote boundary. This does not issue network I/O or spend retry credit.
    pub async fn open_replay_ingress(
        &self,
        account_id: &MemberId,
        mut retained: Vec<TransportDelivery>,
    ) -> Result<ReplayIngress, TransportAdapterError> {
        for delivery in &retained {
            if &delivery.account_id != account_id
                || delivery.group_id_hint.is_none()
                || delivery.message.id.as_slice().len() != 32
            {
                return Err(TransportAdapterError::InvalidInboundEncoding);
            }
        }
        let mut state = self.state.write().await;
        let current = state.account_replay_coverage.get(account_id);
        let shared = state
            .replay_ingresses
            .get(account_id)
            .cloned()
            .unwrap_or_else(|| {
                Arc::new(ReplayIngressState {
                    wake: current.map_or_else(Arc::default, |coverage| coverage.wake.clone()),
                    ..ReplayIngressState::default()
                })
            });
        shared.retain_closed();
        let mut existing = Vec::new();
        let (consumer, retained_ids) = {
            let mut queue = shared.queue.lock().unwrap_or_else(|p| p.into_inner());
            if queue.consumer.is_some() {
                return Err(TransportAdapterError::Other(
                    "native replay consumer already registered".to_owned(),
                ));
            }
            // A reopened client reads the same durable rows. Keep their owned
            // copy rather than charging the native pool for that copy again.
            let held = queue
                .retained
                .iter()
                .chain(
                    queue
                        .ready
                        .values()
                        .flat_map(|batch| batch.deliveries.iter().map(|frame| &frame.delivery)),
                )
                .map(|delivery| delivery.message.id.as_slice())
                .collect::<HashSet<_>>();
            let mut incoming = HashSet::<[u8; 32]>::new();
            retained.retain(|delivery| {
                let id = delivery
                    .message
                    .id
                    .as_slice()
                    .try_into()
                    .expect("validated native id");
                if !incoming.insert(id) || held.contains(delivery.message.id.as_slice()) {
                    return false;
                }
                let group_id = delivery
                    .group_id_hint
                    .as_ref()
                    .expect("validated native group");
                if current
                    .and_then(|coverage| coverage.groups.get(group_id))
                    .is_some_and(|group| group.events.contains_key(&id))
                {
                    existing.push((group_id.clone(), id));
                    return false;
                }
                true
            });
            drop(held);
            let bytes = retained
                .iter()
                .map(|delivery| delivery.message.payload.len())
                .sum::<usize>();
            let buffered_items = current.map_or(0, |coverage| coverage.buffered_items);
            let buffered_bytes = current.map_or(0, |coverage| coverage.buffered_bytes);
            let releasing_items = current.map_or(0, |coverage| coverage.releasing_items);
            let releasing_bytes = current.map_or(0, |coverage| coverage.releasing_bytes);
            if retained.len() > REPLAY_BUFFER_MAX_ITEMS.saturating_sub(queue.items + buffered_items)
                || bytes > REPLAY_BUFFER_MAX_BYTES.saturating_sub(queue.bytes + buffered_bytes)
                || retained.len()
                    > (2 * REPLAY_BUFFER_MAX_ITEMS)
                        .saturating_sub(queue.items + buffered_items + releasing_items)
                || bytes
                    > (2 * REPLAY_BUFFER_MAX_BYTES)
                        .saturating_sub(queue.bytes + buffered_bytes + releasing_bytes)
            {
                return Err(TransportAdapterError::Other(
                    "retained replay exceeds native input bounds".to_owned(),
                ));
            }
            // A duplicate spill row upgrades the held copy's lifetime. Source
            // replacement must retain it even though no second body was queued.
            for batch in queue.ready.values_mut() {
                for frame in &mut batch.deliveries {
                    let id: &[u8; 32] = frame
                        .delivery
                        .message
                        .id
                        .as_slice()
                        .try_into()
                        .expect("native event id");
                    if incoming.contains(id) {
                        frame.origin = ReplayFrameOrigin::Retained;
                    }
                }
            }
            queue.next_consumer = queue
                .next_consumer
                .checked_add(1)
                .expect("native consumer serial");
            let consumer = queue.next_consumer;
            queue.consumer = Some(consumer);
            queue.items += retained.len();
            queue.bytes += bytes;
            queue.retained.extend(retained);
            (consumer, incoming)
        };
        state
            .replay_ingresses
            .insert(account_id.clone(), shared.clone());
        if let Some(coverage) = state.account_replay_coverage.get_mut(account_id) {
            for id in retained_ids {
                if let Some(origin) = coverage.native_ids.get_mut(&id) {
                    *origin = ReplayFrameOrigin::Retained;
                }
            }
            for (group_id, id) in existing {
                let group = coverage
                    .groups
                    .get_mut(&group_id)
                    .expect("held native group");
                let fresh = group.live.insert(id);
                let event = group.events.get_mut(&id).expect("held native event");
                event.retained = true;
                event.owners += usize::from(fresh);
            }
            coverage.attach_ingress(shared.clone());
            coverage.admit_retained();
            coverage.wake_replay();
        }
        Ok(ReplayIngress {
            consumer: Arc::new(ReplayConsumer {
                shared: Arc::downgrade(&shared),
                serial: consumer,
            }),
            shared,
            state: Arc::downgrade(&self.state),
            account: account_id.clone(),
        })
    }
}

impl AccountReplayCoverage {
    pub(super) fn owner_flushable(&self, id: &GroupId, group: &GroupReplay) -> bool {
        let Some(ingress) = &self.ingress else {
            return !group.events.is_empty() && self.group_ready(group);
        };
        let history = group
            .streams
            .values()
            .any(|stream| !stream.claims.is_empty());
        if group.events.is_empty() && !history {
            return false;
        }
        if !self.group_ready(group) {
            return false;
        }
        if !ingress.group_pending(id) {
            return !group.events.is_empty();
        }
        if ingress.queued(id) && (history || group.events.values().any(|event| event.retained)) {
            return true;
        }
        group.streams.values().any(|stream| {
            stream
                .claims
                .iter()
                .any(|event| self.native_owned(id, event))
        })
    }

    pub(super) fn native_owned(&self, group: &GroupId, id: &[u8; 32]) -> bool {
        self.native_ids.contains_key(id)
            && self
                .unplaced
                .get(id)
                .is_some_and(|groups| groups.contains(group))
    }

    pub(super) fn native_held(&self) -> (usize, usize) {
        self.ingress
            .as_ref()
            .map_or((0, 0), |ingress| ingress.held())
    }

    pub(super) fn native_group_pending(&self, group: &GroupId) -> bool {
        self.ingress
            .as_ref()
            .is_some_and(|ingress| ingress.group_pending(group))
    }

    pub(super) fn attach_ingress(&mut self, ingress: Arc<ReplayIngressState>) {
        self.wake = ingress.wake.clone();
        ingress
            .queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .scope = Some(self.scope.clone());
        self.ingress = Some(ingress);
    }

    pub(super) fn admit_retained(&mut self) {
        let Some(ingress) = self.ingress.clone() else {
            return;
        };
        ingress.retain_closed();
        for delivery in ingress.take_retained() {
            let Some(group_id) = delivery.group_id_hint.as_ref() else {
                continue;
            };
            let Ok(id) = <[u8; 32]>::try_from(delivery.message.id.as_slice()) else {
                self.record_loss(self.retained_since.unwrap_or(0));
                continue;
            };
            let since = delivery.message.timestamp.0;
            self.retained_since = Some(self.retained_since.map_or(since, |floor| floor.min(since)));
            let group = self.groups.entry(group_id.clone()).or_default();
            let claimed = group.live.insert(id);
            match group.events.entry(id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().retained = true;
                    entry.get_mut().owners += usize::from(claimed);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    self.buffered_items += 1;
                    self.buffered_bytes += delivery.message.payload.len();
                    entry.insert(BufferedReplay {
                        delivery,
                        owners: 1,
                        retained: true,
                    });
                }
            }
        }
    }

    pub(super) fn queue_owner_batches(&mut self) {
        let Some(ingress) = self.ingress.clone() else {
            return;
        };
        let ready = self
            .groups
            .iter()
            .filter(|(id, group)| self.owner_flushable(id, group))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for group_id in ready {
            let placed = &self.unplaced;
            let native_ids = &self.native_ids;
            let group = self.groups.get_mut(&group_id).expect("ready native group");
            for stream in group.streams.values_mut() {
                stream.claims.retain(|id| {
                    !(native_ids.contains_key(id)
                        && placed
                            .get(id)
                            .is_some_and(|groups| groups.contains(&group_id)))
                });
            }
            let history = group.events.values().any(|event| event.retained)
                || group
                    .streams
                    .values()
                    .any(|stream| !stream.claims.is_empty());
            if group.events.is_empty()
                || (ingress.group_pending(&group_id) && (!ingress.queued(&group_id) || !history))
            {
                self.refresh_boundaries();
                self.wake_replay();
                continue;
            }
            let mut deliveries = Vec::with_capacity(group.events.len());
            let mut bytes = 0;
            for stream in group.streams.values_mut() {
                stream.claims.clear();
            }
            group.live.clear();
            group.ready_history.clear();
            for (_, event) in group.events.drain() {
                self.buffered_items -= 1;
                self.buffered_bytes -= event.delivery.message.payload.len();
                bytes += event.delivery.message.payload.len();
                deliveries.push(ReplayFrame {
                    delivery: event.delivery,
                    origin: if event.retained {
                        ReplayFrameOrigin::Retained
                    } else {
                        ReplayFrameOrigin::Remote
                    },
                });
            }
            deliveries.sort_unstable_by(|a, b| {
                (
                    a.delivery.message.timestamp,
                    a.delivery.message.id.as_slice(),
                )
                    .cmp(&(
                        b.delivery.message.timestamp,
                        b.delivery.message.id.as_slice(),
                    ))
            });
            let mut data = ingress
                .take_queued(&group_id)
                .unwrap_or_else(|| ReplayBatchData {
                    id: 0,
                    group: group_id.clone(),
                    deliveries: VecDeque::new(),
                    bytes: 0,
                    scope: self.scope.clone(),
                    gate: Arc::new(AtomicBool::new(true)),
                });
            data.merge(deliveries, bytes);
            for frame in &data.deliveries {
                let id = frame
                    .delivery
                    .message
                    .id
                    .as_slice()
                    .try_into()
                    .expect("native event id");
                self.remember_delivery(id);
                self.native_ids.insert(id, frame.origin);
                self.pin_delivery(id, Some(&group_id));
            }
            ingress.enqueue(data);
            self.refresh_boundaries();
            self.wake_replay();
        }
    }

    pub(super) fn retain_native_scope(&mut self) {
        self.scope.store(false, Ordering::Release);
        self.retain_supplements();
        if let Some(ingress) = &self.ingress {
            ingress.retain_closed();
        }
    }

    pub(super) fn retain_supplements(&mut self) {
        let Some(ingress) = &self.ingress else {
            return;
        };
        for group in self.groups.values_mut() {
            for (_, event) in group.events.drain() {
                if event.retained {
                    ingress.retain(event.delivery);
                }
            }
        }
    }

    pub(super) fn publish_native_progress(&self) {
        if self
            .ingress
            .as_ref()
            .is_some_and(|ingress| ingress.changed.swap(false, Ordering::AcqRel))
        {
            self.changes.tx.send_replace(self.wire_generation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoNetwork;

    #[async_trait]
    impl NostrRelayClient for NoNetwork {
        async fn subscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            panic!("ingress registration must not subscribe")
        }

        async fn unsubscribe(&self, _: NostrSubscription) -> Result<(), TransportAdapterError> {
            panic!("ingress registration must not unsubscribe")
        }

        async fn unsubscribe_account(
            &self,
            _: &MemberId,
            _: &[NostrSubscription],
        ) -> Result<(), TransportAdapterError> {
            panic!("ingress registration must not replace an account")
        }

        async fn publish_event(
            &self,
            _: &[TransportEndpoint],
            _: &NostrTransportEvent,
            _: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            panic!("ingress registration must not publish")
        }
    }

    fn delivery(at: u8, subscription: &str) -> TransportDelivery {
        TransportDelivery {
            account_id: MemberId::new(vec![0xA1; 32]),
            group_id_hint: Some(GroupId::new(vec![0; 16])),
            message: TransportMessage {
                id: MessageId::new(vec![at; 32]),
                payload: vec![at],
                timestamp: Timestamp(u64::from(at)),
                causal_deps: Vec::new(),
                source: TransportSource(NOSTR_SOURCE.into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![0; 32],
                },
            },
            received_at: Timestamp(1_000),
            source: TransportDeliverySource {
                transport: TransportSource(NOSTR_SOURCE.into()),
                plane: TransportDeliveryPlane::Group,
                endpoint: Some(TransportEndpoint("wss://native.example".into())),
                subscription_id: Some(subscription.to_owned()),
                wire: None,
            },
        }
    }

    fn coverage(
        state: &AdapterState,
        shared: Arc<ReplayIngressState>,
    ) -> (AccountReplayCoverage, String) {
        let account = MemberId::new(vec![0xA1; 32]);
        let source = NostrSubscription::Group {
            account_id: account.clone(),
            group_id: GroupId::new(vec![0; 16]),
            transport_group_id: vec![0; 32],
            endpoints: vec![TransportEndpoint("wss://native.example".into())],
            since: None,
            attempt: SubscriptionAttempt::INITIAL,
        };
        let id = source.subscription_id();
        let mut coverage = AccountReplayCoverage::new(
            account,
            state.replay_losses.clone(),
            state.source_clock.clone(),
        );
        coverage.attach_ingress(shared);
        coverage.add_subscription(
            id.clone(),
            &source,
            HashMap::from([(RelayIndex(0), RelayReplay::Awaiting)]),
        );
        (coverage, id)
    }

    fn fixture(raw: &[u8]) -> (Arc<RwLock<AdapterState>>, ReplayIngress, String) {
        let mut state = AdapterState::default();
        let shared = Arc::new(ReplayIngressState::default());
        shared.queue.lock().unwrap().consumer = Some(1);
        let (mut coverage, id) = coverage(&state, shared.clone());
        shared.retain(delivery(20, &id));
        shared.retain(delivery(10, &id));
        coverage.admit_retained();
        let (tx, _rx) = mpsc::channel(1);
        for &at in raw {
            coverage.record_stored_event(&id, RelayIndex(0), u64::from(at));
            coverage
                .stage_delivery(
                    delivery(at, &id),
                    Some(RelayIndex(0)),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
        }
        coverage.record_eose(&id, RelayIndex(0), 0);
        state
            .account_replay_coverage
            .insert(MemberId::new(vec![0xA1; 32]), coverage);
        state
            .replay_ingresses
            .insert(MemberId::new(vec![0xA1; 32]), shared.clone());
        let state = Arc::new(RwLock::new(state));
        let ingress = ReplayIngress {
            consumer: Arc::new(ReplayConsumer {
                shared: Arc::downgrade(&shared),
                serial: 1,
            }),
            shared,
            state: Arc::downgrade(&state),
            account: MemberId::new(vec![0xA1; 32]),
        };
        (state, ingress, id)
    }

    async fn ready(ingress: &mut ReplayIngress) -> ReplayBatch {
        match ingress.take_batch(None).await {
            ReplayBatchTake::Ready(batch) => batch,
            _ => panic!("complete native range expected"),
        }
    }

    #[tokio::test]
    async fn lease_drop_preserves_order() {
        let (state, mut ingress, id) = fixture(&[]);
        let mut batch = ready(&mut ingress).await;
        assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(10));
        let (tx, mut rx) = mpsc::channel(1);
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .stage_delivery(delivery(30, &id), None, ReplayInput::Untracked, &tx)
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let guard = state.write().await;
        let task = tokio::spawn(async move {
            batch.acknowledge().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(guard);

        let mut retry = ready(&mut ingress).await;
        assert_eq!(retry.delivery().unwrap().message.timestamp, Timestamp(10));
        retry.acknowledge().await;
        assert_eq!(retry.delivery().unwrap().message.timestamp, Timestamp(20));
        retry.acknowledge().await;
        drop(retry);
        let mut later = ready(&mut ingress).await;
        assert_eq!(later.delivery().unwrap().message.timestamp, Timestamp(30));
        later.acknowledge().await;
        drop(later);
        let state = state.read().await;
        assert!(!state.account_replay_coverage[&ingress.account].admission_pending());
        assert!(state.replay_losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn scope_reopen_merges_inputs() {
        let (state, mut ingress, _) = fixture(&[]);
        let old = ready(&mut ingress).await;
        state
            .write()
            .await
            .account_replay_coverage
            .remove(&ingress.account);
        assert!(old.delivery().is_none());
        drop(old);
        let id = {
            let mut state = state.write().await;
            let (mut coverage, id) = coverage(&state, ingress.shared.clone());
            coverage.admit_retained();
            let (tx, _rx) = mpsc::channel(1);
            for at in [5, 15] {
                coverage.record_stored_event(&id, RelayIndex(0), u64::from(at));
                coverage
                    .stage_delivery(
                        delivery(at, &id),
                        Some(RelayIndex(0)),
                        ReplayInput::History,
                        &tx,
                    )
                    .unwrap();
            }
            state
                .account_replay_coverage
                .insert(ingress.account.clone(), coverage);
            id
        };
        assert!(
            matches!(
                ingress.take_batch(Some(&GroupId::new(vec![0; 16]))).await,
                ReplayBatchTake::Pending
            ),
            "local spill waits for the recovered range"
        );
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let mut merged = ready(&mut ingress).await;
        for at in [5, 10, 15, 20] {
            assert_eq!(merged.delivery().unwrap().message.timestamp, Timestamp(at));
            merged.acknowledge().await;
        }
        assert!(merged.delivery().is_none());
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn native_groups_take_turns() {
        let (state, mut ingress, id) = fixture(&[]);
        let mut first = ready(&mut ingress).await;
        first.acknowledge().await;
        let other_group = GroupId::new(vec![1; 16]);
        let mut other = delivery(15, &id);
        other.group_id_hint = Some(other_group.clone());
        other.message.envelope = TransportEnvelope::GroupMessage {
            transport_group_id: vec![1; 32],
        };
        ingress.shared.retain(other);
        {
            let mut state = state.write().await;
            let coverage = state
                .account_replay_coverage
                .get_mut(&ingress.account)
                .unwrap();
            coverage.admit_retained();
            coverage.queue_owner_batches();
        }
        drop(first);
        let mut other = ready(&mut ingress).await;
        assert_eq!(
            other.delivery().unwrap().group_id_hint.as_ref(),
            Some(&other_group)
        );
        other.acknowledge().await;
        drop(other);
        let last = ready(&mut ingress).await;
        assert_eq!(last.delivery().unwrap().message.timestamp, Timestamp(20));
    }

    async fn reopen_history(
        state: &RwLock<AdapterState>,
        ingress: &ReplayIngress,
        id: &str,
        events: &[u8],
    ) {
        let mut state = state.write().await;
        let coverage = state
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap();
        coverage
            .restart_request(id, RelayIndex(0), ReplayStart::Connection)
            .unwrap();
        let (tx, _rx) = mpsc::channel(1);
        for &at in events {
            coverage.record_stored_event(id, RelayIndex(0), u64::from(at));
            coverage
                .stage_delivery(
                    delivery(at, id),
                    Some(RelayIndex(0)),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
        }
    }

    #[tokio::test]
    async fn empty_lease_keeps_successor() {
        let (state, mut ingress, id) = fixture(&[]);
        let mut old = ready(&mut ingress).await;
        old.acknowledge().await;
        old.acknowledge().await;
        ingress.shared.retain(delivery(30, &id));
        {
            let mut state = state.write().await;
            let coverage = state
                .account_replay_coverage
                .get_mut(&ingress.account)
                .unwrap();
            coverage.admit_retained();
            coverage.queue_owner_batches();
        }
        drop(old);
        let (tx, mut rx) = mpsc::channel(1);
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .stage_delivery(delivery(240, &id), None, ReplayInput::Untracked, &tx)
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let mut next = ready(&mut ingress).await;
        assert_eq!(next.delivery().unwrap().message.timestamp, Timestamp(30));
        next.acknowledge().await;
        drop(next);
        let later = ready(&mut ingress).await;
        assert_eq!(later.delivery().unwrap().message.timestamp, Timestamp(240));
    }

    #[tokio::test]
    async fn queued_history_merges_ranges() {
        let (state, mut ingress, id) = fixture(&[]);
        drop(ready(&mut ingress).await);
        reopen_history(&state, &ingress, &id, &[5, 15, 10]).await;
        let group = GroupId::new(vec![0; 16]);
        assert!(matches!(
            ingress.take_batch(Some(&group)).await,
            ReplayBatchTake::Pending
        ));
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let mut merged = ready(&mut ingress).await;
        assert_eq!(ingress.shared.held(), (4, 4));
        for at in [5, 10, 15, 20] {
            assert_eq!(merged.delivery().unwrap().message.timestamp, Timestamp(at));
            merged.acknowledge().await;
        }
        assert_eq!(ingress.shared.held(), (0, 0));
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn new_history_revokes_loan() {
        let (state, mut ingress, id) = fixture(&[]);
        let old = ready(&mut ingress).await;
        reopen_history(&state, &ingress, &id, &[5]).await;
        assert!(
            old.delivery().is_none(),
            "known older history revokes the outstanding loan"
        );
        drop(old);
        let group = GroupId::new(vec![0; 16]);
        assert!(matches!(
            ingress.take_batch(Some(&group)).await,
            ReplayBatchTake::Pending
        ));
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let mut merged = ready(&mut ingress).await;
        for at in [5, 10, 20] {
            assert_eq!(merged.delivery().unwrap().message.timestamp, Timestamp(at));
            merged.acknowledge().await;
        }
    }

    #[tokio::test]
    async fn new_source_revokes_loan() {
        let (state, mut ingress, _) = fixture(&[]);
        let old = ready(&mut ingress).await;
        let group = GroupId::new(vec![0; 16]);
        let source = NostrSubscription::Group {
            account_id: ingress.account.clone(),
            group_id: group.clone(),
            transport_group_id: vec![1; 32],
            endpoints: vec![TransportEndpoint("wss://native.example".into())],
            since: None,
            attempt: SubscriptionAttempt::INITIAL,
        };
        let id = source.subscription_id();
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .add_subscription(
                id.clone(),
                &source,
                HashMap::from([(RelayIndex(0), RelayReplay::Awaiting)]),
            );
        assert!(
            old.delivery().is_none(),
            "new route metadata must revoke the old frontier before any payload"
        );
        drop(old);
        assert!(matches!(
            ingress.take_batch(Some(&group)).await,
            ReplayBatchTake::Pending
        ));
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let mut batch = ready(&mut ingress).await;
        for at in [10, 20] {
            assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(at));
            batch.acknowledge().await;
        }
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn metadata_pending_revokes_loan() {
        let (state, mut ingress, id) = fixture(&[]);
        let old = ready(&mut ingress).await;
        reopen_history(&state, &ingress, &id, &[]).await;
        assert!(
            old.delivery().is_none(),
            "a pending source fences an unstarted loan before its first payload"
        );
        drop(old);
        let group = GroupId::new(vec![0; 16]);
        assert!(matches!(
            ingress.take_batch(Some(&group)).await,
            ReplayBatchTake::Pending
        ));
        reopen_history(&state, &ingress, &id, &[5]).await;
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let mut merged = ready(&mut ingress).await;
        for at in [5, 10, 20] {
            assert_eq!(merged.delivery().unwrap().message.timestamp, Timestamp(at));
            merged.acknowledge().await;
        }
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cached_live_restart_orders() {
        let mut state = AdapterState::default();
        let (mut coverage, id) = coverage(&state, Arc::default());
        coverage.ingress = None;
        let account = delivery(10, &id).account_id;
        let (tx, mut rx) = mpsc::channel(1);
        for at in [30, 20, 10] {
            coverage.record_stored_event(&id, RelayIndex(0), u64::from(at));
            coverage
                .stage_delivery(
                    delivery(at, &id),
                    Some(RelayIndex(0)),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
        }
        coverage.record_eose(&id, RelayIndex(0), 0);
        coverage.flushing = true;
        let cancellation = coverage.cancellation.clone();
        let wake = coverage.wake.clone();
        state
            .account_replay_coverage
            .insert(account.clone(), coverage);
        let state = Arc::new(RwLock::new(state));
        let supervisor = Arc::new(ReplaySupervisor {
            state: Arc::downgrade(&state),
            relay_client: Arc::new(NoNetwork),
            delivery_tx: tx.clone(),
            account_id: account.clone(),
            cancellation,
            wake,
            monotonic_start: Instant::now(),
        });
        let drain = supervisor.clone();
        let task = tokio::spawn(async move { drain.drain_deliveries().await });
        loop {
            if state.read().await.account_replay_coverage[&account].releasing_items == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        {
            let mut guard = state.write().await;
            let coverage = guard.account_replay_coverage.get_mut(&account).unwrap();
            coverage
                .restart_request(&id, RelayIndex(0), ReplayStart::Connection)
                .unwrap();
            let first = rx
                .try_recv()
                .expect("the first handoff preceded the restart");
            assert_eq!(first.message.timestamp, Timestamp(10));
            coverage.ack_placement(&first.message.id);
            coverage.record_stored_event(&id, RelayIndex(0), 5);
            coverage
                .stage_delivery(
                    delivery(5, &id),
                    Some(RelayIndex(0)),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
        }
        task.await.unwrap();
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "a cached live suffix must not cross newly pending source metadata"
        );
        {
            let mut guard = state.write().await;
            let coverage = guard.account_replay_coverage.get_mut(&account).unwrap();
            assert_eq!((coverage.buffered_items, coverage.releasing_items), (3, 0));
            coverage.record_eose(&id, RelayIndex(0), 0);
        }
        let drain = supervisor.clone();
        let task = tokio::spawn(async move { drain.drain_deliveries().await });
        for at in [5, 20, 30] {
            let frame = rx.recv().await.unwrap();
            assert_eq!(frame.message.timestamp, Timestamp(at));
            state
                .write()
                .await
                .account_replay_coverage
                .get_mut(&account)
                .unwrap()
                .ack_placement(&frame.message.id);
        }
        task.await.unwrap();
        let guard = state.read().await;
        let coverage = &guard.account_replay_coverage[&account];
        assert_eq!((coverage.buffered_items, coverage.releasing_items), (0, 0));
        assert!(!coverage.admission_pending());
        assert!(guard.replay_losses.pending.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn empty_lease_expires_no_loss() {
        let (state, mut ingress, id) = fixture(&[]);
        drop(ready(&mut ingress).await);
        reopen_history(&state, &ingress, &id, &[]).await;
        let group = GroupId::new(vec![0; 16]);
        assert!(matches!(
            ingress.take_batch(Some(&group)).await,
            ReplayBatchTake::Pending
        ));
        tokio::time::advance(REPLAY_PAGE_LIMITS.max_duration).await;
        {
            let mut state = state.write().await;
            let coverage = state
                .account_replay_coverage
                .get_mut(&ingress.account)
                .unwrap();
            coverage.expire_replay(tokio::time::Instant::now());
            assert!(
                !coverage.snapshot().complete(),
                "expiry is not history certification"
            );
        }
        let mut batch = ready(&mut ingress).await;
        for at in [10, 20] {
            assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(at));
            batch.acknowledge().await;
        }
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn alias_ack_precedes_eose() {
        let (state, mut ingress, id) = fixture(&[]);
        let mut batch = ready(&mut ingress).await;
        assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(10));
        // The first frame has already been durably ingested when metadata
        // revokes unstarted input. Withholding its ACK cannot undo MLS state.
        reopen_history(&state, &ingress, &id, &[10]).await;
        assert!(batch.delivery().is_none());
        batch.acknowledge().await;
        drop(batch);
        let mut guard = state.write().await;
        let coverage = guard
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap();
        coverage.record_eose(&id, RelayIndex(0), 0);
        drop(guard);
        let mut batch = ready(&mut ingress).await;
        assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(20));
        batch.acknowledge().await;
        let state = state.read().await;
        let coverage = &state.account_replay_coverage[&ingress.account];
        assert!(coverage.request_admitted(&id, Some(RelayIndex(0))));
        assert!(!coverage.admission_pending());
    }

    #[tokio::test]
    async fn closed_owner_releases_pool() {
        let (state, mut ingress, _) = fixture(&[]);
        let batch = ready(&mut ingress).await;
        let shared = ingress.shared.clone();
        state
            .write()
            .await
            .account_replay_coverage
            .remove(&ingress.account);
        drop(ingress);
        drop(batch);
        assert_eq!(
            shared.held(),
            (0, 0),
            "closed accounts retain no native payload pool"
        );
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty(),
            "durable supplement copies were not lost"
        );
    }

    #[tokio::test]
    async fn live_tail_keeps_native_scope() {
        let (state, mut ingress, id) = fixture(&[]);
        let mut retained = ready(&mut ingress).await;
        retained.acknowledge().await;
        retained.acknowledge().await;
        drop(retained);
        let (tx, mut rx) = mpsc::channel(2);
        {
            let mut guard = state.write().await;
            let coverage = guard
                .account_replay_coverage
                .get_mut(&ingress.account)
                .unwrap();
            coverage
                .stage_delivery(
                    delivery(5, &id),
                    Some(RelayIndex(0)),
                    ReplayInput::Live,
                    &tx,
                )
                .unwrap();
            coverage
                .stage_delivery(delivery(15, &id), None, ReplayInput::Untracked, &tx)
                .unwrap();
            coverage.queue_owner_batches();
        }
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "post-EOSE and untracked group copies stay out of the ordinary queue"
        );
        let batch = ready(&mut ingress).await;
        assert_eq!(batch.delivery().unwrap().message.timestamp, Timestamp(5));
        reopen_history(&state, &ingress, &id, &[]).await;
        assert!(batch.delivery().is_none());
        drop(batch);
        state
            .write()
            .await
            .account_replay_coverage
            .get_mut(&ingress.account)
            .unwrap()
            .record_eose(&id, RelayIndex(0), 0);
        let batch = ready(&mut ingress).await;
        assert_eq!(
            batch.delivery().unwrap().message.timestamp,
            Timestamp(5),
            "same-account source replacement preserves the remote live prefix"
        );
        assert_eq!(ingress.shared.held(), (2, 2));
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty()
        );
        drop(batch);
        state
            .write()
            .await
            .account_replay_coverage
            .remove(&ingress.account);
        assert_eq!(ingress.shared.held(), (0, 0));
        assert_eq!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .get(&ingress.account),
            Some(&NostrNotificationLossFloor::Unbounded),
            "actual account closure still charges discarded remote live bodies"
        );
    }

    #[tokio::test]
    async fn native_spill_upgrades_lease() {
        let (state, mut ingress, id) = fixture(&[5]);
        drop(ready(&mut ingress).await);
        let account = ingress.account.clone();
        drop(ingress);
        let mut adapter = NostrTransportAdapter::new(Arc::new(NoNetwork));
        adapter.state = state.clone();
        let mut reopened = adapter
            .open_replay_ingress(&account, vec![delivery(5, &id)])
            .await
            .unwrap();
        assert_eq!(
            reopened.shared.held(),
            (3, 3),
            "a spill duplicate does not copy the ciphertext"
        );
        {
            let mut state = state.write().await;
            state.account_replay_coverage.remove(&account);
            let (mut coverage, id) = coverage(&state, reopened.shared.clone());
            coverage.admit_retained();
            coverage.record_eose(&id, RelayIndex(0), 0);
            state.account_replay_coverage.insert(account, coverage);
        }
        let mut batch = ready(&mut reopened).await;
        for at in [5, 10, 20] {
            assert_eq!(
                batch.delivery().unwrap().message.timestamp,
                Timestamp(at),
                "a newly durable copy survives source replacement"
            );
            batch.acknowledge().await;
        }
        assert!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .is_empty(),
            "retained spill was not lost"
        );
    }

    #[tokio::test]
    async fn scope_close_records_loss() {
        let (state, mut ingress, _) = fixture(&[5]);
        let batch = ready(&mut ingress).await;
        let shared = ingress.shared.clone();
        let account = ingress.account.clone();
        state.write().await.account_replay_coverage.remove(&account);
        drop(ingress);
        drop(batch);
        assert_eq!(shared.held(), (0, 0));
        assert_eq!(
            state
                .read()
                .await
                .replay_losses
                .pending
                .lock()
                .unwrap()
                .get(&account),
            Some(&NostrNotificationLossFloor::Unbounded)
        );
    }
}
