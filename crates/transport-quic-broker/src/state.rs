//! In-memory broker room/backlog engine: per-stream rooms, bounded live
//! subscriber queues, retained-backlog accounting, and room-lifecycle cleanup.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cgka_traits::agent_text_stream::AgentTextStreamRecordV1;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::time::{sleep, timeout};

use crate::control::BrokerStreamKey;
use crate::error::QuicBrokerError;
use crate::protocol::{FINISHED_ROOM_TTL, PUBLISH_SUBSCRIBER_GRACE, UNFINISHED_ROOM_TTL};

#[derive(Debug)]
pub(crate) struct BrokerState {
    per_subscriber_queue: usize,
    max_backlog: usize,
    max_rooms: usize,
    max_backlog_bytes: usize,
    replay_ttl: Duration,
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
    /// Append timestamp used to purge entries older than the broker replay
    /// TTL before serving backlog to a new subscriber.
    appended_at: Instant,
}

/// Drop backlog entries older than the replay TTL from the front of the
/// (append-ordered) backlog. Returns the freed byte count so the caller can
/// adjust the global backlog budget. A zero TTL purges everything.
fn purge_expired_backlog(room: &mut BrokerRoom, replay_ttl: Duration) -> usize {
    let mut freed = 0;
    while let Some(front) = room.backlog.front() {
        if front.appended_at.elapsed() < replay_ttl {
            break;
        }
        let dropped = room.backlog.pop_front().expect("front entry checked above");
        room.backlog_bytes = room.backlog_bytes.saturating_sub(dropped.bytes);
        freed += dropped.bytes;
    }
    freed
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: mpsc::Sender<AgentTextStreamRecordV1>,
}

impl BrokerState {
    pub(crate) fn new(
        per_subscriber_queue: usize,
        max_backlog: usize,
        max_rooms: usize,
        max_backlog_bytes: usize,
        replay_ttl: Duration,
    ) -> Self {
        Self {
            per_subscriber_queue,
            max_backlog,
            max_rooms,
            max_backlog_bytes,
            replay_ttl,
            inner: Mutex::new(BrokerStateInner::default()),
        }
    }

    pub(crate) async fn subscribe(
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
        let (freed, backlog) = {
            let room = inner.rooms.entry(key).or_default();
            if room.finished_at.is_none() {
                room.last_activity_at = Instant::now();
            }
            // Purge entries past the replay window before serving backlog: a
            // late subscriber only sees records the replay TTL still covers,
            // and the default TTL of zero serves no backlog at all.
            let freed = purge_expired_backlog(room, self.replay_ttl);
            let backlog: Vec<_> = room
                .backlog
                .iter()
                .map(|entry| entry.record.clone())
                .collect();
            if room.finished_at.is_none() {
                room.subscribers.push(Subscriber { id, tx });
                room.subscriber_notify.notify_waiters();
                room.subscriber_notify.notify_one();
            }
            (freed, backlog)
        };
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(freed);
        Ok((id, backlog, rx))
    }

    pub(crate) async fn unsubscribe(&self, key: &BrokerStreamKey, id: u64) {
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

    pub(crate) async fn publish(
        &self,
        key: &BrokerStreamKey,
        record: AgentTextStreamRecordV1,
    ) -> Result<usize, QuicBrokerError> {
        // The replay window bounds backlog retention: with the default TTL of
        // zero the broker retains nothing and records reach live subscribers
        // only.
        let retain_backlog = !self.replay_ttl.is_zero();
        let record_bytes = if retain_backlog {
            let record_bytes = record.encode()?.len();
            if record_bytes > self.max_backlog_bytes {
                return Err(QuicBrokerError::BacklogRecordTooLarge {
                    record_bytes,
                    limit: self.max_backlog_bytes,
                });
            }
            Some(record_bytes)
        } else {
            None
        };
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
        if retain_backlog {
            let record_bytes = record_bytes.expect("record bytes computed when retaining backlog");
            let freed = purge_expired_backlog(room, self.replay_ttl);
            total_backlog_bytes = total_backlog_bytes.saturating_sub(freed);
            room.backlog.push_back(BacklogRecord {
                record: record.clone(),
                bytes: record_bytes,
                appended_at: Instant::now(),
            });
            room.backlog_bytes += record_bytes;
            total_backlog_bytes += record_bytes;
            while room.backlog.len() > self.max_backlog
                || total_backlog_bytes > self.max_backlog_bytes
            {
                let Some(dropped) = room.backlog.pop_front() else {
                    break;
                };
                room.backlog_bytes = room.backlog_bytes.saturating_sub(dropped.bytes);
                total_backlog_bytes = total_backlog_bytes.saturating_sub(dropped.bytes);
            }
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

    pub(crate) async fn wait_for_subscriber(
        &self,
        key: &BrokerStreamKey,
    ) -> Result<(), QuicBrokerError> {
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

    pub(crate) async fn drop_room(&self, key: &BrokerStreamKey) {
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

    pub(crate) async fn finish_room(self: &Arc<Self>, key: &BrokerStreamKey) {
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
        let mut freed = 0;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.subscribers.clear();
            freed = purge_expired_backlog(room, self.replay_ttl);
            should_remove = room.backlog.is_empty();
            if !should_remove {
                let now = Instant::now();
                room.finished_at = Some(now);
                room.last_activity_at = now;
                should_retain = true;
            }
        }
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(freed);
        if should_remove {
            remove_room(&mut inner, key);
        }
        should_retain
    }

    pub(crate) async fn drop_expired_finished_room(&self, key: &BrokerStreamKey) {
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
        // Retained rooms also drop backlog entries past the replay window so
        // the broker never holds replay data beyond `replay_ttl`.
        let replay_ttl = self.replay_ttl;
        let mut total_backlog_bytes = 0;
        inner.rooms.retain(|_, room| {
            let retain = if let Some(finished_at) = room.finished_at {
                finished_at.elapsed() < FINISHED_ROOM_TTL
            } else {
                !room.subscribers.is_empty()
                    || room.last_activity_at.elapsed() < UNFINISHED_ROOM_TTL
            };
            if retain {
                purge_expired_backlog(room, replay_ttl);
                total_backlog_bytes += room.backlog_bytes;
            }
            retain
        });
        inner.total_backlog_bytes = total_backlog_bytes;
    }

    #[cfg(test)]
    pub(crate) async fn room_count(&self) -> usize {
        self.inner.lock().await.rooms.len()
    }

    #[cfg(test)]
    pub(crate) async fn backlog_bytes_for_test(&self) -> usize {
        self.inner.lock().await.total_backlog_bytes
    }

    #[cfg(test)]
    pub(crate) async fn age_finished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            room.finished_at = Some(Instant::now().checked_sub(age).unwrap());
        }
    }

    #[cfg(test)]
    pub(crate) async fn age_unfinished_room_for_test(&self, key: &BrokerStreamKey, age: Duration) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key)
            && room.finished_at.is_none()
        {
            room.last_activity_at = Instant::now().checked_sub(age).unwrap();
        }
    }

    #[cfg(test)]
    pub(crate) async fn age_oldest_backlog_for_test(
        &self,
        key: &BrokerStreamKey,
        count: usize,
        age: Duration,
    ) {
        let mut inner = self.inner.lock().await;
        if let Some(room) = inner.rooms.get_mut(key) {
            for entry in room.backlog.iter_mut().take(count) {
                entry.appended_at = Instant::now().checked_sub(age).unwrap();
            }
        }
    }
}

fn remove_room(inner: &mut BrokerStateInner, key: &BrokerStreamKey) {
    if let Some(room) = inner.rooms.remove(key) {
        inner.total_backlog_bytes = inner.total_backlog_bytes.saturating_sub(room.backlog_bytes);
    }
}
