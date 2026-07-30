//! `TransportBus` — an in-memory message bus N clients attach to.
//!
//! Supports several delivery policies:
//! - **Ordered**: FIFO delivery in send order.
//! - **Reverse**: stack — last-sent first.
//! - **SeededRandom**: deterministic shuffle from a seed.
//! - **Partition**: drop messages destined for clients on the partition's
//!   "blocked" side until cleared.
//! - **Duplicate**: emit each message twice (test dedup).
//!
//! The bus is `Send + Sync` and lives behind a single mutex — clients pull
//! their pending mailbox via `mailbox(client_id)`. The harness's `tick()`
//! method drives delivery.
//!
//! Routing model: every group message is broadcast to every attached client
//! EXCEPT the sender. Welcomes are addressed by `TransportEnvelope::Welcome
//! { recipient }` and only delivered to the matching client (post-engine
//! filter). For the canonical "all clients see everything" test bus, set
//! `policy = DeliveryPolicy::Ordered { broadcast_welcomes: true }` to also
//! broadcast welcomes (then the engine's `NotForThisClient` filter kicks
//! in client-side).

use crate::pending_work::BusPendingWorkSnapshot;
use crate::scenario_input_ledger::ScenarioInputMetadata;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{MemberId, MessageId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Stable id assigned by the bus to every attached client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(pub usize);

#[derive(Clone, Debug)]
pub enum DeliveryPolicy {
    /// FIFO send-order delivery. Welcomes target the addressed recipient
    /// only by default; broadcast variant exercises engine-side
    /// `NotForThisClient` filtering.
    Ordered { broadcast_welcomes: bool },
    /// LIFO — last-sent first.
    Reverse,
    /// Deterministic-shuffle from a seed. Useful for proptest scenarios.
    SeededRandom { seed: u64 },
}

#[derive(Clone, Debug)]
struct InFlight {
    sender: ClientId,
    msg: TransportMessage,
}

#[derive(Clone)]
pub struct TransportBus {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    clients: HashMap<ClientId, MemberId>,
    next_client_id: usize,
    queue: Vec<InFlight>,
    policy: DeliveryPolicy,
    /// Per-client pre-delivery buffer.
    mailboxes: HashMap<ClientId, Vec<TransportMessage>>,
    /// If Some, only deliver to clients in this allowlist (partition).
    partition_allowed: Option<std::collections::HashSet<ClientId>>,
    delayed: HashMap<String, Vec<InFlight>>,
    scenario_input_by_transport_id: HashMap<MessageId, ScenarioInputMetadata>,
    scenario_input_by_content_id: HashMap<MessageId, ScenarioInputMetadata>,
    exposed_recipient_counts: HashMap<MessageId, usize>,
}

impl TransportBus {
    pub fn ordered() -> Self {
        Self::with_policy(DeliveryPolicy::Ordered {
            broadcast_welcomes: true,
        })
    }

    pub fn with_policy(policy: DeliveryPolicy) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                clients: HashMap::new(),
                next_client_id: 0,
                queue: Vec::new(),
                policy,
                mailboxes: HashMap::new(),
                partition_allowed: None,
                delayed: HashMap::new(),
                scenario_input_by_transport_id: HashMap::new(),
                scenario_input_by_content_id: HashMap::new(),
                exposed_recipient_counts: HashMap::new(),
            })),
        }
    }

    /// Register a new client by its identity. Returns a stable bus-local id.
    pub fn attach(&self, identity: MemberId) -> ClientId {
        let mut inner = self.inner.lock().unwrap();
        let id = ClientId(inner.next_client_id);
        inner.next_client_id += 1;
        inner.clients.insert(id, identity);
        inner.mailboxes.insert(id, Vec::new());
        id
    }

    /// Send a message into the bus from `sender`. The message becomes
    /// eligible for delivery on the next `step` / `deliver_all`.
    pub fn send(&self, sender: ClientId, msg: TransportMessage) {
        let mut inner = self.inner.lock().unwrap();
        inner.queue.push(InFlight { sender, msg });
    }

    /// Retract every still-undelivered artifact for one pending publication.
    ///
    /// A definite publication failure is valid only while none of the
    /// artifacts has reached a recipient mailbox. Check that precondition
    /// before mutating the queue or delayed sets so a caller cannot partially
    /// retract an already-exposed publication.
    pub(crate) fn retract_undelivered_publication(
        &self,
        sender: ClientId,
        message_ids: &[MessageId],
    ) -> Result<usize, usize> {
        let mut inner = self.inner.lock().unwrap();
        let delivered = message_ids
            .iter()
            .map(|message_id| {
                inner
                    .exposed_recipient_counts
                    .get(message_id)
                    .copied()
                    .unwrap_or_default()
            })
            .sum();
        if delivered > 0 {
            return Err(delivered);
        }

        let queued_before = inner.queue.len();
        inner.queue.retain(|in_flight| {
            in_flight.sender != sender || !message_ids.contains(&in_flight.msg.id)
        });
        let mut retracted = queued_before - inner.queue.len();

        for delayed in inner.delayed.values_mut() {
            let delayed_before = delayed.len();
            delayed.retain(|in_flight| {
                in_flight.sender != sender || !message_ids.contains(&in_flight.msg.id)
            });
            retracted += delayed_before - delayed.len();
        }
        inner.delayed.retain(|_, messages| !messages.is_empty());

        Ok(retracted)
    }

    pub(crate) fn register_scenario_input(
        &self,
        transport_id: MessageId,
        content_id: MessageId,
        mut metadata: ScenarioInputMetadata,
    ) {
        metadata.aliases = vec![transport_id.clone(), content_id.clone()];
        let mut inner = self.inner.lock().unwrap();
        inner
            .scenario_input_by_transport_id
            .insert(transport_id, metadata.clone());
        inner
            .scenario_input_by_content_id
            .insert(content_id, metadata);
    }

    pub(crate) fn scenario_input_for_transport(
        &self,
        message_id: &MessageId,
    ) -> Option<ScenarioInputMetadata> {
        self.inner
            .lock()
            .unwrap()
            .scenario_input_by_transport_id
            .get(message_id)
            .cloned()
    }

    pub(crate) fn scenario_input_for_content(
        &self,
        message_id: &MessageId,
    ) -> Option<ScenarioInputMetadata> {
        self.inner
            .lock()
            .unwrap()
            .scenario_input_by_content_id
            .get(message_id)
            .cloned()
    }

    /// Deliver up to `n` messages from the queue into per-client mailboxes,
    /// honoring the policy + partition.
    pub fn step(&self, n: usize) {
        let mut inner = self.inner.lock().unwrap();
        let policy = inner.policy.clone();
        let partition = inner.partition_allowed.clone();

        // Pick the next batch in policy order.
        let mut batch = take_batch(&mut inner.queue, &policy, n);

        // Snapshot the client list to avoid borrow conflicts during the loop.
        let clients: Vec<(ClientId, MemberId)> =
            inner.clients.iter().map(|(k, v)| (*k, v.clone())).collect();
        let broadcast_welcomes = matches!(
            policy,
            DeliveryPolicy::Ordered {
                broadcast_welcomes: true
            }
        );

        for InFlight { sender, msg } in batch.drain(..) {
            for (cid, ident) in &clients {
                if *cid == sender {
                    continue;
                }
                if let Some(ref allow) = partition
                    && !allow.contains(cid)
                {
                    continue;
                }
                let deliver = match &msg.envelope {
                    TransportEnvelope::Welcome { recipient } => {
                        broadcast_welcomes || recipient == ident
                    }
                    TransportEnvelope::GroupMessage { .. } => true,
                };
                if deliver {
                    inner.mailboxes.get_mut(cid).unwrap().push(msg.clone());
                    *inner
                        .exposed_recipient_counts
                        .entry(msg.id.clone())
                        .or_default() += 1;
                }
            }
        }
    }

    /// Deliver every queued message.
    pub fn deliver_all(&self) {
        loop {
            let pending = {
                let inner = self.inner.lock().unwrap();
                inner.queue.len()
            };
            if pending == 0 {
                break;
            }
            self.step(pending);
        }
    }

    /// Drain a client's pending mailbox.
    pub fn mailbox(&self, client: ClientId) -> Vec<TransportMessage> {
        let mut inner = self.inner.lock().unwrap();
        std::mem::take(inner.mailboxes.get_mut(&client).unwrap())
    }

    /// Restrict deliveries to a subset of clients (the others are
    /// partitioned away). Calling with `None` clears the partition.
    pub fn set_partition(&self, allow: Option<Vec<ClientId>>) {
        let mut inner = self.inner.lock().unwrap();
        inner.partition_allowed = allow.map(|v| v.into_iter().collect());
    }

    /// Inject a previously-captured `TransportMessage` directly into a
    /// specific client's mailbox, bypassing the queue + delivery policy.
    /// This is the hook the proptest "true same-id replay" property uses
    /// to deliver an identical message twice and prove the engine's
    /// the typed duplicate exclusion fires.
    pub fn inject(&self, client: ClientId, msg: TransportMessage) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mb) = inner.mailboxes.get_mut(&client) {
            mb.push(msg.clone());
            *inner.exposed_recipient_counts.entry(msg.id).or_default() += 1;
        }
    }

    /// Number of queued (not yet delivered) messages.
    pub fn queued_len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub(crate) fn pending_work_snapshot(&self, client: ClientId) -> BusPendingWorkSnapshot {
        let inner = self.inner.lock().unwrap();
        let identity = inner
            .clients
            .get(&client)
            .expect("pending-work client is attached");
        BusPendingWorkSnapshot {
            queued_messages: inner
                .queue
                .iter()
                .filter(|in_flight| targets_client(&inner.policy, identity, client, in_flight))
                .count(),
            delayed_messages: inner
                .delayed
                .values()
                .flatten()
                .filter(|in_flight| targets_client(&inner.policy, identity, client, in_flight))
                .count(),
            mailbox_messages: inner.mailboxes.get(&client).map_or(0, Vec::len),
        }
    }

    /// Snapshot queued messages without altering delivery order.
    pub fn queued_messages(&self) -> Vec<TransportMessage> {
        self.inner
            .lock()
            .unwrap()
            .queue
            .iter()
            .map(|in_flight| in_flight.msg.clone())
            .collect()
    }

    /// Drop one queued message by its current queue index.
    pub fn drop_queued(&self, index: usize) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if index >= inner.queue.len() {
            return false;
        }
        inner.queue.remove(index);
        true
    }

    /// Duplicate one queued message, inserting the copy immediately after the
    /// original so FIFO delivery observes the duplicate next.
    pub fn duplicate_queued(&self, index: usize) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(msg) = inner.queue.get(index).cloned() else {
            return false;
        };
        inner.queue.insert(index + 1, msg);
        true
    }

    /// Remove one queued message and hold it under a scenario-visible label.
    pub fn delay_queued(&self, index: usize, delayed: impl Into<String>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if index >= inner.queue.len() {
            return false;
        }
        let msg = inner.queue.remove(index);
        inner.delayed.entry(delayed.into()).or_default().push(msg);
        true
    }

    /// Release delayed messages back to the end of the queue.
    pub fn release_delayed(&self, delayed: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(mut messages) = inner.delayed.remove(delayed) else {
            return false;
        };
        inner.queue.append(&mut messages);
        true
    }

    /// Reorder the entire queue. `order` is a permutation of current queue
    /// indices; each entry names which old queue slot moves into the next
    /// position.
    pub fn reorder_queued(&self, order: &[usize]) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if order.len() != inner.queue.len() {
            return false;
        }
        let mut seen = vec![false; inner.queue.len()];
        let mut reordered = Vec::with_capacity(inner.queue.len());
        for index in order {
            if *index >= inner.queue.len() || seen[*index] {
                return false;
            }
            seen[*index] = true;
            reordered.push(inner.queue[*index].clone());
        }
        inner.queue = reordered;
        true
    }

    /// Reorder the queue per the current policy without delivering. Useful
    /// when a test wants to inspect ordering before stepping.
    pub fn peek_policy(&self) -> DeliveryPolicy {
        self.inner.lock().unwrap().policy.clone()
    }
}

fn targets_client(
    policy: &DeliveryPolicy,
    identity: &MemberId,
    client: ClientId,
    in_flight: &InFlight,
) -> bool {
    if in_flight.sender == client {
        return false;
    }
    match &in_flight.msg.envelope {
        TransportEnvelope::GroupMessage { .. } => true,
        TransportEnvelope::Welcome { recipient } => {
            matches!(
                policy,
                DeliveryPolicy::Ordered {
                    broadcast_welcomes: true
                }
            ) || recipient == identity
        }
    }
}

fn take_batch(queue: &mut Vec<InFlight>, policy: &DeliveryPolicy, n: usize) -> Vec<InFlight> {
    let n = n.min(queue.len());
    match policy {
        DeliveryPolicy::Ordered { .. } => {
            let drained: Vec<_> = queue.drain(..n).collect();
            drained
        }
        DeliveryPolicy::Reverse => {
            let len = queue.len();
            let drained: Vec<_> = queue.drain(len - n..).rev().collect();
            drained
        }
        DeliveryPolicy::SeededRandom { seed } => {
            // Lightweight deterministic shuffle without pulling rand. The
            // hash is specified here so other-language harnesses can match
            // the same seeded delivery order.
            let mut indexed: Vec<(usize, InFlight)> = queue.drain(..).enumerate().collect();
            indexed.sort_by_key(|(i, _)| {
                let mut h = 0xcbf29ce484222325u64;
                for b in seed.to_be_bytes().iter().chain(i.to_be_bytes().iter()) {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(0x100000001b3);
                }
                h
            });
            let mut taken: Vec<InFlight> = Vec::with_capacity(n);
            for (_, m) in indexed.drain(..n) {
                taken.push(m);
            }
            // Anything not taken goes back at the end of the queue, in stable
            // post-shuffle order.
            for (_, m) in indexed {
                queue.push(m);
            }
            taken
        }
    }
}
