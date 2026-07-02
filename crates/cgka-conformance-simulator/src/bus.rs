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

use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::MemberId;
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
    /// `StaleReason::AlreadySeen` dedup fires.
    pub fn inject(&self, client: ClientId, msg: TransportMessage) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mb) = inner.mailboxes.get_mut(&client) {
            mb.push(msg);
        }
    }

    /// Number of queued (not yet delivered) messages.
    pub fn queued_len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
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
