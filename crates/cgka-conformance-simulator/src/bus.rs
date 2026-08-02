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

use crate::pending_work::{BusPendingWorkSnapshot, BusStructuralProgressSnapshot};
use crate::scenario_input_ledger::ScenarioInputMetadata;
use crate::{ScenarioMessageSelectorV2, ScenarioTransportClass};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{MemberId, MessageId};
use std::collections::{HashMap, VecDeque};
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

#[derive(Clone, Debug)]
pub(crate) struct OutboundEmission {
    pub sequence: u64,
    pub msg: TransportMessage,
}

pub(crate) struct CapturedOutboundWindow {
    pub observed_objects: u64,
    pub observed_json_bytes: u64,
    pub emissions: Vec<(ClientId, OutboundEmission)>,
}

#[derive(Clone)]
pub struct TransportBus {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    clients: HashMap<ClientId, MemberId>,
    next_client_id: usize,
    next_outbound_sequence: u64,
    queue: Vec<InFlight>,
    /// Append-only observation of transport artifacts emitted by each
    /// participant. This is deliberately separate from the mutable delivery
    /// queue so a black-box subject can expose publication work without
    /// leaking queue indices or fault-injection internals.
    outbound_emissions: HashMap<ClientId, Vec<OutboundEmission>>,
    /// Bounded forensic evidence, separate from outbound lifecycle state.
    captured_outbound_tail: VecDeque<(ClientId, OutboundEmission, u64)>,
    captured_outbound_json_bytes: u64,
    observed_outbound_objects: u64,
    observed_outbound_json_bytes: u64,
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
                next_outbound_sequence: 0,
                queue: Vec::new(),
                outbound_emissions: HashMap::new(),
                captured_outbound_tail: VecDeque::new(),
                captured_outbound_json_bytes: 0,
                observed_outbound_objects: 0,
                observed_outbound_json_bytes: 0,
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

    pub(crate) fn capture_outbound_for(&self, sender: ClientId) {
        self.inner
            .lock()
            .unwrap()
            .outbound_emissions
            .entry(sender)
            .or_default();
    }

    /// Send a message into the bus from `sender`. The message becomes
    /// eligible for delivery on the next `step` / `deliver_all`.
    pub fn send(&self, sender: ClientId, msg: TransportMessage) {
        let mut inner = self.inner.lock().unwrap();
        if inner.outbound_emissions.contains_key(&sender) {
            let sequence = inner.next_outbound_sequence;
            inner.next_outbound_sequence = inner
                .next_outbound_sequence
                .checked_add(1)
                .expect("outbound emission sequence exhausted");
            inner
                .outbound_emissions
                .get_mut(&sender)
                .expect("outbound capture remains enabled")
                .push(OutboundEmission {
                    sequence,
                    msg: msg.clone(),
                });
            let json_bytes = serde_json::to_vec(&msg).map_or(0, |bytes| bytes.len() as u64);
            inner.observed_outbound_objects = inner.observed_outbound_objects.saturating_add(1);
            inner.observed_outbound_json_bytes = inner
                .observed_outbound_json_bytes
                .saturating_add(json_bytes);
            inner.captured_outbound_json_bytes = inner
                .captured_outbound_json_bytes
                .saturating_add(json_bytes);
            inner.captured_outbound_tail.push_back((
                sender,
                OutboundEmission {
                    sequence,
                    msg: msg.clone(),
                },
                json_bytes,
            ));
            while inner.captured_outbound_tail.len() > crate::MAX_CAPTURED_TRANSPORT_OBJECTS
                || inner.captured_outbound_json_bytes > crate::MAX_CAPTURED_TRANSPORT_JSON_BYTES
            {
                let Some((_, _, evicted_bytes)) = inner.captured_outbound_tail.pop_front() else {
                    break;
                };
                inner.captured_outbound_json_bytes = inner
                    .captured_outbound_json_bytes
                    .saturating_sub(evicted_bytes);
            }
        }
        inner.queue.push(InFlight { sender, msg });
    }

    pub(crate) fn outbound_since(
        &self,
        sender: ClientId,
        after_sequence: Option<u64>,
    ) -> Vec<OutboundEmission> {
        let inner = self.inner.lock().unwrap();
        inner
            .outbound_emissions
            .get(&sender)
            .into_iter()
            .flatten()
            .filter(|emission| after_sequence.is_none_or(|after| emission.sequence > after))
            .cloned()
            .collect()
    }

    pub(crate) fn captured_outbound_window(&self) -> CapturedOutboundWindow {
        let inner = self.inner.lock().unwrap();
        CapturedOutboundWindow {
            observed_objects: inner.observed_outbound_objects,
            observed_json_bytes: inner.observed_outbound_json_bytes,
            emissions: inner
                .captured_outbound_tail
                .iter()
                .map(|(sender, emission, _)| (*sender, emission.clone()))
                .collect(),
        }
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

    pub(crate) fn mailbox_snapshot(&self, client: ClientId) -> Vec<TransportMessage> {
        self.inner
            .lock()
            .unwrap()
            .mailboxes
            .get(&client)
            .cloned()
            .unwrap_or_default()
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

    /// Remove packet-bus copies after a higher-level retained transport adapter
    /// has durably captured the same accepted engine emissions.
    pub(crate) fn discard_queued_messages(&self, message_ids: &[MessageId]) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let queued_before = inner.queue.len();
        inner
            .queue
            .retain(|in_flight| !message_ids.contains(&in_flight.msg.id));
        let mut discarded = queued_before - inner.queue.len();
        for delayed in inner.delayed.values_mut() {
            let delayed_before = delayed.len();
            delayed.retain(|in_flight| !message_ids.contains(&in_flight.msg.id));
            discarded += delayed_before - delayed.len();
        }
        inner.delayed.retain(|_, messages| !messages.is_empty());
        discarded
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

    pub(crate) fn structural_progress_snapshot(&self) -> BusStructuralProgressSnapshot {
        let inner = self.inner.lock().unwrap();
        BusStructuralProgressSnapshot {
            queued_messages: inner.queue.len(),
            delayed_messages: inner.delayed.values().map(Vec::len).sum(),
            mailbox_messages: inner.mailboxes.values().map(Vec::len).sum(),
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

    pub(crate) fn semantic_queue_index(
        &self,
        selector: &ScenarioMessageSelectorV2,
        sender: Option<ClientId>,
        publication_ids: Option<&std::collections::HashSet<MessageId>>,
    ) -> Option<usize> {
        let inner = self.inner.lock().unwrap();
        inner
            .queue
            .iter()
            .enumerate()
            .filter(|(_, in_flight)| {
                sender.is_none_or(|sender| in_flight.sender == sender)
                    && publication_ids
                        .is_none_or(|message_ids| message_ids.contains(&in_flight.msg.id))
                    && selector.action_id.as_ref().is_none_or(|action_id| {
                        inner
                            .scenario_input_by_transport_id
                            .get(&in_flight.msg.id)
                            .is_some_and(|metadata| metadata.scenario_id == *action_id)
                    })
                    && selector.class.is_none_or(|class| {
                        transport_class_matches(
                            class,
                            &in_flight.msg.envelope,
                            inner.scenario_input_by_transport_id.get(&in_flight.msg.id),
                        )
                    })
            })
            .nth(selector.occurrence)
            .map(|(index, _)| index)
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

fn transport_class_matches(
    class: ScenarioTransportClass,
    envelope: &TransportEnvelope,
    metadata: Option<&ScenarioInputMetadata>,
) -> bool {
    match class {
        ScenarioTransportClass::Welcome => matches!(envelope, TransportEnvelope::Welcome { .. }),
        ScenarioTransportClass::GroupMessage => {
            matches!(envelope, TransportEnvelope::GroupMessage { .. })
        }
        ScenarioTransportClass::Commit => {
            metadata.is_some_and(|metadata| metadata.kind == crate::ScenarioInputKind::Commit)
        }
        ScenarioTransportClass::Proposal => {
            metadata.is_some_and(|metadata| metadata.kind == crate::ScenarioInputKind::Proposal)
        }
        ScenarioTransportClass::Application => {
            metadata.is_some_and(|metadata| metadata.kind == crate::ScenarioInputKind::Application)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::transport::{Timestamp, TransportSource};

    #[test]
    fn forensic_outbound_capture_is_bounded_at_emission_time() {
        let bus = TransportBus::ordered();
        let sender = bus.attach(MemberId::new(vec![1; 32]));
        bus.capture_outbound_for(sender);
        for sequence in 0..300_u64 {
            bus.send(
                sender,
                TransportMessage {
                    id: MessageId::new(sequence.to_be_bytes().to_vec()),
                    payload: vec![2; 32],
                    timestamp: Timestamp(sequence),
                    causal_deps: Vec::new(),
                    source: TransportSource("test".into()),
                    envelope: TransportEnvelope::GroupMessage {
                        transport_group_id: vec![3; 32],
                    },
                },
            );
        }

        let capture = bus.captured_outbound_window();
        assert_eq!(capture.observed_objects, 300);
        assert_eq!(
            capture.emissions.len(),
            crate::MAX_CAPTURED_TRANSPORT_OBJECTS
        );
        assert!(capture.observed_json_bytes > 0);
    }
}
