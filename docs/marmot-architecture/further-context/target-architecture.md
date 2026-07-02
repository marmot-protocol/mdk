---
title: "Target Architecture — The Big Picture"
created: 2026-04-15
updated: 2026-04-15
tags: [marmot, architecture, coordinator, cgka, transport, state-machine]
status: reference
related:
  - [[index]]
  - [[architectural-alternatives]]
  - [[decision-points]]
---

# Target Architecture — The Big Picture

> **Reference status.** This is the older long-form architecture note. The active orientation doc is
> [`../overview/target-architecture.md`](../overview/target-architecture.md). Treat trait sketches below as
> illustrative; the current Rust surface lives in `crates/traits` and the engine contract docs.

**The problem this solves:** The current Marmot stack has MLS, Nostr, and application logic deeply coupled together.
Changing anything requires understanding all of it. Transport is not pluggable. The CGKA (continuous group key
agreement) backend is not swappable. Testing requires the full stack. This document defines a _potential_ target
architecture that separates these concerns cleanly — transport, CGKA, and application each behind their own interfaces,
with the engine as the single integration point.

This document captures the core architectural vision. Not an implementation plan. Not a refactor checklist. The idea,
clearly stated, so it doesn't get lost.

---

## The Complete Picture (read this first)

The application layer has one job: **express intent, consume events.**

```
Application layer:
  User Input:  SendIntent - "send this message", "add this member", "rotate keys"
  Output to UI Layer: Stream<GroupEvent>  — "message received", "member added", "epoch advanced"
```

Everything else is below the line. The application layer never needs to know which CGKA backend is running, how the
outer envelope is structured, whether publish-before-apply is required, or which transport is carrying the blobs. All of
that complexity is contained inside the engine.

The four components that make this work:

- **CGKA backend** — defines how group key agreement works; what pending state looks like; whether publish-before-apply
  is required. MLS is the backend today. A different CGKA (e.g. a hypothetical causal-order variant) could implement the
  same trait.
- **TransportPeeler** — one implementation per transport+CGKA pair; handles the two envelope layers (outer transport
  encryption, inner CGKA encryption).
- **Transport adapter** — moves blobs around; reports delivery confirmation back up.
- **CgkaEngine** — wires the above three together; exposes the clean intent-in / events-out interface to the application
  layer.

The complexity lives in the engine and below, where it belongs, fully contained.

> **Note on the examples below:** The specifics throughout this document — kind 445 outer wrapping, group exporter
> secrets, MLS pending commits, Nostr relay echoes — are Marmot-specific (MLS + Nostr). They illustrate the design with
> concrete detail. But the architecture itself is general: any CGKA backend paired with any transport, connected through
> a `TransportPeeler`, behind the same `CgkaEngine` interface. Keep the complete picture in mind and the Marmot
> specifics are just one instantiation of it.

---

## The Three Concerns

Every private group messenger solves three problems:

1. **Continuous Group Key Agreement (CGKA)** — how do members agree on a shared secret, rotate it securely, handle
   membership changes, and provide both FS and PCS?
2. **Transport** — how do encrypted blobs physically move between members?
3. **Application** — accounts, chat lists, UI, notifications, everything else

The goal is to make these three concerns **fully independent**. The key insight is what each boundary looks like and
where the coupling necessarily lives.

---

## The Critical Insight: CGKA Defines Interoperability

**The CGKA backend is the interoperability boundary — not the transport.**

Two clients can use completely different transports (one on Nostr relays, one on FIPS mesh) and still participate in the
same group, as long as they share the same CGKA backend. The transport is just how blobs move. The CGKA defines what
those blobs _are_ and how group state evolves.

The incompatibility line is at the CGKA level. Different CGKA backends have different key material, state machines, and
wire formats. There is no bridge between them. If Marmot ever adopted a different CGKA backend, groups using it would be
a new group type — not a migration of existing groups.

**Clean mental model:**

- **Group type** = CGKA backend → defines interoperability
- **Transport** = how encrypted blobs move → orthogonal to group type
- **TransportPeeler** = the explicit seam where a specific group type meets a specific transport

---

## The Two-Layer Message Model

Every message in the system has two encryption layers, always:

```
┌─────────────────────────────────────────────┐
│  Outer layer: transport encryption          │
│  (e.g. kind 445 wrapped with group          │
│   exporter secret in MLS/Nostr case)        │
│  → reveals: message type + inner payload    │
├─────────────────────────────────────────────┤
│  Inner layer: CGKA encryption               │
│  (e.g. MLS application message,             │
│   commit, proposal, welcome)                │
│  → reveals: plaintext application content   │
│    + drives group state changes             │
└─────────────────────────────────────────────┘
```

This two-layer structure is universal. Any CGKA system will have some outer transport wrapping and some inner group
crypto. The architecture reflects this explicitly rather than hiding it.

**Important:** You cannot identify message type from the outer transport envelope alone. The outer layer must be
decrypted first (usually using group secret material if you're not trusting a centralized server) before you know
whether you're dealing with a commit, proposal, application message, or welcome. This means the CGKA engine must own the
unwrap step — it cannot be done by a stateless transport layer.

---

## The CGKA Engine

The CGKA engine is the heart of the system. It contains both the coordinator/sequencer and the crypto operations. Its
external interface is simple:

**Inbound:** raw `TransportMessage` in any order → ordered (within some time bounded window) `GroupEvent` stream out  
**Outbound:** application `SendIntent` in → encrypted `TransportMessage` out

```rust
trait CgkaEngine {
    // Inbound path
    fn ingest(&mut self, msg: TransportMessage) -> Result<()>;
    fn events(&mut self) -> impl Stream<Item = GroupEvent>;

    // Outbound path
    fn send(&mut self, intent: SendIntent) -> Result<SendResult>;
    fn confirm_published(&mut self, pending: PendingStateRef) -> Result<GroupEvent>;

    // State
    fn group_context(&self) -> &dyn GroupContext;
    fn epoch(&self) -> EpochId;
    fn members(&self) -> Vec<MemberId>;
}

enum SendResult {
    /// Plain application message — fire and forget, no state change needed
    ApplicationMessage {
        msg: TransportMessage,
    },
    /// Group evolution event (commit, add, remove, key rotation)
    /// Publish msg first, then call confirm_published() once relay confirms receipt
    GroupEvolution {
        msg: TransportMessage,
        pending: PendingStateRef, // opaque token
    },
}
```

### Inside the engine: two-phase inbound processing

```
TransportMessage (raw, unordered)
    ↓
[1] TransportPeeler::peel(msg, group_context)
    → PeeledMessage { message_type, payload, ordering_metadata }
    ↓
[2] Coordinator / Sequencer
    → buffers, orders, deduplicates within time window
    → deterministic: same inputs always → same output order
    ↓
[3] CGKA backend (MLS today; the trait allows for alternatives)
    → processes in order: commits, proposals, application messages
    → updates group state
    ↓
GroupEvent stream (ordered, decrypted)
```

### Inside the engine: outbound processing

```
SendIntent (application layer intent)
    ↓
[1] Coordinator: validate epoch state
    → are we in a state where we can safely send?
    → if not, buffer until in-flight commits settle
    ↓
[2] CGKA backend: encrypt
    → produce inner encrypted payload
    → for group evolution: store pending state internally, return PendingStateRef
    ↓
[3] TransportPeeler::wrap(payload, group_context)
    → apply outer transport encryption layer
    ↓
SendResult
  ├─ ApplicationMessage { msg } — publish and done
  └─ GroupEvolution { msg, pending } — publish first, then confirm
```

**For application messages:** fire and forget. Publish the `TransportMessage`, done. The engine's state does not change.

**For group evolution events (commits, adds, removes, rotations):** a two-step contract:

1. Application layer publishes `msg` to transport
2. On successful relay confirmation, calls `engine.confirm_published(pending)`
3. Engine merges pending state → local group state advances → emits a `GroupEvent`

If publish fails, the application layer discards the `PendingStateRef` and the engine's pending state is cleaned up. No
state divergence.

**Why not just apply locally immediately?** MLS requires publish-before-apply for commits. If you apply locally and then
fail to publish, you've diverged from the group — your epoch has advanced but nobody else knows. The `PendingStateRef`
pattern enforces the correct ordering.

**Own commits echoing back from relays:** OpenMLS explicitly returns `CannotDecryptOwnMessage` when you try to process
your own commit via the normal inbound path. The engine handles this internally — when it sees this error on a commit
and there's a pending commit stored, it routes to `merge_pending_commit()` instead. The application layer does not need
to special-case this. However, with the `confirm_published()` pattern above, the echo from the relay becomes a no-op
(commit was already merged on confirmation) — the engine deduplicates by `MessageId`.

---

## The TransportPeeler

The `TransportPeeler` is an injected pluggable function pair — the explicit seam between a specific transport format and
a specific CGKA backend.

```rust
trait TransportPeeler {
    /// Unwrap outer transport encryption → classified message
    fn peel(
        &self,
        msg: TransportMessage,
        ctx: &dyn GroupContext,
    ) -> Result<PeeledMessage>;

    /// Apply outer transport encryption → ready-to-send blob
    fn wrap(
        &self,
        payload: EncryptedPayload,
        ctx: &dyn GroupContext,
    ) -> Result<TransportMessage>;
}
```

**`GroupContext`** is provided by the CGKA backend — an abstract bundle of whatever secret material the current backend
makes available:

```rust
trait GroupContext {
    fn exporter_secret(&self, label: &str) -> Option<[u8; 32]>;
    fn epoch(&self) -> EpochId;
    // other backend-specific accessors as needed
}
```

MLS populates `exporter_secret` (used by the kind 445 outer wrapping in Nostr). A hypothetical alternative backend would
populate whatever its equivalent is, or return None for fields it doesn't support.

**One TransportPeeler per transport+CGKA pair.** Today there is exactly one: `NostrMlsPeeler`. When FIPS is added, a
`FipsMlsPeeler` is written. The combinatorial explosion only happens if you have many transports × many CGKAs
simultaneously in production — an unlikely scenario.

**The no-op case:** A peeler that does nothing is valid. If a transport delivers already-peeled messages
(hypothetically), the default peeler is a passthrough. The injection point still exists; it just does nothing.

---

## The TransportMessage Type

The coordinator's input/output type. Intentionally minimal:

```rust
struct TransportMessage {
    id: MessageId,               // content-addressed hash of payload
    payload: Vec<u8>,            // opaque bytes
    timestamp: Timestamp,        // sender's claimed time (tie-breaking)
    causal_deps: Vec<MessageId>, // what this depends on (if known)
    source: TransportSource,     // which transport (for debugging/routing)
}
```

Nostr adapter: `nostr::Event` → `TransportMessage`  
FIPS adapter: `fips::Frame` → `TransportMessage`

The adapters live in **whitenoise-core**, not in MDK. The engine never sees a Nostr event directly.

---

## The TransportAdapter Trait

All transport adapters implement this trait. `whitenoise-core` holds a `Vec<Box<dyn TransportAdapter>>` and fans out
through them — the application core never knows whether it's talking to Nostr relays, a FIPS mesh, or both
simultaneously.

```rust
trait TransportAdapter {
    /// Push a TransportMessage out to the network.
    /// Returns confirmation once at least one recipient relay/peer acknowledges.
    async fn publish(&self, msg: &TransportMessage) -> Result<PublishConfirmation>;

    /// Subscribe to inbound messages for a group.
    fn subscribe(&self, group_id: &GroupId) -> BoxStream<TransportMessage>;

    /// One-shot fetch for catch-up after being offline.
    async fn fetch(
        &self,
        group_id: &GroupId,
        since: Timestamp,
    ) -> Result<Vec<TransportMessage>>;

    /// Current connection health.
    fn status(&self) -> TransportStatus;
}
```

The transport adapter **only ever sees opaque `TransportMessage` blobs**. It never touches plaintext, intent data, or
anything inside the encrypted payload. The intent → encrypted blob pipeline is entirely the engine's job; the adapter's
job starts and ends at the network boundary.

### Outbound fan-out (in whitenoise-core)

```rust
// After engine.send(intent) returns a GroupEvolution:
let mut confirmation = None;
for adapter in &self.adapters {
    if let Ok(confirm) = adapter.publish(&msg).await {
        confirmation = Some(confirm);
        break; // first-wins policy
    }
}
if let Some(_) = confirmation {
    engine.confirm_published(pending)?;
} else {
    // all adapters failed — retry later, pending state stays in engine
}
```

**Confirmation policy: first-wins.** As soon as any adapter confirms successful delivery, the engine can safely advance
local state. Multiple adapters provide redundancy, not a requirement for consensus. If Nostr relays confirm, you're done
— FIPS delivering it too is a bonus.

**Failure handling:** if all adapters fail, `confirm_published()` is never called. The engine holds the pending state.
The application layer can retry `publish()` later. No diverged state, no partial commits.

### Inbound deduplication

When multiple adapters are active, the same message may arrive via both Nostr and FIPS. The coordinator in the engine
handles deduplication by `MessageId` — the application core can merge the inbound streams without filtering:

```rust
let combined = futures::stream::select_all(
    self.adapters.iter().map(|a| a.subscribe(&group_id))
);
// feed everything into the engine — coordinator deduplicates
while let Some(msg) = combined.next().await {
    engine.ingest(msg)?;
}
```

---

## The PeeledMessage Type

Output of `TransportPeeler::peel()`. The coordinator works with these:

```rust
struct PeeledMessage {
    id: MessageId,
    message_type: MessageType,   // Commit, Proposal, Application, Welcome
    payload: Vec<u8>,            // inner encrypted payload for CGKA backend
    ordering_metadata: OrderingMetadata, // epoch hints, proposal refs, etc.
}

enum MessageType {
    Commit { covers_proposals: Vec<MessageId> },
    Proposal { proposal_type: ProposalType },
    Application,
    Welcome,
}
```

---

## The Full Stack (Target State)

```
┌─────────────────────────────────────────────────────┐
│  Flutter / Native UI                                │
│  (presentation only, zero logic)                    │
├─────────────────────────────────────────────────────┤
│  whitenoise-ffi                                     │
│  (FFI bridge → Dart + Swift bindings, not Flutter-  │
│   specific, works with any consumer)                │
├─────────────────────────────────────────────────────┤
│  whitenoise-core                                    │
│  (application facade: accounts, chat, search,       │
│   push notifications, delivery tracking)            │
│                                                     │
│  Transport adapters live here:                      │
│    NostrAdapter: nostr::Event → TransportMessage    │
│    or FipsAdapter: fips::Frame → TransportMessage   |
│  (multiple adapters can run simultaneously —        │
│   same MLS group reachable over both transports)    │
├─────────────────────────────────────────────────────┤
│  MDK — CgkaEngine                                   │
│  ┌─────────────────────────────────────────────┐    │
│  │  TransportPeeler (injected, pluggable)      │    │
│  │  NostrMlsPeeler | FipsMlsPeeler | ...       │    │
│  ├─────────────────────────────────────────────┤    │
│  │  Coordinator / Sequencer                    │    │
│  │  (deterministic state machine)              │    │
│  │  • buffers PeeledMessages                   │    │
│  │  • orders within time window                │    │
│  │  • deduplicates                             │    │
│  │  • same inputs → always same output order   │    │
│  ├─────────────────────────────────────────────┤    │
│  │  CGKA Backend (trait)                       │    │
│  │  ├── MLS / OpenMLS (today)                  │    │
│  │      (trait allows alternative backends)    │    │
│  └─────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────┤
│  Transport layer (pluggable)                        │
│  ├── Nostr relay pool                               │
│  ├── FIPS mesh (future)                             │
│  └── Direct / BLE (future)                          │
└─────────────────────────────────────────────────────┘
```

---

## Data Flow: Engine to UI

Three distinct layers between the engine and the screen, each with a different purpose:

### 1. GroupEvent stream (engine → application core)

Raw, ordered, decrypted events from the engine. Every commit, every message, every membership change. The application
core consumes this stream and writes to its local database. The stream itself is not stored — it is not a persistent log
you can replay.

However, the _source material_ is always recoverable: when you come back online, the transport adapters call `fetch()`
to pull missed events from relays, flood them into `engine.ingest()`, and the coordinator sequences them correctly. The
GroupEvent stream flows again, and the application core catches its database up to current state. Nothing is lost as
long as the transport has retained the events.

**Reconnect flow:**

```
Come back online
  → transport adapters reconnect
  → adapter.fetch(group_id, since: last_seen) for each group
  → flood of TransportMessages → engine.ingest()
  → coordinator sequences, deduplicates
  → GroupEvent stream resumes
  → application core processes events, updates DB projections
  → UI notified via broadcast channels once caught up
```

### 2. Database projections (application core)

The durable local state. Not raw events — coalesced, rational representations:

- Messages with reactions and edits folded in
- Group membership as it stands now
- Delivery status per message
- Unread counts, pinned state, archive state

This is what the UI queries on screen open. It is always current. The session-projection refactor is making these
projections well-typed, per-account, and explicitly owned — replacing the implicit global state in the current
singleton.

When the UI opens a screen, it **reads the projection first**, then subscribes to a broadcast channel for live updates.
It never replays the GroupEvent stream.

### 3. Broadcast channels (application core → UI)

Fine-grained real-time notifications. The UI subscribes only to what it needs:

- `messages::{group_id}` — new or updated messages in a specific group
- `chat_list` — unread counts, ordering, pinned state
- `members::{group_id}` — membership changes
- `notifications` — push-style alerts

When a new GroupEvent arrives, the application core updates the relevant projection in the database and fans out to the
appropriate broadcast channels. The UI receives the update and re-renders.

**The full path, engine to screen:**

```
Engine
  → GroupEvent stream
    → application core writes to DB projections
    → application core fans out to broadcast channels
      → UI screen (open): read projection on load,
                          receive channel updates while open
```

---

## What the Coordinator Is NOT Responsible For

Being explicit about scope prevents the coordinator from absorbing whitenoise-rs:

- ❌ Relay connections or subscriptions
- ❌ Account management
- ❌ Chat list state or message history
- ❌ Push notifications
- ❌ User discovery or social graph
- ❌ Delivery confirmation (hands blob to transport adapter, done)
- ✅ Message ordering and sequencing
- ✅ Epoch state validity checks (can we send right now?)
- ✅ Buffering during in-flight commit settlement
- ✅ Deduplication of messages arriving from multiple transports
- ✅ Driving crypto operations (via CGKA backend) in correct order

---

## Multi-Transport Simultaneously

Because transport is orthogonal to the CGKA, an app can run multiple transports simultaneously for the same group. Both
the Nostr adapter and the FIPS adapter feed `TransportMessage`s into the same engine. The coordinator deduplicates (same
`MessageId` from two sources = one `PeeledMessage`). The group doesn't know or care which transport carried each
message.

This means: if Nostr relays go down, FIPS mesh keeps the group running. Same group, same MLS state, no re-keying needed.

---

## The Path There

1. **Session projection** (in progress) — decompose whitenoise-rs singleton into per-account sessions
2. **Coordinator in MDK** — formalize sequencer; define `TransportMessage` + `PeeledMessage`; subsumes epoch snapshot
   system; `TransportPeeler` trait introduced
3. **CGKA trait** — abstract OpenMLS behind `CgkaEngine` trait; `GroupContext` defined; clean Nostr types from MDK
   public API
4. **Transport adapter** — extract relay control planes into adapter trait; whitenoise-core becomes the wiring layer

Each step is independently valuable. Step 2 is the highest-leverage next move after the session refactor completes.
