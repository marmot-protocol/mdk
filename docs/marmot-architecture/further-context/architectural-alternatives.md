# Architectural Alternatives

> **Historical context.** This document was written to evaluate the design space before landing on the target architecture. Read [[target-architecture]] first to understand where we ended up, then come back here if you want to understand *why* we made those choices and what alternatives were seriously considered.

**The problem this addresses:** The session-projection refactor improves the current codebase incrementally, but it optimizes within architectural assumptions that may themselves be wrong. Before committing to a refactor path, we need to honestly evaluate whether fundamentally different approaches would serve Marmot better.

The alternatives below are not mutually exclusive; several are combined in the target architecture.

## 1. Decomposition into Smaller Standalone Libraries

**The problem:** whitenoise-rs is a ~100K LOC monolith. The planned refactor reorganizes ownership (singleton → sessions) but keeps everything in one crate. Every module depends on `Whitenoise` or `Database` or both. Nothing is reusable outside the application.

**The alternative:** Break whitenoise-rs into composable crates with explicit dependency boundaries.

```
whitenoise-relay-pool/      — Relay connection pooling, subscription management,
                              session lifecycle. No knowledge of MLS or accounts.

whitenoise-mls-bridge/      — Bridges MDK operations to Nostr events.
                              Takes MLS messages, produces Nostr events.
                              Takes Nostr events, produces MLS messages.
                              No knowledge of UI, chat lists, or accounts.

whitenoise-account-store/   — Account lifecycle, per-account databases,
                              secret storage. No knowledge of MLS or relays.

whitenoise-chat/            — Chat list, message aggregation, streaming.
                              Depends on account-store and mls-bridge.

whitenoise-push/            — MIP-05 push notification token management.
                              Currently 3,632 LOC in one file.

whitenoise-discovery/       — User search, social graph, NIP-50.
                              Depends on relay-pool.

whitenoise-app/             — The facade that wires everything together.
                              FFI entry point. Thin.
```

**Benefits:**
- Each crate has a clear, testable API surface
- Dependencies are explicit and can be audited
- Crates can be versioned and released independently
- Forces clean interfaces where implicit coupling currently exists
- Other projects could use `whitenoise-relay-pool` or `whitenoise-mls-bridge` independently

**Costs:**
- Significant refactoring effort on top of the session projection work
- Workspace management overhead (Cargo features, version alignment)
- Some cross-cutting concerns (error types, config, logging) need careful handling

**Assessment:** This is the right long-term direction but the wrong time to do it all at once. The session-projection refactor is a prerequisite — it establishes the ownership boundaries that would become crate boundaries. Recommendation: complete the session refactor, then extract one crate at a time, starting with `whitenoise-push` (most self-contained, largest single file) and `whitenoise-relay-pool` (most reusable).

## 2. Event Loop / Deterministic State Machine Model

**The problem:** whitenoise-rs uses async Rust with shared mutable state (DashMap, Arc<Mutex>, broadcast channels). State changes are scattered across handlers, scheduled tasks, and login flows. Debugging requires reasoning about interleaving. Testing requires Docker infrastructure. Reproducing bugs requires recreating network conditions.

**The alternative:** Model the core as a deterministic state machine. Input events in, state transitions + output commands out. Like a Redux store for the protocol layer.

```
// Core is a pure function:
fn step(state: &State, event: InputEvent) -> (State, Vec<OutputCommand>)

// InputEvent variants:
enum InputEvent {
    RelayMessage { relay: Url, event: NostrEvent },
    UserAction { action: UserAction },
    Timer { task: ScheduledTask },
    RelayConnected { relay: Url },
    RelayDisconnected { relay: Url },
}

// OutputCommand variants:
enum OutputCommand {
    PublishToRelay { relay: Url, event: NostrEvent },
    SubscribeOnRelay { relay: Url, filter: Filter },
    PersistState { key: StateKey, value: Vec<u8> },
    EmitToUI { update: UIUpdate },
    ScheduleTimer { delay: Duration, task: ScheduledTask },
}
```

**The shell** (the async runtime, relay connections, database, FFI) is a thin adapter that converts I/O into InputEvents and executes OutputCommands. The core never touches I/O directly.

**Benefits:**

1. **Testability transforms.** Feed a sequence of InputEvents, assert on the resulting state and OutputCommands. No relays, no databases, no async runtime needed. Tests become deterministic and fast.

2. **Replay and debugging.** Log all InputEvents → replay any bug by feeding the same sequence. This is enormously valuable for the MLS ordering problem: you can replay commit races, epoch forks, and network partitions from recorded event logs.

3. **Test vector compatibility.** Jeff wants test vectors for CGKA convergence testing. A deterministic state machine produces deterministic output for a given input sequence — exactly what test vectors require.

4. **The CGKA ordering problem fits naturally.** The state machine can buffer incoming events, reorder them, and apply them in the correct sequence. The ordering logic is explicit in the `step` function, not scattered across async handlers and retry loops.

5. **Concurrency becomes trivial.** The state machine is single-threaded. Concurrency lives only in the shell (parallel relay connections, async I/O). No DashMap, no Arc<Mutex>, no broadcast channels in the core.

6. **Migration safety.** State transitions are explicit. You can add assertions, invariant checks, and migration logic at the transition boundary without worrying about concurrent mutations.

**Costs:**

1. **Significant rewrite of the core.** The event processor, scheduled tasks, streaming managers, and login flows would all need to be restructured. This is not a refactor — it's a new architecture.

2. **Impedance mismatch with async Rust.** The shell needs to be async (relay I/O, timers, FFI callbacks), but the core is synchronous. Bridging these requires careful channel design.

3. **Some operations don't fit cleanly.** Media upload/download, Blossom integration, and NIP-55 external signer flows are inherently asynchronous and stateful. They'd need to be modeled as multi-step state machine interactions.

4. **Learning curve.** The team is experienced with async Rust + shared state. The state machine model is conceptually simpler but architecturally unfamiliar.

**Assessment:** This is the most impactful alternative but also the most expensive. The right approach is not to rewrite everything at once, but to introduce the pattern for the MLS message processing path first — the part where ordering, determinism, and testability matter most. The rest of the application can continue using async Rust. Over time, more subsystems can be migrated to the state machine if the pattern proves its value.

**Connection to the coordinator concept:** Jeff's coordinator idea (see below) is essentially a specialized instance of this pattern — a state machine that buffers incoming events, applies ordering logic, and produces ordered output. If the team builds the coordinator, they're already building the core of the state machine. The question is whether to generalize it.

## 3. Separating Transport from Crypto

**The problem:** MLS requires total ordering. Nostr provides unordered pub/sub. The coupling between these two creates the MIP-03 epoch snapshot system, commit race resolution, and the planned coordinator. Every compensating mechanism is a consequence of this mismatch.

**The alternative:** Make the crypto/CGKA layer completely transport-blind. It becomes a pure state machine:

```
trait CgkaEngine {
    fn apply_commit(&mut self, commit: Commit) -> Result<EpochTransition>;
    fn create_commit(&mut self, proposals: Vec<Proposal>) -> Result<Commit>;
    fn encrypt(&self, plaintext: &[u8]) -> Result<Ciphertext>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Plaintext>;
    fn state(&self) -> &GroupState;
}
```

A separate **transport adapter** handles all relay-specific complexity:

```
trait TransportAdapter {
    async fn publish(&self, message: TransportMessage) -> Result<()>;
    fn subscribe(&self, filter: TransportFilter) -> Stream<TransportMessage>;
    fn query(&self, filter: TransportFilter) -> Result<Vec<TransportMessage>>;
}
```

Between them, a **sequencer/coordinator** converts unordered transport messages into ordered CGKA operations:

```
trait Sequencer {
    fn ingest(&mut self, msg: TransportMessage) -> Vec<SequencedOperation>;
    fn pending(&self) -> &[TransportMessage];
    fn state(&self) -> SequencerState;
}
```

**Current state:** MDK is *partially* transport-blind — it processes MLS messages and produces MLS messages, and doesn't know about relays. But the boundary leaks: Nostr event types (`Event`, `Tag`, `EventId`, `PublicKey`) appear in MDK's core API. The `process_message` function takes a Nostr `Event`, not a generic MLS message. Key packages are modeled as Nostr events.

**What clean separation requires:**

1. MDK's public API should accept/return MLS-typed data, not Nostr events. A thin Nostr adapter in whitenoise-rs converts between the two.
2. The sequencer should be a standalone component that can be tested with recorded event sequences.
3. Transport adapters should implement a common trait so that Nostr, FIPS mesh, and direct P2P are pluggable.

**Benefits:**
- Enables alternative transports without touching crypto code
- Isolates the ordering problem in one component (sequencer)
- MDK becomes a pure MLS library usable by non-Nostr projects
- Testing the sequencer becomes a matter of feeding event sequences

**Costs:**
- Additional abstraction layer (more code, more indirection)
- Nostr event metadata (timestamps, event IDs) is currently used for commit race resolution — this information would need to be passed through the transport adapter interface

**Assessment:** Partially achievable without major disruption. The first step is cleaning up MDK's API to not require Nostr types — accepting generic bytes + metadata instead of `nostr::Event`. The sequencer can be built as a standalone component alongside the existing event processor, then gradually take over ordering responsibilities.

## 4. BeeKEM / Causal-Order CGKA Migration Path

**The problem:** MLS/TreeKEM requires total ordering. If the team could use a CGKA that requires only causal ordering, the transport mismatch disappears. BeeKEM (from Ink & Switch / Keyhive) is the most promising candidate: O(log n) per update, standard crypto only (DH + BLAKE3, no exotic BLS), designed for peer-to-peer operation, written in Rust.

**Current BeeKEM status:**
- Designed for document access control (Keyhive), not real-time messaging
- Blanking-based conflict resolution: concurrent updates blank contested tree nodes, recovery via fresh Update
- No production messaging deployment
- Partial Rust implementation exists (research-grade)

**What the architecture needs today to enable future migration:**

1. **Abstract the CGKA behind a trait.** The `CgkaEngine` trait from section 3 above. Both MLS (via MDK) and BeeKEM would implement this trait. Application code never calls OpenMLS directly.

2. **Separate epoch/ordering semantics from the application.** Currently, whitenoise-rs has code paths that depend on MLS epoch numbers, proposal/commit semantics, and TreeKEM-specific concepts. These need to be abstracted behind the CGKA trait.

3. **Design the message format for CGKA agnosticism.** The outer message envelope (the Nostr event) should not contain MLS-specific structures. It should contain an opaque ciphertext that the CGKA engine knows how to process.

4. **Build the sequencer as a separate component.** For MLS, the sequencer provides total ordering. For BeeKEM, the sequencer provides causal ordering (much simpler — just track dependencies). Same interface, different implementation.

5. **Group migration protocol.** When switching CGKA for a group, all members need to:
   - Agree on the new CGKA (capability negotiation)
   - Perform a coordinated migration (similar to MLS ReInit)
   - Preserve message history (re-encryption or dual-read)

**Assessment:** Full BeeKEM migration is a 6-12 month project including implementation, testing, security analysis, and deployment. But the architectural preparation — abstracting the CGKA interface — should happen now regardless, because it also improves testability and modularity. The cost of the abstraction is low. The cost of not having it when you need it is a full rewrite.

**Critical benchmarking need:** BeeKEM's blanking-recovery pattern adds latency under high concurrency. For document access control this is fine. For real-time messaging where users expect sub-second delivery, the recovery latency needs benchmarking. Nobody has measured this for messaging workloads.

## 5. The Coordinator Concept

Jeff has described a coordinator that holds incoming event bursts, applies smarter ordering, and uses epoch rollback/snapshot for recovery. This is the pragmatic near-term answer to the MLS ordering problem.

**How it fits architecturally:**

The coordinator is the **sequencer** from section 3. It sits between the transport layer (relays) and the CGKA engine (MDK):

```
Relay events → Coordinator → Ordered operations → MDK
                    ↓
              Buffered events
              Ordering logic
              Rollback triggers
```

**Design options:**

**Option A: Library (in-process)**
The coordinator is a Rust struct that lives inside whitenoise-rs. It buffers incoming events, applies ordering heuristics (timestamp-based, with tie-breaking by event ID), and emits ordered operations to MDK. Rollback is triggered when a better-ordered commit arrives after processing.

This is essentially what the existing `EpochSnapshotManager` does, but formalized and made explicit. The coordinator would subsume the snapshot manager's responsibilities.

**Pros:** Simple deployment, no additional infrastructure, low latency.
**Cons:** Ordering is still best-effort (no global view), each client may see different orderings.

**Option B: Service (out-of-process)**
The coordinator runs as a separate process (or relay sidecar) that receives events from relays and emits ordered sequences. Clients subscribe to the coordinator instead of (or in addition to) raw relays.

**Pros:** Global ordering view, deterministic for all clients.
**Cons:** Single point of failure, centralization (defeats Nostr's censorship resistance), additional infrastructure.

**Option C: Smart relay (sequencing relay)**
A modified Nostr relay that understands MLS commit ordering and guarantees total ordering for designated groups. Clients use this relay for commit/proposal events while using regular relays for other traffic.

**Pros:** Clean separation, leverages existing relay infrastructure.
**Cons:** Vendor lock-in to specific relay implementation, still centralized for ordering.

**Recommendation:** Option A (library) for now. It's the lowest-risk path and aligns with the state machine model — the coordinator is just the sequencing part of the `step` function. If ordering proves insufficient, Option C (sequencing relay) is the next step, but only after measuring how often ordering conflicts actually occur in practice. The team should instrument the current epoch rollback system to understand the real-world frequency of commit races before over-engineering the solution.

**Connection to the state machine model:** If the team builds the coordinator as a standalone struct with a pure function interface (`ingest(event) → ordered_operations`), they've already built the core of the deterministic state machine. The question is whether to stop there or generalize.

## 6. FIPS Network as Transport Layer

FIPS (Free Internetworking Peering System) is a Nostr-native mesh network in Rust by jmcorgan. It provides:
- Mesh routing with Noise encryption
- Transport-agnostic (UDP, TCP, Tor, BLE, radio, serial)
- IPv6 addresses derived from npub
- TUN interface for non-FIPS-aware apps

**What the transport layer interface needs to support FIPS:**

```rust
trait TransportAdapter {
    /// Publish a message to a destination (relay URL, mesh address, peer ID)
    async fn publish(&self, dest: Destination, message: &[u8]) -> Result<()>;
    
    /// Subscribe to messages matching a filter
    fn subscribe(&self, filter: SubscriptionFilter) -> BoxStream<TransportMessage>;
    
    /// One-shot query
    async fn query(&self, dest: Destination, filter: QueryFilter) 
        -> Result<Vec<TransportMessage>>;
    
    /// Connection health
    fn connection_state(&self, dest: &Destination) -> ConnectionState;
    
    /// Supported capabilities (ordering, reliability, latency bounds)
    fn capabilities(&self) -> TransportCapabilities;
}
```

The `TransportCapabilities` struct is critical — it tells the sequencer/coordinator what guarantees the transport provides:

```rust
struct TransportCapabilities {
    ordering: Ordering,          // None, Causal, Total
    reliability: Reliability,    // BestEffort, AtLeastOnce, ExactlyOnce
    latency: LatencyClass,       // Realtime, NearRealtime, Async
    supports_subscriptions: bool,
    supports_queries: bool,
    max_message_size: Option<usize>,
}
```

For Nostr relays: `{ ordering: None, reliability: BestEffort, ... }`
For FIPS mesh: `{ ordering: None, reliability: BestEffort, ... }` (similar guarantees)
For a sequencing relay: `{ ordering: Total, reliability: AtLeastOnce, ... }`

The coordinator adjusts its behavior based on transport capabilities — more buffering and rollback for unordered transports, passthrough for totally-ordered ones.

**Current blockers:**
- FIPS is v0.2.0, unstable protocol, no production use
- No native API yet (roadmap item — currently TUN interface only)
- No mobile support
- Wire format not versioned

**Assessment:** Not actionable today, but the transport adapter interface should be designed to accommodate FIPS's capabilities. The key insight is that FIPS and Nostr relays have similar guarantee profiles (unordered, best-effort), so any transport abstraction that works for "Nostr vs. sequencing relay" also works for "Nostr vs. FIPS."

## Synthesis: The Layered Architecture

All six alternatives point toward the same target architecture:

```
┌─────────────────────────────────┐
│  Flutter (presentation)         │  ← unchanged
├─────────────────────────────────┤
│  FFI boundary                   │  ← unchanged
├─────────────────────────────────┤
│  Application facade             │  ← thin, wires components together
│  (accounts, chat, search, push) │
├─────────────────────────────────┤
│  Coordinator/Sequencer          │  ← NEW: ordering + buffering
│  (deterministic state machine)  │
├─────────────────────────────────┤
│  CGKA Engine (trait)            │  ← abstract over MLS / BeeKEM
│  ├── MLS impl (MDK)            │
│  └── BeeKEM impl (future)      │
├─────────────────────────────────┤
│  Transport Adapter (trait)      │  ← abstract over transport
│  ├── Nostr relay impl           │
│  ├── Sequencing relay impl      │
│  └── FIPS mesh impl (future)    │
└─────────────────────────────────┘
```

The session-projection refactor is a necessary step toward this — it establishes per-account ownership that maps cleanly to per-account state machines. But it's step 1 of ~4:

1. **Session projection** (in progress) — decompose singleton, typed ownership
2. **Coordinator** — extract sequencing logic into standalone component
3. **CGKA abstraction** — abstract MDK behind trait, clean Nostr types from MDK API
4. **Transport abstraction** — abstract relay control behind trait

Steps 2-4 can proceed incrementally after step 1 completes. Each delivers standalone value. Together they create an architecture that can evolve without rewrites.

See [[decision-points]] for specific recommendations on sequencing and prioritization.
