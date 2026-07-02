---
title: "CGKA Engine Design"
created: 2026-04-16
tags: [marmot, mdk, cgka, state-machines, traits, storage, architecture]
status: reference
related:
  - [[target-architecture]]
  - [[capability-negotiation]]
  - [[decision-points]]
---

# CGKA Engine Design

> **Reference status.** This is the older long-form engine design. The current implementation lives in
> `crates/cgka-engine`, with the post-peeling contract in
> [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md). Treat trait sketches
> below as design history when they differ from `crates/traits`.

**The problem this solves:** MDK today is a monolithic struct with no clean internal boundaries, Nostr types leaking
into storage, and capabilities as hardcoded constants. This creates the compatibility breaks we've already seen
(self-remove), makes testing hard, and makes the codebase difficult to reason about. This document defines what the CGKA
Engine should look like — as a trait, as a set of internal state machines, and as a storage design — so that engineers
have a concrete target to build toward.

A detailed look at how the CGKA Engine layer should be structured — what traits it exposes, what state machines it
contain, how storage fits in, and where the current MDK codebase is well-designed vs. where it needs rethinking.

---

## What the CGKA Engine is responsible for

From [[target-architecture]]:

> The application layer has one job: express intent, consume events. Everything else is below the line.

The CGKA Engine owns:

- Group key agreement (MLS state machine today)
- Message encryption / decryption (inner layer)
- Outbound serialization (intent → encrypted payload)
- Transport envelope wrap/unwrap (via injected `TransportPeeler`)
- Commit/proposal sequencing (the coordinator)
- Capability negotiation (see [[capability-negotiation]])
- Storage of group state, messages, key packages, epoch snapshots

It does NOT own:

- Transport (relay connections, subscriptions)
- Account management
- Chat list state
- Push notifications
- UI concerns

---

## Current MDK structure: what works, what doesn't

### What's well-designed

**Storage traits are clean.** The separation into
`GroupStorage + MessageStorage + WelcomeStorage + StorageProvider<CURRENT_VERSION>` composing into `MdkStorageProvider`
is the right pattern. Multiple backends (SQLite, in-memory) work correctly. The snapshot/rollback system
(`create_group_snapshot`, `rollback_group_to_snapshot`) is a good foundation. Keep all of this.

**The `MDK<Storage>` generic is correct.** Parameterising over storage at the type level (rather than a trait object)
gives zero-cost dispatch and compile-time guarantees that the storage implementation is consistent. Don't change this
pattern.

**OpenMLS delegation is well-abstracted.** MDK wraps OpenMLS via the `MdkProvider<Storage>` struct and the
`OpenMlsProvider` trait. The MLS state machine internals stay inside OpenMLS. MDK shouldn't try to re-implement MLS.

**The epoch snapshot system is a real architectural asset.** The `EpochSnapshotManager` and the rollback/retry logic in
message processing (`OwnCommitPending`, `Retryable` message states) are genuinely clever and solve a hard problem. This
is MDK's key differentiator from plain OpenMLS.

### What needs rethinking

**`MDK<Storage>` is a monolithic struct.** Currently it has ~200 methods across 37+ files in whitenoise-rs (via the
`Whitenoise` facade that wraps it). The struct holds ciphersuite, extensions, provider, config, epoch_snapshots, and
callback as flat fields. There are no internal boundary between "group lifecycle management", "message processing", "key
package management", and "capability management". These should be clearer internal subsystems even if they're not
separate public crates.

**Nostr types leak into the core.** `process_message()` takes a `nostr::Event`. `constant.rs` references Nostr event
kinds (`Kind::Custom(30443)`). `GroupStorage` has fields like `nostr_group_id`. This is the "clean Nostr types from MDK
API" item from the decision points. The CGKA engine should accept `TransportMessage` (opaque bytes + metadata), not
`nostr::Event`. The Nostr-specific unwrapping belongs in the `TransportPeeler`.

**Capabilities are static constants, not runtime-queryable.** `SUPPORTED_PROPOSALS`, `GROUP_CONTEXT_REQUIRED_PROPOSALS`,
`SUPPORTED_EXTENSIONS` are hardcoded in `constant.rs`. There's no `feature_status()` function, no
`constructable_capabilities()`, no way to ask "does this group support disappearing messages?" at runtime. This is the
root cause of the self-remove compatibility break — the capability system doesn't exist yet at the right level.

**No `CgkaEngine` trait.** MDK is a concrete type, not a trait. You can't swap it out, mock it cleanly in tests, or
reason about what the "CGKA contract" actually is. The trait should be defined first; MDK should be the implementation.

---

## The `CgkaEngine` trait

The full public contract of the engine. Application code only calls methods on this trait — never on `MDK<S>` directly.

```rust
pub trait CgkaEngine: Send + Sync {
    // ── Inbound path ──────────────────────────────────────────────────────────

    /// Ingest a raw message from any transport. May be called in any order.
    /// The coordinator buffers and sequences internally.
    fn ingest(&mut self, msg: TransportMessage) -> Result<(), EngineError>;

    /// Subscribe to the ordered, decrypted output stream.
    fn events(&mut self) -> BoxStream<'_, GroupEvent>;

    // ── Outbound path ─────────────────────────────────────────────────────────

    /// Encrypt and prepare an outbound message or group operation.
    fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError>;

    /// Confirm that a GroupEvolution message was successfully published.
    /// Engine merges pending state → local epoch advances → emits GroupEvent.
    fn confirm_published(&mut self, pending: PendingStateRef) -> Result<GroupEvent, EngineError>;

    // ── Group lifecycle ────────────────────────────────────────────────────────

    fn create_group(
        &mut self,
        members: &[KeyPackage],
        name: &str,
    ) -> Result<(GroupId, SendResult), EngineError>;

    fn join_group(&mut self, welcome: Welcome) -> Result<GroupId, EngineError>;

    fn leave_group(&mut self, group_id: &GroupId) -> Result<SendResult, EngineError>;

    // ── Capability negotiation ─────────────────────────────────────────────────

    /// What's the status of a specific feature in a specific group?
    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: Feature,
    ) -> Result<FeatureStatus, EngineError>;

    /// What capabilities can this group's current members support that aren't yet required?
    fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError>;

    /// Upgrade the group to require all currently upgradeable capabilities.
    fn upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError>;

    // ── State inspection ──────────────────────────────────────────────────────

    fn group_context(&self, group_id: &GroupId) -> Result<&dyn GroupContext, EngineError>;
    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError>;
    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError>;
}
```

---

## State machines: what should be an enum, what shouldn't

The rustls lesson: if illegal state transitions exist and they're only caught at runtime via `if/match` checks, model it
as an enum instead. The compiler enforces it for free.

### ✅ Should be explicit state machine enums

**1. Epoch/commit state** Each group is always in one of these states:

```rust
pub enum EpochState {
    /// Normal operation — no pending commit
    Stable { epoch: EpochId },

    /// We've created a commit, waiting for publish confirmation before merging
    PendingPublish {
        epoch: EpochId,
        pending: StagedCommit,
        pending_ref: PendingStateRef,
    },

    /// We've confirmed publish, merging the commit now
    Merging { epoch: EpochId },

    /// We're in an epoch fork — received a commit we couldn't apply cleanly
    /// Holding events, waiting for recovery
    Recovering {
        last_stable_epoch: EpochId,
        buffered_events: Vec<PeeledMessage>,
    },
}
```

The current code handles these states implicitly via `pending_commit().is_some()`, error variants like
`OwnCommitPending`, and the snapshot system. Making it an explicit enum:

- Makes it impossible to call `process_message` when in `PendingPublish` state (compiler error)
- Eliminates the defensive `if group.pending_commit().is_some()` checks throughout
- Makes the recovery flow explicit rather than scattered across error handlers

**2. Welcome/join state**

```rust
pub enum WelcomeState {
    /// No pending welcome
    None,
    /// Received a welcome, haven't accepted yet
    Pending { welcome: Welcome, group_id: GroupId },
    /// Accepted — group is active
    Active,
    /// Rejected
    Declined,
}
```

**3. Member state (per member, per group)**

```rust
pub enum MemberState {
    Active,
    /// Removed by commit — leaf node blanked
    Removed { at_epoch: EpochId },
    /// Left via self-remove proposal
    SelfRemoved { at_epoch: EpochId },
    /// Capability-incompatible — present but can't participate in new features
    Degraded { missing_capabilities: Vec<Feature> },
}
```

### ❌ Should NOT be state machines

**Message processing pipeline** — this is a sequential transformation (receive → peel → sequence → decrypt → emit), not
a state machine. Keep it as a linear function chain.

**Storage operations** — pure data operations, no state machine needed.

**Key package refresh** — periodic background task, not state.

**Relay/transport concerns** — explicitly outside the engine.

---

## Internal subsystems

The monolithic `MDK<Storage>` struct should be reorganised into internal subsystems with clearer boundaries. These don't
need to be separate public crates immediately — internal modules with explicit interfaces is a reasonable first step.

### `GroupLifecycle`

Create, join, leave, add member, remove member, update group data. Owns the MLS group operations that change membership
or group context.

### `MessageProcessor`

Inbound pipeline: peel → sequence (coordinator) → apply MLS → emit `GroupEvent`. Outbound pipeline: `SendIntent` →
encrypt → wrap via peeler → `SendResult`.

### `EpochManager`

Owns the `EpochState` state machine. Manages pending commits, snapshot creation/rollback, and recovery from epoch forks.
Currently scattered across `epoch_snapshots.rs` and the error handling in `messages/process.rs`.

### `CapabilityManager`

Owns feature registry, `feature_status()`, `constructable_capabilities()`, `upgradeable_capabilities()`. Currently
doesn't exist — capabilities are static constants in `constant.rs`.

### `KeyPackageManager`

Publish, refresh, expire, validate key packages. Currently in `key_packages.rs`.

---

## Storage traits: keep the structure, fix the leaks

The current storage trait design is good. Keep:

- `GroupStorage` — group metadata
- `MessageStorage` — message records with state machine (Created → Processed → Failed → Retryable → EpochInvalidated)
- `WelcomeStorage` — pending welcomes
- `MdkStorageProvider` = `GroupStorage + MessageStorage + WelcomeStorage + StorageProvider<1>`
- SQLite and in-memory backends

**What needs fixing:**

**1. Remove Nostr types from storage types.** `Group` in `mdk-storage-traits` has a `nostr_group_id` field. This leaks
Nostr knowledge into a layer that should be transport-agnostic. The group ID in storage should be the MLS group ID only.
The mapping between MLS group ID and Nostr group ID belongs in whitenoise-core's transport adapter, not in MDK storage.

```rust
// Current (wrong):
pub struct Group {
    pub mls_group_id: GroupId,
    pub nostr_group_id: [u8; 32],  // ← Nostr leak
    pub relays: Vec<RelayUrl>,      // ← Nostr leak
    // ...
}

// Target:
pub struct Group {
    pub mls_group_id: GroupId,
    pub name: String,
    pub epoch: u64,
    pub members: Vec<Member>,
    pub required_capabilities: GroupCapabilities,
    // No Nostr types here
}
```

The transport adapter in whitenoise-core maintains the mapping between `GroupId` → `NostrGroupId` and `GroupId` → relay
URLs. MDK doesn't need to know about relays at all.

**2. Add a `CapabilityStorage` trait** for the feature registry and per-group capability state.

```rust
pub trait CapabilityStorage {
    /// Get the registered capability requirement for a feature
    fn feature_requirement(&self, feature: &Feature) -> Option<CapabilityRequirement>;

    /// Register a feature (called at startup with the feature registry)
    fn register_feature(&self, feature: Feature, req: CapabilityRequirement) -> Result<()>;

    /// Cache a member's advertised capabilities (from their latest KeyPackage)
    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> Result<()>;

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
    ) -> Result<Option<GroupCapabilities>>;
}
```

**3. `MdkStorageProvider` becomes:**

```rust
pub trait MdkStorageProvider:
    GroupStorage
    + MessageStorage
    + WelcomeStorage
    + CapabilityStorage
    + StorageProvider<CURRENT_VERSION>
{
    fn backend(&self) -> Backend;
    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> Result<()>;
    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> Result<()>;
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> Result<()>;
}
```

---

## The feature registry: fixing the static constants problem

Currently `SUPPORTED_PROPOSALS` and `GROUP_CONTEXT_REQUIRED_PROPOSALS` are static constants. This is what causes
migration pain — you can't query "does this group support SelfRemove?" at runtime in a way that accounts for members'
actual KeyPackages.

Replace with a runtime feature registry that is initialized at startup:

```rust
pub struct FeatureRegistry {
    features: HashMap<Feature, FeatureSpec>,
}

pub struct FeatureSpec {
    /// Exactly one MLS primitive (proposal type or extension type) that this feature requires.
    ///
    /// One feature = one capability. If a user-facing feature needs multiple MLS primitives
    /// (e.g. both a new extension type and a new proposal type), model it as two separate
    /// Feature variants, each with their own FeatureSpec.
    ///
    /// A group's RequiredCapabilities is always the flat union of all active features'
    /// capabilities — no dependency graph, no traversal, easy to reason about.
    pub requires: Capability,

    /// Required: must be in RequiredCapabilities for all group members
    /// Optional: group can use if all current members happen to support it
    pub requirement_level: RequirementLevel,

    /// Human-readable description (used in UI hints)
    pub description: &'static str,

    /// Since which app version this feature is supported
    pub since_version: AppVersion,
}

pub enum RequirementLevel {
    /// Must be in RequiredCapabilities. New members cannot join without supporting this.
    Required,
    /// Group uses it if universally supported by current members.
    /// New members who don't support it can still join (feature becomes unavailable for them).
    Optional,
    /// Required if and only if a specific transport is active.
    /// See Transport Features below.
    TransportRequired { transport: TransportKind },
}
```

**Why one capability per feature?**

The alternative — a `Vec<Capability>` or a `depends_on: Vec<Feature>` graph — makes it hard to reason about what a group
actually requires. "What does this group need?" becomes a traversal instead of a flat lookup.

With one-capability-per-feature:

- `RequiredCapabilities` = simple union of all active features' single capabilities
- No graph traversal, no hidden dependencies
- Easy to audit: the feature registry is a flat list you can read top-to-bottom

The UI layer activates user-facing features by calling `upgrade_group_capabilities()`, which applies the full set of
upgradeable capabilities atomically. A user-facing "disappearing messages" might map to two engine-level features
(`DisappearingMessagesExtension` + `DisappearingMessagesProposal`), but the user never sees that split — they just see
the feature become available when both capabilities are satisfied.

The registry is populated at `MDK` initialization with all known features. `CapabilityManager` reads from it. The
`CapabilityStorage` trait caches member capabilities locally so `feature_status()` is always a local, cheap operation.

**Migration from static constants:** The existing `SUPPORTED_PROPOSALS` and `GROUP_CONTEXT_REQUIRED_PROPOSALS` arrays
become the initial state of the feature registry. No wire format changes needed.

---

## Transport features: extensions as first-class citizens

This is a significant mental model shift from how MDK currently works.

**Current model:** `NostrGroupData` is a single hardcoded extension. There is no concept of transport-specific
extensions. Every group has it because every group is Nostr.

**Target model:** Transport-specific metadata extensions are features like any other, governed by the same
`RequiredCapabilities` / `FeatureRegistry` system. A group that uses Nostr transport requires `NostrGroupData`. A group
that uses FIPS mesh transport would require a `FipsGroupData` extension. A group using both requires both.

```rust
pub enum Feature {
    // ── Transport features ────────────────────────────────
    /// Nostr relay transport. Requires the NostrGroupData extension (0xF2EE).
    /// Contains: nostr_group_id, relay hints.
    NostrTransport,

    /// FIPS mesh transport (future). Requires a FipsGroupData extension.
    /// Contains: mesh routing hints, FIPS-specific group addressing.
    FipsTransport,

    // ── Protocol features ─────────────────────────────────
    SelfRemove,
    DisappearingMessages,
    EndToEndMedia,       // MIP-04
    MultiDevice,         // MIP-06
    GroupCalling,        // MIP-06 mesh calls
    // etc.
}
```

**Transport features in the registry:**

```rust
Feature::NostrTransport => FeatureSpec {
    requires: Capability::Extension(NOSTR_GROUP_DATA_EXTENSION_TYPE), // 0xF2EE
    requirement_level: RequirementLevel::TransportRequired {
        transport: TransportKind::Nostr
    },
    description: "Nostr relay transport metadata",
    since_version: AppVersion::initial(),
},

Feature::FipsTransport => FeatureSpec {
    requires: Capability::Extension(FIPS_GROUP_DATA_EXTENSION_TYPE), // future assigned type
    requirement_level: RequirementLevel::TransportRequired {
        transport: TransportKind::Fips
    },
    description: "FIPS mesh transport metadata",
    since_version: AppVersion::future(),
},
```

**What this means for group creation:**

When whitenoise-core creates a group, it passes the intended transports:

```rust
engine.create_group(
    members,
    name,
    transports: &[TransportKind::Nostr],  // or [Nostr, Fips] for multi-transport
)
```

The engine (or more precisely, the active transport adapters) constructs the appropriate transport extensions before
creating the MLS group. A group with `transports: [Nostr, Fips]` would have both `NostrGroupData` and `FipsGroupData` in
its `RequiredCapabilities`, meaning all members must have clients that support both transports.

**Transport adapters provide their extension data:**

```rust
trait TransportAdapter {
    // existing methods...

    /// Returns the MLS extension this transport requires, and its content.
    /// Called during group creation to populate RequiredCapabilities.
    fn group_extension(&self, group_id: &GroupId) -> Option<(ExtensionType, Vec<u8>)>;
}
```

The Nostr adapter returns `(NOSTR_GROUP_DATA_EXTENSION_TYPE, serialized_nostr_group_data)`. The FIPS adapter would
return its own. The engine assembles these into the group's extension list and `RequiredCapabilities` at creation time.

**Key insight:** The `NostrGroupRegistry` (the GroupId → NostrGroupId + relay URL mapping) that lives in
whitenoise-core's transport adapter is _derived from_ the `NostrGroupData` extension that lives in the MLS group. The
extension is the source of truth; the registry is a local index for fast lookup. When a new member receives a Welcome
message, they read the `NostrGroupData` extension from the group state and populate their local registry. No separate
communication needed.

**Why this matters long-term:**

Today, adding FIPS support would require changes throughout MDK and whitenoise-rs because Nostr transport is baked in.
With this model:

- Adding FIPS requires: a new `FipsGroupData` extension type, a `FipsTransport` feature in the registry, a `FipsAdapter`
  implementing `TransportAdapter`, and a `FipsMlsPeeler` implementing `TransportPeeler`
- MDK itself changes nothing — the engine is transport-agnostic by design
- Existing Nostr groups continue working unchanged
- New groups can opt into FIPS, Nostr, or both at creation time

---

## What needs cleaning up first (pragmatic order)

Given the session-projection refactor is in progress, here's the recommended order to avoid conflict:

**1. While session projection is landing:**

- Define the `CgkaEngine` trait as a document (like we did for `TransportAdapter`) — no code yet, just the interface
- Add the `feature_status()` / `constructable_capabilities()` / `upgradeable_capabilities()` methods to MDK as concrete
  additions (don't need the trait first to get the value)
- Add the feature registry as a new module in `mdk-core`

**2. After session projection:**

- Extract `EpochManager` into its own internal module — the `EpochState` enum with the state machine
- Add `CapabilityStorage` trait to `mdk-storage-traits` + implement in both backends
- Start removing Nostr types from `mdk-storage-traits` (coordinate with whitenoise-core changes)

**3. Later (as part of CGKA trait introduction):**

- Implement `CgkaEngine` on `MDK<Storage>`
- Update whitenoise-core to call `engine: Box<dyn CgkaEngine>` rather than `mdk: MDK<S>` directly

---

## How this connects to the target architecture

```
whitenoise-core
  → calls CgkaEngine trait methods only
  → never instantiates MDK<Storage> directly (in target state)
  → holds engine: Box<dyn CgkaEngine>

MDK<Storage> implements CgkaEngine
  → internal: GroupLifecycle, MessageProcessor, EpochManager,
              CapabilityManager, KeyPackageManager
  → each subsystem has explicit state machines where needed
  → storage accessed only through MdkStorageProvider trait
  → no Nostr types in MDK public API or storage traits

TransportPeeler (injected into engine)
  → NostrMlsPeeler: unwraps kind 445 using group exporter secret
  → is the ONLY place Nostr types appear in the engine layer

TransportAdapter (in whitenoise-core)
  → maintains GroupId ↔ NostrGroupId mapping
  → maintains GroupId ↔ relay URLs mapping
  → none of this lives in MDK
```

The current MDK is ~66k LOC including tests and storage implementations. The target is a cleaner 66k, not necessarily
smaller — but with the complexity in the right places and the Nostr leakage eliminated. The storage traits are already
the best part of the codebase; the state machines and capability system are the biggest gaps.
