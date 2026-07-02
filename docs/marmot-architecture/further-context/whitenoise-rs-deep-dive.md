# whitenoise-rs Deep Dive

> **Reference doc.** This is a detailed analysis of the current codebase. You don't need to read it to understand the
> target architecture — but if you're making changes to whitenoise-rs or evaluating the refactor scope, this is the
> place to start.

**The problem this addresses:** Before deciding how to evolve the architecture, we need an honest picture of what we're
working with. Where is the complexity? What's well-designed? What's a load-bearing wall? This document answers those
questions based on a full code review.

whitenoise-rs is where the complexity lives. At ~100K LOC it is larger than the crypto layer (mdk, 66K) and the
presentation layer (whitenoise Flutter, 66K Dart) combined in terms of conceptual density. Understanding this codebase
is prerequisite to making any architectural decision about Marmot's future.

## Major Subsystems

### 1. The Whitenoise Singleton

The entire application is organized around a global singleton struct initialized via
`Whitenoise::initialize_whitenoise()` and accessed via `Whitenoise::get_instance()`. This struct holds ~25 fields
spanning every domain:

```rust
Whitenoise {
    config, database, event_tracker, content_parser,
    relay_control, secrets_store, storage, message_aggregator,
    message_stream_manager, user_stream_manager,
    chat_list_stream_manager, notification_stream_manager,
    event_sender, shutdown_sender,
    contact_list_guards, user_resolution_guards,
    background_task_cancellation, external_signers,
    pending_logins, discovery_sync_worker,
    pending_push_token_responses, token_response_semaphore,
    token_request_timestamps,
}
```

This design was pragmatic for early development — FFI requires static initialization, and a singleton simplifies Flutter
integration. But it has become the primary obstacle to testing, modularity, and reasoning about state ownership. Account
scope is enforced by convention (passing `pubkey` arguments), not by the type system. A known bug in
`message_delivery_status` exists because of this.

### 2. Relay Control Plane (~7K LOC)

The newest and most architecturally interesting subsystem. Replaces the earlier approach of a single `nostr-sdk` client
with four specialized planes:

- **Discovery plane** — user metadata (kind 0), relay lists (NIP-65, NIP-50, NIP-51), follow lists (kind 3). Long-lived
  subscriptions, concurrent relay connections.
- **Group plane** — MLS message subscriptions per group. Long-lived relay connections for each active chat.
- **Account inbox plane** — per-account giftwrap (kind 1059) and mute list (kind 10004) subscriptions.
- **Ephemeral plane** — one-off queries (key package fetches, user relay sync). Connection pooling with per-relay
  limits, 30s timeout.

Each plane manages its own relay sessions. Sessions handle WebSocket lifecycle, automatic reconnection with exponential
backoff, subscription context tracking, and frame decompression. A router dispatches events from sessions to the
appropriate handler based on subscription context.

**Status:** Operational but migration incomplete. Legacy shared-client code paths still exist alongside the new planes.

### 3. Event Processing (~4.6K LOC)

All inbound Nostr events flow through a single `mpsc` channel into a sequential event processor:

```
Events → event_sender (mpsc) → processor task → {
    Global: discovery metadata, follow lists
    Per-account: MLS messages, giftwraps, metadata, relay lists, mute lists
}
```

Six specialized handlers:

- `handle_mls_message` (2,329 LOC) — the largest and most coupled handler. Processes MLS messages via MDK, updates
  aggregated messages, triggers streaming, resolves user metadata, tracks delivery status.
- `handle_giftwrap` (1,110 LOC) — NIP-59 giftwrap decryption and routing.
- `handle_contact_list` (578 LOC) — follow relationship processing.
- `handle_metadata` (235 LOC) — user profile caching.
- `handle_relay_list` (181 LOC) — NIP-65/50/51 relay list processing.
- `handle_mute_list` (140 LOC) — mute list processing.

The single-consumer design ensures ordering within a single account but serializes all event processing globally. This
is a deliberate simplicity trade-off — per-account parallelism is possible but deferred.

### 4. Database Layer (~22K LOC)

29 domain-specific SQLx modules. Compile-time query verification. Connection pooling (max 10, 5s acquire timeout) with
retry logic for transient SQLite locks.

Critical tables: accounts, users, groups, group_memberships, aggregated_messages (4,831 LOC module!), published_events,
published_key_packages, media files, relay subscriptions, processed_events (deduplication), push registrations.

45 sequential migrations reflect the evolution of the schema over time. The single-database design (all accounts share
one SQLite file) is a known pain point that the refactor addresses with per-account database files.

### 5. Account Management (~8K LOC)

Three login flows reflecting the complexity of Nostr identity:

- **Standard login** (1,025 LOC) — nsec/hex private key with relay discovery
- **Multi-step login** (3,255 LOC) — interactive relay list discovery and key package publishing. The largest single
  file in the accounts module.
- **External signer login** (959 LOC) — NIP-55 (Amber) integration for hardware-backed keys

Account setup (1,557 LOC) handles creation, metadata publishing, and initial relay configuration.

### 6. Message Handling (~5.2K LOC)

Message operations (3,092 LOC) cover sending, deletion, reactions, and delivery status tracking. The message aggregator
subsystem (2,099 LOC) is a separate concern — it combines messages with reactions, handles emoji normalization, and
manages in-memory aggregation state. These two modules are tightly coupled through the streaming layer.

### 7. Push Notifications (3,632 LOC)

MIP-05 token list management. The largest single file in the codebase. Complex state machine for delayed token response
handling with rate limiting, per-group token caching, and MDK integration for token encryption. This is a strong
candidate for extraction into its own crate or at minimum its own module directory.

### 8. Streaming Infrastructure

Four broadcast channel managers provide real-time updates to Flutter:

- **Message streaming** — per-group message updates with pagination
- **Chat list streaming** — snapshot + delta updates for the main list
- **User streaming** — metadata change notifications
- **Notification streaming** — group event notifications (joins, leaves, key changes)

Pattern: `tokio::sync::broadcast` for fan-out. No backpressure — slow subscribers get dropped. Initial snapshot is sent
before live updates to avoid races.

### 9. User Search (~4 modules)

Five-tier async fetch pipeline: cached graph → follows → follows-of-follows → relay discovery → NIP-50 search relay.
Social graph traversal with concurrency limits, fuzzy keyword matching, and TTL-based cache invalidation.

### 10. Scheduled Tasks (1,793 LOC)

Six background jobs running on `tokio::interval`:

- Key package maintenance (865 LOC) — regenerate below threshold
- Relay list maintenance (475 LOC) — refresh lists, rebuild subscriptions
- Consumed key package cleanup (228 LOC)
- Mute expiry cleanup (92 LOC)
- Cached graph user cleanup (69 LOC)
- Subscription health check (51 LOC)

## Where the Complexity Lives

Ranked by coupling × size × change frequency:

1. **`handle_mls_message.rs`** (2,329 LOC) — touches MDK, message aggregator, database, relay control, user resolution,
   and streaming. Every MLS protocol change ripples through here. This is the critical path for message delivery and the
   hardest code to reason about.

2. **`push_notifications.rs`** (3,632 LOC) — complex interaction between MDK (token encryption), database, relay control
   (ephemeral plane), and rate limiting state machines. Needs extraction.

3. **`accounts_groups.rs`** (2,821 LOC) — the chat membership state machine. Handles join/leave, archive/restore, mute,
   clear, pin/unpin with database persistence and streaming trigger side effects.

4. **`login_multistep.rs`** (3,255 LOC) — the multi-step login flow with relay discovery. High user-facing complexity,
   many edge cases around relay availability and external signers.

5. **The database layer** (22K LOC) — sheer size. The `aggregated_messages.rs` module alone is 4,831 LOC. Changes to
   schema affect many modules simultaneously.

## The Planned Refactor

The session-projection rearchitecture (documented in `docs/session-projection-rearchitecture.md` and
`docs/session-projection-implementation-plan.md`) addresses the singleton problem. Key changes:

### Target Architecture

```
Whitenoise (thin facade — constructed, not singleton)
├── shared: Arc<SharedServices>
│   ├── shared_db, relay_control, user_directory, search,
│   │   app_settings, media_cache, event_tracker, stream_hubs
│
└── accounts: AccountManager
    └── sessions: HashMap<PublicKey, Arc<AccountSession>>

AccountSession (per login)
├── account_pubkey, shared: Arc<SharedServices>
├── account_db: Arc<AccountDatabase>
├── mdk: Arc<MDK<MdkSqliteStorage>>
├── signer: Arc<dyn NostrSigner>
├── repos: AccountRepositories
├── inbox, ephemeral, group_relay (scoped handles)
└── cancellation: watch::Sender<bool>
```

### Key Design Decisions

1. **View pattern for operations** — `session.messages()` returns a lightweight borrowed `MessageOps<'a>` that doesn't
   own the session and can't spawn tasks. Callers (Arc owners) decide whether to spawn.

2. **Per-account database files** — each account gets `account_<pubkey>.sqlite`. Account deletion becomes
   `fs::remove_file`. No more `WHERE account_pubkey = ?` everywhere.

3. **MDK caching** — `create_mdk_for_account()` is currently called ~87 times, creating fresh encrypted DB connections
   each time. Session holds `Arc<MDK>` for its lifetime.

4. **19 phases** — each ~700-1000 LOC, independently landable, app stays working throughout.

5. **Testing transition at Phase 12** — singleton removal breaks existing integration tests. New three-tier model: unit
   (in-memory), MockRelay (in-process), Docker (Blossom only).

### What the Refactor Gets Right

- **Account scope via type system** — the core insight is correct. Convention-based scoping is a bug factory.
- **Incremental approach** — 19 phases with compatibility shims is pragmatic.
- **Per-account databases** — eliminates a class of scope bugs and simplifies deletion.
- **Testing strategy** — MockRelay-based tests are a major improvement. Eliminating Docker for routine development will
  accelerate iteration.
- **View pattern** — clean separation of "what to do" from "how to schedule it."

### What It Might Be Missing

1. **The singleton is a symptom, not the disease.** The real problem is that whitenoise-rs is one monolithic crate doing
   everything — Nostr networking, account management, MLS integration, storage, push notifications, user search, chat
   management. The refactor reorganizes ownership within this monolith but doesn't decompose it into independent
   libraries. See [[architectural-alternatives#Decomposition into smaller standalone libraries]].

2. **Event processing stays single-lane.** The refactor explicitly defers per-session concurrency. For small numbers of
   accounts this is fine. For use cases where multiple accounts are active simultaneously under load, the single event
   processor becomes a bottleneck.

3. **Relay control plane migration is incomplete** and the refactor doesn't address it. Two code paths (legacy + new
   planes) will continue to coexist.

4. **No transport abstraction.** MDK is somewhat transport-blind, but whitenoise-rs bakes in Nostr relay assumptions
   deeply — event kinds, gift wrapping, NIP-specific flows. If the team ever wants to support alternative transports
   (FIPS mesh, direct P2P), this coupling would need to be unwound first.

5. **Durable task runtime is deferred.** The documents acknowledge that fire-and-forget `tokio::spawn` for
   publish/welcome/key-package operations is fragile, but punt the solution to post-refactor. This is a real operational
   risk — dropped tasks mean lost messages or orphaned state.

6. **No consideration of the state machine alternative.** The refactor assumes the async-with-shared-state model is
   correct and optimizes within it. It doesn't evaluate whether a deterministic event-driven state machine would be a
   better foundation. See [[architectural-alternatives#Event loop / deterministic state machine model]].
