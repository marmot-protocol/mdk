# Codebase Survey

> **Reference doc.** Raw data only — skip this unless you need to understand the current size, shape, or dependency
> structure of the repos. For architectural direction, read [[target-architecture]] instead.

**What this covers:** LOC breakdowns, dependency graphs, and module structures for whitenoise (Flutter), whitenoise-rs
(Rust application layer), and mdk (Rust protocol layer). Facts, not opinions.

## Line Counts

### mdk (~66K LOC Rust)

| Crate | LOC | Purpose |
| --- | --- | --- |
| mdk-core | 14,666 | MLS/Nostr integration, group ops, message processing |
| mdk-sqlite-storage | 9,758 | SQLCipher-backed persistent storage |
| mdk-memory-storage | 7,011 | In-memory storage for testing |
| mdk-uniffi | 3,859 | FFI bindings (Swift/Kotlin/Python) |
| mdk-storage-traits | 1,112 | Storage abstraction traits |
| mdk-macros | 343 | Builder/setter proc macros |

**Largest files:**

- `mdk-core/src/groups.rs` — 6,238 lines (group management)
- `mdk-sqlite-storage/src/lib.rs` — 4,858 lines (StorageProvider impl)
- `mdk-core/src/messages/commit.rs` — 2,461 lines (commit processing + rollback)
- `mdk-core/src/encrypted_media/manager.rs` — 2,338 lines (MIP-04)
- `mdk-core/src/messages/validation.rs` — 2,142 lines (identity/proposal validation)
- `mdk-core/src/key_packages.rs` — 3,318 lines (key package lifecycle)

### whitenoise-rs (~100K LOC Rust)

| Module | LOC | Purpose |
| --- | --- | --- |
| whitenoise/ (core) | ~29,366 | Application logic |
| database/ | 22,015 | 29 SQLx domain modules |
| relay_control/ | 6,994 | Relay plane architecture |
| accounts/ | 8,044 | Account mgmt + login flows |
| event_processor/ | 4,579 | Event routing + handlers |
| cli/ | 4,260 | CLI daemon + client |
| push_notifications | 3,632 | MIP-05 token management |
| messages | 3,092 | Message operations |
| accounts_groups | 2,821 | Chat membership state |
| users | 2,691 | User discovery + metadata |
| groups | 2,574 + 1,515 | MLS group operations |
| chat_list | 2,260 | Chat list logic |
| message_aggregator/ | 2,099 | Reactions, aggregation |
| key_packages | 1,889 | Key package lifecycle |
| scheduled_tasks/ | 1,793 | 6 background jobs |
| nostr_manager/ | 1,003 | Nostr utilities |

**45 SQLite migrations** (0001_accounts through 0045_mute_list)

### whitenoise (Flutter)

| Layer | LOC | Files |
| --- | --- | --- |
| Dart (total) | 66,255 | 241 |
| Rust API wrapper | 4,864 | 20 modules |
| FFI generated | ~351KB | frb_generated.dart |
| Screens | 10,600 | 40 |
| Hooks | 5,353 | 47 |
| Providers | ~1,500 | 14 |
| Widgets | ~15,000 | 80+ |
| Tests | ~30,000 | 210 |

## Dependency Graphs

### mdk Dependencies

**Core crypto:**

- openmls 0.8.1 + openmls_traits 0.5 + openmls_rust_crypto 0.5.1
- chacha20poly1305, hkdf, sha2
- nostr 0.44 (with nip44)

**Storage:**

- rusqlite (SQLCipher-bundled)
- refinery (schema migrations)

**Security:**

- keyring-core 0.7 (platform keychains)
- zeroize (secret memory wiping)

**Serialization:**

- serde + serde_json, postcard, tls_codec

**Config:** Edition 2024, MSRV 1.90.0, workspace version 0.7.1

### whitenoise-rs Dependencies

**Nostr:**

- nostr-sdk (with NIP-44, NIP-59)
- nostr-relay-builder (MockRelay for testing — transitive)

**Async:**

- tokio (full features)
- futures

**Storage:**

- sqlx (SQLite, runtime-tokio)

**Concurrency:**

- dashmap

**Crypto:**

- mdk (local path dependency)

**Config:** Edition 2024, MSRV 1.90.0, single workspace with proc-macro helper crate

### whitenoise (Flutter) Dependencies

**State management:** flutter_riverpod, flutter_hooks, riverpod_annotation **Navigation:** go_router **FFI:**
flutter_rust_bridge 2.11.1 **Storage:** flutter_secure_storage **UI:** flutter_screenutil, cached_network_image
**Platform:** platform-specific signer, notifications

## Module Structure Details

### mdk Crate Architecture

```
crates/
├── mdk-core/src/
│   ├── lib.rs (MDK struct, builder, config)
│   ├── groups.rs (6,238 — create, add/remove, update, metadata sync)
│   ├── messages/
│   │   ├── commit.rs (race resolution, rollback, eviction)
│   │   ├── validation.rs (identity, proposals, timestamps)
│   │   ├── process.rs (message orchestration)
│   │   ├── error_handling.rs (failure recovery)
│   │   ├── decryption.rs (multi-secret fallback)
│   │   ├── create.rs (event creation, wrapping)
│   │   ├── proposal.rs (add/remove/update)
│   │   ├── application.rs (app messages)
│   │   └── crypto.rs (ChaCha20-Poly1305, NIP-44 legacy)
│   ├── key_packages.rs (generation, validation, inspection)
│   ├── epoch_snapshots.rs (MIP-03 rollback snapshots)
│   ├── extension/ (NostrGroupDataExtension, group images)
│   ├── encrypted_media/ (MIP-04, feature-gated)
│   ├── welcomes.rs (welcome processing)
│   ├── mip05/ (Nostr Rumor support, optional)
│   └── callback.rs, error.rs, prelude.rs, util.rs
│
├── mdk-storage-traits/src/
│   ├── lib.rs (MdkStorageProvider trait)
│   ├── groups/ (GroupStorage trait + types)
│   ├── messages/ (MessageStorage trait + types)
│   └── welcomes/ (WelcomeStorage trait + types)
│
├── mdk-sqlite-storage/src/
│   ├── lib.rs (4,858 — connection mgmt, snapshot ops)
│   ├── mls_storage/ (OpenMLS StorageProvider impl)
│   ├── groups.rs, messages.rs, welcomes.rs
│   ├── encryption.rs (SQLCipher key mgmt)
│   └── keyring.rs (platform keychain)
│
├── mdk-memory-storage/src/
│   ├── lib.rs (RwLock + LRU cache)
│   ├── mls_storage/ (in-memory OpenMLS impl)
│   └── snapshot.rs (full state capture/restore)
│
├── mdk-uniffi/src/
│   └── lib.rs (UniFFI wrappers, error mapping)
│
└── mdk-macros/src/
    └── lib.rs (setters!, mut_setters!, ref_getters!)
```

### whitenoise-rs Module Layout

```
src/
├── whitenoise/
│   ├── mod.rs (3,665 — Whitenoise singleton struct + init)
│   ├── accounts/ (login, setup, external signers)
│   ├── messages.rs (send, delete, react)
│   ├── message_aggregator/ (reactions, emoji, state)
│   ├── groups.rs + groups/ (MLS ops, membership, media)
│   ├── users.rs + users/ (discovery, relay sync, key packages)
│   ├── accounts_groups.rs (chat membership state machine)
│   ├── chat_list.rs (sort, pin, archive, unread)
│   ├── push_notifications.rs (MIP-05 tokens)
│   ├── key_packages.rs (publish, validate, maintain)
│   ├── event_processor/ (routing + 6 handlers)
│   ├── chat_list_streaming/ (broadcast channels)
│   ├── message_streaming/ (per-group streams)
│   ├── user_streaming/ (metadata updates)
│   ├── notification_streaming/ (group events)
│   ├── user_search/ (5-tier pipeline, NIP-50)
│   ├── database/ (29 domain modules, 22K LOC)
│   ├── scheduled_tasks/ (6 background jobs)
│   ├── storage/ (filesystem media cache)
│   ├── secrets_store.rs (platform keychains)
│   └── error.rs (WhitenoiseError enum)
│
├── relay_control/
│   ├── mod.rs (RelayControlPlane orchestrator)
│   ├── discovery.rs (user/relay metadata)
│   ├── groups.rs (MLS subscriptions per group)
│   ├── account_inbox.rs (giftwrap, mute list)
│   ├── ephemeral.rs (one-off queries)
│   ├── sessions/ (WebSocket lifecycle)
│   ├── router.rs (event dispatch)
│   └── observability.rs (latency, counters)
│
├── nostr_manager/ (parser, utils)
├── cli/ (daemon, client, commands)
└── bin/ (wnd, wn, test runners)
```

### whitenoise (Flutter) Layout

```
lib/
├── main.dart (app init)
├── routes.dart (40+ routes, go_router)
├── providers/ (14 Riverpod providers)
├── hooks/ (47 custom hooks, 5.3K LOC)
├── screens/ (40 screens, 10.6K LOC)
├── widgets/ (80+ components)
├── services/ (7 stateless services)
├── src/rust/
│   ├── api/ (26 auto-generated bridge files)
│   └── frb_generated.dart (351KB)
├── utils/ (13 utility modules)
└── constants/

rust/src/api/ (20 modules, 4.8K LOC — thin FFI wrapper)
```

## Key Metrics

| Metric | mdk | whitenoise-rs | whitenoise |
| --- | --- | --- | --- |
| Total LOC | ~66K Rust | ~100K Rust | 66K Dart + 5K Rust |
| Crates/packages | 6 | 2 | 1 |
| Edition | 2024 | 2024 | Flutter 3.x |
| MSRV | 1.90.0 | 1.90.0 | — |
| DB technology | SQLCipher (rusqlite) | SQLite (sqlx) | — (delegates to Rust) |
| Async model | Synchronous | Tokio (full) | Dart async |
| FFI | UniFFI | flutter_rust_bridge | flutter_rust_bridge |
| Test framework | Unit (in-module) | Integration (Docker) | Widget + unit (99% coverage) |
| Migrations | refinery | sqlx (45 files) | — |
