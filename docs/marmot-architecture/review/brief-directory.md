---
title: "Extraction Brief — Directory into nostr-directory"
created: 2026-10-20
updated: 2026-10-20
tags: [marmot, architecture, review, extraction-brief, directory, nostr]
status: proposed; product-owner decisions made 2026-10-20
---

# Extraction Brief — Directory into `nostr-directory`

Step 3 of the [core structure plan](core-structure.md#5-sequencing). It moves the directory out of `marmot-app` into
a new `nostr-directory` crate without changing behaviour. The directory is the app's cache and lookup service for
other people's public Nostr data: profiles, follow lists, relay lists, KeyPackages, user search and public event
previews. `path:line` citations are at `3fc77b82c` (master after #2493). Production line counts exclude
`#[cfg(test)]` modules. Following the [review's evidence rules](README.md#evidence-rules), statements are observed in
source unless marked (hypothesis).

## Why this seam now

- **It already keeps to itself.** The directory makes no production call to account storage. Its only
  `account_storage(` call is in a test (`directory/sync.rs:683`). It has no account-worker command
  (`runtime/account_worker.rs:339`), and its writes go to its own cache database and the shared database.
- **It is big, and most of it is methods on the hub.** `marmot-app/src/directory/` is 7,551 production lines, and 86
  production methods sit in five `impl MarmotApp` blocks (`methods.rs:55`, `member_key_packages.rs:234`,
  `cached_search.rs:14`, `search.rs:226`, `key_package_recovery.rs:39`). Moving them behind one owned service takes
  the largest product domain off `MarmotApp`.
- **Steps 2 and 4 cleared the way.** The relay plane it calls is in `transport-nostr` (#2387), and the shared
  database it writes is behind `storage-sqlite`'s `SqliteSharedStorage` (`storage-sqlite/src/shared.rs:149`).

## What the directory is today

| Part | Where | Production lines |
| --- | --- | ---: |
| Hub methods: relay-list, profile, follow and KeyPackage fetches; cache lifecycle; ingest; merge with the shared tier | `directory/methods.rs` | 2,046 |
| Streaming web-of-trust search and Open Ranking discovery | `directory/search.rs`, `open_ranking.rs` | 1,812 |
| Whole-roster KeyPackage resolution for create, invite and prewarm; the prewarm cache; supplementary-relay recovery | `directory/member_key_packages.rs`, `key_package_recovery.rs` | 1,251 |
| Per-account cache: `DirectoryCache`, its migration runner and ledger | `directory/cache.rs`, `cache/migrations.rs`, `cache/v1.sql`, `cache/v2.sql` | 1,022 + 73 SQL |
| Records, merge rules and match ranking (the public DTOs) | `directory/records.rs` | 772 |
| Sync planner and background worker | `directory/sync.rs` | 467 |
| Network-free search over cached data | `directory/cached_search.rs` | 153 |

It owns these:

- **A per-account SQLCipher cache.** The file is `<account>/app-cache.sqlite3` (`lib.rs:398`, `methods.rs:1790-1792`),
  keyed with its own HKDF label `marmot-app/directory-cache-sqlcipher-key/v2` (`sqlcipher.rs:183-203`). It has its own
  migration ledger, `app_cache_schema_migrations` (`cache/migrations.rs:72`).
  - Migration 1 creates the directory's six tables (`cache/v1.sql`).
  - Migration 2 creates `public_event_previews` (`cache/v2.sql`). That table belongs to `public_event_preview.rs`,
    which uses the directory's cache handle for raw SQL (`public_event_preview.rs:631`, `:692`, `:764`).
- **State held on the hub.**
  - The cache map `directory_caches` (`lib.rs:545`).
  - The sync handle `directory_sync` (`lib.rs:531`). It is also held a second time on the runtime
    (`runtime/mod.rs:194`).
  - The KeyPackage prewarm cache (`lib.rs:551`), at most 256 entries with a 5-minute TTL
    (`member_key_packages.rs:43-44`).
  - The legacy-import flag (`lib.rs:552`) and the previews' refresh cooldowns (`lib.rs:548`).
  - Test clocks and counters (`lib.rs:554-558`).
- **One-off root files.** A legacy plaintext cache is imported once and deleted (`methods.rs:1886-1947`). A
  future-dated cleanup marker is written once (`methods.rs:1949-1974`).

It uses, but does not own, `<root>/shared.sqlite3`. That database is plain SQLite owned by `storage-sqlite`
(`shared.rs:149-160`). It holds the public directory tier, and also settings. Chat presentation
(`chat_presentation/maintenance.rs:44`) and avatars (`runtime/avatar.rs:40`) read it. The hub opens it
(`lib.rs:7463-7488`), and each saved entry is written to it and to every active account's cache
(`methods.rs:1712-1740`).

## Corrections to the plan

[Core structure](core-structure.md) estimated this step from the module tree. The source says:

- **86 methods on `MarmotApp`, not 67.** 67 is `methods.rs` alone.
- **About 9.0k production lines move, not 11–13k** (see "What moves and what stays"). 11.5k is `directory/` with
  its tests.
- **The relay-plane directory code stays in `transport-nostr`.** `transport-nostr/src/directory.rs` and
  `directory_wire.rs` are relay I/O (about 640 lines) and relay-plane state (about 385 lines): request coalescing,
  subscription and admission bookkeeping, and health. None of it is the directory's caching, freshness or merge
  logic. The [relay-plane brief](brief-relay-plane.md#what-moves-and-what-stays) expected step 3 to take
  "directory bookkeeping" from those files, but there is none there.
- **"Its own databases" needs a qualifier.** The directory owns its per-account cache. The shared database stays with
  `storage-sqlite`, because other readers use it.

## Decision: a new crate above the transport and storage

Create `crates/nostr-directory`. It depends on `transport-nostr`, `transport-nostr-adapter` (event kinds and the
process proxy), `transport-nostr-peeler`, `storage-sqlite`, `cgka-traits`, `cgka-engine` (KeyPackage metadata
checks) and `fs-private`. It depends on neither `marmot-app` nor `marmot-account`, nor on `cgka-session`, which step 5
merges into `marmot-session`. Whatever it needs from the app comes through the host interface below.

- It sits beside the media store as an app service, as in [core structure §4](core-structure.md#4-proposed-target-structure).
- Its relay seam is the relay plane's directory methods (`transport-nostr/src/lib.rs:1902-2159`), not the
  `DirectoryRelayFetcher` trait. The plane methods add relay-safety sanitizing, coalescing and subscription state that
  a direct trait caller would bypass. Today they are `#[doc(hidden)]`; this crate becomes their documented consumer.

## What moves and what stays

| Code | Lines | Moves? |
| --- | ---: | --- |
| `directory/` except publication | about 7,330 | Moves |
| `public_event_preview.rs` | 830 | Moves, as `previews`. It shares the cache database, its key and its migration ledger, so it can't stay behind without splitting that ledger. |
| The directory half of `key_package_records.rs` (other accounts' relay-list status, KeyPackage ranking and selection, revocation evidence, cached-KeyPackage checks) | about 700 | Moves. It breaks today's import cycle between `directory/` and `key_package_records.rs` (`key_package_records.rs:25-31`, `directory/methods.rs:40-44`). |
| Directory types at the `marmot-app` root: `AccountRelayListStatus`, `AccountRelayListState`, `MissingRelayListKind`, `FetchedKeyPackage`, `DirectoryFreshness`, `DirectorySelection`, `sort_directory_records`, the relay-list event parsers, the search caps and kinds 0 and 3 | about 150 | Moves; `marmot-app` re-exports the public ones at the same paths |
| Profile and follow-list publication (`methods.rs:826-1047`) | about 220 | Stays. It is the account publishing its own state, and needs the signer, publish clients, quorum delivery and indexer copies (`lib.rs:3121-3262`, `:7490`, `:7554`). It calls the directory to remember what it published. |
| `retain_safe_discovered_endpoints` (`methods.rs:1315`) | 8 | Stays on `MarmotApp` for its 10 callers there (`lib.rs` 9, `client/push.rs` 1). It only forwards to the relay plane. The 12 call sites in code that moves (`key_package_recovery.rs` 2, `member_key_packages.rs` 6, `methods.rs:250`, `:602`, `search.rs:850`, `public_event_preview.rs:787`) call the relay plane handle directly from PR 1, as onboarding already does (`runtime/onboarding.rs:1901`). |
| The own-account half of `key_package_records.rs` (inventory, merge, publish endpoints) | about 350 | Stays |
| Block lists (`user_blocks.rs`), onboarding (`runtime/onboarding.rs`), relay-list publication (`lib.rs`) | — | Stay. They are account state. They become callers of the crate. |
| `shared.sqlite3` and `SqliteSharedStorage` | — | Stay in `storage-sqlite` (step 8 decides any split) |
| SQLCipher key derivation (`sqlcipher.rs`) | — | Stays in `marmot-app`, with the same label. The host supplies the key. |

That is about 9.0k production lines moving.

## The host interface

The crate holds one `Directory` service that owns everything in "State held on the hub" above. The sync handle
then has a single owner. `marmot-app` constructs it with three things.

**A `DirectoryConfig`**, built once from `MarmotAppConfig` and the deployment. It replaces nine reads of
`self.config` and `self.deployment()`:
- `root`, for the legacy cache and the cleanup marker;
- the default relays (`lib.rs:7375`, fixed at construction);
- the configured directory relays, fallback seeds and future-skew limit (`config.rs:100`, `:108`, `:236`);
- the Open Ranking provider and the KeyPackage client preference (`deployment.rs:32-34`).

**A `DirectoryHost` trait** that `marmot-app` implements. Each method replaces a hub call the directory makes today:

| Host method | Replaces |
| --- | --- |
| Local accounts: id, label, `local_signing` and `is_active_signing()` (`marmot-account/src/home.rs:174-176`) | `account_home()` at 13 sites in `directory/` and one in previews (`public_event_preview.rs:758`). The view must keep the active-signing filter that decides which caches open (`methods.rs:1870`, `cached_search.rs:131`) and the `local_signing` copy onto records (`methods.rs:2016`). |
| Account directory path and cache key | `account_dir`, `sqlcipher_key_locked`, `external_sqlcipher_key` (`methods.rs:1790`, `:1832-1847`) |
| The storage gate, the open lock and closer registration | `ensure_storage_open`, `begin_storage_open`, `database_open_lock`, `root_closers.register` (`methods.rs:1802-1856`). The open order stays the same; only the owner of the map changes. |
| Shared storage | `shared_storage()` at 9 sites (lifecycle stays on the hub) |
| "Entry changed" | the two `presentation_signals` calls (`methods.rs:1760-1764`, `:1916-1920`) |
| A proxy-configured HTTP client builder | `crate::network_proxy::http_builder` (`open_ranking.rs:178`); see below |
| Block-list adoption and reconcile | `ingest_block_list_event`, `fetch_block_list`, `block_update_lock` (`sync.rs:360`, `:441-443`). The sync worker keeps its bounds and queueing (`sync.rs:82-102`, `:295-296`); the hook does the per-account work. |

**A `DirectoryObserver` trait**, for the 10 `product_analytics.begin` sites with their `directory_sample`, `finish` and
`discard` calls. `marmot-app` implements it by forwarding to `ProductAnalytics` with the same family, operation and
unit strings. Step 6 (`marmot-observability`) can later supply it instead.

**Two lifecycle entry points the app calls**, at the points where it touches `directory_caches` today:
- `Directory::evict_account(label)`, called from `drop_account_caches` (`lib.rs:7402-7444`). It removes only the
  label's cache handle, as today.
  - That function runs before an account directory is deleted on removal, setup reset, sign-out and rollback
    (`runtime/mod.rs:6609`, `:6721`, `:6811`, `:8655`, `:8679`; `onboarding/cancellation.rs:235`,
    `onboarding/recovery.rs:221`).
  - Its doc says why: a handle kept across delete and re-import writes to the unlinked old database.
  - Closer registration doesn't cover this, because it only runs at terminal close.
- `Directory::take_caches()`, called from `close_storage` (`lib.rs:6502-6508`). It drains the map so the caches drop
  after `root_closers.close_all()`, in the same order as today.

The relay plane is passed in as a cloned `MarmotRelayPlane` handle, as the hub holds it (`lib.rs:529`). Two more
utilities:
- `blocking_app_task` (`runtime/mod.rs:8936`) becomes the crate's own `spawn_blocking` helper.
- The Open Ranking client (`open_ranking.rs:178`) keeps using `marmot-app`'s `http_builder` (`network_proxy.rs:21`),
  through a host method that returns a proxy-configured `reqwest::ClientBuilder`.
  - That helper first removes environment proxies, so `NO_PROXY` can't bypass the process SOCKS5 proxy and
    `ALL_PROXY` can't replace it. It then installs that proxy with its credentials.
  - Calling the adapter's proxy settings directly would skip both steps, so one implementation stays.
  - The media and collector clients use the same helper. Step 6 can move it to a shared home.

## Errors and public surface

- **`DirectoryError`.** The directory names 15 `AppError` variants over 210 mentions (`error.rs:121`). The crate gets
  its own error type with one variant for each of those, plus the `#[from]` conversions it relies on (rusqlite,
  serde_json, io, hex, `StorageError`). `From<DirectoryError> for AppError` maps each back to the variant and message
  used today, so the bindings, CLI and simulator still see the same errors.
  - One conversion stays on the app side. A KeyPackage that fails the requirements check becomes
    `AppError::from(cgka_session::SessionError::from(error))` (`key_package_records.rs:401`). The crate carries the
    engine's `EngineError`, and the boundary applies the `SessionError` step, so the variant doesn't change.
- **Host errors pass through unchanged.** Some errors come from the app, not the directory. For example,
  `account_home().account(label)?` (`methods.rs:1093`) and `load_signing_keys(...)?` (`methods.rs:1833`) become
  `AppError::AccountHome`, which the bindings split into `UnknownAccount`, `SecretNotFound` and
  `KeystoreUnavailable` (`marmot-uniffi/src/errors.rs:440-468`). The crate can't name that type without depending on
  `marmot-account`.
  - Host methods return the app's own `AppError`, boxed as `Box<dyn Error + Send + Sync>`, and the crate carries it
    as `DirectoryError::Host`.
  - The boundary conversion downcasts it back to that exact value.
  - A downcast that fails is a bug, so the conversion asserts it in debug builds.
  - Downstream code matches these variants, for example `DirectoryLookupIncomplete` (`marmot-uniffi/src/errors.rs:561`,
    `cli/src/error.rs:666`, `cgka-conformance-simulator/src/app_runtime.rs:2729`). The CLI also builds
    `MissingDirectoryEntry` itself (`cli/src/commands/users.rs:57`), so `AppError` keeps every variant.
  - `privacy_safe_kind` must give the same value on either side, because analytics uses it (`methods.rs:1041`,
    `search.rs:349`).
- **Re-exports.** `marmot-app` re-exports the 18 public directory types at their current paths (`lib.rs:221-227`) and
  the moved root types. UniFFI and C conversions compile unchanged, and no binding changes.
- **Methods.** The directory's 19 public `MarmotApp` methods are called by `marmot-uniffi`, `cli`, `agent-connector`
  and tests, for example `directory_entry_for_account_id` (14 outside callers) and `account_relay_list_status_for_account_id`
  (13). During the move they become one-line delegates. PR 6 then repoints callers to `app.directory()` and deletes
  the delegates, as relay-plane PR 4 did for its shim.

## PR sequence

Each PR keeps behaviour unchanged and ships alone.

1. **Move out what stays.**
   - Profile and follow publication moves to `marmot-app/src/profile_publication.rs`.
   - `retain_safe_discovered_endpoints` joins the other relay-plane wrappers.
   - Code moves only.
2. **Pull in what moves.**
   - The root directory types and the directory half of `key_package_records.rs` move into `directory/`.
   - `public_event_preview.rs` becomes `directory/previews.rs`.
   - `marmot-app` re-exports the same public paths.
3. **`DirectoryError`.**
   - Directory code returns `DirectoryError`, and the boundary converts it.
   - A table test covers every variant: the same `AppError` variant, the same message and the same
     `privacy_safe_kind`.
   - The test also covers host failures that pass through `Host`: an unknown account, a missing secret, an
     unavailable keystore, and closed storage.
4. **The `Directory` service.**
   - State moves off `MarmotApp`, and `impl MarmotApp` becomes `impl Directory`.
   - `DirectoryConfig`, `DirectoryHost` and `DirectoryObserver` replace the hub calls.
   - `drop_account_caches` and `close_storage` call the two lifecycle entry points.
   - `MarmotApp` gets one `directory` field and keeps delegates.
   - This is the large PR, so it lands in two slices: 4a moves the state, cache lifecycle and host, and 4b moves the
     remaining methods.
5. **Create `crates/nostr-directory` and move `directory/` into it.**
   - The move is `git mv` plus import paths.
   - `marmot-app` depends on the crate and re-exports.
   - Unit tests move with their modules. `marmot-app` tests that reach internals use a `test-support` feature, or
     move into the crate.
   - The PR adds the crate's README and `AGENTS.md`, the root README crate map and the AGENTS routing row.
6. **Repoint and delete delegates.** `marmot-uniffi`, `cli`, `agent-connector`, `marmot-app` and tests call
   `app.directory()`.
7. **Tracing targets.**
   - `marmot_app::directory` becomes `nostr_directory::<module>`, as storage-boundaries PR 5 did (#2402).
   - The observability docs are updated with it.

PRs 1–3 are small and independent of each other's internals. Run them in order anyway, so each one's diff stays
reviewable.

## Proof that behaviour is unchanged

- **Moves only.** Every PR is reviewable with `git diff -M --color-moved`. No SQL, file name, migration id, ledger
  table, cache TTL, timeout, bound or coverage rule changes.
- **Persisted state.**
  - `cache/v1.sql` and `v2.sql` stay byte-identical, and the assurance tests (`cache/assurance_tests.rs`) move with
    them.
  - The SQLCipher label stays in `marmot-app`, with a test that pins it. A different key would make every existing
    cache unreadable.
- **Errors.** The PR 3 mapping test.
- **Analytics.** The same family, operation, unit and sample strings. A test checks that the observer adapter forwards
  each call.
- **Lifecycle.**
  - `shutdown_and_close` still closes every directory cache, because the caches register through the host's closer.
  - Removing an account still evicts its cache before the directory is deleted. A regression test removes an account,
    re-imports it, and checks that directory writes reach the new cache file.
  - The sync worker shuts down at the same point (`runtime/mod.rs:6046-6055`).
  - The suspension-close tests cover this, and they are load-sensitive: rerun them alone if they fail.
- **Suites.**
  - `marmot-app` lib plus `relay_runtime`, `key_package_selection` and `invite_recovery`.
  - `marmot-uniffi`; `cli` with `test-policy-overrides`; `agent-connector`.
  - `just simulator-smoke` for PRs that move member KeyPackage resolution (PRs 2, 4b, 5), because create and invite
    depend on it.

## Risks

- **PR 4 is large.** It converts 86 methods and rewires about 50 hub calls. The 4a/4b split and moves-only diffs keep
  it reviewable, but it will touch most of `directory/` at once. (hypothesis: about 3k changed lines)
- **Cache opening has a precise order.** The steps are gate, map check, open lock, re-check, key, open, then
  register the closer (`methods.rs:1798-1863`). The host methods must keep that order. Otherwise a close that races
  an open could miss the new connection and leave it open after `shutdown_and_close` (hypothesis).
- **The plane's directory methods become a cross-crate contract.** Today they are hidden from docs. Documenting them
  keeps step 2's boundary visible.
- **Block lists stay coupled to the sync worker.** The kind-10000 subscription is part of the directory's
  local-account subscription (`sync.rs:37-44`). Splitting it out would change subscriptions on relays, so this step
  keeps it and uses a hook.
- **Rust API churn.** PR 6 changes `marmot-app`'s public Rust API for directory calls. Bindings are unaffected. 0.14.0
  already breaks Rust hosts, so it should ship in that cohort (hypothesis: if it misses 0.14.0, keep the delegates
  one more release).

## Out of scope

- Any change to directory behaviour: search radius, TTLs, freshness, coverage rules, Open Ranking, KeyPackage
  ranking.
- Publishing the account's own profile, follow list or relay lists. That stays with the app; a later brief can
  decide whether it belongs with the session runtime (step 5).
- Block lists and onboarding, which are account state. Step 7 takes onboarding out of `AccountManager`.
- Moving or splitting `shared.sqlite3` (step 8).
- The relay plane's directory fetching internals.
- Refreshing `overview/nostr-account-transport.md`. It predates this layout: it says the directory tracks mute
  lists (L41), and it places the directory in the transport layer (L147-148). PR 5 updates its pointers; a rewrite
  is separate.

## Done when

- `crates/nostr-directory` owns the directory, previews and KeyPackage lookup code with their caches. It depends on
  neither `marmot-app` nor `marmot-account`.
- `MarmotApp` has one `directory` field and no directory methods. The sync handle has one owner.
- Bindings and the CLI behave as before. Every listed suite is green.
- Core structure, this brief and #2360 record the step as done.

## Product-owner decisions (2026-10-20)

1. **The crate is `nostr-directory`.** The name says what it caches: other people's public Nostr data.
2. **Previews move with the directory.** They share its database, key and migration ledger, so keeping them in
   `marmot-app` would mean splitting that ledger.
3. **Downstream callers use `app.directory()` (PR 6).** The directory gets one surface, and `MarmotApp` keeps no
   directory methods.
4. **Analytics go through a small observer trait now.** The step order stays, and step 6 (`marmot-observability`)
   can supply the observer later.
