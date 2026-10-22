# AGENTS.md - crates/nostr-directory

The directory of other people's public Nostr data (step 3 of the 2026-10 architecture review). Human overview:
[`README.md`](README.md). Design: [`brief-directory.md`](../../docs/marmot-architecture/review/brief-directory.md).

## Boundary

- **No `marmot-app` and no `marmot-account`.** The crate reaches the host app only through three traits it defines:
  `DirectoryResources` and `BlockListSink` (`src/resources.rs`), and `DirectoryObserver` (`src/observer.rs`).
  `marmot-app` implements them. Dependency direction: `transport-nostr`/`storage-sqlite` -> `nostr-directory` ->
  `marmot-app`.
- **The app owns resources; the crate owns logic and schema.** Opening, keying, evicting and closing the per-account
  caches, label-based account resolution, block lists and the account's own profile publication stay in `marmot-app`.
  The crate owns lookups, search, KeyPackage resolution, previews, the sync worker and the cache schema with its
  migrations.
- **Ask for a cache when it is about to be used, never before a network step.** A handle taken before a fetch can
  outlive its account's eviction and keep writing to a closed account's cache.
- **Block-list work runs where the worker runs it.** `BlockListSink` returns futures and starts nothing: the sync
  worker spawns adoptions into its bounded set and reconciles into one abort-on-drop task, never inline in its event
  loop, where an account's update lock would park it.
- **Privacy-safe logs only:** explicit `target` and `method` fields, aggregate counts, never ids, relay URLs, pubkeys
  or contents (`docs/marmot-architecture/overview/observability.md`). Each target is
  `nostr_directory::<module>`, the module that emits the event.

## Code map

| Path | Owns |
| --- | --- |
| `src/lib.rs` | The public surface: production re-exports, the crate-internal shorthands the moved code uses, and the `test-support`-gated re-exports. |
| `src/test_support.rs` | `_for_test` wrappers over crate-private methods that `marmot-app`'s directory tests call; built only with `test-support`. |
| `src/service.rs` | `Directory<R>`, the service, and `DirectoryState`, what it keeps between calls (preview cooldowns, the member prewarm cache, the sync worker's handle slot). The host builds a fresh `Directory` per call and shares one state. |
| `src/resources.rs`, `src/observer.rs` | The three traits the host implements, and the `DirectoryAccount` view. |
| `src/config.rs` | `DirectoryConfig` (relays, future-skew limit, KeyPackage client preference, Open Ranking provider, fallback seeds, proxy-aware HTTP builder, test clock) and the deployment's `OpenRankingProvider` and `KeyPackageClientPreference`. |
| `src/error.rs` | `DirectoryError`, its `privacy_safe_kind`, and `ResourceError`, which carries a host failure through unchanged. |
| `src/store.rs` | The directory store: entry reads, the `remember_*`/`save_directory_entry*` writes across the caches and the shared tier, relay-event ingest, the freshness bound and record hydration. |
| `src/methods.rs` | Relay-list, profile, KeyPackage and follow-list fetches, refreshes, the cached identity page, synchronous user-directory search and the sync plan. |
| `src/records.rs` | The public `UserDirectory*`/`UserProfileMetadata`/`DirectoryKeyPackage` DTOs and stateless record helpers: cached <-> shared conversion, recency selection, profile and follow-list parsing, search-match ranking, `profile_content_json`. |
| `src/published_records.rs`, `src/ids.rs` | Stateless relay-list and KeyPackage handling for other accounts (status, tag validation, fresh-vs-cached reconciliation, ranking and selection, revocation evidence), the record-selection primitives (`DirectoryFreshness`, `DirectorySelection`, `sort_directory_records`), and the Nostr account-id helpers. |
| `src/member_key_packages.rs`, `src/key_package_recovery.rs` | Whole-roster KeyPackage resolution for create, invite and prewarm, and bounded discovery recovery. |
| `src/search.rs`, `src/cached_search.rs`, `src/open_ranking.rs` | Streaming web-of-trust search, network-free cached search, and the bounded Open Ranking client. |
| `src/previews.rs` | Verified previews of `nostr:` references, stored in the directory cache (tests in `src/previews/tests.rs`). |
| `src/sync.rs` | The directory-subscription sync worker and plan. |
| `src/cache.rs`, `src/cache/` | The per-account SQLCipher cache: its numbered migration runner (`cache/migrations.rs`), frozen schemas (`cache/v1.sql`, `cache/v2.sql`), and populated/interrupted-upgrade tests (`cache/assurance_tests.rs`, fixture `cache/fixtures/pre_ledger.sql`). |

## Rules

- Directory code returns `DirectoryError`. The host converts it back at its boundary (`marmot-app`'s
  `From<DirectoryError> for AppError` restores today's variant, message and `privacy_safe_kind`). A host failure
  reaches directory code as `DirectoryError::Resource` and goes back unchanged. A new variant needs a row in
  `marmot-app`'s `error::directory_error_tests`.
- Anything kept between calls belongs in `DirectoryState`. The sync worker's handle has one owner, the state's slot:
  `Directory::sync_worker()` gets or spawns it and `take_sync_worker()` hands it to shutdown.
- Do not change cache SQL, migration ids, file names, TTLs, timeouts or bounds as part of a move. `cache/v1.sql` and
  `cache/v2.sql` are frozen; schema changes add a numbered migration.
- The public surface is what `src/lib.rs` re-exports, plus the `config` and `error` modules; every other module is
  private. `Directory`'s lookup, refresh, search and KeyPackage-resolution methods are the app-facing API that
  replaced `MarmotApp`'s delegates and stay `pub`. Anything else is `pub` only when another crate's production code
  names it.
- Tests here use only the directory. A test that needs a real `MarmotApp` or runtime belongs in `marmot-app`'s
  `src/directory_tests/`. What only those tests reach is built only with the `test-support` feature: a method stays
  `pub(crate)` and gets a `_for_test` wrapper in `src/test_support.rs`; a free item is `pub` in its private module and
  re-exported from the root's gated block. Never widen an item for a test alone.

## Verification

- `cargo nextest run -p nostr-directory` for changes here, plus `cargo nextest run -p marmot-app --lib -E
  'test(/directory/)'` for anything the app's directory tests cover. Member KeyPackage resolution changes also run
  `just simulator-smoke`.
- `cargo clippy -p nostr-directory --all-targets --all-features --locked -- -D warnings`; a change to a `pub` item
  `marmot-app` uses runs CI's workspace lint once (root `AGENTS.md`).
