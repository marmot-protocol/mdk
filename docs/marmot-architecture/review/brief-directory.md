---
title: "Extraction Brief — Directory into nostr-directory"
created: 2026-10-20
updated: 2026-10-20
tags: [marmot, architecture, review, extraction-brief, directory, nostr]
status: proposed; product-owner decisions made 2026-10-20; reshaped 2026-10-20 after four review rounds
---

# Extraction Brief — Directory into `nostr-directory`

Step 3 of the [core structure plan](core-structure.md#5-sequencing). It moves the directory's logic out of
`marmot-app` into a new `nostr-directory` crate without changing behaviour.

The directory is the app's cache and lookup service for other people's public Nostr data:
- profiles, follow lists and relay lists;
- KeyPackages;
- user search;
- public event previews.

`path:line` citations are at `3fc77b82c` (master after #2493). Production line counts exclude `#[cfg(test)]`
modules. Following the [review's evidence rules](README.md#evidence-rules), statements are observed in source
unless marked (hypothesis).

## The shape in one paragraph

The crate owns the directory's logic and its cache schema. `marmot-app` keeps the cache lifecycle and account
resolution:
- it opens, keys, evicts and closes the per-account caches, beside its other per-account resources;
- it turns account labels into accounts before calling in;
- it hands the crate open handles.

A crossing check replaces hand-written inventories. Every name that `directory/` code resolves in the rest of
`marmot-app` goes on a generated allow-list that only shrinks. The crate moves when the list is empty.

## Why the first version was reshaped

The first version of this brief went through four review rounds. Each round found more gaps, 21 in all, and they
fell into two groups.

- **The boundary cut through the cache lifecycle.**
  - That version moved the per-account cache map, opening under the storage gate, eviction, close and the one-off
    file cleanups into the crate. It then handed the crate the app's primitives back through a host trait: the
    storage gate, closer registration, keys and file removal.
  - Every lifecycle and error finding came from that inversion: the eviction sites, sign-out semantics, close
    order, file-set removal, and keychain errors that needed a downcast.
  - The app already manages every other per-account resource in one place. `drop_account_caches` evicts account
    storages, media stores and directory caches together (`lib.rs:7402-7457`), and `close_storage` drains them
    together (`lib.rs:6459-6543`).
- **The brief enumerated crossings by hand.** About a third of the findings were errors in its own inventory:
  counts, dependency lists and call sites. The rest were further members of categories it already named. The
  [storage-boundaries brief](brief-storage-boundaries.md) hit the same wall and fixed it the same way, with a
  mechanical check and an allow-list that only shrinks.

The core-structure premise for this step was "already owns its state; makes no account-storage calls". It holds for
the directory's data and logic, not for its resources.

## What the directory is today

| Part | Where | Production lines |
| --- | --- | ---: |
| Hub methods: relay-list, profile, follow and KeyPackage fetches; cache lifecycle; ingest; merge with the shared tier | `directory/methods.rs` | 2,046 |
| Streaming web-of-trust search and Open Ranking discovery | `directory/search.rs`, `open_ranking.rs` | 1,812 |
| Whole-roster KeyPackage resolution for create, invite and prewarm | `directory/member_key_packages.rs`, `key_package_recovery.rs` | 1,251 |
| Per-account cache store and its migrations | `directory/cache.rs`, `cache/migrations.rs`, `cache/v1.sql`, `cache/v2.sql` | 1,022 + 73 SQL |
| Records, merge rules and match ranking | `directory/records.rs` | 772 |
| Sync planner and background worker | `directory/sync.rs` | 467 |
| Network-free search over cached data | `directory/cached_search.rs` | 153 |

- **Methods on the hub:** 86 production methods in five `impl MarmotApp` blocks. Core structure said 67, which is
  `methods.rs` alone.
- **Coupling is concentrated.**
  - None: `cache.rs`, `cache/migrations.rs`, `records.rs`; `open_ranking.rs` uses only the proxy helper and the
    id helpers.
  - Light: search, member resolution and sync use one to three hub methods each.
  - Heavy: `methods.rs`, where most of the rest is profile and follow publication and the cache lifecycle.
- **Data it owns.**
  - A per-account SQLCipher cache, `<account>/app-cache.sqlite3` (`lib.rs:398`). It has its own migration ledger
    (`cache/migrations.rs:72`).
  - Migration 2 creates `public_event_previews` for `public_event_preview.rs` (`cache/v2.sql`).
- **Data it uses but doesn't own.** The public directory tier in `<root>/shared.sqlite3`, which `storage-sqlite` owns
  (`storage-sqlite/src/shared.rs:149-160`). Chat presentation and avatars read it too.
- **What isn't directory code.** `transport-nostr/src/directory.rs` and `directory_wire.rs` are relay I/O and
  relay-plane state, so they stay. The [relay-plane brief](brief-relay-plane.md#what-moves-and-what-stays) expected
  step 3 to take "directory bookkeeping" from them, but they hold none.

## What moves and what stays

**Moves to `nostr-directory`:**
- the directory's logic: fetch and merge, ingest, freshness, KeyPackage selection and member resolution, search,
  cached search, the sync planner and the directory part of the sync worker, and the Open Ranking client;
- the cache store: `DirectoryCache`, its schema, migrations and queries, including `DirectoryCache::open(path, key)`;
- public event preview logic (`public_event_preview.rs`), because its table is in the cache's migration ledger;
- the directory types at the `marmot-app` root, with re-exports from `marmot-app` at the same public paths. These
  include `AccountRelayListStatus`, `DirectoryFreshness`, `DirectorySelection`, `FetchedKeyPackage` and the relay-list
  event parsers;
- the other-account half of `key_package_records.rs`: relay-list status, KeyPackage parsing, tag checks, ranking,
  selection and revocation evidence;
- the Nostr account-id helpers in `ids.rs`, so there is one parser and one `nprofile` rule.

**Stays in `marmot-app`:**
- **Cache lifecycle, unchanged.** That covers:
  - the `directory_caches` map and opening under the storage gate, with the open lock, key derivation and closer
    registration;
  - eviction in `drop_account_caches` and draining in `close_storage`;
  - the legacy plaintext import, the future-dated cleanup marker and `remove_sqlite_file_set`;
  - `warm_directory_storage`.

  This code moves out of `directory/` into an app module, so it stops being directory code.
- **Account resolution.** Label-based public methods, such as `account_relay_list_status(label)`, resolve the label
  in `marmot-app` and call the crate with an account. Errors from resolving labels and opening caches stay
  `marmot-app` errors.
- **Profile and follow-list publication**, which needs the signer, publish clients and indexer copies. It calls the
  crate to remember what it published.
- **Block lists, onboarding and relay-list publication**, which are account state.
- **`shared.sqlite3`** stays in `storage-sqlite`, and step 8 decides any split.

## How the crate reaches the app

Nothing in the crate calls an app lifecycle primitive. It gets values, a handle and three narrow interfaces it
defines and `marmot-app` implements.

- **`DirectoryConfig`**, built once from `MarmotAppConfig` and the deployment:
  - default and directory relays, fallback seeds and the future-skew limit;
  - the Open Ranking provider and the KeyPackage client preference;
  - the app's proxy-configured HTTP client builder. Open Ranking keeps using `http_builder` (`network_proxy.rs:21`),
    which strips environment proxies before installing the process SOCKS5 proxy.
- **The relay plane:** a cloned `MarmotRelayPlane` handle. The crate becomes the documented consumer of its
  directory methods (`transport-nostr/src/lib.rs:1902-2159`).
- **`DirectoryResources`**, implemented by `marmot-app` over its existing code. Its methods return handles, never
  primitives:
  - the current caches, and the cache for one account;
  - shared storage;
  - local accounts, as a directory account view;
  - the current account id for a label;
  - "entry changed", for presentation.

  **The account view** carries `account_id_hex`, `label`, `local_signing` and the active-signing flag. That flag is
  `(local_signing || external_signing) && !signed_out` (`marmot-account/src/home.rs:174-176`). The source lists every
  local account, signed-out ones included, in account-home order.
  - The moving code uses the two predicates for different things. Records copy `local_signing` for every account
    (`methods.rs:120-131`, `:2015-2024`), while the sync plan and the searcher's caches keep only active-signing
    accounts (`methods.rs:1366-1370`, `cached_search.rs:131`).
  - The crate keeps today's rule for duplicate ids: the first account's directory link and the last label
    (`methods.rs:121-131`).
  - The moving preview reads take this view instead of `marmot_account::AccountSummary`
    (`public_event_preview.rs:619`, `:676`). The lifecycle functions that stay in the app keep `AccountSummary`.

  **The label lookup** is the preview write's replacement-account check. After a fetch, it refuses to store the
  preview if the label now belongs to a different account (`public_event_preview.rs:757-763`). Asking for the
  current cache is a separate check, the eviction one.

  The directory fetches caches at the moment it writes, after a network step, and must keep doing so. A snapshot
  taken before the fetch would keep writing to a cache evicted mid-fetch. So refreshes, member resolution, previews,
  streaming search and the sync worker all ask for current caches.
- **`BlockListSink`**, implemented by `marmot-app`, for block lists, which are account state.
  - The sync worker keeps the kind-10000 subscription it shares with the directory's local-account kinds
    (`directory/sync.rs:37-44`).
  - It also keeps its bounds and queueing: at most 32 adoptions in flight, with overflow and relay recovery requesting
    one coalesced reconcile (`sync.rs:82-102`, `:295-296`, `:355-380`).
  - The sink does the per-account work: adopt one event, and reconcile every account's list. That work is what calls
    `ingest_block_list_event`, `fetch_block_list` and `block_update_lock` today.
- **`DirectoryObserver`**, for product analytics (decision 4). It covers `begin`, `count`, `directory_sample`,
  `finish`, `discard` and `counts_only`, with the same family, operation and unit strings.

**Errors.**
- The crate returns `DirectoryError`. `From<DirectoryError> for AppError` restores today's variant, message and
  `privacy_safe_kind`.
- A failure from `DirectoryResources` (closed storage, a missing secret) is the app's own `AppError`. It travels as
  an opaque `ResourceError`, which only the app constructs, and the boundary converts it back unchanged.
- Synchronous public methods mostly avoid that path, because the app resolves accounts and opens caches before it
  calls in.

## The crossing check

PR 1 adds a test in `marmot-app`, modelled on `storage-sqlite`'s boundary test
(`storage-sqlite/src/base/boundary_tests.rs`).

- **What it scans.** It parses production files under `directory/`, with test-only items skipped as the storage
  test does. It records every name they resolve in the rest of `marmot-app`:
  - `crate::` paths and `use crate::` leaves outside `directory/`;
  - `MarmotApp` fields and methods not defined under `directory/`;
  - names reached through `super::` from the module root.

  It also fails, with no allow-list, when production `directory/` code names `marmot_account::` or `marmot_app::`.
  The new crate depends on neither, and a path into another crate never shows up as a `marmot-app` crossing.
- **The allow-list.** The crossings found are written to a generated list,
  `crates/marmot-app/src/directory/crossings.txt`. A crossing missing from the list fails, and so does a listed one
  that no longer occurs, so the list only shrinks.
- **How it shrinks.**
  - Each later PR shrinks the list, and its description reports the count before and after.
  - The traits are defined under `directory/`, so code that calls them crosses nothing. The crate move needs the list
    empty.
- **What it misses.** The scan is by name: it misses a call through an unrelated binding. When the code finally
  moves, the compiler checks whatever is left.

## PR sequence

Each PR keeps behaviour unchanged and ships alone.

1. **Crossing check.** The test and the generated allow-list. No code change.
2. **Move out what stays.**
   - Publication, the cache lifecycle and the label-resolving wrappers move from `directory/` to app modules.
   - `retain_safe_discovered_endpoints` joins the other relay-plane wrappers, and moving code calls the plane
     directly.
   - `remember_directory_message_sender` takes the sender id instead of `ReceivedMessage`.
3. **Pull in what moves.** These move into `directory/`, with `marmot-app` re-exporting the same public paths:
   - the root directory types;
   - the other-account half of `key_package_records.rs`;
   - the account-id helpers;
   - `public_event_preview.rs`.
4. **`DirectoryError`.** A table test covers every variant, the `SessionError` step for KeyPackage requirement
   failures (`key_package_records.rs:401`), and a `ResourceError` round trip for each kind of resource failure.
5. **The `Directory` service.**
   - The directory's state moves off `MarmotApp`: the sync handle, now with one owner, the prewarm cache, preview
     cooldowns and test counters.
   - Its methods become `impl Directory`, reaching the app only through config, the plane, `DirectoryResources`,
     `BlockListSink` and `DirectoryObserver`.
   - `MarmotApp` keeps one-line delegates.
   - The allow-list reaches its floor. This is the large PR, so it lands in slices, each shrinking the list.
6. **Create `crates/nostr-directory`.**
   - `git mv` of `directory/`, plus import paths, with `marmot-app` re-exporting.
   - It adds the crate README and `AGENTS.md`, the root README crate map and the AGENTS routing row.
7. **Repoint and delete delegates** (decision 3). `marmot-uniffi`, `cli`, `agent-connector`, `marmot-app` and tests
   call `app.directory()`.
   - Narrow `nostr-directory`'s public surface to what those callers and the host traits need. PR 6 widened by
     compiler error and by name, so modules are `pub mod` and many internals are `pub`; once the delegates are gone,
     what `marmot-app` still names is the real surface, and the rest returns to `pub(crate)`.
8. **Tracing targets.** `marmot_app::directory` becomes `nostr_directory::<module>`, as storage-boundaries PR 5 did
   (#2402).

## Proof that behaviour is unchanged

- **Moves only.** Every PR is reviewable with `git diff -M --color-moved`. No SQL, file name, migration id, ledger
  table, TTL, timeout, bound or coverage rule changes.
- **Lifecycle.** The cache lifecycle doesn't move: `drop_account_caches`, `close_storage`, the legacy import and the
  cleanup marker keep their code and order.
- **Cache timing.** Each write path still asks for current caches after its network step.
- **Persisted state.** `cache/v1.sql` and `v2.sql` stay byte-identical, and the assurance tests move with them. The
  SQLCipher label stays in `marmot-app`, with a test that pins it.
- **Errors.** The PR 4 table test.
- **Analytics.** An observer test, including that the two `counts_only` operations record no `cancelled` sample.
- **Suites.**
  - `marmot-app` lib plus `relay_runtime`, `key_package_selection` and `invite_recovery`.
  - `marmot-uniffi`; `cli` with `test-policy-overrides`; `agent-connector`.
  - `just simulator-smoke` for PRs that move member KeyPackage resolution.

## Risks

- **PR 5 is large.** It converts the remaining methods to `impl Directory`. Its slices and the shrinking list keep
  each diff reviewable. (hypothesis: about 3k changed lines in all)
- **Write-time cache access is easy to break.** A refactor that hoists `caches()` above a network await reintroduces
  the stale-handle bug that `drop_account_caches` documents. Reviews of PR 5 should check every `DirectoryResources`
  call site against today's order.
- **The block-list hand-off.** The sink's methods return futures that the worker runs exactly where it runs them
  today: adoptions in its bounded `JoinSet`, reconciles in its abort-on-drop task. Calling the sink inline in the
  event loop would park the worker on an account's mutation lock, which `sync.rs:82-83` exists to prevent.
- **Rust API churn.** PR 7 changes `marmot-app`'s public Rust API for directory calls; bindings are unaffected.

## Out of scope

- Any change to directory behaviour.
- Moving the cache lifecycle out of `marmot-app`. A later step can give per-account resources their own home (step
  5's `marmot-session`), and the caches would go with the others.
- Publication of the account's own profile, follow list or relay lists.
- Block lists and onboarding.
- Moving or splitting `shared.sqlite3` (step 8).
- The relay plane's directory fetching internals.
- Rewriting `overview/nostr-account-transport.md`, which predates this layout. PR 6 updates its pointers.

## Done when

- `crates/nostr-directory` owns the directory's logic, cache schema, previews and KeyPackage lookup. It depends on
  neither `marmot-app` nor `marmot-account`.
- `marmot-app` keeps the cache lifecycle and account resolution, and has no directory methods after PR 7.
- The crossing list reached empty before the move, and the crate's only routes back into the app are the three
  traits.
- Bindings and the CLI behave as before, and every listed suite is green.

## Product-owner decisions (2026-10-20)

1. **The crate is `nostr-directory`.** The name says what it caches: other people's public Nostr data.
2. **Previews move with the directory.** They share its database, key and migration ledger, so keeping them in
   `marmot-app` would mean splitting that ledger.
3. **Downstream callers use `app.directory()` (PR 7).** The directory gets one surface, and `MarmotApp` keeps no
   directory methods.
4. **Analytics go through a small observer trait now.** The step order stays, and step 6 (`marmot-observability`)
   can supply the observer later.
5. **The crate owns logic and schema; the app keeps the cache lifecycle and account resolution; a crossing check
   with a shrinking allow-list replaces hand-written inventories.** This came from stepping back after four review
   rounds.
