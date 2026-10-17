---
title: "Extraction Brief — Internal Boundaries in storage-sqlite"
created: 2026-10-17
updated: 2026-10-17
tags: [marmot, architecture, review, extraction-brief, storage, sqlite]
status: approved 2026-10-17, in implementation
---

# Extraction Brief — Internal Boundaries in `storage-sqlite`

Step 4 of the [core structure plan](core-structure.md#5-sequencing). It splits `storage-sqlite` into a protocol side
and an app side inside the crate, defined by which side owns each table, so the later split into a protocol store and
an app store (step 8) is a review of a boundary that already holds, not an excavation. No behaviour or schema change.
Counts and `path:line` citations, including those in other crates, are at master `e9ecb12e0`. Master has moved since
(#2380 adds migration 0113, for example); the allow-list PR 2 generates, not these numbers, is the record. Following
the [review's evidence rules](README.md#evidence-rules), statements are observed in source unless marked (hypothesis).

Product-owner decisions this brief assumes (2026-10-17): one database file per account-device stays, unless a strong
reason to split appears; each crate is a black box with a clean interface, and nothing reaches into another crate's
internals.

## Why this step, and why now

- Step 5 moves the engine's account-record storage proxy up into `marmot-session`, and step 8 splits this crate into
  a protocol store and an app store. Both need to know exactly where the two sides touch. Today nothing in the crate
  says so.
- It needs no code from step 2. It still starts after step 2, one extraction at a time; see
  [Sequencing against step 2](#sequencing-against-step-2).
- It is the storage review (Pass 1 system C), scoped to what the plan needs.

## What the crate is today

44,694 production lines: 40,168 of code and 4,526 in 112 migration bodies.

| Part | Production lines | What it is |
| --- | ---: | --- |
| Protocol | 6,508 (16% of non-migration code) | `storage/` (the engine's `StorageProvider` traits, snapshots, maintenance records) and `openmls_storage/` |
| Base | 3,449 + 4,526 migrations | `connection.rs` (SQLCipher connection, transactions, open), `codec.rs`, the migration runner and registry, `open_progress.rs`, `lib.rs` |
| App | 26,707 | Projections (`account_projection`), the recovery ledger (`account_recovery/`), `timeline/`, `chat_list/`, `chat_presentation`, attachments, avatars, drafts, local submissions, media catalog, media secrets |
| Transport-specific (app side) | 1,853 | `transport_reconciliation` (NIP-77), `delivery_spill` (relay plane), `user_blocks` (NIP-51), `moderation_reports` (NIP-59), `agent_stream_sequences` (QUIC), `prepared_group_image_upload` (Blossom) |
| Separate database | 1,080 | `shared.rs` and `shared/` (`SqliteSharedStorage`) |
| Benchmarks (feature-gated) | 571 | `media_store_bench.rs` (`media-store-benchmarks`) |

A fresh database has 128 tables: 33 protocol (29 `cgka_*`, `openmls_values`, the engine-to-app outbox
`pending_application_events` and `pending_application_authority`, and `locally_forgotten_groups`), 94 app (10 of them
transport-specific), and the migration ledger `cgka_schema_migrations`. 8 tables are written from both sides, and 10 of
the 112 migrations touch both sides' tables.

Every module adds inherent methods to one type, `SqliteAccountStorage` (`connection.rs:1050`): 387 `pub` methods, not
counting six feature-gated ones, of which 17 are in protocol or base modules and 370 are app or transport. `marmot-app`
calls about 318 of them (name-match count, hypothesis), through the concrete type; there is no app-side trait. The
engine side already has its seam: `StorageProvider` and its 16 traits (`traits/src/storage.rs:996-1015`), which the
engine is generic over.

## The boundary is table ownership

**Rule:** every table has one owning side, `protocol` or `app` (the ledger belongs to `base`). A module runs SQL only
against its own side's tables and names only its own side's modules and methods. Both sides may use `base`, which
names neither. Code that must touch both sides, in one transaction because there is one file, lives in `cross/`, the
one place allowed to.

A module-path rule alone would miss most of today's crossings. The two sides touch through four channels, and only the
first is visible as a path:

| Channel | Today, in production code (hypothesis: a name-match count) | Guard |
| --- | --- | --- |
| Module paths: `crate::account_recovery::…` from protocol code, `crate::storage::…` from app code | 8 file-to-module pairs, one of them from `base` | Names test (PR 2) |
| Method calls on the shared type, such as `self.forget_group_local_data(…)` from `storage/groups.rs` | 3 protocol to app, 4 app to protocol | Names test (PR 2); impossible after the handle (PR 4) |
| SQL naming the other side's tables | 24 file-to-table pairs: 17 app to protocol (13 reads, 4 writes) and 7 protocol to app (6 writes, 1 read); plus the migration runner's legacy migration 9 reconcile, which adds a column to two app tables (`migrations.rs:1067-1090`) | Table-ownership test (PR 2) |
| Schema links | 3 foreign keys from app tables to `cgka_groups`; 17 triggers that span the sides, all from migration 0072; one ledger; one MLS cache that app writes invalidate | Table-ownership test, for foreign keys and triggers (PR 2); `cross/README.md` for the rest |

Table ownership is also what step 8 needs: the split decides which store each table lands in.

### Three mechanisms

1. **The table-ownership test.** A registry (`base/table_owners.rs`) lists every table and its owning side. A unit
   test checks that the registry names exactly the tables of a freshly migrated database (SQLite's own `sqlite_*`
   tables aside), so a new table cannot land without an owner. It then scans each production file's string literals,
   parsed with `syn`, for registered table names. Each file's side is its folder. It also reads the fresh database's
   foreign keys and triggers and finds the ones that span the sides.
2. **The names test.** The same parse finds `crate::` paths and calls through `self` or `Self` to methods defined on
   the other side (matched by name). `lib.rs`'s crate-root re-exports are exempt.
3. **The app handle, `SqliteAppStorage`** (decided 2026-10-17). The app and transport methods move onto their own
   type, so protocol code cannot call them, and app code cannot call the protocol traits, because neither type has
   the other's methods.

Both tests compare what they find with one checked-in allow-list (`cross/allow-list.txt`), one line per file and target:
channel, file, and the table, module or method it reaches. There are no line numbers, so ordinary edits do not churn it.
Any crossing not on the list fails the test, and so does a listed crossing that no longer occurs, so the list only
shrinks. The failure message prints both kinds in the file's format. PR 2 generates the first list from what the code
does after PR 1; this brief's counts are a preview, and the list is the record. `cross/` files and test code
(`#[cfg(test)]` items and the test files) are exempt, and so are migration bodies: they are schema history, and the
fresh-database checks cover the schema they leave. `shared/` is a separate database and is not scanned.

### Coupling kinds

The kinds the allow-list will hold, with one example each. The §2.2 column maps [core-structure's eleven
couplings](core-structure.md#22-storage-sqlite-two-stores-in-one-type) to them; the allow-list, not this table, is the
full inventory.

| Kind | Example | §2.2 | Step 4 | Later |
| --- | --- | --- | --- | --- |
| A protocol transaction writes or reads app state | `retire_transport_receipts` deletes `seen_events` rows and calls `account_recovery::delete_inventory_tx` (`storage/messages.rs:1298-1305`); release checks `account_state` (`:319-326`) | 3, 4 | A named `cross/` function the protocol code calls inside its transaction | Step 8: an app-side journal, or a hook the app store registers |
| Protocol code calls app code | The confirm path calls `accept_local_submission_tx` and fires the draft observer (`storage/outbound.rs:41,60`) | 2 | Same | Step 8: a hook the app store registers |
| An app transaction writes protocol tables | The projection checkpoint acknowledges the engine outbox (`account_projection.rs:1313-1319`) | 1, 9 | A named `cross/` function | Keep while one transaction must cover both (core-structure §2.5) |
| One local wipe spans both sides | `delete_local_group_data_inner` (`account_projection.rs:1442-1649`) | 5 | Moves to `cross/` whole; callers on both sides call it | Keep: a local delete must be atomic |
| App code reads protocol tables | Chat-list pages join `cgka_leave_requests` and the disband tables (`chat_list/pages.rs:357-362`) | 8 | Read views in `cross/` | Step 8: published read views |
| App code uses a protocol trait for a plain transaction | `StorageProvider::with_transaction` in `recovery_health.rs:30` | — | Switch to `SharedConnection::with_transaction`, which the trait method only wraps (`connection.rs:1643-1649`) | — |
| Schema links | `app_epoch_stall_evidence` cascades from `cgka_groups` (`migrations/0055_epoch_stall_evidence.rs:10`); the chat-list triggers (`migrations/0072_chat_list_pages.rs:70-178`); the ledger's strict order (`migrations.rs:1020`); the MLS cache generation (`connection.rs:1604-1621`) | 6, 7, 10, 11 | Stay; foreign keys and triggers stay on the allow-list, and `cross/README.md` says why each kind exists | Step 8 decides per table |
| `marmot-app` reads protocol state through the engine traits on its own connection | `client/projection.rs:380` in `marmot-app` | — | Recorded; no change here | Step 5: `marmot-session` owns those reads |

## Target layout inside the crate

```text
storage-sqlite/src/
  base/        connection, transactions, codec, migration runner and bodies, open progress, table_owners
  protocol/    storage/* and openmls_storage/*, and the StorageProvider impls: the engine's traits
  app/         projections, recovery ledger, timeline, chat list, attachments, avatars, drafts, ...
    transport/ reconciliation, delivery spill, user blocks, moderation outbox, agent stream sequences,
               prepared group-image upload
  cross/       one named function per crossing kind, allow-list.txt, and README.md
  shared/      the separate shared database, unchanged
```

Transport-specific code is part of the app side, in `app/transport/`, not a third side. It mixes Nostr-specific state
with product state (`user_blocks` also writes the chat list's `chat_list_navigation_meta` and
`chat_list_unread_ready_groups`), step 8 splits two stores, and a third side would add crossings that split does not
need. The folder keeps it together for its later move to `transport-nostr`.

Helper visibility stays as it is. The tests, not `pub(in …)`, are the guard.

## The app handle type (decided 2026-10-17)

Step 4 gives the app side its own handle type, `SqliteAppStorage`, as PR 4, after the folders, the tests and
`cross/`. The app and transport methods move onto it; `SqliteAccountStorage` keeps the protocol traits. `marmot-app`
reaches app storage through the new handle, and only `cross/` holds both. `marmot-app` builds the handle from the
`SqliteAccountStorage` it already opens for the account (marmot-app `lib.rs:6636`) and keeps it beside that storage.
It shares that connection, so it opens no second connection, and the closer already registered for that storage in
`root_closers` (`lib.rs:6653`) closes both; after close, its calls fail the way the account storage's do. The engine's
session keeps only its own storage handle and never receives `SqliteAppStorage`. It is the type the app store crate
gets in step 8, so the work is not thrown away. It is mechanical but wide: every `marmot-app` call to the app methods
it uses, about 318 of them by a name-match count, changes from `storage.x()` to `app_storage.x()`.

Declined: stopping at folders, tests and `cross/`, which would leave the method channel guarded by a name match until
step 8.

## PR sequence

Each PR is green on its own and changes no behaviour or schema.

1. **Create the folders and `git mv` the files.** Keep every crate-root re-export in `lib.rs` (257 names today), so no
   other crate changes. Move the `StorageProvider` and `KeyPackageBundleStorage` impls out of `connection.rs` into
   `protocol/`, and `storage/test_support` into `base/`. Fix the internal paths, `#[path]` attributes and
   `include_str!`/`include_bytes!` fixtures the move breaks; the compiler finds them. Keep the hard-coded tracing
   targets unchanged. Update the crate and nested `AGENTS.md` key-file tables.
2. **Add the registry, both tests and the generated allow-list.** No production change.
3. **Introduce `cross/`.** Move each crossing into a named `cross/` function, one kind at a time (several PRs if the
   diff is large), deleting its allow-list lines as it goes. Switch the plain transactions to
   `SharedConnection::with_transaction`. Write `cross/README.md` for the schema-level kinds. When this is done, the
   allow-list holds only the schema links, the migration 9 reconcile, and the three lines from the account handle in
   `base/connection.rs`, which holds the OpenMLS store and the draft observer and delegates replay snapshots to
   protocol code (PR 2's generated list found them; this brief's preview counted one). PR 4 removes those.
4. **The app handle type**, in mechanical slices: introduce `SqliteAppStorage` over the account's connection, move the
   app and transport methods to it a folder at a time, and repoint the callers the compiler finds, `marmot-app` above
   all. The draft-commit observer is the exception: `cgka-session` installs it on the engine's storage (`cgka-session`
   `lib.rs:490-495`) and the confirm path fires it on that same value (`storage/outbound.rs:60`), so its slot and setter
   stay on `SqliteAccountStorage`, in `cross/`. It is `cgka-session`'s only app-side call on that storage. The names
   test adds two checks: protocol production code never names `SqliteAppStorage`, and app production code outside
   `cross/` never calls the protocol traits; tests may hold both handles. When the app methods have moved,
   `SqliteAccountStorage` is the engine's handle and moves to `protocol/`, `SqliteAppStorage` lives in `app/`, both
   over `base`'s connection, and the draft observer's type and slot go to `cross/`, which ends the handle's three
   allow-list lines.
5. **Tracing targets.** Rename the hard-coded targets (20 today, 3 of them in test files) to the new module paths in
   one PR, and update the docs and simulator filters that match them.

## Sequencing against step 2

Step 4 starts after step 2, one extraction at a time. If parallel work is wanted: PRs 1–3 touch only `storage-sqlite`
(and its `AGENTS.md` files), so they don't collide with the relay-plane move. PR 4 rewrites `marmot-app`'s calls to
about 318 app methods (a name-match count) and must wait until step 2's crate move (its PR 3) and caller repoint (its
PR 4) have landed.

## Proof that behaviour is unchanged

- Each PR on its own: `cargo test -p storage-sqlite`, including the migration assurance, upgrade-fixture and
  snapshot tests; `cargo test -p cgka-engine` (its 36 test files use this crate); `cargo test -p marmot-app`;
  `just simulator-smoke`.
- No schema change: the migration count does not change, and a fresh database's `sqlite_master` and its
  `cgka_schema_migrations` `(version, name)` rows, ordered by version, are identical before and after (add a test
  that compares them). The ledger's `applied_at_unix_seconds` column (`migrations.rs:1010-1013`) records when each
  migration ran, so it is left out of the comparison.
- The migration ledger matches entries by name (`migrations.rs:976-984`), so moving bodies is safe; the strictly
  ordered registry (`:1020`) and the hard-coded migration 9 reconcile (`:1067`) stay.
- No public API change in PRs 1–3: `cargo check --workspace --all-features` with the `lib.rs` re-exports unchanged.
- PR 4 changes the crate's API (a new handle type, methods moving to it) but not behaviour: run
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and the test suites above on each
  slice; the DTOs `marmot-app` re-exports to hosts stay as they are.

## Risks

| Risk | Mitigation |
| --- | --- |
| The SQL scan reads string literals, so it misses a table name assembled at run time and flags one quoted in a message | Today's SQL names its tables in literals, including the loops over table-name arrays (hypothesis, checked when PR 2 generates the list). A false positive goes on the allow-list with the rest; review catches run-time names |
| The names test matches methods by name and only through `self` or `Self`, so it misses a call through another binding, and a name defined on both sides is ambiguous | Count an ambiguous name as same-side; PR 4 makes the channel structural |
| Self-inspection tests split their own file by function name (`messages.rs:2351`, `message_drafts.rs:735`, `value_store.rs:891,920`, `shared.rs:770,879`) | Move the functions they inspect with them, or repoint the tests in the same PR |
| `pub(super)` items in `transport_routes.rs` and `messages.rs:995` assume `storage/` moves as one unit | Move `storage/` whole into `protocol/` |
| 28 files import `crate::storage::test_support`, 13 of them outside `storage/` | Move it to `base/` and repoint every importer in PR 1; keep no `crate::storage::test_support` re-export |
| Tracing targets stop matching module paths after PR 1 | PR 5 renames them; the observability rule is met again then |
| 20 docs pages and `scripts/test_select_ci_tests.py:63` cite `storage-sqlite/src/...` paths | Update the AGENTS tables in PR 1; repoint docs citations as each is next edited, except architecture pages that state current structure |
| Wide diffs collide with concurrent storage work, such as the media store (#2314) | Land PR 1 in a quiet window; it is moves only and rebases mechanically |

## Out of scope

- Splitting the crate (step 8), and choosing which store each shared table lands in.
- Any schema, trigger or foreign-key change.
- A second database file (decided against, 2026-10-17).
- Moving the transport-specific tables to `transport-nostr`.

## Done when

- The crate has `base/`, `protocol/`, `app/` and `cross/`, and both tests pass.
- After PR 4, the allow-list holds only schema links and the migration 9 reconcile, and `cross/README.md` explains each
  kind.
- `marmot-app` reaches app storage only through `SqliteAppStorage`, and the names test covers the handle.
