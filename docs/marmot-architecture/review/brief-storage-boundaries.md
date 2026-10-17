---
title: "Extraction Brief — Internal Boundaries in storage-sqlite"
created: 2026-10-17
updated: 2026-10-17
tags: [marmot, architecture, review, extraction-brief, storage, sqlite]
status: proposed, needs approval before implementation
---

# Extraction Brief — Internal Boundaries in `storage-sqlite`

Step 4 of the [core structure plan](core-structure.md#5-sequencing). It gives `storage-sqlite` explicit protocol,
app and transport boundaries inside the crate, so the later split into a protocol store and an app store
(step 8) is a review of boundaries that already hold, not an excavation. No behaviour or schema change. Counts and
`path:line` citations are at master `e9ecb12e0`. Following the [review's evidence rules](README.md#evidence-rules),
statements are observed in source unless marked (hypothesis).

Product-owner decisions this brief assumes (2026-10-17): one database file per account-device stays, unless a
strong reason to split appears; each crate is a black box with a clean interface, and nothing reaches into
another crate's internals.

## Why this step, and why now

- Step 5 moves the engine's account-record storage proxy up into `marmot-session`, and step 8 splits this crate
  into a protocol store and an app store. Both need to know exactly where the two sides touch. Today nothing
  in the crate says so.
- It needs no code from step 2, so it can run while the relay plane moves.
- It is the storage review (Pass 1 system C), scoped to what the plan needs.

## What the crate is today

44,694 production lines: 40,168 of code and 4,526 in 112 migration bodies.

| Side | Production lines | What it is |
| --- | ---: | --- |
| Protocol | 6,508 (16% of non-migration code) | `storage/` (the engine's `StorageProvider` traits, snapshots, maintenance records) and `openmls_storage/` |
| Base | 3,449 + 4,526 migrations | `connection.rs` (SQLCipher connection, transactions, open), `codec.rs`, the migration runner and registry, `open_progress.rs`, `lib.rs` |
| App | 26,707 | Projections (`account_projection`), the recovery ledger (`account_recovery/`), `timeline/`, `chat_list/`, `chat_presentation`, attachments, avatars, drafts, local submissions, media catalog, media secrets |
| Transport-specific | 1,853 | `transport_reconciliation` (NIP-77), `delivery_spill` (relay plane), `user_blocks` (NIP-51), `moderation_reports` (NIP-59), `agent_stream_sequences` (QUIC), `prepared_group_image_upload` (Blossom) |
| Separate database | 1,080 | `shared.rs` and `shared/` (`SqliteSharedStorage`) |
| Benchmarks (feature-gated) | 571 | `media_store_bench.rs` (`media-store-benchmarks`) |

127 tables: 33 protocol (29 `cgka_*`, `openmls_values`, the engine-to-app outbox `pending_application_events` and
`pending_application_authority`, and `locally_forgotten_groups`), 10 transport, 83 app, and the migration ledger.
13 tables are written by both sides, and 10 migrations (12 if `locally_forgotten_groups` counts as app) touch both
sides' tables.

### The real boundary problem is the type, not the files

Every module adds inherent methods to one type, `SqliteAccountStorage` (`connection.rs:1050`), whose
`connection` and `openmls` fields are `pub(crate)` (`connection.rs:1050-1057`). It has 387 `pub` inherent methods:
21 in protocol or base modules and 366 app or transport. `marmot-app` calls about 318 of them (name-match count,
hypothesis), through the concrete type: there is no app-side trait. So protocol code reaches app code by method
call, not by path. `forget_group_local_data`, `accept_local_submission_tx` and `notify_message_draft_committed` are
examples. Moving files into `protocol/` and `app/` alone would not stop any of those calls (hypothesis, but it
follows from Rust's visibility rules: an inherent `pub` method is callable from anywhere the type is).

The engine side already has its seam: `StorageProvider` and its 16 traits (`traits/src/storage.rs:996-1015`); the
engine is generic over them. The one trait-backed app seam is the media store's (`MediaCatalog`, `PublishTarget`,
`CheckpointTarget`).

## The couplings

All 11 that core-structure counted still exist, plus four more. "Treatment" is what this step does; "later" is
where it can go away.

| # | Coupling | Site | Treatment in step 4 | Later |
| --- | --- | --- | --- | --- |
| 1 | The app's projection checkpoint acknowledges the engine outbox in its own transaction | `account_projection.rs:1313-1319` (in `save_account_projection`, `:1046`) | `cross::acknowledge_outbox_in_projection` | Keep: one transaction must cover both (core-structure §2.5) |
| 2 | The engine's confirm transaction consumes drafts and local submissions and fires the app's draft observer | `storage/outbound.rs:41,48,60` and `:244,250,263` | `cross::consume_drafts_in_confirm` | Keep, behind a hook the app store registers (step 8) |
| 3 | Message release writes the app recovery ledger and `seen_events`, and reads `account_state`; group and route deletion delete the ledger's inventory | `storage/messages.rs:110,118,319-326,354,1298-1305`; `account_recovery::delete_inventory_tx` from `storage/groups.rs:164` and `storage/transport_routes.rs:75,108,153` | `cross::release_for_replay`, `cross::consume_released_receipts` and `cross::delete_recovery_inventory` | Step 8: an app-side journal the engine writes and the app consumes |
| 4 | Group and route deletion clear NIP-77 reconciliation rows | The `transport_reconciliation_*` deletes: `storage/groups.rs:173-192`; `storage/transport_routes.rs:81,87,118,128,163,173` | `cross::clear_reconciliation_for_group` and `..._for_route` | When reconciliation moves to `transport-nostr` |
| 5 | Local forget and delete span both sides in one wipe | `account_projection.rs:1442-1602` | `cross::forget_group_local_data` (the wipe moves there whole) | Keep: a local delete must be atomic |
| 6 | App tables cascade from `cgka_groups` | Migrations 0055:10, 0067:9, 0092:26,51 | Listed in `cross/README.md` | Step 8 decides per table |
| 7 | Engine-table triggers maintain the chat list | Migrations 0071:13-16 and 0072:70-178 (12 triggers) | Listed in `cross/README.md` | Step 8: replace with the outbox, or keep as schema |
| 8 | App reads join engine tables | `chat_list.rs:7-11,2533`, `chat_list/pages.rs:357-362`, `timeline/capture.rs:65-66`, `timeline.rs:1296-1316`, `account_projection.rs:1511-1514,1752,1882,1908`, `delivery_spill.rs:88-91` | Read-only engine views in `cross/` | Step 8: published read views |
| 9 | The app writes the engine's authority outbox | `timeline/reports.rs:555-620` | `cross::backfill_authority_request` | Step 8 |
| 10 | App writes invalidate the engine's MLS cache | `connection.rs:1604-1621` (`PRAGMA data_version`) | Stays in `base/`, documented | Keep while both sides share a file |
| 11 | One migration ledger | `migrations.rs:258-932`; strict order at `:1020` | Stays in `base/` | Keep: one file, one ledger |
| A | A `GroupStorage` method writes the app's media-secret barrier | `storage/groups.rs:40-58` | Into `cross/` | Step 8 |
| B | Protocol code reads app state (`account_state`) | Inside #3 | Covered by #3 | With #3 |
| C | App modules open transactions through `StorageProvider::with_transaction` (`connection.rs:1643`) | `recovery_health.rs:30,71`, `account_recovery/stall.rs:21`, `account_recovery/comparison.rs:149` | Switch to `SharedConnection::with_transaction` (`connection.rs:596`) in PR 3 | — |
| D | `marmot-app` reads protocol state through the engine traits on its own connection | `marmot-app` `local_submissions.rs:317`, `client/projection.rs:380,1221`, `runtime/mod.rs:6700` | Recorded; no change here | Step 5 (`marmot-session` owns those reads) |

## Target layout inside the crate

```text
storage-sqlite/src/
  base/        connection, transactions, codec, migration runner and bodies, open progress
  protocol/    storage/* and openmls_storage/*: implements the engine's StorageProvider traits
  app/         projections, recovery ledger, timeline, chat list, attachments, avatars, drafts, ...
  transport/   reconciliation, delivery spill, user blocks, moderation outbox, agent stream sequences,
               prepared group-image upload
  cross/       one named function per coupling above, plus README.md listing the schema-level ones
  shared/      the separate shared database, unchanged
```

Rules once the layout holds, checked by a test the way the relay-plane move checks its imports:
- `protocol/` names nothing in `app/` or `transport/`, and `app/` and `transport/` name nothing in `protocol/`
  except the engine-owned DTOs the traits already export. Only `cross/` names both sides.
- Helpers that `cross/` calls stay `pub(crate)`: `cross/` is a sibling folder, and `pub(in crate::app)` is not
  visible to it. The boundary test, not visibility, keeps other folders from naming them. Helpers only their own
  folder uses become `pub(in crate::app)`, `pub(in crate::transport)` or `pub(in crate::protocol)`.

## The app handle type (decided 2026-10-17)

Folders and narrowed helper visibility make the couplings visible and stop new path-level reaches. They do not
stop a protocol module calling one of the 366 `pub` app methods on `SqliteAccountStorage`, because those methods
are callable wherever the type is.

**Decision:** step 4 gives the app side its own handle type, `SqliteAppStorage`, as PR 4, after the folders,
`cross/` and the boundary test. The app and transport methods move onto it; `SqliteAccountStorage` keeps the
protocol traits. `marmot-app` reaches app storage through the new handle, and only `cross/` holds both. The handle
shares the account's existing connection and lifecycle, so it opens no second connection and closing the account
storage closes it too. It is the type the app store crate gets in step 8, so the work is not thrown away. It is
mechanical but wide: about 318 call sites in `marmot-app` change from `storage.x()` to `app_storage.x()`.

Declined: stopping at folders, visibility and `cross/`, which would leave the wall a convention until step 8.

## PR sequence

Each PR is green on its own and changes no behaviour or schema.

1. **Create the folders and `git mv` the files.** Keep every crate-root re-export in `lib.rs` (257 names today),
   so no other crate changes. Fix the internal paths that cross the new folders (about 70, hypothesis). Repoint the
   117 `#[path]` attributes in `migrations.rs` and the 6 others, and the `include_str!`/`include_bytes!` fixtures.
   Keep the 18 hard-coded tracing targets unchanged in this PR. Update the crate and nested `AGENTS.md` key-file
   tables.
2. **Introduce `cross/`.** Move each coupling's code into its named function: the protocol modules' 8 reaches
   into `account_recovery` (including the 4 `delete_inventory_tx` calls) and 1 into `message_drafts`, the wipe from
   `account_projection`, the authority backfill from `timeline/reports`. The callees stay where they are, at
   `pub(crate)`. Add `cross/README.md` for the schema-level couplings (#6, #7, #10, #11) with migration
   citations.
3. **Narrow visibility and add the boundary test.** Switch the four app transactions in coupling C to
   `SharedConnection::with_transaction` first. Helpers only their own folder uses become folder-private; the ones
   `cross/` calls stay `pub(crate)`. The test fails on any path from `protocol/` into `app/` or `transport/`, or back,
   outside `cross/`.
4. **The app handle type**, in mechanical slices: introduce `SqliteAppStorage` over the account's connection, move
   the app and transport methods to it a folder at a time, and repoint `marmot-app` and `cgka-session`'s draft
   observer. Extend the boundary test: protocol code never names `SqliteAppStorage`, and app code never calls the
   protocol traits on `SqliteAccountStorage` outside `cross/`.
5. **Tracing targets.** Rename the 18 targets to the new module paths in one PR, and update the docs and simulator
   filters that match them.

## Sequencing against step 2

Step 4 starts after step 2, one extraction at a time. If parallel work is wanted: PRs 1–3 touch only
`storage-sqlite` (and its `AGENTS.md` files), so they don't collide with the relay-plane move. PR 4 rewrites about
318 `marmot-app` call sites and must wait until step 2's crate move (its PR 3) and caller repoint (its PR 4) have
landed.

## Proof that behaviour is unchanged

- Each PR on its own: `cargo test -p storage-sqlite`, including the migration assurance, upgrade-fixture and
  snapshot tests; `cargo test -p cgka-engine` (its 36 test files use this crate); `cargo test -p marmot-app`;
  `just simulator-smoke`.
- No schema change: the migration count stays 112, and a fresh database's `sqlite_master` and
  `cgka_schema_migrations` are identical before and after (add a test that compares them).
- The migration ledger matches entries by name (`migrations.rs:976-984`), so moving bodies is safe; the strictly
  ordered registry (`:1020`) and the hard-coded migration 9 reconcile (`:1067`) stay.
- No public API change in PRs 1–3: `cargo check --workspace --all-features` with the `lib.rs` re-exports unchanged.
- PR 4 changes the crate's API (a new handle type, methods moving to it) but not behaviour: run
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` and the test suites above on each
  slice; the DTOs `marmot-app` re-exports to hosts stay as they are.

## Risks

| Risk | Mitigation |
| --- | --- |
| Self-inspection tests split their own file by function name (`messages.rs:2351`, `message_drafts.rs:735`, `value_store.rs:891,920`, `shared.rs:770,879`) | Move the functions they inspect with them, or repoint the tests in the same PR |
| `pub(super)` items in `transport_routes.rs` and `messages.rs:995` assume `storage/` moves as one unit | Move `storage/` whole into `protocol/` |
| App test modules import `crate::storage::test_support` (`recovery_health.rs:92`, `transport_reconciliation.rs:455,554`, `account_recovery/*`, `delivery_spill.rs:319`, `migrations.rs:1248`) | Move `test_support` to `base/` and keep a re-export |
| Tracing targets stop matching module paths after PR 1 | PR 5 renames them; the observability rule is met again then |
| 20 docs pages and `scripts/test_select_ci_tests.py:63` cite `storage-sqlite/src/...` paths | Update the AGENTS tables in PR 1; repoint docs citations as each is next edited, except architecture pages that state current structure |
| Wide diffs collide with concurrent storage work, such as the media store (#2314) | Land PR 1 in a quiet window; it is moves only and rebases mechanically |

## Out of scope

- Splitting the crate (step 8), and choosing per table which side owns the shared ones.
- Any schema, trigger or foreign-key change.
- A second database file (decided against, 2026-10-17).
- Moving the transport tables to `transport-nostr`.

## Done when

- The crate has `base/`, `protocol/`, `app/`, `transport/` and `cross/`, and the boundary test passes.
- Every coupling in the table is either a named `cross/` function or listed in `cross/README.md`.
- `marmot-app` reaches app storage only through `SqliteAppStorage`, and the boundary test covers the handle.

## Open questions

1. Should `transport/` stay inside this crate until `transport-nostr` can own its tables, or fold into `app/` for
   now?
