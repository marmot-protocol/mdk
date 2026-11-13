# cross

The protocol side and the app side of `storage-sqlite` share one database file, so some operations must change both
sides' tables in one transaction. That code lives here, one named function per crossing, and this is the only folder
`base::boundary_tests` lets name both sides. What still crosses elsewhere is listed in [`allow-list.txt`](allow-list.txt);
the list only shrinks.

## What is here

| Module | The crossing | Called from |
| --- | --- | --- |
| `routes.rs` | Deleting a route's recovery inventory and NIP-77 reconciliation state when the engine deletes the route or the group | `protocol/storage/transport_routes.rs`, `protocol/storage/groups.rs` |
| `groups.rs` | Lifting the media-secret retirement barrier when a forgotten group rejoins | `protocol/storage/groups.rs` |
| `handles.rs` | Constructing the app handle, sharing file-keyed notification revisions, and installing TEMP triggers on app tables for app and protocol mutations | `protocol/handle.rs` (`from_opened`), callers of `app_storage()` |
| `release.rs` | Message release for replay: whether an app owns the messages, retiring seen-ring and inventory entries, un-covering their seconds in the coverage ledger, arming or invalidating the recovery ledger | `protocol/storage/messages.rs` |
| `outbound.rs` | The confirm path consuming the local submission and the draft a message came from, and waking the app's draft observer; the observer's type, its slot on the account handle and its setter, which `marmot-session` calls on the engine's storage | `protocol/storage/outbound.rs` |
| `device_group_moves.rs` | Exact authenticated Welcome consumption records Joined; selected Made cuts trust with capture, old-debt retirement and bootstrap | protocol Welcome admission; finite session move owner |
| `sibling_welcome_resends.rs` | Immutable first accepted-publication time in the fanout receipt transaction, carrier reservation/attachment, and group-lifetime cleanup | `marmot-session` receipt persistence and `marmot-app` DG/publication projection |
| `projection.rs` | The projection checkpoint acknowledging the engine outbox and probing forgotten groups, in its own transaction | `app/account_projection.rs` |
| `authority.rs` | The app queueing backfilled authority requests in the engine's outbox | `app/timeline/reports.rs` |
| `wipe.rs` | The local-forget wipe: a group's app data, and on an engine forget its engine rows and forget marker, in one transaction. `delete_local_group_data`, the app's entry point, lives here on the account handle | `protocol/storage/groups.rs` (`forget_group_local`), `marmot-app` (`delete_local_group_data`) |
| `views.rs` | App reads of engine tables: the chat list's leave and disband state, branch-withdrawal origins, a conversation's group state, a group's routes, the local-deletion frontier's message order, and the spill's released-receipt check | `app/chat_list.rs`, `app/chat_list/pages.rs`, `app/timeline.rs`, `app/timeline/capture.rs`, `app/account_projection.rs`, `app/transport/delivery_spill.rs` |
| `group_writes.rs` | Per-group write counts over the engine's and the app's tables a published group answer reads (mdk#3273): TEMP triggers on both sides, counted per database file (by identity) across this process's connections, with a `PRAGMA data_version` check for writers they miss | `protocol/handle.rs` (`from_opened`), `protocol/provider.rs` (`group_write_generation`) |
| `migrated_template.rs` | Test support only: an in-memory test database copied from a migrated template, which draws the per-database values a fresh database draws on both sides (the chat presentation store epoch, the migration ledger's times) | `protocol/handle.rs` (`in_memory_for_test`) |

Outside the schema links below, the list holds only the legacy migration 9 reconcile. App code reaches the engine's
storage only through this folder: the names test flags app code that names `SqliteAccountStorage` or one of the
traits protocol code implements for it.

## Schema links that stay

These are schema, which step 4 does not change. The foreign keys and triggers stay on `allow-list.txt`; the others are
not table references the test can see.

- **Foreign keys:** `account_recovery_obligations`, `app_epoch_stall_evidence` and `app_group_recovery_failures`
  reference `cgka_groups` and are deleted in cascade with a group (migrations 0092, 0055 and 0067).
- **Triggers:** migration 0072 creates the 17 chat-list key triggers. Twelve on the engine's leave and disband tables
  rewrite `chat_list_rows`; five on `account_groups` and `chat_list_rows` read those engine tables.
- **One migration ledger:** both sides' migrations run in one strictly ordered registry (`base/migrations.rs`), and the
  legacy migration 9 reconcile adds a column to two app tables.
- **One MLS cache generation:** every commit to the file, app writes included, changes `PRAGMA data_version`, which
  invalidates the engine's cached MLS groups (`protocol/provider.rs`, `mls_write_generation`).

Step 8 decides per table which store each lands in.

The sibling-Welcome crossing captures the sender's first actual accepted-publication time atomically with its fanout
receipt. Already-accepted legacy fanouts without a time remain unknown. The app reuses D35 heartbeat activity for the
current roster incarnation; ordinary processed-wrapper admission keeps only its lifetime dedup marker. There is no
per-message proof/alias journal, historical source-recovery rewind, upgrade epoch cutoff or observation ordering clock.
The per-Welcome app row keeps carrier identities and timing only, with a prepared-carrier timestamp high-water
reserved atomically with the engine carrier association on the session's own connection before handoff. Duplicate
projection preserves the first time, only the exact prepared carrier can advance the successful generation, and a late
older callback cannot replace it or resurrect retired metadata. Migration 0174 drops obsolete indexes and the local
ordering clock; unused nullable legacy columns remain inert, without a ledger rebuild.

Retirement walks the existing per-Welcome primary key in bounded batches, including unarmed rows; it stores no second
expiry or origin. The engine marks expiry terminal before the app deletes timing/high-water state, so a backward clock
or a late carrier outcome cannot make the original owed again. Group deletion, including terminal local deletion that
keeps a disband tombstone, removes rows where either the chat or device group matches. Transport fanout settlement
retains its own durable owner and is independent of retirement of this timing metadata.
