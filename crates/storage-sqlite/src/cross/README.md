# cross

The protocol side and the app side of `storage-sqlite` share one database file, so some operations must change both
sides' tables in one transaction. That code lives here, one named function per crossing, and this is the only folder
`base::boundary_tests` lets name both sides. What still crosses elsewhere is listed in [`allow-list.txt`](allow-list.txt);
the list only shrinks. The plan is the
[step 4 storage brief](../../../../docs/marmot-architecture/review/brief-storage-boundaries.md).

## What is here

| Module | The crossing | Called from |
| --- | --- | --- |
| `routes.rs` | Deleting a route's recovery inventory and NIP-77 reconciliation state when the engine deletes the route or the group | `protocol/storage/transport_routes.rs`, `protocol/storage/groups.rs` |
| `groups.rs` | Lifting the media-secret retirement barrier when a forgotten group rejoins | `protocol/storage/groups.rs` |
| `release.rs` | Message release for replay: whether an app owns the messages, retiring seen-ring and inventory entries, arming or invalidating the recovery ledger | `protocol/storage/messages.rs` |
| `outbound.rs` | The confirm path consuming the local submission and the draft a message came from, and waking the app's draft observer; the observer's type, its slot on the account handle and its setter, which `cgka-session` calls on the engine's storage | `protocol/storage/outbound.rs` |
| `projection.rs` | The projection checkpoint acknowledging the engine outbox and probing forgotten groups, in its own transaction | `app/account_projection.rs` |
| `authority.rs` | The app queueing backfilled authority requests in the engine's outbox | `app/timeline/reports.rs` |
| `wipe.rs` | The local-forget wipe: a group's app data, and on an engine forget its engine rows and forget marker, in one transaction. `delete_local_group_data`, the app's entry point, lives here on the account handle | `protocol/storage/groups.rs` (`forget_group_local`), `marmot-app` (`delete_local_group_data`) |
| `views.rs` | App reads of engine tables: the chat list's leave and disband state, branch-withdrawal origins, a conversation's group state, a group's routes, the local-deletion frontier's message order, and the spill's released-receipt check | `app/chat_list.rs`, `app/chat_list/pages.rs`, `app/timeline.rs`, `app/timeline/capture.rs`, `app/account_projection.rs`, `app/transport/delivery_spill.rs` |

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
