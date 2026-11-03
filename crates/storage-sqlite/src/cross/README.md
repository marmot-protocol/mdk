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
| `release.rs` | Message release for replay: whether an app owns the messages, retiring seen-ring and inventory entries, un-covering their seconds in the coverage ledger, arming or invalidating the recovery ledger | `protocol/storage/messages.rs` |
| `outbound.rs` | The confirm path consuming the local submission and the draft a message came from, and waking the app's draft observer; the observer's type, its slot on the account handle and its setter, which `marmot-session` calls on the engine's storage | `protocol/storage/outbound.rs` |
| `sibling_welcome_resends.rs` | Local accepted-publication ordering and immutable qualified DG content observations on the existing processed-wrapper ledger, plus the first matching activity for one Welcome generation, carrier reservation/attachment, and group-lifetime cleanup | `marmot-session` receipt persistence and `marmot-app` DG/publication projection |
| `projection.rs` | The projection checkpoint acknowledging the engine outbox and probing forgotten groups, in its own transaction | `app/account_projection.rs` |
| `authority.rs` | The app queueing backfilled authority requests in the engine's outbox | `app/timeline/reports.rs` |
| `wipe.rs` | The local-forget wipe: a group's app data, and on an engine forget its engine rows and forget marker, in one transaction. `delete_local_group_data`, the app's entry point, lives here on the account handle | `protocol/storage/groups.rs` (`forget_group_local`), `marmot-app` (`delete_local_group_data`) |
| `views.rs` | App reads of engine tables: the chat list's leave and disband state, branch-withdrawal origins, a conversation's group state, a group's routes, the local-deletion frontier's message order, and the spill's released-receipt check | `app/chat_list.rs`, `app/chat_list/pages.rs`, `app/timeline.rs`, `app/timeline/capture.rs`, `app/account_projection.rs`, `app/transport/delivery_spill.rs` |
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

The sibling-Welcome observation crossing (migration 0169) preserves wrapper-id deduplication and adds indexed content
bindings to that same lifetime-of-group ledger. The native accepted-source transaction records immutable first local
observation and a versioned sending-epoch member/leaf proof for protocol-marked device-roster groups only. Direct native
acceptance and actual selected replay share this owner; candidate probes never stamp it. Missing old source-leaf proof
may be attached only after exact ciphertext reauthentication, without changing its first stamp. Later app attribution
under the current trusted roster cannot retime any already-observed content. A valid app's native identity is bound to
its exact source leaf key/tag; after verification its aliases coalesce only under the current roster's verified tag key
and slot. That key attests the source leaf key, so MLS rekey under an unchanged tag principal preserves the earliest
observation; different tag-key incarnations never cross-merge. Unknown old source proof holds only aliases sharing that
inner event identity. `source_resolved` distinguishes pending(0), completed qualification/ignore(1), and verified alias(2);
only canonical qualified1 rows arm timing. Key-unready source hints filter pending reads, never grant attribution. Proof-present and missing-proof pending
scans are independently indexed and bounded at 32; healthy facts project before unavailable-proof recovery. The latter
uses content-id keyset pages plus a group-scoped ephemeral cursor and at most 128 anchor-fingerprint retry hints, so
unavailable old facts cannot permanently block later recovery. The recovery rewind joins the existing group savepoint,
so a failed historical restore cannot leave an old selected view before its optional projection error is isolated. A cache hit never resolves a fact or releases an alias. Wrapper
replay, message upserts, format promotion and MLS snapshots never reset provenance. Native source order and the
fanout's first acceptance order share a scalar local clock; the corresponding observation time measures the fixed
wait. The one per-Welcome app row retains identities and timing only, with a prepared-carrier timestamp high-water
reserved atomically with the engine carrier association on the session’s own connection before handoff; the app and
runtime can otherwise hold separate connections to this same file. Existing local group epochs are
frozen at upgrade as the conservative qualification cutoff; new local groups use -1. No raw-ingress retention changes,
second seen-message ledger or new scheduler are introduced.

Pre-cutoff native facts still retain verified device-principal attribution for alias deduplication. D91 restricts
arming only; a later-epoch or rekeyed alias of already observed content cannot become fresh activity.

Retirement walks the existing per-Welcome primary key in bounded batches, including unarmed rows; it stores no second
expiry or origin. The engine marks expiry terminal before the app deletes timing/high-water state, so a backward clock
or a late carrier outcome cannot make the original owed again. Group deletion, including terminal local deletion that
keeps a disband tombstone, removes rows where either the chat or device group matches. Transport fanout settlement
retains its own durable owner and is independent of retirement of this timing metadata.
