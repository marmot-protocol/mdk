# marmot-app

`marmot-app` is the first non-lab multi-account app runtime bridge.

It wires the app-owned `AccountHome` to encrypted session storage, the Nostr MLS peeler, the Nostr transport adapter, and
relay-backed transport state. The crate is intentionally below presentation layers like `wn` and above the generic
account/session/engine crates.

It owns these local SQLite stores:

- per-account SQLCipher app state in the account's storage database (`accounts/<label>/session.sqlite`) for joined
  groups, app-component profile/image/admin/Nostr-routing projections, pending invite confirmation state, seen relay
  events, and sent/received message projections. The older `accounts/<label>/app.sqlite3` is the legacy projection
  database; its contents are imported once (tracked by the `legacy-account-projection-v1` marker) and then superseded;
- a per-account SQLCipher directory cache at `accounts/<label>/app-cache.sqlite3` for the Nostr user directory:
  local-account links, profile metadata, follow-list caches, bounded search-graph edges, discovered user relay lists,
  and KeyPackages (the root-level `app-cache.sqlite3` is a legacy location that is migrated and then removed);
- an owner-only, unencrypted installation-wide `shared.sqlite3` containing a provenance-stripped public-directory
  mirror, relay-telemetry and audit-log preferences, and the telemetry installation id.

For `N` active signing accounts whose stores have been opened, this is up to `2N + 1` current SQLite files.
`session.sqlite` contains authoritative protocol and recovery state and has a numbered migration history. The two
directory tiers are reconcilable caches, but normal upgrades should preserve them; `shared.sqlite3` also contains
durable installation settings that are not disposable. The per-account cache has its own numbered
`app_cache_schema_migrations` ledger and refuses versions newer than the binary supports. Each migration commits its
schema/data changes and ledger row atomically; version 1 validates and adopts existing unversioned tables and converts
legacy JSON records without discarding directory or search data. Invalid shapes or migration names fail closed.
The shared store still initializes tables without a numbered ledger; neither tier uses the session database's
migration version.

The app runtime exposes those projections through account status, group listing/showing, message listing, and
snapshot-plus-live subscription APIs so CLI and TUI surfaces can inspect app state without opening the databases
directly.

Rust app/runtime draft commands expose selected metadata, conditional save/clear, keyed attachment bytes and
revision-bound sends. Post-commit invalidations let conversation owners reload the selected composer; durable
outbox acceptance clears only the submitted revision. See the
[draft lifecycle contract](../../docs/marmot-architecture/further-context/conversation-drafts.md).

C5's shared conversation presentation builds a compact header, shared capability hints and a complete dictionary
for its bounded visible identity references from local caches. Native management policy delegates to the same
Rust selector; see the
[conversation presentation contract](../../docs/marmot-architecture/further-context/conversation-presentation.md).

`MarmotAppRuntime::open_conversation_window` combines that presentation with bounded history, retained read
state and the selected draft in one initial/live Rust handle. It opens at first unread or latest, follows new
arrivals in latest mode, preserves explicit/history anchors, and serializes paging with refreshes. Capture
failures retain timed retries; account teardown and subscription drop close the handle. It never marks read
or loads attachment bytes. Native handles remain C5 M5; see the
[live conversation contract](../../docs/marmot-architecture/further-context/conversation-live-window-plan.md).

New-account bootstrap publishes the required NIP-65 kind `10002` and inbox kind `10050` relay-list events, a
kind `0` profile, and an initial last-resort Marmot kind `30443` KeyPackage from a default relay set. KeyPackages are
published to (and fetched from) the account's NIP-65 relays; there is no dedicated KeyPackage relay list. Import flows
can check whether those lists are already present before writing local account state. The same status API can fetch
those relay-list events from supplied bootstrap relays and store discovered user relay/KeyPackage data for deterministic
CLI/TUI development. KeyPackage publication keeps a stable replaceable d-tag for the account and tracks the decoded
KeyPackage ref separately; normal publish reuses only a cached current-profile last-resort package, while explicit
rotate, a legacy cache entry, or lifetime-policy rejection creates a new current-profile package under the same slot.
Account inventory listing (`account_key_package_records` / `account_key_packages`) exposes one current relay
event per addressable slot in the validated fetch window. `account_key_package_relay_events` returns that
window's current and superseded public events so a client can delete a superseded event id without targeting
the current winner or inventing a second Published row.

Local-first hosts should call `local_account_key_packages` immediately, then independently await
`refresh_account_key_packages` and replace the displayed snapshot. The local read is storage-only: it does
not wait for network startup, start a worker, or query relays. It is synchronous SQLCipher I/O on the
caller's thread, so hosts should keep it off a UI or main thread. All local rows have `relay == false`.
`local_state` is the durable lifecycle (`Current`, `PendingReplacement`, `RetainedPrivateMaterial`,
`OtherOwned`); `record.relay` is a validated relay observation. Do not infer lifecycle from empty event IDs
or `published_at`. A failed or cancelled refresh must keep the local result. Empty bootstrap relays remain
network-enabled. After a mutation, re-read local inventory rather than applying an older refresh. A retained
row stays `RetainedPrivateMaterial` even when that exact event is observed; `record.relay` becomes true
while local state remains retained.

Account open performs the strict profile cutover before transport processing: the encrypted session transactionally
retires every locally stored legacy KeyPackage private bundle, then the app best-effort deletes cached and
relay-discoverable legacy kind `30443` events. A private owner-only retry marker is written before relay cleanup, so a
crash or relay failure cannot restore legacy join capability or lose the obligation to publish a current replacement.
Legacy Welcomes are terminally rejected. Already-joined legacy groups remain usable by their existing members,
including their Media V1 state, but membership additions and re-additions are refused.

The user directory is keyed by Nostr pubkey. Account setup and the daemon can refresh a local account's contact-list
event, pre-cache direct follows, and cache profile metadata for those likely contacts. Runtime startup builds chunked
directory subscriptions for local accounts and known users so profile, follow-list, relay-list, and KeyPackage updates
keep warming the cache. `search_cached_users(searcher, query, limit)` searches public profiles learned through
**any connected account**, including un-promoted profiles from previous searches, without relay access or group
membership reads. A profile learned during a search under one account is intentionally searchable under another account.
Private labels/nicknames do not participate. `is_followed_by_searcher` is relative only to the
selected account; another account's follows never confer that label. The older `search_user_directory` remains the
explicit offline graph-radius query.

`search_users` emits a `CachedResultsFound` batch, then streams Vertex profile discovery independently of the bounded
follow-graph traversal. The runtime resolves group co-members on the graph path, after the subscription is returned.
Consumers insert `new_results` and replace `updated_results` by `account_id_hex`, then re-sort; `total_result_count`
counts unique people. Results with radius 255 have no established graph distance yet and may receive one later.
Radius 1 also includes group co-members, so only the explicit follow flag means "You follow". Requested radius windows
filter known distances; other cached/provider identities remain discoverable and can recur on later pages.
Deduplicate by account ID across searches/pages as well as within a stream. Cache materialization is capped at
10,000 distinct identities per account cache (in account-ID order), matching the shared directory's existing cap;
the cache-only API and the stream's initial cache batch return at most 10,000 results. At that scale, local results
can be partial; network enrichment remains available.

Hosts should use the cache-only call off the UI thread on each query change, debounce network searches separately,
and discard results when the query or selected account changes. Dropping the streaming subscription cancels both
network sources, including blocked membership reads. A failed cache read or unavailable group membership is an
optional-source failure: search continues without that input rather than emitting a terminal error. Vertex's signed
profiles are cached only in the un-promoted search tier; discovering a stranger never creates a live per-author
subscription. Traversal retains its radius, candidate, batch, and timeout bounds. Aggregate `search_stage` timings
separate cache reads, membership, provider response, profile hydration, and network completion, without logging
queries or identities.

Group creation and invites still take pubkeys at the action boundary. The app canonicalizes and deduplicates the
requested roster and fetches current KeyPackages in bounded multi-author relay batches before building the MLS add.
Cached packages remain useful for discovery, but cannot authorize an invitation or substitute for a failed relay
lookup. Hosts may prewarm that same bounded composition lookup without reserving packages or durably admitting
strangers; the final action reuses discovery routes but fetches packages again before the mutation validates them. This
also applies to another account on the same installation: its local package record is not an invitation shortcut,
and its published package must be reachable on relays. Relay freshness is not proof that the recipient still owns
private material; it avoids authorizing from a stale local copy. Each prewarm call requests a fresh readiness signal,
so hosts should debounce roster changes. The process-local prewarm cache retains only bounded relay metadata;
only completed discovery and advertised-outbox metadata hops can renew its freshness deadline. A usable package
returned after an incomplete metadata hop does not make previously cached routes fresh.

Directory diagnostics (`key-package check` / `fetch`) may still describe cached public packages. Their availability
result is advisory and does not guarantee a fresh relay lookup or acceptance by the Create/Invite admission policy.

New Nostr-routed groups generate
`marmot.transport.nostr.routing.v1` at creation, store the component bytes in
signed MLS app data, and project the decoded `nostr_group_id` plus relay list into group subscriptions and publish
targets.

Incoming welcomes are automatically joined at the MLS/session layer, then projected as pending local chats. Clients can
render accept/decline UI from the group record: accept clears `pending_confirmation`; decline publishes a leave, clears
the pending flag, and archives the local projection so normal chat lists hide it.

`MarmotAppRuntime` owns restored signing accounts, a shared relay plane, live account workers, runtime event hubs, and
the shared agent stream watch manager. The relay plane now also owns shared directory discovery fetches for relay lists,
profiles, follow lists, and KeyPackages, including endpoint safety and in-flight coalescing. Explicit catch-up remains
available for repair and tests, but the daemon path is runtime-owned subscriptions plus typed events.

`MarmotAppRuntime::start()` returns at local readiness: persisted account sessions are hydrated and worker-routed local
reads are available. Relay activation, group-subscription registration, shared-directory synchronization, and initial
catch-up continue asynchronously. Hosts should render local chat projections at that point, show network progress
separately, and allow subsequent relay events to refresh or reorder the rendered rows. Mutating worker commands received
during initial catch-up are deferred and replayed in order once the live client is ready.

Worker startup is isolated per account. A failed open does not discard a sibling that reached
local readiness. Failed accounts have an in-memory, per-account retry delay starting at one second,
doubling to a 60-second cap; the next reconcile or worker request after expiry admits one attempt.
There is no background retry timer. `restart_account` explicitly retries an eligible account, while
successful sign-in, signer registration, and committed setup/onboarding transitions reset that
account's delay. Reconcile and start still report an error if any eligible account failed or is
cooling down; a healthy worker remains usable through account-scoped commands. Successful startup
clears its failure record. Account removal, deactivation, and runtime shutdown discard the record.
Signed-out, missing-signer, and onboarding-gated accounts remain ineligible even after a reset.

The crate root now keeps app construction, shared state, storage/projector wiring, directory bootstrap, account relay
list helpers, and public re-exports. Runtime orchestration lives in the `src/runtime/` module, app-client commands and queries
live in the `src/client/` module, group DTOs/component projection helpers live in `src/groups.rs`, and encrypted-media
DTOs plus Blossom upload/download helpers live in the `src/media/` module.

## Encrypted media endpoints

Encrypted media and encrypted group images are uploaded as opaque `application/octet-stream` blobs. A compatible
Blossom server must accept arbitrary binary data rather than only recognizable image, audio, or video payloads. New
groups use the ordered built-in ciphertext-compatible endpoint list unless the host build supplies
`MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS`. Encrypted media uploads try those endpoints in order; encrypted group-image
uploads use only the primary (first) endpoint.

The endpoint list is embedded in the signed `marmot.group.encrypted-media.v1` component. Changing application defaults
does not rewrite existing group state. An active group admin can migrate an existing group with
`replace_encrypted_media_blob_endpoints` through the app runtime or UniFFI API.

Encrypted group images differ: no endpoint is stored in group state, so upload and fetch both resolve against the
build's primary endpoint. Clients compiled with different defaults therefore look for group images in different
places; re-setting the group image on a current build republishes it to the current primary endpoint.

## Application-owned group state

`MarmotAppRuntime::group_app_component` reads opaque application-owned
component bytes from local MLS state; `update_app_component` replaces one
optional component through an admin-authorized MLS commit. The same methods are
exported by UniFFI and C. Updates to required components are rejected; use the
existing typed APIs for protocol settings.

Applications allocate their own component ids at or above
`APP_OWNED_APP_COMPONENT_ID_START` (`0xf000`) and version their own payloads.
Ids below that boundary are refused. The boundary exists because the protocol
registry allocates upward from `0x8001` and is still growing: an application
that picked the next unassigned private-use id would have that id assigned out
from under it by a later registry entry, which both breaks its own writes and
starts applying protocol format validation to bytes already committed in live
groups. Nothing coordinates ids between applications, so treat the range as
first-come and version the payload.

Payloads are capped at `APP_COMPONENT_DATA_MAX_LEN` (4096 bytes). Before staging
an application update, MDK limits the resulting application-owned state to
32 entries and 8192 encoded bytes, including each entry's id and TLS length
prefix. Replacements count once; empty values still occupy a slot. These are
local authoring limits; unknown optional state received from peers stays opaque. Component
state is re-encoded into the GroupContext of every later commit and into the
GroupInfo of every Welcome, so an oversized value inflates every commit and can
push a Welcome past a relay's event-size limit — after the commit is already
staged. This is a settings channel, not a blob store; put bulk data behind a
reference.

An absent component returns `None`; a present empty payload returns
`Some(Vec::new())`. Empty payloads do not remove a component. The state survives
message expiry and reaches newly invited members in their Welcome, without
sharing earlier application-message history. Unsupported clients preserve
optional component bytes without interpreting them.

Refresh on runtime group events (including `EpochChanged` and convergence)
and after local updates. Reads are serialized through the account worker and
may wait behind an in-flight mutation. Updates use existing publication and
convergence semantics; hosts must handle publication uncertainty and
`GroupChangeSuperseded` rather than assuming a successful local change wins
every later concurrent commit. This API does not add automatic retries of an
application's desired value.

## Run the tests

```sh
cargo test -p marmot-app
cargo test -p marmot-app --features otlp-export
```

See [`AGENTS.md`](AGENTS.md) for the module map and privacy-safe telemetry rules.

## Explicit full-history repair

`MarmotAppRuntime::repair_full_history` requests one owner-authorized unfloored attempt and retains its frozen
scope and endpoint session across checkpointed drain quanta. A quantum yield does not resubscribe or buy another
retry. Success requires qualified exhaustive history and durable admission for every required endpoint/scope;
EOSE alone, a fast subset, or a superseded session cannot certify completion. The current SDK supplies no such
exhaustiveness certificate, so it honestly returns incomplete even if all endpoints report EOSE. Known-event
recovery can instead complete from a validated retained copy. Maintenance uses its separately fenced boundary.

The Rust `AppError::FullHistoryRepairIncomplete` preserves a bounded `FullHistoryRepairIncompleteReason` and an
independent `delivery_loss_pending` flag. Worker/binding calls retain their existing error channel; their safe
error code reports outstanding delivery loss when present, with cancellation taking precedence. No incomplete
attempt is converted to a success. Rust callers can inspect
`AppError::full_history_repair_incomplete()` for the typed reason and independent loss flag,
including through `AccountCatchUp`. It never parses display strings. The API shape for repair calls is unchanged.

The explicit attempt has a 60-second overall cooperative budget, including setup and reconciliation. A started
ingest/checkpoint finishes before deadline or caller/runtime cancellation is observed; this is not a hard bound
on an individual storage or network operation. An earlier terminal transport or drain-silence verdict also ends
the attempt. Partial progress remains durable, outstanding loss survives reopen, and only qualified completion
plus the exact live acknowledgment can reclaim captured loss evidence and release its cursor fence.

The account remains serialized during repair. The worker can serve committed member/roster snapshots while relay
I/O waits; mutations, subsequent repair requests, and reads behind queued mutations retain FIFO order. Send fairness
and isolated nonblocking network acquisition remain #1947 work. All automatic history triggers use the same
owner and durable pacing; bounded investigation can leave unresolved debt parked for new evidence or explicit repair.

## User blocking

`MarmotAppRuntime` exposes `block_user`, `unblock_user`, `get_blocked_users`,
`is_user_blocked`, and `subscribe_blocked_users`. The same API is available in
UniFFI (Swift/Kotlin) and the C ABI. All calls resolve an existing account reference;
user keys use the existing public-key parser. Blocking yourself and repeating an
already completed operation succeed without changing state.

Reads use the account's SQLCipher database. Lists contain `public_key`,
`is_private`, and local `created_at_ms`, sorted newest first with public key as the
tie-breaker. The subscription supplies an initial snapshot and subsequent complete
snapshots with a durable revision. Intermediate revisions may coalesce; subscribers
replace their local list with each snapshot.

Changes fetch the latest readable [NIP-51 kind 10000 list](https://github.com/nostr-protocol/nips/blob/master/51.md)
from the account's NIP-65 relays (or configured discovery relays). New entries are
private NIP-44 tags; legacy NIP-04 content remains readable. Other public and private
tags retain their placement. Startup, reconnect, and owned-account subscriptions
synchronize published lists. Whole-list replacement can still cause independent
cross-device edits to compete.

`BlockListUnavailable` means synchronization or definite publication failed;
changes learned during the preceding fetch are retained. `BlockPublicationUncertain`
means delivery or local completion is unresolved. The exact signed event remains in
the account database. While it is unresolved, other edits return the same uncertainty
error. Retrying the original operation reuses it after fetching again;
a newer remote replacement supersedes the old intent. Startup reconciles retained
intents against relays. A definite rejection on a later retry cannot disprove delivery
of the original attempt: the intent still fences other edits until that original
operation succeeds or a current relay replacement resolves it. Restoring relay write
access may be necessary; retrying alone does not guarantee recovery.
Success requires relay acceptance and committed local state.
An unreadable authenticated replacement prevents edits until a readable replacement
catches up, including after restart. Private plaintext never enters the shared directory.

Blocking retains history and existing DMs, disables their user-authored sends, and
rejects new DMs with `UserBlocked`. It hides blocked authors from app message reads,
search, timelines, media lists, reactions, quotes, previews, and attention counts.
Chat-list activity ordering deliberately still advances on blocked traffic; when
the latest message's author is blocked, its preview is blank and no older visible
message is substituted.
Manual-unread reminders remain independent. Shared groups continue to process MLS
state and permit communication with other members. Pending invitations from blocked
inviters remain stored but hidden; new Welcomes are checked against their authenticated
sender before admission and durably dismissed. Unblocking refreshes retained content
and invitations without replaying suppressed notifications. Raw storage and the
runtime diagnostic event stream remain separate from these presentation APIs.
Notification suppression records are removed when their source event or group is
physically deleted. Dismissed Welcome IDs remain for the account's lifetime: they
have no admitted group or event to attach retention to, and forgetting them would
allow an old relay delivery to create an invitation after unblocking.

Native screens and imports of old White Noise local databases are outside this
feature. Existing published lists migrate through relay synchronization.

## Group reports and admin deletion

`report_message` sends a kind-1984 NIP-56 report with a category and optional
explanation. It references a message event directly, without a revision tag or
per-reporter deduplication. Admins use `dismiss_reports` to label specific report
events with kind 1985 and an optional explanation. Each label is independent.

The existing `delete_message` API sends kind 4891 for admin deletion of a whole
chat, including an unreported message or the admin's own message. Kind 5 remains
author-only retraction. Admin authorization comes from authenticated source state;
later demotion does not revoke an established verdict. Group size and name do not
affect authorization.

`content_reports` lists individual reports, optionally filtered to a message.
`report_dismissals` lists admin labels. `reported_message` returns a reported
target's current deletion-masked projection, bypassing personal blocking.
Timeline records expose `has_reports` through existing subscriptions. There is no
shared queue, counter, or aggregate review status. Hosts choose review UI and
notifications. Report explanations follow their own retention and survive target
deletion while retained.

See [the implementation contract](../../docs/marmot-architecture/overview/content-moderation.md)
for source-state authorization, durable recovery, retention, and client compatibility.
