# marmot-app

`marmot-app` is the first non-lab multi-account app runtime bridge.

It wires the app-owned `AccountHome` to encrypted session storage, the Nostr MLS peeler, the Nostr transport adapter, and
relay-backed transport state. The crate is intentionally below presentation layers like `dm` and above the generic
account/session/engine crates.

It owns the first app projections:

- a per-account SQLCipher directory cache at `accounts/<label>/app-cache.sqlite3` for the Nostr user directory:
  local-account links, profile metadata, follow-list caches, bounded search-graph edges, discovered user relay lists,
  and KeyPackages (the root-level `app-cache.sqlite3` is a legacy location that is migrated and then removed);
- per-account SQLCipher app state in the account's storage database (`accounts/<label>/session.sqlite`) for joined
  groups, app-component profile/image/admin/Nostr-routing projections, pending invite confirmation state, seen relay
  events, and sent/received message projections. The older `accounts/<label>/app.sqlite3` is the legacy projection
  database; its contents are imported once (tracked by the `legacy-account-projection-v1` marker) and then superseded.

The app runtime exposes those projections through account status, group listing/showing, message listing, and
snapshot-plus-live subscription APIs so CLI and TUI surfaces can inspect app state without opening the databases
directly.

New-account bootstrap publishes the required NIP-65 kind `10002` and inbox kind `10050` relay-list events, a
kind `0` profile, and an initial last-resort Marmot kind `30443` KeyPackage from a default relay set. KeyPackages are
published to (and fetched from) the account's NIP-65 relays; there is no dedicated KeyPackage relay list. Import flows
can check whether those lists are already present before writing local account state. The same status API can fetch
those relay-list events from supplied bootstrap relays and store discovered user relay/KeyPackage data for deterministic
CLI/TUI development. KeyPackage publication keeps a stable replaceable d-tag for the account and tracks the decoded
KeyPackage ref separately; normal publish reuses the cached last-resort package, while explicit rotate creates a new
package under the same slot.

The user directory is keyed by Nostr pubkey. Account setup and the daemon can refresh a local account's contact-list
event, pre-cache direct follows, and cache profile metadata for those likely contacts. Runtime startup builds chunked
directory subscriptions for local accounts and known users so profile, follow-list, relay-list, and KeyPackage updates
keep warming the cache. The crate also exposes bounded radius search over cached follow edges for future TUI/mobile
pickers. That search is intentionally cache-backed and bounded; it is not a crawler for the whole Nostr social graph.

Group creation and invites still take pubkeys at the action boundary. If a member's KeyPackage is not already cached but
the directory knows where their KeyPackages are published, the app fetches the latest package before building the MLS
add. New Nostr-routed groups generate `marmot.transport.nostr.routing.v1` at creation, store the component bytes in
signed MLS app data, and project the decoded `nostr_group_id` plus relay list into group subscriptions and publish
targets.

Incoming welcomes are automatically joined at the MLS/session layer, then projected as pending local chats. Clients can
render accept/decline UI from the group record: accept clears `pending_confirmation`; decline publishes a leave, clears
the pending flag, and archives the local projection so normal chat lists hide it.

`MarmotAppRuntime` owns restored signing accounts, a shared relay plane, live account workers, runtime event hubs, and
the shared agent stream watch manager. The relay plane now also owns shared directory discovery fetches for relay lists,
profiles, follow lists, and KeyPackages, including endpoint safety and in-flight coalescing. Explicit catch-up remains
available for repair and tests, but the daemon path is runtime-owned subscriptions plus typed events.

The crate root now keeps app construction, shared state, storage/projector wiring, directory bootstrap, account relay
list helpers, and public re-exports. Runtime orchestration lives in `src/runtime.rs`, app-client commands and queries
live in `src/client.rs`, group DTOs/component projection helpers live in `src/groups.rs`, and encrypted-media DTOs plus
Blossom upload/download helpers live in `src/media.rs`.
