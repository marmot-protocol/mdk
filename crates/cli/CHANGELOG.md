# Changelog

All notable changes to `darkmatter-cli` are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [Unreleased]

### Added

- The TUI now renders kind-1210 group system rows as friendly lines (e.g. "alice added bob", "bob left",
  "alice renamed the group") instead of raw JSON. These durable rows are synthesized locally from authenticated group
  state changes (member added/removed/left, admin granted/revoked, group renamed, avatar changed) and appear inline in
  message and timeline history.

- Added `dm relay-stats`, which prints the device-local relay performance telemetry (aggregate lifecycle counters,
  cross-relay arrival spread, per-relay first-deliverer and first-event/EOSE timing, and redacted relay health). The
  command runs against the live `dmd` runtime when a daemon socket exists. Output is aggregate-only and uses opaque
  device-local relay indices — never relay URLs.
- Added Whitenoise-shaped identity and plural command entrypoints: `dm create-identity`, `dm login`, `dm whoami`,
  `dm accounts`, and `dm groups`.
- Added the remaining Whitenoise-shaped top-level command names (`debug`, `logout`, `export-nsec`, `media`,
  `follows`, `profile`, `relays`, `settings`, `users`, `notifications`, and `reset`) with real local behavior where
  the app runtime supports it and explicit `unsupported_command` errors where lower-layer behavior does not exist yet.
- Added `dm chats subscribe`, `dm chats subscribe-archived`, and `dm groups subscribe-state`, which stream typed
  daemon responses for chat rows and group state.
- Added `dm messages search` and `dm messages search-all` over local projected message history.
- Added Whitenoise-shaped cursor flags for `dm messages list`: `--before`, `--before-message-id`, `--after`, and
  `--after-message-id`.
- Added real `dm groups leave` support over the Marmot SelfRemove path, including app-runtime SelfRemove capability
  advertisement.
- Added real `dm groups promote`, `dm groups demote`, and `dm groups self-demote` support over the Marmot admin-policy
  app component.
- Added typed app-message payloads for `dm messages react`, `dm messages unreact`, `dm messages delete`, and
  `dm messages retry` group-convergence retries. Message projections and `messages subscribe` now expose typed
  `app_message` metadata for reactions, deletions, and media references.
- Added `dm media list <group>`, which lists typed media references already projected from group message history.
- Added `dm media upload` and `dm media download` over `encrypted-media-v1` media and Blossom, using
  `https://blossom.primal.net` as the default upload server.
- Added `dm messages subscribe <group>`, a daemon-backed newline-delimited stream that emits typed `message`,
  `agent_stream_start`, `agent_stream_final`, `agent_stream_delta`, and `stream_preview` updates, including live
  brokered QUIC text chunks from runtime-owned stream watch state.
- Added `dm stream watch --background`, which starts a brokered QUIC stream watch through `dmd` and reports
  runtime-managed running/completed/failed preview state through `dm daemon status --json`.
- Added redacted relay-plane health to `dm daemon status --json`.
- Added `dmd --default-account-relays`, matching `wnd` setup flags and applying daemon account-relay defaults to
  daemon-forwarded account creation.
- Added TUI `/stream` slash commands for starting, watching, finishing, verifying, and inspecting brokered agent text
  stream previews from the selected chat.
- Added a TUI status panel below the composer with the latest status line, selected-chat MLS epoch/group/member state,
  and raw app-component data from `dm groups show --json`.
- Added `dm stream start`, `dm stream finish`, and `dm stream verify` for anchoring agent text
  stream starts/finals through normal encrypted Marmot messages and checking QUIC transcript hashes.
- Added `dm stream watch` and `dm stream send --broker` for brokered QUIC preview streams anchored by the
  durable start message.
- Added `dm stream receive` and `dm stream send` for provisional raw QUIC agent text stream previews.
- Added `dm keys rotate` as an explicit repair command that force-mints and publishes a fresh replacement KeyPackage.
- Added TUI unread badges for chats that receive messages while another chat is selected.
- Added a TUI slash-command suggestion popup that opens on `/` and filters as the composer input narrows.
- Added a scrollable TUI messages panel: Tab to the Messages focus and use Up/Down or `j`/`k` to scroll, plus
  PageUp/PageDown and Home/End from any focus. New messages stay pinned to the bottom unless you have scrolled up.

### Fixed

- `dm messages list` now validates its pagination cursor flags instead of silently mishandling them. Previously,
  `--before-message-id`/`--after-message-id` were ignored unless the matching `--before`/`--after` timestamp was also
  supplied, and any lone cursor flag combined with `--limit` returned the oldest N messages instead of the newest.
  Supplying a message-id cursor without its timestamp (or vice versa), or combining `--before*` with `--after*`, now
  returns a clear error (`message_pagination_cursor_mismatch` / `message_pagination_conflicting_cursors`), matching the
  `dm messages timeline list` behavior.
- Fixed TUI live message subscription gating so highlighted-chat navigation cannot append another chat's incoming
  messages into the loaded conversation or count the visible chat as unread.
- The TUI composer now accepts a leading `?` instead of swallowing it to toggle help. Previously, typing or pasting a
  message that started with `?` into an empty composer toggled the help panel and dropped the character, making it
  impossible to compose such messages. The `?` help shortcut now applies only when the composer is not focused; the
  `/help` and `/?` slash spellings remain available.
- The TUI no longer exits the whole session when an error occurs while a stream composer is active. Failures from
  finishing or cancelling a stream (daemon gone, broker/QUIC error, relay publish rejection) are now caught into the
  status line — mirroring the non-streaming Enter path — so the composer stays open and the user can retry Enter/Esc.
- TUI stream compose now pins the live preview to the group the stream was opened on instead of the
  currently-selected chat. Previously, if a background subscription tick shifted the chat selection while streaming
  (e.g. the streamed-into chat was archived or removed by another member/device), each keystroke upserted the streamed
  text under the wrong group and finishing/cancelling left a permanent ghost "streaming" row under the original group.
- `dm profile update` no longer wipes the rest of your published Nostr profile. It previously published a fresh kind-0
  metadata event built only from the flags you passed, so e.g. `dm profile update --picture URL` erased
  name/display_name/about/nip05/lud16, and `dm profile update` with no flags published an empty profile that wiped
  everything. It now fetches your current published profile from the selected relay, overlays only the provided
  fields, and publishes the merged result. A no-flags invocation is rejected with `empty_profile_update`, and when the
  selected relay holds no current profile event the command refuses with `profile_update_inconclusive` (retry with a
  `--relay` that has your current profile) instead of clobbering it.
- `dmd` no longer exits when a single client connection is abrupt, empty, oversized, malformed, or stalled.
  Per-connection read failures (a client that closes before sending, a mid-write interrupt, a request over the 1 MiB
  cap, or invalid JSON) are now reported to that client and skipped like authorization failures, instead of propagating
  out of the accept loop and killing the daemon (which left a stale socket and pid file). The accept loop also bounds
  how long it waits for a client to send its request frame, so a same-UID client that connects but never sends data can
  no longer wedge the loop and starve other clients. `dm` rejects oversized requests client-side before sending — even
  on the default implicit daemon socket — so e.g. `dm messages send` with a body over the limit fails locally with a
  clear size-limit error instead of silently falling back to local execution or reaching the daemon.

### Security

- Redacted TUI `/login` `nsec` composer input when users type leading whitespace, repeated whitespace, or tabs before
  submitting the import.
- Hardened `dmd` IPC by making daemon-owned socket directories `0700`, daemon sockets `0600`, requiring same-UID
  peers, bounding request size, and refusing `reset`/`logout` execution through the daemon socket.
- Encrypted-media uploads and downloads no longer act on loopback-HTTP blob endpoints (e.g. `http://127.0.0.1:PORT`)
  unless `DM_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1` is set for local development. Such endpoints stay valid group state, but
  a production install treats them as unusable instead of issuing requests at the local host on behalf of a remote
  group admin.

### Changed

- Aligned the experimental `dm stream` QUIC preview transport with the merged spec (pre-interop breaking change):
  broker connections now negotiate ALPN `marmot.quic_broker.v1` and send a binary broker control envelope instead of
  JSON, the plaintext frame cap is 65519 bytes, transcript hashes use QUIC varint length prefixes, receivers silently
  discard replayed records at or below their seq high-water mark, and brokers serve replay backlog only within a
  configurable `--replay-ttl-secs` window (default 0, cap 300). Old and new `dm`/broker builds do not interoperate.

- Removed the kind `10051` KeyPackage relay list. KeyPackage kind `30443` events now publish to, and are fetched from,
  the account's kind `10002` NIP-65 relays. The `key_package` relay type is no longer accepted by `dm relays`, account
  relay-list status no longer reports a `key_package` list, and account bootstrap only requires the NIP-65 and inbox
  relay lists.
- Added plural `dm messages` command spelling for the message send/list/subscribe surface, matching the daemon-hosted
  runtime subscription model. The older singular `dm message` spelling still works during the transition.
- `dm messages subscribe` can now omit the group argument to stream live updates across all local groups for the
  selected account.
- `dm create-identity` and `dm login --nsec-stdin` now publish the initial local KeyPackage automatically after
  relay-list setup, so the normal invite path does not require a separate `keys publish` repair step.
- `dm keys publish` now republishes the cached initial KeyPackage instead of minting a replacement package during
  normal repair/setup flows.
- Message projections now order history by recorded transport time before local receipt/insertion order, so synced
  stream anchors/finals no longer jump ahead of older chat text merely because they arrived first during catch-up.
- Account list, `whoami`, sync, and message-list JSON now include cached Nostr profile display names where available,
  and the TUI uses those names in account chrome and received-message authors before falling back to npubs.
- `dm groups show --json` now includes selected-group MLS state, and group JSON includes the Nostr routing app
  component alongside the other group components.
- The TUI now tails daemon-backed `messages subscribe` updates for the selected chat, so incoming messages and QUIC
  stream-preview deltas can render without timer-driven message-list refreshes.
- The TUI now tails daemon-backed `chats subscribe` updates for the selected account, so newly processed invites appear
  in the chat list without switching accounts.
- The TUI status panel now tails daemon-backed `groups subscribe-state` updates for the selected chat, so MLS epoch and
  app-component diagnostics refresh after live group evolution events.
- Removed the daemon runtime maintenance timer and the TUI's periodic daemon/account/chat/message refresh paths; runtime
  state now advances from startup, explicit CLI/TUI intents, and subscription events.
- TUI stream compose typing now batches append calls instead of blocking the interface on a daemon round-trip for every
  character.
- TUI stream compose now keeps a daemon-side transcript and treats live QUIC publishing as best-effort, so finishing a
  stream still publishes the full durable final message when the broker is slow or unreachable.
- The TUI uses higher-contrast neutral account labels and green focus accents instead of the low-contrast cyan account
  treatment; daemon controls stay focused on start, status, and stop.
- TUI slash commands now accept quoted multi-word names for `/chat new`, so group names with spaces no longer consume
  the first word after the space as a member pubkey.
- TUI stream compose now defaults to the production QUIC broker candidate at `quic://quic-broker.ipf.dev:4450`, and
  daemon auto-watch paths only request insecure local trust for loopback broker candidates.
- Typed app-message payloads are validated before publish/projection; malformed reaction, media, delete, or retry
  envelopes are rejected instead of being treated as valid typed app messages.
- `dm login` and `dm account create` now reject positional `nsec` values; private-key imports must use
  `--nsec-stdin`, and the TUI pipes `/login <nsec>` to the child `dm` process over stdin instead of argv.
- `dmd` now keeps long-lived per-account relay subscriptions for real WebSocket relays instead of rebuilding
  subscriptions through periodic rebuild loops.
- `dm daemon status --json` now reports `last_runtime_activity` instead of `last_sync`, matching the runtime-owned
  subscription model.
- Nostr SDK relay connect and publish calls are now bounded by timeouts so first-run account setup fails with JSON
  instead of hanging indefinitely when a local relay does not ACK publishes.
- `dm create-identity` and `dm login --nsec-stdin` publish the required NIP-65 and inbox relay lists, plus the initial
  KeyPackage event, for new local signing identities from daemon account-relay defaults when relay-list flags are
  omitted; `dm login --nsec-stdin --relay <url>` remains the command-local import fallback.
- Newly created local identities now publish matching Nostr `name` and `display_name` values using two-word pseudonyms
  instead of account-id-derived Marmot labels.
- Imported `nsec` accounts now require `--publish-missing-relay-lists` before publishing missing required relay
  lists discovered from bootstrap relays.
- Removed the file-backed local transport and Marmot Lab crate; local tests now use Nostr SDK mock relays and
  product flows require relay-backed setup.
- Moved the CLI crate source directory from `crates/dm` to `crates/cli`. The Cargo package remains
  `darkmatter-cli`, and the installed binaries remain `dm` and `dmd`.

## [0.1.0] - 2026-05-17

Initial release of the `dm` command-line app, the `dmd` background daemon, and the Ratatui TUI.

### Added

- `dm` account commands for creating local signing accounts, adding public-only accounts, listing local
  accounts, inspecting account status, and checking relay-list readiness.
- `dm keys` commands for publishing the selected account's KeyPackage and fetching another account's latest
  KeyPackage from bootstrap relays.
- `dm group`, `dm chats`, `dm message`, and `dm sync` commands for creating encrypted groups, managing members,
  sending/listing messages, archiving chat projections, and processing relay events for a local account.
- Stable `--json` response envelopes for scripts, daemon forwarding, and TUI integration.
- `dmd` daemon support for socket-backed command execution, pid/log files, daemon status reporting, background
  sync, and app-level Nostr user-directory warming.
- `dm tui`, a terminal interface over the real CLI/daemon command surface with account selection, chat
  navigation, message sending, slash commands, daemon controls, account onboarding, and member management.
- Local installation docs for `cargo install --path crates/cli --locked --bins`.
- Homebrew release checklist and namespaced tap packaging path for `marmot-protocol/tap/darkmatter`.

[Unreleased]: https://github.com/marmot-protocol/darkmatter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/marmot-protocol/darkmatter/releases/tag/v0.1.0
