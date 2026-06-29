# Changelog

All notable changes to `darkmatter-cli` are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [Unreleased]

### Security

- Daemon auto-watch of inbound agent stream starts (kind:1200) no longer derives no-cert-verification
  (`insecure_local`) trust from the sender-controlled `quic://` candidate, and QUIC candidate resolution now rejects
  sender-provided candidates that resolve to loopback, RFC1918/private, link-local (including `169.254.169.254`),
  multicast, unspecified, broadcast, IPv6 unique-local (ULA), or IPv6 unicast link-local endpoints. Local endpoints are
  only reachable when the local user explicitly passes `--insecure-local` (SSRF + trust downgrade hardening).

## [0.2.0] - 2026-06-21

### Added

- Added the `dm-agent` local connector daemon with `serve` and `bootstrap --qr`, bridging Marmot encrypted groups to
  agent gateways through the `marmot.agent-control.v1` Unix-socket NDJSON protocol.
- Added the Hermes Marmot platform plugin (`integrations/hermes/marmot`) and `install-hermes-marmot.sh` for downloading
  versioned `dm-agent` binaries plus the plugin from `dm-agent-v*` GitHub Releases.
- Added the OpenClaw Marmot channel plugin (`integrations/openclaw/marmot`) and `install-openclaw-marmot.sh` for the
  same release cohort; supports durable sends, live QUIC preview streaming, inbound media, reactions, deletes, ambient
  messages, and NIP-27 mention routing through OpenClaw agent tools.
- Added a versioned DM Agent release track (`dm-agent-v<version>`) publishing `dm-agent` for linux-x86_64,
  linux-aarch64, darwin-aarch64, and darwin-x86_64, Hermes and OpenClaw plugin bundles, and pinned installer scripts.
- UniFFI: added `reveal_nsec` to export the selected account private key as `nsec1` bech32 for in-app key backup.
- UniFFI: added NIP-49 encrypted private-key export for password-wrapped backup.
- UniFFI: added per-account `unread_count` without loading a full app session.
- UniFFI: added `retry_group_convergence` for non-duplicating group repair resends.
- Added app-side per-group recovery for hydration-quarantined groups.
- Added engine `sign_out_and_wipe` for full local and remote account teardown, and non-destructive `sign_out` with
  optional relay KeyPackage cleanup.
- Added rich reaction notifications scoped to the reacted-to message author.

- Added `--data-dir` to `dm daemon start` (an alias for `--home`), completing `wnd`/`dmd` setup-flag parity
  alongside the existing `--logs-dir`, `--discovery-relays`, and `--default-account-relays`. The resolved home is
  forwarded to the spawned `dmd` child as before; `--home` still takes precedence when both are given.

- Added `dm groups set-avatar-url <group> --url <https-url> [--dim WxH] [--thumbhash <hex>]` (and `--clear`) to set,
  update, and clear the group URL avatar (`marmot.group.avatar-url.v1`) over the existing app runtime path; a parallel
  legacy `dm group set-avatar-url` form is also available. `dm groups show` / `dm chats show` now surface the
  `avatar_url` component in both human and `--json` output, and an invalid (non-HTTPS / disallowed-host) URL returns
  the stable `invalid_group_avatar_url` JSON error. `set-avatar-url` now requires exactly one of `--url` / `--clear`
  (`--dim` / `--thumbhash` only accompany `--url`), and an explicit empty `--url ""` is rejected as
  `invalid_group_avatar_url` rather than silently clearing the avatar. Human `show` output also surfaces
  `avatar_dim` / `avatar_thumbhash` render hints when present.

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

- CLI and daemon command JSON builders now return the existing `invalid_public_key` error instead of panicking if a
  stored account id cannot be converted to `npub`.

- `dm --help`, `dm <subcommand> --help`, and `dm --version` now print to stdout instead of stderr (exit code 0 was
  already correct). Previously every clap parse result — including the help/version display "errors" that carry exit
  code 0 — was routed to stderr, leaving stdout empty and breaking shell piping and scripts (e.g. `dm --help | less`).
  With `--json`, help/version are now reported as `{"ok": true, "result": {"help"|"version": "..."}}` rather than being
  wrapped as an error object; genuine usage errors still go to stderr (and `ok: false` in JSON mode). Routing is gated
  on clap's exit code, not just the error kind: a missing required subcommand (e.g. `dm messages` with no subcommand)
  renders help text but exits nonzero, so it stays a usage error on stderr / `ok: false` instead of being reported as
  successful help output.
- The distributed-convergence canonicalization apply path now persists its multi-write merge atomically. The
  `merge_staged_commit` replay, Marmot group-record refresh, and message-disposition writes that run when a stored
  out-of-order commit is replayed are wrapped in a single SQLite transaction, closing the residual torn-write window
  left after #157/#421 (which only covered the live state-transition paths). A crash mid-merge now rolls back to the
  prior consistent epoch instead of stranding torn group state and an orphaned apply snapshot.
- OpenMLS group state transitions are now persisted atomically. The multi-write commit-merge path (engine state,
  pending-commit cleanup, and OpenMLS value-store updates) is wrapped in a single SQLite transaction, so a crash or
  interruption mid-merge can no longer leave torn group state on disk; the device either advances to the new epoch
  fully or rolls back to the prior consistent state on next load.
- `dmd` now moves peer authorization and request-frame reads onto per-connection tasks immediately after accept, so a
  client that writes a partial frame and stalls can only stall itself; other clients can still reach Ping, Status, and
  Shutdown without waiting for the stalled request timeout.
- `dmd` now handles daemon-forwarded Execute and subscription setup work on spawned connection tasks instead of awaiting
  worker-mutating requests in the single accept loop. `dm daemon status` and `dm daemon stop` remain responsive while a
  long Execute owns daemon worker state; status falls back to a best-effort worker snapshot when that state is busy.
- `dm stream receive`, unanchored `dm stream send`, and foreground `dm stream watch` now stay client-hosted when a
  daemon socket is configured, and direct daemon Execute requests for those long-running stream commands return
  `daemon_forbidden` instead of blocking `dmd`'s accept loop.
- `dm logout` now stays client-hosted when `dmd` is only auto-discovered from the default socket, so signing out works
  while the daemon is running; explicitly socket-targeted logout requests still fail instead of mutating account state
  inside `dmd`.
- Auto-discovered daemon command forwarding now falls back to local execution only when the client cannot connect to
  `dmd`. If the daemon accepts a command but closes or returns malformed/no output before responding, `dm --json` now
  reports `daemon_state_unknown` instead of silently re-running the command locally.
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
- dm-agent: hardened group-system id deduplication and `send_final` idempotency keys.
- marmot-app: retry distributed convergence after admin promote.
- Engine: tightened MLS proposal ordering and member departure handling.
- agent-connector: replay lagged ambient inbound events after subscription reconnect.
- marmot-account: keep exposed group evolution commits instead of rolling them back after publish.
- Hermes Marmot adapter: select the local-signing account, clamp stream chunks to the policy cap, per-conversation inbound
  concurrency, `send_final` idempotency with bounded retry, rename dead `stream_tool` client method to
  `stream_progress`, and align transcript seed lengths with QUIC varint framing.
- OpenClaw Marmot plugin: filter QUIC candidates to `quic://`, accept singular `MARMOT_QUIC_CANDIDATE`, guard concurrent
  live-preview `ensureBegun`, allowlist outbound media paths, preserve debounced inbound media and signals, cancel
  in-flight live preview begins, and cache per-group `is_direct` with fail-closed lookup errors.
- OpenClaw/Hermes connector parity: mentions via NIP-27 `p` tags, media upload/download, deletes, and ambient inbound
  routing aligned across both adapters.
- marmot-account: confirm relay-accepted auto-publishes instead of rolling back on publish shortfall.
- marmot-app: schedule group convergence retries correctly; serve account-worker reads after hydration, not after catch-up.
- storage-sqlite: retry `SQLITE_BUSY` and classify transient lock contention.
- transport-nostr-adapter: normalization-safe relay URL routing matches.
- CLI: strip invisible and terminal format-spoofing control characters from safe terminal output.
- App messages now attach Nostr expiration metadata where the group retention policy requires it.
- marmot-app: fail over encrypted-media uploads across Blossom endpoints.
- marmot-account: tolerate corrupt account records; reject Windows drive-relative account labels.
- UniFFI: normalize group-id hex in `messages()` and `subscribe_messages()`; bound message subscription snapshots.
- storage-sqlite: exclude invalidated tombstones from unread counts and chat-list previews; group-scope
  `invalidate_app_event_by_message_id`; disambiguate `epoch_key_pairs_id` key encoding.
- marmot-account: prune orphaned KeyPackage bundles on publish failure.
- Shared host-safety classifiers for URL validation across app components.
- Blossom media download redirect validation.
- Engine: quarantine bad groups during hydration; lone uncommitted proposals no longer block outbound app payloads.
- storage-sqlite: recover from corrupt proposal-queue ref-list blobs and undeserializable `QueuedProposal` entries;
  incrementally project new timeline events and prune timeline projections.
- traits: accept query strings on encrypted-media endpoint URLs.
- marmot-app: keep confirmed-but-partial group projections on publish shortfall; avoid rollback after exposed create
  welcome.
- cgka-engine: prune fork recovery snapshots.
- CLI: exponential backoff on failed stream append retries.
- Engine: cache member-validation marker to skip O(groups × members) reverify on open.

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

[Unreleased]: https://github.com/marmot-protocol/darkmatter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/marmot-protocol/darkmatter/releases/tag/v0.2.0
[0.1.0]: https://github.com/marmot-protocol/darkmatter/releases/tag/v0.1.0
