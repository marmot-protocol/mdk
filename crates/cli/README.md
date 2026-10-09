# wn

`wn` is the command-line app for the White Noise/Marmot stack. It manages Nostr-keyed accounts, relay lists,
KeyPackages, chats, groups, messages, media, live runtime subscriptions, and a terminal UI. Use it to drive Marmot from
a shell or script, or interactively with `wn tui`.

The crate (source `crates/cli`, Cargo package `wn-cli`) builds two binaries:

- `wn`: the user-facing CLI and TUI entrypoint.
- `wnd`: the background daemon used by `wn daemon start`.

`wn` uses `marmot-account` for account homes and secret storage, and `marmot-app` for the runtime bridge, transport
setup, group and message projection, and Nostr directory refresh.

## Contents

- [Install](#install)
- [Configuration](#configuration)
- [Quick start](#quick-start)
- [Commands](#commands)
  - [Accounts](#accounts)
  - [KeyPackages](#keypackages)
  - [Chats](#chats)
  - [Groups](#groups)
  - [Messages](#messages)
  - [Media](#media)
  - [Directory, profile, relays, and settings](#directory-profile-relays-and-settings)
  - [Agent text streams](#agent-text-streams)
  - [Sync](#sync)
- [Daemon](#daemon)
- [TUI](#tui)
- [JSON output](#json-output)
- [Packaging](#packaging)
- [Changelog](#changelog)

## Install

Install both binaries from this checkout into your Cargo bin directory, and make sure `~/.cargo/bin` is on `PATH`:

```sh
cargo install --path crates/cli --locked --bins
wn --help
wnd --help
```

To run from a source checkout without installing:

```sh
cargo run -p wn-cli --bin wn -- --help
cargo run -p wn-cli --bin wnd -- --help
```

For isolated development runs, keep the home and secret store explicit:

```sh
export WN_HOME="$(mktemp -d)"
export WN_SECRET_STORE=file
```

The default secret store is the platform keychain. Use `WN_SECRET_STORE=file` only for local development, tests, and
disposable homes.

## Configuration

Global options can be passed as flags or environment variables:

- `--home <path>` or `WN_HOME`: account home, projections, daemon socket, pid, and log.
- `--account <npub-or-hex>` or `WN_ACCOUNT`: selected account for account-scoped commands. `--account` goes before the
  subcommand (`wn --account <npub> chats list`).
- `--socket <path>` or `WN_SOCKET`: daemon socket. The default is `$WN_HOME/dev/wnd.sock`.
- `--secret-store keychain|file` or `WN_SECRET_STORE`: signing-key backend.
- `--keychain-service <name>` or `WN_KEYCHAIN_SERVICE`: keychain service name.
- `--json`: return a stable JSON envelope for scripts, the TUI, and daemon forwarding.
- `WN_RELAY`: fallback relay URL for commands that need one when no relay flag is given (the TUI also uses it to
  auto-start the daemon).

Without `WN_HOME`, the home is the platform user data directory:

- macOS: `~/Library/Application Support/whitenoise`
- Linux and other non-macOS Unix: `$XDG_DATA_HOME/whitenoise`, or `~/.local/share/whitenoise`
- Windows: `%APPDATA%\whitenoise`

Loopback endpoints are refused by default; production installs leave these unset:

- `WN_ALLOW_LOOPBACK_RELAYS=1` lets `wn`/`wnd` open sockets to a `ws://127.0.0.1`-style relay (the local Compose
  stack, or an in-process relay). It admits loopback only; private, link-local, and CGNAT relay hosts stay rejected. The
  local examples below assume it is exported.
- `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1` lets `wn` upload to and download from `http://127.0.0.1`-style Blossom
  endpoints.

Most account-scoped commands resolve the account in this order:

1. `--account <npub-or-hex>`
2. `WN_ACCOUNT`
3. the only account, when exactly one exists. A public-only account is still selected here; commands that require
   signing then fail with an explicit error.

## Quick start

Create two local signing identities, create a chat as Alice, and let Bob receive it through the daemon. The examples use
the repo-owned `dev/data` tree so local state is easy to inspect and delete:

```sh
just relay-up

export WN_HOME="$PWD/dev/data/quickstart"
export WN_SECRET_STORE=file
export WN_ALLOW_LOOPBACK_RELAYS=1   # loopback relays are dev/test only; unset in production
unset WN_SOCKET
rm -rf "$WN_HOME"

wn daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777

wn create-identity
printf '%s\n' "$BOB_NSEC" | wn login --nsec-stdin
wn whoami

wn --account <alice-npub-or-hex> groups create general <bob-npub-or-hex>
wn --account <alice-npub-or-hex> messages send <group-hex> "hello bob"

wn --account <bob-npub-or-hex> chats list
wn --account <bob-npub-or-hex> messages list <group-hex> --limit 20
```

The local Compose stack also exposes `ws://127.0.0.1:28080`, but the examples prefer `27777` because it reliably ACKs
the relay-list publishes used during first-run account setup on current macOS Docker Desktop.

## Commands

Run `wn <command> --help` for the full flag list of any command. Older singular `account`, `group`, and `message`
spellings remain as hidden compatibility aliases; new scripts should use the plural forms shown here.

### Accounts

```sh
wn create-identity
printf '%s\n' "$NSEC" | wn login --nsec-stdin
printf '%s\n' "$NSEC" | wn login --nsec-stdin --relay <relay-url>
wn login <npub-or-hex>
wn whoami
wn logout <npub-or-hex>
wn export-nsec <npub-or-hex>
wn accounts list
wn accounts status [npub-or-hex]
wn accounts relay-lists [npub-or-hex] --bootstrap-relays <relay-url>
wn reset --confirm
```

- When a daemon is running, `create-identity` and `login --nsec-stdin` use the daemon's account-relay defaults to
  publish the required relay lists and an initial KeyPackage. `login --nsec-stdin --relay <url>` is the command-local
  fallback for a custom relay-list publish during import.
- `wn login <npub-or-hex>` adds a public-only identity. It only checks relay-list availability, and is useful for
  relay-list and KeyPackage lookup, but cannot sign, publish KeyPackages, sync groups, or send messages.
- `wn logout` is destructive: it removes that account's local data (messages, group membership, and MLS state) from this
  device, and for a local-signing account deletes the signing key too.
- `export-nsec` exists for command-shape compatibility but returns `private_key_export_disabled`; this CLI never prints
  private keys.
- `accounts create` is kept as a compatibility/repair surface; new setup flows should use `create-identity` or `login`.
- `reset --confirm` deletes all local White Noise CLI data.

### KeyPackages

```sh
wn --account <npub-or-hex> keys list
wn --account <npub-or-hex> keys publish
wn --account <npub-or-hex> keys maintenance-status
wn --account <npub-or-hex> keys rotate
wn keys fetch <npub-or-hex> --bootstrap-relays <relay-url>
wn keys check <npub-or-hex>
wn --account <npub-or-hex> keys delete <event-id>
wn --account <npub-or-hex> keys delete-all --confirm
```

- `keys publish` initializes or retries the durable KeyPackage lifecycle and publishes a fresh replacement under the
  account-device's stable kind-30443 `d` slot. Once an exact event has been signed, every retry reuses it.
- `keys rotate` (alias `force-publish`) explicitly starts the same replacement when none is already pending. Routine
  replacement does not publish a kind-5 deletion.
- `keys maintenance-status` shows the persisted slot, lifetime, refresh, replacement, retry, and
  retained-private-material state.
- `keys list` returns the current winner per addressable slot (plus local-only rows).
- `keys delete` and `keys delete-all` are explicit teardown/legacy-cleanup tools. `keys delete` publishes a Nostr
  deletion for one event id; pass a superseded event id to retire it without deleting the current slot winner.
  `keys delete-all --confirm` publishes deletions for every observed relay KeyPackage event in the validated fetch
  window, including superseded same-slot events.

### Chats

```sh
wn --account <npub-or-hex> chats list
wn --account <npub-or-hex> chats list --include-archived
wn --account <npub-or-hex> chats list-archived
wn --account <npub-or-hex> chats show <group-hex>
wn --account <npub-or-hex> chats subscribe
wn --account <npub-or-hex> chats subscribe-archived
wn --account <npub-or-hex> chats archive <group-hex>
wn --account <npub-or-hex> chats unarchive <group-hex>
wn --account <npub-or-hex> chats mute <group-hex> 1h
wn --account <npub-or-hex> chats mute <group-hex> forever
wn --account <npub-or-hex> chats unmute <group-hex>
wn --account <npub-or-hex> chats mark-read <group-hex> [<message-id-hex>]
```

Chat rows (`chats list`, `list-archived`, and the `subscribe`/`subscribe-archived` feeds) carry the group record plus a
per-chat projection, so a chat list can render unread badges and a preview without a second query:

- `unread_count` (number) and `has_unread` (bool);
- `last_message`: `{ message_id_hex, sender, sender_display_name, plaintext, kind, timeline_at, deleted }`, or `null`;
- `last_read_message_id_hex` / `last_read_timeline_at` (either may be `null`).

These use the same names and `last_message` shape as the `chat_list_row` object on the `messages timeline subscribe`
feed. A chat with no messages or reads reports `0` / `false` / `null` rather than omitting the keys.

The `chats subscribe` feeds emit only on group-state changes (create, rename, archive/unarchive, membership), not on
every message or read, so their projection keys are a snapshot from the last group-state emit. Live unread and
last-message deltas ride the `messages timeline subscribe` feed's `chat_list_row` instead.

`chats mark-read <group-hex> [<message-id-hex>]` advances the read marker and clears the unread count. With no message id
it marks the newest message read; with one it marks read up to that message. The marker is a forward-only high-water
mark: marking an older message leaves newer ones unread and never moves it backward. An empty chat, or a message id that
is not a kind-9 chat message in this chat, leaves the marker untouched and returns success with the current projection
(the same silent contract as `messages react`/`delete` with unknown ids). The response has `account_id`, `npub`,
`group_id`, and the five projection keys above.

`chats mute` and `chats unmute` control local per-chat notification suppression; durations accept `s`, `m`, `h`, `d`,
or `w` suffixes, plus `forever`. A muted chat stays quiet for ordinary messages, but a direct mention of the
receiving account remains eligible for notification; blocked senders stay suppressed.

### Groups

Invitation failures in `--json` responses include `account_id` and a typed `code`. `obsolete_key_package` asks the recipient to update and publish a current KeyPackage; `member_discovery_incomplete` is retryable and means the searched relay coverage was incomplete. The `repair.action` field supplies the corresponding next step.

```sh
wn --account <npub-or-hex> groups list
wn --account <npub-or-hex> groups create <name> [member-npub-or-hex ...] [--description <description>]
wn --account <npub-or-hex> groups create <name> [member ...] --retention 1d [--image <path> [--image-media-type <mime>]]
wn --account <npub-or-hex> groups show <group-hex>
wn --account <npub-or-hex> groups add-members <group-hex> <member-npub-or-hex> [...] [--admin <member-npub-or-hex>]
wn --account <npub-or-hex> groups remove-members <group-hex> <member-npub-or-hex> [...]
wn --account <npub-or-hex> groups members <group-hex>
wn --account <npub-or-hex> groups admins <group-hex>
wn --account <npub-or-hex> groups relays <group-hex>
wn --account <npub-or-hex> groups invites
wn --account <npub-or-hex> groups accept <group-hex>
wn --account <npub-or-hex> groups decline <group-hex>
wn --account <npub-or-hex> groups leave <group-hex>
wn --account <npub-or-hex> groups rename <group-hex> <name>
wn --account <npub-or-hex> groups update <group-hex> [--name <name>] [--description <description>]
wn --account <npub-or-hex> groups set-avatar-url <group-hex> --url <https-url> [--dim <WxH>] [--thumbhash <hex>]
wn --account <npub-or-hex> groups set-avatar-url <group-hex> --clear
wn --account <npub-or-hex> groups set-image <group-hex> <image-path> [--media-type <mime>]
wn --account <npub-or-hex> groups clear-image <group-hex>
wn --account <npub-or-hex> groups download-image <group-hex> [--output <path>]
wn --account <npub-or-hex> groups retention <group-hex> [--set 1d|0]
wn --account <npub-or-hex> groups promote <group-hex> <member-npub-or-hex>
wn --account <npub-or-hex> groups demote <group-hex> <member-npub-or-hex>
wn --account <npub-or-hex> groups self-demote <group-hex>
wn --account <npub-or-hex> groups management <group-hex>
wn --account <npub-or-hex> groups enable-disbanding <group-hex>
wn --account <npub-or-hex> groups disband <group-hex> --confirm
wn --account <npub-or-hex> groups disband-status <group-hex>
wn --account <npub-or-hex> groups acknowledge-disband-failure <group-hex>
wn --account <npub-or-hex> groups recovery-status <group-hex>
wn --account <npub-or-hex> groups confirm-rejoin <welcome-id-hex> --local-state-token <hex> --confirm
wn --account <npub-or-hex> groups decline-rejoin <welcome-id-hex>
wn --account <npub-or-hex> groups quarantined
wn --account <npub-or-hex> groups retry-hydrate <group-hex>
wn --account <npub-or-hex> groups delete-local <group-hex> --confirm
wn --account <npub-or-hex> groups pending-welcomes
wn --account <npub-or-hex> groups redeliver-welcome <message-id-hex>
wn --account <npub-or-hex> groups maintenance-status <group-hex>
wn --account <npub-or-hex> groups schedule-self-update <group-hex>
wn --account <npub-or-hex> groups maintenance-policy [--set enabled|disabled]
wn --account <npub-or-hex> groups pause-maintenance
wn --account <npub-or-hex> groups resume-maintenance
wn --account <npub-or-hex> groups run-maintenance
wn --account <npub-or-hex> groups subscribe-state <group-hex>
```

The hidden legacy `group` namespace keeps `create`, `members`, `invite` (with `--admin`), `remove`, `update`, and
`set-avatar-url` working.

**Group identifiers.** Every `<group-hex>` is the canonical MLS group id (`group_id` in JSON; opaque bytes, 16 bytes for
OpenMLS-created groups). It is not the 32-byte Nostr routing handle shown under `nostr_routing.nostr_group_id_hex`,
which is transport state the group can rotate. Filters, lookups, and JSON always key on the MLS group id.

**Publication versus durable completion.** `published` and `message_ids` on a mutation result mean the relay accepted
the events this device sent. They do not prove that any other member has processed them. Outcomes that finish later
are queryable after the command returns and after a restart: `groups disband-status`, `groups recovery-status`,
`groups pending-welcomes`, and `groups maintenance-status`.

**Invites.** `groups invites` lists groups still awaiting local confirmation. `groups accept` clears that pending state;
`groups decline` leaves and archives the auto-joined pending group.

**Names and admins.** `groups update` is the canonical spelling for name and/or description changes; `groups rename`
and legacy `group update` keep working. `groups add-members ... --admin <member>` (and legacy `group invite --admin`)
grants admin to an invitee inside the same invite commit. An `--admin` that is not one of the invitees fails with
`initial_admin_not_invited` before anything is published. Invite results carry an `initial_admins` list.
`groups management` mirrors the MarmotKit management state (`is_self_admin`, `can_invite`, `can_leave`,
`requires_self_demote_before_leave`, `can_enable_disbanding`, `can_disband`, `disbanding_blockers`, per-member
`member_actions`) from one runtime read.

**Retention.** `groups retention <group-hex>` shows the disappearing-message policy (`disappearing_message_secs`,
`enabled`, and the full `message_retention` component). `--set <duration>` publishes a component update: a bare integer
is seconds, `s`/`m`/`h`/`d`/`w` suffixes scale a positive integer, and `0` or `off` disables retention. `groups create
--retention <duration>` puts the policy in the founding commit instead of a second commit. Only admins may change the
policy (`not_group_admin`). A message keeps the policy of the epoch that delivered it: `messages list` rows carry a
`retention` object (`retention_seconds`, `expires_at`, or `null` for legacy rows) and timeline rows carry
`retention_seconds` / `retention_expires_at`, so changing the policy never re-labels older messages.

**Maintenance.** Newly created or joined groups follow the persisted periodic-maintenance policy, which defaults to
enabled. Pre-rollout groups are not automatically enrolled; `groups schedule-self-update` schedules one rotation without
changing their enrollment. Pause/resume is process-local: it stops new preparation while preserving durable obligations
and already-prepared publication recovery. Application-message JSON results include `maintenance_disposition` (`ready`
or `post_join_rotation_pending_retryable`); a pending post-join rotation does not block the send.

**Disbanding.**

- `groups enable-disbanding` installs and requires lifecycle-v1 in one admin commit. It is idempotent (`published=0`
  when already required), and `disbanding_unsupported_members` lists leaves that do not advertise it yet.
- `groups disband --confirm` durably records the irreversible request and returns `disband_request` plus a one-word
  `state`. The terminal commit is prepared by the runtime's convergence pass (a running `wnd`, or
  `messages retry <group-hex>` from a one-shot `wn`), so a returned request is never proof that the group has ended or
  that any member observed it.
- `groups disband-status` reports `state` as one of `not_enabled`, `enabled`, `pending` (durable local request awaiting
  its terminal commit), `converging` (an authenticated inbound disband is settling), `failed` (see
  `disband_request.failed.reason`, then clear it with `groups acknowledge-disband-failure`), the terminal `disbanded`,
  or `unknown` (no positive signal and the MLS state could not be read, as for a quarantined, terminal, or removed copy;
  `not_enabled` is only asserted from a successful MLS read). It also reports `lifecycle_state`, `disbanding` (ordinary
  outbound work is gated), `disbanded`, `unrecoverable`, and `self_membership` (`member`, `left`, or `removed`).
- Ordinary sends into a disbanding group fail with `group_disbanding`. A removed member's copy records its own removal
  (`self_membership: removed`) when the terminal commit lands; read both fields rather than inferring the end from one.

**Recovery and rejoin.** Consent is branch-bound. `groups recovery-status` returns the durable snapshot
(`automatic_recovery_failed`, `pending_reinvites`, `failed_reinvites`, and `rejoin_invitations` with each offer's
`welcome_id_hex`, authenticated `welcomer_account_id_hex`, `epoch`, and `local_state_token`). `groups confirm-rejoin`
needs the exact offer id and token from that snapshot plus `--confirm`, because it discards the current local copy;
`groups accept` never stands in for rejoin authorization. `groups quarantined` lists stored groups that failed
hydration with a `reason`, and `groups retry-hydrate` re-attempts one without discarding state (`recovered` is the
engine outcome; an id that is not quarantined is `unknown_group`).

**Local deletion.** `groups delete-local --confirm` deletes only this device's local app data for a group (messages,
timeline, chat row, cached media secrets) without an MLS leave, a disband, or archiving. MLS state stays intact and a
fresh delivery can recreate the chat row. It is refused with `group_disbanding` while a disband is in flight.

**Group images.** `groups set-image` encrypts and uploads a PNG/JPEG/GIF/WebP file and commits the
`marmot.group.blossom-image.v1` component; `groups clear-image` commits the absent state; `groups download-image`
fetches and decrypts the current image (`group_image_absent` when there is none). `groups create --image <path>` adds
a founding image to the create commit. Every surface that renders the image component (these commands, the create
response, `groups show` / `groups list`, `chats` rows, and the daemon `group_state` feed) reports only the redacted
summary (`component_id`, `component`, `present`, `image_hash_hex`, `media_type`) and never prints the image key,
upload secret, nonce, or key-bearing `data_hex`. There is no privileged CLI path for those keys; `groups download-image`
is the supported way to obtain the decrypted image. `set-avatar-url` changes the separate URL-avatar component.

**Welcome delivery.** `groups pending-welcomes` lists Welcomes that a confirmed create/invite could not deliver
(`group_id`, `message_id`, `recipient`, `recorded_at`). Create and invite drain their fanout before returning, so this
is normally empty. `groups redeliver-welcome <message-id-hex>` re-publishes one without re-committing.

### Messages

```sh
wn --account <npub-or-hex> messages send <group-hex> "hello"
wn --account <npub-or-hex> messages send --group <group-hex> "--text that starts with a dash"
wn --account <npub-or-hex> messages send --group <group-hex> --reply-to <message-id> "replying to you"
wn --account <npub-or-hex> messages list
wn --account <npub-or-hex> messages list <group-hex> --limit 20
wn --account <npub-or-hex> messages list <group-hex> --before <unix-seconds> --before-message-id <event-id>
wn --account <npub-or-hex> messages list <group-hex> --after <unix-seconds> --after-message-id <event-id>
wn --account <npub-or-hex> messages list <group-hex> --kind 9 --kind 30100
wn --account <npub-or-hex> messages search <group-hex> <query> --limit 20
wn --account <npub-or-hex> messages search-all <query> --limit 20
wn --account <npub-or-hex> messages react <group-hex> <message-id> +
wn --account <npub-or-hex> messages unreact <group-hex> <message-id>
wn --account <npub-or-hex> messages edit <group-hex> <message-id> "corrected text"
wn --account <npub-or-hex> messages delete <group-hex> <message-id>
wn --account <npub-or-hex> messages retry <group-hex> [event-id]
wn --account <npub-or-hex> messages sweep-expired
wn --account <npub-or-hex> messages send-event <group-hex> <kind> [content]
wn --account <npub-or-hex> messages send-event <group-hex> 30100 '{"cursor":7}' --tag '["e","<event-id-hex>"]'
wn --account <npub-or-hex> messages subscribe <group-hex> --limit 50
wn --account <npub-or-hex> messages subscribe <group-hex> --kind 30100
wn --account <npub-or-hex> messages timeline list <group-hex> --limit 20
wn --account <npub-or-hex> messages timeline search <query> --group <group-hex> --limit 20
wn --account <npub-or-hex> messages timeline subscribe <group-hex>
```

**Replies.** `messages send --reply-to <message-id>` sends the text as a reply, using the same wire format other Marmot
clients produce, so recipients see a reply reference and a hydrated preview of the parent. The parent need not exist
locally; its preview hydrates once it arrives. Pass the group with `--group` and put `--reply-to` before the text: the
message text is parsed hyphen-tolerantly, so a `--reply-to` (or `--reply-to=<id>`) placed after the text would be read
as literal text. The CLI rejects that mis-ordering with `reply_to_after_message_text` instead of sending it. As a
consequence, message text containing a bare `--reply-to` or `--reply-to=<id>` token anywhere (for example
`hello --reply-to friend`) cannot be sent this way.

**Reactions.** `messages react` is idempotent for an already-active reaction and reports `published=0`; the emoji
defaults to `+`. `messages unreact` removes all of the account's active reactions from the target in one deletion
event.

**Edits.** `messages edit <group-hex> <message-id> <text>` publishes a kind-1009 edit whose `e` tag references the
target and whose content is the replacement text (hyphen-tolerant, like `send`). The target must be a locally projected
message authored by the selected account: a foreign target fails with `not_message_author` and an unknown id with
`unknown_message` before anything is published, because recipients only honour edits whose authenticated author matches
the target's. Recipients see the edit as a kind-1009 row in `messages list` and the timeline (`--kind 1009` filters to
edits); hosts resolve the latest text per target from those rows. The response is a send result plus
`target_message_id` and `kind`.

**Deletes.** `messages delete <group-hex> <message-id>` publishes an authenticated kind-5 delete tombstone. Members that
honour it hide the target. It is a group-visible deletion request, not secure erasure, and does not touch relay copies
of the original event.

**Retry.** `messages retry <group-hex> [event-id]` retries durable pending work for the whole group: retained events and
pending commits are republished exactly, and fresh plaintext is never re-encrypted. The optional event id is echoed as
`target_event_id` (`null` when omitted) and does not scope the action; `retry_scope` is always `group_convergence`.

**Retention sweep.** `messages sweep-expired` runs the engine-owned disappearing-message sweep for the selected account
now, on the current wall clock (the engine applies its own clock-skew tolerance, unread deferral, and scan bounds;
there is no flag to supply a time). It returns `now_ms`, total `pruned_messages` / `secrets_deleted`, and a per-group
`groups` array with `status` (`no_expired_messages`, `pruned`, `deferred_clock_skew`, `deferred_unread`,
`deferred_scan_exhausted`, or `failed`), counts, `media_ciphertext_sha256` purge hints, and a privacy-safe
`failure_kind`. A running `wnd` does not schedule this sweep; call it explicitly.

**Custom events.** `messages send-event <group-hex> <kind> [content]` sends an app-defined event. Kind, tags, and content
pass through verbatim into the encrypted group message. Kinds MDK owns (chat, reactions, edits, deletes, agent activity,
agent stream anchors, group system rows, push token records) are rejected with `reserved_app_event_kind`. Each `--tag`
takes a JSON array of strings and is repeatable; a malformed tag fails with `invalid_event_tag`. Custom events project as
standalone rows with their own kind and tags and never fold onto a target message. `messages list` and
`messages subscribe` accept repeatable `--kind <KIND>` filters and return every kind without one. On the subscribe feed
a custom event arrives as type `message`; on the timeline feed its change trigger is `CustomEvent`.

**Timeline.** `messages timeline list|search|subscribe` read the materialized timeline, which interleaves messages,
media, and agent-stream anchors/finals in conversation order. Projected history is ordered by recorded message time
first, then local receipt/insertion order, so synced stream anchors and finals stay in conversation order rather than
relay catch-up order.

**Subscriptions.** `messages subscribe`, `messages timeline subscribe`, `chats subscribe`, `chats subscribe-archived`,
`groups subscribe-state`, and `notifications subscribe` require `wnd`. With `--json` they print newline-delimited
responses with a typed `result.type`:

| `result.type` | Meaning |
| --- | --- |
| `message` | normal app messages and app-defined custom kinds |
| `reaction` | reactions |
| `message_delete` | deletions |
| `media` | media references |
| `agent_stream_start`, `agent_stream_final` | durable agent stream anchors and finals |
| `agent_stream_delta` | live brokered QUIC chunks |
| `stream_preview` | runtime-owned QUIC preview summaries |
| `chat` | chat rows |
| `group_state` | group state rows |

### Media

```sh
wn --account <npub-or-hex> media list <group-hex>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --send --message <caption>
wn --account <npub-or-hex> media upload <group-hex> <first.jpg> <second.jpg> --send --message <caption>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --server https://blossom.divine.video
wn --account <npub-or-hex> media send <group-hex> '<media-json>' ['<media-json>' ...] --message <caption>
wn --account <npub-or-hex> media send <group-hex> <plaintext-sha256>
wn --account <npub-or-hex> media set-endpoints <group-hex> https://blossom.example [https://mirror.example]
wn --account <npub-or-hex> media download <group-hex> <file-hash> --output ./file.jpg
```

**Upload.** `media upload` encrypts each file with the group's current `MLS-Exporter("marmot", "encrypted-media", 32)`
media secret, uploads the ciphertext to Blossom, and with `--send` sends one kind-9 media message whose `imeta` tags keep
the command-line order (`attachment_index` in `media list`). The server must accept opaque `application/octet-stream`
uploads. Without `--server`, the upload targets the ordered endpoints in the group's versioned encrypted-media
component: frozen V1 (`0x8008`) for already-joined legacy groups and V2 (`0x800b`) for current-profile groups. Upload
JSON returns an `attachments` array with each attachment's `plaintext_sha256`, `ciphertext_sha256`, and locators.

**Endpoints.** Newly created groups use MDK's built-in ciphertext-compatible endpoint list unless the application was
compiled with `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS`. Endpoint policy is signed group state, so upgrading MDK changes
defaults for new groups only. An active group admin runs `media set-endpoints <group-hex> <url> [...]`
(`--locator-kind` defaults to `blossom-v1`) to replace a group's default endpoints without changing its media version.
Non-admins get `not_group_admin`; the response carries the refreshed `encrypted_media` component.

**Re-sending.** `media send` publishes already-uploaded references as one ordered message without re-uploading. Each
attachment is either the `media` JSON object from `media upload` / `media list` output, or the plaintext SHA-256 of an
attachment already projected in the group. The runtime re-validates every reference against the group's media profile,
locator policy, and version. A reference can only be re-sent while the group is still in the epoch that encrypted it:
the wire `imeta` tag carries no epoch, and recipients derive the media key from the delivering message's epoch.

- A stale reference is refused before publication with `media_reference_stale_epoch` (`source_epoch`,
  `current_epoch`). Upload the file again after the commit and send the new reference. A plaintext hash resolves to the
  newest projected reference carrying it, so after a re-upload the hash form sends the current-epoch copy.
- The send is pinned to the reference's epoch inside the engine too: an epoch change during the send gives the same
  error, and while the epoch is unsettled (your commit still publishing, or peer commits not yet applied) the send is
  refused with `media_reference_epoch_unsettled` rather than queued. Sync and retry, or upload again if the epoch
  advanced.

**Download.** `media download` resolves a projected media reference by plaintext hash, fetches, verifies, and decrypts
the blob, and writes the plaintext file. `--output` is a file path or an existing directory (which receives the
attachment's own file name); without it the file lands in the current directory. The file is written `0600`; existing
directories keep their permissions, and only directories the download creates are made private.

**File paths.** `media upload`, `media download --output`, `groups set-image`, `groups create --image`, and
`groups download-image --output` resolve relative paths against the directory `wn` was run from, so a command forwarded
to a running `wnd` reads and writes exactly the files the caller named.

### Directory, profile, relays, and settings

```sh
wn --account <npub-or-hex> follows list
wn --account <npub-or-hex> follows add <npub-or-hex>
wn --account <npub-or-hex> follows remove <npub-or-hex>
wn --account <npub-or-hex> follows check <npub-or-hex>
wn --account <npub-or-hex> profile show
wn --account <npub-or-hex> profile update --name <name> --about <text>
wn --account <npub-or-hex> relays list --type nip65
wn --account <npub-or-hex> relays add <relay-url> --type inbox
wn --account <npub-or-hex> relays remove <relay-url> --type inbox
wn users show <npub-or-hex>
wn users search <query> --radius 0..2
wn settings show
wn settings theme dark
wn settings language en
wn notifications subscribe
wn --account <npub-or-hex> debug health
wn debug relay-control-state
wn relay-stats
wn --json usage-diagnostics show
wn usage-diagnostics enable
wn usage-diagnostics disable
```

- `users search` searches your follow graph; `--radius START..END` defaults to `0..1` (0 is you, 1 who you follow, 2
  follows-of-follows).
- `notifications subscribe` streams daemon-backed local notification updates as JSON lines.
- `relay-stats` prints device-local relay telemetry: aggregate lifecycle counters, cross-relay arrival spread,
  per-relay first-deliverer and first-event/EOSE timing, and redacted relay health. It reads the live `wnd` runtime
  when a daemon socket exists. Per-relay rows use opaque device-local indices, never relay URLs.
- `usage-diagnostics show|enable|disable` manages the local combined "Share usage and diagnostics" permission. An active
  `wnd` owns the update. Audit consent is separate. See the
  [host and operator contract](../../docs/marmot-architecture/usage-diagnostics.md) for disclosure, endpoint/key
  configuration, and reporting limitations.

### Agent text streams

Provisional QUIC previews of agent text, anchored by durable Marmot messages:

```sh
marmot-quic-broker --bind 127.0.0.1:4450
wn --account <npub-or-hex> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450
wn --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local
wn --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local --background
wn stream send --broker --connect 127.0.0.1:4450 --insecure-local \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> "hello over quic"
wn stream send --connect <host:port> --server-name <dns-name> "hello over quic"
wn stream receive --bind 127.0.0.1:4450
wn --account <npub-or-hex> stream compose-open <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450 --insecure-local
wn --account <npub-or-hex> stream compose-append --stream-id <stream-hex> "hello "
wn --account <npub-or-hex> stream compose-finish --stream-id <stream-hex>
wn --account <npub-or-hex> stream compose-cancel --stream-id <stream-hex>
wn --account <npub-or-hex> stream finish <group-hex> \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> \
  --transcript-hash <hash-hex> --chunk-count <n> "hello over quic"
wn --account <npub-or-hex> stream verify <group-hex> \
  --stream-id <stream-hex> --transcript-hash <hash-hex> --chunk-count <n>
```

- `stream start` and `stream finish` send typed payloads through the normal encrypted Marmot message path. Brokered
  starts include concrete `quic://host:port` candidates.
- `stream watch` reads the durable start payload, subscribes to the broker candidate, and prints the provisional text
  preview plus transcript hash. With `--background` and a running `wnd`, the daemon owns the subscription and the
  command returns immediately; `wn daemon status --json` reports the running/completed/failed state under
  `stream_watches`, and `messages subscribe` emits it as `stream_preview` updates (individual chunks as
  `agent_stream_delta`).
- `stream send --broker` publishes ordered `TextDelta` records through the memory-only broker. Without `--broker` it
  connects directly to a peer receiver (`wn stream receive`).
- `stream verify` compares a received QUIC transcript hash and chunk count against the latest durable final payload for
  the same stream id.
- `stream compose-open|append|finish|cancel` are the daemon-owned live composer used by the TUI and agent connectors,
  and require `wnd`. Opening publishes the durable stream anchor and starts live preview publication; append feeds
  preview text; finish publishes the durable final message; cancel tears down the session without faking a final.

QUIC chunks are transient preview data; normal Marmot messages remain the durable group history.

**Destination safety.** Explicit `--connect` destinations must be public unicast addresses. `--insecure-local` is the
only exception, and it opens loopback only. A pinned `--server-cert-der-hex` is TLS trust, not address authorization, so
unflagged loopback, private, link-local, and CGNAT targets are rejected; local probes therefore need
`wn stream receive --bind 127.0.0.1:4450` plus `--insecure-local` on send. The client source bind is a family-matched
wildcard (`0.0.0.0:0` / `[::]:0`) and does not authorize the remote destination. Use
`quic://quic-broker.ipf.dev:4450` with platform trust for the shared production broker, and `--insecure-local` only for
loopback development with generated self-signed certificates.

### Sync

```sh
wn --account <npub-or-hex> sync
```

`sync` is a diagnostic and repair command. Normal daemon-backed chat, group, and stream flows use runtime subscriptions
and should not need it.

## Daemon

`wn daemon start` launches `wnd` in the background for the selected home. The daemon owns the Unix socket, writes
`dev/wnd.pid`, appends startup errors to `dev/wnd.log`, and hosts one `MarmotAppRuntime`. The runtime keeps long-lived
relay subscriptions for local signing accounts using the daemon's discovery and account-relay defaults, and updates them
automatically after identity, group, message, and stream mutations forwarded through it.

```sh
export WN_HOME="$PWD/dev/data/daemon-demo"
export WN_SECRET_STORE=file
export WN_ALLOW_LOOPBACK_RELAYS=1   # loopback relays are dev/test only; unset in production
unset WN_SOCKET
wn daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777
wn daemon status
wn --account <npub-or-hex> chats list
wn daemon stop
```

- When a daemon socket exists for a home, normal `wn --home <path> ...` commands are forwarded to it. `wn daemon status`,
  `wn daemon stop`, and `wn tui` handle daemon access directly. Use `--socket` or `WN_SOCKET` to target a specific
  daemon.
- `wn daemon status --json` includes `last_runtime_activity`, background `stream_watches`, and a redacted `relay_health`
  object with aggregate relay counts and connection-status buckets. It does not include relay URLs, account ids, group
  ids, subscription ids, or message ids.
- Subscription commands (see [Messages](#messages)) use the daemon socket directly.

Run `wnd` directly when a process supervisor should own the daemon lifecycle. It accepts `--home` (alias `--data-dir`),
`--logs-dir`, `--socket`, `--discovery-relays`, `--default-account-relays`, `--secret-store`, and `--keychain-service`:

```sh
wnd --home "$WN_HOME" \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777
```

### Two-terminal local stream demo

Terminal 1 owns the daemon and the live subscription:

```sh
just relay-up

export WN_HOME="$PWD/dev/data/stream-demo"
export WN_SECRET_STORE=file
export WN_ALLOW_LOOPBACK_RELAYS=1   # loopback relays are dev/test only; unset in production
unset WN_SOCKET
rm -rf "$WN_HOME"

wn daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777

# After Terminal 2 creates $BOB and $GROUP, run:
wn --account "$BOB" messages subscribe "$GROUP" --limit 20
```

Terminal 2 creates Alice and Bob, starts the durable stream, and sends live broker chunks:

```sh
export WN_HOME="$PWD/dev/data/stream-demo"
export WN_SECRET_STORE=file
export WN_ALLOW_LOOPBACK_RELAYS=1   # loopback relays are dev/test only; unset in production
unset WN_SOCKET

ALICE=$(wn --json create-identity | jq -r '.result.account_id')
BOB=$(wn --json create-identity | jq -r '.result.account_id')

GROUP=$(wn --account "$ALICE" --json groups create agent "$BOB" | jq -r '.result.group_id')
wn --account "$ALICE" messages send "$GROUP" "hello bob"

STREAM_ID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
START_ID=$(wn --account "$ALICE" --json stream start "$GROUP" \
  --stream-id "$STREAM_ID" \
  --quic-candidate quic://127.0.0.1:4450 | jq -r '.result.message_ids[0]')

wn --account "$BOB" stream watch "$GROUP" --stream-id "$STREAM_ID" --insecure-local --background
wn stream send --broker --connect 127.0.0.1:4450 --server-name localhost --insecure-local \
  --stream-id "$STREAM_ID" --start-event-id "$START_ID" --chunk-bytes 8 "hello from the stream"
```

Terminal 1 should print typed `message`, `agent_stream_start`, `agent_stream_delta`, and `stream_preview` JSON lines in
real time.

## TUI

`wn tui` is a Ratatui interface over the real `wn --json` command surface. Its main view is chat-first: the chat list on
the left, the materialized message timeline on the right (reactions, reply context, deletion tombstones, and inline
images), the composer below, and a hints bar plus status bar at the bottom.

```sh
wn tui
```

### Startup and the daemon

Startup routes by local account count: none opens the login menu (create an identity or log in with an nsec), exactly
one enters the main view, and several open an account picker. An explicit `--account` (or `WN_ACCOUNT`) that resolves to
a loaded account enters the main view directly. Press `A` from the chat list, or use `/account`, `/login`, and
`/create-identity`, to switch accounts later.

Creating an identity and starting the daemon both need relays. On first run, pass them to `wn tui` and they are
forwarded to the daemon-start and account-setup child commands:

```sh
wn tui \
  --discovery-relays wss://relay.discovery.example \
  --default-account-relays wss://relay.one.example,wss://relay.two.example
```

- When a daemon is running for the same home, TUI child commands use its socket and the TUI attaches to daemon-backed
  subscriptions for live message, chat, and group-state changes. The status bar shows daemon state.
- When no daemon is running at launch, the TUI auto-starts one (as `/daemon start` would) if it has a relay source: the
  flags above, a global `--relay`, or `WN_RELAY`. The status line shows `starting daemon...` and then the outcome.
  Without a relay source no start is attempted, a status notice says so, and the TUI continues degraded; restart it
  with relay flags (or `WN_RELAY`).
- The TUI never stops the daemon when it quits, because other `wn` commands share it. Stop it with `/daemon stop` or
  `wn daemon stop`.
- Without a daemon, off-screen unread badges and previews update only on `/refresh` or when you re-open the chat. Badges
  and the unread total survive restarts either way, since they come from the runtime's durable `chats list` projection.

User-initiated commands (send, reply, react/unreact, delete, open chat, user search, group detail, invites) and ambient
chat-list re-reads run on a background worker, so a `wn` round-trip never freezes input. They show in-flight feedback
(`sending...`, `loading chat...`, `searching...`), mutations keep their submission order, and a load for a target you
have already moved past is dropped. Modal or rare flows (login, logout, daemon start/stop, popup submits) stay
synchronous.

### Keys

Login screen:

- Menu (no accounts): `c` create an identity, `l` log in with an nsec, `q` quit.
- Account picker: `j`/`k` or arrows move; `Enter` selects; `c` create; `l` nsec login; `Esc` returns to the main view
  when one is active; `q` quit.
- Nsec entry: the nsec is rendered masked; `Enter` submits it over stdin; `Esc` cancels.

Main view:

- `Tab`/`BackTab`: cycle the chat list, messages, and composer.
- Chat list: `j`/`k` or arrows move the selection and, after ~150 ms of quiet, preview the highlighted chat in the
  message pane while focus stays on the list. The messages-pane title names the loaded chat, and the composer sends to
  it. `Enter` opens the chat and focuses messages. Opening or previewing a chat marks it read (`chats mark-read`).
  Rows show an unread badge (bold name plus `(N)`) and a last-message preview, ordered by last activity. `g` group
  detail, `s` user search, `p` profile, `h` relay health, `I` pending invites, `A` account picker. A group invite shows
  as a status notice prompting `I`. Background refreshes never move the highlight.
- Messages: `j`/`k` or arrows move; `PageUp`/`PageDown` page; `G`/`End` jump to newest (and pin to the bottom);
  `g`/`Home` jump to oldest. Scrolling past the oldest loaded message loads the previous page. `i` or `Enter` focuses
  the composer. On the selected message:
  - `r` prefills `/react ` (`Enter` sends the default `+`; type an emoji first to customize);
  - `u` removes your reaction immediately;
  - `d` prefills `/delete` for your own message (`Enter` confirms);
  - `R` prefills `/reply ` and shows the reply target on the status line;
  - `o` opens the downloaded image full-size.

  Prefills are skipped when the composer already holds a draft. While a prefill is armed, the hints line says what
  `Enter` will do and to which message.
- Composer: `Left`/`Right`/`Home`/`End` move the cursor; `Backspace`/`Delete` remove a character; `Enter` submits.
  There is no keyboard newline (multi-line content arrives only by paste). The composer grows with its content up to
  8 rows.
- `Esc`: clears an armed `/react`, `/reply`, or `/delete` prefill; a hand-typed draft is left intact. With nothing armed
  it steps back (composer → messages → chats). With a popup open, it closes the popup.
- `Ctrl-U`: clears the whole composer, whatever it holds (also the masked nsec field).
- `?`: help popup.
- `q`: quit, from the chat list or messages pane and only while the composer is empty. In the composer it is a literal
  `q`. `Ctrl-C` always quits.

Popups are modal and capture every key. Text-entry popups submit on `Enter` (when non-empty) and cancel on `Esc`;
confirm popups take `y`/`Enter` or `n`/`Esc`; list pickers move with `j`/`k` and close on `Esc`; help, info, and error
cards close on any key.

`/react` accepts exactly one emoji (one grapheme cluster carrying a non-ASCII scalar, including ZWJ families, skin
tones, flags, and keycaps) or the NIP-25 `+`/`-` sentinels. Anything else, including prose and non-Latin or accented
words, is refused with a status-line error so typed text is never published as a reaction. This guard lives in the TUI;
the `messages react` CLI command stays protocol-faithful.

### Inbound media

Image attachments render inline as cell-exact half-block previews (downscaled with Lanczos3) on any image-capable
terminal. Half-blocks are ordinary colored cells bounded to the reserved block, so an image never overdraws a neighbor
or leaves artifacts when scrolling. Each image is downloaded and decoded in the background; its placeholder moves
through `[img name]` → `[downloading name...]` → `[loading name...]` → the image, or `[name failed: err]`. Terminals
without image support keep `[img name]`, and non-image attachments show `[file name]`.

The `o` viewer uses the terminal's native pixel protocol when the startup query found one (iTerm2's own protocol in
iTerm2), falling back to half-blocks; closing it forces a full repaint. Viewer pixels live in a small in-memory pool
(oldest evicted first). Each image is decrypted into a private `tui-media-cache/` directory under the TUI home, decoded
into memory, and the decrypted file is removed immediately, so no decrypted media stays at rest. Leftovers from a
crashed session are swept at startup.

### Screens

- **Group detail** (`g`): members with admin badges and a `(you)` marker, relay hints, name, and description. `j`/`k`
  move the member selection; `a` searches for someone to add; `A` adds by npub/hex (`groups add-members`); `x` removes
  the selected member; `P` promotes them to admin; `R` renames the group; `L` leaves; `I` opens invites. Admins cannot
  leave: `L` shows a "Cannot Leave Group" card (sole admins must promote another member first; co-admins must step
  down). A non-admin confirms, and on success the chat leaves the list. `Esc` returns to the main view.
- **Invites** (`I`): pending invites from `groups invites`. `a` or `Enter` accepts and opens the chat, `d` declines,
  `Esc` closes. The picker stays open until no invites remain; with none it shows an info card.
- **User search** (`s`, or `/users [query]`): a one-shot `users search` over your follow graph (default radius `0..1`).
  In query focus, type and press `Enter`; in list focus, `j`/`k` move, `Enter` shows the profile card (`users show`),
  `c` starts a new chat (`group create`), `a` adds them to a chat via a group picker and confirm popup, `f` follows and
  `x` unfollows (rows you already follow are badged `[following]`), `i` returns to the query, and `Esc` goes back. Rows
  show the name, a shortened npub, and `matched_field · match_quality · radius`. Opened from group detail with `a`, the
  screen targets that group: `a` skips the chat picker, `Esc` returns to group detail, and the detail reloads after the
  add.
- **Message search** (`/search [query]`): searches the chat loaded in the messages pane (`messages timeline search`),
  capped at 100 hits (a full page shows `100+`; refine the query). Same two-state focus as user search. Matches are
  newest first, shown as `[HH:MM] sender` plus the text. `Enter` jumps to the message if it is inside the loaded
  history (one contiguous run ending at the newest, 100 rows per page up to 1000). An older match reports
  `that message is older than the loaded history; press g to page back first`; page back with `g`/PageUp and search
  again.
- **Profile** (`p`): your name, display name, about, picture URL (as text; no avatar is fetched), nip05, lud16, npub,
  and follows. `Enter` on a field edits and publishes only that field (`profile update --<field>`); `f` follows a user
  by npub/hex; `x` unfollows the selected follow. There is no nsec export anywhere. `Esc` goes back.
- **Relay health** (`h`): a redacted, device-local dashboard from `relay-stats` (from the live `wnd` runtime when a
  socket exists, otherwise a fresh in-process read). It shows connection health, lifecycle counters, cross-relay
  delivery spread (p50/p99 from fixed-bucket histograms, with `n/a` and `>Nms` overflow), subscription first-event/EOSE
  timing, and per-relay rows keyed by an opaque device-local index. No relay URLs appear. `r` refreshes, `j`/`k` and
  PageUp/PageDown scroll, `Esc` goes back.
- **Diagnostics** (`/diagnostics`): toggles a group MLS/component diagnostics panel between the messages pane and the
  composer. Hidden by default.

### Slash commands

```text
/help
/refresh
/diagnostics
/account <npub-or-hex>
/create-identity
/login <nsec-or-npub>
/logout
/daemon status
/daemon start
/daemon stop
/chat new <name> [member-npub-or-hex ...]
/chat rename <name>
/chat describe <description>
/chat archive
/chat unarchive
/chat mute <duration>
/chat unmute
/chat archived [on|off]
/members add <npub-or-hex> [...]
/members remove <npub-or-hex> [...]
/members list
/react [emoji]
/unreact
/delete
/reply <text>
/retry <event-id>
/image <file-path> [caption]
/keys fetch <npub-or-hex>
/keys rotate
/name <display-name>
/profile name <display-name>
/users [query]
/search [query]
/stream [--stream-id <hex>] [--quic-candidate <quic-url>]
/stream start [--stream-id <hex>] --quic-candidate <quic-url>
/stream watch [--stream-id <hex>] [--insecure-local]
/stream status
/stream finish <stream-id> <transcript-hash> <chunk-count> <text>
/stream verify <stream-id> <transcript-hash> [chunk-count]
/quit
```

- `/logout` acts on the selected account and is always confirmed, showing the account npub and stating plainly that
  local data (and, for a local-signing account, the signing key) will be deleted. A local-signing logout is
  irreversible, so it requires typing the literal word `logout` and pressing `Enter`; an empty or mismatched entry keeps
  the popup open and `Esc` cancels. A public-only account uses the lighter `y`/`Enter` confirm. If the removed account
  was the last one, the TUI returns to the login menu.
- `/login <nsec>` redacts the secret in the composer and pipes it to the child `wn` over stdin, never argv.
- `/chat archived` shows archived chats so they can be selected and unarchived; `/chat archived off` returns to the
  visible list. `/members` commands operate on the selected chat.
- `/react`, `/unreact`, `/delete`, and `/reply <text>` act on the selected message and call the real `messages`
  commands; they error to the status line when no message is selected (`/delete` also when it is not yours). `/reply`
  runs `messages send --group <loaded-group> --reply-to <selected-message-id> <text>`. Results fold into the existing
  timeline row without a reload.
- `/retry <event-id>` takes an id rather than acting on the selected message, because timeline rows do not carry
  per-message failed-send state.
- `/image` uses the real encrypted media path (`wn media upload <group> <file> --send`) with the optional caption as
  message text.
- Stream commands operate on the selected chat. `/stream watch` starts a daemon background watch whose completed preview
  appears as a provisional row. `/stream` opens the stream composer, publishes the anchor, starts the receiver watch
  through the daemon, and treats the next submitted line as the streamed text. It uses
  `quic://quic-broker.ipf.dev:4450` when no candidate is supplied.
- There is no `/sync`; the TUI rejects it because live updates come from subscriptions. Use `wn sync` outside the TUI
  as a diagnostic/repair escape hatch.

## JSON output

Pass `--json` for machine-readable output. Success responses wrap command data in a stable result envelope. Errors use
snake_case `error.code` values and include repair fields when the CLI can name the next command. The TUI and daemon both
depend on the JSON shape, so treat response changes as API changes.

## Packaging

Local development installs from the checkout:

```sh
cargo install --path crates/cli --locked --bins
```

Engineers and automation can install from source without a checkout:

```sh
cargo install --git https://github.com/marmot-protocol/mdk.git wn-cli --locked --bins
```

The intended first-class public installer is the namespaced Homebrew tap, whose formula installs both `wn` and `wnd`:

```sh
brew install marmot-protocol/tap/wn
```

The formula lives in `github.com/marmot-protocol/homebrew-tap`; the project-side checklist is
[`docs/release/wn-homebrew.md`](../../docs/release/wn-homebrew.md). `cargo install wn-cli` from crates.io is not
available: the workspace has `publish = false` and the CLI depends on local workspace crates.

## Changelog

Release notes for the CLI crate live in [`CHANGELOG.md`](CHANGELOG.md).
