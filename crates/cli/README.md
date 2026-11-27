# wn

`wn` is the command-line app for the White Noise/Marmot stack. It manages Nostr-keyed accounts, relay lists,
KeyPackages, chats, groups, messages, media, and live runtime subscriptions. Use it to drive Marmot from a shell or
script.

The crate (source `crates/cli`, Cargo package `wn-cli`) builds two binaries:

- `wn`: the user-facing CLI.
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
  - [Device linking](#device-linking)
  - [Chats](#chats)
  - [Groups](#groups)
  - [Messages](#messages)
  - [Media](#media)
  - [Directory, profile, relays, and settings](#directory-profile-relays-and-settings)
  - [Sync](#sync)
- [Daemon](#daemon)
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

A `wnd` that is already running keeps serving the old code after an upgrade. Stop it with `wn daemon stop` and start it
again (see [Daemon](#daemon)).

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
- `--json`: return a stable JSON envelope for scripts and daemon forwarding.
- `WN_RELAY`: fallback relay URL for commands that need one when no relay flag is given.

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
printf '%s\n' "$BUNKER_URI" | wn login --bunker-stdin --approve-permissions
wn login --nostrconnect --signer-relays <relay-url>
wn login <npub-or-hex>
wn whoami
wn logout <npub-or-hex>
wn export-nsec <npub-or-hex>
wn accounts list
wn accounts status [npub-or-hex]
wn accounts relay-lists [npub-or-hex] --bootstrap-relays <relay-url>
printf '%s\n' "$BUNKER_URI" | wn accounts nip46 login --bunker-stdin --approve-permissions [--default-relays <urls>] [--bootstrap-relays <urls>] [--publish-missing-relay-lists]
wn accounts nip46 login --nostrconnect --signer-relays <relay-url> [--approve-permissions]
printf '%s\n' "$BUNKER_URI" | wn accounts nip46 register [npub-or-hex] --bunker-stdin --approve-permissions
wn accounts nip46 status [npub-or-hex]
wn accounts nip46 remove [npub-or-hex]
wn reset --confirm
```

- When a daemon is running, `create-identity` and `login --nsec-stdin` use the daemon's account-relay defaults to
  publish the required relay lists and an initial KeyPackage. `login --nsec-stdin --relay <url>` is the command-local
  fallback for a custom relay-list publish during import.
- **NIP-46 remote signing (`--bunker-stdin`, `--nostrconnect`, `accounts nip46`)**: log in and operate an
  `external_signing` identity without storing the user's `nsec` on the machine. Pipe `bunker://` URIs via
  `--bunker-stdin` (passing `bunker://` or `nostrconnect://` as a CLI argument is rejected so query secrets never leak
  into argv or shell history). Reviewing and approving the exact NIP-46 permissions is required — confirm interactively
  on a terminal or pass `--approve-permissions` for headless/scripted setups. Communication keys and the external
  SQLCipher key respect `--home` and `--secret-store file|keychain`. On `wnd` startup and restart, persisted NIP-46
  sessions are automatically resumed independently so an unreachable remote signer does not block local accounts or
  crash `wnd`. `accounts nip46 register` attaches a NIP-46 session to an existing external-signing account (run
  `accounts nip46 remove` first when replacing an active pairing, since only one communication key can own an account),
  `accounts nip46 status` inspects non-secret session state, and `accounts nip46 remove` erases local pairing
  credentials while preserving encrypted history.
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
wn --account <npub-or-hex> chats subscribe-archived   # deprecated
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
wn --account <npub-or-hex> groups commit-delivery <group-hex>
wn --account <npub-or-hex> groups pending-commit <group-hex>
wn --account <npub-or-hex> groups changes-not-delivered <group-hex>
wn --account <npub-or-hex> groups acknowledge-change-not-delivered <group-hex> <commit-hex>
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
wn --account <npub-or-hex> groups subscribe-state <group-hex>   # deprecated
```

The hidden legacy `group` namespace keeps `create`, `members`, `invite` (with `--admin`), `remove`, `update`, and
`set-avatar-url` working.

**Groups that are still catching up.** While this device's epoch-gap recovery says the group may have moved on without it,
group changes (membership, admins, profile, image, retention, disbanding) fail with JSON error code
`group_catching_up`. A change from a stale epoch can split the group for everyone. Retry once the group syncs, or pass
`--accept-stale` to make the change anyway; scheduled self-updates wait up to a day for the group to catch up.

**Changes not yet on every relay.** A group change counts as published once one group relay accepts it; MDK keeps
retrying the others with the same event. Until they accept it, members who read only those relays cannot follow it, so
once a change has been owed to a relay for two minutes, group changes fail with JSON error code
`group_commit_undelivered`. A relay that refuses a change for good (too large for it, or any other final answer) will
never carry it, so group changes fail with the same code at once, until you accept the refusal. `groups commit-delivery
<group-hex>` shows the oldest change a relay refused, or else the oldest change still owed to a relay, with the relays
owing it, the relays that refused it (`refused_relays`, each with its `cause`) and when the first relay accepted it; it
reports owed relays immediately, before the two minutes pass. Retry once they accept it, or pass `--accept-undelivered`
to make the change anyway, which also dismisses the group's refusals for good; scheduled self-updates wait up to an hour.

**A change still being sent.** A group takes one commit at a time. While this device's last commit in the group has
not confirmed, group changes fail with JSON error code `group_commit_pending`, ahead of `group_catching_up` and
`group_commit_undelivered`; messages still send, and disbanding and an admin's leave are still accepted. `groups
pending-commit <group-hex>` shows it under `pending_commit` (`null` when none): `commit_id_hex`, `origin` and
`intent_kind` for a change of yours (absent for one MDK made on its own), `first_attempt_at`, `state`, and the relays.
`state` is `sending` for its first ten minutes and while no relay may hold it, and `stuck` once some relay may hold it
and none has acknowledged it: MDK keeps resending it and never gives it up. `unconfirmed_relay_urls` may hold it,
`owed_relay_urls` never received it, and `refused_relays` gave a final latest answer with its `cause`.

**Changes that were not applied.** A group change can return before MDK knows whether it reached the group. When MDK
later gives such a change up, nothing reached members and nothing sends it again. Unlike `commit-delivery`, which shows
a change members can see but some relay still owes, these changes never took effect. `groups changes-not-delivered
<group-hex>` lists them, oldest first, under `changes_not_delivered`. Each entry has `commit_id_hex`, `origin`
(`{"type": "direct"}`, or `{"type": "queued_intent", "intent_id_hex": ...}` for a queued change), `intent_kind` (such
as `update_group_data`), `reason` and `at` (Unix seconds). The `reason` is `not_delivered` if no relay received it,
`event_too_large` if it fits none of the group's relays, or `refused` if every relay refused it. An entry stays,
across restarts and later changes, until `groups acknowledge-change-not-delivered <group-hex> <commit-hex>` clears it
(`acknowledged` is `false` if there was nothing to clear). A change that failed inside its own command, or one MDK made
on its own, such as a scheduled self-update, is never listed.

**Group identifiers.** Every `<group-hex>` is the canonical MLS group id (`group_id` in JSON; opaque bytes, 16 bytes for
OpenMLS-created groups). It is not the 32-byte Nostr routing handle shown under `nostr_routing.nostr_group_id_hex`,
which is transport state the group can rotate. Filters, lookups, and JSON always key on the MLS group id.

**Publication versus durable completion.** `published` and `message_ids` on a mutation result mean the relay accepted
the events this device sent. They do not prove that any other member has processed them. Outcomes that finish later
are queryable after the command returns and after a restart: `groups disband-status`, `groups recovery-status`,
`groups pending-welcomes`, and `groups maintenance-status`.

**Members are accounts.** `groups members`, `groups show` and `groups management` list each member account once, even
when it has several devices in the group. Each `members` entry carries `device_count`, how many of that account's
devices are in the group, and member counts, admin counts and the last-admin check count accounts.

**Invites.** `groups invites` lists groups still awaiting local confirmation. `groups accept` clears that pending state;
`groups decline` leaves and archives the auto-joined pending group.

Group creation and member invites resolve each requested account independently using fresh KeyPackages.
Eligible accounts proceed even if others are unavailable. JSON `member_outcomes` lists each canonical account once,
with `account_id_hex`, `status`, and `selected_device_count`. `selected` means eligible for the operation, not joined or delivered.
Other statuses are `missing_key_package`, `obsolete_key_package`, `invalid_key_package`, `incompatible_key_package`,
`missing_inbox_route`, and `incomplete`. If no requested account is eligible, creation returns `group_id: null`;
an invite returns `summary: null` and nullable publication fields, without changing the group.
An empty create roster still creates a creator-only group.

**Names and admins.** `groups update` is the canonical spelling for name and/or description changes; `groups rename`
and legacy `group update` keep working. `groups add-members ... --admin <member>` (and legacy `group invite --admin`)
grants admin to an invitee inside the same invite commit. An `--admin` that is not one of the invitees fails with
`initial_admin_not_invited` before anything is published. Invite results carry selected `initial_admins` and the
original `requested_initial_admins`. An unavailable invitee receives no admin rights.
`groups management` mirrors the MarmotKit management state (`is_self_admin`, `can_invite`, `can_leave`,
`requires_self_demote_before_leave`, `leave_blocked`, `can_enable_disbanding`, `can_disband`, `disbanding_blockers`,
per-member `member_actions`). Leave hints use the shared core capability selector and remain advisory; the command
rechecks current authority. `can_leave` is false for unaccepted invitations and unrecoverable groups.
Leave demotes an eligible nonlast admin account itself before its ordinary departure, so
`requires_self_demote_before_leave` is false: the last active admin account is refused before a new shared invitation
choice or departure publication, and a committed demotion remains if a later departure fails. With
`WN_DEVICE_GROUPS=0` (see [device linking](#device-linking)) the flag is instead true for an admin, including an admin
invitee: `groups leave` and `groups decline` refuse an admin with `admin_policy` before anything is written or
published, until `groups self-demote`; the last admin promotes another account first. An admitted Leave can still be
settling; success is not proof every device departed.

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
  outbound work is gated), `disbanded`, `unrecoverable`, and `self_membership` (`member`, `left`, `removed`, or
  `device_removed`: this device's leaf was removed while the account stays in the group through another of its
  devices).
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
wn --account <npub-or-hex> messages timeline search "" --sender <npub-or-hex> --since <unix-seconds> --until <unix-seconds> --attachment-type image
wn --account <npub-or-hex> messages timeline search <query> --before <timeline-at> --before-message-id <message-id> --cursor-group-id <group-hex>
wn --account <npub-or-hex> messages timeline subscribe <group-hex>   # deprecated
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
now, on the current wall clock (the engine applies its own clock-skew tolerance and unread deferral;
there is no flag to supply a time). It returns `now_ms`, total `pruned_messages` / `secrets_deleted`, and a per-group
`groups` array with `status` (`no_expired_messages`, `pruned`, `deferred_clock_skew`, `deferred_unread`,
or `failed`), counts, `media_ciphertext_sha256` purge hints, and a privacy-safe
`failure_kind`. A running `wnd` does not schedule this sweep; call it explicitly.

**Custom events.** `messages send-event <group-hex> <kind> [content]` sends an app-defined event. Kind, tags, and content
pass through verbatim into the encrypted group message. Kinds MDK owns (chat, reactions, edits, deletes,
retired agent stream starts (kind 1200), group system rows, push token records, and the device-group kinds 457, 458,
459, 460, 461, 473, 475 and 476) are rejected with `reserved_app_event_kind`. Agent items (kind 1201) and answers and
controls (kind 1202) are accepted in the shape the marmot-app README's agent events section gives. Each `--tag`
takes a JSON array of strings and is repeatable; a malformed tag fails with `invalid_event_tag`. Custom events project as
standalone rows with their own kind and tags and never fold onto a target message. `messages list` and
`messages subscribe` accept repeatable `--kind <KIND>` filters and return every kind without one. On the subscribe feed
a custom event arrives as type `message`; on the timeline feed its change trigger is `CustomEvent`. Agent items and
answers are the exception: a 1202 has no timeline row, and a 1201 is one row per item whose first event arrives under the
`AgentItem` trigger and whose later versions arrive under `MessageEditedOrReprojected`.

**Timeline.** `messages timeline list|search|subscribe` read the materialized timeline, which interleaves messages,
media, and group system rows. Group lists and subscriptions use canonical conversation order.

**Timeline search.** `messages timeline search` searches retained local history, across the account unless a group
is supplied. Text is a trimmed, case-insensitive literal substring; query operators and wildcards have no special
meaning. An empty query (`""`) applies only the other filters. `--sender` accepts an exact npub or hex public key.
`--since` is inclusive and `--until` is exclusive, both in Unix seconds on `timeline_at`. `--attachment-type` accepts
`any` (no attachment restriction), `image`, `video`, `audio`, `file` (other or unknown MIME type), or `attachment`
(any attachment). Filters combine before the page limit, which is capped at 200 rows.

Search pages are oldest first in wall-clock order, including group-restricted searches. To fetch older results,
pass the first row's `timeline_at` and `message_id` as `--before` and `--before-message-id`. To fetch newer results,
use the last row with `--after` and `--after-message-id`. Account-wide paging also requires that row's `group_id`
as `--cursor-group-id`, so identical message ids in different groups remain distinct. Keep the same filters between
pages and use `has_more_before` and `has_more_after` from JSON output to find the remaining history.

**Delivery.** A timeline row (`messages timeline list|search|subscribe`) carries `invalidation_status`, which names
why the row was withdrawn or failed (`local_publish_failed`, `LosingBranch`, ...) and is `null` otherwise. A row is
delivered when `invalidation_status` is `null` and either `source_message_id` is set or `recipient_confirmed` is
`true`. The second case is an own send that no relay accepted but another member reacted to, proving they received
it. A row with `invalidation_status` set is not delivered, even when it keeps its `source_message_id`.

**Subscriptions.** `messages subscribe`, `messages timeline subscribe`, `chats subscribe`, `chats subscribe-archived`,
`groups subscribe-state`, and `notifications subscribe` require `wnd`. With `--json` they print newline-delimited
responses with a typed `result.type`. `messages timeline subscribe`, `chats subscribe-archived`,
`groups subscribe-state`, and `notifications subscribe` are deprecated: they served the removed terminal UI and will be
removed in a future release.

| `result.type` | Meaning |
| --- | --- |
| `message` | normal app messages and app-defined custom kinds |
| `reaction` | reactions |
| `message_delete` | deletions |
| `media` | media references |
| `chat` | chat rows |
| `group_state` | group state rows |

### Media

```sh
wn --account <npub-or-hex> media list <group-hex>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --send --message <caption>
wn --account <npub-or-hex> media upload <group-hex> <first.jpg> <second.jpg> --send --message <caption>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --server https://blossom.divine.video
wn --account <npub-or-hex> media send <group-hex> '<media-json>' ['<media-json>' ...] --message <caption>
wn --account <npub-or-hex> media set-endpoints <group-hex> https://blossom.example [https://mirror.example]
wn --account <npub-or-hex> media download <group-hex> <file-hash> --output ./file.jpg
```

**Upload.** `media upload` encrypts each file with the group's current `MLS-Exporter("marmot", "encrypted-media", 32)`
media secret, uploads the ciphertext to Blossom, and with `--send` sends one kind-9 media message whose `imeta` tags keep
the command-line order (`attachment_index` in `media list`). The server must accept opaque `application/octet-stream`
uploads. Without `--server`, the upload targets the ordered endpoints in the group's versioned encrypted-media
component: frozen V1 (`0x8008`) for already-joined legacy groups and V2 (`0x800b`) for current-profile groups. Upload
JSON returns an `attachments` array with each attachment's `plaintext_sha256`, `ciphertext_sha256`, and locators.

**Endpoints.** Newly created groups use White Noise's ciphertext-compatible endpoint list, which `wn` takes from
its White Noise deployment. Endpoint policy is signed group state, so upgrading MDK changes
defaults for new groups only. An active group admin runs `media set-endpoints <group-hex> <url> [...]`
(`--locator-kind` defaults to `blossom-v1`) to replace a group's default endpoints without changing its media version.
Non-admins get `not_group_admin`; the response carries the refreshed `encrypted_media` component.

**Re-sending.** `media send` publishes already-uploaded references as one ordered message without re-uploading. Each
attachment uses the complete `media upload` JSON object, including its local `source_epoch_identity`. Preserve that
object to send it later. The compatibility plaintext-hash input resolves projected metadata but cannot restore its
local upload identity.
References reconstructed from `media list` or a plaintext-hash lookup have no upload provenance and require a fresh
upload before sending. They remain valid download inputs. The runtime re-validates every reference against the
group's media profile, locator policy, version, and exact upload branch. The epoch number alone is insufficient:
branch selection can change the media key while keeping that number. The wire `imeta` tag carries neither epoch nor
local identity; recipients derive the media key from the delivering message's epoch.

- A stale reference is refused before publication with `media_reference_stale_epoch` (`source_epoch`,
  `current_epoch`). Upload the file again and send the returned JSON reference. Missing upload identity requires a
  fresh upload even when both epoch numbers match.
- The send is pinned to the reference's epoch inside the engine too: an epoch change during the send, including a move
  to another branch at the same epoch number, gives the same error, and while the epoch is unsettled (your commit still publishing, or peer commits not yet applied) the send is
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
wn settings language en
wn notifications subscribe   # deprecated
wn --account <npub-or-hex> debug health
wn debug relay-control-state
wn relay-stats
wn --json usage-diagnostics show
wn usage-diagnostics enable
wn usage-diagnostics disable
```

- `follows add|remove` edits your current contact list on the relay: it adds or removes that account's `p` tag and keeps
  every other tag and the content. A list with 2,048 follows or more is refused with `follow_list_too_large`, since
  MDK reads no more than that from one list.
- `users search` searches your follow graph; `--radius START..END` defaults to `0..1` (0 is you, 1 who you follow, 2
  follows-of-follows).
- `notifications subscribe` (deprecated) streams daemon-backed local notification updates as JSON lines.
- `relay-stats` prints device-local relay telemetry: aggregate lifecycle counters, cross-relay arrival spread,
  per-relay first-deliverer and first-event/EOSE timing, and redacted relay health. It reads the live `wnd` runtime
  when a daemon socket exists. Per-relay rows use opaque device-local indices, never relay URLs.
- `usage-diagnostics show|enable|disable` manages the local combined "Share usage and diagnostics" permission. An active
  `wnd` owns the update. Audit consent is separate. See the
  [host and operator contract](../../docs/marmot-architecture/usage-diagnostics.md) for disclosure, endpoint/key
  configuration, and reporting limitations.

### Sync

```sh
wn --account <npub-or-hex> sync
```

`sync` is a diagnostic and repair command. Normal daemon-backed chat, group, and message flows use runtime subscriptions
and should not need it.

## Device linking

Device groups are on by default in every `wn`/`wnd` build, with production settlement/retry timing. Export
`WN_DEVICE_GROUPS=0` (or `false`, `off`, `no`) for both `wn` and `wnd` (the daemon owns the runtime) to turn them off.
A debug build needs the repository's existing [debug-binary stack requirement](../../README.md#development)
when running `wn`/`wnd` directly:

```sh
export RUST_MIN_STACK=4194304
cargo build -p wn-cli --bins --locked
```

Leave `WN_DEV_SETTLEMENT_QUIESCENCE_MS` and other policy-test overrides unset. Against a `wnd` started with `WN_DEVICE_GROUPS=0`,
`devices link` commands fail with `device group refused: pairing_unsupported` (JSON code `command_failed`) and
`devices list` shows no devices; `wn daemon status --json` reports the daemon's `device_groups`.

Use a dedicated account and home for dogfooding. Sign in to that same account on both devices using the existing
`login --nsec-stdin` flow; never put an nsec in argv. Run a persistent daemon on each device with its selected home,
secret store, discovery relays and account relays, using matching `wn`/`wnd` binaries. For example, with
`WN_HOME` and `WN_SOCKET` exported and the intended real relay lists configured:

```sh
wn daemon start --discovery-relays "$DISCOVERY_RELAYS" --default-account-relays "$ACCOUNT_RELAYS"
wn --account "$ACCOUNT" devices list
wn --account "$ACCOUNT" devices link start
wn --account "$ACCOUNT" devices link status
```

Run `start` on the **new** device. Read `status` on both devices until each shows seven emoji. Compare all seven
pictures on the two screens. On the existing device, use its displayed prompt id and approve only if they match:

```sh
wn --account "$ACCOUNT" devices link approve "$PROMPT_ID" --label "Laptop"
```

On the new device, separately confirm the match:

```sh
wn --account "$ACCOUNT" devices link confirm-match
wn --account "$ACCOUNT" devices link status
```

Both confirmations are required; either may happen first. The existing device shows `linking` until the new device's
first selected change arrives, then `linked`; the new device also shows `linked`. Read `devices list` on both to see
their own distinct slots. `devices link cancel` cancels on the new device. Approval uses the existing defaults of
adding to existing chats and bringing history; `--no-add-to-all-chats` and `--no-bring-history` opt out individually.
No command creates or authenticates a device by its account key alone.

The link status JSON includes `chat_progress` for each recent approved link. On the new device, `remaining` counts chats
still joining. On its approver, it counts Adds still owed. An empty list means progress is unavailable.

Running the same `devices link start` flow on an already linked device moves only that device to the destination's
device group. `link status` adds `moves[]`: Joining still trusts the old group; Made is the trust switch after the new
device's first selected change. Old siblings remain local recognition hints, not automatic links. A known failed link
before Made keeps old trust and forgets only the destination. The move leaves existing chat membership intact and does
not promise traffic between device groups; admitted old-group traffic can finish normally. An unrecoverable destination
can stay pending indefinitely while ordinary repair applies, keeping old trust and preventing another confirmed move.
Corrupt or unreadable local move records may need manual local recovery or reset. These conditions do not themselves
unlink this device. See [move behavior and limits](../marmot-uniffi/README.md#moving-this-device-to-another-device-group).

To deliberately discard only this device's local hidden device-group copy before fresh code pairing:

```sh
wn --account "$ACCOUNT" devices link reset --confirm
wn --account "$ACCOUNT" keys rotate
wn --account "$ACCOUNT" devices link start
```

This keeps ordinary chats/history/drafts/settings, account credentials and the current slot; it abandons old link-bound
preparations, not shared-state/security synchronization, and publishes no removal. It refuses active pairing/Move or
unsettled native work (`device_group_busy`),
possibly indefinitely. No trusted copy returns `no_device_group`. Reset does not guarantee fresh admission: an approver
that still lists the slot/old leaf, rejects it or is full can refuse. Reset itself publishes no KeyPackage; use the
existing rotation command before fresh code pairing, as above. A failed publication does not restore old trust;
cancellation/failure can leave needs-link, and no old copy is restored. An already-confirmed fresh Welcome wait retains
its normal restart behavior. Ordinary chat membership and missing-history repair remain separate. See the
[shared reset contract](../marmot-uniffi/README.md#explicit-local-device-group-reset-before-fresh-pairing).

For this dev-testing build, run **all account commands through a persistent matching daemon**. Select it explicitly
with `--socket` or exported `WN_SOCKET`, so connection failure is reported instead of falling back to local execution.
The `devices` commands themselves refuse local execution: without an auto-discovered daemon, their JSON error is
`daemon_required` with a startup hint; an explicitly selected unavailable socket reports `daemon_unavailable`.

Other existing dev account commands can still start one-shot live workers. Such a worker can answer a pending link,
then exit and lose the unconfirmed comparison session. Comparison sessions and prompt ids are also lost on a
daemon/worker restart. If an unconfirmed exchange is interrupted, start both daemons and cancel on the new device only if its exchange
is still active; then start a fresh link with a fresh comparison. Already committed links and owed Welcomes retain their existing durable
behavior, so inspect `devices list` before retrying. Restarting does not roll back an approved link.

This dogfood CLI does not expose the existing-device **Not now** action. Do not approve an unwanted request or
mismatching codes; cancel from the requesting/new device or let the exchange expire. `devices link cancel` applies
only to the requesting/new device; it does not dismiss an existing-device prompt.

This CLI also cannot manually dismiss a move's old-sibling recognition hint. A later confirmed link or selected
departure can end the hint automatically; dismissing a hint does not link or remove a device.

`--json` returns the existing state without terminal escaping: `devices list` has `devices[]` with public slot,
label/status, own-device flag and settings; `link` responses have nullable `new_device` and `prompts[]` with flat
`state` strings. Comparing states include `code[]` objects with `emoji`/`description`; prompts include their opaque
`prompt_id`. Keep comparison codes in the user-facing response, not logs or transcripts.

Local CLI regression tests are not the D66 two-device/VM-and-real-relay acceptance test. Use fresh dedicated test
identities for that separate exercise; VM/device provisioning is manual, not a CLI function. `logout` currently discards
the local account; it is not the shared-runtime sibling sign-out/wipe protocol and must not be used as evidence that
other devices removed it. No new storage migration or background scheduler is introduced by these commands.

## Daemon

`wn daemon start` launches `wnd` in the background for the selected home. The daemon owns the Unix socket, writes
`dev/wnd.pid`, appends startup errors to `dev/wnd.log`, and hosts one `MarmotAppRuntime`. The runtime keeps long-lived
relay subscriptions for local signing accounts using the daemon's discovery and account-relay defaults, and updates them
automatically after identity, group, and message mutations forwarded through it.

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

- `wn daemon start` returns once it knows how the `wnd` it launched turned out. It prints `daemon started` when that
  daemon reports its accounts open, or `daemon already running` when another daemon answers on the socket first; both
  exit 0. If the daemon exits first, the command fails at once with JSON error code `daemon_start_failed`, the log
  path, and the log's last lines. If the daemon is still running but not ready after 60 seconds, the command stops it
  and fails with `daemon_start_timeout`. Ctrl-C stops it too and fails with `daemon_start_interrupted`. A failed start
  never leaves its newly spawned daemon running. The 60 seconds cover the runtime's 45-second budget for opening
  accounts, and macOS can hold the first launch of a newly installed `wnd` for several seconds before it runs.
- Before spawning, `wn daemon start` gives an existing socket up to 60 seconds to answer its readiness probe. If the
  peer does not complete its reply, the command fails with `daemon_unavailable`, preserves that socket, and starts no
  competing daemon. Direct `wnd` startup uses the same 60-second budget to check an existing socket and also preserves
  it on timeout; only a refused connection or a missing socket is treated as stale.
- `wn daemon stop` prints `daemon stopped` only once the daemon process has exited. The daemon answers the request
  before it shuts down its runtime, which can wait on relays; if it is still running 30 seconds later, the command
  fails with `daemon_stop_timeout` and names its pid, and leaves it to finish shutting down.
- When a daemon socket exists for a home, normal `wn --home <path> ...` commands are forwarded to it. `wn daemon status`
  and `wn daemon stop` handle daemon access directly. Use `--socket` or `WN_SOCKET` to target a specific
  daemon.
- `wnd` answers on its socket as soon as it binds it, before it has opened its accounts, which the runtime allows 45
  seconds. Meanwhile `wn daemon status` prints `daemon starting` (`"starting": true` in `--json`), `wn daemon stop`
  stops it, and other commands wait until the accounts are open.
- `wn daemon status --json` includes `device_groups` (false when that `wnd` runs with `WN_DEVICE_GROUPS=0`),
  `last_runtime_activity`, and a redacted `relay_health`
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

### Two-terminal live subscription demo

Terminal 1 owns the daemon and the live subscription:

```sh
just relay-up

export WN_HOME="$PWD/dev/data/subscription-demo"
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

Terminal 2 creates Alice and Bob and sends a message:

```sh
export WN_HOME="$PWD/dev/data/subscription-demo"
export WN_SECRET_STORE=file
export WN_ALLOW_LOOPBACK_RELAYS=1   # loopback relays are dev/test only; unset in production
unset WN_SOCKET

ALICE=$(wn --json create-identity | jq -r '.result.account_id')
BOB=$(wn --json create-identity | jq -r '.result.account_id')

GROUP=$(wn --account "$ALICE" --json groups create agent "$BOB" | jq -r '.result.group_id')
wn --account "$ALICE" messages send "$GROUP" "hello bob"
```

Terminal 1 should print the typed `message` line in real time.

## JSON output

Pass `--json` for machine-readable output. Success responses wrap command data in a stable result envelope. Errors use
snake_case `error.code` values and include repair fields when the CLI can name the next command. Scripts and the daemon
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
