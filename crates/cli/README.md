# wn

`wn` is the command-line app for the White Noise/Marmot stack. It manages Nostr-keyed accounts, relay
lists, KeyPackages, chats, groups, messages, local projections, live runtime subscriptions, and the terminal UI.

The crate builds two binaries:

- `wn`: the user-facing CLI and TUI entrypoint.
- `wnd`: the background daemon used by `wn daemon start`.

`wn` uses `marmot-account` for account homes and secret storage, and `marmot-app` for the runtime bridge,
transport setup, group projection, message projection, and Nostr directory refresh.

The source directory is `crates/cli`. The Cargo package name remains `wn-cli`, and the installed
commands remain `wn` and `wnd`.

## Install From This Checkout

Install both binaries into your local Cargo bin directory:

```sh
cargo install --path crates/cli --locked --bins
```

Make sure `~/.cargo/bin` is on `PATH`, then check the installed commands:

```sh
wn --help
wnd --help
```

For source-checkout work without installing:

```sh
cargo run -p wn-cli --bin wn -- --help
cargo run -p wn-cli --bin wnd -- --help
```

For isolated development runs, keep the home and secret store explicit:

```sh
export WN_HOME="$(mktemp -d)"
export WN_SECRET_STORE=file
```

The default secret store is the platform keychain. Use `WN_SECRET_STORE=file` only for local development,
tests, and disposable homes.

## Configuration

Common options can be passed as flags or environment variables:

- `--home <path>` or `WN_HOME`: account home, projections, daemon socket, pid, and log.
- `--account <npub-or-hex>` or `WN_ACCOUNT`: selected local signing account for account-scoped commands.
- `--socket <path>` or `WN_SOCKET`: daemon socket. The default is `$WN_HOME/dev/wnd.sock`.
- `--secret-store keychain|file` or `WN_SECRET_STORE`: signing-key backend.
- `--keychain-service <name>` or `WN_KEYCHAIN_SERVICE`: keychain service name.
- `--json`: return a stable JSON envelope for scripts, the TUI, and daemon forwarding.

For local development against a loopback Blossom server, set `WN_ALLOW_LOOPBACK_BLOB_ENDPOINTS=1`. By default `wn`
refuses to upload to or download from `http://127.0.0.1`-style blob endpoints; production installs leave this unset.

Likewise, to talk to a loopback relay (the local Compose stack, or an in-process relay), set `WN_ALLOW_LOOPBACK_RELAYS=1`.
By default `wn`/`wnd` refuse to open a socket to a `ws://127.0.0.1`-style (or any non-public) relay host, so the
loopback-relay examples below assume this is exported; production installs leave it unset. This admits loopback only —
private/link-local/CGNAT relay hosts stay rejected either way.

The default home is `WN_HOME` when set. Without `WN_HOME`, `wn` uses the platform user data directory:

- macOS: `~/Library/Application Support/whitenoise`
- Linux and other non-macOS Unix: `$XDG_DATA_HOME/whitenoise`, or `~/.local/share/whitenoise`
- Windows: `%APPDATA%\whitenoise`

## Quick Start

Create two local signing identities, create a chat as Alice, and let Bob receive it through the daemon.
The examples use the repo-owned `dev/data` tree so local state is easy to inspect and delete:

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

Most account-scoped commands resolve the account in this order:

1. `--account <npub-or-hex>`
2. `WN_ACCOUNT`
3. the only account, when exactly one exists — whether or not it can sign; a public-only account is still selected
   here, and commands that require signing then fail with an explicit error

Public-only identities can be added with `wn login <npub-or-hex>`. They are useful for relay-list
and KeyPackage lookup, but cannot sign, publish KeyPackages, sync groups, or send messages.

## Command Map

Identity and account commands:

```sh
wn create-identity
printf '%s\n' "$NSEC" | wn login --nsec-stdin
printf '%s\n' "$NSEC" | wn login --nsec-stdin --relay <relay-url>
wn login <npub-or-hex>
wn whoami
wn logout <npub-or-hex>
wn export-nsec <npub-or-hex>
wn accounts list
wn account list
wn account status [npub-or-hex]
wn account relay-lists [npub-or-hex] --bootstrap-relays <relay-url>
```

The older `wn account create` spelling is kept as a compatibility/repair surface, but new setup flows should use
`wn create-identity` or `wn login`.

When a daemon is running, `create-identity` and `wn login --nsec-stdin` use the daemon's account-relay defaults to
publish the required relay lists and an initial KeyPackage. `printf '%s\n' "$NSEC" | wn login --nsec-stdin --relay
<url>` is the command-local fallback for a custom relay-list publish during import. Public `npub` logins only check
relay-list availability because they cannot sign.
`export-nsec` is present for command-shape compatibility but returns `private_key_export_disabled`; this CLI does not
print private keys.

KeyPackage commands:

```sh
wn --account <npub-or-hex> keys list
wn --account <npub-or-hex> keys publish
wn --account <npub-or-hex> keys rotate
wn keys fetch <npub-or-hex> --bootstrap-relays <relay-url>
wn keys check <npub-or-hex>
wn --account <npub-or-hex> keys delete <event-id>
wn --account <npub-or-hex> keys delete-all --confirm
```

`keys publish` republishes the currently cached KeyPackage; `keys rotate` (alias `force-publish`) force-mints and
publishes a fresh replacement KeyPackage.

KeyPackage publish/fetch/check/list use the current relay-directory path. `keys list` returns the relay event id for
each known KeyPackage record. `keys delete` publishes a Nostr deletion for one event id, and `keys delete-all
--confirm` publishes deletions for every relay-published KeyPackage record found for the selected account.

Chat projection commands:

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
wn --account <npub-or-hex> chats mark-read <group-hex>
wn --account <npub-or-hex> chats mark-read <group-hex> <message-id-hex>
```

Each `chats list`, `chats list-archived`, and `chats subscribe`/`subscribe-archived` row carries the group
record plus a per-chat projection so a chat list can render unread badges and a last-message preview without a
second query: `unread_count` (number), `has_unread` (bool), `last_message` (the last chat message as
`{ message_id_hex, sender, sender_display_name, plaintext, kind, timeline_at, deleted }`, or `null`), and the
`last_read_message_id_hex` / `last_read_timeline_at` read marker (either may be `null`). These keys use the same
names and `last_message` shape as the `chat_list_row` object on the `messages timeline subscribe` feed, so both
feeds agree. A chat with no messages or reads yet reports empty defaults (`0` / `false` / `null`) rather than
omitting the keys.

On the `chats subscribe`/`subscribe-archived` feeds these projection keys refresh only when the feed emits a
row, and the feed emits on group-state changes (create, rename, archive/unarchive, membership) — not on every
new message or read. So the unread count and last-message preview on a subscribed row are a point-in-time
snapshot taken at the last group-state emit, and live unread/last-message deltas ride the
`messages timeline subscribe` feed's `chat_list_row` object instead. `chats mark-read` returns the refreshed
projection directly in its own response.

`chats mark-read <group-hex> [<message-id-hex>]` advances the chat's read marker and clears its unread count.
With no message id it marks the newest message read (the "clear on chat open" case); with an explicit message id
it marks read up to that message. The read marker is a forward-only high-water mark, so marking an older message
leaves any newer ones unread and re-marking never moves it backward; an empty chat is a no-op success. A
`<message-id-hex>` that is not a kind-9 chat message in the chat — foreign, non-existent, or a different event
kind — likewise leaves the marker untouched and returns the current projection as success, the same silent
contract as `messages react`/`delete` with unknown ids. It returns
`account_id`, `npub`, `group_id`, and the same five projection keys as the `chats list` rows
(`unread_count`, `has_unread`, `last_message`, `last_read_message_id_hex`, `last_read_timeline_at`).

Group commands:

```sh
wn --account <npub-or-hex> groups list
wn --account <npub-or-hex> groups create <name> [member-npub-or-hex ...] [--description <description>]
wn --account <npub-or-hex> groups show <group-hex>
wn --account <npub-or-hex> groups add-members <group-hex> <member-npub-or-hex> [...]
wn --account <npub-or-hex> groups remove-members <group-hex> <member-npub-or-hex> [...]
wn --account <npub-or-hex> groups members <group-hex>
wn --account <npub-or-hex> groups admins <group-hex>
wn --account <npub-or-hex> groups relays <group-hex>
wn --account <npub-or-hex> groups invites
wn --account <npub-or-hex> groups accept <group-hex>
wn --account <npub-or-hex> groups decline <group-hex>
wn --account <npub-or-hex> groups leave <group-hex>
wn --account <npub-or-hex> groups rename <group-hex> <name>
wn --account <npub-or-hex> groups set-avatar-url <group-hex> --url <https-url> [--dim <WxH>] [--thumbhash <hex>]
wn --account <npub-or-hex> groups set-avatar-url <group-hex> --clear
wn --account <npub-or-hex> groups promote <group-hex> <member-npub-or-hex>
wn --account <npub-or-hex> groups demote <group-hex> <member-npub-or-hex>
wn --account <npub-or-hex> groups self-demote <group-hex>
wn --account <npub-or-hex> groups subscribe-state <group-hex>

wn --account <npub-or-hex> group create <name> [member-npub-or-hex ...]
wn --account <npub-or-hex> group members <group-hex>
wn --account <npub-or-hex> group invite <group-hex> <member-npub-or-hex> [...]
wn --account <npub-or-hex> group remove <group-hex> <member-npub-or-hex> [...]
wn --account <npub-or-hex> group update <group-hex> --name <name>
wn --account <npub-or-hex> group update <group-hex> --description <description>
wn --account <npub-or-hex> group set-avatar-url <group-hex> --url <https-url> [--dim <WxH>] [--thumbhash <hex>]
wn --account <npub-or-hex> group set-avatar-url <group-hex> --clear
```

Message commands:

```sh
wn --account <npub-or-hex> messages send <group-hex> "hello"
wn --account <npub-or-hex> messages send --group <group-hex> "--text that starts with a dash"
wn --account <npub-or-hex> messages send --group <group-hex> --reply-to <message-id> "replying to you"
wn --account <npub-or-hex> messages list
wn --account <npub-or-hex> messages list <group-hex> --limit 20
wn --account <npub-or-hex> messages list <group-hex> --before <unix-seconds> --before-message-id <event-id>
wn --account <npub-or-hex> messages list <group-hex> --after <unix-seconds> --after-message-id <event-id>
wn --account <npub-or-hex> messages search <group-hex> <query> --limit 20
wn --account <npub-or-hex> messages search-all <query> --limit 20
wn --account <npub-or-hex> messages react <group-hex> <message-id> +
wn --account <npub-or-hex> messages unreact <group-hex> <message-id>
wn --account <npub-or-hex> messages delete <group-hex> <message-id>
wn --account <npub-or-hex> messages retry <group-hex> <event-id>
wn --account <npub-or-hex> messages subscribe <group-hex> --limit 50
wn --account <npub-or-hex> messages timeline list <group-hex> --limit 20
wn --account <npub-or-hex> messages timeline search <group-hex> <query> --limit 20
wn --account <npub-or-hex> messages timeline subscribe <group-hex>
```

`messages send --reply-to <message-id>` sends the text as a reply to an existing message. It uses the same wire
format other Marmot clients produce, so recipients see the row with its reply reference and a hydrated reply preview
of the parent. Pass the group with `--group` and put `--reply-to` before the text when replying: the message text uses
hyphen-tolerant parsing, so a `--reply-to` placed after the text (in either the positional-group or the `--group`
form, and in either spelling: `--reply-to <id>` or `--reply-to=<id>`) is read as literal text rather than as the flag.
Instead of silently sending that stray `--reply-to` as part of the body, the CLI rejects the mis-ordering with a clear
error (code `reply_to_after_message_text`) so it fails loudly. The tradeoff: the guard rejects any message whose text
contains a bare `--reply-to` or `--reply-to=<id>` token anywhere (e.g. `hello --reply-to friend`), so such text can no
longer be sent this way. The parent id is not required to
exist locally; a reply to a message you have not yet synced is still sent (its preview hydrates once the parent
arrives). The JSON response is the same shape as a plain send.

The `messages timeline` subcommands list, search, and subscribe to the materialized message timeline (the projection
that interleaves messages, media, and agent-stream anchors/finals in conversation order).

Projected history is ordered by recorded message time first, then local receipt/insertion order. That keeps synced
stream anchors and final markers in conversation order instead of relay catch-up order.

`messages subscribe`, `chats subscribe`, and `groups subscribe-state` require `wnd`. With `--json`, they print
newline-delimited stream responses as they arrive. Each response has a typed `result.type`; normal app messages use
`message`, reactions use `reaction`, deletions use `message_delete`, media references use `media`, durable agent stream
anchors/finals use `agent_stream_start` and `agent_stream_final`, live brokered QUIC chunks use `agent_stream_delta`,
runtime-owned QUIC preview summaries use `stream_preview`, chat rows use `chat`, and group state rows use `group_state`.

Media commands:

```sh
wn --account <npub-or-hex> media list <group-hex>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --send --message <caption>
wn --account <npub-or-hex> media upload <group-hex> <file-path> --server https://blossom.divine.video
wn --account <npub-or-hex> media download <group-hex> <file-hash> --output ./file.jpg
```

`media upload` encrypts the file with the group's current `MLS-Exporter("marmot", "encrypted-media", 32)` media secret,
uploads the ciphertext to Blossom, and optionally sends a kind-9 media message. Because the encrypted bytes are opaque,
the server must accept `application/octet-stream` uploads. Without `--server`, the upload targets the ordered endpoints
in the group's `marmot.group.encrypted-media.v1` component. Newly created groups use MDK's ciphertext-compatible
built-in endpoint list unless the application was compiled with `MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS`.

Endpoint policy is signed group state. Upgrading MDK changes the defaults for new groups only; an active group admin must
call `replace_encrypted_media_blob_endpoints` to migrate an existing group whose embedded endpoints reject encrypted
blobs.
Upload JSON returns an `attachments` array with each attachment's `plaintext_sha256`, `ciphertext_sha256`, and locators.
`media download` resolves a projected media reference by plaintext hash, fetches the encrypted blob, verifies it,
decrypts it, and writes the plaintext file.

Other Whitenoise-shaped commands:

```sh
wn --account <npub-or-hex> debug health
wn debug relay-control-state
wn --account <npub-or-hex> follows list
wn --account <npub-or-hex> follows add <npub-or-hex>
wn --account <npub-or-hex> follows remove <npub-or-hex>
wn --account <npub-or-hex> follows check <npub-or-hex>
wn --account <npub-or-hex> profile show
wn --account <npub-or-hex> profile update --name <name> --about <text>
wn --account <npub-or-hex> relays list --type nip65
wn --account <npub-or-hex> relays add <relay-url> --type inbox
wn --account <npub-or-hex> relays remove <relay-url> --type inbox
wn settings show
wn settings theme dark
wn settings language en
wn users show <npub-or-hex>
wn users search <query> --radius 0..2
wn notifications subscribe
wn relay-stats
wn relay-stats --json
wn reset --confirm
```

`wn relay-stats` prints device-local relay performance telemetry — aggregate lifecycle counters, cross-relay arrival
spread, per-relay first-deliverer and first-event/EOSE timing, and redacted relay health. It reads the live `wnd`
runtime when a daemon socket exists. The numbers are aggregate-only and per-relay rows use opaque device-local indices,
never relay URLs.

`groups invites` lists groups still awaiting local confirmation; `groups accept` clears that pending state, and
`groups decline` leaves and archives the auto-joined pending group. `notifications subscribe` streams daemon-backed
local notification updates as JSON lines. `chats mute` and `chats unmute` control local per-chat notification
suppression; mute durations accept `s`, `m`, `h`, `d`, or `w` suffixes, plus `forever`.

Agent text stream preview commands:

```sh
marmot-quic-broker --bind 127.0.0.1:4450
wn --account <npub-or-hex> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450
wn --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local
wn --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local --background
wn stream send --broker --connect 127.0.0.1:4450 --insecure-local \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> "hello over quic"
wn stream send --connect <host:port> --server-name <dns-name> "hello over quic"
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

`stream start` and `stream finish` send typed payloads through the normal encrypted Marmot message path. Brokered
starts include concrete `quic://host:port` candidates for that stream. `stream watch` reads the durable start payload,
subscribes to the broker candidate, and prints the provisional text preview plus transcript hash. `stream send --broker`
publishes ordered `TextDelta` records through the memory-only broker. Without `--broker`, `stream send` still connects
directly to a peer receiver, which is useful with `wn stream receive --bind 127.0.0.1:4450` for local transport probes.
`stream verify` compares a received QUIC transcript hash and chunk count against the latest durable final payload for the
same stream id. QUIC chunks are transient preview data; normal Marmot messages remain the durable group history. Use
`quic://quic-broker.ipf.dev:4450` with platform trust for the shared production broker, and use `--insecure-local` only
for loopback development with generated self-signed certificates.

When `wnd` is running, `stream watch --background` starts the broker subscription through the daemon and returns
immediately. The runtime stream manager owns the running/completed/failed preview state. `wn daemon status --json`
includes that state under `stream_watches`, including received preview text and transcript hash after the brokered stream
arrives. The same preview state is emitted as typed `stream_preview` updates from `wn messages subscribe <group-hex>`,
while individual broker chunks arrive as `agent_stream_delta` updates.

`stream compose-open`, `stream compose-append`, `stream compose-finish`, and `stream compose-cancel` are the
daemon-owned live composer used by the TUI and agent connectors. They require `wnd`: opening a session publishes the
durable stream anchor and starts live preview publication, append feeds preview text, finish publishes the durable final
message, and cancel tears down the active session without faking a final marker.

Sync command:

```sh
wn --account <npub-or-hex> sync
```

`sync` is a diagnostic and repair command. Normal daemon-backed chat, group, and stream flows use runtime
subscriptions and should not need a manual sync step.

## Daemon

`wn daemon start` launches `wnd` in the background for the selected home. The daemon owns the Unix socket,
writes `dev/wnd.pid`, appends startup errors to `dev/wnd.log`, and hosts one `MarmotAppRuntime`. The runtime keeps
long-lived relay subscriptions for local signing accounts using the daemon's discovery and account-relay defaults.
Commands forwarded through the daemon update runtime subscription state automatically after identity, group, message,
and stream mutations.

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

`wn daemon status --json` includes `last_runtime_activity` for the TUI plus a redacted `relay_health` object with
aggregate relay counts and connection status buckets. It does not include relay URLs, account ids, group ids,
subscription ids, or message ids.

When a daemon socket exists for a home, normal `wn --home <path> ...` commands are forwarded to that
daemon. `wn daemon status`, `wn daemon stop`, and `wn tui` handle daemon access directly.
Background stream watches started with `wn stream watch --background` are launched by the daemon and tracked by the
runtime stream manager. Long-lived subscriptions use the daemon socket directly:

```sh
wn --account <npub-or-hex> messages subscribe <group-hex> --limit 50
wn --account <npub-or-hex> chats subscribe
wn --account <npub-or-hex> groups subscribe-state <group-hex>
```

Use `--socket` or `WN_SOCKET` to target a specific daemon. Use `wnd` directly when a process supervisor
should own the daemon lifecycle:

```sh
wnd --home "$WN_HOME" \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777
```

### Two-Terminal Local Stream Demo

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

Terminal 2 creates Alice/Bob, starts the durable stream, and sends live broker chunks:

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

`wn tui` is a Ratatui interface over the real `wn --json` command surface. It opens on a login screen when it has
no single obvious account, then drops into a chat-first main view: the chat list on the left, the materialized
message timeline on the right (with reactions, reply context, deletion tombstones, and inline images as cell-exact
half-blocks on image-capable terminals, with `[img name]`/`[file name]` placeholders otherwise), the composer below
them, and a one-line hints bar plus a one-line status bar at the bottom.

```sh
wn tui
```

Startup routes by how many local accounts exist: no accounts open the login menu (create an identity or log in
with an nsec), exactly one drops straight into the main view, and several open an account picker. An explicit
`--account <npub-or-hex>` (or `WN_ACCOUNT`) that resolves to a loaded account enters the main view directly with
that account, even when several accounts exist. The main view no
longer has an always-visible accounts panel; press `A` from the chat list to reopen the account picker, or use the
`/account`, `/login`, and `/create-identity` slash commands.

First run without any relay configuration would otherwise dead-end, because creating an identity and starting the
daemon both need relays. Pass them to `wn tui` and they are forwarded to the daemon-start and account-setup child
commands:

```sh
wn tui \
  --discovery-relays wss://relay.discovery.example \
  --default-account-relays wss://relay.one.example,wss://relay.two.example
```

When a daemon is running for the same home, TUI child commands use the daemon socket. The status bar shows daemon
state. While the daemon is running, the TUI attaches to daemon-backed runtime subscriptions for live message, chat, and
group-state changes, and refreshes snapshots when the composer is idle.

Login screen controls:

- Menu (no accounts): `c` create a new identity, `l` log in with an nsec, `q` quit.
- Account picker (several accounts): `j`/`k` or arrows move the selection; `Enter` selects the account and enters
  the main view; `c` create; `l` nsec login; `Esc` returns to the main view when one is already active; `q` quit.
- Nsec entry: type or paste the nsec (rendered masked); `Enter` submits it over stdin; `Esc` cancels.

Main view controls:

- `Tab`/`BackTab`: cycle the chat list, messages, and composer.
- Chats: `j`/`k` or arrows move the selection; `Enter` opens the chat and focuses the messages pane; `g` opens the
  group-detail screen for the selected chat; `s` opens user search; `p` opens your profile; `h` opens the relay-health
  screen; `I` opens the pending-invites picker; `A` reopens the
  account picker. Each row shows an unread badge (bold name plus `(N)`) and a dark-gray last-message preview (sender
  plus truncated text), and the list orders by last activity, newest first. The badge and the status bar's unread
  total come from the runtime's per-chat projection (`chats list`), so they survive a restart rather than being
  counted in the TUI. Opening a chat clears its badge immediately (via `chats mark-read`); a chat you are viewing
  updates its badge and preview live from the timeline feed, and other chats refresh from a background
  `notifications subscribe` feed (a debounced `chats list` re-read on each new message elsewhere). A group invite
  surfaces as a one-line status notice that prompts `I` to open the invites picker. A background refresh never moves the highlight off the chat you have
  selected. These ambient updates require a running `wnd`: without a daemon, off-screen badges and previews
  update only when you manually refresh (`/refresh`) or re-open the chat. The badge and unread total still
  survive a restart either way, since they come from the runtime's durable `chats list` projection.
- Messages: `j`/`k` or arrows move the message selection; `PageUp`/`PageDown` page; `G`/`End` jump to the newest
  message (and pin to the bottom), `g`/`Home` to the oldest. New messages stay pinned to the bottom while you are at
  the newest message and hold your position when you have scrolled up. Scrolling past the oldest loaded message loads
  the previous page of history. `i` or `Enter` focuses the composer.
- Messages, on the selected message: `r` reacts (it prefills `/react` followed by a space in the composer, so
  `Enter` sends the default
  `+` and typing an emoji first customizes it); `u` removes your own reaction immediately; `d` deletes your own
  message (it prefills `/delete`, so `Enter` is the visible confirmation); `R` replies (it prefills `/reply`
  followed by a space and
  shows the reply target on the status line, so you type the reply and `Enter` sends it). Counts update live in both
  directions from the timeline projection; the list is not reloaded, and a sent reply upserts optimistically the same
  way a plain send does. The `r`, `d`, and `R` prefills are skipped when the composer already holds a draft, so an
  in-progress message is never clobbered (a status-line notice explains the skip). While the composer holds one of
  these prefills, the hints line shows a persistent reminder of what `Enter` will do and to which message (for
  example `reacting to <sender>: <preview> — Enter sends the reaction, Esc clears`), recomputed each frame so it stays
  visible until you send or clear; `Esc` clears the armed prefill (pristine or after you have typed into it) as that
  escape hatch, while a hand-typed draft is left intact (use `Ctrl-U` to clear a hand-typed draft). `/react` accepts
  only one emoji — exactly one grapheme cluster carrying a non-ASCII scalar (real emoji, including ZWJ families, skin
  tones, flags, and keycaps), or the NIP-25 `+`/`-` sentinels. Anything else — multi-word prose, plain-ASCII tokens,
  and non-Latin or accented words like `café`, `你好吗`, or `привет` — is refused with a status-line error that names
  the contract and the escape hatch (`reactions are a single emoji (Enter sends the default +); Esc clears`), so typed
  prose is never published as a reaction. These also work as the `/react`,
  `/unreact`, `/delete`, and `/reply <text>` slash commands, which resolve the target at submit and error to the
  status line when no message is selected (and `/delete` when the message is not yours). `/reply` sends
  `messages send --group <loaded-group> --reply-to <selected-message-id> <text>`, keeping `--reply-to` before the
  text as the guard requires. `o` opens the selected message's downloaded image full-size in a dismiss-on-any-key
  viewer (see "Inbound media" below).
- Inbound media: an image attachment renders inline in the message pane as cell-exact half-block glyphs (`▀` colored
  cells) on any image-capable terminal. The rendering is deliberately cell-exact rather than a native pixel image
  (iTerm2/Kitty/Sixel): half-blocks are ordinary colored cells bounded strictly to the reserved block, so an image can
  never overdraw a neighboring message or leave a terminal-side artifact behind when you scroll. Each image is
  downloaded and decoded in the background — never blocking the event loop — and its placeholder walks `[img name]` ->
  `[downloading name...]` -> `[loading name...]` -> the inline image, or `[name failed: err]` on error. A terminal
  with no image capability keeps the `[img name]` placeholder (and non-image attachments always show `[file name]`).
  The `o` full-size viewer uses the same cell-exact rendering. Downloaded files are cached under the TUI home in
  `tui-media-cache/` (a private directory), so passing `--home` keeps the cache with the account data.
- Composer: full cursor editing — `Left`/`Right`/`Home`/`End` move the cursor, `Backspace`/`Delete` remove a
  character, `Ctrl-U` clears the whole composer (a readline kill-line that empties it whatever it holds — armed prefill
  or hand-typed draft), and mid-string edits keep multi-byte characters intact. `Enter` submits; there is no keyboard
  newline, so multi-line content only arrives by paste. The composer auto-grows with its wrapped content (up to 8
  rows), taking the space from the messages pane.
- `?`: open the help popup.
- `Esc`: clear an armed message-interaction prefill (`/react`, `/reply`, or `/delete`, whether untouched or after you
  have typed into it); a hand-typed draft is left intact so `Esc` never destroys text you wrote — use `Ctrl-U` to
  clear a hand-typed draft. With a popup open, `Esc` closes it.
- `Ctrl-U`: clear the whole composer (readline kill-line), whatever it holds. Also clears the masked nsec-entry field.
- `Ctrl-C`: quit.

Popups are modal: while one is open it captures every key and the screen behind it is inert. A text-entry popup
submits on `Enter` (when non-empty) and cancels on `Esc`; a confirm popup takes `y`/`Enter` or `n`/`Esc`; a list
picker moves with `j`/`k` and closes on `Esc`; and dismiss-on-any-key cards (help, info, errors) close on the next
key. Because the help card is a popup, `q` under it closes the card instead of quitting.

Group detail (`g` from the chat list) shows the selected group's members with admin badges (and a `(you)` marker),
its relay hints, and its name and description; `Esc` returns to the main view. Its keys: `j`/`k` move the member
selection; `A` adds a member by npub/hex (text popup → `groups add-members`); `x` removes the selected member
(confirm → `groups remove-members`); `P` promotes the selected member to admin (confirm → `groups promote`); `R`
renames the group (text popup prefilled with the current name → `groups rename`); `L` leaves the group. An admin
cannot leave: `L` shows a "Cannot Leave Group" info card (sole admins are told to promote another member first,
co-admins to step down as admin), while a non-admin gets a confirm popup (→ `groups leave`) and, on success, the
chat leaves the list and the view returns to the main screen. `I` opens the invites picker from here too.

Invites (`I` from the chat list or group detail) opens a picker of pending invites (`groups invites`): `a` or
`Enter` accepts the highlighted invite (`groups accept`) and opens the newly joined chat, `d` declines it
(`groups decline`), and `Esc` closes the picker. The picker stays open across actions, refolding the refreshed
list after each accept or decline and closing only once no invites remain; accepting from the group-detail screen
returns to the main view. With no pending invites it shows an info card instead.

User search (`s` from the chat list, or `/users [query]`) is a one-shot search over the cached follow-graph directory
(`users search`, default radius `0..2`). The screen has two regions and a two-state focus: in query focus you type the
query (so `j`/`k` are literal text) and `Enter` runs the search; once there are results, focus moves to the list where
`j`/`k` (or arrows) navigate, `Enter` opens the selected user's profile card (`users show`, dismiss-on-any-key), `c`
starts a new chat with them (a text popup names it, then `group create`), and `a` adds them to an existing chat: a
group picker lists your chats (`j`/`k` move, `Enter` picks, `Esc` closes without side effects), preselecting the open
chat when one is loaded, and `Enter` opens the confirm popup that guards the add (`groups add-members`), naming both
the user and the chosen chat. With no chats a status notice explains and points at `c`. `i` returns to the query, and
`Esc` returns to the main view. Result rows show the display name/name, a shortened npub, and the `matched_field · match_quality · radius`
attribution the search returns.

Profile (`p` from the chat list) shows your own profile — name, display name, about, picture URL (as literal text; no
avatar is fetched), nip05, lud16, and npub — from `profile show`, plus your follows from `follows list`. `j`/`k` move a
single cursor over the six fields then the follows; `Enter` on a field opens a text popup prefilled with the current
value and, on submit, publishes only that one field (`profile update --<field>`, which merges over the current profile
so the other fields survive); `f` follows a user by npub/hex (`follows add`), and `x` unfollows the selected follow
(confirm → `follows remove`). There is no nsec export anywhere. `Esc` returns to the main view.

Relay health (`h` from the chat list) is a redacted, device-local telemetry dashboard from `relay-stats` (which reads
the live `wnd` runtime when a socket exists and a fresh in-process read otherwise, so it always renders something —
the header notes the daemon state). It shows the connection-health summary, lifecycle counters, cross-relay delivery
spread (with p50/p99 derived from the fixed-bucket histograms, honest about `n/a` and `>Nms` overflow), subscription
first-event/EOSE sync timing, and per-relay first-deliverer and timing rows keyed by an opaque device-local index.
Per privacy decision, no relay URLs appear anywhere on this screen. `r` refreshes, `j`/`k` and PageUp/PageDown scroll,
and `Esc` returns to the main view.

Group MLS/component diagnostics are hidden by default; `/diagnostics` toggles a diagnostics panel between the
messages pane and the composer.

Composer slash commands:

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
/stream [--stream-id <hex>] [--quic-candidate <quic-url>]
/stream start [--stream-id <hex>] --quic-candidate <quic-url>
/stream watch [--stream-id <hex>] [--insecure-local]
/stream status
/stream finish <stream-id> <transcript-hash> <chunk-count> <text>
/stream verify <stream-id> <transcript-hash> [chunk-count]
/quit
```

`/stream` uses `quic://quic-broker.ipf.dev:4450` when no candidate is supplied.

`/logout` acts on the currently selected account and is always confirmed first. `wn logout` is destructive: it
permanently removes that account's local data (messages, group membership, and MLS state) from this device, and for a
local-signing account it deletes the signing key too, so the confirmation says so plainly, never softens the wording,
and always shows the account npub so it is unambiguous which account is destroyed. A local-signing logout is
irreversible, so its confirmation requires typing the literal word `logout` and pressing `Enter`; an empty or
mismatched entry keeps the popup open (so the wipe is never reachable by a stray Enter-then-Enter) and `Esc` cancels. A
public-only account is re-addable, so it keeps the lighter `y`/`Enter` confirm (`n` or `Esc` cancels). On confirmation
the account list reloads; if the removed account was the last one, the TUI returns to the login menu rather than
pointing at a removed account.

`/login <nsec>` redacts the secret in the composer and pipes it to the child `wn` process over stdin instead of argv.
`/chat archived` shows archived chats so they can be selected and unarchived; `/chat archived off` returns to the
visible-chat list. Member commands operate on the selected chat and call the same group membership commands exposed by
the CLI.
`/react`, `/unreact`, and `/delete` operate on the selected message in the messages pane and call the real
`messages react|unreact|delete` commands; `/react` defaults to the `+` emoji. `/react` also guards its content: it is a
single emoji or the `+` default, so content with whitespace, plain ASCII text, or too long for one emoji is rejected
with a status-line error rather than published as a reaction (the guard lives in the TUI; the `messages react` CLI
command stays protocol-faithful). On success they only update the status
line — the timeline projection folds the reaction or tombstone into the existing row, so the list is not reloaded.
`/retry <event-id>` retries a failed outbound event by id; it takes the id as an argument rather than acting on the
selected message, because timeline rows do not carry per-message failed-send state to target from.
`/image` uses the real encrypted media path (`wn media upload <group> <file> --send`) and sends the optional caption
as the media message text; it does not send plaintext file paths or placeholder messages.
Stream commands operate on the selected chat. `/stream watch` starts a daemon background watch and completed previews
appear as provisional preview rows in the message panel. `/stream` opens the TUI stream composer, publishes the stream
anchor, starts the receiver watch through the daemon, and then treats the next submitted composer line as the streamed
text to finish.
There is no `/sync` slash command in the TUI; it rejects `/sync` because live updates come from subscriptions. Explicit
catch-up is the CLI-only `wn sync` command, used as a diagnostic/repair escape hatch outside the TUI.

## JSON Output

Pass `--json` for machine-readable output. Success responses wrap command data in a stable result envelope.
Errors use snake_case `error.code` values and include repair fields when the CLI can name the next command.

The TUI and daemon both depend on the JSON shape, so treat response changes as API changes.

## Changelog

Release notes for the CLI crate live in [`CHANGELOG.md`](CHANGELOG.md). Update it for user-facing CLI,
daemon, TUI, JSON, install, or packaging changes.

## Packaging Direction

Local development should keep using:

```sh
cargo install --path crates/cli --locked --bins
```

For public releases, Homebrew is the right first-class installer. Use the namespaced tap:

```sh
brew install marmot-protocol/tap/wn
```

The tap formula lives in `github.com/marmot-protocol/homebrew-tap` and installs both `wn` and `wnd` from `crates/cli`.
Once release CI exists, the tap can publish bottles for macOS and Linux so users do not pay the full Rust build cost.
The project-side release checklist lives at `docs/release/wn-homebrew.md`.

While `marmot-protocol/mdk` is private, Homebrew source builds require GitHub access to the source repo. Public
tarball installs can replace that once the source repo is public or release assets are published somewhere installers can
download.

`cargo install --git ssh://git@github.com/marmot-protocol/mdk.git wn-cli --locked --bins` is a useful
source install path for engineers and automation.

`cargo install wn-cli` from crates.io is a later option. The workspace currently has
`publish = false`, and the CLI depends on local workspace crates. Publishing there needs a separate crate
publication plan or a split packaging crate.
