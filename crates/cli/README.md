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
`export-nsec` is present for command-shape compatibility but returns `unsupported_command`; this CLI does not print
private keys.

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

KeyPackage publish/fetch/check/list use the current relay-directory path. KeyPackage deletion commands (`keys delete`,
`keys delete-all`) are present but return `unsupported_command` until Nostr deletion is wired through the app runtime.

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
```

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
wn --account <npub-or-hex> media upload <group-hex> <file-path> --server https://blossom.primal.net
wn --account <npub-or-hex> media download <group-hex> <file-hash> --output ./file.jpg
```

`media upload` encrypts the file with the group's current `MLS-Exporter("marmot", "encrypted-media", 32)` media secret,
uploads the ciphertext to Blossom, and optionally sends a kind-9 media message. Without `--server`, the upload targets
the endpoints in the group's `marmot.group.encrypted-media.v1` component (`https://blossom.primal.net` is the endpoint
baked into newly created groups' component, not a hardcoded CLI default).
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
wn relay-stats
wn relay-stats --json
wn reset --confirm
```

`wn relay-stats` prints device-local relay performance telemetry — aggregate lifecycle counters, cross-relay arrival
spread, per-relay first-deliverer and first-event/EOSE timing, and redacted relay health. It reads the live `wnd`
runtime when a daemon socket exists. The numbers are aggregate-only and per-relay rows use opaque device-local indices,
never relay URLs.

`notifications subscribe`, chat mute/unmute, and user-driven invite accept/decline commands currently return
`unsupported_command` rather than faking behavior.

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

`wn tui` is a Ratatui interface over the real `wn --json` command surface. It lists local accounts, shows
visible chats for the selected local signing account, renders recent messages, sends messages from a composer, and
keeps the latest status plus selected-chat MLS/component state in a status panel below the composer.

```sh
wn tui
```

When a daemon is running for the same home, TUI child commands use the daemon socket. The header shows daemon
state. While the daemon is running, the TUI attaches to daemon-backed runtime subscriptions for live message, chat, and
group-state changes, and refreshes snapshots when the composer is idle.

Controls:

- `Tab`: cycle accounts, chats, and composer.
- Arrow keys or `j`/`k`: move the selected account or chat.
- `Enter`: select the highlighted account/chat or submit the composer.
- `?`: open help.
- `Esc`: clear help or input.
- `Ctrl-C`: quit.

Composer slash commands:

```text
/help
/refresh
/account <npub-or-hex>
/create-identity
/login <nsec-or-npub>
/daemon status
/daemon start
/daemon stop
/chat new <name> [member-npub-or-hex ...]
/chat rename <name>
/chat describe <description>
/chat archive
/chat unarchive
/chat archived [on|off]
/members add <npub-or-hex> [...]
/members remove <npub-or-hex> [...]
/members list
/keys fetch <npub-or-hex>
/keys rotate
/name <display-name>
/profile name <display-name>
/stream [--stream-id <hex>] [--quic-candidate <quic-url>]
/stream start [--stream-id <hex>] --quic-candidate <quic-url>
/stream watch [--stream-id <hex>] [--insecure-local]
/stream status
/stream finish <stream-id> <transcript-hash> <chunk-count> <text>
/stream verify <stream-id> <transcript-hash> [chunk-count]
/quit
```

`/stream` uses `quic://quic-broker.ipf.dev:4450` when no candidate is supplied.

`/login <nsec>` redacts the secret in the composer and pipes it to the child `wn` process over stdin instead of argv.
`/chat archived` shows archived chats so they can be selected and unarchived; `/chat archived off` returns to the
visible-chat list. Member commands operate on the selected chat and call the same group membership commands exposed by
the CLI.
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
