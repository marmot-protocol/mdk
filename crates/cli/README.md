# dm

`dm` is the command-line app for the Darkmatter/Marmot stack. It manages Nostr-keyed accounts, relay
lists, KeyPackages, chats, groups, messages, local projections, live runtime subscriptions, and the terminal UI.

The crate builds two binaries:

- `dm`: the user-facing CLI and TUI entrypoint.
- `dmd`: the background daemon used by `dm daemon start`.

`dm` uses `marmot-account` for account homes and secret storage, and `marmot-app` for the runtime bridge,
transport setup, group projection, message projection, and Nostr directory refresh.

The source directory is `crates/cli`. The Cargo package name remains `darkmatter-cli`, and the installed
commands remain `dm` and `dmd`.

## Install From This Checkout

Install both binaries into your local Cargo bin directory:

```sh
cargo install --path crates/cli --locked --bins
```

Make sure `~/.cargo/bin` is on `PATH`, then check the installed commands:

```sh
dm --help
dmd --help
```

For source-checkout work without installing:

```sh
cargo run -p darkmatter-cli --bin dm -- --help
cargo run -p darkmatter-cli --bin dmd -- --help
```

For isolated development runs, keep the home and secret store explicit:

```sh
export DM_HOME="$(mktemp -d)"
export DM_SECRET_STORE=file
```

The default secret store is the platform keychain. Use `DM_SECRET_STORE=file` only for local development,
tests, and disposable homes.

## Configuration

Common options can be passed as flags or environment variables:

- `--home <path>` or `DM_HOME`: account home, projections, daemon socket, pid, and log.
- `--account <npub-or-hex>` or `DM_ACCOUNT`: selected local signing account for account-scoped commands.
- `--socket <path>` or `DM_SOCKET`: daemon socket. The default is `$DM_HOME/dev/dmd.sock`.
- `--secret-store keychain|file` or `DM_SECRET_STORE`: signing-key backend.
- `--keychain-service <name>` or `DM_KEYCHAIN_SERVICE`: keychain service name.
- `--json`: return a stable JSON envelope for scripts, the TUI, and daemon forwarding.

The default home is `DM_HOME` when set. Without `DM_HOME`, `dm` uses the platform user data directory:

- macOS: `~/Library/Application Support/darkmatter`
- Linux and other non-macOS Unix: `$XDG_DATA_HOME/darkmatter`, or `~/.local/share/darkmatter`
- Windows: `%APPDATA%\darkmatter`

## Quick Start

Create two local signing identities, create a chat as Alice, and let Bob receive it through the daemon.
The examples use the repo-owned `dev/data` tree so local state is easy to inspect and delete:

```sh
just relay-up

export DM_HOME="$PWD/dev/data/quickstart"
export DM_SECRET_STORE=file
unset DM_SOCKET
rm -rf "$DM_HOME"

dm daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777

dm create-identity
printf '%s\n' "$BOB_NSEC" | dm login --nsec-stdin
dm whoami

dm --account <alice-npub-or-hex> groups create general <bob-npub-or-hex>
dm --account <alice-npub-or-hex> messages send <group-hex> "hello bob"

dm --account <bob-npub-or-hex> chats list
dm --account <bob-npub-or-hex> messages list <group-hex> --limit 20
```

The local Compose stack also exposes `ws://127.0.0.1:28080`, but the examples prefer `27777` because it reliably ACKs
the relay-list publishes used during first-run account setup on current macOS Docker Desktop.

Most account-scoped commands resolve the account in this order:

1. `--account <npub-or-hex>`
2. `DM_ACCOUNT`
3. the only local signing account, when exactly one exists

Public-only identities can be added with `dm login <npub-or-hex>`. They are useful for relay-list
and KeyPackage lookup, but cannot sign, publish KeyPackages, sync groups, or send messages.

## Command Map

Identity and account commands:

```sh
dm create-identity
printf '%s\n' "$NSEC" | dm login --nsec-stdin
printf '%s\n' "$NSEC" | dm login --nsec-stdin --relay <relay-url>
dm login <npub-or-hex>
dm whoami
dm logout <npub-or-hex>
dm export-nsec <npub-or-hex>
dm accounts list
dm account list
dm account status [npub-or-hex]
dm account relay-lists [npub-or-hex] --bootstrap-relays <relay-url>
```

The older `dm account create` spelling is kept as a compatibility/repair surface, but new setup flows should use
`dm create-identity` or `dm login`.

When a daemon is running, `create-identity` and `dm login --nsec-stdin` use the daemon's account-relay defaults to
publish the required relay lists and an initial KeyPackage. `printf '%s\n' "$NSEC" | dm login --nsec-stdin --relay
<url>` is the command-local fallback for a custom relay-list publish during import. Public `npub` logins only check
relay-list availability because they cannot sign.
`export-nsec` is present for command-shape compatibility but returns `unsupported_command`; this CLI does not print
private keys.

KeyPackage commands:

```sh
dm --account <npub-or-hex> keys list
dm keys fetch <npub-or-hex> --bootstrap-relays <relay-url>
dm keys check <npub-or-hex>
dm --account <npub-or-hex> keys delete <event-id>
dm --account <npub-or-hex> keys delete-all --confirm
```

KeyPackage publish/fetch/check/list use the current relay-directory path. Relay deletion commands are present but return
`unsupported_command` until Nostr deletion is wired through the app runtime.

Chat projection commands:

```sh
dm --account <npub-or-hex> chats list
dm --account <npub-or-hex> chats list --include-archived
dm --account <npub-or-hex> chats show <group-hex>
dm --account <npub-or-hex> chats subscribe
dm --account <npub-or-hex> chats subscribe-archived
dm --account <npub-or-hex> chats archive <group-hex>
dm --account <npub-or-hex> chats unarchive <group-hex>
```

Group commands:

```sh
dm --account <npub-or-hex> groups list
dm --account <npub-or-hex> groups create <name> [member-npub-or-hex ...] [--description <description>]
dm --account <npub-or-hex> groups show <group-hex>
dm --account <npub-or-hex> groups add-members <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> groups remove-members <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> groups members <group-hex>
dm --account <npub-or-hex> groups admins <group-hex>
dm --account <npub-or-hex> groups relays <group-hex>
dm --account <npub-or-hex> groups leave <group-hex>
dm --account <npub-or-hex> groups rename <group-hex> <name>
dm --account <npub-or-hex> groups promote <group-hex> <member-npub-or-hex>
dm --account <npub-or-hex> groups demote <group-hex> <member-npub-or-hex>
dm --account <npub-or-hex> groups self-demote <group-hex>
dm --account <npub-or-hex> groups subscribe-state <group-hex>

dm --account <npub-or-hex> group create <name> [member-npub-or-hex ...]
dm --account <npub-or-hex> group members <group-hex>
dm --account <npub-or-hex> group invite <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> group remove <group-hex> <member-npub-or-hex> [...]
dm --account <npub-or-hex> group update <group-hex> --name <name>
dm --account <npub-or-hex> group update <group-hex> --description <description>
```

Message commands:

```sh
dm --account <npub-or-hex> messages send <group-hex> "hello"
dm --account <npub-or-hex> messages send --group <group-hex> "--text that starts with a dash"
dm --account <npub-or-hex> messages list
dm --account <npub-or-hex> messages list <group-hex> --limit 20
dm --account <npub-or-hex> messages list <group-hex> --before <unix-seconds> --before-message-id <event-id>
dm --account <npub-or-hex> messages list <group-hex> --after <unix-seconds> --after-message-id <event-id>
dm --account <npub-or-hex> messages search <group-hex> <query> --limit 20
dm --account <npub-or-hex> messages search-all <query> --limit 20
dm --account <npub-or-hex> messages react <group-hex> <message-id> +
dm --account <npub-or-hex> messages unreact <group-hex> <message-id>
dm --account <npub-or-hex> messages delete <group-hex> <message-id>
dm --account <npub-or-hex> messages retry <group-hex> <event-id>
dm --account <npub-or-hex> messages subscribe <group-hex> --limit 50
```

Projected history is ordered by recorded message time first, then local receipt/insertion order. That keeps synced
stream anchors and final markers in conversation order instead of relay catch-up order.

`messages subscribe`, `chats subscribe`, and `groups subscribe-state` require `dmd`. With `--json`, they print
newline-delimited stream responses as they arrive. Each response has a typed `result.type`; normal app messages use
`message`, reactions use `reaction`, deletions use `message_delete`, media references use `media`, durable agent stream
anchors/finals use `agent_stream_start` and `agent_stream_final`, live brokered QUIC chunks use `agent_stream_delta`,
runtime-owned QUIC preview summaries use `stream_preview`, chat rows use `chat`, and group state rows use `group_state`.

Media commands:

```sh
dm --account <npub-or-hex> media list <group-hex>
dm --account <npub-or-hex> media upload <group-hex> <file-path> --send --message <caption>
dm --account <npub-or-hex> media upload <group-hex> <file-path> --server https://blossom.primal.net
dm --account <npub-or-hex> media download <group-hex> <file-hash> --output ./file.jpg
```

`media upload` encrypts the file with the group's MIP-04 encrypted-media exporter secret, uploads the
ciphertext to Blossom (`https://blossom.primal.net` by default), and optionally sends a kind-9 media reference. `media
download` resolves a projected media reference by plaintext hash, fetches the encrypted Blossom blob, verifies it,
decrypts it, and writes the plaintext file.

Other Whitenoise-shaped commands:

```sh
dm --account <npub-or-hex> debug health
dm debug relay-control-state
dm --account <npub-or-hex> follows list
dm --account <npub-or-hex> follows add <npub-or-hex>
dm --account <npub-or-hex> follows remove <npub-or-hex>
dm --account <npub-or-hex> profile show
dm --account <npub-or-hex> profile update --name <name> --about <text>
dm --account <npub-or-hex> relays list --type nip65
dm --account <npub-or-hex> relays add <relay-url> --type inbox
dm settings show
dm settings theme dark
dm settings language en
dm users show <npub-or-hex>
dm users search <query> --radius 0..2
dm reset --confirm
```

`notifications subscribe`, chat mute/unmute, and user-driven invite accept/decline commands currently return
`unsupported_command` rather than faking behavior.

Agent text stream preview commands:

```sh
marmot-quic-broker --bind 127.0.0.1:4450
dm --account <npub-or-hex> stream start <group-hex> \
  --stream-id <stream-hex> --quic-candidate quic://127.0.0.1:4450
dm --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local
dm --account <npub-or-hex> stream watch <group-hex> --stream-id <stream-hex> --insecure-local --background
dm stream send --broker --connect 127.0.0.1:4450 --insecure-local \
  --stream-id <stream-hex> --start-event-id <start-message-id-hex> "hello over quic"
dm stream send --connect <host:port> --server-name <dns-name> "hello over quic"
dm --account <npub-or-hex> stream finish <group-hex> \
  --stream-id <stream-hex> --transcript-hash <hash-hex> --chunk-count <n> "hello over quic"
dm --account <npub-or-hex> stream verify <group-hex> \
  --stream-id <stream-hex> --transcript-hash <hash-hex> --chunk-count <n>
```

`stream start` and `stream finish` send typed payloads through the normal encrypted Marmot message path. Brokered
starts include concrete `quic://host:port` candidates for that stream. `stream watch` reads the durable start payload,
subscribes to the broker candidate, and prints the provisional text preview plus transcript hash. `stream send --broker`
publishes ordered `TextDelta` records through the memory-only broker. Without `--broker`, `stream send` still connects
directly to a peer receiver, which is useful with `dm stream receive --bind 127.0.0.1:4450` for local transport probes.
`stream verify` compares a received QUIC transcript hash and chunk count against the latest durable final payload for the
same stream id. QUIC chunks are transient preview data; normal Marmot messages remain the durable group history. Use
`quic://quic-broker.ipf.dev:4450` with platform trust for the shared production broker, and use `--insecure-local` only
for loopback development with generated self-signed certificates.

When `dmd` is running, `stream watch --background` starts the broker subscription through the daemon and returns
immediately. The runtime stream manager owns the running/completed/failed preview state. `dm daemon status --json`
includes that state under `stream_watches`, including received preview text and transcript hash after the brokered stream
arrives. The same preview state is emitted as typed `stream_preview` updates from `dm messages subscribe <group-hex>`,
while individual broker chunks arrive as `agent_stream_delta` updates.

Sync command:

```sh
dm --account <npub-or-hex> sync
```

`sync` is a diagnostic and repair command. Normal daemon-backed chat, group, and stream flows use runtime
subscriptions and should not need a manual sync step.

## Daemon

`dm daemon start` launches `dmd` in the background for the selected home. The daemon owns the Unix socket,
writes `dev/dmd.pid`, appends startup errors to `dev/dmd.log`, and hosts one `MarmotAppRuntime`. The runtime keeps
long-lived relay subscriptions for local signing accounts using the daemon's discovery and account-relay defaults.
Commands forwarded through the daemon update runtime subscription state automatically after identity, group, message,
and stream mutations.

```sh
export DM_HOME="$PWD/dev/data/daemon-demo"
export DM_SECRET_STORE=file
unset DM_SOCKET
dm daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777
dm daemon status
dm --account <npub-or-hex> chats list
dm daemon stop
```

`dm daemon status --json` includes `last_runtime_activity` for the TUI plus a redacted `relay_health` object with
aggregate relay counts and connection status buckets. It does not include relay URLs, account ids, group ids,
subscription ids, or message ids.

When a daemon socket exists for a home, normal `dm --home <path> ...` commands are forwarded to that
daemon. `dm daemon status`, `dm daemon stop`, and `dm tui` handle daemon access directly.
Background stream watches started with `dm stream watch --background` are launched by the daemon and tracked by the
runtime stream manager. Long-lived subscriptions use the daemon socket directly:

```sh
dm --account <npub-or-hex> messages subscribe <group-hex> --limit 50
dm --account <npub-or-hex> chats subscribe
dm --account <npub-or-hex> groups subscribe-state <group-hex>
```

Use `--socket` or `DM_SOCKET` to target a specific daemon. Use `dmd` directly when a process supervisor
should own the daemon lifecycle:

```sh
dmd --home "$DM_HOME" \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777
```

### Two-Terminal Local Stream Demo

Terminal 1 owns the daemon and the live subscription:

```sh
just relay-up

export DM_HOME="$PWD/dev/data/stream-demo"
export DM_SECRET_STORE=file
unset DM_SOCKET
rm -rf "$DM_HOME"

dm daemon start \
  --discovery-relays ws://127.0.0.1:27777 \
  --default-account-relays ws://127.0.0.1:27777

# After Terminal 2 creates $BOB and $GROUP, run:
dm --account "$BOB" messages subscribe "$GROUP" --limit 20
```

Terminal 2 creates Alice/Bob, starts the durable stream, and sends live broker chunks:

```sh
export DM_HOME="$PWD/dev/data/stream-demo"
export DM_SECRET_STORE=file
unset DM_SOCKET

ALICE=$(dm --json create-identity | jq -r '.result.account_id')
BOB=$(dm --json create-identity | jq -r '.result.account_id')

GROUP=$(dm --account "$ALICE" --json groups create agent "$BOB" | jq -r '.result.group_id')
dm --account "$ALICE" messages send "$GROUP" "hello bob"

STREAM_ID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
START_ID=$(dm --account "$ALICE" --json stream start "$GROUP" \
  --stream-id "$STREAM_ID" \
  --quic-candidate quic://127.0.0.1:4450 | jq -r '.result.message_ids[0]')

dm --account "$BOB" stream watch "$GROUP" --stream-id "$STREAM_ID" --insecure-local --background
dm stream send --broker --connect 127.0.0.1:4450 --server-name localhost --insecure-local \
  --stream-id "$STREAM_ID" --start-event-id "$START_ID" --chunk-bytes 8 "hello from the stream"
```

Terminal 1 should print typed `message`, `agent_stream_start`, `agent_stream_delta`, and `stream_preview` JSON lines in
real time.

## TUI

`dm tui` is a Ratatui interface over the real `dm --json` command surface. It lists local accounts, shows
visible chats for the selected local signing account, renders recent messages, sends messages from a composer, and
keeps the latest status plus selected-chat MLS/component state in a status panel below the composer.

```sh
dm tui
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
/sync
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
/stream [--stream-id <hex>] [--quic-candidate <quic-url>]
/stream start [--stream-id <hex>] --quic-candidate <quic-url>
/stream watch [--stream-id <hex>] [--insecure-local]
/stream status
/stream finish <stream-id> <transcript-hash> <chunk-count> <text>
/stream verify <stream-id> <transcript-hash> [chunk-count]
/quit
```

`/stream` uses `quic://quic-broker.ipf.dev:4450` when no candidate is supplied.

`/login <nsec>` redacts the secret in the composer and pipes it to the child `dm` process over stdin instead of argv.
`/chat archived` shows archived chats so they can be selected and unarchived; `/chat archived off` returns to the
visible-chat list. Member commands operate on the selected chat and call the same group membership commands exposed by
the CLI.
Stream commands operate on the selected chat. `/stream watch` starts a daemon background watch and completed previews
appear as provisional preview rows in the message panel. `/stream` opens the TUI stream composer, publishes the stream
anchor, starts the receiver watch through the daemon, and then treats the next submitted composer line as the streamed
text to finish.
`/sync` is a diagnostic escape hatch for explicit catch-up; it is not part of the normal live runtime path.

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
brew install marmot-protocol/tap/darkmatter
```

The tap formula lives in `github.com/marmot-protocol/homebrew-tap` and installs both `dm` and `dmd` from `crates/cli`.
Once release CI exists, the tap can publish bottles for macOS and Linux so users do not pay the full Rust build cost.
The project-side release checklist lives at `docs/release/dm-homebrew.md`.

While `marmot-protocol/darkmatter` is private, Homebrew source builds require GitHub access to the source repo. Public
tarball installs can replace that once the source repo is public or release assets are published somewhere installers can
download.

`cargo install --git ssh://git@github.com/marmot-protocol/darkmatter.git darkmatter-cli --locked --bins` is a useful
source install path for engineers and automation.

`cargo install darkmatter-cli` from crates.io is a later option. The workspace currently has
`publish = false`, and the CLI depends on local workspace crates. Publishing there needs a separate crate
publication plan or a split packaging crate.
