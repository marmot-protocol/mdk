# Marmot Integrations

Connectors that let you chat with an agent runtime you already run (Hermes, OpenClaw, Claude Code, Codex, OpenCode,
or Pi) from White Noise, over end-to-end encrypted Marmot groups. Each connector runs next to the local `wn-agent`
service on your Mac or Linux machine. Start with [Get Started](#get-started-white-noise--agents); the later sections
explain topology, identities, and sharing for operators.

## Contents

- [Get Started: White Noise + Agents](#get-started-white-noise--agents)
- [Recommended chat setup](#recommended-chat-setup)
- [Connector capabilities](#connector-capabilities)
- [First-install verification](#first-install-verification)
- [How The Connectors Fit Together](#how-the-connectors-fit-together)
- [Default Install Topology](#default-install-topology)
- [Identity Model](#identity-model)
- [What Is Shared](#what-is-shared)
- [What Is Separate](#what-is-separate)
- [Allowlist Behavior](#allowlist-behavior)
- [Sharing Options](#sharing-options)
- [Development Paths](#development-paths)

## Get Started: White Noise + Agents

You need:

- White Noise on your phone, with your account `npub` available;
- one supported agent runtime already installed, authenticated, and working on
  the same Mac or Linux machine where you will run the connector;
- Linux x86_64, Linux arm64, macOS Apple Silicon, or macOS Intel.

Choose the runtime you already use:

| Runtime | Connector style | Best fit |
| --- | --- | --- |
| Hermes | Gateway plugin | Rich chat history, reactions, media, and live previews |
| OpenClaw | Channel plugin | Gateway routing, history and media |
| Claude Code | Terminal harness | Repository and coding tasks through Claude Code |
| Codex | Terminal harness | Repository and coding tasks through Codex |
| OpenCode | Terminal harness | Repository and coding tasks through OpenCode |
| Pi | Terminal harness | Repository and coding tasks through Pi |

The guided installers prompt on the terminal for the White Noise account that
may invite and message the agent. They install the latest published WN Agent release, create
an isolated White Noise identity for the selected connector, and start same-user
services where supported. Download each installer with its adjacent checksum,
verify it, and only then execute the local file:

The example below requires Python 3 and resolves the latest published
`wn-agent-v*` release once, then uses its immutable URL for all downloads.
WN Agent releases are currently marked GitHub pre-releases; the resolver accepts
published numeric tags and excludes draft releases and `-rc`/other suffixes.
GitHub's repository-wide `/releases/latest` may select MDK or MarmotKit instead.
Resolution or checksum failure stops installation; no unverified fallback runs.
For the default cohort, remove stale `MARMOT_RELEASE_REPO`, `MARMOT_RELEASE_TAG`,
`WN_AGENT_VERSION` and `WN_AGENT_SHA` overrides; the published installer defaults
its companion assets to its own release. Explicit overrides are a custom install.
For repeatable deployments, save the printed `base_url` and reuse that exact
release rather than resolving again. The release publisher is the trust anchor;
the sibling checksum verifies downloaded bytes, not an independent endorsement.
A reviewed numeric release URL can replace the resolved value for a pinned install. Minimum host versions and pinned test
cohorts below describe compatibility, not a required MDK install version.

```sh
install_verified() (
  set -eu
  installer_url="$1"
  checksum_url="$2"
  shift 2
  case "$installer_url" in
    https://github.com/marmot-protocol/mdk/releases/download/wn-agent-v*/install-*-marmot.sh) ;;
    *) echo "error: resolve a WN Agent release before installing" >&2; exit 1 ;;
  esac
  if [ "$checksum_url" != "$installer_url.sha256" ]; then
    echo "error: checksum must accompany the same release installer" >&2
    exit 1
  fi
  installer_script="${installer_url##*/}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' 0 HUP INT TERM
  curl -fsSL --connect-timeout 10 --max-time 180 "$installer_url" -o "$tmpdir/$installer_script"
  curl -fsSL --connect-timeout 10 --max-time 180 "$checksum_url" -o "$tmpdir/$installer_script.sha256"
  if command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "$installer_script.sha256")
  elif command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "$installer_script.sha256")
  else
    echo "error: need shasum or sha256sum to verify the installer" >&2
    exit 1
  fi
  bash "$tmpdir/$installer_script" "$@"
)

if base_url="$(python3 - <<'RELEASE'
import json, re, urllib.request
candidates = []
for page in range(1, 11):
    url = f"https://api.github.com/repos/marmot-protocol/mdk/releases?per_page=100&page={page}"
    with urllib.request.urlopen(url, timeout=30) as response:
        releases = json.load(response)
    for release in releases:
        tag = release["tag_name"]
        match = re.fullmatch(r"wn-agent-v([0-9]+)\.([0-9]+)\.([0-9]+)", tag)
        if match and not release["draft"] and release["published_at"]:
            candidates.append((tuple(map(int, match.groups())), tag))
    if len(releases) < 100:
        break
else:
    raise SystemExit("Release listing exceeded 1000 entries; choose a reviewed tag explicitly")
if not candidates:
    raise SystemExit("No published WN Agent release found")
tag = max(candidates)[1]
print(f"https://github.com/marmot-protocol/mdk/releases/download/{tag}")
RELEASE
)" && test -n "$base_url"; then
  printf 'Selected WN Agent release: %s\n' "$base_url"
else
  base_url=""
  printf '%s\n' 'error: release lookup failed; installation is unavailable until resolved' >&2
fi
```

### Hermes

Hermes 0.19.0 or newer must already be installed and working.

If Hermes has multiple profiles or a custom home, read
[first install and profile selection](hermes/marmot/README.md#first-install-and-profile-selection)
**before** invoking the installer. Export the intended `HERMES_HOME`, and choose
separate connector homes/sockets/service names for independent agents. The
installer does not infer the intended profile from the installation prompt.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256"
```

### OpenClaw

OpenClaw 2026.7.1 or newer and Node 22.19 or newer must already be installed.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-openclaw-marmot.sh" \
  "$base_url/install-openclaw-marmot.sh.sha256"
```

### Claude Code

Claude Code 2.1.0 or newer must already be installed, authenticated, and
runnable as `claude`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-claude-marmot.sh" \
  "$base_url/install-claude-marmot.sh.sha256"
```

### Codex

Codex must already be installed, authenticated, and runnable as `codex`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-codex-marmot.sh" \
  "$base_url/install-codex-marmot.sh.sha256"
```

### OpenCode

OpenCode 1.18.18 or newer must already be installed and runnable as `opencode`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-opencode-marmot.sh" \
  "$base_url/install-opencode-marmot.sh.sha256"
```

### Pi

Pi must already be installed, authenticated, and runnable as `pi`.

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-pi-marmot.sh" \
  "$base_url/install-pi-marmot.sh.sha256"
```

### Finish In White Noise

Each installer records the new agent's `npub` and `nprofile` in the
`bootstrap.json` path printed at completion. Display them with:

```sh
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["npub"]); print(d["nprofile"])' \
  "$HOME/.marmot-agents/codex/bootstrap.json"
```

Use `hermes`, `openclaw`, `claude`, `codex`, `harnesses` (OpenCode), or `pi` in that path.
The installers also show these values directly and render a terminal QR when
`qrencode` is installed.

1. Add the displayed agent identity in White Noise.
2. Invite it to a direct message or group from the account you authorized.
3. Send a test message.

Hermes and OpenClaw print one final gateway restart command because the installer
does not restart an existing gateway. Claude Code, Codex, OpenCode, and Pi services are
started by the default install. Their first group message can be `/<path>` to
select a working directory under your home directory.

### Repeatable Agent Or CI Setup

For repeatable CI, save the exact numeric release URL printed during a
reviewed setup and set `base_url` to that saved URL instead of resolving latest
again on every run. Provide the authorized White Noise account explicitly. Terminal harnesses use the welcomer entry for both invitation and
prompt authorization. OpenClaw keeps those boundaries separate: `--allow-welcomer`
is invite admission only, and inbound sender authorization is a distinct
`senderPolicy` / `MARMOT_ALLOWED_USERS` configuration.

Run this example in the same shell where `install_verified` above was defined.

```sh
OWNER_NPUB=npub1...
install_verified "$base_url/install-codex-marmot.sh" \
  "$base_url/install-codex-marmot.sh.sha256" \
  --yes --allow-welcomer "$OWNER_NPUB"
```

Replace `codex` in the URL with `claude`, `openclaw`, `opencode`, or `pi`. Hermes keeps
invite acceptance and message-sender authorization explicit:

Run this example in the same shell where `install_verified` above was defined.

```sh
install_verified "$base_url/install-hermes-marmot.sh" \
  "$base_url/install-hermes-marmot.sh.sha256" \
  --yes --allow-welcomer "$OWNER_NPUB" --allow-user "$OWNER_NPUB"
```

Every installer verifies the downloaded binary and plugin assets against the
checksums from the same immutable release. For independent
verification of the installer itself, download its adjacent `.sha256` asset
before running it.

Use each connector's README for existing-identity imports, shared deployments,
execution profiles, manual service control, and development workflows.

## Recommended chat setup

For a personal agent chat, the recommended setup is a dedicated group/DM with
**the agent promoted to group admin** so it can maintain a useful task title.
The phone owner performs the promotion through White Noise's group management.
Group admin carries real membership/profile authority; keep the human owner as
an admin too. This is recommended for trusted agents, not an automatic grant
in every shared group. Admin status does not authorize new senders or grant
backend tools. Ordinary messages and reactions do not require admin status.

Before installation, settle the few choices that change the setup:

- Which runtime/profile and existing account should this chat use? Default to
  the selected runtime's isolated connector identity; reuse an identity only
  when requested.
- Which phone account may invite and prompt it, and which project directory
  should terminal-harness work start in?
- Is this a trusted personal agent chat with admin/title management? Recommend
  yes; keep a shared group member-only unless its owner chooses otherwise.
- Which files are needed, and is generated-file delivery supported/configured?
  Keep the selected runtime's existing permissions as the execution default.

Use answers already supplied in the installation prompt; ask only for missing
choices. A supplied npub is public authorization information, not a secret
identity import. Summarize the concrete setup plan for the prompt's approval
step. Do not repeatedly ask for choices that have already been made.

### Suggested agent chat instructions

The following is a suggested instruction block to add to the selected agent's
normal profile/project instructions. It is not installed automatically by the
connector, and a terminal session's `/goal` alone cannot expose missing tools:

> Work in the current White Noise conversation. Keep its title a short,
> findable description of the accepted task, optionally with one project emoji.
> Rename only on a real topic change; keep the title during status questions,
> retries and completion. Read the current title first, preserve the current
> chat binding, and read back an update. Never put secrets or personal details
> in a title. After an uncertain write, inspect before retrying.
>
> Use real message reactions for progress: 👀 when an actionable request is
> accepted, ✅ after the requested result is completed and verified, ⏸️ when a
> real user decision is required, and ❌ on terminal failure. Replace your own
> earlier progress reaction rather than stacking it; do not send the emoji as
> a separate chat message. React to the triggering message in this chat. A
> planned change, queued build or draft is not a completed result. Emoji-only
> user messages are context, not blanket approval for a destructive action.
>
> Read the selected connector's setup and capability guide. Use only tools and
> file paths authorized for this deployment. Keep follow-up messages attached
> to the unfinished task unless the user changes it. Report the verified result
> concisely, with a link or delivered file when appropriate. If a required
> title, reaction or file tool is missing, explain that limitation rather than
> pretending the action worked.

### Check the tools before promising the experience

- **Hermes:** `marmot_group_profile` updates a name/description as an admin;
  `marmot_reaction` adds/removes a message reaction. The optional presence
  policy and model-issued reactions need one consistent owner so they do not
  compete. See [the Hermes guide](hermes/marmot/README.md#what-you-can-do).
- **OpenClaw:** the normal `message` tool supports `react` with an emoji,
  target message id and chat target; `remove: true` removes it. There is no
  registered Marmot group-rename action today. Admin status alone does not add
  that action. Title management requires a separately configured, trusted local
  `group_profile_update` tool/helper.
- **Claude Code, Codex, OpenCode and Pi:** shared harness commands handle chat
  sessions, workdirs and goals; they do not register title or reaction tools.
  A deployment may expose a trusted local helper to the backend using
  `group_info`, `group_profile_update`, `send_reaction` and `remove_reaction`
  from the [agent-control protocol](../crates/agent-control/README.md).
  Bind it to the selected connector account and actual chat, with access only
  through the authorized local socket. Do not guess a chat from its display
  name, copy control secrets into prompts, or start a second daemon/CLI writer
  against the same account home. Without that helper, ordinary replies work
  but automated titles/reactions remain unavailable.

### Acceptance check on the phone

1. Invite the bootstrapped agent from the authorized phone account and grant
   admin in the intended chat when title management is selected.
2. Select the project for a terminal harness, then send a small ordinary model
   request. Verify the response lands in that same chat.
3. If title/reaction tools are configured, verify a meaningful task title and
   a 👀 → ✅ transition on the request, without a duplicate emoji message. Make
   a new request to verify session continuity; a status question should keep
   the task title. Never mark a missing helper or rejected admin change as passed.
4. Test one required file type and generated-file return if supported. Check
   [the capability guide](#connector-capabilities) before choosing the test.
5. Report which runtime/profile, connector identity, services and chat were
   verified, and list remaining phone/tool checks explicitly. A service start,
   local `/status` reply or readiness probe alone is not this acceptance check.

## Connector capabilities

All six connectors provide encrypted White Noise conversations with an agent
runtime you already use. The runtime supplies the model, tools and permissions;
`wn-agent` supplies Marmot identity, encrypted transport and durable delivery.
Choose by the features you need:

| Connector | Conversation and controls | Files |
| --- | --- | --- |
| [Hermes](hermes/marmot/README.md#what-you-can-do) | DM/group activation; history, quotes, reactions, own-message deletion, admin group profile updates; optional live previews/presence/approval reactions | Inbound media; image/document/video/voice sends with approved-root staging |
| [OpenClaw](openclaw/marmot/README.md#what-you-can-do) | Gateway routing; DM/group activation; history, quotes, quiet changes, own-message deletion, reactions, consent-based public profile naming; current inbound turns are final-only | Host-authorized inbound/outbound media via normal message tool |
| [Claude Code](claude/marmot/README.md#what-you-can-do) | Per-chat session/project/goal; shared chat and recovery commands; text replies | Text-only; no attachments or generated-file return |
| [Codex](codex/marmot/README.md#what-you-can-do) | Per-chat thread/project/goal; shared chat and recovery commands; completed text replies | Native images and supported staged files; opt-in generated-file return with exact grants |
| [OpenCode](opencode/marmot/README.md#what-you-can-do) | Per-chat session/project/goal; shared chat and recovery commands; text-event replies | Supported images/PDFs/text; no generated-file return |
| [Pi](pi/marmot/README.md#what-you-can-do) | Per-chat session/project/goal; shared chat and recovery commands; completed text replies | Supported images/text; no generated-file return |

For terminal harnesses, start with `/cd src/my-project`, send an ordinary request,
then use `/status`, `/goal <instruction>` or `/new` as needed. The complete
[chat-command reference](terminal-harness/README.md#chat-commands) explains
recovery, session resets and slash escaping. These harnesses do not add gateway
mention activation, reaction tools or live previews.

For gateway plugins, ask in the current chat and use the runtime's registered
Marmot tools and media-delivery contract. A file accepted by a connector is not
a promise that the selected model can interpret it. Voice/audio upload shares
the group's configured media endpoint and limits; personal kind-10063 discovery
is not yet implemented. Each linked guide explains opt-ins, restrictions and
verification steps; installing another connector does not inherit its features.

## First-install verification

For a copied White Noise installation prompt, use the connector's
[first-install checklist](../crates/agent-connector/README.md#first-installation-from-a-white-noise-prompt)
and the selected runtime's guide. Resolve the actual runtime/profile home,
choose one owner for each connector socket/service, verify the downloaded
installer checksum and release cohort, and configure both invitation and
message-sender authorization. A successful install/bootstrap is not proof of
an agent reply reaching the phone: finish with an invited, allowed-account
White Noise round trip.

Before installing, follow the runtime-specific checklist: [Hermes](hermes/marmot/README.md#first-install-and-profile-selection),
[OpenClaw](openclaw/marmot/README.md#first-install-checklist),
[Claude Code](claude/marmot/README.md#first-install-checklist),
[Codex](codex/marmot/README.md#first-install-checklist),
[OpenCode](opencode/marmot/README.md#first-install-checklist), or
[Pi](pi/marmot/README.md#first-install-checklist). The four terminal harnesses also
share a [two-process/environment verification guide](terminal-harness/README.md#first-installation-and-verification).
These guides distinguish invitation authorization from prompt authorization and
actual backend replies from local setup/status acknowledgements.

For Hermes files, stage a regular file under the adapter's approved source root
before returning `MEDIA:<absolute-path>`; see the
[copy-and-send example](hermes/marmot/README.md#sending-a-generated-file).
The default source root is the connector home's `dev/inbound-media`, not an
arbitrary workspace. OpenClaw and terminal harnesses have their own documented
attachment/export contracts; do not apply Hermes's `MEDIA:` syntax to them.

## How The Connectors Fit Together

Current integrations:

- [`hermes/marmot`](hermes/marmot) - Hermes platform plugin.
- [`openclaw/marmot`](openclaw/marmot) - OpenClaw channel plugin.
- [`claude/marmot`](claude/marmot) - `wn-claude` Claude Code harness binary.
- [`codex/marmot`](codex/marmot) - `wn-codex` Codex harness binary.
- [`opencode/marmot`](opencode/marmot) - `wn-opencode` OpenCode harness binary.
- [`pi/marmot`](pi/marmot) - `wn-pi` Pi harness binary.
- [`terminal-harness`](terminal-harness) - shared hardened runtime for the
  Claude Code, Codex, OpenCode, and Pi terminal harnesses.

All integrations are intentionally thin at the Marmot boundary. They do not own MLS
state, Nostr transport, local account storage, relay access, QUIC preview
transport, or durable encrypted sends. `wn-agent` owns those concerns and exposes
the local `marmot.agent-control.v2` newline-delimited JSON protocol over a Unix
socket.

## Default Install Topology

The release installers are published with the `wn-agent-v*` release family:

- `scripts/install-hermes-marmot.sh` (passive `--doctor [--json]` report; not delivery proof)
- `scripts/install-openclaw-marmot.sh`
- `scripts/install-claude-marmot.sh`
- `scripts/install-codex-marmot.sh`
- `scripts/install-opencode-marmot.sh`
- `scripts/install-pi-marmot.sh`

By default the production-shaped installs create separate local agent identities
per connector:

| Integration | Home | Same-user service |
| --- | --- | --- |
| Hermes | `$HOME/.marmot-agents/hermes` | `wn-agent-hermes.service` / `org.marmot.wn-agent.hermes` |
| OpenClaw | `$HOME/.marmot-agents/openclaw` | `wn-agent-openclaw.service` / `org.marmot.wn-agent.openclaw` |
| Claude Code harness | `$HOME/.marmot-agents/claude` | `wn-agent-claude.service` / `org.marmot.wn-agent.claude` plus `wn-claude.service` / `org.marmot.wn-claude` |
| Codex harness | `$HOME/.marmot-agents/codex` | `wn-agent-codex.service` / `org.marmot.wn-agent.codex` plus `wn-codex.service` / `org.marmot.wn-codex` |
| OpenCode harness | `$HOME/.marmot-agents/harnesses` | `wn-agent-harnesses.service` / `org.marmot.wn-agent.harnesses` plus `wn-opencode.service` / `org.marmot.wn-opencode` |
| Pi harness | `$HOME/.marmot-agents/pi` | `wn-agent-pi.service` / `org.marmot.wn-agent.pi` plus `wn-pi.service` / `org.marmot.wn-pi` |

Each home derives its own default socket at `$MARMOT_HOME/dev/wn-agent.sock` and
uses the public relay defaults shared with the phone app pilot setup. Claude Code,
Codex, OpenCode, and Pi use separate connector homes and Marmot identities by default. They share
implementation in `integrations/terminal-harness`, but they do not share prompts,
sessions, sockets, or services unless an operator explicitly configures a shared
deployment.

Hermes and OpenClaw install or patch their host-runtime plugin configuration and
then print restart guidance for the existing gateway. They do not restart the
gateway automatically. `wn-claude`, `wn-codex`, `wn-opencode`, and `wn-pi` each install their own harness
binary and service in addition to `wn-agent`, because they are standalone
harnesses rather than plugins loaded by an existing gateway.

## Identity Model

The default topology creates or reuses one Marmot account per connector home,
which means Hermes, OpenClaw, Claude Code, Codex, OpenCode, and Pi present as separate Nostr
identities when installed with default options.

Within each home, `wn-agent bootstrap` lists local-signing accounts and reuses one
when selection is unambiguous. If no local account exists, bootstrap creates one.
If more than one local-signing account exists, production integrations should
require an explicit account id instead of guessing.

The installers persist the selected account into connector-specific config:

- Hermes uses `MARMOT_ACCOUNT_ID_HEX` or the Marmot plugin config.
- OpenClaw uses `channels.marmot.accountIdHex` or `MARMOT_ACCOUNT_ID_HEX`.
- `wn-claude` uses `WN_CLAUDE_ACCOUNT_ID_HEX`.
- `wn-codex` uses `WN_CODEX_ACCOUNT_ID_HEX`.
- `wn-opencode` uses `WN_OPENCODE_ACCOUNT_ID_HEX`.
- `wn-pi` uses `WN_PI_ACCOUNT_ID_HEX`.

Installing all six connectors on one machine with default options therefore
creates distinct agent identities and distinct chat/group memberships.

## What Is Shared

Within one connector home, the host integration and its `wn-agent` share:

- the local Marmot account and Nostr public key;
- the local MLS/group state and app runtime projection;
- relay configuration and key-package/profile publication through `wn-agent`;
- the account-scoped welcomer allowlist used for invite acceptance;
- the local control socket and optional bearer-token gate;
- durable sends, deletes, media download staging, and idempotency handled by
  `wn-agent`;
- the inbound event stream exposed by `SubscribeInbound`.

Across different default connector homes, those items are not shared.

Advanced deployments can still point multiple integrations at the same
`MARMOT_HOME` and socket. The control socket supports multiple clients, and
multiple integrations can subscribe to inbound events for the same account at the
same time.

## What Is Separate

Each host runtime keeps its own runtime state:

- Hermes keeps Hermes gateway/plugin state under `HERMES_HOME`.
- OpenClaw keeps OpenClaw gateway/channel state under `OPENCLAW_HOME`.
- `wn-claude` keeps harness configuration in `$MARMOT_HOME/dev/wn-claude.env`
  and session state under `$XDG_STATE_HOME/wn-claude` by default.
- `wn-codex` keeps harness configuration in `$MARMOT_HOME/dev/wn-codex.env`
  and session state under `$XDG_STATE_HOME/wn-codex` by default.
- `wn-opencode` keeps harness configuration in
  `$MARMOT_HOME/dev/wn-opencode.env` and session state under
  `$XDG_STATE_HOME/wn-opencode` by default.
- `wn-pi` keeps harness configuration in `$MARMOT_HOME/dev/wn-pi.env`, connector
  state under `$XDG_STATE_HOME/wn-pi`, and Pi sessions under
  `$MARMOT_HOME/dev/pi-sessions` by default.

Each integration also makes its own activation decision:

- Hermes and OpenClaw are gateway/channel integrations. Each applies its own
  inbound sender ACL before activation. In multi-party groups they default to
  mention-style activation and always reply in effective DMs. Activation cannot
  widen sender authorization. They also support richer gateway features such as
  live previews, durable reply routing, profile onboarding, and media handling.
- `wn-claude`, `wn-codex`, `wn-opencode`, and `wn-pi` are pure harnesses. They currently support only
  `always` activation for prompt messages from explicitly allowed senders, and
  have no profile onboarding or live-preview behavior. Their shared runtime
  validates and privately stages bounded ordered attachment batches. `wn-codex`
  maps image batches to ordered Codex image inputs; `wn-opencode` passes each
  file as an ordered `opencode run --file` argument; `wn-pi` passes each image
  or UTF-8 text file as an ordered `@file` operand and rejects the whole batch
  before spawning Pi if any file is another type; `wn-claude` rejects every
  non-empty batch, including its accompanying text, before spawning its backend.

Because activation is per integration, there is no global "claim this message"
lease in shared-account deployments. If several integrations subscribe to the
same account and group, every eligible integration can reply. For example, a
direct message from an allowlisted sender could trigger Hermes/OpenClaw,
`wn-claude`, `wn-codex`, `wn-opencode`, and `wn-pi` if all are running and configured for that account.

## Allowlist Behavior

The `wn-agent` welcomer allowlist is account-scoped, not integration-scoped. In
the default installer topology that means each connector has its own allowlist.
It matters most when several integrations are intentionally configured to manage
the same account.

Invite admission defaults to `allowlist`. Public direct-message bots can opt in
without enabling debug controls by rerunning bootstrap with
`--invite-policy any-authenticated-direct`; this accepts an authenticated
welcomer only when the resulting MLS group has exactly two members. The other
explicit policies are `deny`, `allowlist`, and `any-authenticated` (which also
admits multi-party groups). These account-scoped invite policies remain
independent from each integration's sender and activation policy.

Hermes and OpenClaw can mirror configured `allowFrom`/welcomer entries into
`wn-agent`. That mirroring is invite admission only. Hermes and OpenClaw each
keep a separate inbound sender ACL (`MARMOT_ALLOWED_USERS` /
`MARMOT_ALLOW_ALL_USERS`, plus OpenClaw `channels.marmot.senderPolicy`) and do
not treat membership or welcomer status as authorization to invoke the agent.
Their welcomer sync path is config-driven and may reconcile the connector
allowlist to the configured set. All terminal harnesses require at least one
allowed sender and install those senders into both the prompt allowlist and the
`wn-agent` welcomer allowlist. Their startup mirroring is additive: removing a
sender only from `wn-agent` is not a full harness revoke while the sender remains
in `WN_CLAUDE_ALLOWED_SENDERS_HEX`, `WN_CODEX_ALLOWED_SENDERS_HEX`,
`WN_OPENCODE_ALLOWED_SENDERS_HEX`, or
`WN_PI_ALLOWED_SENDERS_HEX`.

For shared-account deployments, prefer one explicit source of truth for the
account's allowed welcomers, or configure every integration with the same
intended union.

## Sharing Options

Run the default installers when you want each connector to appear as its own
agent identity.

Use an explicit shared deployment when you want one Marmot identity behind
several integrations:

- one shared `MARMOT_HOME`;
- one shared `MARMOT_AGENT_SOCKET`;
- one `wn-agent` service owning that socket;
- explicit account ids in each integration config;
- `--no-service` for secondary installers, or manual service units with a single
  owner for the shared socket;
- separate host-runtime homes such as `HERMES_HOME` and `OPENCLAW_HOME` if the
  gateway runtimes themselves should stay isolated.

The current Hermes, OpenClaw, and terminal-harness release installers are
optimized for isolated defaults. They also expose `MARMOT_HOME`,
`MARMOT_AGENT_SOCKET`, `MARMOT_AGENT_LABEL`, `MARMOT_AGENT_SERVICE_NAME`, and
`MARMOT_AGENT_LAUNCHD_LABEL` overrides for advanced layouts.

If `wn-agent` and a host gateway run as different local users, keep the socket
Unix-domain only and use the existing socket mode plus bearer-token options:
`--auth-token-file`, group-readable socket modes, and
`MARMOT_AGENT_AUTH_TOKEN_FILE`.

That bearer is a full-daemon credential, not an account selector or a read-only
integration key. A holder can read all inbound plaintext and perform every
control operation for every account in that connector home. Share a connector
only among integrations in the same trust boundary. For a less-trusted plugin,
gateway, or tenant, use another `wn-agent` home, socket, token, and account.

## Development Paths

Each integration has its own README and AGENTS file for local details. Common
entry points from the repo root:

```sh
just hermes-dev-script-test
just hermes-dev-e2e-deterministic
just hermes-dev-e2e-connector

just openclaw-dev-test
just openclaw-dev-script-test
just openclaw-dev-e2e-connector

cargo test -p wn-claude
just claude-dev-e2e-connector
just claude-installer-test

cargo test -p wn-codex
just codex-dev-e2e-connector
just codex-installer-test

cargo test -p wn-opencode
just opencode-dev-e2e-connector
just opencode-installer-test

cargo test -p marmot-terminal-harness

cargo test -p wn-pi
just pi-dev-e2e-connector
just pi-installer-test
```

For release-installer work, test dry-runs and real release assets from the
`wn-agent-v*` release family. Do not assume a source checkout script exactly
matches the published installer.
