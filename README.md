# MDK — Marmot Development Kit

MDK is the Rust implementation of [Marmot](https://github.com/marmot-protocol/marmot), an end-to-end encrypted group
messaging protocol built on [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) with Nostr identity. It powers
White Noise: the protocol engine, encrypted storage, Nostr transport, the app runtime behind the mobile bindings, the
`wn` command-line app, and the `wn-agent` connector that brings AI agents into encrypted chats.

The protocol specification lives in [marmot-protocol/marmot](https://github.com/marmot-protocol/marmot). This repository
holds the implementation, its architecture notes, conformance tests, formal models, and release tooling.

## Contents

- [Find your way](#find-your-way)
- [Chat with an AI agent](#chat-with-an-ai-agent)
- [The `wn` command-line app](#the-wn-command-line-app)
- [Build an app on MDK](#build-an-app-on-mdk)
- [How MDK is built](#how-mdk-is-built)
- [How convergence works](#how-convergence-works)
- [Crate map](#crate-map)
- [Development](#development)
- [Releases](#releases)
- [License](#license)

## Find your way

| I want to… | Start here |
| --- | --- |
| Talk to Hermes, OpenClaw, Claude Code, Codex, OpenCode, Pi, or Goose from White Noise | [White Noise + Agents quickstart](integrations/README.md) |
| Use White Noise from a terminal (CLI, daemon, TUI) | [`wn` guide](crates/cli/README.md) |
| Integrate MDK into an iOS, macOS, or Android app | [MarmotKit integration guide](crates/marmot-uniffi/README.md) |
| Integrate from C or another raw-FFI host | [C ABI guide](crates/marmot-c/README.md) |
| Upgrade an app to a new MDK release | [Version upgrade guides](docs/integration/README.md) |
| Understand the Marmot protocol | [Marmot specification](https://github.com/marmot-protocol/marmot) |
| Understand MDK's architecture | [Architecture index](docs/marmot-architecture/index.md) |
| Understand how clients agree on group state | [How convergence works](#how-convergence-works) |
| Contribute code | [Development](#development) |
| Cut a release | [Release guide](release.md) |

## Chat with an AI agent

`wn-agent` gives an agent runtime its own White Noise identity and bridges encrypted Marmot chats to it over a local
control socket (same-user by default, optional bearer token). You invite the agent from White Noise on your phone like any other contact; only accounts
you allowlist can invite or message it.

| Runtime | Connector | Docs |
| --- | --- | --- |
| Hermes | Gateway plugin | [integrations/hermes](integrations/hermes/marmot/README.md) |
| OpenClaw | Channel plugin | [integrations/openclaw](integrations/openclaw/marmot/README.md) |
| Claude Code | Terminal harness | [integrations/claude](integrations/claude/marmot/README.md) |
| Codex | Terminal harness | [integrations/codex](integrations/codex/marmot/README.md) |
| OpenCode | Terminal harness | [integrations/opencode](integrations/opencode/marmot/README.md) |
| Pi | Terminal harness | [integrations/pi](integrations/pi/marmot/README.md) |
| Goose | Terminal harness | [integrations/goose](integrations/goose/marmot/README.md) |

The [quickstart](integrations/README.md) installs a checksum-verified release on macOS or Linux and gets you to a first
encrypted chat. For how connectors share one machine, identities, and allowlists, see
[How the connectors fit together](integrations/README.md#how-the-connectors-fit-together). The connector daemon itself is documented in
[`crates/agent-connector`](crates/agent-connector/README.md).

## The `wn` command-line app

`wn` manages accounts, relays, KeyPackages, chats, groups, and messages, and includes a terminal UI (`wn tui`). `wnd`
is the background daemon that keeps accounts synced and serves the CLI and TUI. Install both from a checkout:

```sh
cargo install --path crates/cli --locked --bins
```

The [`wn` guide](crates/cli/README.md) covers configuration, a two-account quick start against local relays, the full
command map, the daemon, the TUI, and JSON output for scripting.

## Build an app on MDK

Apps embed MDK through the multi-account app runtime ([`marmot-app`](crates/marmot-app/README.md)), exposed as:

- **MarmotKit** — UniFFI bindings for Swift (iOS, macOS) and Kotlin (Android). Start with the
  [integration guide](crates/marmot-uniffi/README.md), then the [complete method reference](crates/marmot-uniffi/API-REFERENCE.md)
  and [distribution notes](crates/marmot-uniffi/DISTRIBUTION.md).
- **Marmot C** — a C ABI over the same runtime, with ownership and blocking-call rules in the
  [C guide](crates/marmot-c/README.md) and every symbol in its [reference](crates/marmot-c/API-REFERENCE.md).

Each release ships a concise [release note](docs/release/) and a detailed [upgrade guide](docs/integration/README.md)
with required changes, new defaults, and optional features. The latest is [0.11.0 → 0.12.0](docs/integration/0.12.0.md);
read every intervening guide when skipping releases. Read docs at the tag matching your binaries — `master` may describe
unreleased APIs.

## How MDK is built

MDK separates the protocol engine from storage, transport, and application concerns so each can be tested, replaced,
and reasoned about on its own:

```text
 apps (MarmotKit / C)    wn CLI · wnd · TUI    wn-agent ──► agent runtimes
            └────────────────┬─────┴──────────────┘
                     marmot-app        multi-account runtime, projections, relay plane
                     marmot-account    account homes, keys, transport orchestration
                     cgka-session      one encrypted account-device lifecycle
                     cgka-engine       OpenMLS group state machine + commit convergence
                     storage-sqlite    SQLCipher persistence (one DB per account-device)

 transport-nostr-peeler / -adapter   Nostr events ⇄ engine messages, relay I/O
 transport-quic-stream / -broker     transient live previews for agent replies
```

- The engine is generic over a storage trait and knows nothing about Nostr; transport code lives in the peeler and
  adapter.
- Nostr plays three roles — identity, app message format, and (pluggable) transport. See
  [Nostr's role](docs/marmot-architecture/overview/nostr-role.md).
- For the full picture, start with the [executive summary](docs/marmot-architecture/overview/executive-summary.md),
  [target architecture](docs/marmot-architecture/overview/target-architecture.md), and
  [protocol boundary](docs/marmot-architecture/overview/protocol-boundary.md), all linked from the
  [architecture index](docs/marmot-architecture/index.md).

## How convergence works

In Marmot, commits are the consensus log. Clients fetch from several relays, see messages in different orders, and may
come back online holding commits from abandoned branches. Every honest client that receives the same valid messages must
still land on the same epoch and group state. The engine — not relay order or timestamps — picks the canonical branch.

| To understand… | Read |
| --- | --- |
| The convergence model | [Distributed convergence](docs/marmot-architecture/distributed-convergence.md) |
| The engine's canonicalization contract | [Canonicalization contract](docs/marmot-architecture/cgka-engine-canonicalization-contract.md) |
| How it is tested: scenarios, vectors, generated chaos, property tests | [Conformance simulator](crates/cgka-conformance-simulator/README.md) |
| Multi-process and container campaigns | [Campaign runner](crates/convergence-campaign-runner/README.md) |
| Formal proofs and how they map to Rust tests | [Tamarin models](formal/tamarin/README.md) |
| What the engine owns and leaves out | [`cgka-engine`](crates/cgka-engine/README.md) |

## Crate map

| Area | Crate | What it is |
| --- | --- | --- |
| Engine | [`cgka-engine`](crates/cgka-engine/README.md) | OpenMLS-backed group state machine and commit convergence |
| | [`traits`](crates/traits/README.md) (`cgka-traits`) | Shared traits and cross-boundary types |
| | [`cgka-session`](crates/cgka-session/README.md) | Encrypted account-device session over the engine |
| Storage | [`storage-sqlite`](crates/storage-sqlite/README.md) | SQLCipher persistence for engine, session, and simulator |
| | [`fs-private`](crates/fs-private/README.md) | Owner-only file, directory, and socket creation |
| Transport | [`transport-nostr-peeler`](crates/transport-nostr-peeler/README.md) | Nostr event ⇄ engine message boundary |
| | [`transport-nostr-adapter`](crates/transport-nostr-adapter/README.md) | Relay I/O behind an injectable client |
| | [`transport-quic-stream`](crates/transport-quic-stream/README.md) | QUIC transport for live agent text previews |
| | [`transport-quic-broker`](crates/transport-quic-broker/README.md) | Memory-only preview broker (`marmot-quic-broker`); [deployment](docs/quic-broker-deployment.md) |
| App | [`marmot-account`](crates/marmot-account/README.md) | Account homes, key storage, transport orchestration |
| | [`marmot-app`](crates/marmot-app/README.md) | Multi-account app runtime used by every front end |
| | [`marmot-markdown`](crates/marmot-markdown/README.md) | CommonMark + Nostr display parser for messages |
| | [`marmot-forensics`](crates/marmot-forensics/README.md) | Append-only JSONL forensic audit schema |
| Bindings | [`marmot-uniffi`](crates/marmot-uniffi/README.md) | MarmotKit: Swift and Kotlin bindings |
| | [`marmot-c`](crates/marmot-c/README.md) | C ABI bindings |
| Front ends | [`cli`](crates/cli/README.md) (`wn-cli`) | `wn`, `wnd`, and `wn tui` |
| Agents | [`agent-connector`](crates/agent-connector/README.md) | The `wn-agent` connector daemon |
| | [`agent-control`](crates/agent-control/README.md) | Agent control protocol messages and framing |
| | [`agent-stream-compose`](crates/agent-stream-compose/README.md) | Live-preview stream composition |
| | [`integrations/`](integrations/README.md) | Per-runtime plugins and terminal harnesses |
| Verification | [`cgka-conformance-simulator`](crates/cgka-conformance-simulator/README.md) | Multi-client scenarios, vectors, chaos, property tests |
| | [`convergence-campaign-runner`](crates/convergence-campaign-runner/README.md) | Distributed container/VM campaigns |
| | [`incident-replay`](crates/incident-replay/README.md) | Triages forensic exports of real incidents into verdicts and simulator vectors |
| | [`formal/tamarin`](formal/tamarin/README.md) | Tamarin models for convergence and lifecycle |

## Development

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml); most tasks run through [`just`](Justfile).

`Cargo.toml` patches HPKE 0.7 with the local [`vendor/hpke-rs-libcrux`](vendor/hpke-rs-libcrux/BACKPORT.md)
provider to use `libcrux-kem 0.0.10`, fixing RUSTSEC-2026-0330 and RUSTSEC-2026-0331.
Its backport notes record provenance, regression commands and the removal condition.

```sh
just fast-ci                 # formatting, doc/naming gates, compile checks, clippy; skips the `just test` matrix
cargo test -p <crate>        # targeted tests for the crate you changed
just ci                      # full local parity with GitHub CI (slow)
```

CI builds the workspace test archive, runs its five shards, and checks doctests and diagnostic exporters on runners
labelled `self-hosted`, `linux`, and `x64`. The jobs install `build-essential`, `pkg-config`, and Perl, bootstrap Rustup
when absent, and install the pinned toolchain. Runners need `apt-get` and either root access or passwordless `sudo`.
Archive builders and test shards need compatible system libraries. Other CI jobs use GitHub-hosted runners.

Common targeted runs:

```sh
cargo test -p cgka-engine
cargo test -p cgka-conformance-simulator                            # scenarios, vectors, property tests
cargo test -p cgka-conformance-simulator --features conformance-slow  # wider property-test run
just tamarin                                                        # formal models
```

The CLI's real-relay end-to-end tests need the local relay stack:

```sh
just relay-up
just e2e-test
just relay-down
```

Notes:

- **Stack size.** [`.cargo/config.toml`](.cargo/config.toml) sets `RUST_MIN_STACK=4194304` for Cargo-launched tests and
  debug binaries; unoptimized OpenMLS can overflow the default 2 MiB thread stack. Export the same value if you run a
  debug binary directly.
- **WASM.** `just wasm-check` is a compile-only gate for `cgka-traits`, `cgka-engine`, and `transport-nostr-peeler` on
  `wasm32-unknown-unknown` (`rustup target add wasm32-unknown-unknown`; set `CC_wasm32_unknown_unknown` to a Clang with a
  wasm32 backend if needed). It does not claim browser support for storage, the runtime, bindings, or the CLI.
- **Commits** must be cryptographically signed.

## Releases

MDK versions the whole workspace as one compatibility cohort and publishes separate artifact tracks from the same
commit: the source snapshot (`v<version>`), the `wn-agent` connector (`wn-agent-v<version>`), MarmotKit bindings
(`marmotkit-v<version>`), and the C bindings (`marmotc-v<version>`). The [release guide](release.md) is the checklist;
per-release notes live in [`docs/release/`](docs/release/).

## License

[MIT](LICENSE).
