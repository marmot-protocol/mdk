# AGENTS.md - mdk

Repository-level map for agents. Read `README.md` first for the human-facing overview.

## Scope

This repo owns the Rust implementation workspace for Marmot:

- shared traits and cross-boundary types,
- OpenMLS-backed engine implementation,
- production-shaped account-device session wrapper,
- account orchestration,
- app runtime bridge,
- SQLCipher-backed storage backend,
- Nostr transport adapter and peeler,
- raw QUIC agent text stream preview transport and memory-only broker,
- agent control protocol, stream composition, and the `wn-agent` connector daemon,
- app message Markdown display parser,
- shared JSONL forensic audit schema,
- UniFFI bindings for the app runtime,
- CLI surface, daemon, and TUI,
- conformance simulator and vector fixtures,
- Tamarin models for distributed convergence,
- architecture notes and CGKA contracts.

The canonical protocol specification lives in
`github.com/marmot-protocol/marmot`. Keep implementation architecture and diagnostics in this repo.

## Where to go

| Task | Start here |
| --- | --- |
| Engine behavior | `crates/cgka-engine/AGENTS.md` |
| Engine integration tests | `crates/cgka-engine/tests/AGENTS.md` |
| Account-device session lifecycle | `crates/cgka-session/AGENTS.md` |
| Account orchestration / app-core shell | `crates/marmot-account/AGENTS.md` |
| App runtime bridge | `crates/marmot-app/AGENTS.md` |
| App message Markdown display parsing | `crates/marmot-markdown/AGENTS.md` |
| Storage traits and shared types | `crates/traits/AGENTS.md` |
| Private file/dir/socket creation helpers | `crates/fs-private/AGENTS.md` |
| SQLite storage | `crates/storage-sqlite/AGENTS.md` |
| Nostr transport adapter | `crates/transport-nostr-adapter/AGENTS.md` |
| Nostr transport peeler | `crates/transport-nostr-peeler/AGENTS.md` |
| QUIC agent text stream previews | `crates/transport-quic-stream/AGENTS.md` |
| QUIC preview broker | `crates/transport-quic-broker/AGENTS.md` |
| Agent control protocol DTOs / framing | `crates/agent-control/AGENTS.md` |
| Agent stream composition | `crates/agent-stream-compose/AGENTS.md` |
| `wn-agent` connector daemon | `crates/agent-connector/AGENTS.md` |
| Forensic audit schema | `crates/marmot-forensics/AGENTS.md` |
| App runtime UniFFI bindings | `crates/marmot-uniffi/AGENTS.md` |
| CLI / daemon / TUI surface | `crates/cli/AGENTS.md` |
| Multi-client harness / vectors | `crates/cgka-conformance-simulator/AGENTS.md` |
| Architecture docs | `docs/AGENTS.md` and `docs/marmot-architecture/AGENTS.md` |
| Formal model | `formal/tamarin/AGENTS.md` |

## Invariants

- Keep the engine generic over `S: cgka_traits::StorageProvider`.
- Keep transport-specific code out of `crates/cgka-engine`, `crates/traits`, and storage crates.
- Keep SQLite persistence one database per Marmot account-device identity.
- Keep Tamarin model names, Rust test names, and vector names easy to grep across layers.
- Keep protocol principles and app-component documents implementation-neutral in `marmot-protocol/marmot`. Local engine,
  storage, queue, and diagnostic notes belong in architecture docs or crate docs here.
- Keep tracing/logging privacy-safe: explicit crate/module `target` and `method` fields, aggregate values only, and no
  account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext, plaintext, or key material. See
  `docs/marmot-architecture/overview/observability.md`.
- Create local files, sockets, and databases restrictive-by-construction via `crates/fs-private` (or equivalent
  posture with an on-disk mode test); see `docs/marmot-architecture/overview/local-artifact-safety.md`.
- When adding an `AGENTS.md`, create a sibling `CLAUDE.md` symlink to it.

## Verification

Run `just fast-ci` before pushing; let GitHub CI run the full `just ci` test matrix.

`just fast-ci` covers formatting, compile-time checks, and clippy across the workspace (including OTLP feature builds).
It intentionally skips `just test`, which is the slow part of CI.

For crate-local changes, add targeted tests on top of `just fast-ci`:

```sh
just fast-ci
cargo test -p <crate-you-touched>
```

Full local parity with GitHub CI (slow):

```sh
just ci
```

Individual gates:

```sh
just fmt-check
just check
just clippy
just test
```

For formal-model changes:

```sh
just tamarin
```
