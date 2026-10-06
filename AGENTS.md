# AGENTS.md - mdk

Repository-level rules and routing for coding agents. `README.md` is the human overview (what each crate is, how the
layers fit); don't duplicate it here.

The canonical protocol specification lives in `github.com/marmot-protocol/marmot`. This repo owns the Rust
implementation, its architecture notes, conformance fixtures, formal models, and diagnostics.

Nested `AGENTS.md` files add rules for their subtree. Read the nearest one before editing.

## MDK and host-app ownership

MDK owns shared product logic and authoritative state; White Noise Android is a
minimal display and Android platform layer. Follow [the host-app boundary](docs/marmot-architecture/overview/app-core-boundary.md#host-app-boundary)
before adding behavior or bindings.

## Where to go

| Task | Start here |
| --- | --- |
| Engine behavior | `crates/cgka-engine/AGENTS.md` (`src/`, `tests/` have their own) |
| Account-device session lifecycle | `crates/cgka-session/AGENTS.md` (`tests/` has its own) |
| Account orchestration / app-core shell | `crates/marmot-account/AGENTS.md` |
| App runtime bridge | `crates/marmot-app/AGENTS.md` |
| App message Markdown display parsing | `crates/marmot-markdown/AGENTS.md` |
| Storage traits and shared types | `crates/traits/AGENTS.md` |
| Private file/dir/socket creation helpers | `crates/fs-private/AGENTS.md` |
| SQLite storage | `crates/storage-sqlite/AGENTS.md` (`src/migrations/`, `src/openmls_storage/`, `src/storage/`, `src/storage/snapshots/` have their own) |
| Nostr transport adapter | `crates/transport-nostr-adapter/AGENTS.md` |
| Nostr transport peeler | `crates/transport-nostr-peeler/AGENTS.md` |
| QUIC agent text stream previews | `crates/transport-quic-stream/AGENTS.md` |
| QUIC preview broker | `crates/transport-quic-broker/AGENTS.md` |
| Agent control protocol DTOs / framing | `crates/agent-control/AGENTS.md` |
| Agent stream composition | `crates/agent-stream-compose/AGENTS.md` |
| `wn-agent` connector daemon | `crates/agent-connector/AGENTS.md` |
| Host integrations / connector coexistence | `integrations/AGENTS.md` |
| Hermes gateway plugin | `integrations/hermes/marmot/AGENTS.md` (tests: `integrations/hermes/tests/marmot/AGENTS.md`) |
| OpenClaw channel plugin | `integrations/openclaw/marmot/AGENTS.md` |
| Shared terminal-harness runtime | `integrations/terminal-harness/AGENTS.md` |
| Claude Code / Codex / OpenCode / Pi harnesses | `integrations/{claude,codex,opencode,pi}/marmot/AGENTS.md` |
| Forensic audit schema | `crates/marmot-forensics/AGENTS.md` |
| App runtime UniFFI bindings | `crates/marmot-uniffi/AGENTS.md` |
| App runtime C ABI bindings | `crates/marmot-c/AGENTS.md` |
| CLI / daemon / TUI surface | `crates/cli/AGENTS.md` |
| Multi-client harness / vectors | `crates/cgka-conformance-simulator/AGENTS.md` (`src/`, `tests/`, `vectors/` have their own) |
| Container/VM convergence campaigns | `crates/convergence-campaign-runner/AGENTS.md` |
| Goggles incident replay adapter | `crates/incident-replay/AGENTS.md` |
| Architecture docs | `docs/AGENTS.md` and `docs/marmot-architecture/AGENTS.md` |
| Formal model | `formal/tamarin/AGENTS.md` |
| Releases | `release.md` |

## Documentation

- `README.md` files are for humans: what it is, how to use it, where to go next. `AGENTS.md` files are for agents:
  boundaries, invariants, code map, editing rules, verification. Keep agent directives out of READMEs and tutorials
  out of `AGENTS.md`; link instead of duplicating.
- When you add, rename, or remove a crate, binary, `just` recipe, or user-facing command, update the root `README.md`
  crate map and the affected crate README in the same change.
- Do not add `CLAUDE.md` files or symlinks; `AGENTS.md` is the single agent-instruction file.

## Invariants

- Keep the engine generic over `S: cgka_traits::StorageProvider`.
- Keep transport-specific code out of `crates/cgka-engine`, `crates/traits`, and storage crates.
- Keep SQLite persistence one database per Marmot account-device identity.
- Keep Tamarin model names, Rust test names, and vector names easy to grep across layers.
- Keep protocol principles and app-component documents implementation-neutral in `marmot-protocol/marmot`. Local engine,
  storage, queue, and diagnostic notes belong in architecture docs or crate docs here.
- Keep MLS group ids distinct from transport routing ids. `GroupId` is opaque MLS group id bytes; OpenMLS-generated ids
  are 16 bytes today, but spec surfaces that bind raw MLS group ids length-prefix them because they are variable-length.
  `nostr_group_id` / `transport_group_id` is the 32-byte Nostr routing handle. Do not apply the 32-byte Nostr route-id
  rule to `GroupId` validation, FFI parsing, storage lookups, or CLI/app group-id filters.
- Keep tracing/logging privacy-safe: explicit crate/module `target` and `method` fields, aggregate values only, and no
  account ids, group ids, message ids, relay URLs, pubkeys, payloads, ciphertext, plaintext, or key material. See
  `docs/marmot-architecture/overview/observability.md`.
- Create local files, sockets, and databases restrictive-by-construction via `crates/fs-private` (or equivalent
  posture with an on-disk mode test), and release their file locks explicitly before a host suspends
  (`MarmotAppRuntime::shutdown_and_close`); see `docs/marmot-architecture/overview/local-artifact-safety.md`.
- Route every outbound connection through the host-safety dial discipline: validate each resolved address with
  `cgka_traits::app_components::reject_non_public_ip`, pin the validated address, choose TLS trust from config (never a
  resolved IP), apply a connect timeout, and gate loopback behind an explicit dev flag. See
  `docs/marmot-architecture/overview/dial-safety.md`.
- Never dial or adopt hosts on the centralized retired-relay denylist. Retired
  relays must not be used for discovery, bootstrap, examples, or runtime
  traffic; keep exact endpoint literals confined to the denylist and rejection
  regression tests.
- Keep multi-step state changes torn-write-free: validate before mutating, compensate every applied step on the error
  path, record intent before external side effects, and never confirm work that reached no one. See
  `docs/marmot-architecture/overview/multi-step-state-changes.md`.
- Treat workspace and conformance-fixture version bumps as manual release operations. Never change the root workspace
  version, workspace package versions in `Cargo.lock`, or vector `conformance_version` values during feature, fix,
  binding, or review-feedback work unless the user explicitly requests that version bump.
- Keep binding READMEs and complete method references current with API changes; run `just binding-docs-gate`.
  Starting with 0.10.2, every release requires concise `docs/release/<version>.md` notes and a detailed
  `docs/integration/<version>.md` companion, indexed and linked both ways. Follow `release.md#release-documentation`:
  distinguish required changes, new defaults, optional adoption and automatic fixes; preserve supported lower-level
  APIs and exact artifact provenance. Post-tag documentation uses a supplement commit, never a moved release tag.
- Title GitHub Releases with the version first so release lists group by cohort: whole-workspace `v<version> - MDK`,
  WN Agent `v<version> - wn-agent`, and MarmotKit `v<version> - MarmotKit`.
- Prefer `just release-all <version>` for a full MDK/WN Agent/MarmotKit cohort release, or
  `just release-all-draft <version>` when releases should stay draft for manual publication.
- Sign every commit before pushing. This repository accepts only cryptographically signed commits;
  configure Git SSH signing (or another accepted signing method) and verify the signature locally.

## Verification

Run `just fast-ci` before pushing; let GitHub CI run the full `just ci` test matrix.

Exception: for an initial cohort-release PR limited to version fields, workspace package versions in `Cargo.lock`,
vector `conformance_version` values, changelogs, release/integration documentation, README/install version pins, and
other release metadata, run only `just release-pr-preflight <version>`, then open the PR and let GitHub CI provide the
compile/test signal. Do not run `just fast-ci`, `just test`, `just ci`, Tamarin, benchmarks, binding bundle builds, or
artifact builds before opening that PR. If preparing the release exposes an implementation or workflow defect, fix it
in a separate PR with the normal targeted verification instead of expanding the metadata PR. After the metadata PR is
merged and required CI succeeds, run `just release-all <version>` to build and publish the cohort.

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
just install-example-sha256-gate
```

The install-example gate renders all six installer `--help` surfaces and checks
release guidance plus workflow-generated notes for download, sibling `.sha256`
verification (`shasum` or `sha256sum`), then local execution. It also rejects
new download-to-shell examples in tracked Markdown, shell, and workflow files.

For formal-model changes:

```sh
just tamarin
```
