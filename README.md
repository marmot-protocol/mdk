# darkmatter

Candidate CGKA engine, storage backends, simulator, and formal models for the
Marmot protocol work.

## What is in this repository

- `crates/traits` defines the cross-boundary engine, transport adapter,
  peeler, storage, and value types.
- `crates/cgka-engine` implements the OpenMLS-backed engine candidate.
- `crates/cgka-session` wires `Engine<SqliteStorage>` into a
  production-shaped account-device lifecycle.
- `crates/marmot-account` is the thin future app-core shell over a session and
  transport adapter: account activation, transport routing policy, KeyPackage
  publication, and publish confirmation/rollback.
- `crates/marmot-lab` provides a local two-client CLI lab over a file-backed
  fake relay for fast end-to-end checks with real sessions and the Nostr
  adapter stack.
- `crates/storage-memory` provides an in-memory backend for tests and simulator
  runs.
- `crates/storage-sqlite` provides SQLCipher-backed persistence for Marmot
  metadata and group-scoped OpenMLS state.
- `crates/transport-nostr-adapter` implements the Nostr transport adapter core:
  account activation, group subscription sync, relay-event routing, and publish
  reports behind an injectable relay-client boundary, with an optional
  `nostr-sdk` backed client.
- `crates/transport-nostr-peeler` maps Nostr kind `445` / `1059` events into
  engine transport messages and peels Nostr/MLS group envelopes.
- `crates/cgka-conformance-simulator` drives multi-client scenarios, generated
  delivery variants, vector fixtures, and property tests.
- `formal/tamarin` contains the abstract convergence model and proof harness.
- `docs/marmot-architecture` contains architecture notes and the CGKA
  engine/convergence contracts.
- `spec/` is the rewrite sandbox for the Marmot protocol spec. It is organized
  by protocol surface instead of MIP number.

## Testing map

The engine tests and simulator answer different questions.

- `cargo test -p cgka-engine` checks the local engine boundary: one engine call,
  one storage backend, one expected outcome.
- `cargo test -p cgka-conformance-simulator` checks many clients running the
  engine together through the Nostr peeler and an in-memory transport bus. It
  also runs the checked-in vector fixtures.
- `cargo test -p cgka-conformance-simulator --features conformance-slow` raises
  the property-test case counts for a slower pre-release pass.

The normal test command already validates the portable JSON vector fixtures.
Run the report command when you want one JSON report per fixture plus a
human-readable pass/fail summary:

```sh
cargo run -p cgka-conformance-simulator --bin cgka-conformance-simulator-report -- \
  --vectors crates/cgka-conformance-simulator/vectors \
  --out target/cgka-conformance-simulator-reports
```

Start with [`crates/cgka-engine/README.md`](crates/cgka-engine/README.md) for
the engine-level story, then use
[`crates/cgka-conformance-simulator/README.md`](crates/cgka-conformance-simulator/README.md)
for scenarios, vectors, generated chaos cases, reports, and property tests.

## Start here

1. `docs/marmot-architecture/index.md`
2. `docs/marmot-architecture/overview/current-state.md`
3. `docs/marmot-architecture/overview/observability.md`
4. `crates/cgka-engine/README.md`
5. `crates/cgka-session/README.md`
6. `crates/marmot-account/README.md`
7. `crates/storage-sqlite/README.md`
8. `crates/transport-nostr-adapter/README.md`
9. `crates/transport-nostr-peeler/README.md`
10. `crates/marmot-lab/README.md`
11. `spec/README.md`
12. `formal/tamarin/README.md`

## Common commands

```sh
just fmt-check
just check
just clippy
just test
just tracing-audit
just tamarin
```

`just tamarin` requires `tamarin-prover` on `PATH`.

## Agent guidance

Read `AGENTS.md` in the directory you are changing. `CLAUDE.md` files are
symlinks to the same guidance so Claude-based tooling reads the canonical file.
For spec rewrite work, start in `spec/README.md` and `spec/AGENTS.md`.
