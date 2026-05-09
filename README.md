# darkmatter

Candidate CGKA engine, storage backends, simulator, and formal models for the
Marmot protocol work.

## What is in this repository

- `crates/traits` defines the cross-boundary engine, transport adapter,
  peeler, storage, and value types.
- `crates/cgka-engine` implements the OpenMLS-backed engine candidate.
- `crates/cgka-session` wires `Engine<SqliteStorage>` into a
  production-shaped account-device lifecycle.
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
- `docs/marmot-architecture` contains the current spec drafts and architecture
  notes.

## Start here

1. `docs/marmot-architecture/index.md`
2. `docs/marmot-architecture/overview/current-state.md`
3. `docs/marmot-architecture/overview/observability.md`
4. `crates/cgka-engine/README.md`
5. `crates/cgka-session/README.md`
6. `crates/storage-sqlite/README.md`
7. `crates/transport-nostr-adapter/README.md`
8. `crates/transport-nostr-peeler/README.md`
9. `formal/tamarin/README.md`

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
