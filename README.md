# darkmatter

Candidate CGKA engine, storage backends, simulator, and formal models for the
Marmot protocol work.

## What is in this repository

- `crates/traits` defines the cross-boundary engine, peeler, storage, and value
  types.
- `crates/cgka-engine` implements the OpenMLS-backed engine candidate.
- `crates/storage-memory` provides an in-memory backend for tests and simulator
  runs.
- `crates/storage-sqlite` provides SQLCipher-backed persistence for Marmot
  metadata and group-scoped OpenMLS state.
- `crates/cgka-conformance-simulator` drives multi-client scenarios, generated
  delivery variants, vector fixtures, and property tests.
- `formal/tamarin` contains the abstract convergence model and proof harness.
- `docs/marmot-architecture` contains the current spec drafts and architecture
  notes.

## Start here

1. `docs/marmot-architecture/index.md`
2. `docs/marmot-architecture/overview/current-state.md`
3. `crates/cgka-engine/README.md`
4. `crates/storage-sqlite/README.md`
5. `formal/tamarin/README.md`

## Common commands

```sh
just fmt-check
just check
just clippy
just test
just tamarin
```

`just tamarin` requires `tamarin-prover` on `PATH`.

## Agent guidance

Read `AGENTS.md` in the directory you are changing. `CLAUDE.md` files are
symlinks to the same guidance so Claude-based tooling reads the canonical file.
