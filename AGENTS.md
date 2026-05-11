# AGENTS.md - darkmatter

Repository-level map for agents. Read `README.md` first for the human-facing
overview.

## Scope

This repo owns the candidate CGKA engine workspace:

- shared traits and cross-boundary types,
- OpenMLS-backed engine implementation,
- production-shaped account-device session wrapper,
- future app-core account orchestration,
- in-memory and SQLCipher-backed storage backends,
- Nostr transport adapter and peeler,
- conformance simulator and vector fixtures,
- Tamarin models for distributed convergence,
- architecture notes and CGKA contracts,
- Marmot protocol spec rewrite drafts.

## Where to go

| Task | Start here |
| --- | --- |
| Engine behavior | `crates/cgka-engine/AGENTS.md` |
| Engine integration tests | `crates/cgka-engine/tests/AGENTS.md` |
| Account-device session lifecycle | `crates/cgka-session/AGENTS.md` |
| Account orchestration / app-core shell | `crates/marmot-account/AGENTS.md` |
| Storage traits and shared types | `crates/traits/AGENTS.md` |
| In-memory storage | `crates/storage-memory/AGENTS.md` |
| SQLite storage | `crates/storage-sqlite/AGENTS.md` |
| Nostr transport adapter | `crates/transport-nostr-adapter/AGENTS.md` |
| Nostr transport peeler | `crates/transport-nostr-peeler/AGENTS.md` |
| Local two-client lab | `crates/marmot-lab/README.md` |
| Multi-client harness / vectors | `crates/cgka-conformance-simulator/AGENTS.md` |
| Architecture docs | `docs/AGENTS.md` and `docs/marmot-architecture/AGENTS.md` |
| Spec rewrite sandbox | `spec/AGENTS.md` |
| Formal model | `formal/tamarin/AGENTS.md` |

## Invariants

- Keep the engine generic over `S: cgka_traits::StorageProvider`.
- Keep transport-specific code out of `crates/cgka-engine`, `crates/traits`,
  and storage crates.
- Keep SQLite persistence one database per Marmot account-device identity.
- Keep Tamarin model names, Rust test names, and vector names easy to grep
  across layers.
- Keep protocol laws and app-component drafts in `spec/` implementation-neutral.
  Local engine, storage, queue, and diagnostic notes belong in
  `spec/implementation-model.md` or architecture docs.
- Keep tracing/logging privacy-safe: explicit crate/module `target` and
  `method` fields, aggregate values only, and no account ids, group ids,
  message ids, relay URLs, pubkeys, payloads, ciphertext, plaintext, or key
  material. See `docs/marmot-architecture/overview/observability.md`.
- When adding an `AGENTS.md`, create a sibling `CLAUDE.md` symlink to it.

## Verification

Use the smallest command that covers the change, then widen before checkpointing
cross-crate work:

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
