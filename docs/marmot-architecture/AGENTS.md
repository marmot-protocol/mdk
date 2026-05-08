# AGENTS.md - docs/marmot-architecture

Agent map for the Marmot architecture docs.

## Read order

1. `index.md`
2. `overview/executive-summary.md`
3. `overview/target-architecture.md`
4. `overview/current-state.md`
5. `cgka-engine-spec.md`
6. `cgka-engine-canonicalization-contract.md`
7. `distributed-convergence.md`

## Document roles

| Path | Role |
| --- | --- |
| `overview/` | Current short orientation docs. Keep these readable in one sitting. |
| `further-context/` | Older or deeper context. Check status and dates before relying on it. |
| `cgka-engine-spec.md` | Draft normative engine spec. |
| `cgka-engine-canonicalization-contract.md` | Detailed post-peeling convergence contract. |
| `distributed-convergence.md` | Branch selection, retained anchors, and convergence model. |

## Conventions

- Use `CgkaEngine`, `TransportPeeler`, and `TransportAdapter` consistently.
- Treat `storage-sqlite` as the current persistent backend.
- Keep Nostr language separated into identity, app message format, and
  transport roles.
- If Tamarin or Rust tests add a named scenario, mirror the name in the docs
  when that scenario becomes part of the contract.
