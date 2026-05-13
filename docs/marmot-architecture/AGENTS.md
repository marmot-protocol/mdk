# AGENTS.md - docs/marmot-architecture

Agent map for the Marmot architecture docs.

## Read order

1. `index.md`
2. `overview/executive-summary.md`
3. `overview/target-architecture.md`
4. `overview/current-state.md`
5. `overview/cgka-engine-quality-and-vectors.md`
6. `overview/whitenoise-integration-map.md`
7. `cgka-engine-spec.md`
8. `cgka-engine-canonicalization-contract.md`
9. `distributed-convergence.md`
10. `../../spec/README.md` when the task touches the Marmot v2 protocol draft.

## Document roles

- **Path:** `overview/`
  - **Role:** Current short orientation docs. Keep these readable in one sitting.

- **Path:** `overview/cgka-engine-quality-and-vectors.md`
  - **Role:** Current near-term engine quality and vector plan.

- **Path:** `overview/nostr-account-transport.md`
  - **Role:** Current working note for Nostr directory, bootstrap, relay-plane, and routing boundaries.

- **Path:** `overview/whitenoise-integration-map.md`
  - **Role:** Current shim map and engine API friction list for whitenoise-rs integration.

- **Path:** `further-context/`
  - **Role:** Older or deeper context. Check status and dates before relying on it.

- **Path:** `cgka-engine-spec.md`
  - **Role:** Draft normative engine spec.

- **Path:** `cgka-engine-canonicalization-contract.md`
  - **Role:** Detailed post-peeling convergence contract.

- **Path:** `distributed-convergence.md`
  - **Role:** Branch selection, retained anchors, and convergence model.

- **Path:** `../../spec/`
  - **Role:** Marmot v2 protocol draft by stable surface and app component.

## Conventions

- Use `CgkaEngine`, `TransportPeeler`, and `TransportAdapter` consistently.
- Treat `storage-sqlite` as the current persistent backend.
- Keep Nostr language separated into identity, app message format, and transport roles.
- Keep implementation architecture here. Put implementation-neutral protocol principles, wire surfaces, and app
  components in `../../spec/`.
- If Tamarin or Rust tests add a named scenario, mirror the name in the docs when that scenario becomes part of the
  contract.
