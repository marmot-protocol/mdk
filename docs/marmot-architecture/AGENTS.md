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
9. `convergence-reliability-plan.md`
10. `distributed-convergence.md`
11. `relay-delivery-telemetry.md`
12. `relay-observability.md`
13. `github.com/marmot-protocol/marmot` when the task touches the Marmot protocol specification.

## Document roles

- **Path:** `overview/`
  - **Role:** Current short orientation docs. Keep these readable in one sitting.

- **Path:** `overview/cgka-engine-quality-and-vectors.md`
  - **Role:** Current near-term engine quality and vector plan.

- **Path:** `overview/nostr-account-transport.md`
  - **Role:** Current working note for Nostr directory, bootstrap, relay-plane, and routing boundaries.

- **Path:** `overview/whitenoise-integration-map.md`
  - **Role:** Current shim map and engine API friction list for whitenoise-rs integration.

- **Path:** `overview/local-artifact-safety.md`
  - **Role:** Restrictive-by-construction creation policy for local files, sockets, and databases; the
    `crates/fs-private` helper contract; the close-before-suspension rules for WAL connections and the root lease.

- **Path:** `overview/dial-safety.md`
  - **Role:** One host-safety discipline for every outbound connection (validate resolved addresses, pin, trust from
    config, connect timeout); the `cgka_traits::app_components::host_safety` classifier and per-transport chokepoints.

- **Path:** `overview/multi-step-state-changes.md`
  - **Role:** No-torn-writes convention for multi-step state changes: validation/mutation ordering, compensation,
    intent-first reconciliation, and reality-reflecting confirmation.

- **Path:** `further-context/`
  - **Role:** Older or deeper context. Check status and dates before relying on it.

- **Path:** `cgka-engine-spec.md`
  - **Role:** Draft normative engine spec.

- **Path:** `cgka-engine-canonicalization-contract.md`
  - **Role:** Detailed post-peeling convergence contract.

- **Path:** `convergence-reliability-plan.md`
  - **Role:** Tracked convergence assurance, constant classification, simulator roadmap, verification gates, and
    campaign evidence.

- **Path:** `distributed-convergence.md`
  - **Role:** Branch selection, retained anchors, and convergence model.

- **Path:** `relay-delivery-telemetry.md`
  - **Role:** Relay delivery measurement and quiescence tuning; companion to `distributed-convergence.md`.

- **Path:** `relay-observability.md`
  - **Role:** Export contract for client-side relay telemetry: privacy contract, metric catalogue, and observability.md amendment.

- **Path:** `telemetry.md`
  - **Role:** Current implementation inventory for telemetry, logging, and tracing: OTLP export, engine reorg metrics, and the collected/exported fields.

- **Path:** `audit-logging.md`
  - **Role:** Current implementation inventory for opt-in forensic JSONL logs: file identity, event kinds/metadata, and upload/tracker behavior.

- **Path:** `runtime-state-bounds.md`
  - **Role:** Inventory of long-lived daemon/broker runtime structures with their bounds and eviction/reclamation rules; the tracked-resource discipline for new long-lived state.

- **Path:** `hermes-agent-production-runbook.md`
  - **Role:** Draft operational runbook for the Hermes agent deployment. Check status and dates before relying on it.

- **Path:** `hermes-openclaw-agent-integration-plan.md`
  - **Role:** Working plan for the Hermes/OpenClaw agent integration. Check status and dates before relying on it.

- **Path:** `../../integrations/AGENTS.md`, `../../integrations/hermes/marmot/AGENTS.md`,
  `../../integrations/openclaw/marmot/AGENTS.md`, `../../integrations/codex/marmot/AGENTS.md`,
  `../../integrations/opencode/marmot/AGENTS.md`,
  `../../integrations/pi/marmot/AGENTS.md`, and `../../integrations/terminal-harness/AGENTS.md`
  - **Role:** Host integration boundaries, connector coexistence, and verification for the Hermes, OpenClaw,
    Codex, OpenCode, and Pi integrations plus their shared terminal-harness runtime.

- **Repo:** `github.com/marmot-protocol/marmot`
  - **Role:** Marmot protocol specification by stable surface and app component.

## Conventions

- Use `CgkaEngine`, `TransportPeeler`, and `TransportAdapter` consistently.
- Treat `storage-sqlite` as the current persistent backend.
- Keep Nostr language separated into identity, app message format, and transport roles.
- Keep implementation architecture here. Put implementation-neutral protocol principles, wire surfaces, and app
  components in `github.com/marmot-protocol/marmot`.
- If Tamarin or Rust tests add a named scenario, mirror the name in the docs when that scenario becomes part of the
  contract.
- When adding or changing a convergence policy, resource, scheduler, or history-recovery constant, register it on all
  five ledger surfaces: a row per symbol in `convergence-constant-inventory.txt`; a Table 1 row, a Table 2 ownership
  row, and a progress-log row in `convergence-reliability-plan.md`; the `expected_ids` allowlist in
  `scripts/check_convergence_constant_ledger.sh`; and a `decision(...)` entry (one per ledger id, array length bumped)
  in `crates/cgka-conformance-simulator/src/policy_contract.rs`. One ledger id may own several symbols that answer one
  decision (A3, E7, A10 do). Enforcement is split and disjoint, so run both gates — `just fast-ci` runs only the first:

  ```sh
  just convergence-ledger-gate
  cargo test -p cgka-conformance-simulator --test protocol_decision_gate
  ```
