# AGENTS.md - docs

Docs guidance for agents.

## Current docs

Use `marmot-architecture/index.md` as the entry point. The `overview/` pages are
the current orientation set. The `further-context/` pages are deeper background
and may contain older exploratory wording.

The protocol spec rewrite sandbox lives outside this directory in `../spec/`.
Use it for implementation-neutral Marmot protocol text. Keep repository and
engine-specific notes in `marmot-architecture/` or crate docs.

`required-features.md` is the protocol boundary principles document. Treat it
as a high-level constraint, not an implementation checklist.

## Editing rules

- Update `updated:` dates in front matter when changing a dated architecture
  page.
- Keep spec-like language in `cgka-engine-spec.md`,
  `cgka-engine-canonicalization-contract.md`, and
  `distributed-convergence.md`.
- Keep overview docs short. Move long rationale into `further-context/`.
- When changing code behavior, update `overview/current-state.md` if the public
  status changed.
- Keep observability guidance current in
  `marmot-architecture/overview/observability.md` when tracing/logging policy
  changes.
- When a protocol rule graduates from exploratory architecture text, link to the
  matching `../spec/` document instead of copying the rule into multiple docs.

## Verification

After doc changes, run:

```sh
rg -n "TODO|TBD|open question|future SQLite|production storage|retry-deferred|AlreadyAtEpoch.*Peel" docs --glob '!AGENTS.md'
```

Review matches before deciding whether they are stale.
