# AGENTS.md - docs

Docs guidance for agents.

## Current docs

Use `marmot-architecture/index.md` as the entry point. The `overview/` pages are
the current orientation set. The `further-context/` pages are deeper background
and may contain older exploratory wording.

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

## Verification

After doc changes, run:

```sh
rg -n "future SQLite|production storage|TODO|TBD" docs
```

Review matches before deciding whether they are stale.
