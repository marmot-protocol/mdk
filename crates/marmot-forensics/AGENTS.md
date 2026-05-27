# AGENTS.md - marmot-forensics

Shared forensic dump schema for Marmot incident capture.

## Scope

- Own serializable dump types shared by app exports, UniFFI bindings, and internal analysis tooling.
- Keep this crate independent of engine, app, storage, transport SDK, and simulator crates.
- Keep public-mode helpers privacy-preserving by default: hash operational identifiers and never include raw payload bytes.
- Keep sensitive-mode fields explicit and easy to audit.

## Verification

```sh
cargo test -p marmot-forensics
```
