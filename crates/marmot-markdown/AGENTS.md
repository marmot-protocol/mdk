# AGENTS.md - crates/marmot-markdown

Markdown parser and typed AST for app message rendering.

## Scope

- Keep this crate independent from CGKA engine, storage, transport, and runtime state.
- Parse plaintext message content into a display-oriented AST only; do not define wire format or persistence policy here.
- Keep the parser dependency-light. Runtime dependencies should stay limited to `serde` unless a deliberate parser-design change is made.
- Preserve nostr-aware inline handling and reject ergonomic rendering for private-key entities.
- Add parser behavior with golden/unit coverage before exposing it through FFI.

## Verification

```sh
cargo test -p marmot-markdown
```
