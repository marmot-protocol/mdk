# AGENTS.md - crates/marmot-markdown

Markdown parser and typed AST for app message rendering. For the human overview, renderer security contract, and
`<details>` rules see [`README.md`](README.md).

## Scope

- Keep this crate independent from CGKA engine, storage, transport, and runtime state.
- Parse plaintext message content into a display-oriented AST only; do not define wire format or persistence policy here.
- Keep the parser dependency-light. Runtime dependencies should stay limited to `serde` unless a deliberate
  parser-design change is made. `serde_json` is a dev-dependency only. `unsafe_code` is forbidden.
- Preserve nostr-aware inline handling and reject ergonomic rendering for private-key entities.
- Add parser behavior with golden/unit coverage before exposing it through FFI (`marmot-app` / `marmot-uniffi`).

## Layout

- `src/lib.rs` — `parse`, public constants (`MAX_CONTAINER_DEPTH`, `MAX_SOURCE_BLANK_LINES`), re-exports.
- `src/ast.rs` — `Block`, `Inline`, `Document`, `LinkDestinationKind`, and other AST types.
- `src/block.rs` — pass 1, block structure. `src/inline.rs` — pass 2, inline tokenization. Keep the passes unfused.
- `src/details.rs` — bounded `<details>` / `<summary>` grammar.
- `src/destination.rs` — untrusted link-destination classification.
- `src/nostr.rs` — bech32 shape validation and HRP classification (shape only, no checksum).
- `src/entity.rs` — HTML entity decoding. `src/scanner.rs` — shared byte-level scanning helpers.
- `tests/golden/` — `*.md` inputs with `*.json` expected ASTs; `tests/unit_*.rs`, `tests/spec*.rs` — focused coverage.

## Verification

```sh
cargo test -p marmot-markdown
# Regenerate golden fixtures only for an intentional output change, then review the diff:
MARMOT_MD_UPDATE_GOLDEN=1 cargo test -p marmot-markdown --test golden
```
