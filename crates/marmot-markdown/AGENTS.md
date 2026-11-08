# AGENTS.md - crates/marmot-markdown

Markdown parser and typed AST for app message rendering. For the human overview, renderer security contract, and
`<details>` rules see [`README.md`](README.md).

## Scope

- Keep this crate independent from CGKA engine, storage, transport, and runtime state.
- Parse plaintext message content into a display-oriented AST only; do not define wire format or persistence policy here.
- Keep the parser dependency-light. Runtime dependencies are the AST package and its `serde` dependency.
  `serde_json` is a dev-dependency only. Rust denies unsafe code except for the private
  C ABI and graph conversion in `src/native.rs`.
- Preserve nostr-aware inline handling and reject ergonomic rendering for private-key entities.
- Add parser behavior with golden/unit coverage before exposing it through FFI (`marmot-app` / `marmot-uniffi`).

## Layout

- `src/lib.rs` — Rust `parse` and classification API, public limits, re-exports; no parsing logic.
- `../marmot-markdown-ast/src/lib.rs` — unchanged owned AST types and serde implementations, re-exported as `ast`.
- `src/native.rs` — private C layout and owned-AST conversion; arena ownership must survive unwinding.
- `odin/block.odin` — pass 1, block structure. `odin/inline.odin` — pass 2, inline tokenization. Keep the passes unfused.
- `odin/details.odin` — bounded `<details>` / `<summary>` grammar; native work-bound tests in `details_test.odin`.
- `odin/helpers.odin` — destination classification, bech32 shape checks, entities and byte-level scanning.
- `odin/text.odin`, `odin/lowercase.odin` — byte-string helpers, UTF-8 encoding and Unicode lowercase mappings.
- `odin/maps.odin` — concrete reference-label and delimiter-index tables; zero values are empty tables.
- `odin/types.odin` — native graph layout, mirrored by `src/native.rs`; update both sides together.
- `odin/bridge.odin` — caller-owned stack scratch, overflow arena blocks and C exports. No Rust parser fallback.
- `odin/push.odin` — initialized-element array growth; raw writes require capacity to be reserved first.
- `build.rs` — pinned Odin invocation and target selection; optimized Linux amd64 finalizes native code with pinned LLVM tools.
- `tests/golden/` — `*.md` inputs with `*.json` expected ASTs; `tests/unit_*.rs`, `tests/spec*.rs` — focused coverage.

Production builds use `-bedrock`, without runtime type information or built-in maps. The arena must obtain its overflow
backing from `runtime.heap_allocator()`; the default context allocator is nil in this mode. Keep parser allocation
inside the parse arena and preserve the Rust bridge's input/scratch borrow until conversion finishes.
The C exports initialize only their assertion handler and explicit allocator. Reference-map keys use direct OS entropy;
do not reintroduce the default context's TLS random generator, which cannot link on Android ARMv7.

Clean compile measurements must remove both Markdown packages and native outputs. The AST package is first-party
parser code, not a reusable dependency-cache allowance. Linux's partitioned backend must write native machine code
before Cargo builds the shim; bitcode-only archives and deferred application-link optimization do not satisfy the gate.

## Verification

```sh
cargo test -p marmot-markdown
odin test crates/marmot-markdown/odin
# Regenerate golden fixtures only for an intentional output change, then review the diff:
MARMOT_MD_UPDATE_GOLDEN=1 cargo test -p marmot-markdown --test golden
```

Use the crate README's measurement runner for parity-preserving performance work. Include native compilation and
Rust AST conversion in comparisons. Every measured case must meet the runtime threshold; aggregate wins cannot
hide regressions. Do not claim runtime or compile thresholds from parser-only timings.
