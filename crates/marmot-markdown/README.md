# marmot-markdown

CommonMark and Nostr-aware display parser for Marmot app messages.

This crate turns plaintext message content into a display-oriented AST for CLI, TUI, and mobile renderers. It does not
define wire format, persistence, or CGKA engine behavior.

## What this crate does

- Parses Markdown into a typed, serde-friendly AST suitable for rendering.
- Handles Nostr-aware inline entities and rejects ergonomic rendering for private-key material.
- Keeps dependencies minimal (`serde` only in normal builds).

## What it does not do

- No CGKA engine, storage, transport, or runtime state.
- No UniFFI surface of its own (bindings expose parsed output through `marmot-app` / `marmot-uniffi` as needed).

Golden fixtures under `tests/golden/` lock parser output for regression coverage.

## Run the tests

```sh
cargo test -p marmot-markdown
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
