# marmot-markdown

CommonMark and Nostr-aware display parser for Marmot app messages.

This crate turns plaintext message content into a display-oriented AST for CLI, TUI, and mobile renderers. It does not
define wire format, persistence, or CGKA engine behavior.

## What this crate does

- Parses Markdown into a typed, serde-friendly AST suitable for rendering.
- Handles Nostr-aware inline entities and classifies private-key destinations as sensitive.
- Keeps dependencies minimal (`serde` only in normal builds).

## Renderer security contract

Message Markdown and every link destination are untrusted. The parser preserves destinations instead of deleting or
rewriting them, and annotates links, images, and autolinks with `LinkDestinationKind`. That classification is context
for client policy; it is not authorization to navigate or fetch.

Renderers **must inspect `classification` before making a destination actionable**. In particular:

- `Dangerous` (`javascript:`, `data:`, `vbscript:`, `file:`) and `Sensitive` (`nsec` / `ncryptsec`, including Nostr
  wrappers) should remain non-actionable by default.
- `Unknown` and `Relative` require an explicit client decision rather than inheriting a WebView or OS opener default.
- `Web`, `Contact`, `App`, and `Nostr` identify recognized destination families, but clients still apply their own
  navigation, deep-link, privacy, and network policies.
- Image renderers must apply the classification and their network policy before fetching `dest`; classification alone
  does not establish that a host or resolved address is safe.

The same classification is present on the MarmotKit/UniFFI Markdown types. Clients may still display the original
destination or link text when policy keeps it inert.

## What it does not do

- No CGKA engine, storage, transport, or runtime state.
- No UniFFI surface of its own (bindings expose parsed output through `marmot-app` / `marmot-uniffi` as needed).

Golden fixtures under `tests/golden/` lock parser output for regression coverage.

## Run the tests

```sh
cargo test -p marmot-markdown
```

See [`AGENTS.md`](AGENTS.md) for scope and invariants.
