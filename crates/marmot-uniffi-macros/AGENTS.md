# AGENTS.md - marmot-uniffi-macros

Proc macros used only by `crates/marmot-uniffi`. What the macro does and why: [`README.md`](README.md).

## Layout

- `src/lib.rs` — `on_tokio_runtime`: splits each exported `async fn` into the original method (not exported) and an
  exported `__ffi_<name>` wrapper that spawns it through `crate::tokio_runtime::spawn_export`.

## Rules

- Keep the generated bindings byte-identical: the wrapper carries the original docs, the FFI name via
  `#[uniffi::method(name = "...")]` merged into any existing `#[uniffi::method(...)]`, and the same arguments and
  return type. UniFFI keeps only the last `uniffi` method attribute, so never emit a second one.
- Do not put `#[doc(hidden)]` directly on an exported item: UniFFI reads every `doc` attribute as a docstring and
  rejects it. Hide wrappers with `#[cfg_attr(doc, doc(hidden))]`.
- Reject `async_runtime` on the export. It would wrap the join handle in `async_compat` and start its fallback thread.
- The expansion names `crate::tokio_runtime`; it is only meaningful inside `marmot-uniffi`.
- `marmot-uniffi`'s `tokio_runtime::tests::every_async_export_block_runs_on_the_tokio_runtime` fails if an async
  export block lacks this attribute. Keep it in step with the attribute's spelling.

## Verification

```sh
cargo test -p marmot-uniffi
just binding-docs-gate
```

Compare generated bindings before and after any change to the expansion (`uniffi-bindgen generate --library` on both
builds, then `diff -r`).
