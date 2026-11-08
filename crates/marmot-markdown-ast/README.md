# marmot-markdown-ast

Owned Markdown document types and their serde implementations. The parser re-exports these types through
`marmot_markdown::ast` and its existing top-level exports.

This crate contains no parsing or native code. Keeping the type definitions separate lets Cargo compile them while
[`marmot-markdown`](../marmot-markdown/README.md) builds its Odin archive. Clean-build measurements rebuild both crates.
