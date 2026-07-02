//! Per-domain `impl Marmot` command blocks for the UniFFI surface.
//!
//! [`crate::lib`] keeps the [`Marmot`](crate::Marmot) struct, the UniFFI
//! scaffolding, construction/lifecycle methods, broadly-shared free helpers,
//! and the re-exports. Each sub-module here adds an `impl Marmot { ... }` block
//! for one app-API domain, mirroring the split already used in
//! `crate::conversions`. The blocks keep every `#[uniffi::export]` attribute
//! attached to the same methods, so the generated bindings are unaffected.

mod account;
mod agent_stream;
mod audit;
mod chat_list;
mod directory;
mod group;
mod media;
mod message;
mod notification;
mod push;
mod relay;
mod subscription;
mod timeline;
