//! `#[repr(C)]` mirrors of the `marmot-uniffi` FFI value types.
//!
//! One module per `marmot-uniffi` conversions module. Every mirror follows
//! the same mapping rules (see `AGENTS.md`):
//!
//! - `String` → owned `*mut c_char`; `Option<String>` → nullable pointer.
//! - `Vec<T>` → owned `(ptr, len)`; empty is `(NULL, 0)`.
//! - `Option<record>` → nullable owned pointer; `Option<scalar>` →
//!   `has_x: bool` + value field.
//! - Fieldless enums → `#[repr(C)]` enums; payload enums → `#[repr(C)]`
//!   Rust enums (tag + union in the generated header).
//! - Each mirror implements `From<…Ffi>` (allocating) and `CFree`
//!   (deep-free). Types returned across the ABI as ownership roots get a
//!   public `marmot_*_free` function; commands returning `Vec<T>` return a
//!   `Marmot…List` root instead of a bare pair.
//! - Input records additionally implement a borrowed `to_ffi` reader that
//!   never takes ownership of caller memory.

pub mod account;
pub mod agent_stream;
pub mod audit;
pub mod chat_list;
pub mod common;
pub mod event;
pub mod group;
pub mod markdown;
pub mod media;
pub mod message;
pub mod notification;
pub mod push;
pub mod relay;
pub mod timeline;
