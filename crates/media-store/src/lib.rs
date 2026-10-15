//! Encrypted per-file media store for one Marmot account (mdk#2314).
//!
//! Retained attachment bodies move out of SQLCipher rows into one encrypted
//! file each. This crate owns the file side end to end; metadata (each file's
//! random key, state and references) stays in the account database, reached
//! through a catalog trait, and this crate never touches SQL.
//!
//! `format` is the on-disk file format: a header and the age v1 payload.

pub mod format;

#[cfg(test)]
mod format_tests;
