//! Encrypted per-file media store (mdk#2314).
//!
//! Retained attachment bodies move out of SQLCipher rows into one encrypted
//! file each, with the random per-file key kept in the account database.
//! `format` is the on-disk file format. The store itself (metadata tables,
//! intent-first publish, the sweep) and its callers land in later steps; until
//! then nothing in the runtime writes or reads this format.

pub mod format;

#[cfg(feature = "media-store-benchmarks")]
pub mod bench;

#[cfg(test)]
mod format_tests;
