//! Encrypted per-file media store (mdk#2314).
//!
//! Retained attachment bodies move out of SQLCipher rows into one encrypted
//! file each, with the random per-file key kept in the account database.
//! `format` is the on-disk file format and `store` the file store: metadata
//! rows (migration 0110), intent-first publish, key-first deletion and the
//! sweep. Attachments move onto it in later steps; until then nothing in the
//! runtime writes or reads it.

pub mod format;
mod store;

pub(crate) use store::MediaStoreShared;
pub use store::{
    MediaCategory, MediaFileId, MediaFileState, MediaFileStore, MediaPublishOutcome,
    MediaStoreReader, MediaSweepReport,
};

#[cfg(feature = "media-store-benchmarks")]
pub mod bench;

#[cfg(test)]
mod format_tests;
