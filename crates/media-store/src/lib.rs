//! Encrypted per-file media store for one Marmot account (mdk#2314).
//!
//! Retained attachment bodies move out of SQLCipher rows into one encrypted
//! file each. This crate owns the file side end to end: the format, the
//! publish/delete/sweep lifecycle and its crash ordering, and the layout.
//! Metadata (each file's random key, state and references) stays in the
//! account database, reached through [`MediaCatalog`], [`PublishTarget`] and
//! [`CheckpointTarget`]; this crate never touches SQL.
//!
//! Everything here is synchronous and blocking. Run it on a blocking thread
//! pool, never inline on an async task.

pub mod catalog;
mod disk;
mod error;
pub mod format;
mod store;

#[cfg(any(test, feature = "catalog-conformance"))]
pub mod conformance;
#[cfg(any(test, feature = "catalog-conformance"))]
pub mod memory;

pub use catalog::{
    CatalogError, CatalogResult, Category, CheckpointStart, CheckpointTarget, ExistingOutcome,
    FileId, FilePresence, FileState, MediaCatalog, NewFile, Presence, PublishTarget, ReadyFile,
    ReadyOutcome,
};
pub use disk::{Admission, DiskPolicy, free_space};
pub use error::{MediaError, MediaResult};
pub use format::FileKey;
pub use store::{
    CHECKPOINT_APPEND_MAX, MEDIA_DIRECTORY, MediaReader, MediaStore, PublishOutcome, SweepReport,
    sync_file,
};

#[cfg(test)]
mod format_tests;
