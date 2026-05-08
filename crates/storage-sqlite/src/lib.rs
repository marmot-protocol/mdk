//! # storage-sqlite
//!
//! SQLCipher-backed SQLite implementation of the Marmot storage aggregate.
//! The backend stores Marmot metadata and custom OpenMLS storage rows in the
//! same database so group snapshot and rollback can be atomic across both
//! layers.

mod codec;
mod connection;
mod migrations;
mod openmls_storage;
mod storage;

pub use connection::{
    SqlCipherKey, SqliteJournalMode, SqliteStorage, SqliteStorageOptions, SqliteSynchronous,
};
pub use openmls_storage::SqliteOpenMlsStorageError;

pub(crate) use codec::{
    SqliteResultExt, created_at_to_i64, deserialize, epoch_to_i64, message_state_to_i64, serialize,
};
