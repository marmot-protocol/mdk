//! Version marker for the MessagePack encoding of `openmls_values`.
//!
//! Rows written from this version on start with a NUL-prefixed format tag and
//! carry MessagePack instead of a serde_json document. The table shape is
//! unchanged and older rows stay readable, so this migration alters nothing;
//! it exists so a build without the decoder refuses to open the database
//! through `reject_unknown_future_migrations` instead of failing on the first
//! group load.

use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(_tx: &Transaction<'_>) -> StorageResult<()> {
    Ok(())
}
