//! Migration 0138: this device's history key (mdk#2628 4.1).
//!
//! One HPKE key pair per account-device identity, kept next to the MLS
//! signer's binding in the encrypted account database. Its public half goes
//! into the device's roster entry so siblings can seal chat history to it.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS cgka_account_device_history_keys (
    marmot_identity BLOB PRIMARY KEY,
    ciphersuite INTEGER NOT NULL CHECK (ciphersuite BETWEEN 0 AND 65535),
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);
"#,
    )
    .storage()
}
