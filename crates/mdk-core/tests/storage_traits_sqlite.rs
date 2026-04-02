//! SQLite storage implementation tests using shared test functions

use mdk_sqlite_storage::MdkSqliteStorage;

mod shared;

storage_backend_tests!(MdkSqliteStorage::new_unencrypted(":memory:").unwrap());
