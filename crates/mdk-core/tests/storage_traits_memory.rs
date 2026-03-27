//! Memory storage implementation tests using shared test functions

use mdk_memory_storage::MdkMemoryStorage;

mod shared;

storage_backend_tests!(MdkMemoryStorage::default());
