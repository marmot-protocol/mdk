//! The `test-support` feature only adds helpers. With it on, as in workspace
//! builds that unify dependents' dev-dependencies, `in_memory()` still opens
//! with the production defaults; only this crate's own unit tests and callers of
//! `in_memory_for_test()` leave out memory security.

use storage_sqlite::SqliteAccountStorage;

#[test]
fn in_memory_keeps_memory_security_outside_this_crates_unit_tests() {
    let _storage = SqliteAccountStorage::in_memory().unwrap();

    // Memory security is process-wide, and this binary runs nothing else.
    let probe = rusqlite::Connection::open_in_memory().unwrap();
    let state: String = probe
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "1");
}
