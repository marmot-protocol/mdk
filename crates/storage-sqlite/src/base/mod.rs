//! The connection, codec, migrations and open progress both sides build on.

#[cfg(test)]
mod boundary_tests;
pub(crate) mod codec;
pub(crate) mod connection;
pub(crate) mod migrations;
pub(crate) mod open_progress;
#[cfg(test)]
pub(crate) mod query_work_test_support;
#[cfg(test)]
pub(crate) mod table_owners;
#[cfg(test)]
pub(crate) mod test_support;
