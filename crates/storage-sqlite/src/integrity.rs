//! Privacy-safe, read-only structural checks on the existing keyed connection.
use crate::SqliteAccountStorage;
use cgka_traits::storage::StorageResult;
use std::time::{Duration, Instant};

/// A completed check is distinct from a probe that could not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityProbe {
    Healthy,
    Corrupt,
    Incomplete,
}

impl SqliteAccountStorage {
    /// Check SQLite structure without exposing diagnostic rows (which can contain
    /// private values). This is not a full index/foreign-key or MLS semantic audit.
    /// The budget interrupts SQLite VM work; connection waits and filesystem I/O
    /// are not preemptible. No migrations, new connections, or repair are performed.
    pub fn probe_integrity(&self, budget: Duration) -> StorageResult<IntegrityProbe> {
        let connection = self.lock()?;
        Ok(probe(&connection, budget))
    }
}

fn probe(connection: &rusqlite::Connection, budget: Duration) -> IntegrityProbe {
    if budget.is_zero() {
        return IntegrityProbe::Incomplete;
    }
    let started = Instant::now();
    if connection
        .progress_handler(100, Some(move || started.elapsed() >= budget))
        .is_err()
    {
        return IntegrityProbe::Incomplete;
    }
    let mut progress = ProbeProgressHandler {
        connection,
        armed: true,
    };
    let result = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0));
    // Clear the connection-local callback even when SQLite rejects the query.
    // If clearing fails, Drop retries before this connection can be reused.
    if progress.disarm().is_err() {
        return IntegrityProbe::Incomplete;
    }
    match result {
        Ok(result) if result == "ok" => IntegrityProbe::Healthy,
        Ok(_) => IntegrityProbe::Corrupt,
        Err(error) => match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
                IntegrityProbe::Corrupt
            }
            _ => IntegrityProbe::Incomplete,
        },
    }
}

struct ProbeProgressHandler<'a> {
    connection: &'a rusqlite::Connection,
    armed: bool,
}

impl ProbeProgressHandler<'_> {
    fn disarm(&mut self) -> rusqlite::Result<()> {
        self.connection.progress_handler(0, None::<fn() -> bool>)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ProbeProgressHandler<'_> {
    fn drop(&mut self) {
        if self.armed {
            // A failed clear must never leave the elapsed-budget callback
            // installed. Retry the clear and, if it still fails, replace it
            // with a callback that cannot interrupt later queries.
            if self
                .connection
                .progress_handler(0, None::<fn() -> bool>)
                .is_err()
            {
                let _ = self.connection.progress_handler(100, Some(|| false));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_encrypted_page_is_corrupt() {
        use std::io::{Seek, SeekFrom, Write};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.sqlite");
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "key", "test-only-key")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('test payload');",
            )
            .unwrap();
        let root: i64 = connection
            .query_row(
                "SELECT rootpage FROM sqlite_master WHERE name='sample'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let page_size: i64 = connection
            .query_row("PRAGMA cipher_page_size", [], |r| r.get::<_, String>(0))
            .unwrap()
            .parse()
            .unwrap();
        connection.close().unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(
            ((root - 1) * page_size).try_into().unwrap(),
        ))
        .unwrap();
        file.write_all(&[0; 64]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "key", "test-only-key")
            .unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Corrupt
        );
    }

    #[test]
    fn healthy_and_interrupted_checks_leave_connection_usable() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE sample(value INTEGER); WITH RECURSIVE values_to_check(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM values_to_check WHERE v<1000) INSERT INTO sample SELECT v FROM values_to_check;").unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Healthy
        );
        assert_eq!(
            probe(&connection, Duration::ZERO),
            IntegrityProbe::Incomplete
        );
        assert_eq!(
            probe(&connection, Duration::from_nanos(1)),
            IntegrityProbe::Incomplete
        );
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Healthy
        );
    }

    #[test]
    fn corrupt_structure_is_reported_without_returning_private_diagnostics() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE sample(value TEXT CHECK(length(value) < 2)); PRAGMA ignore_check_constraints=ON; INSERT INTO sample VALUES ('private sentinel'); PRAGMA ignore_check_constraints=OFF;").unwrap();
        assert_eq!(
            probe(&connection, Duration::from_secs(1)),
            IntegrityProbe::Corrupt
        );
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM sample", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
