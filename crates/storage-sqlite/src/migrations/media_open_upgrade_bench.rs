//! Explicit, ignored encrypted-media upgrade measurements using synthetic data only.
#[cfg(test)]
mod max_startup_investigation {
    /// Disposable benchmark of the exact migration against encrypted, retained legacy bytes.
    #[test]
    #[ignore = "explicit investigation benchmark, synthetic data only"]
    fn encrypted_retention_upgrade_measurement() {
        use crate::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
        use std::time::Instant;
        let _trace = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );
        let mib: usize = std::env::var("MAX_REPRO_MIB")
            .unwrap_or_else(|_| "32".into())
            .parse()
            .unwrap();
        let enhanced =
            std::env::var("MAX_REPRO_MEMORY_SECURITY").unwrap_or_else(|_| "true".into()) == "true";
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic.sqlite");
        fs_private::ensure_private_db_files(&path).unwrap();
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        let key = SqlCipherKey::new("synthetic-investigation-only".to_owned()).unwrap();
        open_hardened_sqlcipher(
            &conn,
            &key,
            SqlCipherHardening {
                cipher_memory_security: enhanced,
                ..SqlCipherHardening::live_cache()
            },
        )
        .unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY);
            INSERT INTO attachment_acquisition VALUES(x'01');
            CREATE TABLE retained_attachment_bytes(token BLOB PRIMARY KEY REFERENCES attachment_acquisition(token) ON DELETE CASCADE,bytes BLOB NOT NULL);
            CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY,byte_count INTEGER);
            CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN SELECT 1; END;
            CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN SELECT 1; END;
            CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN SELECT 1; END;").unwrap();
        let len = mib * 1024 * 1024;
        conn.execute(
            "INSERT INTO retained_attachment_bytes VALUES(x'01',zeroblob(?1))",
            [len as i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attachment_retention_usage VALUES(1,?1)",
            [len as i64],
        )
        .unwrap();
        let buffer = vec![0x5Au8; 64 * 1024];
        {
            let mut blob = conn
                .blob_open("main", "retained_attachment_bytes", "bytes", 1, false)
                .unwrap();
            for offset in (0..len).step_by(buffer.len()) {
                blob.write_at(&buffer, offset).unwrap();
            }
            blob.close().unwrap();
        }
        let started = Instant::now();
        let tx = conn.transaction().unwrap();
        super::super::migration_0104_file_attachment_retention::apply(&tx).unwrap();
        let strategy = "fixed";
        let apply_ms = started.elapsed().as_millis();
        tx.commit().unwrap();
        let total_ms = started.elapsed().as_millis();
        let blob = conn
            .blob_open("main", "retained_attachment_bytes", "bytes", 1, true)
            .unwrap();
        let mut actual = vec![0u8; buffer.len()];
        for offset in (0..len).step_by(buffer.len()) {
            blob.read_at_exact(&mut actual, offset).unwrap();
            assert_eq!(actual, buffer);
        }
        blob.close().unwrap();
        let usage: i64 = conn
            .query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(usage, len as i64);
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        conn.execute("DELETE FROM attachment_acquisition", [])
            .unwrap();
        let remaining: i64 = conn
            .query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
        tracing::info!(
            target: "storage_sqlite::upgrade_measurement", method = "retained_upgrade",
            strategy, mib, enhanced_memory = enhanced, apply_ms = apply_ms as u64,
            total_ms = total_ms as u64, verified_bytes = len,
            "synthetic retained upgrade verified"
        );
    }
}

#[cfg(test)]
mod max_partial_investigation {
    /// Measure the shipped checkpoint rewrite with encrypted synthetic chunks only.
    #[test]
    #[ignore = "explicit investigation benchmark"]
    fn encrypted_partial_upgrade_measurement() {
        use crate::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
        use std::time::Instant;
        let _trace = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_test_writer()
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );
        let mib: usize = std::env::var("MAX_REPRO_MIB")
            .unwrap_or_else(|_| "512".into())
            .parse()
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic.sqlite");
        fs_private::ensure_private_db_files(&path).unwrap();
        let mut conn = rusqlite::Connection::open(path).unwrap();
        let key = SqlCipherKey::new("synthetic-investigation-only".to_owned()).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY,state INTEGER,cancelled INTEGER DEFAULT 0,permission_paused INTEGER DEFAULT 0); INSERT INTO attachment_acquisition VALUES(x'01',1,0,0);").unwrap();
        let tx = conn.transaction().unwrap();
        super::super::migration_0085_attachment_partials::apply(&tx).unwrap();
        let len = mib * 1024 * 1024;
        tx.execute("INSERT INTO attachment_partial VALUES(x'01',zeroblob(32),zeroblob(32),'etag',?1,?1,100)",[len as i64]).unwrap();
        let bytes = vec![0x5Au8; 1024 * 1024];
        for offset in (0..len).step_by(bytes.len()) {
            tx.execute(
                "INSERT INTO attachment_partial_chunk VALUES(x'01',?1,?2,zeroblob(32))",
                rusqlite::params![offset as i64, bytes],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        let started = Instant::now();
        super::super::ensure_migration_table(&conn).unwrap();
        let migration = super::super::Migration {
            version: 105,
            name: "0105_file_attachment_partials",
            suspend_foreign_keys:
                crate::migrations::migration_0105_file_attachment_partials::SUSPEND_FOREIGN_KEYS,
            apply: super::super::migration_0105_file_attachment_partials::apply,
        };
        super::super::apply_migration(&mut conn, &migration).unwrap();
        let apply_ms = started.elapsed().as_millis();
        let total_ms = started.elapsed().as_millis();
        let mut stmt = conn
            .prepare("SELECT offset,bytes FROM attachment_partial_chunk ORDER BY offset")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .unwrap();
        let mut verified = 0usize;
        for row in rows {
            let (offset, actual) = row.unwrap();
            assert_eq!(offset as usize, verified);
            assert_eq!(actual, bytes);
            verified += actual.len();
        }
        drop(stmt);
        assert_eq!(verified, len);
        let usage: i64 = conn
            .query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(usage, len as i64);
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let fk: i64 = conn
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(fk, 0);
        conn.execute("DELETE FROM attachment_acquisition", [])
            .unwrap();
        let usage: i64 = conn
            .query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(usage, 0);
        tracing::info!(
            target: "storage_sqlite::upgrade_measurement", method = "partial_upgrade",
            mib, apply_ms = apply_ms as u64, total_ms = total_ms as u64,
            verified_bytes = verified,
            "synthetic partial upgrade verified"
        );
    }
}
