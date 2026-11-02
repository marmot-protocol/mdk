//! Migration 0117: share the push registration with every joined group again
//! (mdk#2604).
//!
//! Earlier releases shared a device's token only when the device first saw a
//! group or its registration changed, so members added later never received
//! it. Queue the current registration once for every joined group while native
//! push is on; the account worker drains the queue after open. A group whose
//! share already completed is queued and published again.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "INSERT INTO pending_push_registration_shares (
            group_id_hex, token_fingerprint, registration_updated_at_ms,
            queued_at_ms, last_attempted_at_ms
         )
         SELECT account_groups.group_id_hex, current_registration.token_fingerprint,
                current_registration.updated_at_ms, current_registration.updated_at_ms, NULL
         FROM account_groups
         CROSS JOIN (
            SELECT push_registration.token_fingerprint, push_registration.updated_at_ms
            FROM push_registration
            JOIN notification_settings
              ON notification_settings.account_label = push_registration.account_label
            WHERE notification_settings.native_push_enabled = 1
            ORDER BY push_registration.updated_at_ms DESC, push_registration.account_label DESC
            LIMIT 1
         ) AS current_registration
         WHERE account_groups.self_membership = 'member'
         ON CONFLICT(group_id_hex) DO UPDATE SET
            token_fingerprint = excluded.token_fingerprint,
            registration_updated_at_ms = excluded.registration_updated_at_ms,
            queued_at_ms = excluded.queued_at_ms,
            last_attempted_at_ms = NULL;
         UPDATE push_registration
         SET last_shared_at_ms = NULL
         WHERE EXISTS (
            SELECT 1 FROM notification_settings
            WHERE notification_settings.account_label = push_registration.account_label
              AND notification_settings.native_push_enabled = 1
         )
         AND EXISTS (
            SELECT 1 FROM pending_push_registration_shares
            WHERE pending_push_registration_shares.token_fingerprint =
                    push_registration.token_fingerprint
              AND pending_push_registration_shares.registration_updated_at_ms =
                    push_registration.updated_at_ms
         );",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    fn before_repair(native_push_enabled: bool) -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..116]).unwrap();
        conn.execute_batch(&format!(
            "INSERT INTO account_groups(group_id_hex, endpoint, self_membership, updated_at)
             VALUES ('shared', '', 'member', 0), ('unshared', '', 'member', 0),
                    ('left', '', 'left', 0), ('removed', '', 'removed', 0);
             INSERT INTO push_registration(
                account_label, account_id_hex, platform, token_fingerprint, token_bytes,
                server_pubkey_hex, created_at_ms, updated_at_ms, last_shared_at_ms
             ) VALUES ('alice', 'aa', 2, 'fingerprint', X'01', 'bb', 10, 11, 12);
             INSERT INTO notification_settings(
                account_label, account_id_hex, native_push_enabled, updated_at_ms
             ) VALUES ('alice', 'aa', {}, 0);
             INSERT INTO pending_push_registration_shares(
                group_id_hex, token_fingerprint, registration_updated_at_ms,
                queued_at_ms, last_attempted_at_ms
             ) VALUES ('unshared', 'fingerprint', 11, 5, 6);",
            i64::from(native_push_enabled),
        ))
        .unwrap();
        conn
    }

    fn pending(conn: &Connection) -> Vec<(String, String, i64, Option<i64>)> {
        conn.prepare(
            "SELECT group_id_hex, token_fingerprint, registration_updated_at_ms,
                    last_attempted_at_ms
             FROM pending_push_registration_shares ORDER BY group_id_hex",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn last_shared_at_ms(conn: &Connection) -> Option<i64> {
        conn.query_row(
            "SELECT last_shared_at_ms FROM push_registration",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// Every joined group is queued for the current revision, including one
    /// whose share already completed; departed groups are not.
    #[test]
    fn queues_every_joined_group_for_the_current_registration() {
        let mut conn = before_repair(true);
        run(&mut conn, MIGRATIONS).unwrap();
        let queued = |group: &str| (group.to_owned(), "fingerprint".to_owned(), 11, None);
        assert_eq!(pending(&conn), vec![queued("shared"), queued("unshared")]);
        assert_eq!(last_shared_at_ms(&conn), None);
    }

    /// Native push off: the stored registration is not advertised.
    #[test]
    fn leaves_accounts_with_native_push_off_alone() {
        let mut conn = before_repair(false);
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            pending(&conn),
            vec![("unshared".to_owned(), "fingerprint".to_owned(), 11, Some(6))]
        );
        assert_eq!(last_shared_at_ms(&conn), Some(12));
    }

    /// No registration: nothing to share.
    #[test]
    fn leaves_accounts_without_a_registration_alone() {
        let mut conn = before_repair(true);
        conn.execute_batch(
            "DELETE FROM pending_push_registration_shares; DELETE FROM push_registration;",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert!(pending(&conn).is_empty());
    }
}
