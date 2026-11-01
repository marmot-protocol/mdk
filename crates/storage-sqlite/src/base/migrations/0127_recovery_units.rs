//! Migration 0127: the recovery runner's durable retry state and staging
//! (mdk#2660 phase 4).
//!
//! - `account_recovery_units`: one row per (route, relay) unit the runner has
//!   touched. `state` is 0 active, 1 broken or 2 retired; whether an active
//!   unit is caught up, owed or backing off is derived from the coverage
//!   ledger and `next_attempt_at_seconds`. A broken unit keeps its reason
//!   (0 no progress, 1 refused), its park revision and park time, and may hold
//!   one probe attempt earned by new loss.
//! - `account_recovery_unit_spans`: a unit's parked (kind 0) and retired
//!   (kind 1) `created_at` ranges. A retired range keeps its reason: 0
//!   dismissed, 1 route gone, 2 before this copy. Neither is ever coverage.
//! - `account_recovery_relays`: each relay's unreachable streak, cooldown and
//!   last known NIP-11 caps.
//! - `account_recovery_budget`: attempts and fetched event bytes per minute,
//!   summed over a rolling hour for the account breaker.
//! - `account_recovery_park_revision`: the account-wide park revision counter,
//!   so a revision is never reused after its unit row is gone.
//! - `account_recovery_staged`: fetched history held for oldest-first
//!   admission, keyed by event id, encoded like `account_delivery_spill`.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE account_recovery_units (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL CHECK (length(relay) > 0),
            state INTEGER NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2)),
            broken_reason INTEGER CHECK (broken_reason IN (0, 1)),
            probe INTEGER NOT NULL DEFAULT 0 CHECK (probe IN (0, 1)),
            no_progress INTEGER NOT NULL DEFAULT 0 CHECK (no_progress >= 0),
            backoff_step INTEGER NOT NULL DEFAULT 0 CHECK (backoff_step >= 0),
            next_attempt_at_seconds INTEGER NOT NULL DEFAULT 0
                CHECK (next_attempt_at_seconds >= 0),
            attempt_minute INTEGER CHECK (attempt_minute >= 0),
            fencing INTEGER NOT NULL DEFAULT 0 CHECK (fencing IN (0, 1)),
            slice_width_seconds INTEGER CHECK (slice_width_seconds > 0),
            observed_cap INTEGER CHECK (observed_cap > 0),
            planned_caps_known INTEGER NOT NULL DEFAULT 0 CHECK (planned_caps_known IN (0, 1)),
            planned_max_limit INTEGER CHECK (planned_max_limit > 0),
            planned_negentropy INTEGER NOT NULL DEFAULT 0 CHECK (planned_negentropy IN (0, 1)),
            park_revision INTEGER NOT NULL DEFAULT 0 CHECK (park_revision >= 0),
            parked_at_seconds INTEGER CHECK (parked_at_seconds >= 0),
            recheck_position_seconds INTEGER CHECK (recheck_position_seconds >= 0),
            recheck_completed_at_seconds INTEGER CHECK (recheck_completed_at_seconds >= 0),
            last_served_at_seconds INTEGER CHECK (last_served_at_seconds >= 0),
            PRIMARY KEY (route_kind, route_id, relay),
            CHECK ((state = 1) = (broken_reason IS NOT NULL)),
            CHECK (probe = 0 OR state = 1),
            CHECK (planned_caps_known = 1 OR (planned_max_limit IS NULL AND planned_negentropy = 0))
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_unit_spans (
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL CHECK (length(relay) > 0),
            kind INTEGER NOT NULL CHECK (kind IN (0, 1)),
            since_seconds INTEGER NOT NULL CHECK (since_seconds >= 0),
            until_seconds INTEGER NOT NULL CHECK (until_seconds >= since_seconds),
            reason INTEGER CHECK (reason IN (0, 1, 2)),
            PRIMARY KEY (route_kind, route_id, relay, kind, since_seconds),
            CHECK ((kind = 1) = (reason IS NOT NULL))
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_relays (
            relay TEXT PRIMARY KEY CHECK (length(relay) > 0),
            unreachable_streak INTEGER NOT NULL DEFAULT 0 CHECK (unreachable_streak >= 0),
            cooldown_step INTEGER NOT NULL DEFAULT 0 CHECK (cooldown_step >= 0),
            cooldown_since_seconds INTEGER CHECK (cooldown_since_seconds >= 0),
            cooldown_until_seconds INTEGER CHECK (cooldown_until_seconds >= 0),
            caps_known INTEGER NOT NULL DEFAULT 0 CHECK (caps_known IN (0, 1)),
            caps_max_limit INTEGER CHECK (caps_max_limit > 0),
            caps_negentropy INTEGER NOT NULL DEFAULT 0 CHECK (caps_negentropy IN (0, 1)),
            caps_fetched_at_seconds INTEGER CHECK (caps_fetched_at_seconds >= 0),
            CHECK (caps_known = 1 OR (caps_max_limit IS NULL AND caps_negentropy = 0)),
            CHECK ((cooldown_until_seconds IS NULL) = (cooldown_since_seconds IS NULL))
        ) WITHOUT ROWID;
        CREATE TABLE account_recovery_budget (
            minute INTEGER PRIMARY KEY CHECK (minute >= 0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            event_bytes INTEGER NOT NULL DEFAULT 0 CHECK (event_bytes >= 0)
        );
        CREATE TABLE account_recovery_park_revision (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            revision INTEGER NOT NULL CHECK (revision >= 0)
        );
        INSERT INTO account_recovery_park_revision (singleton, revision) VALUES (1, 0);
        CREATE TABLE account_recovery_staged (
            event_id BLOB PRIMARY KEY CHECK (typeof(event_id) = 'blob' AND length(event_id) > 0),
            route_kind INTEGER NOT NULL CHECK (route_kind IN (0, 1)),
            route_id BLOB NOT NULL,
            relay TEXT NOT NULL CHECK (length(relay) > 0),
            created_at_seconds INTEGER NOT NULL CHECK (created_at_seconds >= 0),
            payload BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
            metadata BLOB NOT NULL CHECK (typeof(metadata) = 'blob'),
            format INTEGER NOT NULL CHECK (format = 1),
            bytes INTEGER NOT NULL CHECK (bytes >= 0),
            staged_at_seconds INTEGER NOT NULL CHECK (staged_at_seconds >= 0)
        ) WITHOUT ROWID;
        CREATE INDEX account_recovery_staged_order
            ON account_recovery_staged(route_kind, route_id, created_at_seconds, event_id);
        CREATE INDEX account_recovery_staged_relay
            ON account_recovery_staged(route_kind, route_id, relay);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    /// A broken unit keeps its reason, only a broken unit holds a probe, and
    /// only a retired span keeps a reason.
    #[test]
    fn unit_rows_keep_their_state_shape() {
        let mut conn = Connection::open_in_memory().unwrap();
        let end = MIGRATIONS.iter().position(|m| m.version == 127).unwrap() + 1;
        run(&mut conn, &MIGRATIONS[..end]).unwrap();
        let unit = |state: i64, reason: Option<i64>, probe: i64| {
            conn.execute(
                "INSERT INTO account_recovery_units (route_kind, route_id, relay, state, broken_reason, probe)
                 VALUES (0, x'', 'wss://a', ?1, ?2, ?3)",
                rusqlite::params![state, reason, probe],
            )
        };
        assert!(unit(1, None, 0).is_err());
        assert!(unit(0, Some(0), 0).is_err());
        assert!(unit(0, None, 1).is_err());
        unit(1, Some(1), 1).unwrap();
        let span = |kind: i64, reason: Option<i64>| {
            conn.execute(
                "INSERT INTO account_recovery_unit_spans
                 (route_kind, route_id, relay, kind, since_seconds, until_seconds, reason)
                 VALUES (0, x'', 'wss://a', ?1, 10, 20, ?2)",
                rusqlite::params![kind, reason],
            )
        };
        assert!(span(0, Some(0)).is_err());
        assert!(span(1, None).is_err());
        span(1, Some(2)).unwrap();
        let revision: i64 = conn
            .query_row(
                "SELECT revision FROM account_recovery_park_revision",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, 0);
    }
}
