//! Per-admission invitation decisions and work, independent of chat presentation.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};

/// A retained account decision for exactly one authenticated admission generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationDecision {
    pub group_id_hex: String,
    pub generation: [u8; 32],
    pub version: u64,
    pub declined: bool,
}

impl InvitationDecision {
    pub fn is_valid(&self) -> bool {
        !self.group_id_hex.is_empty()
            && self.group_id_hex.len() <= 512
            && self.group_id_hex.len().is_multiple_of(2)
            && self
                .group_id_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && (1..=crate::MAX_SMALL_STATE_NUMBER).contains(&self.version)
    }

    /// D34: higher version, then equal-version decline. Sender and clock do not decide.
    pub fn wins_over(&self, held: &Self) -> bool {
        self.version > held.version
            || (self.version == held.version && self.declined && !held.declined)
    }
}

/// Pending presentation and ordinary Leave handoff for a retained decision.
#[derive(Clone, Debug)]
pub struct InvitationDecisionWork {
    pub decision: InvitationDecision,
    pub apply_owed: bool,
    pub decline_owed: bool,
}

impl SqliteAppStorage {
    pub fn invitation_decision(
        &self,
        chat: &str,
        generation: &[u8; 32],
    ) -> StorageResult<Option<InvitationDecision>> {
        held(&*self.lock()?, chat, generation)
    }

    /// A user's explicit change: value, broadcast and required Leave work commit together.
    pub fn record_invitation_decision(
        &self,
        chat: &str,
        generation: [u8; 32],
        declined: bool,
    ) -> StorageResult<InvitationDecision> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let version = held(&conn, chat, &generation)?.map_or(0, |item| item.version);
            let decision = InvitationDecision {
                group_id_hex: chat.to_owned(),
                generation,
                version: version + 1,
                declined,
            };
            if !decision.is_valid() {
                return Err(StorageError::Backend(
                    "invalid or exhausted invitation decision".into(),
                ));
            }
            put(&conn, &decision, true)?;
            Ok(decision)
        })
    }

    /// Creation is implicitly accepted once, never a fresh action on replay/restart.
    pub fn ensure_founding_invitation_decision(
        &self,
        chat: &str,
        generation: [u8; 32],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if held(&conn, chat, &generation)?.is_none() {
                let decision = InvitationDecision {
                    group_id_hex: chat.to_owned(),
                    generation,
                    version: 1,
                    declined: false,
                };
                if decision.is_valid() {
                    put(&conn, &decision, true)?;
                }
            }
            Ok(())
        })
    }

    /// A remote winner is durable before presentation or Leave effects. It is not a local action.
    pub fn merge_invitation_decisions(
        &self,
        decisions: &[InvitationDecision],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for decision in decisions.iter().filter(|item| item.is_valid()) {
                let prior = held(&conn, &decision.group_id_hex, &decision.generation)?;
                if prior.as_ref().is_none_or(|prior| decision.wins_over(prior)) {
                    put(&conn, decision, false)?;
                }
            }
            Ok(())
        })
    }

    pub fn unsent_invitation_decisions(&self) -> StorageResult<Vec<InvitationDecision>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare_cached("SELECT group_id_hex, generation, version, declined FROM invitation_decisions WHERE unsent = 1 ORDER BY group_id_hex, generation").storage()?;
        statement
            .query_map([], row_decision)
            .storage()?
            .map(|row| row.storage())
            .collect()
    }

    pub fn mark_invitation_decisions_sent(
        &self,
        decisions: &[InvitationDecision],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for decision in decisions {
                conn.execute_cached("UPDATE invitation_decisions SET unsent = 0 WHERE group_id_hex = ?1 AND generation = ?2 AND version = ?3 AND declined = ?4", params![decision.group_id_hex, decision.generation.as_slice(), decision.version as i64, decision.declined]).storage()?;
            }
            Ok(())
        })
    }

    pub fn invitation_decision_work(&self) -> StorageResult<Vec<InvitationDecisionWork>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare_cached("SELECT group_id_hex, generation, version, declined, apply_owed, decline_owed FROM invitation_decisions WHERE apply_owed = 1 OR decline_owed = 1 ORDER BY group_id_hex, generation").storage()?;
        statement
            .query_map([], |row| {
                Ok(InvitationDecisionWork {
                    decision: row_decision(row)?,
                    apply_owed: row.get(4)?,
                    decline_owed: row.get(5)?,
                })
            })
            .storage()?
            .map(|row| row.storage())
            .collect()
    }

    pub fn mark_invitation_decision_applied(
        &self,
        decision: &InvitationDecision,
    ) -> StorageResult<()> {
        self.lock()?.execute_cached("UPDATE invitation_decisions SET apply_owed = 0 WHERE group_id_hex = ?1 AND generation = ?2 AND version = ?3 AND declined = ?4", params![decision.group_id_hex, decision.generation.as_slice(), decision.version as i64, decision.declined]).storage()?;
        Ok(())
    }

    /// A successful native admission makes its exact retained decision actionable.
    pub fn owe_installed_invitation_decision(
        &self,
        chat: &str,
        generation: &[u8; 32],
    ) -> StorageResult<()> {
        self.lock()?.execute_cached("UPDATE invitation_decisions SET apply_owed = 1, decline_owed = declined WHERE group_id_hex = ?1 AND generation = ?2", params![chat, generation.as_slice()]).storage()?;
        Ok(())
    }

    /// No matching installed copy exists. Retain its value; only a later
    /// exact native admission re-arms application work.
    pub fn defer_uninstalled_invitation_decision(
        &self,
        decision: &InvitationDecision,
    ) -> StorageResult<()> {
        self.lock()?.execute_cached("UPDATE invitation_decisions SET apply_owed = 0, decline_owed = 0 WHERE group_id_hex = ?1 AND generation = ?2 AND version = ?3 AND declined = ?4", params![decision.group_id_hex, decision.generation.as_slice(), decision.version as i64, decision.declined]).storage()?;
        Ok(())
    }

    /// The ordinary Leave owner now holds the request, or membership is already terminal.
    pub fn invitation_decline_handed_off(
        &self,
        chat: &str,
        generation: &[u8; 32],
    ) -> StorageResult<()> {
        self.lock()?.execute_cached("UPDATE invitation_decisions SET decline_owed = 0 WHERE group_id_hex = ?1 AND generation = ?2", params![chat, generation.as_slice()]).storage()?;
        Ok(())
    }
}

fn held(
    conn: &Connection,
    chat: &str,
    generation: &[u8; 32],
) -> StorageResult<Option<InvitationDecision>> {
    conn.query_row_cached("SELECT group_id_hex, generation, version, declined FROM invitation_decisions WHERE group_id_hex = ?1 AND generation = ?2", params![chat, generation.as_slice()], row_decision).optional().storage()
}

fn row_decision(row: &rusqlite::Row<'_>) -> rusqlite::Result<InvitationDecision> {
    let generation: Vec<u8> = row.get(1)?;
    Ok(InvitationDecision {
        group_id_hex: row.get(0)?,
        generation: generation
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        version: row.get::<_, i64>(2)? as u64,
        declined: row.get(3)?,
    })
}

fn put(conn: &Connection, decision: &InvitationDecision, unsent: bool) -> StorageResult<()> {
    conn.execute_cached("INSERT INTO invitation_decisions(group_id_hex, generation, version, declined, unsent, apply_owed, decline_owed)
        VALUES (?1, ?2, ?3, ?4, ?5, 1, ?4) ON CONFLICT(group_id_hex, generation) DO UPDATE SET
        version = excluded.version, declined = excluded.declined, unsent = excluded.unsent,
        apply_owed = 1, decline_owed = excluded.decline_owed",
        params![decision.group_id_hex, decision.generation.as_slice(), decision.version as i64, decision.declined, unsent]).storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    #[test]
    fn invitation_decisions_atomically_keep_work_and_clear_only_exact_sent_values() {
        let account = SqliteAccountStorage::in_memory_for_test().unwrap();
        let storage = account.app_storage();
        let first = storage
            .record_invitation_decision("0102", [1; 32], false)
            .unwrap();
        let decline = storage
            .record_invitation_decision("0102", [1; 32], true)
            .unwrap();
        assert_eq!(decline.version, 2);
        storage.mark_invitation_decisions_sent(&[first]).unwrap();
        assert_eq!(
            storage.unsent_invitation_decisions().unwrap(),
            [decline.clone()]
        );
        let accepted = InvitationDecision {
            version: 3,
            declined: false,
            ..decline.clone()
        };
        storage
            .merge_invitation_decisions(&[accepted.clone()])
            .unwrap();
        assert!(
            !storage.invitation_decision_work().unwrap()[0].decline_owed,
            "a newer accept replaces unrequested decline intent"
        );
        let tied_decline = InvitationDecision {
            declined: true,
            ..accepted.clone()
        };
        storage
            .merge_invitation_decisions(&[tied_decline.clone(), accepted])
            .unwrap();
        assert_eq!(
            storage.invitation_decision("0102", &[1; 32]).unwrap(),
            Some(tied_decline.clone())
        );
        assert!(storage.invitation_decision_work().unwrap()[0].decline_owed);
        storage.lock().unwrap().execute_batch("CREATE TRIGGER refuse_invite_decision BEFORE UPDATE ON invitation_decisions BEGIN SELECT RAISE(ABORT, 'invitation intent rollback'); END").unwrap();
        let failure = storage
            .record_invitation_decision("0102", [1; 32], false)
            .unwrap_err();
        assert!(
            failure.to_string().contains("invitation intent rollback"),
            "{failure}"
        );
        assert_eq!(
            storage.invitation_decision("0102", &[1; 32]).unwrap(),
            Some(tied_decline)
        );
        assert!(storage.invitation_decision_work().unwrap()[0].decline_owed);
        assert!(storage.unsent_invitation_decisions().unwrap().is_empty());
    }
}
