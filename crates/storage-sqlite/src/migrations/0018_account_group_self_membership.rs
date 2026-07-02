use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Track the local account's own membership in each projected group so the
    // removed-group-suppressed unread aggregate can exclude groups the account
    // has left or been removed from. Default 'member' preserves every existing
    // row and every still-joined group: uncertainty never suppresses, only an
    // observed self-removal flips the value to 'removed'.
    //
    // This SQLite-layer migration cannot see decrypted MLS/engine roster state,
    // so it cannot tell whether a pre-existing row's local account is still a
    // member. Defaulting to 'member' here would leave rows for groups the
    // account already left / was removed from *before* upgrading still inflating
    // `account_unread_total()` (the frozen unread row has no future removal
    // event to flip the flag). The upgrade/open path closes that gap with a
    // one-time backfill that derives membership from the engine roster — see
    // `marmot_app::AppClient::backfill_self_membership_once` (gated by the
    // `self-membership-backfill-v1` account-import marker). Keeping that derivation
    // on the open path leaves this migration's hot path projection-only.
    tx.execute_batch(
        r#"
ALTER TABLE account_groups
    ADD COLUMN self_membership TEXT NOT NULL DEFAULT 'member';
"#,
    )
    .storage()
}
