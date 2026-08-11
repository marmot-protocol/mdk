use crate::{
    SQLITE_BIND_PARAMETER_CHUNK, SqliteAccountStorage, SqliteResultExt, bool_i64,
    connection::retry_on_busy,
    encrypted_media_secrets::retire_all_encrypted_media_secrets_for_group_tx, i64_to_usize,
    tags_from_json, unix_now_ms, unix_now_seconds, unix_now_seconds_i64, usize_to_i64,
};
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::types::MessageId;
use rusqlite::{
    Connection, OptionalExtension, TransactionBehavior, params, params_from_iter,
    types::{Type, Value},
};
use serde::{Deserialize, Serialize};
use std::fmt;

const SECURE_DELETE_RETENTION_OPERATION: &str = "retention";
const SECURE_DELETE_LOCAL_GROUP_OPERATION: &str = "local_group";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteLocalGroupDataResult {
    /// Rows removed by every logical wipe accumulated in the durable
    /// checkpoint intent. If a group is re-created and wiped again before WAL
    /// truncation succeeds, this count spans those wipes.
    pub deleted_rows: usize,
    /// True when this call completed a WAL erasure checkpoint left pending by
    /// an earlier call whose logical deletion had already committed.
    pub completed_pending_checkpoint: bool,
    /// True when logical deletion committed but WAL truncation remains
    /// durably pending. A later local wipe call retries the checkpoint even
    /// when it finds no additional rows to delete.
    #[serde(default)]
    pub erasure_pending: bool,
}

impl DeleteLocalGroupDataResult {
    pub fn did_delete(&self) -> bool {
        self.deleted_rows > 0
    }
}

#[derive(Clone, Debug)]
struct SecureDeleteIntent {
    nonce: Vec<u8>,
    result_json: String,
}

#[derive(Clone, Debug)]
struct SecureDeleteCheckpointFinish<T> {
    result: Option<T>,
    erasure_pending: bool,
}

/// Whether a stored per-chat mute row is effective at `now_ms`.
///
/// Missing rows are unmuted, `NULL` means an indefinite mute, and finite
/// mutes expire exactly at their stored boundary.
pub(crate) fn chat_mute_is_effective(
    row_exists: bool,
    muted_until_ms: Option<i64>,
    now_ms: i64,
) -> bool {
    row_exists && muted_until_ms.is_none_or(|until| until > now_ms)
}

/// The local account's own membership in a projected group.
///
/// `Member` is the default and the fallback for unknown/forward-incompatible
/// state: uncertainty must never hide a conversation. `Left` and `Removed` are
/// both terminal "no longer a member" states that suppress the account's unread
/// aggregate; they differ only in *why* membership ended — `Left` is a
/// voluntary self-removal (including declining an invite), `Removed` is an
/// eviction by another member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfMembership {
    #[default]
    Member,
    Left,
    Removed,
}

impl SelfMembership {
    /// The persisted `account_groups.self_membership` text for this state.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SelfMembership::Member => "member",
            SelfMembership::Left => "left",
            SelfMembership::Removed => "removed",
        }
    }

    /// Reads persisted membership text. Unknown values fall back to `Member` so
    /// a row written by a newer schema never suppresses its unread here.
    pub(crate) fn from_storage(value: &str) -> Self {
        match value {
            "left" => SelfMembership::Left,
            "removed" => SelfMembership::Removed,
            _ => SelfMembership::Member,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredAccountState {
    pub label: String,
    pub seen_events: Vec<String>,
    pub last_transport_timestamp: Option<u64>,
    pub groups: Vec<StoredAccountGroup>,
}

/// `image_key_hex`/`image_upload_key_hex` are key material mirrored from the
/// blossom image component for chat-list projection. They are stored in
/// SQLCipher, but must not appear in `Debug` output. Nested
/// [`StoredAccountGroupComponent`] values redact in-band component bytes that
/// carry the same keys.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredAccountGroup {
    pub group_id_hex: String,
    pub endpoint: String,
    pub profile_name: String,
    pub profile_description: String,
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub image_media_type: Option<String>,
    pub admin_keys_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    /// Current locally observed MLS roster size. `None` for legacy rows until a
    /// live group hydration persists the projection.
    pub member_count: Option<u64>,
    pub welcomer_account_id_hex: Option<String>,
    pub via_welcome_message_id_hex: Option<String>,
    pub nostr_routing_last_epoch: u64,
    /// Authenticated Nostr routes that preceded the current group component
    /// and still intersect a retained-history window.
    pub prior_nostr_routes: Vec<StoredNostrRoute>,
    /// The local account's membership in this group. Read-only on this struct:
    /// it is loaded from `account_groups` but owned exclusively by
    /// [`SqliteAccountStorage::set_group_self_membership`], so the projection
    /// save deliberately ignores it (a routine resave must not clobber a
    /// membership change). New rows take the schema default `Member`.
    pub self_membership: SelfMembership,
    pub components: Vec<StoredAccountGroupComponent>,
}

impl fmt::Debug for StoredAccountGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredAccountGroup")
            .field("group_id_hex", &self.group_id_hex)
            .field("endpoint", &self.endpoint)
            .field("profile_name", &self.profile_name)
            .field("profile_description", &self.profile_description)
            .field("image_hash_hex", &self.image_hash_hex)
            .field("image_key_hex", &"<redacted>")
            .field("image_nonce_hex", &self.image_nonce_hex)
            .field("image_upload_key_hex", &"<redacted>")
            .field("image_media_type", &self.image_media_type)
            .field("admin_keys_hex", &self.admin_keys_hex)
            .field("archived", &self.archived)
            .field("pending_confirmation", &self.pending_confirmation)
            .field("member_count", &self.member_count)
            .field("welcomer_account_id_hex", &self.welcomer_account_id_hex)
            .field(
                "via_welcome_message_id_hex",
                &self.via_welcome_message_id_hex,
            )
            .field("nostr_routing_last_epoch", &self.nostr_routing_last_epoch)
            .field("prior_nostr_routes", &self.prior_nostr_routes)
            .field("self_membership", &self.self_membership)
            .field("components", &self.components)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredNostrRoute {
    pub nostr_group_id_hex: String,
    pub relays: Vec<String>,
    pub last_epoch: u64,
}

/// `component_data_hex` carries MLS-protected component bytes. Blossom image
/// payloads embed avatar decryption and Blossom upload keys; other components
/// may carry sensitive policy bytes. SQLCipher protects persistence, but
/// `Debug` must never render raw component bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredAccountGroupComponent {
    pub component_id: u16,
    pub component_name: String,
    pub component_data_hex: String,
}

impl fmt::Debug for StoredAccountGroupComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredAccountGroupComponent")
            .field("component_id", &self.component_id)
            .field("component_name", &self.component_name)
            .field("component_data_hex", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoredAppMessageQuery {
    pub group_id_hex: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
enum SecurePruneAppEventsMode {
    RecordedBefore(u64),
    ExpiredAt(u64),
}

impl SecurePruneAppEventsMode {
    fn trace_method(self) -> &'static str {
        match self {
            Self::RecordedBefore(_) => "secure_prune_app_events_before",
            Self::ExpiredAt(_) => "secure_prune_expired_app_events",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAppMessageRecord {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub source_epoch: Option<u64>,
    pub retention: Option<cgka_traits::app_event::AppMessageRetentionDecision>,
    pub recorded_at: u64,
    pub received_at: u64,
    /// True when convergence retained this raw row only as an invalidated
    /// losing-branch tombstone. Invalidated modifiers must never be replayed as
    /// effective agent events.
    pub invalidated: bool,
    /// Whether this delete carried an authenticated moderation grant when it
    /// was recorded. False for every non-delete event.
    pub moderation_grant: bool,
    /// Local `app_events` insert order (rowid). The final, LOCAL tiebreak of the
    /// raw-event replay ordering; see [`AppEventReplayCursor`]. Never used for
    /// cross-client display order (that is the materialized-timeline surface).
    pub insert_order: i64,
}

impl StoredAppMessageRecord {
    /// The raw-event replay cursor for this row (recovery ordering only).
    pub fn replay_cursor(&self) -> AppEventReplayCursor {
        AppEventReplayCursor {
            recorded_at: self.recorded_at,
            message_id_hex: self.message_id_hex.clone(),
            insert_order: self.insert_order,
        }
    }
}

/// Column list for [`SqliteAccountStorage::app_messages`], ending in
/// `insert_order`, `moderation_grant`, and `invalidated` (column indexes
/// 12-14, read by
/// `app_message_from_row`).
const APP_EVENT_REPLAY_COLUMNS: &str = "message_id_hex, direction, group_id_hex, sender, plaintext, \
     kind, tags_json, source_epoch, retention_seconds, retention_expires_at, recorded_at, \
     received_at, insert_order, moderation_grant, invalidated";

/// The ONE ascending order for the raw-event replay surface (recovery / lag
/// replay), shared by [`SqliteAccountStorage::app_messages`] and — via
/// [`AppEventReplayCursor`]'s `Ord` — the runtime recovery watermark and
/// suppression, so the query order and the watermark cut-point can never drift
/// (#630, #736 boundary contract 1). This is the RAW-EVENT surface only: it is
/// NOT the materialized-timeline `(timeline_at, message_id_hex)` display order.
pub(crate) const APP_EVENT_REPLAY_ORDER_ASC: &str = "recorded_at, message_id_hex, insert_order";
/// Descending variant of [`APP_EVENT_REPLAY_ORDER_ASC`] for the newest-first
/// `LIMIT` window that a bounded replay materializes before re-sorting ascending.
pub(crate) const APP_EVENT_REPLAY_ORDER_DESC: &str =
    "recorded_at DESC, message_id_hex DESC, insert_order DESC";

/// Total order over the RAW-EVENT replay surface: `(recorded_at, message_id_hex,
/// insert_order)`. `insert_order` is a LOCAL rowid, which is correct here because
/// this cursor is only ever a per-client recovery cut-point (the lag-recovery
/// watermark + suppression), never the cross-client user-visible timeline order.
/// The third field is load-bearing for unscoped (all-groups) recovery: the same
/// `message_id_hex` can appear in two groups (it is unique only per group — e.g.
/// a sender posting identical content to two groups in the same second), so a
/// two-field cut-point could wrongly suppress a genuinely-new same-second row.
/// This is the single canonical comparator behind #630; keep it byte-identical
/// to [`APP_EVENT_REPLAY_ORDER_ASC`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppEventReplayCursor {
    pub recorded_at: u64,
    pub message_id_hex: String,
    pub insert_order: i64,
}

impl Ord for AppEventReplayCursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.recorded_at
            .cmp(&other.recorded_at)
            .then_with(|| self.message_id_hex.cmp(&other.message_id_hex))
            .then_with(|| self.insert_order.cmp(&other.insert_order))
    }
}

impl PartialOrd for AppEventReplayCursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountNotificationSettings {
    pub account_label: String,
    pub account_id_hex: String,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountChatNotificationSettings {
    pub group_id_hex: String,
    pub muted: bool,
    pub muted_until_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPushRegistration {
    pub account_label: String,
    pub account_id_hex: String,
    pub platform: u8,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_shared_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountStoredPushRegistration {
    pub registration: AccountPushRegistration,
    pub token_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPendingPushRegistrationRemoval {
    pub group_id_hex: String,
    pub registration: AccountPushRegistration,
    pub last_attempted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountGroupPushToken {
    pub group_id_hex: String,
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: u8,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub encrypted_token: Vec<u8>,
    /// Owner-signed millisecond ordering stamp (high half of the primitive).
    pub owner_ts: i64,
    /// 128-hex BIP-340 signature by `member_id_hex` over the canonical record.
    pub owner_sig: String,
    /// `SHA-256(SignedRecord)` hex — the ordering tie-breaker. Stored so the
    /// engine-free storage layer can compare stamps without the crypto code.
    pub record_digest: String,
    pub updated_at_ms: i64,
}

struct RawStoredAccountGroup {
    group_id_hex: String,
    endpoint: String,
    profile_name: String,
    profile_description: String,
    image_hash_hex: String,
    image_key_hex: String,
    image_nonce_hex: String,
    image_upload_key_hex: String,
    image_media_type: Option<String>,
    admin_keys_hex: String,
    archived: bool,
    pending_confirmation: bool,
    member_count: Option<i64>,
    welcomer_account_id_hex: Option<String>,
    via_welcome_message_id_hex: Option<String>,
    nostr_routing_last_epoch: i64,
    prior_nostr_routes_json: String,
    self_membership: SelfMembership,
}

impl SqliteAccountStorage {
    pub fn ensure_account_projection(&self, label: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO account_state (label, updated_at)
                 VALUES (?1, ?2)
                 ON CONFLICT(label) DO NOTHING",
                params![label, unix_now_seconds_i64()],
            )
            .storage()?;
        Ok(())
    }

    pub fn load_account_projection_state(
        &self,
        label: &str,
        max_seen_events: usize,
    ) -> StorageResult<StoredAccountState> {
        self.ensure_account_projection(label)?;
        let conn = self.lock()?;
        let last_transport_timestamp = conn
            .query_row(
                "SELECT last_transport_timestamp FROM account_state WHERE label = ?1",
                params![label],
                |row| row.get::<_, Option<i64>>(0),
            )
            .storage()?
            .and_then(|value| u64::try_from(value).ok());

        let mut seen_statement = conn
            .prepare(
                "SELECT event_id FROM (
                    SELECT event_id, seen_at, rowid FROM seen_events
                    ORDER BY seen_at DESC, rowid DESC
                    LIMIT ?1
                 )
                 ORDER BY seen_at, rowid",
            )
            .storage()?;
        let seen_events = seen_statement
            .query_map(params![usize_to_i64(max_seen_events)?], |row| {
                row.get::<_, String>(0)
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;

        let mut group_statement = conn
            .prepare(
                "SELECT group_id_hex, endpoint, profile_name, profile_description,
                        image_hash_hex, image_key_hex, image_nonce_hex,
                        image_upload_key_hex, image_media_type, admin_keys_hex,
                        archived, pending_confirmation, welcomer_account_id_hex,
                        via_welcome_message_id_hex, nostr_routing_last_epoch,
                        prior_nostr_routes_json, self_membership, member_count
                 FROM account_groups
                 ORDER BY updated_at, group_id_hex",
            )
            .storage()?;
        let raw_groups = group_statement
            .query_map([], |row| {
                Ok(RawStoredAccountGroup {
                    group_id_hex: row.get(0)?,
                    endpoint: row.get(1)?,
                    profile_name: row.get(2)?,
                    profile_description: row.get(3)?,
                    image_hash_hex: row.get(4)?,
                    image_key_hex: row.get(5)?,
                    image_nonce_hex: row.get(6)?,
                    image_upload_key_hex: row.get(7)?,
                    image_media_type: row.get(8)?,
                    admin_keys_hex: row.get(9)?,
                    archived: row.get::<_, i64>(10)? != 0,
                    pending_confirmation: row.get::<_, i64>(11)? != 0,
                    welcomer_account_id_hex: row.get(12)?,
                    via_welcome_message_id_hex: row.get(13)?,
                    nostr_routing_last_epoch: row.get(14)?,
                    prior_nostr_routes_json: row.get(15)?,
                    self_membership: SelfMembership::from_storage(&row.get::<_, String>(16)?),
                    member_count: row.get(17)?,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        drop(group_statement);

        let mut components_by_group = all_account_group_components(&conn)?;
        let mut groups = Vec::with_capacity(raw_groups.len());
        for raw in raw_groups {
            let prior_nostr_routes = serde_json::from_str(&raw.prior_nostr_routes_json)
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            let components = components_by_group
                .remove(&raw.group_id_hex)
                .unwrap_or_default();
            groups.push(StoredAccountGroup {
                group_id_hex: raw.group_id_hex,
                endpoint: raw.endpoint,
                profile_name: raw.profile_name,
                profile_description: raw.profile_description,
                image_hash_hex: raw.image_hash_hex,
                image_key_hex: raw.image_key_hex,
                image_nonce_hex: raw.image_nonce_hex,
                image_upload_key_hex: raw.image_upload_key_hex,
                image_media_type: raw.image_media_type,
                admin_keys_hex: raw.admin_keys_hex,
                archived: raw.archived,
                pending_confirmation: raw.pending_confirmation,
                member_count: raw.member_count.and_then(|value| value.try_into().ok()),
                welcomer_account_id_hex: raw.welcomer_account_id_hex,
                via_welcome_message_id_hex: raw.via_welcome_message_id_hex,
                nostr_routing_last_epoch: raw
                    .nostr_routing_last_epoch
                    .try_into()
                    .unwrap_or_default(),
                prior_nostr_routes,
                self_membership: raw.self_membership,
                components,
            });
        }

        Ok(StoredAccountState {
            label: label.to_owned(),
            seen_events,
            last_transport_timestamp,
            groups,
        })
    }

    /// Persist one account-projection snapshot.
    ///
    /// # Cross-process semantics
    ///
    /// Multiple runtimes may save over the same account database concurrently
    /// (for example a main app process and a short-lived notification-wake
    /// process). The transaction is `BEGIN IMMEDIATE`, so everything below is
    /// atomic against concurrent writers, and the write is shaped so a stale
    /// or fresh writer can never regress durable delivery state:
    ///
    /// - `last_transport_timestamp` is merged, never overwritten: the stored
    ///   cursor is read back inside the transaction and folded with the
    ///   snapshot cursor via [`merged_transport_timestamp`]. When both sides
    ///   are present they are each clamped to `now + max_future_skew_secs` and
    ///   the max wins, so a stored value poisoned above the ceiling comes out
    ///   healed instead of winning the max forever. A snapshot that never
    ///   learned a cursor (`None`) is cursor-neutral and preserves the stored
    ///   value unchanged; a fresh store adopts the snapshot side clamped to the
    ///   same ceiling. Known residual: a skew-inflated but still within-clamp
    ///   value persists until wall clock passes it (bounded by
    ///   `max_future_skew_secs`). Any future deliberate cursor reset must be a
    ///   dedicated, named API — a raw save cannot lower the merged value.
    /// - `seen_events` is a `seen_at`-refreshing union pruned to the newest
    ///   `max_seen_events` rows, so a re-seen event outlives rows whose only
    ///   sighting is old. It only narrows cross-restart redelivery;
    ///   engine-level dedup stays the authoritative duplicate guard.
    /// - Group and component rows are snapshot-replaced (last writer wins),
    ///   except that a durable local-deletion frontier wins over stale snapshot
    ///   writers, and a group row remains while it owns an unsent draft so
    ///   pruning re-derivable metadata cannot cascade-delete user-authored content.
    ///   Consequently, a stale draft-owning group remains visible in the
    ///   projection/chat list until its draft is removed and a later save can
    ///   prune the group. Full multi-writer reconciliation is an explicit
    ///   non-goal.
    ///
    /// `max_future_skew_secs` is caller policy (the app layer passes its
    /// transport-cursor skew); this crate only enforces the column merge rule.
    pub fn save_account_projection_state(
        &self,
        state: &StoredAccountState,
        max_seen_events: usize,
        max_future_skew_secs: u64,
    ) -> StorageResult<()> {
        self.save_account_projection_state_clearing_local_group_deletion_frontiers(
            state,
            max_seen_events,
            max_future_skew_secs,
            &[],
        )
    }

    /// Persist the account snapshot while atomically clearing only the
    /// local-deletion markers whose insertion-order frontier still matches the
    /// caller's batch-start observation. A concurrent repeated delete advances
    /// the frontier and therefore keeps both its marker and projection filter.
    pub fn save_account_projection_state_clearing_local_group_deletion_frontiers(
        &self,
        state: &StoredAccountState,
        max_seen_events: usize,
        max_future_skew_secs: u64,
        frontiers_to_clear: &[(String, u64)],
    ) -> StorageResult<()> {
        self.save_account_projection_state_clearing_local_group_deletion_frontiers_and_acking_application_events(
            state,
            max_seen_events,
            max_future_skew_secs,
            frontiers_to_clear,
            &[],
        )
    }

    /// Persist the account projection, clear matched local-delete frontiers,
    /// and acknowledge authenticated application deliveries in one transaction.
    /// A crash can therefore leave the outbox pending or the full projection
    /// committed, but never strand the engine ahead of the app.
    pub fn save_account_projection_state_clearing_local_group_deletion_frontiers_and_acking_application_events(
        &self,
        state: &StoredAccountState,
        max_seen_events: usize,
        max_future_skew_secs: u64,
        frontiers_to_clear: &[(String, u64)],
        application_event_ids_to_ack: &[MessageId],
    ) -> StorageResult<()> {
        let now = unix_now_seconds();
        let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for (group_id_hex, expected_frontier) in frontiers_to_clear {
                conn.execute(
                    "DELETE FROM local_group_deletion_frontiers
                     WHERE group_id_hex = ?1 AND message_insert_order = ?2",
                    params![
                        group_id_hex,
                        i64::try_from(*expected_frontier).unwrap_or(i64::MAX)
                    ],
                )
                .storage()?;
            }
            let stored_cursor = conn
                .query_row(
                    "SELECT last_transport_timestamp FROM account_state WHERE label = ?1",
                    params![&state.label],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()
                .storage()?
                .flatten()
                .and_then(|value| u64::try_from(value).ok());
            let last_transport_timestamp = merged_transport_timestamp(
                stored_cursor,
                state.last_transport_timestamp,
                now,
                max_future_skew_secs,
            );
            conn.execute(
                "INSERT INTO account_state (label, updated_at, last_transport_timestamp)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(label) DO UPDATE SET
                    updated_at = excluded.updated_at,
                    last_transport_timestamp = excluded.last_transport_timestamp",
                params![
                    &state.label,
                    now_i64,
                    last_transport_timestamp.and_then(|value| i64::try_from(value).ok()),
                ],
            )
            .storage()?;

            let retained_start = state.seen_events.len().saturating_sub(max_seen_events);
            for event_id in &state.seen_events[retained_start..] {
                conn.execute(
                    "INSERT INTO seen_events (event_id, seen_at)
                     VALUES (?1, ?2)
                     ON CONFLICT(event_id) DO UPDATE SET
                        seen_at = excluded.seen_at",
                    params![event_id, now_i64],
                )
                .storage()?;
            }
            conn.execute(
                "DELETE FROM seen_events
                 WHERE event_id NOT IN (
                    SELECT event_id FROM seen_events
                    ORDER BY seen_at DESC, rowid DESC
                    LIMIT ?1
                 )",
                params![usize_to_i64(max_seen_events)?],
            )
            .storage()?;

            let locally_deleted_group_ids = {
                let mut statement = conn
                    .prepare("SELECT group_id_hex FROM local_group_deletion_frontiers")
                    .storage()?;
                statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .storage()?
                    .collect::<Result<std::collections::HashSet<_>, _>>()
                    .storage()?
            };
            let retained_group_ids = state
                .groups
                .iter()
                .filter(|group| !locally_deleted_group_ids.contains(&group.group_id_hex))
                .map(|group| group.group_id_hex.as_str())
                .collect::<std::collections::HashSet<_>>();
            // Draft text and attachment plaintext are user-authored durable data,
            // unlike this re-derivable projection. Exclude their owning groups
            // from stale candidates so the account_groups FK cascade cannot
            // destroy them. This intentionally keeps that stale group visible in
            // projection/chat-list reads while its draft exists. Once the draft
            // is deleted, the next save selects the group as a candidate and
            // cleans it up normally.
            delete_stale_text_keys(
                &conn,
                "SELECT group_id_hex
                 FROM account_groups
                 WHERE NOT EXISTS (
                    SELECT 1 FROM message_drafts
                    WHERE message_drafts.group_id_hex = account_groups.group_id_hex
                 )",
                &[],
                "DELETE FROM account_groups WHERE group_id_hex IN",
                &[],
                &retained_group_ids,
            )?;

            for group in state
                .groups
                .iter()
                .filter(|group| !locally_deleted_group_ids.contains(&group.group_id_hex))
            {
                let group_was_new = !conn
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM account_groups WHERE group_id_hex = ?1
                         )",
                        params![&group.group_id_hex],
                        |row| row.get::<_, bool>(0),
                    )
                    .storage()?;
                let nostr_routing_last_epoch =
                    i64::try_from(group.nostr_routing_last_epoch).unwrap_or(i64::MAX);
                let prior_nostr_routes_json = serde_json::to_string(&group.prior_nostr_routes)
                    .map_err(|err| StorageError::Serialization(err.to_string()))?;
                conn.execute(
                    "INSERT INTO account_groups (
                        group_id_hex, endpoint, profile_name, profile_description,
                        image_hash_hex, image_key_hex, image_nonce_hex,
                        image_upload_key_hex, image_media_type, admin_keys_hex, archived,
                        pending_confirmation, welcomer_account_id_hex, via_welcome_message_id_hex,
                        nostr_routing_last_epoch, prior_nostr_routes_json,
                        conversation_created_at, updated_at, member_count
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
                     ON CONFLICT(group_id_hex) DO UPDATE SET
                        endpoint = excluded.endpoint,
                        profile_name = excluded.profile_name,
                        profile_description = excluded.profile_description,
                        image_hash_hex = excluded.image_hash_hex,
                        image_key_hex = excluded.image_key_hex,
                        image_nonce_hex = excluded.image_nonce_hex,
                        image_upload_key_hex = excluded.image_upload_key_hex,
                        image_media_type = excluded.image_media_type,
                        admin_keys_hex = excluded.admin_keys_hex,
                        archived = excluded.archived,
                        pending_confirmation = excluded.pending_confirmation,
                        welcomer_account_id_hex = excluded.welcomer_account_id_hex,
                        via_welcome_message_id_hex = excluded.via_welcome_message_id_hex,
                        nostr_routing_last_epoch = excluded.nostr_routing_last_epoch,
                        prior_nostr_routes_json = excluded.prior_nostr_routes_json,
                        member_count = excluded.member_count,
                        updated_at = excluded.updated_at
                     WHERE account_groups.endpoint IS NOT excluded.endpoint
                        OR account_groups.profile_name IS NOT excluded.profile_name
                        OR account_groups.profile_description IS NOT excluded.profile_description
                        OR account_groups.image_hash_hex IS NOT excluded.image_hash_hex
                        OR account_groups.image_key_hex IS NOT excluded.image_key_hex
                        OR account_groups.image_nonce_hex IS NOT excluded.image_nonce_hex
                        OR account_groups.image_upload_key_hex IS NOT excluded.image_upload_key_hex
                        OR account_groups.image_media_type IS NOT excluded.image_media_type
                        OR account_groups.admin_keys_hex IS NOT excluded.admin_keys_hex
                        OR account_groups.archived IS NOT excluded.archived
                        OR account_groups.pending_confirmation IS NOT excluded.pending_confirmation
                        OR account_groups.welcomer_account_id_hex IS NOT excluded.welcomer_account_id_hex
                        OR account_groups.via_welcome_message_id_hex IS NOT excluded.via_welcome_message_id_hex
                        OR account_groups.nostr_routing_last_epoch IS NOT excluded.nostr_routing_last_epoch
                        OR account_groups.prior_nostr_routes_json IS NOT excluded.prior_nostr_routes_json
                        OR account_groups.member_count IS NOT excluded.member_count",
                    params![
                        &group.group_id_hex,
                        &group.endpoint,
                        &group.profile_name,
                        &group.profile_description,
                        &group.image_hash_hex,
                        &group.image_key_hex,
                        &group.image_nonce_hex,
                        &group.image_upload_key_hex,
                        &group.image_media_type,
                        &group.admin_keys_hex,
                        bool_i64(group.archived),
                        bool_i64(group.pending_confirmation),
                        &group.welcomer_account_id_hex,
                        &group.via_welcome_message_id_hex,
                        nostr_routing_last_epoch,
                        prior_nostr_routes_json,
                        now_i64,
                        now_i64,
                        group.member_count.and_then(|count| i64::try_from(count).ok())
                    ],
                )
                .storage()?;

                if group_was_new {
                    let queued = conn
                        .execute(
                            "INSERT INTO pending_push_registration_shares (
                                group_id_hex, token_fingerprint,
                                registration_updated_at_ms, queued_at_ms,
                                last_attempted_at_ms
                             )
                             SELECT ?1, token_fingerprint, updated_at_ms, ?2, NULL
                             FROM push_registration
                             LIMIT 1
                             ON CONFLICT(group_id_hex) DO UPDATE SET
                                token_fingerprint = excluded.token_fingerprint,
                                registration_updated_at_ms = excluded.registration_updated_at_ms,
                                queued_at_ms = excluded.queued_at_ms,
                                last_attempted_at_ms = NULL",
                            params![&group.group_id_hex, unix_now_ms()],
                        )
                        .storage()?;
                    if queued > 0 {
                        conn.execute("UPDATE push_registration SET last_shared_at_ms = NULL", [])
                            .storage()?;
                    }
                }

                delete_stale_group_components(&conn, &group.group_id_hex, &group.components)?;
                for component in &group.components {
                    upsert_group_component(&conn, &group.group_id_hex, component, now_i64)?;
                }
            }
            for message_id in application_event_ids_to_ack {
                conn.execute(
                    "DELETE FROM pending_application_events WHERE message_id = ?1",
                    params![message_id.as_slice()],
                )
                .storage()?;
            }
            Ok(())
        })
    }

    /// Transactionally removes all app-local data for one group without touching
    /// the stored MLS/OpenMLS group state. This is the storage primitive for the
    /// local delete/wipe UX: it drops the chat-list/account projection, plaintext
    /// app events, timeline rows, agent-stream start projection rows, cached
    /// encrypted-media epoch secrets, and group push-token rows keyed by
    /// `group_id_hex`. A metadata-only media-secret retirement barrier remains
    /// because protocol/MLS state is intentionally retained; without it that
    /// state could immediately rederive wiped key bytes. `seen_events` and
    /// protocol/MLS tables are left intact for active groups. A durable local
    /// deletion frontier distinguishes the intentionally absent projection from
    /// a torn write, suppressing historical relay replay while allowing a
    /// causally newer chat message to re-create it. A terminal group is
    /// different: its live MLS state is already erased, so this transaction also
    /// removes the full `cgka_groups` row and retains only
    /// `cgka_disband_tombstones` as the permanent anti-resurrection guard. The
    /// logical wipe and a durable WAL checkpoint intent commit together under
    /// `secure_delete = ON`. If `wal_checkpoint(TRUNCATE)` is blocked by a reader,
    /// the committed result is returned with `erasure_pending`; a retry recovers
    /// the accumulated result from the intent and attempts truncation again.
    pub fn delete_local_group_data(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<DeleteLocalGroupDataResult> {
        if group_id_hex.trim().is_empty() {
            return Err(StorageError::Backend(
                "local group delete id must not be empty".to_owned(),
            ));
        }
        let group_id = hex::decode(group_id_hex).map_err(|error| {
            StorageError::Serialization(format!("invalid local group id: {error}"))
        })?;

        let newly_deleted = retry_on_busy(|| {
            let mut conn = self.lock()?;
            let original = secure_delete_pragma(&conn)?;
            conn.execute_batch("PRAGMA secure_delete = ON;").storage()?;
            let delete_result = (|| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .storage()?;
                let mut deleted =
                    retire_all_encrypted_media_secrets_for_group_tx(&tx, group_id_hex)?;
                let prior_nostr_routes_json = tx
                    .query_row(
                        "SELECT prior_nostr_routes_json
                         FROM account_groups
                         WHERE group_id_hex = ?1",
                        params![group_id_hex],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .storage()?
                    .unwrap_or_else(|| "[]".to_owned());
                deleted = deleted.saturating_add(
                    tx.execute(
                        "DELETE FROM pending_application_events WHERE group_id = ?1",
                        params![&group_id],
                    )
                    .storage()?,
                );
                for table in [
                    "app_events",
                    "message_timeline",
                    "agent_stream_starts",
                    "conversation_read_state",
                    "chat_list_rows",
                    "account_group_app_components",
                    "group_push_tokens",
                    "group_push_token_tombstones",
                    "pending_push_registration_shares",
                    "chat_notification_settings",
                    "encrypted_media_epoch_secret_references",
                    "encrypted_media_epoch_secrets",
                    "account_groups",
                ] {
                    deleted = deleted.saturating_add(
                        tx.execute(
                            &format!("DELETE FROM {table} WHERE group_id_hex = ?1"),
                            params![group_id_hex],
                        )
                        .storage()?,
                    );
                }
                let (terminal, active, message_insert_order) = tx
                    .query_row(
                        "SELECT
                            EXISTS(SELECT 1 FROM cgka_disband_tombstones WHERE group_id = ?1),
                            EXISTS(SELECT 1 FROM cgka_groups WHERE id = ?1),
                            COALESCE(
                                (SELECT MAX(insert_order) FROM cgka_messages WHERE group_id = ?1),
                                0
                            )",
                        params![&group_id],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)? != 0,
                                row.get::<_, i64>(1)? != 0,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                    .storage()?;
                if active && !terminal {
                    tx.execute(
                        "INSERT INTO local_group_deletion_frontiers (
                            group_id_hex, message_insert_order, prior_nostr_routes_json
                         ) VALUES (?1, ?2, ?3)
                         ON CONFLICT(group_id_hex) DO UPDATE SET
                            message_insert_order = MAX(
                                local_group_deletion_frontiers.message_insert_order,
                                excluded.message_insert_order
                            ),
                            prior_nostr_routes_json = CASE
                                WHEN excluded.prior_nostr_routes_json = '[]'
                                    THEN local_group_deletion_frontiers.prior_nostr_routes_json
                                ELSE excluded.prior_nostr_routes_json
                            END",
                        params![
                            hex::encode(&group_id),
                            message_insert_order,
                            prior_nostr_routes_json
                        ],
                    )
                    .storage()?;
                }
                if terminal {
                    tx.execute(
                        "DELETE FROM local_group_deletion_frontiers WHERE group_id_hex = ?1",
                        params![hex::encode(&group_id)],
                    )
                    .storage()?;
                    deleted = deleted.saturating_add(
                        tx.execute("DELETE FROM cgka_groups WHERE id = ?1", params![&group_id])
                            .storage()?,
                    );
                }
                if deleted > 0 {
                    merge_local_group_delete_intent_tx(&tx, group_id_hex, deleted)?;
                }
                tx.commit().storage()?;
                Ok(deleted)
            })();
            let restore = restore_secure_delete_pragma(&conn, original);
            combine_secure_delete_operation_and_restore(delete_result, restore)
        })?;

        let finish = match finish_secure_delete_checkpoint_intent::<DeleteLocalGroupDataResult>(
            self,
            SECURE_DELETE_LOCAL_GROUP_OPERATION,
            group_id_hex,
        ) {
            Ok(finish) => finish,
            Err(_) => {
                // The logical deletion and its checkpoint intent committed before
                // this best-effort finish step. Report that committed outcome and
                // leave the durable intent for a later retry instead of inviting
                // the caller to restore projection state that was already erased.
                tracing::warn!(
                    target: "storage_sqlite::account_projection",
                    method = "delete_local_group_data",
                    "secure-delete checkpoint cleanup remains pending after committed local deletion"
                );
                return Ok(DeleteLocalGroupDataResult {
                    deleted_rows: newly_deleted,
                    completed_pending_checkpoint: false,
                    erasure_pending: true,
                });
            }
        };
        match finish.result {
            Some(mut result) => {
                result.completed_pending_checkpoint =
                    newly_deleted == 0 && result.deleted_rows > 0 && !finish.erasure_pending;
                result.erasure_pending = finish.erasure_pending;
                Ok(result)
            }
            // Another process may have checkpointed and consumed this intent
            // after our logical deletion committed. In that case erasure is
            // complete, and this caller must still report its locally known
            // deletion instead of incorrectly returning "nothing existed".
            None => Ok(DeleteLocalGroupDataResult {
                deleted_rows: newly_deleted,
                completed_pending_checkpoint: false,
                erasure_pending: false,
            }),
        }
    }

    /// Return the durable message-ingress frontier recorded by a deliberate
    /// local group deletion. Its presence distinguishes an intentionally absent
    /// app projection from a torn projection write while the MLS group remains
    /// live, without trusting a remote sender's timestamp.
    pub fn local_group_deletion_frontier(&self, group_id_hex: &str) -> StorageResult<Option<u64>> {
        self.lock()?
            .query_row(
                "SELECT message_insert_order
                 FROM local_group_deletion_frontiers
                 WHERE group_id_hex = ?1",
                params![group_id_hex],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .storage()?
            .map(|value| {
                u64::try_from(value).map_err(|_| {
                    StorageError::Serialization("negative local group deletion frontier".to_owned())
                })
            })
            .transpose()
    }

    /// Return the exact Nostr route/relay pairs retained by a deliberate local
    /// deletion. The current signed routing component remains engine-owned; this
    /// durable history preserves routes observed before and while the group was
    /// hidden.
    pub fn local_group_deletion_prior_nostr_routes(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<Vec<StoredNostrRoute>> {
        let routes_json = self
            .lock()?
            .query_row(
                "SELECT prior_nostr_routes_json
                 FROM local_group_deletion_frontiers
                 WHERE group_id_hex = ?1",
                params![group_id_hex],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .storage()?;
        routes_json
            .map(|routes| {
                serde_json::from_str(&routes)
                    .map_err(|error| StorageError::Serialization(error.to_string()))
            })
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    /// Retain exact routing coordinates observed while a locally deleted MLS
    /// group remains live. A hidden group may rotate more than once before the
    /// app restarts, so every route that was current must remain reconstructible
    /// without borrowing relay endpoints from a later route id.
    pub fn retain_local_group_deletion_nostr_routes(
        &self,
        group_id_hex: &str,
        routes: &[StoredNostrRoute],
    ) -> StorageResult<()> {
        if routes.is_empty() {
            return Ok(());
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let Some(routes_json) = conn
                .query_row(
                    "SELECT prior_nostr_routes_json
                     FROM local_group_deletion_frontiers
                     WHERE group_id_hex = ?1",
                    params![group_id_hex],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .storage()?
            else {
                return Ok(());
            };
            let mut retained = serde_json::from_str::<Vec<StoredNostrRoute>>(&routes_json)
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            for route in routes {
                if let Some(existing) = retained.iter_mut().find(|existing| {
                    existing.nostr_group_id_hex == route.nostr_group_id_hex
                        && existing.relays == route.relays
                }) {
                    existing.last_epoch = existing.last_epoch.max(route.last_epoch);
                } else {
                    retained.push(route.clone());
                }
            }
            let group_id = hex::decode(group_id_hex).map_err(|error| {
                StorageError::Serialization(format!("invalid local group id: {error}"))
            })?;
            let active_route_ids = {
                let mut statement = conn
                    .prepare(
                        "SELECT transport_group_id
                         FROM cgka_transport_group_routes
                         WHERE group_id = ?1",
                    )
                    .storage()?;
                statement
                    .query_map(params![group_id], |row| row.get::<_, Vec<u8>>(0))
                    .storage()?
                    .collect::<Result<std::collections::HashSet<_>, _>>()
                    .storage()?
            };
            // Hydrated live groups always have an engine-owned route index. An
            // empty set can still occur while upgrading a legacy database before
            // hydration backfills migration 0043, so retain its exact history
            // until the engine supplies an authoritative overlap window.
            if !active_route_ids.is_empty() {
                retained.retain(|route| {
                    hex::decode(&route.nostr_group_id_hex)
                        .is_ok_and(|route_id| active_route_ids.contains(&route_id))
                });
            }
            retained.sort_by(|left, right| {
                left.last_epoch
                    .cmp(&right.last_epoch)
                    .then_with(|| left.nostr_group_id_hex.cmp(&right.nostr_group_id_hex))
                    .then_with(|| left.relays.cmp(&right.relays))
            });
            let retained_json = serde_json::to_string(&retained)
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            if retained_json == routes_json {
                return Ok(());
            }
            conn.execute(
                "UPDATE local_group_deletion_frontiers
                 SET prior_nostr_routes_json = ?2
                 WHERE group_id_hex = ?1",
                params![group_id_hex, retained_json],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Clear a local-delete marker only when `message_id` belongs to this group
    /// and was durably inserted after the deletion frontier. Exact or rewrapped
    /// historical replay resolves to an older existing row and stays suppressed.
    pub fn clear_local_group_deletion_frontier_if_message_is_newer(
        &self,
        group_id_hex: &str,
        message_id: &MessageId,
    ) -> StorageResult<bool> {
        let group_id = hex::decode(group_id_hex).map_err(|error| {
            StorageError::Serialization(format!("invalid local group id: {error}"))
        })?;
        Ok(self
            .lock()?
            .execute(
                "DELETE FROM local_group_deletion_frontiers
                 WHERE group_id_hex = ?1
                   AND message_insert_order < (
                       SELECT insert_order
                       FROM cgka_messages
                       WHERE id = ?2 AND group_id = ?3
                   )",
                params![group_id_hex, message_id.as_slice(), group_id],
            )
            .storage()?
            > 0)
    }

    /// Return whether `message_id` belongs to `group_id_hex` and was durably
    /// inserted after the supplied batch-start local-deletion frontier. This
    /// intentionally does not clear the marker: the caller persists the
    /// crossing projection and clears the expected frontier in one transaction.
    pub fn local_group_deletion_message_is_newer_than(
        &self,
        group_id_hex: &str,
        message_id: &MessageId,
        frontier: u64,
    ) -> StorageResult<bool> {
        let group_id = hex::decode(group_id_hex).map_err(|error| {
            StorageError::Serialization(format!("invalid local group id: {error}"))
        })?;
        self.lock()?
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM cgka_messages
                    WHERE id = ?1 AND group_id = ?2 AND insert_order > ?3
                 )",
                params![
                    message_id.as_slice(),
                    group_id,
                    i64::try_from(frontier).unwrap_or(i64::MAX)
                ],
                |row| row.get::<_, bool>(0),
            )
            .storage()
    }

    /// Remove a local-delete marker once the protocol group reaches a terminal
    /// state. Terminal engine state is the anti-resurrection authority, so the
    /// app-only marker no longer serves a purpose.
    pub fn clear_local_group_deletion_frontier(&self, group_id_hex: &str) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute(
                "DELETE FROM local_group_deletion_frontiers WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?
            > 0)
    }

    /// Record the local account's own membership in `group_id_hex` so the
    /// chat list and removed-group-suppressed unread aggregate reflect whether
    /// the account is still in the group and, if not, how it left. `Left` and
    /// `Removed` both suppress the group's unread; `Member` re-affirms it
    /// (preserve / un-suppress on re-add). No-op when the group has no
    /// `account_groups` row yet, so this never resurrects pruned projection
    /// state.
    pub fn set_group_self_membership(
        &self,
        group_id_hex: &str,
        membership: SelfMembership,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let updated = conn
                .execute(
                    "UPDATE account_groups
                     SET self_membership = ?2
                     WHERE group_id_hex = ?1",
                    params![group_id_hex, membership.as_str()],
                )
                .storage()?;
            if updated == 0 {
                return Ok(());
            }
            match membership {
                SelfMembership::Member => {
                    let queued_at_ms = unix_now_ms();
                    let queued = conn
                        .execute(
                            "INSERT INTO pending_push_registration_shares (
                                group_id_hex, token_fingerprint,
                                registration_updated_at_ms, queued_at_ms,
                                last_attempted_at_ms
                             )
                             SELECT ?1, token_fingerprint, updated_at_ms, ?2, NULL
                             FROM push_registration
                             LIMIT 1
                             ON CONFLICT(group_id_hex) DO UPDATE SET
                                token_fingerprint = excluded.token_fingerprint,
                                registration_updated_at_ms = excluded.registration_updated_at_ms,
                                queued_at_ms = excluded.queued_at_ms,
                                last_attempted_at_ms = NULL",
                            params![group_id_hex, queued_at_ms],
                        )
                        .storage()?;
                    if queued > 0 {
                        conn.execute("UPDATE push_registration SET last_shared_at_ms = NULL", [])
                            .storage()?;
                    }
                }
                SelfMembership::Left | SelfMembership::Removed => {
                    conn.execute(
                        "DELETE FROM pending_push_registration_shares
                         WHERE group_id_hex = ?1",
                        params![group_id_hex],
                    )
                    .storage()?;
                }
            }
            Ok(())
        })
    }

    /// `group_id_hex` of every `account_groups` row whose `self_membership` is
    /// still the migration default `'member'`. Used by the one-time
    /// open/upgrade backfill to decide which legacy rows need their membership
    /// derived from current engine state — rows already explicitly flipped to
    /// `'removed'` (or re-affirmed `'member'` by a live event) are skipped, so
    /// the backfill stays idempotent and the hot path keeps reading the
    /// projection only.
    pub fn account_group_ids_defaulting_to_member(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex
                 FROM account_groups
                 WHERE self_membership = 'member'
                 ORDER BY group_id_hex",
            )
            .storage()?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(ids)
    }

    /// Authoritative `account_groups.self_membership` for one group row.
    pub fn group_self_membership(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<Option<SelfMembership>> {
        let conn = self.lock()?;
        let value = conn
            .query_row(
                "SELECT self_membership FROM account_groups WHERE group_id_hex = ?1",
                params![group_id_hex],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .storage()?;
        Ok(value.map(|stored| SelfMembership::from_storage(&stored)))
    }

    /// Authoritative `account_groups.self_membership` for every group row.
    pub fn account_group_self_memberships(
        &self,
    ) -> StorageResult<std::collections::HashMap<String, SelfMembership>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare("SELECT group_id_hex, self_membership FROM account_groups")
            .storage()?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    SelfMembership::from_storage(&row.get::<_, String>(1)?),
                ))
            })
            .storage()?;
        let mut memberships = std::collections::HashMap::new();
        for row in rows {
            let (group_id_hex, membership) = row.storage()?;
            memberships.insert(group_id_hex, membership);
        }
        Ok(memberships)
    }

    pub fn app_messages(
        &self,
        query: StoredAppMessageQuery,
    ) -> StorageResult<Vec<StoredAppMessageRecord>> {
        // Single-source the column list + replay ordering so the query order and
        // the runtime recovery watermark/suppression (via `AppEventReplayCursor`)
        // cannot drift (#630, #736). The limited variants take the newest-first
        // `LIMIT` window, then re-sort ascending into replay order.
        let cols = APP_EVENT_REPLAY_COLUMNS;
        let asc = APP_EVENT_REPLAY_ORDER_ASC;
        let desc = APP_EVENT_REPLAY_ORDER_DESC;
        let sql = match (&query.group_id_hex, query.limit) {
            (Some(_), Some(_)) => format!(
                "SELECT {cols} FROM (
                    SELECT {cols} FROM app_events
                    WHERE group_id_hex = ?1
                    ORDER BY {desc} LIMIT ?2
                 ) ORDER BY {asc}"
            ),
            (Some(_), None) => {
                format!("SELECT {cols} FROM app_events WHERE group_id_hex = ?1 ORDER BY {asc}")
            }
            (None, Some(_)) => format!(
                "SELECT {cols} FROM (
                    SELECT {cols} FROM app_events
                    ORDER BY {desc} LIMIT ?1
                 ) ORDER BY {asc}"
            ),
            (None, None) => format!("SELECT {cols} FROM app_events ORDER BY {asc}"),
        };
        let conn = self.lock()?;
        let mut statement = conn.prepare(&sql).storage()?;
        let rows = match (&query.group_id_hex, query.limit) {
            (Some(group_id_hex), Some(limit)) => statement
                .query_map(
                    params![group_id_hex, usize_to_i64(limit)?],
                    app_message_from_row,
                )
                .storage()?,
            (Some(group_id_hex), None) => statement
                .query_map(params![group_id_hex], app_message_from_row)
                .storage()?,
            (None, Some(limit)) => statement
                .query_map(params![usize_to_i64(limit)?], app_message_from_row)
                .storage()?,
            (None, None) => statement.query_map([], app_message_from_row).storage()?,
        };
        rows.collect::<Result<Vec<_>, _>>().storage()
    }

    /// Resolve one durable raw app event without scanning group history.
    pub fn app_message(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Option<StoredAppMessageRecord>> {
        let cols = APP_EVENT_REPLAY_COLUMNS;
        self.lock()?
            .query_row(
                &format!(
                    "SELECT {cols} FROM app_events
                     WHERE group_id_hex = ?1 AND message_id_hex = ?2
                     LIMIT 1"
                ),
                params![group_id_hex, message_id_hex],
                app_message_from_row,
            )
            .optional()
            .storage()
    }

    pub fn app_message_count(&self) -> StorageResult<usize> {
        let count = self
            .lock()?
            .query_row("SELECT count(*) FROM app_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .storage()?;
        Ok(count.try_into().unwrap_or_default())
    }

    pub fn prune_app_events_before(
        &self,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
        local_account_id_hex: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<usize> {
        self.secure_prune_app_events_before(
            group_id_hex,
            cutoff_recorded_at,
            local_account_id_hex,
            mention_classifier,
        )
        .map(|outcome| outcome.pruned_messages)
    }

    pub fn secure_prune_app_events_before(
        &self,
        group_id_hex: &str,
        cutoff_recorded_at: u64,
        local_account_id_hex: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<crate::timeline::SecurePruneAppEventsResult> {
        self.secure_prune_app_events(
            group_id_hex,
            SecurePruneAppEventsMode::RecordedBefore(cutoff_recorded_at),
            local_account_id_hex,
            mention_classifier,
        )
    }

    /// Delete only app events whose durable source-epoch retention decision
    /// has expired at or before `now`. Logical deletion and its result commit
    /// with a durable checkpoint intent. Checkpoint contention is reported as
    /// `erasure_pending`, and a retry can complete erasure without losing
    /// counts or media hashes.
    pub fn secure_prune_expired_app_events(
        &self,
        group_id_hex: &str,
        now: u64,
        local_account_id_hex: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<crate::timeline::SecurePruneAppEventsResult> {
        self.secure_prune_app_events(
            group_id_hex,
            SecurePruneAppEventsMode::ExpiredAt(now),
            local_account_id_hex,
            mention_classifier,
        )
    }

    fn secure_prune_app_events(
        &self,
        group_id_hex: &str,
        mode: SecurePruneAppEventsMode,
        local_account_id_hex: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<crate::timeline::SecurePruneAppEventsResult> {
        // `secure_delete` must be ON *before* the prune transaction begins:
        // SQLite does not guarantee zero-on-free for pages freed in the same
        // transaction that toggles the pragma, so setting it inside the
        // transaction (the previous shape) silently weakened the prune on
        // connections opened with `secure_delete: false`.
        let outcome = retry_on_busy(|| {
            // Keep the connection mutex for the entire save/set/prune/restore
            // sequence. `secure_delete` is connection-global, so releasing it
            // between those steps lets concurrent prunes save each other's
            // temporary ON value and restore the wrong configuration.
            let mut conn = self.lock()?;
            let original = secure_delete_pragma(&conn)?;
            conn.execute_batch("PRAGMA secure_delete = ON;").storage()?;
            let prune_outcome = (|| {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .storage()?;
                let outcome = match mode {
                    SecurePruneAppEventsMode::RecordedBefore(cutoff) => {
                        crate::timeline::secure_prune_app_events_before_tx(
                            &tx,
                            group_id_hex,
                            cutoff,
                            local_account_id_hex,
                            mention_classifier,
                        )?
                    }
                    SecurePruneAppEventsMode::ExpiredAt(now) => {
                        crate::timeline::secure_prune_expired_app_events_tx(
                            &tx,
                            group_id_hex,
                            now,
                            local_account_id_hex,
                            mention_classifier,
                        )?
                    }
                };
                if outcome.pruned_messages > 0 || outcome.pruned_media_epoch_secrets > 0 {
                    merge_secure_prune_intent_tx(&tx, group_id_hex, &outcome)?;
                }
                tx.commit().storage()?;
                Ok(outcome)
            })();
            let restore = restore_secure_delete_pragma(&conn, original);
            combine_secure_delete_operation_and_restore(prune_outcome, restore)
        })?;
        let finish = finish_secure_delete_checkpoint_intent::<
            crate::timeline::SecurePruneAppEventsResult,
        >(self, SECURE_DELETE_RETENTION_OPERATION, group_id_hex)?;
        let mut outcome = finish.result.unwrap_or(outcome);
        outcome.erasure_pending = finish.erasure_pending;
        if outcome.pruned_media_epoch_secrets > 0 {
            tracing::debug!(
                target: "storage_sqlite::retention",
                method = mode.trace_method(),
                pruned_media_epoch_secrets = outcome.pruned_media_epoch_secrets,
                "retired encrypted-media epoch secrets after final retained references expired"
            );
        }
        Ok(outcome)
    }

    pub fn account_import_marker(&self, name: &str) -> StorageResult<bool> {
        let exists = self
            .lock()?
            .query_row(
                "SELECT 1 FROM account_import_markers WHERE name = ?1",
                params![name],
                |_| Ok(()),
            )
            .optional()
            .storage()?
            .is_some();
        Ok(exists)
    }

    pub fn mark_account_import_complete(&self, name: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO account_import_markers (name, completed_at_unix_seconds)
                 VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET
                    completed_at_unix_seconds = excluded.completed_at_unix_seconds",
                params![name, unix_now_seconds_i64()],
            )
            .storage()?;
        Ok(())
    }

    pub fn notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.lock()?
            .query_row(
                "SELECT account_label, account_id_hex, local_notifications_enabled,
                        native_push_enabled
                 FROM notification_settings
                 WHERE account_label = ?1",
                params![account_label],
                |row| {
                    Ok(AccountNotificationSettings {
                        account_label: row.get(0)?,
                        account_id_hex: row.get(1)?,
                        local_notifications_enabled: row.get::<_, i64>(2)? != 0,
                        native_push_enabled: row.get::<_, i64>(3)? != 0,
                    })
                },
            )
            .storage()
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.lock()?
            .execute(
                "UPDATE notification_settings
                 SET local_notifications_enabled = ?2, updated_at_ms = ?3
                 WHERE account_label = ?1",
                params![account_label, bool_i64(enabled), unix_now_ms()],
            )
            .storage()?;
        self.notification_settings(account_label, account_id_hex)
    }

    pub fn set_native_push_enabled(
        &self,
        account_label: &str,
        account_id_hex: &str,
        enabled: bool,
    ) -> StorageResult<AccountNotificationSettings> {
        self.ensure_notification_settings(account_label, account_id_hex)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let was_enabled = conn
                .query_row(
                    "SELECT native_push_enabled FROM notification_settings
                     WHERE account_label = ?1",
                    params![account_label],
                    |row| Ok(row.get::<_, i64>(0)? != 0),
                )
                .storage()?;
            let now_ms = unix_now_ms();
            conn.execute(
                "UPDATE notification_settings
                 SET native_push_enabled = ?2, updated_at_ms = ?3
                 WHERE account_label = ?1",
                params![account_label, bool_i64(enabled), now_ms],
            )
            .storage()?;
            if enabled && !was_enabled {
                let queued = conn
                    .execute(
                        "INSERT INTO pending_push_registration_shares (
                            group_id_hex, token_fingerprint,
                            registration_updated_at_ms, queued_at_ms,
                            last_attempted_at_ms
                         )
                         SELECT account_groups.group_id_hex,
                                push_registration.token_fingerprint,
                                push_registration.updated_at_ms, ?1, NULL
                         FROM account_groups
                         CROSS JOIN push_registration
                         WHERE account_groups.self_membership = 'member'
                         ON CONFLICT(group_id_hex) DO UPDATE SET
                            token_fingerprint = excluded.token_fingerprint,
                            registration_updated_at_ms = excluded.registration_updated_at_ms,
                            queued_at_ms = excluded.queued_at_ms,
                            last_attempted_at_ms = NULL",
                        params![now_ms],
                    )
                    .storage()?;
                if queued > 0 {
                    conn.execute("UPDATE push_registration SET last_shared_at_ms = NULL", [])
                        .storage()?;
                }
            } else if !enabled {
                let existing = conn
                    .query_row(
                        "SELECT account_label, account_id_hex, platform, token_fingerprint,
                                token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                                updated_at_ms, last_shared_at_ms
                         FROM push_registration
                         WHERE account_label = ?1",
                        params![account_label],
                        stored_push_registration_from_row,
                    )
                    .optional()
                    .storage()?;
                if let Some(existing) = existing {
                    queue_push_registration_removals_with_conn(
                        &conn,
                        &existing.registration,
                        now_ms,
                    )?;
                }
                conn.execute("DELETE FROM pending_push_registration_shares", [])
                    .storage()?;
                conn.execute(
                    "DELETE FROM push_registration WHERE account_label = ?1",
                    params![account_label],
                )
                .storage()?;
            }
            drop(conn);
            self.notification_settings(account_label, account_id_hex)
        })
    }

    pub fn chat_notification_settings(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<AccountChatNotificationSettings> {
        self.chat_notification_settings_at(group_id_hex, unix_now_ms())
    }

    pub fn chat_notification_settings_at(
        &self,
        group_id_hex: &str,
        now_ms: i64,
    ) -> StorageResult<AccountChatNotificationSettings> {
        let row = self
            .lock()?
            .query_row(
                "SELECT muted_until_ms, updated_at_ms
                 FROM chat_notification_settings
                 WHERE group_id_hex = ?1",
                params![group_id_hex],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .storage()?;
        // Missing rows are unmuted. `None` means "muted forever", so the
        // absent-row default must be a timestamp that is already expired.
        let row_exists = row.is_some();
        let (muted_until_ms, updated_at_ms) = row.unwrap_or((Some(0), 0));
        Ok(AccountChatNotificationSettings {
            group_id_hex: group_id_hex.to_owned(),
            muted: chat_mute_is_effective(row_exists, muted_until_ms, now_ms),
            muted_until_ms,
            updated_at_ms,
        })
    }

    pub fn set_chat_muted(
        &self,
        group_id_hex: &str,
        muted_until_ms: Option<i64>,
    ) -> StorageResult<AccountChatNotificationSettings> {
        self.lock()?
            .execute(
                "INSERT INTO chat_notification_settings (
                    group_id_hex, muted_until_ms, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(group_id_hex) DO UPDATE SET
                    muted_until_ms = excluded.muted_until_ms,
                    updated_at_ms = excluded.updated_at_ms",
                params![group_id_hex, muted_until_ms, unix_now_ms()],
            )
            .storage()?;
        self.chat_notification_settings(group_id_hex)
    }

    pub fn clear_chat_muted(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<AccountChatNotificationSettings> {
        self.lock()?
            .execute(
                "DELETE FROM chat_notification_settings WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?;
        self.chat_notification_settings(group_id_hex)
    }

    pub fn push_registration(
        &self,
        account_label: &str,
    ) -> StorageResult<Option<AccountStoredPushRegistration>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT account_label, account_id_hex, platform, token_fingerprint,
                        token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                        updated_at_ms, last_shared_at_ms
                 FROM push_registration
                 WHERE account_label = ?1",
            )
            .storage()?;
        statement
            .query_row(params![account_label], stored_push_registration_from_row)
            .optional()
            .storage()
    }

    pub fn upsert_push_registration(
        &self,
        mut registration: AccountPushRegistration,
        token_bytes: Vec<u8>,
    ) -> StorageResult<AccountStoredPushRegistration> {
        self.connection.with_transaction(|| {
            let existing = self.push_registration(&registration.account_label)?;
            let created_at_ms = existing
                .as_ref()
                .map(|existing| existing.registration.created_at_ms)
                .unwrap_or(registration.created_at_ms);
            if let Some(existing) = &existing
                && registration.updated_at_ms <= existing.registration.updated_at_ms
            {
                registration.updated_at_ms = existing
                    .registration
                    .updated_at_ms
                    .checked_add(1)
                    .ok_or_else(|| {
                        StorageError::Backend(
                            "push registration revision space was exhausted".to_owned(),
                        )
                    })?;
            }
            let conn = self.lock()?;
            if let Some(existing) = &existing
                && (existing.registration.platform != registration.platform
                    || existing.registration.server_pubkey_hex != registration.server_pubkey_hex)
            {
                queue_push_registration_removals_with_conn(
                    &conn,
                    &existing.registration,
                    registration.updated_at_ms,
                )?;
            }
            conn.execute("DELETE FROM pending_push_registration_shares", [])
                .storage()?;
            conn.execute(
                "INSERT INTO push_registration (
                        account_label, account_id_hex, platform, token_fingerprint,
                        token_bytes, server_pubkey_hex, relay_hint, created_at_ms,
                        updated_at_ms, last_shared_at_ms
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)
                     ON CONFLICT(account_label) DO UPDATE SET
                        account_id_hex = excluded.account_id_hex,
                        platform = excluded.platform,
                        token_fingerprint = excluded.token_fingerprint,
                        token_bytes = excluded.token_bytes,
                        server_pubkey_hex = excluded.server_pubkey_hex,
                        relay_hint = excluded.relay_hint,
                        updated_at_ms = excluded.updated_at_ms,
                        last_shared_at_ms = NULL",
                params![
                    &registration.account_label,
                    &registration.account_id_hex,
                    i64::from(registration.platform),
                    &registration.token_fingerprint,
                    token_bytes,
                    &registration.server_pubkey_hex,
                    &registration.relay_hint,
                    created_at_ms,
                    registration.updated_at_ms,
                ],
            )
            .storage()?;
            drop(conn);
            self.queue_push_registration_shares(
                &registration.token_fingerprint,
                registration.updated_at_ms,
                registration.updated_at_ms,
            )?;
            self.push_registration(&registration.account_label)?
                .ok_or_else(|| StorageError::Backend("push registration was not stored".to_owned()))
        })
    }

    /// Reconcile durable gossip intent to the currently joined group set and
    /// queue every joined group for the supplied registration version.
    pub fn queue_push_registration_shares(
        &self,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        queued_at_ms: i64,
    ) -> StorageResult<usize> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute(
                "DELETE FROM pending_push_registration_shares
                 WHERE group_id_hex NOT IN (
                    SELECT group_id_hex FROM account_groups WHERE self_membership = 'member'
                 )",
                [],
            )
            .storage()?;
            conn.execute(
                "INSERT INTO pending_push_registration_shares (
                    group_id_hex, token_fingerprint, registration_updated_at_ms,
                    queued_at_ms, last_attempted_at_ms
                 )
                 SELECT group_id_hex, ?1, ?2, ?3, NULL
                 FROM account_groups
                 WHERE self_membership = 'member'
                 ON CONFLICT(group_id_hex) DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    registration_updated_at_ms = excluded.registration_updated_at_ms,
                    queued_at_ms = excluded.queued_at_ms,
                    last_attempted_at_ms = NULL",
                params![token_fingerprint, registration_updated_at_ms, queued_at_ms],
            )
            .storage()?;
            let count = conn
                .query_row(
                    "SELECT COUNT(*) FROM pending_push_registration_shares
                     WHERE token_fingerprint = ?1
                       AND registration_updated_at_ms = ?2",
                    params![token_fingerprint, registration_updated_at_ms],
                    |row| row.get::<_, i64>(0),
                )
                .storage()?;
            let count = i64_to_usize(count)?;
            if count > 0 {
                conn.execute("UPDATE push_registration SET last_shared_at_ms = NULL", [])
                    .storage()?;
            }
            Ok(count)
        })
    }

    pub fn pending_push_registration_shares(
        &self,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
    ) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex
                 FROM pending_push_registration_shares
                 WHERE token_fingerprint = ?1
                   AND registration_updated_at_ms = ?2
                 ORDER BY group_id_hex",
            )
            .storage()?;
        statement
            .query_map(
                params![token_fingerprint, registration_updated_at_ms],
                |row| row.get(0),
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    pub fn mark_push_registration_share_attempted(
        &self,
        group_id_hex: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        attempted_at_ms: i64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "UPDATE pending_push_registration_shares
                 SET last_attempted_at_ms = ?4
                 WHERE group_id_hex = ?1 AND token_fingerprint = ?2
                   AND registration_updated_at_ms = ?3",
                params![
                    group_id_hex,
                    token_fingerprint,
                    registration_updated_at_ms,
                    attempted_at_ms
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn complete_push_registration_share(
        &self,
        group_id_hex: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
    ) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute(
                "DELETE FROM pending_push_registration_shares
                 WHERE group_id_hex = ?1 AND token_fingerprint = ?2
                   AND registration_updated_at_ms = ?3",
                params![group_id_hex, token_fingerprint, registration_updated_at_ms],
            )
            .storage()?
            > 0)
    }

    pub fn mark_push_registration_shared(
        &self,
        account_label: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        shared_at_ms: i64,
    ) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute(
                "UPDATE push_registration
                 SET last_shared_at_ms = ?4
                 WHERE account_label = ?1
                   AND token_fingerprint = ?2
                   AND updated_at_ms = ?3
                   AND NOT EXISTS (
                       SELECT 1 FROM pending_push_registration_shares
                   )",
                params![
                    account_label,
                    token_fingerprint,
                    registration_updated_at_ms,
                    shared_at_ms
                ],
            )
            .storage()?
            > 0)
    }

    pub fn clear_push_registration(
        &self,
        account_label: &str,
    ) -> StorageResult<Option<AccountStoredPushRegistration>> {
        self.connection.with_transaction(|| {
            let existing = self.push_registration(account_label)?;
            let conn = self.lock()?;
            if let Some(existing) = &existing {
                queue_push_registration_removals_with_conn(
                    &conn,
                    &existing.registration,
                    unix_now_ms(),
                )?;
            }
            conn.execute(
                "DELETE FROM push_registration WHERE account_label = ?1",
                params![account_label],
            )
            .storage()?;
            conn.execute("DELETE FROM pending_push_registration_shares", [])
                .storage()?;
            Ok(existing)
        })
    }

    pub fn queue_push_registration_removals(
        &self,
        registration: &AccountPushRegistration,
        queued_at_ms: i64,
    ) -> StorageResult<usize> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            queue_push_registration_removals_with_conn(&conn, registration, queued_at_ms)
        })
    }

    /// Queue one registration removal for one group without depending on the
    /// app-local group projection surviving until publish.
    pub fn queue_push_registration_removal_for_group(
        &self,
        group_id_hex: &str,
        registration: &AccountPushRegistration,
        queued_at_ms: i64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute(
                "DELETE FROM pending_push_registration_shares
                 WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?;
            insert_push_registration_removal_with_conn(
                &conn,
                group_id_hex,
                registration,
                queued_at_ms,
            )?;
            Ok(())
        })
    }

    /// Requeue the current registration for one still-joined group. This is the
    /// compensation path when a departure fails after its removal published.
    pub fn queue_push_registration_share_for_group(
        &self,
        group_id_hex: &str,
        token_fingerprint: &str,
        registration_updated_at_ms: i64,
        queued_at_ms: i64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let inserted = conn
                .execute(
                    "INSERT INTO pending_push_registration_shares (
                    group_id_hex, token_fingerprint, registration_updated_at_ms,
                    queued_at_ms, last_attempted_at_ms
                 )
                 SELECT group_id_hex, ?2, ?3, ?4, NULL
                 FROM account_groups
                 WHERE group_id_hex = ?1 AND self_membership = 'member'
                 ON CONFLICT(group_id_hex) DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    registration_updated_at_ms = excluded.registration_updated_at_ms,
                    queued_at_ms = excluded.queued_at_ms,
                    last_attempted_at_ms = NULL",
                    params![
                        group_id_hex,
                        token_fingerprint,
                        registration_updated_at_ms,
                        queued_at_ms,
                    ],
                )
                .storage()?
                > 0;
            if inserted {
                conn.execute(
                    "UPDATE push_registration
                     SET last_shared_at_ms = NULL
                     WHERE token_fingerprint = ?1 AND updated_at_ms = ?2",
                    params![token_fingerprint, registration_updated_at_ms],
                )
                .storage()?;
            }
            Ok(inserted)
        })
    }

    pub fn has_pending_push_registration_work(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pending_push_registration_shares
                    UNION ALL
                    SELECT 1 FROM pending_push_registration_removals
                 )",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    pub fn pending_push_registration_removals(
        &self,
    ) -> StorageResult<Vec<AccountPendingPushRegistrationRemoval>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex, account_label, account_id_hex, platform,
                        token_fingerprint, server_pubkey_hex, relay_hint,
                        registration_created_at_ms, registration_updated_at_ms,
                        last_attempted_at_ms
                 FROM pending_push_registration_removals
                 ORDER BY queued_at_ms, group_id_hex, platform, server_pubkey_hex,
                          token_fingerprint, registration_updated_at_ms",
            )
            .storage()?;
        statement
            .query_map([], |row| {
                Ok(AccountPendingPushRegistrationRemoval {
                    group_id_hex: row.get(0)?,
                    registration: AccountPushRegistration {
                        account_label: row.get(1)?,
                        account_id_hex: row.get(2)?,
                        platform: row.get(3)?,
                        token_fingerprint: row.get(4)?,
                        server_pubkey_hex: row.get(5)?,
                        relay_hint: row.get(6)?,
                        created_at_ms: row.get(7)?,
                        updated_at_ms: row.get(8)?,
                        last_shared_at_ms: None,
                    },
                    last_attempted_at_ms: row.get(9)?,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    pub fn mark_push_registration_removal_attempted(
        &self,
        removal: &AccountPendingPushRegistrationRemoval,
        attempted_at_ms: i64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "UPDATE pending_push_registration_removals
                 SET last_attempted_at_ms = ?6
                 WHERE group_id_hex = ?1 AND platform = ?2
                   AND server_pubkey_hex = ?3 AND token_fingerprint = ?4
                   AND registration_updated_at_ms = ?5",
                params![
                    &removal.group_id_hex,
                    i64::from(removal.registration.platform),
                    &removal.registration.server_pubkey_hex,
                    &removal.registration.token_fingerprint,
                    removal.registration.updated_at_ms,
                    attempted_at_ms,
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn complete_push_registration_removal(
        &self,
        removal: &AccountPendingPushRegistrationRemoval,
    ) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute(
                "DELETE FROM pending_push_registration_removals
                 WHERE group_id_hex = ?1 AND platform = ?2
                   AND server_pubkey_hex = ?3 AND token_fingerprint = ?4
                   AND registration_updated_at_ms = ?5",
                params![
                    &removal.group_id_hex,
                    i64::from(removal.registration.platform),
                    &removal.registration.server_pubkey_hex,
                    &removal.registration.token_fingerprint,
                    removal.registration.updated_at_ms,
                ],
            )
            .storage()?
            > 0)
    }

    /// Unconditional upsert keyed on `(group, member, leaf, platform, server)`.
    /// Used for the local account's own self-update (always its newest token) and
    /// legacy import. Inbound gossip from other members goes through
    /// [`Self::apply_group_push_token`], which enforces the ordering primitive and
    /// tombstones.
    pub fn upsert_group_push_token(&self, token: &AccountGroupPushToken) -> StorageResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,
                    server_pubkey_hex, relay_hint, encrypted_token, owner_ts, owner_sig,
                    record_digest, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    relay_hint = excluded.relay_hint,
                    encrypted_token = excluded.encrypted_token,
                    owner_ts = excluded.owner_ts,
                    owner_sig = excluded.owner_sig,
                    record_digest = excluded.record_digest,
                    updated_at_ms = excluded.updated_at_ms",
            params![
                &token.group_id_hex,
                &token.member_id_hex,
                u32_to_i64(token.leaf_index),
                i64::from(token.platform),
                &token.token_fingerprint,
                &token.server_pubkey_hex,
                &token.relay_hint,
                &token.encrypted_token,
                token.owner_ts,
                &token.owner_sig,
                &token.record_digest,
                token.updated_at_ms,
            ],
        )
        .storage()?;
        Ok(())
    }

    /// Apply an owner-verified inbound token record under the spec's ordering
    /// primitive: store it only when its `(owner_ts, record_digest)` stamp is
    /// strictly greater than both the existing live record and any tombstone for
    /// the same record key, and clear the tombstone when it does. Returns whether
    /// the record was applied. Callers verify `owner_sig` and group membership
    /// before calling.
    pub fn apply_group_push_token(&self, token: &AccountGroupPushToken) -> StorageResult<bool> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn.transaction().storage()?;
            let incoming = (token.owner_ts, token.record_digest.as_str());
            let key = PushTokenKey {
                group_id_hex: &token.group_id_hex,
                member_id_hex: &token.member_id_hex,
                leaf_index: token.leaf_index,
                platform: token.platform,
                server_pubkey_hex: &token.server_pubkey_hex,
            };
            let tombstone = read_push_tombstone_stamp(&tx, key)?;
            let live = read_push_token_stamp(&tx, key)?;
            let strictly_newer = |stored: &Option<(i64, String)>| {
                push_stamp_strictly_newer(incoming, stored.as_ref().map(|(t, d)| (*t, d.as_str())))
            };
            if !strictly_newer(&tombstone) || !strictly_newer(&live) {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO group_push_tokens (
                    group_id_hex, member_id_hex, leaf_index, platform, token_fingerprint,
                    server_pubkey_hex, relay_hint, encrypted_token, owner_ts, owner_sig,
                    record_digest, updated_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    token_fingerprint = excluded.token_fingerprint,
                    relay_hint = excluded.relay_hint,
                    encrypted_token = excluded.encrypted_token,
                    owner_ts = excluded.owner_ts,
                    owner_sig = excluded.owner_sig,
                    record_digest = excluded.record_digest,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    &token.group_id_hex,
                    &token.member_id_hex,
                    u32_to_i64(token.leaf_index),
                    i64::from(token.platform),
                    &token.token_fingerprint,
                    &token.server_pubkey_hex,
                    &token.relay_hint,
                    &token.encrypted_token,
                    token.owner_ts,
                    &token.owner_sig,
                    &token.record_digest,
                    token.updated_at_ms,
                ],
            )
            .storage()?;
            delete_push_tombstone(&tx, key)?;
            tx.commit().storage()?;
            Ok(true)
        })
    }

    /// Apply an owner-verified removal: when its `(owner_ts, record_digest)` stamp
    /// is strictly greater than both the live record and any existing tombstone
    /// for the key, delete the live record and write/refresh the durable
    /// tombstone. Returns whether the removal was applied.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_group_push_token_tombstone(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
        leaf_index: u32,
        platform: u8,
        server_pubkey_hex: &str,
        owner_ts: i64,
        record_digest: &str,
        created_at_ms: i64,
    ) -> StorageResult<bool> {
        retry_on_busy(|| {
            let mut conn = self.lock()?;
            let tx = conn.transaction().storage()?;
            let incoming = (owner_ts, record_digest);
            let key = PushTokenKey {
                group_id_hex,
                member_id_hex,
                leaf_index,
                platform,
                server_pubkey_hex,
            };
            let tombstone = read_push_tombstone_stamp(&tx, key)?;
            let live = read_push_token_stamp(&tx, key)?;
            let strictly_newer = |stored: &Option<(i64, String)>| {
                push_stamp_strictly_newer(incoming, stored.as_ref().map(|(t, d)| (*t, d.as_str())))
            };
            if !strictly_newer(&tombstone) || !strictly_newer(&live) {
                return Ok(false);
            }
            delete_push_token(&tx, key)?;
            tx.execute(
                "INSERT INTO group_push_token_tombstones (
                    group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex,
                    owner_ts, record_digest, created_at_ms
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
                 DO UPDATE SET
                    owner_ts = excluded.owner_ts,
                    record_digest = excluded.record_digest,
                    created_at_ms = excluded.created_at_ms",
                params![
                    group_id_hex,
                    member_id_hex,
                    u32_to_i64(leaf_index),
                    i64::from(platform),
                    server_pubkey_hex,
                    owner_ts,
                    record_digest,
                    created_at_ms,
                ],
            )
            .storage()?;
            tx.commit().storage()?;
            Ok(true)
        })
    }

    pub fn group_push_tokens(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<Vec<AccountGroupPushToken>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare(
                "SELECT group_id_hex, member_id_hex, leaf_index, platform,
                        token_fingerprint, server_pubkey_hex, relay_hint,
                        encrypted_token, owner_ts, owner_sig, record_digest, updated_at_ms
                 FROM group_push_tokens
                 WHERE group_id_hex = ?1
                 ORDER BY member_id_hex, leaf_index, platform, server_pubkey_hex",
            )
            .storage()?;
        statement
            .query_map(params![group_id_hex], group_push_token_from_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    pub fn remove_group_push_token(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
        platform: u8,
        token_fingerprint: &str,
        server_pubkey_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?1
                   AND member_id_hex = ?2
                   AND platform = ?3
                   AND token_fingerprint = ?4
                   AND server_pubkey_hex = ?5",
                params![
                    group_id_hex,
                    member_id_hex,
                    i64::from(platform),
                    token_fingerprint,
                    server_pubkey_hex,
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Local cleanup when a member leaves the group: drop every live record and
    /// every tombstone for that member, per the spec's member-cleanup rule. The
    /// member is gone, so no relayed record for them can ever verify against
    /// current membership again, which is why the durable tombstones are safe to
    /// clear here (and only here).
    pub fn remove_group_push_tokens_for_member(
        &self,
        group_id_hex: &str,
        member_id_hex: &str,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| -> StorageResult<()> {
            let conn = self.lock()?;
            conn.execute(
                "DELETE FROM group_push_tokens
                 WHERE group_id_hex = ?1 AND member_id_hex = ?2",
                params![group_id_hex, member_id_hex],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM group_push_token_tombstones
                 WHERE group_id_hex = ?1 AND member_id_hex = ?2",
                params![group_id_hex, member_id_hex],
            )
            .storage()?;
            Ok(())
        })
    }

    pub fn remove_stale_group_push_tokens(
        &self,
        group_id_hex: &str,
        active_members: &[String],
    ) -> StorageResult<usize> {
        self.connection
            .with_transaction(|| -> StorageResult<usize> {
                let conn = self.lock()?;
                let active_members = active_members
                    .iter()
                    .map(String::as_str)
                    .collect::<std::collections::HashSet<_>>();
                let scope = [Value::Text(group_id_hex.to_owned())];
                // Clear tombstones for departed members too: once a member is gone, no
                // relayed record for them can verify against current membership, so their
                // tombstones are no longer load-bearing.
                delete_stale_text_keys(
                    &conn,
                    "SELECT DISTINCT member_id_hex
                     FROM group_push_token_tombstones
                     WHERE group_id_hex = ?",
                    &scope,
                    "DELETE FROM group_push_token_tombstones
                     WHERE group_id_hex = ? AND member_id_hex IN",
                    &scope,
                    &active_members,
                )?;
                delete_stale_text_keys(
                    &conn,
                    "SELECT DISTINCT member_id_hex
                     FROM group_push_tokens
                     WHERE group_id_hex = ?",
                    &scope,
                    "DELETE FROM group_push_tokens
                     WHERE group_id_hex = ? AND member_id_hex IN",
                    &scope,
                    &active_members,
                )
            })
    }

    fn ensure_notification_settings(
        &self,
        account_label: &str,
        account_id_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO notification_settings (
                    account_label, account_id_hex, local_notifications_enabled,
                    native_push_enabled, updated_at_ms
                 )
                 VALUES (?1, ?2, 1, 0, ?3)
                 ON CONFLICT(account_label) DO UPDATE SET
                    account_id_hex = excluded.account_id_hex",
                params![account_label, account_id_hex, unix_now_ms()],
            )
            .storage()?;
        Ok(())
    }
}

fn queue_push_registration_removals_with_conn(
    conn: &Connection,
    registration: &AccountPushRegistration,
    queued_at_ms: i64,
) -> StorageResult<usize> {
    conn.execute(
        "INSERT INTO pending_push_registration_removals (
            group_id_hex, account_label, account_id_hex, platform,
            token_fingerprint, server_pubkey_hex, relay_hint,
            registration_created_at_ms, registration_updated_at_ms,
            queued_at_ms, last_attempted_at_ms
         )
         SELECT group_id_hex, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL
         FROM account_groups
         WHERE self_membership = 'member'
         ON CONFLICT(
            group_id_hex, platform, server_pubkey_hex,
            token_fingerprint, registration_updated_at_ms
         ) DO UPDATE SET
            account_label = excluded.account_label,
            account_id_hex = excluded.account_id_hex,
            relay_hint = excluded.relay_hint,
            registration_created_at_ms = excluded.registration_created_at_ms,
            queued_at_ms = excluded.queued_at_ms,
            last_attempted_at_ms = NULL",
        params![
            &registration.account_label,
            &registration.account_id_hex,
            i64::from(registration.platform),
            &registration.token_fingerprint,
            &registration.server_pubkey_hex,
            &registration.relay_hint,
            registration.created_at_ms,
            registration.updated_at_ms,
            queued_at_ms,
        ],
    )
    .storage()?;
    let count = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_push_registration_removals
             WHERE platform = ?1 AND server_pubkey_hex = ?2
               AND token_fingerprint = ?3 AND registration_updated_at_ms = ?4",
            params![
                i64::from(registration.platform),
                &registration.server_pubkey_hex,
                &registration.token_fingerprint,
                registration.updated_at_ms,
            ],
            |row| row.get::<_, i64>(0),
        )
        .storage()?;
    i64_to_usize(count)
}

fn insert_push_registration_removal_with_conn(
    conn: &Connection,
    group_id_hex: &str,
    registration: &AccountPushRegistration,
    queued_at_ms: i64,
) -> StorageResult<()> {
    conn.execute(
        "INSERT INTO pending_push_registration_removals (
            group_id_hex, account_label, account_id_hex, platform,
            token_fingerprint, server_pubkey_hex, relay_hint,
            registration_created_at_ms, registration_updated_at_ms,
            queued_at_ms, last_attempted_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)
         ON CONFLICT(
            group_id_hex, platform, server_pubkey_hex,
            token_fingerprint, registration_updated_at_ms
         ) DO UPDATE SET
            account_label = excluded.account_label,
            account_id_hex = excluded.account_id_hex,
            relay_hint = excluded.relay_hint,
            registration_created_at_ms = excluded.registration_created_at_ms,
            queued_at_ms = excluded.queued_at_ms,
            last_attempted_at_ms = NULL",
        params![
            group_id_hex,
            &registration.account_label,
            &registration.account_id_hex,
            i64::from(registration.platform),
            &registration.token_fingerprint,
            &registration.server_pubkey_hex,
            &registration.relay_hint,
            registration.created_at_ms,
            registration.updated_at_ms,
            queued_at_ms,
        ],
    )
    .storage()?;
    Ok(())
}

/// Clamp a cursor timestamp to `now + max_future_skew_secs`.
///
/// This is the single definition of the future-skew clamp for the persisted
/// `last_transport_timestamp` column: the app layer applies it at ingest time
/// (marmot-app's `clamped_transport_cursor`) and
/// [`merged_transport_timestamp`] applies it to both sides of the save-time
/// merge. The bound is caller policy; this crate only enforces the arithmetic.
pub fn clamp_to_max_future_skew(timestamp: u64, now: u64, max_future_skew_secs: u64) -> u64 {
    timestamp.min(now.saturating_add(max_future_skew_secs))
}

/// Merge the stored and snapshot `last_transport_timestamp` into the value a
/// save may persist. Every arm is deliberate:
///
/// - `(None, None)` — nothing to persist; stays `None`.
/// - `(None, Some(snapshot))` — a fresh store adopts the snapshot cursor,
///   clamped to `now + max_future_skew_secs`. The clamp is load-bearing here:
///   the legacy-import migration (marmot-app's
///   `migrate_legacy_account_projection_if_needed`) writes a legacy-loaded
///   state into a brand-new store through this arm, and a pre-clamp-era legacy
///   projection can carry a cursor poisoned above the ceiling (mdk#182).
///   Adopting it raw would persist that poison.
/// - `(Some(stored), None)` — a save that never learned a cursor is
///   cursor-neutral: the stored value passes through unchanged, never clamped
///   or otherwise moved. Healing a poisoned stored value is the job of a save
///   that *did* learn a cursor (the arm below); a cursor-less save must not
///   move durable state at all.
/// - `(Some(stored), Some(snapshot))` — both sides are clamped to
///   `now + max_future_skew_secs` via [`clamp_to_max_future_skew`], then the
///   max wins. Clamping the *stored* side at save-time `now` is what heals a
///   cursor poisoned above the ceiling instead of letting it win the max
///   forever.
fn merged_transport_timestamp(
    stored: Option<u64>,
    snapshot: Option<u64>,
    now: u64,
    max_future_skew_secs: u64,
) -> Option<u64> {
    match (stored, snapshot) {
        (None, None) => None,
        (None, Some(snapshot)) => Some(clamp_to_max_future_skew(
            snapshot,
            now,
            max_future_skew_secs,
        )),
        (Some(stored), None) => Some(stored),
        (Some(stored), Some(snapshot)) => Some(
            clamp_to_max_future_skew(stored, now, max_future_skew_secs).max(
                clamp_to_max_future_skew(snapshot, now, max_future_skew_secs),
            ),
        ),
    }
}

fn secure_delete_pragma(conn: &Connection) -> StorageResult<i64> {
    conn.query_row("PRAGMA secure_delete", [], |row| row.get(0))
        .storage()
}

fn restore_secure_delete_pragma(conn: &Connection, original: i64) -> StorageResult<()> {
    conn.execute_batch(&format!("PRAGMA secure_delete = {original};"))
        .storage()
}

fn combine_secure_delete_operation_and_restore<T>(
    operation: StorageResult<T>,
    restore: StorageResult<()>,
) -> StorageResult<T> {
    match operation {
        Ok(value) => {
            if restore.is_err() {
                // The transaction has already committed. Leaving secure_delete
                // enabled on this connection is fail-safe; surfacing an error
                // here would falsely tell callers that the deletion did not
                // happen and could make them restore stale projection state.
                tracing::warn!(
                    target: "storage_sqlite::account_projection",
                    method = "combine_secure_delete_operation_and_restore",
                    "secure-delete pragma restoration failed after committed operation"
                );
            }
            Ok(value)
        }
        Err(error) => {
            let _ = restore;
            Err(error)
        }
    }
}

fn secure_delete_intent(
    conn: &Connection,
    operation_kind: &str,
    scope: &str,
) -> StorageResult<Option<SecureDeleteIntent>> {
    conn.query_row(
        "SELECT intent_nonce, result_json
         FROM secure_delete_checkpoint_intents
         WHERE operation_kind = ?1 AND scope = ?2",
        params![operation_kind, scope],
        |row| {
            Ok(SecureDeleteIntent {
                nonce: row.get(0)?,
                result_json: row.get(1)?,
            })
        },
    )
    .optional()
    .storage()
}

fn upsert_secure_delete_intent_tx(
    tx: &Connection,
    operation_kind: &str,
    scope: &str,
    result_json: &str,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO secure_delete_checkpoint_intents (
            operation_kind, scope, intent_nonce, result_json
         ) VALUES (?1, ?2, randomblob(16), ?3)
         ON CONFLICT(operation_kind, scope) DO UPDATE SET
            intent_nonce = randomblob(16),
            result_json = excluded.result_json",
        params![operation_kind, scope, result_json],
    )
    .storage()?;
    Ok(())
}

fn merge_secure_prune_intent_tx(
    tx: &Connection,
    group_id_hex: &str,
    new_result: &crate::timeline::SecurePruneAppEventsResult,
) -> StorageResult<()> {
    let mut merged = secure_delete_intent(tx, SECURE_DELETE_RETENTION_OPERATION, group_id_hex)?
        .map(|intent| {
            serde_json::from_str::<crate::timeline::SecurePruneAppEventsResult>(&intent.result_json)
                .map_err(|error| StorageError::Serialization(error.to_string()))
        })
        .transpose()?
        .unwrap_or_default();
    merged.pruned_messages = merged
        .pruned_messages
        .saturating_add(new_result.pruned_messages);
    merged.pruned_media_epoch_secrets = merged
        .pruned_media_epoch_secrets
        .saturating_add(new_result.pruned_media_epoch_secrets);
    let mut hashes = merged
        .media_ciphertext_sha256
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    hashes.extend(new_result.media_ciphertext_sha256.iter().cloned());
    merged.media_ciphertext_sha256 = hashes.into_iter().collect();
    merged.erasure_pending = false;
    let result_json = serde_json::to_string(&merged)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    upsert_secure_delete_intent_tx(
        tx,
        SECURE_DELETE_RETENTION_OPERATION,
        group_id_hex,
        &result_json,
    )
}

fn merge_local_group_delete_intent_tx(
    tx: &Connection,
    group_id_hex: &str,
    deleted_rows: usize,
) -> StorageResult<()> {
    let mut merged = secure_delete_intent(tx, SECURE_DELETE_LOCAL_GROUP_OPERATION, group_id_hex)?
        .map(|intent| {
            serde_json::from_str::<DeleteLocalGroupDataResult>(&intent.result_json)
                .map_err(|error| StorageError::Serialization(error.to_string()))
        })
        .transpose()?
        .unwrap_or_default();
    merged.deleted_rows = merged.deleted_rows.saturating_add(deleted_rows);
    merged.completed_pending_checkpoint = false;
    merged.erasure_pending = false;
    let result_json = serde_json::to_string(&merged)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    upsert_secure_delete_intent_tx(
        tx,
        SECURE_DELETE_LOCAL_GROUP_OPERATION,
        group_id_hex,
        &result_json,
    )
}

fn finish_secure_delete_checkpoint_intent<T>(
    storage: &SqliteAccountStorage,
    operation_kind: &str,
    scope: &str,
) -> StorageResult<SecureDeleteCheckpointFinish<T>>
where
    T: serde::de::DeserializeOwned,
{
    let mut last_result = None;
    for _ in 0..8 {
        let conn = storage.lock()?;
        let Some(intent) = secure_delete_intent(&conn, operation_kind, scope)? else {
            return Ok(SecureDeleteCheckpointFinish {
                result: None,
                erasure_pending: false,
            });
        };
        let result = serde_json::from_str(&intent.result_json)
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        match checkpoint_wal_truncate_after_secure_delete(&conn) {
            Ok(()) => {}
            Err(StorageError::Busy(_)) => {
                return Ok(SecureDeleteCheckpointFinish {
                    result: Some(result),
                    erasure_pending: true,
                });
            }
            Err(error) => return Err(error),
        }
        let deleted = conn
            .execute(
                "DELETE FROM secure_delete_checkpoint_intents
                 WHERE operation_kind = ?1 AND scope = ?2
                   AND intent_nonce = ?3",
                params![operation_kind, scope, &intent.nonce],
            )
            .storage()?;
        if deleted == 0 {
            last_result = Some(result);
            continue;
        }
        return Ok(SecureDeleteCheckpointFinish {
            result: Some(result),
            erasure_pending: false,
        });
    }
    Ok(SecureDeleteCheckpointFinish {
        result: last_result,
        erasure_pending: true,
    })
}

fn checkpoint_wal_truncate_after_secure_delete(conn: &Connection) -> StorageResult<()> {
    retry_on_busy(|| {
        let (busy, _log_frames, _checkpointed_frames): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .storage()?;
        if busy == 0 {
            Ok(())
        } else {
            Err(StorageError::Busy(
                "secure-delete WAL checkpoint could not truncate while readers are active"
                    .to_owned(),
            ))
        }
    })
}

/// #762: load ALL account-group components in one ordered query, bucketed by
/// group in Rust, instead of an N+1 per-group query during full-projection load.
/// Ordered by `(group_id_hex, component_id)` so each group's components keep
/// `component_id` order (matching the prior per-group `ORDER BY component_id`).
fn all_account_group_components(
    conn: &rusqlite::Connection,
) -> StorageResult<std::collections::HashMap<String, Vec<StoredAccountGroupComponent>>> {
    let mut statement = conn
        .prepare(
            "SELECT group_id_hex, component_id, component_name, component_data_hex
             FROM account_group_app_components
             ORDER BY group_id_hex, component_id",
        )
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                StoredAccountGroupComponent {
                    component_id: i64_to_u16(row.get(1)?, 1)?,
                    component_name: row.get(2)?,
                    component_data_hex: row.get(3)?,
                },
            ))
        })
        .storage()?;
    let mut by_group: std::collections::HashMap<String, Vec<StoredAccountGroupComponent>> =
        std::collections::HashMap::new();
    for row in rows {
        let (group_id_hex, component) = row.storage()?;
        by_group.entry(group_id_hex).or_default().push(component);
    }
    Ok(by_group)
}

/// Deletes text keys that exist in a scoped query but are absent from
/// `retained_keys`.
///
/// The retained set is never bound into SQL: `NOT IN` cannot be safely split
/// into chunks because each partial statement would delete keys retained by a
/// later chunk. Instead, this queries existing keys, computes the stale set in
/// Rust, and chunk-deletes that stale set with positive `IN` predicates.
fn delete_stale_text_keys(
    conn: &Connection,
    existing_keys_sql: &str,
    existing_keys_params: &[Value],
    delete_sql_prefix: &str,
    delete_prefix_params: &[Value],
    retained_keys: &std::collections::HashSet<&str>,
) -> StorageResult<usize> {
    let mut statement = conn.prepare(existing_keys_sql).storage()?;
    let existing_keys = statement
        .query_map(params_from_iter(existing_keys_params.iter()), |row| {
            row.get::<_, String>(0)
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    drop(statement);

    let stale_keys = existing_keys
        .into_iter()
        .filter(|key| !retained_keys.contains(key.as_str()))
        .collect::<Vec<_>>();
    let mut deleted = 0;
    let key_chunk_size = SQLITE_BIND_PARAMETER_CHUNK
        .checked_sub(delete_prefix_params.len())
        .filter(|size| *size > 0)
        .ok_or_else(|| {
            StorageError::Backend(
                "stale-key delete prefix exceeds SQLite bind-parameter budget".to_owned(),
            )
        })?;
    for chunk in stale_keys.chunks(key_chunk_size) {
        let placeholders = std::iter::repeat_n("?", chunk.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("{delete_sql_prefix} ({placeholders})");
        let mut values = Vec::with_capacity(delete_prefix_params.len() + chunk.len());
        values.extend_from_slice(delete_prefix_params);
        values.extend(chunk.iter().cloned().map(Value::Text));
        deleted += conn
            .execute(&sql, params_from_iter(values.iter()))
            .storage()?;
    }
    Ok(deleted)
}

fn delete_stale_group_components(
    tx: &Connection,
    group_id_hex: &str,
    components: &[StoredAccountGroupComponent],
) -> StorageResult<()> {
    if components.is_empty() {
        tx.execute(
            "DELETE FROM account_group_app_components WHERE group_id_hex = ?1",
            params![group_id_hex],
        )
        .storage()?;
        return Ok(());
    }
    let placeholders = std::iter::repeat_n("?", components.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "DELETE FROM account_group_app_components
         WHERE group_id_hex = ?
           AND component_id NOT IN ({placeholders})"
    );
    let mut values = Vec::with_capacity(components.len() + 1);
    values.push(Value::Text(group_id_hex.to_owned()));
    for component in components {
        values.push(Value::Integer(i64::from(component.component_id)));
    }
    tx.execute(&sql, params_from_iter(values.iter()))
        .storage()?;
    Ok(())
}

fn upsert_group_component(
    tx: &Connection,
    group_id_hex: &str,
    component: &StoredAccountGroupComponent,
    now: i64,
) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO account_group_app_components (
            group_id_hex, component_id, component_name, component_data_hex, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(group_id_hex, component_id) DO UPDATE SET
            component_name = excluded.component_name,
            component_data_hex = excluded.component_data_hex,
            updated_at = excluded.updated_at
         WHERE account_group_app_components.component_name IS NOT excluded.component_name
            OR account_group_app_components.component_data_hex IS NOT excluded.component_data_hex",
        params![
            group_id_hex,
            i64::from(component.component_id),
            &component.component_name,
            &component.component_data_hex,
            now
        ],
    )
    .storage()?;
    Ok(())
}

fn app_message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAppMessageRecord> {
    let retention_seconds = row
        .get::<_, Option<i64>>(8)?
        .and_then(|seconds| seconds.try_into().ok());
    let retention_expires_at = row
        .get::<_, Option<i64>>(9)?
        .and_then(|expires_at| expires_at.try_into().ok());
    Ok(StoredAppMessageRecord {
        message_id_hex: row.get(0)?,
        direction: row.get(1)?,
        group_id_hex: row.get(2)?,
        sender: row.get(3)?,
        plaintext: row.get(4)?,
        kind: row.get::<_, i64>(5)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(6)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(6, Type::Text, Box::new(err))
        })?,
        source_epoch: row
            .get::<_, Option<i64>>(7)?
            .and_then(|value| value.try_into().ok()),
        retention: retention_seconds.map(|retention_seconds| {
            cgka_traits::app_event::AppMessageRetentionDecision {
                retention_seconds,
                expires_at: retention_expires_at,
            }
        }),
        recorded_at: row.get::<_, i64>(10)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(11)?.try_into().unwrap_or_default(),
        insert_order: row.get::<_, i64>(12)?,
        moderation_grant: row.get::<_, i64>(13)? != 0,
        invalidated: row.get::<_, i64>(14)? != 0,
    })
}

fn stored_push_registration_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AccountStoredPushRegistration> {
    Ok(AccountStoredPushRegistration {
        registration: AccountPushRegistration {
            account_label: row.get(0)?,
            account_id_hex: row.get(1)?,
            platform: i64_to_u8(row.get(2)?, 2)?,
            token_fingerprint: row.get(3)?,
            server_pubkey_hex: row.get(5)?,
            relay_hint: row.get(6)?,
            created_at_ms: row.get(7)?,
            updated_at_ms: row.get(8)?,
            last_shared_at_ms: row.get(9)?,
        },
        token_bytes: row.get(4)?,
    })
}

fn group_push_token_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountGroupPushToken> {
    Ok(AccountGroupPushToken {
        group_id_hex: row.get(0)?,
        member_id_hex: row.get(1)?,
        leaf_index: i64_to_u32(row.get(2)?, 2)?,
        platform: i64_to_u8(row.get(3)?, 3)?,
        token_fingerprint: row.get(4)?,
        server_pubkey_hex: row.get(5)?,
        relay_hint: row.get(6)?,
        encrypted_token: row.get(7)?,
        owner_ts: row.get(8)?,
        owner_sig: row.get(9)?,
        record_digest: row.get(10)?,
        updated_at_ms: row.get(11)?,
    })
}

/// Identifies one push record key `(group, member, leaf, platform, server)`,
/// shared by the live `group_push_tokens` table and the tombstone table.
#[derive(Clone, Copy)]
struct PushTokenKey<'a> {
    group_id_hex: &'a str,
    member_id_hex: &'a str,
    leaf_index: u32,
    platform: u8,
    server_pubkey_hex: &'a str,
}

/// True when `incoming` is strictly greater than `stored` under the
/// `(owner_ts, record_digest)` ordering primitive (and always when there is no
/// stored stamp).
fn push_stamp_strictly_newer(incoming: (i64, &str), stored: Option<(i64, &str)>) -> bool {
    match stored {
        None => true,
        Some((ts, digest)) => incoming.0 > ts || (incoming.0 == ts && incoming.1 > digest),
    }
}

fn read_push_token_stamp(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<Option<(i64, String)>> {
    tx.query_row(
        "SELECT owner_ts, record_digest FROM group_push_tokens
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .storage()
}

fn read_push_tombstone_stamp(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<Option<(i64, String)>> {
    tx.query_row(
        "SELECT owner_ts, record_digest FROM group_push_token_tombstones
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .storage()
}

fn delete_push_token(tx: &rusqlite::Transaction<'_>, key: PushTokenKey<'_>) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM group_push_tokens
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
    )
    .storage()?;
    Ok(())
}

fn delete_push_tombstone(
    tx: &rusqlite::Transaction<'_>,
    key: PushTokenKey<'_>,
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM group_push_token_tombstones
         WHERE group_id_hex = ?1 AND member_id_hex = ?2 AND leaf_index = ?3
           AND platform = ?4 AND server_pubkey_hex = ?5",
        params![
            key.group_id_hex,
            key.member_id_hex,
            u32_to_i64(key.leaf_index),
            i64::from(key.platform),
            key.server_pubkey_hex,
        ],
    )
    .storage()?;
    Ok(())
}

fn u32_to_i64(value: u32) -> i64 {
    i64::from(value)
}

fn i64_to_u8(value: i64, column: usize) -> rusqlite::Result<u8> {
    u8::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn i64_to_u16(value: i64, column: usize) -> rusqlite::Result<u16> {
    u16::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

fn i64_to_u32(value: i64, column: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(column, Type::Integer, Box::new(err))
    })
}

#[cfg(test)]
mod tests;
