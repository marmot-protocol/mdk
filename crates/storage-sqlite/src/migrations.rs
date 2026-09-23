#[path = "migrations/0001_initial_schema.rs"]
mod migration_0001_initial_schema;
#[path = "migrations/0002_account_device_signers.rs"]
mod migration_0002_account_device_signers;
#[path = "migrations/0003_group_foreign_keys.rs"]
mod migration_0003_group_foreign_keys;
#[path = "migrations/0004_app_timeline.rs"]
mod migration_0004_app_timeline;
#[path = "migrations/0005_account_projection.rs"]
mod migration_0005_account_projection;
#[path = "migrations/0006_chat_list_projection.rs"]
mod migration_0006_chat_list_projection;
#[path = "migrations/0007_timeline_projection_indexes.rs"]
mod migration_0007_timeline_projection_indexes;
#[path = "migrations/0008_timeline_invalidation_status.rs"]
mod migration_0008_timeline_invalidation_status;
#[path = "migrations/0009_app_event_source_epoch.rs"]
mod migration_0009_app_event_source_epoch;
#[path = "migrations/0010_encrypted_media_epoch_secrets.rs"]
mod migration_0010_encrypted_media_epoch_secrets;
#[path = "migrations/0011_chat_list_avatar_url.rs"]
mod migration_0011_chat_list_avatar_url;
#[path = "migrations/0012_app_event_origin_commit.rs"]
mod migration_0012_app_event_origin_commit;
#[path = "migrations/0013_app_event_kind_order_index.rs"]
mod migration_0013_app_event_kind_order_index;
#[path = "migrations/0014_message_timeline_reply_lookup_index.rs"]
mod migration_0014_message_timeline_reply_lookup_index;
#[path = "migrations/0015_member_validation_cache.rs"]
mod migration_0015_member_validation_cache;
#[path = "migrations/0016_leave_requests.rs"]
mod migration_0016_leave_requests;
#[path = "migrations/0017_notification_settings_default_on.rs"]
mod migration_0017_notification_settings_default_on;
#[path = "migrations/0018_account_group_self_membership.rs"]
mod migration_0018_account_group_self_membership;
#[path = "migrations/0019_chat_list_unread_mention_count.rs"]
mod migration_0019_chat_list_unread_mention_count;
#[path = "migrations/0020_message_modifier_edges.rs"]
mod migration_0020_message_modifier_edges;
#[path = "migrations/0021_push_token_owner_signatures.rs"]
mod migration_0021_push_token_owner_signatures;
#[path = "migrations/0022_chat_list_self_membership.rs"]
mod migration_0022_chat_list_self_membership;
#[path = "migrations/0023_chat_list_projection_version.rs"]
mod migration_0023_chat_list_projection_version;
#[path = "migrations/0024_pending_welcome_delivery.rs"]
mod migration_0024_pending_welcome_delivery;
#[path = "migrations/0025_chat_notification_settings.rs"]
mod migration_0025_chat_notification_settings;
#[path = "migrations/0026_message_drafts.rs"]
mod migration_0026_message_drafts;
#[path = "migrations/0027_app_event_moderation_grant.rs"]
mod migration_0027_app_event_moderation_grant;
#[path = "migrations/0028_ingress_dedup.rs"]
mod migration_0028_ingress_dedup;
#[path = "migrations/0029_app_event_retention_decision.rs"]
mod migration_0029_app_event_retention_decision;
#[path = "migrations/0030_prior_nostr_routes.rs"]
mod migration_0030_prior_nostr_routes;
#[path = "migrations/0031_outbound_fanout.rs"]
mod migration_0031_outbound_fanout;
#[path = "migrations/0032_encrypted_media_secret_references.rs"]
mod migration_0032_encrypted_media_secret_references;
#[path = "migrations/0033_push_registration_gossip_outbox.rs"]
mod migration_0033_push_registration_gossip_outbox;
#[path = "migrations/0034_maintenance_publication.rs"]
mod migration_0034_maintenance_publication;
#[path = "migrations/0035_durable_convergence_passes.rs"]
mod migration_0035_durable_convergence_passes;
#[path = "migrations/0036_agent_stream_publisher_sequences.rs"]
mod migration_0036_agent_stream_publisher_sequences;
#[path = "migrations/0037_chat_list_semantic_timestamps.rs"]
mod migration_0037_chat_list_semantic_timestamps;
#[path = "migrations/0038_chat_list_interaction_state.rs"]
mod migration_0038_chat_list_interaction_state;
#[path = "migrations/0039_chat_pin_positions.rs"]
mod migration_0039_chat_pin_positions;
#[path = "migrations/0040_disband_requests.rs"]
mod migration_0040_disband_requests;
#[path = "migrations/0041_secure_delete_checkpoint_intents.rs"]
mod migration_0041_secure_delete_checkpoint_intents;
#[path = "migrations/0042_group_state_checkpoints.rs"]
mod migration_0042_group_state_checkpoints;
#[path = "migrations/0043_transport_group_routes.rs"]
mod migration_0043_transport_group_routes;
#[path = "migrations/0044_local_group_deletion_frontiers.rs"]
mod migration_0044_local_group_deletion_frontiers;
#[path = "migrations/0045_timeline_canonical_order.rs"]
mod migration_0045_timeline_canonical_order;
#[path = "migrations/0046_message_group_state_epoch_index.rs"]
mod migration_0046_message_group_state_epoch_index;
#[path = "migrations/0047_normalized_message_records.rs"]
mod migration_0047_normalized_message_records;
#[path = "migrations/0048_deferred_peel_generations.rs"]
mod migration_0048_deferred_peel_generations;
#[path = "migrations/0049_pending_invite_index.rs"]
mod migration_0049_pending_invite_index;
#[path = "migrations/0050_direct_conversation_members.rs"]
mod migration_0050_direct_conversation_members;
#[path = "migrations/0051_prepared_group_image_uploads.rs"]
mod migration_0051_prepared_group_image_uploads;
#[path = "migrations/0052_epoch_backfill_intents.rs"]
mod migration_0052_epoch_backfill_intents;
#[path = "migrations/0053_account_delivery_recovery.rs"]
mod migration_0053_account_delivery_recovery;
#[path = "migrations/0054_transport_reconciliation_items.rs"]
mod migration_0054_transport_reconciliation_items;
#[path = "migrations/0055_epoch_stall_evidence.rs"]
mod migration_0055_epoch_stall_evidence;
#[path = "migrations/0056_chat_list_accepted_activity_high_water.rs"]
mod migration_0056_chat_list_accepted_activity_high_water;
#[path = "migrations/0057_openmls_values_msgpack.rs"]
mod migration_0057_openmls_values_msgpack;
#[path = "migrations/0058_processed_transport_ids.rs"]
mod migration_0058_processed_transport_ids;
#[path = "migrations/0059_chat_list_unread_membership.rs"]
mod migration_0059_chat_list_unread_membership;
#[path = "migrations/0060_released_transport_receipts.rs"]
mod migration_0060_released_transport_receipts;
#[path = "migrations/0061_transport_reconciliation_replay_cursor.rs"]
mod migration_0061_transport_reconciliation_replay_cursor;
#[path = "migrations/0062_chat_list_preview_indexes.rs"]
mod migration_0062_chat_list_preview_indexes;
#[path = "migrations/0063_query_indexes.rs"]
mod migration_0063_query_indexes;
#[path = "migrations/0064_own_commit_intents.rs"]
mod migration_0064_own_commit_intents;
#[path = "migrations/0065_chat_presentation.rs"]
mod migration_0065_chat_presentation;
#[path = "migrations/0066_chat_presentation_maintenance.rs"]
mod migration_0066_chat_presentation_maintenance;
#[path = "migrations/0067_invitation_recovery.rs"]
mod migration_0067_invitation_recovery;
#[path = "migrations/0068_media_epoch_index.rs"]
mod migration_0068_media_epoch_index;
#[path = "migrations/0069_chat_readiness_index.rs"]
mod migration_0069_chat_readiness_index;
#[path = "migrations/0070_forgotten_groups.rs"]
mod migration_0070_forgotten_groups;
#[path = "migrations/0071_group_reset_cutoff.rs"]
mod migration_0071_group_reset_cutoff;
#[path = "migrations/0072_chat_list_pages.rs"]
mod migration_0072_chat_list_pages;
#[cfg(test)]
#[path = "migrations/query_work_tests.rs"]
mod query_work_tests;
#[cfg(test)]
#[path = "migrations/test_support.rs"]
mod test_support;

use crate::SqliteResultExt;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

#[path = "migrations/0073_message_draft_revisions.rs"]
mod migration_0073_message_draft_revisions;

#[path = "migrations/0074_chat_list_invite_attention.rs"]
mod migration_0074_chat_list_invite_attention;
#[path = "migrations/0075_user_blocks.rs"]
mod migration_0075_user_blocks;
#[path = "migrations/0076_accepted_edits.rs"]
mod migration_0076_accepted_edits;
#[path = "migrations/0077_avatar_cache.rs"]
mod migration_0077_avatar_cache;
#[path = "migrations/0078_avatar_acquisition.rs"]
mod migration_0078_avatar_acquisition;
#[path = "migrations/0079_content_reports.rs"]
mod migration_0079_content_reports;
#[path = "migrations/0080_avatar_target_lookup.rs"]
mod migration_0080_avatar_target_lookup;
#[path = "migrations/0081_attachment_history.rs"]
mod migration_0081_attachment_history;
#[path = "migrations/0083_attachment_acquisition.rs"]
mod migration_0083_attachment_acquisition;
#[path = "migrations/0084_attachment_worker_demand.rs"]
mod migration_0084_attachment_worker_demand;
#[path = "migrations/0085_attachment_partials.rs"]
mod migration_0085_attachment_partials;
#[path = "migrations/0086_attachment_controls.rs"]
mod migration_0086_attachment_controls;
#[path = "migrations/0089_local_submissions.rs"]
mod migration_0089_local_submissions;
#[path = "migrations/0090_poll_response_edges.rs"]
mod migration_0090_poll_response_edges;
#[path = "migrations/0091_account_local_identity.rs"]
mod migration_0091_account_local_identity;
#[path = "migrations/0092_account_recovery_owner.rs"]
mod migration_0092_account_recovery_owner;
#[path = "migrations/0093_recovery_route_snapshot.rs"]
mod migration_0093_recovery_route_snapshot;
#[path = "migrations/0094_qualified_stall_observations.rs"]
mod migration_0094_qualified_stall_observations;
#[path = "migrations/0095_recovery_comparison.rs"]
mod migration_0095_recovery_comparison;

#[path = "migrations/0082_deletion_provenance.rs"]
mod migration_0082_deletion_provenance;

#[path = "migrations/0087_attachment_automatic_history.rs"]
mod migration_0087_attachment_automatic_history;
#[path = "migrations/0088_draft_attachment_descriptors.rs"]
mod migration_0088_draft_attachment_descriptors;

pub(crate) struct Migration {
    pub(crate) version: i64,
    pub(crate) name: &'static str,
    pub(crate) apply: fn(&Transaction<'_>) -> StorageResult<()>,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial_schema",
        apply: migration_0001_initial_schema::apply,
    },
    Migration {
        version: 2,
        name: "0002_account_device_signers",
        apply: migration_0002_account_device_signers::apply,
    },
    Migration {
        version: 3,
        name: "0003_group_foreign_keys",
        apply: migration_0003_group_foreign_keys::apply,
    },
    Migration {
        version: 4,
        name: "0004_app_timeline",
        apply: migration_0004_app_timeline::apply,
    },
    Migration {
        version: 5,
        name: "0005_account_projection",
        apply: migration_0005_account_projection::apply,
    },
    Migration {
        version: 6,
        name: "0006_chat_list_projection",
        apply: migration_0006_chat_list_projection::apply,
    },
    Migration {
        version: 7,
        name: "0007_timeline_projection_indexes",
        apply: migration_0007_timeline_projection_indexes::apply,
    },
    Migration {
        version: 8,
        name: "0008_timeline_invalidation_status",
        apply: migration_0008_timeline_invalidation_status::apply,
    },
    Migration {
        version: 9,
        name: "0009_app_event_source_epoch",
        apply: migration_0009_app_event_source_epoch::apply,
    },
    Migration {
        version: 10,
        name: "0010_encrypted_media_epoch_secrets",
        apply: migration_0010_encrypted_media_epoch_secrets::apply,
    },
    Migration {
        version: 11,
        name: "0011_chat_list_avatar_url",
        apply: migration_0011_chat_list_avatar_url::apply,
    },
    Migration {
        version: 12,
        name: "0012_app_event_origin_commit",
        apply: migration_0012_app_event_origin_commit::apply,
    },
    Migration {
        version: 13,
        name: "0013_app_event_kind_order_index",
        apply: migration_0013_app_event_kind_order_index::apply,
    },
    Migration {
        version: 14,
        name: "0014_message_timeline_reply_lookup_index",
        apply: migration_0014_message_timeline_reply_lookup_index::apply,
    },
    Migration {
        version: 15,
        name: "0015_member_validation_cache",
        apply: migration_0015_member_validation_cache::apply,
    },
    Migration {
        version: 16,
        name: "0016_leave_requests",
        apply: migration_0016_leave_requests::apply,
    },
    Migration {
        version: 17,
        name: "0017_notification_settings_default_on",
        apply: migration_0017_notification_settings_default_on::apply,
    },
    Migration {
        version: 18,
        name: "0018_account_group_self_membership",
        apply: migration_0018_account_group_self_membership::apply,
    },
    Migration {
        version: 19,
        name: "0019_chat_list_unread_mention_count",
        apply: migration_0019_chat_list_unread_mention_count::apply,
    },
    Migration {
        version: 20,
        name: "0020_message_modifier_edges",
        apply: migration_0020_message_modifier_edges::apply,
    },
    Migration {
        version: 21,
        name: "0021_push_token_owner_signatures",
        apply: migration_0021_push_token_owner_signatures::apply,
    },
    Migration {
        version: 22,
        name: "0022_chat_list_self_membership",
        apply: migration_0022_chat_list_self_membership::apply,
    },
    Migration {
        version: 23,
        name: "0023_chat_list_projection_version",
        apply: migration_0023_chat_list_projection_version::apply,
    },
    Migration {
        version: 24,
        name: "0024_pending_welcome_delivery",
        apply: migration_0024_pending_welcome_delivery::apply,
    },
    Migration {
        version: 25,
        name: "0025_chat_notification_settings",
        apply: migration_0025_chat_notification_settings::apply,
    },
    Migration {
        version: 26,
        name: "0026_message_drafts",
        apply: migration_0026_message_drafts::apply,
    },
    Migration {
        version: 27,
        name: "0027_app_event_moderation_grant",
        apply: migration_0027_app_event_moderation_grant::apply,
    },
    Migration {
        version: 28,
        name: "0028_ingress_dedup",
        apply: migration_0028_ingress_dedup::apply,
    },
    Migration {
        version: 29,
        name: "0029_app_event_retention_decision",
        apply: migration_0029_app_event_retention_decision::apply,
    },
    Migration {
        version: 30,
        name: "0030_prior_nostr_routes",
        apply: migration_0030_prior_nostr_routes::apply,
    },
    Migration {
        version: 31,
        name: "0031_outbound_fanout",
        apply: migration_0031_outbound_fanout::apply,
    },
    Migration {
        version: 32,
        name: "0032_encrypted_media_secret_references",
        apply: migration_0032_encrypted_media_secret_references::apply,
    },
    Migration {
        version: 33,
        name: "0033_push_registration_gossip_outbox",
        apply: migration_0033_push_registration_gossip_outbox::apply,
    },
    Migration {
        version: 34,
        name: "0034_maintenance_publication",
        apply: migration_0034_maintenance_publication::apply,
    },
    Migration {
        version: 35,
        name: "0035_durable_convergence_passes",
        apply: migration_0035_durable_convergence_passes::apply,
    },
    Migration {
        version: 36,
        name: "0036_agent_stream_publisher_sequences",
        apply: migration_0036_agent_stream_publisher_sequences::apply,
    },
    Migration {
        version: 37,
        name: "0037_chat_list_semantic_timestamps",
        apply: migration_0037_chat_list_semantic_timestamps::apply,
    },
    Migration {
        version: 38,
        name: "0038_chat_list_interaction_state",
        apply: migration_0038_chat_list_interaction_state::apply,
    },
    Migration {
        version: 39,
        name: "0039_chat_pin_positions",
        apply: migration_0039_chat_pin_positions::apply,
    },
    Migration {
        version: 40,
        name: "0040_disband_requests",
        apply: migration_0040_disband_requests::apply,
    },
    Migration {
        version: 41,
        name: "0041_secure_delete_checkpoint_intents",
        apply: migration_0041_secure_delete_checkpoint_intents::apply,
    },
    Migration {
        version: 42,
        name: "0042_group_state_checkpoints",
        apply: migration_0042_group_state_checkpoints::apply,
    },
    Migration {
        version: 43,
        name: "0043_transport_group_routes",
        apply: migration_0043_transport_group_routes::apply,
    },
    Migration {
        version: 44,
        name: "0044_local_group_deletion_frontiers",
        apply: migration_0044_local_group_deletion_frontiers::apply,
    },
    Migration {
        version: 45,
        name: "0045_timeline_canonical_order",
        apply: migration_0045_timeline_canonical_order::apply,
    },
    Migration {
        version: 46,
        name: "0046_message_group_state_epoch_index",
        apply: migration_0046_message_group_state_epoch_index::apply,
    },
    Migration {
        version: 47,
        name: "0047_normalized_message_records",
        apply: migration_0047_normalized_message_records::apply,
    },
    Migration {
        version: 48,
        name: "0048_deferred_peel_generations",
        apply: migration_0048_deferred_peel_generations::apply,
    },
    Migration {
        version: 49,
        name: "0049_pending_invite_index",
        apply: migration_0049_pending_invite_index::apply,
    },
    Migration {
        version: 50,
        name: "0050_direct_conversation_members",
        apply: migration_0050_direct_conversation_members::apply,
    },
    Migration {
        version: 51,
        name: "0051_prepared_group_image_uploads",
        apply: migration_0051_prepared_group_image_uploads::apply,
    },
    Migration {
        version: 52,
        name: "0052_epoch_backfill_intents",
        apply: migration_0052_epoch_backfill_intents::apply,
    },
    Migration {
        version: 53,
        name: "0053_account_delivery_recovery",
        apply: migration_0053_account_delivery_recovery::apply,
    },
    Migration {
        version: 54,
        name: "0054_transport_reconciliation_items",
        apply: migration_0054_transport_reconciliation_items::apply,
    },
    Migration {
        version: 55,
        name: "0055_epoch_stall_evidence",
        apply: migration_0055_epoch_stall_evidence::apply,
    },
    Migration {
        version: 56,
        name: "0056_chat_list_accepted_activity_high_water",
        apply: migration_0056_chat_list_accepted_activity_high_water::apply,
    },
    Migration {
        version: 57,
        name: "0057_openmls_values_msgpack",
        apply: migration_0057_openmls_values_msgpack::apply,
    },
    Migration {
        version: 58,
        name: "0058_processed_transport_ids",
        apply: migration_0058_processed_transport_ids::apply,
    },
    Migration {
        version: 59,
        name: "0059_chat_list_unread_membership",
        apply: migration_0059_chat_list_unread_membership::apply,
    },
    Migration {
        version: 60,
        name: "0060_released_transport_receipts",
        apply: migration_0060_released_transport_receipts::apply,
    },
    Migration {
        version: 61,
        name: "0061_transport_reconciliation_replay_cursor",
        apply: migration_0061_transport_reconciliation_replay_cursor::apply,
    },
    Migration {
        version: 62,
        name: "0062_chat_list_preview_indexes",
        apply: migration_0062_chat_list_preview_indexes::apply,
    },
    Migration {
        version: 63,
        name: "0063_query_indexes",
        apply: migration_0063_query_indexes::apply,
    },
    Migration {
        version: 64,
        name: "0064_own_commit_intents",
        apply: migration_0064_own_commit_intents::apply,
    },
    Migration {
        version: 65,
        name: "0065_chat_presentation",
        apply: migration_0065_chat_presentation::apply,
    },
    Migration {
        version: 66,
        name: "0066_chat_presentation_maintenance",
        apply: migration_0066_chat_presentation_maintenance::apply,
    },
    Migration {
        version: 67,
        name: "0067_invitation_recovery",
        apply: migration_0067_invitation_recovery::apply,
    },
    Migration {
        version: 68,
        name: "0068_media_epoch_index",
        apply: migration_0068_media_epoch_index::apply,
    },
    Migration {
        version: 69,
        name: "0069_chat_readiness_index",
        apply: migration_0069_chat_readiness_index::apply,
    },
    Migration {
        version: 70,
        name: "0070_forgotten_groups",
        apply: migration_0070_forgotten_groups::apply,
    },
    Migration {
        version: 71,
        name: "0071_group_reset_cutoff",
        apply: migration_0071_group_reset_cutoff::apply,
    },
    Migration {
        version: 72,
        name: "0072_chat_list_pages",
        apply: migration_0072_chat_list_pages::apply,
    },
    Migration {
        version: 73,
        name: "0073_message_draft_revisions",
        apply: migration_0073_message_draft_revisions::apply,
    },
    Migration {
        version: 74,
        name: "0074_chat_list_invite_attention",
        apply: migration_0074_chat_list_invite_attention::apply,
    },
    Migration {
        version: 75,
        name: "0075_user_blocks",
        apply: migration_0075_user_blocks::apply,
    },
    Migration {
        version: 76,
        name: "0076_accepted_edits",
        apply: migration_0076_accepted_edits::apply,
    },
    Migration {
        version: 77,
        name: "0077_avatar_cache",
        apply: migration_0077_avatar_cache::apply,
    },
    Migration {
        version: 78,
        name: "0078_avatar_acquisition",
        apply: migration_0078_avatar_acquisition::apply,
    },
    Migration {
        version: 79,
        name: "0079_content_reports",
        apply: migration_0079_content_reports::apply,
    },
    Migration {
        version: 80,
        name: "0080_avatar_target_lookup",
        apply: migration_0080_avatar_target_lookup::apply,
    },
    Migration {
        version: 81,
        name: "0081_attachment_history",
        apply: migration_0081_attachment_history::apply,
    },
    Migration {
        version: 82,
        name: "0082_deletion_provenance",
        apply: migration_0082_deletion_provenance::apply,
    },
    Migration {
        version: 83,
        name: "0083_attachment_acquisition",
        apply: migration_0083_attachment_acquisition::apply,
    },
    Migration {
        version: 84,
        name: "0084_attachment_worker_demand",
        apply: migration_0084_attachment_worker_demand::apply,
    },
    Migration {
        version: 85,
        name: "0085_attachment_partials",
        apply: migration_0085_attachment_partials::apply,
    },
    Migration {
        version: 86,
        name: "0086_attachment_controls",
        apply: migration_0086_attachment_controls::apply,
    },
    Migration {
        version: 87,
        name: "0087_attachment_automatic_history",
        apply: migration_0087_attachment_automatic_history::apply,
    },
    Migration {
        version: 88,
        name: "0088_draft_attachment_descriptors",
        apply: migration_0088_draft_attachment_descriptors::apply,
    },
    Migration {
        version: 89,
        name: "0089_local_submissions",
        apply: migration_0089_local_submissions::apply,
    },
    Migration {
        version: 90,
        name: "0090_poll_response_edges",
        apply: migration_0090_poll_response_edges::apply,
    },
    Migration {
        version: 91,
        name: "0091_account_local_identity",
        apply: migration_0091_account_local_identity::apply,
    },
    Migration {
        version: 92,
        name: "0092_account_recovery_owner",
        apply: migration_0092_account_recovery_owner::apply,
    },
    Migration {
        version: 93,
        name: "0093_recovery_route_snapshot",
        apply: migration_0093_recovery_route_snapshot::apply,
    },
    Migration {
        version: 94,
        name: "0094_qualified_stall_observations",
        apply: migration_0094_qualified_stall_observations::apply,
    },
    Migration {
        version: 95,
        name: "0095_recovery_comparison",
        apply: migration_0095_recovery_comparison::apply,
    },
];

pub(crate) fn run_all(connection: &mut Connection) -> StorageResult<usize> {
    run_with_summary(connection, MIGRATIONS)
}

#[cfg(test)]
pub(crate) fn run(connection: &mut Connection, migrations: &[Migration]) -> StorageResult<()> {
    run_with_summary(connection, migrations).map(|_| ())
}

fn run_with_summary(connection: &mut Connection, migrations: &[Migration]) -> StorageResult<usize> {
    ensure_migration_table(connection)?;
    ensure_ordered(migrations)?;
    reconcile_legacy_migration_names(connection, migrations)?;
    reject_unknown_future_migrations(connection, migrations)?;

    let mut applied = 0;
    for migration in migrations {
        match applied_name(connection, migration.version)? {
            Some(name) if name == migration.name => continue,
            Some(name) => {
                return Err(StorageError::Backend(format!(
                    "migration {} was applied as {name}, expected {}",
                    migration.version, migration.name
                )));
            }
            None => {
                apply_migration(connection, migration)?;
                applied += 1;
            }
        }
    }

    Ok(applied)
}

fn ensure_migration_table(connection: &Connection) -> StorageResult<()> {
    connection
        .execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS cgka_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix_seconds INTEGER NOT NULL
);
"#,
        )
        .storage()
}

fn ensure_ordered(migrations: &[Migration]) -> StorageResult<()> {
    let mut previous = None;
    for migration in migrations {
        if migration.version <= 0 {
            return Err(StorageError::Backend(format!(
                "migration versions must be positive: {}",
                migration.version
            )));
        }
        if let Some(previous) = previous
            && migration.version <= previous
        {
            return Err(StorageError::Backend(format!(
                "migrations must be strictly ordered: {previous} then {}",
                migration.version
            )));
        }
        previous = Some(migration.version);
    }
    Ok(())
}

fn reject_unknown_future_migrations(
    connection: &Connection,
    migrations: &[Migration],
) -> StorageResult<()> {
    let latest_known = migrations.last().map(|m| m.version).unwrap_or(0);
    let unknown: Option<i64> = connection
        .query_row(
            "SELECT version FROM cgka_schema_migrations
             WHERE version > ?1
             ORDER BY version DESC
             LIMIT 1",
            params![latest_known],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    if let Some(version) = unknown {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: version,
            latest_supported: latest_known,
        });
    }
    Ok(())
}

fn reconcile_legacy_migration_names(
    connection: &mut Connection,
    migrations: &[Migration],
) -> StorageResult<()> {
    const LEGACY_CHAT_LIST_AVATAR_URL: &str = "0009_chat_list_avatar_url";
    const APP_EVENT_SOURCE_EPOCH: &str = "0009_app_event_source_epoch";

    let expects_app_event_source_epoch = migrations
        .iter()
        .any(|migration| migration.version == 9 && migration.name == APP_EVENT_SOURCE_EPOCH);
    if !expects_app_event_source_epoch {
        return Ok(());
    }

    let Some(applied) = applied_name(connection, 9)? else {
        return Ok(());
    };
    if applied != LEGACY_CHAT_LIST_AVATAR_URL {
        return Ok(());
    }

    let tx = connection.transaction().storage()?;
    add_column_if_missing(&tx, "app_events", "source_epoch", "INTEGER")?;
    add_column_if_missing(&tx, "message_timeline", "source_epoch", "INTEGER")?;
    tx.execute(
        "UPDATE cgka_schema_migrations
            SET name = ?1
          WHERE version = 9
            AND name = ?2",
        params![APP_EVENT_SOURCE_EPOCH, LEGACY_CHAT_LIST_AVATAR_URL],
    )
    .storage()?;
    tx.commit().storage()
}

fn add_column_if_missing(
    tx: &Transaction<'_>,
    table: &str,
    column: &str,
    definition: &str,
) -> StorageResult<()> {
    if table_has_column(tx, table, column)? {
        return Ok(());
    }
    tx.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition};"
    ))
    .storage()
}

fn table_has_column(tx: &Transaction<'_>, table: &str, column: &str) -> StorageResult<bool> {
    let mut statement = tx
        .prepare(&format!("PRAGMA table_info({table})"))
        .storage()?;
    let mut rows = statement.query([]).storage()?;
    while let Some(row) = rows.next().storage()? {
        let name: String = row.get("name").storage()?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn applied_name(connection: &Connection, version: i64) -> StorageResult<Option<String>> {
    connection
        .query_row(
            "SELECT name FROM cgka_schema_migrations WHERE version = ?1",
            params![version],
            |row| row.get(0),
        )
        .optional()
        .storage()
}

fn apply_migration(connection: &mut Connection, migration: &Migration) -> StorageResult<()> {
    let tx = connection.transaction().storage()?;
    (migration.apply)(&tx)?;
    tx.execute(
        "INSERT INTO cgka_schema_migrations
            (version, name, applied_at_unix_seconds)
         VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER))",
        params![migration.version, migration.name],
    )
    .storage()?;
    #[cfg(test)]
    migration_crash_pause(migration.version);
    tx.commit().storage()
}

#[cfg(test)]
fn migration_crash_pause(version: i64) {
    let expected = version.to_string();
    if std::env::var("MDK_STORAGE_TEST_MIGRATION_CRASH_VERSION").as_deref() != Ok(expected.as_str())
    {
        return;
    }
    let ready = std::env::var_os("MDK_STORAGE_TEST_CRASH_READY_FILE")
        .expect("migration crash ready-file path");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ready)
        .expect("create migration crash ready file");
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, mid, sample_group, sample_message};
    use crate::{
        SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, epoch_to_i64, message_state_to_i64,
        open_hardened_sqlcipher, serialize,
    };
    use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
    use std::io::{Read, Write};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    const CRASH_CHILD_ENV: &str = "MDK_STORAGE_TEST_CRASH_CHILD";

    const CRASH_DATABASE_ENV: &str = "MDK_STORAGE_TEST_CRASH_DATABASE";
    const CRASH_READY_FILE_ENV: &str = "MDK_STORAGE_TEST_CRASH_READY_FILE";
    const TEST_DATABASE_KEY: &str = "storage format migration crash key";
    const V0_9_12_FIXTURE_KEY: &str = "mdk storage v1 fixture key";
    const V0_9_12_FIXTURE: &[u8] = include_bytes!("../fixtures/storage-v1-v0.9.12.bin");

    #[test]
    fn presentation_upgrade_adds_durable_storage_without_rewriting_group_names() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..64]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at)
                            VALUES ('aa', 'fixture', 'Deliberately chosen name', 7);
             INSERT INTO chat_list_rows(group_id_hex, activity_sort_at, updated_at) VALUES ('aa', 19, 7);
             INSERT INTO direct_conversation_members VALUES ('aa', 'bb'), ('aa', 'cc');",
        )
        .unwrap();
        // Simulate interruption after the DDL/data work but before commit.
        {
            let tx = conn.transaction().unwrap();
            super::migration_0065_chat_presentation::apply(&tx).unwrap();
            tx.rollback().unwrap();
        }
        let columns: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('chat_list_rows') WHERE name = 'presentation_json'", [], |r| r.get(0)).unwrap();
        assert_eq!(columns, 0);
        run_all(&mut conn).unwrap();
        run_all(&mut conn).unwrap();
        let present: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('chat_list_rows') WHERE name = 'presentation_json')",
            [], |row| row.get(0),
        ).unwrap();
        assert!(
            present,
            "chat rows must persist selected presentation in the account database"
        );
        let name: String = conn
            .query_row(
                "SELECT profile_name FROM account_groups WHERE group_id_hex = 'aa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "Deliberately chosen name");
        let preserved: (i64, i64, bool) = conn.query_row("SELECT activity_sort_at, length(presentation_row_epoch), presentation_json IS NULL FROM chat_list_rows WHERE group_id_hex = 'aa'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(preserved, (19, 16, true));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM chat_presentation_members", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap(),
            2
        );
    }

    #[test]
    fn preview_indexes_are_repeatable() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut conn = store.lock().unwrap();
        let tx = conn.transaction().unwrap();
        migration_0062_chat_list_preview_indexes::apply(&tx).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn seen_recency_index_upgrade() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..62]).unwrap();
        conn.execute_batch(
            "INSERT INTO seen_events(rowid, event_id, seen_at) VALUES
             (2, 'old', 1), (5, 'tie-first', 9), (11, 'tie-last', 9);",
        )
        .unwrap();
        run_all(&mut conn).unwrap();
        run_all(&mut conn).unwrap();
        let mut statement = conn
            .prepare("SELECT event_id FROM seen_events ORDER BY seen_at DESC, rowid DESC")
            .unwrap();
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(ids, ["tie-last", "tie-first", "old"]);
        assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
    }

    #[test]
    fn master_query_indexes_upgrade_to_own_commit_intents_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master-to-own-intents.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..63]).unwrap();
        conn.execute_batch(
            "INSERT INTO seen_events(event_id, seen_at) VALUES ('retained', 9);
             INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 1, x'00');",
        )
        .unwrap();

        run_all(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_own_commit_intents(commit_id, group_id, insert_order, record)
             VALUES (x'01', x'aa', 1, x'bb');",
        )
        .unwrap();
        drop(conn);

        let mut conn = keyed_connection(&path);
        run_all(&mut conn).unwrap();
        assert_eq!(
            applied_name(&conn, 63).unwrap().as_deref(),
            Some("0063_query_indexes")
        );
        assert_eq!(
            applied_name(&conn, 64).unwrap().as_deref(),
            Some("0064_own_commit_intents")
        );
        let retained: String = conn
            .query_row(
                "SELECT event_id FROM seen_events INDEXED BY idx_seen_events_recency",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, "retained");
        let intent: Vec<u8> = conn
            .query_row("SELECT record FROM cgka_own_commit_intents", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(intent, [0xbb]);
    }

    fn recovery_completion_rows(
        conn: &Connection,
        table: &str,
    ) -> Vec<Vec<rusqlite::types::Value>> {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn recovery_completion_migration_preserves_populated_state_and_rolls_back_interruption() {
        fn interrupted(tx: &Transaction<'_>) -> StorageResult<()> {
            migration_0093_recovery_route_snapshot::apply(tx)?;
            Err(StorageError::Backend(
                "injected completion migration interruption".into(),
            ))
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery-completion.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..91]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label,updated_at) VALUES ('alice',100);
            INSERT INTO cgka_groups(id,epoch,record) VALUES (x'aa',7,x'00');
            INSERT INTO app_epoch_backfill_intents VALUES (x'aa',7,123);
            INSERT INTO account_delivery_recovery VALUES ('alice',42,124,0);
            INSERT INTO app_epoch_stall_evidence VALUES (x'aa',7,2,0,123000,123);
            INSERT INTO cgka_released_transport_receipts VALUES (x'bb',x'aa',7);
            INSERT INTO cgka_maintenance_obligations VALUES (x'01',x'aa',1,x'1234');
            INSERT INTO transport_reconciliation_items VALUES (0,x'',zeroblob(32),120);
            INSERT INTO transport_reconciliation_route_state VALUES (0,x'',119,zeroblob(32));
            INSERT INTO transport_reconciliation_scheduler VALUES (1,0,x'');",
        )
        .unwrap();
        run(&mut conn, &MIGRATIONS[..92]).unwrap();
        conn.execute_batch("UPDATE account_recovery_state SET next_attempt=9,retry_ordinal=4,
            retry_recorded_at_ms=1000,retry_delay_ms=15000,retry_not_before_ms=16000;
            INSERT INTO account_recovery_obligations(demand_key,cause,created_at_ms,updated_at_ms,caller_origin,urgency)
            VALUES ('explicit:existing',3,1000,1000,1,1);").unwrap();
        let preserved = [
            "account_recovery_obligations",
            "account_recovery_scopes",
            "account_delivery_loss_evidence",
            "app_epoch_stall_evidence",
            "cgka_released_transport_receipts",
            "cgka_maintenance_obligations",
            "transport_reconciliation_items",
            "transport_reconciliation_route_state",
            "transport_reconciliation_scheduler",
        ];
        let before: Vec<_> = preserved
            .iter()
            .map(|table| recovery_completion_rows(&conn, table))
            .collect();
        let retry_before = recovery_completion_rows(&conn, "account_recovery_state");
        assert!(
            apply_migration(
                &mut conn,
                &Migration {
                    version: 93,
                    name: "0093_recovery_route_snapshot",
                    apply: interrupted
                }
            )
            .is_err()
        );
        assert_eq!(applied_name(&conn, 93).unwrap(), None);
        assert!(
            conn.prepare("SELECT route_snapshot FROM account_recovery_state")
                .is_err()
        );
        assert_eq!(
            recovery_completion_rows(&conn, "account_recovery_state"),
            retry_before
        );
        assert!(
            conn.prepare("SELECT inventory_invalidated FROM cgka_released_transport_receipts")
                .is_err(),
            "interrupted migration must roll back the journal column too"
        );
        for (table, expected) in preserved.iter().zip(&before) {
            assert_eq!(
                &recovery_completion_rows(&conn, table),
                expected,
                "{table} changed after rollback"
            );
        }
        // Also interrupt the integration's qualified-stagnation migration.
        // Schema and historical evidence must roll back together before reopen.
        run(&mut conn, &MIGRATIONS[..93]).unwrap();
        let before_stall: Vec<_> = preserved
            .iter()
            .map(|table| recovery_completion_rows(&conn, table))
            .collect();
        let state_before_stall = recovery_completion_rows(&conn, "account_recovery_state");
        fn interrupted_stall(tx: &Transaction<'_>) -> StorageResult<()> {
            migration_0094_qualified_stall_observations::apply(tx)?;
            Err(StorageError::Backend(
                "injected qualified observation migration interruption".into(),
            ))
        }
        assert!(
            apply_migration(
                &mut conn,
                &Migration {
                    version: 94,
                    name: "0094_qualified_stall_observations",
                    apply: interrupted_stall,
                }
            )
            .is_err()
        );
        assert_eq!(applied_name(&conn, 94).unwrap(), None);
        assert!(
            conn.prepare("SELECT qualified_certificate FROM app_epoch_stall_evidence")
                .is_err()
        );
        assert_eq!(
            recovery_completion_rows(&conn, "account_recovery_state"),
            state_before_stall
        );
        for (table, expected) in preserved.iter().zip(&before_stall) {
            assert_eq!(
                &recovery_completion_rows(&conn, table),
                expected,
                "{table} changed after qualified observation migration rollback"
            );
        }
        run(&mut conn, &MIGRATIONS[..94]).unwrap();
        let before_comparison = recovery_completion_rows(&conn, "account_recovery_state");
        fn interrupted_comparison(tx: &Transaction<'_>) -> StorageResult<()> {
            migration_0095_recovery_comparison::apply(tx)?;
            Err(StorageError::Backend(
                "injected comparison migration interruption".into(),
            ))
        }
        assert!(
            apply_migration(
                &mut conn,
                &Migration {
                    version: 95,
                    name: "0095_recovery_comparison",
                    apply: interrupted_comparison,
                }
            )
            .is_err()
        );
        assert_eq!(applied_name(&conn, 95).unwrap(), None);
        assert!(
            conn.prepare("SELECT revision FROM account_recovery_comparison")
                .is_err()
        );
        assert_eq!(
            recovery_completion_rows(&conn, "account_recovery_state"),
            before_comparison
        );
        run_all(&mut conn).unwrap();
        assert!(
            run(&mut conn, &MIGRATIONS[..92]).is_err(),
            "old runner must refuse schema 93"
        );
        drop(conn);
        let mut conn = keyed_connection(&path);
        assert_eq!(run_all(&mut conn).unwrap(), 0);
        for (table, expected) in preserved.iter().zip(&before) {
            let mut upgraded = expected.clone();
            if *table == "cgka_released_transport_receipts" {
                // Existing journals have no proof that invalidation ran.
                for row in &mut upgraded {
                    row.push(rusqlite::types::Value::Integer(0));
                }
            }
            if *table == "app_epoch_stall_evidence" {
                // Preserve every legacy counter and warning, but never promote
                // old EOSE observations into qualified stagnation evidence.
                for row in &mut upgraded {
                    use rusqlite::types::Value::{Integer, Null};
                    row.extend([Null, Integer(0), Integer(0), Null]);
                }
            }
            assert_eq!(
                &recovery_completion_rows(&conn, table),
                &upgraded,
                "{table} changed after reopen"
            );
        }
        let state = recovery_completion_rows(&conn, "account_recovery_state");
        assert_eq!(
            &state[0][..retry_before[0].len()],
            retry_before[0].as_slice()
        );
        use rusqlite::types::Value::{Integer, Null};
        assert_eq!(
            &state[0][retry_before[0].len()..],
            &[Null, Integer(0), Integer(0)],
            "route identity and qualified observation allocators must start empty"
        );
        assert!(conn.execute("INSERT INTO account_recovery_obligations(demand_key,cause,created_at_ms,updated_at_ms) VALUES ('explicit:second',3,1001,1001)",[]).is_err());
        assert_eq!(
            &recovery_completion_rows(&conn, "account_recovery_obligations"),
            &before[0]
        );
    }

    #[test]
    fn recovery_completion_migration_refuses_duplicate_explicit_rows_without_losing_debt() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..92]).unwrap();
        // The published foundation has no explicit-demand writer. Unexpected
        // preexisting rows still fail closed rather than silently discarding debt.
        conn.execute_batch(
            "INSERT INTO account_recovery_obligations(demand_key,cause,created_at_ms,updated_at_ms)
            VALUES ('explicit:first',3,1000,1000),('explicit:second',3,1001,1001);",
        )
        .unwrap();
        let before = recovery_completion_rows(&conn, "account_recovery_obligations");
        assert!(run_all(&mut conn).is_err());
        assert_eq!(applied_name(&conn, 93).unwrap(), None);
        assert!(
            conn.prepare("SELECT route_snapshot FROM account_recovery_state")
                .is_err()
        );
        assert_eq!(
            recovery_completion_rows(&conn, "account_recovery_obligations"),
            before
        );
    }

    #[test]
    fn recovery_owner_migration_preserves_populated_demand_and_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery-owner.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..91]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label, updated_at) VALUES ('alice', 100);
             INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 7, x'00');
             INSERT INTO app_epoch_backfill_intents VALUES (x'aa', 7, 123);
             INSERT INTO cgka_groups(id, epoch, record) VALUES (x'abcd', 3, x'01');
             INSERT INTO app_epoch_backfill_intents VALUES (x'abcd', 3, 122);
             INSERT INTO account_delivery_recovery VALUES ('alice', 42, 124, 9);
             INSERT INTO app_epoch_stall_evidence VALUES (x'aa', 7, 2, 0, 123000, 123);
             INSERT INTO cgka_released_transport_receipts VALUES (x'bb', x'aa', 7);
             INSERT INTO cgka_maintenance_obligations VALUES (x'01', x'aa', 1, x'1234');
             INSERT INTO transport_reconciliation_items VALUES (0, x'', zeroblob(32), 120);
             INSERT INTO transport_reconciliation_route_state VALUES (0, x'', 119, zeroblob(32));
             INSERT INTO transport_reconciliation_scheduler VALUES (1, 0, x'');",
        )
        .unwrap();
        let preserved = [
            "app_epoch_stall_evidence",
            "cgka_released_transport_receipts",
            "cgka_maintenance_obligations",
            "transport_reconciliation_items",
            "transport_reconciliation_route_state",
            "transport_reconciliation_scheduler",
        ];
        fn rows(conn: &Connection, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
            let mut statement = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }
        let before: Vec<_> = preserved.iter().map(|table| rows(&conn, table)).collect();
        run_all(&mut conn).unwrap();
        for (table, expected) in preserved.iter().zip(&before) {
            let mut upgraded = expected.clone();
            if *table == "cgka_released_transport_receipts" {
                // Existing journals have no proof that invalidation ran.
                for row in &mut upgraded {
                    row.push(rusqlite::types::Value::Integer(0));
                }
            }
            if *table == "app_epoch_stall_evidence" {
                // Preserve every legacy counter and warning, but never promote
                // old EOSE observations into qualified stagnation evidence.
                for row in &mut upgraded {
                    use rusqlite::types::Value::{Integer, Null};
                    row.extend([Null, Integer(0), Integer(0), Null]);
                }
            }
            assert_eq!(
                &rows(&conn, table),
                &upgraded,
                "{table} changed during migration"
            );
        }
        let demands: Vec<(i64, Option<i64>, Option<i64>)> = conn
            .prepare("SELECT cause, stalled_epoch, marker_token FROM account_recovery_obligations ORDER BY cause, stalled_epoch")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            demands,
            vec![(0, None, Some(42)), (1, Some(3), None), (1, Some(7), None)]
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM account_recovery_scopes WHERE snapshot_state = 0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
        assert_eq!(
            conn.query_row(
                "SELECT dropped_count FROM account_delivery_loss_evidence",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            9
        );
        assert_eq!(
            conn.query_row(
                "SELECT fruitless_completions FROM app_epoch_stall_evidence",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM cgka_released_transport_receipts",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(
            run(&mut conn, &MIGRATIONS[..91]).is_err(),
            "old binary must refuse the new schema"
        );
        drop(conn);
        let mut conn = keyed_connection(&path);
        run_all(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM account_recovery_obligations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
    }

    #[test]
    fn recovery_owner_interrupted_migration_keeps_old_authority() {
        fn fail_after_conversion(tx: &Transaction<'_>) -> StorageResult<()> {
            migration_0092_account_recovery_owner::apply(tx)?;
            Err(StorageError::Backend(
                "injected migration interruption".into(),
            ))
        }
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(&mut conn, &MIGRATIONS[..91]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_state(label, updated_at) VALUES ('alice', 100);
             INSERT INTO account_delivery_recovery VALUES ('alice', 42, 124, 9);",
        )
        .unwrap();
        let migration = Migration {
            version: 92,
            name: "0092_account_recovery_owner",
            apply: fail_after_conversion,
        };
        assert!(apply_migration(&mut conn, &migration).is_err());
        assert_eq!(
            conn.query_row(
                "SELECT marker_token FROM account_delivery_recovery",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            42
        );
        assert!(!conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'account_recovery_obligations')", [], |r| r.get::<_, bool>(0)).unwrap());
        assert_eq!(applied_name(&conn, 92).unwrap(), None);
        run_all(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT marker_token FROM account_recovery_obligations",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            42
        );
    }

    #[test]
    fn invitation_recovery_upgrade_preserves_existing_data_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invitation-recovery.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..66]).unwrap();
        conn.execute_batch(
            "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 1, x'00');
            INSERT INTO cgka_own_commit_intents(commit_id, group_id, insert_order, record)
            VALUES (x'01', x'aa', 1, x'bb');",
        )
        .unwrap();
        conn.execute_batch(
            "UPDATE chat_presentation_checkpoint SET generation=7, state=x'cafe' WHERE id=1;",
        )
        .unwrap();
        run_all(&mut conn).unwrap();
        drop(conn);
        let mut conn = keyed_connection(&path);
        run_all(&mut conn).unwrap();
        assert_eq!(
            applied_name(&conn, 67).unwrap().as_deref(),
            Some("0067_invitation_recovery")
        );
        let intent: Vec<u8> = conn
            .query_row("SELECT record FROM cgka_own_commit_intents", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(intent, [0xbb]);
        let checkpoint: (i64, Vec<u8>) = conn
            .query_row(
                "SELECT generation, state FROM chat_presentation_checkpoint WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(checkpoint, (7, vec![0xca, 0xfe]));
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM app_group_recovery_failures",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "upgrading must not invent recovery failures");
    }

    fn applied_migrations(store: &SqliteAccountStorage) -> Vec<(i64, String)> {
        let conn = store.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT version, name FROM cgka_schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn expected_migrations() -> Vec<(i64, String)> {
        MIGRATIONS
            .iter()
            .map(|migration| (migration.version, migration.name.to_string()))
            .collect()
    }

    #[test]
    fn avatar_cache_upgrade_preserves_existing_account_and_store_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("avatar-upgrade.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..76]).unwrap();
        conn.execute_batch(
            "INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at, member_count)
             VALUES('aabb', 'fixture', 'Retained group', 7, 2);"
        ).unwrap();
        let before: Vec<u8> = conn
            .query_row(
                "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        run_all(&mut conn).unwrap();
        assert_eq!(run_all(&mut conn).unwrap(), 0);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM avatar_assets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(conn);
        let mut reopened = keyed_connection(&path);
        assert_eq!(run_all(&mut reopened).unwrap(), 0);
        let after: Vec<u8> = reopened
            .query_row(
                "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
        let name: String = reopened
            .query_row(
                "SELECT profile_name FROM account_groups WHERE group_id_hex='aabb'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(name, "Retained group");
    }

    #[test]
    fn avatar_acquisition_upgrade_bootstraps_once_and_preserves_cached_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("avatar-acquisition-upgrade.db");
        let mut conn = keyed_connection(&path);
        run(&mut conn, &MIGRATIONS[..77]).unwrap();
        let value = crate::StoredChatPresentation {
            presentation: crate::ConversationPresentation {
                title: crate::PresentationText::Literal("Chat".into()),
                avatar: crate::SelectedAvatar::RemoteImage {
                    url: "https://example.com/avatar.png".into(),
                    cache_key: "source".into(),
                },
                title_source: crate::PresentationSource::Group,
                avatar_source: crate::PresentationSource::Group,
                peer_id: None,
                resolution: crate::PresentationResolution::Cached,
            },
            profile_version: None,
        };
        let bytes = serde_json::to_vec(&serde_json::json!({"format": 1, "value": value})).unwrap();
        conn.execute_batch("INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at, member_count) VALUES('aabb', 'fixture', 'Chat', 7, 3);
            INSERT INTO chat_list_rows(group_id_hex, activity_sort_at, updated_at) VALUES('aabb', 19, 7);").unwrap();
        conn.execute("UPDATE chat_list_rows SET presentation_json = ?1, presentation_applied_source_revision = presentation_source_revision WHERE group_id_hex = 'aabb'", [bytes]).unwrap();
        run_all(&mut conn).unwrap();
        drop(conn);
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();
        let storage = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(!storage.bootstrap_avatar_acquisition().unwrap());
        let job = storage.claim_avatar_acquisition(0).unwrap().unwrap();
        let image =
            crate::AvatarImage::new(vec![1; 8], crate::AvatarImageFormat::Png, 1, 1).unwrap();
        storage
            .complete_avatar_acquisition(&job, &image, None)
            .unwrap();
        storage.close().unwrap();
        let reopened = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened.read_avatar(&job.reference, 0).unwrap().image,
            Some(image)
        );
        reopened.remove_avatar_source(&job.reference).unwrap();
        reopened.close().unwrap();
        let reopened = crate::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(!reopened.bootstrap_avatar_acquisition().unwrap());
        assert!(reopened.claim_avatar_acquisition(0).unwrap().is_none());
    }

    fn keyed_connection(path: &Path) -> rusqlite::Connection {
        let connection = rusqlite::Connection::open(path).unwrap();
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();
        open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
        connection.busy_timeout(Duration::from_secs(1)).unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        let _: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .unwrap();
        connection
    }

    fn seed_file_backed_v1_database(path: &Path, message_count: u8) -> Vec<MessageRecord> {
        let mut connection = keyed_connection(path);
        run(&mut connection, &MIGRATIONS[..46]).unwrap();
        let group = sample_group(gid(1), 0, 0);
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, ?2, ?3)",
                params![
                    group.id.as_slice(),
                    epoch_to_i64(group.epoch).unwrap(),
                    serialize(&group).unwrap()
                ],
            )
            .unwrap();
        let messages = (1..=message_count)
            .map(|id| {
                let mut message = sample_message(mid(id), group.id.clone(), 0);
                message.payload = vec![id; 16_727];
                connection
                    .execute(
                        "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            message.id.as_slice(),
                            message.group_id.as_slice(),
                            epoch_to_i64(message.epoch).unwrap(),
                            message_state_to_i64(message.state),
                            serialize(&message).unwrap(),
                        ],
                    )
                    .unwrap();
                message
            })
            .collect();
        drop(connection);
        messages
    }

    fn benchmark_message_id(index: usize) -> cgka_traits::MessageId {
        cgka_traits::MessageId::new(index.to_be_bytes().to_vec())
    }

    fn benchmark_legacy_message(index: usize, group_id: &cgka_traits::GroupId) -> MessageRecord {
        let message_id = benchmark_message_id(index);
        let transport = TransportMessage {
            id: message_id.clone(),
            payload: vec![u8::try_from(index % 251).unwrap(); 16_727],
            timestamp: Timestamp(u64::try_from(index).unwrap()),
            causal_deps: Vec::new(),
            source: TransportSource("storage-format-ops".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: cgka_traits::MemberId::new(vec![0x44; 32]),
            },
        };
        // Call serde_json directly to pin the v1 envelope. The current
        // `StoredMessagePayload::encode` intentionally emits binary v2.
        let payload =
            serde_json::to_vec(&StoredMessagePayload::outbound_welcome(transport)).unwrap();
        MessageRecord {
            id: message_id,
            group_id: group_id.clone(),
            epoch: cgka_traits::EpochId(u64::try_from(index).unwrap()),
            state: MessageState::Sent,
            payload,
            deferred_peel: None,
        }
    }

    fn seed_file_backed_v1_benchmark_database(path: &Path, message_count: usize) -> usize {
        let mut connection = keyed_connection(path);
        run(&mut connection, &MIGRATIONS[..46]).unwrap();
        let group = sample_group(gid(1), 0, 0);
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, ?2, ?3)",
                params![
                    group.id.as_slice(),
                    epoch_to_i64(group.epoch).unwrap(),
                    serialize(&group).unwrap()
                ],
            )
            .unwrap();
        let tx = connection.transaction().unwrap();
        let mut representative_record_bytes = 0;
        for index in 1..=message_count {
            let message = benchmark_legacy_message(index, &group.id);
            let record = serialize(&message).unwrap();
            representative_record_bytes = record.len();
            tx.execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    message.id.as_slice(),
                    message.group_id.as_slice(),
                    epoch_to_i64(message.epoch).unwrap(),
                    message_state_to_i64(message.state),
                    record,
                ],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        drop(connection);
        representative_record_bytes
    }

    fn database_footprint(path: &Path) -> u64 {
        [
            path.to_path_buf(),
            path.with_extension("sqlite3-wal"),
            path.with_extension("sqlite3-shm"),
        ]
        .into_iter()
        .filter_map(|artifact| std::fs::metadata(artifact).ok())
        .map(|metadata| metadata.len())
        .sum()
    }

    fn measure_database_operation<T>(
        path: &Path,
        operation: impl FnOnce() -> T,
    ) -> (T, Duration, u64) {
        let stop = Arc::new(AtomicBool::new(false));
        let sampler_stop = Arc::clone(&stop);
        let sampler_path = path.to_path_buf();
        let sampler = thread::spawn(move || {
            let mut peak = database_footprint(&sampler_path);
            while !sampler_stop.load(Ordering::Relaxed) {
                peak = peak.max(database_footprint(&sampler_path));
                thread::sleep(Duration::from_millis(1));
            }
            peak.max(database_footprint(&sampler_path))
        });
        let started = Instant::now();
        let result = operation();
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        let peak = sampler.join().unwrap();
        (result, elapsed, peak)
    }

    fn checkpoint_database(path: &Path) {
        let connection = keyed_connection(path);
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
    }

    fn kill_child_at(
        test_name: &str,
        child_mode: &str,
        crash_env: &str,
        crash_value: &str,
        database: &Path,
        ready_suffix: &str,
    ) {
        let ready_file = database.with_extension(format!("{ready_suffix}.ready"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", test_name, "--nocapture"])
            .env(CRASH_CHILD_ENV, child_mode)
            .env(CRASH_DATABASE_ENV, database)
            .env(CRASH_READY_FILE_ENV, &ready_file)
            .env(crash_env, crash_value)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !ready_file.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if !ready_file.exists() {
            let _ = child.kill();
            let _ = child.wait();
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("child did not reach {ready_suffix}; stderr:\n{stderr}");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    #[ignore = "spawned by file-backed migration crash test"]
    fn storage_format_migration_crash_child() {
        if std::env::var(CRASH_CHILD_ENV).as_deref() != Ok("migration") {
            return;
        }
        let path = std::env::var_os(CRASH_DATABASE_ENV).unwrap();
        let mut connection = keyed_connection(Path::new(&path));
        run(&mut connection, MIGRATIONS).unwrap();
        panic!("migration crash point was not reached");
    }

    #[test]
    #[ignore = "spawned by file-backed promotion crash test"]
    fn storage_format_promotion_crash_child() {
        if std::env::var(CRASH_CHILD_ENV).as_deref() != Ok("promotion") {
            return;
        }
        let path = std::env::var_os(CRASH_DATABASE_ENV).unwrap();
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();
        let store = SqliteAccountStorage::open_encrypted(Path::new(&path), &key).unwrap();
        store.promote_legacy_message_rows(3).unwrap();
        panic!("promotion crash point was not reached");
    }

    fn semantic_chat_list_timestamps(store: &SqliteAccountStorage) -> Vec<(String, u64, u64)> {
        let mut rows = store
            .chat_list_rows(crate::ChatListQuery {
                include_archived: true,
            })
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.group_id_hex,
                    row.conversation_created_at,
                    row.activity_sort_at,
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }

    fn no_mentions(_plaintext: &str, _tags: &[Vec<String>]) -> bool {
        false
    }

    #[test]
    fn replay_cursor_migration_preserves_existing_route_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = keyed_connection(&dir.path().join("replay-upgrade.db"));
        run(&mut conn, &MIGRATIONS[..60]).unwrap();
        conn.execute(
            "INSERT INTO transport_reconciliation_route_state
            (route_kind, route_id, inventory_since) VALUES (0, X'', 123)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transport_reconciliation_items
            (route_kind, route_id, event_id, created_at) VALUES (0, X'', ?1, 124)",
            params![[7_u8; 32].as_slice()],
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let state: (i64, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT inventory_since, replay_after FROM transport_reconciliation_route_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (123, None));
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM transport_reconciliation_items",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        conn.execute(
            "UPDATE transport_reconciliation_route_state SET replay_after = ?1",
            params![[8_u8; 32].as_slice()],
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let cursor: Vec<u8> = conn
            .query_row(
                "SELECT replay_after FROM transport_reconciliation_route_state",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, [8; 32]);
        assert!(
            conn.execute(
                "UPDATE transport_reconciliation_route_state SET replay_after = X'01'",
                []
            )
            .is_err()
        );
        conn.close().unwrap();
    }

    #[test]
    fn initial_schema_migration_is_recorded() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(applied_migrations(&store), expected_migrations());
    }

    #[test]
    fn file_backed_v1_database_upgrades_once_and_refuses_downgrade() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("v1-upgrade.sqlite3");
        let expected = seed_file_backed_v1_database(&database, 1);
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();

        let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        assert_eq!(
            store.get_group(&gid(1)).unwrap(),
            sample_group(gid(1), 0, 0)
        );
        assert_eq!(store.get_message(&mid(1)).unwrap(), expected[0]);
        assert_eq!(applied_migrations(&store), expected_migrations());
        store.close().unwrap();

        let mut older_connection = keyed_connection(&database);
        let before: i64 = older_connection
            .query_row("SELECT count(*) FROM cgka_messages", [], |row| row.get(0))
            .unwrap();
        let error = run(&mut older_connection, &MIGRATIONS[..46]).unwrap_err();
        assert!(matches!(
            error,
            StorageError::UnsupportedSchemaVersion {
                found,
                latest_supported: 46,
            } if found == MIGRATIONS.last().unwrap().version
        ));
        let after: i64 = older_connection
            .query_row("SELECT count(*) FROM cgka_messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            after, before,
            "downgrade refusal must not touch account rows"
        );
    }

    #[test]
    fn exact_v0_9_12_database_upgrades_and_promotes_without_semantic_change() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("v0.9.12-upgrade.sqlite3");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        fs_private::set_private_file_mode(&mut options);
        let mut fixture_copy = options.open(&database).unwrap();
        fixture_copy.write_all(V0_9_12_FIXTURE).unwrap();
        fixture_copy.sync_all().unwrap();
        drop(fixture_copy);
        let key = SqlCipherKey::new(V0_9_12_FIXTURE_KEY).unwrap();

        let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let group = store
            .get_group(&cgka_traits::GroupId::new(vec![0x11; 16]))
            .unwrap();
        assert_eq!(group.name, "storage-v1-fixture");
        assert_eq!(group.epoch, cgka_traits::EpochId(7));

        let message_id = cgka_traits::MessageId::new(vec![0x22; 32]);
        let before = store.get_message(&message_id).unwrap();
        assert_eq!(before.state, cgka_traits::message::MessageState::Sent);
        let decoded = StoredMessagePayload::decode(&before.payload).unwrap();
        let welcome = decoded.as_outbound_welcome().unwrap();
        assert_eq!(welcome.payload.len(), 16_727);
        assert_eq!(welcome.source.0, "fixture");

        let progress = store.promote_legacy_message_rows(1).unwrap();
        assert_eq!(progress.promoted, 1);
        assert!(!progress.has_more);
        assert_eq!(store.get_message(&message_id).unwrap(), before);
        store.close().unwrap();

        let mut older_connection = {
            let connection = rusqlite::Connection::open(&database).unwrap();
            open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
            connection
        };
        let error = run(&mut older_connection, &MIGRATIONS[..46]).unwrap_err();
        assert!(matches!(
            error,
            StorageError::UnsupportedSchemaVersion {
                found,
                latest_supported: 46,
            } if found == MIGRATIONS.last().unwrap().version
        ));
    }

    #[test]
    #[ignore = "large file-backed storage-format benchmark; run via `just bench-storage-upgrade`"]
    fn storage_format_upgrade_benchmark() {
        let message_count = std::env::var("MDK_STORAGE_OPS_ROWS")
            .ok()
            .map(|value| value.parse::<usize>().expect("MDK_STORAGE_OPS_ROWS usize"))
            .unwrap_or(512);
        assert!((1..=100_000).contains(&message_count));

        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("storage-format-upgrade.sqlite3");
        let representative_record_bytes =
            seed_file_backed_v1_benchmark_database(&database, message_count);
        let before_bytes = database_footprint(&database);
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();

        let (store, migration_duration, migration_peak_bytes) =
            measure_database_operation(&database, || {
                SqliteAccountStorage::open_encrypted(&database, &key).unwrap()
            });
        let legacy_after_migration = usize::try_from(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM cgka_messages WHERE storage_format = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(legacy_after_migration, message_count);
        let after_migration_bytes = database_footprint(&database);

        let (
            (promotion_batches, promoted, promotion_max_batch_ms),
            promotion_duration,
            promotion_peak_bytes,
        ) = measure_database_operation(&database, || {
            let mut batches = 0usize;
            let mut promoted = 0usize;
            let mut max_batch = Duration::ZERO;
            loop {
                let batch_started = Instant::now();
                let progress = store.promote_legacy_message_rows(32).unwrap();
                max_batch = max_batch.max(batch_started.elapsed());
                batches += 1;
                promoted += progress.promoted;
                if !progress.has_more {
                    break;
                }
            }
            (batches, promoted, max_batch.as_millis())
        });
        assert_eq!(promoted, message_count);
        assert_eq!(
            store.get_message(&benchmark_message_id(1)).unwrap().payload,
            benchmark_legacy_message(1, &gid(1)).payload
        );
        assert_eq!(
            store
                .get_message(&benchmark_message_id(message_count))
                .unwrap()
                .payload,
            benchmark_legacy_message(message_count, &gid(1)).payload
        );
        store.close().unwrap();
        checkpoint_database(&database);
        let after_promotion_bytes = database_footprint(&database);

        let (reopened, reopen_duration, _) = measure_database_operation(&database, || {
            SqliteAccountStorage::open_encrypted(&database, &key).unwrap()
        });
        reopened.close().unwrap();
        checkpoint_database(&database);

        let (_, vacuum_duration, vacuum_peak_bytes) = measure_database_operation(&database, || {
            let connection = keyed_connection(&database);
            connection.execute_batch("VACUUM").unwrap();
        });
        checkpoint_database(&database);
        let after_vacuum_bytes = database_footprint(&database);

        let promotion_rows_per_second = u64::try_from(
            u128::try_from(message_count)
                .unwrap()
                .saturating_mul(1_000_000_000)
                / promotion_duration.as_nanos().max(1),
        )
        .unwrap_or(u64::MAX);
        super::test_support::emit_benchmark_line(format!(
            "MDK_BENCH storage_format_upgrade rows={message_count} \
             representative_record_bytes={representative_record_bytes} \
             before_bytes={before_bytes} migration_ms={} \
             migration_peak_bytes={migration_peak_bytes} migration_extra_bytes={} \
             after_migration_bytes={after_migration_bytes} \
             promotion_batches={promotion_batches} promotion_ms={} \
             promotion_max_batch_ms={promotion_max_batch_ms} \
             promotion_rows_per_second={promotion_rows_per_second} \
             promotion_peak_bytes={promotion_peak_bytes} \
             after_promotion_bytes={after_promotion_bytes} reopen_ms={} \
             vacuum_ms={} vacuum_peak_bytes={vacuum_peak_bytes} \
             after_vacuum_bytes={after_vacuum_bytes}",
            migration_duration.as_millis(),
            migration_peak_bytes.saturating_sub(before_bytes),
            promotion_duration.as_millis(),
            reopen_duration.as_millis(),
            vacuum_duration.as_millis(),
        ));
    }

    #[test]
    fn process_kill_mid_migration_reopens_and_upgrades_once() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("migration-kill.sqlite3");
        let expected = seed_file_backed_v1_database(&database, 2);

        kill_child_at(
            "migrations::tests::storage_format_migration_crash_child",
            "migration",
            "MDK_STORAGE_TEST_MIGRATION_CRASH_VERSION",
            "47",
            &database,
            "migration-47",
        );

        let connection = keyed_connection(&database);
        assert_eq!(applied_name(&connection, 47).unwrap(), None);
        let storage_format_columns: i64 = connection
            .query_row(
                "SELECT count(*) FROM pragma_table_info('cgka_messages') WHERE name = 'storage_format'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(storage_format_columns, 0);
        let count: i64 = connection
            .query_row("SELECT count(*) FROM cgka_messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2, "killed migration must retain every v1 row");
        drop(connection);

        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();
        let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        assert_eq!(store.get_message(&mid(1)).unwrap(), expected[0]);
        assert_eq!(store.get_message(&mid(2)).unwrap(), expected[1]);
        assert_eq!(applied_migrations(&store), expected_migrations());
    }

    #[test]
    fn process_kill_mid_promotion_rolls_back_and_retry_converges() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("promotion-kill.sqlite3");
        let expected = seed_file_backed_v1_database(&database, 3);
        let key = SqlCipherKey::new(TEST_DATABASE_KEY).unwrap();
        SqliteAccountStorage::open_encrypted(&database, &key)
            .unwrap()
            .close()
            .unwrap();

        kill_child_at(
            "migrations::tests::storage_format_promotion_crash_child",
            "promotion",
            "MDK_STORAGE_TEST_PROMOTION_CRASH_AFTER",
            "1",
            &database,
            "promotion-1",
        );

        let connection = keyed_connection(&database);
        let legacy: i64 = connection
            .query_row(
                "SELECT count(*) FROM cgka_messages WHERE storage_format = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy, 3, "killed promotion batch must roll back every row");
        drop(connection);

        let store = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
        let progress = store.promote_legacy_message_rows(3).unwrap();
        assert_eq!(progress.promoted, 3);
        assert!(!progress.has_more);
        for (index, message) in expected.iter().enumerate() {
            assert_eq!(&store.get_message(&mid(index as u8 + 1)).unwrap(), message);
        }
        let normalized: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM cgka_messages WHERE storage_format = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(normalized, 3);
    }

    #[test]
    fn normalized_message_migration_preserves_legacy_rows_without_backfill() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..46]).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, ?2)",
                params![&[0xaa_u8], b"group"],
            )
            .unwrap();
        let legacy = br#"{"payload":[1,2,3]}"#;
        connection
            .execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, 3, 4, ?3)",
                params![&[0x01_u8], &[0xaa_u8], legacy],
            )
            .unwrap();

        run(&mut connection, MIGRATIONS).unwrap();

        let migrated = connection
            .query_row(
                "SELECT storage_format, record, payload, deferred_peel
                 FROM cgka_messages WHERE id = ?1",
                params![&[0x01_u8]],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(migrated, (1, legacy.to_vec(), None, None));
    }

    #[test]
    fn normalized_message_migration_is_atomic_before_commit() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..46]).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, ?2)",
                params![&[0xaa_u8], b"group"],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, 3, 4, ?3)",
                params![&[0x01_u8], &[0xaa_u8], b"legacy-record"],
            )
            .unwrap();

        let tx = connection.transaction().unwrap();
        migration_0047_normalized_message_records::apply(&tx).unwrap();
        // Models termination after the schema/data rewrite but before the
        // migration runner can commit its transaction.
        tx.rollback().unwrap();

        let columns = connection
            .prepare("PRAGMA table_info(cgka_messages)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(!columns.iter().any(|column| column == "storage_format"));
        let record: Vec<u8> = connection
            .query_row(
                "SELECT record FROM cgka_messages WHERE id = ?1",
                params![&[0x01_u8]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(record, b"legacy-record");

        run(&mut connection, MIGRATIONS).unwrap();
    }

    #[test]
    fn pre_format_v2_binary_refuses_current_database() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut connection, MIGRATIONS).unwrap();

        let error = run(&mut connection, &MIGRATIONS[..46]).unwrap_err();
        assert!(matches!(
            error,
            StorageError::UnsupportedSchemaVersion {
                found,
                latest_supported: 46,
            } if found == MIGRATIONS.last().unwrap().version
        ));
        assert_eq!(
            applied_migrations_from_connection(&connection),
            expected_migrations(),
            "downgrade refusal must not mutate migration state"
        );
    }

    #[test]
    fn local_group_deletion_frontier_migration_preserves_absent_live_groups() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..43]).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, 0, ?2)",
                params![&[0xaa_u8], &[0_u8]],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
                 VALUES (?1, ?2, 0, 0, ?3)",
                params![&[1_u8], &[0xaa_u8], &[0_u8]],
            )
            .unwrap();

        run(&mut connection, MIGRATIONS).unwrap();

        let frontier: i64 = connection
            .query_row(
                "SELECT message_insert_order
                 FROM local_group_deletion_frontiers
                 WHERE group_id_hex = 'aa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(frontier, 1);
        let retained_routes: String = connection
            .query_row(
                "SELECT prior_nostr_routes_json
                 FROM local_group_deletion_frontiers
                 WHERE group_id_hex = 'aa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_routes, "[]");
        let pending_application_event_columns = connection
            .prepare("PRAGMA table_info(pending_application_events)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            pending_application_event_columns,
            vec!["message_id", "group_id", "message_insert_order", "record"],
            "serialized application events follow the storage record-blob convention",
        );
    }

    #[test]
    fn canonical_timeline_order_migration_backfills_read_anchor_and_virtual_keys() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..44]).unwrap();
        connection
            .execute(
                "INSERT INTO account_groups (group_id_hex, endpoint, updated_at)
                 VALUES ('aa', 'relay', 1)",
                [],
            )
            .unwrap();
        for (id, source_id, epoch, timeline_at, invalidation) in [
            ("marker", Some("source-marker"), Some(8_i64), 150_i64, None),
            ("pending", None, None, 999, None),
            ("failed", None, None, 1_000, Some("local_publish_failed")),
        ] {
            connection
                .execute(
                    "INSERT INTO message_timeline (
                         group_id_hex, message_id_hex, source_message_id_hex, source_epoch,
                         direction, sender, plaintext, kind, tags_json, timeline_at,
                         received_at, reactions_json, invalidation_status
                     ) VALUES ('aa', ?1, ?2, ?3, 'received', 'sender', '', 9, '[]', ?4,
                         ?4, '[]', ?5)",
                    params![id, source_id, epoch, timeline_at, invalidation],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO conversation_read_state (
                     group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                     initialized_at, updated_at
                 ) VALUES ('aa', 'marker', 150, 1, 1)",
                [],
            )
            .unwrap();

        run(&mut connection, MIGRATIONS).unwrap();

        let read_anchor: (i64, i64) = connection
            .query_row(
                "SELECT last_read_order_class, last_read_order_primary
                 FROM conversation_read_state WHERE group_id_hex = 'aa'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(read_anchor, (1, 8));
        let keys = connection
            .prepare(
                "SELECT message_id_hex, timeline_order_class, timeline_order_primary,
                        timeline_order_phase, timeline_order_at
                 FROM message_timeline ORDER BY message_id_hex",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            keys,
            vec![
                ("failed".to_owned(), 2, 1_000, 1, 1_000),
                ("marker".to_owned(), 1, 8, 1, 150),
                ("pending".to_owned(), 2, 999, 1, 999),
            ]
        );
    }

    #[test]
    fn media_secret_reference_migration_backfills_known_rows_conservatively() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        run(&mut connection, &MIGRATIONS[..28]).unwrap();
        let media_tags =
            serde_json::to_string(&[vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()]])
                .unwrap();
        connection
            .execute(
                "INSERT INTO app_events (
                     group_id_hex, message_id_hex, source_message_id_hex, source_epoch,
                     direction, sender, plaintext, kind, tags_json, recorded_at, received_at
                 ) VALUES ('aa', 'media', 'source-media', 7, 'received', 'sender', '', 9, ?1, 10, 10)",
                params![media_tags],
            )
            .unwrap();
        for (epoch, secret) in [(7_i64, vec![1_u8, 2, 3]), (8, vec![4_u8, 5, 6])] {
            connection
                .execute(
                    "INSERT INTO encrypted_media_epoch_secrets (
                         group_id_hex, component_id, source_epoch, secret,
                         created_at_unix_seconds
                     ) VALUES ('aa', 32776, ?1, ?2, 10)",
                    params![epoch, secret],
                )
                .unwrap();
        }

        run(&mut connection, MIGRATIONS).unwrap();

        let references: i64 = connection
            .query_row(
                "SELECT count(*) FROM encrypted_media_epoch_secret_references
                 WHERE group_id_hex = 'aa' AND message_id_hex = 'media'
                   AND component_id = 32776 AND source_epoch = 7",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(references, 1);
        let managed = connection
            .prepare(
                "SELECT source_epoch, retention_managed
                 FROM encrypted_media_epoch_secrets
                 ORDER BY source_epoch",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(managed, vec![(7, 1), (8, 0)]);
    }

    #[test]
    fn chat_list_semantic_timestamps_backfill_from_durable_history() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(&mut conn, &MIGRATIONS[..35]).unwrap();
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, updated_at)
             VALUES ('never-messaged', 'relay', 100),
                    ('active', 'relay', 200),
                    ('pruned-read', 'relay', 300),
                    ('zero-updated', 'relay', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, recorded_at, received_at
             ) VALUES ('active', 'origin', 'received', 'sender', 'origin', 9, '[]', 140, 140)",
            [],
        )
        .unwrap();
        // `zero-updated` exercises the `ag.updated_at = 0` sentinel branch: the
        // group has app events but no persisted group timestamp, so
        // `conversation_created_at` must fall back to the earliest event time
        // (250) rather than collapsing to `MIN(0, 250) = 0`.
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, recorded_at, received_at
             ) VALUES
                ('zero-updated', 'first', 'received', 'sender', 'first', 9, '[]', 250, 250),
                ('zero-updated', 'later', 'received', 'sender', 'later', 9, '[]', 275, 275)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, timeline_at, received_at, reactions_json
             ) VALUES ('active', 'latest', 'received', 'sender', 'latest', 9, '[]', 150, 150, '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, timeline_at, received_at, reactions_json, invalidation_status
             ) VALUES (
                'active', 'invalidated', 'received', 'sender', 'losing branch',
                9, '[]', 160, 160, '[]', 'LosingBranch'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conversation_read_state (
                group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                initialized_at, updated_at
             ) VALUES ('pruned-read', 'pruned-message', 350, 0, 400)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, timeline_at, received_at, reactions_json
             ) VALUES (
                'pruned-read', 'older-survivor', 'received', 'sender', 'older',
                9, '[]', 310, 310, '[]'
             )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows (group_id_hex, updated_at)
             VALUES ('never-messaged', 500), ('active', 500), ('pruned-read', 500),
                    ('zero-updated', 500)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let rows = conn
            .prepare(
                "SELECT group_id_hex, conversation_created_at, activity_sort_at
                 FROM chat_list_rows ORDER BY group_id_hex",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("active".to_owned(), 140, 150),
                ("never-messaged".to_owned(), 100, 100),
                ("pruned-read".to_owned(), 300, 350),
                ("zero-updated".to_owned(), 250, 250),
            ]
        );

        run(&mut conn, MIGRATIONS).unwrap();
        let after_second_run: Vec<(String, i64, i64)> = conn
            .prepare(
                "SELECT group_id_hex, conversation_created_at, activity_sort_at
                 FROM chat_list_rows ORDER BY group_id_hex",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(after_second_run, rows);

        let store = SqliteAccountStorage::from_connection_with_options(
            conn,
            crate::SqliteStorageOptions::default(),
        )
        .unwrap();
        let expected = rows
            .into_iter()
            .map(|(group_id, created_at, activity_at)| {
                (
                    group_id,
                    u64::try_from(created_at).unwrap(),
                    u64::try_from(activity_at).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        store
            .refresh_chat_list_rows("local-account", &no_mentions)
            .unwrap();
        assert_eq!(semantic_chat_list_timestamps(&store), expected);

        store
            .refresh_chat_list_rows("local-account", &no_mentions)
            .unwrap();
        assert_eq!(semantic_chat_list_timestamps(&store), expected);
    }

    #[test]
    fn accepted_activity_high_water_migration_backfills_existing_chat_history() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-55 are the schema immediately before the durable preview
        // demotion boundary.
        run(&mut conn, &MIGRATIONS[..55]).unwrap();
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, profile_name, updated_at)
             VALUES ('active', 'relay', 'Migration group', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, direction,
                sender, plaintext, kind, tags_json, recorded_at, received_at
             ) VALUES
                ('active', 'pending', NULL, 'sent', 'alice', 'pending', 9, '[]', 20, 20),
                ('active', 'accepted', 'source-accepted', 'received', 'bob',
                 'accepted', 9, '[]', 10, 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, source_message_id_hex, direction,
                sender, plaintext, kind, tags_json, timeline_at, received_at,
                reactions_json
             ) VALUES
                ('active', 'pending', NULL, 'sent', 'alice', 'pending', 9, '[]', 20, 20, '[]'),
                ('active', 'accepted', 'source-accepted', 'received', 'bob',
                 'accepted', 9, '[]', 10, 10, '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_list_rows (group_id_hex, updated_at)
             VALUES ('active', 1)",
            [],
        )
        .unwrap();
        let accepted_insert_order: i64 = conn
            .query_row(
                "SELECT insert_order FROM app_events
                 WHERE group_id_hex = 'active' AND message_id_hex = 'accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let high_water: i64 = conn
            .query_row(
                "SELECT accepted_activity_insert_order FROM chat_list_rows
                 WHERE group_id_hex = 'active'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(high_water, accepted_insert_order);
    }

    #[test]
    fn message_timeline_reply_lookup_index_is_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        assert!(connection_has_index(
            &conn,
            "message_timeline",
            "idx_message_timeline_reply_lookup"
        ));
    }

    #[test]
    fn chat_notification_settings_table_is_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        assert!(connection_has_column(
            &conn,
            "chat_notification_settings",
            "group_id_hex"
        ));
        assert!(connection_has_column(
            &conn,
            "chat_notification_settings",
            "muted_until_ms"
        ));
    }

    #[test]
    fn chat_pin_positions_are_migrated_with_archive_cleanup() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(&mut conn, &MIGRATIONS[..38]).unwrap();
        conn.execute(
            "INSERT INTO account_groups
                (group_id_hex, endpoint, archived, updated_at)
             VALUES ('existing-group', 'wss://relay.example', 0, 1)",
            [],
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();

        assert!(connection_has_column(
            &conn,
            "chat_pin_positions",
            "ordinal"
        ));
        assert_eq!(
            foreign_key(&conn, "chat_pin_positions", "group_id_hex"),
            Some(("account_groups".to_owned(), "CASCADE".to_owned()))
        );
        assert!(connection_has_index(
            &conn,
            "chat_pin_positions",
            "idx_chat_pin_positions_order"
        ));
        let trigger_exists = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'trigger' AND name = 'unpin_chat_when_archived'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap();
        assert!(trigger_exists);

        conn.execute(
            "INSERT INTO chat_pin_positions (group_id_hex, ordinal)
             VALUES ('existing-group', 7)",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE account_groups SET archived = 1 WHERE group_id_hex = 'existing-group'",
            [],
        )
        .unwrap();
        let pin_count = conn
            .query_row("SELECT COUNT(*) FROM chat_pin_positions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(pin_count, 0);
    }

    #[test]
    fn chat_list_interaction_state_columns_are_migrated_with_safe_defaults() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        assert_eq!(
            column_default(&conn, "conversation_read_state", "manually_marked_unread").as_deref(),
            Some("0")
        );
        assert!(connection_has_column(
            &conn,
            "account_groups",
            "member_count"
        ));
        assert_eq!(
            column_default(&conn, "chat_list_rows", "manually_marked_unread").as_deref(),
            Some("0")
        );
        assert!(connection_has_column(
            &conn,
            "chat_list_rows",
            "last_message_media_json"
        ));
        assert_eq!(
            column_default(&conn, "chat_list_rows", "last_message_delivery_state").as_deref(),
            Some("'not_applicable'")
        );
    }

    #[test]
    fn direct_conversation_members_table_is_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'direct_conversation_members'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        assert!(connection_has_column(
            &conn,
            "direct_conversation_members",
            "member_id_hex"
        ));
    }

    #[test]
    fn message_drafts_tables_are_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        assert!(connection_has_column(&conn, "message_drafts", "content"));
        assert!(connection_has_column(
            &conn,
            "message_draft_attachments",
            "plaintext"
        ));
    }

    #[test]
    fn secure_delete_checkpoint_intents_table_is_migrated() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'secure_delete_checkpoint_intents'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
        let columns = conn
            .prepare("PRAGMA table_info(secure_delete_checkpoint_intents)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "intent_nonce"));
        assert!(!columns.iter().any(|column| column == "generation"));
        assert!(
            !columns
                .iter()
                .any(|column| column == "checkpoint_completed")
        );
        assert!(
            !columns
                .iter()
                .any(|column| column == "created_at_unix_seconds")
        );
    }

    #[test]
    fn notification_settings_default_migration_preserves_existing_choices() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-16 are the schema state immediately before
        // 0017_notification_settings_default_on.
        run(&mut conn, &MIGRATIONS[..16]).unwrap();
        assert_eq!(
            column_default(
                &conn,
                "notification_settings",
                "local_notifications_enabled"
            )
            .as_deref(),
            Some("0")
        );
        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, native_push_enabled, updated_at_ms
             )
             VALUES ('legacy-default', 'aa', 0, 10)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, local_notifications_enabled,
                native_push_enabled, updated_at_ms
             )
             VALUES ('explicit-on', 'bb', 1, 0, 11)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            column_default(
                &conn,
                "notification_settings",
                "local_notifications_enabled"
            )
            .as_deref(),
            Some("1")
        );
        let preserved_disabled: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'legacy-default'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_disabled, 0);
        let preserved_enabled: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'explicit-on'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_enabled, 1);

        conn.execute(
            "INSERT INTO notification_settings (
                account_label, account_id_hex, native_push_enabled, updated_at_ms
             )
             VALUES ('new-default', 'cc', 0, 12)",
            [],
        )
        .unwrap();
        let new_default: i64 = conn
            .query_row(
                "SELECT local_notifications_enabled
                 FROM notification_settings
                 WHERE account_label = 'new-default'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_default, 1);
    }

    #[test]
    fn account_group_self_membership_migration_defaults_existing_rows_to_member() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-17 are the schema state immediately before
        // 0018_account_group_self_membership.
        run(&mut conn, &MIGRATIONS[..17]).unwrap();
        assert!(!connection_has_column(
            &conn,
            "account_groups",
            "self_membership"
        ));
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, updated_at)
             VALUES ('11', 'relay', 1)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        assert!(connection_has_column(
            &conn,
            "account_groups",
            "self_membership"
        ));
        assert_eq!(
            column_default(&conn, "account_groups", "self_membership").as_deref(),
            Some("'member'")
        );
        let legacy_membership: String = conn
            .query_row(
                "SELECT self_membership FROM account_groups WHERE group_id_hex = '11'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_membership, "member");
    }

    #[test]
    fn prior_nostr_routes_migration_defaults_existing_groups_to_empty_history() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(&mut conn, &MIGRATIONS[..29]).unwrap();
        conn.execute(
            "INSERT INTO account_groups (group_id_hex, endpoint, updated_at)
             VALUES ('11', 'relay', 1)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            column_default(&conn, "account_groups", "prior_nostr_routes_json").as_deref(),
            Some("'[]'")
        );
        assert_eq!(
            column_default(&conn, "account_groups", "nostr_routing_last_epoch").as_deref(),
            Some("0")
        );
        let history: String = conn
            .query_row(
                "SELECT prior_nostr_routes_json FROM account_groups WHERE group_id_hex = '11'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history, "[]");
    }

    #[test]
    fn chat_list_self_membership_migration_adds_member_defaulted_column() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-21 are the schema state immediately before
        // 0022_chat_list_self_membership.
        run(&mut conn, &MIGRATIONS[..21]).unwrap();
        assert!(!connection_has_column(
            &conn,
            "chat_list_rows",
            "self_membership"
        ));

        run(&mut conn, MIGRATIONS).unwrap();

        assert!(connection_has_column(
            &conn,
            "chat_list_rows",
            "self_membership"
        ));
        assert_eq!(
            column_default(&conn, "chat_list_rows", "self_membership").as_deref(),
            Some("'member'")
        );
    }

    #[test]
    fn message_modifier_edges_migration_backfills_existing_reaction_and_delete_rows() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        // Versions 1-19 are the schema state immediately before
        // 0020_message_modifier_edges.
        run(&mut conn, &MIGRATIONS[..19]).unwrap();

        let group = "11".repeat(32);
        // A reaction app_event referencing one target via an "e" tag.
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                plaintext, kind, tags_json, recorded_at, received_at
             )
             VALUES (?1, 'reaction-1', 'source-reaction-1', 'received', 'bob',
                     '+', 7, ?2, 2, 2)",
            params![group, r#"[["e","target"]]"#],
        )
        .unwrap();
        // A delete app_event referencing two targets, producing two edges.
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                plaintext, kind, tags_json, recorded_at, received_at
             )
             VALUES (?1, 'delete-1', 'source-delete-1', 'received', 'alice',
                     '', 5, ?2, 3, 3)",
            params![group, r#"[["e","target"],["e","other"]]"#],
        )
        .unwrap();
        // A non-modifier chat event must NOT produce any edge.
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                plaintext, kind, tags_json, recorded_at, received_at
             )
             VALUES (?1, 'chat-1', 'source-chat-1', 'received', 'alice',
                     'hello', 9, '[]', 1, 1)",
            params![group],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let edges: Vec<(String, String, i64, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT modifier_message_id_hex, target_message_id_hex, kind, sender
                     FROM message_modifier_edges
                     ORDER BY modifier_message_id_hex, target_message_id_hex",
                )
                .unwrap();
            stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };

        assert_eq!(
            edges,
            vec![
                (
                    "delete-1".to_owned(),
                    "other".to_owned(),
                    5,
                    "alice".to_owned()
                ),
                (
                    "delete-1".to_owned(),
                    "target".to_owned(),
                    5,
                    "alice".to_owned()
                ),
                (
                    "reaction-1".to_owned(),
                    "target".to_owned(),
                    7,
                    "bob".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn encrypted_reopen_does_not_reapply_migrations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("migration key").unwrap();

        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            assert_eq!(applied_migrations(&store).len(), MIGRATIONS.len());
        }

        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(applied_migrations(&reopened), expected_migrations());
    }

    #[test]
    fn canonical_pre_avatar_database_upgrades_through_current_migrations() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..8]).unwrap();
        assert_eq!(
            applied_name(&conn, 8).unwrap().as_deref(),
            Some("0008_timeline_invalidation_status")
        );
        assert_eq!(applied_name(&conn, 9).unwrap(), None);
        assert!(!connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(!connection_has_column(
            &conn,
            "chat_list_rows",
            "avatar_url"
        ));

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_app_event_source_epoch")
        );
        assert_eq!(
            applied_name(&conn, 11).unwrap().as_deref(),
            Some("0011_chat_list_avatar_url")
        );
        assert!(connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(connection_has_column(
            &conn,
            "encrypted_media_epoch_secrets",
            "secret"
        ));
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        assert_eq!(
            applied_migrations_from_connection(&conn),
            expected_migrations()
        );
    }

    #[test]
    fn legacy_chat_list_avatar_migration_slot_is_reconciled() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let legacy_migrations = [
            Migration {
                version: 1,
                name: "0001_initial_schema",
                apply: migration_0001_initial_schema::apply,
            },
            Migration {
                version: 2,
                name: "0002_account_device_signers",
                apply: migration_0002_account_device_signers::apply,
            },
            Migration {
                version: 3,
                name: "0003_group_foreign_keys",
                apply: migration_0003_group_foreign_keys::apply,
            },
            Migration {
                version: 4,
                name: "0004_app_timeline",
                apply: migration_0004_app_timeline::apply,
            },
            Migration {
                version: 5,
                name: "0005_account_projection",
                apply: migration_0005_account_projection::apply,
            },
            Migration {
                version: 6,
                name: "0006_chat_list_projection",
                apply: migration_0006_chat_list_projection::apply,
            },
            Migration {
                version: 7,
                name: "0007_timeline_projection_indexes",
                apply: migration_0007_timeline_projection_indexes::apply,
            },
            Migration {
                version: 8,
                name: "0008_timeline_invalidation_status",
                apply: migration_0008_timeline_invalidation_status::apply,
            },
            Migration {
                version: 9,
                name: "0009_chat_list_avatar_url",
                apply: |tx| {
                    tx.execute_batch("ALTER TABLE chat_list_rows ADD COLUMN avatar_url TEXT;")
                        .storage()
                },
            },
        ];
        run(&mut conn, &legacy_migrations).unwrap();
        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_chat_list_avatar_url")
        );
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        assert!(!connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(!connection_has_column(
            &conn,
            "message_timeline",
            "source_epoch"
        ));

        run(&mut conn, MIGRATIONS).unwrap();

        assert_eq!(
            applied_name(&conn, 9).unwrap().as_deref(),
            Some("0009_app_event_source_epoch")
        );
        assert!(connection_has_column(&conn, "app_events", "source_epoch"));
        assert!(connection_has_column(
            &conn,
            "message_timeline",
            "source_epoch"
        ));
        assert!(connection_has_column(&conn, "chat_list_rows", "avatar_url"));
        let applied = applied_migrations_from_connection(&conn);
        assert_eq!(applied, expected_migrations());
    }

    #[test]
    fn group_owned_tables_have_cascading_foreign_keys() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();

        for (table, column) in [
            ("cgka_messages", "group_id"),
            ("cgka_queued_outbound", "group_id"),
            ("cgka_member_capabilities", "group_id"),
            ("cgka_convergence_policies", "group_id"),
            ("cgka_member_validation_cache", "group_id"),
            ("cgka_group_snapshots", "group_id"),
            ("cgka_group_state_checkpoints", "group_id"),
            ("cgka_processed_transport_ids", "group_id"),
        ] {
            assert_eq!(
                foreign_key(&conn, table, column),
                Some(("cgka_groups".to_owned(), "CASCADE".to_owned())),
                "{table}.{column} should cascade when a group is deleted"
            );
        }
        assert_eq!(
            foreign_key(&conn, "pending_push_registration_shares", "group_id_hex"),
            Some(("account_groups".to_owned(), "CASCADE".to_owned())),
            "pending shares should cascade when a projection group is deleted"
        );
        assert_eq!(
            foreign_key(&conn, "pending_push_registration_removals", "group_id_hex"),
            None,
            "durable removal intent must survive projection group deletion"
        );
        assert_eq!(
            foreign_key(&conn, "account_recovery_obligations", "group_id"),
            Some(("cgka_groups".to_owned(), "CASCADE".to_owned())),
            "durable recovery intent must survive projection deletion but cascade with its protocol group"
        );
        assert_eq!(
            foreign_key(&conn, "app_epoch_stall_evidence", "group_id"),
            Some(("cgka_groups".to_owned(), "CASCADE".to_owned())),
            "frozen-epoch evidence is bounded by its protocol group and cascades with it"
        );
    }

    #[test]
    fn retention_migration_keeps_legacy_app_events_unknown_and_safe() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..28]).unwrap();
        conn.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, direction, sender, plaintext,
                kind, tags_json, recorded_at, received_at
             ) VALUES ('aa', 'legacy', 'received', 'sender', 'plaintext',
                       9, '[]', 10, 11)",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let decision = conn
            .query_row(
                "SELECT retention_seconds, retention_expires_at
                 FROM app_events
                 WHERE group_id_hex = 'aa' AND message_id_hex = 'legacy'",
                [],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .unwrap();
        assert_eq!(decision, (None, None));
        assert!(connection_has_index(
            &conn,
            "app_events",
            "idx_app_events_group_retention_expiry"
        ));
    }

    #[test]
    fn push_registration_gossip_outbox_migration_backfills_joined_groups() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(&mut conn, &MIGRATIONS[..32]).unwrap();
        conn.execute(
            "INSERT INTO account_groups (
                group_id_hex, endpoint, self_membership, updated_at
             ) VALUES ('joined', 'relay', 'member', 1),
                      ('left', 'relay', 'left', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO push_registration (
                account_label, account_id_hex, platform, token_fingerprint,
                token_bytes, server_pubkey_hex, created_at_ms, updated_at_ms,
                last_shared_at_ms
             ) VALUES ('alice', 'aa', 1, 'fingerprint', X'01', 'bb', 10, 11, 12)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO push_registration (
                account_label, account_id_hex, platform, token_fingerprint,
                token_bytes, server_pubkey_hex, created_at_ms, updated_at_ms,
                last_shared_at_ms
             ) VALUES (
                'stale-label', 'cc', 1, 'stale-fingerprint',
                X'02', 'dd', 8, 9, 10
             )",
            [],
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let pending = conn
            .query_row(
                "SELECT group_id_hex, token_fingerprint, registration_updated_at_ms,
                        queued_at_ms
                 FROM pending_push_registration_shares",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            pending,
            ("joined".to_owned(), "fingerprint".to_owned(), 11, 11)
        );
        let last_shared_at_ms: Option<i64> = conn
            .query_row(
                "SELECT last_shared_at_ms FROM push_registration WHERE account_label = 'alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(last_shared_at_ms, None);
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pending_push_registration_removals",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn group_owned_tables_reject_orphan_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let conn = store.lock().unwrap();
        let orphan_group = vec![0x99_u8; 4];

        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![vec![0x01_u8; 4], orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_processed_transport_ids (id, group_id)
             VALUES (?1, ?2)",
            params![vec![0x09_u8; 4], orphan_group],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO pending_push_registration_shares (
                group_id_hex, token_fingerprint, registration_updated_at_ms,
                queued_at_ms
             ) VALUES ('orphan', 'fingerprint', 1, 1)",
            [],
        ));
        conn.execute(
            "INSERT INTO pending_push_registration_removals (
                group_id_hex, account_label, account_id_hex, platform,
                token_fingerprint, server_pubkey_hex,
                registration_created_at_ms, registration_updated_at_ms,
                queued_at_ms
             ) VALUES ('orphan', 'alice', 'aa', 1, 'fingerprint', 'bb', 1, 1, 1)",
            [],
        )
        .expect("removal intent must not depend on a projection group row");
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_queued_outbound (id, group_id, created_at_ms, record)
             VALUES (?1, ?2, 0, ?3)",
            params![vec![0x02_u8; 4], orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities)
             VALUES (?1, ?2, ?3)",
            params![orphan_group, vec![0x03_u8; 4], vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_convergence_policies (group_id, policy)
             VALUES (?1, ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_member_validation_cache (group_id, marker)
             VALUES (?1, ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
        assert_foreign_key_error(conn.execute(
            "INSERT INTO cgka_group_snapshots (group_id, name, snapshot)
             VALUES (?1, 'anchor', ?2)",
            params![orphan_group, vec![0xAA_u8]],
        ));
    }

    #[test]
    fn foreign_key_migration_fails_hard_on_existing_orphans() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run(
            &mut conn,
            &[Migration {
                version: 1,
                name: "0001_initial_schema",
                apply: migration_0001_initial_schema::apply,
            }],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cgka_messages (id, group_id, epoch, state, record)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![vec![0x01_u8; 4], vec![0x99_u8; 4], vec![0xAA_u8]],
        )
        .unwrap();

        let result = run(
            &mut conn,
            &[
                Migration {
                    version: 1,
                    name: "0001_initial_schema",
                    apply: migration_0001_initial_schema::apply,
                },
                Migration {
                    version: 2,
                    name: "0002_account_device_signers",
                    apply: migration_0002_account_device_signers::apply,
                },
                Migration {
                    version: 3,
                    name: "0003_group_foreign_keys",
                    apply: migration_0003_group_foreign_keys::apply,
                },
            ],
        );

        assert!(result.is_err());
        assert_eq!(applied_name(&conn, 3).unwrap(), None);
    }

    #[test]
    fn rust_migrations_can_transform_existing_data() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let migrations = [
            Migration {
                version: 1,
                name: "0001_create_fixture",
                apply: |tx| {
                    tx.execute_batch(
                        "CREATE TABLE transform_fixture (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                         INSERT INTO transform_fixture (id, value) VALUES (1, 'needs-transform');",
                    )
                    .storage()
                },
            },
            Migration {
                version: 2,
                name: "0002_transform_fixture",
                apply: |tx| {
                    let value: String = tx
                        .query_row(
                            "SELECT value FROM transform_fixture WHERE id = 1",
                            [],
                            |row| row.get(0),
                        )
                        .storage()?;
                    tx.execute(
                        "UPDATE transform_fixture SET value = ?1 WHERE id = 1",
                        [value.replace("needs", "did")],
                    )
                    .storage()?;
                    Ok(())
                },
            },
        ];

        run(&mut conn, &migrations).unwrap();

        let transformed: String = conn
            .query_row(
                "SELECT value FROM transform_fixture WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(transformed, "did-transform");
    }

    fn foreign_key(
        conn: &rusqlite::Connection,
        table: &str,
        column: &str,
    ) -> Option<(String, String)> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA foreign_key_list({table})"))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(6)?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|(parent_table, from_column, on_delete)| {
            if from_column == column {
                Some((parent_table, on_delete))
            } else {
                None
            }
        })
    }

    fn assert_foreign_key_error(result: rusqlite::Result<usize>) {
        let err = result.expect_err("orphan insert should fail");
        assert!(
            err.to_string().contains("FOREIGN KEY constraint failed"),
            "unexpected error: {err}"
        );
    }

    fn applied_migrations_from_connection(conn: &rusqlite::Connection) -> Vec<(i64, String)> {
        let mut stmt = conn
            .prepare("SELECT version, name FROM cgka_schema_migrations ORDER BY version")
            .unwrap();
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn connection_has_column(conn: &rusqlite::Connection, table: &str, column: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>("name"))
            .unwrap()
            .any(|name| name.as_deref() == Ok(column))
    }

    fn column_default(conn: &rusqlite::Connection, table: &str, column: &str) -> Option<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>("name")?,
                row.get::<_, Option<String>>("dflt_value")?,
            ))
        })
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|(name, default)| if name == column { default } else { None })
    }

    fn connection_has_index(conn: &rusqlite::Connection, table: &str, index: &str) -> bool {
        let mut stmt = conn
            .prepare(&format!("PRAGMA index_list({table})"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>("name"))
            .unwrap()
            .any(|name| name.as_deref() == Ok(index))
    }
}

#[cfg(test)]
mod group_reset_tests {
    use super::*;

    #[test]
    fn permanent_forget_marker_migrates_to_awaiting_fresh_welcome() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..70]).unwrap();
        conn.execute(
            "INSERT INTO locally_forgotten_groups(group_id) VALUES (x'aa')",
            [],
        )
        .unwrap();
        let before = crate::codec::unix_now_seconds_i64();
        run(&mut conn, MIGRATIONS).unwrap();
        let (cutoff, awaiting): (i64, bool) = conn.query_row(
            "SELECT forgotten_at, awaiting_welcome FROM locally_forgotten_groups WHERE group_id = x'aa'",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert!(cutoff >= before && cutoff <= crate::codec::unix_now_seconds_i64());
        assert!(awaiting);
        assert!(
            conn.execute(
                "INSERT INTO cgka_groups(id, epoch, record) VALUES (x'aa', 0, x'00')",
                []
            )
            .is_err()
        );
        // Upgrading/reopening again must not advance the user's reset boundary.
        run(&mut conn, MIGRATIONS).unwrap();
        let unchanged: i64 = conn
            .query_row(
                "SELECT forgotten_at FROM locally_forgotten_groups WHERE group_id = x'aa'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, cutoff);
    }
}

#[cfg(test)]
mod content_reports_tests {
    use super::*;
    #[test]
    fn adds_reports_without_resetting_history_or_legacy_deletions() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        run(&mut conn, &MIGRATIONS[..78]).unwrap();
        for (id, kind, grant) in [
            ("chat", 9, 0),
            ("report", 1984, 0),
            ("label", 1985, 1),
            ("removal", 4891, 1),
            ("legacy-delete", 5, 1),
        ] {
            conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at,moderation_grant)
                VALUES('group',?1,'received','author','retained history',?2,'[]',1,1,?3)",rusqlite::params![id,kind,grant]).unwrap();
        }
        run(&mut conn, MIGRATIONS).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM app_events WHERE plaintext='retained history'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 5);
        let legacy:(i64,i64)=conn.query_row("SELECT moderation_grant,authority_state FROM app_events WHERE message_id_hex='legacy-delete'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(legacy, (1, 0));
        for id in ["label", "removal"] {
            let verdict: (i64, i64, Option<Vec<u8>>) = conn.query_row(
                "SELECT moderation_grant,authority_state,authority_context FROM app_events WHERE message_id_hex=?1",
                [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).unwrap();
            assert_eq!(verdict, (0, 1, None));
        }
        let report_state: i64 = conn
            .query_row(
                "SELECT authority_state FROM app_events WHERE message_id_hex='report'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(report_state, 0);
        let progress: (i64, i64) = conn
            .query_row(
                "SELECT after_order,through_order FROM content_report_backfill",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(progress, (0, 5));
        assert!(conn.prepare("SELECT * FROM content_moderation").is_err());
        assert!(
            conn.prepare("SELECT revision_id_hex FROM content_reports")
                .is_err()
        );
        assert!(
            conn.prepare("SELECT reporting_allowed FROM app_events")
                .is_err()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM app_events", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            5
        );
    }
}

#[cfg(test)]
mod deletion_provenance_tests {
    use super::*;

    #[test]
    fn deletion_provenance_migration_preserves_legacy_tombstones() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..81]).unwrap();
        conn.execute_batch(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, timeline_at, received_at, reactions_json, deleted,
                deleted_by_message_id_hex
            ) VALUES (
                'group', 'message', 'received', 'author', '', 9,
                '[]', 1, 1, '{}', 1, 'missing-evidence'
            );",
        )
        .unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let row: (bool, String, String, String) = conn
            .query_row(
                "SELECT deleted, plaintext, deleted_by_message_id_hex, deletion_source
             FROM message_timeline",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                true,
                String::new(),
                "missing-evidence".into(),
                "unknown".into()
            )
        );
        run(&mut conn, MIGRATIONS).unwrap();
    }
}

#[cfg(test)]
mod attachment_history_tests {
    use super::*;

    #[test]
    fn attachment_history_upgrade_indexes_existing_delivered_slots_and_tracks_removal() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..80]).unwrap();
        conn.execute_batch(r#"
            INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,
                direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
            VALUES('aa','old','source','received','alice','',9,'[]',1,2,'[]',
                '{"imeta":[["imeta","url https://example.com/a"],null]}');
        "#).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM attachment_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            count, 2,
            "legacy delivered slots, including a rejected slot, stay discoverable"
        );
        conn.execute(
            "UPDATE message_timeline SET deleted=1 WHERE message_id_hex='old'",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_history", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[cfg(test)]
mod poll_response_edge_tests {
    use super::*;

    #[test]
    fn poll_response_upgrade_backfills_edges_and_removes_legacy_timeline_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        let poll_migration = MIGRATIONS
            .iter()
            .position(|migration| migration.version == 90)
            .unwrap();
        run(&mut conn, &MIGRATIONS[..poll_migration]).unwrap();
        conn.execute_batch(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, recorded_at, received_at
             ) VALUES (
                'group', 'response', 'received', 'alice', '', 1018,
                '[[\"e\",\"poll\"],[\"response\",\"0\"]]', 2, 2
             );
             INSERT INTO message_timeline (
                group_id_hex, message_id_hex, direction, sender, plaintext, kind,
                tags_json, timeline_at, received_at, reactions_json
             ) VALUES (
                'group', 'response', 'received', 'alice', '', 1018,
                '[[\"e\",\"poll\"],[\"response\",\"0\"]]', 2, 2, '[]'
             );",
        )
        .unwrap();

        run(&mut conn, MIGRATIONS).unwrap();

        let edge: (String, String, i64) = conn
            .query_row(
                "SELECT modifier_message_id_hex, target_message_id_hex, kind
                 FROM message_modifier_edges",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(edge, ("response".into(), "poll".into(), 1018));
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM message_timeline WHERE kind = 1018",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM app_events WHERE kind = 1018",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            1
        );
    }
}
