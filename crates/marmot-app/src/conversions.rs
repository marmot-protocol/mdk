//! Mechanical mappers between `storage_sqlite` `Stored*` types and this crate's
//! app-facing DTOs.
//!
//! These are pure, stateless conversions for account state, groups, group
//! components, messages, app events, notification/push registrations, and
//! telemetry/audit settings. They hold no `MarmotApp` state.

use crate::error::AppError;
use crate::notifications;
use crate::{
    AGENT_TEXT_STREAM_COMPONENT_ID, AccountState, AppAgentTextStreamComponent,
    AppGroupAdminPolicyComponent, AppGroupAvatarUrlComponent, AppGroupEncryptedMediaComponent,
    AppGroupImageInput, AppGroupMessageRetentionComponent, AppGroupNostrRoutingComponent,
    AppGroupRecord, AppMessageProjection, AppMessageRecord, AuditLogSettings,
    GROUP_AVATAR_URL_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GroupPushTokenRecord, NOSTR_ROUTING_COMPONENT_ID,
    NotificationSettings, PushPlatform, PushRegistration, RelayTelemetrySettings,
};
use storage_sqlite::{
    AccountGroupPushToken, AccountNotificationSettings, AccountPushRegistration,
    AccountStoredPushRegistration, StoredAccountGroup, StoredAccountGroupComponent,
    StoredAccountState, StoredAppEvent, StoredAppMessageRecord, StoredAuditLogSettings,
    StoredRelayTelemetrySettings,
};

pub(crate) fn stored_state_from_account_state(state: &AccountState) -> StoredAccountState {
    StoredAccountState {
        label: state.label.clone(),
        seen_events: state.seen_events.clone(),
        last_transport_timestamp: state.last_transport_timestamp,
        groups: state
            .groups
            .iter()
            .map(stored_group_from_app_group)
            .collect(),
    }
}

pub(crate) fn account_state_from_stored(
    stored: StoredAccountState,
) -> Result<AccountState, AppError> {
    Ok(AccountState {
        label: stored.label,
        seen_events: stored.seen_events,
        last_transport_timestamp: stored.last_transport_timestamp,
        groups: stored
            .groups
            .into_iter()
            .map(app_group_from_stored_group)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn stored_group_from_app_group(group: &AppGroupRecord) -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: group.group_id_hex.clone(),
        endpoint: group.endpoint.clone(),
        profile_name: group.profile.name.clone(),
        profile_description: group.profile.description.clone(),
        image_hash_hex: group.image.image_hash_hex.clone(),
        image_key_hex: group.image.image_key_hex.clone(),
        image_nonce_hex: group.image.image_nonce_hex.clone(),
        image_upload_key_hex: group.image.image_upload_key_hex.clone(),
        image_media_type: group.image.media_type.clone(),
        admin_keys_hex: group.admin_policy.admins.join(","),
        archived: group.archived,
        pending_confirmation: group.pending_confirmation,
        // Ignored by the projection save (owned by `set_group_self_membership`);
        // carried for struct completeness and round-trip symmetry.
        self_membership: group.self_membership,
        welcomer_account_id_hex: group.welcomer_account_id_hex.clone(),
        via_welcome_message_id_hex: group.via_welcome_message_id_hex.clone(),
        components: stored_components_from_app_group(group),
    }
}

pub(crate) fn stored_components_from_app_group(
    group: &AppGroupRecord,
) -> Vec<StoredAccountGroupComponent> {
    let mut components = vec![
        StoredAccountGroupComponent {
            component_id: group.profile.component_id,
            component_name: group.profile.component.clone(),
            component_data_hex: group.profile.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.image.component_id,
            component_name: group.image.component.clone(),
            component_data_hex: group.image.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.admin_policy.component_id,
            component_name: group.admin_policy.component.clone(),
            component_data_hex: group.admin_policy.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.message_retention.component_id,
            component_name: group.message_retention.component.clone(),
            component_data_hex: group.message_retention.data_hex.clone(),
        },
        StoredAccountGroupComponent {
            component_id: group.nostr_routing.component_id,
            component_name: group.nostr_routing.component.clone(),
            component_data_hex: group.nostr_routing.data_hex.clone(),
        },
    ];
    if group.agent_text_stream.required {
        components.push(StoredAccountGroupComponent {
            component_id: group.agent_text_stream.component_id,
            component_name: group.agent_text_stream.component.clone(),
            component_data_hex: group.agent_text_stream.data_hex.clone(),
        });
    }
    if group.avatar_url.present {
        components.push(StoredAccountGroupComponent {
            component_id: group.avatar_url.component_id,
            component_name: group.avatar_url.component.clone(),
            component_data_hex: group.avatar_url.data_hex.clone(),
        });
    }
    if group.encrypted_media.required {
        components.push(StoredAccountGroupComponent {
            component_id: group.encrypted_media.component_id,
            component_name: group.encrypted_media.component.clone(),
            component_data_hex: group.encrypted_media.data_hex.clone(),
        });
    }
    components
}

pub(crate) fn app_group_from_stored_group(
    stored: StoredAccountGroup,
) -> Result<AppGroupRecord, AppError> {
    let routing_bytes = hex::decode(
        account_component_data_hex(&stored.components, NOSTR_ROUTING_COMPONENT_ID).ok_or_else(
            || AppError::InvalidNostrRouting("stored group is missing routing".into()),
        )?,
    )?;
    let retention =
        account_component_data_hex(&stored.components, GROUP_MESSAGE_RETENTION_COMPONENT_ID)
            .map(hex::decode)
            .transpose()?
            .map(|bytes| AppGroupMessageRetentionComponent::from_bytes(&bytes))
            .unwrap_or_else(AppGroupMessageRetentionComponent::disabled);
    let mut group = AppGroupRecord::new(
        stored.group_id_hex,
        AppGroupNostrRoutingComponent::from_bytes(&routing_bytes)?,
        stored.profile_name,
        stored.profile_description,
        AppGroupImageInput {
            image_hash_hex: stored.image_hash_hex,
            image_key_hex: stored.image_key_hex,
            image_nonce_hex: stored.image_nonce_hex,
            image_upload_key_hex: stored.image_upload_key_hex,
            media_type: stored.image_media_type,
        },
        AppGroupAdminPolicyComponent::new(parse_admin_keys_hex(&stored.admin_keys_hex)),
        retention,
    );
    if let Some(agent_hex) =
        account_component_data_hex(&stored.components, AGENT_TEXT_STREAM_COMPONENT_ID)
        && !agent_hex.is_empty()
    {
        let agent_bytes = hex::decode(agent_hex)?;
        group.agent_text_stream = AppAgentTextStreamComponent::from_bytes(&agent_bytes);
    }
    if let Some(avatar_hex) =
        account_component_data_hex(&stored.components, GROUP_AVATAR_URL_COMPONENT_ID)
        && !avatar_hex.is_empty()
    {
        let avatar_bytes = hex::decode(avatar_hex)?;
        group.avatar_url = AppGroupAvatarUrlComponent::from_bytes(&avatar_bytes);
    }
    if let Some(media_hex) =
        account_component_data_hex(&stored.components, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID)
        && !media_hex.is_empty()
    {
        let media_bytes = hex::decode(media_hex)?;
        group.encrypted_media = AppGroupEncryptedMediaComponent::from_bytes(&media_bytes);
    }
    group.archived = stored.archived;
    group.pending_confirmation = stored.pending_confirmation;
    group.self_membership = stored.self_membership;
    group.welcomer_account_id_hex = stored.welcomer_account_id_hex;
    group.via_welcome_message_id_hex = stored.via_welcome_message_id_hex;
    Ok(group)
}

pub(crate) fn account_component_data_hex(
    components: &[StoredAccountGroupComponent],
    component_id: u16,
) -> Option<&str> {
    components
        .iter()
        .find(|component| component.component_id == component_id)
        .map(|component| component.component_data_hex.as_str())
}

pub(crate) fn parse_admin_keys_hex(value: &str) -> Vec<[u8; 32]> {
    value
        .split(',')
        .filter_map(|key| {
            let bytes = hex::decode(key).ok()?;
            let array: [u8; 32] = bytes.try_into().ok()?;
            Some(array)
        })
        .collect()
}

pub(crate) fn app_message_record_from_stored(record: StoredAppMessageRecord) -> AppMessageRecord {
    AppMessageRecord {
        message_id_hex: record.message_id_hex,
        direction: record.direction,
        group_id_hex: record.group_id_hex,
        sender: record.sender,
        plaintext: record.plaintext,
        kind: record.kind,
        tags: record.tags,
        source_epoch: record.source_epoch,
        recorded_at: record.recorded_at,
        received_at: record.received_at,
        insert_order: record.insert_order,
    }
}

pub(crate) fn stored_app_event_from_projection(
    message: &AppMessageProjection,
    received_at: u64,
) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: message.group_id_hex.clone(),
        message_id_hex: message.message_id_hex.clone(),
        source_message_id_hex: message.source_message_id_hex.clone(),
        direction: message.direction.clone(),
        sender: message.sender.clone(),
        plaintext: message.plaintext.clone(),
        kind: message.kind,
        tags: message.tags.clone(),
        source_epoch: message.source_epoch,
        recorded_at: message.recorded_at.unwrap_or(received_at),
        received_at,
        origin_commit_id: message.origin_commit_id.clone(),
    }
}

pub(crate) fn stored_app_event_from_message_record(record: &AppMessageRecord) -> StoredAppEvent {
    StoredAppEvent {
        group_id_hex: record.group_id_hex.clone(),
        message_id_hex: record.message_id_hex.clone(),
        source_message_id_hex: None,
        direction: record.direction.clone(),
        sender: record.sender.clone(),
        plaintext: record.plaintext.clone(),
        kind: record.kind,
        tags: record.tags.clone(),
        source_epoch: record.source_epoch,
        recorded_at: record.recorded_at,
        received_at: record.received_at,
        origin_commit_id: None,
    }
}

pub(crate) fn notification_settings_from_account(
    settings: AccountNotificationSettings,
) -> NotificationSettings {
    NotificationSettings {
        account_ref: settings.account_label,
        account_id_hex: settings.account_id_hex,
        local_notifications_enabled: settings.local_notifications_enabled,
        native_push_enabled: settings.native_push_enabled,
    }
}

pub(crate) fn relay_telemetry_settings_from_storage(
    settings: StoredRelayTelemetrySettings,
) -> RelayTelemetrySettings {
    RelayTelemetrySettings {
        export_enabled: settings.export_enabled,
        export_interval_seconds: settings.export_interval_seconds,
    }
}

pub(crate) fn relay_telemetry_settings_to_storage(
    settings: RelayTelemetrySettings,
) -> StoredRelayTelemetrySettings {
    StoredRelayTelemetrySettings {
        export_enabled: settings.export_enabled,
        export_interval_seconds: settings.export_interval_seconds,
    }
}

pub(crate) fn audit_log_settings_from_storage(
    settings: StoredAuditLogSettings,
) -> AuditLogSettings {
    AuditLogSettings {
        enabled: settings.enabled,
        data_mode: audit_data_mode_from_token(&settings.data_mode),
    }
}

pub(crate) fn audit_log_settings_to_storage(settings: AuditLogSettings) -> StoredAuditLogSettings {
    StoredAuditLogSettings {
        enabled: settings.enabled,
        data_mode: audit_data_mode_token(settings.data_mode).to_owned(),
    }
}

/// Parse a stored audit data-mode token into the typed mode, mapping any
/// unknown/legacy token to the safe obfuscated default.
fn audit_data_mode_from_token(token: &str) -> marmot_forensics::AuditDataMode {
    match token {
        "full_data" => marmot_forensics::AuditDataMode::FullData,
        _ => marmot_forensics::AuditDataMode::ObfuscatedSensitiveData,
    }
}

/// The canonical storage token for an audit data mode (matches the forensics
/// enum's serde string).
fn audit_data_mode_token(mode: marmot_forensics::AuditDataMode) -> &'static str {
    match mode {
        marmot_forensics::AuditDataMode::FullData => "full_data",
        marmot_forensics::AuditDataMode::ObfuscatedSensitiveData => "obfuscated_sensitive_data",
    }
}

pub(crate) fn normalize_relay_telemetry_settings(
    settings: RelayTelemetrySettings,
) -> Result<RelayTelemetrySettings, AppError> {
    settings
        .validate()
        .map_err(AppError::InvalidRelayTelemetrySettings)?;
    Ok(settings)
}

pub(crate) fn account_push_registration_from_app(
    registration: PushRegistration,
) -> AccountPushRegistration {
    AccountPushRegistration {
        account_label: registration.account_ref,
        account_id_hex: registration.account_id_hex,
        platform: registration.platform.platform_byte(),
        token_fingerprint: registration.token_fingerprint,
        server_pubkey_hex: registration.server_pubkey_hex,
        relay_hint: registration.relay_hint,
        created_at_ms: registration.created_at_ms,
        updated_at_ms: registration.updated_at_ms,
        last_shared_at_ms: registration.last_shared_at_ms,
    }
}

pub(crate) fn stored_push_registration_from_account(
    stored: AccountStoredPushRegistration,
) -> Result<notifications::StoredPushRegistration, AppError> {
    Ok(notifications::StoredPushRegistration {
        registration: PushRegistration {
            account_ref: stored.registration.account_label,
            account_id_hex: stored.registration.account_id_hex,
            platform: PushPlatform::from_platform_byte(stored.registration.platform)?,
            token_fingerprint: stored.registration.token_fingerprint,
            server_pubkey_hex: stored.registration.server_pubkey_hex,
            relay_hint: stored.registration.relay_hint,
            created_at_ms: stored.registration.created_at_ms,
            updated_at_ms: stored.registration.updated_at_ms,
            last_shared_at_ms: stored.registration.last_shared_at_ms,
        },
        token_bytes: stored.token_bytes,
    })
}

pub(crate) fn account_group_push_token_from_app(
    token: &GroupPushTokenRecord,
) -> AccountGroupPushToken {
    AccountGroupPushToken {
        group_id_hex: token.group_id_hex.clone(),
        member_id_hex: token.member_id_hex.clone(),
        leaf_index: token.leaf_index,
        platform: token.platform.platform_byte(),
        token_fingerprint: token.token_fingerprint.clone(),
        server_pubkey_hex: token.server_pubkey_hex.clone(),
        relay_hint: token.relay_hint.clone(),
        encrypted_token: token.encrypted_token.clone(),
        owner_ts: token.owner_ts,
        owner_sig: token.owner_sig.clone(),
        // Stored so the storage layer can compare ordering stamps without the
        // crypto code. Recomputed from the record's owner-signed bytes;
        // best-effort because legacy/placeholder records may carry non-canonical
        // fields — owner-verified gossip records always produce a real digest.
        record_digest: token.record_digest().unwrap_or_default(),
        updated_at_ms: token.updated_at_ms,
    }
}

pub(crate) fn group_push_token_from_account(
    token: AccountGroupPushToken,
) -> Result<GroupPushTokenRecord, AppError> {
    Ok(GroupPushTokenRecord {
        group_id_hex: token.group_id_hex,
        member_id_hex: token.member_id_hex,
        leaf_index: token.leaf_index,
        platform: PushPlatform::from_platform_byte(token.platform)?,
        token_fingerprint: token.token_fingerprint,
        server_pubkey_hex: token.server_pubkey_hex,
        relay_hint: token.relay_hint,
        encrypted_token: token.encrypted_token,
        owner_ts: token.owner_ts,
        owner_sig: token.owner_sig,
        updated_at_ms: token.updated_at_ms,
    })
}
