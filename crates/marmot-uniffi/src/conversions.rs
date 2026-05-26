//! FFI-friendly value types and conversions from marmot-app's internal types.
//!
//! Internal Rust types that don't map cleanly to UniFFI (byte newtypes,
//! enums-of-structs with associated payloads, types that aren't `Send`) are
//! re-exposed as plain records/enums here. Conversion is one-way for now
//! (Rust → FFI). When the iOS side needs to round-trip data back into
//! marmot-app we'll add the reverse direction explicitly.

use std::collections::{HashMap, HashSet};

use cgka_traits::GroupId;
use marmot_app::{
    AccountKeyPackageRecord, AccountRelayListState, AccountRelayListStatus,
    AppGroupAdminPolicyComponent, AppGroupMemberRecord, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupProfileComponent, AppGroupRecord, AppMessageRecord,
    GroupInviteDeclineResult, GroupPushDebugInfo, GroupPushTokenDebugEntry,
    LocalPushRegistrationDebug, MarmotAppEvent, MediaDownloadResult, MediaReference,
    MediaUploadRequest, MediaUploadResult, NotificationCollectionStatus, NotificationSettings,
    NotificationTrigger, NotificationUpdate, NotificationUser, NotificationWakeSource,
    PushPlatform, PushRegistration, ReceivedMessage, RelayPlaneHealth, RuntimeAgentStreamUpdate,
    RuntimeMessageReceived, RuntimeMessageUpdate, SendSummary, UserProfileMetadata,
    account_id_hex_from_ref, npub_for_account_id,
};

use crate::errors::MarmotKitError;

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub running: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SendSummaryFfi {
    pub published: u32,
    pub message_ids: Vec<String>,
}

impl From<SendSummary> for SendSummaryFfi {
    fn from(value: SendSummary) -> Self {
        Self {
            published: value.published as u32,
            message_ids: value.message_ids,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountKeyPackageFfi {
    pub account_ref: Option<String>,
    pub account_id_hex: String,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub event_id_hex: String,
    pub published_at: u64,
    pub key_package_bytes: u64,
    pub source_relays: Vec<String>,
    pub local: bool,
    pub relay: bool,
}

impl From<AccountKeyPackageRecord> for AccountKeyPackageFfi {
    fn from(value: AccountKeyPackageRecord) -> Self {
        Self {
            account_ref: value.account_label,
            account_id_hex: value.account_id_hex,
            key_package_id: value.key_package_id,
            key_package_ref_hex: value.key_package_ref_hex,
            event_id_hex: value.key_package_event_id,
            published_at: value.published_at,
            key_package_bytes: value.key_package_bytes as u64,
            source_relays: value.source_relays,
            local: value.local,
            relay: value.relay,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PushPlatformFfi {
    Apns,
    Fcm,
}

impl From<PushPlatform> for PushPlatformFfi {
    fn from(value: PushPlatform) -> Self {
        match value {
            PushPlatform::Apns => Self::Apns,
            PushPlatform::Fcm => Self::Fcm,
        }
    }
}

impl From<PushPlatformFfi> for PushPlatform {
    fn from(value: PushPlatformFfi) -> Self {
        match value {
            PushPlatformFfi::Apns => Self::Apns,
            PushPlatformFfi::Fcm => Self::Fcm,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationWakeSourceFfi {
    ApnsNse,
    FcmDataMessage,
    AndroidForegroundService,
    ManualCatchUp,
}

impl From<NotificationWakeSourceFfi> for NotificationWakeSource {
    fn from(value: NotificationWakeSourceFfi) -> Self {
        match value {
            NotificationWakeSourceFfi::ApnsNse => Self::ApnsNse,
            NotificationWakeSourceFfi::FcmDataMessage => Self::FcmDataMessage,
            NotificationWakeSourceFfi::AndroidForegroundService => Self::AndroidForegroundService,
            NotificationWakeSourceFfi::ManualCatchUp => Self::ManualCatchUp,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationCollectionStatusFfi {
    NewData,
    NoData,
    Failed,
}

impl From<NotificationCollectionStatus> for NotificationCollectionStatusFfi {
    fn from(value: NotificationCollectionStatus) -> Self {
        match value {
            NotificationCollectionStatus::NewData => Self::NewData,
            NotificationCollectionStatus::NoData => Self::NoData,
            NotificationCollectionStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationTriggerFfi {
    NewMessage,
    GroupInvite,
}

impl From<NotificationTrigger> for NotificationTriggerFfi {
    fn from(value: NotificationTrigger) -> Self {
        match value {
            NotificationTrigger::NewMessage => Self::NewMessage,
            NotificationTrigger::GroupInvite => Self::GroupInvite,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationSettingsFfi {
    pub account_ref: String,
    pub account_id_hex: String,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
}

impl From<NotificationSettings> for NotificationSettingsFfi {
    fn from(value: NotificationSettings) -> Self {
        Self {
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PushRegistrationFfi {
    pub account_ref: String,
    pub account_id_hex: String,
    pub platform: PushPlatformFfi,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_shared_at_ms: Option<i64>,
}

impl From<PushRegistration> for PushRegistrationFfi {
    fn from(value: PushRegistration) -> Self {
        Self {
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            platform: value.platform.into(),
            token_fingerprint: value.token_fingerprint,
            server_pubkey_hex: value.server_pubkey_hex,
            relay_hint: value.relay_hint,
            created_at_ms: value.created_at_ms,
            updated_at_ms: value.updated_at_ms,
            last_shared_at_ms: value.last_shared_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationUserFfi {
    pub account_id_hex: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

impl From<NotificationUser> for NotificationUserFfi {
    fn from(value: NotificationUser) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            display_name: value.display_name,
            picture_url: value.picture_url,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationUpdateFfi {
    pub notification_key: String,
    pub conversation_key: String,
    pub trigger: NotificationTriggerFfi,
    pub account_ref: String,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub group_name: Option<String>,
    pub is_dm: bool,
    pub message_id_hex: Option<String>,
    pub sender: NotificationUserFfi,
    pub receiver: NotificationUserFfi,
    pub preview_text: Option<String>,
    pub timestamp_ms: i64,
    pub is_from_self: bool,
}

impl From<NotificationUpdate> for NotificationUpdateFfi {
    fn from(value: NotificationUpdate) -> Self {
        Self {
            notification_key: value.notification_key,
            conversation_key: value.conversation_key,
            trigger: value.trigger.into(),
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            group_id_hex: value.group_id_hex,
            group_name: value.group_name,
            is_dm: value.is_dm,
            message_id_hex: value.message_id_hex,
            sender: value.sender.into(),
            receiver: value.receiver.into(),
            preview_text: value.preview_text,
            timestamp_ms: value.timestamp_ms,
            is_from_self: value.is_from_self,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct BackgroundNotificationCollectionFfi {
    pub status: NotificationCollectionStatusFfi,
    pub notifications: Vec<NotificationUpdateFfi>,
    pub error: Option<String>,
}

impl From<marmot_app::BackgroundNotificationCollection> for BackgroundNotificationCollectionFfi {
    fn from(value: marmot_app::BackgroundNotificationCollection) -> Self {
        Self {
            status: value.status.into(),
            notifications: value.notifications.into_iter().map(Into::into).collect(),
            error: value.error,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct LocalPushRegistrationDebugFfi {
    pub registered: bool,
    pub shareable: bool,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
    pub local_leaf_index: Option<u32>,
    pub local_token_cached: bool,
}

impl From<LocalPushRegistrationDebug> for LocalPushRegistrationDebugFfi {
    fn from(value: LocalPushRegistrationDebug) -> Self {
        Self {
            registered: value.registered,
            shareable: value.shareable,
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
            local_leaf_index: value.local_leaf_index,
            local_token_cached: value.local_token_cached,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupPushTokenDebugEntryFfi {
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: PushPlatformFfi,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub has_relay_hint: bool,
    pub active_leaf: bool,
    pub member_matches_active_leaf: bool,
    pub is_local_member: bool,
    pub updated_at_ms: i64,
}

impl From<GroupPushTokenDebugEntry> for GroupPushTokenDebugEntryFfi {
    fn from(value: GroupPushTokenDebugEntry) -> Self {
        Self {
            member_id_hex: value.member_id_hex,
            leaf_index: value.leaf_index,
            platform: value.platform.into(),
            token_fingerprint: value.token_fingerprint,
            server_pubkey_hex: value.server_pubkey_hex,
            has_relay_hint: value.has_relay_hint,
            active_leaf: value.active_leaf,
            member_matches_active_leaf: value.member_matches_active_leaf,
            is_local_member: value.is_local_member,
            updated_at_ms: value.updated_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupPushDebugInfoFfi {
    pub total_token_count: u32,
    pub active_token_count: u32,
    pub stale_token_count: u32,
    pub missing_relay_hint_count: u32,
    pub last_token_list_updated_at_ms: Option<i64>,
    pub local_registration: LocalPushRegistrationDebugFfi,
    pub tokens: Vec<GroupPushTokenDebugEntryFfi>,
}

impl From<GroupPushDebugInfo> for GroupPushDebugInfoFfi {
    fn from(value: GroupPushDebugInfo) -> Self {
        Self {
            total_token_count: value.total_token_count,
            active_token_count: value.active_token_count,
            stale_token_count: value.stale_token_count,
            missing_relay_hint_count: value.missing_relay_hint_count,
            last_token_list_updated_at_ms: value.last_token_list_updated_at_ms,
            local_registration: value.local_registration.into(),
            tokens: value.tokens.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaReferenceFfi {
    pub url: String,
    pub file_hash_hex: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: String,
}

impl From<MediaReference> for MediaReferenceFfi {
    fn from(value: MediaReference) -> Self {
        Self {
            url: value.url,
            file_hash_hex: value.file_hash_hex,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
        }
    }
}

impl From<MediaReferenceFfi> for MediaReference {
    fn from(value: MediaReferenceFfi) -> Self {
        Self {
            url: value.url,
            file_hash_hex: value.file_hash_hex,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadRequestFfi {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
}

impl From<MediaUploadRequestFfi> for MediaUploadRequest {
    fn from(value: MediaUploadRequestFfi) -> Self {
        Self {
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            caption: value.caption,
            send: value.send,
            blossom_server: value.blossom_server,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadResultFfi {
    pub reference: MediaReferenceFfi,
    pub encrypted_hash_hex: String,
    pub encrypted_size_bytes: u64,
    pub sent: Option<SendSummaryFfi>,
}

impl From<MediaUploadResult> for MediaUploadResultFfi {
    fn from(value: MediaUploadResult) -> Self {
        Self {
            reference: value.reference.into(),
            encrypted_hash_hex: value.encrypted_hash_hex,
            encrypted_size_bytes: value.encrypted_size_bytes,
            sent: value.sent.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaDownloadResultFfi {
    pub plaintext: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

impl From<MediaDownloadResult> for MediaDownloadResultFfi {
    fn from(value: MediaDownloadResult) -> Self {
        Self {
            plaintext: value.plaintext,
            file_name: value.file_name,
            media_type: value.media_type,
            size_bytes: value.size_bytes,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaRecordFfi {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub reference: MediaReferenceFfi,
    pub caption: Option<String>,
    pub recorded_at: u64,
    pub received_at: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AgentStreamStartFfi {
    pub stream_id_hex: String,
    pub published: u32,
    pub message_ids: Vec<String>,
}

impl AgentStreamStartFfi {
    pub(crate) fn new(stream_id_hex: String, summary: SendSummary) -> Self {
        Self {
            stream_id_hex,
            published: summary.published as u32,
            message_ids: summary.message_ids,
        }
    }
}

/// One update from a live agent-text-stream watch. `Chunk.text` is an
/// incremental fragment; `Finished.text` is the complete transcript.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum AgentStreamUpdateFfi {
    Chunk {
        seq: u64,
        text: String,
    },
    Finished {
        text: String,
        transcript_hash_hex: String,
        chunk_count: u64,
    },
    Failed {
        message: String,
    },
}

impl From<RuntimeAgentStreamUpdate> for AgentStreamUpdateFfi {
    fn from(value: RuntimeAgentStreamUpdate) -> Self {
        match value {
            RuntimeAgentStreamUpdate::Chunk { seq, text } => Self::Chunk { seq, text },
            RuntimeAgentStreamUpdate::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            } => Self::Finished {
                text,
                transcript_hash_hex,
                chunk_count,
            },
            RuntimeAgentStreamUpdate::Failed { message } => Self::Failed { message },
        }
    }
}

/// One Nostr tag from an inner Marmot app event, e.g. `["e", "<id>"]` or an
/// `["imeta", …]` media descriptor. Host apps branch on the inner event `kind`
/// plus these tags instead of a fixed payload enum.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageTagFfi {
    pub values: Vec<String>,
}

fn message_tags_ffi(tags: Vec<Vec<String>>) -> Vec<MessageTagFfi> {
    tags.into_iter()
        .map(|values| MessageTagFfi { values })
        .collect()
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppMessageRecordFfi {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event (9 chat, 7 reaction, …).
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl From<AppMessageRecord> for AppMessageRecordFfi {
    fn from(value: AppMessageRecord) -> Self {
        Self {
            message_id_hex: value.message_id_hex,
            direction: value.direction,
            group_id_hex: value.group_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            kind: value.kind,
            tags: message_tags_ffi(value.tags),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

pub(crate) fn media_records_ffi(messages: Vec<AppMessageRecord>) -> Vec<MediaRecordFfi> {
    messages
        .into_iter()
        .filter_map(|message| {
            let reference = media_reference_from_tags(&message.tags)?;
            let caption = (!message.plaintext.is_empty()).then_some(message.plaintext);
            Some(MediaRecordFfi {
                message_id_hex: message.message_id_hex,
                direction: message.direction,
                group_id_hex: message.group_id_hex,
                sender: message.sender,
                reference,
                caption,
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            })
        })
        .collect()
}

fn media_reference_from_tags(tags: &[Vec<String>]) -> Option<MediaReferenceFfi> {
    let fields = tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .map(|tag| {
            tag.iter()
                .skip(1)
                .filter_map(|field| field.split_once(' '))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect::<HashMap<_, _>>()
        })?;
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
    };
    Some(MediaReferenceFfi {
        url: required("url")?,
        file_hash_hex: required("x")?,
        nonce_hex: required("n")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
    })
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupRecordFfi {
    pub group_id_hex: String,
    pub endpoint: String,
    pub name: String,
    pub description: String,
    pub admins: Vec<String>,
    pub relays: Vec<String>,
    pub nostr_group_id_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub welcomer_account_id_hex: Option<String>,
    pub via_welcome_message_id_hex: Option<String>,
}

impl From<AppGroupRecord> for AppGroupRecordFfi {
    fn from(value: AppGroupRecord) -> Self {
        let AppGroupProfileComponent {
            name, description, ..
        } = value.profile;
        let AppGroupAdminPolicyComponent { admins, .. } = value.admin_policy;
        let AppGroupNostrRoutingComponent {
            nostr_group_id_hex,
            relays,
            ..
        } = value.nostr_routing;
        Self {
            group_id_hex: value.group_id_hex,
            endpoint: value.endpoint,
            name,
            description,
            admins,
            relays,
            nostr_group_id_hex,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            welcomer_account_id_hex: value.welcomer_account_id_hex,
            via_welcome_message_id_hex: value.via_welcome_message_id_hex,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupMemberRecordFfi {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
}

impl From<AppGroupMemberRecord> for AppGroupMemberRecordFfi {
    fn from(value: AppGroupMemberRecord) -> Self {
        Self {
            member_id_hex: value.member_id_hex,
            account: value.account,
            local: value.local,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MemberRefFfi {
    pub member_ref: String,
    pub account_id_hex: String,
    pub npub: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMemberDetailsFfi {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
    pub is_admin: bool,
    pub is_self: bool,
    pub npub: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupDetailsFfi {
    pub group: AppGroupRecordFfi,
    pub members: Vec<GroupMemberDetailsFfi>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMemberActionStateFfi {
    pub member_id_hex: String,
    pub is_self: bool,
    pub is_admin: bool,
    pub can_remove: bool,
    pub can_promote: bool,
    pub can_demote: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupManagementStateFfi {
    pub my_account_id_hex: String,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_invite: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    pub member_actions: Vec<GroupMemberActionStateFfi>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMutationResultFfi {
    pub summary: SendSummaryFfi,
    pub details: GroupDetailsFfi,
    pub management_state: GroupManagementStateFfi,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupInviteDeclineResultFfi {
    pub group: AppGroupRecordFfi,
    pub summary: SendSummaryFfi,
}

impl From<GroupInviteDeclineResult> for GroupInviteDeclineResultFfi {
    fn from(value: GroupInviteDeclineResult) -> Self {
        Self {
            group: value.group.into(),
            summary: value.summary.into(),
        }
    }
}

pub(crate) fn normalize_member_ref_ffi(member_ref: &str) -> Result<MemberRefFfi, MarmotKitError> {
    let canonical = canonical_member_ref_input(member_ref);
    let account_id_hex =
        account_id_hex_from_ref(&canonical).map_err(|err| MarmotKitError::InvalidIdentity {
            details: err.to_string(),
        })?;
    let npub =
        npub_for_account_id(&account_id_hex).map_err(|err| MarmotKitError::InvalidIdentity {
            details: err.to_string(),
        })?;
    Ok(MemberRefFfi {
        member_ref: account_id_hex.clone(),
        account_id_hex,
        npub,
    })
}

fn canonical_member_ref_input(member_ref: &str) -> String {
    let trimmed = member_ref.trim();
    let without_nostr = trimmed.strip_prefix("nostr:").unwrap_or(trimmed);
    let without_profile = without_nostr
        .strip_prefix("darkmatter://profile/")
        .unwrap_or(without_nostr);
    without_profile
        .split(['?', '#'])
        .next()
        .unwrap_or(without_profile)
        .trim_matches('/')
        .trim()
        .to_string()
}

pub(crate) fn group_details_ffi(
    group: AppGroupRecordFfi,
    members: Vec<AppGroupMemberRecordFfi>,
    my_account_id_hex: &str,
    display_names: HashMap<String, String>,
) -> Result<GroupDetailsFfi, MarmotKitError> {
    let admin_ids = group.admins.iter().cloned().collect::<HashSet<_>>();
    let members = members
        .into_iter()
        .map(|member| {
            let npub = npub_for_account_id(&member.member_id_hex).map_err(|err| {
                MarmotKitError::InvalidIdentity {
                    details: err.to_string(),
                }
            })?;
            Ok(GroupMemberDetailsFfi {
                is_admin: admin_ids.contains(&member.member_id_hex),
                is_self: member.member_id_hex == my_account_id_hex,
                display_name: display_names.get(&member.member_id_hex).cloned(),
                npub,
                member_id_hex: member.member_id_hex,
                account: member.account,
                local: member.local,
            })
        })
        .collect::<Result<Vec<_>, MarmotKitError>>()?;
    Ok(GroupDetailsFfi { group, members })
}

pub(crate) fn group_management_state_ffi(
    my_account_id_hex: &str,
    details: &GroupDetailsFfi,
) -> GroupManagementStateFfi {
    let admin_count = details
        .members
        .iter()
        .filter(|member| member.is_admin)
        .count();
    let self_member = details
        .members
        .iter()
        .find(|member| member.member_id_hex == my_account_id_hex);
    let is_self_admin = self_member.is_some_and(|member| member.is_admin);
    let is_last_admin = is_self_admin && admin_count == 1;
    let can_invite = is_self_admin;
    let can_leave = self_member.is_some() && !is_self_admin;
    let requires_self_demote_before_leave = self_member.is_some() && is_self_admin;
    let member_actions = details
        .members
        .iter()
        .map(|member| {
            let would_remove_last_admin = member.is_admin && admin_count == 1;
            GroupMemberActionStateFfi {
                member_id_hex: member.member_id_hex.clone(),
                is_self: member.is_self,
                is_admin: member.is_admin,
                can_remove: is_self_admin && !member.is_self && !would_remove_last_admin,
                can_promote: is_self_admin && !member.is_admin,
                can_demote: is_self_admin
                    && member.is_admin
                    && !member.is_self
                    && !would_remove_last_admin,
            }
        })
        .collect();
    GroupManagementStateFfi {
        my_account_id_hex: my_account_id_hex.to_string(),
        is_self_admin,
        is_last_admin,
        can_invite,
        can_leave,
        requires_self_demote_before_leave,
        member_actions,
    }
}

/// MLS-level group state for the conversation's developer/debug view: the
/// current epoch, live member count, and the app components the group requires.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupMlsStateFfi {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_count: u32,
    pub required_app_components: Vec<u16>,
}

impl From<AppGroupMlsState> for AppGroupMlsStateFfi {
    fn from(value: AppGroupMlsState) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            epoch: value.epoch,
            member_count: value.member_count as u32,
            required_app_components: value.required_app_components,
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct UserProfileMetadataFfi {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub nip05: Option<String>,
    pub lud16: Option<String>,
}

impl From<UserProfileMetadata> for UserProfileMetadataFfi {
    fn from(value: UserProfileMetadata) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
        }
    }
}

impl From<UserProfileMetadataFfi> for UserProfileMetadata {
    fn from(value: UserProfileMetadataFfi) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
            created_at: 0,
            source_relays: vec![],
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ReceivedMessageFfi {
    pub message_id_hex: String,
    pub group_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
}

impl From<&ReceivedMessage> for ReceivedMessageFfi {
    fn from(value: &ReceivedMessage) -> Self {
        Self {
            message_id_hex: value.message_id_hex.clone(),
            group_id_hex: hex::encode(value.group_id.as_slice()),
            sender: value.sender.clone(),
            sender_display_name: value.sender_display_name.clone(),
            plaintext: value.plaintext.clone(),
            kind: value.kind,
            tags: message_tags_ffi(value.tags.clone()),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RuntimeMessageReceivedFfi {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessageFfi,
}

impl From<RuntimeMessageReceived> for RuntimeMessageReceivedFfi {
    fn from(value: RuntimeMessageReceived) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            account_label: value.account_label,
            message: ReceivedMessageFfi::from(&value.message),
        }
    }
}

/// A unified update from a messages subscription. Each variant carries enough
/// context for host apps to update an in-memory timeline without holding
/// onto the underlying marmot-app types.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MessageUpdateFfi {
    /// A timeline message: chat, reply, media, reaction, delete, or the kind-9
    /// stream-final. Host apps branch on `received.message.kind` and `tags`; a
    /// kind-9 carrying a `stream` tag is the stream-final that replaces the
    /// ephemeral preview.
    Message { received: RuntimeMessageReceivedFfi },
    /// A kind-1200 agent text stream start — the signal to open the QUIC
    /// preview. Its stream id, route, and brokers live on `message.tags`.
    AgentStreamStarted { received: RuntimeMessageReceivedFfi },
}

impl From<RuntimeMessageUpdate> for MessageUpdateFfi {
    fn from(value: RuntimeMessageUpdate) -> Self {
        match value {
            RuntimeMessageUpdate::Message(m) => Self::Message { received: m.into() },
            RuntimeMessageUpdate::AgentStreamStarted(m) => Self::AgentStreamStarted {
                received: RuntimeMessageReceivedFfi {
                    account_id_hex: m.account_id_hex,
                    account_label: m.account_label,
                    message: ReceivedMessageFfi::from(&m.message),
                },
            },
        }
    }
}

/// Top-level event firehose, FFI-shaped. Agent streams collapse to a single
/// "agent stream activity" variant — host apps do not differentiate them at
/// the surface level for v1.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MarmotEventFfi {
    GroupJoined {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    GroupStateUpdated {
        account_id_hex: String,
        account_label: String,
        group_id_hex: String,
    },
    MessageReceived {
        received: RuntimeMessageReceivedFfi,
    },
    GroupEvent {
        account_id_hex: String,
        account_label: String,
    },
    AccountError {
        account_id_hex: String,
        account_label: String,
        message: String,
    },
    AgentStreamActivity {
        account_id_hex: String,
        account_label: String,
    },
}

impl From<MarmotAppEvent> for MarmotEventFfi {
    fn from(value: MarmotAppEvent) -> Self {
        match value {
            MarmotAppEvent::GroupJoined {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupJoined {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id,
            } => Self::GroupStateUpdated {
                account_id_hex,
                account_label,
                group_id_hex: hex::encode(group_id.as_slice()),
            },
            MarmotAppEvent::MessageReceived(m) => Self::MessageReceived { received: m.into() },
            MarmotAppEvent::GroupEvent(e) => Self::GroupEvent {
                account_id_hex: e.account_id_hex,
                account_label: e.account_label,
            },
            MarmotAppEvent::AccountError(e) => Self::AccountError {
                account_id_hex: e.account_id_hex,
                account_label: e.account_label,
                message: e.message,
            },
            MarmotAppEvent::AgentStreamStarted(m) => Self::AgentStreamActivity {
                account_id_hex: m.account_id_hex,
                account_label: m.account_label,
            },
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayListFfi {
    pub kind: u64,
    pub relays: Vec<String>,
}

impl From<AccountRelayListState> for RelayListFfi {
    fn from(value: AccountRelayListState) -> Self {
        Self {
            kind: value.kind,
            relays: value.relays,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountRelayListsFfi {
    pub complete: bool,
    pub missing: Vec<String>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: RelayListFfi,
    pub inbox: RelayListFfi,
    pub key_package: RelayListFfi,
}

impl From<AccountRelayListStatus> for AccountRelayListsFfi {
    fn from(value: AccountRelayListStatus) -> Self {
        Self {
            complete: value.complete,
            missing: value.missing,
            default_relays: value.default_relays,
            bootstrap_relays: value.bootstrap_relays,
            nip65: value.nip65.into(),
            inbox: value.inbox.into(),
            key_package: value.key_package.into(),
        }
    }
}

/// Live relay-plane connection health for the diagnostics view.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayHealthFfi {
    pub sdk_backed: bool,
    pub total_relays: u32,
    pub initialized: u32,
    pub pending: u32,
    pub connecting: u32,
    pub connected: u32,
    pub disconnected: u32,
    pub terminated: u32,
    pub banned: u32,
    pub sleeping: u32,
    pub connection_attempts: u32,
    pub connection_successes: u32,
}

impl From<RelayPlaneHealth> for RelayHealthFfi {
    fn from(value: RelayPlaneHealth) -> Self {
        Self {
            sdk_backed: value.sdk_backed,
            total_relays: value.total_relays as u32,
            initialized: value.initialized as u32,
            pending: value.pending as u32,
            connecting: value.connecting as u32,
            connected: value.connected as u32,
            disconnected: value.disconnected as u32,
            terminated: value.terminated as u32,
            banned: value.banned as u32,
            sleeping: value.sleeping as u32,
            connection_attempts: value.connection_attempts as u32,
            connection_successes: value.connection_successes as u32,
        }
    }
}

/// Decode a hex-encoded group id back into the engine's byte newtype.
pub fn group_id_from_hex(group_id_hex: &str) -> Result<GroupId, crate::errors::MarmotKitError> {
    let bytes =
        hex::decode(group_id_hex).map_err(|err| crate::errors::MarmotKitError::InvalidHex {
            details: err.to_string(),
        })?;
    Ok(GroupId::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(admins: Vec<&str>) -> AppGroupRecordFfi {
        AppGroupRecordFfi {
            group_id_hex: "01".repeat(32),
            endpoint: "marmot:group:01".into(),
            name: "Test".into(),
            description: String::new(),
            admins: admins.into_iter().map(ToOwned::to_owned).collect(),
            relays: vec![],
            nostr_group_id_hex: "02".repeat(32),
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
        }
    }

    fn member(member_id_hex: &str, is_admin: bool, is_self: bool) -> GroupMemberDetailsFfi {
        GroupMemberDetailsFfi {
            member_id_hex: member_id_hex.to_owned(),
            account: None,
            local: is_self,
            is_admin,
            is_self,
            npub: "npub1placeholder".into(),
            display_name: None,
        }
    }

    #[test]
    fn group_management_state_marks_last_admin_self_demote_requirement() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let bob_id = "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![self_id]),
            members: vec![member(self_id, true, true), member(bob_id, false, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(state.is_self_admin);
        assert!(state.is_last_admin);
        assert!(state.can_invite);
        assert!(!state.can_leave);
        assert!(state.requires_self_demote_before_leave);
        let self_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == self_id)
            .expect("self action");
        assert!(!self_action.can_remove);
        assert!(!self_action.can_demote);
        let bob_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == bob_id)
            .expect("bob action");
        assert!(bob_action.can_remove);
        assert!(bob_action.can_promote);
        assert!(!bob_action.can_demote);
    }

    #[test]
    fn group_management_state_allows_demoting_another_admin_when_one_remains() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let bob_id = "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![self_id, bob_id]),
            members: vec![member(self_id, true, true), member(bob_id, true, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(state.is_self_admin);
        assert!(!state.is_last_admin);
        let bob_action = state
            .member_actions
            .iter()
            .find(|action| action.member_id_hex == bob_id)
            .expect("bob action");
        assert!(bob_action.can_remove);
        assert!(!bob_action.can_promote);
        assert!(bob_action.can_demote);
    }

    #[test]
    fn group_management_state_keeps_non_admin_self_to_leave_only() {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let alice_id = "cc4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let details = GroupDetailsFfi {
            group: group(vec![alice_id]),
            members: vec![member(self_id, false, true), member(alice_id, true, false)],
        };

        let state = group_management_state_ffi(self_id, &details);

        assert!(!state.is_self_admin);
        assert!(!state.is_last_admin);
        assert!(!state.can_invite);
        assert!(state.can_leave);
        assert!(!state.requires_self_demote_before_leave);
        assert!(
            state
                .member_actions
                .iter()
                .all(|action| !action.can_remove && !action.can_promote && !action.can_demote)
        );
    }
}
