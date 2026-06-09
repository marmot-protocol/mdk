//! FFI-friendly value types and conversions from marmot-app's internal types.
//!
//! Internal Rust types that don't map cleanly to UniFFI (byte newtypes,
//! enums-of-structs with associated payloads, types that aren't `Send`) are
//! re-exposed as plain records/enums here. Conversion is one-way for now
//! (Rust → FFI). When the iOS side needs to round-trip data back into
//! marmot-app we'll add the reverse direction explicitly.

use std::collections::{HashMap, HashSet};

use cgka_traits::{GroupId, app_event::MARMOT_APP_EVENT_KIND_CHAT};
use marmot_app::{
    AccountKeyPackageRecord, AccountRelayListState, AccountRelayListStatus, AppBlobEndpoint,
    AppGroupAdminPolicyComponent, AppGroupEncryptedMediaComponent, AppGroupMemberRecord,
    AppGroupMlsState, AppGroupNostrRoutingComponent, AppGroupProfileComponent, AppGroupRecord,
    AppMessageRecord, AppProjectionUpdate, AuditLogFile, AuditLogSettings, AuditLogTrackerConfig,
    AuditLogTrackerUpdateResult, AuditLogUploadResult, AuditLogUploadSource, ChatListAvatar,
    ChatListMessagePreview, ChatListRow, GroupInviteDeclineResult, GroupPushDebugInfo,
    GroupPushTokenDebugEntry, LocalPushRegistrationDebug, MarmotAppEvent, MediaAttachmentReference,
    MediaDownloadResult, MediaLocator, MediaUploadAttachmentRequest, MediaUploadRequest,
    MediaUploadResult, NotificationCollectionStatus, NotificationSettings, NotificationTrigger,
    NotificationUpdate, NotificationUser, NotificationWakeSource, PushPlatform, PushRegistration,
    ReceivedMessage, RelayPlaneHealth, RelayTelemetryResource, RelayTelemetryRuntimeConfig,
    RelayTelemetrySettings, RuntimeAgentStreamUpdate, RuntimeChatListUpdate,
    RuntimeMessageReceived, RuntimeMessageUpdate, RuntimeProjectionUpdate,
    RuntimeTimelineMessageUpdate, SendSummary, TimelineMessageChange, TimelineMessageRecord,
    TimelinePage, TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview,
    TimelineUpdateTrigger, TimelineUserReaction, UserProfileMetadata, account_id_hex_from_ref,
    npub_for_account_id,
};

use crate::errors::MarmotKitError;
use crate::markdown::{MarkdownDocumentFfi, parse_markdown_document};

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogFileFfi {
    pub account_ref: String,
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

impl From<AuditLogFile> for AuditLogFileFfi {
    fn from(value: AuditLogFile) -> Self {
        Self {
            account_ref: value.account_ref,
            path: value.path,
            file_name: value.file_name,
            size_bytes: value.size_bytes,
            modified_at_ms: value.modified_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogUploadResultFfi {
    pub path: String,
    pub status: u16,
    pub bytes_sent: u64,
}

impl From<AuditLogUploadResult> for AuditLogUploadResultFfi {
    fn from(value: AuditLogUploadResult) -> Self {
        Self {
            path: value.path,
            status: value.status,
            bytes_sent: value.bytes_sent,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogTrackerUpdateResultFfi {
    pub enabled: bool,
    pub uploaded: Vec<AuditLogUploadResultFfi>,
    pub skipped_reason: Option<String>,
}

impl From<AuditLogTrackerUpdateResult> for AuditLogTrackerUpdateResultFfi {
    fn from(value: AuditLogTrackerUpdateResult) -> Self {
        Self {
            enabled: value.enabled,
            uploaded: value.uploaded.into_iter().map(Into::into).collect(),
            skipped_reason: value.skipped_reason,
        }
    }
}

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
pub struct RelayTelemetrySettingsFfi {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

impl From<RelayTelemetrySettings> for RelayTelemetrySettingsFfi {
    fn from(value: RelayTelemetrySettings) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

impl From<RelayTelemetrySettingsFfi> for RelayTelemetrySettings {
    fn from(value: RelayTelemetrySettingsFfi) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetryResourceFfi {
    pub service_version: String,
    pub service_instance_id: String,
    pub deployment_environment: String,
    pub tenant: String,
    pub os_type: String,
    pub os_version: String,
    pub device_model_identifier: Option<String>,
}

impl From<RelayTelemetryResourceFfi> for RelayTelemetryResource {
    fn from(value: RelayTelemetryResourceFfi) -> Self {
        Self {
            service_version: value.service_version,
            service_instance_id: value.service_instance_id,
            deployment_environment: value.deployment_environment,
            tenant: value.tenant,
            os_type: value.os_type,
            os_version: value.os_version,
            device_model_identifier: value.device_model_identifier,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetryRuntimeConfigFfi {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResourceFfi>,
}

impl From<RelayTelemetryRuntimeConfigFfi> for RelayTelemetryRuntimeConfig {
    fn from(value: RelayTelemetryRuntimeConfigFfi) -> Self {
        Self {
            otlp_endpoint: value.otlp_endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            resource: value.resource.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogSettingsFfi {
    pub enabled: bool,
}

impl From<AuditLogSettings> for AuditLogSettingsFfi {
    fn from(value: AuditLogSettings) -> Self {
        Self {
            enabled: value.enabled,
        }
    }
}

impl From<AuditLogSettingsFfi> for AuditLogSettings {
    fn from(value: AuditLogSettingsFfi) -> Self {
        Self {
            enabled: value.enabled,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogUploadSourceFfi {
    pub account_label: Option<String>,
    pub device_label: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
}

impl From<AuditLogUploadSourceFfi> for AuditLogUploadSource {
    fn from(value: AuditLogUploadSourceFfi) -> Self {
        Self {
            account_label: value.account_label,
            device_label: value.device_label,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

impl From<AuditLogUploadSource> for AuditLogUploadSourceFfi {
    fn from(value: AuditLogUploadSource) -> Self {
        Self {
            account_label: value.account_label,
            device_label: value.device_label,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogTrackerConfigFfi {
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub source: AuditLogUploadSourceFfi,
}

impl From<AuditLogTrackerConfigFfi> for AuditLogTrackerConfig {
    fn from(value: AuditLogTrackerConfigFfi) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            source: value.source.into(),
        }
    }
}

impl From<AuditLogTrackerConfig> for AuditLogTrackerConfigFfi {
    fn from(value: AuditLogTrackerConfig) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            source: value.source.into(),
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
pub struct MediaLocatorFfi {
    pub kind: String,
    pub value: String,
}

impl From<MediaLocator> for MediaLocatorFfi {
    fn from(value: MediaLocator) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

impl From<MediaLocatorFfi> for MediaLocator {
    fn from(value: MediaLocatorFfi) -> Self {
        Self {
            kind: value.kind,
            value: value.value,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaAttachmentReferenceFfi {
    pub locators: Vec<MediaLocatorFfi>,
    pub ciphertext_sha256: String,
    pub plaintext_sha256: String,
    pub nonce_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub version: String,
    pub source_epoch: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaAttachmentReference> for MediaAttachmentReferenceFfi {
    fn from(value: MediaAttachmentReference) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

impl From<MediaAttachmentReferenceFfi> for MediaAttachmentReference {
    fn from(value: MediaAttachmentReferenceFfi) -> Self {
        Self {
            locators: value.locators.into_iter().map(Into::into).collect(),
            ciphertext_sha256: value.ciphertext_sha256,
            plaintext_sha256: value.plaintext_sha256,
            nonce_hex: value.nonce_hex,
            file_name: value.file_name,
            media_type: value.media_type,
            version: value.version,
            source_epoch: value.source_epoch,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentRequestFfi {
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl From<MediaUploadAttachmentRequestFfi> for MediaUploadAttachmentRequest {
    fn from(value: MediaUploadAttachmentRequestFfi) -> Self {
        Self {
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            dim: value.dim,
            thumbhash: value.thumbhash,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadRequestFfi {
    pub attachments: Vec<MediaUploadAttachmentRequestFfi>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
}

impl From<MediaUploadRequestFfi> for MediaUploadRequest {
    fn from(value: MediaUploadRequestFfi) -> Self {
        Self {
            attachments: value.attachments.into_iter().map(Into::into).collect(),
            caption: value.caption,
            send: value.send,
            blossom_server: value.blossom_server,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadAttachmentResultFfi {
    pub reference: MediaAttachmentReferenceFfi,
    pub encrypted_size_bytes: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MediaUploadResultFfi {
    pub attachments: Vec<MediaUploadAttachmentResultFfi>,
    pub sent: Option<SendSummaryFfi>,
}

impl From<MediaUploadResult> for MediaUploadResultFfi {
    fn from(value: MediaUploadResult) -> Self {
        Self {
            attachments: value
                .attachments
                .into_iter()
                .map(|attachment| MediaUploadAttachmentResultFfi {
                    reference: attachment.reference.into(),
                    encrypted_size_bytes: attachment.encrypted_size_bytes,
                })
                .collect(),
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
    pub attachment_index: u32,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub reference: MediaAttachmentReferenceFfi,
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
    Status {
        seq: u64,
        status: String,
    },
    Progress {
        seq: u64,
        text: String,
    },
    Record {
        seq: u64,
        record_type: u8,
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
            RuntimeAgentStreamUpdate::Status { seq, status } => Self::Status { seq, status },
            RuntimeAgentStreamUpdate::Progress { seq, text } => Self::Progress { seq, text },
            RuntimeAgentStreamUpdate::Record {
                seq,
                record_type,
                text,
            } => Self::Record {
                seq,
                record_type,
                text,
            },
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

fn markdown_content_tokens(kind: u64, plaintext: &str) -> MarkdownDocumentFfi {
    if kind == MARMOT_APP_EVENT_KIND_CHAT {
        parse_markdown_document(plaintext)
    } else {
        MarkdownDocumentFfi::default()
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppMessageRecordFfi {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    /// Nostr `kind` of the inner Marmot app event (9 chat, 7 reaction, …).
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl From<AppMessageRecord> for AppMessageRecordFfi {
    fn from(value: AppMessageRecord) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            direction: value.direction,
            group_id_hex: value.group_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            tags: message_tags_ffi(value.tags),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListAvatarFfi {
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
}

impl From<ChatListAvatar> for ChatListAvatarFfi {
    fn from(value: ChatListAvatar) -> Self {
        Self {
            image_hash_hex: value.image_hash_hex,
            image_key_hex: value.image_key_hex,
            image_nonce_hex: value.image_nonce_hex,
            image_upload_key_hex: value.image_upload_key_hex,
            media_type: value.media_type,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListMessagePreviewFfi {
    pub message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
}

impl From<ChatListMessagePreview> for ChatListMessagePreviewFfi {
    fn from(value: ChatListMessagePreview) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            sender: value.sender,
            sender_display_name: value.sender_display_name,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            timeline_at: value.timeline_at,
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListRowFfi {
    pub group_id_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub title: String,
    pub group_name: String,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatarFfi>,
    pub last_message: Option<ChatListMessagePreviewFfi>,
    pub unread_count: u64,
    pub has_unread: bool,
    pub first_unread_message_id_hex: Option<String>,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    pub updated_at: u64,
}

impl From<ChatListRow> for ChatListRowFfi {
    fn from(value: ChatListRow) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            title: value.title,
            group_name: value.group_name,
            avatar_url: value.avatar_url,
            avatar: value.avatar.map(Into::into),
            last_message: value.last_message.map(Into::into),
            unread_count: value.unread_count,
            has_unread: value.has_unread,
            first_unread_message_id_hex: value.first_unread_message_id_hex,
            last_read_message_id_hex: value.last_read_message_id_hex,
            last_read_timeline_at: value.last_read_timeline_at,
            updated_at: value.updated_at,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ChatListSubscriptionUpdateFfi {
    Row {
        trigger: ChatListUpdateTriggerFfi,
        row: ChatListRowFfi,
    },
    RemoveRow {
        trigger: ChatListUpdateTriggerFfi,
        group_id_hex: String,
    },
}

impl From<RuntimeChatListUpdate> for ChatListSubscriptionUpdateFfi {
    fn from(value: RuntimeChatListUpdate) -> Self {
        match value {
            RuntimeChatListUpdate::Row { trigger, row } => Self::Row {
                trigger: trigger.into(),
                row: (*row).into(),
            },
            RuntimeChatListUpdate::RemoveRow {
                trigger,
                group_id_hex,
            } => Self::RemoveRow {
                trigger: trigger.into(),
                group_id_hex,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ChatListUpdateTriggerFfi {
    NewGroup,
    NewLastMessage,
    LastMessageDeleted,
    ArchiveChanged,
    PendingConfirmationChanged,
    MembershipChanged,
    UnreadChanged,
    SnapshotRefresh,
    Removed,
}

impl From<marmot_app::ChatListUpdateTrigger> for ChatListUpdateTriggerFfi {
    fn from(value: marmot_app::ChatListUpdateTrigger) -> Self {
        match value {
            marmot_app::ChatListUpdateTrigger::NewGroup => Self::NewGroup,
            marmot_app::ChatListUpdateTrigger::NewLastMessage => Self::NewLastMessage,
            marmot_app::ChatListUpdateTrigger::LastMessageDeleted => Self::LastMessageDeleted,
            marmot_app::ChatListUpdateTrigger::ArchiveChanged => Self::ArchiveChanged,
            marmot_app::ChatListUpdateTrigger::PendingConfirmationChanged => {
                Self::PendingConfirmationChanged
            }
            marmot_app::ChatListUpdateTrigger::MembershipChanged => Self::MembershipChanged,
            marmot_app::ChatListUpdateTrigger::UnreadChanged => Self::UnreadChanged,
            marmot_app::ChatListUpdateTrigger::SnapshotRefresh => Self::SnapshotRefresh,
            marmot_app::ChatListUpdateTrigger::Removed => Self::Removed,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReactionEmojiFfi {
    pub emoji: String,
    pub senders: Vec<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineUserReactionFfi {
    pub reaction_message_id_hex: String,
    pub target_message_id_hex: String,
    pub sender: String,
    pub emoji: String,
    pub reacted_at: u64,
}

impl From<TimelineUserReaction> for TimelineUserReactionFfi {
    fn from(value: TimelineUserReaction) -> Self {
        Self {
            reaction_message_id_hex: value.reaction_message_id_hex,
            target_message_id_hex: value.target_message_id_hex,
            sender: value.sender,
            emoji: value.emoji,
            reacted_at: value.reacted_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReactionSummaryFfi {
    pub by_emoji: Vec<TimelineReactionEmojiFfi>,
    pub user_reactions: Vec<TimelineUserReactionFfi>,
}

impl From<TimelineReactionSummary> for TimelineReactionSummaryFfi {
    fn from(value: TimelineReactionSummary) -> Self {
        Self {
            by_emoji: value
                .by_emoji
                .into_iter()
                .map(|(emoji, senders)| TimelineReactionEmojiFfi { emoji, senders })
                .collect(),
            user_reactions: value.user_reactions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct TimelineMessageQueryFfi {
    pub group_id_hex: Option<String>,
    pub search: Option<String>,
    pub before: Option<u64>,
    pub before_message_id: Option<String>,
    pub after: Option<u64>,
    pub after_message_id: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReplyPreviewFfi {
    pub message_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub media_json: Option<String>,
    pub agent_text_stream_json: Option<String>,
    pub deleted: bool,
}

impl From<TimelineReplyPreview> for TimelineReplyPreviewFfi {
    fn from(value: TimelineReplyPreview) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            media_json: value.media.map(|media| media.to_string()),
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineMessageRecordFfi {
    pub message_id_hex: String,
    pub source_message_id_hex: Option<String>,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub tags: Vec<MessageTagFfi>,
    pub timeline_at: u64,
    pub received_at: u64,
    pub reply_to_message_id_hex: Option<String>,
    pub reply_preview: Option<TimelineReplyPreviewFfi>,
    pub media_json: Option<String>,
    pub agent_text_stream_json: Option<String>,
    pub reactions: TimelineReactionSummaryFfi,
    pub deleted: bool,
    pub deleted_by_message_id_hex: Option<String>,
    /// Set when convergence invalidated this message (it landed on a losing
    /// branch). The message is kept as a "did not reach the group" tombstone
    /// instead of disappearing; the value is the engine invalidation reason
    /// (e.g. `LosingBranch`). `None` for delivered messages.
    pub invalidation_status: Option<String>,
}

impl From<TimelineMessageRecord> for TimelineMessageRecordFfi {
    fn from(value: TimelineMessageRecord) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            source_message_id_hex: value.source_message_id_hex,
            direction: value.direction,
            group_id_hex: value.group_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            tags: message_tags_ffi(value.tags),
            timeline_at: value.timeline_at,
            received_at: value.received_at,
            reply_to_message_id_hex: value.reply_to_message_id_hex,
            reply_preview: value.reply_preview.map(Into::into),
            media_json: value.media.map(|media| media.to_string()),
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            reactions: value.reactions.into(),
            deleted: value.deleted,
            deleted_by_message_id_hex: value.deleted_by_message_id_hex,
            invalidation_status: value.invalidation_status,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelinePageFfi {
    pub messages: Vec<TimelineMessageRecordFfi>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

impl From<TimelinePage> for TimelinePageFfi {
    fn from(value: TimelinePage) -> Self {
        Self {
            messages: value.messages.into_iter().map(Into::into).collect(),
            has_more_before: value.has_more_before,
            has_more_after: value.has_more_after,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum TimelineMessageChangeFfi {
    Upsert {
        trigger: TimelineUpdateTriggerFfi,
        message: TimelineMessageRecordFfi,
    },
    Remove {
        message_id_hex: String,
        reason: TimelineRemoveReasonFfi,
    },
}

impl From<TimelineMessageChange> for TimelineMessageChangeFfi {
    fn from(value: TimelineMessageChange) -> Self {
        match value {
            TimelineMessageChange::Upsert { trigger, message } => Self::Upsert {
                trigger: trigger.into(),
                message: (*message).into(),
            },
            TimelineMessageChange::Remove {
                message_id_hex,
                reason,
            } => Self::Remove {
                message_id_hex,
                reason: reason.into(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum TimelineUpdateTriggerFfi {
    NewMessage,
    MessageEditedOrReprojected,
    ReactionAdded,
    ReactionRemoved,
    MessageDeleted,
    ReplyPreviewChanged,
    AgentStreamStarted,
    AgentStreamFinished,
    AgentActivity,
    AgentOperation,
    GroupSystem,
    DeliveryOrSendStateChanged,
    ReceiptChanged,
    SnapshotRefresh,
}

impl From<TimelineUpdateTrigger> for TimelineUpdateTriggerFfi {
    fn from(value: TimelineUpdateTrigger) -> Self {
        match value {
            TimelineUpdateTrigger::NewMessage => Self::NewMessage,
            TimelineUpdateTrigger::MessageEditedOrReprojected => Self::MessageEditedOrReprojected,
            TimelineUpdateTrigger::ReactionAdded => Self::ReactionAdded,
            TimelineUpdateTrigger::ReactionRemoved => Self::ReactionRemoved,
            TimelineUpdateTrigger::MessageDeleted => Self::MessageDeleted,
            TimelineUpdateTrigger::ReplyPreviewChanged => Self::ReplyPreviewChanged,
            TimelineUpdateTrigger::AgentStreamStarted => Self::AgentStreamStarted,
            TimelineUpdateTrigger::AgentStreamFinished => Self::AgentStreamFinished,
            TimelineUpdateTrigger::AgentActivity => Self::AgentActivity,
            TimelineUpdateTrigger::AgentOperation => Self::AgentOperation,
            TimelineUpdateTrigger::GroupSystem => Self::GroupSystem,
            TimelineUpdateTrigger::DeliveryOrSendStateChanged => Self::DeliveryOrSendStateChanged,
            TimelineUpdateTrigger::ReceiptChanged => Self::ReceiptChanged,
            TimelineUpdateTrigger::SnapshotRefresh => Self::SnapshotRefresh,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum TimelineRemoveReasonFfi {
    Invalidated,
    Cleared,
    Pruned,
    NoLongerMatchesQuery,
}

impl From<TimelineRemoveReason> for TimelineRemoveReasonFfi {
    fn from(value: TimelineRemoveReason) -> Self {
        match value {
            TimelineRemoveReason::Invalidated => Self::Invalidated,
            TimelineRemoveReason::Cleared => Self::Cleared,
            TimelineRemoveReason::Pruned => Self::Pruned,
            TimelineRemoveReason::NoLongerMatchesQuery => Self::NoLongerMatchesQuery,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineProjectionUpdateFfi {
    pub group_id_hex: String,
    pub messages: Vec<TimelineMessageRecordFfi>,
    pub changes: Vec<TimelineMessageChangeFfi>,
    pub chat_list_row: Option<ChatListRowFfi>,
    pub chat_list_trigger: ChatListUpdateTriggerFfi,
}

impl From<AppProjectionUpdate> for TimelineProjectionUpdateFfi {
    fn from(value: AppProjectionUpdate) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            messages: value
                .timeline_messages
                .into_iter()
                .map(Into::into)
                .collect(),
            changes: value.timeline_changes.into_iter().map(Into::into).collect(),
            chat_list_row: value.chat_list_row.map(Into::into),
            chat_list_trigger: value.chat_list_trigger.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RuntimeProjectionUpdateFfi {
    pub account_id_hex: String,
    pub account_label: String,
    pub update: TimelineProjectionUpdateFfi,
}

impl From<RuntimeProjectionUpdate> for RuntimeProjectionUpdateFfi {
    fn from(value: RuntimeProjectionUpdate) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            account_label: value.account_label,
            update: value.update.into(),
        }
    }
}

// FFI enum: variants carry rich payloads by value because UniFFI doesn't
// support `Box` in the wire format — boxing here would not satisfy the lint
// in practice and would force every host language to dereference.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum TimelineSubscriptionUpdateFfi {
    Page { page: TimelinePageFfi },
    Projection { update: RuntimeProjectionUpdateFfi },
}

impl From<RuntimeTimelineMessageUpdate> for TimelineSubscriptionUpdateFfi {
    fn from(value: RuntimeTimelineMessageUpdate) -> Self {
        match value {
            RuntimeTimelineMessageUpdate::Page { page } => Self::Page { page: page.into() },
            RuntimeTimelineMessageUpdate::Projection(update) => Self::Projection {
                update: update.into(),
            },
        }
    }
}

pub(crate) fn media_records_ffi(messages: Vec<AppMessageRecord>) -> Vec<MediaRecordFfi> {
    let mut records = Vec::new();
    for message in messages {
        let caption = (!message.plaintext.is_empty()).then_some(message.plaintext.clone());
        for (attachment_index, reference) in media_attachments_from_message(&message)
            .into_iter()
            .enumerate()
        {
            records.push(MediaRecordFfi {
                message_id_hex: message.message_id_hex.clone(),
                attachment_index: attachment_index.try_into().unwrap_or(u32::MAX),
                direction: message.direction.clone(),
                group_id_hex: message.group_id_hex.clone(),
                sender: message.sender.clone(),
                reference: reference.into(),
                caption: caption.clone(),
                recorded_at: message.recorded_at,
                received_at: message.received_at,
            });
        }
    }
    records
}

fn media_attachments_from_message(message: &AppMessageRecord) -> Vec<MediaAttachmentReference> {
    message
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| media_attachment_from_imeta_tag(tag, message.source_epoch))
        .collect()
}

fn media_attachment_from_imeta_tag(
    tag: &[String],
    source_epoch: Option<u64>,
) -> Option<MediaAttachmentReference> {
    let mut locators = Vec::new();
    let mut fields = HashMap::new();
    for field in tag.iter().skip(1) {
        if field.starts_with("blurhash ") {
            return None;
        }
        if let Some(rest) = field.strip_prefix("locator ") {
            let (kind, value) = rest.split_once(' ')?;
            locators.push(MediaLocator {
                kind: kind.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }
        if let Some((key, value)) = field.split_once(' ') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }
    let required = |key: &str| {
        fields
            .get(key)
            .cloned()
            .filter(|value| !value.trim().is_empty())
    };
    Some(MediaAttachmentReference {
        locators,
        ciphertext_sha256: required("ciphertext_sha256")?,
        plaintext_sha256: required("plaintext_sha256")?,
        nonce_hex: required("nonce")?,
        file_name: required("filename")?,
        media_type: required("m")?,
        version: required("v")?,
        source_epoch: source_epoch.unwrap_or_default(),
        dim: fields.get("dim").cloned(),
        thumbhash: fields.get("thumbhash").cloned(),
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
    /// URL-based group avatar (`marmot.group.avatar-url.v1`), `None` when absent.
    /// When set it takes precedence over a Blossom image avatar.
    pub avatar_url: Option<String>,
    pub avatar_dim: Option<String>,
    pub avatar_thumbhash: Option<String>,
    pub encrypted_media: AppGroupEncryptedMediaComponentFfi,
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
        let avatar = value.avatar_url;
        Self {
            group_id_hex: value.group_id_hex,
            endpoint: value.endpoint,
            name,
            description,
            admins,
            relays,
            nostr_group_id_hex,
            avatar_url: avatar.present.then_some(avatar.url),
            avatar_dim: avatar.dim,
            avatar_thumbhash: avatar.thumbhash,
            encrypted_media: value.encrypted_media.into(),
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            welcomer_account_id_hex: value.welcomer_account_id_hex,
            via_welcome_message_id_hex: value.via_welcome_message_id_hex,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppBlobEndpointFfi {
    pub locator_kind: String,
    pub base_url: String,
}

impl From<AppBlobEndpoint> for AppBlobEndpointFfi {
    fn from(value: AppBlobEndpoint) -> Self {
        Self {
            locator_kind: value.locator_kind,
            base_url: value.base_url,
        }
    }
}

impl From<AppBlobEndpointFfi> for AppBlobEndpoint {
    fn from(value: AppBlobEndpointFfi) -> Self {
        Self {
            locator_kind: value.locator_kind,
            base_url: value.base_url,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupEncryptedMediaComponentFfi {
    pub component_id: u32,
    pub component: String,
    pub required: bool,
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<AppBlobEndpointFfi>,
}

impl From<AppGroupEncryptedMediaComponent> for AppGroupEncryptedMediaComponentFfi {
    fn from(value: AppGroupEncryptedMediaComponent) -> Self {
        Self {
            component_id: u32::from(value.component_id),
            component: value.component,
            required: value.required,
            media_format: value.media_format,
            allowed_locator_kinds: value.allowed_locator_kinds,
            default_blob_endpoints: value
                .default_blob_endpoints
                .into_iter()
                .map(Into::into)
                .collect(),
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
    pub content_tokens: MarkdownDocumentFfi,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
    /// Source-event timestamp (seconds since epoch) for the MLS-delivered
    /// message. Clients should sort the timeline by this value so chronology
    /// reflects send time, not delivery time. Zero means the timestamp was
    /// unavailable at decode time.
    pub recorded_at: u64,
}

impl From<&ReceivedMessage> for ReceivedMessageFfi {
    fn from(value: &ReceivedMessage) -> Self {
        Self {
            message_id_hex: value.message_id_hex.clone(),
            group_id_hex: hex::encode(value.group_id.as_slice()),
            sender: value.sender.clone(),
            sender_display_name: value.sender_display_name.clone(),
            plaintext: value.plaintext.clone(),
            content_tokens: markdown_content_tokens(value.kind, &value.plaintext),
            kind: value.kind,
            tags: message_tags_ffi(value.tags.clone()),
            recorded_at: value.recorded_at,
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
    /// A raw message update: chat, reply, media, reaction, delete, or the kind-9
    /// stream-final. Materialized timeline pages also include kind-1200 stream
    /// starts as `TimelineMessageRecordFfi` rows.
    Message { received: RuntimeMessageReceivedFfi },
    /// A kind-1200 agent text stream start — the signal to open the QUIC
    /// preview for raw message subscribers. Its stream id, route, and brokers
    /// live on `message.tags`.
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
// FFI enum: see `TimelineSubscriptionUpdateFfi` — UniFFI lowers each variant
// by value, so boxing wouldn't change the wire size.
#[allow(clippy::large_enum_variant)]
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
    ProjectionUpdated {
        update: RuntimeProjectionUpdateFfi,
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
            MarmotAppEvent::ProjectionUpdated(update) => Self::ProjectionUpdated {
                update: update.into(),
            },
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
    use crate::markdown::{MarkdownBlockFfi, MarkdownInlineFfi};
    use std::collections::BTreeMap;

    fn group(admins: Vec<&str>) -> AppGroupRecordFfi {
        AppGroupRecordFfi {
            group_id_hex: "01".repeat(32),
            endpoint: "marmot:group:01".into(),
            name: "Test".into(),
            description: String::new(),
            admins: admins.into_iter().map(ToOwned::to_owned).collect(),
            relays: vec![],
            nostr_group_id_hex: "02".repeat(32),
            avatar_url: None,
            avatar_dim: None,
            avatar_thumbhash: None,
            encrypted_media: AppGroupEncryptedMediaComponentFfi {
                component_id: 0x8008,
                component: "marmot.group.encrypted-media.v1".into(),
                required: true,
                media_format: "encrypted-media-v1".into(),
                allowed_locator_kinds: vec!["blossom-v1".into()],
                default_blob_endpoints: vec![AppBlobEndpointFfi {
                    locator_kind: "blossom-v1".into(),
                    base_url: "https://blossom.primal.net".into(),
                }],
            },
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
    fn timeline_message_record_ffi_preserves_materialized_metadata() {
        let record = TimelineMessageRecord {
            message_id_hex: "message-1".to_owned(),
            source_message_id_hex: Some("source-1".to_owned()),
            source_epoch: Some(7),
            direction: "received".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: "hello".to_owned(),
            kind: 9,
            tags: vec![vec!["q".to_owned(), "parent".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: Some("parent".to_owned()),
            reply_preview: Some(TimelineReplyPreview {
                message_id_hex: "parent".to_owned(),
                sender: "bb".repeat(32),
                plaintext: "parent text".to_owned(),
                kind: 9,
                media: None,
                agent_text_stream: None,
                deleted: false,
            }),
            media: Some(serde_json::json!({
                "imeta": [["imeta", "url https://blob.example/file"]]
            })),
            agent_text_stream: Some(serde_json::json!({
                "stream_id_hex": "22"
            })),
            reactions: TimelineReactionSummary {
                by_emoji: BTreeMap::from([("+".to_owned(), vec!["bob".to_owned()])]),
                user_reactions: vec![TimelineUserReaction {
                    reaction_message_id_hex: "reaction-1".to_owned(),
                    target_message_id_hex: "message-1".to_owned(),
                    sender: "bob".to_owned(),
                    emoji: "+".to_owned(),
                    reacted_at: 12,
                }],
            },
            deleted: true,
            deleted_by_message_id_hex: Some("delete-1".to_owned()),
            invalidation_status: None,
        };

        let page = TimelinePageFfi::from(TimelinePage {
            messages: vec![record],
            has_more_before: true,
            has_more_after: false,
        });

        assert!(page.has_more_before);
        assert!(!page.has_more_after);
        let message = &page.messages[0];
        assert_eq!(message.message_id_hex, "message-1");
        assert_eq!(message.source_message_id_hex.as_deref(), Some("source-1"));
        assert_eq!(message.reply_to_message_id_hex.as_deref(), Some("parent"));
        assert!(matches!(
            &message.content_tokens.blocks[0],
            MarkdownBlockFfi::Paragraph { inlines }
                if matches!(
                    &inlines[0],
                    MarkdownInlineFfi::Text { content } if content == "hello"
                )
        ));
        let preview = message.reply_preview.as_ref().expect("reply preview");
        assert_eq!(preview.message_id_hex, "parent");
        assert_eq!(preview.sender, "bb".repeat(32));
        assert_eq!(preview.plaintext, "parent text");
        assert!(matches!(
            &preview.content_tokens.blocks[0],
            MarkdownBlockFfi::Paragraph { inlines }
                if matches!(
                    &inlines[0],
                    MarkdownInlineFfi::Text { content } if content == "parent text"
                )
        ));
        assert!(!preview.deleted);
        assert_eq!(message.tags[0].values, vec!["q", "parent"]);
        assert_eq!(
            message.media_json.as_deref(),
            Some(r#"{"imeta":[["imeta","url https://blob.example/file"]]}"#)
        );
        assert_eq!(
            message.agent_text_stream_json.as_deref(),
            Some(r#"{"stream_id_hex":"22"}"#)
        );
        assert_eq!(message.reactions.by_emoji[0].emoji, "+");
        assert_eq!(message.reactions.by_emoji[0].senders, vec!["bob"]);
        assert_eq!(
            message.reactions.user_reactions[0].reaction_message_id_hex,
            "reaction-1"
        );
        assert!(message.deleted);
        assert_eq!(
            message.deleted_by_message_id_hex.as_deref(),
            Some("delete-1")
        );
    }

    #[test]
    fn app_message_record_ffi_leaves_non_chat_tokens_empty() {
        let record = AppMessageRecord {
            message_id_hex: "reaction-1".to_owned(),
            direction: "sent".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: "reaction".to_owned(),
            kind: 7,
            tags: vec![vec!["e".to_owned(), "target".to_owned()]],
            source_epoch: None,
            recorded_at: 10,
            received_at: 11,
        };

        let ffi = AppMessageRecordFfi::from(record);

        assert_eq!(ffi.kind, 7);
        assert_eq!(ffi.content_tokens, MarkdownDocumentFfi::default());
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
