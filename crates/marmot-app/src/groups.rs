use std::collections::HashMap;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_ROLE_FANOUT,
    AGENT_TEXT_STREAM_ROLE_RECEIVE, AGENT_TEXT_STREAM_ROLE_SEND, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData, BlobStoreEndpointV1,
    EncryptedMediaPolicyV1, GROUP_ADMIN_POLICY_COMPONENT, GROUP_ADMIN_POLICY_COMPONENT_ID,
    GROUP_AVATAR_URL_COMPONENT, GROUP_AVATAR_URL_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT,
    GROUP_ENCRYPTED_MEDIA_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    GroupAvatarUrlV1, NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    decode_encrypted_media_policy_v1, decode_group_avatar_url_v1, decode_nostr_routing_v1,
    decode_quic_varint, encode_component_vectors, encode_encrypted_media_policy_v1,
    encode_group_avatar_url_v1, encode_nostr_routing_v1, encode_quic_varint,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent as MarmotInnerEvent};
use cgka_traits::engine::GroupEvent;
use cgka_traits::group::Group;
use cgka_traits::{GroupId, TransportEndpoint, TransportGroupSubscription};
use serde::{Deserialize, Serialize};

use crate::media::media_imeta_tags_are_valid;
use crate::{AccountState, AppError, ReceivedMessage, SendSummary, SyncSummary};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupRecord {
    pub group_id_hex: String,
    pub endpoint: String,
    pub nostr_routing: AppGroupNostrRoutingComponent,
    pub profile: AppGroupProfileComponent,
    pub image: AppGroupImageComponent,
    /// URL-based group avatar. When `present`, it takes precedence over `image`
    /// for rendering (spec: `marmot.group.avatar-url.v1`).
    #[serde(default)]
    pub avatar_url: AppGroupAvatarUrlComponent,
    pub admin_policy: AppGroupAdminPolicyComponent,
    #[serde(default)]
    pub message_retention: AppGroupMessageRetentionComponent,
    #[serde(default)]
    pub agent_text_stream: AppAgentTextStreamComponent,
    #[serde(default)]
    pub encrypted_media: AppGroupEncryptedMediaComponent,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub pending_confirmation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcomer_account_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_welcome_message_id_hex: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMemberRecord {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMlsState {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_count: usize,
    pub required_app_components: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupProfileComponent {
    pub component_id: u16,
    pub component: String,
    pub name: String,
    pub description: String,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupImageComponent {
    pub component_id: u16,
    pub component: String,
    pub present: bool,
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupAvatarUrlComponent {
    pub component_id: u16,
    pub component: String,
    pub present: bool,
    pub url: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub data_hex: String,
}

impl Default for AppGroupAvatarUrlComponent {
    fn default() -> Self {
        Self::absent()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupAdminPolicyComponent {
    pub component_id: u16,
    pub component: String,
    pub admins: Vec<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupMessageRetentionComponent {
    pub component_id: u16,
    pub component: String,
    pub disappearing_message_secs: u64,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupNostrRoutingComponent {
    pub component_id: u16,
    pub component: String,
    pub nostr_group_id_hex: String,
    pub relays: Vec<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAgentTextStreamComponent {
    pub component_id: u16,
    pub component: String,
    pub required: bool,
    pub required_member_roles: Vec<String>,
    pub allowed_member_roles: Vec<String>,
    pub max_plaintext_frame_len: u32,
    pub replay_ttl_secs: u32,
    pub padding_bucket_bytes: u16,
    pub data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppBlobEndpoint {
    pub locator_kind: String,
    pub base_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupEncryptedMediaComponent {
    pub component_id: u16,
    pub component: String,
    pub required: bool,
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<AppBlobEndpoint>,
    pub data_hex: String,
}

impl Default for AppAgentTextStreamComponent {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Default for AppGroupEncryptedMediaComponent {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Default for AppGroupMessageRetentionComponent {
    fn default() -> Self {
        Self::disabled()
    }
}

impl AppGroupRecord {
    pub(crate) fn new(
        group_id_hex: String,
        nostr_routing: AppGroupNostrRoutingComponent,
        profile_name: String,
        profile_description: String,
        image: AppGroupImageInput,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
    ) -> Self {
        let endpoint = nostr_routing.relays.first().cloned().unwrap_or_default();
        Self {
            group_id_hex,
            endpoint,
            nostr_routing,
            profile: AppGroupProfileComponent::new(profile_name, profile_description),
            image: AppGroupImageComponent::new(image),
            avatar_url: AppGroupAvatarUrlComponent::absent(),
            admin_policy,
            message_retention,
            agent_text_stream: AppAgentTextStreamComponent::disabled(),
            encrypted_media: AppGroupEncryptedMediaComponent::disabled(),
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_group(
        group_id: &GroupId,
        nostr_routing: AppGroupNostrRoutingComponent,
        group: Option<&Group>,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
        agent_text_stream: AppAgentTextStreamComponent,
        avatar_url: AppGroupAvatarUrlComponent,
        encrypted_media: AppGroupEncryptedMediaComponent,
        image: AppGroupImageInput,
    ) -> Self {
        let (profile_name, profile_description) = group
            .map(|group| (group.name.clone(), group.description.clone()))
            .unwrap_or_default();
        let mut record = Self::new(
            hex::encode(group_id.as_slice()),
            nostr_routing,
            profile_name,
            profile_description,
            image,
            admin_policy,
            message_retention,
        );
        record.agent_text_stream = agent_text_stream;
        record.avatar_url = avatar_url;
        record.encrypted_media = encrypted_media;
        record
    }

    pub(crate) fn refresh_from_group(&mut self, projection: &EventGroupProjection<'_>) {
        let nostr_routing = projection.nostr_routing.clone();
        self.endpoint = nostr_routing.relays.first().cloned().unwrap_or_default();
        self.nostr_routing = nostr_routing;
        self.admin_policy = projection.admin_policy.clone();
        self.message_retention = projection.message_retention.clone();
        self.agent_text_stream = projection.agent_text_stream.clone();
        self.avatar_url = projection.avatar_url.clone();
        self.encrypted_media = projection.encrypted_media.clone();
        self.image = AppGroupImageComponent::new(projection.image.clone());
        if let Some(group) = projection.group_metadata {
            self.profile =
                AppGroupProfileComponent::new(group.name.clone(), group.description.clone());
        }
    }

    pub(crate) fn apply_confirmation_state(&mut self, state: GroupConfirmationProjection) {
        match state {
            GroupConfirmationProjection::Preserve => {}
            GroupConfirmationProjection::Accepted => {
                self.pending_confirmation = false;
                self.archived = false;
            }
            GroupConfirmationProjection::Pending {
                via_welcome_message_id_hex,
                welcomer_account_id_hex,
            } => {
                // Short-circuit only on a true replay: an already-resolved
                // group (accepted or declined, so `pending_confirmation` is
                // false) whose recorded welcome id matches the incoming one.
                // A genuine re-invite carries a *different* `via_welcome` id and
                // must re-surface as pending even though MLS auto-joined, so the
                // pending-invite projection stays visible until accepted
                // (see darkmatter#184).
                if !self.pending_confirmation
                    && self.via_welcome_message_id_hex.as_deref()
                        == Some(via_welcome_message_id_hex.as_str())
                {
                    return;
                }
                self.pending_confirmation = true;
                self.archived = false;
                self.via_welcome_message_id_hex = Some(via_welcome_message_id_hex);
                self.welcomer_account_id_hex = welcomer_account_id_hex;
            }
        }
    }
}

impl AppGroupProfileComponent {
    fn new(name: String, description: String) -> Self {
        let data = encode_component_vectors(&[name.as_bytes(), description.as_bytes()]);
        Self {
            component_id: GROUP_PROFILE_COMPONENT_ID,
            component: GROUP_PROFILE_COMPONENT.to_owned(),
            name,
            description,
            data_hex: hex::encode(data),
        }
    }
}

impl AppGroupImageComponent {
    pub(crate) fn new(input: AppGroupImageInput) -> Self {
        let present = !input.image_hash_hex.is_empty()
            || !input.image_key_hex.is_empty()
            || !input.image_nonce_hex.is_empty()
            || !input.image_upload_key_hex.is_empty()
            || input.media_type.is_some();
        let image_hash = hex::decode(&input.image_hash_hex).unwrap_or_default();
        let image_key = hex::decode(&input.image_key_hex).unwrap_or_default();
        let image_nonce = hex::decode(&input.image_nonce_hex).unwrap_or_default();
        let image_upload_key = hex::decode(&input.image_upload_key_hex).unwrap_or_default();
        let media_type_bytes = input.media_type.as_deref().unwrap_or("").as_bytes();
        let data = encode_component_vectors(&[
            image_hash.as_slice(),
            image_key.as_slice(),
            image_nonce.as_slice(),
            image_upload_key.as_slice(),
            media_type_bytes,
        ]);
        Self {
            component_id: GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
            component: GROUP_BLOSSOM_IMAGE_COMPONENT.to_owned(),
            present,
            image_hash_hex: input.image_hash_hex,
            image_key_hex: input.image_key_hex,
            image_nonce_hex: input.image_nonce_hex,
            image_upload_key_hex: input.image_upload_key_hex,
            media_type: input.media_type,
            data_hex: hex::encode(data),
        }
    }
}

impl AppGroupAvatarUrlComponent {
    /// Build a present avatar from validated parts (used on the send path).
    pub(crate) fn new(
        url: String,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<Self, AppError> {
        let avatar = GroupAvatarUrlV1 {
            url,
            dim,
            thumbhash,
        };
        let data = encode_group_avatar_url_v1(&avatar).map_err(AppError::InvalidGroupAvatarUrl)?;
        // Decode the encoded bytes back so the struct fields carry the normalized
        // URL, matching `from_bytes(to_app_component_data(..))` for any input.
        let normalized =
            decode_group_avatar_url_v1(&data).map_err(AppError::InvalidGroupAvatarUrl)?;
        Ok(Self::from_decoded(normalized, data))
    }

    pub(crate) fn absent() -> Self {
        // Encode the canonical empty state (three zero-length fields) so a
        // "clear avatar" update is engine-valid, not raw-empty bytes.
        let data = encode_group_avatar_url_v1(&GroupAvatarUrlV1::default()).unwrap_or_default();
        Self {
            component_id: GROUP_AVATAR_URL_COMPONENT_ID,
            component: GROUP_AVATAR_URL_COMPONENT.to_owned(),
            present: false,
            url: String::new(),
            dim: None,
            thumbhash: None,
            data_hex: hex::encode(data),
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        match decode_group_avatar_url_v1(bytes) {
            Ok(avatar) if !avatar.url.is_empty() => Self::from_decoded(avatar, bytes.to_vec()),
            _ => Self::absent(),
        }
    }

    fn from_decoded(avatar: GroupAvatarUrlV1, data: Vec<u8>) -> Self {
        Self {
            component_id: GROUP_AVATAR_URL_COMPONENT_ID,
            component: GROUP_AVATAR_URL_COMPONENT.to_owned(),
            present: !avatar.url.is_empty(),
            url: avatar.url,
            dim: avatar.dim,
            thumbhash: avatar.thumbhash,
            data_hex: hex::encode(data),
        }
    }

    pub(crate) fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_AVATAR_URL_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }
}

impl AppGroupAdminPolicyComponent {
    pub(crate) fn new(mut admins: Vec<[u8; 32]>) -> Self {
        admins.sort();
        admins.dedup();
        let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
        for admin in &admins {
            admin_bytes.extend_from_slice(admin);
        }
        let mut data = Vec::new();
        encode_quic_varint(admin_bytes.len() as u64, &mut data);
        data.extend_from_slice(&admin_bytes);
        Self {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            component: GROUP_ADMIN_POLICY_COMPONENT.to_owned(),
            admins: admins.iter().map(hex::encode).collect(),
            data_hex: hex::encode(data),
        }
    }

    pub(crate) fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }
}

impl AppGroupMessageRetentionComponent {
    pub(crate) fn new(disappearing_message_secs: u64) -> Self {
        Self {
            component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            component: GROUP_MESSAGE_RETENTION_COMPONENT.to_owned(),
            disappearing_message_secs,
            data_hex: hex::encode(disappearing_message_secs.to_be_bytes()),
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() != 8 {
            return Self {
                component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
                component: GROUP_MESSAGE_RETENTION_COMPONENT.to_owned(),
                disappearing_message_secs: 0,
                data_hex: hex::encode(bytes),
            };
        }
        let mut value = [0_u8; 8];
        value.copy_from_slice(bytes);
        Self::new(u64::from_be_bytes(value))
    }

    pub(crate) fn disabled() -> Self {
        Self::new(0)
    }

    pub(crate) fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_MESSAGE_RETENTION_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }
}

impl AppGroupNostrRoutingComponent {
    pub(crate) fn new(routing: NostrRoutingV1) -> Result<Self, AppError> {
        let data = encode_nostr_routing_v1(&routing).map_err(AppError::InvalidNostrRouting)?;
        Ok(Self {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            component: NOSTR_ROUTING_COMPONENT.to_owned(),
            nostr_group_id_hex: hex::encode(routing.nostr_group_id),
            relays: routing.relays,
            data_hex: hex::encode(data),
        })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        let routing = decode_nostr_routing_v1(bytes).map_err(AppError::InvalidNostrRouting)?;
        Self::new(routing)
    }

    pub(crate) fn subscription(
        &self,
        group_id: &GroupId,
    ) -> Result<TransportGroupSubscription, AppError> {
        Ok(TransportGroupSubscription {
            group_id: group_id.clone(),
            transport_group_id: hex::decode(&self.nostr_group_id_hex)?,
            endpoints: self.relays.iter().cloned().map(TransportEndpoint).collect(),
        })
    }
}

impl AppAgentTextStreamComponent {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        match AgentTextStreamQuicPolicyV1::decode_component_state(bytes) {
            Ok(policy) => Self::from_policy(policy, bytes.to_vec()),
            Err(_) => Self {
                component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
                component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
                required: true,
                required_member_roles: Vec::new(),
                allowed_member_roles: Vec::new(),
                max_plaintext_frame_len: 0,
                replay_ttl_secs: 0,
                padding_bucket_bytes: 0,
                data_hex: hex::encode(bytes),
            },
        }
    }

    fn from_policy(policy: AgentTextStreamQuicPolicyV1, data: Vec<u8>) -> Self {
        Self {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
            required: true,
            required_member_roles: role_names(policy.required_member_roles),
            allowed_member_roles: role_names(policy.allowed_member_roles),
            max_plaintext_frame_len: policy.max_plaintext_frame_len,
            replay_ttl_secs: policy.replay_ttl_secs,
            padding_bucket_bytes: policy.padding_bucket_bytes,
            data_hex: hex::encode(data),
        }
    }

    pub(crate) fn disabled() -> Self {
        Self {
            component_id: AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
            component: AGENT_TEXT_STREAM_QUIC_COMPONENT.to_owned(),
            required: false,
            required_member_roles: Vec::new(),
            allowed_member_roles: Vec::new(),
            max_plaintext_frame_len: 0,
            replay_ttl_secs: 0,
            padding_bucket_bytes: 0,
            data_hex: String::new(),
        }
    }
}

impl AppGroupEncryptedMediaComponent {
    pub(crate) fn new(policy: EncryptedMediaPolicyV1) -> Result<Self, AppError> {
        let data =
            encode_encrypted_media_policy_v1(&policy).map_err(AppError::InvalidEncryptedMedia)?;
        let decoded =
            decode_encrypted_media_policy_v1(&data).map_err(AppError::InvalidEncryptedMedia)?;
        Ok(Self::from_policy(decoded, data))
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        match decode_encrypted_media_policy_v1(bytes) {
            Ok(policy) => Self::from_policy(policy, bytes.to_vec()),
            Err(_) => Self {
                component_id: GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
                component: GROUP_ENCRYPTED_MEDIA_COMPONENT.to_owned(),
                required: true,
                media_format: String::new(),
                allowed_locator_kinds: Vec::new(),
                default_blob_endpoints: Vec::new(),
                data_hex: hex::encode(bytes),
            },
        }
    }

    fn from_policy(policy: EncryptedMediaPolicyV1, data: Vec<u8>) -> Self {
        Self {
            component_id: GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
            component: GROUP_ENCRYPTED_MEDIA_COMPONENT.to_owned(),
            required: true,
            media_format: policy.media_format,
            allowed_locator_kinds: policy.allowed_locator_kinds,
            default_blob_endpoints: policy
                .default_blob_endpoints
                .into_iter()
                .map(|endpoint| AppBlobEndpoint {
                    locator_kind: endpoint.locator_kind,
                    base_url: endpoint.base_url,
                })
                .collect(),
            data_hex: hex::encode(data),
        }
    }

    pub(crate) fn disabled() -> Self {
        Self {
            component_id: GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
            component: GROUP_ENCRYPTED_MEDIA_COMPONENT.to_owned(),
            required: false,
            media_format: String::new(),
            allowed_locator_kinds: Vec::new(),
            default_blob_endpoints: Vec::new(),
            data_hex: String::new(),
        }
    }

    pub(crate) fn to_app_component_data(&self) -> Result<AppComponentData, AppError> {
        Ok(AppComponentData {
            component_id: GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
            data: hex::decode(&self.data_hex)?,
        })
    }

    pub(crate) fn endpoint_policy(&self) -> Result<EncryptedMediaPolicyV1, AppError> {
        if !self.required {
            return Err(AppError::InvalidEncryptedMedia(
                "group does not require encrypted media".into(),
            ));
        }
        EncryptedMediaPolicyV1::new(
            self.media_format.clone(),
            self.allowed_locator_kinds.clone(),
            self.default_blob_endpoints
                .iter()
                .map(|endpoint| BlobStoreEndpointV1 {
                    locator_kind: endpoint.locator_kind.clone(),
                    base_url: endpoint.base_url.clone(),
                }),
            true,
        )
        .map_err(AppError::InvalidEncryptedMedia)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AppGroupImageInput {
    pub(crate) image_hash_hex: String,
    pub(crate) image_key_hex: String,
    pub(crate) image_nonce_hex: String,
    pub(crate) image_upload_key_hex: String,
    pub(crate) media_type: Option<String>,
}

impl AppGroupImageInput {
    /// Whether a usable image is present (matches the engine's all-or-nothing
    /// validation: hash, key, nonce, and media type must all be set).
    pub(crate) fn is_present(&self) -> bool {
        !self.image_hash_hex.is_empty()
            && !self.image_key_hex.is_empty()
            && !self.image_nonce_hex.is_empty()
            && self.media_type.is_some()
    }

    /// Decode the `marmot.group.blossom.image.v1` component wire format
    /// (`encode_component_vectors([hash, key, nonce, upload_key, media_type])`).
    /// Returns the default (absent) input when the component is empty.
    pub(crate) fn from_component_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = bytes;
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(5);
        for _ in 0..5 {
            fields.push(read_component_vector(&mut cursor)?);
        }
        if !cursor.is_empty() {
            return None;
        }
        let media_type = fields.pop().unwrap_or_default();
        let media_type = if media_type.is_empty() {
            None
        } else {
            Some(String::from_utf8(media_type).ok()?)
        };
        Some(Self {
            image_hash_hex: hex::encode(&fields[0]),
            image_key_hex: hex::encode(&fields[1]),
            image_nonce_hex: hex::encode(&fields[2]),
            image_upload_key_hex: hex::encode(&fields[3]),
            media_type,
        })
    }
}

/// Read a single QUIC-varint-length-prefixed byte vector, advancing the cursor.
fn read_component_vector(cursor: &mut &[u8]) -> Option<Vec<u8>> {
    let (len, width) = decode_quic_varint(cursor).ok()?;
    let len = len as usize;
    let rest = cursor.get(width..)?;
    if rest.len() < len {
        return None;
    }
    let (head, tail) = rest.split_at(len);
    *cursor = tail;
    Some(head.to_vec())
}

pub(crate) struct EventGroupProjection<'a> {
    pub(crate) nostr_routing: AppGroupNostrRoutingComponent,
    pub(crate) group_metadata: Option<&'a Group>,
    pub(crate) admin_policy: AppGroupAdminPolicyComponent,
    pub(crate) message_retention: AppGroupMessageRetentionComponent,
    pub(crate) agent_text_stream: AppAgentTextStreamComponent,
    pub(crate) avatar_url: AppGroupAvatarUrlComponent,
    pub(crate) encrypted_media: AppGroupEncryptedMediaComponent,
    pub(crate) image: AppGroupImageInput,
}

#[derive(Clone, Debug)]
pub(crate) enum GroupConfirmationProjection {
    Preserve,
    Accepted,
    Pending {
        via_welcome_message_id_hex: String,
        welcomer_account_id_hex: Option<String>,
    },
}

/// Strictly decode the inner Marmot app event from MLS plaintext and bind it to
/// the MLS-authenticated sender. Returns `None` (rejecting the message) when the
/// canonical id does not match or the inner `pubkey` is not the authenticated
/// sender — both are integrity failures that must not reach the timeline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_received_event(
    payload: &[u8],
    sender_hex: &str,
    sender_display_name: Option<String>,
    group_id: &GroupId,
    source_epoch: u64,
    source_message_id_hex: &str,
    source_recorded_at: u64,
    allow_loopback_http: bool,
) -> Option<ReceivedMessage> {
    let event = match MarmotInnerEvent::decode(payload) {
        Ok(event) => event,
        Err(_) => {
            tracing::warn!(
                target: "marmot_app::ingest",
                method = "decode_received_event",
                "rejecting MLS application message: inner app event failed strict decode",
            );
            return None;
        }
    };
    if event.validate_sender(sender_hex).is_err() {
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: inner author is not the authenticated sender",
        );
        return None;
    }
    // The inner app event MUST NOT carry transport routing tags. For the Nostr
    // binding these are h (group routing id), p (recipient), relays (relay hints),
    // and expiration (NIP-40); they belong on the outer envelope only. See
    // spec/protocol-core/group-messaging.md ("App payloads") and
    // spec/foundation/application-messages.md ("Encoding"). Application-content
    // tags (e, imeta, system, stream-*) are not routing tags and are allowed.
    if event.tags.iter().any(|tag| {
        matches!(
            tag.first().map(String::as_str),
            Some("h" | "p" | "relays" | "expiration")
        )
    }) {
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: inner app event carries a transport routing tag",
        );
        return None;
    }
    if event.kind == MARMOT_APP_EVENT_KIND_CHAT
        && event
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta"))
        && !media_imeta_tags_are_valid(&event.tags, allow_loopback_http)
    {
        // Ingest is purely STRUCTURAL: a media reference drops the message only
        // when a locator is structurally malformed (empty kind/value, unparseable
        // URL) or another required field is missing/invalid. A well-formed locator
        // whose kind is out of the group policy or unsupported by this client is
        // UNFETCHABLE, never invalid (media is authenticated by its hashes + AEAD
        // independent of the locator), so it MUST NOT drop the message. Policy is
        // applied at fetch time, not here.
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: structurally invalid encrypted media reference",
        );
        return None;
    }
    Some(ReceivedMessage {
        message_id_hex: event.id,
        source_message_id_hex: source_message_id_hex.to_owned(),
        sender: sender_hex.to_owned(),
        sender_display_name,
        group_id: group_id.clone(),
        source_epoch,
        plaintext: event.content,
        kind: event.kind,
        tags: event.tags,
        recorded_at: source_recorded_at,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn observe_event(
    state: &mut AccountState,
    display_names: &HashMap<String, String>,
    summary: &mut SyncSummary,
    event: &GroupEvent,
    group_projection: Option<&EventGroupProjection<'_>>,
    source_message_id_hex: &str,
    source_recorded_at: u64,
    allow_loopback_http: bool,
) -> Option<ReceivedMessage> {
    match event {
        GroupEvent::GroupJoined { group_id, .. } | GroupEvent::GroupCreated { group_id } => {
            if let Some(projection) = group_projection {
                add_group(
                    state,
                    group_id,
                    projection,
                    match event {
                        GroupEvent::GroupCreated { .. } => GroupConfirmationProjection::Accepted,
                        GroupEvent::GroupJoined {
                            via_welcome,
                            welcomer,
                            ..
                        } => GroupConfirmationProjection::Pending {
                            via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                            welcomer_account_id_hex: welcomer
                                .as_ref()
                                .map(|member_id| hex::encode(member_id.as_slice())),
                        },
                        _ => GroupConfirmationProjection::Preserve,
                    },
                );
            }
            summary.joined_groups.push(group_id.clone());
            summary.events.push(event.clone());
            None
        }
        GroupEvent::MessageReceived {
            group_id,
            sender,
            epoch,
            payload,
        } => {
            if let Some(projection) = group_projection {
                add_group(
                    state,
                    group_id,
                    projection,
                    GroupConfirmationProjection::Preserve,
                );
            }
            let sender_hex = hex::encode(sender.as_slice());
            let sender_display_name = display_names.get(&sender_hex).cloned();
            // The MLS layer authenticated `sender`; the inner Nostr-shaped event
            // must (1) carry a valid canonical id and (2) name `sender` as its
            // author. Reject anything that fails either check rather than
            // rendering an unauthenticated or tampered payload. Media references
            // are validated structurally only inside `decode_received_event`:
            // locator-kind policy gates fetchability at download time, never
            // delivery, so the group's `allowed_locator_kinds` is not consulted
            // on the ingest path.
            let Some(message) = decode_received_event(
                payload,
                &sender_hex,
                sender_display_name,
                group_id,
                epoch.0,
                source_message_id_hex,
                source_recorded_at,
                allow_loopback_http,
            ) else {
                summary.events.push(event.clone());
                return None;
            };
            summary.messages.push(message.clone());
            summary.events.push(event.clone());
            Some(message)
        }
        _ => {
            if let (Some(group_id), Some(projection)) = (event_group_id(event), group_projection) {
                add_group(
                    state,
                    group_id,
                    projection,
                    GroupConfirmationProjection::Preserve,
                );
            }
            summary.events.push(event.clone());
            None
        }
    }
}

pub(crate) fn event_group_id(event: &GroupEvent) -> Option<&GroupId> {
    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::GroupStateChanged { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::CommitRolledBack { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id, .. }
        | GroupEvent::PendingCommitRecovered { group_id, .. }
        | GroupEvent::GroupHydrationQuarantined { group_id, .. } => Some(group_id),
    }
}

pub(crate) fn add_group(
    state: &mut AccountState,
    group_id: &GroupId,
    projection: &EventGroupProjection<'_>,
    confirmation: GroupConfirmationProjection,
) {
    let group_id_hex = hex::encode(group_id.as_slice());
    if let Some(existing) = state
        .groups
        .iter_mut()
        .find(|group| group.group_id_hex == group_id_hex)
    {
        existing.refresh_from_group(projection);
        existing.apply_confirmation_state(confirmation);
        return;
    }
    let mut group = AppGroupRecord::from_group(
        group_id,
        projection.nostr_routing.clone(),
        projection.group_metadata,
        projection.admin_policy.clone(),
        projection.message_retention.clone(),
        projection.agent_text_stream.clone(),
        projection.avatar_url.clone(),
        projection.encrypted_media.clone(),
        projection.image.clone(),
    );
    group.apply_confirmation_state(confirmation);
    state.groups.push(group);
}

/// Decide whether per-endpoint publish failures should abort an app-layer
/// operation, gated on how the underlying MLS pending state resolved.
///
/// A `PublishFailure` lands in `effects.failures` whenever an outbound message
/// fails to reach the required acknowledgement count. On its own that is *not*
/// enough to know whether the operation succeeded: the runtime confirms a
/// create/commit once it is durably live (e.g. a create whose commit is at
/// epoch 1 with at least one welcome exposed), even if some welcomes or relays
/// were unreached. Dropping the local app projection in that case strands the
/// creator with a confirmed MLS group its own UI never recorded, while invitees
/// who did receive a welcome see a real group (darkmatter#428).
///
/// Resolution semantics:
/// - no failures: success.
/// - any pending `RolledBack`: the commit/create was reverted at the MLS layer,
///   so the publish failure is a genuine hard error the caller must see.
/// - any pending `Confirmed` (and none rolled back): confirmed-but-partial. The
///   operation is live at its new epoch; unreached endpoints are recoverable
///   "ghost member" conditions. Keep the local projection (caller still runs
///   `add_group` / `save_state`) and surface a soft warning only.
/// - failures with no pending resolution at all (e.g. a plain application
///   message or proposal publish that never landed): hard error, as before.
pub(crate) fn fail_if_publish_failed(
    effects: &marmot_account::AccountDeviceEffects,
) -> Result<(), AppError> {
    if effects.failures.is_empty() {
        return Ok(());
    }

    let mut any_confirmed = false;
    let mut any_rolled_back = false;
    for resolution in &effects.pending {
        match resolution {
            marmot_account::PendingResolution::Confirmed { .. } => any_confirmed = true,
            marmot_account::PendingResolution::RolledBack { .. } => any_rolled_back = true,
        }
    }

    if any_rolled_back {
        return Err(publish_failure_error(&effects.failures));
    }

    if any_confirmed {
        tracing::warn!(
            target: "marmot_app",
            method = "fail_if_publish_failed",
            failures = effects.failures.len(),
            "publish reached insufficient endpoints but pending state confirmed; \
             treating unreached endpoints as recoverable and keeping local projection"
        );
        return Ok(());
    }

    Err(publish_failure_error(&effects.failures))
}

fn publish_failure_error(failures: &[marmot_account::PublishFailure]) -> AppError {
    AppError::Publish(
        failures
            .iter()
            .map(|failure| failure.reason.as_str())
            .collect::<Vec<_>>()
            .join("; "),
    )
}

pub(crate) fn send_summary_from_effects(
    effects: &marmot_account::AccountDeviceEffects,
) -> SendSummary {
    SendSummary {
        published: effects.reports.len(),
        message_ids: effects
            .reports
            .iter()
            .map(|report| hex::encode(report.message_id.as_slice()))
            .collect(),
    }
}

pub(crate) fn validate_group_profile(name: &str, description: &str) -> Result<(), AppError> {
    if name.len() > 256 {
        return Err(AppError::InvalidGroupProfile(
            "name must be at most 256 UTF-8 bytes".into(),
        ));
    }
    if description.len() > 4096 {
        return Err(AppError::InvalidGroupProfile(
            "description must be at most 4096 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

fn role_names(mask: u8) -> Vec<String> {
    let mut roles = Vec::new();
    if mask & AGENT_TEXT_STREAM_ROLE_RECEIVE != 0 {
        roles.push("receive".to_owned());
    }
    if mask & AGENT_TEXT_STREAM_ROLE_SEND != 0 {
        roles.push("send".to_owned());
    }
    if mask & AGENT_TEXT_STREAM_ROLE_FANOUT != 0 {
        roles.push("fanout".to_owned());
    }
    roles
}

#[cfg(test)]
mod avatar_url_tests {
    use super::*;

    #[test]
    fn avatar_url_component_round_trips_through_bytes() {
        let component = AppGroupAvatarUrlComponent::new(
            "https://cdn.example.com/a.png".to_owned(),
            Some("512x512".to_owned()),
            Some("thumbhash-bytes".to_owned()),
        )
        .unwrap();
        assert!(component.present);

        let data = component.to_app_component_data().unwrap();
        let decoded = AppGroupAvatarUrlComponent::from_bytes(&data.data);
        assert_eq!(decoded, component);
        assert_eq!(decoded.url, "https://cdn.example.com/a.png");
        assert_eq!(decoded.dim.as_deref(), Some("512x512"));
        assert_eq!(decoded.thumbhash.as_deref(), Some("thumbhash-bytes"));
    }

    #[test]
    fn absent_avatar_round_trips_and_is_engine_valid_bytes() {
        let absent = AppGroupAvatarUrlComponent::absent();
        assert!(!absent.present);
        // Clearing the avatar must produce non-empty, decodable bytes.
        let data = absent.to_app_component_data().unwrap();
        assert!(!data.data.is_empty());
        assert!(!AppGroupAvatarUrlComponent::from_bytes(&data.data).present);
    }

    #[test]
    fn non_https_avatar_url_is_rejected() {
        let err =
            AppGroupAvatarUrlComponent::new("http://cdn.example.com/a.png".to_owned(), None, None)
                .unwrap_err();
        assert!(matches!(err, AppError::InvalidGroupAvatarUrl(_)));
    }
}

#[cfg(test)]
mod confirmation_state_tests {
    use super::*;

    fn test_record() -> AppGroupRecord {
        let routing = AppGroupNostrRoutingComponent::new(NostrRoutingV1 {
            nostr_group_id: [0u8; 32],
            relays: vec!["wss://relay.example.com".to_owned()],
        })
        .expect("routing component");
        AppGroupRecord::new(
            hex::encode([1u8; 32]),
            routing,
            "group".to_owned(),
            "desc".to_owned(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )
    }

    fn pending(via_welcome: &str, welcomer: Option<&str>) -> GroupConfirmationProjection {
        GroupConfirmationProjection::Pending {
            via_welcome_message_id_hex: via_welcome.to_owned(),
            welcomer_account_id_hex: welcomer.map(str::to_owned),
        }
    }

    // A genuine re-invite (a new GroupJoined carrying a *different* welcome id)
    // after the user accepted must re-surface the group as pending and record
    // the new welcome/welcomer. Regression test for darkmatter#184.
    #[test]
    fn reinvite_after_accept_resurfaces_as_pending() {
        let mut record = test_record();

        record.apply_confirmation_state(pending("welcome-1", Some("welcomer-1")));
        assert!(record.pending_confirmation);

        // User accepts: pending cleared, welcome id retained.
        record.apply_confirmation_state(GroupConfirmationProjection::Accepted);
        assert!(!record.pending_confirmation);
        assert_eq!(
            record.via_welcome_message_id_hex.as_deref(),
            Some("welcome-1")
        );

        // Genuine re-invite: a different welcome id must re-mark pending and
        // update the recorded welcome/welcomer fields.
        record.apply_confirmation_state(pending("welcome-2", Some("welcomer-2")));
        assert!(record.pending_confirmation);
        assert!(!record.archived);
        assert_eq!(
            record.via_welcome_message_id_hex.as_deref(),
            Some("welcome-2")
        );
        assert_eq!(
            record.welcomer_account_id_hex.as_deref(),
            Some("welcomer-2")
        );
    }

    // A re-invite after the user declined (pending=false, archived=true) must
    // also re-surface the group as a fresh pending invite.
    #[test]
    fn reinvite_after_decline_resurfaces_as_pending() {
        let mut record = test_record();
        record.apply_confirmation_state(pending("welcome-1", None));

        // Simulate decline: leave + archive, pending cleared, welcome retained.
        record.pending_confirmation = false;
        record.archived = true;

        record.apply_confirmation_state(pending("welcome-2", Some("welcomer-2")));
        assert!(record.pending_confirmation);
        assert!(!record.archived);
        assert_eq!(
            record.via_welcome_message_id_hex.as_deref(),
            Some("welcome-2")
        );
        assert_eq!(
            record.welcomer_account_id_hex.as_deref(),
            Some("welcomer-2")
        );
    }

    // A true replay (same welcome id on an already-resolved group) must NOT
    // re-mark pending — otherwise an accepted/declined group would bounce back
    // to the invite list on every redelivered GroupJoined.
    #[test]
    fn replay_same_welcome_id_does_not_resurface() {
        let mut record = test_record();
        record.apply_confirmation_state(pending("welcome-1", Some("welcomer-1")));
        record.apply_confirmation_state(GroupConfirmationProjection::Accepted);
        assert!(!record.pending_confirmation);

        // Redelivery of the same welcome id is a replay: stay resolved.
        record.apply_confirmation_state(pending("welcome-1", Some("welcomer-1")));
        assert!(!record.pending_confirmation);
        assert_eq!(
            record.via_welcome_message_id_hex.as_deref(),
            Some("welcome-1")
        );
    }

    // While a group is still pending, a redelivered welcome (same or different
    // id) keeps it pending and refreshes the welcome metadata.
    #[test]
    fn pending_record_keeps_pending_on_redelivery() {
        let mut record = test_record();
        record.apply_confirmation_state(pending("welcome-1", Some("welcomer-1")));
        assert!(record.pending_confirmation);

        record.apply_confirmation_state(pending("welcome-2", Some("welcomer-2")));
        assert!(record.pending_confirmation);
        assert_eq!(
            record.via_welcome_message_id_hex.as_deref(),
            Some("welcome-2")
        );
    }
}

#[cfg(test)]
mod routing_tag_tests {
    use super::*;

    fn decode_with_tags(tags: Vec<Vec<String>>) -> Option<ReceivedMessage> {
        let pubkey = "aa".repeat(32);
        let event =
            MarmotInnerEvent::new(pubkey.clone(), 1, MARMOT_APP_EVENT_KIND_CHAT, tags, "hi");
        let payload = event.encode().unwrap();
        decode_received_event(
            &payload,
            &pubkey,
            None,
            &GroupId::new(vec![0x01; 32]),
            1,
            &"00".repeat(32),
            0,
            false,
        )
    }

    #[test]
    fn inner_event_with_transport_routing_tag_is_rejected() {
        for name in ["h", "p", "relays", "expiration"] {
            assert!(
                decode_with_tags(vec![vec![name.to_string(), "x".to_string()]]).is_none(),
                "inner transport routing tag {name} must be rejected"
            );
        }
    }

    #[test]
    fn inner_event_with_application_tag_is_accepted() {
        // `e` (reply/edit target) is application content, not a routing tag.
        assert!(decode_with_tags(vec![vec!["e".to_string(), "ab".repeat(32)]]).is_some());
    }
}

#[cfg(test)]
mod fail_if_publish_failed_tests {
    use super::*;
    use cgka_traits::MessageId;
    use cgka_traits::engine_state::PendingStateRef;
    use marmot_account::{AccountDeviceEffects, PendingResolution, PublishFailure};

    fn failure(reason: &str) -> PublishFailure {
        PublishFailure {
            message_id: MessageId::new(vec![0xab; 32]),
            reason: reason.to_owned(),
        }
    }

    fn pending_ref() -> PendingStateRef {
        PendingStateRef::new(7)
    }

    #[test]
    fn no_failures_is_ok() {
        let effects = AccountDeviceEffects::default();
        assert!(fail_if_publish_failed(&effects).is_ok());
    }

    // darkmatter#428: a confirmed-but-partial create/commit (pending Confirmed,
    // welcomes/relays unreached) must NOT abort the app-layer projection. The
    // group is live at its new epoch; unreached endpoints are recoverable.
    #[test]
    fn confirmed_partial_publish_is_soft_pass() {
        let mut effects = AccountDeviceEffects::default();
        effects
            .failures
            .push(failure("insufficient publish acknowledgements"));
        effects.pending.push(PendingResolution::Confirmed {
            pending: pending_ref(),
        });
        assert!(
            fail_if_publish_failed(&effects).is_ok(),
            "confirmed-but-partial create must keep the local projection (darkmatter#428)"
        );
    }

    // A rolled-back pending means the commit/create was reverted at the MLS
    // layer, so the publish failure is a genuine hard error.
    #[test]
    fn rolled_back_publish_is_hard_error() {
        let mut effects = AccountDeviceEffects::default();
        effects
            .failures
            .push(failure("insufficient publish acknowledgements"));
        effects.pending.push(PendingResolution::RolledBack {
            pending: pending_ref(),
        });
        let err = fail_if_publish_failed(&effects).unwrap_err();
        assert!(matches!(err, AppError::Publish(_)));
    }

    // A plain application-message/proposal publish carries no pending
    // resolution; a failure there means the message never landed, so it stays a
    // hard error (preserves pre-#428 behavior).
    #[test]
    fn failure_without_pending_is_hard_error() {
        let mut effects = AccountDeviceEffects::default();
        effects.failures.push(failure("relay rejected"));
        let err = fail_if_publish_failed(&effects).unwrap_err();
        assert!(matches!(err, AppError::Publish(_)));
    }

    // A mixed resolution where any pending rolled back must hard-fail even if
    // another pending confirmed: a reverted commit is not recoverable.
    #[test]
    fn rolled_back_dominates_confirmed() {
        let mut effects = AccountDeviceEffects::default();
        effects.failures.push(failure("insufficient acks"));
        effects.pending.push(PendingResolution::Confirmed {
            pending: PendingStateRef::new(1),
        });
        effects.pending.push(PendingResolution::RolledBack {
            pending: PendingStateRef::new(2),
        });
        let err = fail_if_publish_failed(&effects).unwrap_err();
        assert!(matches!(err, AppError::Publish(_)));
    }

    // The hard-error message joins all failure reasons, unchanged from the
    // original contract.
    #[test]
    fn hard_error_joins_all_failure_reasons() {
        let mut effects = AccountDeviceEffects::default();
        effects.failures.push(failure("reason-a"));
        effects.failures.push(failure("reason-b"));
        match fail_if_publish_failed(&effects).unwrap_err() {
            AppError::Publish(msg) => assert_eq!(msg, "reason-a; reason-b"),
            other => panic!("expected AppError::Publish, got {other:?}"),
        }
    }
}
