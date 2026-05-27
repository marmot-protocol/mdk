use std::collections::HashMap;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT, AGENT_TEXT_STREAM_ROLE_FANOUT,
    AGENT_TEXT_STREAM_ROLE_RECEIVE, AGENT_TEXT_STREAM_ROLE_SEND, AgentTextStreamQuicPolicyV1,
};
use cgka_traits::app_components::{
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID, AppComponentData, GROUP_ADMIN_POLICY_COMPONENT,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_BLOSSOM_IMAGE_COMPONENT,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_MESSAGE_RETENTION_COMPONENT,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT, GROUP_PROFILE_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, decode_nostr_routing_v1,
    encode_component_vectors, encode_nostr_routing_v1, encode_quic_varint,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent as MarmotInnerEvent};
use cgka_traits::engine::GroupEvent;
use cgka_traits::group::Group;
use cgka_traits::{GroupId, TransportEndpoint, TransportGroupSubscription};
use serde::{Deserialize, Serialize};

use crate::{AccountState, AppError, ReceivedMessage, SendSummary, SyncSummary};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppGroupRecord {
    pub group_id_hex: String,
    pub endpoint: String,
    pub nostr_routing: AppGroupNostrRoutingComponent,
    pub profile: AppGroupProfileComponent,
    pub image: AppGroupImageComponent,
    pub admin_policy: AppGroupAdminPolicyComponent,
    #[serde(default)]
    pub message_retention: AppGroupMessageRetentionComponent,
    #[serde(default)]
    pub agent_text_stream: AppAgentTextStreamComponent,
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

impl Default for AppAgentTextStreamComponent {
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
            admin_policy,
            message_retention,
            agent_text_stream: AppAgentTextStreamComponent::disabled(),
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
        }
    }

    pub(crate) fn from_group(
        group_id: &GroupId,
        nostr_routing: AppGroupNostrRoutingComponent,
        group: Option<&Group>,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
        agent_text_stream: AppAgentTextStreamComponent,
    ) -> Self {
        let (profile_name, profile_description) = group
            .map(|group| (group.name.clone(), group.description.clone()))
            .unwrap_or_default();
        let mut record = Self::new(
            hex::encode(group_id.as_slice()),
            nostr_routing,
            profile_name,
            profile_description,
            AppGroupImageInput::default(),
            admin_policy,
            message_retention,
        );
        record.agent_text_stream = agent_text_stream;
        record
    }

    pub(crate) fn refresh_from_group(
        &mut self,
        nostr_routing: AppGroupNostrRoutingComponent,
        group: Option<&Group>,
        admin_policy: AppGroupAdminPolicyComponent,
        message_retention: AppGroupMessageRetentionComponent,
        agent_text_stream: AppAgentTextStreamComponent,
    ) {
        self.endpoint = nostr_routing.relays.first().cloned().unwrap_or_default();
        self.nostr_routing = nostr_routing;
        self.admin_policy = admin_policy;
        self.message_retention = message_retention;
        self.agent_text_stream = agent_text_stream;
        if let Some(group) = group {
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
                if !self.pending_confirmation && self.via_welcome_message_id_hex.is_some() {
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
    fn new(input: AppGroupImageInput) -> Self {
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AppGroupImageInput {
    pub(crate) image_hash_hex: String,
    pub(crate) image_key_hex: String,
    pub(crate) image_nonce_hex: String,
    pub(crate) image_upload_key_hex: String,
    pub(crate) media_type: Option<String>,
}

pub(crate) struct EventGroupProjection<'a> {
    pub(crate) nostr_routing: AppGroupNostrRoutingComponent,
    pub(crate) group_metadata: Option<&'a Group>,
    pub(crate) admin_policy: AppGroupAdminPolicyComponent,
    pub(crate) message_retention: AppGroupMessageRetentionComponent,
    pub(crate) agent_text_stream: AppAgentTextStreamComponent,
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
pub(crate) fn decode_received_event(
    payload: &[u8],
    sender_hex: &str,
    sender_display_name: Option<String>,
    group_id: &GroupId,
    source_message_id_hex: &str,
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
    if event.kind == MARMOT_APP_EVENT_KIND_CHAT
        && event
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta"))
        && !media_imeta_is_valid(&event.tags)
    {
        tracing::warn!(
            target: "marmot_app::ingest",
            method = "decode_received_event",
            "rejecting MLS application message: invalid encrypted media reference",
        );
        return None;
    }
    Some(ReceivedMessage {
        message_id_hex: event.id,
        source_message_id_hex: source_message_id_hex.to_owned(),
        sender: sender_hex.to_owned(),
        sender_display_name,
        group_id: group_id.clone(),
        plaintext: event.content,
        kind: event.kind,
        tags: event.tags,
    })
}

fn media_imeta_is_valid(tags: &[Vec<String>]) -> bool {
    let Some(imeta) = tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("imeta"))
    else {
        return true;
    };
    let fields = imeta
        .iter()
        .skip(1)
        .filter_map(|field| field.split_once(' '))
        .collect::<HashMap<_, _>>();
    let required = ["url", "m", "filename", "x", "n", "v"];
    if required
        .iter()
        .any(|name| fields.get(name).is_none_or(|value| value.trim().is_empty()))
    {
        return false;
    }
    if fields.get("v") != Some(&"mip04-v2") {
        return false;
    }
    match hex::decode(fields["x"]) {
        Ok(hash) if hash.len() == 32 => {}
        _ => return false,
    }
    match hex::decode(fields["n"]) {
        Ok(nonce) if nonce.len() == 12 => {}
        _ => return false,
    }
    true
}

pub(crate) fn observe_event(
    state: &mut AccountState,
    display_names: &HashMap<String, String>,
    summary: &mut SyncSummary,
    event: &GroupEvent,
    group_projection: Option<&EventGroupProjection<'_>>,
    source_message_id_hex: &str,
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
                        GroupEvent::GroupJoined { via_welcome, .. } => {
                            GroupConfirmationProjection::Pending {
                                via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                                welcomer_account_id_hex: None,
                            }
                        }
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
            // rendering an unauthenticated or tampered payload.
            let Some(message) = decode_received_event(
                payload,
                &sender_hex,
                sender_display_name,
                group_id,
                source_message_id_hex,
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
        | GroupEvent::MemberAdded { group_id, .. }
        | GroupEvent::MemberRemoved { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::ForkRecovered { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id } => Some(group_id),
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
        existing.refresh_from_group(
            projection.nostr_routing.clone(),
            projection.group_metadata,
            projection.admin_policy.clone(),
            projection.message_retention.clone(),
            projection.agent_text_stream.clone(),
        );
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
    );
    group.apply_confirmation_state(confirmation);
    state.groups.push(group);
}

pub(crate) fn fail_if_publish_failed(
    failures: &[marmot_account::PublishFailure],
) -> Result<(), AppError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Publish(
            failures
                .iter()
                .map(|failure| failure.reason.as_str())
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
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
