//! FFI-friendly value types and conversions from marmot-app's internal types.
//!
//! Internal Rust types that don't map cleanly to UniFFI (byte newtypes,
//! enums-of-structs with associated payloads, types that aren't `Send`) are
//! re-exposed as plain records/enums here. Conversion is one-way for now
//! (Rust → FFI). When the iOS side needs to round-trip data back into
//! marmot-app we'll add the reverse direction explicitly.

use cgka_traits::{GroupId, MarmotAppMessagePayloadV1, MarmotReactionActionV1};
use marmot_app::{
    AccountRelayListState, AccountRelayListStatus, AppGroupAdminPolicyComponent,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupNostrRoutingComponent,
    AppGroupProfileComponent, AppGroupRecord, AppMessageRecord, MarmotAppEvent, ReceivedMessage,
    RelayPlaneHealth, RuntimeAgentStreamUpdate, RuntimeMessageReceived, RuntimeMessageUpdate,
    SendSummary, UserProfileMetadata,
};

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

/// Structured chat payloads (reactions, replies, deletes, …) carried inside a
/// message. Flattened from `MarmotAppMessagePayloadV1` for host bindings.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum AppMessagePayloadFfi {
    Reaction {
        target_message_id: String,
        emoji: String,
        removed: bool,
    },
    Delete {
        target_message_id: String,
    },
    Retry {
        target_message_id: String,
    },
    Media {
        file_name: String,
        media_type: String,
        size_bytes: u64,
        caption: Option<String>,
    },
    Reply {
        target_message_id: String,
        text: String,
    },
}

impl From<MarmotAppMessagePayloadV1> for AppMessagePayloadFfi {
    fn from(value: MarmotAppMessagePayloadV1) -> Self {
        match value {
            MarmotAppMessagePayloadV1::Reaction {
                target_message_id,
                emoji,
                action,
            } => Self::Reaction {
                target_message_id,
                emoji,
                removed: matches!(action, MarmotReactionActionV1::Remove),
            },
            MarmotAppMessagePayloadV1::Delete { target_message_id } => {
                Self::Delete { target_message_id }
            }
            MarmotAppMessagePayloadV1::Retry {
                target_message_id, ..
            } => Self::Retry { target_message_id },
            MarmotAppMessagePayloadV1::Media { reference, caption } => Self::Media {
                file_name: reference.file_name,
                media_type: reference.media_type,
                size_bytes: reference.size_bytes,
                caption,
            },
            MarmotAppMessagePayloadV1::Reply {
                target_message_id,
                text,
            } => Self::Reply {
                target_message_id,
                text,
            },
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppMessageRecordFfi {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub app_message: Option<AppMessagePayloadFfi>,
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
            app_message: value.app_message.map(Into::into),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
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
    pub app_message: Option<AppMessagePayloadFfi>,
}

impl From<&ReceivedMessage> for ReceivedMessageFfi {
    fn from(value: &ReceivedMessage) -> Self {
        Self {
            message_id_hex: value.message_id_hex.clone(),
            group_id_hex: hex::encode(value.group_id.as_slice()),
            sender: value.sender.clone(),
            sender_display_name: value.sender_display_name.clone(),
            plaintext: value.plaintext.clone(),
            app_message: value.app_message.clone().map(Into::into),
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
    Message { received: RuntimeMessageReceivedFfi },
    AgentStreamStarted { received: RuntimeMessageReceivedFfi },
    AgentStreamFinalized { received: RuntimeMessageReceivedFfi },
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
            RuntimeMessageUpdate::AgentStreamFinalized(m) => Self::AgentStreamFinalized {
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
            MarmotAppEvent::AgentStreamStarted(m) | MarmotAppEvent::AgentStreamFinalized(m) => {
                Self::AgentStreamActivity {
                    account_id_hex: m.account_id_hex,
                    account_label: m.account_label,
                }
            }
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
            message: err.to_string(),
        })?;
    Ok(GroupId::new(bytes))
}
