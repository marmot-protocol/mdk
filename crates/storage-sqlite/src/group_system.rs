//! Local presentation of kind-1210 content. This is not a wire-format change.
use cgka_traits::app_event::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupSystemEventProvenance {
    AuthenticatedGroupState,
    #[default]
    MemberAuthored,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupSystemEventProjection {
    /// Established from the stored projection origin, never from payload claims.
    #[serde(default)]
    pub provenance: GroupSystemEventProvenance,
    /// Prepared locally by the app; absent on the narrower storage surface.
    #[serde(default)]
    pub actor_display_name: Option<String>,
    #[serde(default)]
    pub subject_display_name: Option<String>,
    pub system_type: String,
    pub text: String,
    pub actor_account_id_hex: Option<String>,
    pub subject_account_id_hex: Option<String>,
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_retention_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_retention_seconds: Option<u64>,
}

/// Decode raw claims only. This helper has no storage origin and therefore
/// always returns MemberAuthored; payload IDs here are assertions, not proof.
/// Use projected timeline/chat-list records for authenticated attribution.
pub fn group_system_event_from_message(
    kind: u64,
    plaintext: &str,
) -> Option<GroupSystemEventProjection> {
    if kind != MARMOT_APP_EVENT_KIND_GROUP_SYSTEM || plaintext.len() > 16 * 1024 {
        return None;
    }
    let event = GroupSystemEvent::parse(plaintext).ok()?;
    if event.v != GROUP_SYSTEM_EVENT_VERSION {
        return None;
    }
    let actor_account_id_hex = non_empty_group_system_data(&event, GROUP_SYSTEM_DATA_ACTOR);
    let subject_account_id_hex = non_empty_group_system_data(&event, GROUP_SYSTEM_DATA_SUBJECT);
    let name = non_empty_group_system_data(&event, GROUP_SYSTEM_DATA_NAME);
    let old_name = non_empty_group_system_data(&event, GROUP_SYSTEM_DATA_OLD_NAME);
    let old_retention_seconds = event.data_u64(GROUP_SYSTEM_DATA_OLD_RETENTION_SECONDS);
    let new_retention_seconds = event.data_u64(GROUP_SYSTEM_DATA_NEW_RETENTION_SECONDS);
    Some(GroupSystemEventProjection {
        provenance: GroupSystemEventProvenance::MemberAuthored,
        actor_display_name: None,
        subject_display_name: None,
        system_type: event.system_type,
        text: event.text,
        actor_account_id_hex,
        subject_account_id_hex,
        name,
        old_name,
        old_retention_seconds,
        new_retention_seconds,
    })
}

fn non_empty_group_system_data(event: &GroupSystemEvent, key: &str) -> Option<String> {
    event
        .data_str(key)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
/// The owning storage query supplies proof tied to this exact payload and row.
pub(crate) fn projected_group_system(
    kind: u64,
    plaintext: &str,
    authenticated: bool,
    deleted: bool,
) -> Option<GroupSystemEventProjection> {
    if deleted {
        return None;
    }
    let mut event = group_system_event_from_message(kind, plaintext)?;
    if authenticated {
        event.provenance = GroupSystemEventProvenance::AuthenticatedGroupState;
    } else {
        // Raw claims stay in plaintext; they are not trusted attribution.
        event.actor_account_id_hex = None;
        event.subject_account_id_hex = None;
    }
    Some(event)
}
