//! Pure classification/routing helpers over [`MarmotAppEvent`] used by the
//! subscription fan-out tasks.

use cgka_traits::GroupId;
use cgka_traits::engine::GroupEvent;

use super::{ChatListUpdateTrigger, MarmotAppEvent, RuntimeMessageUpdate, RuntimeProjectionUpdate};
use crate::TimelineMessageQuery;

pub(crate) fn runtime_message_update_from_event(
    event: MarmotAppEvent,
) -> Option<RuntimeMessageUpdate> {
    match event {
        // Raw message updates keep kind-1200 stream starts distinct from
        // message rows. The materialized storage timeline still includes those
        // starts when clients call `timeline_messages`.
        MarmotAppEvent::MessageReceived(message) => Some(RuntimeMessageUpdate::Message(message)),
        MarmotAppEvent::AgentStreamStarted(message) => {
            Some(RuntimeMessageUpdate::AgentStreamStarted(message))
        }
        MarmotAppEvent::GroupJoined { .. }
        | MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

pub(crate) fn projection_update_from_event(
    event: &MarmotAppEvent,
) -> Option<&RuntimeProjectionUpdate> {
    match event {
        MarmotAppEvent::ProjectionUpdated(update) => Some(update),
        MarmotAppEvent::GroupJoined { .. }
        | MarmotAppEvent::GroupStateUpdated { .. }
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::GroupEvent(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

pub(crate) fn projection_update_matches_query(
    update: &RuntimeProjectionUpdate,
    account_id_hex: &str,
    group_id_hex: Option<&str>,
) -> bool {
    update.account_id_hex == account_id_hex
        && group_id_hex.is_none_or(|wanted| update.update.group_id_hex == wanted)
        && (!update.update.timeline_messages.is_empty()
            || !update.update.timeline_changes.is_empty())
}

pub(crate) fn timeline_query_can_apply_projection_delta(query: &TimelineMessageQuery) -> bool {
    query
        .search
        .as_ref()
        .is_none_or(|search| search.trim().is_empty())
        && query.pagination.before.is_none()
        && query.pagination.before_message_id.is_none()
        && query.pagination.after.is_none()
        && query.pagination.after_message_id.is_none()
}

pub(crate) fn runtime_group_event_route(event: &MarmotAppEvent) -> Option<(&str, &GroupId)> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        }
        | MarmotAppEvent::GroupStateUpdated {
            account_id_hex,
            group_id,
            ..
        } => Some((account_id_hex, group_id)),
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => None,
            event => Some((&group_event.account_id_hex, group_id_from_event(event))),
        },
        MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

pub(crate) fn chat_list_event_route(event: &MarmotAppEvent) -> Option<(&str, &GroupId)> {
    match event {
        MarmotAppEvent::GroupJoined {
            account_id_hex,
            group_id,
            ..
        }
        | MarmotAppEvent::GroupStateUpdated {
            account_id_hex,
            group_id,
            ..
        } => Some((account_id_hex, group_id)),
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => None,
            event => Some((&group_event.account_id_hex, group_id_from_event(event))),
        },
        MarmotAppEvent::ProjectionUpdated(_)
        | MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => None,
    }
}

pub(crate) fn chat_list_trigger_from_event(event: &MarmotAppEvent) -> ChatListUpdateTrigger {
    match event {
        MarmotAppEvent::GroupJoined { .. } => ChatListUpdateTrigger::NewGroup,
        MarmotAppEvent::GroupStateUpdated { .. } => ChatListUpdateTrigger::MembershipChanged,
        MarmotAppEvent::GroupEvent(group_event) => match &group_event.event {
            GroupEvent::GroupCreated { .. } | GroupEvent::GroupJoined { .. } => {
                ChatListUpdateTrigger::NewGroup
            }
            GroupEvent::GroupStateChanged { .. }
            | GroupEvent::EpochChanged { .. }
            | GroupEvent::ForkRecovered { .. }
            | GroupEvent::CommitRolledBack { .. }
            | GroupEvent::GroupUnrecoverable { .. }
            | GroupEvent::PendingCommitRecovered { .. }
            | GroupEvent::GroupHydrationQuarantined { .. } => {
                ChatListUpdateTrigger::MembershipChanged
            }
            GroupEvent::MessageReceived { .. } | GroupEvent::AppMessageInvalidated { .. } => {
                ChatListUpdateTrigger::SnapshotRefresh
            }
        },
        MarmotAppEvent::ProjectionUpdated(update) => update.update.chat_list_trigger,
        MarmotAppEvent::MessageReceived(_)
        | MarmotAppEvent::AgentStreamStarted(_)
        | MarmotAppEvent::AccountError(_) => ChatListUpdateTrigger::SnapshotRefresh,
    }
}

fn group_id_from_event(event: &GroupEvent) -> &GroupId {
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
        | GroupEvent::GroupHydrationQuarantined { group_id, .. } => group_id,
    }
}
