use crate::{AppGroupLifecycleState, SelfMembership};
use serde::Serialize;

/// Scalar inputs captured by an account reader. No roster or profile is needed
/// by the selector. Unknown self membership must be represented by `is_member = false`.
/// These are display hints; every command still checks current engine authority.
#[derive(Clone, Copy, Debug)]
pub struct ConversationAuthority {
    pub is_member: bool,
    pub self_membership: SelfMembership,
    pub is_admin: bool,
    pub admin_count: usize,
    pub pending_confirmation: bool,
    pub leave_request_pending: bool,
    pub lifecycle: AppGroupLifecycleState,
    pub unrecoverable: bool,
    pub disbanding: bool,
    pub disbanding_enabled: bool,
    pub has_disbanding_blockers: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ConversationParticipation {
    PendingInvitation,
    Active,
    Leaving,
    Left,
    Removed,
    Disbanded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ConversationCapabilities {
    pub participation: ConversationParticipation,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_send: bool,
    pub can_invite: bool,
    pub can_edit_group: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    pub can_enable_disbanding: bool,
    pub can_disband: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversationMemberActions {
    pub can_remove: bool,
    pub can_promote: bool,
    pub can_demote: bool,
}

impl ConversationAuthority {
    pub fn capabilities(self) -> ConversationCapabilities {
        use ConversationParticipation as P;
        let participation = if self.lifecycle == AppGroupLifecycleState::Disbanded {
            P::Disbanded
        } else if self.self_membership == SelfMembership::Removed {
            P::Removed
        } else if self.leave_request_pending {
            P::Leaving
        } else if self.self_membership == SelfMembership::Left {
            P::Left
        } else if self.pending_confirmation {
            P::PendingInvitation
        } else if !self.is_member {
            P::Unavailable
        } else {
            P::Active
        };
        let ordinary = participation == P::Active
            && !self.disbanding
            && !self.unrecoverable
            && self.lifecycle != AppGroupLifecycleState::Unrecoverable;
        let admin = self.is_member && self.is_admin;
        let manage = ordinary && admin;
        ConversationCapabilities {
            participation,
            is_self_admin: admin,
            is_last_admin: admin && self.admin_count == 1,
            can_send: ordinary,
            can_invite: manage,
            can_edit_group: manage,
            can_leave: ordinary && !admin,
            requires_self_demote_before_leave: manage,
            can_enable_disbanding: manage
                && self.lifecycle == AppGroupLifecycleState::Stable
                && !self.disbanding_enabled
                && !self.has_disbanding_blockers,
            can_disband: manage
                && self.lifecycle == AppGroupLifecycleState::Stable
                && self.disbanding_enabled,
        }
    }

    /// Shared policy for the existing full-roster management screen. The
    /// compact conversation header deliberately carries none of this array.
    pub fn member_actions(self, is_self: bool, is_admin: bool) -> ConversationMemberActions {
        let manage = self.capabilities().can_edit_group;
        let last_admin = is_admin && self.admin_count == 1;
        ConversationMemberActions {
            can_remove: manage && !is_self && !last_admin,
            can_promote: manage && !is_admin,
            can_demote: manage && is_admin && !is_self && !last_admin,
        }
    }
}
