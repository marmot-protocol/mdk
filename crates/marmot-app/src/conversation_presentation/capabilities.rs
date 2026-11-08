use crate::{AppGroupLifecycleState, SelfMembership};

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
    /// The outstanding leave is blocked: this account is the last active
    /// admin on the selected branch (mdk#3014). Read with
    /// `leave_request_pending` from the same engine row.
    pub leave_blocked: bool,
    pub lifecycle: AppGroupLifecycleState,
    pub unrecoverable: bool,
    pub disbanding: bool,
    pub disbanding_enabled: bool,
    pub has_disbanding_blockers: bool,
    /// Whether Leave takes an admin account off the admin list itself
    /// (mdk#2628 D99): only while device groups are on. Otherwise an admin's
    /// Leave is refused until the host demotes it (mdk#3014 interim); read
    /// it from `MarmotApp::admin_leave_steps_down`.
    pub admin_leave_steps_down: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum ConversationParticipation {
    PendingInvitation,
    Active,
    Leaving,
    Left,
    Removed,
    Disbanded,
    Unavailable,
    /// This device's leaf was removed while the account keeps another device
    /// in the conversation. Not a removal from the conversation (mdk#2628 D62).
    DeviceRemoved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct ConversationCapabilities {
    pub participation: ConversationParticipation,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_send: bool,
    pub can_invite: bool,
    pub can_edit_group: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    /// Offer Cancel on a blocked leave. The chat still reads as `Leaving`;
    /// only the user's Cancel makes it joined again. `cancel_leave` rechecks
    /// that the leave is blocked.
    pub can_cancel_leave: bool,
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
        } else if self.self_membership == SelfMembership::DeviceRemoved {
            P::DeviceRemoved
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
        // Pending confirmation and lifecycle gates affect display actions, not
        // the observed MLS role. A retained departed roster is no active role.
        let admin =
            self.is_member && self.self_membership == SelfMembership::Member && self.is_admin;
        let manage = ordinary && admin;
        // Declining a pending invitation is a Leave too, so an admin invitee
        // demotes first as well.
        let departs_as_admin = admin
            && matches!(participation, P::Active | P::PendingInvitation)
            && !self.disbanding
            && !self.unrecoverable
            && self.lifecycle != AppGroupLifecycleState::Unrecoverable;
        ConversationCapabilities {
            participation,
            is_self_admin: admin,
            is_last_admin: admin && self.admin_count == 1,
            can_send: ordinary,
            can_invite: manage,
            can_edit_group: manage,
            // With device groups on, UserLeave performs any eligible account
            // demotion in core. Otherwise the host demotes first.
            can_leave: ordinary
                && (!admin || (self.admin_leave_steps_down && self.admin_count > 1)),
            requires_self_demote_before_leave: departs_as_admin && !self.admin_leave_steps_down,
            can_cancel_leave: participation == P::Leaving && self.leave_blocked,
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
