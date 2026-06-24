//! Group lifecycle, membership, admin, profile, and MLS-state commands.
//!
//! The group-admin preflight helpers and the group-detail/management/mutation
//! builders are co-located here because the group commands are their only
//! callers.

use std::time::Instant;

use cgka_traits::GroupId;

use crate::Marmot;
use crate::conversions::{
    AppBlobEndpointFfi, AppGroupMemberRecordFfi, AppGroupMlsStateFfi, AppGroupRecordFfi,
    AppQuarantinedGroupFfi, GroupDetailsFfi, GroupInviteDeclineResultFfi, GroupManagementStateFfi,
    GroupMemberActionStateFfi, GroupMutationResultFfi, MemberRefFfi, SendSummaryFfi,
    group_details_ffi, group_id_from_hex, group_management_state_ffi, normalize_member_ref_ffi,
};
use crate::errors::MarmotKitError;

pub(crate) async fn group_details_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    group_id_hex: &str,
) -> Result<GroupDetailsFfi, MarmotKitError> {
    let started_at = Instant::now();
    let result = async {
        let account = kit.runtime.accounts().resolve(account_ref)?;
        let group = kit
            .app
            .group(&account.label, group_id_hex)?
            .ok_or_else(|| MarmotKitError::UnknownGroup {
                group_id_hex: group_id_hex.to_string(),
            })?;
        let group = AppGroupRecordFfi::from(group);
        let members = kit
            .runtime
            .group_members(account_ref, group_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<AppGroupMemberRecordFfi>>();
        let member_ids = members
            .iter()
            .map(|member| member.member_id_hex.clone())
            .collect::<Vec<_>>();
        let display_names = kit
            .runtime
            .display_names_for_account_ids(&member_ids)
            .unwrap_or_default();
        group_details_ffi(group, members, &account.account_id_hex, display_names)
    }
    .await;
    kit.runtime
        .record_group_details_read(started_at.elapsed(), result.is_ok());
    result
}

pub(crate) async fn group_management_state_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    group_id_hex: &str,
) -> Result<GroupManagementStateFfi, MarmotKitError> {
    let account = kit.runtime.accounts().resolve(account_ref)?;
    let details = group_details_for(kit, account_ref, group_id, group_id_hex).await?;
    Ok(group_management_state_ffi(
        &account.account_id_hex,
        &details,
    ))
}

pub(crate) async fn group_mutation_result_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    group_id_hex: &str,
    summary: SendSummaryFfi,
) -> Result<GroupMutationResultFfi, MarmotKitError> {
    let account = kit.runtime.accounts().resolve(account_ref)?;
    let details = group_details_for(kit, account_ref, group_id, group_id_hex).await?;
    let management_state = group_management_state_ffi(&account.account_id_hex, &details);
    Ok(GroupMutationResultFfi {
        summary,
        details,
        management_state,
    })
}

fn group_member_action<'a>(
    state: &'a GroupManagementStateFfi,
    group_id_hex: &str,
    member_ref: &str,
) -> Result<(&'a GroupMemberActionStateFfi, MemberRefFfi), MarmotKitError> {
    let normalized = normalize_member_ref_ffi(member_ref)?;
    let action = state
        .member_actions
        .iter()
        .find(|member| member.member_id_hex == normalized.account_id_hex)
        .ok_or_else(|| MarmotKitError::MemberNotInGroup {
            group_id_hex: group_id_hex.to_string(),
            member_id_hex: normalized.account_id_hex.clone(),
        })?;
    Ok((action, normalized))
}

fn ensure_group_admin(
    state: &GroupManagementStateFfi,
    group_id_hex: &str,
) -> Result<(), MarmotKitError> {
    if state.is_self_admin {
        Ok(())
    } else {
        Err(MarmotKitError::NotGroupAdmin {
            group_id_hex: group_id_hex.to_string(),
        })
    }
}

fn ensure_can_remove_members(
    state: &GroupManagementStateFfi,
    group_id_hex: &str,
    member_refs: &[String],
) -> Result<(), MarmotKitError> {
    ensure_group_admin(state, group_id_hex)?;
    for member_ref in member_refs {
        let (action, normalized) = group_member_action(state, group_id_hex, member_ref)?;
        if action.is_self {
            return Err(MarmotKitError::AdminCannotSelfRemove {
                group_id_hex: group_id_hex.to_string(),
            });
        }
        if !action.can_remove && action.is_admin {
            return Err(MarmotKitError::WouldRemoveLastAdmin {
                group_id_hex: group_id_hex.to_string(),
            });
        }
        if !action.can_remove {
            return Err(MarmotKitError::Runtime {
                details: format!(
                    "member {} cannot be removed from group {}",
                    normalized.account_id_hex, group_id_hex
                ),
            });
        }
    }
    Ok(())
}

fn ensure_can_promote_admin(
    state: &GroupManagementStateFfi,
    group_id_hex: &str,
    member_ref: &str,
) -> Result<(), MarmotKitError> {
    let (action, normalized) = group_member_action(state, group_id_hex, member_ref)?;
    ensure_group_admin(state, group_id_hex)?;
    if action.is_admin {
        Err(MarmotKitError::AlreadyAdmin {
            group_id_hex: group_id_hex.to_string(),
            member_id_hex: normalized.account_id_hex,
        })
    } else {
        Ok(())
    }
}

fn ensure_can_demote_admin(
    state: &GroupManagementStateFfi,
    group_id_hex: &str,
    member_ref: &str,
) -> Result<(), MarmotKitError> {
    let (action, normalized) = group_member_action(state, group_id_hex, member_ref)?;
    ensure_group_admin(state, group_id_hex)?;
    if !action.is_admin {
        return Err(MarmotKitError::NotAdmin {
            group_id_hex: group_id_hex.to_string(),
            member_id_hex: normalized.account_id_hex,
        });
    }
    if state.is_last_admin {
        return Err(MarmotKitError::WouldRemoveLastAdmin {
            group_id_hex: group_id_hex.to_string(),
        });
    }
    Ok(())
}

fn ensure_can_self_demote_admin(
    state: &GroupManagementStateFfi,
    group_id_hex: &str,
) -> Result<(), MarmotKitError> {
    if !state.is_self_admin {
        return Err(MarmotKitError::NotAdmin {
            group_id_hex: group_id_hex.to_string(),
            member_id_hex: state.my_account_id_hex.clone(),
        });
    }
    if state.is_last_admin {
        return Err(MarmotKitError::WouldRemoveLastAdmin {
            group_id_hex: group_id_hex.to_string(),
        });
    }
    Ok(())
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    // -----------------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------------

    /// Create a new MLS group with `name` and the given members. Members are
    /// referenced by `npub` or hex account id. Returns the group id as hex.
    pub async fn create_group(
        &self,
        account_ref: String,
        name: String,
        member_refs: Vec<String>,
        description: Option<String>,
    ) -> Result<String, MarmotKitError> {
        let group_id = self
            .runtime
            .create_group(&account_ref, &name, &member_refs, description)
            .await?;
        Ok(hex::encode(group_id.as_slice()))
    }

    /// Normalize a member reference for group-management UI. Accepts hex,
    /// `npub`, `nostr:npub...`, and `darkmatter://profile/...` references.
    pub fn normalize_member_ref(&self, member_ref: String) -> Result<MemberRefFfi, MarmotKitError> {
        normalize_member_ref_ffi(&member_ref)
    }

    /// Membership roster for `group_id_hex`.
    pub async fn group_members(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Vec<AppGroupMemberRecordFfi>, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let members = self.runtime.group_members(&account_ref, &group_id).await?;
        Ok(members.into_iter().map(Into::into).collect())
    }

    /// Group plus enriched member rows for detail screens.
    pub async fn group_details(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupDetailsFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        group_details_for(self, &account_ref, &group_id, &group_id_hex).await
    }

    /// Current caller permissions plus per-member action availability.
    pub async fn group_management_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupManagementStateFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await
    }

    pub async fn invite_members(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .invite_members(&account_ref, &group_id, &member_refs)
            .await?;
        Ok(summary.into())
    }

    pub async fn remove_members(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_remove_members(&state, &group_id_hex, &member_refs)?;
        let summary = self
            .runtime
            .remove_members(&account_ref, &group_id, &member_refs)
            .await?;
        Ok(summary.into())
    }

    pub async fn leave_group(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        if state.requires_self_demote_before_leave {
            return Err(MarmotKitError::AdminCannotSelfRemove {
                group_id_hex: group_id_hex.clone(),
            });
        }
        if !state.can_leave {
            return Err(MarmotKitError::MemberNotInGroup {
                group_id_hex: group_id_hex.clone(),
                member_id_hex: state.my_account_id_hex,
            });
        }
        let summary = self.runtime.leave_group(&account_ref, &group_id).await?;
        Ok(summary.into())
    }

    /// Delete this group's local app data without performing an MLS leave. The
    /// caller should cancel any active UI subscriptions for the group before
    /// invoking the wipe. The runtime removes the active transport route, then
    /// transactionally drops the chat-list/account projection, plaintext app
    /// events, timeline rows, agent-stream projection rows, push-token rows, and
    /// cached encrypted-media epoch secrets. MLS/OpenMLS group state is left
    /// intact; a future fresh group delivery can recreate a local chat row.
    /// Returns true if any local rows or a live route were removed.
    pub async fn delete_group_local(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<bool, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .delete_group_local(&account_ref, &group_id)
            .await?)
    }

    /// Set the per-group disappearing-message retention, wrapping the engine's
    /// `update_message_retention`. `disappearing_message_secs` of `0` disables
    /// expiry; any positive value is the retention window in seconds. Thin
    /// passthrough over the already-public engine API (darkmatter#571).
    pub async fn update_message_retention(
        &self,
        account_ref: String,
        group_id_hex: String,
        disappearing_message_secs: u64,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .update_message_retention(&account_ref, &group_id, disappearing_message_secs)
            .await?;
        Ok(summary.into())
    }

    pub async fn accept_group_invite(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<AppGroupRecordFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group = self
            .runtime
            .accept_group_invite(&account_ref, &group_id)
            .await?;
        Ok(group.into())
    }

    pub async fn decline_group_invite(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupInviteDeclineResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let result = self
            .runtime
            .decline_group_invite(&account_ref, &group_id)
            .await?;
        Ok(result.into())
    }

    pub async fn update_group_profile(
        &self,
        account_ref: String,
        group_id_hex: String,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .update_group_profile(&account_ref, &group_id, name, description)
            .await?;
        Ok(summary.into())
    }

    /// Set (or clear, with `url = None`) the group's URL-based avatar
    /// (`marmot.group.avatar-url.v1`). The URL is validated (https-only, no
    /// localhost/private hosts) and normalized before it is committed.
    pub async fn update_group_avatar_url(
        &self,
        account_ref: String,
        group_id_hex: String,
        url: Option<String>,
        dim: Option<String>,
        thumbhash: Option<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .update_group_avatar_url(&account_ref, &group_id, url, dim, thumbhash)
            .await?;
        Ok(summary.into())
    }

    /// Replace the group's encrypted-media default blob endpoints as a full
    /// `marmot.group.encrypted-media.v1` component update. Requires the caller
    /// to be an admin.
    pub async fn replace_encrypted_media_blob_endpoints(
        &self,
        account_ref: String,
        group_id_hex: String,
        endpoints: Vec<AppBlobEndpointFfi>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .replace_encrypted_media_blob_endpoints(
                &account_ref,
                &group_id,
                endpoints.into_iter().map(Into::into).collect(),
            )
            .await?;
        Ok(summary.into())
    }

    /// Grant admin rights to `member_ref` (npub or hex). Requires the caller
    /// to be an admin; publishes a group state update.
    pub async fn promote_admin(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_ref: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_promote_admin(&state, &group_id_hex, &member_ref)?;
        let summary = self
            .runtime
            .promote_admin(&account_ref, &group_id, &member_ref)
            .await?;
        Ok(summary.into())
    }

    /// Revoke `member_ref`'s admin rights.
    pub async fn demote_admin(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_ref: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_demote_admin(&state, &group_id_hex, &member_ref)?;
        let summary = self
            .runtime
            .demote_admin(&account_ref, &group_id, &member_ref)
            .await?;
        Ok(summary.into())
    }

    /// Step down as an admin of `group_id_hex` (demote the active account).
    pub async fn self_demote_admin(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_self_demote_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .self_demote_admin(&account_ref, &group_id)
            .await?;
        Ok(summary.into())
    }

    pub async fn invite_members_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .invite_members(&account_ref, &group_id, &member_refs)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    pub async fn remove_members_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_remove_members(&state, &group_id_hex, &member_refs)?;
        let summary = self
            .runtime
            .remove_members(&account_ref, &group_id, &member_refs)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    pub async fn promote_admin_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_ref: String,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_promote_admin(&state, &group_id_hex, &member_ref)?;
        let summary = self
            .runtime
            .promote_admin(&account_ref, &group_id, &member_ref)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    pub async fn demote_admin_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_ref: String,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_demote_admin(&state, &group_id_hex, &member_ref)?;
        let summary = self
            .runtime
            .demote_admin(&account_ref, &group_id, &member_ref)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    pub async fn self_demote_admin_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_can_self_demote_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .self_demote_admin(&account_ref, &group_id)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    /// Current MLS state (epoch, member count, required components) for the
    /// conversation developer/debug view.
    pub async fn group_mls_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<AppGroupMlsStateFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let state = self
            .runtime
            .group_mls_state(&account_ref, &group_id)
            .await?;
        Ok(state.into())
    }

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (darkmatter#151 / #417). These groups are
    /// not in the live roster and otherwise vanish from the account with no
    /// explanation; surface them in a per-group recovery flow (darkmatter#426)
    /// distinct from healthy and archived groups, using `reason` to pick the
    /// per-reason guidance, and offer
    /// [`Self::retry_hydrate_quarantined_group`].
    pub async fn quarantined_groups(
        &self,
        account_ref: String,
    ) -> Result<Vec<AppQuarantinedGroupFfi>, MarmotKitError> {
        let groups = self.runtime.quarantined_groups(&account_ref).await?;
        Ok(groups.into_iter().map(Into::into).collect())
    }

    /// Re-attempt hydration of a single quarantined group (darkmatter#426).
    ///
    /// Non-destructive, user-initiated recovery for a transiently-bad group
    /// (e.g. a partial DB restore that has since completed). Returns `true` if
    /// the group recovered and is now a live chat (it leaves the quarantine
    /// list and reappears in the chat list), `false` if it is still unhealthy
    /// and stays quarantined. Errors with `UnknownGroup` if the id is not
    /// currently quarantined.
    pub async fn retry_hydrate_quarantined_group(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<bool, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .retry_hydrate_quarantined_group(&account_ref, &group_id)
            .await?)
    }

    /// Flag a group archived (or restore it). Local-only projection state —
    /// it does not change membership or publish anything. The chats list
    /// filters archived groups unless `include_archived` is set.
    pub async fn set_group_archived(
        &self,
        account_ref: String,
        group_id_hex: String,
        archived: bool,
    ) -> Result<AppGroupRecordFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .runtime
            .set_group_archived(&account_ref, &group_id_hex, archived)
            .await?;
        Ok(group.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(self_admin: bool, last_admin: bool) -> GroupManagementStateFfi {
        let self_id = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
        let member_id = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        GroupManagementStateFfi {
            my_account_id_hex: self_id.into(),
            is_self_admin: self_admin,
            is_last_admin: last_admin,
            can_invite: self_admin,
            can_leave: !self_admin,
            requires_self_demote_before_leave: self_admin,
            member_actions: vec![
                GroupMemberActionStateFfi {
                    member_id_hex: self_id.into(),
                    is_self: true,
                    is_admin: self_admin,
                    can_remove: false,
                    can_promote: false,
                    can_demote: false,
                },
                GroupMemberActionStateFfi {
                    member_id_hex: member_id.into(),
                    is_self: false,
                    is_admin: true,
                    can_remove: self_admin && !last_admin,
                    can_promote: false,
                    can_demote: self_admin && !last_admin,
                },
            ],
        }
    }

    #[test]
    fn promote_preflight_returns_already_admin() {
        let group_id_hex = "01".repeat(32);
        let member_id = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let err = ensure_can_promote_admin(&state(true, false), &group_id_hex, member_id)
            .expect_err("promoting an admin should fail");
        assert!(matches!(err, MarmotKitError::AlreadyAdmin { .. }));
    }

    #[test]
    fn self_demote_preflight_protects_last_admin() {
        let group_id_hex = "01".repeat(32);
        let err = ensure_can_self_demote_admin(&state(true, true), &group_id_hex)
            .expect_err("last admin self-demote should fail");
        assert!(matches!(err, MarmotKitError::WouldRemoveLastAdmin { .. }));
    }

    #[test]
    fn admin_mutation_preflight_checks_caller_admin_first() {
        let group_id_hex = "01".repeat(32);
        let member_id = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let err = ensure_can_demote_admin(&state(false, false), &group_id_hex, member_id)
            .expect_err("non-admin caller should fail");
        assert!(matches!(err, MarmotKitError::NotGroupAdmin { .. }));
    }
}
