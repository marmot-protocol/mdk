//! Group lifecycle, membership, admin, profile, and MLS-state commands.
//!
//! The group-admin preflight helpers and the group-detail/management/mutation
//! builders are co-located here because the group commands are their only
//! callers.

use std::time::Instant;

use cgka_traits::GroupId;

use crate::Marmot;
use crate::conversions::{
    AppBlobEndpointFfi, AppGroupMemberIdsFfi, AppGroupMemberRecordFfi, AppGroupMlsStateFfi,
    AppGroupRecordFfi, AppQuarantinedGroupFfi, DisbandRequestFfi, GroupConversationSnapshotFfi,
    GroupDetailsFfi, GroupInviteDeclineResultFfi, GroupMaintenanceStatusFfi,
    GroupManagementStateFfi, GroupMemberActionStateFfi, GroupMutationResultFfi, GroupRosterFfi,
    KeyPackageMaintenanceStatusFfi, MaintenanceRunSummaryFfi, MemberRefFfi,
    PeriodicMaintenancePolicyFfi, SendSummaryFfi, group_conversation_snapshot_ffi,
    group_details_from_conversation_snapshot_ffi, group_id_from_hex, group_management_state_ffi,
    group_roster_ffi, normalize_member_ref_ffi,
};
use crate::errors::MarmotKitError;

#[derive(Clone, uniffi::Record)]
pub struct InitialGroupImageFfi {
    pub plaintext: Vec<u8>,
    pub media_type: String,
    pub source_url: Option<String>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

impl std::fmt::Debug for InitialGroupImageFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialGroupImageFfi")
            .field("plaintext_len", &self.plaintext.len())
            .field("media_type", &self.media_type)
            .field("has_source_url", &self.source_url.is_some())
            .field("dim", &self.dim)
            .field("thumbhash", &self.thumbhash)
            .finish()
    }
}

pub(crate) async fn group_details_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
) -> Result<GroupDetailsFfi, MarmotKitError> {
    let started_at = Instant::now();
    let result = async {
        let snapshot = kit
            .runtime
            .group_conversation_snapshot(account_ref, group_id)
            .await?;
        group_details_from_conversation_snapshot_ffi(snapshot)
    }
    .await;
    kit.runtime
        .record_group_details_read(started_at.elapsed(), result.is_ok());
    result
}

pub(crate) async fn group_conversation_snapshot_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
) -> Result<GroupConversationSnapshotFfi, MarmotKitError> {
    let started_at = Instant::now();
    let result = async {
        let snapshot = kit
            .runtime
            .group_conversation_snapshot(account_ref, group_id)
            .await?;
        let my_account_id_hex = snapshot.my_account_id_hex.clone();
        let details = group_details_from_conversation_snapshot_ffi(snapshot)?;
        Ok(group_conversation_snapshot_ffi(&my_account_id_hex, details))
    }
    .await;
    kit.runtime
        .record_group_conversation_snapshot_read(started_at.elapsed(), result.is_ok());
    result
}

pub(crate) async fn group_management_state_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    _group_id_hex: &str,
) -> Result<GroupManagementStateFfi, MarmotKitError> {
    let account = kit.runtime.accounts().resolve(account_ref)?;
    let details = group_details_for(kit, account_ref, group_id).await?;
    Ok(group_management_state_ffi(
        &account.account_id_hex,
        &details,
    ))
}

pub(crate) async fn group_mutation_result_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    _group_id_hex: &str,
    summary: SendSummaryFfi,
) -> Result<GroupMutationResultFfi, MarmotKitError> {
    let account = kit.runtime.accounts().resolve(account_ref)?;
    let details = group_details_for(kit, account_ref, group_id).await?;
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

fn validate_group_image_plaintext(plaintext: &[u8]) -> Result<(), MarmotKitError> {
    if plaintext.is_empty() {
        Err(MarmotKitError::InvalidMediaReference {
            details: "group image cannot be empty; use clear_group_image to remove it".into(),
        })
    } else {
        Ok(())
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
    ensure_group_admin(state, group_id_hex)?;
    let (action, normalized) = group_member_action(state, group_id_hex, member_ref)?;
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
    ensure_group_admin(state, group_id_hex)?;
    let (action, normalized) = group_member_action(state, group_id_hex, member_ref)?;
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
    /// referenced by `npub` or hex account id. Returns the locally canonical
    /// group id as hex; this confirms local canonicalization, not Welcome
    /// delivery. `WelcomeDeliveryPending` is a delivery-failure signal, not an
    /// acknowledgement. Hosts should subscribe before creation and/or query
    /// `pending_welcome_deliveries` afterward before presenting invitation
    /// success.
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

    /// Create a group with an optional initial avatar. MDK prefers an
    /// encrypted Blossom image and uses `source_url` only when the founding
    /// members do not all support that component but do support URL avatars.
    pub async fn create_group_with_initial_image(
        &self,
        account_ref: String,
        name: String,
        member_refs: Vec<String>,
        description: Option<String>,
        initial_image: Option<InitialGroupImageFfi>,
    ) -> Result<String, MarmotKitError> {
        let initial_image = initial_image.map(|image| marmot_app::AppInitialGroupImage {
            plaintext: image.plaintext,
            media_type: image.media_type,
            source_url: image.source_url,
            dim: image.dim,
            thumbhash: image.thumbhash,
        });
        let group_id = self
            .runtime
            .create_group_with_initial_image(
                &account_ref,
                &name,
                &member_refs,
                description,
                initial_image,
            )
            .await?;
        Ok(hex::encode(group_id.as_slice()))
    }

    /// Normalize a member reference for group-management UI. Accepts hex,
    /// `npub`, `nostr:npub...`, and `marmot://profile/...` references.
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

    /// Identifier-only rosters for a bounded page of groups.
    ///
    /// This is the chat-projection companion read: it is one worker command,
    /// performs no profile enrichment, and fails the whole page if any group
    /// is unknown or quarantined. Each row includes member and admin
    /// identifiers so recipient-selection screens do not need a per-group
    /// `group_roster` fanout.
    pub async fn group_member_ids_page(
        &self,
        account_ref: String,
        group_ids_hex: Vec<String>,
    ) -> Result<Vec<AppGroupMemberIdsFfi>, MarmotKitError> {
        if group_ids_hex.len() > marmot_app::MAX_GROUP_MEMBER_IDS_PAGE_SIZE {
            return Err(MarmotKitError::InvalidGroupMembershipPage {
                max_groups: marmot_app::MAX_GROUP_MEMBER_IDS_PAGE_SIZE as u64,
            });
        }
        let group_ids = group_ids_hex
            .iter()
            .map(|group_id_hex| group_id_from_hex(group_id_hex))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .runtime
            .group_member_ids_page(&account_ref, &group_ids)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Group plus enriched member rows for detail screens.
    pub async fn group_details(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupDetailsFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        group_details_for(self, &account_ref, &group_id).await
    }

    /// Group details and management state captured for conversation loading in
    /// one worker command. The authoritative group record, roster, and MLS
    /// state share one session/snapshot frontier; management state is derived
    /// from those exact returned details without another await.
    pub async fn group_conversation_snapshot(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupConversationSnapshotFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        group_conversation_snapshot_for(self, &account_ref, &group_id).await
    }

    /// Lightweight membership roster projection for membership screens.
    pub async fn group_roster(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupRosterFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let roster = self.runtime.group_roster(&account_ref, &group_id).await?;
        group_roster_ffi(roster)
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

    /// Install lifecycle-v1 and require it in one admin Commit.
    pub async fn enable_group_disbanding(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .enable_group_disbanding(&account_ref, &group_id)
            .await?;
        group_mutation_result_for(self, &account_ref, &group_id, &group_id_hex, summary.into())
            .await
    }

    /// Durably accept an irreversible disband request. Completion is observed
    /// through normal group state updates after bounded convergence.
    pub async fn disband_group(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<DisbandRequestFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let request = self.runtime.disband_group(&account_ref, &group_id).await?;
        Ok(request.into())
    }

    pub async fn acknowledge_disband_failure(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<bool, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .acknowledge_disband_failure(&account_ref, &group_id)
            .await?)
    }

    /// Invite `member_refs` into an existing group.
    pub async fn invite_members(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        self.invite_members_with_initial_admins(account_ref, group_id_hex, member_refs, Vec::new())
            .await
    }

    /// Invite `member_refs` and grant admin to `initial_admin_refs` in the
    /// same invite commit. Each initial admin must be one of the invitees.
    pub async fn invite_members_with_initial_admins(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
        initial_admin_refs: Vec<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .invite_members_with_initial_admins(
                &account_ref,
                &group_id,
                &member_refs,
                &initial_admin_refs,
            )
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
        // A fast-path reject only, not the source of correctness: this read and
        // the worker command that acts on it are not atomic, so two concurrent
        // leaves can both pass here. The engine settles it under its own lock and
        // returns `EngineError::LeaveAlreadyRequested`, which maps to this same
        // variant — see `MarmotKitError::from_engine_error`.
        //
        // Checked before the two below because a pending leave also clears
        // `can_leave`, so letting them run would report a wrong reason
        // (`MemberNotInGroup`) for a group the account is very much still in.
        if state.leave_request_pending {
            return Err(MarmotKitError::LeaveAlreadyRequested {
                group_id_hex: group_id_hex.clone(),
            });
        }
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
    /// passthrough over the already-public engine API (mdk#571).
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

    /// Encrypt and upload a group avatar to Blossom, then commit the
    /// `marmot.group.blossom.image.v1` component. `plaintext` must contain the
    /// decoded image bytes; use `clear_group_image` to remove an existing
    /// encrypted Blossom avatar.
    pub async fn update_group_image(
        &self,
        account_ref: String,
        group_id_hex: String,
        plaintext: Vec<u8>,
        media_type: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        validate_group_image_plaintext(&plaintext)?;
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .update_group_image(&account_ref, &group_id, plaintext, media_type)
            .await?;
        Ok(summary.into())
    }

    /// Clear the group's encrypted Blossom avatar by committing the absent
    /// `marmot.group.blossom.image.v1` component state.
    pub async fn clear_group_image(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .update_group_image(&account_ref, &group_id, Vec::new(), String::new())
            .await?;
        Ok(summary.into())
    }

    /// Fetch and decrypt the group's encrypted Blossom avatar
    /// (`marmot.group.blossom.image.v1`) into raw image bytes (PNG/JPEG/…).
    /// Errors when the group has no Blossom image set. Presence and the
    /// content hash (for caching) are on `AppGroupRecordFfi::image_hash_hex`;
    /// when the group also carries a URL avatar, the URL takes precedence
    /// for rendering.
    pub async fn download_group_blossom_image(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Vec<u8>, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let bytes = self
            .runtime
            .download_group_blossom_image(&account_ref, &group_id)
            .await?;
        Ok(bytes)
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

    /// Same as [`Self::invite_members`], returning the post-mutation group
    /// snapshot.
    pub async fn invite_members_detailed(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        self.invite_members_detailed_with_initial_admins(
            account_ref,
            group_id_hex,
            member_refs,
            Vec::new(),
        )
        .await
    }

    /// Same as [`Self::invite_members_with_initial_admins`], returning the
    /// post-mutation group snapshot.
    pub async fn invite_members_detailed_with_initial_admins(
        &self,
        account_ref: String,
        group_id_hex: String,
        member_refs: Vec<String>,
        initial_admin_refs: Vec<String>,
    ) -> Result<GroupMutationResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let state =
            group_management_state_for(self, &account_ref, &group_id, &group_id_hex).await?;
        ensure_group_admin(&state, &group_id_hex)?;
        let summary = self
            .runtime
            .invite_members_with_initial_admins(
                &account_ref,
                &group_id,
                &member_refs,
                &initial_admin_refs,
            )
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
    /// rest of the account could open (mdk#151 / #417). These groups are
    /// not in the live roster and otherwise vanish from the account with no
    /// explanation; surface them in a per-group recovery flow (mdk#426)
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

    /// Re-attempt hydration of a single quarantined group (mdk#426).
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

    pub async fn group_maintenance_status(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupMaintenanceStatusFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .maintenance_status(&account_ref, &group_id)
            .await?
            .into())
    }

    pub async fn key_package_maintenance_status(
        &self,
        account_ref: String,
    ) -> Result<Option<KeyPackageMaintenanceStatusFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .key_package_maintenance_status(&account_ref)
            .await?
            .map(Into::into))
    }

    pub async fn schedule_group_self_update(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<String, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .schedule_manual_self_update(&account_ref, &group_id)
            .await?)
    }

    pub async fn periodic_maintenance_policy(
        &self,
        account_ref: String,
    ) -> Result<PeriodicMaintenancePolicyFfi, MarmotKitError> {
        Ok(self
            .runtime
            .periodic_maintenance_policy(&account_ref)
            .await?
            .into())
    }

    pub async fn set_periodic_maintenance_policy(
        &self,
        account_ref: String,
        policy: PeriodicMaintenancePolicyFfi,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .set_periodic_maintenance_policy(&account_ref, policy.into())
            .await?)
    }

    pub async fn pause_maintenance(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.pause_maintenance(&account_ref).await?)
    }

    pub async fn resume_maintenance(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.resume_maintenance(&account_ref).await?)
    }

    pub async fn run_due_maintenance(
        &self,
        account_ref: String,
    ) -> Result<MaintenanceRunSummaryFfi, MarmotKitError> {
        Ok(self.runtime.run_due_maintenance(&account_ref).await?.into())
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    use super::*;

    #[test]
    fn group_conversation_snapshot_round_trips_shape_and_errors() {
        let test_thread = std::thread::Builder::new()
            .name("ffi-group-conversation-snapshot".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(group_conversation_snapshot_round_trip_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn group_conversation_snapshot_round_trip_body() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(root.path(), vec![relay_url.clone()]);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let endpoint = TransportEndpoint(relay_url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create identity");
        let account_ref = account.account.account_id_hex;
        let group_id_hex = kit
            .create_group(
                account_ref.clone(),
                "Snapshot test".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create group");

        let details = kit
            .group_details(account_ref.clone(), group_id_hex.clone())
            .await
            .expect("individual details");
        let management = kit
            .group_management_state(account_ref.clone(), group_id_hex.clone())
            .await
            .expect("individual management state");
        let before = kit.app_performance_snapshot();
        let snapshot = kit
            .group_conversation_snapshot(account_ref.clone(), group_id_hex.clone())
            .await
            .expect("combined conversation snapshot");

        assert_eq!(
            snapshot.details.group.group_id_hex,
            details.group.group_id_hex
        );
        assert_eq!(snapshot.details.group.name, details.group.name);
        assert_eq!(snapshot.details.group.admins, details.group.admins);
        assert_eq!(snapshot.details.mls_state.epoch, details.mls_state.epoch);
        assert_eq!(snapshot.details.members.len(), details.members.len());
        assert_eq!(
            snapshot.management_state.my_account_id_hex,
            management.my_account_id_hex
        );
        assert_eq!(
            snapshot.management_state.is_self_admin,
            management.is_self_admin
        );
        assert_eq!(
            snapshot.management_state.member_actions.len(),
            snapshot.details.members.len()
        );

        let unknown = kit
            .group_conversation_snapshot(account_ref.clone(), "00".to_owned())
            .await
            .expect_err("unknown group must retain typed error mapping");
        assert!(matches!(unknown, MarmotKitError::UnknownGroup { .. }));

        let after = kit.app_performance_snapshot();
        assert_eq!(
            after.group_conversation_snapshot_read.attempts,
            before.group_conversation_snapshot_read.attempts + 2
        );
        assert_eq!(
            after.group_conversation_snapshot_read.successes,
            before.group_conversation_snapshot_read.successes + 1
        );
        assert_eq!(
            after.group_conversation_snapshot_read.failures,
            before.group_conversation_snapshot_read.failures + 1
        );

        kit.runtime.shutdown().await;
        let stopped = kit
            .group_conversation_snapshot(account_ref, group_id_hex)
            .await
            .expect_err("stopped account must retain typed error mapping");
        assert!(matches!(stopped, MarmotKitError::RuntimeStopping));
    }

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
            leave_request_pending: false,
            leave_requested_at_ms: None,
            lifecycle_state: crate::conversions::GroupLifecycleStateFfi::Stable,
            disbanding_enabled: true,
            disbanding: false,
            can_enable_disbanding: false,
            can_disband: self_admin,
            disbanding_blockers: vec![],
            disband_request: None,
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

    #[test]
    fn admin_mutation_preflight_checks_admin_before_membership() {
        // A non-admin caller must not be able to distinguish "member exists" from
        // "member absent" via error-variant differences (membership-existence
        // oracle). Both promote and demote must short-circuit on caller admin
        // status before resolving the target, even for a ref that is not in the
        // group (mdk#667).
        let group_id_hex = "01".repeat(32);
        let absent_member = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

        let promote_err =
            ensure_can_promote_admin(&state(false, false), &group_id_hex, absent_member)
                .expect_err("non-admin promote should fail");
        assert!(matches!(promote_err, MarmotKitError::NotGroupAdmin { .. }));

        let demote_err =
            ensure_can_demote_admin(&state(false, false), &group_id_hex, absent_member)
                .expect_err("non-admin demote should fail");
        assert!(matches!(demote_err, MarmotKitError::NotGroupAdmin { .. }));
    }

    #[test]
    fn group_image_upload_requires_nonempty_plaintext() {
        let err = validate_group_image_plaintext(&[])
            .expect_err("empty image bytes must use the explicit clear method");
        assert!(matches!(
            err,
            MarmotKitError::InvalidMediaReference { details }
                if details.contains("clear_group_image")
        ));
        validate_group_image_plaintext(&[0x89, b'P', b'N', b'G'])
            .expect("nonempty image bytes should reach the runtime");
    }
}
