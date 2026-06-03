//! UniFFI bindings for the Marmot app runtime.
//!
//! This crate is a thin FFI adapter over [`marmot_app::MarmotApp`] and
//! [`marmot_app::MarmotAppRuntime`]. It is consumed by generated Swift and
//! Kotlin bindings, plus anything else that wants a UniFFI-shaped surface.
//!
//! Design notes:
//! - One process-wide [`Marmot`] handle owns the [`MarmotApp`] + runtime pair.
//! - All async methods rely on UniFFI's tokio integration (the global tokio
//!   runtime is implicit via the `async_runtime = "tokio"` attribute).
//! - Internal Rust types that don't map cleanly across the FFI boundary are
//!   re-exposed as FFI-friendly records (e.g. byte ids → hex strings,
//!   variant-with-payload enums → flattened variants).
//! - Subscriptions are returned as long-lived `uniffi::Object` instances;
//!   host apps drive them by awaiting `next()` until it returns `None`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::{GroupId, TransportEndpoint};
use marmot_app::{
    AccountSetupRequest, AppMessageQuery, ForensicsExportOptions, MarmotApp, MarmotAppRuntime,
    TimelineMessageQuery, TimelinePagination, UserProfileMetadata,
};
use rand::RngCore;
use rand::rngs::OsRng;

mod conversions;
mod errors;
mod subscriptions;

use conversions::{
    AccountSummaryFfi, AgentStreamStartFfi, AppGroupMemberRecordFfi, AppGroupMlsStateFfi,
    AppGroupRecordFfi, AppMessageRecordFfi, GroupDetailsFfi, GroupInviteDeclineResultFfi,
    GroupManagementStateFfi, GroupMemberActionStateFfi, GroupMutationResultFfi, MemberRefFfi,
    SendSummaryFfi, UserProfileMetadataFfi, group_details_ffi, group_id_from_hex,
    group_management_state_ffi, media_records_ffi, normalize_member_ref_ffi,
};
pub use errors::MarmotKitError;
use subscriptions::{
    AgentStreamSubscription, ChatListSubscription, ChatsSubscription, EventsSubscription,
    GroupStateSubscription, MessagesSubscription, NotificationsSubscription,
    TimelineMessagesSubscription,
};

uniffi::setup_scaffolding!();

pub use conversions::{
    BackgroundNotificationCollectionFfi, ChatListAvatarFfi, ChatListMessagePreviewFfi,
    ChatListRowFfi, ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi, ForensicsDumpModeFfi,
    GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi, LocalPushRegistrationDebugFfi,
    MediaDownloadResultFfi, MediaRecordFfi, MediaReferenceFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi, NotificationCollectionStatusFfi, NotificationSettingsFfi,
    NotificationTriggerFfi, NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi,
    PushPlatformFfi, PushRegistrationFfi, RuntimeProjectionUpdateFfi, TimelineMessageChangeFfi,
    TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineSubscriptionUpdateFfi, TimelineUpdateTriggerFfi,
    TimelineUserReactionFfi,
};

/// Convenience: turn an FFI string list of relay URLs into the engine's
/// [`TransportEndpoint`] wrapper, dedup-stripped of empties.
fn endpoints(urls: &[String]) -> Vec<TransportEndpoint> {
    urls.iter()
        .filter(|u| !u.trim().is_empty())
        .map(|u| TransportEndpoint::from(u.as_str()))
        .collect()
}

fn random_agent_stream_id() -> Vec<u8> {
    let mut stream_id = vec![0; 32];
    OsRng.fill_bytes(&mut stream_id);
    stream_id
}

fn random_forensics_public_salt() -> Vec<u8> {
    let mut salt = vec![0_u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn forensics_public_salt(
    public_redaction_salt_hex: Option<String>,
) -> Result<Vec<u8>, MarmotKitError> {
    let Some(value) = public_redaction_salt_hex else {
        return Ok(random_forensics_public_salt());
    };
    let salt = hex::decode(value.trim()).map_err(|err| MarmotKitError::InvalidHex {
        details: err.to_string(),
    })?;
    if salt.len() < 16 {
        return Err(MarmotKitError::InvalidHex {
            details: "public redaction salt must be at least 16 bytes".to_owned(),
        });
    }
    Ok(salt)
}

fn optional_group_id_hex(group_id_hex: Option<String>) -> Result<Option<String>, MarmotKitError> {
    match group_id_hex {
        Some(value) if !value.trim().is_empty() => Ok(Some(hex::encode(
            group_id_from_hex(value.trim())?.as_slice(),
        ))),
        _ => Ok(None),
    }
}

fn optional_message_id_hex(
    message_id_hex: Option<String>,
) -> Result<Option<String>, MarmotKitError> {
    let Some(value) = message_id_hex else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(value).map_err(|err| MarmotKitError::InvalidHex {
        details: err.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(MarmotKitError::InvalidHex {
            details: format!("expected 32-byte message id, got {} bytes", bytes.len()),
        });
    }
    Ok(Some(hex::encode(bytes)))
}

fn timeline_query_from_ffi(
    query: TimelineMessageQueryFfi,
) -> Result<TimelineMessageQuery, MarmotKitError> {
    Ok(TimelineMessageQuery {
        group_id_hex: optional_group_id_hex(query.group_id_hex)?,
        search: query.search.and_then(|value| {
            let value = value.trim().to_owned();
            (!value.is_empty()).then_some(value)
        }),
        pagination: TimelinePagination {
            before: query.before,
            before_message_id: optional_message_id_hex(query.before_message_id)?,
            after: query.after,
            after_message_id: optional_message_id_hex(query.after_message_id)?,
            limit: query.limit.map(|value| value as usize),
        },
    })
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn group_details_for(
    kit: &Marmot,
    account_ref: &str,
    group_id: &GroupId,
    group_id_hex: &str,
) -> Result<GroupDetailsFfi, MarmotKitError> {
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
    let display_names = members
        .iter()
        .filter_map(|member| {
            kit.runtime
                .display_name_for_account_id(&member.member_id_hex)
                .map(|display_name| (member.member_id_hex.clone(), display_name))
        })
        .collect();
    group_details_ffi(group, members, &account.account_id_hex, display_names)
}

async fn group_management_state_for(
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

async fn group_mutation_result_for(
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

#[derive(uniffi::Object)]
pub struct Marmot {
    app: MarmotApp,
    runtime: MarmotAppRuntime,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Open the Marmot app at `root_path`, configured with the given default
    /// relay URLs. Account secrets (Nostr private keys) are stored in the
    /// platform keyring (Keychain on Apple platforms, Android's native
    /// keyring on Android) via the default keychain-backed account home —
    /// not in a plaintext file. Fallible because initializing the platform
    /// secret store can fail. Call [`Marmot::start`] before subscribing to
    /// events.
    #[uniffi::constructor]
    pub fn new(root_path: String, relay_urls: Vec<String>) -> Result<Arc<Self>, MarmotKitError> {
        let account_home = marmot_account::AccountHome::open_with_default_keychain(&root_path)
            .map_err(marmot_app::AppError::from)?;
        let app = MarmotApp::with_relays_and_account_home(&root_path, relay_urls, account_home);
        let runtime = app.runtime();
        Ok(Arc::new(Self { app, runtime }))
    }

    /// Bring the runtime online: reconcile known accounts, start workers,
    /// subscribe to transport events.
    pub async fn start(&self) -> Result<(), MarmotKitError> {
        self.runtime.start().await?;
        Ok(())
    }

    /// Tear the runtime down. Drops all subscriptions; long-lived
    /// [`EventsSubscription`] / [`ChatsSubscription`] / etc. instances on the
    /// host side will see their `next()` return `None` shortly after.
    pub async fn shutdown(&self) {
        self.runtime.shutdown().await;
    }

    /// True once shutdown has started. Host apps can use this to avoid
    /// launching more subscriptions or account work while they are moving to
    /// the background.
    pub fn is_stopping(&self) -> bool {
        self.runtime.is_stopping()
    }

    // -----------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------

    /// All accounts known to the runtime, in stable order. `running` is
    /// `false` for accounts that haven't been brought up by the current
    /// process yet.
    pub fn list_accounts(&self) -> Result<Vec<AccountSummaryFfi>, MarmotKitError> {
        let managed = self.runtime.accounts().managed_accounts()?;
        Ok(managed
            .into_iter()
            .map(|m| AccountSummaryFfi {
                label: m.label,
                account_id_hex: m.account_id_hex,
                local_signing: m.local_signing,
                running: m.running,
            })
            .collect())
    }

    /// Create a brand-new Nostr identity, store its secret in the platform
    /// keychain, and publish initial relay lists + key package.
    pub async fn create_identity(
        &self,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.create_identity(request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            running: true,
        })
    }

    /// Log in with an existing identity. `identity` can be an `nsec` (private
    /// key) for a local-signing account, or an `npub` to track a public
    /// identity without local signing.
    pub async fn login(
        &self,
        identity: String,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<AccountSummaryFfi, MarmotKitError> {
        let request = AccountSetupRequest {
            identity: None,
            default_relays: endpoints(&default_relays),
            bootstrap_relays: endpoints(&bootstrap_relays),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
        };
        let result = self.runtime.login(identity, request).await?;
        Ok(AccountSummaryFfi {
            label: result.account.label,
            account_id_hex: result.account.account_id_hex,
            local_signing: result.account.local_signing,
            running: true,
        })
    }

    /// Publish (or re-publish) NIP-65, inbox, and key-package relay lists for
    /// `account_ref`. Idempotent — safe to call on every launch.
    pub async fn publish_relay_lists(
        &self,
        account_ref: String,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        let bootstrap = marmot_app::AccountRelayListBootstrap::new(
            endpoints(&default_relays),
            endpoints(&bootstrap_relays),
        );
        self.app
            .publish_account_relay_lists(&account_ref, bootstrap)
            .await?;
        Ok(())
    }

    pub fn account_nip65_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_nip65_relays(&account_ref)?)
    }

    pub fn account_inbox_relays(&self, account_ref: String) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_inbox_relays(&account_ref)?)
    }

    pub fn account_key_package_relays(
        &self,
        account_ref: String,
    ) -> Result<Vec<String>, MarmotKitError> {
        Ok(self.runtime.account_key_package_relays(&account_ref)?)
    }

    /// List the local and relay-discovered Marmot KeyPackage publications for
    /// `account_ref`.
    pub async fn account_key_packages(
        &self,
        account_ref: String,
        bootstrap_relays: Vec<String>,
    ) -> Result<Vec<conversions::AccountKeyPackageFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .account_key_packages(&account_ref, endpoints(&bootstrap_relays))
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Publish a new fresh KeyPackage for `account_ref`.
    pub async fn publish_new_key_package(
        &self,
        account_ref: String,
    ) -> Result<u64, MarmotKitError> {
        Ok(self.runtime.publish_new_key_package(&account_ref).await? as u64)
    }

    /// Re-publish the latest cached KeyPackage when possible, otherwise
    /// publish a fresh one.
    pub async fn republish_key_package(&self, account_ref: String) -> Result<u64, MarmotKitError> {
        Ok(self.runtime.publish_key_package(&account_ref).await? as u64)
    }

    /// Publish a NIP-09 deletion for a KeyPackage event.
    pub async fn delete_account_key_package(
        &self,
        account_ref: String,
        event_id_hex: String,
        relays: Vec<String>,
    ) -> Result<u64, MarmotKitError> {
        Ok(self
            .runtime
            .delete_key_package(&account_ref, &event_id_hex, endpoints(&relays))
            .await? as u64)
    }

    pub async fn set_account_nip65_relays(
        &self,
        account_ref: String,
        relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let status = self
            .runtime
            .set_account_nip65_relays(
                &account_ref,
                endpoints(&relays),
                endpoints(&bootstrap_relays),
            )
            .await?;
        Ok(status.into())
    }

    pub async fn set_account_inbox_relays(
        &self,
        account_ref: String,
        relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let status = self
            .runtime
            .set_account_inbox_relays(
                &account_ref,
                endpoints(&relays),
                endpoints(&bootstrap_relays),
            )
            .await?;
        Ok(status.into())
    }

    pub async fn set_account_key_package_relays(
        &self,
        account_ref: String,
        relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let status = self
            .runtime
            .set_account_key_package_relays(
                &account_ref,
                endpoints(&relays),
                endpoints(&bootstrap_relays),
            )
            .await?;
        Ok(status.into())
    }

    /// Publish the Nostr kind:0 metadata for `account_ref`. The returned
    /// metadata is what marmot-app actually published (any server-applied
    /// defaults are reflected here).
    pub async fn publish_user_profile(
        &self,
        account_ref: String,
        profile: UserProfileMetadataFfi,
        default_relays: Vec<String>,
        bootstrap_relays: Vec<String>,
    ) -> Result<UserProfileMetadataFfi, MarmotKitError> {
        let bootstrap = marmot_app::AccountRelayListBootstrap::new(
            endpoints(&default_relays),
            endpoints(&bootstrap_relays),
        );
        let pushed = self
            .runtime
            .publish_user_profile(&account_ref, UserProfileMetadata::from(profile), bootstrap)
            .await?;
        Ok(pushed.into())
    }

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

    /// Export a forensic JSON bundle for this account/device's local view of a
    /// group. Public mode redacts operational identifiers, payload bytes, and
    /// stable payload digests. Pass the same public salt across devices when
    /// comparing public dumps from one incident.
    pub async fn group_forensics_json(
        &self,
        account_ref: String,
        group_id_hex: String,
        mode: ForensicsDumpModeFfi,
        public_redaction_salt_hex: Option<String>,
    ) -> Result<String, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let mode = mode.into();
        let options = match mode {
            marmot_app::ForensicsDumpMode::Public => {
                ForensicsExportOptions::public(forensics_public_salt(public_redaction_salt_hex)?)
            }
            marmot_app::ForensicsDumpMode::Sensitive => ForensicsExportOptions::sensitive(),
        };
        let bundle = self
            .runtime
            .group_forensics_bundle(&account_ref, &group_id, options)
            .await?;
        serde_json::to_string_pretty(&bundle).map_err(|err| MarmotKitError::Runtime {
            details: err.to_string(),
        })
    }

    /// Flag a group archived (or restore it). Local-only projection state —
    /// it does not change membership or publish anything. The chats list
    /// filters archived groups unless `include_archived` is set.
    pub fn set_group_archived(
        &self,
        account_ref: String,
        group_id_hex: String,
        archived: bool,
    ) -> Result<AppGroupRecordFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let group_id_hex = hex::encode(group_id.as_slice());
        let group = self
            .runtime
            .set_group_archived(&account_ref, &group_id_hex, archived)?;
        Ok(group.into())
    }

    // -----------------------------------------------------------------------
    // Messaging
    // -----------------------------------------------------------------------

    /// Send a plain UTF-8 text message. Structured payloads (reactions,
    /// replies, deletes, media) go through dedicated methods.
    pub async fn send_text(
        &self,
        account_ref: String,
        group_id_hex: String,
        text: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .send_message(&account_ref, &group_id, text.into_bytes())
            .await?;
        Ok(summary.into())
    }

    /// React to `target_message_id` with `emoji` (an "add" reaction).
    pub async fn react_to_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        emoji: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .react_to_message(&account_ref, &group_id, &target_message_id, &emoji)
            .await?;
        Ok(summary.into())
    }

    /// Remove this account's reaction from `target_message_id`.
    pub async fn unreact_from_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .unreact_from_message(&account_ref, &group_id, &target_message_id)
            .await?;
        Ok(summary.into())
    }

    /// Send `text` as a reply that quotes `target_message_id`.
    pub async fn reply_to_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        text: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .reply_to_message(&account_ref, &group_id, &target_message_id, &text)
            .await?;
        Ok(summary.into())
    }

    /// Mark `target_message_id` deleted for the whole group. This is a
    /// tombstone — the original stays in everyone's store; clients render a
    /// "message deleted" placeholder.
    pub async fn delete_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .delete_message(&account_ref, &group_id, &target_message_id)
            .await?;
        Ok(summary.into())
    }

    /// Send an already-uploaded encrypted media reference as a kind-9 chat
    /// carrying a NIP-92 `imeta` tag.
    pub async fn send_media_reference(
        &self,
        account_ref: String,
        group_id_hex: String,
        reference: MediaReferenceFfi,
        caption: Option<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .send_media_reference(&account_ref, &group_id, reference.into(), caption)
            .await?;
        Ok(summary.into())
    }

    /// Encrypt plaintext, upload the ciphertext to Blossom, and optionally
    /// send the resulting media reference into the group.
    pub async fn upload_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        request: MediaUploadRequestFfi,
    ) -> Result<MediaUploadResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let upload = self
            .runtime
            .upload_media(&account_ref, &group_id, request.into())
            .await?;
        Ok(upload.into())
    }

    /// Fetch an encrypted Blossom blob and decrypt it using the group's
    /// MIP-04 encrypted-media exporter secret.
    pub async fn download_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        reference: MediaReferenceFfi,
    ) -> Result<MediaDownloadResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let download = self
            .runtime
            .download_media(&account_ref, &group_id, reference.into())
            .await?;
        Ok(download.into())
    }

    /// Typed media references projected from group message history. Host apps
    /// can pass a returned `reference` back to `download_media`.
    pub fn list_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        limit: Option<u32>,
    ) -> Result<Vec<MediaRecordFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let records = self.runtime.messages_with_query(
            &account_ref,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: limit.map(|n| n as usize),
            },
        )?;
        Ok(media_records_ffi(records))
    }

    /// Anchor a live agent text stream start in the encrypted group history.
    /// Host apps pass the broker candidate(s) they will publish to, such as
    /// `quic://quic-broker.ipf.dev:4450`; omit `stream_id_hex` to let Rust
    /// generate a 32-byte stream id.
    pub async fn start_agent_text_stream(
        &self,
        account_ref: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<AgentStreamStartFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let stream_id = match stream_id_hex {
            Some(value) => hex::decode(value).map_err(|err| MarmotKitError::InvalidHex {
                details: err.to_string(),
            })?,
            None => random_agent_stream_id(),
        };
        let stream_id_hex = hex::encode(&stream_id);
        let (_, summary) = self
            .runtime
            .start_agent_text_stream(
                &account_ref,
                &group_id,
                &stream_id,
                unix_now_seconds(),
                quic_candidates,
            )
            .await?;
        Ok(AgentStreamStartFfi::new(stream_id_hex, summary))
    }

    /// Watch a live agent text stream over the brokered QUIC channel. Pass
    /// `stream_id_hex = None` to follow the latest stream in the group (the
    /// common case when reacting to an AgentStreamStarted event). The returned
    /// subscription yields incremental `Chunk`s then a terminal `Finished` /
    /// `Failed`. `server_cert_der` pins a self-signed broker cert (else platform
    /// trust); `insecure_local` is loopback-only for testing.
    ///
    /// `async` only so the underlying runtime call can spawn the QUIC
    /// subscriber task via `tokio::spawn` (which needs an active runtime); the
    /// method itself does not await. Mirrors `subscribe_chats` /
    /// `subscribe_messages`.
    pub async fn watch_agent_text_stream(
        &self,
        account_ref: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        server_cert_der: Option<Vec<u8>>,
        insecure_local: bool,
    ) -> Result<Arc<AgentStreamSubscription>, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let watch = self
            .runtime
            .watch_agent_text_stream(
                &account_ref,
                &group_id,
                marmot_app::AgentStreamWatchOptions {
                    stream_id_hex,
                    server_cert_der,
                    insecure_local,
                },
            )
            .await?;
        Ok(AgentStreamSubscription::new(watch))
    }

    /// Best-effort cached display name for an account id. Returns the Nostr
    /// kind:0 display_name/name when the runtime has projected one, or the
    /// local account label if the id refers to one of our own accounts.
    /// `None` when nothing is known yet — call `refresh_directory` to fetch.
    pub fn display_name(&self, account_id_hex: String) -> Option<String> {
        self.runtime.display_name_for_account_id(&account_id_hex)
    }

    /// Convert a hex account id (Nostr public key) into its `npub…` bech32
    /// form for display. `None` if the hex isn't a valid public key.
    pub fn npub(&self, account_id_hex: String) -> Option<String> {
        marmot_app::npub_for_account_id(&account_id_hex).ok()
    }

    /// Normalize a public-key reference (npub or hex) to canonical hex.
    /// `None` if it isn't a valid public key. Used to resolve a scanned or
    /// deep-linked npub back to the account id the rest of the API expects.
    pub fn account_id_hex(&self, reference: String) -> Option<String> {
        normalize_member_ref_ffi(&reference)
            .ok()
            .map(|normalized| normalized.account_id_hex)
    }

    /// Per-account relay lists: the NIP-65, inbox, and key-package lists the
    /// account has published, plus the configured default/bootstrap sets.
    pub fn account_relay_lists(
        &self,
        account_ref: String,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let account = self.runtime.accounts().resolve(&account_ref)?;
        let status = self.app.account_relay_list_status(&account.label)?;
        Ok(status.into())
    }

    /// Live relay-plane connection health (connected / connecting /
    /// disconnected counts, etc.) for the relay diagnostics view.
    pub async fn relay_health(&self) -> conversions::RelayHealthFfi {
        let shared = self.runtime.shared_services();
        shared.relay_plane().relay_health().await.into()
    }

    // -----------------------------------------------------------------------
    // Notifications
    // -----------------------------------------------------------------------

    pub fn notification_settings(
        &self,
        account_ref: String,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self.runtime.notification_settings(&account_ref)?.into())
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_ref: String,
        enabled: bool,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_local_notifications_enabled(&account_ref, enabled)?
            .into())
    }

    pub async fn set_native_push_enabled(
        &self,
        account_ref: String,
        enabled: bool,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_native_push_enabled(&account_ref, enabled)
            .await?
            .into())
    }

    pub fn push_registration(
        &self,
        account_ref: String,
    ) -> Result<Option<PushRegistrationFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .push_registration(&account_ref)?
            .map(Into::into))
    }

    pub async fn upsert_push_registration(
        &self,
        account_ref: String,
        platform: PushPlatformFfi,
        raw_token: String,
        server_pubkey_hex: String,
        relay_hint: Option<String>,
    ) -> Result<PushRegistrationFfi, MarmotKitError> {
        Ok(self
            .runtime
            .upsert_push_registration(
                &account_ref,
                platform.into(),
                &raw_token,
                &server_pubkey_hex,
                relay_hint,
            )
            .await?
            .into())
    }

    pub async fn clear_push_registration(&self, account_ref: String) -> Result<(), MarmotKitError> {
        self.runtime.clear_push_registration(&account_ref).await?;
        Ok(())
    }

    pub async fn group_push_debug_info(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<GroupPushDebugInfoFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .group_push_debug_info(&account_ref, &group_id)
            .await?
            .into())
    }

    pub async fn catch_up_accounts(&self) -> Result<(), MarmotKitError> {
        self.runtime.catch_up_accounts().await?;
        Ok(())
    }

    pub async fn collect_notifications_after_wake(
        &self,
        max_wait_ms: u32,
        source: NotificationWakeSourceFfi,
    ) -> Result<BackgroundNotificationCollectionFfi, MarmotKitError> {
        Ok(self
            .runtime
            .collect_notifications_after_wake(max_wait_ms, source.into())
            .await
            .into())
    }

    /// Full cached Nostr kind:0 profile for an account id (name, display
    /// name, about, picture, nip05, lud16), if the runtime has one
    /// projected. The local account's own profile is cached immediately
    /// after `publish_user_profile`; other accounts' profiles populate via
    /// `refresh_directory`. Returns `None` when nothing is cached yet.
    pub fn user_profile(
        &self,
        account_id_hex: String,
    ) -> Result<Option<UserProfileMetadataFfi>, MarmotKitError> {
        let entry = self.app.directory_entry_for_account_id(&account_id_hex)?;
        Ok(entry.and_then(|record| record.profile).map(Into::into))
    }

    /// Fetch and cache an account's own Nostr kind:0 profile from `relays`.
    /// After this resolves, `user_profile` / `display_name` return the
    /// freshly-fetched metadata (name, picture, etc.) for that account.
    pub async fn refresh_profile(
        &self,
        account_id_hex: String,
        relays: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        self.app
            .refresh_profile_for_account_id(&account_id_hex, endpoints(&relays))
            .await?;
        Ok(())
    }

    /// Initial history fetch for a group (or, when `group_id_hex` is None,
    /// the account-wide tail). Used to populate the conversation view before
    /// the subscription stream takes over.
    pub fn messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
    ) -> Result<Vec<AppMessageRecordFfi>, MarmotKitError> {
        let query = AppMessageQuery {
            group_id_hex,
            limit: limit.map(|n| n as usize),
        };
        let records = self.runtime.messages_with_query(&account_ref, query)?;
        Ok(records.into_iter().map(Into::into).collect())
    }

    /// Materialized conversation timeline for a group or account-wide tail.
    ///
    /// This is the app-facing aggregated view: kind-9 chat/reply/media rows,
    /// kind-1200 stream-start rows, stream-final metadata pointing back to the
    /// start, reaction summaries, delete tombstones, and pagination flags. Raw
    /// kind-7/kind-5 events remain available through `messages(...)` for
    /// diagnostics.
    pub fn timeline_messages(
        &self,
        account_ref: String,
        query: TimelineMessageQueryFfi,
    ) -> Result<TimelinePageFfi, MarmotKitError> {
        let page = self
            .runtime
            .timeline_messages_with_query(&account_ref, timeline_query_from_ffi(query)?)?;
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "timeline_page_conversion",
            method = "timeline_messages"
        )
        .entered();
        Ok(page.into())
    }

    /// Durable chat-list rows for fast app launch. Rows include the group
    /// title/avatar, last kind-9 preview, unread count, and read anchors.
    pub fn chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Vec<ChatListRowFfi>, MarmotKitError> {
        let rows = self.runtime.chat_list(&account_ref, include_archived)?;
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "chat_list_conversion",
            method = "chat_list"
        )
        .entered();
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Establish the unread baseline the first time a user opens a group.
    /// Existing kind-9 history remains read; later remote kind-9 messages count
    /// until marked visible via `mark_timeline_message_read`.
    pub fn initialize_chat_read_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .initialize_chat_read_state(&account_ref, &group_id_hex)?
            .map(Into::into))
    }

    /// Mark a kind-9 timeline message visible/read. Own kind-9 messages can
    /// advance the marker too, which clears any earlier unread messages.
    pub fn mark_timeline_message_read(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let message_id_hex = optional_message_id_hex(Some(message_id_hex))?.ok_or_else(|| {
            MarmotKitError::InvalidHex {
                details: "message id is required".to_owned(),
            }
        })?;
        Ok(self
            .runtime
            .mark_timeline_message_read(&account_ref, &group_id_hex, &message_id_hex)?
            .map(Into::into))
    }

    // -----------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------

    /// Top-level event firehose. One subscription, every account, every event
    /// type. Useful for global diagnostics; specific UIs prefer the
    /// per-account chats/messages/group-state subscriptions below.
    pub fn subscribe_events(&self) -> Arc<EventsSubscription> {
        EventsSubscription::new(self.runtime.subscribe_events())
    }

    pub async fn subscribe_notifications(
        &self,
    ) -> Result<Arc<NotificationsSubscription>, MarmotKitError> {
        let inner = self.runtime.subscribe_notifications()?;
        Ok(NotificationsSubscription::new(inner))
    }

    /// Per-account chats list. Emits whenever a group's projection changes.
    ///
    /// `async` is required even though the body is synchronous: marmot-app's
    /// `subscribe_chats` spawns a background filter task via `tokio::spawn`,
    /// which panics ("no reactor running") if invoked outside a tokio
    /// runtime. UniFFI only enters the tokio runtime for `async` exports, so
    /// the subscribe methods that spawn must be async.
    pub async fn subscribe_chats(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Arc<ChatsSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_chats(&account_ref, include_archived)?;
        Ok(ChatsSubscription::new(inner))
    }

    /// Per-account durable chat-list projection. Async for the same
    /// tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Arc<ChatListSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_chat_list(&account_ref, include_archived)?;
        Ok(ChatListSubscription::new(inner))
    }

    /// Messages for a specific group (when `group_id_hex` is `Some`) or
    /// every message across the account (when `None`). Async for the same
    /// tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
    ) -> Result<Arc<MessagesSubscription>, MarmotKitError> {
        let query = AppMessageQuery {
            group_id_hex,
            limit: None,
        };
        let inner = self.runtime.subscribe_messages(&account_ref, query)?;
        Ok(MessagesSubscription::new(inner))
    }

    /// Live materialized timeline updates for a group or account-wide tail.
    /// The snapshot and each update are full pages for the supplied query.
    pub async fn subscribe_timeline_messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
    ) -> Result<Arc<TimelineMessagesSubscription>, MarmotKitError> {
        let query = TimelineMessageQuery {
            group_id_hex: optional_group_id_hex(group_id_hex)?,
            search: None,
            pagination: TimelinePagination {
                limit: limit.map(|value| value as usize),
                ..TimelinePagination::default()
            },
        };
        let inner = self
            .runtime
            .subscribe_timeline_messages(&account_ref, query)?;
        Ok(TimelineMessagesSubscription::new(inner))
    }

    /// Member/profile/roster changes for one group. Async for the same
    /// tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_group_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Arc<GroupStateSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_group_state(&account_ref, &group_id_hex)?;
        Ok(GroupStateSubscription::new(inner))
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
    fn optional_message_id_hex_trims_and_canonicalizes() {
        assert_eq!(optional_message_id_hex(None).unwrap(), None);
        assert_eq!(optional_message_id_hex(Some("  ".into())).unwrap(), None);
        assert_eq!(
            optional_message_id_hex(Some(format!(" {} ", "AB".repeat(32)))).unwrap(),
            Some("ab".repeat(32))
        );
        assert!(optional_message_id_hex(Some("abcd".into())).is_err());
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
    fn forensics_public_salt_accepts_shared_hex_salt() {
        let salt_hex = "11".repeat(32);
        let salt = forensics_public_salt(Some(salt_hex)).expect("valid salt");

        assert_eq!(salt, vec![0x11; 32]);
    }

    #[test]
    fn forensics_public_salt_rejects_tiny_salt() {
        let err = forensics_public_salt(Some("11".repeat(4))).expect_err("tiny salt rejected");

        assert!(matches!(err, MarmotKitError::InvalidHex { .. }));
    }
}
