//! Turning on `marmot.group.account-devices.v1` in an existing group, for
//! `SendIntent::EnableAccountDevices` (account-devices-v1.md, "Activation in an
//! existing group"; mdk#2628 item 2.4).
//!
//! Activation is one admin Commit that adds `0x800d` to the GroupContext
//! `app_components` required list. The component has no initial state. If the
//! GroupContext still carries an entry under its id, which only an earlier
//! client could have left there, the same Commit removes it ("Data").
//!
//! [`account_devices_activation_refusal`] is the one eligibility answer: the
//! host's read before offering the action and the intent's check before
//! staging both call it, on the state the Commit is prepared on. Its reasons
//! are aggregate and never name the members or devices that block activation.
//! The checks only name the reason for a refusal; the resulting-state rules
//! that 2.1 enforces on every staged Commit stay the backstop
//! ([`crate::app_components::validate_current_profile_invariants_for_staged_commit`]).
//!
//! A send that has to wait for convergence is checked before it is queued,
//! so a refusal the current state already shows is answered at once. The
//! drain checks again on the settled state; a refusal there retires the
//! queued intent ([`is_refused_queued_activation`]) instead of leaving a
//! record that fails every later drain.
//!
//! The Commit goes through the generic AppDataUpdate path, which does not
//! commit proposals by reference: in normal operation retained inbound
//! proposals live in message storage, not OpenMLS's proposal store. Like
//! `EnableDisbanding`, the intent keeps no `OwnCommitIntent`, so when branch
//! selection supersedes it nothing re-issues it. The user asks again, and the
//! checks then run on the winning branch: an activation that lost to an Add
//! of an unsupported device is refused there instead of committed.

use std::collections::BTreeMap;

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::MemberId;
use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID, AppComponentData,
    MAX_LEAVES_PER_ACCOUNT, encode_components_list,
};
use cgka_traits::engine::{SendIntent, SendResult};
use cgka_traits::error::{AccountDevicesActivationRefusal, EngineError};
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;
use openmls::prelude::BasicCredential;
use openmls_traits::OpenMlsProvider as _;

/// Why `self_id` cannot activate account-devices in `group` now, or `None`
/// when it can.
///
/// The admin check comes first, so a member that may not activate learns
/// nothing else about the group's leaves. The leaf checks walk the ratchet
/// tree, so one device's support never stands in for a sibling's; the first
/// failing rule, in the order the reasons are listed, is reported.
pub(crate) fn account_devices_activation_refusal(
    group: &MlsGroup,
    self_id: &MemberId,
) -> Result<Option<AccountDevicesActivationRefusal>, EngineError> {
    let account = crate::app_components::admin_pubkey_from_member_id(self_id)?;
    if !crate::app_components::admins_of_group(group)?.contains(&account) {
        return Ok(Some(AccountDevicesActivationRefusal::NotAdmin));
    }
    if crate::account_identity_proof::protocol_profile_of_group(group)? == ProtocolProfile::Legacy {
        return Ok(Some(AccountDevicesActivationRefusal::LegacyProfile));
    }
    if crate::app_components::required_app_components_of_group(group)?
        .contains(ACCOUNT_DEVICES_COMPONENT_ID)
    {
        return Ok(Some(AccountDevicesActivationRefusal::AlreadyRequired));
    }

    let mut unsupported = false;
    let mut carries_data = false;
    let mut leaves_per_account: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for leaf in crate::app_components::ratchet_tree_leaves(group.export_ratchet_tree())? {
        unsupported |= !crate::app_components::app_components_of_leaf(&leaf)?
            .contains(ACCOUNT_DEVICES_COMPONENT_ID);
        carries_data |= crate::app_components::carries_account_devices_data(
            leaf.extensions().app_data_dictionary(),
        );
        let identity = BasicCredential::try_from(leaf.credential().clone())
            .map_err(|_| EngineError::Other("a leaf has no basic credential".into()))?
            .identity()
            .to_vec();
        *leaves_per_account.entry(identity).or_default() += 1;
    }
    Ok(if unsupported {
        Some(AccountDevicesActivationRefusal::UnsupportedLeaves)
    } else if carries_data {
        Some(AccountDevicesActivationRefusal::LeafCarriesData)
    } else if leaves_per_account
        .values()
        .any(|count| *count > MAX_LEAVES_PER_ACCOUNT)
    {
        Some(AccountDevicesActivationRefusal::LeafLimitExceeded)
    } else {
        None
    })
}

/// The error a refused activation returns: a non-admin gets the same answer
/// as for any other admin action, every other reason the typed refusal.
fn refusal_error(group_id: GroupId, reason: AccountDevicesActivationRefusal) -> EngineError {
    match reason {
        AccountDevicesActivationRefusal::NotAdmin => EngineError::NotGroupAdmin { group_id },
        reason => EngineError::AccountDevicesActivationRefused { group_id, reason },
    }
}

/// Whether preparing a queued `intent` failed because the settled state
/// refuses the activation. The user's request has then failed, as a direct
/// send's refusal would, so the drain retires the intent rather than keep a
/// record every later drain fails on.
pub(crate) fn is_refused_queued_activation(intent: &SendIntent, error: &EngineError) -> bool {
    matches!(intent, SendIntent::EnableAccountDevices { .. })
        && matches!(
            error,
            EngineError::AccountDevicesActivationRefused { .. } | EngineError::NotGroupAdmin { .. }
        )
}

impl<S: StorageProvider> Engine<S> {
    /// Refuse an activation the current state already rules out, before the
    /// send is queued behind convergence. The drain checks again on the
    /// settled state.
    pub(crate) fn check_account_devices_activation(
        &self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        match self.account_devices_activation_refusal(group_id)? {
            None => Ok(()),
            Some(reason) => Err(refusal_error(group_id.clone(), reason)),
        }
    }

    /// Why this device cannot turn on account-devices in `group_id` now, or
    /// `None` when it can. An advisory read for a host deciding whether to
    /// offer the action; the intent repeats the check under the engine
    /// mutation lock, so a roster change in between stays safe.
    pub fn account_devices_activation_refusal(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<AccountDevicesActivationRefusal>, EngineError> {
        self.ensure_group_live(group_id)?;
        self.with_mls_group(group_id, |group| {
            account_devices_activation_refusal(group, self.identity.self_id())
        })
    }

    pub(crate) async fn do_enable_account_devices(
        &mut self,
        group_id: GroupId,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        if let Some(reason) =
            account_devices_activation_refusal(&mls_group, self.identity.self_id())?
        {
            return Err(refusal_error(group_id, reason));
        }

        let mut required = crate::app_components::required_app_components_of_group(&mls_group)?;
        required.insert(ACCOUNT_DEVICES_COMPONENT_ID);
        let updates = vec![AppComponentData {
            component_id: APP_COMPONENTS_COMPONENT_ID,
            data: encode_components_list(&required.ids),
        }];
        let removals = if crate::app_components::carries_account_devices_data(
            mls_group.extensions().app_data_dictionary(),
        ) {
            vec![ACCOUNT_DEVICES_COMPONENT_ID]
        } else {
            Vec::new()
        };
        drop(mls_group);
        self.do_send_app_data_updates(group_id, updates, removals)
            .await
    }
}
