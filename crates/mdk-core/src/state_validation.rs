//! Shared validation helpers for MLS group state.
//!
//! Keep state-transition checks here when they compare current MLS state with
//! staged post-commit state. Broader proposal and group evolution validation can
//! move here incrementally as follow-up work.

use std::collections::BTreeSet;

use mdk_storage_traits::MdkStorageProvider;
use nostr::PublicKey;
use openmls::prelude::{LeafNodeIndex, MlsGroup, Proposal, Sender, StagedCommit};

use crate::MDK;
use crate::error::Error;
use crate::extension::NostrGroupDataExtension;

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Returns the Nostr public keys for the live members of an MLS group.
    pub(crate) fn member_pubkeys(
        &self,
        mls_group: &MlsGroup,
    ) -> Result<BTreeSet<PublicKey>, Error> {
        mls_group
            .members()
            .map(|member| self.pubkey_from_credential(&member.credential))
            .collect()
    }

    /// Returns the Nostr public keys for members after applying a staged commit.
    pub(crate) fn post_commit_member_pubkeys(
        &self,
        mls_group: &MlsGroup,
        staged_commit: &StagedCommit,
    ) -> Result<BTreeSet<PublicKey>, Error> {
        let departing_leaf_indices = Self::departing_leaf_indices(staged_commit);
        let mut member_pubkeys =
            self.member_pubkeys_after_departures(mls_group, &departing_leaf_indices)?;

        for add_proposal in staged_commit.add_proposals() {
            let credential = add_proposal
                .add_proposal()
                .key_package()
                .leaf_node()
                .credential();
            member_pubkeys.insert(self.pubkey_from_credential(credential)?);
        }

        Ok(member_pubkeys)
    }

    /// Validates that removing the specified members would not deplete all admins.
    ///
    /// The admin set is checked against post-departure live MLS members so stale
    /// admin entries do not satisfy the invariant.
    pub(crate) fn validate_admin_depletion(
        &self,
        mls_group: &MlsGroup,
        departing_leaf_indices: &[LeafNodeIndex],
    ) -> Result<(), Error> {
        let group_data = NostrGroupDataExtension::from_group(mls_group)?;
        let departing_leaf_indices = departing_leaf_indices.iter().copied().collect();
        let member_pubkeys =
            self.member_pubkeys_after_departures(mls_group, &departing_leaf_indices)?;
        Self::validate_active_admins(&group_data.admins, &member_pubkeys)
    }

    /// Validates that an admin set contains at least one live member.
    pub(crate) fn validate_active_admins(
        admins: &BTreeSet<PublicKey>,
        member_pubkeys: &BTreeSet<PublicKey>,
    ) -> Result<(), Error> {
        if admins.is_disjoint(member_pubkeys) {
            return Err(Error::Group("Would leave group with no admins".to_string()));
        }

        Ok(())
    }

    /// Validates that the current MLS group contains at least one active admin.
    pub(crate) fn validate_active_admins_in_group(
        &self,
        mls_group: &MlsGroup,
        admins: &BTreeSet<PublicKey>,
    ) -> Result<(), Error> {
        let member_pubkeys = self.member_pubkeys(mls_group)?;
        Self::validate_active_admins(admins, &member_pubkeys)
    }

    /// Validates that a staged commit leaves at least one active admin.
    pub(crate) fn validate_admin_invariant_after_commit(
        &self,
        mls_group: &MlsGroup,
        staged_commit: &StagedCommit,
    ) -> Result<(), Error> {
        let group_data =
            NostrGroupDataExtension::from_group_context(staged_commit.group_context())?;
        let member_pubkeys = self.post_commit_member_pubkeys(mls_group, staged_commit)?;
        Self::validate_active_admins(&group_data.admins, &member_pubkeys)
    }

    fn member_pubkeys_after_departures(
        &self,
        mls_group: &MlsGroup,
        departing_leaf_indices: &BTreeSet<LeafNodeIndex>,
    ) -> Result<BTreeSet<PublicKey>, Error> {
        for leaf_index in departing_leaf_indices {
            mls_group
                .member_at(*leaf_index)
                .ok_or(Error::MessageFromNonMember)?;
        }

        mls_group
            .members()
            .filter(|member| !departing_leaf_indices.contains(&member.index))
            .map(|member| self.pubkey_from_credential(&member.credential))
            .collect()
    }

    fn departing_leaf_indices(staged_commit: &StagedCommit) -> BTreeSet<LeafNodeIndex> {
        staged_commit
            .queued_proposals()
            .filter_map(|queued| match queued.proposal() {
                Proposal::Remove(remove) => Some(remove.removed()),
                Proposal::SelfRemove => match queued.sender() {
                    Sender::Member(leaf_index) => Some(*leaf_index),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }
}
