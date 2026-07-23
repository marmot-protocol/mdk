//! Marmot semantic authorization for standalone and staged MLS proposals.
//!
//! OpenMLS validates wire syntax and signatures; this module enforces protocol-core
//! rules from `group-messaging.md` and `member-departure.md` against the
//! authenticated source-epoch / candidate-parent group state. Every inbound seam
//! that can queue or commit proposals must call these helpers before mutating
//! pending proposal state.

use cgka_traits::app_components::AppComponentData;
use cgka_traits::ingest::ProposalRejectionCategory;
use cgka_traits::types::GroupId;
use openmls::framing::Sender;
use openmls::group::{MlsGroup, ProcessMessageError, StageCommitError};
use openmls::messages::proposals::{AppDataUpdateOperation, Proposal};
use openmls::prelude::{
    ContentType, ProposalOrRefType, ProposalValidationError, QueuedProposal, StagedCommit,
    ValidationError,
};

use crate::app_components::{
    admins_of_group, credential_account_pubkey, validate_app_component_remove,
    validate_app_component_update,
};
use crate::capabilities::capabilities_of_key_package;
use crate::capability_manager::{
    required_capabilities_from_group, required_role_capabilities_from_group,
};
use crate::identity::member_id_of_sender;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalAuthorizationContext {
    Standalone,
    StagedCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalAuthorizationOutcome {
    Authorized,
    Rejected(ProposalRejectionCategory),
}

pub(crate) fn proposal_rejection_category_tag(category: ProposalRejectionCategory) -> &'static str {
    match category {
        ProposalRejectionCategory::AuthorizationFailed => "authorization_failed",
        ProposalRejectionCategory::UnsupportedProposal => "unsupported_proposal",
        ProposalRejectionCategory::InvalidEncoding => "invalid_encoding",
        ProposalRejectionCategory::InvalidSignature => "invalid_signature",
        ProposalRejectionCategory::InvalidSelfRemove => "invalid_self_remove",
    }
}

/// Authorize one queued proposal against `mls_group`'s current epoch state.
pub(crate) fn authorize_queued_proposal(
    mls_group: &MlsGroup,
    _group_id: &GroupId,
    queued: &QueuedProposal,
    context: ProposalAuthorizationContext,
) -> ProposalAuthorizationOutcome {
    let ciphersuite = mls_group.ciphersuite();
    let sender_member = member_id_of_sender(queued.sender(), mls_group);
    let sender_account = sender_account_pubkey(mls_group, queued.sender());
    let admins = match admins_of_group(mls_group) {
        Ok(admins) => admins,
        Err(_) => {
            return ProposalAuthorizationOutcome::Rejected(
                ProposalRejectionCategory::InvalidEncoding,
            );
        }
    };
    if admins.is_empty() {
        // Current-profile groups require admin-policy state; absence is fail-closed
        // at this profile-policy seam (no permissive legacy fallback).
        return ProposalAuthorizationOutcome::Rejected(ProposalRejectionCategory::InvalidEncoding);
    }
    let sender_is_admin = sender_account
        .as_ref()
        .is_some_and(|pk| admins.iter().any(|admin| admin == pk));

    match queued.proposal() {
        Proposal::SelfRemove => {
            authorize_self_remove_proposal(queued.sender(), sender_account, &admins)
        }
        Proposal::AppDataUpdate(update) => {
            if !sender_is_admin {
                return ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::AuthorizationFailed,
                );
            }
            match update.operation() {
                AppDataUpdateOperation::Update(data) => {
                    let component = AppComponentData {
                        component_id: update.component_id(),
                        data: data.as_slice().to_vec(),
                    };
                    if validate_app_component_update(&component).is_err() {
                        return ProposalAuthorizationOutcome::Rejected(
                            ProposalRejectionCategory::InvalidEncoding,
                        );
                    }
                }
                AppDataUpdateOperation::Remove => {
                    if validate_app_component_remove(mls_group, update.component_id()).is_err() {
                        return ProposalAuthorizationOutcome::Rejected(
                            ProposalRejectionCategory::InvalidEncoding,
                        );
                    }
                }
            }
            ProposalAuthorizationOutcome::Authorized
        }
        Proposal::Add(add) => {
            if !sender_is_admin {
                return ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::AuthorizationFailed,
                );
            }
            let advertised = capabilities_of_key_package(add.key_package());
            let missing_required =
                required_capabilities_from_group(mls_group).missing_from(&advertised);
            let missing_roles =
                required_role_capabilities_from_group(mls_group).missing_from(&advertised);
            if !missing_required.is_empty() || !missing_roles.is_empty() {
                return ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::UnsupportedProposal,
                );
            }
            if crate::key_package::validate_add_proposal_key_package(add, ciphersuite).is_err() {
                return ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::InvalidEncoding,
                );
            }
            ProposalAuthorizationOutcome::Authorized
        }
        Proposal::Update(update) => match context {
            ProposalAuthorizationContext::Standalone => {
                if sender_is_admin {
                    ProposalAuthorizationOutcome::Rejected(
                        ProposalRejectionCategory::UnsupportedProposal,
                    )
                } else {
                    ProposalAuthorizationOutcome::Rejected(
                        ProposalRejectionCategory::AuthorizationFailed,
                    )
                }
            }
            ProposalAuthorizationContext::StagedCommit => {
                // A by-reference Update originated as a standalone proposal, so
                // it remains subject to the standalone sender rule when a later
                // Commit consumes it. This is the commit-time revalidation seam
                // for proposals retained before the current policy was applied.
                if queued.proposal_or_ref_type() == ProposalOrRefType::Reference && !sender_is_admin
                {
                    return ProposalAuthorizationOutcome::Rejected(
                        ProposalRejectionCategory::AuthorizationFailed,
                    );
                }
                let Some(sender_member) = sender_member.as_ref() else {
                    return ProposalAuthorizationOutcome::Rejected(
                        ProposalRejectionCategory::InvalidSignature,
                    );
                };
                if crate::account_identity_proof::validate_leaf_account_identity_proof_for_member(
                    update.leaf_node(),
                    ciphersuite,
                    sender_member,
                    "Update proposal",
                )
                .is_err()
                {
                    return ProposalAuthorizationOutcome::Rejected(
                        ProposalRejectionCategory::InvalidEncoding,
                    );
                }
                ProposalAuthorizationOutcome::Authorized
            }
        },
        Proposal::Remove(_) | Proposal::GroupContextExtensions(_) => {
            if !sender_is_admin {
                ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::AuthorizationFailed,
                )
            } else {
                ProposalAuthorizationOutcome::Authorized
            }
        }
        Proposal::PreSharedKey(_)
        | Proposal::ReInit(_)
        | Proposal::ExternalInit(_)
        | Proposal::AppEphemeral(_)
        | Proposal::Custom(_) => {
            if sender_is_admin {
                // v1 protocol core does not define admin standalone shapes for these
                // proposal types; fail closed rather than admit by omission.
                ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::UnsupportedProposal,
                )
            } else {
                ProposalAuthorizationOutcome::Rejected(
                    ProposalRejectionCategory::AuthorizationFailed,
                )
            }
        }
    }
}

/// Revalidate every by-reference and by-value proposal consumed by a staged commit.
pub(crate) fn authorize_staged_commit_queued_proposals(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    staged: &StagedCommit,
) -> ProposalAuthorizationOutcome {
    for queued in staged.queued_proposals() {
        let outcome = authorize_queued_proposal(
            mls_group,
            group_id,
            queued,
            ProposalAuthorizationContext::StagedCommit,
        );
        if outcome != ProposalAuthorizationOutcome::Authorized {
            return outcome;
        }
    }
    ProposalAuthorizationOutcome::Authorized
}

/// Map only proposal-specific OpenMLS processing failures into the stable
/// rejection taxonomy. Unrelated commit/path failures remain ordinary engine
/// errors so callers do not mislabel them as rejected proposals.
pub(crate) fn classify_process_message_error<StorageError>(
    err: &ProcessMessageError<StorageError>,
    content_type: ContentType,
) -> Option<ProposalRejectionCategory> {
    match (content_type, err) {
        (ContentType::Proposal, ProcessMessageError::UnsupportedProposalType) => {
            Some(ProposalRejectionCategory::UnsupportedProposal)
        }
        (ContentType::Proposal, ProcessMessageError::IncompatibleWireFormat) => {
            Some(ProposalRejectionCategory::InvalidEncoding)
        }
        (ContentType::Proposal, ProcessMessageError::ValidationError(validation)) => {
            match validation {
                ValidationError::WrongEpoch => None,
                ValidationError::UnknownMember
                | ValidationError::MissingMembershipTag
                | ValidationError::InvalidMembershipTag
                | ValidationError::InvalidSignature
                | ValidationError::UnauthorizedExternalSender
                | ValidationError::NoExternalSendersExtension
                | ValidationError::InvalidLeafNodeSignature
                | ValidationError::InvalidSenderType => {
                    Some(ProposalRejectionCategory::InvalidSignature)
                }
                _ => Some(ProposalRejectionCategory::InvalidEncoding),
            }
        }
        // A commit-level WrongWireFormat is the OpenMLS error currently used
        // when an inline AppDataUpdate payload fails validation. Keep all other
        // message-level commit failures on the ordinary commit classification
        // path; they are not evidence that a proposal failed Marmot semantics.
        (
            ContentType::Commit,
            ProcessMessageError::ValidationError(ValidationError::WrongWireFormat),
        ) => Some(ProposalRejectionCategory::InvalidEncoding),
        (
            ContentType::Commit,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                validation,
            )),
        ) => Some(match validation {
            ProposalValidationError::InsufficientCapabilities
            | ProposalValidationError::UnsupportedProposalType => {
                ProposalRejectionCategory::UnsupportedProposal
            }
            ProposalValidationError::UnknownMember
            | ProposalValidationError::UpdateFromNonMember => {
                ProposalRejectionCategory::InvalidSignature
            }
            _ => ProposalRejectionCategory::InvalidEncoding,
        }),
        (
            ContentType::Commit,
            ProcessMessageError::InvalidCommit(
                StageCommitError::AppDataUpdateValidationError(_)
                | StageCommitError::ApplyAppDataUpdateError(_)
                | StageCommitError::GroupContextExtensionsProposalValidationError(_)
                | StageCommitError::LeafNodeValidation(_),
            ),
        ) => Some(ProposalRejectionCategory::InvalidEncoding),
        _ => None,
    }
}

fn authorize_self_remove_proposal(
    sender: &Sender,
    sender_account: Option<[u8; 32]>,
    admins: &[[u8; 32]],
) -> ProposalAuthorizationOutcome {
    let Sender::Member(_leaf_idx) = sender else {
        return ProposalAuthorizationOutcome::Rejected(ProposalRejectionCategory::InvalidSignature);
    };
    // SelfRemove admin comparison uses the 32-byte BasicCredential identity on
    // the same non-curve-validating basis as `decode_admin_policy` /
    // `credential_account_pubkey`, NOT the secp256k1-validating
    // `identity::member_id_of_sender` (mdk#728). The admin set is not
    // curve-validated, so a leaf whose 32-byte identity equals a listed admin
    // key but fails secp256k1 validation would resolve to `None` under the
    // validating chokepoint and skip this guard. Matching the admin-set basis
    // keeps both sides of the comparison comparable. Fail CLOSED: a SelfRemove
    // whose sender cannot be resolved on that basis is rejected.
    let Some(sender_pubkey) = sender_account else {
        return ProposalAuthorizationOutcome::Rejected(
            ProposalRejectionCategory::InvalidSelfRemove,
        );
    };
    if admins.iter().any(|admin| admin == &sender_pubkey) {
        return ProposalAuthorizationOutcome::Rejected(
            ProposalRejectionCategory::InvalidSelfRemove,
        );
    }
    ProposalAuthorizationOutcome::Authorized
}

fn sender_account_pubkey(mls_group: &MlsGroup, sender: &Sender) -> Option<[u8; 32]> {
    match sender {
        Sender::Member(leaf_idx) => mls_group
            .member_at(*leaf_idx)
            .and_then(|member| credential_account_pubkey(member.credential)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::proposal_rejection_category_tag;
    use cgka_traits::ingest::ProposalRejectionCategory;

    #[test]
    fn rejection_category_tags_are_stable() {
        assert_eq!(
            proposal_rejection_category_tag(ProposalRejectionCategory::AuthorizationFailed),
            "authorization_failed"
        );
        assert_eq!(
            proposal_rejection_category_tag(ProposalRejectionCategory::UnsupportedProposal),
            "unsupported_proposal"
        );
    }
}
