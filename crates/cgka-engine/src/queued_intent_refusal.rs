//! What the outbound drain does with a queued intent whose preparation fails
//! once the group has settled (mdk#2694).
//!
//! A send that has to wait for convergence is queued and prepared again once
//! the group settles (group-state.md, "Local actions during convergence").
//! That preparation is the send: it runs the checks a direct send runs, on the
//! settled state. A failure is one of two things.
//!
//! - **Refused.** The failure is a verdict on this intent against the settled
//!   state: the sender is no longer an admin, a precondition no longer holds,
//!   the change is not valid there. Preparing it again on that state gives the
//!   same answer, and only a change the user did not ask for could make it
//!   pass. The drain retires the record, as a direct send's refusal leaves
//!   nothing behind, announces [`GroupEvent::QueuedIntentRefused`], and goes
//!   on with the next record. Nothing prepares the intent again; the user may
//!   ask again.
//! - **Held.** The error reports the device or the group's lifecycle rather
//!   than the intent ([`reports_the_device`]), or a gate that holds back every
//!   send of the group was closed when the preparation failed: the group is
//!   not `Stable`, is halted, is disbanding or terminal, or owes a
//!   restored-epoch rotation. The record stays queued and a later drain
//!   prepares it, as before.
//!
//! The drain decides from the group's gates, not from an error's text, because
//! one error type carries both kinds: an `InvalidTransition` is a lifecycle
//! hold ("send requires Stable") or a verdict (strict cutover refusing an
//! Invite into a legacy group) depending on where it came from.
//!
//! `Backend` is a refusal. The engine maps every OpenMLS error to it, and
//! most are verdicts on the intent: a KeyPackage whose signature fails, a
//! same-account Add of a device already in the group. Holding `Backend` would
//! leave each of those failing every later drain. The cost is an OpenMLS
//! storage failure during a drain: it retires that one intent and announces
//! it, as a direct send's failure leaves nothing behind, and the user may ask
//! again. `Storage` errors, which the engine's own writes raise, stay held.
//!
//! An intent's KeyPackages are also checked before it is queued
//! ([`Engine::check_queued_key_packages`]): those checks read nothing of the
//! group's state, so the sender learns of a bad package at once, as from a
//! direct send, rather than from a later announcement. A lifetime is checked
//! against the clock at both points: a package not yet valid is refused when
//! queued, and one that expires while queued is refused at drain.
//!
//! The announcement rides `events_buf` like `LocalGroupCopyTerminated`'s: a
//! crash between the durable retirement and the host draining events loses
//! it, and the record is already gone.

use crate::engine::Engine;
use cgka_traits::engine::{GroupEvent, SendIntent};
use cgka_traits::engine_state::EpochState;
use cgka_traits::error::EngineError;
use cgka_traits::storage::{QueuedOutboundIntent, StorageProvider};
use cgka_traits::types::GroupId;

/// What a failed drain-time preparation means for the queued record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueuedPreparationFailure {
    /// The settled state refused the intent: retire it and tell the host.
    Refused,
    /// The device or the group could not send anything now: keep it queued.
    Held,
}

/// Whether `error` reports the device or the group's lifecycle rather than
/// the intent, so a later preparation can succeed with no change to the
/// group's state. Exhaustive, so a new error variant is classified here
/// before the drain can retire anything on it.
fn reports_the_device(error: &EngineError) -> bool {
    match error {
        EngineError::Storage(_)
        | EngineError::Peeler(_)
        | EngineError::UnknownGroup(_)
        | EngineError::GroupNotHydrated(_)
        | EngineError::GroupUnrecoverableRepairRequired { .. }
        | EngineError::ForkedEpoch { .. }
        | EngineError::QueuedOutboundAtCapacity { .. }
        | EngineError::UnknownPending => true,
        EngineError::NotAMember { .. }
        | EngineError::NotGroupAdmin { .. }
        | EngineError::UnknownMember { .. }
        | EngineError::InvalidCredentialIdentity(_)
        | EngineError::AdminCannotSelfRemove { .. }
        | EngineError::LeaveAlreadyRequested { .. }
        | EngineError::AdminDepletion { .. }
        | EngineError::MissingRequiredCapabilities { .. }
        | EngineError::DisbandingUnsupportedMembers { .. }
        | EngineError::DisbandingNotEnabled { .. }
        | EngineError::AccountDevicesActivationRefused { .. }
        | EngineError::UnsupportedCiphersuite { .. }
        | EngineError::InvalidAppMessagePayload(_)
        | EngineError::InvalidAccountIdentityProof(_)
        | EngineError::InvalidKeyPackageLifetime { .. }
        | EngineError::InvalidKeyPackageCapabilities { .. }
        | EngineError::NoDataAppComponent { .. }
        | EngineError::AppMessageEpochMismatch { .. }
        | EngineError::AppMessageEpochUnsettled { .. }
        | EngineError::LinkDeviceUnsettled { .. }
        | EngineError::InvalidTransition(_)
        | EngineError::Serialize(_)
        // Every OpenMLS error, verdicts included; see the module docs.
        | EngineError::Backend(_)
        | EngineError::InvalidWelcome
        | EngineError::MissingWelcomeKeyPackage
        | EngineError::WelcomeNotAddressedToThisDevice
        | EngineError::WelcomeAlreadyProcessed
        | EngineError::UnexpectedDeviceGroupWelcome
        | EngineError::Other(_) => false,
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Refuse now an intent whose KeyPackages a direct send would refuse now.
    /// Run before it is queued, so the sender is answered at once rather than
    /// by a later [`GroupEvent::QueuedIntentRefused`].
    pub(crate) fn check_queued_key_packages(&self, intent: &SendIntent) -> Result<(), EngineError> {
        let (SendIntent::Invite { key_packages, .. }
        | SendIntent::AddOwnAccountDevices { key_packages, .. }) = intent
        else {
            return Ok(());
        };
        for key_package in key_packages {
            self.parse_key_package(key_package)?;
        }
        Ok(())
    }

    /// Classify a failed drain-time preparation of a queued intent in
    /// `group_id`. A gate this cannot read counts as closed: when in doubt,
    /// the record stays queued.
    pub(crate) fn queued_preparation_failure(
        &mut self,
        group_id: &GroupId,
        error: &EngineError,
    ) -> QueuedPreparationFailure {
        if reports_the_device(error) || self.group_send_gate_closed(group_id).unwrap_or(true) {
            QueuedPreparationFailure::Held
        } else {
            QueuedPreparationFailure::Refused
        }
    }

    /// Whether a gate that holds back every send of `group_id` is closed: the
    /// group-wide checks `do_send_ready` runs before or beside the intent's
    /// own, and the restored-epoch rotation drain maintenance owes first.
    fn group_send_gate_closed(&mut self, group_id: &GroupId) -> Result<bool, EngineError> {
        let group = self.stored_group_record(group_id)?;
        Ok(group.as_ref().is_none_or(|group| group.is_terminal())
            || self.sync_unrecoverable_halt_from_record(group_id, group.as_ref())
            || self.disbanding_in_progress(group_id)?
            || self
                .epoch_manager
                .state(group_id)
                .is_some_and(|state| !matches!(state, EpochState::Stable { .. }))
            || self.needs_replay_rotation(group_id)?)
    }

    /// Retire a queued intent the settled state refused and tell the host.
    /// Nothing was staged for it, so the durable delete is the only write; the
    /// announcement follows it.
    pub(crate) fn retire_refused_queued_intent(
        &mut self,
        record: &QueuedOutboundIntent,
        error: &EngineError,
    ) -> Result<(), EngineError> {
        self.storage.delete_queued_outbound_intent(&record.id)?;
        let intent_kind = crate::audit_helpers::send_intent_kind_str(&record.intent);
        let reason = error.privacy_safe_kind();
        self.audit_group(
            &record.group_id,
            marmot_forensics::AuditEventKind::Rejection {
                msg_id: hex::encode(record.id.as_slice()),
                reason: "queued_outbound_intent_refused_on_settled_state".to_string(),
            },
        );
        // Privacy-safe: the intent's kind and the error's variant name only.
        tracing::info!(
            target: "cgka_engine::queued_intent_refusal",
            method = "retire_refused_queued_intent",
            intent_kind,
            error_kind = reason,
            "queued intent refused on the settled state; retired"
        );
        self.events_buf.push_back(GroupEvent::QueuedIntentRefused {
            group_id: record.group_id.clone(),
            intent_id: record.id.clone(),
            intent_kind: intent_kind.to_string(),
            reason: reason.to_string(),
        });
        Ok(())
    }
}
