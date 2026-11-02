//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages this
//! device issues to one sibling and hands over inside the device group. The
//! engine keeps each one's record with its private key; the host decides when
//! to issue, sends the hand-offs and reports them queued. A sibling Welcome
//! (3.5) joins a chat with one; the host admits it first. Adding a sibling to
//! a chat leaves one owed, which the host sends in the device group.

use cgka_traits::MessageId;
use cgka_traits::TransportAdapter;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::storage::IssuedPrivateKeyPackage;
use cgka_traits::transport::Timestamp;
use cgka_traits::welcome::SiblingWelcomeJoin;

use super::AccountDeviceRuntime;
use crate::error::AccountResult;
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;
use crate::session::{OwedSiblingWelcome, SiblingWelcome};

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Issue `count` private KeyPackages to the sibling in `recipient`, their
    /// hand-offs not yet queued. With `request`, they answer it: earlier ones
    /// stop counting, and a request already answered issues nothing. Returns
    /// how many were issued.
    pub fn issue_private_key_packages(
        &mut self,
        recipient: &DeviceSlotId,
        count: usize,
        request: Option<&MessageId>,
        now: u64,
    ) -> AccountResult<usize> {
        Ok(self
            .session
            .issue_private_key_packages(recipient, count, request, now)?)
    }

    /// Join a chat from a sibling Welcome carried by the device-group message
    /// `message_id`. The caller admits it from the trusted device group first,
    /// and drains the join's events afterwards, as for a confirmed rejoin.
    /// See [`cgka_engine::Engine::join_sibling_welcome`].
    pub async fn join_sibling_welcome(
        &mut self,
        message_id: &MessageId,
        welcome: &SiblingWelcome,
        created_at: Option<Timestamp>,
    ) -> AccountResult<SiblingWelcomeJoin> {
        Ok(self
            .session
            .join_sibling_welcome(message_id, welcome, created_at)
            .await?)
    }

    /// Every sibling Welcome this device owes at `now`, for the host to send
    /// in the device group. See [`cgka_engine::Engine::owed_sibling_welcomes`].
    pub fn owed_sibling_welcomes(&self, now: Timestamp) -> AccountResult<Vec<OwedSiblingWelcome>> {
        Ok(self.session.owed_sibling_welcomes(now)?)
    }

    /// Record `carrier`, the app event id of the device-group message about
    /// to carry the owed sibling Welcome `id`. See
    /// [`cgka_engine::Engine::carry_sibling_welcome`].
    pub fn carry_sibling_welcome(&self, id: &MessageId, carrier: &[u8]) -> AccountResult<bool> {
        Ok(self.session.carry_sibling_welcome(id, carrier)?)
    }

    /// Mark the sibling Welcome `id` delivered by its published `carrier`.
    /// See [`cgka_engine::Engine::sibling_welcome_delivered`].
    pub fn sibling_welcome_delivered(&self, id: &MessageId, carrier: &[u8]) -> AccountResult<bool> {
        Ok(self.session.sibling_welcome_delivered(id, carrier)?)
    }

    /// Clear the failed `carrier` from the sibling Welcome `id`, so it is
    /// owed again. See [`cgka_engine::Engine::sibling_welcome_send_failed`].
    pub fn sibling_welcome_send_failed(
        &self,
        id: &MessageId,
        carrier: &[u8],
    ) -> AccountResult<bool> {
        Ok(self.session.sibling_welcome_send_failed(id, carrier)?)
    }

    /// Every private KeyPackage this device issued, oldest first.
    pub fn issued_private_key_packages(&self) -> AccountResult<Vec<IssuedPrivateKeyPackage>> {
        Ok(self.session.issued_private_key_packages()?)
    }

    /// Record whether the hand-offs of `references` are queued.
    pub fn set_private_key_package_hand_offs_queued(
        &mut self,
        references: &[Vec<u8>],
        queued: bool,
    ) -> AccountResult<()> {
        Ok(self
            .session
            .set_private_key_package_hand_offs_queued(references, queued)?)
    }

    /// Stop counting private KeyPackages that no longer advertise this
    /// client's capabilities, so upkeep replaces them. Returns how many.
    pub fn uncount_outdated_private_key_packages(&mut self) -> AccountResult<usize> {
        Ok(self.session.uncount_outdated_private_key_packages()?)
    }

    /// Delete private KeyPackages with their keys: those expired at `now`,
    /// and with `recipient`, every one issued to that sibling (3.6 removes a
    /// sibling through this). Returns how many went.
    pub fn discard_private_key_packages(
        &mut self,
        now: u64,
        recipient: Option<&DeviceSlotId>,
    ) -> AccountResult<usize> {
        Ok(self.session.discard_private_key_packages(now, recipient)?)
    }
}
