//! Private KeyPackages (mdk#2628 item 3.4b): single-use KeyPackages this
//! device issues to one sibling and hands over inside the device group. The
//! engine keeps each one's record with its private key; the host decides when
//! to issue, sends the hand-offs and reports them queued. A sibling Welcome
//! (3.5) joins a chat with one; the host admits it first.

use cgka_traits::MessageId;
use cgka_traits::TransportAdapter;
use cgka_traits::app_components::DeviceSlotId;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::storage::IssuedPrivateKeyPackage;
use cgka_traits::transport::Timestamp;

use super::AccountDeviceRuntime;
use crate::error::AccountResult;
use crate::key_package::KeyPackagePublisher;
use crate::routing::TransportRoutingPolicy;
use crate::session::SiblingWelcome;

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
    ) -> AccountResult<IngestOutcome> {
        Ok(self
            .session
            .join_sibling_welcome(message_id, welcome, created_at)
            .await?)
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
