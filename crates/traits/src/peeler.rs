//! The `TransportPeeler` trait is the crypto boundary between the engine and
//! transport-specific wrapping below it.
//!
//! Welcomes and group messages are separate operations: they use different
//! keys and addressing rules, so they get separate methods.
//!
//! The peeler takes a [`GroupContextSnapshot`] (value type) rather than
//! `&dyn GroupContext` so async peeler calls do not borrow live engine state.

use crate::error::PeelerError;
use crate::group_context::GroupContextSnapshot;
use crate::ingest::PeeledMessage;
use crate::transport::{EncryptedPayload, TransportMessage};
use crate::types::MemberId;
use async_trait::async_trait;

/// Unwrap and rewrap transport-layer envelopes. A single peeler typically
/// handles one transport (e.g. `NostrMlsPeeler`).
///
/// ### Method invariants
///
/// - `peel_group_message` MUST fail cleanly with `PeelerError::DecryptFailed`
///   on wrong exporter secrets. If envelope metadata shows the message source
///   epoch is older than the supplied context, prefer `PeelerError::StaleEpoch`.
///   The engine maps both to
///   `StaleReason::PeelFailed`, choosing retry or terminal storage from
///   the available epoch evidence.
/// - `peel_welcome` MUST fail cleanly for welcomes not addressed to the
///   local identity — the engine maps that to `StaleReason::NotForThisClient`.
/// - `wrap_group_message` MUST be deterministic given the same input
///   (same `EncryptedPayload` + same `GroupContextSnapshot.epoch` →
///   reproducible wire bytes modulo outer-layer nonces/timestamps). The
///   harness asserts on this where applicable.
/// - Implementations are `Send + Sync`; the `#[async_trait]` macro handles
///   the lifetime gymnastics.
#[async_trait]
pub trait TransportPeeler: Send + Sync {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError>;

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError>;

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError>;

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError>;
}
