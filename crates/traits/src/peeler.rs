//! The `TransportPeeler` trait is the crypto boundary between the engine and
//! transport-specific wrapping below it.
//!
//! Welcomes and group messages are separate operations: they use different
//! keys and addressing rules, so they get separate methods.
//!
//! The peeler takes a [`GroupContextSnapshot`] (value type) rather than
//! `&dyn GroupContext` so async peeler calls do not borrow live engine state.

use crate::engine::WelcomeMetadata;
use crate::error::PeelerError;
use crate::group_context::GroupContextSnapshot;
use crate::ingest::PeeledMessage;
use crate::transport::{EncryptedPayload, TransportMessage};
use crate::types::MemberId;
use async_trait::async_trait;

/// MLS group-message payload metadata the engine knows before transport wrap.
///
/// Transport peelers cannot inspect the encrypted MLS bytes. Any transport hint
/// that depends on the plaintext application payload or MLS message class must
/// be carried explicitly at this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMessageMetadata {
    /// An MLS application message whose plaintext is a Marmot inner app event.
    Application {
        /// The sender-authenticated `created_at` from the inner app event.
        inner_created_at: u64,
        /// The active group message-retention duration, in seconds. `None` and
        /// `Some(0)` both mean transport expiration is disabled.
        retention_seconds: Option<u64>,
    },
    /// MLS group-state history: commits and proposals. Transport expiration
    /// MUST NOT be attached to these messages.
    CommitOrProposal,
}

impl GroupMessageMetadata {
    pub fn application(inner_created_at: u64, retention_seconds: Option<u64>) -> Self {
        Self::Application {
            inner_created_at,
            retention_seconds,
        }
    }

    pub fn commit_or_proposal() -> Self {
        Self::CommitOrProposal
    }

    /// The `created_at` to stamp on the OUTER transport envelope so the sender
    /// and every receiver agree on the message's timestamp (#630 cross-client /
    /// package E). Only application messages carry a sender-authenticated inner
    /// `created_at`; commits/proposals have none, so `None` here means the
    /// transport default (wrap time) stands. Binding the outer `created_at` to
    /// the inner one changes the outer transport event id (it is part of the id
    /// preimage) and makes broadcasts of identical content to multiple groups
    /// share a timestamp — an accepted trade-off for cross-client ordering.
    pub fn outer_created_at(&self) -> Option<u64> {
        match self {
            Self::Application {
                inner_created_at, ..
            } => Some(*inner_created_at),
            Self::CommitOrProposal => None,
        }
    }

    /// Compute the transport-level expiration timestamp, if any.
    pub fn expiration_timestamp(&self) -> Result<Option<u64>, GroupMessageMetadataError> {
        let Self::Application {
            inner_created_at,
            retention_seconds,
        } = self
        else {
            return Ok(None);
        };
        let Some(retention_seconds) = retention_seconds else {
            return Ok(None);
        };
        if *retention_seconds == 0 {
            return Ok(None);
        }
        inner_created_at
            .checked_add(*retention_seconds)
            .map(Some)
            .ok_or(GroupMessageMetadataError::ExpirationTimestampOverflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupMessageMetadataError {
    ExpirationTimestampOverflow,
}

/// Unwrap and rewrap transport-layer envelopes. A single peeler typically
/// handles one transport (e.g. `NostrMlsPeeler`).
///
/// ### Method invariants
///
/// - `peel_group_message` MUST fail cleanly with `PeelerError::DecryptFailed`
///   on wrong exporter secrets. A transport that carries an authenticated
///   message-source-epoch hint MAY instead return `PeelerError::StaleEpoch`
///   when that hint is older than the supplied context; transports without
///   such a hint (e.g. the Nostr binding, whose kind-445 content is opaque
///   `base64(nonce || ciphertext)`) simply return `DecryptFailed`. The engine
///   maps both to `StaleReason::PeelFailed`, choosing retry or terminal
///   storage from the available epoch evidence.
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

    async fn wrap_group_message_with_metadata(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
        _metadata: &GroupMessageMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError>;

    async fn wrap_welcome_with_metadata(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
        _metadata: &WelcomeMetadata,
    ) -> Result<TransportMessage, PeelerError> {
        self.wrap_welcome(payload, recipient).await
    }
}
