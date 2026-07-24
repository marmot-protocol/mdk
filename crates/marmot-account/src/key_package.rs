//! KeyPackage publication: publication payload, publisher trait, and no-op impl.

use async_trait::async_trait;
use cgka_traits::engine::KeyPackage;
use cgka_traits::maintenance::SignedPublicationArtifact;
use cgka_traits::{MemberId, Timestamp, TransportEndpoint};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackagePublication {
    pub account_id: MemberId,
    pub key_package: KeyPackage,
    /// Stable replaceable-event slot (`d` for Nostr kind 30443).
    pub slot_id: String,
    /// Exact authored timestamp selected by lifecycle orchestration.
    pub created_at: Timestamp,
    pub endpoints: Vec<TransportEndpoint>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPackagePublishReceipt {
    pub accepted: Vec<TransportEndpoint>,
    pub failed: Vec<TransportEndpoint>,
}

/// Failure returned by a [`KeyPackagePublisher`].
///
/// `externally_exposed` records whether the KeyPackage may already have been
/// published to an external transport (e.g. accepted by a relay) before the
/// error occurred. The orphan-cleanup path in
/// [`crate::AccountDeviceRuntime::publish_fresh_key_package`] keys on this flag:
///
/// - `externally_exposed == false`: publication failed before any external
///   exposure, so the just-generated private bundle is safe to prune
///   (mdk#160 — the original orphan-accumulation bug).
/// - `externally_exposed == true`: the KeyPackage may already be discoverable on
///   a relay, so the private bundle MUST be retained. Pruning it would turn a
///   local post-publish failure (e.g. a cache write) into a remotely visible but
///   unjoinable KeyPackage: an inviter could build a Welcome against the
///   published event, but the account could never join because the matching
///   private bundle was deleted (mdk#160 adversarial review).
#[derive(Debug, thiserror::Error)]
#[error("key package publication failed: {message}")]
pub struct KeyPackagePublishError {
    pub message: String,
    pub externally_exposed: bool,
}

impl KeyPackagePublishError {
    /// The publication failed before any external exposure could occur; the
    /// caller may safely prune the just-generated private bundle.
    pub fn unexposed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            externally_exposed: false,
        }
    }

    /// The publication may have exposed the KeyPackage to an external transport
    /// before failing; the caller MUST retain the private bundle.
    pub fn exposed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            externally_exposed: true,
        }
    }
}

#[async_trait]
pub trait KeyPackagePublisher: Send + Sync {
    /// One-time compatibility import for the former JSON cache authority.
    fn legacy_slot_id(&self, _account_id: &MemberId) -> Option<String> {
        None
    }

    /// Produce the exact signed transport artifact without network exposure.
    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<SignedPublicationArtifact, KeyPackagePublishError>;

    /// Publish an already signed artifact. Retries must pass the identical
    /// bytes returned by `prepare_key_package`.
    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopKeyPackagePublisher;

#[async_trait]
impl KeyPackagePublisher for NoopKeyPackagePublisher {
    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<SignedPublicationArtifact, KeyPackagePublishError> {
        use sha2::{Digest, Sha256};
        let mut bytes = publication.key_package.bytes().to_vec();
        bytes.extend_from_slice(publication.slot_id.as_bytes());
        bytes.extend_from_slice(&publication.created_at.0.to_be_bytes());
        let id = cgka_traits::MessageId::new(Sha256::digest(&bytes).to_vec());
        Ok(SignedPublicationArtifact {
            id,
            created_at: publication.created_at,
            bytes,
        })
    }

    async fn publish_prepared_key_package(
        &self,
        _publication: &KeyPackagePublication,
        _artifact: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        Ok(KeyPackagePublishReceipt {
            accepted: _publication.endpoints.clone(),
            failed: Vec::new(),
        })
    }
}
