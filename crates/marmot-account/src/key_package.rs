//! KeyPackage publication: publication payload, publisher trait, and no-op impl.

use async_trait::async_trait;
use cgka_traits::engine::KeyPackage;
use cgka_traits::maintenance::SignedPublicationArtifact;
use cgka_traits::{MemberId, MessageId, Timestamp, TransportEndpoint};

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

/// Endpoint-level publication evidence for lifecycle-aware callers.
///
/// This additive receipt preserves distinctions that the legacy
/// [`KeyPackagePublishReceipt`] cannot represent. Implementers that only
/// provide the legacy publisher method remain source-compatible: the trait's
/// default detailed method adapts their accepted/failed result.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DetailedKeyPackagePublishReceipt {
    pub accepted: Vec<TransportEndpoint>,
    /// Endpoint returned an explicit negative acknowledgement for this exact
    /// publication attempt. This remains retryable and does not prove absence:
    /// a legacy client may have exposed the same signed event before crashing
    /// without persisting its pre-I/O marker.
    pub rejected: Vec<TransportEndpoint>,
    /// Endpoint explicitly proved the exact event absent (for example a
    /// kind-5 target-not-found response). This is terminal for deletion and
    /// proves a rejected publication revision needs no later deletion there.
    pub confirmed_absent: Vec<TransportEndpoint>,
    pub failed: Vec<TransportEndpoint>,
}

impl From<KeyPackagePublishReceipt> for DetailedKeyPackagePublishReceipt {
    fn from(receipt: KeyPackagePublishReceipt) -> Self {
        Self {
            accepted: receipt.accepted,
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: receipt.failed,
        }
    }
}

impl From<DetailedKeyPackagePublishReceipt> for KeyPackagePublishReceipt {
    fn from(mut receipt: DetailedKeyPackagePublishReceipt) -> Self {
        receipt.failed.append(&mut receipt.rejected);
        receipt.failed.append(&mut receipt.confirmed_absent);
        receipt.failed.sort();
        receipt.failed.dedup();
        receipt
            .failed
            .retain(|endpoint| !receipt.accepted.contains(endpoint));
        Self {
            accepted: receipt.accepted,
            failed: receipt.failed,
        }
    }
}

/// Failure returned by a [`KeyPackagePublisher`].
///
/// `externally_exposed` records whether the exact signed event crossed the
/// transport boundary before the error occurred. The pending replacement and
/// its private bundle remain durable in either case until acknowledgement or
/// MLS lifetime expiry; this bit only distinguishes safe regeneration before
/// exposure from an ambiguous publication that must retry identical bytes
/// within the authored revision. A bounded-age transport may later supersede
/// that revision at the same replaceable coordinate.
#[derive(Debug, thiserror::Error)]
#[error("key package publication failed: {message}")]
pub struct KeyPackagePublishError {
    pub message: String,
    pub externally_exposed: bool,
}

impl KeyPackagePublishError {
    /// The publication failed before any external exposure could occur.
    pub fn unexposed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            externally_exposed: false,
        }
    }

    /// The publication may have exposed the KeyPackage to an external transport
    /// before failing.
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
    ///
    /// `Ok(None)` means no legacy record exists. The account/device creation
    /// layer must provision and persist a fresh slot before publication; the
    /// runtime never guesses freshness or mints a replacement slot.
    fn legacy_slot_id(
        &self,
        _account_id: &MemberId,
    ) -> Result<Option<String>, KeyPackagePublishError> {
        Ok(None)
    }

    /// Inclusive age at which a prepared signed artifact is reauthored before
    /// the next publish attempt.
    ///
    /// `None` disables age-based reauthoring and preserves legacy exact-retry
    /// behavior. Transports whose relays enforce a bounded timestamp window
    /// may return an age below that window. At `artifact_age >= threshold`,
    /// the account runtime requests a strictly newer `created_at` for the same
    /// semantic KeyPackage and stable replaceable-event slot, then persists
    /// that replacement revision before any network attempt.
    fn signed_artifact_reauthor_at_age_secs(&self) -> Option<u64> {
        None
    }

    /// Produce the exact signed transport artifact without network exposure.
    async fn prepare_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<SignedPublicationArtifact, KeyPackagePublishError>;

    /// Publish an already signed artifact. Retries within one authored
    /// revision must pass the identical bytes returned by
    /// `prepare_key_package`. The runtime may prepare and durably replace a
    /// stale revision first when [`Self::signed_artifact_reauthor_at_age_secs`]
    /// opts this transport into bounded-age reauthoring.
    async fn publish_prepared_key_package(
        &self,
        publication: &KeyPackagePublication,
        artifact: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError>;

    /// Publish an already signed artifact with detailed endpoint evidence.
    ///
    /// Existing implementations need not override this additive method; their
    /// legacy accepted/failed receipt is promoted conservatively by default.
    async fn publish_prepared_key_package_detailed(
        &self,
        publication: &KeyPackagePublication,
        artifact: &SignedPublicationArtifact,
    ) -> Result<DetailedKeyPackagePublishReceipt, KeyPackagePublishError> {
        self.publish_prepared_key_package(publication, artifact)
            .await
            .map(Into::into)
    }

    /// Delete one superseded signed revision from the listed transport
    /// endpoints.
    ///
    /// Implementations must report endpoint identities exactly. The account
    /// runtime removes only acknowledged endpoints from its durable deletion
    /// obligation; a failed, cancelled, or ambiguous call remains retryable.
    async fn delete_key_package_revision(
        &self,
        _event_id: &MessageId,
        endpoints: &[TransportEndpoint],
    ) -> Result<DetailedKeyPackagePublishReceipt, KeyPackagePublishError> {
        Err(KeyPackagePublishError::unexposed(format!(
            "key package revision deletion is unsupported for {} endpoint(s)",
            endpoints.len()
        )))
    }
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
        publication: &KeyPackagePublication,
        _artifact: &SignedPublicationArtifact,
    ) -> Result<KeyPackagePublishReceipt, KeyPackagePublishError> {
        Ok(KeyPackagePublishReceipt {
            accepted: publication.endpoints.clone(),
            failed: Vec::new(),
        })
    }

    async fn delete_key_package_revision(
        &self,
        _event_id: &MessageId,
        endpoints: &[TransportEndpoint],
    ) -> Result<DetailedKeyPackagePublishReceipt, KeyPackagePublishError> {
        Ok(DetailedKeyPackagePublishReceipt {
            accepted: endpoints.to_vec(),
            rejected: Vec::new(),
            confirmed_absent: Vec::new(),
            failed: Vec::new(),
        })
    }
}
