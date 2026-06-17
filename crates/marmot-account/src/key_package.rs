//! KeyPackage publication: publication payload, publisher trait, and no-op impl.

use async_trait::async_trait;
use cgka_traits::MemberId;
use cgka_traits::TransportEndpoint;
use cgka_traits::engine::KeyPackage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackagePublication {
    pub account_id: MemberId,
    pub key_package: KeyPackage,
    pub endpoints: Vec<TransportEndpoint>,
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
///   (darkmatter#160 — the original orphan-accumulation bug).
/// - `externally_exposed == true`: the KeyPackage may already be discoverable on
///   a relay, so the private bundle MUST be retained. Pruning it would turn a
///   local post-publish failure (e.g. a cache write) into a remotely visible but
///   unjoinable KeyPackage: an inviter could build a Welcome against the
///   published event, but the account could never join because the matching
///   private bundle was deleted (darkmatter#160 adversarial review).
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
    async fn publish_key_package(
        &self,
        publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopKeyPackagePublisher;

#[async_trait]
impl KeyPackagePublisher for NoopKeyPackagePublisher {
    async fn publish_key_package(
        &self,
        _publication: KeyPackagePublication,
    ) -> Result<(), KeyPackagePublishError> {
        Ok(())
    }
}
