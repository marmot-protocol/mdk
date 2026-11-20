use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretCredentialKind {
    Signing,
    ExternalDatabase,
    Nip46Session,
}

#[derive(Clone, Copy, Debug)]
pub struct SecretCredential<'a> {
    pub label: &'a str,
    pub account_id_hex: &'a str,
    pub home_id: &'a str,
    pub owner_id: &'a str,
    pub kind: SecretCredentialKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClaimMode {
    CreateOnly,
    AdoptOnly,
    CreateOrAdopt,
    MigrateLegacy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOrigin {
    Created,
    Existing,
}

pub struct AcquiredSecret {
    pub keys: nostr::prelude::Keys,
    pub origin: SecretOrigin,
}

impl std::fmt::Debug for AcquiredSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredSecret")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReleaseMode {
    DeleteIfUnowned,
    Preserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretReleaseOutcome {
    /// The requested managed-receipt operation completed.
    Released,
    /// Managed retirement and deletion completed; only raw legacy cleanup remains unresolved.
    PendingLegacy,
}
